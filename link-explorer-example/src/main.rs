extern crate reqwest;
extern crate select;
#[macro_use]
extern crate error_chain;

use select::document::Document;
use select::predicate::Name;
use std::sync::{Arc, Mutex};
use threadpool::ThreadPool;

error_chain! {
   foreign_links {
       ReqError(reqwest::Error);
       IoError(std::io::Error);
   }
}

const TARGET_PAGE: &str = "https://baike.baidu.com/item/%E5%A4%9A%E7%BA%BF%E7%A8%8B";

// Define a struct to put in the Arc<Mutex<T>>
struct Article {
    url: String,
    length: usize,
}

// Nothing interesting here; feel free to ignore.
fn get_linked_pages(html_body: &str) -> Result<Vec<String>> {
    Ok(Document::from_read(html_body.as_bytes())?
        .find(Name("a"))
        .filter_map(|n| {
            if let Some(link_str) = n.attr("href") {
                if link_str.starts_with("/item/") {
                    Some(format!("{}/{}", "https://baike.baidu.com", &link_str[1..]))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect::<Vec<String>>())
}

// Adapted from https://rust-lang-nursery.github.io/rust-cookbook/web/scraping.html
fn main() -> Result<()> {
    // Get the body of the page
    let html_body = reqwest::blocking::get(TARGET_PAGE)?.text()?;
    // Identify all linked wikipedia pages
    let links = get_linked_pages(&html_body)?;

    // Arc containing a mutex containing an Article
    let longest_article = Arc::new(Mutex::new(Article {
        url: "".to_string(),
        length: 0,
    }));

    // Get each link
    let threadpool = ThreadPool::new(20);
    for link in links {
        let longest_article_handle = longest_article.clone();
        threadpool.execute(move || {
            let body = reqwest::blocking::get(&link).unwrap().text().unwrap();
            let curr_len = body.len();
            let mut longest_article = longest_article_handle.lock().unwrap();
            if curr_len > longest_article.length {
                longest_article.length = curr_len;
                longest_article.url = link.to_string();
            }
        });
    }
    threadpool.join();
    let longest_article_ref = longest_article.lock().unwrap();
    println!(
        "{} was the longest article with length {}",
        longest_article_ref.url, longest_article_ref.length
    );
    Ok(())
}
