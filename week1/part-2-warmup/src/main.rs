/* The following exercises were borrowed from Will Crichton's CS 242 Rust lab. */

use std::collections::HashSet;
use std::io::{self, Write};
use std::ops::IndexMut;

fn prompt_user_input(s: &str) -> String {
    let mut buf = String::new();
    print!("{}", s);
    io::stdout().flush();
    io::stdin().read_line(&mut buf).unwrap();
    buf.trim_end().to_string()
}

fn read_shopping_list() -> Vec<String> {
    // Read the shopping list and return it

    // Remember: if you're trying to return a variable called "shopping_list"
    // at the end, the last line of this function should be "shopping_list"
    // instead of "return shopping_list;". Both would do the same thing, but
    // it's considered more idiomatic style to write the former.

    let mut shopping_list = Vec::new();
    loop {
        let input = prompt_user_input("Enter an item to add to the list: ");
        if input.to_lowercase() == "done" {
            break;
        }
        shopping_list.push(input);
    }
    shopping_list
}

fn print_shopping_list(shopping_list: &Vec<String>) {
    // Print shopping_list
    println!("Remember to buy:");
    for item in shopping_list {
        println!("* {}", item);
    }
}

fn main() {
    let shopping_list = read_shopping_list();
    print_shopping_list(&shopping_list);
}

fn add_n(v: Vec<i32>, n: i32) -> Vec<i32> {
    let mut mv = v;
    mv[0] += n;
    return mv;
}

fn add_n_inplace(v: &mut Vec<i32>, n: i32) {
    v[0] += n;
}

fn dedup(v: &mut Vec<i32>) {
    let mut h = HashSet::new();
    v.retain(|&x| {
        if h.contains(&x) {
            false
        } else {
            h.insert(x);
            true
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_add_n() {
        assert_eq!(add_n(vec![1], 2), vec![3]);
    }

    #[test]
    fn test_add_n_inplace() {
        let mut v = vec![1];
        add_n_inplace(&mut v, 2);
        assert_eq!(v, vec![3]);
    }

    #[test]
    fn test_dedup() {
        let mut v = vec![3, 1, 0, 1, 4, 4];
        dedup(&mut v);
        assert_eq!(v, vec![3, 1, 0, 4]);
    }
}
