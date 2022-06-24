use std::sync::Arc;
use std::sync::Mutex;
use std::{thread, time};

fn ticket_agent(id: usize, remaining_tickets: Arc<Mutex<usize>>) {
    loop {
        let mut remaining_tickets_ref = remaining_tickets.lock().unwrap();
        if *remaining_tickets_ref == 0 {
            break;
        }
        *remaining_tickets_ref -= 1;
        println!(
            "Agent #{} sold a ticket! ({} more to be sold)",
            id, *remaining_tickets_ref
        );
    }
    println!("Agent #{} notices all tickets are sold, and goes home!", id);
}

fn main() {
    let remaining_tickets: Arc<Mutex<usize>> = Arc::new(Mutex::new(250));
    let mut threads = Vec::new();
    for i in 0..10 {
        let remaining_tickets_handle = remaining_tickets.clone();
        threads.push(thread::spawn(move || {
            ticket_agent(i, remaining_tickets_handle);
        }));
    }
    // wait for all the threads to finish
    for handle in threads {
        handle.join().expect("Panic occurred in thread!");
    }
    println!("End of business day!");
}
