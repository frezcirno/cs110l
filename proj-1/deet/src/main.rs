mod debugger;
mod debugger_command;
mod inferior;
mod dwarf_data;
mod gimli_wrapper;

use crate::debugger::Debugger;
use nix::sys::signal::{signal, SigHandler, Signal};
use std::env;

/// `add_one` 将指定值加1
///
/// # Examples11
///
/// ```
/// let arg = 5;
/// let answer = world_hello::compute::add_one(arg);
///
/// assert_eq!(6, answer);
/// ```
pub fn add_one(x: i32) -> i32 {
    x + 1
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <target program>", args[0]);
        std::process::exit(1);
    }
    let target = &args[1];

    // Disable handling of ctrl+c in this process (so that ctrl+c only gets delivered to child
    // processes)
    unsafe { signal(Signal::SIGINT, SigHandler::SigIgn) }.expect("Error disabling SIGINT handling");

    Debugger::new(target).run();
}
