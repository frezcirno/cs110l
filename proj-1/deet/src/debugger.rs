use crate::debugger_command::DebuggerCommand;
use crate::dwarf_data::{DwarfData, Error as DwarfError};
use crate::inferior::{Inferior, Status};
use rustyline::error::ReadlineError;
use rustyline::Editor;

fn parse_address(addr: &str) -> Option<u64> {
    let addr_without_0x = if addr.to_lowercase().starts_with("0x") {
        &addr[2..]
    } else {
        &addr
    };
    u64::from_str_radix(addr_without_0x, 16).ok()
}

pub struct Debugger {
    target: String,
    history_path: String,
    readline: Editor<()>,
    inferior: Option<Inferior>,
    debug_data: DwarfData,
    breakpoints: Vec<u64>,
}

impl Debugger {
    /// Initializes the debugger.
    pub fn new(target: &str) -> Debugger {
        let debug_data = match DwarfData::from_file(target) {
            Ok(val) => val,
            Err(DwarfError::ErrorOpeningFile) => {
                println!("Could not open file {}", target);
                std::process::exit(1);
            }
            Err(DwarfError::DwarfFormatError(err)) => {
                println!(
                    "Could not load debugging symbols from {}: {:?}",
                    target, err
                );
                std::process::exit(1);
            }
        };
        debug_data.print();

        let history_path = format!("{}/.deet_history", std::env::var("HOME").unwrap());
        let mut readline = Editor::<()>::new();
        // Attempt to load history from ~/.deet_history if it exists
        let _ = readline.load_history(&history_path);

        Debugger {
            target: target.to_string(),
            history_path,
            readline,
            inferior: None,
            debug_data,
            breakpoints: Vec::new(),
        }
    }

    pub fn reap(&mut self) {
        if let Some(inferior) = &mut self.inferior {
            println!("Killing running inferior (pid {})", inferior.pid());
            inferior.kill().unwrap();
        }
    }

    pub fn report(&self, status: Status) {
        match status {
            Status::Stopped(sig, rip) => {
                println!("Child stopped (signal {})", sig);
                if let Some(line) = self.debug_data.get_line_from_addr(rip) {
                    println!("Stopped at {}:{}", line.file, line.number);
                }
            }
            Status::Signaled(sig) => {
                println!("Child died (signal {})", sig.to_string())
            }
            Status::Exited(status) => println!("Child exited (status {})", status),
        };
    }

    pub fn run(&mut self) {
        loop {
            match self.get_next_command() {
                DebuggerCommand::Run(args) => {
                    self.reap();
                    if let Some(inferior) = Inferior::new(&self.target, &args, &self.breakpoints) {
                        // Create the inferior
                        self.inferior = Some(inferior);
                        self.report(self.inferior.as_ref().unwrap().cont().unwrap());
                    } else {
                        println!("Error starting subprocess");
                    }
                }
                DebuggerCommand::Quit => {
                    self.reap();
                    return;
                }
                DebuggerCommand::Cont => {
                    if let Some(inferior) = &self.inferior {
                        self.report(inferior.cont().unwrap());
                    } else {
                        println!("No subprocess");
                    }
                }
                DebuggerCommand::Backtrace => {
                    if let Some(inferior) = &self.inferior {
                        inferior.print_backtrace(&self.debug_data).unwrap();
                    } else {
                        println!("No subprocess");
                    }
                }
                DebuggerCommand::Break(pos) => {
                    let mut address = None;
                    if pos.starts_with("*") {
                        if let Some(addr) = parse_address(&pos[1..]) {
                            println!("Set breakpoint {} at {}", self.breakpoints.len(), &pos[1..]);
                            address = Some(addr);
                        }
                    } else if let Ok(line_number) = u64::from_str_radix(&pos, 10) {
                        if let Some(addr) = self
                            .debug_data
                            .get_addr_for_line(None, line_number as usize)
                        {
                            println!(
                                "Set breakpoint {} at 0x{:x} (line {})",
                                self.breakpoints.len(),
                                addr,
                                &pos
                            );
                            address = Some(addr as u64);
                        }
                    } else if let Some(addr) = self.debug_data.get_addr_for_function(None, &pos) {
                        println!(
                            "Set breakpoint {} at 0x{:x} (function {})",
                            self.breakpoints.len(),
                            addr,
                            &pos
                        );
                        address = Some(addr as u64);
                    }

                    if let Some(addr) = address {
                        if let Some(inferior) = &mut self.inferior {
                            inferior.set_breakpoint(addr).unwrap();
                        } else {
                            self.breakpoints.push(addr);
                        }
                    } else {
                        println!("Set breakpoint at {} failed", &pos);
                    }
                }
            }
        }
    }

    /// This function prompts the user to enter a command, and continues re-prompting until the user
    /// enters a valid command. It uses DebuggerCommand::from_tokens to do the command parsing.
    ///
    /// You don't need to read, understand, or modify this function.
    fn get_next_command(&mut self) -> DebuggerCommand {
        loop {
            // Print prompt and get next line of user input
            match self.readline.readline("(deet) ") {
                Err(ReadlineError::Interrupted) => {
                    // User pressed ctrl+c. We're going to ignore it
                    println!("Type \"quit\" to exit");
                }
                Err(ReadlineError::Eof) => {
                    // User pressed ctrl+d, which is the equivalent of "quit" for our purposes
                    return DebuggerCommand::Quit;
                }
                Err(err) => {
                    panic!("Unexpected I/O error: {:?}", err);
                }
                Ok(line) => {
                    if line.trim().len() == 0 {
                        continue;
                    }
                    self.readline.add_history_entry(line.as_str());
                    if let Err(err) = self.readline.save_history(&self.history_path) {
                        println!(
                            "Warning: failed to save history file at {}: {}",
                            self.history_path, err
                        );
                    }
                    let tokens: Vec<&str> = line.split_whitespace().collect();
                    if let Some(cmd) = DebuggerCommand::from_tokens(&tokens) {
                        return cmd;
                    } else {
                        println!("Unrecognized command.");
                    }
                }
            }
        }
    }
}
