use crate::dwarf_data::DwarfData;
use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::mem::size_of;
use std::os::unix::prelude::CommandExt;
use std::process::{Child, Command};

pub enum Status {
    /// Indicates inferior stopped. Contains the signal that stopped the process, as well as the
    /// current instruction pointer that it is stopped at.
    Stopped(signal::Signal, usize),

    /// Indicates inferior exited normally. Contains the exit status code.
    Exited(i32),

    /// Indicates the inferior exited due to a signal. Contains the signal that killed the
    /// process.
    Signaled(signal::Signal),
}

/// This function calls ptrace with PTRACE_TRACEME to enable debugging on a process. You should use
/// pre_exec with Command to call this in the child process.
fn child_traceme() -> Result<(), std::io::Error> {
    ptrace::traceme().or(Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ptrace TRACEME failed",
    )))
}

fn align_addr_to_word(addr: u64) -> u64 {
    addr & (-(size_of::<u64>() as i64) as u64)
}

pub struct Inferior {
    child: Child,
    breakpoint: HashMap<u64, u8>,
}

impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>, breakpoints: &Vec<u64>) -> Option<Inferior> {
        let mut cmd = Command::new(target);
        cmd.args(args);
        unsafe {
            cmd.pre_exec(child_traceme);
        }
        let child = cmd.spawn().expect("Inferior::new(): spawn() failed");
        let mut inferior = Inferior {
            child,
            breakpoint: HashMap::new(),
        };
        match inferior.wait(None).expect("Inferior::new(): wait() failed") {
            Status::Stopped(Signal::SIGTRAP, _) => {
                for &bp in breakpoints {
                    inferior
                        .set_breakpoint(bp)
                        .expect("Inferior::new(): Set breakpoint error");
                }
                Some(inferior)
            }
            _ => {
                println!("Inferior::new(): wait() not return SIGTRAP");
                None
            }
        }
    }

    /// Returns the pid of this inferior.
    pub fn pid(&self) -> Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<Status, nix::Error> {
        Ok(match waitpid(self.pid(), options)? {
            WaitStatus::Exited(_pid, exit_code) => Status::Exited(exit_code),
            WaitStatus::Signaled(_pid, signal, _core_dumped) => {
                let regs = ptrace::getregs(self.pid())?;
                println!(
                    "wait: signaled at 0x{:x} by {} {}",
                    regs.rip,
                    signal.to_string(),
                    if _core_dumped { "(core dumped)" } else { "" }
                );
                Status::Signaled(signal)
            }
            WaitStatus::Stopped(_pid, signal) => {
                let mut regs = ptrace::getregs(self.pid())?;
                if self.breakpoint.contains_key(&(regs.rip - 1)) {
                    // Stop by a breakpoint
                    regs.rip = regs.rip - 1;
                    self.write_byte(regs.rip, *self.breakpoint.get(&regs.rip).unwrap())?;
                    ptrace::setregs(self.pid(), regs)?;
                }
                Status::Stopped(signal, regs.rip as usize)
            }
            other => panic!("waitpid returned unexpected status: {:?}", other),
        })
    }

    pub fn cont(&self) -> Result<Status, nix::Error> {
        let pid = self.pid();
        let regs = ptrace::getregs(pid)?;
        if self.breakpoint.contains_key(&regs.rip) {
            // Continue and re-setup the breakpoint
            ptrace::step(pid, None).unwrap();
            match waitpid(pid, None).unwrap() {
                WaitStatus::Exited(_, exit_code) => {
                    return Ok(Status::Exited(exit_code));
                }
                WaitStatus::Signaled(_, signal, _) => {
                    return Ok(Status::Signaled(signal));
                }
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    self.write_byte(regs.rip, 0xcc).unwrap();
                }
                other => panic!("waitpid returned unexpected status: {:?}", other),
            }
        }
        ptrace::cont(pid, None)?;
        self.wait(None)
    }

    pub fn kill(&mut self) -> Result<(), std::io::Error> {
        self.child.kill()
    }

    pub fn print_backtrace(&self, dwarf_data: &DwarfData) -> Result<(), nix::Error> {
        let regs = ptrace::getregs(self.pid())?;
        let mut rip = regs.rip;
        let mut rbp = regs.rbp;
        loop {
            let _func = dwarf_data.get_function_from_addr(rip as usize);
            match &_func {
                Some(func) => print!("{}", func),
                None => print!("unknown func"),
            }
            match &dwarf_data.get_line_from_addr(rip as usize) {
                Some(line) => println!(" ({}:{})", line.file, line.number),
                None => println!(" (unknown file)"),
            }
            if let Some(func) = &_func {
                if func == "main" {
                    break;
                }
            }
            rip = ptrace::read(self.pid(), (rbp + 8) as ptrace::AddressType)? as u64;
            rbp = ptrace::read(self.pid(), rbp as ptrace::AddressType)? as u64;
        }
        return Ok(());
    }

    pub fn set_breakpoint(&mut self, addr: u64) -> Result<(), nix::Error> {
        self.breakpoint.insert(addr, self.write_byte(addr, 0xcc)?);
        Ok(())
    }

    fn write_byte(&self, addr: u64, val: u8) -> Result<u8, nix::Error> {
        let aligned_addr = align_addr_to_word(addr);
        let byte_offset = addr - aligned_addr;
        let word = ptrace::read(self.pid(), aligned_addr as ptrace::AddressType)? as u64;
        let orig_byte = (word >> 8 * byte_offset) & 0xff;
        let masked_word = word & !(0xff << 8 * byte_offset);
        let updated_word = masked_word | ((val as u64) << 8 * byte_offset);
        ptrace::write(
            self.pid(),
            aligned_addr as ptrace::AddressType,
            updated_word as *mut std::ffi::c_void,
        )?;
        Ok(orig_byte as u8)
    }
}
