use std::{env, io, thread, time};
use std::ptr::{null_mut};
use colored::Colorize;
use winapi::shared::minwindef::{BOOL, FALSE};
use winapi::um::processthreadsapi::{CreateProcessA, OpenThread, ResumeThread, PROCESS_INFORMATION, STARTUPINFOA};
use winapi_comm::GetLastError;
use windows_sys::Win32::System::Threading::{CREATE_SUSPENDED, THREAD_RESUME};
use crate::ainz::ainz::*;
use crate::ainz::ainz::InjectMode::*;
use crate::config::config::{load_dlls_from_config, load_game_from_config};

pub mod ainz;

mod config;


fn main() {
    let args: Vec<String> = env::args().collect();
    dbg!(&args);


    let mut ainz = Ainz {
        dlls: load_dlls_from_config(&args[2].clone()),
        target_proc_name: args[1].clone(),
        ainz_ctx: AinzCtx::new(),
        delay_between: args[5].parse().unwrap(),
        inject_mode: match args[4].as_str() {
            "native" => Native,
            _ => Native
        },
        inject_method: match args[6].as_str() {
            "existing" => InjectMethod::ExistingProcess,
            "wait" => InjectMethod::WaitProcess,
            "run" => InjectMethod::LaunchProcess,
            _ => InjectMethod::WaitProcess
        },
        is_unlink_module: args[7].parse().unwrap(),
    };
    unsafe {
        let _ = ainz.init();
        match ainz.inject_method {
            InjectMethod::WaitProcess => {
                println!("{}", "Waiting for process...".cyan());
                while !ainz.is_process_alive() {
                    thread::sleep(time::Duration::from_millis(100));
                }
                println!("{}", "Process found! Waiting for initialization...".green());
                thread::sleep(time::Duration::from_millis(100));
                let _ = ainz.init();
            }
            InjectMethod::LaunchProcess => {
                println!("{}", "Launching process...".cyan());
                let game_path = load_game_from_config(&args[3].clone());
                let cmdline = format!("\"{}\"", game_path);

                unsafe {
                    let mut si: STARTUPINFOA = std::mem::zeroed();
                    si.cb = size_of::<STARTUPINFOA>() as u32;

                    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
                    let result = CreateProcessA(
                        null_mut(),
                        cmdline.as_ptr() as *mut _,
                        null_mut(),
                        null_mut(),
                        FALSE,
                        CREATE_SUSPENDED,
                        null_mut(),
                        null_mut(),
                        &mut si,
                        &mut pi,
                    );
                    if result == 0 {
                        println!("CreateProcessA failed: {}", GetLastError());
                    }

                    println!(
                        "Launched suspended! PID={}, TID={}",
                        pi.dwProcessId, pi.dwThreadId
                    );
                    ainz.init().expect("TODO: panic message");

                    std::thread::sleep(time::Duration::from_millis(2000));
                    if ainz.ainz_ctx.tid > 0 {
                        let thread = OpenThread(THREAD_RESUME, BOOL::from(false), ainz.ainz_ctx.tid);
                        if ResumeThread(thread) as i32 != -1 {
                            println!("Resume thread {} successfully.", ainz.ainz_ctx.tid);
                        }
                    }
                }
            }
            _ => {}
        }
        if ainz.inject() {
            println!("{}", "Inject successful.".green());
        } else {
           println!("{}", "Inject failed.".red());
        };

        if ainz.is_unlink_module {
            thread::sleep(time::Duration::from_millis(15000));
            match ainz.unlink_module() {
                Ok(_) => { println!("{}", "Unlinked module successfully.".green()); },
                Err(UnlinkError::InvalidHandle) => { println!("{}", "[Unlink] Invalid process handle.".red()); },
                Err(UnlinkError::InvalidPPEB) => { println!("{}", "[Unlink] Invalid PPEB.".red()); },
                Err(UnlinkError::InvalidPEB) => { println!("{}", "[Unlink] Invalid PEB.".red()); },
                Err(UnlinkError::InvalidLdr) => { println!("{}", "[Unlink] Invalid Ldr.".red()); },
                Err(UnlinkError::FailedReadLdr) => { println!("{}", "[Unlink] Failed read Ldr.".red()); },
                Err(UnlinkError::FailedReadPEB) => { println!("{}", "[Unlink] Failed read PEB.".red()); },
                Err(UnlinkError::FailedHideEntry) => { println!("{}", "[Unlink] Failed hide entry.".red()); },
                Err(UnlinkError::FailedInternalReadCurrent) => { println!("{}", "[Unlink->Hide] Failed internal read (*current).".red()); },
                Err(UnlinkError::FailedInternalReadDllBuffer) => { println!("{}", "[Unlink->Hide] Failed internal read dll buffer.".red()); },
                Err(UnlinkError::FailedInternalReadEntryAddress) => { println!("{}", "[Unlink->Hide] Failed internal read entry address.".red()); },
                Err(UnlinkError::FailedMutate) => { println!("{}", "[Unlink->Hide->Mutate] Failed mutate.".red()); },
            }
        }
    }
    let _ = io::read_to_string(io::stdin());
}