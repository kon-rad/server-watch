//! Small helpers: run a command with a timeout, read files, clock, hashing.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct Out {
    pub stdout: String,
    pub stderr: String,
    pub ok: bool,
}

/// Run a command, kill it after `timeout`, never invoke a shell.
/// Returns None if the program is missing or timed out.
pub fn run(cmd: &str, args: &[&str], timeout: Duration) -> Option<Out> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let mut so = child.stdout.take()?;
    let mut se = child.stderr.take()?;
    let t1 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let t2 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(_) => return None,
        }
    };
    let b1 = t1.join().unwrap_or_default();
    let b2 = t2.join().unwrap_or_default();
    Some(Out {
        stdout: String::from_utf8_lossy(&b1).into_owned(),
        stderr: String::from_utf8_lossy(&b2).into_owned(),
        ok: status.map(|s| s.success()).unwrap_or(false),
    })
}

/// stdout of a command that succeeded, else None.
pub fn out(cmd: &str, args: &[&str], secs: u64) -> Option<String> {
    run(cmd, args, Duration::from_secs(secs))
        .filter(|o| o.ok)
        .map(|o| o.stdout)
}

pub fn which(cmd: &str) -> bool {
    let path = std::env::var("PATH").unwrap_or_default();
    let extra = ["/usr/sbin", "/sbin", "/usr/local/bin", "/opt/homebrew/bin"];
    path.split(':')
        .chain(extra.iter().copied())
        .any(|d| std::path::Path::new(d).join(cmd).is_file())
}

pub fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Epoch seconds to `2026-10-27 07:40 UTC`.
pub fn iso(epoch: u64) -> String {
    let days = (epoch / 86400) as i64;
    let rem = epoch % 86400;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60
    )
}

pub fn sha8(s: &str) -> String {
    let h = Sha256::digest(s.as_bytes());
    h.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

pub fn hostname() -> String {
    out("hostname", &[], 3)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".into())
}

pub fn human_age(secs: u64) -> String {
    match secs {
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 172800 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_known_dates() {
        assert_eq!(iso(0), "1970-01-01 00:00 UTC");
        assert_eq!(iso(1_793_086_800), "2026-10-27 07:40 UTC");
        assert_eq!(iso(951_782_400), "2000-02-29 00:00 UTC");
    }

    #[test]
    fn age() {
        assert_eq!(human_age(90), "1m");
        assert_eq!(human_age(7200), "2h");
        assert_eq!(human_age(3 * 86400), "3d");
    }
}
