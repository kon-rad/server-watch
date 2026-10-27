//! Collectors. Each reads one thing about the machine and adds metrics, findings or facts.
//! A missing tool or file means the check is skipped, never an error.

use crate::config::Config;
use crate::finding::{Counters, Finding, Severity, Snapshot};
use crate::util::{out, read, sha8, which};
use std::collections::BTreeMap;

pub struct Ctx<'a> {
    pub cfg: &'a Config,
    /// Deep checks are slow (full-disk setuid scan, sshd config, firewall); run them daily.
    pub deep: bool,
    /// Look at logs since this epoch.
    pub since: u64,
    pub now: u64,
    pub prev: Option<Counters>,
}

const LINUX: bool = cfg!(target_os = "linux");
const MAC: bool = cfg!(target_os = "macos");

pub fn collect(ctx: &Ctx) -> Snapshot {
    let mut s = Snapshot::default();
    let on = |n: &str| ctx.cfg.enabled(n);
    let _t = &ctx.cfg.thresholds;

    if on("disk") {
        disk(&mut s, ctx.cfg);
    }
    memory(&mut s, ctx);
    load(&mut s, ctx);
    uptime(&mut s);
    logins(&mut s);
    if on("ports") {
        ports(&mut s);
    }
    if on("authkeys") {
        authkeys(&mut s);
    }
    if LINUX {
        if on("reboot") {
            reboot(&mut s);
        }
        if on("updates") {
            updates(&mut s);
        }
        if on("unattended") {
            unattended(&mut s);
        }
        if on("needrestart") {
            needrestart(&mut s);
        }
        if on("failed_units") {
            failed_units(&mut s);
        }
        if on("ssh_logins") {
            ssh_logins(&mut s, ctx);
        }
        if on("users") {
            users(&mut s);
        }
        if on("cron") {
            cron(&mut s);
        }
        if on("units") {
            units(&mut s);
        }
        if on("processes") {
            processes(&mut s);
        }
        lynis(&mut s);
        if ctx.deep {
            if on("suid") {
                suid(&mut s);
            }
            if on("sshd_config") {
                sshd_config(&mut s);
            }
            if on("firewall") {
                firewall(&mut s);
            }
            if on("blocker") {
                blocker(&mut s);
            }
        }
    }
    if MAC && ctx.deep && on("updates") {
        mac_updates(&mut s);
    }
    s
}

// ---------- disk ----------

pub fn parse_df(s: &str) -> Vec<(String, u64)> {
    s.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 6 || !f[0].starts_with("/dev/") || f[0].starts_with("/dev/loop") {
                return None;
            }
            let mount = f[5..].join(" ");
            if mount.starts_with("/System/Volumes/") && mount != "/System/Volumes/Data" {
                return None;
            }
            Some((mount, f[4].trim_end_matches('%').parse().ok()?))
        })
        .collect()
}

fn disk(s: &mut Snapshot, cfg: &Config) {
    let Some(o) = out("df", &["-Pk"], 10) else {
        return;
    };
    let (warn, crit) = (cfg.thresholds.disk_warn, cfg.thresholds.disk_crit);
    let mut max = 0;
    for (mount, pct) in parse_df(&o) {
        // Xcode simulator runtimes are read-only disk images that always sit near 100%.
        if mount.starts_with("/Library/Developer/CoreSimulator/")
            || cfg
                .disk_ignore
                .iter()
                .any(|i| mount.starts_with(i.as_str()))
        {
            continue;
        }
        max = max.max(pct);
        s.metric(&format!("disk_pct:{mount}"), pct);
        if pct >= crit {
            s.add(Finding::new(
                format!("disk:{mount}"),
                Severity::Critical,
                format!("Disk {mount} is {pct}% full"),
                format!("Critical threshold {crit}%"),
            ));
        } else if pct >= warn {
            s.add(Finding::new(
                format!("disk:{mount}"),
                Severity::Warn,
                format!("Disk {mount} is {pct}% full"),
                format!("Warn threshold {warn}%"),
            ));
        }
    }
    s.metric("disk_max_pct", max);
}

// ---------- memory and swap ----------

#[derive(Default, Debug, PartialEq)]
pub struct Mem {
    pub total_kb: u64,
    pub avail_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

pub fn parse_meminfo(s: &str) -> Mem {
    let mut m = Mem::default();
    for l in s.lines() {
        let mut it = l.split_whitespace();
        let (Some(k), Some(v)) = (it.next(), it.next()) else {
            continue;
        };
        let v: u64 = v.parse().unwrap_or(0);
        match k {
            "MemTotal:" => m.total_kb = v,
            "MemAvailable:" => m.avail_kb = v,
            "SwapTotal:" => m.swap_total_kb = v,
            "SwapFree:" => m.swap_free_kb = v,
            _ => {}
        }
    }
    m
}

fn mac_mem() -> Option<Mem> {
    let total: u64 = out("sysctl", &["-n", "hw.memsize"], 3)?
        .trim()
        .parse()
        .ok()?;
    let vm = out("vm_stat", &[], 3)?;
    let page: u64 = vm
        .split("page size of ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let get = |k: &str| -> u64 {
        vm.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().trim_end_matches('.').parse().ok())
            .unwrap_or(0)
    };
    let avail = (get("Pages free")
        + get("Pages inactive")
        + get("Pages speculative")
        + get("Pages purgeable"))
        * page;
    let mut m = Mem {
        total_kb: total / 1024,
        avail_kb: avail / 1024,
        ..Default::default()
    };
    if let Some(sw) = out("sysctl", &["-n", "vm.swapusage"], 3) {
        let num = |key: &str| -> u64 {
            sw.split(key)
                .nth(1)
                .and_then(|r| r.trim_start_matches([' ', '=']).split('M').next())
                .and_then(|v| v.trim().parse::<f64>().ok())
                .map(|v| (v * 1024.0) as u64)
                .unwrap_or(0)
        };
        m.swap_total_kb = num("total");
        m.swap_free_kb = num("free");
    }
    Some(m)
}

pub fn parse_vmstat(s: &str) -> (u64, u64) {
    let get = |k: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(k))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    };
    (get("pswpin "), get("pswpout "))
}

/// Top processes by swap use: (kB, name).
pub fn top_swap() -> Vec<(u64, String)> {
    let mut v = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return v;
    };
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if !n.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(st) = read(&format!("/proc/{n}/status")) else {
            continue;
        };
        let name = st
            .lines()
            .find_map(|l| l.strip_prefix("Name:"))
            .map(|x| x.trim().to_string())
            .unwrap_or_default();
        let kb = st
            .lines()
            .find_map(|l| l.strip_prefix("VmSwap:"))
            .and_then(|x| x.split_whitespace().next()?.parse::<u64>().ok())
            .unwrap_or(0);
        if kb > 0 {
            v.push((kb, format!("{name}({n})")));
        }
    }
    v.sort_by(|a, b| b.0.cmp(&a.0));
    v.truncate(4);
    v
}

fn memory(s: &mut Snapshot, ctx: &Ctx) {
    let m = if LINUX {
        read("/proc/meminfo").map(|x| parse_meminfo(&x))
    } else {
        mac_mem()
    };
    let Some(m) = m.filter(|m| m.total_kb > 0) else {
        return;
    };
    let t = &ctx.cfg.thresholds;
    let avail_pct = m.avail_kb * 100 / m.total_kb;
    let swap_used_pct = if m.swap_total_kb > 0 {
        (m.swap_total_kb - m.swap_free_kb.min(m.swap_total_kb)) * 100 / m.swap_total_kb
    } else {
        0
    };
    s.metric("mem_total_mb", m.total_kb / 1024);
    s.metric("mem_avail_pct", avail_pct);
    s.metric("mem_used_pct", 100 - avail_pct.min(100));
    s.metric("swap_total_mb", m.swap_total_kb / 1024);
    s.metric("swap_used_pct", swap_used_pct);
    let detail = format!("{} MB total, {}% available", m.total_kb / 1024, avail_pct);
    if ctx.cfg.enabled("memory") {
        if avail_pct <= t.mem_avail_crit {
            s.add(Finding::new(
                "memory",
                Severity::Critical,
                format!("Only {avail_pct}% of RAM available"),
                detail,
            ));
        } else if avail_pct <= t.mem_avail_warn {
            s.add(Finding::new(
                "memory",
                Severity::Warn,
                format!("Only {avail_pct}% of RAM available"),
                detail,
            ));
        }
    }
    if !ctx.cfg.enabled("swap") {
        return;
    }
    let who = || {
        if LINUX {
            let v = top_swap();
            if v.is_empty() {
                String::new()
            } else {
                format!(
                    "Top swap users: {}",
                    v.iter()
                        .map(|(kb, n)| format!("{n} {} MB", kb / 1024))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        } else {
            String::new()
        }
    };
    if swap_used_pct >= t.swap_used_warn {
        s.add(Finding::new(
            "swap_full",
            Severity::Warn,
            format!("Swap is {swap_used_pct}% used"),
            who(),
        ));
    }
    if LINUX {
        if let Some(v) = read("/proc/vmstat") {
            let (pin, pout) = parse_vmstat(&v);
            if let Some(p) = &ctx.prev {
                let dt = ctx.now.saturating_sub(p.ts);
                if dt >= 30 {
                    let rate = pout.saturating_sub(p.pswpout) as f64 / dt as f64;
                    s.metric("swapout_pps", (rate * 10.0).round() / 10.0);
                    if rate > t.swap_out_warn_pps {
                        s.add(Finding::new(
                            "swap_paging",
                            Severity::Warn,
                            format!("Actively paging out: {rate:.0} pages/s to swap"),
                            who(),
                        ));
                    }
                }
            }
            s.counters = Some(Counters {
                ts: ctx.now,
                pswpin: pin,
                pswpout: pout,
            });
        }
    }
}

// ---------- load, uptime, logins ----------

pub fn parse_loadavg(s: &str) -> Option<(f64, f64, f64)> {
    let nums: Vec<f64> = s
        .trim_matches(|c| c == '{' || c == '}' || c == ' ')
        .split_whitespace()
        .take(3)
        .filter_map(|x| x.parse().ok())
        .collect();
    if nums.len() == 3 {
        Some((nums[0], nums[1], nums[2]))
    } else {
        None
    }
}

fn load(s: &mut Snapshot, ctx: &Ctx) {
    let raw = if LINUX {
        read("/proc/loadavg")
    } else {
        out("sysctl", &["-n", "vm.loadavg"], 3)
    };
    let Some((l1, l5, l15)) = raw.and_then(|r| parse_loadavg(&r)) else {
        return;
    };
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as f64;
    s.metric("cores", cores as u64);
    s.metric("load1", l1);
    s.metric("load5", l5);
    s.metric("load15", l15);
    if !ctx.cfg.enabled("load") {
        return;
    }
    let per = l5 / cores;
    let t = &ctx.cfg.thresholds;
    let detail = format!("load {l1:.2} {l5:.2} {l15:.2} on {cores:.0} core(s)");
    if per >= t.load_crit {
        s.add(Finding::new(
            "load",
            Severity::Critical,
            format!("Load is {per:.1}x core count"),
            detail,
        ));
    } else if per >= t.load_warn {
        s.add(Finding::new(
            "load",
            Severity::Warn,
            format!("Load is {per:.1}x core count"),
            detail,
        ));
    }
}

fn uptime(s: &mut Snapshot) {
    if let Some(u) = read("/proc/uptime").and_then(|u| {
        u.split_whitespace()
            .next()
            .and_then(|x| x.parse::<f64>().ok())
    }) {
        s.metric("uptime_hours", (u / 3600.0).round() as u64);
    }
}

fn logins(s: &mut Snapshot) {
    let Some(w) = out("who", &[], 3) else { return };
    let list: Vec<String> = w
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect();
    s.metric("sessions", list.len() as u64);
    s.metric("session_list", list.join("; "));
}

// ---------- listening ports ----------

/// `ss -H -tulnp` lines to (key "tcp/22/public", detail "sshd").
pub fn parse_ss(s: &str) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for l in s.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let proto = if f[0].starts_with("udp") {
            "udp"
        } else {
            "tcp"
        };
        let local = f[4];
        let Some((addr, port)) = local.rsplit_once(':') else {
            continue;
        };
        let scope = scope_of(addr);
        let proc = f
            .get(6..)
            .map(|p| p.join(" "))
            .and_then(|p| p.split('"').nth(1).map(String::from))
            .unwrap_or_else(|| "unknown process".into());
        v.push((
            format!("{proto}/{port}/{scope}"),
            format!("{proc} on {local}"),
        ));
    }
    v
}

fn scope_of(addr: &str) -> &'static str {
    let a = addr.trim_matches(|c| c == '[' || c == ']');
    if a.starts_with("127.")
        || a == "::1"
        || a.starts_with("127.0.0.53%")
        || a.starts_with("::ffff:127.")
    {
        "local"
    } else {
        "public"
    }
}

/// macOS `lsof -nP -iTCP -sTCP:LISTEN` lines.
pub fn parse_lsof(s: &str) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for l in s.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        let Some(i) = f.iter().position(|x| *x == "(LISTEN)") else {
            continue;
        };
        if i == 0 {
            continue;
        }
        let name = f[i - 1];
        let Some((addr, port)) = name.rsplit_once(':') else {
            continue;
        };
        let addr = if addr == "*" { "0.0.0.0" } else { addr };
        v.push((
            format!("tcp/{port}/{}", scope_of(addr)),
            format!("{} on {name}", f[0]),
        ));
    }
    v
}

fn ports(s: &mut Snapshot) {
    let rows = if LINUX {
        out("ss", &["-H", "-tulnp"], 10).map(|o| parse_ss(&o))
    } else {
        out("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"], 10).map(|o| parse_lsof(&o))
    };
    let Some(rows) = rows else { return };
    s.fact_set("ports");
    let public = rows
        .iter()
        .filter(|(k, _)| k.ends_with("/public"))
        .map(|(k, _)| k.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    s.metric("ports_public", public as u64);
    for (k, d) in rows {
        s.fact("ports", k, d);
    }
}

// ---------- ssh authorized keys ----------

fn authkeys(s: &mut Snapshot) {
    let mut homes = vec!["/root".to_string()];
    for base in ["/home", "/Users"] {
        if let Ok(rd) = std::fs::read_dir(base) {
            homes.extend(rd.flatten().map(|e| e.path().to_string_lossy().to_string()));
        }
    }
    s.fact_set("authkeys");
    for h in homes {
        for f in ["authorized_keys", "authorized_keys2"] {
            let path = format!("{h}/.ssh/{f}");
            let Some(body) = read(&path) else { continue };
            for line in body
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
            {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let ty = parts
                    .iter()
                    .find(|p| {
                        p.starts_with("ssh-") || p.starts_with("ecdsa-") || p.starts_with("sk-")
                    })
                    .copied()
                    .unwrap_or("key");
                let comment = parts
                    .last()
                    .filter(|_| parts.len() > 2)
                    .copied()
                    .unwrap_or("no comment");
                s.fact(
                    "authkeys",
                    format!("{path}#{}", sha8(line)),
                    format!("{ty} ({comment}) in {path}"),
                );
            }
        }
    }
}

// ---------- Linux: patching ----------

fn reboot(s: &mut Snapshot) {
    let need = std::path::Path::new("/var/run/reboot-required").exists();
    s.metric("reboot_required", need);
    if need {
        let pkgs = read("/var/run/reboot-required.pkgs")
            .map(|p| p.lines().collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        s.add(Finding::new(
            "reboot_required",
            Severity::Warn,
            "Reboot required to finish updates",
            if pkgs.is_empty() {
                "Run `server-watch harden --apply` to reboot automatically at a quiet hour.".into()
            } else {
                format!("Packages: {pkgs}")
            },
        ));
    }
}

/// Count `Inst` lines from `apt-get -s dist-upgrade`: (total, security, first names).
pub fn parse_apt_sim(s: &str) -> (u64, u64, Vec<String>) {
    let (mut total, mut sec, mut names) = (0, 0, Vec::new());
    for l in s.lines().filter(|l| l.starts_with("Inst ")) {
        total += 1;
        if l.contains("-security") {
            sec += 1;
            if names.len() < 8 {
                names.push(l.split_whitespace().nth(1).unwrap_or("?").to_string());
            }
        }
    }
    (total, sec, names)
}

fn updates(s: &mut Snapshot) {
    let Some(o) = out(
        "apt-get",
        &["-s", "-o", "Debug::NoLocking=1", "dist-upgrade"],
        60,
    ) else {
        return;
    };
    let (total, sec, names) = parse_apt_sim(&o);
    s.metric("updates_total", total);
    s.metric("updates_security", sec);
    if sec > 0 {
        s.add(Finding::new(
            "updates_security",
            Severity::Warn,
            format!("{sec} security update(s) pending ({total} total)"),
            format!(
                "Including: {}. Run `apt upgrade`, or enable unattended-upgrades.",
                names.join(", ")
            ),
        ));
    }
}

/// Value of `Key "value";` from `apt-config dump`.
pub fn apt_cfg(dump: &str, key: &str) -> Option<String> {
    dump.lines()
        .find_map(|l| l.strip_prefix(key))
        .map(|r| r.trim().trim_end_matches(';').trim_matches('"').to_string())
}

fn unattended(s: &mut Snapshot) {
    let Some(d) = out("apt-config", &["dump"], 10) else {
        return;
    };
    let on = apt_cfg(&d, "APT::Periodic::Unattended-Upgrade ")
        .is_some_and(|v| v != "0" && !v.is_empty());
    let reboot = apt_cfg(&d, "Unattended-Upgrade::Automatic-Reboot ")
        .is_some_and(|v| v == "true" || v == "1");
    s.metric("unattended_upgrades", on);
    s.metric("auto_reboot", reboot);
    if !on {
        s.add(Finding::new(
            "unattended_off",
            Severity::Warn,
            "unattended-upgrades is not enabled",
            "Security patches will not install on their own. Fix: `server-watch harden --apply`.",
        ));
    }
    if !reboot {
        s.add(Finding::new("auto_reboot_off", Severity::Warn, "Automatic reboot is off", "The reboot-required flag will never clear by itself. Fix: `server-watch harden --apply`."));
    }
}

fn needrestart(s: &mut Snapshot) {
    if !which("needrestart") {
        return;
    }
    let Some(o) = out("needrestart", &["-b"], 60) else {
        return;
    };
    let svc: Vec<&str> = o
        .lines()
        .filter_map(|l| l.strip_prefix("NEEDRESTART-SVC:"))
        .map(str::trim)
        .collect();
    s.metric("services_need_restart", svc.len() as u64);
    if !svc.is_empty() {
        s.add(Finding::new(
            "needrestart",
            Severity::Info,
            format!("{} service(s) run old libraries", svc.len()),
            svc.join(", "),
        ));
    }
}

fn failed_units(s: &mut Snapshot) {
    let Some(o) = out(
        "systemctl",
        &["--failed", "--no-legend", "--plain", "--no-pager"],
        10,
    ) else {
        return;
    };
    let names: Vec<&str> = o
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    s.metric("failed_units", names.len() as u64);
    if !names.is_empty() {
        s.add(Finding::new(
            "failed_units",
            Severity::Warn,
            format!("{} failed systemd unit(s)", names.len()),
            names.join(", "),
        ));
    }
}

// ---------- Linux: intrusion signals ----------

/// (failed auth events, accepted logins as "user@ip" -> method)
pub fn parse_ssh_log(s: &str) -> (u64, BTreeMap<String, String>) {
    let mut failed = 0;
    let mut ok = BTreeMap::new();
    for l in s.lines() {
        if l.contains("Failed password")
            || l.contains("Failed publickey")
            || l.contains("Invalid user")
        {
            failed += 1;
        } else if let Some(r) = l.split("Accepted ").nth(1) {
            let w: Vec<&str> = r.split_whitespace().collect();
            let user = w
                .iter()
                .position(|x| *x == "for")
                .and_then(|i| w.get(i + 1));
            let ip = w
                .iter()
                .position(|x| *x == "from")
                .and_then(|i| w.get(i + 1));
            if let (Some(u), Some(ip)) = (user, ip) {
                ok.insert(format!("{u}@{ip}"), w.first().unwrap_or(&"?").to_string());
            }
        }
    }
    (failed, ok)
}

fn ssh_logins(s: &mut Snapshot, ctx: &Ctx) {
    let since = format!("@{}", ctx.since);
    let Some(o) = out(
        "journalctl",
        &[
            "--no-pager",
            "-q",
            "-o",
            "cat",
            "--since",
            &since,
            "-u",
            "ssh.service",
            "-u",
            "sshd.service",
        ],
        20,
    ) else {
        return;
    };
    let (failed, ok) = parse_ssh_log(&o);
    s.metric("ssh_failed_events", failed);
    s.fact_set("ssh_sources");
    for (k, m) in ok {
        s.fact("ssh_sources", k, format!("accepted via {m}"));
    }
    let t = ctx.cfg.thresholds.failed_ssh_warn;
    if failed >= t {
        s.add(Finding::new(
            "ssh_bruteforce",
            Severity::Warn,
            format!("{failed} failed SSH attempts since the last run"),
            "Check that a blocker (CrowdSec or fail2ban) is running and password login is off.",
        ));
    }
}

/// Accounts that can log in: uid 0 or >= 1000 with a real shell.
pub fn parse_passwd(s: &str) -> Vec<(String, String)> {
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            let uid: u32 = f[2].parse().ok()?;
            let shell = f[6];
            let real =
                !(shell.ends_with("nologin") || shell.ends_with("false") || shell.is_empty());
            if real && (uid == 0 || (1000..65534).contains(&uid)) {
                Some((f[0].to_string(), format!("uid {uid}, shell {shell}")))
            } else {
                None
            }
        })
        .collect()
}

fn users(s: &mut Snapshot) {
    if let Some(p) = read("/etc/passwd") {
        s.fact_set("users");
        for (u, d) in parse_passwd(&p) {
            s.fact("users", u, d);
        }
    }
    if let Some(g) = read("/etc/group") {
        s.fact_set("admins");
        for l in g.lines() {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() == 4 && ["sudo", "admin", "wheel"].contains(&f[0]) {
                for m in f[3].split(',').filter(|m| !m.is_empty()) {
                    s.fact(
                        "admins",
                        format!("{}:{m}", f[0]),
                        format!("{m} can sudo via group {}", f[0]),
                    );
                }
            }
        }
    }
}

fn cron(s: &mut Snapshot) {
    let mut files = vec!["/etc/crontab".to_string()];
    for d in [
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
        "/var/spool/cron",
    ] {
        if let Ok(rd) = std::fs::read_dir(d) {
            files.extend(rd.flatten().map(|e| e.path().to_string_lossy().to_string()));
        }
    }
    s.fact_set("cron");
    for f in files {
        if let Some(body) = read(&f) {
            s.fact(
                "cron",
                format!("{f}@{}", sha8(&body)),
                format!("{f} (content hash changed or file is new)"),
            );
        }
    }
}

fn units(s: &mut Snapshot) {
    let Some(o) = out(
        "systemctl",
        &[
            "list-unit-files",
            "--state=enabled",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
        15,
    ) else {
        return;
    };
    s.fact_set("units");
    for l in o.lines() {
        if let Some(u) = l.split_whitespace().next() {
            s.fact("units", u, "enabled systemd unit");
        }
    }
}

fn processes(s: &mut Snapshot) {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return;
    };
    let mut hits: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for e in rd.flatten() {
        let pid = e.file_name().to_string_lossy().to_string();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
            continue;
        };
        let p = exe.to_string_lossy().replace(" (deleted)", "");
        if ["/tmp/", "/dev/shm/", "/var/tmp/"]
            .iter()
            .any(|d| p.starts_with(d))
        {
            hits.entry(p).or_default().push(pid);
        }
    }
    for (p, pids) in hits {
        s.add(Finding::new(
            format!("proc_tmp:{p}"),
            Severity::Critical,
            format!("Process running from a temp directory: {p}"),
            format!(
                "pid(s) {}. Malware often runs from /tmp or /dev/shm.",
                pids.join(", ")
            ),
        ));
    }
}

fn lynis(s: &mut Snapshot) {
    if let Some(r) = read("/var/log/lynis-report.dat") {
        if let Some(i) = r
            .lines()
            .find_map(|l| l.strip_prefix("hardening_index="))
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            s.metric("lynis_hardening_index", i);
        }
    }
}

// ---------- deep checks ----------

fn suid(s: &mut Snapshot) {
    let Some(o) = crate::util::run(
        "nice",
        &[
            "-n", "19", "find", "/", "-xdev", "-type", "f", "-perm", "-4000",
        ],
        std::time::Duration::from_secs(300),
    ) else {
        return;
    };
    s.fact_set("suid");
    for p in o.stdout.lines().filter(|p| !p.is_empty()) {
        s.fact("suid", p, "setuid-root binary");
    }
}

pub fn parse_sshd_t(s: &str, key: &str) -> Option<String> {
    s.lines()
        .find_map(|l| l.strip_prefix(key))
        .map(|v| v.trim().to_string())
}

fn sshd_config(s: &mut Snapshot) {
    let Some(o) = out("sshd", &["-T"], 10) else {
        return;
    };
    if parse_sshd_t(&o, "permitrootlogin ").as_deref() == Some("yes") {
        s.add(Finding::new(
            "sshd_root_login",
            Severity::Warn,
            "SSH allows root login with a password",
            "Set `PermitRootLogin prohibit-password` in sshd_config.",
        ));
    }
    if parse_sshd_t(&o, "passwordauthentication ").as_deref() == Some("yes") {
        s.add(Finding::new(
            "sshd_password_auth",
            Severity::Warn,
            "SSH password login is on",
            "Set `PasswordAuthentication no` once your key works.",
        ));
    }
}

fn firewall(s: &mut Snapshot) {
    let ufw = out("ufw", &["status"], 10).is_some_and(|o| o.contains("Status: active"));
    let nft = out("nft", &["list", "ruleset"], 10).is_some_and(|o| o.lines().count() > 8);
    s.metric("host_firewall", ufw || nft);
    if !(ufw || nft) {
        s.add(Finding::new(
            "no_firewall",
            Severity::Info,
            "No host firewall rules found",
            "If a cloud firewall guards this machine this is fine; otherwise enable ufw.",
        ));
    }
}

fn blocker(s: &mut Snapshot) {
    let active =
        |u: &str| out("systemctl", &["is-active", u], 5).is_some_and(|o| o.trim() == "active");
    let up = active("crowdsec") || active("fail2ban");
    s.metric("blocker_active", up);
    if !up {
        s.add(Finding::new(
            "no_blocker",
            Severity::Info,
            "No brute-force blocker running",
            "Install CrowdSec or fail2ban.",
        ));
    }
}

fn mac_updates(s: &mut Snapshot) {
    let Some(o) = crate::util::run(
        "softwareupdate",
        &["-l"],
        std::time::Duration::from_secs(90),
    ) else {
        return;
    };
    let text = format!("{}{}", o.stdout, o.stderr);
    let labels: Vec<&str> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("* Label:"))
        .map(str::trim)
        .collect();
    s.metric("updates_total", labels.len() as u64);
    if !labels.is_empty() {
        s.add(Finding::new(
            "updates_macos",
            Severity::Warn,
            format!("{} macOS update(s) available", labels.len()),
            labels.join(", "),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn df_skips_virtual_and_loops() {
        let s = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 100 38 62 38% /\ntmpfs 10 1 9 10% /run\n/dev/loop3 10 10 0 100% /snap/x\n/dev/vda15 100 6 94 6% /boot/efi\n";
        assert_eq!(
            parse_df(s),
            vec![("/".to_string(), 38), ("/boot/efi".to_string(), 6)]
        );
    }

    #[test]
    fn meminfo() {
        let m = parse_meminfo(
            "MemTotal: 1000 kB\nMemAvailable: 400 kB\nSwapTotal: 200 kB\nSwapFree: 86 kB\n",
        );
        assert_eq!(
            m,
            Mem {
                total_kb: 1000,
                avail_kb: 400,
                swap_total_kb: 200,
                swap_free_kb: 86
            }
        );
    }

    #[test]
    fn vmstat_counters() {
        assert_eq!(parse_vmstat("pgfault 1\npswpin 7\npswpout 42\n"), (7, 42));
    }

    #[test]
    fn loadavg_linux_and_mac() {
        assert_eq!(
            parse_loadavg("1.83 1.50 1.20 2/300 123\n"),
            Some((1.83, 1.50, 1.20))
        );
        assert_eq!(
            parse_loadavg("{ 2.10 1.90 1.80 }"),
            Some((2.10, 1.90, 1.80))
        );
    }

    #[test]
    fn ss_scopes_and_process() {
        let s = "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\ntcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:*\ntcp LISTEN 0 4096 [::]:22 [::]:*\nudp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n";
        let v = parse_ss(s);
        assert_eq!(v[0], ("tcp/22/public".into(), "sshd on 0.0.0.0:22".into()));
        assert_eq!(v[1].0, "tcp/5432/local");
        assert_eq!(v[2].0, "tcp/22/public");
        assert_eq!(v[3].0, "udp/53/local");
    }

    #[test]
    fn lsof_listen() {
        let s = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nControlCe 1 k 8u IPv4 0x1 0t0 TCP *:7000 (LISTEN)\nnode 2 k 9u IPv4 0x2 0t0 TCP 127.0.0.1:3000 (LISTEN)\n";
        let v = parse_lsof(s);
        assert_eq!(v[0].0, "tcp/7000/public");
        assert_eq!(v[1].0, "tcp/3000/local");
    }

    #[test]
    fn apt_sim_counts_security() {
        let s = "Inst libssl3 [1] (2 Ubuntu:24.04/noble-security [amd64])\nInst vim [1] (2 Ubuntu:24.04/noble-updates [amd64])\nConf vim\n";
        let (t, sec, n) = parse_apt_sim(s);
        assert_eq!((t, sec, n), (2, 1, vec!["libssl3".to_string()]));
    }

    #[test]
    fn apt_config_values() {
        let d = "APT::Periodic::Unattended-Upgrade \"1\";\nUnattended-Upgrade::Automatic-Reboot \"false\";\n";
        assert_eq!(
            apt_cfg(d, "APT::Periodic::Unattended-Upgrade ").as_deref(),
            Some("1")
        );
        assert_eq!(
            apt_cfg(d, "Unattended-Upgrade::Automatic-Reboot ").as_deref(),
            Some("false")
        );
        assert_eq!(apt_cfg(d, "Nope "), None);
    }

    #[test]
    fn ssh_log_parse() {
        let s = "Accepted publickey for root from 100.64.1.2 port 5 ssh2: ED25519 SHA256:x\nFailed password for invalid user admin from 1.2.3.4 port 9 ssh2\nInvalid user admin from 1.2.3.4 port 9\n";
        let (failed, ok) = parse_ssh_log(s);
        assert_eq!(failed, 2);
        assert_eq!(
            ok.get("root@100.64.1.2").map(String::as_str),
            Some("publickey")
        );
    }

    #[test]
    fn passwd_login_users_only() {
        let s = "root:x:0:0:r:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\nkon:x:1000:1000::/home/kon:/bin/zsh\nsvc:x:1001:1001::/:/bin/false\n";
        let u: Vec<String> = parse_passwd(s).into_iter().map(|x| x.0).collect();
        assert_eq!(u, vec!["root", "kon"]);
    }

    #[test]
    fn sshd_t_keys() {
        assert_eq!(
            parse_sshd_t("port 22\npermitrootlogin yes\n", "permitrootlogin ").as_deref(),
            Some("yes")
        );
    }
}
