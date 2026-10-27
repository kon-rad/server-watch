//! Telegram and webhook delivery. Secrets come from the environment only.

use serde_json::json;
use std::time::Duration;

pub const ENV_TOKEN: &str = "SERVER_WATCH_TELEGRAM_TOKEN";
pub const ENV_CHAT: &str = "SERVER_WATCH_TELEGRAM_CHAT_ID";
pub const ENV_WEBHOOK: &str = "SERVER_WATCH_WEBHOOK_URL";

pub fn telegram_configured() -> bool {
    std::env::var(ENV_TOKEN).is_ok() && std::env::var(ENV_CHAT).is_ok()
}

/// Split on line boundaries to stay under Telegram's 4096-char limit.
pub fn chunks(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if !cur.is_empty() && cur.len() + line.len() + 1 > max {
            out.push(std::mem::take(&mut cur));
        }
        let mut line = line;
        while line.len() > max {
            let mut cut = max;
            while !line.is_char_boundary(cut) {
                cut -= 1;
            }
            out.push(line[..cut].to_string());
            line = &line[cut..];
        }
        cur.push_str(line);
        cur.push('\n');
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Errors never contain the bot token: it is part of the request URL.
fn scrub(msg: String, token: &str) -> String {
    msg.replace(token, "***")
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .build()
}

pub fn send_telegram(text: &str) -> Result<(), String> {
    let token = std::env::var(ENV_TOKEN).map_err(|_| format!("{ENV_TOKEN} is not set"))?;
    let chat = std::env::var(ENV_CHAT).map_err(|_| format!("{ENV_CHAT} is not set"))?;
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    for part in chunks(text, 3900) {
        agent()
            .post(&url)
            .send_json(json!({"chat_id": chat, "text": part, "disable_web_page_preview": true}))
            .map_err(|e| scrub(format!("telegram: {e}"), &token))?;
    }
    Ok(())
}

pub fn send_webhook(
    host: &str,
    severity: &str,
    text: &str,
    extra: serde_json::Value,
) -> Result<(), String> {
    let url = std::env::var(ENV_WEBHOOK).map_err(|_| format!("{ENV_WEBHOOK} is not set"))?;
    agent()
        .post(&url)
        .send_json(json!({"host": host, "severity": severity, "text": text, "data": extra}))
        .map(|_| ())
        .map_err(|e| scrub(format!("webhook: {e}"), &url))
}

/// Send to every configured channel. Ok if at least one delivered; Err if none did.
pub fn send_all(
    host: &str,
    severity: &str,
    text: &str,
    extra: serde_json::Value,
) -> Result<Vec<&'static str>, String> {
    let mut sent = Vec::new();
    let mut errs = Vec::new();
    if telegram_configured() {
        match send_telegram(text) {
            Ok(()) => sent.push("telegram"),
            Err(e) => errs.push(e),
        }
    }
    if std::env::var(ENV_WEBHOOK).is_ok() {
        match send_webhook(host, severity, text, extra) {
            Ok(()) => sent.push("webhook"),
            Err(e) => errs.push(e),
        }
    }
    if sent.is_empty() {
        Err(if errs.is_empty() {
            "no notification channel configured (set SERVER_WATCH_TELEGRAM_TOKEN and SERVER_WATCH_TELEGRAM_CHAT_ID)".into()
        } else {
            errs.join("; ")
        })
    } else {
        Ok(sent)
    }
}

pub fn get_me() -> Result<String, String> {
    let token = std::env::var(ENV_TOKEN).map_err(|_| format!("{ENV_TOKEN} is not set"))?;
    let r: serde_json::Value = agent()
        .get(&format!("https://api.telegram.org/bot{token}/getMe"))
        .call()
        .map_err(|e| scrub(format!("telegram: {e}"), &token))?
        .into_json()
        .map_err(|e| e.to_string())?;
    Ok(r["result"]["username"].as_str().unwrap_or("?").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunking_respects_limit_and_keeps_text() {
        let text = (0..50)
            .map(|i| format!("line number {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let parts = chunks(&text, 100);
        assert!(parts.len() > 1);
        assert!(parts.iter().all(|p| p.len() <= 101));
        assert_eq!(parts.concat().lines().count(), 50);
    }

    #[test]
    fn long_line_is_cut() {
        let parts = chunks(&"é".repeat(100), 30);
        assert!(parts.iter().all(|p| p.len() <= 31));
    }

    #[test]
    fn token_is_scrubbed() {
        assert_eq!(
            scrub("GET https://x/bot123:ABC/send failed".into(), "123:ABC"),
            "GET https://x/bot***/send failed"
        );
    }
}
