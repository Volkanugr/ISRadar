use crate::config::Config;
use std::time::SystemTime;

pub fn stop_reason(config: &Config) -> Option<&'static str> {
    match std::fs::symlink_metadata(&config.kill_switch) {
        Ok(_) => return Some("kill_switch"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Some("kill_switch_unreadable"),
    }
    if let Some(lease) = &config.controller_lease {
        let age = std::fs::metadata(&lease.heartbeat_file)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| SystemTime::now().duration_since(t).ok());
        if age.is_none_or(|age| age.as_secs() >= lease.max_age_seconds) {
            return Some("controller_disconnected");
        }
    }
    None
}
