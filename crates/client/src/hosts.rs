//! Hosts management (BEGIN/END AGILE-NET marker block in the system hosts file).

use anyhow::Result;
use std::path::PathBuf;

/// System hosts file management (BEGIN/END AGILE-NET marker block).
pub struct HostsManager {
    path: PathBuf,
}

impl HostsManager {
    pub fn new() -> Self {
        let path = if cfg!(windows) {
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
            PathBuf::from(root)
                .join("System32")
                .join("drivers")
                .join("etc")
                .join("hosts")
        } else {
            PathBuf::from("/etc/hosts")
        };
        Self { path }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// Write managed hosts (127.0.0.1 pointing; traffic forwarded via the local proxy).
    pub fn apply(&self, hosts: &[String]) -> Result<()> {
        let content = std::fs::read_to_string(&self.path).unwrap_or_default();
        let cleaned = strip_managed_block(&content);

        if hosts.is_empty() {
            if cleaned != content {
                std::fs::write(&self.path, cleaned)?;
            }
            return Ok(());
        }

        let mut block = String::from("# BEGIN AGILE-NET\n");
        for h in hosts {
            block.push_str(&format!("127.0.0.1 {h}\n"));
        }
        block.push_str("# END AGILE-NET\n");

        let mut new_content = cleaned;
        if !new_content.ends_with('\n') && !new_content.is_empty() {
            new_content.push('\n');
        }
        new_content.push_str(&block);
        std::fs::write(&self.path, new_content)?;
        Ok(())
    }

    /// Remove all managed entries.
    pub fn cleanup(&self) {
        if let Ok(content) = std::fs::read_to_string(&self.path) {
            let cleaned = strip_managed_block(&content);
            if cleaned != content {
                let _ = std::fs::write(&self.path, cleaned);
            }
        }
    }
}

impl Default for HostsManager {
    fn default() -> Self {
        Self::new()
    }
}

fn strip_managed_block(content: &str) -> String {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "# BEGIN AGILE-NET" {
            in_block = true;
            continue;
        }
        if trimmed == "# END AGILE-NET" {
            in_block = false;
            continue;
        }
        if !in_block {
            out.push(line);
        }
    }
    let mut s = out.join("\n");
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s
}
