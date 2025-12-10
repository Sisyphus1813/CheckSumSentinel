// Copyright (C) 2025  Sisyphus1813
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::checks::ScanResult;
use log::{error, info, warn};
use notify_rust::{Notification, Urgency};
use std::path::Path;

pub fn notify_user(path: &Path, result: &ScanResult, console: bool) {
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string_lossy().to_string());
    let mut body = format!("File: {}\nPath: {}\n\n", file_name, path.display());
    body.push_str(&format!(
        "MD5: {}\nSHA1: {}\nSHA256: {}\n\n",
        result.md5, result.sha1, result.sha256
    ));
    if result.hash_match {
        body.push_str("****Matching malicious hash found!!****\n\n");
    } else {
        body.push_str("No matching malicious hash found.\n\n");
    }
    if result.yara_match {
        body.push_str("****Matching YARA rule(s) found!!****\n");
        for id in &result.yara_rules {
            body.push_str(&format!("- {}\n", id));
        }
        body.push('\n');
    } else {
        body.push_str("No matching YARA rule found.\n\n");
    }
    let (summary, verdict) = if result.hash_match || result.yara_match {
        (
            "Suspicious file detected",
            "VERDICT: Indicators suggest the possible presence of malware.",
        )
    } else {
        (
            "Scan completed",
            "VERDICT: No known malicious indicators detected.",
        )
    };
    body.push_str(verdict);
    body.push_str("\n\nNote: Detections or the absence thereof do not guarantee compromise nor safety. Results reflect current rule and hash databases.");
    if console {
        println!("{}\n{}", summary, body);
    } else {
        let urgency = if result.hash_match || result.yara_match {
            Urgency::Critical
        } else {
            Urgency::Normal
        };
        if let Err(e) = Notification::new()
            .summary(summary)
            .body(&body)
            .icon("dialog-warning")
            .urgency(urgency)
            .timeout(0)
            .show()
        {
            error!("Failed to send desktop notification: {e}");
            match urgency {
                Urgency::Critical => warn!("{}: {}", summary, body),
                _ => info!("{}: {}", summary, body),
            }
        }
    }
}
