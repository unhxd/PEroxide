use crate::indicators::*;
use crate::types::*;
use crate::utils::*;

use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

pub fn scan_file(file_path: PathBuf, file_info: FileInfo, scan_id: String, scan_store: ScanStore) {
    thread::spawn(move || {
        send_progress(&scan_id, 10, "Reading file content...", &scan_store);

        let content = match fs::read(&file_path) {
            Ok(c) => c,
            Err(e) => {
                let mut store = scan_store.lock().unwrap();
                if let Some(result) = store.get_mut(&scan_id) {
                    result.status = "error".to_string();
                    result.logs.push(format!("Error reading file: {}", e));
                }
                let _ = fs::remove_file(&file_path);
                return;
            }
        };

        send_progress(&scan_id, 30, "Scanning file headers...", &scan_store);

        let mut threats = Vec::new();

        if content.len() >= 2 {
            let signature = &content[0..2];
            if signature == b"MZ" {
                send_progress(
                    &scan_id,
                    50,
                    "PE executable detected, analyzing...",
                    &scan_store,
                );
            }
        }

        send_progress(
            &scan_id,
            60,
            "Performing signature analysis...",
            &scan_store,
        );

        let content_str = String::from_utf8_lossy(&content);

        let detected_threats = check_indicators(&content_str);
        threats.extend(detected_threats);

        send_progress(&scan_id, 90, "Finalizing results...", &scan_store);

        thread::sleep(Duration::from_secs(1));

        send_progress(&scan_id, 100, "Scan complete!", &scan_store);

        let malicious_count = threats.iter().filter(|t| t.severity == "malicious").count();
        let suspicious_count = threats
            .iter()
            .filter(|t| t.severity == "suspicious")
            .count();
        let neutral_count = threats.iter().filter(|t| t.severity == "neutral").count();

        // Only mark as "unsafe" if there are malicious indicators
        let status = if malicious_count > 0 {
            "unsafe"
        } else if suspicious_count > 0 || neutral_count > 0 {
            "suspicious"
        } else {
            "safe"
        };

        let result = ScanResult {
            status: status.to_string(),
            threats: threats.clone(),
            stats: ScanStats {
                threats_found: threats.len(),
                malicious: malicious_count,
                suspicious: suspicious_count,
                neutral: neutral_count,
            },
            logs: {
                let store = scan_store.lock().unwrap();
                store
                    .get(&scan_id)
                    .map(|r| r.logs.clone())
                    .unwrap_or_default()
            },
            file_info: Some(file_info),
        };

        let mut store = scan_store.lock().unwrap();
        store.insert(scan_id.clone(), result);

        let _ = fs::remove_file(&file_path);
        println!("Scan complete for {}, file cleaned up", scan_id);
    });
}
