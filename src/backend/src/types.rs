use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// shared state for storing scan results
pub type ScanStore = Arc<Mutex<HashMap<String, ScanResult>>>;

#[derive(Clone, Serialize, Deserialize)]
pub struct UploadResponse {
    #[serde(rename = "scanId")]
    pub scan_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub status: String,
    pub threats: Vec<Threat>,
    pub stats: ScanStats,
    pub logs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_info: Option<FileInfo>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub filename: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Threat {
    #[serde(rename = "type")]
    pub threat_type: String,
    pub details: String,
    pub severity: String, // "malicious", "suspicious", or "neutral"
    #[serde(rename = "threatId")]
    pub threat_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ScanStats {
    #[serde(rename = "threatsFound")]
    pub threats_found: usize,
    pub malicious: usize,
    pub suspicious: usize,
    pub neutral: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProgressUpdate {
    pub progress: u32,
    pub message: String,
}
