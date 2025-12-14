use crate::types::ScanStore;
use sha2::{Digest, Sha256};
use tiny_http::{Header, Response};

pub fn add_cors_headers<R: std::io::Read>(response: Response<R>) -> Response<R> {
    response
        .with_header(Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap())
        .with_header(
            Header::from_bytes(
                &b"Access-Control-Allow-Methods"[..],
                &b"GET, POST, OPTIONS"[..],
            )
            .unwrap(),
        )
        .with_header(
            Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type"[..]).unwrap(),
        )
}

pub fn parse_multipart(body: &[u8], boundary: &str) -> Result<(String, Vec<u8>), String> {
    let body_str = String::from_utf8_lossy(body);

    let parts: Vec<&str> = body_str.split(&format!("--{}", boundary)).collect();

    for part in parts {
        if part.contains("Content-Disposition") && part.contains("filename=") {
            let filename = part
                .lines()
                .find(|line| line.contains("filename="))
                .and_then(|line| {
                    line.split("filename=\"")
                        .nth(1)
                        .and_then(|s| s.split('"').next())
                })
                .unwrap_or("uploaded_file")
                .to_string();

            if let Some(data_start) = part.find("\r\n\r\n") {
                let data_section = &part[data_start + 4..];
                let data_end = data_section.find("\r\n--").unwrap_or(data_section.len());
                let file_data = data_section.as_bytes()[..data_end].to_vec();

                return Ok((filename, file_data));
            }
        }
    }

    Err("No file found in multipart data".to_string())
}

pub fn send_progress(scan_id: &str, progress: u32, message: &str, scan_store: &ScanStore) {
    let mut store = scan_store.lock().unwrap();
    if let Some(result) = store.get_mut(scan_id) {
        result.logs.push(format!("[{}%] {}", progress, message));
    }
}

pub fn calculate_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}
