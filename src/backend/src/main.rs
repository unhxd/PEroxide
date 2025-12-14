mod config;
use config::*;
mod types;
use types::*;
mod utils;
use utils::*;
mod scanner;
use scanner::*;
mod indicators;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Method, Response, Server};
use uuid::Uuid;

fn handle_options(request: tiny_http::Request) {
    let response = Response::from_string("");
    let response = add_cors_headers(response);
    let _ = request.respond(response);
}

fn handle_upload(mut request: tiny_http::Request, scan_store: ScanStore) {
    let content_type = request
        .headers()
        .iter()
        .find(|h| h.field.as_str().to_ascii_lowercase() == "content-type")
        .map(|h| h.value.as_str())
        .unwrap_or("");

    if !content_type.starts_with("multipart/form-data") {
        let error_response = serde_json::json!({"error": "Expected multipart/form-data"});
        let response = Response::from_string(error_response.to_string())
            .with_status_code(400)
            .with_header(
                Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
            );
        let response = add_cors_headers(response);
        let _ = request.respond(response);
        return;
    }

    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .unwrap_or("")
        .to_string();

    let mut body = Vec::new();
    if request.as_reader().read_to_end(&mut body).is_err() {
        let error_response = serde_json::json!({"error": "Failed to read request body"});
        let response = Response::from_string(error_response.to_string()).with_status_code(400);
        let response = add_cors_headers(response);
        let _ = request.respond(response);
        return;
    }

    let (filename, file_data) = match parse_multipart(&body, &boundary) {
        Ok(result) => result,
        Err(e) => {
            let error_response = serde_json::json!({"error": e});
            let response = Response::from_string(error_response.to_string())
                .with_status_code(400)
                .with_header(
                    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                );
            let response = add_cors_headers(response);
            let _ = request.respond(response);
            return;
        }
    };

    let file_size = file_data.len() as u64;
    println!(
        "Upload request received: {} ({} bytes)",
        filename, file_size
    );

    if file_size > MAX_FILE_SIZE {
        println!(
            "File size {} exceeds limit of {} bytes",
            file_size, MAX_FILE_SIZE
        );
        let error_response = serde_json::json!({
            "error": format!("File size exceeds maximum limit of {}MB", MAX_FILE_SIZE / 1024 / 1024)
        });
        let response = Response::from_string(error_response.to_string())
            .with_status_code(400)
            .with_header(
                Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
            );
        let response = add_cors_headers(response);
        let _ = request.respond(response);
        return;
    }

    let sha256 = calculate_sha256(&file_data);
    let scan_id = format!("scan-{}", Uuid::new_v4());
    println!("Generated scan ID: {}", scan_id);

    let file_path = PathBuf::from(UPLOAD_DIR).join(format!("{}_{}", scan_id, filename));
    if let Err(e) = fs::write(&file_path, &file_data) {
        println!("Failed to save file: {}", e);
        let error_response = serde_json::json!({"error": "Failed to save file"});
        let response = Response::from_string(error_response.to_string())
            .with_status_code(500)
            .with_header(
                Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
            );
        let response = add_cors_headers(response);
        let _ = request.respond(response);
        return;
    }

    println!("File saved: {:?}", file_path);
    println!("SHA256: {}", sha256);

    let file_info = FileInfo {
        filename: filename.clone(),
        size: file_size,
        sha256: sha256.clone(),
    };

    let result = ScanResult {
        status: "scanning".to_string(),
        threats: vec![],
        stats: ScanStats {
            threats_found: 0,
            malicious: 0,
            suspicious: 0,
            neutral: 0,
        },
        logs: vec!["[0%] Initializing scan...".to_string()],
        file_info: Some(file_info.clone()),
    };

    {
        let mut store = scan_store.lock().unwrap();
        store.insert(scan_id.clone(), result);
    }

    scan_file(file_path, file_info, scan_id.clone(), scan_store.clone());

    let response_data = UploadResponse { scan_id };
    let response = Response::from_string(serde_json::to_string(&response_data).unwrap())
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
    let response = add_cors_headers(response);
    let _ = request.respond(response);
}

fn handle_scan_status(request: tiny_http::Request, scan_store: ScanStore, scan_id: String) {
    println!("SSE connection established for scan: {}", scan_id);

    {
        let store = scan_store.lock().unwrap();
        if !store.contains_key(&scan_id) {
            let error_response = serde_json::json!({"error": "Scan not found"});
            let response = Response::from_string(error_response.to_string()).with_status_code(404);
            let response = add_cors_headers(response);
            let _ = request.respond(response);
            return;
        }
    }

    let mut sse_data = String::new();
    let mut last_progress = 0;
    let mut scan_complete = false;

    // poll for updates until scan is complete
    while !scan_complete {
        thread::sleep(Duration::from_millis(100));

        let store = scan_store.lock().unwrap();
        if let Some(result) = store.get(&scan_id) {
            for (i, log) in result.logs.iter().enumerate() {
                if i >= last_progress {
                    // extract progress from log message
                    let progress = if let Some(start) = log.find('[') {
                        if let Some(end) = log.find('%') {
                            log[start + 1..end].parse::<u32>().unwrap_or(0)
                        } else {
                            0
                        }
                    } else {
                        0
                    };

                    let message = if let Some(bracket_end) = log.find(']') {
                        &log[bracket_end + 2..]
                    } else {
                        log.as_str()
                    };

                    let update = ProgressUpdate {
                        progress,
                        message: message.to_string(),
                    };
                    sse_data.push_str(&format!(
                        "data: {}\n\n",
                        serde_json::to_string(&update).unwrap()
                    ));
                    last_progress = i + 1;
                }
            }

            if result.status != "scanning" {
                scan_complete = true;
            }
        }
    }

    let response = Response::from_string(sse_data)
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap())
        .with_header(Header::from_bytes(&b"Cache-Control"[..], &b"no-cache"[..]).unwrap())
        .with_header(Header::from_bytes(&b"Connection"[..], &b"keep-alive"[..]).unwrap());
    let response = add_cors_headers(response);
    let _ = request.respond(response);
}

fn handle_scan_result(request: tiny_http::Request, scan_store: ScanStore, scan_id: String) {
    println!("Fetching result for scan: {}", scan_id);

    let store = scan_store.lock().unwrap();
    match store.get(&scan_id) {
        Some(result) => {
            let response = Response::from_string(serde_json::to_string(result).unwrap())
                .with_header(
                    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                );
            let response = add_cors_headers(response);
            let _ = request.respond(response);
        }
        None => {
            let error_response = serde_json::json!({"error": "Scan not found"});
            let response = Response::from_string(error_response.to_string()).with_status_code(404);
            let response = add_cors_headers(response);
            let _ = request.respond(response);
        }
    }
}

fn main() {
    println!("Starting PEroxide backend server...");

    fs::create_dir_all(UPLOAD_DIR).expect("Failed to create upload directory");

    let server = Server::http("0.0.0.0:3001").unwrap();
    let scan_store: ScanStore = Arc::new(Mutex::new(HashMap::new()));

    println!("🚀 Server starting on http://0.0.0.0:3001");
    println!("📡 Ready to receive file scan requests");
    println!("📁 Upload directory: {}", UPLOAD_DIR);

    for request in server.incoming_requests() {
        let scan_store = scan_store.clone();

        if request.method() == &Method::Options {
            handle_options(request);
            continue;
        }

        let url = request.url().to_string();
        let parts: Vec<&str> = url.split('/').collect();

        // POST /api/upload
        if request.method() == &Method::Post && url == "/api/upload" {
            handle_upload(request, scan_store.clone());
            continue;
        }
        // GET /api/scan-status/{scanId}
        else if request.method() == &Method::Get
            && parts.len() >= 4
            && parts[1] == "api"
            && parts[2] == "scan-status"
        {
            let scan_id = parts[3].to_string();
            handle_scan_status(request, scan_store.clone(), scan_id);
            continue;
        }
        // GET /api/scan-result/{scanId}
        else if request.method() == &Method::Get
            && parts.len() >= 4
            && parts[1] == "api"
            && parts[2] == "scan-result"
        {
            let scan_id = parts[3].to_string();
            handle_scan_result(request, scan_store.clone(), scan_id);
            continue;
        } else {
            let error_response = serde_json::json!({"error": "Not found"});
            let response = Response::from_string(error_response.to_string()).with_status_code(404);
            let response = add_cors_headers(response);
            let _ = request.respond(response);
        }
    }
}
