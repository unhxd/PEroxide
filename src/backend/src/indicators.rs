use crate::types::Threat;

pub fn check_indicators(content: &str) -> Vec<Threat> {
    let mut threats = Vec::new();

    if content.contains("malware") || content.contains("virus") {
        threats.push(Threat {
            threat_type: "Suspicious String".to_string(),
            details: "File contains suspicious keywords".to_string(),
            severity: "suspicious".to_string(),
            threat_id: "S001".to_string(),
        });
    }

    if content.contains("CreateRemoteThread") && content.contains("VirtualAllocEx") {
        threats.push(Threat {
            threat_type: "Process Injection API".to_string(),
            details: "Contains process injection function calls".to_string(),
            severity: "malicious".to_string(),
            threat_id: "S002".to_string(),
        });
    }

    if content.contains("RegSetValue") && content.contains("RegCreateKey") {
        threats.push(Threat {
            threat_type: "Registry Modification".to_string(),
            details: "Contains registry manipulation functions".to_string(),
            severity: "suspicious".to_string(),
            threat_id: "S003".to_string(),
        });
    }

    threats
}
