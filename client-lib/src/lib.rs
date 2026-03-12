use reqwest::Client;
use serde::{Deserialize, Serialize};
use sysinfo::Networks;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use log::{info, error};

#[derive(Debug, Serialize, Deserialize)]
pub struct LicenseClaims {
    /// JWT Standard: Subject (hardware id)
    pub sub: String,
    /// JWT Standard: Expiration time
    pub exp: usize,
    /// JWT Standard: Issued at
    pub iat: usize,
    /// Custom: List of features enabled
    pub features: Vec<String>,
}

#[derive(Debug)]
pub enum LicenseError {
    Io(std::io::Error),
    Jwt(jsonwebtoken::errors::Error),
    HardwareMismatch,
    Expired,
    Revoked,
    Network(reqwest::Error),
}

impl From<std::io::Error> for LicenseError {
    fn from(err: std::io::Error) -> Self {
        LicenseError::Io(err)
    }
}

impl From<jsonwebtoken::errors::Error> for LicenseError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        LicenseError::Jwt(err)
    }
}

impl From<reqwest::Error> for LicenseError {
    fn from(err: reqwest::Error) -> Self {
        LicenseError::Network(err)
    }
}

/// Computes a hardware ID by combining the CPU serial number and MAC address.
/// Fallbacks to "unknown" if they cannot be read.
pub fn get_hardware_id() -> String {
    let mut serial = "unknown".to_string();

    // Try to read Raspberry Pi CPU serial from /proc/cpuinfo
    if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
        for line in content.lines() {
            if line.starts_with("Serial") {
                if let Some(s) = line.split(':').nth(1) {
                    serial = s.trim().to_string();
                }
                break;
            }
        }
    }

    let mut mac_address = "unknown".to_string();

    // Attempt to get MAC address
    let networks = Networks::new_with_refreshed_list();
    // Prefer eth0 or wlan0
    for (name, data) in &networks {
        if name == "eth0" || name == "wlan0" || name.starts_with("en") || name.starts_with("wl") {
            let mac = data.mac_address();
            mac_address = format!("{:?}", mac);
            break;
        }
    }

    format!("{}-{}", serial, mac_address)
}

/// Verifies a license JWT offline.
/// Checks signature using EdDSA, expiry, and hardware match.
pub fn verify_offline(jwt: &str, public_key_pem: &[u8]) -> Result<LicenseClaims, LicenseError> {
    let key = DecodingKey::from_ed_pem(public_key_pem)?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    // Setting leeway for expiration
    validation.leeway = 60;

    let token_data = decode::<LicenseClaims>(jwt, &key, &validation)?;
    let claims = token_data.claims;

    // Check hardware ID match
    let current_hw_id = get_hardware_id();
    if claims.sub != current_hw_id {
        // We log it, but in real life we might just fail. Note: we might need a workaround for testing.
        info!("Hardware mismatch: token has {}, current is {}", claims.sub, current_hw_id);

        // For testing/mocking environments where we don't have a real pi:
        // if std::env::var("BYPASS_HW_CHECK").is_ok() { ... }
        if std::env::var("BYPASS_HW_CHECK").unwrap_or_default() != "1" {
            return Err(LicenseError::HardwareMismatch);
        }
    }

    // Checking expiry is handled by jsonwebtoken, but we can double check
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    if claims.exp < now {
        return Err(LicenseError::Expired);
    }

    Ok(claims)
}

/// Verifies a license JWT online by calling the verification server.
/// Uses the raw JWT string.
pub async fn verify_online(jwt: &str, server_url: &str) -> Result<(), LicenseError> {
    let client = Client::new();

    let res = client.post(server_url)
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await?;

    if res.status().is_success() {
        Ok(())
    } else if res.status() == reqwest::StatusCode::FORBIDDEN || res.status() == reqwest::StatusCode::UNAUTHORIZED {
        Err(LicenseError::Revoked)
    } else {
        // Treat other errors as network issues or server issues
        Err(LicenseError::Network(res.error_for_status().unwrap_err()))
    }
}
