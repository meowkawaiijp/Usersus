# Usersus - License Management System for Raspberry Pi 4

This is a Rust-based license management system, built specifically for Raspberry Pi 4. It uses Ed25519-signed JSON Web Tokens (JWT) to securely manage and verify licenses linked to the hardware ID (CPU serial number and MAC address).

## Components

The workspace contains three main components:

1. **`client-lib`**: The client library to be integrated into your Raspberry Pi application. It handles hardware ID generation, offline license verification (using a public key), and online verification (falling back to a server check).
2. **`license-issuer`**: A command-line tool for administrators to generate key pairs and issue signed licenses to specific hardware IDs with configured expiration times and features.
3. **`license-server`**: An HTTP server that acts as the online verification backend. It checks the signature and expiration of tokens, and allows for licenses to be revoked.

## Getting Started

### 1. Build the project

```bash
cargo build --release
```

### 2. Generate Keys

Use the `license-issuer` CLI to generate a new Ed25519 key pair:

```bash
cargo run --bin license-issuer -- generate-keys --private-key private_key.pem --public-key public_key.pem
```

### 3. Issue a License

Find the Hardware ID of the target Raspberry Pi 4. You can write a tiny script using `client-lib::get_hardware_id()`.
Assume the hardware ID is `10000000abcde123-aa:bb:cc:dd:ee:ff`.

```bash
cargo run --bin license-issuer -- issue \
    --hardware-id "10000000abcde123-aa:bb:cc:dd:ee:ff" \
    --days 365 \
    --features "pro,ai_vision" \
    --private-key private_key.pem \
    --output my_license.jwt
```

### 4. Run the License Server

The server needs the `public_key.pem` to verify licenses.

```bash
PUBLIC_KEY_PATH=public_key.pem cargo run --bin license-server
```

The server will start listening on `0.0.0.0:3000`.

### 5. Verify the License on the Client

In your Raspberry Pi 4 application, depend on `client-lib` and use it to verify the JWT token offline and online.

```rust
use client_lib::{verify_offline, verify_online, get_hardware_id};

#[tokio::main]
async fn main() {
    let hw_id = get_hardware_id();
    println!("Current Hardware ID: {}", hw_id);

    // Read public key and JWT
    let public_key_pem = std::fs::read("public_key.pem").unwrap();
    let jwt = std::fs::read_to_string("my_license.jwt").unwrap();

    // 1. Offline Verification
    match verify_offline(&jwt, &public_key_pem) {
        Ok(claims) => {
            println!("Offline Verification Successful!");
            println!("Enabled Features: {:?}", claims.features);
        }
        Err(e) => {
            println!("Offline Verification Failed: {:?}", e);
            return;
        }
    }

    // 2. Online Verification (Optional but recommended)
    match verify_online(&jwt, "http://127.0.0.1:3000/api/v1/verify").await {
        Ok(_) => println!("Online Verification Successful! License is active."),
        Err(e) => println!("Online Verification Failed (or revoked): {:?}", e),
    }
}
```

### Revoking a License

You can revoke a hardware ID by calling the server's revoke endpoint (for testing):

```bash
curl -X POST http://localhost:3000/api/v1/revoke \
     -H "Content-Type: application/json" \
     -d '"10000000abcde123-aa:bb:cc:dd:ee:ff"'
```
