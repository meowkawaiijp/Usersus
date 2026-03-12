use clap::{Parser, Subcommand};
use client_lib::LicenseClaims;
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::rand::SystemRandom;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates a new Ed25519 key pair
    GenerateKeys {
        /// File to save the private key (PKCS8)
        #[arg(short, long, default_value = "private_key.pem")]
        private_key: String,

        /// File to save the public key (PEM)
        #[arg(short = 'u', long, default_value = "public_key.pem")]
        public_key: String,
    },
    /// Issues a new license
    Issue {
        /// The hardware ID (e.g., serial-mac)
        #[arg(short = 'w', long)]
        hardware_id: String,

        /// Valid duration in days
        #[arg(short, long, default_value_t = 365)]
        days: u64,

        /// Features enabled (comma separated)
        #[arg(short, long, default_value = "")]
        features: String,

        /// Path to the private key (PEM format)
        #[arg(short, long, default_value = "private_key.pem")]
        private_key: String,

        /// Output file for the JWT
        #[arg(short, long, default_value = "license.jwt")]
        output: String,
    },
}

fn generate_keys(priv_path: &str, pub_path: &str) -> std::io::Result<()> {
    // Generate an Ed25519 key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Key generation failed"))?;

    // The key pair includes the public key
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Failed to load key pair"))?;

    // Format to PEM
    let priv_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8_bytes.as_ref()));
    let pub_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", key_pair.public_key().as_ref()));

    fs::write(priv_path, priv_pem)?;
    fs::write(pub_path, pub_pem)?;

    println!("Keys generated successfully.");
    println!("Private key: {}", priv_path);
    println!("Public key: {}", pub_path);

    Ok(())
}

fn issue_license(
    hw_id: &str,
    days: u64,
    features_str: &str,
    priv_path: &str,
    out_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let priv_pem = fs::read(priv_path)?;

    // Parse the PEM format, we just need the raw PKCS8 bytes for jsonwebtoken
    let key = EncodingKey::from_ed_pem(&priv_pem)?;

    let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as usize;
    let exp = iat + (days * 24 * 3600) as usize;

    let features = if features_str.is_empty() {
        vec![]
    } else {
        features_str.split(',').map(|s| s.trim().to_string()).collect()
    };

    let claims = LicenseClaims {
        sub: hw_id.to_string(),
        exp,
        iat,
        features,
    };

    let header = Header::new(Algorithm::EdDSA);
    let token = encode(&header, &claims, &key)?;

    fs::write(out_path, token)?;

    println!("License issued successfully.");
    println!("Hardware ID: {}", hw_id);
    println!("Expires at (UNIX timestamp): {}", exp);
    println!("Output: {}", out_path);

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateKeys { private_key, public_key } => {
            generate_keys(private_key, public_key)?;
        }
        Commands::Issue {
            hardware_id,
            days,
            features,
            private_key,
            output,
        } => {
            issue_license(hardware_id, *days, features, private_key, output)?;
        }
    }

    Ok(())
}
