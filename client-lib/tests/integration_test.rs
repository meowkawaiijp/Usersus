use client_lib::{get_hardware_id, verify_offline};
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;

fn generate_test_keys() -> (Vec<u8>, Vec<u8>) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    // Get the private key in PKCS8 DER format
    let priv_der = signing_key.to_pkcs8_der().unwrap().to_bytes().to_vec();

    // Get the public key in PEM format
    let pub_pem = signing_key.verifying_key().to_public_key_pem(Default::default()).unwrap().into_bytes();

    (priv_der, pub_pem)
}

#[test]
fn test_hardware_id_generation() {
    let hw_id = get_hardware_id();
    assert!(!hw_id.is_empty());
}

#[test]
fn test_offline_verification() {
    let (priv_der, pub_pem) = generate_test_keys();
    let hw_id = get_hardware_id();

    // from_ed_der expects PKCS8 DER bytes
    let key = EncodingKey::from_ed_der(&priv_der);

    let iat = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let exp = iat + 3600; // 1 hour

    let claims = client_lib::LicenseClaims {
        sub: hw_id,
        exp,
        iat,
        features: vec!["test_feature".to_string()],
    };

    let header = Header::new(Algorithm::EdDSA);
    let token = encode(&header, &claims, &key).unwrap();

    // We bypass HW check since this test can run in different containers
    unsafe {
        std::env::set_var("BYPASS_HW_CHECK", "1");
    }
    let verified_claims = verify_offline(&token, &pub_pem).expect("Should verify successfully");
    assert_eq!(verified_claims.features, vec!["test_feature".to_string()]);
}
