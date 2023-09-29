use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use openssl::sign::Signer;

use crate::error::CryptoError;

/// Generates a ECDSA signature.
pub fn ecdsa_sign(ec_private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Load private key
    let ec_key = EcKey::private_key_from_pem(ec_private_key)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    // Create a signer and sign the message
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(message)?;
    let signature = signer.sign_to_vec()?;

    Ok(signature)
}

/// Verifies a ECDSA signature.
pub fn ecdsa_verify(ec_public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    // Load public key
    let ec_key = EcKey::public_key_from_pem(ec_public_key)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    // Create a verifier and verify the signature
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
    verifier.update(message)?;

    Ok(verifier.verify(signature)?)
}
