use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::sign::Verifier;

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
pub fn ecdsa_verify(
    ec_public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    // Load public key
    let ec_key = EcKey::public_key_from_pem(ec_public_key)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    // Create a verifier and verify the signature
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
    verifier.update(message)?;

    Ok(verifier.verify(signature)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_verify_should_ok() {
        let key = hex::decode("2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4\
                                             d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a30444\
                                             15163445167414548614633747158744e4e7137507973456470664b6\
                                             93736336a4767340a6e4f31444d586f706a586378625652426463417\
                                             976466339584f537a7241742f4b35714e534d704c6d517a692b6a7a6\
                                             e584d6e524a7944364e513d3d0a2d2d2d2d2d454e44205055424c494\
                                             3204b45592d2d2d2d2d").unwrap();
        let message = hex::decode(
            "64b793a2c818ebb26f723e260be1fdb8cca07df254e9b48cad50\
                                                3ac9d767e2f2",
        )
        .unwrap();
        let signature = hex::decode("304502200fdd1c1f69789928eb63c1cb54c179611b8893948c2\
                                                   feac69123f1d16548f586022100d05865fb3558a919e69153486\
                                                   92820d6e15229283dc0f2ed2815235d0c7fd91a").unwrap();

        let result = ecdsa_verify(&key, &message, &signature).unwrap();
        assert_eq!(result, true);
    }
}
