use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::pkey::PKey;
use crate::error::CryptoError;
use crate::hash;

pub enum KDFType {
    MD5,
    SHA1,
    SHA256,
}


pub fn gen_ecdh_key_pair(nid: Nid) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Create an EC_GROUP object.
    let group = EcGroup::from_curve_name(nid)?;

    // Create an EC_KEY from the EC_GROUP.
    let ec_key = EcKey::generate(&group)?;

    // Extract the public key from the EC_KEY.
    let mut ctx = BigNumContext::new()?;
    let pub_key = ec_key.public_key().to_bytes(&group, openssl::ec::PointConversionForm::COMPRESSED, &mut ctx)?;

    //  Extract the private key from the EC_KEY.
    let pri_key = ec_key.private_key_to_der()?;

    Ok((pub_key, pri_key))
}

/// Computes the ECDH secret.
pub fn compute_ecdh_secret(nid: Nid, pub_key: &[u8], pri_key: &[u8], kdf_type: KDFType) -> Result<Vec<u8>, CryptoError> {
   // Create an EC_GROUP object.
   let group = EcGroup::from_curve_name(nid)?;

   // Load the private key.
   let ec_pri_key: PKey<_> = EcKey::private_key_from_der(pri_key)?.try_into()?;

    let mut ctx = openssl::bn::BigNumContext::new()?;
    let public_key = EcPoint::from_bytes(&group, &pub_key, &mut ctx)?;
    let ec_pub_key: PKey<_> = EcKey::from_public_key(&group, &public_key)?.try_into()?;

    let mut deriver: Deriver<'_> = Deriver::new(&ec_pri_key)?;
    deriver.set_peer(&ec_pub_key)?;
    let secret = deriver.derive_to_vec()?;

    let result = match kdf_type {
        KDFType::MD5 => hash::md5(&secret)?,
        KDFType::SHA1 => hash::sha1(&secret)?,
        KDFType::SHA256 => hash::sha256(&secret)?,
    };
   
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_gen_ecdh_key_pair() {
        let (pub_key, pri_key) = gen_ecdh_key_pair(Nid::X9_62_PRIME256V1).unwrap();
        assert_eq!(pub_key.len(), 65);
        assert_eq!(pri_key.len(), 121);
    }

    #[test]
    fn test_compute_key_should_ok() {
        let private_key = hex::decode("307702010104202a166bdf53fc14814dd19d5ed7cf56ccce503098d7\
                                                     1f2389c733206d88301d62a00a06082a8648ce3d030107a1440342000\
                                                     44571c5937c6a7701fe2fd10909798a5838b2b83bcca825e852ae0341\
                                                     b467321b2bd36c8c631a0b2e4b438e60687360bb4c5c44d075da6773d\
                                                     c8c42ee880fa454").unwrap();
        let pub_key = hex::decode("04a9b854ed27a0572c79b1ba931b43f568322c266585636444bb5d1cba5284\
        0fe43bd2d1d7f73e9beaf2f7dc9697ae9cc439025fb635d735ba78c007a29e0d9618").unwrap();
        let secret = compute_ecdh_secret(
                Nid::X9_62_PRIME256V1, 
                &pub_key, 
                &private_key, 
                KDFType::SHA256).unwrap();
        
        assert_eq!(secret, hex::decode("3e2f31f9ddcf8bf6bcc7b97b8b22671932397fc9f71bf2003ebdbb05b41e4a64").unwrap());
    }
}