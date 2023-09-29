use crate::error::CryptoError;
use crate::hash;
use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::PKey;

pub enum KDFType {
    None,
    MD5,
    SHA1,
    SHA256,
}

/// Generates an ECDH key pair.
pub fn gen_ecdh_key_pair(nid: Nid, use_compress: bool) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Create an EC_GROUP object.
    let group = EcGroup::from_curve_name(nid)?;

    // Create an EC_KEY from the EC_GROUP.
    let ec_key = EcKey::generate(&group)?;

    // Extract the public key from the EC_KEY.
    let mut ctx = BigNumContext::new()?;
    let conversion_from = if use_compress {
        openssl::ec::PointConversionForm::COMPRESSED
    } else {
        openssl::ec::PointConversionForm::UNCOMPRESSED
    };
    let pub_key = ec_key
        .public_key()
        .to_bytes(&group, conversion_from, &mut ctx)?;

    //  Extract the private key from the EC_KEY.
    let mut pri_key = ec_key.private_key_to_der()?;
    if use_compress {
        pri_key.truncate(((ec_key.private_key().num_bits() + 7) / 8) as _);
    }

    Ok((pub_key, pri_key))
}

/// Computes the ECDH secret.
pub fn compute_ecdh_secret(
    nid: Nid,
    pub_key: &[u8],
    pri_key: &[u8],
    pri_key_is_der: bool,
    kdf_type: KDFType,
) -> Result<Vec<u8>, CryptoError> {
    // Create an EC_GROUP object.
    let group = EcGroup::from_curve_name(nid)?;

    // Create an EC_KEY from the EC_GROUP.
    let mut ctx = openssl::bn::BigNumContext::new()?;
    let public_key = EcPoint::from_bytes(&group, &pub_key, &mut ctx)?;
    let ec_pub_key: PKey<_> = EcKey::from_public_key(&group, &public_key)?.try_into()?;

    // Load the private key.
    let ec_pri_key: PKey<_>;
    if pri_key_is_der {
        ec_pri_key = EcKey::private_key_from_der(&pri_key)?.try_into()?;
    } else {
        let pri_big_num = BigNum::from_slice(pri_key)?;
        ec_pri_key =
            EcKey::from_private_components(&group, &pri_big_num, &public_key)?.try_into()?;
    }

    let mut deriver: Deriver<'_> = Deriver::new(&ec_pri_key)?;
    deriver.set_peer(&ec_pub_key)?;
    let secret = deriver.derive_to_vec()?;

    Ok(match kdf_type {
        KDFType::None => secret,
        KDFType::MD5 => hash::md5(&secret)?,
        KDFType::SHA1 => hash::sha1(&secret)?,
        KDFType::SHA256 => hash::sha256(&secret)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_gen_ecdh_key_pair() {
        let (pub_key, pri_key) = gen_ecdh_key_pair(Nid::X9_62_PRIME256V1, false).unwrap();
        assert_eq!(pub_key.len(), 65);
        assert_eq!(pri_key.len(), 121);

        let (pub_key, pri_key) = gen_ecdh_key_pair(Nid::X9_62_PRIME256V1, true).unwrap();
        assert_eq!(pub_key.len(), 33);
        assert_eq!(pri_key.len(), 32);
    }

    #[test]
    fn test_compute_uncompress_key_should_ok() {
        let private_key = hex::decode("307702010104202a166bdf53fc14814dd19d5ed7cf56ccce503098d7\
                                                     1f2389c733206d88301d62a00a06082a8648ce3d030107a1440342000\
                                                     44571c5937c6a7701fe2fd10909798a5838b2b83bcca825e852ae0341\
                                                     b467321b2bd36c8c631a0b2e4b438e60687360bb4c5c44d075da6773d\
                                                     c8c42ee880fa454").unwrap();
        let pub_key = hex::decode(
            "04a9b854ed27a0572c79b1ba931b43f568322c266585636444bb5d1cba5284\
        0fe43bd2d1d7f73e9beaf2f7dc9697ae9cc439025fb635d735ba78c007a29e0d9618",
        )
        .unwrap();
        let secret = compute_ecdh_secret(
            Nid::X9_62_PRIME256V1,
            &pub_key,
            &private_key,
            true,
            KDFType::SHA256,
        )
        .unwrap();

        assert_eq!(
            secret,
            hex::decode("3e2f31f9ddcf8bf6bcc7b97b8b22671932397fc9f71bf2003ebdbb05b41e4a64")
                .unwrap()
        );
    }

    #[test]
    fn test_compute_compress_key_should_ok() {
        let private_key =
            hex::decode("ca12a9b71f1e1af57f921e48fb38065321f5d6411c51a5341ce6a28294ca90bb")
                .unwrap();
        let pub_key =
            hex::decode("03de19a842dfb903f6c892e90b9c4e5a8e7abc43e2b8dd187a24af2a1fbf2fe1a9")
                .unwrap();
        let secret = compute_ecdh_secret(
            Nid::X9_62_PRIME256V1,
            &pub_key,
            &private_key,
            false,
            KDFType::None,
        )
        .unwrap();
        assert_eq!(
            secret,
            hex::decode("6c6d3f76583bc0202877c6a0e4eae4a2e6448b5a10eeca06d06d9d7449f9699f")
                .unwrap()
        );
    }
}
