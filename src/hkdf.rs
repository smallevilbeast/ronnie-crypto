use crate::{hmac::hmac_sha256, error::CryptoError}; 

const CRYPTO_HMAC_SHA256: usize = 32;

pub fn hkdf_expand(key: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
    let hash_len = CRYPTO_HMAC_SHA256;
    if length > 255 * hash_len {
        return Err(CryptoError::InvalidHkdfInfoLength(length));
    }

    let blocks_needed = length / hash_len + if length % hash_len == 0 { 0 } else { 1 };
    let mut okm = Vec::new();
    let mut output_block = Vec::new();

    for counter in 0..blocks_needed {
        let mut data = output_block.clone();
        data.extend_from_slice(info);
        data.push(counter as u8 + 1);

        output_block = hmac_sha256(key, &data)?;
        okm.extend_from_slice(&output_block);
    }

    Ok(okm[0..length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_hkdf() {
        let key = hex::decode("d8f0e69f37c161cd32e2246987478381ecff00c0b189840e3d1e9f9719812406").unwrap();
        let info = hex::decode("c06982567a20d01b1e07c4ee8ba834fee2935bdc6cb2412224ae87a9fd30f27e").unwrap();
        let okm = hkdf_expand(&key, &info, 42).unwrap();
        let test_okm = hex::decode("4a190048d535dece319b88a1e93b8bd4d199247255785e5d1134c14aa9c1c794d0789f7f2fa8f520bef8").unwrap();
        assert_eq!(okm, test_okm);
    }
}