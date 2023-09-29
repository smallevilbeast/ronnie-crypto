use openssl::rsa::{ Rsa, Padding };
use openssl::bn::BigNum;

use crate::error::CryptoError;

pub fn get_public_key_en(pem: &[u8]) -> Result<(String, String), CryptoError> {
    let rsa = Rsa::public_key_from_pem(pem)?;
    let e = rsa.e().to_hex_str()?.to_string();
    let n = rsa.n().to_hex_str()?.to_string();
    Ok((e, n))
}

pub fn rsa_public_encrypt(
    public_key_n: &[u8],
    public_key_e: &[u8],
    input: &[u8]
) -> Result<Vec<u8>, CryptoError> {
    let n = BigNum::from_slice(public_key_n)?;
    let e = BigNum::from_slice(public_key_e)?;
    let rsa = Rsa::from_public_components(n, e)?;

    let rsa_len = rsa.size() as usize;
    let mut encrypted_data = Vec::new();

    if input.len() >= rsa_len - 11 {
        let mut blocks = Vec::new();
        let block_size = rsa_len - 11;
        for chunk in input.chunks(block_size) {
            blocks.push(chunk);
        }

        for block in blocks {
            let mut buffer = vec![0; rsa_len];
            match rsa.public_encrypt(block, &mut buffer, Padding::PKCS1) {
                Ok(size) => encrypted_data.extend(&buffer[..size]),
                Err(e) => {
                    return Err(CryptoError::OpensslError(e));
                }
            }
        }
    } else {
        let mut buffer = vec![0; rsa_len];
        match rsa.public_encrypt(input, &mut buffer, Padding::PKCS1) {
            Ok(size) => encrypted_data.extend(&buffer[..size]),
            Err(e) => {
                return Err(CryptoError::OpensslError(e));
            }
        }
    }

    Ok(encrypted_data)
}

pub fn rsa_private_decrypt(
    private_key_der: &[u8],
    encrypted_data: &[u8]
) -> Result<Vec<u8>, CryptoError> {
    let rsa = Rsa::private_key_from_der(private_key_der)?;

    let mut decrypted = vec![0u8; rsa.size() as usize];
    let mut total_decrypted = 0;
    for chunk in encrypted_data.chunks(rsa.size() as usize) {
        let size = rsa.private_decrypt(chunk, &mut decrypted[total_decrypted..], Padding::PKCS1)?;
        total_decrypted += size;
    }
    decrypted.truncate(total_decrypted);
    Ok(decrypted)
}
