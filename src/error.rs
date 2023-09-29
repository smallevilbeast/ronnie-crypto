use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("OpenSSL error: {0}")]
    OpensslError(#[from] openssl::error::ErrorStack),

    #[error("Invalid hkdf info length: {0}")]
    InvalidHkdfInfoLength(usize),

    #[error("Rsa block error")]
    RsaBlockError,
}
