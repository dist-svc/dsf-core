//! Crypto module provides cryptographic interfaces and implementations for DSF
//! 

use crate::types::*;

pub mod sodium;
pub use sodium::*;

#[cfg(feature="crypto-dalek")]
pub mod dalek;

/// Signer trait, used for generating page signatures
pub trait Signer {
    type Error;

    fn sign(&mut self, id: &Id, data: &[u8]) -> Result<Signature, Self::Error>;
}

/// Validator trait, used for checking page signatures.
/// This should return Ok(true) for success, Ok(false) for an unknown ID:Key pair
/// or an error on a signature mismatch
pub trait Validator {
    type Error;

    fn validate(&self, id: &Id, sig: &Signature, data: &[u8]) -> Result<bool, Self::Error>;
}

/// Encrypter trait, used to encrypt data for a given service
pub trait Encrypter {
    type Error;

    fn encrypt(&mut self, id: &Id, key: &SecretKey, data: &mut [u8]) -> Result<(), Self::Error>;
}

/// Decrypter trait, used to decrypt data for a given service
pub trait Decrypter {
    type Error;

    fn decrypt(&mut self, id: &Id, key: &SecretKey, data: &mut [u8]) -> Result<(), Self::Error>;
}
