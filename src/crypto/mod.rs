//! Crypto module provides cryptographic interfaces and implementations for DSF
//!

use core::fmt::Debug;
use core::ops::Deref;
use core::convert::TryFrom;

use sha2::Digest;
use sha2::digest::FixedOutput;

use crate::prelude::Keys;
use crate::types::*;

pub mod native;


pub type Crypto = native::RustCrypto;
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

pub trait PubKey {
    type Error: Debug;

    fn new_pk() -> Result<(PublicKey, PrivateKey), Self::Error>;

    fn pk_sign(private_key: &PrivateKey, data: &[u8]) -> Result<Signature, Self::Error>;

    fn pk_verify(public_key: &PublicKey, signature: &Signature, data: &[u8]) -> Result<bool, Self::Error>;

    /// Derive secret keys for symmetric use from pub/pri keys.
    /// Note that these must be swapped (rx->tx, tx->rx) depending on direction
    fn kx(pub_key: &PublicKey, pri_key: &PrivateKey, remote: &PublicKey) -> Result<(SecretKey, SecretKey), Self::Error>;

    fn get_public(private_key: &PrivateKey) -> PublicKey {
        let mut public_key = PublicKey::default();

        public_key.copy_from_slice(&private_key[32..]);

        public_key
    }
}

pub trait SecKey {
    type Error: Debug;

    fn new_sk() -> Result<SecretKey, Self::Error>;

    fn sk_encrypt(secret_key: &SecretKey, assoc: Option<&[u8]>, message: &mut [u8]) -> Result<SecretMeta, Self::Error>;

    fn sk_decrypt(secret_key: &SecretKey, meta: &[u8], assoc: Option<&[u8]>, message: &mut [u8]) -> Result<(), Self::Error>;

    fn sk_reencrypt(secret_key: &SecretKey, meta: &[u8], assoc: Option<&[u8]>, message: &mut [u8]) -> Result<SecretMeta, Self::Error>;
}

pub trait Hash {
    type Error: Debug;

    fn hash(data: &[u8]) -> Result<CryptoHash, ()> {
        let h = sha2::Sha512Trunc256::digest(data);
        Ok(CryptoHash::try_from(h.deref()).unwrap())
    }

    /// Blake2b key derivation function via libsodium
    fn kdf(seed: &[u8]) -> Result<CryptoHash, ()> { todo!() }

    /// Hasher to generate TIDs for a given ID and keyset
    fn hash_tid(id: Id, keys: &Keys, o: impl Queryable) -> Result<CryptoHash, ()> {
        // Generate seed for tertiary hash based on secret or public
        let seed: CryptoHash = match (&keys.sec_key, &keys.pub_key) {
            // If we have a secret key, derive a new key for hashing
            (Some(sk), _) => Self::kdf(&sk)?,
            // Otherwise use the public key
            (_, Some(pk)) => Self::kdf(&pk)?,
            _ => todo!(),
        };
    
    
        // Generate new identity hash
        let mut h = sha2::Sha512Trunc256::new();
        h.input(&seed);
        
        if !o.hash(&mut h) {
            error!("Attempted to hash non-queryable type: {:?}", o);
            return Err(())
        }

        let d = h.fixed_result();
        let d = CryptoHash::try_from(d.deref()).unwrap();
    
        // XOR with ns ID to give new location
        Ok(d ^ CryptoHash::from(id.as_bytes()))
    }
}

impl CryptoHasher for sha2::Sha512Trunc256 {
    fn update(&mut self, buff: &[u8]) {
        self.input( buff)
    }
}
