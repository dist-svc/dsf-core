//! Crypto module provides cryptographic interfaces and implementations for DSF
//!

use core::fmt::Debug;
use core::ops::Deref;
use core::convert::TryFrom;

use sha2::Digest;
use sha2::digest::FixedOutput;

use crate::prelude::Keys;
use crate::types::*;

#[cfg(feature = "crypto_sodium")]
mod sodium;

#[cfg(feature = "crypto_rust")]
pub mod native;

#[cfg(not(any(feature = "crypto_sodium", feature = "crypto_rust")))]
compile_error!("crypto_sodium or crypto_rust features are required");

cfg_if::cfg_if!{
    if #[cfg(feature = "crypto_sodium")] {
        pub type Crypto = sodium::SodiumCrypto;
    } else if #[cfg(feature = "crypto_rust")] {
        pub type Crypto = native::RustCrypto;
    }
}

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

    fn sk_sign(secret_key: &SecretKey, message: &[u8]) -> Result<Signature, Self::Error>;

    fn sk_verify(secret_key: &PublicKey, signature: &Signature, data: &[u8]) -> Result<bool, Self::Error>;

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
    fn kdf(seed: Array32) -> Result<Array32, ()> { todo!() }

    /// Hasher to generate TIDs for a given ID and keyset
    fn hash_tid(id: Id, keys: &Keys, o: impl Queryable) -> Result<CryptoHash, ()> {
        // Generate seed for tertiary hash
        let seed: Array32 = match (&keys.sec_key, &keys.pub_key) {
            // If we have a secret key, derive a new key for hashing
            (Some(sk), _) => Self::kdf(sk.clone())?,
            // Otherwise use the public key
            (_, Some(pk)) => pk.clone(),
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
        Ok(d ^ id)
    }
}

impl CryptoHasher for sha2::Sha512Trunc256 {
    fn update(&mut self, buff: &[u8]) {
        self.input( buff)
    }
}

/// Compatibility tests, only included if both `crypto_sodium` and `crypto_rust` are enabled
#[cfg(all(test, feature="crypto_sodium", feature="crypto_rust"))]
mod test {
    use super::{PubKey, SecKey, Hash, native::RustCrypto, sodium::SodiumCrypto};

    fn setup() {
        #[cfg(feature="simplelog")]
        let _ = simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default());
    }

    #[test]
    fn test_pk_sodium_dalek_sig() {
        setup();

        let (public, private) = SodiumCrypto::new_pk().unwrap();
        let mut data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let signature = SodiumCrypto::pk_sign(&private, &data).unwrap();

        let valid = RustCrypto::pk_verify(&public, &signature, &data).unwrap();
        assert_eq!(valid, true);

        data[0] = data[0] + 1;
        let valid = RustCrypto::pk_verify(&public, &signature, &data).unwrap();
        assert_eq!(valid, false);
    }

    #[test]
    fn test_pk_dalek_sodium_sig() {
        setup();

        let (public, private) = RustCrypto::new_pk().unwrap();
        let mut data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let signature = RustCrypto::pk_sign(&private, &data).unwrap();

        let valid = SodiumCrypto::pk_verify(&public, &signature, &data).unwrap();
        assert_eq!(valid, true);

        data[0] = data[0] + 1;
        let valid = SodiumCrypto::pk_verify(&public, &signature, &data).unwrap();
        assert_eq!(valid, false);
    }

    #[test]
    fn test_sk_dalek_sodium_enc() {
        setup();

        let sk = SodiumCrypto::new_sk().unwrap();
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut d1 = data.clone();

        let meta = RustCrypto::sk_encrypt(&sk, None, &mut d1).unwrap();

        println!("Encrypted with tag: {}", meta);

        SodiumCrypto::sk_decrypt(&sk, &meta, None, &mut d1).unwrap();
        assert_eq!(data, d1);
    }

    #[test]
    fn test_sk_sodium_dalek_enc() {
        setup();

        let sk = RustCrypto::new_sk().unwrap();
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut d1 = data.clone();

        let meta = SodiumCrypto::sk_encrypt(&sk, None, &mut d1).unwrap();

        println!("Encrypted with tag: {}", meta);

        RustCrypto::sk_decrypt(&sk, &meta, None, &mut d1).unwrap();
        assert_eq!(data, d1);
    }

    #[test]
    fn test_pk_dalek_sodium_kx() {
        let (pub1, pri1) = RustCrypto::new_pk().expect("Error generating public/private keypair");
        let (pub2, pri2) = SodiumCrypto::new_pk().expect("Error generating public/private keypair");

        let (a1, a2) = RustCrypto::kx( &pub1, &pri1, &pub2).unwrap();
        let (b1, b2) = SodiumCrypto::kx( &pub2, &pri2, &pub1).unwrap();

        println!("A1: {} A2: {}", a1, a2);
        println!("B1: {} B2: {}", b1, b2);

        assert_eq!(a1, b1);
        assert_eq!(a2, b2);
    }

    #[test]
    fn test_rust_sodium_kdf() {
        let (pub1, _pri1) = RustCrypto::new_pk().expect("Error generating public/private keypair");
        
        let derived1 = RustCrypto::kdf(pub1.clone());
        let derived2 = SodiumCrypto::kdf(pub1.clone());

        assert_eq!(derived1, derived2)
    }

}