//! Crypto module provides cryptographic interfaces and implementations for DSF
//!

use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::PublicKey as SodiumPublicKey;
use sodiumoxide::crypto::sign::ed25519::SecretKey as SodiumPrivateKey;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key as SodiumSecretKey;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Nonce as SodiumSecretNonce;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Tag as SodiumSecretTag;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{MACBYTES, NONCEBYTES};

use sodiumoxide::crypto::hash::sha256;

use crate::types::{CryptoHash, PrivateKey, PublicKey, SecretKey, Signature};

/// new_pk creates a new public/private key pair
pub fn new_pk() -> Result<(PublicKey, PrivateKey), ()> {
    let (public_key, private_key) = sign::gen_keypair();
    Ok((public_key.0.into(), private_key.0.into()))
}

/// pk_sign generates a signature for the provided slice of data
pub fn pk_sign(private_key: &PrivateKey, data: &[u8]) -> Result<Signature, ()> {
    // Parse key from provided slice
    let private_key = SodiumPrivateKey::from_slice(private_key).unwrap();
    // Generate signature
    let sig = sign::sign_detached(data, &private_key);
    // Return signature object
    Ok(sig.0.into())
}

/// pk_validate checks a provided signature against a public key and slice of data
pub fn pk_validate(public_key: &PublicKey, signature: &Signature, data: &[u8]) -> Result<bool, ()> {
    // Parse key from provided slice
    let public_key = SodiumPublicKey::from_slice(public_key).unwrap();
    // Parse signature from provided slice
    let sig = sign::ed25519::Signature::from_slice(signature).unwrap();
    // Verify signature (returns true or)
    Ok(sign::verify_detached(&sig, data, &public_key))
}

pub const SK_META: usize = MACBYTES + NONCEBYTES;

/// new_sk creates a new secret key for symmetric encryption and decryption
pub fn new_sk() -> Result<SecretKey, ()> {
    let key = secretbox::gen_key();
    Ok(key.0.into())
}

pub fn sk_encrypt(secret_key: &SecretKey, message: &mut [u8]) -> Result<[u8; SK_META], ()> {
    let secret_key = SodiumSecretKey::from_slice(secret_key).unwrap();
    let nonce = secretbox::gen_nonce();

    // Perform in-place encryption
    let tag = secretbox::seal_detached(message, &nonce, &secret_key);

    // Generate encryption metadata
    let mut meta = [0u8; SK_META];
    (&mut meta[..MACBYTES]).copy_from_slice(&tag.0);
    (&mut meta[MACBYTES..]).copy_from_slice(&nonce.0);

    Ok(meta)
}

pub fn sk_decrypt(secret_key: &SecretKey, meta: &[u8], message: &mut [u8]) -> Result<(), ()> {
    let secret_key = SodiumSecretKey::from_slice(secret_key).unwrap();

    // Parse encryption metadata
    let tag = SodiumSecretTag::from_slice(&meta[..MACBYTES]).unwrap();
    let nonce = SodiumSecretNonce::from_slice(&meta[MACBYTES..]).unwrap();

    // Perform in-place decryption
    secretbox::open_detached(message, &tag, &nonce, &secret_key)
}

/// sk_encrypt2 encrypts data_len bytes of the data in-place in the provided buffer,
/// appends NONCE and TAG information to the buffer, and returns the complete length (encrypted data + overheads)
pub fn sk_encrypt2<T>(secret_key: &SecretKey, mut buff: T, data_len: usize) -> Result<usize, ()>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    let data = buff.as_mut();

    let secret_key = SodiumSecretKey::from_slice(secret_key).unwrap();
    let nonce = secretbox::gen_nonce();

    // Perform in-place encryption
    let tag = secretbox::seal_detached(&mut data[..data_len], &nonce, &secret_key);

    // Append encryption metadata
    let mut i = data_len;
    (&mut data[i..i + MACBYTES]).copy_from_slice(&tag.0);
    i += MACBYTES;
    (&mut data[i..i + NONCEBYTES]).copy_from_slice(&nonce.0);

    Ok(data_len + MACBYTES + NONCEBYTES)
}

/// sk_decrypt2 decrypts the data in-place in the provided buffer,
/// this will strip NONCE and TAG information, and returns the data length (decrypted data w/out overheads)
pub fn sk_decrypt2<T>(secret_key: &SecretKey, mut buff: T) -> Result<usize, ()>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    let data = buff.as_mut();
    let len = data.len() - NONCEBYTES - MACBYTES;

    let secret_key = SodiumSecretKey::from_slice(secret_key).unwrap();

    // Parse encryption metadata
    let mut i = len;
    let tag = SodiumSecretTag::from_slice(&data[i..i + MACBYTES]).unwrap();
    i += MACBYTES;
    let nonce = SodiumSecretNonce::from_slice(&data[i..i + NONCEBYTES]).unwrap();

    // Perform in-place decryption
    secretbox::open_detached(&mut data[..len], &tag, &nonce, &secret_key)?;

    Ok(len)
}

/// Hash performs a hash function over the provided slice
pub fn hash(data: &[u8]) -> Result<CryptoHash, ()> {
    let digest = sha256::hash(data);
    Ok(digest.0.into())
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_sign_verify() {
        let (public, private) = new_pk().expect("Error generating public/private keypair");
        let mut data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let signature = pk_sign(&private, &data).expect("Error generating signature");

        let valid = pk_validate(&public, &signature, &data).expect("Error validating signature");
        assert_eq!(true, valid);

        data[3] = 100;
        let valid = pk_validate(&public, &signature, &data).expect("Error validating signature");
        assert_eq!(false, valid);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let secret = new_sk().expect("Error generating secret key");
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut message = data.clone();

        let meta = sk_encrypt(&secret, &mut message).expect("Error encrypting data");
        assert!(data != message);

        sk_decrypt(&secret, &meta, &mut message).expect("Error decrypting data");
        assert_eq!(data, message);
    }

    #[test]
    fn test_encrypt_decrypt2() {
        let secret = new_sk().expect("Error generating secret key");
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let mut buff = data.clone();
        buff.append(&mut vec![0u8; 128]);

        let n = sk_encrypt2(&secret, &mut buff, data.len()).expect("Error encrypting data");
        assert_eq!(n, data.len() + NONCEBYTES + MACBYTES);
        assert!(data != &buff[..data.len()]);

        let m = sk_decrypt2(&secret, &mut buff[..n]).expect("Error decrypting data");
        assert_eq!(m, data.len());
        assert_eq!(data, &buff[..m]);
    }
}
