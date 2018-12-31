

use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::PublicKey as SodiumPublicKey;
use sodiumoxide::crypto::sign::ed25519::SecretKey as SodiumPrivateKey;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key as SodiumSecretKey;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Nonce as SodiumSecretNonce;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::NONCEBYTES;

use sodiumoxide::crypto::hash::sha256;

use crate::types::{PublicKey, PrivateKey, Signature, SecretKey, Hash};

/// Signer trait, used for generating page signatures
pub trait Signer {
    type Error;

    fn sign(&mut self, id: &[u8], data: &[u8]) -> Result<Signature, Self::Error>;
}

/// Validator trait, used for checking page signatures.
/// This should return Ok(true) for success, Ok(false) for an unknown ID:Key pair
/// or an error on a signature mismatch
pub trait Validator {
    type Error;

    fn validate(&self, id: &[u8], sig: &[u8], data: &[u8]) -> Result<bool, Self::Error>;
}

/// Encrypter trait, used to encrypt data for a given service
pub trait Encrypter {
    type Error;

    fn encrypt(&mut self, id: &[u8], key: &[u8], data: &mut [u8]) -> Result<(), Self::Error>;
}

/// Decrypter trait, used to decrypt data for a given service
pub trait Decrypter {
    type Error;

    fn decrypt(&mut self, id: &[u8], key: &[u8], data: &mut [u8]) -> Result<(), Self::Error>;
}


pub fn new_pk() -> Result<(PublicKey, PrivateKey), ()> {
     let (public_key, private_key) = sign::gen_keypair();
     Ok((public_key.0, private_key.0))
}

pub fn pk_sign(private_key: &[u8], data: &[u8]) -> Result<Signature, ()> {
     // Parse key from provided slice
     let private_key = SodiumPrivateKey::from_slice(private_key).unwrap();
     // Generate signature
     let sig = sign::sign_detached(data, &private_key);
     // Return signature object
     Ok(sig.0.into())
}

pub fn pk_validate(public_key: &[u8], signature: &[u8], data: &[u8]) -> Result<bool, ()> {
     // Parse key from provided slice
     let public_key = SodiumPublicKey::from_slice(public_key).unwrap();
     // Parse signature from provided slice
     let sig = sign::ed25519::Signature::from_slice(signature).unwrap();
     // Verify signature (returns true or)
     Ok(sign::verify_detached(&sig, data, &public_key))
}  

pub fn new_sk() -> Result<SecretKey, ()> {
     let key = secretbox::gen_key();
     Ok(key.0)
}

pub fn sk_encrypt(secret_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ()> {
     let secret_key = SodiumSecretKey::from_slice(secret_key).unwrap();
     let nonce = secretbox::gen_nonce();

     let mut ciphertext = secretbox::seal(plaintext, &nonce, &secret_key);

     ciphertext.extend_from_slice(&nonce.0);

     Ok(ciphertext)
}

pub fn sk_decrypt(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
     let secret_key = SodiumSecretKey::from_slice(secret_key).unwrap();

     let split = ciphertext.len() - NONCEBYTES;
     let data = &ciphertext[..split];
     let nonce = &ciphertext[split..];

     let nonce = SodiumSecretNonce::from_slice(nonce).unwrap();

     secretbox::open(data, &nonce, &secret_key)
}


pub fn hash(data: &[u8]) -> Result<Hash, ()> {
    let digest = sha256::hash(data);
    Ok(digest.0)
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_sign_verify() {
          let (public, private) = new_pk().expect("Error generating public/private keypair");
          let mut data = vec!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);

          let signature = pk_sign(&private, &data).expect("Error generating signature");
          
          let valid = pk_validate(&public, signature.as_ref(), &data).expect("Error validating signature");
          assert_eq!(true, valid);

          data[3] = 100;
          let valid = pk_validate(&public, signature.as_ref(), &data).expect("Error validating signature");
          assert_eq!(false, valid);
    }

     #[test]
    fn test_encrypt_decrypt() {
         let secret = new_sk().expect("Error generating secret key");
         let mut data = vec!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);

         let ciphertext = sk_encrypt(&secret, &data).expect("Error encrypting data");
         let plaintext = sk_decrypt(&secret, &ciphertext).expect("Error decrypting data");

         assert_eq!(data, plaintext);
    }

}