// TODO: implement dalek-based sodium equivalence

extern crate ed25519_dalek;

use crate::types::*;

use ed25519_dalek::{Keypair, Signature};
use rand::rngs::OsRng;
use sha2::Sha512;

pub fn pk_new() -> (PublicKey, PrivateKey) {
    let mut csprng = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate::<Sha512, _>(&mut csprng);

    (keypair.public.to_bytes().into(), keypair.to_bytes().into())
}

pub fn pk_sign(private_key: &PrivateKey, data: &[u8]) -> Result<Signature, ()> {
    unimplemented!()
}

pub fn pk_validate(public_key: &PublicKey, signature: &Signature, data: &[u8]) -> Result<bool, ()> {
    unimplemented!()
}
