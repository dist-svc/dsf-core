// TODO: implement dalek-based sodium equivalence

use crate::types::*;

use ed25519_dalek::{
    Keypair, PublicKey as DalekPublicKey, SecretKey as DalekSecretKey, Signature, SignatureError,
};

use rand_facade::GlobalRng;

pub fn pk_new() -> (PublicKey, PrivateKey) {
    let keypair = Keypair::generate(&mut GlobalRng::get());
    (keypair.public.to_bytes().into(), keypair.to_bytes().into())
}

pub fn pk_sign(private_key: &PrivateKey, data: &[u8]) -> Result<Signature, SignatureError> {
    let secret = DalekSecretKey::from_bytes(&private_key)?;
    let public = DalekPublicKey::from(&secret);

    let keypair = Keypair { secret, public };

    let signature: Signature = keypair.sign(data);

    Ok(signature.into())
}

pub fn pk_validate(
    public_key: &PublicKey,
    signature: &Signature,
    data: &[u8],
) -> Result<bool, SignatureError> {
    let public_key = DalekPublicKey::from_bytes(&public_key).unwrap();
    Ok(public_key.verify(data, signature).is_ok())
}
