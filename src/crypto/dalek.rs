// TODO: implement dalek-based sodium equivalence

use crate::types::*;

use ed25519_dalek::{
    Signer as _, Verifier as _,
    Keypair, PublicKey as DalekPublicKey, SecretKey as DalekSecretKey, Signature, SignatureError,
};

use rand::rngs::OsRng;

pub fn pk_new() -> (PublicKey, PrivateKey) {
    let mut csprng = OsRng{};
    let keypair = Keypair::generate(&mut csprng);
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


#[cfg(test)]
mod test {
    extern crate test;
    use test::Bencher;

    use crate::types::SECRET_KEY_TAG_LEN;
    use super::*;
    #[bench]
    fn bench_pk_sign(b: &mut Bencher) {
        let (_public, private) = pk_new();
        let data = [0xabu8; 256];

        b.iter(|| {
            let _sig = pk_sign(&private, &data).expect("Error generating signature");
        })
    }

    #[bench]
    fn bench_pk_verify(b: &mut Bencher) {
        let (public, private) = pk_new();
        let data = [0xabu8; 256];

        let signature = pk_sign(&private, &data).expect("Error generating signature");

        b.iter(|| {
            let valid =
                pk_validate(&public, &signature, &data).expect("Error validating signature");
            assert_eq!(true, valid);
        })
    }
}