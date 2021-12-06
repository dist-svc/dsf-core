//! Wire provides a container type to map byte data to fixed fields (and vice versa)
//! to support wire encoding and decoding.

#[cfg(feature = "alloc")]
use alloc::vec::{Vec};

use core::ops::{DerefMut};
use std::convert::TryFrom;

use pretty_hex::*;

use crate::base::{Base, Body, Header, MaybeEncrypted};
use crate::crypto;
use crate::error::Error;
use crate::options::{Options, Filters};
use crate::types::*;
use crate::wire::builder::Encrypt;
/// Header provides a low-cost header abstraction for encoding/decoding
pub mod header;

/// Builder provides methods to construct a container using a mutable buffer and base types
pub mod builder;
pub use builder::Builder;

/// Container provides methods to access underlying wire object fields
pub mod container;
pub use container::Container;

use crate::keys::{KeySource, Keys};



/// Header object length
pub const HEADER_LEN: usize = 16;

/// Offsets for fixed fields in the protocol header
mod offsets {
    pub const PROTO_VERSION: usize = 0;
    pub const APPLICATION_ID: usize = 2;
    pub const OBJECT_KIND: usize = 4;
    pub const FLAGS: usize = 6;
    pub const INDEX: usize = 8;
    pub const DATA_LEN: usize = 10;
    pub const PRIVATE_OPTIONS_LEN: usize = 12;
    pub const PUBLIC_OPTIONS_LEN: usize = 14;
    pub const ID: usize = 16;
    pub const BODY: usize = 48;
}


/// Helper for validating signatures in symmetric or asymmetric modes
fn validate(
    keys: &Keys,
    id: &Id,
    kind: Kind,
    flags: Flags,
    sig: &Signature,
    data: &[u8],
) -> Result<bool, Error> {
    // Attempt to use secret key mode if available
    let valid = if flags.contains(Flags::SYMMETRIC_MODE) {
        debug!("Using symmetric mode");

        // Ensure symmetric mode is only used for messages
        if !kind.is_message() {
            return Err(Error::UnsupportedSignatureMode);
        }

        // Check for matching symmetric key
        let sk = match &keys.sym_keys {
            Some(s) if flags.contains(Flags::SYMMETRIC_DIR) => &s.0,
            Some(s) => &s.1,
            None => {
                return Err(Error::NoSymmetricKeys);
            }
        };

        // Validate signature
        crypto::sk_validate(&sk, sig, data).map_err(|_e| Error::CryptoError)?

    // Otherwise use public key
    } else {
        debug!("Using asymmetric mode");
        
        // Check for matching public key
        let pub_key = match &keys.pub_key {
            Some(pk) => pk,
            None => return Err(Error::NoPublicKey),
        };
        
        // Check ID matches public key
        let h = crypto::hash(pub_key).unwrap();
        if id != &h {
            error!("Public key mismatch for object from {:?} ({})", id, h);
            return Err(Error::KeyIdMismatch);
        }

        // Validate signature
        crypto::pk_validate(pub_key, sig, data).map_err(|_e| Error::CryptoError)?
    };

    Ok(valid)
}

impl<'a, T: ImmutableData> Container<T> {
    /// Parses a data array into a base object using the pub_key and sec_key functions to locate keys for validation and decryption
    pub fn parse<K>(data: T, key_source: &K) -> Result<Container<T>, Error>
    where
        K: KeySource,
    {
        // Build container over buffer
        let (mut container, n) = Container::from(data);
        let header = container.header();
        
        trace!("Parsing object: {:02x?}", container.hex_dump());

        trace!("Parsed header: {:02x?}", header);

        // Fetch required fields
        let flags = header.flags();
        let kind = header.kind();
        let id: Id = container.id().into();

        debug!("Container: {:?} Header: {:?}", container, header);

        // Fetch signature for page
        let mut verified = false;
        let signature: Signature = container.signature().into();

        // Validate primary types immediately if pubkey is known
        let is_primary = !flags.contains(Flags::SECONDARY) && !flags.contains(Flags::TERTIARY);

        match (is_primary, key_source.keys(&id)) {
            (true, Some(keys)) if keys.pub_key.is_some() => {
                let pub_key = keys.pub_key.as_ref().unwrap();

                trace!("Early signature validate: {:02x?} using key: {:?}", signature.as_ref(), pub_key);

                // Perform verification
                verified = validate(&keys, &id, kind, flags, &signature, container.signed())?;

                // Stop processing if signature is invalid
                if !verified {
                    info!("Invalid signature with known pubkey");
                    return Err(Error::InvalidSignature);
                }
            },
            _ => {
                trace!("Skipping early signature validation, no keys loaded");
            },
        }

        trace!("Fetching public options");

        // Fetch public options
        let mut peer_id = None;
        let mut pub_key = None;
        let mut parent = None;

        for o in container.public_options_iter() {
            match o {
                Options::PeerId(v) => {
                    peer_id = Some(v.peer_id.clone());
                },
                Options::PubKey(v) => {
                    pub_key = Some(v.public_key.clone());
                },
                Options::PrevSig(v) => {
                    parent = Some(v.sig.clone());
                },
                _ => (),
            }
        }

        // Look for signing ID
        let signing_id: Id = match (!is_primary, &peer_id) {
            (false, _) => Ok(container.id().into()),
            (true, Some(id)) => Ok(id.clone()),
            _ => Err(Error::NoPeerId),
        }?;

        trace!("Peer id: {:?} pub_key: {:?} parent: {:?} signing_id: {:?}",
            peer_id, pub_key, parent, signing_id);

        // Fetch public key
        let keys: Option<Keys> = match (key_source.keys(&signing_id), &pub_key) {
            (Some(keys), _) if keys.pub_key.is_some() => Some(keys),
            (_, Some(key)) => Some(Keys::new(key.clone())),
            _ => {
                warn!(
                    "Missing public key for message: {:?} signing id: {:?}",
                    header.index(), signing_id
                );
                None
            }
        };

        trace!("Re-validating object (keys: {:?})", keys);

        // Late validation for self-signed objects from unknown sources
        match (verified, keys) {
            (false, Some(keys)) => {
                // Check signature
                verified = validate(&keys, &signing_id, kind, flags, &signature, container.signed())?;

                // Stop processing on verification failure
                if !verified {
                    info!("Invalid signature for self-signed object from {:?}", id);
                    return Err(Error::InvalidSignature);
                }
            }
            (false, None) => {
                error!("No signature or key for object from {:?}", id);
                return Err(Error::NoSignature);
            }
            _ => (),
        }

        trace!("Parse OK! (verified: {:?})", verified);
        container.verified = verified;
        container.len = container.len();

        // Return verified container
        Ok(container)
    }
}

// Temporary patch to build base object for container while refactoring out base
impl <T: ImmutableData> TryFrom<Container<T>> for Base {
    type Error = Error;

    fn try_from(c: Container<T>) -> Result<Self, Self::Error> {
        // Fetch public options
        let mut peer_id = None;
        let mut pub_key = None;
        let mut prev_sig = None;

        let public_options: Vec<_> = c
            .public_options_iter()
            .filter_map(|o| match &o {
                Options::PeerId(v) => {
                    peer_id = Some(v.peer_id.clone());
                    None
                }
                Options::PubKey(v) => {
                    pub_key = Some(v.public_key.clone());
                    None
                }
                Options::PrevSig(v) => {
                    prev_sig = Some(v.sig.clone());
                    None
                }
                _ => Some(o),
            })
            .collect();

        // Map body and options depending on encryption state
        let body = match (c.header().data_len(), c.encrypted()) {
            (0, _) => MaybeEncrypted::None,
            (_, false) => MaybeEncrypted::Cleartext(c.body().to_vec()),
            (_, true) => MaybeEncrypted::Encrypted(c.body().to_vec()),
        };

        let private_opts = match (c.header().private_options_len(), c.encrypted()) {
            (0, _) => MaybeEncrypted::None,
            (_, false) => MaybeEncrypted::Cleartext(c.private_options_iter().collect()),
            (_, true) => MaybeEncrypted::Encrypted(c.private_options().to_vec())
        };

        Ok(Base {
            id: c.id(),
            header: Header::from(&c.header()),
            body: body,

            private_options: private_opts,
            public_options: public_options,

            parent: prev_sig,
            peer_id: peer_id,
            public_key: pub_key,

            tag: c.tag(),
            signature: Some(c.signature()),
            verified: c.verified,

            raw: Some(c.raw().to_vec()),
        })
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]>> Container<T> {
    pub fn encode(buff: T, base: &Base, keys: &Keys) -> Result<(Self, usize), Error> {
        trace!("Encode for object: {:?}", base);

        // Setup base builder with header and ID
        let bb = Builder::new(buff).id(base.id()).header(base.header());
        let flags = base.flags();

        // Check private key exists
        let private_key = match &keys.pri_key {
            Some(k) => k,
            None => panic!("Attempted to sign object with no private key"),
        };

        // Check encryption key exists if required
        let _encryption_key = match (flags.contains(Flags::ENCRYPTED), keys.sec_key.as_ref()) {
            (true, Some(k)) => Some(k),
            (true, None) => return Err(Error::NoSecretKey),
            _ => None,
        };

        let encrypted = flags.contains(Flags::ENCRYPTED);
        let sec_key = keys.sec_key.as_ref();

        // Append body
        let bb = match &base.body {
            MaybeEncrypted::Cleartext(c) => bb.body(&c[..])?,
            MaybeEncrypted::Encrypted(e) => bb.body(&e[..])?,
            MaybeEncrypted::None => bb.body(&[])?,
        };
        
        // Append private options
        let bb = match &base.private_options {
            MaybeEncrypted::Cleartext(c) => bb.private_options(c)?,
            MaybeEncrypted::Encrypted(e) => bb.private_options_raw(e)?,
            MaybeEncrypted::None => bb.private_options(&[])?,
        };


        // Ensure state is valid and apply encryption
        // TODO: it'd be great to enforce this better via the builder
        let mut bb = match (encrypted, sec_key, &base.body, &base.private_options, &base.tag) {
            // If we're not encrypted, bypass
            (false, _, _, _, _) => bb.public(),
            // If we're holding encrypted data, just re-encode it
            (true, _, Body::Encrypted(_) | Body::None, MaybeEncrypted::Encrypted(_) | MaybeEncrypted::None, Some(t)) => {
                bb.tag(t)?
            },
            // If we have keys and a tag, re-encrypt
            (true, Some(sk), Body::Cleartext(_) | Body::None, MaybeEncrypted::Cleartext(_) | MaybeEncrypted::None, Some(t)) => {
                bb.re_encrypt(sk, t)?
            },
            // If we have keys but no tag, new encryption
            (true, Some(sk), Body::Cleartext(_) | Body::None, MaybeEncrypted::Cleartext(_) | MaybeEncrypted::None , None) => {
                bb.encrypt(sk)?
            },
            // If we have no keys, fail
            (true, _, _, _, _) => {
                error!("Encrypt failed, no secret key or mismatched clear/cyphertexts");
                return Err(Error::NoSecretKey);
            },
        };

        // Write public options
        // Add public key option if specified
        if let Some(k) = &base.public_key {
            bb.public_option(&Options::pub_key(k.clone()))?;
        }

        if let Some(s) = &base.parent {
            bb.public_option(&Options::prev_sig(s))?;
        }

        if let Some(i) = &base.peer_id {
            bb.public_option(&Options::peer_id(i.clone()))?;
        }

        let bb = bb.public_options(&base.public_options())?;

        // Sign object
        let c = if !flags.contains(Flags::SYMMETRIC_MODE) {
            bb.sign_pk(&private_key)?
        } else {
            // Ensure this can only be used for req/resp messages
            if !base.header().kind().is_message() {
                panic!("Attempted to sign non-message type with symmetric keys");
            }

            let sec_key = match &keys.sym_keys {
                Some(k) if flags.contains(Flags::SYMMETRIC_DIR) => &k.1,
                Some(k) => &k.0,
                _ => panic!("Attempted to sign object with no secret key"),
            };

            bb.sign_sk(&sec_key)?
        };

        // Update length
        let len = c.len;

        // Return signed container and length
        Ok((c, len))
    }
}

/// Helper to decrypt optionally encrypted fields
pub(crate) fn decrypt(sk: &SecretKey, body: &mut MaybeEncrypted, private_opts: &mut MaybeEncrypted<Vec<Options>>, tag: Option<&SecretMeta>) -> Result<(), Error> {
    
    // Check we have a tag
    let tag = match tag {
        Some(t) => t,
        None => return Err(Error::Unknown),
    };

    // Build cyphertext
    let mut cyphertext: Vec<u8> = vec![];
    
    let body_len = match body {
        MaybeEncrypted::Cleartext(_) => return Err(Error::Unknown),
        MaybeEncrypted::None => 0,
        MaybeEncrypted::Encrypted(e) => {
            cyphertext.extend(e.iter());
            e.len()
        },
    };

    let private_opt_len = match private_opts {
        MaybeEncrypted::Cleartext(_) => return Err(Error::Unknown),
        MaybeEncrypted::None => 0,
        MaybeEncrypted::Encrypted(e) => {
            cyphertext.extend(e.iter());
            e.len()
        },
    };

    // Perform decryption
    let _n = crypto::sk_decrypt(&sk, tag, cyphertext.deref_mut())
            .map_err(|_e| Error::InvalidSignature)?;

    // Write-back decrypted data
    if body_len > 0 {
        *body = MaybeEncrypted::Cleartext(cyphertext[..body_len].to_vec());
    }

    if private_opt_len > 0 {
        let (opts, _n) = Options::parse_vec(&cyphertext[body_len..])?;
        *private_opts = MaybeEncrypted::Cleartext(opts);
    }

    return Ok(())
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use super::*;

    use crate::crypto;

    fn setup() -> (Id, Keys) {
        let (pub_key, pri_key) =
            crypto::new_pk().expect("Error generating new public/private key pair");
        let id = crypto::hash(&pub_key)
            .expect("Error generating new ID")
            .into();
        let sec_key = crypto::new_sk().expect("Error generating new secret key");
        (
            id,
            Keys {
                pub_key: Some(pub_key),
                pri_key: Some(pri_key),
                sec_key: Some(sec_key),
                sym_keys: None,
            },
        )
    }

    #[test]
    fn encode_decode_primary_page() {
        let (id, mut keys) = setup();
        keys.sec_key = None;

        let header = Header {
            kind: PageKind::Generic.into(),
            application_id: 10,
            index: 12,
            ..Default::default()
        };
        let data = vec![1, 2, 3, 4, 5, 6, 7];

        // Encode using builder
        let c = Builder::new(vec![0u8; 1024])
            .id(&id)
            .header(&header)
            .body(data).unwrap()
            .private_options(&[]).unwrap()
            .public()
            .sign_pk(keys.pri_key.as_ref().unwrap())
            .expect("Error encoding page");


        // Decode into container
        let d = Container::parse(c.buff.clone(), &keys)
            .expect("Error decoding page");

        // TODO: convert to pages and compare

        assert_eq!(c, d);
    }
}
