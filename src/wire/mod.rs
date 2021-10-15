//! Wire provides a container type to map byte data to fixed fields (and vice versa)
//! to support wire encoding and decoding.

#[cfg(feature = "alloc")]
use alloc::prelude::v1::*;

use pretty_hex::*;

use crate::base::{Base, Body, Header, PrivateOptions};
use crate::crypto;
use crate::error::Error;
use crate::options::{Options, OptionsList};
use crate::types::*;

/// Header provides a low-cost header abstraction for encoding/decoding
pub mod header;

/// Builder provides methods to construct a container using a mutable buffer and base types
pub mod builder;
pub use builder::Builder;

/// Container provides methods to access underlying wire object fields
pub mod container;
pub use container::Container;

use crate::{KeySource, Keys};

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
        // TEnsure symmetric mode is only used for messages
        if !kind.is_message() {
            return Err(Error::UnsupportedSignatureMode);
        }

        let sk = match &keys.sym_keys {
            Some(s) if flags.contains(Flags::SYMMETRIC_DIR) => &s.0,
            Some(s) => &s.1,
            None => {
                return Err(Error::NoSymmetricKeys);
            }
        };

        crypto::sk_validate(&sk, sig, data).map_err(|_e| Error::CryptoError)?

    // Otherwise use public key
    } else {
        
        // Check ID matches public key
        let h = crypto::hash(&keys.pub_key).unwrap();
        if id != &h {
            error!("Public key mismatch for object from {:?} ({})", id, h);
            return Err(Error::KeyIdMismatch);
        }

        crypto::pk_validate(&keys.pub_key, sig, data).map_err(|_e| Error::CryptoError)?
    };

    Ok(valid)
}

impl<'a, T: AsRef<[u8]>> Container<T> {
    /// Parses a data array into a base object using the pub_key and sec_key functions to locate
    /// keys for validation and decyption
    pub fn parse<K>(data: T, key_source: &K) -> Result<(Base, usize), Error>
    where
        K: KeySource,
    {
        let mut verified = false;

        // Build container over buffer
        let (container, n) = Container::from(data);
        let header = container.header();

        trace!("Parsing object: {:02x?}", container.hex_dump());

        trace!("Parsed header: {:02x?}", header);

        // Fetch required fields
        let flags = header.flags();
        let kind = header.kind();
        let id: Id = container.id().into();

        // Fetch signature for page
        let signature: Signature = container.signature().into();

        trace!("Validating signature: {:02x?}", signature.as_ref());

        // Validate primary types immediately if pubkey is known
        if !flags.contains(Flags::SECONDARY) {
            // Lookup public key
            if let Some(keys) = key_source.keys(&id) {
                // Check ID matches key
                if id != crypto::hash(&keys.pub_key).unwrap() {
                    return Err(Error::KeyIdMismatch);
                }

                // Perform verification
                verified = validate(&keys, &id, kind, flags, &signature, container.signed())?;

                // Stop processing if signature is invalid
                if !verified {
                    info!("Invalid signature with known pubkey");
                    return Err(Error::InvalidSignature);
                }
            }
        }

        trace!("Fetching public options");

        // Fetch public options
        let mut peer_id = None;
        let mut pub_key = None;
        let mut parent = None;

        let public_options: Vec<_> = container
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
                    parent = Some(v.sig.clone());
                    None
                }
                _ => Some(o),
            })
            .collect();

        // Look for signing ID
        let signing_id: Id = match (flags.contains(Flags::SECONDARY), &peer_id) {
            (false, _) => Ok(container.id().into()),
            (true, Some(id)) => Ok(id.clone()),
            _ => Err(Error::NoPeerId),
        }?;

        // Fetch public key
        let keys: Option<Keys> = match (key_source.keys(&signing_id), &pub_key) {
            (Some(keys), _) => Some(keys),
            (None, Some(key)) => Some(Keys::new(key.clone())),
            _ => {
                warn!(
                    "Missing public key for message: {:?} signing id: {:?}",
                    header.index(), signing_id
                );
                None
            }
        };

        trace!("Re-validating object");

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

        trace!("Starting decryption");

        let sk = key_source.keys(&id).map(|k| k.sec_key ).flatten();

        let (body, private_options, tag) = match (flags.contains(Flags::ENCRYPTED), sk) {
            // If we're encrypted _and_ we have keys, attempt decryption
            (true, Some(sk)) => {
                let mut cyphertext = container.cyphertext().to_vec();
                let tag = container.tag();

                trace!("Decrypting block: {:?}", cyphertext.hex_dump());
                trace!("Decryption tag: {:?}", tag.hex_dump());

                let _n = crypto::sk_decrypt(&sk, tag, &mut cyphertext)
                    .map_err(|_e| Error::InvalidSignature);

                trace!("Decrypted: {:?}", cyphertext.hex_dump());

                let (opts, _n) = Options::parse_vec(&cyphertext[header.data_len()..])?;

                let body = match header.data_len() {
                    0 => Body::None,
                    _ => Body::Cleartext(cyphertext[..header.data_len()].to_vec()),
                };

                let opts = match opts.len() {
                    0 => PrivateOptions::None,
                    _ => PrivateOptions::Cleartext(opts)
                };

                (body, opts, Some(tag.to_vec()))
            },
            // If we're encrypted and _don't_ have keys, return cyphertexts
            (true, None) => {
                debug!("No secret key found for object from: {}", id);

                let tag = container.tag();

                let body = match header.data_len() {
                    0 => Body::None,
                    _ => Body::Encrypted(container.body().to_vec()),
                };

                let opts = match container.private_options().len() {
                    0 => PrivateOptions::None,
                    _ => PrivateOptions::Encrypted(container.private_options().to_vec())
                };

                (body, opts, Some(tag.to_vec()))
            },
            // If we're not encrypted, return data directly
            _ => {
                let (opts, _n) = Options::parse_vec(container.private_options())?;

                let body = match header.data_len() {
                    0 => Body::None,
                    _ => Body::Cleartext(container.body().to_vec()),
                };

                let opts = match opts.len() {
                    0 => PrivateOptions::None,
                    _ => PrivateOptions::Cleartext(opts)
                };

                (body, opts, None)
            }
        };

        trace!("Parse OK!");

        // Return page and options
        Ok((
            Base {
                id,
                header: Header::new(
                    header.application_id(),
                    header.kind(),
                    header.index(),
                    header.flags(),
                ),
                body,

                private_options,
                public_options,

                parent,
                peer_id: peer_id.clone(),
                public_key: pub_key.clone(),

                tag,
                signature: Some(signature),
                verified,

                raw: Some(container.raw().to_vec()),
            },
            n,
        ))
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]>> Container<T> {
    pub fn encode(buff: T, base: &Base, keys: &Keys) -> (Self, usize) {
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
        let encryption_key = match (flags.contains(Flags::ENCRYPTED), keys.sec_key.as_ref()) {
            (true, Some(k)) => Some(k),
            (true, None) => panic!("Attempted to encrypt object with no secret key"),
            _ => None,
        };

        let encrypted = flags.contains(Flags::ENCRYPTED);
        let sec_key = keys.sec_key.as_ref();

        // Append body
        let bb = match &base.body {
            Body::Cleartext(c) => bb.body(c).unwrap(),
            Body::Encrypted(e) => bb.body(e).unwrap(),
            Body::None => bb.body(&[]).unwrap(),
        };
        
        // Append private options
        let bb = match &base.private_options {
            OptionsList::Cleartext(c) => bb.private_options(c).unwrap(),
            OptionsList::Encrypted(e) => bb.private_options_raw(e).unwrap(),
            OptionsList::None => bb.private_options(&[]).unwrap(),
        };


        // Ensure state is valid and apply encryption
        // TODO: it'd be great to enforce this better via the builder
        let mut bb = match (encrypted, sec_key, &base.body, &base.private_options, &base.tag) {
            // If we're not encrypted, bypass
            (false, _, _, _, _) => bb.public(),
            // If we're holding encrypted data, just re-encode it
            (true, _, Body::Encrypted(_) | Body::None, OptionsList::Encrypted(_) | OptionsList::None, Some(t)) => {
                bb.tag(t).unwrap()
            },
            // If we have keys and a tag, re-encrypt
            (true, Some(sk), Body::Cleartext(_) | Body::None, OptionsList::Cleartext(_) | OptionsList::None, Some(t)) => {
                bb.re_encrypt(sk, t).unwrap()
            },
            // If we have keys but no tag, new encryption
            (true, Some(sk), Body::Cleartext(_) | Body::None, OptionsList::Cleartext(_) | OptionsList::None , None) => {
                bb.encrypt(sk).unwrap()
            },
            // If we have no keys, fail
            (true, _, _, _, _) => {
                panic!("Encrypt failed, no secret key or mismatched clear/cyphertexts");
            },
            _ => panic!("Unexpected encrypt state"),
        };

        // Write public options
        // Add public key option if specified
        if let Some(k) = &base.public_key {
            bb.public_option(&Options::pub_key(k.clone())).unwrap();
        }

        if let Some(s) = &base.parent {
            bb.public_option(&Options::prev_sig(s)).unwrap();
        }

        if let Some(i) = &base.peer_id {
            bb.public_option(&Options::peer_id(i.clone())).unwrap();
        }

        let bb = bb.public_options(&base.public_options()).unwrap();

        // Sign object
        let c = if !flags.contains(Flags::SYMMETRIC_MODE) {
            bb.sign_pk(&private_key).unwrap()
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

            bb.sign_sk(&sec_key).unwrap()
        };

        // Update length
        let len = c.len;

        // Return signed container and length
        (c, len)
    }
}

#[cfg(test)]
mod test {



    
}
