//! Wire provides a container type to map byte data to fixed fields (and vice versa)
//! to support wire encoding and decoding.

#[cfg(feature = "alloc")]
use alloc::prelude::v1::*;

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

impl<'a, T: AsRef<[u8]>> Container<T> {
    /// Parses a data array into a base object using the pub_key and sec_key functions to locate
    /// keys for validation and decyption
    pub fn parse<P, S>(data: T, mut pub_key_s: P, mut sec_key_s: S) -> Result<(Base, usize), Error>
    where
        P: FnMut(&Id) -> Option<PublicKey>,
        S: FnMut(&Id) -> Option<SecretKey>,
    {
        let mut verified = false;

        // Build container over buffer
        let (container, n) = Container::from(data);
        let header = container.header();

        // Fetch page flags
        let flags = header.flags();

        // Fetch page ID
        let id: Id = container.id().into();

        // Fetch signature for page
        let signature: Signature = container.signature().into();

        // Validate primary types immediately if pubkey is known
        if !flags.contains(Flags::SECONDARY) {
            // Lookup public key
            if let Some(key) = (pub_key_s)(&id) {
                // Check ID matches key
                if id != crypto::hash(&key).unwrap() {
                    return Err(Error::KeyIdMismatch);
                }

                // Validate message body against key
                verified = crypto::pk_validate(&key, &signature, container.signed())
                    .map_err(|_e| Error::CryptoError)?;

                // Stop processing if signature is invalid
                if !verified {
                    info!("Invalid signature with known pubkey");
                    return Err(Error::InvalidSignature);
                }
            }
        }

        // Fetch public options
        let mut peer_id = None;
        let mut pub_key = None;
        let mut parent = None;

        let public_options: Vec<_> = container
            .public_options()
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
        let public_key: Option<PublicKey> = match ((pub_key_s)(&signing_id), &pub_key) {
            (Some(key), _) => Some(key),
            (None, Some(key)) => Some(key.clone()),
            _ => {
                warn!(
                    "Missing public key for message: {:?} signing id: {:?}",
                    id, signing_id
                );
                None
            }
        };

        // Late validation for self-signed objects from unknown sources
        match (verified, public_key) {
            (false, Some(public_key)) => {
                // Check ID matches key
                if signing_id != crypto::hash(&public_key).unwrap() {
                    error!("Public key mismatch for object from {:?}", id);
                    return Err(Error::KeyIdMismatch);
                }

                // Verify body
                verified = crypto::pk_validate(&public_key, &signature, container.signed())
                    .map_err(|_e| Error::CryptoError)?;

                // Stop processing on verification error
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

        let mut body_data = container.body().to_vec();
        let mut private_options_data = container.private_options().to_vec();

        // Handle body decryption or parsing
        let body = match (flags.contains(Flags::ENCRYPTED), sec_key_s(&id)) {
            (true, Some(sk)) if body_data.len() > 0 => {
                // Decrypt body
                let n = crypto::sk_decrypt2(&sk, &mut body_data)
                    .map_err(|_e| Error::InvalidSignature)?;
                body_data = (&body_data[..n]).to_vec();

                Body::Cleartext(body_data)
            }
            (true, None) if body_data.len() > 0 => {
                debug!("No encryption key found for data");

                Body::Encrypted(body_data)
            }
            (false, _) if body_data.len() > 0 => Body::Cleartext(body_data),
            _ => Body::None,
        };

        // Handle private_options decryption or parsing
        let private_options = match (flags.contains(Flags::ENCRYPTED), sec_key_s(&id)) {
            (true, Some(sk)) if private_options_data.len() > 0 => {
                // Decrypt private options
                let n = crypto::sk_decrypt2(&sk, &mut private_options_data)
                    .map_err(|_e| Error::InvalidSignature)?;
                private_options_data = (&private_options_data[..n]).to_vec();

                // Decode private options
                let (private_options, _n) = Options::parse_vec(&private_options_data)?;

                PrivateOptions::Cleartext(private_options)
            }
            (true, None) if private_options_data.len() > 0 => {
                debug!("No encryption key found for data");

                PrivateOptions::Encrypted(private_options_data)
            }
            _ => PrivateOptions::None,
        };

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

                signature: Some(signature),
                verified,

                raw: Some(container.raw().to_vec()),
            },
            n,
        ))
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]>> Container<T> {
    pub fn encode(
        buff: T,
        base: &Base,
        signing_key: &PrivateKey,
        encryption_key: Option<&SecretKey>,
    ) -> (Self, usize) {
        // Setup base builder with header and ID
        let bb = Builder::new(buff).id(base.id()).header(base.header());

        // Check encryption key exists if required
        let encryption_key = match (base.flags().contains(Flags::ENCRYPTED), encryption_key) {
            (true, Some(k)) => Some(k),
            (true, None) => panic!("Attempted to encrypt object with no secret key"),
            _ => None,
        };

        // Write body
        let bb = bb.body(base.body(), encryption_key).unwrap();

        // Write private options
        let mut bb = bb
            .private_options(base.private_options(), encryption_key)
            .unwrap();

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

        let opts = OptionsList::<_, &[u8]>::Cleartext(base.public_options());
        let bb = bb.public_options(&opts).unwrap();

        // Sign object
        let c = bb.sign(signing_key).unwrap();
        let len = c.len;

        (c, len)
    }
}

#[cfg(test)]
mod test {}
