//! Wire provides a container type to map byte data to fixed fields (and vice versa)
//! to support wire encoding and decoding.


use crate::types::*;
use crate::base::{BaseError, Body, Header, PrivateOptions};
use crate::options::{Options, OptionsList};
use crate::crypto;

use crate::base::Base;

/// Header provides a low-cost header abstraction for encoding/decoding
pub mod header;

/// Builder provides methods to construct a container using a mutable buffer and base types
pub mod builder;
pub use builder::Builder;

/// Container provides methods to access underlying wire object fields
pub mod container;
pub use container::Container;



impl <'a, T: AsRef<[u8]>> Container<T> {
    /// Parses a data array into a base object using the pub_key and sec_key functions to locate 
    /// keys for validation and decyption
    pub fn parse<P, S>(data: T, mut pub_key_s: P, mut sec_key_s: S) -> Result<(Base, usize), BaseError>
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
                    return Err(BaseError::PublicKeyIdMismatch);
                }

                // Validate message body against key
                verified = crypto::pk_validate(&key, &signature, container.signed()).map_err(|_e| BaseError::ValidateError )?;

                // Stop processing if signature is invalid
                if !verified {
                    info!("Invalid signature with known pubkey");
                    return Err(BaseError::InvalidSignature);
                }
            }
        }

        // Fetch public options
        let mut peer_id = None;
        let mut pub_key = None;
        let mut parent = None;

        let public_options: Vec<_> = container.public_options()
        .filter_map(|o| {
            match &o {
                Options::PeerId(v) => { peer_id = Some(v.peer_id); None },
                Options::PubKey(v) => { pub_key = Some(v.public_key); None },
                Options::PrevSig(v) => { parent = Some(v.sig); None }
                _ => Some(o),
            }
        })
        .collect();

        // Look for signing ID
        let signing_id: Id = match (flags.contains(Flags::SECONDARY), peer_id) {
            (false, _) => Ok(container.id().into()),
            (true, Some(id)) => Ok(id),
            _ => Err(BaseError::NoPeerId), 
        }?;

        // Fetch public key
        let public_key: PublicKey = match ((pub_key_s)(&signing_id), pub_key) {
            (Some(key), _) => Ok(key),
            (None, Some(key)) => Ok(key),
            _ => {
                warn!("Missing public key for message: {:?} signing id: {:?}", id, signing_id);
                Err(BaseError::NoPublicKey)
            },
        }?;

        // Late validation for self-signed objects from unknown sources
        if !verified {
            // Check ID matches key
            if signing_id != crypto::hash(&public_key).unwrap() {
                return Err(BaseError::PublicKeyIdMismatch);
            }

            // Verify body
            verified = crypto::pk_validate(&public_key, &signature, container.signed()).map_err(|_e| BaseError::ValidateError )?;

            // Stop processing on verification error
            if !verified {
                info!("Invalid signature for self-signed object");
                return Err(BaseError::InvalidSignature);
            }
        }

        let mut body_data = container.body().to_vec();
        let mut private_options_data = container.private_options().to_vec();

        // Handle body decryption or parsing
        let body = match (flags.contains(Flags::ENCRYPTED), sec_key_s(&id)) {
            (true, Some(sk)) if body_data.len() > 0 => {
                // Decrypt body
                let n = crypto::sk_decrypt2(&sk, &mut body_data)
                        .map_err(|_e| BaseError::InvalidSignature )?;
                body_data = (&body_data[..n]).to_vec();

                Body::Cleartext(body_data)
            },
            (true, None) if body_data.len() > 0 => {
                debug!("No encryption key found for data");

                Body::Encrypted(body_data)
            },
            (false, _) if body_data.len() > 0 => {
                Body::Cleartext(body_data)
            },
            _ => {
                Body::None
            }
        };

        // Handle private_options decryption or parsing
        let private_options = match (flags.contains(Flags::ENCRYPTED), sec_key_s(&id)) {
            (true, Some(sk)) if private_options_data.len() > 0 => {

                // Decrypt private options
                let n = crypto::sk_decrypt2(&sk, &mut private_options_data)
                        .map_err(|_e| BaseError::InvalidSignature )?;
                private_options_data = (&private_options_data[..n]).to_vec();

                // Decode private options
                let (private_options, _n)= Options::parse_vec(&private_options_data)?;

                PrivateOptions::Cleartext(private_options)
            },
            (true, None) if private_options_data.len() > 0 => {
                debug!("No encryption key found for data");

                PrivateOptions::Encrypted(private_options_data)
            },
            _ => {
                PrivateOptions::None
            },
        };

        // Return page and options
        Ok((
            Base {
                id: id,
                header: Header::new(header.application_id(), header.kind(), header.index(), header.flags()),
                body,
                
                private_options,
                public_options,

                parent,
                peer_id,
                public_key: pub_key,

                signature: Some(signature),

                
                raw: Some(container.raw().to_vec()),
            },
            n,
        ))
    }
}


impl <'a, T: AsRef<[u8]> + AsMut<[u8]>> Container<T> {
    pub fn encode(buff: T, base: &Base, signing_key: &PrivateKey, encryption_key: Option<&SecretKey>) -> (Self, usize) {

        // Setup base builder with header and ID
        let bb = Builder::new(buff)
            .id(base.id())
            .header(base.header());

        // Check encryption key exists if required
        let encryption_key = match (base.flags().contains(Flags::ENCRYPTED), encryption_key) {
            (true, Some(k)) => Some(k),
            (true, None) => panic!("Attempted to encrypt object with no secret key"),
            _ => None,
        };

        // Write body
        let bb = bb.body(base.body(), encryption_key).unwrap();

        // Write private options
        let mut bb = bb.private_options(base.private_options(), encryption_key).unwrap();

        // Write public options
        // Add public key option if specified
        if let Some(k) = base.public_key {
            bb.public_option(&Options::pub_key(k)).unwrap();
        }

        if let Some(s) = base.parent {
            bb.public_option(&Options::prev_sig(&s)).unwrap();
        }

        if let Some(i) = base.peer_id {
            bb.public_option(&Options::peer_id(i)).unwrap();
        }

        let opts = OptionsList::<_, &[u8]>::Cleartext(base.public_options());
        let bb = bb.public_options(&opts).unwrap();

        // Sign object
        let c= bb.sign(signing_key).unwrap();
        let len = c.len;

        (c, len)
    }
}



#[cfg(test)]
mod test {

}

