//! Container is a type that maps a byte array to fixed fields (and vice versa)
//! for wire encoding.

use byteorder::{ByteOrder, NetworkEndian};

use crate::types::{Id, ID_LEN, Signature, SIGNATURE_LEN, Flags, Kind, PublicKey, PrivateKey, SecretKey};
use crate::base::{Encode, BaseError, Body, Header, PrivateOptions};
use crate::options::{Options, OptionsIter};
use crate::crypto;


const HEADER_LEN: usize = 16;

/// Container object provides base field accessors over an arbitrary (mutable or immutable) buffers
/// See https://lab.whitequark.org/notes/2016-12-13/abstracting-over-mutability-in-rust/ for details
#[derive(Clone, Debug, PartialEq)]
pub struct Container<T: AsRef<[u8]>> {
    buff: T,
}

use crate::base::Base;

/// Offsets for fixed fields in the protocol container
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

impl <'a, T: AsRef<[u8]>> Container<T> {
    /// Create a new container object from an existing buffer
    /// This parses the header and splits the data into fields to simplify access
    pub fn from(buff: T) -> (Self, usize) {
        let c = Container{buff};
        let n = c.len();
        (c, n)
    }

    pub fn protocol_version(&self) -> Kind {
        let data = self.buff.as_ref();
        
        Kind::from(NetworkEndian::read_u16(&data[offsets::PROTO_VERSION..]))
    }

    pub fn application_id(&self) -> u16 {
        let data = self.buff.as_ref();
        
        NetworkEndian::read_u16(&data[offsets::APPLICATION_ID..])
    }

    pub fn kind(&self) -> Kind {
        let data = self.buff.as_ref();
        
        Kind::from(NetworkEndian::read_u16(&data[offsets::OBJECT_KIND..]))
    }

    pub fn flags(&self) -> Flags {
        let data = self.buff.as_ref();

        let flags_raw = NetworkEndian::read_u16(&data[offsets::FLAGS..]);
        
        Flags::from_bits(flags_raw).unwrap()
    }

    pub fn index(&self) -> u16 {
        let data = self.buff.as_ref();
        
        NetworkEndian::read_u16(&data[offsets::INDEX..])
    }

    pub fn data_len(&self) -> usize {
        let data = self.buff.as_ref();
        
        NetworkEndian::read_u16(&data[offsets::DATA_LEN..]) as usize
    }

    pub fn private_options_len(&self) -> usize {
        let data = self.buff.as_ref();
        
        NetworkEndian::read_u16(&data[offsets::PRIVATE_OPTIONS_LEN..]) as usize
    }

    pub fn public_options_len(&self) -> usize {
        let data = self.buff.as_ref();
        
        NetworkEndian::read_u16(&data[offsets::PUBLIC_OPTIONS_LEN..]) as usize
    }

    pub fn id(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        &data[offsets::ID..offsets::BODY]
    }

    /// Return the body of data
    pub fn body(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        let n = HEADER_LEN + ID_LEN;
        let s = self.data_len();
        &data[n..n+s]
    }

    /// Return the private options section data
    pub fn private_options(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        let n = HEADER_LEN + ID_LEN + self.data_len();
        let s = self.private_options_len();
        &data[n..n+s]
    }

    /// Return the public options section data
    pub fn public_options(&self) -> impl Iterator<Item=Options> + '_ {
        let data = self.buff.as_ref();
        
        let n = HEADER_LEN + ID_LEN + self.data_len() + self.private_options_len();
        let s = self.public_options_len();
        OptionsIter::new(&data[n..n+s])
    }

    /// Return the signed portion of the message for signing or verification
    pub fn signed(&self) -> &[u8] {
        let data = self.buff.as_ref();
        let n = self.len();

        &data[..n-SIGNATURE_LEN]
    }

    /// Return the signature portion of the message for verification
    pub fn signature(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        let n = self.len() - SIGNATURE_LEN;
        let s = SIGNATURE_LEN;

        &data[n..n+s]
    }

    pub fn len(&self) -> usize {
        HEADER_LEN + ID_LEN + self.data_len() + self.private_options_len() + self.public_options_len() + SIGNATURE_LEN
    }

    /// Verify the contents of a given container
    /// This calls the provided verifier with the id, body, and signature and forwards the result to the caller
    pub fn verify<V, E>(&self, mut verifier: V) -> Result<bool, E> 
    where
        V: FnMut(&Id, &Signature, &[u8]) -> Result<bool, E>
    {
        let id: Id = self.id().into();
        let data = self.signed();
        let sig: Signature = self.signature().into();

        (verifier)(&id, &sig, &data)
    }

    pub fn raw(&self) -> &[u8] {
        let data = self.buff.as_ref();
        let len = self.len();
        
        &data[0..len]
    }

}

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

        // Fetch page flags
        let flags = container.flags();

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
                Options::PeerId(v) => { peer_id = Some(v.peer_id); Some(o) },
                Options::PubKey(v) => { pub_key = Some(v.public_key); None },
                Options::PrevSig(v) => { parent = Some(v.sig); None }
                _ => Some(o),
            }
        })
        .collect();

        trace!("public options: {:?}", public_options);

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
                header: Header::new(container.application_id(), container.kind(), container.index(), container.flags()),
                body,
                private_options,
                public_options,
                parent,
                signature: Some(signature),

                public_key: Some(public_key),
                raw: Some(container.raw().to_vec()),
            },
            n,
        ))
    }
}

impl <'a, T: AsRef<[u8]> + AsMut<[u8]>> Container<T> {
    /// Encode a a higher level base object into a container using the provided buffer
    /// This encodes the base object into the buff and constructs a container from this encoded object
    pub fn encode(mut buff: T, base: &Base, signing_key: &PrivateKey, encryption_key: Option<&SecretKey>) -> (Self, usize) {
        let data = buff.as_mut();

        // Skip header until sizes are known
        let mut n = HEADER_LEN;

        // Write ID
        let id = &mut data[n..n+ID_LEN];
        id.clone_from_slice(base.id());
        n += ID_LEN;

        // Check encryption key exists if required
        let encryption_key = match (base.flags().contains(Flags::ENCRYPTED), encryption_key) {
            (true, Some(k)) => Some(k),
            (true, None) => panic!("Attempted to encrypt object with no secret key"),
            _ => None,
        };

        // Write body
        let body_len = match (&base.body, encryption_key) {
            (Body::Cleartext(c), None) => {
                (&mut data[n..n+c.len()]).clone_from_slice(c);
                c.len()
            },
            (Body::Cleartext(c), Some(secret_key)) => {
                (&mut data[n..n+c.len()]).clone_from_slice(c);
                crypto::sk_encrypt2(&secret_key, &mut data[n..], c.len()).unwrap()
            },
            (Body::Encrypted(e), _) => {
                (&mut data[n..n+e.len()]).clone_from_slice(e);
                e.len()
            },
            (Body::None, _) => {
                0
            }
        };
        n += body_len;

        // Write private options
        let private_options_len = match (&base.private_options, encryption_key) {
            (PrivateOptions::Cleartext(c), None) => {
                Options::encode_vec(c, &mut data[n..]).expect("error encoding private options")
            },
            (PrivateOptions::Cleartext(c), Some(secret_key)) => {
                let encoded_len = Options::encode_vec(c, &mut data[n..]).expect("error encoding private options");
                crypto::sk_encrypt2(&secret_key, &mut data[n..], encoded_len).unwrap()
            },
            (PrivateOptions::Encrypted(e), _) => {
                (&mut data[n..n+e.len()]).clone_from_slice(e);
                e.len()
            },
            (PrivateOptions::None, _) => 0,
        };
        n += private_options_len;

        let mut public_options = vec![];
        
        // Add public key option if specified
        if let Some(k) = base.public_key {
            public_options.push(Options::pub_key(k));
        }

        if let Some(s) = base.parent {
            public_options.push(Options::prev_sig(&s));
        }
        
        public_options.append(&mut base.public_options().to_vec());

        // Write public options
        let public_options_len = { Options::encode_vec(&public_options, &mut data[n..]).expect("error encoding public options") };
        n += public_options_len;

        // Write header
        let header = &mut data[..HEADER_LEN];
        // TODO: un-unwrap this and bubble error?
        // OR, change to infallible impl
        base.header().encode(header).expect("error encoding header");

        // Write lengths
        NetworkEndian::write_u16(&mut header[offsets::DATA_LEN..], body_len as u16);
        NetworkEndian::write_u16(&mut header[offsets::PRIVATE_OPTIONS_LEN..], private_options_len as u16);
        NetworkEndian::write_u16(&mut header[offsets::PUBLIC_OPTIONS_LEN..], public_options_len as u16);

        // Reserve and write signature
        let sig = crypto::pk_sign(signing_key, &data[..n]).unwrap();

        let signature_data = &mut data[n..n+SIGNATURE_LEN];
        signature_data.copy_from_slice(&sig);
        n += SIGNATURE_LEN;

        (Container{buff}, n)
    }
}

#[cfg(test)]
mod test {

}

