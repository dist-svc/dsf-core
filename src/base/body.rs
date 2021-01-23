//! Base object is a common owned object that is used to represent pages / messages / data
//! and can be encoded and decoded for wire communication.

#[cfg(feature = "alloc")]
use alloc::prelude::v1::*;

use crate::base::Header;
use crate::error::Error;
use crate::net;
use crate::options::Options;
use crate::page;
use crate::types::*;
use crate::wire::Container;

#[derive(Clone, Debug)]
pub struct Base {
    /// Page or Object Identifier
    pub(crate) id: Id,

    /// Header contains object parsing information and flags
    pub(crate) header: Header,

    /// Body contains arbitrary service data for Pages, Blocks, and Messages
    pub(crate) body: Body,

    /// Private options supports the addition of options that are only visible
    /// to authorized service consumers
    pub(crate) private_options: PrivateOptions,

    /// Public options provide a simple mechanism for extension of objects
    pub(crate) public_options: Vec<Options>,

    /// Page parent / previous page link
    /// Used for constructing a hash-chain of published objects and included as a public option
    /// This is automatically included / extracted to simplify higher level parsing
    pub(crate) parent: Option<Signature>,

    /// Service public key
    /// Used to support self-signed objects and included as a public option
    /// This is automatically included / extracted to simplify higher level parsing
    pub(crate) public_key: Option<PublicKey>,

    /// Object PeerID
    /// Used to support secondary objects and included as a public option
    /// This is automatically included / extracted to simplify higher level parsing
    pub(crate) peer_id: Option<Id>,

    /// Object signature
    pub(crate) signature: Option<Signature>,

    /// Verified flag indicates object signature verification status
    pub(crate) verified: bool,

    /// Raw object container, used to avoid re-encoding objects
    pub(crate) raw: Option<Vec<u8>>,
}

/// Options for constructing base objects
pub struct BaseOptions {
    /// Private / encrypted options
    pub private_options: PrivateOptions,
    /// Public / plaintext options
    pub public_options: Vec<Options>,
    /// Parent object signature
    pub parent: Option<Signature>,
    /// Parent service public key
    pub public_key: Option<PublicKey>,
    /// Peer ID for secondary object mapping
    pub peer_id: Option<Id>,
    /// Object signature
    pub signature: Option<Signature>,
    /// Raw / pre-encoded object data
    pub raw: Option<Vec<u8>>,
}

impl Default for BaseOptions {
    fn default() -> Self {
        Self {
            private_options: PrivateOptions::None,
            public_options: vec![],
            parent: None,
            public_key: None,
            peer_id: None,
            signature: None,
            raw: None,
        }
    }
}

impl BaseOptions {
    pub fn append_public_option(&mut self, o: Options) -> &mut Self {
        self.public_options.push(o);
        self
    }

    pub fn append_private_option(&mut self, o: Options) -> &mut Self {
        match &mut self.private_options {
            PrivateOptions::Cleartext(opts) => opts.push(o),
            _ => self.private_options = PrivateOptions::Cleartext(vec![o]),
        }
        self
    }
}

impl PartialEq for Base {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.header == other.header
            && self.body == other.body
            && self.private_options == other.private_options
            && self.public_options == other.public_options
            && self.parent == other.parent
            && self.public_key == other.public_key
            && self.peer_id == other.peer_id
            && self.signature == other.signature
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum NewBody<T: ImmutableData> {
    Cleartext(T),
    Encrypted(T),
    None,
}

impl Body {
    /// Decrypt an object body with the provided secret key
    pub fn decrypt(&mut self, secret_key: Option<&SecretKey>) -> Result<(), Error> {
        let body = match (&self, &secret_key) {
            (NewBody::Cleartext(b), _) => b.to_vec(),
            (NewBody::Encrypted(e), Some(sk)) => {
                let mut d = e.to_vec();

                let n = match crate::crypto::sk_decrypt2(sk, &mut d) {
                    Ok(n) => n,
                    Err(_) => return Err(Error::SecretKeyMismatch),
                };

                d.truncate(n);

                d
            }
            _ => return Err(Error::NoSecretKey),
        };

        *self = Self::Cleartext(body);

        Ok(())
    }
}

/// Body may be empty, encrypted, or Cleartext
// TODO: move NewBody from wire to here, propagate generic types
pub type Body = NewBody<Vec<u8>>;

impl From<Vec<u8>> for Body {
    fn from(o: Vec<u8>) -> Self {
        if o.len() > 0 {
            Body::Cleartext(o)
        } else {
            Body::None
        }
    }
}

impl From<Option<Body>> for Body {
    fn from(o: Option<Body>) -> Self {
        match o {
            Some(b) => b,
            None => Body::None,
        }
    }
}

//pub type OptionsList = crate::wire::builder::OptionsList<Vec<Options>, Vec<u8>>;
pub type PrivateOptions = crate::options::OptionsList<Vec<Options>, Vec<u8>>;

impl From<Vec<Options>> for PrivateOptions {
    fn from(o: Vec<Options>) -> Self {
        if o.len() > 0 {
            PrivateOptions::Cleartext(o)
        } else {
            PrivateOptions::None
        }
    }
}

impl PrivateOptions {
    pub fn append(&mut self, o: Options) {
        match self {
            PrivateOptions::Cleartext(opts) => opts.push(o),
            PrivateOptions::None => *self = PrivateOptions::Cleartext(vec![o]),
            _ => panic!("attmepting to append private options to encrypted object"),
        }
    }
}

pub enum Parent<'a, 'b, 'c> {
    None,
    Page(&'a page::Page),
    Request(&'b net::Request),
    Response(&'c net::Response),
}

impl Base {
    /// Create a new base object the provided options
    pub fn new(id: Id, header: Header, body: Body, options: BaseOptions) -> Self {
        Self {
            id,
            header,
            body,
            private_options: options.private_options,
            public_options: options.public_options,
            parent: options.parent,
            public_key: options.public_key,
            peer_id: options.peer_id,
            signature: options.signature,
            verified: false,
            raw: options.raw,
        }
    }

    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn flags(&self) -> Flags {
        self.header.flags()
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn public_options(&self) -> &[Options] {
        &self.public_options
    }

    pub fn private_options(&self) -> &PrivateOptions {
        &self.private_options
    }

    pub fn signature(&self) -> &Option<Signature> {
        &self.signature
    }

    pub fn set_signature(&mut self, sig: Signature) {
        self.signature = Some(sig);
    }

    pub fn append_public_option(&mut self, o: Options) {
        self.public_options.push(o);
    }

    pub fn append_private_option(&mut self, o: Options) {
        match &mut self.private_options {
            PrivateOptions::Cleartext(opts) => opts.push(o),
            PrivateOptions::None => self.private_options = PrivateOptions::Cleartext(vec![o]),
            _ => panic!("attmepting to append private options to encrypted object"),
        }
    }

    pub fn clean(&mut self) {}
}

// TODO: move these to the options module?
impl Base {
    pub fn pub_key_option(options: &[Options]) -> Option<PublicKey> {
        options.iter().find_map(|o| match o {
            Options::PubKey(pk) => Some(pk.public_key.clone()),
            _ => None,
        })
    }

    pub fn peer_id_option(options: &[Options]) -> Option<Id> {
        options.iter().find_map(|o| match o {
            Options::PeerId(peer_id) => Some(peer_id.peer_id.clone()),
            _ => None,
        })
    }

    pub fn issued_option(options: &[Options]) -> Option<DateTime> {
        options.iter().find_map(|o| match o {
            Options::Issued(t) => Some(t.when),
            _ => None,
        })
    }

    pub fn expiry_option(options: &[Options]) -> Option<DateTime> {
        options.iter().find_map(|o| match o {
            Options::Expiry(t) => Some(t.when),
            _ => None,
        })
    }

    pub fn prev_sig_option(options: &[Options]) -> Option<Signature> {
        options.iter().find_map(|o| match o {
            Options::PrevSig(s) => Some(s.sig.clone()),
            _ => None,
        })
    }

    pub fn address_option(options: &[Options]) -> Option<Address> {
        options.iter().find_map(|o| match o {
            Options::IPv4(addr) => Some(addr.clone().into()),
            Options::IPv6(addr) => Some(addr.clone().into()),
            _ => None,
        })
    }

    pub fn raw(&self) -> &Option<Vec<u8>> {
        &self.raw
    }

    pub fn set_raw(&mut self, raw: Vec<u8>) {
        self.raw = Some(raw);
    }
}

impl Base {
    /// Parses a data array into a base object using the pubkey_source to locate
    /// a key for validation
    pub fn parse<'a, P, S, T: AsRef<[u8]>>(
        data: T,
        pub_key_s: P,
        sec_key_s: S,
    ) -> Result<(Base, usize), Error>
    where
        P: FnMut(&Id) -> Option<PublicKey>,
        S: FnMut(&Id) -> Option<SecretKey>,
    {
        Container::parse(data, pub_key_s, sec_key_s)
    }
}

impl Base {
    pub fn encode<'a, T: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        signing_key: Option<&PrivateKey>,
        encryption_key: Option<&SecretKey>,
        mut buff: T,
    ) -> Result<usize, Error> {
        // Short circuit if raw object is available
        if let Some(raw) = &self.raw {
            let d = buff.as_mut();

            &mut d[0..raw.len()].copy_from_slice(&raw);

            return Ok(raw.len());
        }

        let signing_key = match signing_key {
            Some(k) => k,
            None => return Err(Error::NoPrivateKey),
        };

        // Build container and encode / encrypt / sign page
        let (container, n) = Container::encode(buff, &self, signing_key, encryption_key);

        // Update base object signature
        self.set_signature(container.signature().into());

        Ok(n)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::base::*;
    use crate::types::PageKind;

    use crate::crypto;

    fn setup() -> (Id, PublicKey, PrivateKey, SecretKey) {
        let (pub_key, pri_key) =
            crypto::new_pk().expect("Error generating new public/private key pair");
        let id = crypto::hash(&pub_key)
            .expect("Error generating new ID")
            .into();
        let sec_key = crypto::new_sk().expect("Error generating new secret key");
        (id, pub_key, pri_key, sec_key)
    }

    #[test]
    fn encode_decode_primary_page() {
        let (id, pub_key, pri_key, _sec_key) = setup();

        let header = Header {
            kind: PageKind::Generic.into(),
            ..Default::default()
        };
        let data = vec![1, 2, 3, 4, 5, 6, 7];

        let mut page = Base::new(id, header, Body::Cleartext(data), BaseOptions::default());

        let mut buff = vec![0u8; 1024];
        let n = page
            .encode(Some(&pri_key), None, &mut buff)
            .expect("Error encoding page");

        let (mut decoded, m) = Base::parse(&buff[..n], |_id| Some(pub_key.clone()), |_id| None)
            .expect("Error decoding page");

        decoded.clean();

        assert_eq!(page, decoded);
        assert_eq!(n, m);
    }

    #[test]
    fn encode_decode_secondary_page() {
        let (id, pub_key, pri_key, _sec_key) = setup();

        let header = Header {
            kind: PageKind::Replica.into(),
            flags: Flags::SECONDARY,
            ..Default::default()
        };
        let data = vec![1, 2, 3, 4, 5, 6, 7];

        let mut page = Base::new(
            id.clone(),
            header,
            Body::Cleartext(data),
            BaseOptions {
                peer_id: Some(id.clone()),
                public_key: Some(pub_key.clone()),
                ..Default::default()
            },
        );

        let mut buff = vec![0u8; 1024];
        let n = page
            .encode(Some(&pri_key), None, &mut buff)
            .expect("Error encoding page");
        page.raw = Some(buff[..n].to_vec());

        let (mut decoded, m) = Base::parse(&buff[..n], |_id| Some(pub_key.clone()), |_id| None)
            .expect("Error decoding page with known public key");

        decoded.clean();
        assert_eq!(page, decoded);
        assert_eq!(n, m);

        let (mut decoded, m) = Base::parse(&buff[..n], |_id| None, |_id| None)
            .expect("Error decoding page with unknown public key");

        decoded.clean();
        assert_eq!(page, decoded);
        assert_eq!(n, m);
    }

    #[test]
    fn encode_decode_encrypted_page() {
        let (id, pub_key, pri_key, sec_key) = setup();

        let header = Header {
            kind: PageKind::Generic.into(),
            flags: Flags::ENCRYPTED,
            ..Default::default()
        };
        let data = vec![1, 2, 3, 4, 5, 6, 7];

        let mut page = Base::new(id, header, Body::Cleartext(data), BaseOptions::default());

        let mut buff = vec![0u8; 1024];
        let n = page
            .encode(Some(&pri_key), Some(&sec_key), &mut buff)
            .expect("Error encoding page");

        let (mut decoded, m) = Base::parse(
            &buff[..n],
            |_id| Some(pub_key.clone()),
            |_id| Some(sec_key.clone()),
        )
        .expect("Error decoding page");

        decoded.clean();

        assert_eq!(page, decoded);
        assert_eq!(n, m);
    }
}
