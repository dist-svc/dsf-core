//! Base object is a common owned object that is used to represent pages / messages / data
//! and can be encoded and decoded for wire communication.

use std::net::{SocketAddr};

use crate::types::{Id, Signature, Flags, Kind, PublicKey, PrivateKey, SecretKey, Address, DateTime};
use crate::base::Header;
use crate::options::{Options, OptionsError};
use crate::wire::Container;


#[derive(Clone, Builder, Debug)]
pub struct Base {
    /// Page or Object Identifier
    pub(crate) id:             Id,

    /// Header contains object parsing information and flags
    pub(crate) header:         Header,

    /// Body contains arbitrary service data for Pages, Blocks, and Messages
    #[builder(default = "Body::None")]
    pub(crate) body:           Body,

    /// Private options supports the addition of options that are only visible
    /// to authorized service consumers
    #[builder(default = "PrivateOptions::None")]
    pub(crate) private_options: PrivateOptions,

    /// Public options provide a simple mechanism for extension of objects
    #[builder(default = "vec![]")]
    pub(crate) public_options: Vec<Options>,

    /// Page parent / previous page link
    /// Used for constructing a hash-chain of published objects
    /// Included as a Public Option
    #[builder(default = "None")]
    pub(crate) parent:      Option<Signature>,
    
    /// Service public key
    /// Used to support self-signed objects
    /// Included as a Public Option
    #[builder(default = "None")]
    pub(crate) public_key:      Option<PublicKey>,

    /// Object signature
    #[builder(default = "None")]
    pub(crate) signature:      Option<Signature>,

    /// Raw object container, used to avoid re-encoding objects
    #[builder(default = "None")]
    pub(crate) raw: Option<Vec<u8>>,
}

impl PartialEq for Base {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id &&
        self.header == other.header &&
        self.body == other.body &&
        self.private_options == other.private_options &&
        self.public_options == other.public_options &&
        self.parent == other.parent &&
        self.signature == other.signature 
    }
}

/// Body may be empty, encrypted, or Cleartext
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum Body {
    None,
    Encrypted(Vec<u8>),
    Cleartext(Vec<u8>),
}

impl From<Vec<u8>> for Body {
    fn from(o: Vec<u8>) -> Self {
        if o.len() > 0 {
            Body::Cleartext(o)
        } else {
            Body::None
        }
    }
}

/// Private options may be empty, encrypted, or Cleartext
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum PrivateOptions {
    None,
    Encrypted(Vec<u8>),
    Cleartext(Vec<Options>),
}

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

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum BaseError {
    Io,
    Options(OptionsError),
    InvalidSignature,
    NoPublicKey,
    NoPrivateKey,
    NoPeerId,
    ValidateError,
    DecryptError,
    NoDecryptionKey,
    PublicKeyIdMismatch,
}

use crate::page;
use crate::net;

pub enum Parent<'a, 'b, 'c> {
    None,
    Page(&'a page::Page),
    Request(&'b net::Request),
    Response(&'c net::Response),
}

impl From<OptionsError> for BaseError {
    fn from(o: OptionsError) -> BaseError {
        BaseError::Options(o)
    }
}

impl From<std::io::Error> for BaseError {
    fn from(e: std::io::Error) -> BaseError {
        error!("io error: {}", e);
        BaseError::Io
    }
}

impl BaseBuilder {
    pub fn base(&mut self, id: Id, application_id: u16, kind: Kind, index: u16, flags: Flags) -> &mut Self {
        let header = Header::new(application_id, kind, index, flags);
        self.id = Some(id);
        self.header = Some(header);
        self
    }

    pub fn append_public_option(&mut self, o: Options) -> &mut Self {
        match &mut self.public_options {
            Some(opts) => opts.push(o),
            None => self.public_options = Some(vec![o]),
        }
        self
    }

     pub fn append_private_option(&mut self, o: Options) -> &mut Self {
        match &mut self.private_options {
            Some(PrivateOptions::Cleartext(opts)) => opts.push(o),
            _ => self.private_options = Some(PrivateOptions::Cleartext(vec![o])),
        }
        self
    }
}


impl Base {
    pub fn new(id: Id, application_id: u16, kind: Kind, flags: Flags, version: u16, body: Body, public_options: Vec<Options>, private_options: PrivateOptions) -> Base {
        let header = Header::new(application_id, kind, version, flags);
        
        Base{id, header, body, public_options, private_options, parent: None, signature: None, public_key: None, raw: None}
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

    pub fn clean(&mut self) {
        self.public_key = None;
    }
}

// TODO: move these to the options module?
impl Base {


    pub fn pub_key_option(options: &[Options]) -> Option<PublicKey> {
        options.iter().find_map(|o| {
            match o { 
                Options::PubKey(pk) => Some(pk.public_key.clone()),
                 _ => None 
            } 
        })
    }

    pub fn peer_id_option(options: &[Options]) -> Option<Id> {
        options.iter().find_map(|o| {
            match o { 
                Options::PeerId(peer_id) => Some(peer_id.peer_id.clone()),
                 _ => None 
            } 
        })
    }

    pub fn issued_option(options: &[Options]) -> Option<DateTime> {
        options.iter().find_map(|o| {
            match o { 
                Options::Issued(t) => Some(t.when),
                 _ => None 
            } 
        })
    }

    pub fn expiry_option(options: &[Options]) -> Option<DateTime> {
        options.iter().find_map(|o| {
            match o { 
                Options::Expiry(t) => Some(t.when),
                 _ => None 
            } 
        })
    }


    pub fn prev_sig_option(options: &[Options]) -> Option<Signature> {
        options.iter().find_map(|o| {
            match o { 
                Options::PrevSig(s) => Some(s.sig),
                 _ => None 
            } 
        })
    }

    pub fn address_option(options: &[Options]) -> Option<Address> {
        options.iter().find_map(|o| {
            match o { 
                Options::IPv4(addr) => Some(SocketAddr::V4(*addr)),
                Options::IPv6(addr) => Some(SocketAddr::V6(*addr)),
                 _ => None 
            } 
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
    pub fn parse<'a, P, S, T: AsRef<[u8]>>(data: T, pub_key_s: P, sec_key_s: S) -> Result<(Base, usize), BaseError>
    where 
        P: FnMut(&Id) -> Option<PublicKey>,
        S: FnMut(&Id) -> Option<SecretKey>,
    {
        Container::parse(data, pub_key_s, sec_key_s)
    }
}

use std::io::Write;

impl Base {
    pub fn encode<'a, T: AsRef<[u8]> + AsMut<[u8]>>(&mut self, signing_key: Option<&PrivateKey>, encryption_key: Option<&SecretKey>, mut buff: T) -> Result<usize, BaseError> {
        // Short circuit if raw object is available
        if let Some(raw) = &self.raw {
            let mut d = buff.as_mut();

            d.write(&raw)?;

            return Ok(raw.len())
        }

        let signing_key = match signing_key {
            Some(k) => k,
            None => return Err(BaseError::NoPrivateKey),
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
        let (pub_key, pri_key) = crypto::new_pk().expect("Error generating new public/private key pair");
        let id = crypto::hash(&pub_key).expect("Error generating new ID").into();
        let sec_key = crypto::new_sk().expect("Error generating new secret key");
        (id, pub_key, pri_key, sec_key)
    }

    #[test]
    fn encode_decode_primary_page() {
        let (id, pub_key, pri_key, _sec_key) = setup();

        let header = HeaderBuilder::default().kind(PageKind::Generic.into()).build().expect("Error building page header");
        let data = vec![1, 2, 3, 4, 5, 6, 7];

        let mut page = BaseBuilder::default().id(id).header(header).body(Body::Cleartext(data)).build().expect("Error building page");

        let mut buff = vec![0u8; 1024];
        let n = page.encode(Some(&pri_key), None, &mut buff).expect("Error encoding page");

        let (mut decoded, m) = Base::parse(&buff[..n], |_id| Some(pub_key), |_id| None ).expect("Error decoding page");

        decoded.clean();

        assert_eq!(page, decoded);
        assert_eq!(n, m);
    }

        #[test]
    fn encode_decode_secondary_page() {
        let (id, pub_key, pri_key, _sec_key) = setup();
        let fake_id = crypto::hash(&[0x00, 0x11, 0x22]).unwrap();

        let header = HeaderBuilder::default().flags(Flags::SECONDARY).kind(PageKind::Replica.into()).build().expect("Error building page header");
        let data = vec![1, 2, 3, 4, 5, 6, 7];

        let mut page = BaseBuilder::default().id(fake_id).header(header).body(Body::Cleartext(data)).public_options(vec![Options::peer_id(id.clone())]).public_key(Some(pub_key.clone())).build().expect("Error building page");

        let mut buff = vec![0u8; 1024];
        let n = page.encode(Some(&pri_key), None, &mut buff).expect("Error encoding page");

        let (mut decoded, m) = Base::parse(&buff[..n], |_id| Some(pub_key), |_id| None ).expect("Error decoding page with known public key");

        decoded.clean();
        assert_eq!(page, decoded);
        assert_eq!(n, m);

        let (mut decoded, m) = Base::parse(&buff[..n], |_id| None, |_id| None ).expect("Error decoding page with unknown public key");

        decoded.clean();
        assert_eq!(page, decoded);
        assert_eq!(n, m);
    }

    #[test]
    fn encode_decode_encrypted_page() {
        let (id, pub_key, pri_key, sec_key) = setup();

        let header = HeaderBuilder::default().flags(Flags::ENCRYPTED).kind(PageKind::Generic.into()).build().expect("Error building page header");
        let data = vec![1, 2, 3, 4, 5, 6, 7];

        let mut page = BaseBuilder::default().id(id).header(header).body(Body::Cleartext(data)).build().expect("Error building page");

        let mut buff = vec![0u8; 1024];
        let n = page.encode(Some(&pri_key), Some(&sec_key), &mut buff).expect("Error encoding page");

        let (mut decoded, m) = Base::parse(&buff[..n], |_id| Some(pub_key), |_id| Some(sec_key) ).expect("Error decoding page");

        decoded.clean();

        assert_eq!(page, decoded);
        assert_eq!(n, m);
    }

}
