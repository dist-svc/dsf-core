//! Page is a high level representation of pages stored in the database
//! These can be converted into and from a base object for encoding and decoding.

use std::time::{SystemTime, Duration};
use std::ops::Add;

use try_from::TryFrom;

use crate::types::*;
use crate::protocol::WireEncode;
use crate::protocol::options::Options;
use crate::protocol::base::Base;
use crate::crypto;

//pub type Page = Base;
//pub type PageBuilder = BaseBuilder;

/// High level description of a database page
/// Check out `PageBuilder` for a helper for constructing `Page` objects
#[derive(Debug, PartialEq, Clone, Builder)]
pub struct Page {
    // Header
    id: Id,

    #[builder(default = "0")]
    application_id: u16,

    #[builder(default = "Flags::default()")]
    flags: Flags,
    #[builder(default = "0")]
    version: u16,

    kind: Kind,
    info: PageInfo,
    
    // Body
    #[builder(default = "vec![]")]
    body: Vec<u8>,

    // Common options
    #[builder(default = "SystemTime::now().into()")]
    issued: DateTime,
    #[builder(default = "SystemTime::now().add(Duration::from_secs(24 * 60 * 60)).into()")]
    expiry: DateTime,

    #[builder(default = "vec![]")]
    public_options: Vec<Options>,
    #[builder(default = "vec![]")]
    private_options: Vec<Options>,

    // Signature (if signed or decoded)
    #[builder(default = "None")]
    signature: Option<Signature>,

    // Private key (for signing when required)
    #[builder(default = "None")]
    private_key: Option<PrivateKey>,

    // Encryption key (for encryption where specified)
    #[builder(default = "None")]
    encryption_key: Option<SecretKey>,
}

impl Page {

    /// Create a new page
    pub fn new(id: Id, application_id: u16, kind: Kind, flags: Flags, version: u16, info: PageInfo, body: Vec<u8>, issued: SystemTime, expiry: SystemTime) -> Self {
        Page{
            id, application_id, kind, flags, version, info, body, issued: issued.into(), expiry: expiry.into(), 
            public_options: vec![],
            private_options: vec![],
            
            signature: None,
            private_key: None,
            encryption_key: None,
        }
    }

    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn application_id(&self) -> u16 {
        self.application_id
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn info(&self) -> &PageInfo {
        &self.info
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn public_options(&self) -> &[Options] {
        &self.public_options
    }

    pub fn private_options(&self) -> &[Options] {
        &self.private_options
    }

    pub fn signature(&self) -> Option<Signature> {
        self.signature.clone()
    }

    pub fn set_signature(&mut self, sig: Signature) {
        self.signature = Some(sig);
    }

    pub fn set_private_key(&mut self, private_key: PrivateKey) {
        self.private_key = Some(private_key);
    }

    pub fn set_encryption_key(&mut self, secret_key: SecretKey) {
        self.encryption_key = Some(secret_key);
    }

    pub fn clean(&mut self) {
        self.encryption_key = None;
        self.private_key = None;
    }
}

impl Page {
    pub fn decode_pages<V>(buff: &[u8], key_source: V) -> Result<Vec<Page>, Error> 
    where 
        V: Fn(&Id) -> Option<PublicKey>
    {
        let mut pages = vec![];
        let mut i = 0;

        // Last key used to cache the previous primary key to decode secondary pages published by a service in a single message.
        let mut last_key: Option<(Id, PublicKey)> = None;

        while i < buff.len() {
            // TODO: validate signatures against existing services!
            let (b, n) = Base::parse(&buff[i..], |id| {
                // se key_source first
                if let Some(key) = (key_source)(id) {
                   return Some(key)
                };

                // Check for last entry second
                if let Some(prev) = last_key {
                    if &prev.0 == id {
                        return Some(prev.1)
                    }
                }

                // Fail if no public key is found
                None
            } )?;

            let page = match Page::try_from(b) {
                Ok(p) => p,
                Err(e) => {
                    error!("Error loading page from message: {:?}", e);
                    continue;
                },
            };

            // Cache key for next run
            if let Some(key) = page.info().pub_key() {
                last_key = Some((page.id().clone(), key));
            }

            // Push page to parsed list
            pages.push(page);

            i += n;
        }

        Ok(pages) 
    }

    pub fn encode_pages(pages: &[Page], buff: &mut [u8]) -> Result<usize, Error> {
        let mut i = 0;

        for p in pages {
            // Check page has associated signature
            match (p.signature, p.private_key) {
                (None, None) => {
                    error!("cannot encode page without associated signature or private key");
                    continue;
                }
                _ => (),
            };

            // Convert and encode
            let mut b = Base::from(p);
            let n = b.encode(|_id, _data| Err(Error::NoSignature) , &mut buff[i..])?;

            i += n;
        }

        Ok(i)
    }
}

impl PageBuilder {
    pub fn append_public_option(&mut self, o: Options) -> &mut Self {
        match &mut self.public_options {
            Some(opts) => opts.push(o),
            None => self.public_options = Some(vec![o]),
        }
        self
    }

    pub fn append_private_option(&mut self, o: Options) -> &mut Self {
        match &mut self.private_options {
            Some(opts) => opts.push(o),
            None => self.private_options = Some(vec![o]),
        }
        self
    }

    pub fn valid_for(&mut self, d: Duration) -> &mut Self {
        self.expiry = Some(SystemTime::now().add(d).into());
        self
    }
}

impl From<&Page> for Base {
    fn from(page: &Page) -> Base {
        let mut flags = page.flags.clone();
        let sig = page.signature().clone();

        // Insert default options
        let mut default_options = vec![
            Options::issued(page.issued),
            Options::expiry(page.expiry),
        ];
        
        // Add public fields for Primary and Secondary pages
        match &page.info {
            PageInfo::Primary(primary) => {
                default_options.push(Options::public_key(primary.pub_key));
            },
            PageInfo::Secondary(secondary) => {
                default_options.push(Options::peer_id(secondary.peer_id));
            }
        }

        // Add additional public options
        // TODO: ideally these should be specified by type rather than an arbitrary list
        let mut public_options = page.public_options.clone();
        public_options.append(&mut default_options);

        // Enable encryption if key is provided
        if let Some(_key) = page.encryption_key {
            flags.set_encrypted(true);
        }

        // Generate base object
        let mut b = Base::new(page.id, page.application_id, page.kind, flags, page.version, page.body.clone(), public_options, page.private_options.clone());

        if let Some(sig) = sig {
            b.set_signature(sig);
        }

        if let Some(key) = page.private_key {
            b.set_private_key(key);
        }
        if let Some(key) = page.encryption_key {
            b.set_encryption_key(key);
        }
    
        b
    }
}

impl WireEncode for Page {
    type Error = Error;

    fn encode(&mut self, buff: &mut [u8]) -> Result<usize, Error> {
        let mut b = Base::from(&*self);

        let res = b.encode(|_id, _data| Err(()), buff)
            .map_err(|e| panic!(e) );

        if let Some(sig) = b.signature() {
            self.set_signature(sig.clone());
        }

        res
    }
}

impl TryFrom<Base> for Page {
    type Err = Error;

    fn try_from(base: Base) -> Result<Self, Error> {

        let header = base.header();
        let body = base.body();
        let signature = base.signature();

        let _flags = header.flags();
        let kind = header.kind();

        let mut public_options = base.public_options().to_vec();
        let private_options = base.private_options().to_vec();

        let issued = match Base::filter_issued_option(&mut public_options) {
            Some(issued) => issued,
            None => return Err(Error::Unimplemented),
        };

        let expiry = match Base::filter_expiry_option(&mut public_options) {
            Some(expiry) => expiry,
            None => return Err(Error::Unimplemented),
        };

        let info = if kind.is_primary_page() {
            // Handle primary page parsing

            // Fetch public key from options
            let public_key: PublicKey = match Base::filter_pub_key_option(&mut public_options) {
                Some(pk) => pk,
                None => return Err(Error::NoPublicKey)
            };

            // Check public key and ID match
            let hash: Id = crypto::hash(&public_key).unwrap().into();
            if &hash != base.id() {
                return Err(Error::KeyIdMismatch)
            }

            PageInfo::primary(public_key)

        } else if kind.is_secondary_page() {
            // Handle secondary page parsing
            let peer_id = match Base::filter_peer_id_option(&mut public_options) {
                Some(id) => id,
                None => return Err(Error::NoPublicKey)
            };

            PageInfo::secondary(peer_id)

        } else {
            error!("Attempted to convert non-page base object ({:?}) to page", kind);
            return Err(Error::UnexpectedPageType);
        };

        Ok(Page{
            id: base.id().clone(),
            application_id: header.application_id(),
            kind: header.kind(),
            flags: header.flags(),
            version: header.index(),
            info,
            body: body.to_vec(),
            issued,
            expiry,
            public_options: public_options,
            private_options: private_options,
            signature: signature.clone(),
            private_key: None,
            encryption_key: None,
        })
    }
}


#[derive(Debug, PartialEq, Clone)]
pub enum PageInfo {
    Primary(Primary),
    Secondary(Secondary),
}

impl PageInfo {
    pub fn primary(pub_key: PublicKey) -> Self {
        PageInfo::Primary(Primary{pub_key})
    }

    pub fn secondary(peer_id: Id) -> Self {
        PageInfo::Secondary(Secondary{peer_id})
    }

    pub fn is_primary(&self) -> bool {
        match self {
            PageInfo::Primary(_) => true,
            _ => false,
        }
    }

    pub fn is_secondary(&self) -> bool {
        match self {
            PageInfo::Secondary(_) => true,
            _ => false,
        }
    }

    pub fn pub_key(&self) -> Option<PublicKey> {
        match self {
            PageInfo::Primary(p) => Some(p.pub_key),
            _ => None,
        }
    }

    pub fn peer_id(&self) -> Option<Id> {
        match self {
            PageInfo::Secondary(s) => Some(s.peer_id),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Primary {
    pub pub_key: PublicKey,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Secondary {
    pub peer_id: Id,
}
