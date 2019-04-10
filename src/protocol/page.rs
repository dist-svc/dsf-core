
use std::time::{SystemTime, Duration};
use std::ops::Add;

use try_from::TryFrom;

use crate::types::*;
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

    // Encryption / Decryption
    #[builder(default = "None")]
    encryption_key: Option<SecretKey>,

    #[builder(default = "vec![]")]
    public_options: Vec<Options>,
    #[builder(default = "vec![]")]
    private_options: Vec<Options>,

    // Signature (if signed or decoded)
    #[builder(default = "None")]
    signature: Option<Signature>,
}

impl Page {

    /// Create a new page
    pub fn new(id: Id, flags: Flags, version: u16, kind: Kind, info: PageInfo, body: Vec<u8>, issued: SystemTime, expiry: SystemTime) -> Self {
        Page{
            id, flags, version, kind, info, body, issued: issued.into(), expiry: expiry.into(), 
            public_options: vec![],
            private_options: vec![],
            encryption_key: None,
            signature: None,
        }
    }

    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn kind(&self) -> Kind {
        self.kind
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
}

impl Page {
    pub fn decode_pages(buff: &[u8]) -> Result<Vec<Page>, Error> {
        let mut pages = vec![];
        let mut i = 0;


        while i < buff.len() {
            let (b, n) = Base::parse(&buff[i..], |_id, _data, _sig| -> Result<bool, ()> { Ok(true) } )?;

            match Page::try_from(b) {
                Ok(p) => pages.push(p),
                Err(e) => error!("Error loading page from message: {:?}", e),
            };

            i += n;
        }

        Ok(pages) 
    }

    pub fn encode_pages(pages: &[Page], buff: &mut [u8]) -> Result<usize, Error> {
        let mut i = 0;

        for p in pages {
            // Check page has associated signature
            if let None = p.signature() {
                error!("cannot encode page without associated signature");
                continue;
            }

            // Convert and encode
            let mut b: Base = p.clone().into();
            let n = b.encode(|_id, _data| Err(()) , &mut buff[i..]).unwrap();

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


impl Into<Base> for Page {
    fn into(self) -> Base {
        let mut flags = self.flags.clone();
        let sig = self.signature().clone();

        // Insert default options
        let mut default_options = vec![
            Options::issued(self.issued),
            Options::expiry(self.expiry),
        ];
        
        // Add public fields for Primary and Secondary pages
        match self.info {
            PageInfo::Primary(primary) => {
                default_options.push(Options::public_key(primary.pub_key));
            },
            PageInfo::Secondary(secondary) => {
                default_options.push(Options::peer_id(secondary.peer_id));
            }
        }

        // Add additional public options
        // TODO: ideally these should be specified by type rather than an arbitrary list
        let mut public_options = self.public_options.clone();
        public_options.append(&mut default_options);

        // Enable encryption if key is provided
        if let Some(_key) = self.encryption_key {
            flags.set_encrypted(true);
        }

        // Generate base object
        let mut b = Base::new(self.id, self.kind, flags, self.version, self.body, public_options, self.private_options);

        if let Some(sig) = sig {
            b.set_signature(sig);
        }
    
        b
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
            flags: header.flags(),
            version: header.index(),
            kind: header.kind(),
            info,
            body: body.to_vec(),
            issued,
            expiry,
            encryption_key: None,
            public_options: public_options,
            private_options: private_options,
            signature: signature.clone(),
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
