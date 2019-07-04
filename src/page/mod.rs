//! Page is a high level representation of pages stored in the database
//! These can be converted into and from a base object for encoding and decoding.

use std::time::{SystemTime, Duration};
use std::ops::Add;
use std::convert::TryFrom;

use crate::types::*;
use crate::base::{Body, PrivateOptions};
use crate::options::Options;
use crate::base::Base;
use crate::crypto;

mod info;
pub use info::PageInfo;

//pub type Page = Base;
//pub type PageBuilder = BaseBuilder;

/// High level description of a database page
/// Check out `PageBuilder` for a helper for constructing `Page` objects
#[derive(Debug, Clone, Builder)]
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
    #[builder(default = "Body::None")]
    body: Body,

    // Common options
    #[builder(default = "SystemTime::now().into()")]
    issued: DateTime,
    #[builder(default = "None")]
    expiry: Option<DateTime>,

    // Previous page signature
    #[builder(default = "None")]
    pub(crate) previous_sig: Option<Signature>,

    #[builder(default = "vec![]")]
    public_options: Vec<Options>,
    #[builder(default = "PrivateOptions::None")]
    private_options: PrivateOptions,

    // Public key (for decoding and encoding)
    #[builder(default = "None")]
    pub(crate) public_key: Option<PublicKey>,

    // Signature (if signed or decoded)
    #[builder(default = "None")]
    signature: Option<Signature>,

    // Private key (for signing when required)
    #[builder(default = "None")]
    private_key: Option<PrivateKey>,

    // Encryption key (for encryption where specified)
    #[builder(default = "None")]
    encryption_key: Option<SecretKey>,

    // Raw (encoded) data
    #[builder(default = "None")]
    pub(crate) raw: Option<Vec<u8>>
}

impl PartialEq for Page {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id &&
        self.application_id == o.application_id &&
        self.flags == o.flags &&
        self.version == o.version &&
        self.kind == o.kind &&
        self.info == o.info &&
        self.body == o.body &&
        self.issued == o.issued &&
        self.expiry == o.expiry &&
        self.previous_sig == o.previous_sig &&
        self.public_options == o.public_options &&
        self.private_options == o.private_options &&
        self.public_key == o.public_key &&
        self.signature == o.signature
    }
}

impl Page {

    /// Create a new page
    pub fn new(id: Id, application_id: u16, kind: Kind, flags: Flags, version: u16, info: PageInfo, body: Body, issued: SystemTime, expiry: Option<SystemTime>) -> Self {
        Page {
            id, application_id, kind, flags, version, info, body, 
            issued: issued.into(), 
            expiry: expiry.map(|v| v.into() ), 
            previous_sig: None,
            public_options: vec![],
            private_options: PrivateOptions::None,
            
            public_key: None,
            signature: None,
            private_key: None,
            encryption_key: None,
            raw: None,
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

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn issued(&self) -> SystemTime {
        self.issued.into()
    }

    pub fn expiry(&self) -> Option<SystemTime> {
         self.expiry.map(|t| t.into() )
    }

    pub fn public_options(&self) -> &[Options] {
        &self.public_options
    }

    pub fn private_options(&self) -> &PrivateOptions {
        &self.private_options
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        self.public_key.clone()
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

    pub fn raw(&self) -> &Option<Vec<u8>> {
        &self.raw
    }

    pub fn clean(&mut self) {
        self.encryption_key = None;
        self.private_key = None;
        self.raw = None;
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
            let (b, n) = Base::parse(&buff[i..], 
            |id| {
                // Try key_source first
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
            },
            |_id| None
            )?;

            i += n;

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
            let n = b.encode(None, None, &mut buff[i..])?;

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
        if let Some(opts) = &mut self.private_options {
            opts.append(o)
        }
        self
    }

    pub fn valid_for(&mut self, d: Duration) -> &mut Self {
        self.expiry = Some(Some(SystemTime::now().add(d).into()));
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
        ];

        if let Some(expiry) = page.expiry {
            default_options.push(Options::expiry(expiry));
        }

        if let Some(prev_sig) = page.previous_sig {
            default_options.push(Options::prev_sig(&prev_sig));
        }
        
        // Add public fields for different object types
        match &page.info {
            PageInfo::Primary(primary) => {
                default_options.push(Options::public_key(primary.pub_key));
            },
            PageInfo::Secondary(secondary) => {
                default_options.push(Options::peer_id(secondary.peer_id));
            },
            PageInfo::Data(_data) => {
                
            }
        }

        // Add additional public options
        // TODO: ideally these should be specified by type rather than an arbitrary list
        let mut public_options = page.public_options.clone();
        public_options.append(&mut default_options);

        // Enable encryption if key is provided
        if let Some(_key) = page.encryption_key {
            flags |= Flags::ENCRYPTED;
        }

        // Generate base object
        let mut b = Base::new(page.id, page.application_id, page.kind, flags, page.version, page.body.clone(), public_options, page.private_options.clone());

        b.public_key = page.public_key;

        if let Some(sig) = sig {
            b.set_signature(sig);
        }

        if let Some(raw) = &page.raw {
            b.set_raw(raw.clone());
        }
    
        b
    }
}

impl TryFrom<Base> for Page {
    type Error = Error;

    fn try_from(base: Base) -> Result<Self, Error> {

        let header = base.header();
        let signature = base.signature();

        let flags = header.flags();
        let kind = header.kind();

        if !kind.is_page() && !kind.is_data() {
            return Err(Error::InvalidPageKind)
        }

        let (mut issued, mut expiry, mut previous_sig, mut peer_id) = (None, None, None, None);
        let public_options = base.public_options().iter()
        .filter_map(|o| {
            match &o {
                Options::Issued(v) => { issued = Some(v.when); None },
                Options::Expiry(v) => { expiry = Some(v.when); None },
                Options::PrevSig(v) => { previous_sig = Some(v.sig); None },
                Options::PeerId(v) => { peer_id = Some(v.peer_id); None },
                _ => Some(o),
            }
        }).map(|o| o.clone() ).collect();

        // TODO: parse out private options too?
        let _private_options = base.private_options();

        let info = if kind.is_page() && !flags.contains(Flags::SECONDARY) {
            // Handle primary page parsing

            // Fetch public key from options
            let public_key: PublicKey = match base.public_key {
                Some(pk) => Ok(pk),
                None => Err(Error::NoPublicKey)
            }?;

            // Check public key and ID match
            let hash: Id = crypto::hash(&public_key).unwrap().into();
            if &hash != base.id() {
                return Err(Error::KeyIdMismatch)
            }

            PageInfo::primary(public_key)

        } else if kind.is_page() && flags.contains(Flags::SECONDARY) {
            // Handle secondary page parsing
            let peer_id = match peer_id {
                Some(id) => Ok(id),
                None => Err(Error::NoPeerId)
            }?;

            PageInfo::secondary(peer_id)

        } else if kind.is_data() {

            PageInfo::Data(())

        } else {
            error!("Attempted to convert non-page base object ({:?}) to page", kind);
            return Err(Error::UnexpectedPageType);
        };

        Ok(Page {
            id: base.id().clone(),
            application_id: header.application_id(),
            kind: header.kind(),
            flags: header.flags(),
            version: header.index(),
            info,
            body: base.body.clone(),
            issued: issued.expect("missing issued option"),
            expiry: expiry,
            previous_sig: previous_sig,
            public_options: public_options,
            private_options: base.private_options.clone(),
            signature: signature.clone(),

            public_key: base.public_key,
            private_key: None,
            encryption_key: None,
            raw: base.raw().clone(),
        })
    }
}



