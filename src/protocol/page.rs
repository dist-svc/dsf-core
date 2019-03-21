
use std::time::SystemTime;

use try_from::TryFrom;

use crate::types::*;
use crate::protocol::options::Options;
use crate::protocol::base::{Base, BaseBuilder};
use crate::protocol::container::Container;
use crate::crypto;

//pub type Page = Base;
//pub type PageBuilder = BaseBuilder;

/// High level description of a database page
/// Check out `PageBuilder` for a helper for constructing `Page` objects
#[derive(Debug, PartialEq, Clone, Builder)]
pub struct Page {
    // Header
    id: Id,
    flags: Flags,
    version: u16,

    kind: PageKind,

    // Body
    body: Vec<u8>,

    // Common options
    issued: SystemTime,
    expiry: SystemTime,

    // Encryption / Decryption
    encryption_key: Option<SecretKey>,

    public_options: Vec<Options>,
    private_options: Vec<Options>,
}

impl Page {

    /// Create a new page
    pub fn new(id: Id, flags: Flags, version: u16, kind: PageKind, body: Vec<u8>, issued: SystemTime, expiry: SystemTime) -> Self {
        Page{
            id, kind, flags, version, body, issued, expiry, 
            public_options: vec![],
            private_options: vec![],
            encryption_key: None
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

    pub fn kind(&self) -> &PageKind {
        &self.kind
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
}

impl Page {
    pub fn decode_pages<T: AsRef<[u8]>>(buff: T) -> Result<Vec<Page>, ()> {
        let mut pages = vec![];

        let mut i = 0;

        loop {
            // Fetch next chunk of data
            let d = &buff.as_ref()[i..];
            if d.len() == 0 {
                break;
            }

            // Fetch container
            let (c, n) = Container::from(d);

            // Validate signature

            // Decode to page

            // Update index
            i += n;
        }

        Ok(pages) 
    }
}


impl Into<Base> for Page {
    fn into(self) -> Base {
        let mut flags = Flags::default();

        // Insert default options
        let mut default_options = vec![
            Options::issued(self.issued),
            Options::expiry(self.expiry),
        ];
        
        // Add public fields for Primary and Secondary pages
        match self.kind {
            PageKind::Primary(primary) => {
                default_options.push(Options::public_key(primary.pub_key));
            },
            PageKind::Secondary(secondary) => {
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
        Base::new(self.id, Kind::None, flags, self.version, self.body, public_options, self.private_options)
    }
}

impl TryFrom<Base> for Page {
    type Err = Error;

    fn try_from(base: Base) -> Result<Self, Error> {

        let header = base.header();
        let body = base.body();
        let flags = header.flags();
        let kind = header.kind();

        let public_options = base.public_options();
        let private_options = base.private_options();

        if kind.is_primary_page() {
            // Handle primary page parsing

            // Fetch public key from options
            let public_key: PublicKey = match public_options.iter().find_map(|o| match o { Options::PubKey(pk) => Some(pk), _ => None } ) {
                Some(pk) => pk.public_key.clone(),
                None => return Err(Error::NoPublicKey)
            };

            // Check public key and ID match
            let hash: Id = crypto::hash(&public_key).unwrap().into();
            if &hash != header.id() {
                return Err(Error::KeyIdMismatch)
            }
        } else if kind.is_secondary_page() {
            // Handle secondary page parsing
            let peer_id: Id = match public_options.iter().find_map(|o| match o { Options::PeerId(id) => Some(id), _ => None } ) {
                Some(id) => id.peer_id.clone(),
                None => return Err(Error::NoPublicKey)
            };


        } else {
            err!("Attempted to convert non-page base object to page");
            return Err(Error::UnexpectedPageType);
        }



       unimplemented!();
    }
}


#[derive(Debug, PartialEq, Clone)]
pub enum PageKind {
    Primary(Primary),
    Secondary(Secondary),
}

impl PageKind {
    pub fn primary(pub_key: PublicKey) -> Self {
        PageKind::Primary(Primary{pub_key})
    }

    pub fn secondary(peer_id: Id) -> Self {
        PageKind::Secondary(Secondary{peer_id})
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
