//! Pages are a high level representation of pages stored in the database
//! These can be converted into and from a base object for encoding and decoding.

use core::convert::TryFrom;

#[cfg(feature = "alloc")]
use alloc::prelude::v1::*;

use crate::base::{Base, BaseOptions, Body, Header, PrivateOptions};
use crate::crypto;
use crate::error::Error;
use crate::options::Options;
use crate::types::*;
use crate::{KeySource, Keys};

mod info;
pub use info::PageInfo;

//pub type Page = Base;
//pub type PageBuilder = BaseBuilder;

/// High level description of a database page
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Page {
    // Page ID
    pub id: Id,

    // Page header
    pub header: Header,

    // Information associated with different object kinds
    pub info: PageInfo,

    // Page Body
    pub body: Body,

    // Common options
    pub issued: Option<DateTime>,
    pub expiry: Option<DateTime>,

    pub public_options: Vec<Options>,

    pub private_options: PrivateOptions,

    // Previous page signature
    pub previous_sig: Option<Signature>,

    // Signature (if signed or decoded)
    pub signature: Option<Signature>,

    /// Verified flag
    pub verified: bool,

    // Raw (encoded) data
    pub raw: Option<Vec<u8>>,

    _extend: (),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PageOptions {
    // Page issued time
    pub issued: Option<DateTime>,
    // Page expiry time
    pub expiry: Option<DateTime>,

    // Public options
    pub public_options: Vec<Options>,
    // Private options
    pub private_options: PrivateOptions,

    // Previous page signature
    pub previous_sig: Option<Signature>,
    // Signature (if signed or decoded)
    pub signature: Option<Signature>,
    // Raw (encoded) data
    pub raw: Option<Vec<u8>>,
}

impl Default for PageOptions {
    fn default() -> Self {
        Self {
            issued: None,
            expiry: None,
            public_options: vec![],
            private_options: PrivateOptions::None,
            previous_sig: None,
            signature: None,
            raw: None,
        }
    }
}

impl PartialEq for Page {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id
            && self.header == o.header
            && self.info == o.info
            && self.body == o.body
            && self.issued == o.issued
            && self.expiry == o.expiry
            && self.previous_sig == o.previous_sig
            && self.public_options == o.public_options
            && self.private_options == o.private_options
            && self.signature == o.signature
    }
}

impl Page {
    /// Create a new page
    pub fn new(id: Id, header: Header, info: PageInfo, body: Body, options: PageOptions) -> Self {
        Page {
            id,
            header,
            info,
            body,

            issued: options.issued,
            expiry: options.expiry,

            public_options: options.public_options,
            private_options: options.private_options,

            previous_sig: options.previous_sig,

            signature: options.signature,
            raw: options.raw,

            verified: false,

            _extend: (),
        }
    }

    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn info(&self) -> &PageInfo {
        &self.info
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn issued(&self) -> Option<DateTime> {
        self.issued
    }

    pub fn expiry(&self) -> Option<DateTime> {
        self.expiry
    }

    #[cfg(feature = "std")]
    pub fn valid(&self) -> bool {
        use std::ops::Add;

        // Convert issued and expiry times
        let (issued, expiry): (Option<std::time::SystemTime>, Option<std::time::SystemTime>) = (
            self.issued().map(|v| v.into()),
            self.expiry().map(|v| v.into()),
        );

        // Compute validity
        match (issued, expiry) {
            // For fixed expiry, use this
            (_, Some(expiry)) => std::time::SystemTime::now() > expiry,
            // For no expiry, use 1h
            (Some(issued), None) => {
                std::time::SystemTime::now() < issued.add(std::time::Duration::from_secs(3600))
            }
            // Otherwise default to true
            // TODO: should we allow services _without_ valid time records?
            _ => true,
        }
    }

    pub fn public_options(&self) -> &[Options] {
        &self.public_options
    }

    pub fn private_options(&self) -> &PrivateOptions {
        &self.private_options
    }

    pub fn signature(&self) -> Option<Signature> {
        self.signature.clone()
    }

    pub fn set_signature(&mut self, sig: Signature) {
        self.signature = Some(sig);
    }

    pub fn raw(&self) -> &Option<Vec<u8>> {
        &self.raw
    }

    pub fn clean(&mut self) {
        self.raw = None;
    }
}

impl Page {
    pub fn decode_pages<V>(buff: &[u8], key_source: &V) -> Result<Vec<Page>, Error>
    where
        V: KeySource,
    {
        let mut pages = vec![];
        let mut i = 0;

        // Last key used to cache the previous primary key to decode secondary pages published by a service in a single message.
        let mut last_key: Option<(Id, Keys)> = None;

        while i < buff.len() {
            // TODO: validate signatures against existing services!
            let (b, n) = Base::parse(&buff[i..], &key_source.cached(last_key.clone()))?;

            i += n;

            let page = match Page::try_from(b) {
                Ok(p) => p,
                Err(e) => {
                    error!("Error loading page from message: {:?}", e);
                    continue;
                }
            };

            // Cache key for next run
            if let Some(key) = page.info().pub_key() {
                last_key = Some((page.id().clone(), Keys::new(key)));
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
            match (&p.signature, &p.raw) {
                (None, None) => {
                    error!("cannot encode page without associated signature or private key");
                    continue;
                }
                _ => (),
            };

            // Convert and encode, note these must be pre-signed
            let mut b = Base::from(p);
            let n = b.encode(None, &mut buff[i..])?;

            i += n;
        }

        Ok(i)
    }
}

impl From<&Page> for Base {
    fn from(page: &Page) -> Base {
        let sig = page.signature().clone();

        // Insert default options
        let mut default_options = vec![];

        if let Some(issued) = page.issued {
            default_options.push(Options::issued(issued));
        }

        if let Some(expiry) = page.expiry {
            default_options.push(Options::expiry(expiry));
        }

        if let Some(prev_sig) = &page.previous_sig {
            default_options.push(Options::prev_sig(prev_sig));
        }

        // Add public fields for different object types
        match &page.info {
            PageInfo::Primary(primary) => {
                default_options.push(Options::public_key(primary.pub_key.clone()));
            }
            PageInfo::Secondary(secondary) => {
                default_options.push(Options::peer_id(secondary.peer_id.clone()));
            }
            PageInfo::Data(_data) => {}
        }

        // Add additional public options
        // TODO: ideally these should be specified by type rather than an arbitrary list
        let mut public_options = page.public_options.clone();
        public_options.append(&mut default_options);

        // Generate base object
        let mut b = Base::new(
            page.id.clone(),
            page.header.clone(),
            page.body.clone(),
            BaseOptions {
                public_options,
                private_options: page.private_options.clone(),
                ..Default::default()
            },
        );

        if let Some(sig) = sig {
            b.set_signature(sig);
        }

        if let Some(raw) = &page.raw {
            b.set_raw(raw.clone());
        }

        b.verified = page.verified;

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
            return Err(Error::InvalidPageKind);
        }

        let (mut issued, mut expiry, mut previous_sig, mut peer_id) = (None, None, None, None);
        let public_options = base
            .public_options()
            .iter()
            .filter_map(|o| match &o {
                Options::Issued(v) => {
                    issued = Some(v.when);
                    None
                }
                Options::Expiry(v) => {
                    expiry = Some(v.when);
                    None
                }
                Options::PrevSig(v) => {
                    previous_sig = Some(v.sig.clone());
                    None
                }
                Options::PeerId(v) => {
                    peer_id = Some(v.peer_id.clone());
                    None
                }
                _ => Some(o),
            })
            .map(|o| o.clone())
            .collect();

        let peer_id = base.peer_id.clone();

        // TODO: parse out private options too?
        let _private_options = base.private_options();

        let info = if kind.is_page() && !flags.contains(Flags::SECONDARY) {
            // Handle primary page parsing

            // Fetch public key from options
            let public_key: PublicKey = match &base.public_key {
                Some(pk) => Ok(pk.clone()),
                None => Err(Error::NoPublicKey),
            }?;

            // Check public key and ID match
            let hash: Id = crypto::hash(&public_key).unwrap().into();
            if &hash != base.id() {
                return Err(Error::KeyIdMismatch);
            }

            PageInfo::primary(public_key)
        } else if kind.is_page() && flags.contains(Flags::SECONDARY) {
            // Handle secondary page parsing
            let peer_id = match peer_id {
                Some(id) => Ok(id),
                None => Err(Error::NoPeerId),
            }?;

            PageInfo::secondary(peer_id)
        } else if kind.is_data() {
            PageInfo::Data(())
        } else {
            error!(
                "Attempted to convert non-page base object ({:?}) to page",
                kind
            );
            return Err(Error::UnexpectedPageType);
        };

        Ok(Page {
            id: base.id().clone(),
            header: header.clone(),
            info,
            body: base.body.clone(),
            issued,
            expiry,

            previous_sig,

            public_options,
            private_options: base.private_options.clone(),
            signature: signature.clone(),
            verified: base.verified,

            raw: base.raw().clone(),
            _extend: (),
        })
    }
}
