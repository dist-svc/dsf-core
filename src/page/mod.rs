//! Pages are a high level representation of pages stored in the database
//! These can be converted into and from a base object for encoding and decoding.

use core::convert::TryFrom;

#[cfg(feature = "alloc")]
use alloc::vec::{Vec};

use crate::base::{Body, Header, MaybeEncrypted};
use crate::crypto;
use crate::error::Error;
use crate::options::Options;
use crate::prelude::Encode;
use crate::types::*;
use crate::keys::{KeySource, Keys};
use crate::wire::Container;


mod info;
pub use info::{PageInfo, Primary, Secondary, Tertiary};

//pub type Page = Base;
//pub type PageBuilder = BaseBuilder;

/// High level description of a database page
#[derive(derivative::Derivative, Clone)]
#[derivative(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Page<Raw=Vec<u8>> {
    // Page ID
    pub id: Id,

    // Page header
    pub header: Header,

    // Information associated with different object kinds
    pub info: PageInfo,

    // Common options
    pub issued: Option<DateTime>,
    pub expiry: Option<DateTime>,

    // Previous page signature
    pub previous_sig: Option<Signature>,

    // Page Body
    pub body: MaybeEncrypted<Vec<u8>>,

    // Full options lists
    pub public_options: Vec<Options>,
    pub private_options: MaybeEncrypted<Vec<Options>>,


    // Tag (if encrypted)
    pub tag: Option<SecretMeta>,

    // Signature (if signed or decoded)
    pub signature: Option<Signature>,

    /// Verified flag
    pub verified: bool,

    // Raw (encoded) data
    #[derivative(Debug="ignore")]
    pub raw: Option<Raw>,

    _extend: (),
}
#[derive(derivative::Derivative, Clone, PartialEq)]
#[derivative(Debug)]
pub struct PageOptions<'a, Raw=Vec<u8>>{
    // Page issued time
    pub issued: Option<DateTime>,
    // Page expiry time
    pub expiry: Option<DateTime>,

    // Public options
    pub public_options: &'a [Options],
    // Private options
    pub private_options: MaybeEncrypted<&'a [Options], &'a [u8]>,

    // Previous page signature
    pub previous_sig: Option<Signature>,
    // Signature (if signed or decoded)
    pub signature: Option<Signature>,

    // Raw (encoded) data
    #[derivative(Debug="ignore")]
    pub raw: Option<Raw>,
}

impl<'a> Default for PageOptions<'a> {
    fn default() -> Self {
        Self {
            issued: None,
            expiry: None,
            public_options: &[],
            private_options: MaybeEncrypted::None,
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

            public_options: options.public_options.to_vec(),
            private_options: options.private_options.to_vec(),

            previous_sig: options.previous_sig,

            tag: None,
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

    pub fn private_options(&self) -> &MaybeEncrypted<Vec<Options>> {
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

    pub fn decrypt(&mut self, sk: &SecretKey) -> Result<(), Error> {
        crate::wire::decrypt(sk, &mut self.body, &mut self.private_options, self.tag.as_ref())
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
            let c = match Container::parse((&buff[i..]).to_vec(), &key_source.cached(last_key.clone())){
                Ok(v) => v,
                Err(e) => {
                    debug!("Error parsing base message: {:?}", e);
                    return Err(e);
                }
            };

            i += c.len();

            let page = match Page::try_from(c) {
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

            // Convert and encode, note these must be pre-signed / encrypted
            let n = p.encode(&mut buff[i..])?;

            i += n;
        }

        Ok(i)
    }
}

impl Encode for Page {
    type Error = Error;

    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
        // Check page has associated signature
        let sig = match (&self.signature, &self.raw) {
            // Short circuit if we have a raw copy
            (_, Some(r)) => {
                buff[..r.len()].copy_from_slice(r);
                return Ok(r.len())
            },
            // Return signature if available
            (Some(sig), _) => sig,
            // Otherwise fail re-encoding
            _ => return Err(Error::NoSignature),
        };

        // TODO: check body is or can be encrypted
        let encrypted = self.header.flags.contains(Flags::ENCRYPTED);
        
        // Convert and encode page, note this _must_ be pre-signed (and encrypted)
        let b = Container::builder(buff)
            .id(&self.id)
            .header(&self.header)
            .body(&self.body)?;

        let b = match &self.private_options {
            MaybeEncrypted::Cleartext(o) => b.private_options(&o)?,
            MaybeEncrypted::Encrypted(r) => b.private_options_raw(r)?,
            MaybeEncrypted::None => b.private_options(&[])?,
        };

        let mut b = match (encrypted, &self.tag, &self.private_options, &self.body) {
            (true, Some(_), MaybeEncrypted::Cleartext(_), MaybeEncrypted::Cleartext(_)) => {
                panic!("Cannot re-encrypt without secret keys")
            },
            (true, Some(tag), MaybeEncrypted::Encrypted(_), MaybeEncrypted::Encrypted(_)) => {
                b.tag(tag)?
            },
            (true, _, _, _) => return Err(Error::CryptoError),
            (false, _, _, _) => b.public(),
        };

        if let Some(issued) = self.issued {
            b.public_option(&Options::issued(issued))?;
        }

        if let Some(expiry) = self.expiry {
            b.public_option(&Options::expiry(expiry))?;
        }

        if let Some(prev_sig) = &self.previous_sig {
            b.public_option(&Options::prev_sig(prev_sig))?;
        }

        match &self.info {
            PageInfo::Primary(primary) => {
                b.public_option(&Options::public_key(primary.pub_key.clone()))?;
            },
            PageInfo::Secondary(secondary) => {
                b.public_option(&Options::peer_id(secondary.peer_id.clone()))?;
            },
            PageInfo::Tertiary(_tertiary) => {},
            PageInfo::Data(_data) => {},
        }

        let c = b.sign_raw(sig)?;
        
        Ok(c.len())
    }
}

/// Convert a Container<T> into a Page object
impl <T: ImmutableData> TryFrom<Container<T>> for Page {
    type Error = Error;

    fn try_from(container: Container<T>) -> Result<Self, Error> {
        let header = container.header();
        let _signature = container.signature();

        let flags = header.flags();
        let kind = header.kind();

        if !kind.is_page() && !kind.is_data() {
            return Err(Error::InvalidPageKind);
        }

        // Extract common option fields
        let (mut issued, mut expiry, mut previous_sig, mut peer_id, mut pub_key) = (None, None, None, None, None);
        let public_options = container
            .public_options_iter()
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
                Options::PubKey(v) => {
                    pub_key = Some(v.public_key.clone());
                    None
                }
                _ => Some(o),
            })
            .collect();

        // Map body and options depending on encryption state
        let body = match (container.header().data_len(), container.encrypted()) {
            (0, _) => MaybeEncrypted::None,
            (_, false) => MaybeEncrypted::Cleartext(container.body_raw().to_vec()),
            (_, true) => MaybeEncrypted::Encrypted(container.body_raw().to_vec()),
        };

        let private_options = match (container.header().private_options_len(), container.encrypted()) {
            (0, _) => MaybeEncrypted::None,
            (_, false) => MaybeEncrypted::Cleartext(container.private_options_iter().collect()),
            (_, true) => MaybeEncrypted::Encrypted(container.private_options_raw().to_vec())
        };

        let info = if kind.is_page() && !flags.contains(Flags::SECONDARY) && !flags.contains(Flags::TERTIARY) {
            // Handle primary page parsing

            // Fetch public key from options
            let public_key: PublicKey = match &pub_key {
                Some(pk) => Ok(pk.clone()),
                None => Err(Error::NoPublicKey),
            }?;

            // Check public key and ID match
            let hash: Id = crypto::hash(&public_key).unwrap();
            if &hash != &container.id() {
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
        
        } else if kind.is_page() && flags.contains(Flags::TERTIARY) {
            // Handle tertiary page parsing
            let _peer_id = match peer_id {
                Some(id) => Ok(id),
                None => Err(Error::NoPeerId),
            }?;

            let target_id = Id::from(container.body_raw());

            PageInfo::tertiary(target_id)

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
            id: container.id(),
            header: Header::from(&header),
            info,
            body, //base.body.clone(),
            issued,
            expiry,

            previous_sig,

            public_options,
            // TODO: complete this
            private_options, //private_options,
            tag: None,
            signature: Some(container.signature()),
            verified: container.verified,

            // TODO: revisit this
            raw: Some(container.as_ref().to_vec()),
            _extend: (),
        })
    }
}


#[cfg(test)]
mod test {
    
}