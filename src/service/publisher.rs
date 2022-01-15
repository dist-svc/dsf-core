use core::ops::Add;

#[cfg(feature = "alloc")]
use alloc::vec::{Vec};

use crate::base::{Header, MaybeEncrypted, DataBody};
use crate::error::Error;
use crate::options::Options;
use crate::page::{Page};
use crate::prelude::{Encode, Parse};
use crate::service::Service;
use crate::types::*;
use crate::wire::builder::{Encrypt, SetPublicOptions};
use crate::wire::{Builder, Container};

/// Publisher trait allows services to generate primary, data, and secondary pages
/// as well as to encode (and sign and optionally encrypt) generated pages
pub trait Publisher<const N: usize = 512> {
    /// Generates a primary page to publish for the given service and encodes it into the provided buffer
    fn publish_primary<T: MutableData>(
        &mut self,
        options: PrimaryOptions,
        buff: T,
    ) -> Result<(usize, Container<T>), Error>;

    // Helper to publish primary page using fixed sized buffer
    fn publish_primary_buff(&mut self, options: PrimaryOptions) -> Result<(usize, Container<[u8; N]>), Error> {
        let buff = [0u8; N];
        let (n, c) = self.publish_primary(options, buff)?;
        Ok((n, c))
    }

    /// Create a data object for publishing with the provided options and encodes it into the provided buffer
    fn publish_data<B: DataBody, T: MutableData>(
        &mut self,
        options: DataOptions<B>,
        buff: T,
    ) -> Result<(usize, Container<T>), Error>;

    // Helper to publish data block using fixed size buffer
    fn publish_data_buff<B: DataBody>(&mut self, options: DataOptions<B>) -> Result<(usize, Container<[u8; N]>), Error> {
        let buff = [0u8; N];
        let (n, c) = self.publish_data(options, buff)?;
        Ok((n, c))
    }

    /// Create a secondary page for publishing with the provided options and encodes it into the provided buffer
    fn publish_secondary<T: MutableData>(
        &mut self,
        id: &Id,
        options: SecondaryOptions,
        buff: T,
    ) -> Result<(usize, Container<T>), Error>;

    /// Helper to publish secondary page fixed size buffer
    fn publish_secondary_buff(&mut self, id: &Id, options: SecondaryOptions) -> Result<(usize, Container<[u8; N]>), Error> {
        let buff = [0u8; N];
        let (n, c) = self.publish_secondary(id, options, buff)?;
        Ok((n, c))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PrimaryOptions {
    /// Page publish time
    pub issued: Option<DateTime>,

    /// Page expiry time
    pub expiry: Option<DateTime>,
}

impl Default for PrimaryOptions {
    fn default() -> Self {
        Self {
            issued: default_issued(),
            expiry: default_expiry(),
        }
    }
}

fn default_issued() -> Option<DateTime> {
    #[cfg(feature="std")]
    return Some(std::time::SystemTime::now().into());

    #[cfg(not(feature="std"))]
    return None;
}

fn default_expiry() -> Option<DateTime> {
    #[cfg(feature="std")]
    return Some(std::time::SystemTime::now()
        .add(std::time::Duration::from_secs(24*60*60)).into());

    #[cfg(not(feature="std"))]
    return None;
}

#[derive(Clone)]
pub struct SecondaryOptions<'a, Body=&'a [u8]> {
    /// Application ID of primary service
    pub application_id: u16,

    /// Page object kind
    pub page_kind: Kind,

    /// Page version
    /// This is monotonically increased for any successive publishing of the same page
    pub version: u16,

    /// Page body
    pub body: Option<Body>,

    /// Page publish time
    pub issued: Option<DateTime>,

    /// Page expiry time
    pub expiry: Option<DateTime>,

    /// Public options attached to the page
    pub public_options: &'a [Options],

    /// Private options attached to the page
    pub private_options: &'a [Options],
}

impl <'a>Default for SecondaryOptions<'a> {
    fn default() -> Self {
        Self {
            application_id: 0,
            page_kind: PageKind::Generic.into(),
            version: 0,
            body: None,
            issued: default_issued(),
            expiry: default_expiry(),
            public_options: &[],
            private_options: &[],
        }
    }
}


#[derive(Clone, Debug)]
pub struct DataOptions<'a, Body: DataBody = &'a [u8]> {
    /// Data object kind
    pub data_kind: Kind,

    /// Data object body
    pub body: Option<Body>,

    /// Data publish time
    pub issued: Option<DateTime>,

    /// Data expiry time
    pub expiry: Option<DateTime>,

    /// Public options attached to the data object
    pub public_options: &'a [Options],

    /// Private options attached to the data object
    pub private_options: &'a [Options],

    /// Do not attach last signature to object
    pub no_last_sig: bool,
}

impl<'a, Body: DataBody> Default for DataOptions<'a, Body> {
    fn default() -> Self {
        Self {
            data_kind: DataKind::Generic.into(),
            body: None,
            issued: default_issued(),
            expiry: default_expiry(),
            public_options: &[],
            private_options: &[],
            no_last_sig: false,
        }
    }
}

impl Publisher for Service {
    /// Publish generates a page to publishing for the given service.
    fn publish_primary<T: MutableData>(
        &mut self,
        options: PrimaryOptions,
        buff: T,
    ) -> Result<(usize, Container<T>), Error> {
        let mut flags = Flags::default();
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        debug!("Primary options: {:?}", options);

        // Setup header
        let header = Header {
            application_id: self.application_id,
            kind: self.kind.into(),
            index: self.version,
            flags,
            ..Default::default()
        };

        let body = match &self.body {
            MaybeEncrypted::Cleartext(b) => &b[..],
            MaybeEncrypted::None => &[],
            _ => return Err(Error::CryptoError),
        };

        let private_opts = match &self.private_options {
            MaybeEncrypted::Cleartext(o) => &o[..],
            MaybeEncrypted::None => &[],
            _ => return Err(Error::CryptoError),
        };

        // Build object
        let b = Builder::new(buff)
           .header(&header)
           .id(&self.id())
           .body(body)?
           .private_options(&private_opts)?;
        
        // Apply internal encryption if enabled
        let mut b = self.encrypt(b)?;

        // Generate and append public options
        b = b.public_options(&[
            Options::pub_key(self.public_key.clone()),
        ])?;

        // Attach last sig if available
        if let Some(last) = &self.last_sig {
            b = b.public_options(&[Options::prev_sig(last)])?;
        }

        // Generate and append public options

        // Attach issued if provided
        if let Some(iss) = options.issued {
            b = b.public_options(&[Options::expiry(iss)])?;
        }
        // Attach expiry if provided
        if let Some(exp) = options.expiry {
            b = b.public_options(&[Options::expiry(exp)])?;
        }
        
        // Then finally attach public options
        let b = b.public_options(&self.public_options)?;

        // Sign generated object
        let c = self.sign(b)?;
        
        // Return container and encode
        return Ok((c.len(), c))
    }

    /// Secondary generates a secondary page using this service to be attached to / stored at the provided service ID
    fn publish_secondary<T: MutableData>(
        &mut self,
        id: &Id,
        options: SecondaryOptions,
        buff: T,
    ) -> Result<(usize, Container<T>), Error> {
        // Set secondary page flags
        let mut flags = Flags::SECONDARY;
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        // Check we are publishing a page
        assert!(options.page_kind.is_page());

        // Setup header
        let header = Header {
            application_id: self.application_id,
            kind: options.page_kind,
            flags,
            index: options.version,
            ..Default::default()
        };

        // Build object
        let b = Builder::new(buff)
            .header(&header)
            .id(id);

        let b = match options.body {
            Some(body) => b.body(body)?,
            None => b.with_body(|_b| Ok(0) )?,
        };

        let b = b.private_options(&options.private_options)?;

        // Apply internal encryption if enabled
        let b = self.encrypt(b)?;

        // Generate and append public options
        let mut b = b.public_options(&[
            Options::peer_id(self.id.clone()),
        ])?;

        // Attach issued if provided
        if let Some(iss) = options.issued {
            b = b.public_options(&[Options::expiry(iss)])?;
        }
        // Attach expiry if provided
        if let Some(exp) = options.expiry {
            b = b.public_options(&[Options::expiry(exp)])?;
        }
        // Attach last sig if available
        if let Some(last) = &self.last_sig {
            b = b.public_options(&[Options::prev_sig(last)])?;
        }
        // Then finally attach public options
        let b = b.public_options(options.public_options)?;

        // Sign generated object
        let c = self.sign(b)?;
        
        Ok((c.len(), c))
    }

    fn publish_data<B: DataBody, T: MutableData>(
        &mut self,
        options: DataOptions<B>,
        buff: T,
    ) -> Result<(usize, Container<T>), Error> {
        let mut flags = Flags::default();
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        assert!(options.data_kind.is_data());

        self.data_index += 1;

        let header = Header {
            application_id: self.application_id,
            kind: options.data_kind,
            flags,
            index: self.data_index,
            ..Default::default()
        };

        // Build object
        let b = Builder::new(buff)
            .header(&header)
            .id(&self.id());

        let b = match options.body {
            Some(body) => b.body(body).map_err(|e| {
                error!("Failed to encode data body: {:?}", e);
                Error::EncodeFailed
            })?,
            None => b.with_body(|_b| Ok(0) )?,
        };
    
        let b = b.private_options(&options.private_options)?;

        // Apply internal encryption if enabled
        let mut b = self.encrypt(b)?;

        // Generate and append public options

        // Attach issued if provided
        if let Some(iss) = options.issued {
            b = b.public_options(&[Options::expiry(iss)])?;
        }

        // Attach last sig if available
        if let Some(last) = &self.last_sig {
            b = b.public_options(&[Options::prev_sig(last)])?;
        }

        // Then finally attach public options
        let b = b.public_options(options.public_options)?;

        // Sign generated object
        let c = self.sign(b)?;
        
        // Return container and encoded length
        Ok((c.len(), c))
    }
}

impl Service {
    // Encode a page to the provided buffer, updating the internal signature state
    #[deprecated]
    pub fn encode<T: MutableData>(
        &mut self,
        page: &mut Page,
        buff: T,
    ) -> Result<usize, Error> {
        // Map page to base object
        let mut b = crate::base::Base::from(&*page);

        // Attach previous signature
        b.parent = self.last_sig.clone();

        // Encode and sign object
        let keys = self.keys();
        let n = b.encode(Some(&keys), buff)?;

        // Update service last_sig
        self.last_sig = b.signature;

        // Attach page sig
        page.signature = self.last_sig.clone();

        // TODO: should we attach the raw object here..?

        Ok(n)
    }

    pub(super) fn encrypt<T: MutableData>(&mut self, b: Builder<Encrypt, T>) -> Result<Builder<SetPublicOptions, T>, Error> {

        // Apply internal encryption if enabled
        let b = match (self.encrypted, &self.secret_key) {
            (true, Some(sk)) => b.encrypt(sk)?,
            (false, _) => b.public(),
            _ => todo!(),
        };

        Ok(b)
    }

    pub(super) fn sign<T: MutableData>(&mut self, b: Builder<SetPublicOptions, T> ) -> Result<Container<T>, Error> {

        // Sign generated object
        let c = match &self.private_key {
            Some(pk) => b.sign_pk(pk)?,
            None => {
                error!("No public key for object signing");
                return Err(Error::NoPrivateKey);
            }
        };

        // Update last signature
        self.last_sig = Some(c.signature());
        
        // Return signed container
        Ok(c)
    }
}

#[cfg(test)]
mod test {

}