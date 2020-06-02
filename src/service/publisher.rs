use core::ops::Add;

#[cfg(feature = "std")]
use std::time::{SystemTime, Duration};

use crate::base::{Base, Header, Body, PrivateOptions};
use crate::options::Options;
use crate::page::{Page, PageOptions, PageInfo};
use crate::service::Service;
use crate::error::Error;
use crate::types::*;

/// Publisher trait allows services to generate primary, data, and secondary pages
/// as well as to encode (and sign and optionally encrypt) generated pages
pub trait Publisher {
    /// Generates a primary page to publish for the given service and encodes it into the provided buffer
    fn publish_primary<T: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        buff: T,
    ) -> Result<(usize, Page), Error>;

    /// Create a data object for publishing with the provided options and encodes it into the provided buffer
    fn publish_data<T: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        options: DataOptions,
        buff: T,
    ) -> Result<(usize, Page), Error>;

    /// Create a secondary page for publishing with the provided options and encodes it into the provided buffer
    fn publish_secondary<T: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        id: &Id,
        options: SecondaryOptions,
        buff: T,
    ) -> Result<(usize, Page), Error>;
}

#[derive(Clone)]
pub struct SecondaryOptions {
    /// Application ID of primary service
    pub application_id: u16,

    /// Page object kind
    pub page_kind: Kind,

    /// Page version
    /// This is monotonically increased for any successive publishing of the same page
    pub version: u16,

    /// Page body
    pub body: Body,

    /// Page publish time
    pub issued: Option<DateTime>,

    /// Page expiry time
    pub expiry: Option<DateTime>,

    /// Public options attached to the page
    pub public_options: Vec<Options>,

    /// Private options attached to the page
    pub private_options: Vec<Options>,
}

impl Default for SecondaryOptions {
    fn default() -> Self {
        Self {
            application_id: 0,
            page_kind: PageKind::Generic.into(),
            version: 0,
            body: Body::None,
            issued: None,
            expiry: None,
            public_options: vec![],
            private_options: vec![],
        }
    }
}

#[derive(Clone)]
pub struct DataOptions {
    /// Data object kind
    pub data_kind: Kind,

    /// Data object body
    pub body: Body,

    /// Data publish time
    pub issued: Option<DateTime>,

    /// Data expiry time
    pub expiry: Option<DateTime>,

    /// Public options attached to the data object
    pub public_options: Vec<Options>,

    /// Private options attached to the data object
    pub private_options: Vec<Options>,
}

impl Default for DataOptions {
    fn default() -> Self {
        Self {
            data_kind: PageKind::Generic.into(),
            body: Body::None,
            issued: None,
            expiry: None,
            public_options: vec![],
            private_options: vec![],
        }
    }
}

impl Publisher for Service {
    /// Publish generates a page to publishing for the given service.
    fn publish_primary<T: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        buff: T,
    ) -> Result<(usize, Page), Error> {
        let mut flags = Flags::default();
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        let header = Header{
            application_id: self.application_id,
            kind: self.kind.into(),
            index: self.version,
            flags,
            ..Default::default()
        };

        let page_options = PageOptions{
            // TODO: re-enable page issue / expiry for no-std
            #[cfg(feature = "std")]
            issued: Some(SystemTime::now().into()),
            #[cfg(feature = "std")]
            expiry: Some(SystemTime::now().add(Duration::from_secs(24 * 60 * 60)).into()),
            ..Default::default()
        };

        // Build page
        let mut p = Page::new(
            self.id.clone(),
            header,
            PageInfo::primary(self.public_key.clone()),
            self.body.clone(),
            page_options
        );

        self.encode(&mut p, buff).map(|n| (n, p))
    }

    /// Secondary generates a secondary page using this service to be attached to / stored at the provided service ID
    fn publish_secondary<T: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        id: &Id,
        options: SecondaryOptions,
        buff: T,
    ) -> Result<(usize, Page), Error> {
        let mut flags = Flags::SECONDARY;
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        assert!(options.page_kind.is_page());

        let header = Header{
            application_id: self.application_id,
            kind: options.page_kind,
            flags,
            index: options.version,
            ..Default::default()
        };

        let page_options = PageOptions{
            public_options: options.public_options,
            private_options: PrivateOptions::Cleartext(options.private_options),
            // TODO: Re-enable issued time
            #[cfg(feature = "std")]
            issued: Some(SystemTime::now().into()),
            expiry: options.expiry,
            ..Default::default()
        };

        let mut page = Page::new(id.clone(), header, PageInfo::secondary(self.id.clone()), options.body, page_options);

        self.encode(&mut page, buff).map(|n| (n, page))
    }

    fn publish_data<T: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        options: DataOptions,
        buff: T,
    ) -> Result<(usize, Page), Error> {
        let mut flags = Flags::default();
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        assert!(options.data_kind.is_data());

        self.data_index += 1;

        let header = Header{
            application_id: self.application_id,
            kind: options.data_kind,
            flags,
            index: self.data_index,
            ..Default::default()
        };

        let page_options = PageOptions{
            public_options: options.public_options,
            private_options: PrivateOptions::Cleartext(options.private_options),
            #[cfg(feature = "std")]
            issued: Some(SystemTime::now().into()),
            ..Default::default()
        };

        let mut p = Page::new(
            self.id.clone(),
            header,
            PageInfo::Data(()),
            options.body,
            page_options,
        );

        self.encode(&mut p, buff).map(|n| (n, p))
    }
}

impl Service {
    // Encode a page to the provided buffer, updating the internal signature state
    fn encode<T: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        page: &mut Page,
        buff: T,
    ) -> Result<usize, Error> {
        // Map page to base object
        let mut b = Base::from(&*page);

        // Attach previous signature
        b.parent = self.last_sig.clone();

        // Encode and sign object
        let n = b.encode(self.private_key.as_ref(), self.secret_key.as_ref(), buff)?;

        // Update service last_sig
        self.last_sig = b.signature;

        // Attach page sig
        page.signature = self.last_sig.clone();

        // TODO: should we attach the raw object here..?

        Ok(n)
    }
}
