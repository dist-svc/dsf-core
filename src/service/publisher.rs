
use std::time::{Duration, SystemTime};
use std::ops::Add;

use crate::types::*;
use crate::service::Service;
use crate::options::Options;
use crate::base::{Base, Body, PrivateOptions};
use crate::page::{Page, PageBuilder, PageInfo};

/// Publisher trait allows services to generate primary, data, and secondary pages
/// as well as to encode (and sign and optionally encrypt) generated pages
pub trait Publisher {
    /// Generates a primary page to publish for the given service and encodes it into the provided buffer
    fn publish_primary<T: AsRef<[u8]> + AsMut<[u8]>>(&mut self, buff: T) -> Result<(usize, Page), Error>;

    /// Create a data object for publishing with the provided options and encodes it into the provided buffer
    fn publish_data<T: AsRef<[u8]> + AsMut<[u8]>>(&mut self, options: DataOptions, buff: T) -> Result<(usize, Page), Error>;

    /// Create a secondary page for publishing with the provided options and encodes it into the provided buffer
    fn publish_secondary<T: AsRef<[u8]> + AsMut<[u8]>>(&mut self, options: SecondaryOptions, buff: T) -> Result<(usize, Page), Error>;

}

#[derive(Clone, Builder)]
pub struct SecondaryOptions {
    /// ID of primary service
    id: Id,

    /// Application ID of primary service 
    #[builder(default = "0")]
    application_id: u16,

    /// Page object kind
    #[builder(default = "Kind(0)")]
    page_kind: Kind,

    /// Page version 
    /// This is monotonically increased for any successive publishing of the same page
    #[builder(default = "0")]
    version: u16,

    /// Page body
    #[builder(default = "Body::None")]
    body: Body,

    /// Page expiry time
    #[builder(default = "Some(SystemTime::now().add(Duration::from_secs(24 * 60 * 60)))")]
    expiry: Option<SystemTime>,

    /// Public options attached to the page
    #[builder(default = "vec![]")]
    public_options: Vec<Options>,

    /// Private options attached to the page
    #[builder(default = "PrivateOptions::None")]
    private_options: PrivateOptions,
}

#[derive(Clone, Builder)]
pub struct DataOptions {
    /// Data object kind
    #[builder(default = "DataKind::Generic.into()")]
    data_kind: Kind,

    /// Data object body
    #[builder(default = "Body::None")]
    body: Body,

    /// Data expiry time
    #[builder(default = "None")]
    expiry: Option<SystemTime>,

    /// Public options attached to the data object
    #[builder(default = "vec![]")]
    public_options: Vec<Options>,
    
    /// Private options attached to the data object
    #[builder(default = "PrivateOptions::None")]
    private_options: PrivateOptions
}

impl Publisher for Service {
    /// Publish generates a page to publishing for the given service.
    fn publish_primary<T: AsRef<[u8]> + AsMut<[u8]>>(&mut self, buff: T) -> Result<(usize, Page), Error> {
        let mut flags = Flags::default();
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        //Page::new(self.id.clone(), self.kind, flags, self.version, self.body.clone(), public_options, self.private_options.clone())

        let mut p = Page::new(self.id.clone(), self.application_id, self.kind.into(), flags, self.version, PageInfo::primary(self.public_key.clone()), self.body.clone(), SystemTime::now(), Some(SystemTime::now().add(Duration::from_secs(24 * 60 * 60))));

        // Attach public key to primary page
        p.public_key = Some(self.public_key());
    
        self.encode(&mut p, buff).map(|n| (n, p))
    }

    /// Secondary generates a secondary page using this service to be attached to the provided service ID
    fn publish_secondary<T: AsRef<[u8]> + AsMut<[u8]>>(&mut self, options: SecondaryOptions, buff: T) -> Result<(usize, Page), Error> {
        let mut flags = Flags::SECONDARY;
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        assert!(options.page_kind.is_page());

        //let mut p = Page::new(options.id.clone(), options.application_id, options.page_kind, flags, options.version, PageInfo::secondary(self.id.clone()), options.body, SystemTime::now(), options.expiry);

        let mut b = PageBuilder::default();
        b.id(options.id.clone())
            .application_id(options.application_id)
            .kind(options.page_kind)
            .flags(flags)
            .version(options.version)
            .info(PageInfo::secondary(self.id.clone()))
            .body(options.body)
            .public_options(options.public_options)
            .private_options(options.private_options)
            .issued(SystemTime::now().into())
            .expiry(options.expiry.map(|v| v.into() ));

        let mut p = b.build().unwrap();

        self.encode(&mut p, buff).map(|n| (n, p))
    }

    fn publish_data<T: AsRef<[u8]> + AsMut<[u8]>>(&mut self, options: DataOptions, buff: T) -> Result<(usize, Page), Error> {
        let mut flags = Flags::default();
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        assert!(options.data_kind.is_data());

        self.data_index += 1;

        let mut p = Page::new(self.id.clone(), self.application_id, options.data_kind, flags, self.data_index, PageInfo::Data(()), options.body, SystemTime::now(), options.expiry);

        self.encode(&mut p, buff).map(|n| (n, p))
    }

}

impl Service{
    // Encode a page to the provided buffer, updating the internal signature state
    fn encode<T: AsRef<[u8]> + AsMut<[u8]>>(&mut self, page: &mut Page, buff: T) -> Result<usize, Error> {
        // Map page to base object
        let mut b = Base::from(&*page);

        // Attach previous signature
        b.parent = self.last_sig;

        // Encode and sign object
        let n = b.encode(self.private_key.as_ref(), self.secret_key.as_ref(), buff)?;

        // Update service last_sig
        self.last_sig = b.signature;

        // Attach page sig
        page.signature = b.signature;

        Ok(n)
    }
}