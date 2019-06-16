
use std::time::{Duration, SystemTime};
use std::ops::Add;

use crate::types::*;
use crate::service::Service;
use crate::options::Options;
use crate::page::{Page, PageBuilder, PageInfo};

pub trait Publisher {
    /// Generates a primary page to publish for the given service.
    fn publish_primary(&self) -> Page;

    /// Create a data object for publishing with the provided options
    fn publish_data(&mut self, options: DataOptions) -> Page;

    /// Create a secondary page for publishing with the provided options
    fn publish_secondary(&self, options: SecondaryOptions) -> Page;
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
    #[builder(default = "vec![]")]
    body: Vec<u8>,

    /// Page expiry time
    #[builder(default = "Some(SystemTime::now().add(Duration::from_secs(24 * 60 * 60)))")]
    expiry: Option<SystemTime>,

    /// Public options attached to the page
    #[builder(default = "vec![]")]
    public_options: Vec<Options>,

    /// Private options attached to the page
    #[builder(default = "vec![]")]
    private_options: Vec<Options>,
}

#[derive(Clone, Builder)]
pub struct DataOptions {
    /// Data object kind
    #[builder(default = "DataKind::Generic.into()")]
    data_kind: Kind,

    /// Data object body
    #[builder(default = "vec![]")]
    body: Vec<u8>,

    /// Data expiry time
    #[builder(default = "None")]
    expiry: Option<SystemTime>,

    /// Public options attached to the data object
    #[builder(default = "vec![]")]
    public_options: Vec<Options>,
    
    /// Private options attached to the data object
    #[builder(default = "vec![]")]
    private_options: Vec<Options>,
}

impl Publisher for Service {
    /// Publish generates a page to publishing for the given service.
    fn publish_primary(&self) -> Page {
        let mut flags = Flags::default();
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        //Page::new(self.id.clone(), self.kind, flags, self.version, self.body.clone(), public_options, self.private_options.clone())

        let mut p = Page::new(self.id.clone(), self.application_id, self.kind.into(), flags, self.version, PageInfo::primary(self.public_key.clone()), self.body.clone(), SystemTime::now(), Some(SystemTime::now().add(Duration::from_secs(24 * 60 * 60))));

        p.public_key = Some(self.public_key());

        if let Some(key) = self.private_key {
            p.set_private_key(key);
        }
        
        if let Some(key) = self.secret_key {
            p.set_encryption_key(key);
        }
    
        p
    }

    /// Secondary generates a secondary page using this service to be attached to the provided service ID
    fn publish_secondary(&self, options: SecondaryOptions) -> Page {
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

        p.public_key = Some(self.public_key());

        if let Some(key) = self.private_key {
            p.set_private_key(key);
        }
        
        if let Some(key) = self.secret_key {
            p.set_encryption_key(key);
        }

        p
    }

    fn publish_data(&mut self, options: DataOptions) -> Page {
        let mut flags = Flags::default();
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        assert!(options.data_kind.is_data());

        self.data_index += 1;

        let mut p = Page::new(self.id.clone(), self.application_id, options.data_kind, flags, self.data_index, PageInfo::Data(()), options.body, SystemTime::now(), options.expiry);

        p.public_key = Some(self.public_key());

        if let Some(key) = self.private_key {
            p.set_private_key(key);
        }
        
        if let Some(key) = self.secret_key {
            p.set_encryption_key(key);
        }

        p
    }



    #[cfg(feature = "nope")]
    fn data(&self, body: Vec<u8>, public_options: Vec<Options>, private_options: Vec<Options>) -> Page {

        let mut flags = Flags(0);
        flags.set_encrypted(self.encrypted);

        let mut p = Page::new(self.id.clone(), self.application_id, self.kind.into(), flags, self.version, PageInfo::primary(self.public_key.clone()), self.body.clone(), SystemTime::now(), SystemTime::now().add(Duration::from_secs(24 * 60 * 60)));

        if let Some(key) = self.private_key {
            p.set_private_key(key);
        }
        
        if let Some(key) = self.secret_key {
            p.set_encryption_key(key);
        }

        p
    }
}