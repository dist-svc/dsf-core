
use std::time::{Duration, SystemTime};
use std::ops::Add;

use crate::types::{Id, Kind, Flags, Error, Address, PublicKey, PrivateKey, Signature, SecretKey};
use crate::protocol::{options::Options};
use crate::protocol::base::{Base, BaseBuilder};
use crate::protocol::page::{Page, PageInfo};

use crate::crypto;

use crate::service::Service;

pub struct PublishOptions {

}

pub trait Publisher {
    /// Update allows services to be updated (and re-published)
    fn update<U>(&mut self, update_fn: U) 
        where U: Fn(&mut Vec<u8>, &mut Vec<Options>, &mut Vec<Options>);

    /// Publish generates a page to publishing for the given service.
    fn publish(&self) -> Page;

    //fn data(&mut self) -> Page;
}

impl Publisher for Service {
    /// Update a service.
    /// This allows in-place editing of descriptors and options and causes an update of the service version number.
    fn update<U>(&mut self, update_fn: U) 
        where U: Fn(&mut Vec<u8>, &mut Vec<Options>, &mut Vec<Options>)
    {
        update_fn(&mut self.body, &mut self.public_options, &mut self.private_options);
        self.version += 1;
    }

    /// Publish generates a page to publishing for the given service.
    fn publish(&self) -> Page {
        // Insert default options
        // TODO: is this the right place to do this? Should they be deduplicated?
        let mut default_options = vec![
            Options::issued(SystemTime::now()),
            Options::expiry(SystemTime::now().add(Duration::from_secs(24 * 60 * 60))),
            Options::public_key(self.public_key.clone()),
        ];

        let mut public_options = self.public_options.clone();
        public_options.append(&mut default_options);

        let mut flags = Flags(0);
        flags.set_encrypted(self.encrypted);

        //Page::new(self.id.clone(), self.kind, flags, self.version, self.body.clone(), public_options, self.private_options.clone())

        let mut p = Page::new(self.id.clone(), self.application_id, self.kind.into(), flags, self.version, PageInfo::primary(self.public_key.clone()), self.body.clone(), SystemTime::now(), SystemTime::now().add(Duration::from_secs(24 * 60 * 60)));

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

    }
}