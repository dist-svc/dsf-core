use std::time::{Duration, SystemTime};
use std::ops::Add;

use crate::types::{Id, Kind, Flags, Error, Address, PublicKey, PrivateKey, Signature, SecretKey};
use crate::protocol::{options::Options};
use crate::protocol::base::{Base, BaseBuilder};
use crate::protocol::page::{Page, PageInfo};

use crate::crypto;

use crate::service::Service;

pub trait Subscriber {
    type Service;

    /// Create a service replica from a given service page
    fn load(page: &Page) -> Result<Self::Service, Error>;
    
    /// Apply an updated page to an existing service instance
    fn apply(&mut self, update: &Page) -> Result<(), Error>;
}

impl Subscriber for Service {
    type Service = Service;

    /// Create a service instance from a given page
    fn load(page: &Page) -> Result<Service, Error> {

        let flags = page.flags();

        let public_key = match page.info() {
            PageInfo::Primary(primary) => primary.pub_key.clone(),
            _ => {
                error!("Attempted to load service from secondary page");
                return Err(Error::UnexpectedPageType);
            }
        };

        let body = page.body();

        let public_options = page.public_options();
        let private_options = page.private_options();


        Ok(Service{
            id: page.id().clone(),

            application_id: page.application_id(),
            kind: page.kind().into(),

            version: page.version(),

            body: body.to_vec(),

            public_options: public_options.to_vec(),
            private_options: private_options.to_vec(),

            public_key,
            private_key: None,

            encrypted: flags.encrypted(),
            secret_key: None,
        })
    }

    /// Apply an upgrade to an existing service.
    /// This consumes a new page and updates the service instance
    fn apply(&mut self, update: &Page) -> Result<(), Error> {

        let body = update.body();
        let flags = update.flags();
        
        let public_options = update.public_options();
        let private_options = update.private_options();

        // Check fields match
        if update.id() != &self.id {
            return Err(Error::UnexpectedServiceId)
        }
        if update.version() == self.version {
            return Ok(())
        }
        if update.version() <= self.version {
            return Err(Error::InvalidServiceVersion)
        }
        if update.kind() != self.kind.into() {
            return Err(Error::InvalidPageKind)
        }
        if update.flags().secondary() {
            return Err(Error::ExpectedPrimaryPage)
        }

        // Fetch public key from options
        let public_key: PublicKey = match update.info() {
            PageInfo::Primary(primary) => primary.pub_key.clone(),
            _ => {
                error!("Attempted to update service from secondary page");
                return Err(Error::UnexpectedPageType);
            }
        };

        // Check public key and ID match
        if self.id != crypto::hash(&public_key).unwrap() {
            return Err(Error::KeyIdMismatch)
        }

        // Check public key hasn't changed
        if self.public_key != public_key {
            return Err(Error::PublicKeyChanged)
        }

        self.version = update.version();
        self.encrypted = flags.encrypted();
        self.body = body.to_vec();
        self.public_options = public_options.to_vec();
        self.private_options = private_options.to_vec();
    
        Ok(())
    }
}