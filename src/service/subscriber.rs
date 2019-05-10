use std::convert::TryInto;

use crate::types::*;
use crate::service::Service;
use crate::protocol::page::{Page, PageInfo};
use crate::crypto;


pub trait Subscriber {
    /// Create a service instance (or replica) from a given primary service page
    fn load(page: &Page) -> Result<Service, Error>;
    
    /// Apply an updated primary page to an existing service instance
    fn apply_primary(&mut self, primary: &Page) -> Result<(), Error>;

    /// Validate a given secondary page published by this service
    fn validate_secondary(&mut self, secondary: &Page) -> Result<(), Error>;

    /// Validate a given data object published by this service
    fn validate_data(&mut self, data: &Page) -> Result<(), Error>;
}

impl Subscriber for Service {

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
            kind: page.kind().try_into().unwrap(),

            version: page.version(),
            data_index: 0,

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
    fn apply_primary(&mut self, update: &Page) -> Result<(), Error> {
        let flags = update.flags();
        let body = update.body();

        let public_options = update.public_options();
        let private_options = update.private_options();

        // Check fields match
        if !update.kind().is_page() {
            return Err(Error::ExpectedPrimaryPage);
        }
        if !update.flags().primary() {
            return Err(Error::ExpectedPrimaryPage)
        }
        

        if update.id() != &self.id {
            return Err(Error::UnexpectedServiceId)
        }
        if update.application_id() != self.application_id {
            return Err(Error::UnexpectedApplicationId)
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
       

        // Fetch public key from options
        let public_key: PublicKey = match update.info() {
            PageInfo::Primary(primary) => primary.pub_key.clone(),
            _ => {
                error!("Attempted to update service from secondary page");
                return Err(Error::ExpectedPrimaryPage);
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

    fn validate_secondary(&mut self, secondary: &Page) -> Result<(), Error> {
        if !secondary.kind().is_page() {
            return Err(Error::ExpectedPrimaryPage);
        }
        if !secondary.flags().secondary() {
            return Err(Error::ExpectedSecondaryPage)
        }

        let publisher_id = match secondary.info().peer_id() {
            Some(p) => p,
            None => return Err(Error::NoPeerId)
        };
        if publisher_id != self.id {
            return Err(Error::UnexpectedPeerId)
        }

        if secondary.application_id() != self.application_id {
            return Err(Error::UnexpectedApplicationId)
        }

        return Ok(())
    }

    fn validate_data(&mut self, data: &Page) -> Result<(), Error> {
        if !data.kind().is_data() {
            return Err(Error::ExpectedDataObject);
        }

        if data.id() != &self.id {
            return Err(Error::UnexpectedServiceId)
        }
        if data.application_id() != self.application_id {
            return Err(Error::UnexpectedApplicationId)
        }

        return Ok(())
    }

}