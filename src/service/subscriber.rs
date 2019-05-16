use std::convert::TryInto;

use crate::types::*;
use crate::service::Service;
use crate::protocol::page::{Page, PageInfo};
use crate::crypto;


pub trait Subscriber {
    /// Create a service instance (or replica) from a given primary service page
    fn load(page: &Page) -> Result<Service, Error>;
    
    /// Apply an updated primary page to an existing service instance
    fn apply_primary(&mut self, primary: &Page) -> Result<bool, Error>;

    /// Validate a given secondary page published by this service
    fn validate_page(&mut self, page: &Page) -> Result<(), Error>;
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
    fn apply_primary(&mut self, update: &Page) -> Result<bool, Error> {
        let flags = update.flags();
        let body = update.body();

        let public_options = update.public_options();
        let private_options = update.private_options();

        self.validate_primary(update)?;

        if update.version() == self.version {
            return Ok(false)
        }
        if update.version() <= self.version {
            return Err(Error::InvalidServiceVersion)
        }

        self.version = update.version();
        self.encrypted = flags.encrypted();
        self.body = body.to_vec();
        self.public_options = public_options.to_vec();
        self.private_options = private_options.to_vec();
    
        Ok(true)
    }

    fn validate_page(&mut self, page: &Page) -> Result<(), Error> {
        if page.kind().is_page() {
            if page.flags().primary() {
                self.validate_primary(page)
            } else {
                self.validate_secondary(page)
            }
        } else if page.kind().is_data() {
            self.validate_data(page)
        } else {
            Err(Error::UnexpectedPageKind)
        }
    }

}

impl Service {
    /// Validate a primary page
    pub(crate) fn validate_primary(&mut self, page: &Page) -> Result<(), Error> {
        if !page.kind().is_page() {
            return Err(Error::ExpectedPrimaryPage);
        }
        if !page.flags().primary() {
            return Err(Error::ExpectedPrimaryPage)
        }

        if page.id() != &self.id {
            return Err(Error::UnexpectedServiceId)
        }
        if page.application_id() != self.application_id {
            return Err(Error::UnexpectedApplicationId)
        }
        if page.kind() != self.kind.into() {
            return Err(Error::InvalidPageKind)
        }

        // Fetch public key from options
        let public_key: PublicKey = match page.info() {
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

        return Ok(())
    }

    /// Validate a secondary page
    pub(crate) fn validate_secondary(&mut self, secondary: &Page) -> Result<(), Error> {
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

    /// Validate a data objects
    pub(crate) fn validate_data(&mut self, data: &Page) -> Result<(), Error> {
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