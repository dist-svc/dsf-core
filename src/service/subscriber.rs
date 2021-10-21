use core::convert::TryInto;

#[cfg(feature = "alloc")]
use alloc::vec::{Vec};

use crate::crypto;
use crate::error::Error;
use crate::page::{Page, PageInfo};
use crate::service::Service;
use crate::types::*;

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
        let header = page.header();
        let flags = header.flags();

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

        Ok(Service {
            id: page.id().clone(),

            application_id: header.application_id(),
            kind: header.kind().try_into().unwrap(),

            version: header.index(),
            data_index: 0,

            body: body.clone(),

            public_options: public_options.to_vec(),
            private_options: private_options.clone(),

            public_key,
            private_key: None,

            encrypted: flags.contains(Flags::ENCRYPTED),
            secret_key: None,

            last_sig: page.signature(),
        })
    }

    /// Apply an upgrade to an existing service.
    /// This consumes a new page and updates the service instance
    fn apply_primary(&mut self, update: &Page) -> Result<bool, Error> {
        let header = update.header();

        let flags = header.flags();
        let body = update.body();

        let public_options = update.public_options();
        let private_options = update.private_options();

        self.validate_primary(update)?;

        if header.index() == self.version {
            return Ok(false);
        }
        if header.index() <= self.version {
            return Err(Error::InvalidServiceVersion);
        }

        self.version = header.index();
        self.encrypted = flags.contains(Flags::ENCRYPTED);
        self.body = body.clone();
        self.public_options = public_options.to_vec();
        self.private_options = private_options.clone();

        Ok(true)
    }

    fn validate_page(&mut self, page: &Page) -> Result<(), Error> {
        let header = page.header();

        if header.kind().is_page() {
            if !header.flags().contains(Flags::SECONDARY) {
                self.validate_primary(page)
            } else {
                self.validate_secondary(page)
            }
        } else if header.kind().is_data() {
            self.validate_data(page)
        } else {
            Err(Error::UnexpectedPageKind)
        }
    }
}

impl Service {
    /// Validate a primary page
    pub(crate) fn validate_primary(&mut self, page: &Page) -> Result<(), Error> {
        let header = page.header();

        if !header.kind().is_page() {
            return Err(Error::ExpectedPrimaryPage);
        }
        if header.flags().contains(Flags::SECONDARY) {
            return Err(Error::ExpectedPrimaryPage);
        }

        if page.id() != &self.id {
            return Err(Error::UnexpectedServiceId);
        }
        if header.application_id() != self.application_id {
            return Err(Error::UnexpectedApplicationId);
        }
        if header.kind() != self.kind.into() {
            return Err(Error::InvalidPageKind);
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
            return Err(Error::KeyIdMismatch);
        }

        // Check public key hasn't changed
        if self.public_key != public_key {
            return Err(Error::PublicKeyChanged);
        }

        Ok(())
    }

    /// Validate a secondary page
    pub(crate) fn validate_secondary(&mut self, secondary: &Page) -> Result<(), Error> {
        let header = secondary.header();

        if !header.kind().is_page() {
            return Err(Error::ExpectedPrimaryPage);
        }
        if !header.flags().contains(Flags::SECONDARY) {
            return Err(Error::ExpectedSecondaryPage);
        }

        let publisher_id = match secondary.info().peer_id() {
            Some(p) => p,
            None => return Err(Error::NoPeerId),
        };
        if publisher_id != self.id {
            return Err(Error::UnexpectedPeerId);
        }

        if header.application_id() != self.application_id {
            return Err(Error::UnexpectedApplicationId);
        }

        Ok(())
    }

    /// Validate a data objects
    pub(crate) fn validate_data(&mut self, data: &Page) -> Result<(), Error> {
        let header = data.header();

        if !header.kind().is_data() {
            return Err(Error::ExpectedDataObject);
        }

        if data.id() != &self.id {
            return Err(Error::UnexpectedServiceId);
        }
        if header.application_id() != self.application_id {
            return Err(Error::UnexpectedApplicationId);
        }

        Ok(())
    }
}
