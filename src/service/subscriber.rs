use core::convert::TryInto;



use crate::crypto;
use crate::error::Error;
use crate::page::{PageInfo};
use crate::prelude::MaybeEncrypted;
use crate::service::Service;
use crate::types::*;
use crate::wire::Container;

pub trait Subscriber {
    /// Create a service instance (or replica) from a given primary service page
    fn load<T: ImmutableData>(page: &Container<T>) -> Result<Service, Error>;

    /// Apply an updated primary page to an existing service instance
    fn apply_primary<T: ImmutableData>(&mut self, primary: &Container<T>) -> Result<bool, Error>;

    /// Validate a given secondary (or tertiary) page published by this service
    fn validate_page<T: ImmutableData>(&mut self, page: &Container<T>) -> Result<(), Error>;

    /// Validate data published by this service
    fn validate_block<T: ImmutableData>(&mut self, _block: &Container<T>) -> Result<(), Error> { todo!() }
}

impl Subscriber for Service {
    /// Create a service instance from a given page
    fn load<T: ImmutableData>(page: &Container<T>) -> Result<Service, Error> {
        let header = page.header();
        let flags = header.flags();

        let public_key = match page.info()? {
            PageInfo::Primary(primary) => primary.pub_key.clone(),
            _ => {
                error!("Attempted to load service from secondary page");
                return Err(Error::UnexpectedPageType);
            }
        };

        let body = match page.encrypted() {
            true => MaybeEncrypted::Encrypted(page.body_raw().to_vec()),
            false => MaybeEncrypted::Cleartext(page.body_raw().to_vec()),
        };

        let public_options: Vec<_> = page.public_options_iter().collect();
        let private_options = match page.encrypted() {
            true => MaybeEncrypted::Encrypted(page.private_options_raw().to_vec()),
            false => MaybeEncrypted::Cleartext(page.private_options_iter().collect()),
        };

        Ok(Service {
            id: page.id().clone(),

            application_id: header.application_id(),
            kind: header.kind().try_into().unwrap(),

            version: header.index(),
            data_index: 0,

            body: body.clone(),

            public_options: public_options,
            private_options: private_options,

            public_key,
            private_key: None,

            encrypted: flags.contains(Flags::ENCRYPTED),
            secret_key: None,

            last_sig: Some(page.signature()),
        })
    }

    /// Apply an upgrade to an existing service.
    /// This consumes a new page and updates the service instance
    fn apply_primary<T: ImmutableData>(&mut self, update: &Container<T>) -> Result<bool, Error> {
        let header = update.header();

        let flags = header.flags();
        
        let body = match update.encrypted() {
            true => MaybeEncrypted::Encrypted(update.body_raw().to_vec()),
            false => MaybeEncrypted::Cleartext(update.body_raw().to_vec()),
        };

        let public_options: Vec<_> = update.public_options_iter().collect();
        let private_options = match update.encrypted() {
            true => MaybeEncrypted::Encrypted(update.private_options_raw().to_vec()),
            false => MaybeEncrypted::Cleartext(update.private_options_iter().collect()),
        };

        self.validate_primary(update)?;

        if header.index() == self.version {
            return Ok(false);
        }
        if header.index() <= self.version {
            return Err(Error::InvalidServiceVersion);
        }

        self.version = header.index();
        self.encrypted = flags.contains(Flags::ENCRYPTED);
        self.body = body;
        self.public_options = public_options;
        self.private_options = private_options;

        Ok(true)
    }

    fn validate_page<T: ImmutableData>(&mut self, page: &Container<T>) -> Result<(), Error> {
        let header = page.header();

        if header.kind().is_page() {
            if !header.flags().contains(Flags::SECONDARY) && !header.flags().contains(Flags::TERTIARY) {
                self.validate_primary(page)?
            } else if header.flags().contains(Flags::SECONDARY) {
                self.validate_secondary(page)?
            } else if header.flags().contains(Flags::TERTIARY) {
                todo!("Tertiary page validation");
            }
        } else if header.kind().is_data() {
            self.validate_data(page)?
        } else {
            return Err(Error::UnexpectedPageKind)
        }
        
        Ok(())
    }
}

impl Service {
    /// Validate a primary page
    pub(crate) fn validate_primary<T: ImmutableData>(&mut self, page: &Container<T>) -> Result<(), Error> {
        let header = page.header();

        if !header.kind().is_page() {
            return Err(Error::ExpectedPrimaryPage);
        }
        if header.flags().contains(Flags::SECONDARY) {
            return Err(Error::ExpectedPrimaryPage);
        }

        if page.id() != self.id {
            return Err(Error::UnexpectedServiceId);
        }
        if header.application_id() != self.application_id {
            return Err(Error::UnexpectedApplicationId);
        }
        if header.kind() != self.kind.into() {
            return Err(Error::InvalidPageKind);
        }

        // Fetch public key from options
        let public_key: PublicKey = match page.info()? {
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
    pub(crate) fn validate_secondary<T: ImmutableData>(&mut self, secondary: &Container<T>) -> Result<(), Error> {
        let header = secondary.header();

        if !header.kind().is_page() {
            return Err(Error::ExpectedPrimaryPage);
        }
        if !header.flags().contains(Flags::SECONDARY) {
            return Err(Error::ExpectedSecondaryPage);
        }

        let publisher_id = match secondary.info()?.peer_id() {
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
    pub(crate) fn validate_data<T: ImmutableData>(&mut self, data: &Container<T>) -> Result<(), Error> {
        let header = data.header();

        if !header.kind().is_data() {
            return Err(Error::ExpectedDataObject);
        }

        if data.id() != self.id {
            return Err(Error::UnexpectedServiceId);
        }
        if header.application_id() != self.application_id {
            return Err(Error::UnexpectedApplicationId);
        }

        Ok(())
    }
}
