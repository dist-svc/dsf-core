
use std::ops::Add;

use crate::options::Options;

use crate::error::Error;
use crate::prelude::{Header};
use crate::types::{Id, Kind, PageKind, Flags, Queryable, DateTime};
use crate::wire::{Builder, Container};

use super::Service;

pub trait Registry{
    /// Generate ID for registry lookup
    fn resolve(&self, q: impl Queryable) -> Result<Id, Error>;

    /// Generates a tertiary page for the provided service ID and options
    fn publish_tertiary<const N: usize, Q: Queryable> (
        &mut self,
        id: Id,
        opts: TertiaryOptions,
        q: Q,
    ) -> Result<Container<[u8; N]>, Error>;
}

/// Tertiary page configuration options
#[derive(Clone, PartialEq, Debug)]
pub struct TertiaryOptions {
    pub issued: DateTime,
    pub expiry: DateTime,
}

#[cfg(feature="std")]
impl Default for TertiaryOptions {
    /// Create a tertiary page with default 1 day expiry
    fn default() -> Self {
        let now = std::time::SystemTime::now();

        Self { 
            issued: now.into(), 
            expiry: now.add(std::time::Duration::from_secs(24 * 60 * 60)).into(),
        }
    }
}

impl Registry for Service {
    fn resolve(&self, q: impl Queryable) -> Result<Id, Error>{
        // Generate ID for page lookup using this registry
        let tid = crate::crypto::hash_tid(self.id(), &self.keys(), q);
        // Return ID for page lookup
        Ok(tid)
    }

    fn publish_tertiary<const N: usize, Q: Queryable>(
        &mut self,
        id: Id,
        opts: TertiaryOptions,
        q: Q,
    ) -> Result<Container<[u8; N]>, Error> {

        // Generate TID
        let tid = crate::crypto::hash_tid(self.id(), &self.keys(), q);

        // Setup flags
        let mut flags = Flags::TERTIARY;
        if self.encrypted {
            flags |= Flags::ENCRYPTED;
        }

        // Setup header
        let header = Header {
            kind: Kind::page(PageKind::Tertiary as u16),
            index: 0,
            flags,
            ..Default::default()
        };

        // TODO: should service link be in private options..?
        let b = Builder::new([0u8; N])
            .header(&header)
            .id(&tid)
            .body(&id)?
            .private_options(&[])?;

        // Apply internal encryption if enabled
        let b = self.encrypt(b)?;

        let b = b.public_options(&[
            Options::peer_id(self.id()),
            Options::issued(opts.issued),
            Options::expiry(opts.expiry),
        ])?;

        // Sign generated object
        let c = self.sign(b)?;

        Ok(c)
    }
}


#[cfg(test)]
mod test {
    use crate::{prelude::*, service::Publisher};
    use crate::options::{Options, Name, Filters};

    use super::*;

    fn registry_publish(mut r: Service) {
        // Build target service
        let opt_name = Name::new("something");
        let mut c = ServiceBuilder::generic().public_options(vec![Options::Name(opt_name.clone())]).build().unwrap();
        
        let (_n, _c) = c.publish_primary_buff(Default::default()).unwrap();

        // Generate page for name entry
        let p1 = Registry::publish_tertiary::<512, _>(&mut r, c.id(), TertiaryOptions::default(), &opt_name).unwrap();

        println!("Tertiary page: {:02x?}", p1);

        // Lookup TID for name
        let tid_name = Registry::resolve(&r, &opt_name).unwrap();
        assert_eq!(&p1.id(), &tid_name);

        // Check link to registry
        let opts: Vec<_> = p1.public_options_iter().collect();
        let pid = Filters::peer_id(&opts.iter()).unwrap();
        assert_eq!(pid, r.id());

        // Check link to service
        #[cfg(todo)]
        {
        let pi = match p1.info() {
            PageInfo::Tertiary(t) => Some(t),
            _ => None,
        }.unwrap();
        assert_eq!(pi.target_id, c.id());
    }
    }

    #[test]
    fn registry_publish_public() {
        // Build registry service
        let r = ServiceBuilder::ns("test.com")
            .build().unwrap();

        // Test publishing
        registry_publish(r);
    }

    #[test]
    fn registry_publish_private() {
        // Build registry service
        let r = ServiceBuilder::ns("test.com")
            .encrypt().build().unwrap();

        // Test publishing
        registry_publish(r);
    }
}
