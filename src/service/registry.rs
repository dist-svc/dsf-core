
use std::ops::Add;

use crate::options::Options;
use crate::page::{Page, PageOptions};
use crate::error::Error;
use crate::prelude::{Body, Header, PageInfo};
use crate::types::{Id, Kind, PageKind, Flags, Queryable, DateTime};

use super::Service;

pub trait Registry<const N: usize = 512> {
    /// Generate ID for registry lookup
    fn resolve(&self, q: impl Queryable) -> Result<Id, Error>;

    /// Generates a tertiary page for the provided service ID and options
    fn publish_tertiary(
        &mut self,
        id: Id,
        opts: TertiaryOptions,
        q: impl Queryable,
    ) -> Result<Page, Error>;
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

impl <const N: usize> Registry<N> for Service {
    fn resolve(&self, q: impl Queryable) -> Result<Id, Error>{
        // Generate ID for page lookup using this registry
        let tid = crate::crypto::hash_tid(self.id(), &self.keys(), q);
        // Return ID for page lookup
        Ok(tid)
    }

    fn publish_tertiary(
        &mut self,
        id: Id,
        opts: TertiaryOptions,
        q: impl Queryable,
    ) -> Result<Page, Error> {

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
    
        let opts = PageOptions {
            public_options: &[
                Options::peer_id(self.id()),
                Options::issued(opts.issued),
                Options::expiry(opts.expiry),
            ],
            ..Default::default()
        };
    
        let mut p = Page::new(
            tid.clone(),
            header,
            // TODO: link ns and ts IDs
            PageInfo::tertiary(id),
            Body::None,
            opts,
        );
        
        // Encode page
        let mut b = [0u8; N];
        let _n = self.encode(&mut p, &mut b).unwrap();

        Ok(p)
    }
}


#[cfg(test)]
mod test {
    use crate::{prelude::*, service::Publisher};
    use crate::options::{Options, Name};

    use super::*;

    fn registry_publish(mut r: Service) {
        // Build target service
        let opt_name = Name::new("something");
        let mut c = ServiceBuilder::generic().public_options(vec![Options::Name(opt_name.clone())]).build().unwrap();
        
        let (_n, _c) = c.publish_primary_buff(Default::default()).unwrap();

        // Generate page for name entry
        let p1 = Registry::<256>::publish_tertiary(&mut r, c.id(), TertiaryOptions::default(), &opt_name).unwrap();

        // Lookup TID for name
        let tid_name = Registry::<256>::resolve(&r, &opt_name).unwrap();
        assert_eq!(p1.id(), &tid_name);

        // Check link to registry
        let pid = p1.public_options().iter().find_map(|o| {
            match o {
                Options::PeerId(p) => Some(p),
                _ => None,
            }
        }).unwrap();
        assert_eq!(pid.peer_id, r.id());

        // Check link to service
        let pi = match p1.info() {
            PageInfo::Tertiary(t) => Some(t),
            _ => None,
        }.unwrap();
        assert_eq!(pi.target_id, c.id());
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
