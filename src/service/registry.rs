
use crate::page::{Page, PageOptions, Tertiary};
use crate::error::Error;
use crate::prelude::{Body, Header, PageInfo};
use crate::types::{Id, Kind, PageKind, Flags, Queryable};

use super::Service;

pub trait Registry<const N: usize = 512> {
    /// Generate ID for registry lookup
    fn resolve(&self, q: impl Queryable) -> Result<Id, Error>;

    /// Generates a tertiary page for the provided service ID and options
    fn publish_tertiary(
        &mut self,
        id: Id,
        q: impl Queryable,
    ) -> Result<(Page), Error>;
}

impl <const N: usize> Registry<N> for Service {
    fn resolve(&self, q: impl Queryable) -> Result<Id, Error>{
        // Generate ID for page lookup using this registry
        let tid = crate::crypto::hash_tid(self.id(), &self.keys(), q.as_ref());
        Ok(tid)
    }

    fn publish_tertiary(
        &mut self,
        id: Id,
        q: impl Queryable,
    ) -> Result<(Page), Error> {

        // Generate TID
        let tid = crate::crypto::hash_tid(self.id(), &self.keys(), q.as_ref());

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
            public_options: &[],
            ..Default::default()
        };
    
        let mut p = Page::new(
            tid.clone(),
            header,
            // TODO: link ns and ts IDs
            PageInfo::Tertiary(Tertiary{service_id: id}),
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
    use super::*;

    #[test]
    fn test_registry_publish() {
        // Buld registry service
        let mut r = ServiceBuilder::ns("test.com").build().unwrap();

        // Build target service
        let mut c = ServiceBuilder::generic().public_options(vec![Options::name("something")]).build().unwrap();
         
        let p = c.publish_primary_buff().unwrap();

        // TODO: how to actually abstractly generate hashes..?


    }
}