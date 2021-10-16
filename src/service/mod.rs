//! This module provides a DSF Service implementation.
//!
//! `Publisher`, `Subscriber`, and `Net` traits provide functionality for publishing services,
//! subscribing to services, and sending messages respectively.

use crate::base::{Body, MaybeEncrypted};
use crate::crypto;
use crate::error::Error;
use crate::options::Options;
use crate::types::*;

#[cfg(feature = "alloc")]
use alloc::prelude::v1::*;

mod kinds;
pub use kinds::*;
// Service extensions
mod publisher;
pub use publisher::{Publisher, DataOptions, SecondaryOptions};

mod subscriber;
pub use subscriber::Subscriber;

mod net;
pub use net::Net;

mod builder;
pub use builder::ServiceBuilder;

use crate::keys::Keys;

/// Generic Service Type.
/// This provides the basis for all services in DSF.
///
/// Services should be constructed using the ServiceBuilder type
#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "diesel", derive(diesel::Queryable))]
pub struct Service {
    id: Id,

    application_id: u16,
    kind: PageKind,

    version: u16,
    data_index: u16,

    body: Body,

    public_options: Vec<Options>,
    private_options: MaybeEncrypted<Vec<Options>>,

    public_key: PublicKey,
    private_key: Option<PrivateKey>,

    encrypted: bool,
    secret_key: Option<SecretKey>,

    last_sig: Option<Signature>,
}

impl Default for Service {
    /// Create a default / blank Service for further initialisation.
    fn default() -> Service {
        // Generate service key-pair
        let (public_key, private_key) = crypto::new_pk().unwrap();

        // Generate service ID from public key
        let id = crypto::hash(&public_key).unwrap().into();

        // Create service object
        Service {
            id,
            application_id: 0,
            kind: PageKind::Generic,
            version: 0,
            data_index: 0,
            body: Body::None,
            public_options: vec![],
            private_options: MaybeEncrypted::None,
            public_key,
            private_key: Some(private_key),
            encrypted: false,
            secret_key: None,
            last_sig: None,
        }
    }
}

impl Service {
    pub fn id(&self) -> Id {
        self.id.clone()
    }

    /// Update a service.
    /// This allows in-place editing of descriptors and options and causes an update of the service version number
    /// as well as a reset of the data_index.
    pub fn update<U>(&mut self, update_fn: U) -> Result<(), Error>
    where
        U: Fn(&mut Body, &mut Vec<Options>, &mut MaybeEncrypted<Vec<Options>>),
    {
        if self.private_key().is_none() {
            return Err(Error::NoPrivateKey);
        }

        update_fn(
            &mut self.body,
            &mut self.public_options,
            &mut self.private_options,
        );

        // Update service version
        self.version += 1;

        // Reset data index to 0;
        self.data_index = 0;

        Ok(())
    }

    pub fn is_origin(&self) -> bool {
        match (&self.private_key, &self.encrypted, &self.secret_key) {
            (Some(_), false, _) => true,
            (Some(_), true, Some(_)) => true,
            _ => false,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    pub fn private_key(&self) -> Option<PrivateKey> {
        self.private_key.clone()
    }

    pub fn secret_key(&self) -> Option<SecretKey> {
        self.secret_key.clone()
    }

    pub fn set_private_key(&mut self, key: Option<PrivateKey>) {
        self.private_key = key;
    }

    pub fn set_secret_key(&mut self, key: Option<SecretKey>) {
        self.secret_key = key;
    }

    pub fn keys(&self) -> Keys {
        Keys {
            pub_key: self.public_key.clone(),
            pri_key: self.private_key.as_ref().map(|v| v.clone()),
            sec_key: self.secret_key.as_ref().map(|v| v.clone()),
            sym_keys: None,
        }
    }
}

#[cfg(test)]
mod test {

    use core::convert::TryInto;
    use std::net::{Ipv4Addr, SocketAddrV4};

    use crate::base::Base;
    use crate::page::Page;
    use crate::service::publisher::{DataOptions, Publisher, SecondaryOptions};
    use crate::service::subscriber::Subscriber;

    use super::*;

    #[test]
    fn test_service() {
        //let _ = simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default());

        let socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080);

        println!("Creating new service");
        let service_builder = ServiceBuilder::default()
            .kind(PageKind::Generic.into())
            .public_options(vec![Options::name("Test Service")])
            .private_options(vec![Options::address_v4(socket)].into())
            .encrypt();
        let mut service = service_builder.build().unwrap();
        let keys = service.keys();

        println!("Generating and encoding service page");
        let mut buff = vec![0u8; 1024];
        let (n, mut page1) = service
            .publish_primary(&mut buff)
            .expect("Error creating page");

        // Append sig to page1
        //page1.set_signature(base1.signature().clone().unwrap());
        assert_eq!(service.version, 0, "initial service version");

        // Clear private data from encoded pages
        page1.clean();

        println!("Encoded service to {} bytes", n);

        println!("Decoding service page");
        let s = service.clone();

        let (base2, m) = Base::parse(&buff[..n], &keys).expect("Error parsing service page");
        assert_eq!(n, m);
        let mut page2: Page = base2
            .try_into()
            .expect("Error converting base message to page");
        page2.raw = None;
        assert_eq!(page1, page2);

        println!("Generating service replica");
        let mut replica = Service::load(&page2).expect("Error generating service replica");

        println!("Updating service");
        service
            .update(|_body, public_options, _private_options| {
                public_options.push(Options::kind("Test Kind"));
            })
            .expect("Error updating service");
        assert_eq!(service.version, 1, "service.update updates service version");

        println!("Generating updated page");
        let (_n, page3) = service
            .publish_primary(&mut buff)
            .expect("Error publishing primary page");

        println!("Applying updated page to replica");
        replica
            .apply_primary(&page3)
            .expect("Error updating service replica");
        assert_eq!(replica.version, 1);

        println!("Generating a secondary page");
        let secondary_options = SecondaryOptions::default();
        let (_n, secondary) = service
            .publish_secondary(&s.id(), secondary_options, &mut buff)
            .expect("Error publishing secondary page");

        println!("Validating secondary page");
        service
            .validate_secondary(&secondary)
            .expect("Error validating secondary page against publisher");

        println!("Generating a data object");
        let data_options = DataOptions::default();
        let (_n, data) = service
            .publish_data(data_options, &mut buff)
            .expect("Error publishing data object");

        println!("Validating data object");
        replica
            .validate_data(&data)
            .expect("Error validating data against replica");
    }
}
