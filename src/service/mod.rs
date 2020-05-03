//! This module provides a DSF Service implementation.
//!
//! `Publisher`, `Subscriber`, and `Net` traits provide functionality for publishing services,
//! subscribing to services, and sending messages respectively.

use crate::base::{Body, PrivateOptions};
use crate::crypto;
use crate::options::Options;
use crate::types::*;

pub mod kinds;

// Service extensions
pub mod publisher;
pub use publisher::{DataOptionsBuilder, Publisher, SecondaryOptionsBuilder};

pub mod subscriber;
pub use subscriber::Subscriber;

pub mod net;
pub use net::Net;

mod builder;

/// Generic Service Type.
/// This provides the basis for all services in DSR.
///
/// Services should be constructed using the ServiceBuilder type
#[derive(PartialEq, Debug, Clone, Builder)]
#[builder(default, build_fn(validate = "Self::validate"))]
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
    private_options: PrivateOptions,

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
            private_options: PrivateOptions::None,
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
        U: Fn(&mut Body, &mut Vec<Options>, &mut PrivateOptions),
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
}

#[cfg(test)]
mod test {

    use std::convert::TryInto;
    use std::net::{Ipv4Addr, SocketAddrV4};

    use crate::base::Base;
    use crate::page::Page;
    use crate::service::publisher::{DataOptionsBuilder, Publisher, SecondaryOptionsBuilder};
    use crate::service::subscriber::Subscriber;

    use super::*;

    #[test]
    fn test_service() {
        let socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080);

        println!("Creating new service");
        let mut service = ServiceBuilder::default()
            .kind(PageKind::Generic.into())
            .public_options(vec![Options::name("Test Service")])
            .private_options(vec![Options::address(socket)].into())
            .encrypt()
            .build()
            .unwrap();

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
        let pub_key = s.public_key();
        let sec_key = s.secret_key();

        let (base2, m) = Base::parse(&buff[..n], |_id| Some(pub_key.clone()), |_id| sec_key.clone())
            .expect("Error parsing service page");
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
        let secondary_options = SecondaryOptionsBuilder::default()
            .id(s.id())
            .build()
            .expect("Error building secondary options");
        let (_n, secondary) = service
            .publish_secondary(secondary_options, &mut buff)
            .expect("Error publishing secondary page");

        println!("Validating secondary page");
        service
            .validate_secondary(&secondary)
            .expect("Error validating secondary page against publisher");

        println!("Generating a data object");
        let data_options = DataOptionsBuilder::default()
            .build()
            .expect("Error building data options");
        let (_n, data) = service
            .publish_data(data_options, &mut buff)
            .expect("Error publishing data object");

        println!("Validating data object");
        replica
            .validate_data(&data)
            .expect("Error validating data against replica");
    }
}
