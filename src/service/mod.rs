//! This module provides a DSF Service implementation.
//!
//! `Publisher`, `Subscriber`, and `Net` traits provide functionality for publishing services,
//! subscribing to services, and sending messages respectively.

use crate::base::{MaybeEncrypted, PageBody};
use crate::crypto::{Crypto, PubKey as _, SecKey as _, Hash as _};
use crate::error::Error;
use crate::options::Options;
use crate::types::*;

#[cfg(feature = "alloc")]
use alloc::vec::{Vec};

mod kinds;
pub use kinds::*;
// Service extensions
mod publisher;
pub use publisher::{Publisher, DataOptions, SecondaryOptions};

mod subscriber;
pub use subscriber::Subscriber;

mod registry;
pub use registry::{Registry, TertiaryOptions};

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
pub struct Service<B: PageBody = Vec<u8>> {
    id: Id,

    application_id: u16,
    kind: PageKind,

    version: u16,
    data_index: u16,

    body: MaybeEncrypted<B>,

    public_options: Vec<Options>,
    private_options: MaybeEncrypted<Vec<Options>>,

    public_key: PublicKey,
    private_key: Option<PrivateKey>,

    encrypted: bool,
    secret_key: Option<SecretKey>,

    last_sig: Option<Signature>,
}

impl <B: PageBody> Default for Service<B> {
    /// Create a default / blank Service for further initialisation.
    fn default() -> Self {
        // Generate service key-pair
        let (public_key, private_key) = Crypto::new_pk().unwrap();

        // Generate service ID from public key
        let id = Crypto::hash(&public_key).unwrap();

        // Create service object
        Service {
            id: Id::from(id.as_bytes()),
            application_id: 0,
            kind: PageKind::Generic,
            version: 0,
            data_index: 0,
            body: MaybeEncrypted::None,
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

impl <B: PageBody> Service<B> {
    pub fn id(&self) -> Id {
        self.id.clone()
    }

    /// Update a service.
    /// This allows in-place editing of descriptors and options and causes an update of the service version number
    /// as well as a reset of the data_index.
    pub fn update<U>(&mut self, update_fn: U) -> Result<(), Error>
    where
        U: Fn(&mut MaybeEncrypted<B>, &mut Vec<Options>, &mut MaybeEncrypted<Vec<Options>>),
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

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn kind(&self) -> PageKind {
        self.kind
    }

    pub fn body(&self) -> &MaybeEncrypted<B> {
        &self.body
    }

    pub fn public_options(&self) -> &[Options] {
        &self.public_options
    }

    pub fn encrypted(&self) -> bool {
        self.encrypted
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
            pub_key: Some(self.public_key.clone()),
            pri_key: self.private_key.as_ref().cloned(),
            sec_key: self.secret_key.as_ref().cloned(),
            sym_keys: None,
        }
    }
}

#[cfg(test)]
mod test {

    use std::net::{Ipv4Addr, SocketAddrV4};

    use pretty_assertions::{assert_eq};

    use crate::service::publisher::{DataOptions, Publisher, SecondaryOptions};
    use crate::service::subscriber::Subscriber;
    use crate::wire::Container;

    use super::*;

    #[test]
    fn test_service() {
        //let _ = simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default());

        let socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080);

        println!("Creating new service");
        let service_builder = ServiceBuilder::<Vec<u8>>::default()
            .kind(PageKind::Generic.into())
            .public_options(vec![Options::name("Test Service")])
            .private_options(vec![Options::address_v4(socket)].into())
            .encrypt();
        let mut service = service_builder.build().unwrap();
        let keys = service.keys();

        println!("Generating and encoding service page");
        let (n, page1) = service
            .publish_primary_buff(Default::default())
            .expect("Error creating page");

        debug!("page1: {:?}", page1);

        let pp1 = Container::parse(page1.raw().to_vec(), &keys).unwrap();

        debug!("pp1: {:?}", pp1);

        // Append sig to page1
        //page1.set_signature(base1.signature().clone().unwrap());
        assert_eq!(service.version, 1, "initial service version");

        println!("Encoded service to {} bytes", n);

        println!("Decoding service page");
        let s = service.clone();

        let base2 = Container::parse(page1.raw().to_vec(), &keys).expect("Error parsing service page");
        assert_eq!(n, base2.len());
        assert_eq!(pp1, base2);

        println!("Generating service replica");
        let mut replica = Service::<Vec<u8>>::load(&base2).expect("Error generating service replica");

        println!("Updating service");
        service
            .update(|_body, public_options, _private_options| {
                public_options.push(Options::kind("Test Kind"));
            })
            .expect("Error updating service");
        assert_eq!(service.version, 2, "service.update updates service version");

        println!("Generating updated page");
        let (_n, page3) = service
            .publish_primary_buff(Default::default())
            .expect("Error publishing primary page");

        let pp3 = Container::parse(page3.raw().to_vec(), &keys).unwrap();

        println!("Applying updated page to replica");
        replica
            .apply_primary(&pp3)
            .expect("Error updating service replica");
        assert_eq!(replica.version, 3);

        println!("Generating a secondary page");
        let secondary_options = SecondaryOptions::default();
        let (_n, secondary) = service
            .publish_secondary_buff(&s.id(), secondary_options)
            .expect("Error publishing secondary page");

        println!("Validating secondary page");
        // Convert secondary container to page
        let b = Container::parse(secondary.raw().to_vec(), &s.keys()).unwrap();
        service
            .validate_secondary(&b)
            .expect("Error validating secondary page against publisher");

        println!("Generating a data object");
        let data_options = DataOptions::<'static, &[u8]>::default();
        let (_n, data) = service
            .publish_data_buff(data_options)
            .expect("Error publishing data object");

        println!("Validating data object");
        let b = Container::parse(data.raw().to_vec(), &s.keys()).unwrap();
        replica
            .validate_data(&b)
            .expect("Error validating data against replica");
    }
}
