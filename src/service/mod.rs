


use crate::types::*;
use crate::protocol::{options::Options};
use crate::crypto;

pub mod kinds;

// Service extensions
pub mod publisher;
pub use publisher::{Publisher, SecondaryOptionsBuilder, DataOptionsBuilder};

pub mod subscriber;
pub use subscriber::Subscriber;

pub mod net;
pub use net::Net;

mod builder;

/// Generic Service Type.
/// This provides the basis for all services in DSR.
/// 
/// Services should be constructed using the ServiceBuilder type
#[derive(Clone, Debug, Builder, Serialize, Deserialize)]
#[builder(default, build_fn(validate = "Self::validate"))]
pub struct Service {
    id: Id,

    application_id: u16,
    kind: PageKind,

    version: u16,
    data_index: u16,

    body: Vec<u8>,

    public_options: Vec<Options>,
    private_options: Vec<Options>,

    public_key: PublicKey,
    private_key: Option<PrivateKey>,

    encrypted: bool,
    secret_key: Option<SecretKey>,
}

impl Default for Service {
    /// Create a default / blank Service for further initialisation.
    fn default() -> Service {
         // Generate service key-pair
        let (public_key, private_key) = crypto::new_pk().unwrap();

        // Generate service ID from public key
        let id = crypto::hash(&public_key).unwrap().into();

        // Create service object
        Service{id, application_id: 0, kind: PageKind::Generic, version: 0, data_index: 0, body: vec![], public_options: vec![], private_options: vec![], public_key: public_key, private_key: Some(private_key), encrypted: false, secret_key: None}
    }
}

impl Service
{
    pub fn id(&self) -> Id {
        self.id.clone()
    }

    /// Update a service.
    /// This allows in-place editing of descriptors and options and causes an update of the service version number.
    pub fn update<U>(&mut self, update_fn: U) -> Result<(), Error>
        where U: Fn(&mut Vec<u8>, &mut Vec<Options>, &mut Vec<Options>)
    {
        if let None = self.private_key() {
            return Err(Error::NoPrivateKey);
        }

        update_fn(&mut self.body, &mut self.public_options, &mut self.private_options);
        self.version += 1;

        Ok(())
    }

    pub fn is_origin(&self) -> bool {
        match (self.private_key, self.encrypted, self.secret_key) {
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
}



/// Service Cryptographic Methods
pub trait Crypto {
    fn sign(&mut self, data: &[u8]) -> Result<Signature, Error>;
    fn validate(&self, signature: &Signature, data: &[u8]) -> Result<bool, Error>;

    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

impl Crypto for Service {
    /// Sign the provided data with the associated service key.
    /// This returns an error if the service does not have an attached service private key
    fn sign(&mut self, data: &[u8]) -> Result<Signature, Error> {
        if let Some(private_key) = &self.private_key {
            let sig = crypto::pk_sign(&private_key, data).unwrap();
            Ok(sig)
        } else {
            Err(Error::NoPrivateKey)
        }
    }

    /// Validate a signature against the service public key.
    /// This returns true on success, false for an invalid signature, and an error if an internal fault occurs
    fn validate(&self, signature: &Signature, data: &[u8]) -> Result<bool, Error> {
        let valid = crypto::pk_validate(&self.public_key, signature, data).unwrap();
        Ok(valid)
    }

    fn encrypt(&mut self, _data: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some(_secret_key) = &self.secret_key {
            //let encrypted = crypto::sk_encrypt(&secret_key, data).unwrap();
            //Ok(encrypted)
            Err(Error::Unimplemented)
        } else {
            Err(Error::NoPrivateKey)
        }
    }

    fn decrypt(&self, _data: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some(_secret_key) = &self.secret_key {
            //let encrypted = crypto::sk_encrypt(&secret_key, data).unwrap();
            //Ok(encrypted)
            Err(Error::Unimplemented)
        } else {
            Err(Error::NoPrivateKey)
        }
    }
}


#[cfg(test)]
mod test {

    use std::net::{SocketAddrV4, Ipv4Addr};
    use std::convert::TryInto;

    use crate::service::subscriber::Subscriber;
    use crate::service::publisher::{Publisher, SecondaryOptionsBuilder, DataOptionsBuilder};
    use crate::protocol::WireEncode;
    use crate::protocol::{base::Base, page::Page};

    use super::*;

    #[test]
    fn test_service() {
        let socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080);

        println!("Creating new service");
        let mut service = ServiceBuilder::default()
                .kind(PageKind::Generic.into())
                .public_options(vec![Options::name("Test Service")])
                .private_options(vec![Options::address(socket)])
                .encrypt()
                .build().unwrap();

        println!("Generating service page");
        let mut page1 = service.publish_primary();

        println!("Encoding service page");
        let mut buff = vec![0u8; 1024];
        let n = WireEncode::encode(&mut page1, &mut buff).expect("Error encoding service page");
        // Append sig to page1
        //page1.set_signature(base1.signature().clone().unwrap());

        // Clear private data from encoded pages
        page1.clean();

        println!("Encoded service to {} bytes", n);
    
        println!("Decoding service page");
        let s = service.clone();
        let pub_key = s.public_key();
        let (base2, m) = Base::parse(&buff[..n], |_id| Some(pub_key) ).expect("Error parsing service page");
        assert_eq!(n, m);
        let mut page2: Page = base2.try_into().expect("Error converting base message to page");
        page2.clean();
        assert_eq!(page1, page2);

        println!("Generating service replica");
        let mut replica = Service::load(&page2).expect("Error generating service replica");

        println!("Updating service");
        service.update(|_body, public_options, _private_options| {
            public_options.push(Options::kind("Test Kind"));
        }).expect("Error updating service");
        assert_eq!(service.version, 1, "service.update updates service version");

        println!("Generating updated page");
        let page3 = service.publish_primary();

        println!("Applying updated page to replica");
        replica.apply_primary(&page3).expect("Error updating service replica");
        assert_eq!(replica.version, 1);

        println!("Generating a secondary page");
        let secondary_options = SecondaryOptionsBuilder::default().id(s.id()).build().expect("Error building secondary options");
        let secondary = service.publish_secondary(secondary_options);

        println!("Validating secondary page");
        service.validate_secondary(&secondary).expect("Error validating secondary page against publisher");

        println!("Generating a data object");
        let data_options = DataOptionsBuilder::default().build().expect("Error building data options");
        let data = service.publish_data(data_options);
        
        println!("Validating data object");
        replica.validate_data(&data).expect("Error validating data against replica");
    }
}