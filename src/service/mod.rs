

use std::time::{Duration, SystemTime};
use std::ops::Add;

use crate::types::{Id, Kind, Flags, Error, PublicKey, PrivateKey, Signature, SecretKey};
use crate::protocol::{page::Page, options::Options};

use crate::crypto;

/// Generic Service Type.
/// This provides the basis for all services in DSR.
/// 
/// Services should be constructed using the ServiceBuilder type
#[derive(Clone, Builder)]
#[builder(default, build_fn(validate = "Self::validate"))]
pub struct Service {
    id: Id,
    kind: Kind,
    version: u16,
    flags: Flags,

    body: Vec<u8>,

    public_options: Vec<Options>,
    private_options: Vec<Options>,

    public_key: PublicKey,
    private_key: Option<PrivateKey>,
    secret_key: Option<SecretKey>,
}

impl ServiceBuilder {
    /// Validate service options prior to building
    fn validate(&self) -> Result<(), String> {
        // Ensure a secret key is available if private options are used
        if let Some(private_opts) = &self.private_options {
            if private_opts.len() > 0 && self.secret_key.is_none() {
                return Err("Private options cannot be used without specifying or creating an associated secret key".to_owned());
            }
        }

        Ok(())
    }

    /// Setup a peer service.
    /// This is equivalent to .kind(Kind::Peer)
    pub fn peer(&mut self) -> &mut Self {
        let mut new = self;
        new.kind = Some(Kind::Peer);
        new
    }

    /// Setup a generic service.
    /// This is equivalent to .kind(Kind::Generic)
    pub fn generic(&mut self) -> &mut Self {
        let mut new = self;
        new.kind = Some(Kind::Generic);
        new
    }

    /// Setup a private service.
    /// This is equivalent to .kind(Kind::Private)
    pub fn private(&mut self) -> &mut Self {
        let mut new = self;
        new.kind = Some(Kind::Generic);
        new
    }

    /// Generate a new encrypted service with secret key
    pub fn encrypted(&mut self) -> &mut Self {
        let mut new = self;

        let secret_key = crypto::new_sk().unwrap();
        new.secret_key = Some(Some(secret_key));

        new
    }
}

impl Service
{
    /// Update a service.
    /// This allows in-place editing of descriptors and options and causes an update of the service version number.
    pub fn update<U>(&mut self, update_fn: U) 
    where U: Fn(&mut Vec<u8>, &mut Vec<Options>, &mut Vec<Options>)
    {
        update_fn(&mut self.body, &mut self.public_options, &mut self.private_options);
        self.version += 1;
    }

    /// Create a service instance from a given page
    pub fn from(page: &Page) -> Result<Self, Error> {
        let header = page.header();
        let body = page.body();
        let public_options = page.public_options();
        let private_options = page.private_options();

        // Fetch public key from options
        let public_key = match public_options.iter().find_map(|o| match o { Options::PubKey(pk) => Some(pk), _ => None } ) {
            Some(pk) => pk.public_key,
            None => return Err(Error::NoPublicKey)
        };

        Ok(Service{
            id: *page.id(),
            kind: header.kind(),
            version: header.version(),
            flags: header.flags(),

            body: body.to_vec(),

            public_options: public_options.to_vec(),
            private_options: private_options.to_vec(),

            public_key,
            private_key: None,
            secret_key: None,
        })
    }

    /// Apply an upgrade to an existing service.
    /// This consumes a new page and updates the service instance
    pub fn apply_update(&mut self, page: &Page) -> Result<(), Error> {
        let header = page.header();
        let body = page.body();
        
        let public_options = page.public_options();
        let private_options = page.private_options();

        // Check fields match
        if page.id() != &self.id {
            return Err(Error::UnexpectedServiceId)
        }
        if header.version() <= self.version {
            return Err(Error::InvalidServiceVersion)
        }
        if header.kind() != self.kind {
            return Err(Error::InvalidPageKind)
        }

        self.version = header.version();
        self.flags = header.flags();
        self.body = body.to_vec();
        self.public_options = public_options.to_vec();
        self.private_options = private_options.to_vec();
    
        Ok(())
    }

    /// Publish generates a page for publishing for the given service.
    pub fn publish(&self) -> Page {
        // Insert default options
        // TODO: is this the right place to do this? Should they be deduplicated?
        let mut default_options = vec![
            Options::issued(SystemTime::now()),
            Options::expiry(SystemTime::now().add(Duration::from_secs(24 * 60 * 60))),
            Options::public_key(self.public_key),
        ];

        let mut public_options = self.public_options.clone();
        public_options.append(&mut default_options);

        Page::new(self.id.clone(), self.kind, self.flags, self.version, self.body.clone(), public_options, self.private_options.clone())
    }
 

    /// Sign the provided data with the associated service key.
    /// This returns an error if the service does not have an attached service private key
    pub fn sign(&mut self, data: &[u8]) -> Result<Signature, Error> {
        if let Some(private_key) = self.private_key {
            let sig = crypto::pk_sign(&private_key, data).unwrap();
            Ok(sig)
        } else {
            Err(Error::NoPrivateKey)
        }
    }

    /// Validate a signature against the service public key.
    /// This returns true on success, false for an invalid signature, and an error if an internal fault occurs
    pub fn validate(&self, signature: &[u8], data: &[u8]) -> Result<bool, Error> {
        let valid = crypto::pk_validate(&self.public_key, signature, data).unwrap();

        Ok(valid)
    }
}

impl Default for Service {
    /// Create a default / blank Service for further initialisation.
    fn default() -> Service {
         // Generate service key-pair
        let (public_key, private_key) = crypto::new_pk().unwrap();

        // Generate service ID from public key
        let id = crypto::hash(&public_key).unwrap();

        // Create service object
        Service{id, kind: Kind::None, flags: 0.into(), version: 0, body: vec![], public_options: vec![], private_options: vec![], public_key: public_key, private_key: Some(private_key), secret_key: None}
    }
}


#[cfg(test)]
mod test {

    use std::net::{SocketAddrV4, Ipv4Addr};

    use super::*;

    #[test]
    fn test_service() {
        let socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080);

        println!("Creating new service");
        let mut service = ServiceBuilder::default()
                .kind(Kind::Generic)
                .public_options(vec![Options::name("Test Service")])
                .private_options(vec![Options::address(socket)])
                .encrypted()
                .build().unwrap();

        println!("Generating service page");
        let mut page1 = service.publish();

        println!("Encoding service page");
        let mut buff = vec![0u8; 1024];
        let (encoded, _n) = page1.encode(|_, d| service.sign(d).unwrap(), &mut buff).expect("Error encoding service page");

        println!("Encoded service to {} bytes", encoded.len());
    
        println!("Decoding service page");
        let (page2, _) = Page::parse(|_, d, s| true, encoded).expect("Error parsing service page");
        assert_eq!(page1, page2);

        println!("Generating service replica");
        let mut replica = Service::from(&page2).expect("Error generating service replica");

        println!("Updating service");
        service.update(|_body, public_options, _private_options| {
            public_options.push(Options::kind("Test Kind"));
        });
        assert_eq!(service.version, 1, "service.update updates service version");

        println!("Generating updated page");
        let mut page3 = service.publish();

        println!("Applying updated page to replica");
        replica.apply_update(&page3).expect("Error updating service replica");

    }
}