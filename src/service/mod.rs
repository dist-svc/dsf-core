

use std::time::{Duration, SystemTime};
use std::ops::Add;

use crate::types::{Id, Kind, Flags, Error, Address, PublicKey, PrivateKey, Signature, SecretKey};
use crate::protocol::{options::Options};
use crate::protocol::base::{Base, BaseBuilder};
use crate::protocol::page::{Page, PageInfo};
use crate::protocol::messages::{Request, Response, RequestKind, ResponseKind};

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

    body: Vec<u8>,

    public_options: Vec<Options>,
    private_options: Vec<Options>,

    public_key: PublicKey,
    private_key: Option<PrivateKey>,

    encrypted: bool,
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
        new.kind = Some(Kind::Private);
        new
    }

    /// Generate a new encrypted service
    /// this is equivalent to .secret_key(crypto::new_sk().unwrap()).encrypted(true);
    pub fn encrypt(&mut self) -> &mut Self {
        let mut new = self;
        let secret_key = crypto::new_sk().unwrap();
        new.secret_key = Some(Some(secret_key));
        new.encrypted = Some(true);
        new
    }
}

impl Default for Service {
    /// Create a default / blank Service for further initialisation.
    fn default() -> Service {
         // Generate service key-pair
        let (public_key, private_key) = crypto::new_pk().unwrap();

        // Generate service ID from public key
        let id = crypto::hash(&public_key).unwrap().into();

        // Create service object
        Service{id, kind: Kind::Generic, version: 0, body: vec![], public_options: vec![], private_options: vec![], public_key: public_key, private_key: Some(private_key), encrypted: false, secret_key: None}
    }
}

trait Publisher {
    /// Update allows services to be updated (and re-published)
    fn update<U>(&mut self, update_fn: U) 
        where U: Fn(&mut Vec<u8>, &mut Vec<Options>, &mut Vec<Options>);
    /// Publish generates a page for publishing for the given service.
    fn publish(&self) -> Page;
}

impl Publisher for Service {
    /// Update a service.
    /// This allows in-place editing of descriptors and options and causes an update of the service version number.
    fn update<U>(&mut self, update_fn: U) 
        where U: Fn(&mut Vec<u8>, &mut Vec<Options>, &mut Vec<Options>)
    {
        update_fn(&mut self.body, &mut self.public_options, &mut self.private_options);
        self.version += 1;
    }

    /// Publish generates a page for publishing for the given service.
    fn publish(&self) -> Page {
        // Insert default options
        // TODO: is this the right place to do this? Should they be deduplicated?
        let mut default_options = vec![
            Options::issued(SystemTime::now()),
            Options::expiry(SystemTime::now().add(Duration::from_secs(24 * 60 * 60))),
            Options::public_key(self.public_key.clone()),
        ];

        let mut public_options = self.public_options.clone();
        public_options.append(&mut default_options);

        let mut flags = Flags(0);
        flags.set_encrypted(self.encrypted);

        //Page::new(self.id.clone(), self.kind, flags, self.version, self.body.clone(), public_options, self.private_options.clone())

        Page::new(self.id.clone(), flags, self.version, self.kind.into(), PageInfo::primary(self.public_key.clone()), self.body.clone(), SystemTime::now(), SystemTime::now().add(Duration::from_secs(24 * 60 * 60)))
    }
}

trait Subscriber {
    type Service;

    /// Create a service replica from a given service page
    fn load(page: &Page) -> Result<Self::Service, Error>;
    /// Apply an updated page to an existing service instance
    fn apply(&mut self, update: &Page) -> Result<(), Error>;
}

impl Subscriber for Service {
    type Service = Service;

    /// Create a service instance from a given page
    fn load(page: &Page) -> Result<Service, Error> {

        let flags = page.flags();

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


        Ok(Service{
            id: page.id().clone(),
            kind: page.kind().into(),
            version: page.version(),

            body: body.to_vec(),

            public_options: public_options.to_vec(),
            private_options: private_options.to_vec(),

            public_key,
            private_key: None,

            encrypted: flags.encrypted(),
            secret_key: None,
        })
    }

    /// Apply an upgrade to an existing service.
    /// This consumes a new page and updates the service instance
    fn apply(&mut self, update: &Page) -> Result<(), Error> {

        let body = update.body();
        let flags = update.flags();
        
        let public_options = update.public_options();
        let private_options = update.private_options();

        // Check fields match
        if update.id() != &self.id {
            return Err(Error::UnexpectedServiceId)
        }
        if update.version() <= self.version {
            return Err(Error::InvalidServiceVersion)
        }
        if update.kind() != self.kind.into() {
            return Err(Error::InvalidPageKind)
        }
        if update.flags().secondary() {
            return Err(Error::ExpectedPrimaryPage)
        }

        // Fetch public key from options
        let public_key: PublicKey = match update.info() {
            PageInfo::Primary(primary) => primary.pub_key.clone(),
            _ => {
                error!("Attempted to update service from secondary page");
                return Err(Error::UnexpectedPageType);
            }
        };

        // Check public key and ID match
        if self.id != crypto::hash(&public_key).unwrap() {
            return Err(Error::KeyIdMismatch)
        }

        // Check public key hasn't changed
        if self.public_key != public_key {
            return Err(Error::PublicKeyChanged)
        }

        self.version = update.version();
        self.encrypted = flags.encrypted();
        self.body = body.to_vec();
        self.public_options = public_options.to_vec();
        self.private_options = private_options.to_vec();
    
        Ok(())
    }
}

/// Service Cryptographic Methods
pub trait Crypto {
    fn sign(&mut self, data: &[u8]) -> Result<Signature, Error>;
    fn validate(&self, signature: &[u8], data: &[u8]) -> Result<bool, Error>;
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
    fn validate(&self, signature: &[u8], data: &[u8]) -> Result<bool, Error> {
        let valid = crypto::pk_validate(&self.public_key, signature, data).unwrap();
        Ok(valid)
    }
}

#[derive(Clone, Builder)]
pub struct SecondaryOptions {
    #[builder(default = "Kind::Generic")]
    kind: Kind,
    #[builder(default = "Flags(0)")]
    flags: Flags,
    #[builder(default = "0")]
    version: u16,

    #[builder(default = "vec![]")]
    body: Vec<u8>,

    #[builder(default = "vec![]")]
    public_options: Vec<Options>,
    #[builder(default = "vec![]")]
    private_options: Vec<Options>,
}

impl Service
{
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Secondary generates a secondary page using this service to be attached to the provided service ID
    pub fn secondary(&self, options: SecondaryOptions) -> Page {
        let mut default_options = vec![
            Options::peer_id(self.id.clone()),
            Options::issued(SystemTime::now()),
            Options::expiry(SystemTime::now().add(Duration::from_secs(24 * 60 * 60))),
        ];

        let mut public_options = options.public_options.clone();
        public_options.append(&mut default_options);

        let mut flags = options.flags;
        flags.set_secondary(true);

        //Page::new(self.id.clone(), options.kind, options.flags, options.version, options.body, public_options, options.private_options)

        //Page::new(self.id.clone(), options.flags, options.version, PageInfo::Secondary(self.id.clone()), options.body, SystemTime::now(), SystemTime::now().add(Duration::from_secs(24 * 60 * 60)))

        unimplemented!();
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn encrypt(&self) {

    }

    pub fn decrypt(&self) {
        
    }

    /// Generate a protocol message from a request object
    pub fn build_request(&self, req: &Request) -> Base {
        let kind: Kind;
        let mut flags = Flags(0);
        let mut body = vec![];

        let mut builder = BaseBuilder::default();

        match &req.data {
            RequestKind::Hello => {
                kind = Kind::Hello;
                flags.set_address_request(true);
            },
            RequestKind::Ping => {
                kind = Kind::Ping;
                flags.set_address_request(true);
            },
            RequestKind::FindNode(id) => {
                kind = Kind::FindNodes;
                body = id.to_vec();
            },
            RequestKind::FindValue(id) => {
                kind = Kind::FindValues;
                body = id.to_vec();
            },
            RequestKind::Store(_id, _value) => {
                kind = Kind::Store;
            }
        }

        // Append request ID option
        builder.append_public_option(Options::request_id(req.id));

        builder.base(self.id().clone(), kind, 0, flags).body(body).build().unwrap()
    }



    /// Generate a response message
    pub fn build_response(&self, req: &Request, from: Address, resp: &Response) -> Base {
        let kind: Kind;
        let flags = Flags(0);

        let mut builder = BaseBuilder::default();

        match &resp.data {
            ResponseKind::Status => {
                kind = Kind::Status;
            },
            ResponseKind::NodesFound(_id, _nodes) => {
                kind = Kind::NodesFound;
            },
            ResponseKind::ValuesFound(_id, _values) => {
                kind = Kind::ValuesFound;
            },
            ResponseKind::NoResult => {
                kind = Kind::NoResult;
            }
        };

        // Append address option if address request flag is set
        if req.flags.address_request() {
            let o = Options::address(from);
            builder.append_public_option(o);
        }

        // Append request ID
        builder.append_public_option(Options::request_id(resp.id));

        builder.base(self.id().clone(), kind, 0, flags).build().unwrap()
    }


}




#[cfg(test)]
mod test {

    use std::net::{SocketAddrV4, Ipv4Addr};

    use try_from::TryInto;

    use super::*;

    #[test]
    fn test_service() {
        let socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080);

        println!("Creating new service");
        let mut service = ServiceBuilder::default()
                .kind(Kind::Generic)
                .public_options(vec![Options::name("Test Service")])
                .private_options(vec![Options::address(socket)])
                .encrypt()
                .build().unwrap();

        println!("Generating service page");
        let page1 = service.publish();

        println!("Encoding service page");
        let mut buff = vec![0u8; 1024];
        let mut base1: Base = page1.clone().into();
        let n = base1.encode(|_id, d| service.sign(d).map_err(|_e| () ), &mut buff).expect("Error encoding service page");

        println!("Encoded service to {} bytes", n);
    
        println!("Decoding service page");
        let (base2, m) = Base::parse(&buff[..n]).expect("Error parsing service page");
        assert_eq!(base1, base2);
        assert_eq!(n, m);
        let page2: Page = base2.try_into().expect("Error converting base message to page");
        assert_eq!(page1, page2);


        println!("Generating service replica");
        let mut replica = Service::load(&page2).expect("Error generating service replica");

        println!("Updating service");
        service.update(|_body, public_options, _private_options| {
            public_options.push(Options::kind("Test Kind"));
        });
        assert_eq!(service.version, 1, "service.update updates service version");

        println!("Generating updated page");
        let page3 = service.publish();

        println!("Applying updated page to replica");
        replica.apply(&page3).expect("Error updating service replica");
        assert_eq!(replica.version, 1);

        println!("Generating a secondary page");
        let secondary_options = SecondaryOptionsBuilder::default().build().expect("Error building secondary options");
        let _secondary = service.secondary(secondary_options);

        


    }
}