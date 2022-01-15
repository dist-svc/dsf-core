#[cfg(feature = "alloc")]
use alloc::vec::{Vec};

use crate::base::{Body, MaybeEncrypted, PageBody};
use crate::crypto;
use crate::error::Error;
use crate::options::Options;
use crate::types::*;
use crate::keys::Keys;

use super::Service;

/// Service builder to assist in the construction of service instances
pub struct ServiceBuilder<B: PageBody = Body> {
    id: Option<Id>,
    public_key: Option<PublicKey>,

    kind: PageKind,
    application_id: u16,
    index: u16,
    body: B,

    private_key: Option<PrivateKey>,
    secret_key: Option<SecretKey>,
    encrypted: bool,

    public_options: Vec<Options>,
    private_options: Vec<Options>,


    last_sig: Option<Signature>,
}

impl <B: PageBody + Default> Default for ServiceBuilder<B> {
    /// Create a default service builder instance
    fn default() -> Self {
        Self {
            id: None,
            public_key: None,

            application_id: 0,
            index: 0,
            kind: PageKind::Generic,
            body: B::default(),

            private_key: None,
            secret_key: None,
            encrypted: false,

            public_options: vec![],
            private_options: vec![],

            last_sig: None,
        }
    }
}

impl ServiceBuilder {
    /// Setup a peer service.
    /// This is equivalent to .kind(Kind::Peer)
    pub fn peer() -> Self {
        Self {
            kind: PageKind::Peer,
            ..Default::default()
        }
    }

    /// Setup a generic service.
    /// This is equivalent to .kind(Kind::Generic)
    pub fn generic() -> Self {
        Self {
            kind: PageKind::Generic,
            ..Default::default()
        }
    }

    /// Setup a private service.
    /// This is equivalent to .kind(Kind::Private)
    pub fn private() -> Self {
        Self {
            kind: PageKind::Private,
            ..Default::default()
        }
    }

    /// Setup a name service with the specified prefix
    pub fn ns(prefix: &str) -> Self {
        let mut s = Self {
            // TODO: fix up kinds, seems to be conflation between DB and DSF pages?
            // maybe this should be flags for pri | sec | ter + enum for variant?
            kind: PageKind::Generic,
            ..Default::default()
        };

        s.private_options = vec![Options::name(prefix)];

        s
    }
}

/// ServiceBuilder provides helpers for constructing service instances
impl <B: PageBody + Default> ServiceBuilder<B> {
    /// Set the ID and public key for the service
    pub fn id(mut self, id: Id, public_key: PublicKey) -> Self {
        self.id = Some(id);
        self.public_key = Some(public_key);
        self
    }
    
    pub fn last_index(mut self, index: u16) -> Self {
        self.index = index;
        self
    }

    pub fn kind(mut self, kind: PageKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn body(mut self, body: B) -> Self {
        self.body = body;
        self
    }

    pub fn private_key(mut self, private_key: PrivateKey) -> Self {
        self.private_key = Some(private_key);
        self
    }

    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    pub fn keys(mut self, keys: Keys) -> Self {
        let Keys{sec_key, pri_key, ..} = keys;

        if let Some(pk) = pri_key {
            self.private_key = Some(pk)
        }

        if let Some(sk) = sec_key {
            self.secret_key = Some(sk)
        }

        self
    }

    pub fn application_id(mut self, application_id: u16) -> Self {
        self.application_id = application_id;
        self
    }

    /// Enable service encryption
    /// this is equivalent to .secret_key(crypto::new_sk().unwrap()).encrypted(true);
    pub fn encrypt(mut self) -> Self {
        let secret_key = crypto::new_sk().unwrap();
        self.secret_key = Some(secret_key);
        self.encrypted = true;
        self
    }

    pub fn public_options(mut self, mut o: Vec<Options>) -> Self {
        self.public_options.append(&mut o);
        self
    }

    pub fn private_options(mut self, mut o: Vec<Options>) -> Self {
        self.private_options.append(&mut o);
        self
    }

    pub fn last_signature(mut self, s: Signature) -> Self {
        self.last_sig = Some(s);
        self
    }

    pub fn build(self) -> Result<Service<B>, Error> {
        // TODO: perform any validation (no private options without secret key etc.)

        // Generate new keys if required
        let (id, public_key, private_key) = match (self.id, self.public_key, self.private_key) {
            (Some(id), Some(public_key), private_key) => (id, public_key, private_key),
            (_, _, Some(private_key)) => {
                // Regenerate public key and ID from private key
                let public_key = crypto::pk_derive(&private_key).unwrap();
                let id = crypto::hash(&public_key).unwrap();
                (id, public_key, Some(private_key))
            }
            (None, None, None) => {
                // Generate new keypair
                let (public_key, private_key) = crypto::new_pk().unwrap();
                let id = crypto::hash(&public_key).unwrap();
                (id, public_key, Some(private_key))
            }
            _ => panic!("Invalid service builder configuration"),
        };

        // Build service
        Ok(Service {
            id,
            application_id: self.application_id,
            kind: self.kind,
            version: 0,
            data_index: 0,
            body: self.body,
            public_options: self.public_options,
            private_options: MaybeEncrypted::Cleartext(self.private_options),
            public_key,
            private_key,
            encrypted: self.encrypted,
            secret_key: self.secret_key,
            last_sig: None,
        })
    }
}
