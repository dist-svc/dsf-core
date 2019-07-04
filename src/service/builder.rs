

use crate::types::{PageKind};
use crate::crypto;
use crate::options::Options;

pub use super::ServiceBuilder;

/// ServiceBuilder provides helpers for constructing service instances
impl ServiceBuilder {
    /// Validate service options prior to building
    pub(crate) fn validate(&self) -> Result<(), String> {
        // Ensure a secret key is available if private options are used
        if let Some(_private_opts) = &self.private_options {
            if self.secret_key.is_none() {
                return Err("Private options cannot be used without specifying or creating an associated secret key".to_owned());
            }
        }

        Ok(())
    }

    /// Setup a peer service.
    /// This is equivalent to .kind(Kind::Peer)
    pub fn peer(&mut self) -> &mut Self {
        let mut new = self;
        new.kind = Some(PageKind::Peer);
        new
    }

    /// Setup a generic service.
    /// This is equivalent to .kind(Kind::Generic)
    pub fn generic(&mut self) -> &mut Self {
        let mut new = self;
        new.kind = Some(PageKind::Generic);
        new
    }

    /// Setup a private service.
    /// This is equivalent to .kind(Kind::Private)
    pub fn private(&mut self) -> &mut Self {
        let mut new = self;
        new.kind = Some(PageKind::Private);
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

    pub fn append_public_option(&mut self, o: Options) -> &mut Self {
        match &mut self.public_options {
            Some(opts) => opts.push(o),
            None => self.public_options = Some(vec![o]),
        }
        self
    }

     pub fn append_private_option(&mut self, o: Options) -> &mut Self {
        match &mut self.private_options {
            Some(opts) => opts.append(o),
            None => panic!("attempting to append private option to encrypted field"),
        }
        self
    }
}