

use crate::types::{Kind};
use crate::crypto;

pub use super::ServiceBuilder;

/// ServiceBuilder provides helpers for constructing service instances
impl ServiceBuilder {
    /// Validate service options prior to building
    pub(crate) fn validate(&self) -> Result<(), String> {
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