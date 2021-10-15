

use crate::types::{Id, PrivateKey, PublicKey, SecretKey};
use crate::crypto;

/// Key object stored and returned by a KeySource
#[derive(Clone, PartialEq, Debug)]
pub struct Keys {
    /// Service public key
    pub pub_key: PublicKey,
    /// Service private key
    pub pri_key: Option<PrivateKey>,
    /// Secret key for data encryption
    pub sec_key: Option<SecretKey>,
    /// Symmetric keys for p2p message signing / verification
    pub sym_keys: Option<(SecretKey, SecretKey)>,
}

impl Keys {
    pub fn new(pub_key: PublicKey) -> Self {
        Self {
            pub_key,
            pri_key: None,
            sec_key: None,
            sym_keys: None,
        }
    }

    pub fn with_pri_key(mut self, pri_key: PrivateKey) -> Self {
        self.pri_key = Some(pri_key);
        self
    }

    pub fn with_sec_key(mut self, sec_key: SecretKey) -> Self {
        self.sec_key = Some(sec_key);
        self
    }

    /// Derive encryption keys for the specified peer
    pub fn derive_peer(&self, pub_key: PublicKey) -> Result<Keys, ()> {
        // Derivation requires our public key
        let pri_key = match &self.pri_key {
            Some(p) => p,
            None => return Err(()),
        };

        // Generate symmetric keys
        let sym_keys = crypto::sk_derive(&self.pub_key, pri_key, &pub_key)?;

        // Return generated key object
        Ok(Keys {
            pub_key,
            pri_key: self.pri_key.clone(),
            sec_key: None,
            sym_keys: Some(sym_keys),
        })
    }
}

impl KeySource for Keys {
    fn keys(&self, _id: &Id) -> Option<Keys> {
        Some(self.clone())
    }
}

impl KeySource for Option<Keys> {
    fn keys(&self, _id: &Id) -> Option<Keys> {
        self.clone()
    }
}

pub trait KeySource: Sized {
    /// Find keys for a given service / peer ID
    fn keys(&self, id: &Id) -> Option<Keys>;

    fn cached(&self, existing: Option<(Id, Keys)>) -> CachedKeySource<Self> {
        CachedKeySource {
            key_source: self,
            cached: existing,
        }
    }

    fn null(&self) -> NullKeySource {
        NullKeySource
    }
}

/// Wrapper to cache a KeySource with a value for immediate lookup
pub struct CachedKeySource<'a, K: KeySource + Sized> {
    key_source: &'a K,
    cached: Option<(Id, Keys)>,
}

impl<'a, K: KeySource + Sized> KeySource for CachedKeySource<'a, K> {
    fn keys(&self, id: &Id) -> Option<Keys> {
        if let Some(k) = self.key_source.keys(id) {
            return Some(k);
        }

        match &self.cached {
            Some(e) if &e.0 == id => Some(e.1.clone()),
            _ => None,
        }
    }
}

pub struct NullKeySource;

impl KeySource for NullKeySource {
    fn keys(&self, _id: &Id) -> Option<Keys> {
        None
    }
}

#[cfg(feature = "std")]
impl KeySource for std::collections::HashMap<Id, Keys> {
    fn keys(&self, id: &Id) -> Option<Keys> {
        self.get(id).map(|v| v.clone())
    }
}