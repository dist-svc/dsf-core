//#![feature(try_from)]
//#![feature(test)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "alloc", feature(alloc_prelude))]

#![feature(test)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

#[cfg(feature = "libc")]
extern crate libc;

#[cfg(feature = "cty")]
extern crate cty as libc;

extern crate async_trait;
extern crate base64;
extern crate byteorder;
extern crate bytes;
extern crate managed;
extern crate rand_core;
extern crate slice_ext;
extern crate sodiumoxide;

#[cfg(feature = "serde")]
extern crate serde;

#[macro_use]
extern crate log;

#[macro_use]
extern crate bitflags;

#[cfg(feature = "std")]
extern crate chrono;

pub mod types;

pub mod error;

pub mod crypto;

pub mod options;

pub mod base;

pub mod service;

pub mod wire;

pub mod page;

pub mod net;

#[cfg(feature = "std")]
pub mod api;

pub mod prelude;

use crate::types::{Id, PublicKey, PrivateKey, SecretKey};

/// Key object stored and returned by a KeySource
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
        Self{ 
            pub_key,
            pri_key: None,
            sec_key: None,
            sym_keys: None,
        }
    }
}

pub trait KeySource: Sized {
    /// Find keys for a given service / peer ID
    fn keys(&self, id: &Id) -> Option<Keys>;

    fn cached(&self, existing: Option<(Id, Keys)>) -> CachedKeySource<Self> {
        CachedKeySource{key_source: self, cached: existing}
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

impl <'a, K: KeySource + Sized> KeySource for CachedKeySource<'a, K> {
    fn keys(&self, id: &Id) -> Option<Keys> {
        if let Some(k) = self.key_source.keys(id) {
            return Some(k);
        }

        match self.cached {
            Some(e) if &e.0 == id => Some(e.1),
            _ => None,
        }
    }
}

pub struct NullKeySource;

impl KeySource for NullKeySource {
    fn keys(&self, id: &Id) -> Option<Keys> {
        None
    }
}
