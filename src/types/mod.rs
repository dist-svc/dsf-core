
use std::fmt::Debug;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::hash::{Hash, Hasher};

pub const ID_LEN: usize = 32;
pub type Id = Array32;

pub const REQUEST_ID_LEN: usize = 8;
pub type RequestId = u64;

pub const PUBLIC_KEY_LEN: usize = 32;
pub type PublicKey = Array32;

pub const PRIVATE_KEY_LEN: usize = 64;
pub type PrivateKey = Array64;

pub const SIGNATURE_LEN: usize = 64;
//pub struct Signature([u8; SIGNATURE_LEN]);
pub type Signature = Array64;

pub const SECRET_KEY_LEN: usize = 32;
pub type SecretKey = Array32;

pub const HASH_LEN: usize = 32;
pub type CryptoHash = Array32;

pub const ENCRYPTED_META_LEN: usize = 64;
pub type EncryptedMeta = Array64;

pub type Address = SocketAddr;

pub type Data = u64;


pub mod kinds;
pub use self::kinds::*;

pub mod flags;
pub use self::flags::*;

pub mod errors;
pub use self::errors::*;

macro_rules! arr {
    ($name:ident, $len:expr) => (
        
        #[derive(Clone)]
        pub struct $name ([u8; $len]);

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Deref for $name {
            type Target = [u8];

            fn deref(&self) -> &[u8] {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut [u8] {
                &mut self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name([0u8; $len])
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(data: [u8; $len]) -> Self {
                $name(data)
            }
        }

        impl Into<[u8; $len]> for $name {
            fn into(self) -> [u8; $len] {
                self.0
            }
        }

        impl PartialEq<$name> for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0.as_ref() == other.0.as_ref()
            }
        }

        impl PartialEq<[u8; $len]> for $name {
            fn eq(&self, other: &[u8; $len]) -> bool {
                self.0.as_ref() == other.as_ref()
            }
        }

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.0.hash(state)
            }
        }

        impl Eq for $name {}

        impl Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                for i in 0..self.0.len() {
                    if i == 0 {
                        write!(f, "{:.2X}", self.0[i])?;
                    } else {
                        write!(f, ":{:.2X}", self.0[i])?;
                    }
                }
                Ok(())
            }
        }
    );
}

arr!(Array32, 32);
arr!(Array64, 64);