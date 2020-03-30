//! Types defines common data types for use in DSF
//! 
//! 

use std::fmt;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::hash::{Hash, Hasher};
use std::cmp::{PartialOrd, Ord, Ordering};
use std::str::FromStr;

use base64;

#[cfg(feature = "serde")]
use serde::{Serializer, Deserializer};
#[cfg(feature = "serde")]
use serde::de::{self, Visitor};

/// ImmutableData trait wraps AsRef<[u8]>
pub trait ImmutableData: AsRef<[u8]> {}

/// Generic impl of ImmutableData trait (since we don't have trait aliasing)
impl <T: AsRef<[u8]>> ImmutableData for T {}

/// MutableData trait, wraps AsMut<[u8]> and ImmutableData traits
pub trait MutableData: AsMut<[u8]> + ImmutableData {}

/// Generic impl of MutableData trait (since we don't have trait aliasing)
impl <T: AsMut<[u8]> + ImmutableData> MutableData for T {}


pub const ID_LEN: usize = 32;

/// ID type
pub type Id = Array32;

pub const REQUEST_ID_LEN: usize = 2;

/// Request ID type
pub type RequestId = u16;

pub const PUBLIC_KEY_LEN: usize = 32;

/// Public key type
pub type PublicKey = Array32;

pub const PRIVATE_KEY_LEN: usize = 64;

/// Private key type
pub type PrivateKey = Array64;

pub const SIGNATURE_LEN: usize = 64;
//pub struct Signature([u8; SIGNATURE_LEN]);

/// Signature type
pub type Signature = Array64;

pub const SECRET_KEY_LEN: usize = 32;

/// Secret key type
pub type SecretKey = Array32;

pub const HASH_LEN: usize = 32;

pub type CryptoHash = Array32;

pub const ENCRYPTED_META_LEN: usize = 64;
pub type EncryptedMeta = Array64;

pub type Address = SocketAddr;

//#[derive(Clone, PartialEq, Debug)]
use crate::page::Page;
pub type Data = Page;

pub mod kinds;
pub use self::kinds::*;

pub mod flags;
pub use self::flags::*;

pub mod errors;
pub use self::errors::*;

pub mod datetime;
pub use self::datetime::DateTime;

macro_rules! arr {
    ($name:ident, $len:expr) => (
        
        #[derive(Clone, Copy)]
        pub struct $name ([u8; $len]);

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsMut<[u8]> for $name {
            fn as_mut(&mut self) -> &mut [u8] {
                &mut self.0
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

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> Ordering {
                self.0.cmp(&other.0)
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl From<&[u8]> for $name {
            fn from(data: &[u8]) -> Self {
                let mut a = [0u8; $len];
                a.copy_from_slice(data);
                a.into()
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

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let r: &[u8] = &self.0;
                let encoded = base64::encode_config(&r, base64::URL_SAFE);
                write!(f, "{}", encoded)?;
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }

        impl fmt::UpperHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                for i in 0..self.0.len() {
                    if i == 0 {
                        write!(f, "{:02X}", self.0[i])?;
                    } else {
                        write!(f, ":{:02X}", self.0[i])?;
                    }
                }
                Ok(())
            }
        }

        impl FromStr for $name {
            type Err = base64::DecodeError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut data = [0u8; $len];
                let decoded = base64::decode_config(s, base64::URL_SAFE)?;
                data.clone_from_slice(&decoded);
                Ok(data.into())
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let encoded = self.to_string();
                serializer.serialize_str(&encoded)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct B64Visitor;

                impl<'de> Visitor<'de> for B64Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("a base64 encoded string")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $name::from_str(value).map_err(|_e| de::Error::custom("decoding b64") )
                    }
                }

                deserializer.deserialize_str(B64Visitor)
            }
        }

    );
}




arr!(Array32, 32);
arr!(Array64, 64);


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_array32() {

        let a = Array32([0u8; 32]);

        let b = a.to_string();

        println!("B: {}", b);

        let c = Array32::from_str(&b).unwrap();


        assert_eq!(a, c);
    }

}