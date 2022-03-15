//! Types defines common data types for use in DSF
//!
//!

use core::cmp::{Ord, Ordering, PartialOrd};
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::{Deref, DerefMut};
use core::str::FromStr;
use core::marker::PhantomData;
use core::ops::BitXor;
use core::convert::{Infallible, TryFrom};

#[cfg(feature = "serde")]
use serde::de::{self, Visitor};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

#[cfg(feature = "std")]
pub use chrono::Duration;

/// ImmutableData trait wraps AsRef<[u8]>
pub trait ImmutableData: AsRef<[u8]> + crate::Debug {}

/// Generic impl of ImmutableData trait (since we don't have trait aliasing)
impl<T: AsRef<[u8]> + crate::Debug> ImmutableData for T {}

/// MutableData trait, wraps AsMut<[u8]> and ImmutableData traits
pub trait MutableData: AsMut<[u8]> + ImmutableData {}

/// Generic impl of MutableData trait (since we don't have trait aliasing)
impl<T: AsMut<[u8]> + ImmutableData> MutableData for T {}

/// Queryable trait for name resolution services
pub trait Queryable: core::fmt::Debug {
    fn hash<H: CryptoHasher>(&self, h: &mut H) -> bool;
}

pub trait CryptoHasher {
    fn update(&mut self, buff: &[u8]);
}


pub const ID_LEN: usize = 32;
/// ID type
pub type Id = Array<ID_LEN>;


impl Queryable for Id {
    fn hash<H: CryptoHasher>(&self, state: &mut H) -> bool {
        state.update(&self.0);
        true
    }
}

/// Encode an ID directly into a buffer
impl Encode for Id {
    type Error = Infallible;

    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
        buff[..ID_LEN].copy_from_slice(&self.0);
        Ok(ID_LEN)
    }
}

pub const REQUEST_ID_LEN: usize = 2;
/// Request ID type
pub type RequestId = u16;

pub const PUBLIC_KEY_LEN: usize = 32;
/// Public key type
pub type PublicKey = Array<PUBLIC_KEY_LEN>;

pub const PRIVATE_KEY_LEN: usize = 64;
/// Private key type
pub type PrivateKey = Array<PRIVATE_KEY_LEN>;

pub const SIGNATURE_LEN: usize = 64;
/// Signature type
pub type Signature = Array<SIGNATURE_LEN>;

pub const SECRET_KEY_LEN: usize = 32;
/// Secret key type
pub type SecretKey = Array<SECRET_KEY_LEN>;

pub const SECRET_KEY_TAG_LEN: usize = 40;
/// Secret key encryption metadata (tag and nonce)
pub type SecretMeta = Array<SECRET_KEY_TAG_LEN>;


pub const HASH_LEN: usize = 32;
/// Cryptographic hash value
pub type CryptoHash = Array<HASH_LEN>;


use crate::prelude::{Encode, DsfError};
use crate::wire::Container;
pub type Data = Container;

pub mod kinds;
pub use self::kinds::*;

pub mod flags;
pub use self::flags::*;

pub mod datetime;
pub use self::datetime::DateTime;

pub mod address;
pub use self::address::{Address, AddressV4, AddressV6, Ip};

/// Basic const-generic array type to override display etc.
#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct  Array<const N: usize> ([u8; N]);


pub type Array32 = Array<32>;
pub type Array64 = Array<64>;
pub type Array40 = Array<40>;


impl <const N: usize> AsRef<[u8]> for Array<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl <const N: usize> AsMut<[u8]> for Array<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl <const N: usize> Deref for Array<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl <const N: usize> DerefMut for Array<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl <const N: usize> Default for Array<N> {
    fn default() -> Self {
        Array([0u8; N])
    }
}

impl <const N: usize> Ord for Array<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl <const N: usize> PartialOrd for Array<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl <const N: usize> TryFrom<&[u8]> for Array<N> {
    type Error = DsfError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut a = [0u8; N];

        if data.len() != N {
            return Err(DsfError::BufferLength);
        }

        a.copy_from_slice(data);

        Ok(a.into())
    }
}

impl <const N: usize> From<[u8; N]> for Array<N> {
    fn from(data: [u8; N]) -> Self {
        Array(data)
    }
}

impl <const N: usize> From<&[u8; N]> for Array<N> {
    fn from(data: &[u8; N]) -> Self {
        let mut a = [0u8; N];

        a.copy_from_slice(data);

        a.into()
    }
}

impl <const N: usize> Into<[u8; N]> for Array<N> {
    fn into(self) -> [u8; N] {
        self.0
    }
}

impl <const N: usize> PartialEq<[u8; N]> for Array<N> {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.0.as_ref() == other.as_ref()
    }
}

impl <const N: usize> Hash for Array<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl <const N: usize> Eq for Array<N> {}

impl <const N: usize> BitXor for Array<N> {
    type Output = Array<N>;

    fn bitxor(self, rhs: Array<N>) -> Self::Output {
        let mut s = self;
        for i in 0..N {
            s[i] ^= rhs[i]
        }
        s
    }
}

impl <const N: usize> fmt::Display for Array<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let r: &[u8] = &self.0;
        let encoded = base64::encode_config(&r, base64::URL_SAFE);
        write!(f, "{}", encoded)?;
        Ok(())
    }
}

impl <const N: usize> fmt::Debug for Array<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let r: &[u8] = &self.0;
        let encoded = base64::encode_config(&r, base64::URL_SAFE);
        write!(f, "{}", encoded)?;
        Ok(())
    }
}

impl <const N: usize> fmt::UpperHex for Array<N> {
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

impl <const N: usize> FromStr for Array<N> {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut data = [0u8; N];
        let decoded = base64::decode_config(s, base64::URL_SAFE)?;
        data.clone_from_slice(&decoded);
        Ok(data.into())
    }
}

#[cfg(feature = "serde")]
impl <const N: usize> serde::Serialize for Array<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = self.to_string();
        serializer.serialize_str(&encoded)
    }
}

#[cfg(feature = "serde")]
impl<'de, const N: usize> serde::Deserialize<'de> for Array<N> {
    fn deserialize<D>(deserializer: D) -> Result<Array<N>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct B64Visitor<T>(PhantomData<T>);

        impl<'de, T: FromStr> Visitor<'de> for B64Visitor<T> {
            type Value = T;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a base64 encoded string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                T::from_str(value).map_err(|_e| de::Error::custom("decoding b64"))
            }
        }

        deserializer.deserialize_str(B64Visitor::<Array<N>>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_array32() {
        let a = Array::<32>([0u8; 32]);

        let b = a.to_string();

        println!("B: {}", b);

        let c = Array32::from_str(&b).unwrap();

        assert_eq!(a, c);
    }
}
