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
pub type Id = Array<IdTy, ID_LEN>;

pub struct IdTy {}

impl From<CryptoHash> for Id {
    fn from(h: CryptoHash) -> Self {
        Self(h.0, PhantomData)
    }
}


impl Queryable for Id {
    fn hash<H: CryptoHasher>(&self, state: &mut H) -> bool {
        state.update(&self.0);
        true
    }
}

impl Queryable for CryptoHash {
    fn hash<H: CryptoHasher>(&self, state: &mut H) -> bool {
        state.update(&self.0);
        true
    }
}

pub const REQUEST_ID_LEN: usize = 2;
/// Request ID type
pub type RequestId = u16;

pub const PUBLIC_KEY_LEN: usize = 32;
/// Public key type
pub type PublicKey = Array<PublicKeyTy, PUBLIC_KEY_LEN>;

pub struct PublicKeyTy {}

pub const PRIVATE_KEY_LEN: usize = 64;
/// Private key type
pub type PrivateKey = Array<PrivateKeyTy, PRIVATE_KEY_LEN>;

pub struct PrivateKeyTy {}

pub const SIGNATURE_LEN: usize = 64;
/// Signature type
pub type Signature = Array<SignatureTy, SIGNATURE_LEN>;

pub struct SignatureTy {}

pub const SECRET_KEY_LEN: usize = 32;
/// Secret key type
pub type SecretKey = Array<SecretKeyTy, SECRET_KEY_LEN>;

pub struct SecretKeyTy {}

pub const SECRET_KEY_TAG_LEN: usize = 40;
/// Secret key encryption metadata (tag and nonce)
pub type SecretMeta = Array<SecretMetaTy, SECRET_KEY_TAG_LEN>;

pub struct SecretMetaTy {}


pub const HASH_LEN: usize = 32;
/// Cryptographic hash value
pub type CryptoHash = Array<CryptoHashTy, HASH_LEN>;

pub struct CryptoHashTy {}

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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Array<K, const N: usize> ([u8; N], PhantomData<K>);

impl <K, const N: usize> Array<K, N> {
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl <K, const N: usize> AsRef<[u8]> for Array<K, N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl <K, const N: usize> AsMut<[u8]> for Array<K, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl <K, const N: usize> Deref for Array<K, N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl <K, const N: usize> DerefMut for Array<K, N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl <K, const N: usize> Default for Array<K, N> {
    fn default() -> Self {
        Array([0u8; N], PhantomData)
    }
}

impl <K, const N: usize> Clone for Array<K, N> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}


impl <K, const N: usize> PartialEq for Array<K, N> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}


impl <K, const N: usize> Ord for Array<K, N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl <K, const N: usize> PartialOrd for Array<K, N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl <K, const N: usize> crate::base::Encode for Array<K, N> {
    type Error = DsfError;

    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
        if buff.len() < N {
            return Err(DsfError::BufferLength);
        }

        buff[..N].copy_from_slice(&self.0);
        
        Ok(N)
    }
}

impl <K, const N: usize> crate::base::Parse for Array<K, N> {
    type Output = Self;

    type Error = DsfError;

    fn parse<'a>(buff: &'a[u8]) -> Result<(Self::Output, usize), Self::Error> {
        if buff.len() < N {
            return Err(DsfError::BufferLength);
        }

        let mut d = [0u8; N];
        d.copy_from_slice(buff);

        Ok((Self(d, PhantomData), N))
    }
}

impl <K, const N: usize> TryFrom<&[u8]> for Array<K, N> {
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

impl <K, const N: usize> From<[u8; N]> for Array<K, N> {
    fn from(data: [u8; N]) -> Self {
        Array(data, PhantomData)
    }
}

impl <K, const N: usize> From<&[u8; N]> for Array<K, N> {
    fn from(data: &[u8; N]) -> Self {
        let mut a = [0u8; N];

        a.copy_from_slice(data);

        a.into()
    }
}

impl <K, const N: usize> Into<[u8; N]> for Array<K, N> {
    fn into(self) -> [u8; N] {
        self.0
    }
}

impl <K, const N: usize> PartialEq<[u8; N]> for Array<K, N> {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.0.as_ref() == other.as_ref()
    }
}

impl <K, const N: usize> Hash for Array<K, N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl <K, const N: usize> Eq for Array<K, N> {}

impl <K, const N: usize> BitXor for Array<K, N> {
    type Output = Array<K, N>;

    fn bitxor(self, rhs: Array<K, N>) -> Self::Output {
        let mut s = self;
        for i in 0..N {
            s[i] ^= rhs[i]
        }
        s
    }
}

impl <K, const N: usize> fmt::Display for Array<K, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let r: &[u8] = &self.0;
        let encoded = base64::encode_config(&r, base64::URL_SAFE);
        write!(f, "{}", encoded)?;
        Ok(())
    }
}

impl <K, const N: usize> fmt::Debug for Array<K, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let r: &[u8] = &self.0;
        let encoded = base64::encode_config(&r, base64::URL_SAFE);
        write!(f, "{}", encoded)?;
        Ok(())
    }
}

impl <K, const N: usize> fmt::UpperHex for Array<K, N> {
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

impl <K, const N: usize> FromStr for Array<K, N> {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut data = [0u8; N];
        let _decoded = base64::decode_config_slice(s, base64::URL_SAFE, &mut data)?;
        // TODO: check decoded length

        Ok(data.into())
    }
}

#[cfg(feature = "serde")]
impl <K, const N: usize> serde::Serialize for Array<K, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de, K, const N: usize> serde::Deserialize<'de> for Array<K, N> {
    fn deserialize<D>(deserializer: D) -> Result<Array<K, N>, D::Error>
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

        deserializer.deserialize_str(B64Visitor::<Array<K, N>>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_array32() {
        let a = Array::<IdTy, 32>([0u8; 32], PhantomData);

        let b = a.to_string();

        println!("B: {}", b);

        let c = Array::<IdTy, 32>::from_str(&b).unwrap();

        assert_eq!(a, c);
    }
}
