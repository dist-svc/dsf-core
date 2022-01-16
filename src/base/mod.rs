//! Base module provides a low-level structure for data encoding and decoding

use core::marker::PhantomData;
use core::fmt::Debug;
use std::convert::Infallible;

mod header;
pub use header::*;

use crate::options::Options;
use crate::types::ImmutableData;
use crate::error::Error;

pub type Body = MaybeEncrypted;

/// Parse trait for building parse-able objects
pub trait Parse {
    /// Output type returned from parsing
    type Output;
    
    /// Error type returned on parse error
    type Error;

    /// Parse method consumes a slice and returns an object and the remaining slice.
    fn parse(buff: &[u8]) -> Result<(Self::Output, usize), Self::Error>;

    /// Parse iter consumes a slice and returns an iterator over decoded objects
    fn parse_iter<'a>(buff: &'a [u8]) -> ParseIter<'a, Self::Output, Self::Error> {
        ParseIter {
            buff,
            index: 0,
            _t: PhantomData,
            _e: PhantomData,
        }
    }
}

/// Iterative parser object, constructed with `Parse::parse_iter` for types implementing `Parse`
pub struct ParseIter<'a, T, E> {
    buff: &'a [u8],
    index: usize,
    _t: PhantomData<T>,
    _e: PhantomData<E>,
}

impl<'a, T, E> Iterator for ParseIter<'a, T, E>
where
    T: Parse<Output = T, Error = E>,
{
    type Item = Result<T, E>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.buff.len() {
            return None;
        }

        let (v, n) = match T::parse(&self.buff[self.index..]) {
            Ok((v, n)) => (v, n),
            Err(e) => return Some(Err(e)),
        };

        self.index += n;

        Some(Ok(v))
    }
}

/// Encode trait for building encodable objects
pub trait Encode: Debug {
    /// Error type returned on parse error
    type Error: Debug;

    /// Encode method writes object data to the provided writer
    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error>;

    /// Encode len fetches expected encoded length for an object
    fn encode_len(&self) -> Result<usize, Self::Error> {
        todo!()
    }

    /// Encode a iterator of encodable objects
    fn encode_iter<'a, V: Iterator<Item = &'a Self>>(
        vals: V,
        buff: &mut [u8],
    ) -> Result<usize, Self::Error>
    where
        Self: 'static,
    {
        let mut index = 0;

        for i in vals {
            index += i.encode(&mut buff[index..])?;
        }

        Ok(index)
    }

    /// Encode into a fixed size buffer
    fn encode_buff<const N: usize>(&self) -> Result<([u8; N], usize), Self::Error> {
        let mut b = [0u8; N];
        let n = self.encode(&mut b)?;
        Ok((b, n))
    }
}

/// Encode for pointers to encodable types
impl <T: Encode> Encode for &T {
    type Error = <T as Encode>::Error;

    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
        T::encode(self, buff)
    }
}

/// Encode for arrays of encodable types
impl <T: Encode> Encode for &[T] {
    type Error = <T as Encode>::Error;

    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
        let mut index = 0;

        for i in *self {
            index += i.encode(&mut buff[index..])?;
        }

        Ok(index)
    }
}

/// Encode for raw slices
impl Encode for &[u8] {
    type Error = Infallible;

    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
        buff[..self.len()].copy_from_slice(*self);
        Ok(self.len())
    }
}

/// Encode for empty raw slices
impl Encode for &[u8; 0] {
    type Error = Infallible;

    fn encode(&self, _buff: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }
}


impl Parse for Vec<u8> {
    type Output = Vec<u8>;
    type Error = Error;

    fn parse<'a>(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let value = Vec::from(data);

        Ok((value, data.len()))
    }
}

impl Encode for Vec<u8> {
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        data[..self.len()].copy_from_slice(self);

        Ok(self.len())
    }
}


/// Marker trait for page body types
pub trait PageBody: Encode {}

impl PageBody for &[u8] {}

//TODO: impl PageBody for Vec<u8> {}

/// Marker trait for data body types
pub trait DataBody: Encode {}

impl DataBody for &[u8] {}

//TODO: impl DataBody for Vec<u8> {}


/// Container for objects / collections that may be encrypted
#[derive(PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MaybeEncrypted<O: Debug = Vec<u8>, E: ImmutableData = Vec<u8>> {
    Cleartext(O),
    Encrypted(E),
    None,
}

impl <O: Debug, E: ImmutableData> MaybeEncrypted<O, E> {
    pub fn cleartext(o: O) -> Self {
        Self::Cleartext(o)
    }

    pub fn encrypted(e: E) -> Self {
        Self::Encrypted(e)
    }
}

impl <O: Encode + Debug, E: ImmutableData + Debug> Encode for MaybeEncrypted<O, E> 
{
    type Error = <O as Encode>::Error;

    /// Encode a MaybeEncrypted object, writing data directly if encrypted or
    /// calling the inner .encode function for decrypted objects
    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
        
        let n = match self {
            Self::Encrypted(e) if e.as_ref().len() > 0 => {
                let l = e.as_ref();
                buff[..l.len()].copy_from_slice(l);
                l.len()
            },
            Self::Cleartext(o) => { o.encode(buff)? },
            _ => 0
        };

        debug!("Encoded: {:02x?} ({} bytes)", self, n);

        Ok(n)
    }
}

impl <O: Encode + Debug, E: ImmutableData> Default for MaybeEncrypted<O, E> {
    fn default() -> Self {
        MaybeEncrypted::None
    }
}

impl <'a> MaybeEncrypted<&'a [Options], &'a [u8]> {
    pub fn to_vec(&self) -> MaybeEncrypted<Vec<Options>, Vec<u8>> {
        match self {
            Self::Encrypted(e) => MaybeEncrypted::Encrypted(e.to_vec()),
            Self::Cleartext(e) => MaybeEncrypted::Cleartext(e.to_vec()),
            Self::None => MaybeEncrypted::None,
        }
    }   
}

impl <'a, C, E> MaybeEncrypted<C, E> 
where
    C: AsRef<[Options]> + Debug,
    E: ImmutableData,
{
    pub fn as_ref(&'a self) -> MaybeEncrypted<&'a [Options], &'a [u8]> {
        match self {
            Self::Encrypted(e) => MaybeEncrypted::Encrypted(e.as_ref()),
            Self::Cleartext(c) => MaybeEncrypted::Cleartext(c.as_ref()),
            Self::None => MaybeEncrypted::None,
        }
    }
}

impl From<Vec<u8>> for MaybeEncrypted<Vec<u8>, Vec<u8>> {
    fn from(o: Vec<u8>) -> Self {
        if o.len() > 0 {
            MaybeEncrypted::Cleartext(o)
        } else {
            MaybeEncrypted::None
        }
    }
}

impl From<Option<MaybeEncrypted>> for MaybeEncrypted {
    fn from(o: Option<MaybeEncrypted>) -> Self {
        match o {
            Some(b) => b,
            None => MaybeEncrypted::None,
        }
    }
}

/// Allow MaybeEncrypted type to be used for page and block data
impl <O: Encode + Debug, E: ImmutableData + Debug> PageBody for MaybeEncrypted<O, E> {}
