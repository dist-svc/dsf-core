
#![no_std]

use core::fmt::Debug;
use core::marker::PhantomData;
use core::convert::{TryFrom, Infallible};

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod error;
pub use error::Error;

/// Parse trait for building parse-able objects
pub trait Parse {
    /// Output type returned from parsing
    type Output: Debug;
    
    /// Error type returned on parse error
    type Error: Debug;

    /// Parse method consumes a slice and returns an object and the remaining slice.
    fn parse<'a>(buff: &'a[u8]) -> Result<(Self::Output, usize), Self::Error>;

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
    fn encode_iter<'a, V: IntoIterator<Item = &'a Self>>(
        vals: V,
        buff: &mut [u8],
    ) -> Result<usize, Self::Error>
    where
        Self: 'static,
    {
        let mut index = 0;

        for i in vals.into_iter() {
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


impl Parse for () {
    type Output = ();

    type Error = Error;

    fn parse<'a>(_buff: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        Ok(((), 0))
    }
}

/// Encode null / `()` types
impl Encode for () {
    type Error = Error;

    fn encode(&self, _buff: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
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
    type Error = Error;

    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
        buff[..self.len()].copy_from_slice(*self);
        Ok(self.len())
    }
}

/// Encode for empty raw slices
impl Encode for &[u8; 0] {
    type Error = Error;

    fn encode(&self, _buff: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }
}

/// [`Parse`] for `Vec<u8>` where `feature = "alloc"`
#[cfg(feature = "alloc")]
impl Parse for alloc::vec::Vec<u8> {
    type Output = alloc::vec::Vec<u8>;
    type Error = Error;

    fn parse<'a>(data: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        let value = alloc::vec::Vec::from(data);

        Ok((value, data.len()))
    }
}

/// [`Encode`] for `Vec<u8>` where `feature = "alloc"`
#[cfg(feature = "alloc")]
impl Encode for alloc::vec::Vec<u8> {
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        if data.len() < self.len() {
            return Err(Error::BufferLength);
        }

        data[..self.len()].copy_from_slice(self);

        Ok(self.len())
    }
}
