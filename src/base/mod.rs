//! Base module provides a low-level structure for data encoding and decoding

use core::marker::PhantomData;

pub mod header;
pub use header::*;

pub mod body;
pub use body::*;

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
        ParseIter{
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

impl <'a, T, E> Iterator for ParseIter<'a, T, E>
where
    T: Parse<Output=T, Error=E> 
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
pub trait Encode {
    /// Error type returned on parse error
    type Error;

    /// Encode method writes object data to the provided writer
    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error>;

    /// Encode a iterator of encodable objects
    fn encode_iter<'a, V: Iterator<Item = &'a Self>>(vals: V, buff: &mut [u8]) -> Result<usize, Self::Error> where Self: 'static {
        let mut index = 0;

        for i in vals {
            index += i.encode(&mut buff[index..])?;
        }

        Ok(index)
    }
}