//! Base module provides a low-level structure for data encoding and decoding

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


pub trait WireEncode {
    type Error;

    fn encode(&mut self, buff: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Parse trait for building parse-able objects
pub trait WireDecode {
    /// Output type returned from parsing
    type Output;
    /// Error type returned on parse error
    type Error;
    /// Context used in decoding
    type Ctx;

    /// Parse method consumes a slice and returns an object and the remaining slice.
    fn decode(ctx: Self::Ctx, buff: &[u8]) -> Result<(Self::Output, usize), Self::Error>;
}


