
pub mod helpers;
pub mod options;
pub mod header;

pub mod container;
pub mod base;

pub mod page;
pub mod messages;


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
}

