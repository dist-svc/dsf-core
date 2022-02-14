use core::str;
use core::str::FromStr;
use core::fmt::Display;

use byteorder::{ByteOrder, NetworkEndian};

use crate::base::{Encode, Parse};
use crate::error::Error;
use crate::types::{DateTime, PublicKey};
use super::Options;

impl Parse for String {
    type Output = String;
    type Error = Error;

    fn parse<'a>(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let length = NetworkEndian::read_u16(&data[0..2]) as usize;
        let value = str::from_utf8(&data[2..2 + length]).unwrap().to_owned();

        Ok((value, length + 2))
    }
}

impl Encode for String {
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let value = self.as_bytes();

        NetworkEndian::write_u16(&mut data[0..], value.len() as u16);
        data[2..value.len() + 2].copy_from_slice(value);

        Ok(value.len() + 2)
    }
}

impl Parse for DateTime {
    type Output = DateTime;
    type Error = Error;

    fn parse<'a>(data: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        let raw = NetworkEndian::read_u64(&data[0..]);
        let when = DateTime::from_secs(raw);

        Ok((when, 10))
    }
}

impl Encode for DateTime {
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut *data, 8);
        let time_s = self.as_secs();

        NetworkEndian::write_u64(&mut data[2..], time_s);

        Ok(10)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature="thiserror", derive(thiserror::Error))]
pub enum OptionsParseError {
    #[cfg_attr(feature="thiserror", error("Invalid format (expected key:value)"))]
    InvalidFormat,
    
    #[cfg_attr(feature="thiserror", error("String encode/decode not supported for this option kind"))]
    Unsupported,

    #[cfg_attr(feature="thiserror", error("Base64 decode error: {0}"))]
    B64(base64::DecodeError),
}

impl FromStr for Options {
    type Err = OptionsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use OptionsParseError::*;

        let mut p = s.split(":");
        let (prefix, data) = match (p.next(), p.next()) {
            (Some(p), Some(d)) => (p, d),
            _ => return Err(InvalidFormat),
        };

        match prefix {
            "pub_key" => Options::pub_key(PublicKey::from_str(&data).map_err(B64)?),
            "name" => Options::name(&data),
            "kind" => Options::kind(&data),
            _ => return Err(Unsupported),
        };
        
        todo!()
    }
}

impl Display for Options {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Options::PubKey(o) => write!(f, "pub_key:{}", o.public_key),
            Options::Name(o) => write!(f, "name:{}", o.value),
            Options::Kind(o) => write!(f, "kind:{}", o.value),
            //Options::Building(o) => write!(f, "name:{}", name.value),
            //Options::Room(o) => write!(f, "kind:{}", kind.value),
            _ => write!(f, "{:?}", self),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_options_parsing() {


    }

}