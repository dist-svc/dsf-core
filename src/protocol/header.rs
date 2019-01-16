
use std::io::{Cursor, Error as IoError};


use byteorder::{ByteOrder, NetworkEndian, ReadBytesExt, WriteBytesExt};


use crate::types::{Kind, Flags};
use crate::protocol::{Encode, Parse};


/// Header encodes information for a given page in the database
#[derive(Clone, PartialEq, Debug, Builder)]
pub struct Header {
    kind: Kind,
    #[builder(default = "Flags(0)")]
    flags: Flags,
    #[builder(default = "0")]
    version: u16,
}

impl HeaderBuilder {
    pub fn address_request(&mut self) -> &mut Self {
        let mut flags = self.flags.or(Some(Flags(0))).unwrap();
        flags.set_address_request(true);
        self.flags = Some(flags);
        self
    }
}

impl Header {
    pub fn new(kind: Kind, version: u16, flags: Flags) -> Header {
        Header{kind, flags, version}
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn version(&self) -> u16 {
        self.version
    }
}

impl Parse for Header {
    type Output = Header;
    type Error = IoError;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut r = Cursor::new(data);
        
        let kind = Kind::from(r.read_u16::<NetworkEndian>()?);
        let flags = r.read_u16::<NetworkEndian>()?.into();
        let version = r.read_u16::<NetworkEndian>()?;

        Ok((Header {kind, flags, version}, r.position() as usize))
    }
}

impl Encode for Header {
    type Error = IoError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);
        
        w.write_u16::<NetworkEndian>(self.kind.into())?;
        w.write_u16::<NetworkEndian>(self.flags.into())?;
        w.write_u16::<NetworkEndian>(self.version)?;

        Ok(w.position() as usize)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_encode_page_header() {
        let h1 = Header::new(Kind::Generic, 1, 2.into());

        let mut buff = [0u8; 1024];
        let n1 = h1.encode(&mut buff).expect("Header encoding failed");
        let b = &buff[..n1];

        let (h2, n2) = Header::parse(&b).expect("Header parsing failed");
        assert_eq!(h1, h2);
        assert_eq!(n1, n2);
    }
}