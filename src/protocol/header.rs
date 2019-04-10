
use std::io::{Cursor, Error as IoError};


use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};


use crate::types::{Kind, Flags};
use crate::protocol::{Encode, Parse};


/// Header encodes information for a given page in the database
#[derive(Clone, PartialEq, Debug, Builder)]
pub struct Header {
    #[builder(default = "0")]
    protocol_version: u16,
    #[builder(default = "0")]
    application_id: u16,

    kind: Kind,
    #[builder(default = "Flags(0)")]
    flags: Flags,

    #[builder(default = "0")]
    /// Index is the Page Version for Pages, or the Request ID for messages
    index: u16,
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
    pub fn new(kind: Kind, index: u16, flags: Flags) -> Header {
        Header{protocol_version: 0, application_id: 0, kind, flags, index}
    }

    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn application_id(&self) -> u16 {
        self.application_id
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn index(&self) -> u16 {
        self.index
    }
}

impl Parse for Header {
    type Output = Header;
    type Error = IoError;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut r = Cursor::new(data);
        
        let protocol_version = r.read_u16::<NetworkEndian>()?;
        let application_id = r.read_u16::<NetworkEndian>()?;
        let kind = Kind::from(r.read_u16::<NetworkEndian>()?);
        let flags = r.read_u16::<NetworkEndian>()?.into();
        let index = r.read_u16::<NetworkEndian>()?;

        // TODO: validate incoming fields here

        Ok((Header {protocol_version, application_id, kind, flags, index}, r.position() as usize))
    }
}

impl Encode for Header {
    type Error = IoError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);
        
        w.write_u16::<NetworkEndian>(self.protocol_version)?;
        w.write_u16::<NetworkEndian>(self.application_id)?;
        w.write_u16::<NetworkEndian>(self.kind.into())?;
        w.write_u16::<NetworkEndian>(self.flags.into())?;
        w.write_u16::<NetworkEndian>(self.index)?;

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