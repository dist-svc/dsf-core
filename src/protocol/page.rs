

use byteorder::{ByteOrder, NetworkEndian};

use crate::types::{Id, ID_LEN, Signature, SIGNATURE_LEN, Flags, Kind};
use crate::protocol::{Encode, Parse};
use crate::protocol::header::PageHeader;
use crate::protocol::options::{Options, OptionsError};


#[derive(Clone, Builder, Debug, PartialEq)]
pub struct Page {
    id:             Id,
    header:         PageHeader,
    #[builder(default = "vec![]")]
    body:           Vec<u8>,
    #[builder(default = "vec![]")]
    private_options: Vec<Options>,
    #[builder(default = "vec![]")]
    public_options: Vec<Options>,
    #[builder(default = "None")]
    signature:      Option<Signature>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum PageError {
    Io(std::io::ErrorKind),
    Options(OptionsError),
    InvalidSignature,
}

impl From<OptionsError> for PageError {
    fn from(o: OptionsError) -> PageError {
        PageError::Options(o)
    }
}

impl From<std::io::Error> for PageError {
    fn from(e: std::io::Error) -> PageError {
        PageError::Io(e.kind())
    }
}

const PAGE_HEADER_LEN: usize = 12;

impl Page {
    pub fn new(id: Id, kind: Kind, flags: Flags, version: u16, body: Vec<u8>, public_options: Vec<Options>, private_options: Vec<Options>) -> Page {
        let header = PageHeader::new(kind, version, flags);
        Page{id, header, body, public_options, private_options, signature: None}
    }

    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn header(&self) -> &PageHeader {
        &self.header
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn public_options(&self) -> &[Options] {
        &self.public_options
    }

    pub fn private_options(&self) -> &[Options] {
        &self.private_options
    }

    pub fn signature(&self) -> &Option<Signature> {
        &self.signature
    }
}

impl Page {
    /// Parses an array containing a page into a page object
    pub fn parse<'a, V>(validator: V, data: &'a [u8]) -> Result<(Page, Option<&'a [u8]>), PageError> 
    where 
        V: Fn(&[u8], &[u8], &[u8]) -> bool
    {
        // Parse page header
        let header_data = &data[0..PAGE_HEADER_LEN];
        let (header, _) = PageHeader::parse(header_data)?;

        // Parse lengths from header
        let data_len = NetworkEndian::read_u16(&header_data[6..8]) as usize;
        let private_options_len = NetworkEndian::read_u16(&header_data[8..10]) as usize;
        let public_options_len = NetworkEndian::read_u16(&header_data[10..12]) as usize;

        // Parse ID for page
        let mut id = [0u8; ID_LEN];
        id.clone_from_slice(&data[PAGE_HEADER_LEN..PAGE_HEADER_LEN+ID_LEN]);

        let page_len = PAGE_HEADER_LEN + ID_LEN + data_len + private_options_len + public_options_len + SIGNATURE_LEN;

        // Fetch data ranges and check signature
        let page_data = &data[..page_len-SIGNATURE_LEN];

        let mut signature = [0u8; SIGNATURE_LEN];
        signature.clone_from_slice(&data[page_len-SIGNATURE_LEN..page_len]);

        // Validate signature here (pass if unknown or new)
        if !(validator)(&id, page_data, &signature) {
            return Err(PageError::InvalidSignature);
        }

        let mut index = PAGE_HEADER_LEN + ID_LEN;

        let body = &data[index..index+data_len];
        index += data_len;

        let (private_options, _) = Options::parse_vec(&page_data[index..index+private_options_len])?;
        index += private_options_len;

        let (public_options, _) = Options::parse_vec(&page_data[index..index+public_options_len])?;
        index += public_options_len;

        assert_eq!(index + SIGNATURE_LEN, page_len);

        // Return page and options
        Ok((
            Page {
                id,
                header,
                body: body.into(),
                private_options,
                public_options,
                signature: Some(signature.into()),
            },
            data.get(page_len..),
        ))
    }
}

impl Page {
    pub fn encode<'a, S>(&mut self, mut signer: S, buff: &'a mut [u8]) -> Result<(&'a [u8], usize), PageError> 
    where 
        S: FnMut(&[u8], &[u8]) -> Signature
    {
        let mut i = PAGE_HEADER_LEN;

        // Write ID
        (&mut buff[PAGE_HEADER_LEN..PAGE_HEADER_LEN+ID_LEN]).copy_from_slice(&self.id);
        i += ID_LEN;

        // Write data
        (&mut buff[i..i+self.body.len()]).copy_from_slice(&self.body);
        i += self.body.len();

        // Write secret options
        let private_options_len = { Options::encode_vec(&self.private_options, &mut buff[i..])?};
        i += private_options_len;

        // Write public options
        let public_options_len = { Options::encode_vec(&self.public_options, &mut buff[i..])?};
        i += public_options_len;

        // Write header
        {
            let mut header_data = &mut buff[0..PAGE_HEADER_LEN];
            self.header.encode(&mut header_data)?;

            NetworkEndian::write_u16(&mut header_data[6..8], self.body().len() as u16);
            NetworkEndian::write_u16(&mut header_data[8..10], private_options_len as u16);
            NetworkEndian::write_u16(&mut header_data[10..12], public_options_len as u16);
        }
        

        // Calculate signature over written data
        let signature = (signer)(&self.id, &buff[..i]);

        // Attach signature to page object
        self.signature = Some(signature);

        // Write signature
        (&mut buff[i..i+SIGNATURE_LEN]).copy_from_slice(signature.as_ref());
        i += SIGNATURE_LEN;

        Ok((&buff[..i], i))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn new_page() {
        
    }

    #[test]
    fn encode_page() {
        
    }



}
