

use byteorder::{ByteOrder, NetworkEndian};

use crate::types::{Id, ID_LEN, Signature, SIGNATURE_LEN, Flags, Kind, ENCRYPTED_META_LEN};
use crate::protocol::{Encode, Parse};
use crate::protocol::header::Header;
use crate::protocol::options::{Options, OptionsError};


#[derive(Clone, Builder, Debug, PartialEq)]
pub struct Base {
    id:             Id,
    header:         Header,
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
pub enum BaseError {
    Io(std::io::ErrorKind),
    Options(OptionsError),
    InvalidSignature,
}

impl From<OptionsError> for BaseError {
    fn from(o: OptionsError) -> BaseError {
        BaseError::Options(o)
    }
}

impl From<std::io::Error> for BaseError {
    fn from(e: std::io::Error) -> BaseError {
        BaseError::Io(e.kind())
    }
}

impl BaseBuilder {
    pub fn base(&mut self, id: Id, kind: Kind, version: u16, flags: Flags) -> &mut Self {
        let header = Header::new(kind, version, flags);
        self.id = Some(id);
        self.header = Some(header);
        self
    }

    pub fn append_public_option(&mut self, o: Options) -> &mut Self {
        match &mut self.public_options {
            Some(opts) => opts.push(o),
            None => self.public_options = Some(vec![o]),
        }
        self
    }

     pub fn append_private_option(&mut self, o: Options) -> &mut Self {
        match &mut self.private_options {
            Some(opts) => opts.push(o),
            None => self.private_options = Some(vec![o]),
        }
        self
    }
}

const PAGE_HEADER_LEN: usize = 12;

impl Base {
    pub fn new(id: Id, kind: Kind, flags: Flags, version: u16, body: Vec<u8>, public_options: Vec<Options>, private_options: Vec<Options>) -> Base {
        let header = Header::new(kind, version, flags);
        Base{id, header, body, public_options, private_options, signature: None}
    }

    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn header(&self) -> &Header {
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

impl Base {
    /// Parses an array containing a page into a page object
    pub fn parse<'a, V>(validator: V, data: &'a [u8]) -> Result<(Base, usize), BaseError> 
    where 
        V: Fn(&[u8], &[u8], &[u8]) -> bool
    {
        // Parse page header
        let header_data = &data[0..PAGE_HEADER_LEN];
        let (header, _) = Header::parse(header_data)?;
        let flags = header.flags();

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
            return Err(BaseError::InvalidSignature);
        }

        let mut index = PAGE_HEADER_LEN + ID_LEN;

        let body_data = &data[index..index+data_len];
        index += data_len;

        let private_option_data = &page_data[index..index+private_options_len];
        index += private_options_len;

        let public_option_data = &page_data[index..index+public_options_len];
        index += public_options_len;

        // TODO: handle decryption here

        let (private_options, _) = Options::parse_vec(private_option_data)?;

        let (public_options, _) = Options::parse_vec(public_option_data)?;

        assert_eq!(index + SIGNATURE_LEN, page_len);

        // Return page and options
        Ok((
            Base {
                id,
                header,
                body: body_data.into(),
                private_options,
                public_options,
                signature: Some(signature.into()),
            },
            page_len,
        ))
    }
}

impl Base {
    pub fn encode<'a, S>(&mut self, mut signer: S, buff: &'a mut [u8]) -> Result<usize, BaseError> 
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

        // TODO: handle encryption here

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

        Ok(i)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::protocol::header::*;

    use crate::crypto;

    #[test]
    fn encode_decode_page() {
        let (pub_key, pri_key) = crypto::new_pk().expect("Error generating new public/private key pair");
        let id = crypto::hash(&pub_key).expect("Error generating new ID");

        let sec_key = crypto::new_sk().expect("Error generating new secret key");

        let header = HeaderBuilder::default().kind(Kind::Generic).build().expect("Error building page header");
        let data = vec![1, 2, 3, 4, 5, 6, 7];

        let mut page = BaseBuilder::default().id(id).header(header).body(data).build().expect("Error building page");

        let mut buff = vec![0u8; 1024];
        let n = page.encode(move |_id, data| crypto::pk_sign(&pri_key, data).unwrap(), &mut buff).expect("Error encoding page");

        let (decoded, m) = Base::parse(move |_id, data, sig| crypto::pk_validate(&pub_key, sig, data).unwrap(), &buff[..n]).expect("Error decoding page");;

        assert_eq!(page, decoded);
        assert_eq!(n, m);
    }

}
