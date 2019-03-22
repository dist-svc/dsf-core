
use std::net::{SocketAddr};
use std::time::SystemTime;

use byteorder::{ByteOrder, NetworkEndian};

use crate::types::{Id, ID_LEN, Signature, SIGNATURE_LEN, Flags, Kind, PublicKey, RequestId, Address, DateTime};
use crate::protocol::{Encode, Parse};
use crate::protocol::header::Header;
use crate::protocol::options::{Options, OptionsError};
use crate::crypto;
use crate::protocol::container::Container;

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

    pub fn flags(&self) -> Flags {
        self.header.flags()
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

    pub fn append_public_option(&mut self, o: Options) {
        self.public_options.push(o);
    }

    pub fn append_private_option(&mut self, o: Options) {
        self.private_options.push(o);
    }

    pub fn pub_key_option(&self) -> Option<PublicKey> {
        self.public_options().iter().find_map(|o| {
            match o { 
                Options::PubKey(pk) => Some(pk.public_key.clone()),
                 _ => None 
            } 
        })
    }

    pub fn req_id_option(&self) -> Option<RequestId> {
        self.public_options().iter().find_map(|o| {
            match o { 
                Options::RequestId(req_id) => Some(req_id.request_id),
                 _ => None 
            } 
        })
    }

    pub fn peer_id_option(&self) -> Option<Id> {
        self.public_options().iter().find_map(|o| {
            match o { 
                Options::PeerId(peer_id) => Some(peer_id.peer_id.clone()),
                 _ => None 
            } 
        })
    }

    pub fn issued_option(&self) -> Option<DateTime> {
        self.public_options().iter().find_map(|o| {
            match o { 
                Options::Issued(t) => Some(t.when),
                 _ => None 
            } 
        })
    }

    pub fn expiry_option(&self) -> Option<DateTime> {
        self.public_options().iter().find_map(|o| {
            match o { 
                Options::Expiry(t) => Some(t.when),
                 _ => None 
            } 
        })
    }

    pub fn address_option(&self) -> Option<Address> {
        self.public_options().iter().find_map(|o| {
            match o { 
                Options::IPv4(addr) => Some(SocketAddr::V4(*addr)),
                Options::IPv6(addr) => Some(SocketAddr::V6(*addr)),
                 _ => None 
            } 
        })
    }
}

impl Base {
    #[deprecated]
    pub fn raw_id(data: &[u8]) -> Id {
        let mut id = [0u8; ID_LEN];
        id.clone_from_slice(&data[PAGE_HEADER_LEN..PAGE_HEADER_LEN+ID_LEN]);
        id.into()
    }
    #[deprecated]
    pub fn raw_sig(data: &[u8]) -> Signature {
        let mut sig = [0u8; SIGNATURE_LEN];
        sig.clone_from_slice(&data[data.len()-SIGNATURE_LEN..]);
        sig.into()
    }
    #[deprecated]
    pub fn validate(public_key: &[u8], data: &[u8]) -> bool {
        // TODO: check length is valid
        let sig = &data[data.len()-SIGNATURE_LEN..];
        let body = &data[..data.len()-SIGNATURE_LEN];

        crypto::pk_validate(public_key, sig, body).unwrap()
    }

    /// Parses an array containing a page into a page object
    pub fn parse<'a, T: AsRef<[u8]>>(data: T) -> Result<(Base, usize), BaseError> 
    {
        let (container, n) = Container::from(data);

        // Fetch ID for page
        let mut id = [0u8; ID_LEN];
        id.clone_from_slice(container.id());

        // Fetch signature for page
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.clone_from_slice(container.signature());

        // TODO: handle decryption here
        let body_data = container.body();
        // TODO: handle decryption here
        let (private_options, _) = Options::parse_vec(container.private_options())?;

        let (public_options, _) = Options::parse_vec(container.public_options())?;

        // Return page and options
        Ok((
            Base {
                id: id.into(),
                header: Header::new(container.kind(), container.version(), container.flags()),
                body: body_data.into(),
                private_options,
                public_options,
                signature: Some(signature.into()),
            },
            n,
        ))
    }
}

impl Base {
    pub fn encode<'a, S, E, T: AsRef<[u8]> + AsMut<[u8]>>(&mut self, mut signer: S, buff: T) -> Result<usize, BaseError> 
    where 
        S: FnMut(&[u8], &[u8]) -> Result<Signature, E>
    {

        // Build container and encode page
        let (mut container, n) = Container::encode(buff, &self);

        // Calculate signature over written data (if sig does not already exist)
        if let None = self.signature {
            // Generate signature
            let sig = container.sign(signer).map_err(|_e| BaseError::InvalidSignature )?;

            // Attach signature to page object
            self.signature = Some(sig.clone());
        }

        Ok(n)
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
        let id = crypto::hash(&pub_key).expect("Error generating new ID").into();

        let _sec_key = crypto::new_sk().expect("Error generating new secret key");

        let header = HeaderBuilder::default().kind(Kind::Generic).build().expect("Error building page header");
        let data = vec![1, 2, 3, 4, 5, 6, 7];

        let mut page = BaseBuilder::default().id(id).header(header).body(data).build().expect("Error building page");

        let mut buff = vec![0u8; 1024];
        let n = page.encode(move |_id, data| crypto::pk_sign(&pri_key, data), &mut buff).expect("Error encoding page");

        let (decoded, m) = Base::parse(&buff[..n]).expect("Error decoding page");;

        assert_eq!(page, decoded);
        assert_eq!(n, m);
    }

}
