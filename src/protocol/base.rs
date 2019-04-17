//! Base object is a common owned object that is used to represent pages / messages / data
//! and can be encoded and decoded for wire communication.

use std::net::{SocketAddr};

use crate::types::{Id, ID_LEN, Signature, SIGNATURE_LEN, Flags, Kind, PublicKey, Address, DateTime};
use crate::protocol::header::Header;
use crate::protocol::options::{Options, OptionsError};
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
    pub fn base(&mut self, id: Id, application_id: u16, kind: Kind, index: u16, flags: Flags) -> &mut Self {
        let header = Header::new(application_id, kind, index, flags);
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


impl Base {
    pub fn new(id: Id, application_id: u16, kind: Kind, flags: Flags, version: u16, body: Vec<u8>, public_options: Vec<Options>, private_options: Vec<Options>) -> Base {
        let header = Header::new(application_id, kind, version, flags);
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

    pub fn set_signature(&mut self, sig: Signature) {
        self.signature = Some(sig);
    }

    pub fn append_public_option(&mut self, o: Options) {
        self.public_options.push(o);
    }

    pub fn append_private_option(&mut self, o: Options) {
        self.private_options.push(o);
    }
}

const PAGE_HEADER_LEN: usize = 16;
use crate::crypto;

// TODO: move these to the options module?
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
    pub fn validate(public_key: &PublicKey, data: &[u8]) -> bool {
        // TODO: check length is valid
        let sig = Base::raw_sig(data);
        let body = &data[..data.len()-SIGNATURE_LEN];

        crypto::pk_validate(public_key, &sig, body).unwrap()
    }

    pub fn pub_key_option(options: &[Options]) -> Option<PublicKey> {
        options.iter().find_map(|o| {
            match o { 
                Options::PubKey(pk) => Some(pk.public_key.clone()),
                 _ => None 
            } 
        })
    }

    pub fn filter_pub_key_option(options: &mut Vec<Options>) -> Option<PublicKey>
    {
        let o = Base::pub_key_option(&options);

        (*options) = options.iter().filter_map(|o| {
            match o { 
                Options::PubKey(_) => None,
                _ => Some(o.clone()), 
            }
        }).collect();

        o
    }

    pub fn peer_id_option(options: &[Options]) -> Option<Id> {
        options.iter().find_map(|o| {
            match o { 
                Options::PeerId(peer_id) => Some(peer_id.peer_id.clone()),
                 _ => None 
            } 
        })
    }

    pub fn filter_peer_id_option(options: &mut Vec<Options>) -> Option<Id>
    {
        let o = Base::peer_id_option(&options);

        (*options) = options.iter().filter_map(|o| {
            match o { 
                Options::PeerId(_) => None,
                _ => Some(o.clone()), 
            }
        }).collect();

        o
    }


    pub fn issued_option(options: &[Options]) -> Option<DateTime> {
        options.iter().find_map(|o| {
            match o { 
                Options::Issued(t) => Some(t.when),
                 _ => None 
            } 
        })
    }

    pub fn filter_issued_option(options: &mut Vec<Options>) -> Option<DateTime>
    {
        let o = Base::issued_option(&options);

        (*options) = options.iter().filter_map(|o| {
            match o { 
                Options::Issued(_t) => None,
                _ => Some(o.clone()), 
            }
        }).collect();

        o
    }

    pub fn expiry_option(options: &[Options]) -> Option<DateTime> {
        options.iter().find_map(|o| {
            match o { 
                Options::Expiry(t) => Some(t.when),
                 _ => None 
            } 
        })
    }

    pub fn filter_expiry_option(options: &mut Vec<Options>) -> Option<DateTime>
    {
        let o = Base::expiry_option(&options);

        (*options) = options.iter().filter_map(|o| {
            match o { 
                Options::Expiry(_t) => None,
                _ => Some(o.clone()), 
            }
        }).collect();

        o
    }

    pub fn address_option(options: &[Options]) -> Option<Address> {
        options.iter().find_map(|o| {
            match o { 
                Options::IPv4(addr) => Some(SocketAddr::V4(*addr)),
                Options::IPv6(addr) => Some(SocketAddr::V6(*addr)),
                 _ => None 
            } 
        })
    }

    pub fn filter_address_option(options: &mut Vec<Options>) -> Option<Address>
    {
        let address = Base::address_option(&options);

        (*options) = options.iter().filter_map(|o| {
            match o { 
                Options::IPv4(_addr) => None,
                Options::IPv6(_addr) => None,
                _ => Some(o.clone()), 
            }
        }).collect();

        address
    }
}

impl Base {
    /// Parses an array containing a page into a page object
    /// fn v(id, data, sig)
    pub fn parse<'a, V, T: AsRef<[u8]>>(data: T, verifier: V) -> Result<(Base, usize), BaseError>
    where 
        V: FnMut(&Id, &Signature, &[u8]) -> Result<bool, ()>
    {
        // Build container over buffer
        let (container, n) = Container::from(data);

        // Verify container contents
        if !container.verify(verifier).map_err(|_e| BaseError::InvalidSignature )? {
            return Err(BaseError::InvalidSignature);
        }

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
                header: Header::new(container.application_id(), container.kind(), container.index(), container.flags()),
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
    pub fn encode<'a, S, E, T: AsRef<[u8]> + AsMut<[u8]>>(&mut self, signer: S, buff: T) -> Result<usize, BaseError> 
    where 
        S: FnMut(&Id, &[u8]) -> Result<Signature, E>
    {

        // Build container and encode page
        let (mut container, n) = Container::encode(buff, &self);

        // Calculate signature over written data (if sig does not already exist)
        if let None = self.signature {
            // Generate signature
            let sig = container.sign(signer).map_err(|_e| BaseError::InvalidSignature )?;

            trace!("created sig: {:?}", sig);

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

        let (decoded, m) = Base::parse(&buff[..n], |_id, sig, data| crypto::pk_validate(&pub_key, sig, data) ).expect("Error decoding page");;

        assert_eq!(page, decoded);
        assert_eq!(n, m);
    }

}
