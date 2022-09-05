use byteorder::{NetworkEndian, ByteOrder};
use crate::base::{Encode, PageBody};
use crate::error::Error;
use crate::net::{Request, RequestBody, Response, ResponseBody, Common};
use crate::options::Options;
use crate::prelude::{Header, Keys};
use crate::service::Service;
use crate::types::{MutableData, RequestKind, ResponseKind, Address, Flags, Kind};
use crate::wire::builder::{SetPublicOptions, Encrypt};
use crate::wire::{Container, Builder};

#[derive(Clone, Debug, PartialEq)]
pub struct MessageOptions {
    pub append_public_key: bool,

    pub remote_addr: Option<Address>,

    pub peer_keys: Keys,
}

impl Default for MessageOptions {
    fn default() -> Self {
        Self { 
            append_public_key: false, 
            remote_addr: Default::default(), 
            peer_keys: Default::default()
        }
    }
}

pub trait Net{

    /// Encode a request using the provided peer keys and buffer
    fn encode_request<B: MutableData>(&self, req: &Request, peer_keys: &Keys, buff: B) -> Result<Container<B>, Error>;

    /// Encode a response using the provided peer keys and buffer
    fn encode_response<B: MutableData>(&self, resp: &Response, peer_keys: &Keys, buff: B) -> Result<Container<B>, Error>;

    /// Helper to encode and sign a request using fixed size buffer
    fn encode_request_buff<const N: usize>(
        &self,
        req: &Request,
        peer_keys: &Keys,
    ) -> Result<Container<[u8; N]>, Error> {
        self.encode_request(req, peer_keys, [0u8; N])
    }

    /// Helper to encode and sign a response using fixed size buffer
    fn encode_response_buff<const N: usize>(
        &self,
        resp: &Response,
        peer_keys: &Keys,
    ) -> Result<Container<[u8; N]>, Error> {
        self.encode_response(resp, peer_keys, [0u8; N])
    }
}


impl <D: PageBody> Net for Service<D> {
    fn encode_request<B: MutableData>(&self, req: &Request, keys: &Keys, buff: B) -> Result<Container<B>, Error> {

        // Create generic header
          let header = Header {
            kind: Kind::from(RequestKind::from(&req.data)),
            flags: req.flags,
            index: req.id,
            ..Default::default()
        };

        // Setup builder
        let b = Builder::new(buff)
            .id(&self.id)
            .header(&header);

        // Encode body
        let b = match &req.data {
            RequestBody::Hello | RequestBody::Ping => b.body(&[])?,
            RequestBody::FindNode(id) | RequestBody::FindValue(id) | RequestBody::Subscribe(id) | RequestBody::Unsubscribe(id) | RequestBody::Query(id) | RequestBody::Locate(id) | RequestBody::Unregister(id) => b.body(id.as_ref())?,
            RequestBody::Store(id, pages) | RequestBody::PushData(id, pages) | RequestBody::Register(id, pages) => {
                b.with_body(|buff| {
                    let mut n = id.encode(buff)?;
                    n += Container::encode_pages(pages, &mut buff[n..])?;
                    Ok(n)
                })?
            },
            // TODO: filter on options here too
            RequestBody::Discover(body, _opts) => {
                b.body(body)?
            },
        };

        // Attach options
        let b = b.private_options(&[])?
            .public();

        // Encrypt if running symmetric mode
        //let b = self.encrypt_message(req.flags, keys, b)?;

        // Sign/encrypt object using provided keying
        let c = self.finalise_message(req.flags, &req.common, keys, b)?;

        // Return new container
        Ok(c)
    }

    fn encode_response<B: MutableData>(&self, resp: &Response, keys: &Keys, buff: B) -> Result<Container<B>, Error> {
        // Create generic header
        let header = Header {
            kind: Kind::from(ResponseKind::from(&resp.data)),
            flags: resp.flags,
            index: resp.id,
            ..Default::default()
        };

        // Setup builder
        let b = Builder::new(buff)
            .id(&self.id)
            .header(&header);

        // Encode body
        let b = match &resp.data {
            ResponseBody::Status(status) => b.with_body(|buff| {
                NetworkEndian::write_u32(buff, status.into());
                Ok(4)
            })?,
            ResponseBody::NodesFound(id, nodes) => b.with_body(|buff| {
                    let mut i = id.encode(buff)?;
                    for n in nodes {
                        i += Options::encode_iter(&[
                            Options::peer_id(n.0.clone()),
                            Options::address(n.1),
                            Options::pub_key(n.2.clone())
                        ], &mut buff[i..])?
                    }
                    Ok(i)
            })?,
            ResponseBody::ValuesFound(id, pages) | ResponseBody::PullData(id, pages) => {
                b.with_body(|buff| {
                    let mut i = id.encode(buff)?;
                    i += Container::encode_pages(pages, &mut buff[i..])?;
                    Ok(i)
                })?
            },
            ResponseBody::NoResult => b.body(&[])?,
        };

        // Attach options
        let b = b.private_options(&[])?
            .public();

        // Encrypt if running symmetric mode
        //let b = self.encrypt_message(resp.flags, keys, b)?;
        
        // Sign/encrypt object using provided keying
        let c = self.finalise_message(resp.flags, &resp.common, keys, b)?;

        // Return new container
        Ok(c)
    }
}


impl <D: PageBody> Service<D> {

    pub fn encrypt_message<T: MutableData>(&self, flags: Flags, keys: &Keys, b: Builder<Encrypt, T>) -> Result<Builder<SetPublicOptions, T>, Error> {

        // Apply symmetric encryption if enabled
        if flags.contains(Flags::SYMMETRIC_MODE) && flags.contains(Flags::ENCRYPTED) {
            // Select matching symmetric key
            let sec_key = match &keys.sym_keys {
                Some(k) if flags.contains(Flags::SYMMETRIC_DIR) => &k.1,
                Some(k) => &k.0,
                _ => panic!("Attempted to encrypt object with no secret key"),
            };

            b.encrypt(&sec_key)
        } else {
            Ok(b.public())
        }
    }

    pub fn finalise_message<T: MutableData>(&self, flags: Flags, common: &Common, keys: &Keys, mut b: Builder<SetPublicOptions, T> ) -> Result<Container<T>, Error> {

        // Append public key if required
        if let Some(pk) = &common.public_key {
            b.public_option(&Options::pub_key(pk.clone()))?;
        }

        // Append remote address if provided
        if let Some(addr) = &common.remote_address {
            b.public_option(&Options::address(*addr))?;
        }

        // TODO: messages should be encrypted not just signed..?
        //let mut b = b.encrypt(opts.sk)?;

        // Sign/encrypt object using provided keying
        let c = if !flags.contains(Flags::SYMMETRIC_MODE) {
            // Public key mode, no KX required

            // TODO: attempt encryption against peer pub key if available

            // Check we have a private key to sign with 
            let private_key = match &self.private_key {
                Some(k) => k,
                None => return Err(Error::NoPrivateKey),
            };

            // Perform signing
            b.sign_pk(private_key)?

        } else {
            // Secret key mode, available following KX

            // Derive key by direction
            let sec_key = match &keys.sym_keys {
                Some(k) if flags.contains(Flags::SYMMETRIC_DIR) => &k.1,
                Some(k) => &k.0,
                _ => panic!("Attempted to sign object with no secret key"),
            };

            // Sign/Encrypt (AEAD) using secret key
            b.encrypt_sk(sec_key)?
        };

        Ok(c)
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use pretty_assertions::assert_eq;

    use crate::{prelude::*, net::{Status, Message}};
    use super::*;

    fn setup() -> (Service, Service) {
        #[cfg(feature="simplelog")]
        let _ = simplelog::SimpleLogger::init(simplelog::LevelFilter::Trace, simplelog::Config::default());

        let s = ServiceBuilder::generic().build().unwrap();
        let p = ServiceBuilder::generic().build().unwrap();
        (s, p)
    }

    fn requests(source: Id, target: Id, flags: Flags, page: Container) -> Vec<Request> {
        let request_id = 120;

        vec![
            Request::new(
                source.clone(),
                0,
                RequestBody::Hello,
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                1,
                RequestBody::Ping,
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                request_id,
                RequestBody::FindNode(target.clone()),
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                request_id,
                RequestBody::Store(source.clone(), vec![page.clone()]),
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                request_id,
                RequestBody::Subscribe(target.clone()),
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                request_id,
                RequestBody::Query(target.clone()),
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                request_id,
                RequestBody::PushData(source.clone(), vec![page.clone()]),
                flags.clone(),
            ),
        ]
    }


    #[test]
    fn encode_decode_requests_pk() {
        let (mut source, target) = setup();
        let (_n, page) = source.publish_primary_buff(Default::default()).unwrap();

        let flags = Flags::ADDRESS_REQUEST;
        let reqs = requests(source.id(), target.id(), flags, page.to_owned());

        for r in reqs {
            let mut buff = vec![0u8; 1024];

            println!("Encoding: {:?}", r);

            // Encode request
            let enc = source.encode_request(&r,  &target.keys(), &mut buff)
                .expect("Error encoding request");

            println!("Encoded to {:?} ({} bytes)", enc, enc.raw().len());

            // Parse back and check objects match
            let (r2, _) = Message::parse(enc.raw().to_vec(), &source.keys())
                .expect("error parsing message");

            println!("Decoded: {:?}", r2);

            assert_eq!(Message::request(r), r2);
        }
    }

    #[test]
    fn encode_decode_requests_sk() {
        let (mut source, target) = setup();
        let (_n, page) = source.publish_primary_buff(Default::default()).unwrap();

        let source_keys = source.keys().derive_peer(target.public_key()).unwrap();
        let target_keys = target.keys().derive_peer(source.public_key()).unwrap();

        let flags = Flags::ADDRESS_REQUEST | Flags::SYMMETRIC_MODE | Flags::ENCRYPTED;
        let reqs = requests(source.id(), target.id(), flags, page.to_owned());


        for r in reqs {
            let mut buff = vec![0u8; 1024];

            println!("Encoding: {:?}", r);

            // Encode request
            let enc = source.encode_request( &r, &source_keys, &mut buff)
                .expect("Error encoding request");

            println!("Encoded to {:?} ({} bytes)", enc, enc.raw().len());

            // Parse back and check objects match
            let (r2, _) = Message::parse(enc.raw().to_vec(), &target_keys)
                .expect("error parsing message");

            println!("Decoded: {:?}", r2);

            assert_eq!(Message::request(r), r2);
        }
    }


    fn responses(source: &Service, target: &Service, flags: Flags, page: Container) -> Vec<Response> {
        let request_id = 123;
        
        vec![
            Response::new(
                source.id(),
                request_id,
                ResponseBody::Status(Status::Ok),
                flags.clone(),
            ),
            // TODO: put node information here
            Response::new(
                source.id(),
                request_id,
                ResponseBody::NodesFound(
                    target.id(),
                    vec![(
                        target.id(),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).into(),
                        target.public_key(),
                    )],
                ),
                flags.clone(),
            ),
            Response::new(
                source.id(),
                request_id,
                ResponseBody::ValuesFound(target.id(), vec![page.clone()]),
                flags.clone(),
            ),
            Response::new(
                source.id(),
                request_id,
                ResponseBody::NoResult,
                flags.clone(),
            ),
            Response::new(
                source.id(),
                request_id,
                ResponseBody::PullData(target.id(), vec![page.clone()]),
                flags.clone(),
            ),
        ]
    }

    #[test]
    fn encode_decode_response_pk() {
        let (mut source, target) = setup();
        let (_n, page) = source.publish_primary_buff(Default::default()).unwrap();

        let flags = Flags::ADDRESS_REQUEST;
        let resps = responses(&source, &target, flags, page.to_owned());

        for r in resps {
            let mut buff = vec![0u8; 1024];

            println!("Encoding: {:?}", r);

            // Encode request
            let enc = source.encode_response(&r, &source.keys(), &mut buff)
                .expect("Error encoding response");

            // Parse back and check objects match
            let (r2, _) = Message::parse(enc.raw().to_vec(), &source.keys())
                .expect("error parsing message");

            assert_eq!(Message::response(r), r2);
        }
    }

    #[test]
    fn encode_decode_response_sk() {
        let (mut source, target) = setup();
        let (_n, page) = source.publish_primary_buff(Default::default()).unwrap();

        let source_keys = source.keys().derive_peer(target.public_key()).unwrap();
        let target_keys = target.keys().derive_peer(source.public_key()).unwrap();

        let flags = Flags::ADDRESS_REQUEST | Flags::SYMMETRIC_MODE | Flags::ENCRYPTED;
        let resps = responses(&source, &target, flags, page.to_owned());

        for r in resps {
            let mut buff = vec![0u8; 1024];

            println!("Encoding: {:?}", r);

            // Encode request
            let enc = source.encode_response( &r, &source_keys, &mut buff)
                .expect("Error encoding response");

            println!("Decoding: {:?}", enc);

            // Parse back and check objects match
            let (r2, _) = Message::parse(enc.raw().to_vec(), &target_keys)
                .expect("error parsing message");

            assert_eq!(Message::response(r), r2);
        }
    }
}
