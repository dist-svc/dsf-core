use byteorder::{NetworkEndian, ByteOrder};

use crate::base::{Base, Encode};
use crate::error::Error;
use crate::net::{Message, Request, RequestKind, Response, ResponseKind, Common};
use crate::options::Options;
use crate::prelude::{Body, Header, Keys, Page, KeySource};
use crate::service::Service;
use crate::types::{MutableData, MessageKind, PublicKey, Address, Flags};
use crate::wire::builder::SetPublicOptions;
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

pub trait Net<const N: usize = 1024>{

    /// Encode a request using the provided peer keys and buffer
    fn encode_request<B: MutableData>(&self, req: &Request, peer_keys: &Keys, buff: B) -> Result<Container<B>, Error>;

    /// Encode a response using the provided peer keys and buffer
    fn encode_response<B: MutableData>(&self, resp: &Response, peer_keys: &Keys, buff: B) -> Result<Container<B>, Error>;

    /// Helper to encode and sign a request using fixed size buffer
    fn encode_request_buff(
        &self,
        req: &Request,
        peer_keys: &Keys,
    ) -> Result<Container<[u8; N]>, Error> {
        self.encode_request(req, peer_keys, [0u8; N])
    }

    /// Helper to encode and sign a response using fixed size buffer
    fn encode_response_buff(
        &self,
        resp: &Response,
        peer_keys: &Keys,
    ) -> Result<Container<[u8; N]>, Error> {
        self.encode_response(resp, peer_keys, [0u8; N])
    }
}


impl Net for Service {
    fn encode_request<B: MutableData>(&self, req: &Request, keys: &Keys, buff: B) -> Result<Container<B>, Error> {

        // Create generic header
          let header = Header {
            kind: MessageKind::from(&req.data).into(),
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
            RequestKind::Hello | RequestKind::Ping => b.body(&[])?,
            RequestKind::FindNode(id) | RequestKind::FindValue(id) | RequestKind::Subscribe(id) | RequestKind::Unsubscribe(id) | RequestKind::Query(id) | RequestKind::Locate(id) | RequestKind::Unregister(id) => b.body(id.as_ref())?,
            RequestKind::Store(id, pages) | RequestKind::PushData(id, pages) | RequestKind::Register(id, pages) => {
                b.with_body(|buff| {
                    let mut n = id.encode(buff)?;
                    n += Page::encode_pages(&pages, &mut buff[n..])?;
                    Ok(n)
                })?
            },
            RequestKind::Discover(_, _) => todo!("Implement discover encoding"),
        };

        // Attach options
        let b = b.private_options(&[])?
            .public();

        // Sign/encrypt object using provided keying
        let c = self.finalise_message(req.flags, &req.common, keys, b)?;

        // Return new container
        Ok(c)
    }

    fn encode_response<B: MutableData>(&self, resp: &Response, keys: &Keys, buff: B) -> Result<Container<B>, Error> {
        // Create generic header
        let header = Header {
            kind: MessageKind::from(&resp.data).into(),
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
            ResponseKind::Status(status) => b.with_body(|buff| {
                NetworkEndian::write_u32(buff, status.into());
                Ok(4)
            })?,
            ResponseKind::NodesFound(id, nodes) => b.with_body(|buff| {
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
            ResponseKind::ValuesFound(id, pages) | ResponseKind::PullData(id, pages) => {
                b.with_body(|buff| {
                    let mut i = id.encode(buff)?;
                    i += Page::encode_pages(&pages, &mut buff[i..])?;
                    Ok(i)
                })?
            },
            ResponseKind::NoResult => b.body(&[])?,
        };

        // Attach options
        let b = b.private_options(&[])?
            .public();

        // Sign/encrypt object using provided keying
        let c = self.finalise_message(resp.flags, &resp.common, keys, b)?;

        // Return new container
        Ok(c)
    }
}


impl Service {

    pub fn finalise_message<T: MutableData>(&self, flags: Flags, common: &Common, keys: &Keys, mut b: Builder<SetPublicOptions, T> ) -> Result<Container<T>, Error> {

        // Append public key if required
        if let Some(pk) = &common.public_key {
            b.public_option(&Options::pub_key(pk.clone()))?;
        }

        // Append remote address if provided
        if let Some(addr) = &common.remote_address {
            b.public_option(&Options::address(addr.clone()))?;
        }

        // TODO: messages should be encrypted not just signed..?
        //let mut b = b.encrypt(opts.sk)?;

        // Sign/encrypt object using provided keying
        let c = if !flags.contains(Flags::SYMMETRIC_MODE) {
            // Public key mode, no KX required

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

            // Sign using secret key
            b.sign_sk(&sec_key)?
        };

        Ok(c)
    }
}

#[cfg(test)]
mod test {
    use std::{convert::TryFrom, net::{IpAddr, Ipv4Addr, SocketAddr}};

    use pretty_assertions::assert_eq;

    use crate::{prelude::*, net::Status};
    use super::*;

    fn setup() -> (Service, Service) {
        let s = ServiceBuilder::generic().build().unwrap();
        let p = ServiceBuilder::generic().build().unwrap();
        (s, p)
    }

    fn requests(source: Id, target: Id, flags: Flags, page: Page) -> Vec<Request> {
        let request_id = 120;

        vec![
            Request::new(
                source.clone(),
                0,
                RequestKind::Hello,
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                1,
                RequestKind::Ping,
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                request_id,
                RequestKind::FindNode(target.clone()),
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                request_id,
                RequestKind::Store(source.clone(), vec![page.clone()]),
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                request_id,
                RequestKind::Subscribe(target.clone()),
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                request_id,
                RequestKind::Query(target.clone()),
                flags.clone(),
            ),
            Request::new(
                source.clone(),
                request_id,
                RequestKind::PushData(source.clone(), vec![page.clone()]),
                flags.clone(),
            ),
        ]
    }


    #[test]
    fn encode_decode_requests_pk() {
        let (mut source, target) = setup();
        let (_n, page) = source.publish_primary_buff(Default::default()).unwrap();

        let flags = Flags::ADDRESS_REQUEST;
        let reqs = requests(source.id(), target.id(), flags, Page::try_from(page).unwrap());

        for r in reqs {
            let mut buff = vec![0u8; 1024];

            println!("Encoding: {:?}", r);

            // Encode request
            let enc = source.encode_request(&r,  &target.keys(), &mut buff)
                .expect("Error encoding request");

            // Parse back and check objects match
            let (mut dec, m) = Base::parse(enc.raw().to_vec(), &source.keys())
                .expect("error parsing message");
            dec.clean();

            println!("Decoded: {:?}", dec);

            // Cast to message and check instances match
            let r2 = Request::convert(dec, &source.keys())
                .expect("error converting base object to message");

            assert_eq!(r, r2);
        }
    }

    #[test]
    fn encode_decode_requests_sk() {
        let (mut source, target) = setup();
        let (_n, page) = source.publish_primary_buff(Default::default()).unwrap();

        let source_keys = source.keys().derive_peer(target.public_key()).unwrap();
        let target_keys = target.keys().derive_peer(source.public_key()).unwrap();

        let flags = Flags::ADDRESS_REQUEST | Flags::SYMMETRIC_MODE;
        let reqs = requests(source.id(), target.id(), flags, Page::try_from(page).unwrap());


        for r in reqs {
            let mut buff = vec![0u8; 1024];

            println!("Encoding: {:?}", r);

            // Encode request
            let enc = source.encode_request( &r, &source_keys, &mut buff)
                .expect("Error encoding request");

            println!("Decoding: {:?}", enc);

            // Parse back and check objects match
            let (mut dec, _m) = Base::parse(enc.raw().to_vec(), &target_keys)
                .expect("error parsing message");
            dec.clean();

            println!("Decoded: {:?}", dec);

            // Cast to message and check instances match
            let r2 = Request::convert(dec, &target_keys)
                .expect("error converting base object to message");

            assert_eq!(r, r2);
        }
    }


    fn responses(source: &Service, target: &Service, flags: Flags, page: Page) -> Vec<Response> {
        let request_id = 123;
        
        vec![
            Response::new(
                source.id(),
                request_id,
                ResponseKind::Status(Status::Ok),
                flags.clone(),
            ),
            // TODO: put node information here
            Response::new(
                source.id(),
                request_id,
                ResponseKind::NodesFound(
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
                ResponseKind::ValuesFound(target.id(), vec![page.clone()]),
                flags.clone(),
            ),
            Response::new(
                source.id(),
                request_id,
                ResponseKind::NoResult,
                flags.clone(),
            ),
            Response::new(
                source.id(),
                request_id,
                ResponseKind::PullData(target.id(), vec![page.clone()]),
                flags.clone(),
            ),
        ]
    }

    #[test]
    fn encode_decode_response_pk() {
        let (mut source, target) = setup();
        let (_n, page) = source.publish_primary_buff(Default::default()).unwrap();

        let flags = Flags::ADDRESS_REQUEST;
        let resps = responses(&source, &target, flags, Page::try_from(page).unwrap());

        for r in resps {
            let mut buff = vec![0u8; 1024];

            println!("Encoding: {:?}", r);

            // Encode request
            let enc = source.encode_response(&r, &source.keys(), &mut buff)
                .expect("Error encoding response");

            // Parse back and check objects match
            let (mut dec, m) = Base::parse(enc.raw().to_vec(), &source.keys())
                .expect("error parsing message");
            dec.clean();

            println!("Decoded: {:?}", dec);

            // Cast to message and check instances match
            let r2 = Response::convert(dec, &source.keys())
                .expect("error converting base object to message");

            assert_eq!(r, r2);
        }
    }

    #[test]
    fn encode_decode_response_sk() {
        let (mut source, target) = setup();
        let (_n, page) = source.publish_primary_buff(Default::default()).unwrap();

        let source_keys = source.keys().derive_peer(target.public_key()).unwrap();
        let target_keys = target.keys().derive_peer(source.public_key()).unwrap();

        let flags = Flags::ADDRESS_REQUEST | Flags::SYMMETRIC_MODE;
        let resps = responses(&source, &target, flags, Page::try_from(page).unwrap());

        for r in resps {
            let mut buff = vec![0u8; 1024];

            println!("Encoding: {:?}", r);

            // Encode request
            let enc = source.encode_response( &r, &source_keys, &mut buff)
                .expect("Error encoding response");

            println!("Decoding: {:?}", enc);

            // Parse back and check objects match
            let (mut dec, _m) = Base::parse(enc.raw().to_vec(), &target_keys)
                .expect("error parsing message");
            dec.clean();

            println!("Decoded: {:?}", dec);

            // Cast to message and check instances match
            let r2 = Response::convert(dec, &target_keys)
                .expect("error converting base object to message");

            assert_eq!(r, r2);
        }
    }
}
