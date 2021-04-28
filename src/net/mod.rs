//! Net module contains high-level message objects used to communicate between peers
//! to maintain the network, publish and subscribe to services, and exchange data.
//! These can be converted to and from base objects for encoding/decoding.

use crate::base::Base;
use crate::error::Error;
use crate::types::*;

pub mod request;
pub use request::{Request, RequestKind};

pub mod response;
pub use response::{Response, ResponseKind, Status};

pub const BUFF_SIZE: usize = 10 * 1024;

use crate::{KeySource, Keys};

/// Message is a network request or response message
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Message {
    Request(Request),
    Response(Response),
}

impl Message {
    pub fn request(req: Request) -> Self {
        Self::Request(req)
    }

    pub fn response(resp: Response) -> Self {
        Self::Response(resp)
    }

    pub fn request_id(&self) -> RequestId {
        match self {
            Message::Request(req) => req.id,
            Message::Response(resp) => resp.id,
        }
    }

    pub fn from(&self) -> Id {
        match self {
            Message::Request(req) => req.from.clone(),
            Message::Response(resp) => resp.from.clone(),
        }
    }

    pub fn flags(&self) -> Flags {
        match self {
            Message::Request(req) => req.common.flags,
            Message::Response(resp) => resp.common.flags,
        }
    }

    pub fn flags_mut(&mut self) -> &mut Flags {
        match self {
            Message::Request(req) => req.flags(),
            Message::Response(resp) => resp.flags(),
        }
    }

    pub fn pub_key(&self) -> Option<PublicKey> {
        match self {
            Message::Request(req) => req.public_key.clone(),
            Message::Response(resp) => resp.public_key.clone(),
        }
    }

    pub fn set_public_key(&mut self, pub_key: PublicKey) {
        match self {
            Message::Request(req) => req.common.public_key = Some(pub_key),
            Message::Response(resp) => resp.common.public_key = Some(pub_key),
        }
    }
}

impl Into<Base> for Message {
    fn into(self) -> Base {
        match self {
            Message::Request(req) => req.into(),
            Message::Response(resp) => resp.into(),
        }
    }
}

impl Message {
    /// Parses an array containing a page into a page object using the provided key source
    pub fn parse<'a, K, T: AsRef<[u8]>>(data: T, key_source: &K) -> Result<(Message, usize), Error>
    where
        K: KeySource,
    {
        let (b, n) = Base::parse(data, key_source)?;

        let m = Message::convert(b, key_source)?;

        Ok((m, n))
    }

    pub fn encode(&self, keys: &Keys, buff: &mut [u8]) -> Result<usize, Error> {
        // Cast to base
        let mut b: Base = self.clone().into();

        // Encode base
        let n = b.encode(Some(keys), buff)?;

        Ok(n)
    }
}

impl Message {
    pub fn convert<K>(base: Base, key_source: &K) -> Result<Message, Error>
    where
        K: KeySource,
    {
        let header = base.header();
        let app_id = header.application_id();
        let kind = header.kind();

        // Check for DSF messages
        if app_id != 0 {
            error!(
                "Error converting application-specific base object {:?} to message",
                kind
            );
            return Err(Error::InvalidMessageType);
        }

        // Parse request and response types
        if kind.is_request() {
            Ok(Message::Request(Request::convert(base, key_source)?))
        } else if kind.is_response() {
            Ok(Message::Response(Response::convert(base, key_source)?))
        } else {
            debug!("Error converting base object of kind {:?} to message", kind);
            Err(Error::InvalidMessageType)
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Common {
    pub from: Id,
    pub id: RequestId,
    pub flags: Flags,

    pub remote_address: Option<Address>,
    pub public_key: Option<PublicKey>,
}

#[cfg(test)]
mod tests {

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::base::{Body, Header};
    use crate::page::{Page, PageInfo, PageOptions};
    use crate::types::PageKind;

    use crate::{crypto, Keys};

    #[test]
    fn encode_decode_messages_pk() {
        let mut buff = vec![0u8; BUFF_SIZE];

        let (pub_key, pri_key) =
            crypto::new_pk().expect("Error generating new public/private key pair");
        let id = crypto::hash(&pub_key).expect("Error generating new ID");
        let fake_id = crypto::hash(&[0, 1, 2, 3, 4]).expect("Error generating fake target ID");
        let flags = Flags::ADDRESS_REQUEST;
        let request_id = 120;

        let keys = Keys {
            pub_key: pub_key.clone(),
            pri_key: Some(pri_key),
            sec_key: None,
            sym_keys: None,
        };

        // Create and sign page
        let header = Header {
            kind: PageKind::Generic.into(),
            ..Default::default()
        };
        let mut page = Page::new(
            id.clone(),
            header,
            PageInfo::primary(pub_key.clone()),
            Body::None,
            PageOptions::default(),
        );

        let mut b = Base::from(&page);
        let n = b
            .encode(Some(&keys), &mut buff)
            .expect("Error signing page");
        let sig = b.signature().clone().unwrap();

        page.set_signature(sig);
        page.raw = Some(buff[0..n].to_vec());

        let messages: Vec<Message> = vec![
            Message::Request(Request::new(
                id.clone(),
                0,
                RequestKind::Hello,
                flags.clone(),
            )),
            Message::Request(Request::new(
                id.clone(),
                1,
                RequestKind::Ping,
                flags.clone(),
            )),
            Message::Request(Request::new(
                id.clone(),
                request_id,
                RequestKind::FindNode(fake_id.clone()),
                flags.clone(),
            )),
            Message::Request(Request::new(
                id.clone(),
                request_id,
                RequestKind::Store(id.clone(), vec![page.clone()]),
                flags.clone(),
            )),
            Message::Request(Request::new(
                id.clone(),
                request_id,
                RequestKind::Subscribe(fake_id.clone()),
                flags.clone(),
            )),
            Message::Request(Request::new(
                id.clone(),
                request_id,
                RequestKind::Query(fake_id.clone()),
                flags.clone(),
            )),
            Message::Request(Request::new(
                id.clone(),
                request_id,
                RequestKind::PushData(id.clone(), vec![page.clone()]),
                flags.clone(),
            )),
            Message::Response(Response::new(
                id.clone(),
                request_id,
                ResponseKind::Status(Status::Ok),
                flags.clone(),
            )),
            // TODO: put node information here
            Message::Response(Response::new(
                id.clone(),
                request_id,
                ResponseKind::NodesFound(
                    fake_id.clone(),
                    vec![(
                        fake_id.clone(),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).into(),
                        pub_key.clone(),
                    )],
                ),
                flags.clone(),
            )),
            Message::Response(Response::new(
                id.clone(),
                request_id,
                ResponseKind::ValuesFound(fake_id.clone(), vec![page.clone()]),
                flags.clone(),
            )),
            Message::Response(Response::new(
                id.clone(),
                request_id,
                ResponseKind::NoResult,
                flags.clone(),
            )),
            Message::Response(Response::new(
                id.clone(),
                request_id,
                ResponseKind::PullData(fake_id.clone(), vec![page.clone()]),
                flags.clone(),
            )),
        ];

        for message in messages {
            // Cast to base
            let mut b: Base = message.clone().into();
            // Encode base
            let n = b
                .encode(Some(&keys), &mut buff)
                .expect("error encoding message");
            // Parse base and check instances match
            let (mut d, m) = Base::parse(&buff[..n], &keys).expect("error parsing message");

            assert_eq!(n, m);

            d.raw = None;
            b.raw = None;

            assert_eq!(b, d);

            // Cast to message and check instances match
            let message2 =
                Message::convert(d, &keys).expect("error converting base object to message");

            assert_eq!(message, message2);

            assert_eq!(message.request_id(), message2.request_id());
        }
    }

    #[test]
    fn encode_decode_messages_sk() {
        let mut buff = vec![0u8; BUFF_SIZE];

        let (pub_key_a, pri_key_a) = crypto::new_pk().unwrap();
        let id_a = crypto::hash(&pub_key_a).unwrap();
        let (pub_key_b, pri_key_b) = crypto::new_pk().unwrap();

        let keys_a = Keys::new(pub_key_a.clone()).with_pri_key(pri_key_a);
        let keys_b = Keys::new(pub_key_b.clone()).with_pri_key(pri_key_b);

        let req = Message::Request(Request::new(
            id_a.clone(),
            0,
            RequestKind::Hello,
            Flags::SYMMETRIC_MODE,
        ));

        let keys_enc = keys_a.derive_peer(pub_key_b).unwrap();
        let n = req
            .encode(&keys_enc, &mut buff)
            .expect("Error encoding message w/ symmetric keys");

        let keys_dec = keys_b.derive_peer(pub_key_a).unwrap();
        let _req_a = Message::parse(&buff[..n], &keys_dec)
            .expect("Error decoding message w/ symmetric keys");
    }

    extern crate test;
    use test::Bencher;

    #[bench]
    fn bench_encode_messages_pk(b: &mut Bencher) {
        let mut buff = vec![0u8; BUFF_SIZE];

        let (pub_key_a, pri_key_a) = crypto::new_pk().unwrap();
        let id_a = crypto::hash(&pub_key_a).unwrap();
        let (pub_key_b, pri_key_b) = crypto::new_pk().unwrap();

        let keys_a = Keys::new(pub_key_a.clone()).with_pri_key(pri_key_a);
        let _keys_b = Keys::new(pub_key_b.clone()).with_pri_key(pri_key_b);

        let req = Message::Request(Request::new(
            id_a.clone(),
            0,
            RequestKind::Hello,
            Flags::empty(),
        ));

        let keys_enc = keys_a.derive_peer(pub_key_b).unwrap();

        b.iter(|| {
            let _n = req
                .encode(&keys_enc, &mut buff)
                .expect("Error encoding message w/ symmetric keys");
        });
    }

    #[bench]
    fn bench_decode_messages_pk(b: &mut Bencher) {
        let mut buff = vec![0u8; BUFF_SIZE];

        let (pub_key_a, pri_key_a) = crypto::new_pk().unwrap();
        let id_a = crypto::hash(&pub_key_a).unwrap();
        let (pub_key_b, pri_key_b) = crypto::new_pk().unwrap();

        let keys_a = Keys::new(pub_key_a.clone()).with_pri_key(pri_key_a);
        let keys_b = Keys::new(pub_key_b.clone()).with_pri_key(pri_key_b);

        let req = Message::Request(Request::new(
            id_a.clone(),
            0,
            RequestKind::Hello,
            Flags::empty(),
        ));

        let keys_enc = keys_a.derive_peer(pub_key_b).unwrap();
        let keys_dec = keys_b.derive_peer(pub_key_a).unwrap();

        let n = req
            .encode(&keys_enc, &mut buff)
            .expect("Error encoding message w/ symmetric keys");

        b.iter(|| {
            let _req_a = Message::parse(&buff[..n], &keys_dec)
                .expect("Error decoding message w/ symmetric keys");
        });
    }

    #[bench]
    fn bench_encode_messages_sk(b: &mut Bencher) {
        let mut buff = vec![0u8; BUFF_SIZE];

        let (pub_key_a, pri_key_a) = crypto::new_pk().unwrap();
        let id_a = crypto::hash(&pub_key_a).unwrap();
        let (pub_key_b, pri_key_b) = crypto::new_pk().unwrap();

        let keys_a = Keys::new(pub_key_a.clone()).with_pri_key(pri_key_a);
        let _keys_b = Keys::new(pub_key_b.clone()).with_pri_key(pri_key_b);

        let req = Message::Request(Request::new(
            id_a.clone(),
            0,
            RequestKind::Hello,
            Flags::SYMMETRIC_MODE,
        ));

        let keys_enc = keys_a.derive_peer(pub_key_b).unwrap();

        b.iter(|| {
            let _n = req
                .encode(&keys_enc, &mut buff)
                .expect("Error encoding message w/ symmetric keys");
        });
    }

    #[bench]
    fn bench_decode_messages_sk(b: &mut Bencher) {
        let mut buff = vec![0u8; BUFF_SIZE];

        let (pub_key_a, pri_key_a) = crypto::new_pk().unwrap();
        let id_a = crypto::hash(&pub_key_a).unwrap();
        let (pub_key_b, pri_key_b) = crypto::new_pk().unwrap();

        let keys_a = Keys::new(pub_key_a.clone()).with_pri_key(pri_key_a);
        let keys_b = Keys::new(pub_key_b.clone()).with_pri_key(pri_key_b);

        let req = Message::Request(Request::new(
            id_a.clone(),
            0,
            RequestKind::Hello,
            Flags::SYMMETRIC_MODE,
        ));

        let keys_enc = keys_a.derive_peer(pub_key_b).unwrap();
        let keys_dec = keys_b.derive_peer(pub_key_a).unwrap();

        let n = req
            .encode(&keys_enc, &mut buff)
            .expect("Error encoding message w/ symmetric keys");

        b.iter(|| {
            let _req_a = Message::parse(&buff[..n], &keys_dec)
                .expect("Error decoding message w/ symmetric keys");
        });
    }
}
