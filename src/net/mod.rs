//! Net module contains high-level message objects used to communicate between peers
//! to maintain the network, publish and subscribe to services, and exchange data.
//! These can be converted to and from base objects for encoding/decoding.

use crate::base::Base;
use crate::types::*;

pub mod request;
pub use request::{Request, RequestKind};

pub mod response;
pub use response::{Response, ResponseKind, Status};

pub const BUFF_SIZE: usize = 10 * 1024;

/// Message is a network request or response message
#[derive(Clone, PartialEq, Debug)]
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
    /// Parses an array containing a page into a page object
    /// fn v(id, data, sig)
    pub fn parse<'a, V, T: AsRef<[u8]>>(data: T, pub_key_s: V) -> Result<(Message, usize), Error>
    where
        V: Fn(&Id) -> Option<PublicKey>,
    {
        let (b, n) = Base::parse(data, &pub_key_s, |_id| None)?;

        let m = Message::convert(b, &pub_key_s)?;

        Ok((m, n))
    }
}

impl Message {
    pub fn convert<V>(base: Base, key_source: V) -> Result<Message, Error>
    where
        V: Fn(&Id) -> Option<PublicKey>,
    {
        let header = base.header();
        let app_id = header.application_id();
        let kind = header.kind();

        // Check for DSF messages
        if app_id != 0 {
            println!(
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
            println!("Error converting base object of kind {:?} to message", kind);
            Err(Error::InvalidMessageType)
        }
    }
}

#[derive(Clone, Debug)]
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
    use crate::page::{PageBuilder, PageInfo};
    use crate::types::PageKind;

    use crate::crypto;
    #[test]
    fn encode_decode_messages() {
        let mut buff = vec![0u8; BUFF_SIZE];

        let (pub_key, pri_key) =
            crypto::new_pk().expect("Error generating new public/private key pair");
        let id = crypto::hash(&pub_key).expect("Error generating new ID");
        let fake_id = crypto::hash(&[0, 1, 2, 3, 4]).expect("Error generating fake target ID");
        let flags = Flags::ADDRESS_REQUEST;
        let request_id = 120;

        // Create and sign page
        let mut page = PageBuilder::default()
            .id(id.clone())
            .kind(PageKind::Generic.into())
            .info(PageInfo::primary(pub_key.clone()))
            .build()
            .expect("Error building page");

        let mut b = Base::from(&page);
        let n = b
            .encode(Some(&pri_key), None, &mut buff)
            .expect("Error signing page");
        let sig = b.signature().clone().unwrap();

        page.set_signature(sig);
        page.raw = Some(buff[0..n].to_vec());

        let messages: Vec<Message> = vec![
            Message::Request(Request::new(id.clone(), RequestKind::Hello, flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::Ping, flags.clone())),
            Message::Request(Request::new(
                id.clone(),
                RequestKind::FindNode(fake_id.clone()),
                flags.clone(),
            )),
            Message::Request(Request::new(
                id.clone(),
                RequestKind::Store(id.clone(), vec![page.clone()]),
                flags.clone(),
            )),
            Message::Request(Request::new(
                id.clone(),
                RequestKind::Subscribe(fake_id.clone()),
                flags.clone(),
            )),
            Message::Request(Request::new(
                id.clone(),
                RequestKind::Query(fake_id.clone()),
                flags.clone(),
            )),
            Message::Request(Request::new(
                id.clone(),
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
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
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
                .encode(Some(&pri_key), None, &mut buff)
                .expect("error encoding message");
            // Parse base and check instances match
            let (mut d, m) = Base::parse(&buff[..n], |_id| Some(pub_key), |_id| None)
                .expect("error parsing message");

            assert_eq!(n, m);

            d.raw = None;
            b.raw = None;

            assert_eq!(b, d);

            // Cast to message and check instances match
            let message2 = Message::convert(d, |_id| Some(pub_key))
                .expect("error converting base object to message");

            assert_eq!(message, message2);

            assert_eq!(message.request_id(), message2.request_id());
        }
    }
}
