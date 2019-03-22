
//use core::convert::TryFrom;
use try_from::TryFrom;

use crate::types::{Id, ID_LEN, RequestId, Address, Kind, Flags, PublicKey, Error};

use crate::protocol::options::Options;
use crate::protocol::base::{Base, BaseBuilder};
use crate::protocol::page::Page;

use crate::protocol::{Parse, Encode};

#[derive(Clone, PartialEq, Debug)]
pub enum Message {
    Request(Request),
    Response(Response),
}

impl Message {
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

    pub fn pub_key(&self) -> Option<PublicKey> {
        match self {
            Message::Request(req) => req.public_key.clone(),
            Message::Response(resp) => resp.public_key.clone(),
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

impl TryFrom<Base> for Message {
    type Err = Error;

    fn try_from(base: Base) -> Result<Message, Error> {
        let kind = base.header().kind();

        // Check for DSD messages
        if !kind.is_dsd() {
            return Err(Error::InvalidMessageType)
        }

        // Parse request and response types
        if kind.is_request() {
            Ok(Message::Request(Request::try_from(base)?))
        } else if kind.is_response() {
            Ok(Message::Response(Response::try_from(base)?))
        } else {
            Err(Error::InvalidMessageType)
        }
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub from: Id,
    pub id: RequestId,
    pub flags: Flags,
    pub data: RequestKind,

    pub public_key: Option<PublicKey>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum RequestKind {
    Hello,
    Ping,
    FindNode(Id),
    FindValue(Id),
    Store(Id, Vec<Page>),
}

impl Request {
    pub fn new(from: Id, data: RequestKind, flags: Flags) -> Request {
        Request {
            from,
            id: rand::random(),
            data,
            flags,

            public_key: None,
        }
    }

    pub fn with_public_key(mut self, pk: PublicKey) -> Self {
        self.public_key = Some(pk);
        self
    }
}

impl PartialEq for Request {
    fn eq(&self, b: &Self) -> bool {
        self.from == b.from && self.flags == b.flags && self.data == b.data
    }
}

impl TryFrom<Base> for Request {
    type Err = Error;

    fn try_from(base: Base) -> Result<Request, Error> {
        let header = base.header();
        let body = base.body();

        let data = match header.kind() {
            Kind::Hello => {
                RequestKind::Hello
            },
            Kind::Ping => {
                RequestKind::Ping
            },
            Kind::FindNodes => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::FindNode(id)
            },
            Kind::FindValues => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::FindValue(id)
            },
            Kind::Store => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                let _base = &body[ID_LEN..];
                // TODO: parse pages and store
                RequestKind::Store(id, vec![])
            },
            _ => {
                return Err(Error::InvalidMessageKind)
            }
        };

        // Fetch request id from options
        let request_id = match base.req_id_option() {
            Some(req_id) => req_id,
            None => return Err(Error::NoRequestId)
        };

        // Fetch other key options
        let public_key = base.pub_key_option();

        Ok(Request{from: base.id().clone(), id: request_id, data: data, flags: header.flags(), public_key })
    }
}

// TODO: this is duplicated in the service module
// where should it be?
impl Into<Base> for Request {
    fn into(self) -> Base {

        let kind: Kind;
        let body;

        let mut builder = BaseBuilder::default();

        match &self.data {
            RequestKind::Hello => {
                kind = Kind::Hello;
                body = vec![];
            },
            RequestKind::Ping => {
                kind = Kind::Ping;
                body = vec![];
            },
            RequestKind::FindNode(id) => {
                kind = Kind::FindNodes;
                body = id.to_vec();
            },
            RequestKind::FindValue(id) => {
                kind = Kind::FindValues;
                body = id.to_vec();
            },
            RequestKind::Store(id, pages) => {
                kind = Kind::Store;

                let mut buff = vec![0u8; 4096];
                let n = 0;
                (&mut buff[n..ID_LEN]).copy_from_slice(id);

                // TODO: store data
                
                for p in pages {
                    let mut b: Base = p.clone().into();
                    let n = b.encode(|_id, _data| Err(()) , &mut buff).unwrap();
                }


                body = buff[..n].to_vec();
            }
        }

        // Append request ID option
        builder.append_public_option(Options::request_id(self.id));

        builder.base(self.from, kind, 0, self.flags).body(body).build().unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub from: Id,
    pub id: RequestId,
    pub flags: Flags,
    pub data: ResponseKind,

    pub remote_address: Option<Address>,
    pub public_key: Option<PublicKey>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum ResponseKind {
    Status,
    NodesFound(Id, Vec<(Id, Address)>),
    ValuesFound(Id, Vec<u64>),
    NoResult,
}


impl Response {
    pub fn new(from: Id, id: RequestId, data: ResponseKind, flags: Flags) -> Response {
        Response {
            from,
            id,
            data,
            flags,

            remote_address: None,
            public_key: None,
        }
    }


    pub fn with_remote_address(mut self, addr: Address) -> Self {
        self.remote_address = Some(addr);
        self
    }

    pub fn with_public_key(mut self, pk: PublicKey) -> Self {
        self.public_key = Some(pk);
        self
    }
}

impl PartialEq for Response {
    fn eq(&self, b: &Self) -> bool {
        self.from == b.from && self.flags == b.flags && self.data == b.data
    }
}


impl TryFrom<Base> for Response {
    type Err = Error;

    fn try_from(base: Base) -> Result<Response, Error> {
        let header = base.header();
        let body = base.body();

        let data = match header.kind() {
            Kind::Status => {
                ResponseKind::Status
            },
            Kind::NoResult => {
                ResponseKind::NoResult
            },
            Kind::NodesFound => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                ResponseKind::NodesFound(id, vec![])
            },
            Kind::ValuesFound => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                ResponseKind::ValuesFound(id, vec![])
            },
            _ => {
                return Err(Error::InvalidMessageKind)
            }
        };

        // Fetch request id from options
        let request_id = match base.req_id_option() {
            Some(req_id) => req_id,
            None => return Err(Error::NoRequestId)
        };

        // Fetch other key options
        let public_key = base.pub_key_option();

        let remote_address = base.address_option();

        Ok(Response{from: base.id().clone(), id: request_id, data: data, flags: header.flags(), public_key, remote_address })
    }
}

impl Into<Base> for Response {
    fn into(self) -> Base {

        let kind: Kind;
        let body: Vec<u8>;

        let mut builder = BaseBuilder::default();

        match &self.data {
            ResponseKind::Status => {
                kind = Kind::Status;
                body = vec![];
            },
            ResponseKind::NoResult => {
                kind = Kind::NoResult;
                body = vec![];
            },
            ResponseKind::NodesFound(id, _nodes) => {
                kind = Kind::NodesFound;
                body = id.to_vec();
                // TODO
            },
            ResponseKind::ValuesFound(id, _values) => {
                kind = Kind::ValuesFound;
                body = id.to_vec();
                // TODO

            },
        }

        // Append request ID option
        builder.append_public_option(Options::request_id(self.id));

        builder.base(self.from, kind, 0, self.flags).body(body).build().unwrap()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::protocol::header::{HeaderBuilder};
    use crate::protocol::page::{Page, PageBuilder, PageInfo};

    use crate::crypto;
    #[test]
    fn encode_decode_messages() {
        let (pub_key, pri_key) = crypto::new_pk().expect("Error generating new public/private key pair");
        let id = crypto::hash(&pub_key).expect("Error generating new ID");
        let fake_id = crypto::hash(&[0, 1, 2, 3, 4]).expect("Error generating fake target ID");
        let flags = Flags::default().set_address_request(true);

        let mut page = PageBuilder::default().id(id.clone()).kind(Kind::Generic).info(PageInfo::primary(pub_key.clone())).build().expect("Error building page");


        let messages: Vec<Message> = vec![
            Message::Request(Request::new(id.clone(), RequestKind::Hello, flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::Ping, flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::FindNode(fake_id.clone()), flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::Store(id.clone(), vec![page.clone()]), flags.clone())),
        ];

        let mut buff = vec![0u8; 4096];

        for message in messages {
            // Cast to base
            let mut b: Base = message.clone().into();
            // Encode base
            let n = b.encode(|_id, data| crypto::pk_sign(&pri_key, data), &mut buff).unwrap();
            // Parse base and check instances match
            let (d, m)= Base::parse(&buff[..n]).unwrap();

            assert_eq!(n, m);
            assert_eq!(b, d);

            // Cast to message and check instances match
            let message2 = Message::try_from(d).unwrap();

            assert_eq!(message, message2);
        }

    }
}