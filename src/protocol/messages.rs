
use core::convert::TryFrom;

use crate::types::{Id, ID_LEN, RequestId, Address, Signature, Kind, Flags, Error};

use crate::protocol::header::{Header, HeaderBuilder};
use crate::protocol::options::Options;
use crate::protocol::base::{Base, BaseError, BaseBuilder};


#[derive(Clone, PartialEq, Debug)]
pub enum Message {
    Request(Request),
    Response(Response),
}

impl Message {
    pub fn id(&self) -> RequestId {
        match self {
            Message::Request(req) => req.id,
            Message::Response(resp) => resp.id,
        }
    }
}

impl TryFrom<Base> for Message {
    type Error = Error;

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
}

#[derive(Clone, PartialEq, Debug)]
pub enum RequestKind {
    Ping,
    FindNode(Id),
    FindValue(Id),
    Store(Id, Vec<u64>),
}

impl Request {
    pub fn new(from: Id, data: RequestKind, flags: Flags) -> Request {
        Request {
            from,
            id: rand::random(),
            data,
            flags,
        }
    }
}

impl PartialEq for Request {
    fn eq(&self, b: &Self) -> bool {
        self.from == b.from && self.flags == b.flags && self.data == b.data
    }
}

impl TryFrom<Base> for Request {
    type Error = Error;

    fn try_from(base: Base) -> Result<Request, Error> {
        let header = base.header();
        let body = base.body();

        let data = match header.kind() {
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
                let base = &body[ID_LEN..];
                // TODO: store data
                RequestKind::Store(id, vec![])
            },
            _ => {
                return Err(Error::InvalidPageKind)
            }
        };

        // Fetch request id from options
        let request_id: RequestId = match base.public_options().iter().find_map(|o| match o { Options::RequestId(id) => Some(id), _ => None } ) {
            Some(req_id) => req_id.request_id,
            None => return Err(Error::NoRequestId)
        };

        Ok(Request{from: base.id().clone(), id: request_id, data: data, flags: header.flags() })
    }
}

impl Into<Base> for Request {
    fn into(self) -> Base {

        let kind: Kind;
        let mut flags = Flags(0);
        let mut body = vec![];

        let mut builder = BaseBuilder::default();

        match &self.data {
            RequestKind::Ping => {
                kind = Kind::Ping;
                flags.set_address_request(true);
            },
            RequestKind::FindNode(id) => {
                kind = Kind::FindNodes;
                body = id.to_vec();
            },
            RequestKind::FindValue(id) => {
                kind = Kind::FindValues;
                body = id.to_vec();
            },
            RequestKind::Store(id, _value) => {
                kind = Kind::Store;
                // TODO: store data
                body = id.to_vec();
            }
        }

        // Append request ID option
        builder.append_public_option(Options::request_id(self.id));

        builder.base(self.from, kind, 0, flags).body(body).build().unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub from: Id,
    pub id: RequestId,
    pub flags: Flags,
    pub data: ResponseKind,
}

#[derive(Clone, PartialEq, Debug)]
pub enum ResponseKind {
    NodesFound(Vec<(Id, Address)>),
    ValuesFound(Vec<u64>),
    NoResult,
}


impl Response {
    pub fn new(from: Id, id: RequestId, data: ResponseKind, flags: Flags) -> Response {
        Response {
            from,
            id,
            data,
            flags,
        }
    }
}

impl PartialEq for Response {
    fn eq(&self, b: &Self) -> bool {
        self.from == b.from && self.flags == b.flags && self.data == b.data
    }
}


impl TryFrom<Base> for Response {
    type Error = Error;

    fn try_from(base: Base) -> Result<Response, Error> {
        let header = base.header();
        let body = base.body();

        let data = match header.kind() {
            Kind::NoResult => {
                ResponseKind::NoResult
            },
            Kind::NodesFound => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                ResponseKind::NodesFound(vec![])
            },
            Kind::ValuesFound => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                ResponseKind::ValuesFound(vec![])
            },
            _ => {
                return Err(Error::InvalidPageKind)
            }
        };

        // Fetch request id from options
        let request_id: RequestId = match base.public_options().iter().find_map(|o| match o { Options::RequestId(id) => Some(id), _ => None } ) {
            Some(req_id) => req_id.request_id,
            None => return Err(Error::NoRequestId)
        };

        Ok(Response{from: base.id().clone(), id: request_id, data: data, flags: header.flags() })
    }
}

impl Into<Base> for Response {
    fn into(self) -> Base {

        let kind: Kind;
        let mut flags = Flags(0);
        let mut body = vec![];

        let mut builder = BaseBuilder::default();

        match &self.data {
            ResponseKind::NoResult => {
                kind = Kind::NoResult;
            },
            ResponseKind::NodesFound(id) => {
                kind = Kind::NodesFound;
                // TODO
            },
            ResponseKind::ValuesFound(id) => {
                kind = Kind::ValuesFound;
                // TODO
            },
        }

        // Append request ID option
        builder.append_public_option(Options::request_id(self.id));

        builder.base(self.from, kind, 0, flags).body(body).build().unwrap()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::crypto;
    #[test]
    fn test_encode_decode() {
        let (pub_key, pri_key) = crypto::new_pk().expect("Error generating new public/private key pair");
        let id = crypto::hash(&pub_key).expect("Error generating new ID");
        let fake_id = crypto::hash(&[0, 1, 2, 3, 4]).expect("Error generating fake target ID");

        let messages: Vec<Message> = vec![
            //Message::ping(id, fake_id),
        ];

        let mut buff = vec![0u8; 1024];

        for m in messages {
            //let b: Base = m.clone().into();

        }

    }
}