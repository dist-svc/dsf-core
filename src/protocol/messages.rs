

use crate::types::{Id, ID_LEN, RequestId, Address, Signature, Kind, Flags, Error};

use crate::protocol::header::{Header, HeaderBuilder};
use crate::protocol::options::Options;
use crate::protocol::base::{Base, BaseError, BaseBuilder};


#[derive(Clone, PartialEq, Debug)]
pub enum Message {
    Request(Request),
    Response(Response),
}

#[derive(Clone, PartialEq, Debug)]
pub struct Request {
    pub id: RequestId,
    pub flags: Flags,
    pub data: RequestKind,
}

#[derive(Clone, PartialEq, Debug)]
pub enum RequestKind {
    Ping,
    FindNode(Id),
    FindValue(Id),
    Store(Id, ()),
}

impl Request {
    pub fn new(data: RequestKind, flags: Flags) -> Request {
        Request {
            id: rand::random(),
            data,
            flags,
        }
    }

    pub fn to_base(&self, id: Id, req: &Request) -> Base {
        let kind: Kind;
        let mut flags = Flags(0);
        let mut body = vec![];

        let mut builder = BaseBuilder::default();

        match &req.data {
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
                body = id.to_vec();
            }
        }

        // Append request ID option
        builder.append_public_option(Options::request_id(req.id));

        builder.base(id, kind, 0, flags).body(body).build().unwrap()
    }

    pub fn from_base(base: &Base) -> Result<Request, Error> {
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
                RequestKind::Store(id, ())
            },
            _ => {
                return Err(Error::InvalidPageKind)
            }
        };

        // Fetch public key from options
        let request_id: RequestId = match base.public_options().iter().find_map(|o| match o { Options::RequestId(id) => Some(id), _ => None } ) {
            Some(req_id) => req_id.request_id,
            None => return Err(Error::NoRequestId)
        };

        Ok(Request{id: request_id, data: data, flags: header.flags() })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Response {
    pub id: RequestId,
    pub flags: Flags,
    pub data: ResponseKind,
}

#[derive(Clone, PartialEq, Debug)]
pub enum ResponseKind {
    NodesFound(Vec<(Id, Address)>),
    ValuesFound(Vec<Base>),
    NoResult,
}


impl Response {
    pub fn new(id: RequestId, data: ResponseKind, flags: Flags) -> Response {
        Response {
            id,
            data,
            flags,
        }
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