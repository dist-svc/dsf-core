

use crate::types::{Id, RequestId, Address, Signature, Kind, Flags};

use crate::protocol::header::{Header, HeaderBuilder};
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
    Store(Id, Base),
}

impl Request {
    pub fn new(data: RequestKind, flags: Flags) -> Request {
        Request {
            id: rand::random(),
            data,
            flags,
        }
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
            let b: Base = m.clone().into();

        }

    }
}