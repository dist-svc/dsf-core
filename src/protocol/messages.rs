

use crate::types::{Id, RequestId, Address, Signature, Kind, Flags};

use crate::protocol::header::{Header, HeaderBuilder};
use crate::protocol::base::{Base, BaseError, BaseBuilder};


#[derive(Clone, PartialEq, Debug)]
pub struct Message {
    pub from: Id,
    pub request_id: u128,
    pub data: MessageKind,
}

#[derive(Clone, PartialEq, Debug)]
pub enum MessageKind {
    Request(Request),
    Response(Response),
}

#[derive(Clone, PartialEq, Debug)]
pub enum Request {
    Ping,
    FindNode(Id),
    FindValue(Id),
    Store(Id, Vec<Base>),
}

#[derive(Clone, PartialEq, Debug)]
pub enum Response {
    NodesFound(Vec<(Id, Address)>),
    ValuesFound(Vec<Base>),
    NoResult,
}

impl Message {
    pub fn request(from: Id, req: Request) -> Message {
        Message {
            from,
            request_id: rand::random(),
            data: MessageKind::Request(req),
        }
    }

    pub fn response(&self, from: Id, resp: Response) -> Message {
        Message {
            from,
            request_id: self.request_id,
            data: MessageKind::Response(resp),
        }
    }

    pub fn ping(from: Id, to: Id) -> Message {
        Message::request(from, Request::Ping)
    }
}

impl Into<Base> for Message {
    fn into(self) -> Base {
        let mut base_builder = BaseBuilder::default();
        let mut header_builder = HeaderBuilder::default();
        let mut flags = Flags(0);

        match &self.data {
            MessageKind::Request(req) => {
                match req {
                    Request::Ping => {
                        header_builder.kind(Kind::Ping);
                        flags.set_address_request(true);
                    },
                    Request::FindNode(_id) => {

                    },
                    Request::FindValue(_id) => {

                    },
                    Request::Store(_id, _values) => {

                    }
                }
            },
            MessageKind::Response(resp) => {
                 match resp {
                    Response::NodesFound(_nodes) => {

                    },
                    Response::ValuesFound(_values) => {

                    },
                    Response::NoResult => {

                    }
                }
            }
        }

        header_builder.flags(flags);
        base_builder.header(header_builder.build().unwrap());
        base_builder.build().unwrap()
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

        let messages = vec![
            Message::ping(id, fake_id),
        ];

        let mut buff = vec![0u8; 1024];

        for m in messages {
            let b: Base = m.clone().into();

        }

    }
}