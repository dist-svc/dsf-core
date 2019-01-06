

use crate::types::{Id, RequestId};

type Address = std::net::SocketAddr;
type Data = ();

#[derive(Clone, PartialEq, Debug)]
pub struct Message {
    pub request_id: u128,
    pub data: Kind,
}

impl Message {
    pub fn request(req: Request) -> Message {
        Message {
            request_id: rand::random(),
            data: Kind::Request(req),
        }
    }

    pub fn response(id: u128, resp: Response) -> Message {
        Message {
            request_id: rand::random(),
            data: Kind::Response(resp),
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum Kind {
    Request(Request),
    Response(Response),
}

#[derive(Clone, PartialEq, Debug)]
pub enum Request {
    Ping,
    FindNode(Id),
    FindValue(Id),
    Store(Id, Vec<Data>),
}

#[derive(Clone, PartialEq, Debug)]
pub enum Response {
    NodesFound(Vec<(Id, Address)>),
    ValuesFound(Vec<Data>),
    NoResult,
}

