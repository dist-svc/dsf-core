
use kad::{Node as KadNode, Request as KadRequest, Response as KadResponse};

use crate::core::{Id, Address, Data};

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
    NodesFound(Vec<KadNode<Id, Address>>),
    ValuesFound(Vec<Data>),
    NoResult,
}

impl From<KadRequest<Id, Data>> for Request {
    fn from(k: KadRequest<Id, Data>) -> Request {
        match k {
            KadRequest::Ping => Request::Ping,
            KadRequest::FindNode(id) => Request::FindNode(id),
            KadRequest::FindValue(id) => Request::FindValue(id),
            KadRequest::Store(id, val) => Request::Store(id, val),
            _ => unimplemented!(),
        }
    }
}

impl Into<KadRequest<Id, Data>> for Request {
    fn into(self) -> KadRequest<Id, Data> {
        match self {
            Request::Ping => KadRequest::Ping,
            Request::FindNode(id) => KadRequest::FindNode(id),
            Request::FindValue(id) => KadRequest::FindValue(id),
            Request::Store(id, val) => KadRequest::Store(id, val),
            _ => unimplemented!(),
        }
    }
}

impl From<KadResponse<Id, Address, Data>> for Response {
    fn from(r: KadResponse<Id, Address, Data>) -> Response {
        match r {
            KadResponse::NodesFound(nodes) => Response::NodesFound(nodes),
            KadResponse::ValuesFound(values) => Response::ValuesFound(values),
            KadResponse::NoResult => Response::NoResult,
            _ => unimplemented!(),
        }
    }
}

impl Into<KadResponse<Id, Address, Data>> for Response {
    fn into(self) -> KadResponse<Id, Address, Data> {
        match self {
            Response::NodesFound(nodes) => KadResponse::NodesFound(nodes),
            Response::ValuesFound(values) => KadResponse::ValuesFound(values),
            Response::NoResult => KadResponse::NoResult,
            _ => unimplemented!(),
        }
    }
}

