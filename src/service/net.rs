

use crate::types::*;
use crate::service::Service;
use crate::protocol::base::{Base};
use crate::protocol::net::{Request, Response};

pub struct PublishOptions {

}

pub trait Net {
    /// Generate a protocol request object from a request message
    fn build_request(&self, req: &Request) -> Base;

    /// Generate a protocol response object from a response message (and it's associated request)
    fn build_response(&self, req: &Request, from: Address, resp: &Response) -> Base;
}

impl Net for Service {
    /// Generate a protocol request object from a request message
    fn build_request(&self, req: &Request) -> Base {
        let mut req = req.clone();

        req.from = self.id;
        
        req.into()
    }

    /// Generate a protocol response object from a response message (and it's associated request)
    fn build_response(&self, req: &Request, _from: Address, resp: &Response) -> Base {
        let mut resp = resp.clone();

        resp.from = self.id;
        resp.id = req.id;
        
        resp.into()
    }
}
