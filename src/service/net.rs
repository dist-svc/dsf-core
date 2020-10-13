use crate::base::Base;
use crate::error::Error;
use crate::net::{Message, Request, RequestKind, Response};
use crate::service::Service;
use crate::types::*;

pub struct PublishOptions {}

pub trait Net {
    /// Generate a protocol request object from a request message
    fn build_request(&self, request_id: u16, kind: RequestKind, flags: Flags) -> Base;

    /// Generate a protocol response object from a response message (and it's associated request)
    fn build_response(&self, req: &Request, from: Address, resp: &Response) -> Base;

    /// Encode and sign a message
    fn encode_message<T: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        msg: Message,
        buff: T,
    ) -> Result<usize, Error>;
}

impl Net for Service {
    /// Generate a protocol request object from a request message
    fn build_request(&self, request_id: u16, kind: RequestKind, flags: Flags) -> Base {

        let req = Request::new(
            self.id.clone(),
            request_id,
            kind,
            flags,
        );

        req.into()
    }

    /// Generate a protocol response object from a response message (and it's associated request)
    fn build_response(&self, req: &Request, _from: Address, resp: &Response) -> Base {
        let mut resp = resp.clone();

        resp.common.from = self.id.clone();
        resp.common.id = req.id;

        resp.into()
    }

    /// Encode a message
    fn encode_message<T: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        msg: Message,
        buff: T,
    ) -> Result<usize, Error> {
        let mut b: Base = msg.into();

        let n = b.encode(self.private_key.as_ref(), None, buff)?;

        Ok(n)
    }
}
