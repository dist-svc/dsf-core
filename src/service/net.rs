use crate::base::Base;
use crate::error::Error;
use crate::net::{Message, Request, RequestKind, Response, ResponseKind};
use crate::service::Service;
use crate::types::*;

pub struct PublishOptions {}

pub trait Net {
    /// Generate a protocol request object from a request message
    fn build_request(&self, request_id: u16, kind: RequestKind, flags: Flags) -> Base;

    /// Generate a protocol response object from a response message (and it's associated request)
    fn build_response(&self, request_id: u16, resp: ResponseKind, flags: Flags) -> Base;

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
    fn build_response(&self, request_id: u16, kind: ResponseKind, flags: Flags) -> Base {

        let resp = Response::new(
            self.id.clone(),
            request_id,
            kind,
            flags,
        );

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
