//! Net module contains high-level message objects used to communicate between peers.
//! 
//! These messages are used to maintain the network, publish and subscribe to services, and exchange data,
//! and can be converted to and from base objects for encoding/decoding.

use crate::wire::Container;
use crate::error::Error;
use crate::types::*;

pub mod request;
pub use request::{Request, RequestBody};

pub mod response;
pub use response::{Response, ResponseBody, Status};

pub const BUFF_SIZE: usize = 10 * 1024;

use crate::keys::{KeySource};


/// Message is a network request or response message
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Message {
    Request(Request),
    Response(Response),
}

impl From<Request> for Message {
    fn from(req: Request) -> Self {
        Self::Request(req)
    }
}

impl From<Response> for Message {
    fn from(resp: Response) -> Self {
        Self::Response(resp)
    }
}

impl Message {
    pub fn request(req: Request) -> Self {
        Self::Request(req)
    }

    pub fn response(resp: Response) -> Self {
        Self::Response(resp)
    }

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

    pub fn flags(&self) -> Flags {
        match self {
            Message::Request(req) => req.common.flags,
            Message::Response(resp) => resp.common.flags,
        }
    }

    pub fn flags_mut(&mut self) -> &mut Flags {
        match self {
            Message::Request(req) => req.flags(),
            Message::Response(resp) => resp.flags(),
        }
    }

    pub fn pub_key(&self) -> Option<PublicKey> {
        match self {
            Message::Request(req) => req.public_key.clone(),
            Message::Response(resp) => resp.public_key.clone(),
        }
    }

    pub fn set_public_key(&mut self, pub_key: PublicKey) {
        match self {
            Message::Request(req) => req.common.public_key = Some(pub_key),
            Message::Response(resp) => resp.common.public_key = Some(pub_key),
        }
    }
}

impl Message {
    /// Parses an array containing a page into a page object using the provided key source
    pub fn parse<'a, K, T: ImmutableData>(data: T, key_source: &K) -> Result<(Message, usize), Error>
    where
        K: KeySource,
    {
        let c = Container::parse(data, key_source)?;
        let n = c.len();

        let m = Message::convert(c, key_source)?;

        Ok((m, n))
    }
}

impl Message {
    pub fn convert<T: ImmutableData, K: KeySource>(base: Container<T>, key_source: &K) -> Result<Message, Error> {
        let header = base.header();
        let app_id = header.application_id();
        let kind = header.kind();

        // Check for DSF messages
        if app_id != 0 {
            error!(
                "Error converting application-specific base object {:?} to message",
                kind
            );
            return Err(Error::InvalidMessageType);
        }

        // Parse request and response types
        if kind.is_request() {
            Ok(Message::Request(Request::convert(base, key_source)?))
        } else if kind.is_response() {
            Ok(Message::Response(Response::convert(base, key_source)?))
        } else {
            debug!("Error converting base object of kind {:?} to message", kind);
            Err(Error::InvalidMessageType)
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Common {
    pub from: Id,
    pub id: RequestId,
    pub flags: Flags,

    pub remote_address: Option<Address>,
    pub public_key: Option<PublicKey>,
}
