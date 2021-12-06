use core::convert::TryFrom;
use core::ops::Deref;

#[cfg(feature = "alloc")]
use alloc::vec::{Vec};

use byteorder::{ByteOrder, NetworkEndian};
use slice_ext::SplitBefore;

use crate::base::{Base, BaseOptions, Body, Header};
use crate::error::Error;
use crate::options::Options;
use crate::page::Page;
use crate::types::*;
use crate::keys::KeySource;

use super::Common;
use super::BUFF_SIZE;

/// Generic Response message
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Response {
    pub common: Common,
    pub data: ResponseKind,
}

/// Response message kinds
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "strum", derive(strum_macros::Display))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ResponseKind {
    Status(Status),
    NodesFound(Id, Vec<(Id, Address, PublicKey)>),
    ValuesFound(Id, Vec<Page>),
    NoResult,
    PullData(Id, Vec<Page>),
}

/// Convert response kind object to protocol message enumeration
impl From<&ResponseKind> for MessageKind {
    fn from(r: &ResponseKind) -> Self {
        match r {
            ResponseKind::Status(_) => MessageKind::Status,
            ResponseKind::NodesFound(_, _) => MessageKind::NodesFound,
            ResponseKind::ValuesFound(_, _) => MessageKind::ValuesFound,
            ResponseKind::NoResult => MessageKind::NoResult,
            ResponseKind::PullData(_, _) => MessageKind::PullData,
        }
    }
}

mod status {
    pub const OK: u32 = 0x00;
    pub const INVALID_REQUEST: u32 = 0x01;
    pub const FAILED: u32 = 0x02;
}

/// Status response codes
#[derive(Copy, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Status {
    Ok,
    InvalidRequest,
    Failed,
    Unknown(u32),
}

impl From<u32> for Status {
    fn from(v: u32) -> Self {
        match v {
            status::OK => Status::Ok,
            status::INVALID_REQUEST => Status::InvalidRequest,
            status::FAILED => Status::Failed,
            _ => Status::Unknown(v),
        }
    }
}

impl From<&Status> for u32 {
    fn from(s: &Status) -> u32 {
        match s {
            Status::Ok => status::OK,
            Status::InvalidRequest => status::INVALID_REQUEST,
            Status::Failed => status::FAILED,
            Status::Unknown(v) => *v,
        }
    }
}

impl Deref for Response {
    type Target = Common;

    fn deref(&self) -> &Common {
        &self.common
    }
}

impl Response {
    pub fn new(from: Id, id: RequestId, data: ResponseKind, mut flags: Flags) -> Response {
        flags.remove(Flags::SYMMETRIC_DIR);
        let common = Common {
            from,
            id,
            flags,
            public_key: None,
            remote_address: None,
        };
        Response { common, data }
    }

    pub fn flags(&mut self) -> &mut Flags {
        &mut self.common.flags
    }

    pub fn with_remote_address(mut self, addr: Address) -> Self {
        self.common.remote_address = Some(addr);
        self
    }

    pub fn set_public_key(&mut self, pk: PublicKey) {
        self.common.public_key = Some(pk);
    }

    pub fn with_public_key(mut self, pk: PublicKey) -> Self {
        self.common.public_key = Some(pk);
        self
    }
}

impl PartialEq for Response {
    fn eq(&self, b: &Self) -> bool {
        self.from == b.from && self.flags == b.flags && self.data == b.data
    }
}

impl Response {
    pub fn convert<K>(base: Base, key_source: &K) -> Result<Response, Error>
    where
        K: KeySource,
    {
        let header = base.header();

        let empty_body = vec![];
        let body = match base.body() {
            Body::Cleartext(d) => d,
            Body::None => &empty_body,
            Body::Encrypted(_e) => {
                panic!("Attempting to convert encrypted object to response message")
            }
        };

        let remote_address = None;

        let _public_options = base.public_options().to_vec();
        //let _private_options = base.private_options().to_vec();

        let kind = match MessageKind::try_from(header.kind()) {
            Ok(k) => k,
            Err(_) => return Err(Error::InvalidMessageKind),
        };

        let data = match kind {
            MessageKind::Status => {
                let status = NetworkEndian::read_u32(&body);
                ResponseKind::Status(status.into())
            }
            MessageKind::NoResult => ResponseKind::NoResult,
            MessageKind::NodesFound => {
                let mut id = Id::default();
                id.copy_from_slice(&body[..ID_LEN]);

                // Build options array from body
                let (options, _n) = Options::parse_vec(&body[ID_LEN..]).unwrap();

                let nodes: Vec<_> = (&options[..])
                    .split_before(|o| match o {
                        Options::PeerId(_) => true,
                        _ => false,
                    })
                    .filter_map(|opts| {
                        let id = Base::peer_id_option(&opts);
                        let addr = Base::address_option(&opts);
                        let key = Base::pub_key_option(&opts);

                        match (id, addr, key) {
                            (Some(id), Some(addr), Some(key)) => Some((id, addr, key)),
                            // TODO: warn here
                            _ => None,
                        }
                    })
                    .collect();

                ResponseKind::NodesFound(id, nodes)
            }
            MessageKind::ValuesFound => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);

                let pages = Page::decode_pages(&body[ID_LEN..], key_source)?;

                ResponseKind::ValuesFound(id, pages)
            }
            MessageKind::PullData => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);

                let pages = Page::decode_pages(&body[ID_LEN..], key_source)?;

                ResponseKind::PullData(id, pages)
            }
            _ => {
                error!(
                    "Error converting base object of kind {:?} to response message",
                    header.kind()
                );
                return Err(Error::InvalidMessageKind);
            }
        };

        // Fetch other key options
        let public_key = base.public_key.clone();

        //let remote_address = Base::filter_address_option(&mut public_options);

        let common = Common {
            from: base.id().clone(),
            id: header.index(),
            flags: header.flags(),
            public_key,
            remote_address,
        };
        Ok(Response { common, data })
    }
}
