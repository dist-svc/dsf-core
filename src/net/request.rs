use core::convert::TryFrom;
use core::ops::Deref;

#[cfg(feature = "alloc")]
use alloc::vec::{Vec};

use crate::error::Error;
use crate::options::{Options, Filters};
use crate::types::*;
use crate::keys::KeySource;
use crate::wire::Container;

use super::Common;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Request {
    pub common: Common,
    pub data: RequestBody,
}

impl Deref for Request {
    type Target = Common;

    fn deref(&self) -> &Common {
        &self.common
    }
}

#[derive(Clone, PartialEq, Debug, strum::Display)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RequestBody {
    Hello,
    Ping,
    FindNode(Id),
    FindValue(Id),
    Store(Id, Vec<Container>),

    Locate(Id),
    Subscribe(Id),
    Unsubscribe(Id),
    Query(Id),
    PushData(Id, Vec<Container>),

    Register(Id, Vec<Container>),
    Unregister(Id),
    Discover(Vec<u8>, Vec<Options>),
}

/// Convert request kind containers to protocol message enumerations
impl From<&RequestBody> for RequestKind {
    fn from(r: &RequestBody) -> Self {
        match r {
            RequestBody::Hello => RequestKind::Hello,
            RequestBody::Ping => RequestKind::Ping,
            RequestBody::FindNode(_) => RequestKind::FindNodes,
            RequestBody::FindValue(_) => RequestKind::FindValues,
            RequestBody::Store(_, _) => RequestKind::Store,
            RequestBody::Locate(_) => RequestKind::Locate,
            RequestBody::Subscribe(_) => RequestKind::Subscribe,
            RequestBody::Unsubscribe(_) => RequestKind::Unsubscribe,
            RequestBody::Query(_) => RequestKind::Query,
            RequestBody::PushData(_, _) => RequestKind::PushData,
            RequestBody::Register(_, _) => RequestKind::Register,
            RequestBody::Unregister(_) => RequestKind::Unregister,
            RequestBody::Discover(_, _) => RequestKind::Discover,
        }
    }
}

impl Request {
    pub fn new(from: Id, request_id: u16, data: RequestBody, flags: Flags) -> Request {
        let common = Common {
            from,
            id: request_id,
            flags: flags | Flags::SYMMETRIC_DIR,
            public_key: None,
            remote_address: None,
        };
        Request { common, data }
    }

    pub fn flags(&mut self) -> &mut Flags {
        &mut self.common.flags
    }

    pub fn set_public_key(&mut self, pk: PublicKey) {
        self.common.public_key = Some(pk);
    }

    pub fn with_public_key(mut self, pk: PublicKey) -> Self {
        self.common.public_key = Some(pk);
        self
    }
}

impl PartialEq for Request {
    fn eq(&self, b: &Self) -> bool {
        self.from == b.from && self.flags == b.flags && self.data == b.data
    }
}

impl Request {
    pub fn convert<T: ImmutableData, K: KeySource>(base: Container<T>, key_source: &K) -> Result<Request, Error>
    {
        let header = base.header();

        if base.encrypted() {
            error!("Attempted to convert encrypted container to request");
            return Err(Error::CryptoError);
        }

        let body = base.body_raw();

        let remote_address = None;
        let public_options: Vec<_> = base.public_options_iter().collect();

        let public_key = Filters::pub_key(&public_options.iter());
        //let _private_options = base.private_options().to_vec();

        let kind = match RequestKind::try_from(header.kind()) {
            Ok(k) => k,
            Err(_) => return Err(Error::InvalidRequestKind),
        };

        let data = match kind {
            RequestKind::Hello => RequestBody::Hello,
            RequestKind::Ping => RequestBody::Ping,
            RequestKind::FindNodes => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestBody::FindNode(id)
            }
            RequestKind::FindValues => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestBody::FindValue(id)
            }
            RequestKind::Subscribe => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestBody::Subscribe(id)
            }
            RequestKind::Unsubscribe => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestBody::Unsubscribe(id)
            }
            RequestKind::Query => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestBody::Query(id)
            }
            RequestKind::Locate => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestBody::Locate(id)
            }
            RequestKind::Store => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);

                // Perhaps i should not fetch pages until later..?
                // And also sign them earlier..?
                let pages = Container::decode_pages(&body[ID_LEN..], key_source)?;

                RequestBody::Store(id, pages)
            }
            RequestKind::PushData => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);

                let pages = Container::decode_pages(&body[ID_LEN..], key_source)?;

                RequestBody::PushData(id, pages)
            }
            RequestKind::Register => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);

                let pages = Container::decode_pages(&body[ID_LEN..], key_source)?;

                RequestBody::Register(id, pages)
            }
            RequestKind::Unregister => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);

                RequestBody::Unregister(id)
            }
            RequestKind::Discover => {
                // TODO: pass through discover options
                RequestBody::Discover(body.to_vec(), public_options)
            },
        };

        // TODO: fetch message specific options
        //let remote_address = Base::filter_address_option(&mut public_options);

        let common = Common {
            from: base.id(),
            id: header.index(),
            flags: header.flags(),
            public_key,
            remote_address,
        };
        Ok(Request { common, data })
    }
}
