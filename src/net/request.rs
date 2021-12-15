use core::convert::TryFrom;
use core::ops::Deref;

#[cfg(feature = "alloc")]
use alloc::vec::{Vec};

use crate::base::{Base, Body};
use crate::error::Error;
use crate::options::Options;
use crate::page::Page;
use crate::types::*;
use crate::keys::KeySource;

use super::Common;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Request {
    pub common: Common,
    pub data: RequestKind,
}

impl Deref for Request {
    type Target = Common;

    fn deref(&self) -> &Common {
        &self.common
    }
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "strum", derive(strum_macros::Display))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RequestKind {
    Hello,
    Ping,
    FindNode(Id),
    FindValue(Id),
    Store(Id, Vec<Page>),

    Locate(Id),
    Subscribe(Id),
    Unsubscribe(Id),
    Query(Id),
    PushData(Id, Vec<Page>),

    Register(Id, Vec<Page>),
    Unregister(Id),
    Discover(Vec<u8>, Vec<Options>),
}

/// Convert request kind containers to protocol message enumerations
impl From<&RequestKind> for MessageKind {
    fn from(r: &RequestKind) -> Self {
        match r {
            RequestKind::Hello => MessageKind::Hello,
            RequestKind::Ping => MessageKind::Ping,
            RequestKind::FindNode(_) => MessageKind::FindNodes,
            RequestKind::FindValue(_) => MessageKind::FindValues,
            RequestKind::Store(_, _) => MessageKind::Store,
            RequestKind::Locate(_) => MessageKind::Locate,
            RequestKind::Subscribe(_) => MessageKind::Subscribe,
            RequestKind::Unsubscribe(_) => MessageKind::Unsubscribe,
            RequestKind::Query(_) => MessageKind::Query,
            RequestKind::PushData(_, _) => MessageKind::PushData,
            RequestKind::Register(_, _) => MessageKind::Register,
            RequestKind::Unregister(_) => MessageKind::Unregister,
            RequestKind::Discover(_, _) => MessageKind::Discover,
        }
    }
}

impl Request {
    pub fn new(from: Id, request_id: u16, data: RequestKind, flags: Flags) -> Request {
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
    pub fn convert<K>(base: Base, key_source: &K) -> Result<Request, Error>
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
        let public_options = base.public_options().to_vec();
        //let _private_options = base.private_options().to_vec();

        let kind = match MessageKind::try_from(header.kind()) {
            Ok(k) => k,
            Err(_) => return Err(Error::InvalidMessageKind),
        };

        let data = match kind {
            MessageKind::Hello => RequestKind::Hello,
            MessageKind::Ping => RequestKind::Ping,
            MessageKind::FindNodes => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::FindNode(id)
            }
            MessageKind::FindValues => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::FindValue(id)
            }
            MessageKind::Subscribe => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::Subscribe(id)
            }
            MessageKind::Unsubscribe => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::Unsubscribe(id)
            }
            MessageKind::Query => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::Query(id)
            }
            MessageKind::Locate => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::Locate(id)
            }
            MessageKind::Store => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);

                // Perhaps i should not fetch pages until later..?
                // And also sign them earlier..?
                let pages = Page::decode_pages(&body[ID_LEN..], key_source)?;

                RequestKind::Store(id, pages)
            }
            MessageKind::PushData => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);

                let pages = Page::decode_pages(&body[ID_LEN..], key_source)?;

                RequestKind::PushData(id, pages)
            }
            MessageKind::Register => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);

                let pages = Page::decode_pages(&body[ID_LEN..], key_source)?;

                RequestKind::Register(id, pages)
            }
            MessageKind::Unregister => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);

                RequestKind::Unregister(id)
            }
            MessageKind::Discover => {
                // TODO: pass through discover options
                RequestKind::Discover(body.to_vec(), public_options)
            },
            _ => {
                error!(
                    "No handler for converting base object of kind {:?} to request message",
                    header.kind()
                );
                return Err(Error::Unimplemented);
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
        Ok(Request { common, data })
    }
}
