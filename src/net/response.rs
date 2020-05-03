use core::convert::TryFrom;
use core::ops::Deref;

use byteorder::{ByteOrder, NetworkEndian};
use slice_ext::SplitBefore;

use crate::base::{Base, BaseBuilder, Body};
use crate::options::Options;
use crate::page::Page;
use crate::types::*;

use super::Common;
use super::BUFF_SIZE;

/// Generic Response message
#[derive(Clone, Debug)]
pub struct Response {
    pub common: Common,
    pub data: ResponseKind,
}

/// Response message kinds
#[derive(Clone, PartialEq, Debug)]
pub enum ResponseKind {
    Status(Status),
    NodesFound(Id, Vec<(Id, Address, PublicKey)>),
    ValuesFound(Id, Vec<Page>),
    NoResult,
    PullData(Id, Vec<Page>),
}

mod status {
    pub const OK: u32 = 0x0000_0000;
    pub const INVALID_REQUEST: u32 = 0x0000_0001;
}

/// Status response codes
#[derive(Clone, PartialEq, Debug)]
pub enum Status {
    Ok,
    InvalidRequest,
    Unknown(u32),
}

impl From<u32> for Status {
    fn from(v: u32) -> Self {
        match v {
            status::OK => Status::Ok,
            status::INVALID_REQUEST => Status::InvalidRequest,
            _ => Status::Unknown(v),
        }
    }
}

impl Into<u32> for Status {
    fn into(self) -> u32 {
        match self {
            Status::Ok => status::OK,
            Status::InvalidRequest => status::INVALID_REQUEST,
            Status::Unknown(v) => v,
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
    pub fn new(from: Id, id: RequestId, data: ResponseKind, flags: Flags) -> Response {
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

#[cfg(nope)]
impl fmt::Debug for ResponseKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ResponseKind::Status => write!(f, "status"),
            ResponseKind::NodesFound(id, nodes) => {
                write!(f, "NodesFound({:?}): [", id)?;
                for n in nodes {
                    write!(f, "\n    - {:?}", n)?;
                }
                writeln!(f, "]")
            }
            ResponseKind::ValuesFound(id, values) => {
                write!(f, "ValuesFound({:?}): [", id)?;
                for v in values {
                    write!(f, "\n    - {:?}", v)?;
                }
                writeln!(f, "]")
            }
            ResponseKind::NoResult => write!(f, "NoResult"),
            ResponseKind::PullData(id, values) => {
                write!(f, "PullData({:?}): [", id)?;
                for v in values {
                    write!(f, "\n    - {:?}", v)?;
                }
                writeln!(f, "]")
            }
        }
    }
}

impl PartialEq for Response {
    fn eq(&self, b: &Self) -> bool {
        self.from == b.from && self.flags == b.flags && self.data == b.data
    }
}

impl Response {
    pub fn convert<V>(base: Base, key_source: V) -> Result<Response, Error>
    where
        V: Fn(&Id) -> Option<PublicKey>,
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

                let pages = Page::decode_pages(&body[ID_LEN..], key_source).unwrap();

                ResponseKind::ValuesFound(id, pages)
            }
            MessageKind::PullData => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);

                let pages = Page::decode_pages(&body[ID_LEN..], key_source).unwrap();

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
        let public_key = base.public_key;

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

impl Into<Base> for Response {
    fn into(self) -> Base {
        let kind: MessageKind;
        let body: Vec<u8>;

        let mut buff = vec![0; BUFF_SIZE];

        let mut builder = BaseBuilder::default();

        match &self.data {
            ResponseKind::Status(code) => {
                kind = MessageKind::Status;
                NetworkEndian::write_u32(&mut buff, code.clone().into());
                body = (&buff[0..4]).to_vec();
            }
            ResponseKind::NoResult => {
                kind = MessageKind::NoResult;
                //TODO?: (&mut body[..ID_LEN]).copy_from_slice(&id);
                body = vec![];
            }
            ResponseKind::NodesFound(id, nodes) => {
                kind = MessageKind::NodesFound;
                (&mut buff[..ID_LEN]).copy_from_slice(&id);

                // Build options list from nodes
                let mut options = Vec::with_capacity(nodes.len() * 3);
                for n in nodes {
                    options.push(Options::peer_id(n.0));
                    options.push(Options::address(n.1));
                    options.push(Options::pub_key(n.2));
                }

                // Encode options list to body
                let n = Options::encode_vec(&options, &mut buff[ID_LEN..]).unwrap();

                body = buff[..ID_LEN + n].to_vec();
            }
            ResponseKind::ValuesFound(id, pages) => {
                kind = MessageKind::ValuesFound;
                (&mut buff[..ID_LEN]).copy_from_slice(&id);

                let n = Page::encode_pages(&pages, &mut buff[ID_LEN..]).unwrap();

                body = buff[..ID_LEN + n].to_vec();
            }
            ResponseKind::PullData(id, pages) => {
                kind = MessageKind::PullData;
                (&mut buff[..ID_LEN]).copy_from_slice(&id);

                let n = Page::encode_pages(&pages, &mut buff[ID_LEN..]).unwrap();

                body = buff[..ID_LEN + n].to_vec();
            }
        }

        let builder = builder
            .base(
                self.common.from,
                0,
                kind.into(),
                self.common.id,
                self.common.flags,
            )
            .body(Body::from(body));

        builder.public_key(self.common.public_key);

        if let Some(a) = self.remote_address {
            builder.append_public_option(Options::address(a));
        }

        builder.build().unwrap()
    }
}
