//! Messages are a high level representation of messages used to communicate between peers
//! to maintain the network, publish and subscribe to services, and exchange data.

//use core::convert::TryFrom;
use try_from::TryFrom;
use slice_ext::SplitBefore;

use crate::types::{Id, ID_LEN, RequestId, Address, Kind, Flags, PublicKey, Error};

use crate::protocol::options::Options;
use crate::protocol::base::{Base, BaseBuilder};
use crate::protocol::page::Page;

pub const BUFF_SIZE: usize = 10 * 1024;

#[derive(Clone, PartialEq, Debug)]
pub enum Message {
    Request(Request),
    Response(Response),
}

impl Message {
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
            Message::Request(req) => req.public_key = Some(pub_key),
            Message::Response(resp) => resp.public_key = Some(pub_key),
        }
    }
}

impl Into<Base> for Message {
    fn into(self) -> Base {
        match self {
            Message::Request(req) => req.into(),
            Message::Response(resp) => resp.into(),
        }
    }
}

impl TryFrom<Base> for Message {
    type Err = Error;

    fn try_from(base: Base) -> Result<Message, Error> {
        let kind = base.header().kind();

        // Check for DSF messages
        if !kind.is_dsf() {
            println!("Error converting application-specific base object {:?} to message", kind);
            return Err(Error::InvalidMessageType)
        }

        // Parse request and response types
        if kind.is_request() {
            Ok(Message::Request(Request::try_from(base)?))
        } else if kind.is_response() {
            Ok(Message::Response(Response::try_from(base)?))
        } else {
            println!("Error converting base object of kind {:?} to message", kind);
            Err(Error::InvalidMessageType)
        }
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub from: Id,
    pub id: RequestId,
    pub flags: Flags,
    pub data: RequestKind,

    pub public_key: Option<PublicKey>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum RequestKind {
    Hello,
    Ping,
    FindNode(Id),
    FindValue(Id),
    Store(Id, Vec<Page>),
}

impl Request {
    pub fn new(from: Id, data: RequestKind, flags: Flags) -> Request {
        Request {
            from,
            id: rand::random(),
            data,
            flags,

            public_key: None,
        }
    }

    pub fn flags(&mut self) -> &mut Flags {
        &mut self.flags
    }


    pub fn set_public_key(&mut self, pk: PublicKey) {
        self.public_key = Some(pk);
    }

    pub fn with_public_key(mut self, pk: PublicKey) -> Self {
        self.public_key = Some(pk);
        self
    }

    pub fn with_request_id(mut self, req_id: RequestId) -> Self {
        self.id = req_id;
        self
    }
}

impl PartialEq for Request {
    fn eq(&self, b: &Self) -> bool {
        self.from == b.from && self.flags == b.flags && self.data == b.data
    }
}

impl TryFrom<Base> for Request {
    type Err = Error;

    fn try_from(base: Base) -> Result<Request, Error> {
        let header = base.header();
        let body = base.body();

        let data = match header.kind() {
            Kind::Hello => {
                RequestKind::Hello
            },
            Kind::Ping => {
                RequestKind::Ping
            },
            Kind::FindNodes => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::FindNode(id)
            },
            Kind::FindValues => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::FindValue(id)
            },
            Kind::Store => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                
                let pages = Page::decode_pages(&body[ID_LEN..]).unwrap();

                RequestKind::Store(id, pages)
            },
            _ => {
                println!("Error converting base object of kind {:?} to request message", header.kind());
                return Err(Error::InvalidMessageKind)
            }
        };

        // Fetch other key options
        let public_key = Base::pub_key_option(base.public_options());

        Ok(Request{from: base.id().clone(), id: header.index(), data: data, flags: header.flags(), public_key })
    }
}

// TODO: this is duplicated in the service module
// where should it be?
impl Into<Base> for Request {
    fn into(self) -> Base {

        let kind: Kind;
        let body;

        let mut builder = BaseBuilder::default();

        match &self.data {
            RequestKind::Hello => {
                kind = Kind::Hello;
                body = vec![];
            },
            RequestKind::Ping => {
                kind = Kind::Ping;
                body = vec![];
            },
            RequestKind::FindNode(id) => {
                kind = Kind::FindNodes;
                body = id.to_vec();
            },
            RequestKind::FindValue(id) => {
                kind = Kind::FindValues;
                body = id.to_vec();
            },
            RequestKind::Store(id, pages) => {
                kind = Kind::Store;

                let mut buff = vec![0u8; BUFF_SIZE];
                (&mut buff[..ID_LEN]).copy_from_slice(id);
             
                let i = Page::encode_pages(pages, &mut buff[ID_LEN..]).unwrap();

                body = buff[..ID_LEN + i].to_vec();
            }
        }

        builder.base(self.from, 0, kind, self.id, self.flags).body(body).build().unwrap()
    }
}

#[cfg(nope)]
impl fmt::Debug for RequestKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RequestKind::Hello => write!(f, "status"),
            RequestKind::Ping => {
                write!(f, "Ping")
            },
            RequestKind::FindNode(id) => {
                write!(f, "FindNode ({:?})", id)
            },
            RequestKind::FindValue(id) => {
                write!(f, "FindValue ({:?})", id)
            },
            RequestKind::Store(id, values) => {
                write!(f, "Store({:?}): [", id)?;
                for v in values {
                    write!(f, "\n    - {:?}", v)?;
                }
                write!(f, "]\n")
            }
        
        }
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub from: Id,
    pub id: RequestId,
    pub flags: Flags,
    pub data: ResponseKind,

    pub remote_address: Option<Address>,
    pub public_key: Option<PublicKey>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum ResponseKind {
    Status,
    NodesFound(Id, Vec<(Id, Address, PublicKey)>),
    ValuesFound(Id, Vec<Page>),
    NoResult,
}


impl Response {
    pub fn new(from: Id, id: RequestId, data: ResponseKind, flags: Flags) -> Response {
        Response {
            from,
            id,
            data,
            flags,

            remote_address: None,
            public_key: None,
        }
    }

    pub fn flags(&mut self) -> &mut Flags {
        &mut self.flags
    }

    pub fn with_remote_address(mut self, addr: Address) -> Self {
        self.remote_address = Some(addr);
        self
    }

    pub fn set_public_key(&mut self, pk: PublicKey) {
        self.public_key = Some(pk);
    }

    pub fn with_public_key(mut self, pk: PublicKey) -> Self {
        self.public_key = Some(pk);
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
                write!(f, "]\n")
            },
            ResponseKind::ValuesFound(id, values) => {
                write!(f, "ValuesFound({:?}): [", id)?;
                for v in values {
                    write!(f, "\n    - {:?}", v)?;
                }
                write!(f, "]\n")
            },
            ResponseKind::NoResult => {
                write!(f, "NoResult")
            }
        }
    }
}

impl PartialEq for Response {
    fn eq(&self, b: &Self) -> bool {
        self.from == b.from && self.flags == b.flags && self.data == b.data
    }
}


impl TryFrom<Base> for Response {
    type Err = Error;

    fn try_from(base: Base) -> Result<Response, Error> {
        let header = base.header();
        let body = base.body();

        let mut public_options = base.public_options().to_vec();
        let _private_options = base.private_options().to_vec();

        let data = match header.kind() {
            Kind::Status => {
                ResponseKind::Status
            },
            Kind::NoResult => {
                ResponseKind::NoResult
            },
            Kind::NodesFound => {
                let mut id = Id::default();
                id.copy_from_slice(&body[..ID_LEN]);
                
                // Build options array from body
                let (options, _n) = Options::parse_vec(&body[ID_LEN..]).unwrap();

                let nodes: Vec<_> = (&options[..]).split_before(|o| {
                    match o {
                        Options::PeerId(_) => true,
                        _ => false,
                    }
                }).filter_map(|opts| {

                    let id = Base::peer_id_option(&opts);
                    let addr = Base::address_option(&opts);
                    let key = Base::pub_key_option(&opts);

                    match (id, addr, key) {
                        (Some(id), Some(addr), Some(key)) => Some((id, addr, key)),
                        // TODO: warn here
                        _ => None,
                    }
                }).collect();

                ResponseKind::NodesFound(id, nodes)
            },
            Kind::ValuesFound => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
   
                let pages = Page::decode_pages(&body[ID_LEN..]).unwrap();

                ResponseKind::ValuesFound(id, pages)
            },
            _ => {
                error!("Error converting base object of kind {:?} to response message", header.kind());
                return Err(Error::InvalidMessageKind)
            }
        };

        // Fetch other key options
        let public_key = Base::filter_pub_key_option(&mut public_options);

        let remote_address = Base::filter_address_option(&mut public_options);

        Ok(Response{from: base.id().clone(), id: header.index(), data: data, flags: header.flags(), public_key, remote_address })
    }
}

impl Into<Base> for Response {
    fn into(self) -> Base {

        let kind: Kind;
        let mut body: Vec<u8>;

        let mut buff = vec![0; BUFF_SIZE];

        let mut builder = BaseBuilder::default();

        match self.data {
            ResponseKind::Status => {
                kind = Kind::Status;
                body = vec![];
                
            },
            ResponseKind::NoResult => {
                kind = Kind::NoResult;
                //TODO?: (&mut body[..ID_LEN]).copy_from_slice(&id);
                body = vec![];
            },
            ResponseKind::NodesFound(id, nodes) => {
                kind = Kind::NodesFound;
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

                body = buff[.. ID_LEN + n].to_vec();
            },
            ResponseKind::ValuesFound(id, pages) => {
                kind = Kind::ValuesFound;
                (&mut buff[..ID_LEN]).copy_from_slice(&id);
             
                let n = Page::encode_pages(&pages, &mut buff[ID_LEN..]).unwrap();

                body = buff[.. ID_LEN + n].to_vec();
            },
        }

        builder.base(self.from, 0, kind, self.id, self.flags).body(body).build().unwrap()
    }
}

#[cfg(test)]
mod tests {

    use std::net::{SocketAddr, IpAddr, Ipv4Addr};

    use super::*;
    use crate::protocol::page::{PageBuilder, PageInfo};

    use crate::crypto;
    #[test]
    fn encode_decode_messages() {
        let mut buff = vec![0u8; BUFF_SIZE];

        let (pub_key, pri_key) = crypto::new_pk().expect("Error generating new public/private key pair");
        let id = crypto::hash(&pub_key).expect("Error generating new ID");
        let fake_id = crypto::hash(&[0, 1, 2, 3, 4]).expect("Error generating fake target ID");
        let flags = Flags::default().set_address_request(true);
        let request_id = 120;

        // Create and sign page
        let mut page = PageBuilder::default().id(id.clone()).kind(Kind::Generic).info(PageInfo::primary(pub_key.clone())).build().expect("Error building page");
        let mut b = Base::from(&page);
        b.encode(|_id, data| crypto::pk_sign(&pri_key, data), &mut buff).expect("Error signing page");
        let sig = b.signature().clone().unwrap();
        page.set_signature(sig);

        let messages: Vec<Message> = vec![
            Message::Request(Request::new(id.clone(), RequestKind::Hello, flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::Ping, flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::FindNode(fake_id.clone()), flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::Store(id.clone(), vec![page.clone()]), flags.clone())),
            Message::Response(Response::new(id.clone(), request_id, ResponseKind::Status, flags.clone())),
            // TODO: put node information here
            Message::Response(Response::new(id.clone(), request_id, ResponseKind::NodesFound(fake_id.clone(), vec![(fake_id.clone(), SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080), pub_key.clone())]), flags.clone())),
            Message::Response(Response::new(id.clone(), request_id, ResponseKind::ValuesFound(fake_id.clone(), vec![page.clone()]), flags.clone())),
            Message::Response(Response::new(id.clone(), request_id, ResponseKind::NoResult, flags.clone())),
        ];


        for message in messages {
            // Cast to base
            let mut b: Base = message.clone().into();
            // Encode base
            let n = b.encode(|_id, data| crypto::pk_sign(&pri_key, data), &mut buff).expect("error encoding message");
            // Parse base and check instances match
            let (d, m)= Base::parse(&buff[..n], |_id, sig, data| crypto::pk_validate(&pub_key, sig, data) ).expect("error parsing message");

            assert_eq!(n, m);
            assert_eq!(b, d);

            // Cast to message and check instances match
            let message2 = Message::try_from(d).expect("error converting base object to message");

            assert_eq!(message, message2);
        }

    }
}