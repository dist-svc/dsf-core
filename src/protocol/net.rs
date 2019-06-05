//! Messages are a high level representation of messages used to communicate between peers
//! to maintain the network, publish and subscribe to services, and exchange data.

use core::convert::TryFrom;
use core::ops::Deref;

use slice_ext::SplitBefore;
use byteorder::{ByteOrder, NetworkEndian};

use crate::types::*;
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
            Message::Request(req) => req.common.public_key = Some(pub_key),
            Message::Response(resp) => resp.common.public_key = Some(pub_key),
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

impl Message {
    /// Parses an array containing a page into a page object
    /// fn v(id, data, sig)
    pub fn parse<'a, V, T: AsRef<[u8]>>(data: T, key_source: V) -> Result<(Message, usize), Error>
    where 
        V: Fn(&Id) -> Option<PublicKey>
    {
        let (b, n) = Base::parse(data, &key_source)?;

        let m = Message::convert(b, &key_source)?;

        Ok((m, n))
    }

}

impl Message {

    pub fn convert<V>(base: Base, key_source: V) -> Result<Message, Error> 
    where 
        V: Fn(&Id) -> Option<PublicKey>
    {
        let header = base.header();
        let app_id = header.application_id();
        let kind = header.kind();

        // Check for DSF messages
        if app_id != 0 {
            println!("Error converting application-specific base object {:?} to message", kind);
            return Err(Error::InvalidMessageType)
        }

        // Parse request and response types
        if kind.is_request() {
            Ok(Message::Request(Request::convert(base, key_source)?))
        } else if kind.is_response() {
            Ok(Message::Response(Response::convert(base, key_source)?))
        } else {
            println!("Error converting base object of kind {:?} to message", kind);
            Err(Error::InvalidMessageType)
        }
    }
}

#[derive(Clone, Debug)]
pub struct Common {
    pub from: Id,
    pub id: RequestId,
    pub flags: Flags,

    pub remote_address: Option<Address>,
    pub public_key: Option<PublicKey>,
}

#[derive(Clone, Debug)]
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
pub enum RequestKind {
    Hello,
    Ping,
    FindNode(Id),
    FindValue(Id),
    Store(Id, Vec<Page>),
    Subscribe(Id),
    Query(Id),
    PushData(Id, Vec<Page>),
}

impl Request {
    pub fn new(from: Id, data: RequestKind, flags: Flags) -> Request {
        let common = Common{ from, id: rand::random(), flags, public_key: None, remote_address: None };
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

    pub fn with_request_id(mut self, req_id: RequestId) -> Self {
        self.common.id = req_id;
        self
    }
}

impl PartialEq for Request {
    fn eq(&self, b: &Self) -> bool {
        self.from == b.from && self.flags == b.flags && self.data == b.data
    }
}

impl Request {

    pub fn convert<V>(base: Base, key_source: V) -> Result<Request, Error> 
    where 
        V: Fn(&Id) -> Option<PublicKey>
    {
        let header = base.header();
        let body = base.body();
        
        let mut public_options = base.public_options().to_vec();
        let _private_options = base.private_options().to_vec();

        let kind = match MessageKind::try_from(header.kind()) {
            Ok(k) => k,
            Err(_) => return Err(Error::InvalidMessageKind),
        };

        let data = match kind {
            MessageKind::Hello => {
                RequestKind::Hello
            },
            MessageKind::Ping => {
                RequestKind::Ping
            },
            MessageKind::FindNodes => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::FindNode(id)
            },
            MessageKind::FindValues => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::FindValue(id)
            },
            MessageKind::Subscribe => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::Subscribe(id)
            },
            MessageKind::Query => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                RequestKind::Query(id)
            },
            MessageKind::Store => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                
                // Perhaps i should not fetch pages until later..?
                // And also sign them earlier..?
                let pages = Page::decode_pages(&body[ID_LEN..], key_source ).unwrap();

                RequestKind::Store(id, pages)
            },
            MessageKind::PushData => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
                
                // Perhaps i should not fetch pages until later..?
                // And also sign them earlier..?
                let pages = Page::decode_pages(&body[ID_LEN..], key_source ).unwrap();

                RequestKind::PushData(id, pages)
            },
            _ => {
                println!("Error converting base object of kind {:?} to request message", header.kind());
                return Err(Error::InvalidMessageKind)
            }
        };

        // Fetch other key options
        let public_key = base.public_key;
        let remote_address = Base::filter_address_option(&mut public_options);

        let common = Common{ from: base.id().clone(), id: header.index(), flags: header.flags(), public_key, remote_address }; 
        Ok(Request{common, data})
    }
}

// TODO: this is duplicated in the service module
// where should it be?
impl Into<Base> for Request {
    fn into(self) -> Base {

        let kind: MessageKind;
        let body;

        let mut builder = BaseBuilder::default();

        match &self.data {
            RequestKind::Hello => {
                kind = MessageKind::Hello;
                body = vec![];
            },
            RequestKind::Ping => {
                kind = MessageKind::Ping;
                body = vec![];
            },
            RequestKind::FindNode(id) => {
                kind = MessageKind::FindNodes;
                body = id.to_vec();
            },
            RequestKind::FindValue(id) => {
                kind = MessageKind::FindValues;
                body = id.to_vec();
            },
            RequestKind::Store(id, pages) => {
                kind = MessageKind::Store;

                let mut buff = vec![0u8; BUFF_SIZE];
                (&mut buff[..ID_LEN]).copy_from_slice(id);
             
                let i = Page::encode_pages(pages, &mut buff[ID_LEN..]).unwrap();

                body = buff[..ID_LEN + i].to_vec();
            },
            RequestKind::Subscribe(id) => {
                kind = MessageKind::Subscribe;
                body = id.to_vec();
            },
            RequestKind::Query(id) => {
                kind = MessageKind::Query;
                body = id.to_vec();
            },
            RequestKind::PushData(id, pages) => {
                kind = MessageKind::PushData;

                let mut buff = vec![0u8; BUFF_SIZE];
                (&mut buff[..ID_LEN]).copy_from_slice(id);
             
                let i = Page::encode_pages(pages, &mut buff[ID_LEN..]).unwrap();

                body = buff[..ID_LEN + i].to_vec();
            },
        }

        let builder = builder.base(self.from, 0, kind.into(), self.id, self.flags).body(body);

        builder.public_key(self.public_key);


        builder.build().unwrap()
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
    pub const OK                : u32 = 0x0000_0000;
    pub const INVALID_REQUEST   : u32 = 0x0000_0001;
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
            status::OK                  => Status::Ok,
            status::INVALID_REQUEST     => Status::InvalidRequest,
            _ => Status::Unknown(v)
        }
    }
}

impl Into<u32> for Status {
    fn into(self) -> u32 {
        match self {
            Status::Ok                  => status::OK,
            Status::InvalidRequest      => status::INVALID_REQUEST,
            Status::Unknown(v)          => v
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
        let common = Common{ from, id, flags, public_key: None, remote_address: None };
        Response {
            common,
            data,
        }
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
            ResponseKind::PullData(id, values) => {
                write!(f, "PullData({:?}): [", id)?;
                for v in values {
                    write!(f, "\n    - {:?}", v)?;
                }
                write!(f, "]\n")
            },
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
        V: Fn (&Id) -> Option<PublicKey>
    {
        let header = base.header();
        let body = base.body();

        let mut public_options = base.public_options().to_vec();
        let _private_options = base.private_options().to_vec();

        let kind = match MessageKind::try_from(header.kind()) {
            Ok(k) => k,
            Err(_) => return Err(Error::InvalidMessageKind),
        };

        let data = match kind {
            MessageKind::Status => {
                let status = NetworkEndian::read_u32(&body);
                ResponseKind::Status(status.into())
            },
            MessageKind::NoResult => {
                ResponseKind::NoResult
            },
            MessageKind::NodesFound => {
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
            MessageKind::ValuesFound => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
   
                let pages = Page::decode_pages(&body[ID_LEN..], key_source ).unwrap();

                ResponseKind::ValuesFound(id, pages)
            },
            MessageKind::PullData => {
                let mut id = Id::default();
                id.copy_from_slice(&body[0..ID_LEN]);
   
                let pages = Page::decode_pages(&body[ID_LEN..], key_source ).unwrap();

                ResponseKind::PullData(id, pages)
            },
            _ => {
                error!("Error converting base object of kind {:?} to response message", header.kind());
                return Err(Error::InvalidMessageKind)
            }
        };

        // Fetch other key options
        let public_key = base.public_key;

        let remote_address = Base::filter_address_option(&mut public_options);

        let common = Common{ from: base.id().clone(), id: header.index(), flags: header.flags(), public_key, remote_address };
        Ok(Response{common, data})
    }
}

impl Into<Base> for Response {
    fn into(self) -> Base {

        let kind: MessageKind;
        let mut body: Vec<u8>;

        let mut buff = vec![0; BUFF_SIZE];

        let mut builder = BaseBuilder::default();

        match self.data {
            ResponseKind::Status(code) => {
                kind = MessageKind::Status;
                NetworkEndian::write_u32(&mut buff, code.into());
                body = (&buff[0..4]).to_vec();
                
            },
            ResponseKind::NoResult => {
                kind = MessageKind::NoResult;
                //TODO?: (&mut body[..ID_LEN]).copy_from_slice(&id);
                body = vec![];
            },
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

                body = buff[.. ID_LEN + n].to_vec();
            },
            ResponseKind::ValuesFound(id, pages) => {
                kind = MessageKind::ValuesFound;
                (&mut buff[..ID_LEN]).copy_from_slice(&id);
             
                let n = Page::encode_pages(&pages, &mut buff[ID_LEN..]).unwrap();

                body = buff[.. ID_LEN + n].to_vec();
            },
            ResponseKind::PullData(id, pages) => {
                kind = MessageKind::PullData;
                (&mut buff[..ID_LEN]).copy_from_slice(&id);
             
                let n = Page::encode_pages(&pages, &mut buff[ID_LEN..]).unwrap();

                body = buff[.. ID_LEN + n].to_vec();
            },
        }

        let builder = builder.base(self.common.from, 0, kind.into(), self.common.id, self.common.flags).body(body);

        builder.public_key(self.common.public_key);

        builder.build().unwrap()
    }
}

#[cfg(test)]
mod tests {

    use std::net::{SocketAddr, IpAddr, Ipv4Addr};

    use super::*;
    use crate::protocol::page::{PageBuilder, PageInfo};
    use crate::types::PageKind;

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
        let mut page = PageBuilder::default().id(id.clone()).kind(PageKind::Generic.into()).info(PageInfo::primary(pub_key.clone())).build().expect("Error building page");
        page.public_key = Some(pub_key.clone());

        let mut b = Base::from(&page);
        b.encode(|_id, data| crypto::pk_sign(&pri_key, data), &mut buff).expect("Error signing page");
        let sig = b.signature().clone().unwrap();
        page.set_signature(sig);

        let messages: Vec<Message> = vec![
            Message::Request(Request::new(id.clone(), RequestKind::Hello, flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::Ping, flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::FindNode(fake_id.clone()), flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::Store(id.clone(), vec![page.clone()]), flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::Subscribe(fake_id.clone()), flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::Query(fake_id.clone()), flags.clone())),
            Message::Request(Request::new(id.clone(), RequestKind::PushData(id.clone(), vec![page.clone()]), flags.clone())),

            Message::Response(Response::new(id.clone(), request_id, ResponseKind::Status(Status::Ok), flags.clone())),
            // TODO: put node information here
            Message::Response(Response::new(id.clone(), request_id, ResponseKind::NodesFound(fake_id.clone(), vec![(fake_id.clone(), SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080), pub_key.clone())]), flags.clone())),
            Message::Response(Response::new(id.clone(), request_id, ResponseKind::ValuesFound(fake_id.clone(), vec![page.clone()]), flags.clone())),
            Message::Response(Response::new(id.clone(), request_id, ResponseKind::NoResult, flags.clone())),
            Message::Response(Response::new(id.clone(), request_id, ResponseKind::PullData(fake_id.clone(), vec![page.clone()]), flags.clone())),
        ];


        for message in messages {
            // Cast to base
            let mut b: Base = message.clone().into();
            // Encode base
            let n = b.encode(|_id, data| crypto::pk_sign(&pri_key, data), &mut buff).expect("error encoding message");
            // Parse base and check instances match
            let (mut d, m)= Base::parse(&buff[..n], |_id| Some(pub_key) ).expect("error parsing message");

            assert_eq!(n, m);

            d.raw = None;
            b.raw = None;
            
            assert_eq!(b, d);

            // Cast to message and check instances match
            let message2 = Message::convert(d, |_id| Some(pub_key) ).expect("error converting base object to message");

            assert_eq!(message, message2);
        }

    }
}