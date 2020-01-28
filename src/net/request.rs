
use core::convert::TryFrom;
use core::ops::Deref;




use crate::types::*;
use crate::options::Options;
use crate::base::{Base, BaseBuilder, Body};
use crate::page::Page;

use super::Common;
use super::BUFF_SIZE;

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
        let r = Request { common, data };
        r
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
        //let remote_address = Base::filter_address_option(&mut public_options);

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

        let builder = builder.base(self.from, 0, kind.into(), self.id, self.flags).body(Body::from(body));

        builder.public_key(self.public_key);
        if let Some(a) = self.remote_address {
            builder.append_public_option(Options::address(a));
        }

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
