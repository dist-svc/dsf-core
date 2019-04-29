

use futures::prelude::*;
use structopt::StructOpt;

use crate::types::{Id, Address, SecretKey};
use crate::service::Service;
use crate::protocol::page::Page;

/// Connect API trait used to initiate a connection to a known peer
pub trait Connect {
    type Error;

    /// Register a service in the distributed database
    fn connect(&mut self, options: ConnectOptions) -> Box<Future<Item=ConnectInfo, Error=Self::Error>>;
}

/// ConnectOptions passed to connect function
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, StructOpt)]
pub struct ConnectOptions {
    #[structopt(parse(try_from_str = "try_parse_sock_addr"))]
    /// Socket address for connection attempt
    pub address: Address,

    #[structopt(short="i", long="id")]
    /// ID of the remote node
    pub id: Option<Id>,
}

/// ConnectInfo returned by connect function
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectInfo {
    pub id: Id,
    pub peers: usize,
}

/// Create API trait used to generate new services
pub trait Create {
    type Error;

    /// Register a service in the distributed database
    fn create(&mut self, options: CreateOptions) -> Box<Future<Item=CreateInfo, Error=Self::Error>>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, StructOpt)]
pub struct CreateOptions {
    #[structopt(short = "i", long = "application-id", default_value = "0")]
    /// Application ID    
    pub application_id: u16,

    #[structopt(short = "k", long = "page-kind")]
    /// Page Kind (defaults to Generic)
    pub page_kind: Option<u16>,

    #[structopt(name = "body", parse(try_from_str = "try_load_file"))]
    /// Service Page Body (loaded from the specified file)
    pub body: Option<Body>,

    #[structopt(short = "a", long = "address")]
    /// Service Addresses
    pub addresses: Vec<Address>,

    #[structopt(short = "m", long = "metadata", parse(try_from_str = "try_parse_kv"))]
    /// Service Metadata key:value pairs
    pub metadata: Vec<(String, String)>,

    #[structopt(short = "p", long = "public")]
    /// Indicate the service should be public (unencrypted)
    pub public: bool,

    #[structopt(long = "register")]
    /// Indicate the service should be registered following creation
    pub register: bool,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self{
            application_id: 0,
            page_kind: None,
            body: None,
            addresses: vec![],
            metadata: vec![],
            public: false,
            register: false,
        }
    }
}

impl CreateOptions {
    pub fn and_register(mut self) -> Self {
        self.register = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateInfo {
    pub id: Id,
    pub secret_key: Option<SecretKey>,
}


/// Producer API trait used by service producers
pub trait Register {
    type Error;

    /// Register a service in the distributed database
    fn register(&mut self, s: &Service) -> Box<Future<Item=(), Error=Self::Error>>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, StructOpt)]
pub struct RegisterOptions {
    #[structopt(short="i", long="id")]
    /// ID of the service to register
    pub id: Id,
}

impl RegisterOptions {
    pub fn new(id: Id) -> Self {
        Self{id}
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterInfo {

}


/// Consumer APi trait used by service consumers
pub trait Locate {
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn locate(&mut self, options: LocateOptions) -> Box<Future<Item=LocateInfo, Error=Self::Error>>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, StructOpt)]
pub struct LocateOptions {
    #[structopt(short="i", long="id")]
    /// ID of the service to locate
    pub id: Id,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocateInfo {
    pub origin: bool,
    pub updated: bool,
}


/// Publisher API trait used by publishers of service data
pub trait Publish {
    type Error;

    /// Publish service data
    fn publish(&mut self, s: &Service, data: &Page) -> Box<Future<Item=(), Error=Self::Error>>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, StructOpt)]
pub struct PublishOptions {

}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublishInfo {

}


/// Subscriber API used by subscribers to service data
pub trait Subscribe {
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn subscribe(&mut self, service: &Service) -> Box<Future<Item=Stream<Item=Service, Error=Self::Error>, Error=Self::Error>>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, StructOpt)]
pub struct SubscribeOptions {
    #[structopt(short="i", long="id")]
    /// ID of the service to subscribe to
    pub id: Id,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubscribeInfo {

}



use std::net::{SocketAddr, ToSocketAddrs};
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

pub fn try_parse_sock_addr(from: &str) -> Result<SocketAddr, IoError> {
    let mut addrs = from.to_socket_addrs()?;

    match addrs.next() {
        Some(a) => Ok(a),
        None => Err(IoError::new(IoErrorKind::Other, "no socket addresses found")),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Body {
    pub data: Vec<u8>,
}

use std::fs;
pub fn try_load_file(from: &str) -> Result<Body, IoError> {
    let data = fs::read(from)?;
    Ok(Body{data})
}

use std::str;

pub fn try_parse_kv(from: &str) -> Result<(String, String), IoError> {
    let split: Vec<_> = from.split(":").collect();
    if split.len() != 2 {
        return Err(IoError::new(IoErrorKind::Other, "key:value pair parsing failed"));
    }

    Ok((split[0].to_owned(), split[1].to_owned()))
}
