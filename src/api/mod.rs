

use futures::prelude::*;

use super::service::Service;
use crate::protocol::page::Page;

/// Producer API trait used by service producers
pub trait Producer {
    type Error;

    /// Register a service in the distributed database
    fn register(s: &Page) -> Future<Item=(), Error=Self::Error>;
}

/// Consumer APi trait used by service consumers
pub trait Consumer {
    type Id;
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn locate(id: Self::Id) -> Future<Item=Vec<Page>, Error=Self::Error>;
}


/// Publisher API trait used by publishers of service data
pub trait Publisher {
    type Error;

    /// Publish service data
    fn publish(s: &Service, data: &Page) -> Future<Item=(), Error=Self::Error>;
}

/// Subscriber API used by subscribers to service data
pub trait Subscriber {
    type Id;
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn subscribe(service: &Service) -> Future<Item=Stream<Item=Service, Error=Self::Error>, Error=Self::Error>;
}

use std::net::SocketAddr;

use crate::types::Id;
use crate::types::Error;

/// Request from the client to the daemon
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Request {
    Status,
    Connect(SocketAddr),
    Search(Id),
    Publish,
}

/// Response from the daemon to the client
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Response {
    None,
    StatusResponse,
    //Value(String),
    Unrecognised,
}
