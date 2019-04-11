
use futures::prelude::*;

use crate::types::Id;
use crate::service::Service;
use crate::protocol::page::Page;

/// Producer API trait used by service producers
pub trait Producer {
    type Error;

    /// Register a service in the distributed database
    fn register(&mut self, s: &Service) -> Box<Future<Item=(), Error=Self::Error>>;
}

/// Consumer APi trait used by service consumers
pub trait Consumer {
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn locate(&mut self, id: Id) -> Box<Future<Item=Service, Error=Self::Error>>;
}


/// Publisher API trait used by publishers of service data
pub trait Publisher {
    type Error;

    /// Publish service data
    fn publish(&mut self, s: &Service, data: &Page) -> Box<Future<Item=(), Error=Self::Error>>;
}

/// Subscriber API used by subscribers to service data
pub trait Subscriber {
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn subscribe(&mut self, service: &Service) -> Box<Future<Item=Stream<Item=Service, Error=Self::Error>, Error=Self::Error>>;
}



