
use futures::prelude::*;

use crate::service::Service;
use crate::protocol::page::Page;

/// Producer API trait used by service producers
pub trait Creator {
    type Error;

    /// Register a service in the distributed database
    fn create(&mut self) -> Future<Item=(), Error=Self::Error>;
}

/// Producer API trait used by service producers
pub trait Producer {
    type Error;

    /// Register a service in the distributed database
    fn register(&mut self, s: &Page) -> Future<Item=(), Error=Self::Error>;
}

/// Consumer APi trait used by service consumers
pub trait Consumer {
    type Id;
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn locate(&mut self, id: Self::Id) -> Future<Item=Vec<Page>, Error=Self::Error>;
}


/// Publisher API trait used by publishers of service data
pub trait Publisher {
    type Error;

    /// Publish service data
    fn publish(&mut self, s: &Service, data: &Page) -> Future<Item=(), Error=Self::Error>;
}

/// Subscriber API used by subscribers to service data
pub trait Subscriber {
    type Id;
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn subscribe(&mut self, service: &Service) -> Future<Item=Stream<Item=Service, Error=Self::Error>, Error=Self::Error>;
}

