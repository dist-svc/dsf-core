
//! API module defines the DSF remote API
//! This allows for limited capability devices to perform network operations via
//! a full-featured device

use futures::prelude::*;

use crate::types::{Id};
use crate::service::Service;
use crate::protocol::page::Page;

/// Producer API trait used to register an existing service
pub trait Register {
    type Error;

    /// Register a service in the distributed database
    fn register(&mut self, p: &Page) -> Box<Future<Item=(), Error=Self::Error>>;
}


/// Locate API trait used to find an existing service
pub trait Locate {
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn locate(&mut self, id: &Id) -> Box<Future<Item=Service, Error=Self::Error>>;
}

/// Publisher API trait used by publishers of service data
pub trait Publish {
    type Error;

    /// Publish service data
    fn publish(&mut self, s: &Service, data: &Page) -> Box<Future<Item=(), Error=Self::Error>>;
}


/// Subscriber API used by subscribers to service data
pub trait Subscribe {
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn subscribe(&mut self, service: &Service) -> Box<Future<Item=Stream<Item=Page, Error=Self::Error>, Error=Self::Error>>;
}

