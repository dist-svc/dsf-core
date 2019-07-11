
//! API module defines the DSF remote API
//! This allows for limited capability devices to perform network operations via
//! a full-featured device

use futures::prelude::*;

use crate::types::{Id};


#[derive(Debug, Clone, PartialEq)]
pub struct ServiceHandle {
    pub id: Id,
}

/// A boxed future result to shorten method definitions
pub type FutureResult<I, E> = Box<Future<Item=I, Error=E> + Send>;

/// Creation API used to create services
pub trait Create {
    type Options;
    type Error;

    /// Create a new service with the provided options
    fn create(options: &Self::Options) -> FutureResult<ServiceHandle, Self::Error>;
}


/// Producer API trait used to register an existing service
pub trait Register {
    type Error;

    /// Register a service in the distributed database
    fn register(&mut self, s: &mut ServiceHandle) -> FutureResult<(), Self::Error>;
}


/// Locate API trait used to find an existing service
pub trait Locate {
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn locate(&mut self, id: &Id) -> FutureResult<ServiceHandle, Self::Error>;
}


/// Publisher API trait used by publishers of service data
pub trait Publish {
    type Data;
    type Error;

    /// Publish service data
    fn publish(&mut self, s: &ServiceHandle, data: Self::Data) -> FutureResult<(), Self::Error>;
}

/// A boxed future stream to shorten method definitions
pub type FutureStream<I, E> = FutureResult<Stream<Item=I, Error=E>, E>;

/// Subscriber API used by subscribers to service data
pub trait Subscribe {
    type Options;
    type Data;
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn subscribe(&mut self, service: &ServiceHandle, options: Self::Options) -> FutureStream<Self::Data, Self::Error>;
}

