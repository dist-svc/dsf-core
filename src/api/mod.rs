
//! API module defines the DSF remote API
//! This allows for limited capability devices to perform network operations via
//! a full-featured device

use futures::prelude::*;
use async_trait::async_trait;

use crate::types::{Id, DataKind};

/// ServiceHandle objects are used to pass around instances of a service
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceHandle {
    pub id: Id,
}

impl ServiceHandle {
    pub fn new(id: Id) -> Self {
        Self{id}
    }
}

/// Creation API used to create services
#[async_trait]
pub trait Create {
    type Options;
    type Error;

    /// Create a new service with the provided options
    async fn create(&mut self, options: Self::Options) -> Result<ServiceHandle, Self::Error>;
}


/// Producer API trait used to register an existing service
#[async_trait]
pub trait Register {
    type Error;

    /// Register a service in the distributed database
    async fn register(&mut self, s: &mut ServiceHandle) -> Result<(), Self::Error>;
}


/// Locate API trait used to find an existing service
#[async_trait]
pub trait Locate {
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    async fn locate(&mut self, id: &Id) -> Result<ServiceHandle, Self::Error>;
}


/// Publisher API trait used by publishers of service data
#[async_trait]
pub trait Publish {
    type Error;

    /// Publish service data
    async fn publish(&mut self, s: &ServiceHandle, kind: Option<DataKind>, data: Option<&[u8]>) -> Result<(), Self::Error>;
}

/// A boxed future stream to shorten method definitions
/// #[async_trait]
//pub type FutureStream<E> = impl Stream<Item=E>;

/// Subscriber API used by subscribers to service data
#[async_trait]
pub trait Subscribe {
    type Options;
    type Data;
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    async fn subscribe(&mut self, service: &ServiceHandle, options: Self::Options) -> Result<Box<dyn Stream<Item=Self::Data>>, Self::Error>;
}

