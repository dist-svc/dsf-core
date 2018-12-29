

use futures::prelude::*;

use super::service::Service;

/// Producer API trait used by service producers
pub trait Producer {
    type Error;

    /// Register a service in the distributed database
    fn register(s: &Service) -> Future<Item=(), Error=Self::Error>;
}

/// Consumer APi trait used by service consumers
pub trait Consumer {
    type Id;
    type Error;

    /// Locate a DIoT service in the distributed database
    /// This returns a future that will resolve to the desired service or an error
    fn locate(id: Self::Id) -> Future<Item=Service, Error=Self::Error>;
}

