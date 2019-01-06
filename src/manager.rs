
use std::net::SocketAddr;

use futures::prelude::*;

use crate::types::{Id, Error};
use crate::service::{Service, ServiceBuilder};
use crate::protocol::messages::{Message, Kind, Request, Response};

/// P2P-SD Configuration Object
#[derive(Default, StructOpt)]
pub struct Config {
    addr: Vec<SocketAddr>,

}

pub struct Dsd<S> {
    config: Config,
    sender: S,
    service: Service,
    //dht: StandardDht<Id, SocketAddr, (), Connector>,
}

impl <S>Dsd<S> 
where
    S: FnMut() -> Box<Future<Item=(), Error=()>>,
{
    pub fn new(config: Config, sender: S) -> Dsd<S> {
        //let connector = Connector::new(stream, sink);
        //let dht = Dht::standard(id, addr, config.dht, connector);
        let service = ServiceBuilder::default().peer().build().unwrap();

        Dsd{config, sender, service}
    }

    pub fn connect(&mut self, address: SocketAddr) -> impl Future<Item=(), Error=Error> {
        // Attempt to connect to new peer

        // Generate connection request
        let req = Request::FindNode(self.service.id().clone());
        
        
        futures::future::err(Error::Unimplemented)
    }

    pub fn register(&mut self, id: &[u8], address: SocketAddr) -> impl Future<Item=(), Error=Error> {
        futures::future::err(Error::Unimplemented)
    }

    pub fn locate(&mut self, id: &[u8]) -> impl Future<Item=(), Error=Error> {
        futures::future::err(Error::Unimplemented)
    }
}
