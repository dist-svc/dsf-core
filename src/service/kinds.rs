
use std::collections::HashMap;

pub enum ServiceKind {
    Generic,
    Peer,
    Replica,
    Unknown,
    Private
}

pub struct Generic {
    pub name: String,
    pub addresses: Vec<String>,
    pub meta: HashMap<String, String>,
}

pub struct Unknown {
    pub body: Vec<u8>,
}


