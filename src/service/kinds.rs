
use std::collections::HashMap;

pub enum ServiceKind {
    Generic,
    Peer,
    Replica,
    Unknown,
    Private
}

pub struct Generic {
    name: String,
    addresses: Vec<String>,
    meta: HashMap<String, String>,
}

pub struct Unknown {
    body: Vec<u8>,
}


