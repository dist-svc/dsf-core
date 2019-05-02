
use std::collections::HashMap;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum ServiceKind {
    Generic,
    Peer,
    Replica,
    Unknown,
    Private
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Generic {
    pub name: String,
    pub addresses: Vec<String>,
    pub meta: HashMap<String, String>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Unknown {
    pub body: Vec<u8>,
}


