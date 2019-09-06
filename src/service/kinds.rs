
use std::collections::HashMap;

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum ServiceKind {
    Generic,
    Peer,
    Replica,
    Unknown,
    Private
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Generic {
    pub name: String,
    pub addresses: Vec<String>,
    pub meta: HashMap<String, String>,
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Unknown {
    pub body: Vec<u8>,
}


