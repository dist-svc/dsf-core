
use std::collections::HashMap;

pub enum ServiceKinds {
    Generic(Generic),
    Unknown(Unknown),
}

pub struct Generic {
    name: String,
    addresses: Vec<String>,
    meta: HashMap<String, String>,
}

pub struct Unknown {
    body: Vec<u8>,
}


