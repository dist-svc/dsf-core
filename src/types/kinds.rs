use core::convert::TryFrom;


#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct Kind(pub u16);

impl Kind {
    pub fn is_page(&self) -> bool {
        self.0 & kinds::KIND_MASK == kinds::PAGE_FLAGS
    }

    pub fn is_message(&self) -> bool {
        self.is_request() || self.is_response()
    }

    pub fn is_request(&self) -> bool {
        self.0 & kinds::KIND_MASK == kinds::REQUEST_FLAGS
    }

    pub fn is_response(&self) -> bool {
         self.0 & kinds::KIND_MASK == kinds::RESPONSE_FLAGS
    }

    pub fn is_data(&self) -> bool {
        println!("V: {:#b} M: {:#b}, V: {:#b}", self.0, self.0 & kinds::KIND_MASK, kinds::DATA_FLAGS);
        self.0 & kinds::KIND_MASK == kinds::DATA_FLAGS
    }
}

impl From<u16> for Kind {
    fn from(v: u16) -> Self {
        Kind(v)
    }
}

impl Into<u16> for Kind {
    fn into(self) -> u16 {
        self.0
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum KindError {
    InvalidKind(u16),
    Unrecognized(u16),
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum PageKind {
    Generic,
    Peer,
    Replica,
    Private,
}

impl TryFrom<Kind> for PageKind {
    type Error = KindError;

    fn try_from(v: Kind) -> Result<Self, Self::Error> {
        if (v.0 & kinds::KIND_MASK != kinds::PAGE_FLAGS) {
            return Err(KindError::InvalidKind(v.0 & kinds::KIND_MASK))
        }

        let base = match v.0 & !kinds::KIND_MASK {
             kinds::PAGE_GENERIC => PageKind::Generic,
             kinds::PAGE_PEER    => PageKind::Peer,
             kinds::PAGE_REPLICA => PageKind::Replica,
             kinds::PAGE_PRIVATE => PageKind::Private,
             _ => return Err(KindError::Unrecognized(v.0 & !kinds::KIND_MASK)),
        };

        Ok(base)
    }
}

impl Into<Kind> for PageKind {
    fn into(self) -> Kind {
        Kind(match self {
            PageKind::Generic => kinds::PAGE_GENERIC,
            PageKind::Peer    => kinds::PAGE_PEER,
            PageKind::Replica => kinds::PAGE_REPLICA,
            PageKind::Private => kinds::PAGE_PRIVATE,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum MessageKind {
    Hello,
    Status,
    Ping,
    FindNodes,
    FindValues,
    Store,
    NodesFound,
    ValuesFound,
    NoResult,
}

impl TryFrom<Kind> for MessageKind {
    type Error = KindError;

    fn try_from(v: Kind) -> Result<Self, Self::Error> {
        let base = match v.0 & kinds::KIND_MASK {
            kinds::REQUEST_FLAGS => {
                match v.0 {
                    kinds::HELLO        => MessageKind::Hello,
                    kinds::PING         => MessageKind::Ping,
                    kinds::FIND_NODES   => MessageKind::FindNodes,
                    kinds::FIND_VALUES  => MessageKind::FindValues,
                    kinds::STORE        => MessageKind::Store,
                    _ => return Err(KindError::Unrecognized(v.0))
                }
            },
            kinds::RESPONSE_FLAGS => {
                match v.0 {
                    kinds::STATUS       => MessageKind::Status,
                    kinds::NODES_FOUND  => MessageKind::NodesFound,
                    kinds::VALUES_FOUND => MessageKind::ValuesFound,
                    kinds::NO_RESULT    => MessageKind::NoResult,
                    _ => return Err(KindError::Unrecognized(v.0))
                }
            },
            _ => return Err(KindError::InvalidKind(v.0 & kinds::KIND_MASK))
        };
        
        Ok(base)
    }
}

impl Into<Kind> for MessageKind {
    fn into(self) -> Kind {
        let base = match self {
            MessageKind::Hello       => kinds::HELLO,
            MessageKind::Ping        => kinds::PING,
            MessageKind::FindNodes   => kinds::FIND_NODES,
            MessageKind::FindValues  => kinds::FIND_VALUES,
            MessageKind::Store       => kinds::STORE,

            MessageKind::Status      => kinds::STATUS,
            MessageKind::NodesFound  => kinds::NODES_FOUND,
            MessageKind::ValuesFound => kinds::VALUES_FOUND,
            MessageKind::NoResult    => kinds::NO_RESULT,
        };
        Kind(base)
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum DataKind {
    Generic,
}

impl TryFrom<Kind> for DataKind {
    type Error = KindError;

    fn try_from(v: Kind) -> Result<Self, Self::Error> {
        if (v.0 & kinds::KIND_MASK != kinds::DATA_FLAGS) {
            return Err(KindError::InvalidKind(v.0 & kinds::KIND_MASK))
        }

        let base = match v.0 {
            kinds::DATA_GENERIC => DataKind::Generic,
            _ => return Err(KindError::Unrecognized(v.0))
        };

        Ok(base)
    }
}

impl Into<Kind> for DataKind {
    fn into(self) -> Kind {
        let base = match self {
            DataKind::Generic => kinds::DATA_GENERIC,
        };

        Kind(base)
    }
}

pub mod kinds {
    pub const NONE          : u16 = 0x0000;

    pub const KIND_MASK     : u16 = 0b1100_0000_0000_0000;

    // Page Kinds
    pub const PAGE_FLAGS     : u16 = 0b0000_0000_0000_0000;
    pub const PAGE_GENERIC   : u16 = 0x0000 | PAGE_FLAGS;
    pub const PAGE_PEER      : u16 = 0x0001 | PAGE_FLAGS;
    pub const PAGE_REPLICA   : u16 = 0x0002 | PAGE_FLAGS;
    pub const PAGE_PRIVATE   : u16 = 0x0FFF | PAGE_FLAGS;
    
    // Message Kinds
    pub const REQUEST_FLAGS  : u16 = 0b0100_0000_0000_0000;
    pub const HELLO          : u16 = 0x0000 | REQUEST_FLAGS;
    pub const PING           : u16 = 0x0001 | REQUEST_FLAGS;
    pub const FIND_NODES     : u16 = 0x0002 | REQUEST_FLAGS;
    pub const FIND_VALUES    : u16 = 0x0003 | REQUEST_FLAGS;
    pub const STORE          : u16 = 0x0004 | REQUEST_FLAGS;

    pub const RESPONSE_FLAGS : u16 = 0b1000_0000_0000_0000;
    pub const STATUS         : u16 = 0x0000 | RESPONSE_FLAGS;
    pub const NO_RESULT      : u16 = 0x0001 | RESPONSE_FLAGS;
    pub const NODES_FOUND    : u16 = 0x0002 | RESPONSE_FLAGS;
    pub const VALUES_FOUND   : u16 = 0x0003 | RESPONSE_FLAGS;
    
    pub const DATA_FLAGS     : u16 = 0b1100_0000_0000_0000;
    pub const DATA_GENERIC   : u16 = 0x0000 | DATA_FLAGS;
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_kinds() {
        let tests = vec![
            // Pages
            (PageKind::Generic, Kind(0b0000_0000_0000_0000)),
            (PageKind::Peer,    Kind(0b0000_0000_0000_0001)),
            (PageKind::Replica, Kind(0b0000_0000_0000_0010)),
            (PageKind::Private, Kind(0b0000_1111_1111_1111)),
        ];

        for (t, v) in tests {
            println!("page t: {:?}, v: {:#b}", t, v.0);
            assert_eq!(v.is_page(), true);
            let k: Kind = t.into();
            assert_eq!(v, k, "error converting {:?}", t);
            let d = PageKind::try_from(v).expect("error parsing");
            assert_eq!(t, d, "error decoding {:?}", t);
        }
    }

    #[test]
    fn test_message_kinds() {
        let tests = vec![
            (MessageKind::Hello,       Kind(0b0100_0000_0000_0000)),
            (MessageKind::Ping,        Kind(0b0100_0000_0000_0001)),
            (MessageKind::FindNodes,   Kind(0b0100_0000_0000_0010)),
            (MessageKind::FindValues,  Kind(0b0100_0000_0000_0011)),
            (MessageKind::Store,       Kind(0b0100_0000_0000_0100)),

            (MessageKind::Status,      Kind(0b1000_0000_0000_0000)),
            (MessageKind::NoResult,    Kind(0b1000_0000_0000_0001)),
            (MessageKind::NodesFound,  Kind(0b1000_0000_0000_0010)),
            (MessageKind::ValuesFound, Kind(0b1000_0000_0000_0011)),
        ];

        for (t, v) in tests {
            println!("message t: {:?}, v: {:#b}", t, v.0);
            assert_eq!(v.is_message(), true);
            let k: Kind = t.into();
            assert_eq!(v, k, "error converting {:?} into: {:?}", t, k);
            let d = MessageKind::try_from(v).expect("error parsing: {:?}");
            assert_eq!(t, d, "error decoding {:?}", t);
        }
    }

        #[test]
    fn test_data_kinds() {
        let tests = vec![
            (DataKind::Generic,          Kind(0b1100_0000_0000_0000)),
        ];

        for (t, v) in tests {
            println!("data t: {:?}, v: {:#b}", t, v.0);
            assert_eq!(v.is_data(), true);
            let k: Kind = t.into();
            assert_eq!(v, k, "error converting {:?}", t);
            let d = DataKind::try_from(v).expect("error parsing");
            assert_eq!(t, d, "error decoding {:?}", t);
        }
    }
}