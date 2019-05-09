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

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum PageKind {
    Generic,
    Peer,
    Replica,
    Private,
}

impl TryFrom<Kind> for PageKind {
    type Error = ();

    fn try_from(v: Kind) -> Result<Self, ()> {
        if (v.0 & kinds::KIND_MASK != kinds::PAGE_FLAGS) {
            return Err(())
        }

        let base = match v.0 {
             kinds::GENERIC => PageKind::Generic,
             kinds::PEER    => PageKind::Peer,
             kinds::REPLICA => PageKind::Replica,
             kinds::PRIVATE => PageKind::Private,
             _ => return Err(()),
        };

        Ok(base)
    }
}

impl Into<Kind> for PageKind {
    fn into(self) -> Kind {
        let base = match self {
            PageKind::Generic => kinds::GENERIC,
            PageKind::Peer    => kinds::PEER,
            PageKind::Replica => kinds::REPLICA,
            PageKind::Private => kinds::PRIVATE,
        };

        Kind(base | kinds::PAGE_FLAGS)
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
    type Error = ();

    fn try_from(v: Kind) -> Result<Self, ()> {
        let base = match v.0 & kinds::KIND_MASK {
            kinds::REQUEST_FLAGS => {
                match v.0 & !kinds::KIND_MASK {
                    kinds::HELLO        => MessageKind::Hello,
                    kinds::PING         => MessageKind::Ping,
                    kinds::FIND_NODES   => MessageKind::FindNodes,
                    kinds::FIND_VALUES  => MessageKind::FindValues,
                    kinds::STORE        => MessageKind::Store,
                    _ => return Err(())
                }
            },
            kinds::RESPONSE_FLAGS => {
                match v.0 & !kinds::KIND_MASK {
                    kinds::STATUS       => MessageKind::Status,
                    kinds::NODES_FOUND  => MessageKind::NodesFound,
                    kinds::VALUES_FOUND => MessageKind::ValuesFound,
                    kinds::NO_RESULT    => MessageKind::NoResult,
                    _ => return Err(())
                }
            },
            _ => return Err(())
        };
        
        Ok(base)
    }
}

impl Into<Kind> for MessageKind {
    fn into(self) -> Kind {
        let base = match self {
            MessageKind::Hello       => kinds::HELLO        | kinds::REQUEST_FLAGS,
            MessageKind::Ping        => kinds::PING         | kinds::REQUEST_FLAGS,
            MessageKind::FindNodes   => kinds::FIND_NODES   | kinds::REQUEST_FLAGS,
            MessageKind::FindValues  => kinds::FIND_VALUES  | kinds::REQUEST_FLAGS,
            MessageKind::Store       => kinds::STORE        | kinds::REQUEST_FLAGS,

            MessageKind::Status      => kinds::STATUS       | kinds::RESPONSE_FLAGS,
            MessageKind::NodesFound  => kinds::NODES_FOUND  | kinds::RESPONSE_FLAGS,
            MessageKind::ValuesFound => kinds::VALUES_FOUND | kinds::RESPONSE_FLAGS,
            MessageKind::NoResult    => kinds::NO_RESULT    | kinds::RESPONSE_FLAGS,
        };
        Kind(base)
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum DataKind {
    Generic,
}

impl TryFrom<Kind> for DataKind {
    type Error = ();

    fn try_from(v: Kind) -> Result<Self, ()> {
        if (v.0 & kinds::KIND_MASK != kinds::DATA_FLAGS) {
            return Err(())
        }

        let base = match v.0 {
            kinds::GENERIC => DataKind::Generic,
            _ => return Err(())
        };

        Ok(base)
    }
}

impl Into<Kind> for DataKind {
    fn into(self) -> Kind {
        let base = match self {
            DataKind::Generic => kinds::GENERIC,
        };

        Kind(base | kinds::DATA_FLAGS)
    }
}

pub mod kinds {
    pub const NONE          : u16 = 0x0000;

    pub const KIND_MASK     : u16 = 0b1100_0000_0000_0001;

    // Page Kinds
    pub const PAGE_FLAGS     : u16 = 0x0000;
    pub const GENERIC        : u16 = 0x0001 | PAGE_FLAGS;
    pub const PEER           : u16 = 0x0002 | PAGE_FLAGS;
    pub const REPLICA        : u16 = 0x0003 | PAGE_FLAGS;
    pub const PRIVATE        : u16 = 0x0FFF | PAGE_FLAGS;
    

    // Message Kinds
    pub const REQUEST_FLAGS  : u16 = 0x4000;
    pub const HELLO          : u16 = 0x0000 | REQUEST_FLAGS;
    pub const PING           : u16 = 0x0001 | REQUEST_FLAGS;
    pub const FIND_NODES     : u16 = 0x0002 | REQUEST_FLAGS;
    pub const FIND_VALUES    : u16 = 0x0003 | REQUEST_FLAGS;
    pub const STORE          : u16 = 0x0004 | REQUEST_FLAGS;

    pub const RESPONSE_FLAGS : u16 = 0x8000;
    pub const STATUS         : u16 = 0x0000 | RESPONSE_FLAGS;
    pub const NO_RESULT      : u16 = 0x0001 | RESPONSE_FLAGS;
    pub const NODES_FOUND    : u16 = 0x0002 | RESPONSE_FLAGS;
    pub const VALUES_FOUND   : u16 = 0x0003 | RESPONSE_FLAGS;
    
    pub const DATA_FLAGS     : u16 = 0xc000; 
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_kinds() {
        let tests = vec![
            // Pages
            (PageKind::Generic, Kind(0b0000_0000_0000_0001)),
            (PageKind::Peer,    Kind(0b0000_0000_0000_0010)),
            (PageKind::Replica, Kind(0b0000_0000_0000_0011)),
            (PageKind::Private, Kind(0b0000_1111_1111_1111)),
        ];

        for (t, v) in tests {
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
            (DataKind::Generic,          Kind(0b1100_0000_0000_000)),
        ];

        for (t, v) in tests {
            assert_eq!(v.is_data(), true);
            let k: Kind = t.into();
            assert_eq!(v, k, "error converting {:?}", t);
            let d = DataKind::try_from(v).expect("error parsing");
            assert_eq!(t, d, "error decoding {:?}", t);
        }
    }
}