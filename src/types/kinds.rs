
/// Page Kinds.
/// 
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    None,

    // Pages
    Peer,
    Generic,
    Private,

    // Messages
    Hello,
    Status,
    Ping,
    FindNodes,
    FindValues,
    Store,
    NodesFound,
    ValuesFound,
    NoResult,

    Data(u16),

    // Other DSD / Unknown    
    Other(u16),

    Application(u16),
}

pub mod kinds {
    pub const NONE          : u16 = 0x0000;

    pub const KIND_MASK     : u16 = 0xe000;

    pub const APP_FLAG      : u16 = 0x8000;

    // Page Kinds
    pub const PAGE_FLAGS    : u16 = 0x0000;
    pub const PEER          : u16 = 0x0001 | PAGE_FLAGS;
    pub const GENERIC       : u16 = 0x0002 | PAGE_FLAGS;
    pub const PRIVATE       : u16 = 0x0FFF | PAGE_FLAGS;

    // Message Kinds
    pub const REQUEST_FLAGS : u16 = 0x2000;
    pub const HELLO         : u16 = 0x0000 | REQUEST_FLAGS;
    pub const PING          : u16 = 0x0001 | REQUEST_FLAGS;
    pub const FIND_NODES    : u16 = 0x0002 | REQUEST_FLAGS;
    pub const FIND_VALUES   : u16 = 0x0003 | REQUEST_FLAGS;
    pub const STORE         : u16 = 0x0004 | REQUEST_FLAGS;

    pub const RESPONSE_FLAGS : u16 = 0x4000;
    pub const STATUS         : u16 = 0x0000 | RESPONSE_FLAGS;
    pub const NO_RESULT      : u16 = 0x0001 | RESPONSE_FLAGS;
    pub const NODES_FOUND    : u16 = 0x0002 | RESPONSE_FLAGS;
    pub const VALUES_FOUND   : u16 = 0x0003 | RESPONSE_FLAGS;
    
    pub const DATA_FLAGS    : u16 = 0x6000; 
}

impl Kind {
    pub fn is_dsd(&self) -> bool {
        !self.is_application()
    }

     pub fn is_application(&self) -> bool {
        match self {
            Kind::Application(_) => true,
            _ => false,
        }
    }

    pub fn is_page(&self) -> bool {
        match self {
            Kind::Peer => true,
            Kind::Generic => true,
            Kind::Private => true,
            _ => false,
        }
    }

    pub fn is_request(&self) -> bool {
        match self {
            Kind::Hello => true,
            Kind::Ping => true,
            Kind::FindNodes => true,
            Kind::FindValues => true,
            Kind::Store => true,
            _ => false,
        }
    }

    pub fn is_response(&self) -> bool {
        match self {
            Kind::Status => true,
            Kind::NodesFound => true,
            Kind::ValuesFound => true,
            Kind::NoResult => true,
            _ => false,
        }
    }

    pub fn is_data(&self) -> bool {
        match self {
            Kind::Data(_) => true,
            _ => false,
        }
    }

}

impl From<u16> for Kind {
    fn from(val: u16) -> Kind {
        // Short circuit for application messages
        if val & kinds::APP_FLAG != 0 {
            return Kind::Application(val)
        }

        match val {
            kinds::NONE         => Kind::None,

            kinds::PEER         => Kind::Peer,
            kinds::GENERIC      => Kind::Generic,
            kinds::PRIVATE      => Kind::Private,

            kinds::HELLO        => Kind::Hello,
            kinds::PING         => Kind::Ping,
            kinds::FIND_NODES   => Kind::FindNodes,
            kinds::FIND_VALUES  => Kind::FindValues,
            kinds::STORE        => Kind::Store,

            kinds::STATUS       => Kind::Status,
            kinds::NODES_FOUND  => Kind::NodesFound,
            kinds::VALUES_FOUND => Kind::ValuesFound,
            kinds::NO_RESULT    => Kind::NoResult,

            _ => {
                if val & kinds::KIND_MASK == kinds::DATA_FLAGS {
                    Kind::Data(val & !(kinds::KIND_MASK))
                } else {
                    Kind::Other(val & !(kinds::KIND_MASK))
                }
            },
        }
    }
}

impl Into<u16> for Kind {
    fn into(self) -> u16 {
        match self {
            Kind::Application(v) => v | kinds::APP_FLAG,

            Kind::None          => kinds::NONE,

            Kind::Peer          => kinds::PEER,
            Kind::Generic       => kinds::GENERIC,
            Kind::Private       => kinds::PRIVATE,
            Kind::Hello         => kinds::HELLO,

            Kind::Ping          => kinds::PING,
            Kind::FindNodes     => kinds::FIND_NODES,
            Kind::FindValues    => kinds::FIND_VALUES,
            Kind::Store         => kinds::STORE,

            Kind::Status        => kinds::STATUS,
            Kind::NodesFound    => kinds::NODES_FOUND,
            Kind::ValuesFound   => kinds::VALUES_FOUND,
            Kind::NoResult      => kinds::NO_RESULT,

            Kind::Data(v)       => v | kinds::DATA_FLAGS,

            Kind::Other(v)      => v,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kinds() {
        let tests = vec![
            (Kind::None,            0b0000_0000_0000_0000),

            (Kind::Peer,            0b0000_0000_0000_0001),
            (Kind::Generic,         0b0000_0000_0000_0010),
            (Kind::Private,         0b0000_1111_1111_1111),

            (Kind::Hello,           0b0010_0000_0000_0000),
            (Kind::Ping,            0b0010_0000_0000_0001),
            (Kind::FindNodes,       0b0010_0000_0000_0010),
            (Kind::FindValues,      0b0010_0000_0000_0011),
            (Kind::Store,           0b0010_0000_0000_0100),

            (Kind::Status,          0b0100_0000_0000_0000),
            (Kind::NoResult,        0b0100_0000_0000_0001),
            (Kind::NodesFound,      0b0100_0000_0000_0010),
            (Kind::ValuesFound,     0b0100_0000_0000_0011),
            

            (Kind::Data(0b1010),    0b0110_0000_0000_1010),

            (Kind::Other(0b1010),   0b0000_0000_0000_1010)
        ];

        for (t, v) in tests {
            let e: u16 = t.into();
            assert_eq!(v, e, "error encoding {:?}", t);
            let d: Kind = v.into();
            assert_eq!(t, d, "error decoding {:?}", t);
        }

    }
}