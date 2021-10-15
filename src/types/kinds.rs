use core::convert::TryFrom;
use core::str::FromStr;

/// Kind identifies the type of the of the obvject
#[derive(PartialEq, Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Kind(pub u16);

impl Kind {
    pub fn is_application(&self) -> bool {
        self.0 & kind_flags::APP_FLAG != 0
    }

    pub fn is_page(&self) -> bool {
        self.0 & kind_flags::KIND_MASK == kind_flags::PAGE_FLAGS
    }

    pub fn is_message(&self) -> bool {
        self.is_request() || self.is_response()
    }

    pub fn is_request(&self) -> bool {
        self.0 & kind_flags::KIND_MASK == kind_flags::REQUEST_FLAGS
    }

    pub fn is_response(&self) -> bool {
        self.0 & kind_flags::KIND_MASK == kind_flags::RESPONSE_FLAGS
    }

    pub fn is_data(&self) -> bool {
        self.0 & kind_flags::KIND_MASK == kind_flags::DATA_FLAGS
    }

    pub fn page(value: u16) -> Self {
        Kind(value | kind_flags::PAGE_FLAGS)
    }

    pub fn request(value: u16) -> Self {
        Kind(value | kind_flags::REQUEST_FLAGS)
    }

    pub fn response(value: u16) -> Self {
        Kind(value | kind_flags::RESPONSE_FLAGS)
    }

    pub fn data(value: u16) -> Self {
        Kind(value | kind_flags::DATA_FLAGS)
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

// Error parsing kind values
#[derive(Clone, PartialEq, Debug, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KindError {
    InvalidKind(u16),
    Unrecognized(u16),
}

/// PageKind describes DSF-specific page kinds
#[derive(PartialEq, Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "strum", derive(strum_macros::EnumString))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PageKind {
    Generic,
    Peer,
    Replica,
    Private,
}

impl TryFrom<Kind> for PageKind {
    type Error = KindError;

    fn try_from(v: Kind) -> Result<Self, Self::Error> {
        if v.0 & kind_flags::KIND_MASK != kind_flags::PAGE_FLAGS {
            return Err(KindError::InvalidKind(v.0 & kind_flags::KIND_MASK));
        }

        let base = match v.0 & !kind_flags::KIND_MASK {
            kind_flags::PAGE_GENERIC => PageKind::Generic,
            kind_flags::PAGE_PEER => PageKind::Peer,
            kind_flags::PAGE_REPLICA => PageKind::Replica,
            kind_flags::PAGE_PRIVATE => PageKind::Private,
            _ => return Err(KindError::Unrecognized(v.0 & !kind_flags::KIND_MASK)),
        };

        Ok(base)
    }
}

impl Into<Kind> for PageKind {
    fn into(self) -> Kind {
        Kind(match self {
            PageKind::Generic => kind_flags::PAGE_GENERIC,
            PageKind::Peer => kind_flags::PAGE_PEER,
            PageKind::Replica => kind_flags::PAGE_REPLICA,
            PageKind::Private => kind_flags::PAGE_PRIVATE,
        })
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
#[cfg_attr(feature = "strum_macros", derive(strum_macros::EnumString, strum_macros::Display))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MessageKind {
    Hello,
    Ping,
    FindNodes,
    FindValues,
    Store,
    Subscribe,
    Unsubscribe,
    Query,
    PushData,
    Register,
    Unregister,
    Locate,

    Status,
    NodesFound,
    ValuesFound,
    NoResult,
    PullData,
    Discover,
}

impl TryFrom<Kind> for MessageKind {
    type Error = KindError;

    fn try_from(v: Kind) -> Result<Self, Self::Error> {
        // TODO: do not attempt to parse application specific flags

        let base = match v.0 & kind_flags::KIND_MASK {
            kind_flags::REQUEST_FLAGS => match v.0 {
                kind_flags::HELLO => MessageKind::Hello,
                kind_flags::PING => MessageKind::Ping,
                kind_flags::FIND_NODES => MessageKind::FindNodes,
                kind_flags::FIND_VALUES => MessageKind::FindValues,
                kind_flags::STORE => MessageKind::Store,
                kind_flags::SUBSCRIBE => MessageKind::Subscribe,
                kind_flags::UNSUBSCRIBE => MessageKind::Unsubscribe,
                kind_flags::QUERY => MessageKind::Query,
                kind_flags::PUSH_DATA => MessageKind::PushData,
                kind_flags::REGISTER => MessageKind::Register,
                kind_flags::UNREGISTER => MessageKind::Unregister,
                kind_flags::DISCOVER => MessageKind::Discover,
                kind_flags::LOCATE => MessageKind::Locate,
                _ => return Err(KindError::Unrecognized(v.0)),
            },
            kind_flags::RESPONSE_FLAGS => match v.0 {
                kind_flags::STATUS => MessageKind::Status,
                kind_flags::NODES_FOUND => MessageKind::NodesFound,
                kind_flags::VALUES_FOUND => MessageKind::ValuesFound,
                kind_flags::NO_RESULT => MessageKind::NoResult,
                kind_flags::PULL_DATA => MessageKind::PullData,
                _ => return Err(KindError::Unrecognized(v.0)),
            },
            _ => return Err(KindError::InvalidKind(v.0 & kind_flags::KIND_MASK)),
        };

        Ok(base)
    }
}

impl Into<Kind> for MessageKind {
    fn into(self) -> Kind {
        let base = match self {
            MessageKind::Hello => kind_flags::HELLO,
            MessageKind::Ping => kind_flags::PING,
            MessageKind::FindNodes => kind_flags::FIND_NODES,
            MessageKind::FindValues => kind_flags::FIND_VALUES,
            MessageKind::Store => kind_flags::STORE,
            MessageKind::Subscribe => kind_flags::SUBSCRIBE,
            MessageKind::Unsubscribe => kind_flags::UNSUBSCRIBE,
            MessageKind::Query => kind_flags::QUERY,
            MessageKind::PushData => kind_flags::PUSH_DATA,
            MessageKind::Register => kind_flags::REGISTER,
            MessageKind::Unregister => kind_flags::UNREGISTER,
            MessageKind::Discover => kind_flags::DISCOVER,
            MessageKind::Locate => kind_flags::LOCATE,

            MessageKind::Status => kind_flags::STATUS,
            MessageKind::NodesFound => kind_flags::NODES_FOUND,
            MessageKind::ValuesFound => kind_flags::VALUES_FOUND,
            MessageKind::NoResult => kind_flags::NO_RESULT,
            MessageKind::PullData => kind_flags::PULL_DATA,
        };
        Kind(base)
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DataKind {
    Generic,
    Iot,
    Unknown(u16),
}

impl TryFrom<Kind> for DataKind {
    type Error = KindError;

    fn try_from(v: Kind) -> Result<Self, Self::Error> {
        if v.0 & kind_flags::KIND_MASK != kind_flags::DATA_FLAGS {
            return Err(KindError::InvalidKind(v.0 & kind_flags::KIND_MASK));
        }

        let base = match v.0 {
            kind_flags::DATA_GENERIC => DataKind::Generic,
            kind_flags::DATA_IOT => DataKind::Iot,
            _ => return Err(KindError::Unrecognized(v.0)),
        };

        Ok(base)
    }
}

impl Into<Kind> for DataKind {
    fn into(self) -> Kind {
        let base = match self {
            DataKind::Generic => kind_flags::DATA_GENERIC,
            DataKind::Iot => kind_flags::DATA_IOT,
            DataKind::Unknown(v) => kind_flags::DATA_FLAGS | v,
        };

        Kind(base)
    }
}

impl FromStr for DataKind {
    type Err = core::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.to_ascii_lowercase() == "generic" {
            Ok(DataKind::Generic)
        } else {
            let v: u16 = s.parse()?;
            Ok(DataKind::Unknown(v))
        }
    }
}

pub mod kind_flags {
    pub const NONE: u16 = 0x0000;

    pub const KIND_MASK: u16 = 0b0110_0000_0000_0000;

    pub const APP_FLAG: u16 = 0b1000_0000_0000_0000;

    // Page Kinds
    pub const PAGE_FLAGS: u16 = 0b0000_0000_0000_0000;
    pub const PAGE_GENERIC: u16 = 0x0000 | PAGE_FLAGS;
    pub const PAGE_PEER: u16 = 0x0001 | PAGE_FLAGS;
    pub const PAGE_REPLICA: u16 = 0x0002 | PAGE_FLAGS;
    pub const PAGE_PRIVATE: u16 = 0x0FFF | PAGE_FLAGS;

    // Message Kinds
    pub const REQUEST_FLAGS: u16 = 0b0010_0000_0000_0000;
    pub const HELLO: u16 = 0x0000 | REQUEST_FLAGS;
    pub const PING: u16 = 0x0001 | REQUEST_FLAGS;
    pub const FIND_NODES: u16 = 0x0002 | REQUEST_FLAGS;
    pub const FIND_VALUES: u16 = 0x0003 | REQUEST_FLAGS;
    pub const STORE: u16 = 0x0004 | REQUEST_FLAGS;
    pub const SUBSCRIBE: u16 = 0x0005 | REQUEST_FLAGS;
    pub const QUERY: u16 = 0x0006 | REQUEST_FLAGS;
    pub const PUSH_DATA: u16 = 0x0007 | REQUEST_FLAGS;
    pub const UNSUBSCRIBE: u16 = 0x0008 | REQUEST_FLAGS;
    pub const REGISTER: u16 = 0x0009 | REQUEST_FLAGS;
    pub const UNREGISTER: u16 = 0x000a | REQUEST_FLAGS;
    pub const DISCOVER: u16 = 0x000b | REQUEST_FLAGS;
    pub const LOCATE: u16 = 0x000c | REQUEST_FLAGS;

    pub const RESPONSE_FLAGS: u16 = 0b0100_0000_0000_0000;
    pub const STATUS: u16 = 0x0000 | RESPONSE_FLAGS;
    pub const NO_RESULT: u16 = 0x0001 | RESPONSE_FLAGS;
    pub const NODES_FOUND: u16 = 0x0002 | RESPONSE_FLAGS;
    pub const VALUES_FOUND: u16 = 0x0003 | RESPONSE_FLAGS;
    pub const PULL_DATA: u16 = 0x0004 | RESPONSE_FLAGS;

    pub const DATA_FLAGS: u16 = 0b0110_0000_0000_0000;
    pub const DATA_GENERIC: u16 = 0x0000 | DATA_FLAGS;
    pub const DATA_IOT: u16 = 0x0001 | DATA_FLAGS;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_kinds() {
        let tests = vec![
            // Pages
            (PageKind::Generic, Kind(0b0000_0000_0000_0000)),
            (PageKind::Peer, Kind(0b0000_0000_0000_0001)),
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
            (MessageKind::Hello, Kind(0b0010_0000_0000_0000)),
            (MessageKind::Ping, Kind(0b0010_0000_0000_0001)),
            (MessageKind::FindNodes, Kind(0b0010_0000_0000_0010)),
            (MessageKind::FindValues, Kind(0b0010_0000_0000_0011)),
            (MessageKind::Store, Kind(0b0010_0000_0000_0100)),
            (MessageKind::Subscribe, Kind(0b0010_0000_0000_0101)),
            (MessageKind::Query, Kind(0b0010_0000_0000_0110)),
            (MessageKind::PushData, Kind(0b0010_0000_0000_0111)),
            (MessageKind::Unsubscribe, Kind(0b0010_0000_0000_1000)),
            (MessageKind::Register, Kind(0b0010_0000_0000_1001)),
            (MessageKind::Unregister, Kind(0b0010_0000_0000_1010)),
            (MessageKind::Discover, Kind(0b0010_0000_0000_1011)),
            (MessageKind::Status, Kind(0b0100_0000_0000_0000)),
            (MessageKind::NoResult, Kind(0b0100_0000_0000_0001)),
            (MessageKind::NodesFound, Kind(0b0100_0000_0000_0010)),
            (MessageKind::ValuesFound, Kind(0b0100_0000_0000_0011)),
            (MessageKind::PullData, Kind(0b0100_0000_0000_0100)),
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
        let tests = vec![(DataKind::Generic, Kind(0b0110_0000_0000_0000))];

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
