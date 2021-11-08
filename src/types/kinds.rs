use core::convert::TryFrom;
use core::str::FromStr;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use self::kind_flags::REQUEST_FLAGS;

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
#[derive(PartialEq, Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "strum", derive(strum_macros::EnumString))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u16)]
    pub enum PageKind {
    Generic     = 0x0000 | PAGE_FLAGS,
    Peer        = 0x0001 | PAGE_FLAGS,
    Replica     = 0x0002 | PAGE_FLAGS,
    Tertiary    = 0x0003 | PAGE_FLAGS,
    Private     = 0x0FFF | PAGE_FLAGS,
}

impl TryFrom<Kind> for PageKind {
    type Error = KindError;

    fn try_from(v: Kind) -> Result<Self, Self::Error> {
        // Check kind mask
        if v.0 & kind_flags::KIND_MASK != kind_flags::PAGE_FLAGS {
            return Err(KindError::InvalidKind(v.0 & kind_flags::KIND_MASK));
        }

        // Convert to page kind
        match PageKind::try_from(v.0) {
            Ok(v) => Ok(v),
            Err(_e) => {
                Err(KindError::InvalidKind(v.0 & kind_flags::KIND_MASK))
            }
        }
    }
}

impl Into<Kind> for PageKind {
    fn into(self) -> Kind {
        Kind(self.into())
    }
}

use kind_flags::{RESPONSE_FLAGS, PAGE_FLAGS};

#[derive(PartialEq, Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "strum_macros", derive(strum_macros::EnumString, strum_macros::Display))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u16)]
pub enum MessageKind {
    Hello           = 0x0000 | REQUEST_FLAGS,
    Ping            = 0x0001 | REQUEST_FLAGS,         
    FindNodes       = 0x0002 | REQUEST_FLAGS,
    FindValues      = 0x0003 | REQUEST_FLAGS,
    Store           = 0x0004 | REQUEST_FLAGS,
    Subscribe       = 0x0005 | REQUEST_FLAGS,
    Query           = 0x0006 | REQUEST_FLAGS,
    PushData        = 0x0007 | REQUEST_FLAGS,
    Unsubscribe     = 0x0008 | REQUEST_FLAGS,
    Register        = 0x0009 | REQUEST_FLAGS,
    Unregister      = 0x000a | REQUEST_FLAGS,
    Discover        = 0x000b | REQUEST_FLAGS,
    Locate          = 0x000c | REQUEST_FLAGS,

    Status          = 0x0000 | RESPONSE_FLAGS,
    NoResult        = 0x0001 | RESPONSE_FLAGS,
    NodesFound      = 0x0002 | RESPONSE_FLAGS,
    ValuesFound     = 0x0003 | RESPONSE_FLAGS,
    PullData        = 0x0004 | RESPONSE_FLAGS,
}

impl TryFrom<Kind> for MessageKind {
    type Error = KindError;

    fn try_from(v: Kind) -> Result<Self, Self::Error> {
        // Check kind is message
        if (v.0 & kind_flags::KIND_MASK) != kind_flags::REQUEST_FLAGS
            && (v.0 & kind_flags::KIND_MASK) != kind_flags::RESPONSE_FLAGS {
            return Err(KindError::InvalidKind(v.0 & kind_flags::KIND_MASK));
        }
        
        // TODO: do not attempt to parse application specific kinds
        
        // Parse message kind
        match MessageKind::try_from(v.0) {
            Ok(v) => Ok(v),
            Err(_e) => {
                Err(KindError::InvalidKind(v.0 & kind_flags::KIND_MASK))
            }
        }
    }
}

impl Into<Kind> for MessageKind {
    fn into(self) -> Kind {
        Kind(self.into())
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

    // Message Kinds
    pub const REQUEST_FLAGS: u16 = 0b0010_0000_0000_0000;
    pub const RESPONSE_FLAGS: u16 = 0b0100_0000_0000_0000;

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
            (PageKind::Tertiary, Kind(0b0000_0000_0000_0011)),
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
            println!("message t: {:02x?}, v: {:#b}", t, v.0);
            assert_eq!(v.is_message(), true);
            let k: Kind = t.into();
            assert_eq!(v, k, "error converting {:02x?} into: {:02x?}", t, k);
            let d = MessageKind::try_from(v).expect("error parsing message kind");
            assert_eq!(t, d, "error decoding {:02x?}", t);
        }
    }

    #[test]
    fn test_data_kinds() {
        let tests = vec![(DataKind::Generic, Kind(0b0110_0000_0000_0000))];

        for (t, v) in tests {
            println!("data t: {:02x?}, v: {:#b}", t, v.0);
            assert_eq!(v.is_data(), true);
            let k: Kind = t.into();
            assert_eq!(v, k, "error converting {:02x?}", t);
            let d = DataKind::try_from(v).expect("error parsing data kind");
            assert_eq!(t, d, "error decoding {:02x?}", t);
        }
    }
}
