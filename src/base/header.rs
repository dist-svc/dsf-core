//! Header is a high level representation of the protocol header used in all DSF objects

use crate::types::{Flags, Kind};

/// Header object length
pub const HEADER_LEN: usize = 16;

/// Offsets for fixed fields in the protocol header
pub mod offsets {
    pub const PROTO_VERSION: usize = 0;
    pub const APPLICATION_ID: usize = 2;
    pub const OBJECT_KIND: usize = 4;
    pub const FLAGS: usize = 6;
    pub const INDEX: usize = 8;
    pub const DATA_LEN: usize = 10;
    pub const PRIVATE_OPTIONS_LEN: usize = 12;
    pub const PUBLIC_OPTIONS_LEN: usize = 14;
    pub const ID: usize = 16;
    pub const BODY: usize = 48;
}

/// Header encodes information for a given page in the database.
/// Wire encoding and decoding exists in `wire::header`
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Header {
    /// Protocol version
    pub protocol_version: u16,

    // Application ID
    pub application_id: u16,

    /// Object kind
    pub kind: Kind,

    /// Object flags
    pub flags: Flags,

    /// Index is the Page Version for Pages, or the Request ID for messages
    pub index: u16,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            protocol_version: 0,
            application_id: 0,
            kind: Kind(0),
            flags: Flags::default(),
            index: 0,
        }
    }
}

impl Header {
    pub fn new(application_id: u16, kind: Kind, index: u16, flags: Flags) -> Header {
        Header {
            protocol_version: 0,
            application_id,
            kind,
            flags,
            index,
        }
    }

    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn application_id(&self) -> u16 {
        self.application_id
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn index(&self) -> u16 {
        self.index
    }
}
