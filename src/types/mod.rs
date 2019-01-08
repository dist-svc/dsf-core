
use std::time::SystemTimeError;
use std::io::Error as IoError;
use std::net::SocketAddr;

pub const ID_LEN: usize = 32;
pub type Id = [u8; ID_LEN];

pub const REQUEST_ID_LEN: usize = 8;
pub type RequestId = [u8; REQUEST_ID_LEN];

pub const PUBLIC_KEY_LEN: usize = 32;
pub type PublicKey = [u8; PUBLIC_KEY_LEN];

pub const PRIVATE_KEY_LEN: usize = 64;
pub type PrivateKey = [u8; PRIVATE_KEY_LEN];

pub const SIGNATURE_LEN: usize = 64;
//pub struct Signature([u8; SIGNATURE_LEN]);
pub type Signature = Array64<u8>;

pub const SECRET_KEY_LEN: usize = 32;
pub type SecretKey = [u8; SECRET_KEY_LEN];

pub const HASH_LEN: usize = 32;
pub type Hash = [u8; HASH_LEN];

pub const ENCRYPTED_META_LEN: usize = 64;
pub type EncryptedMeta = Array64<u8>;

pub type Address = SocketAddr;

newtype_array!(pub struct Array64(pub 64));

/// Page Kinds.
/// 
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    // Pages
    None,
    Peer,
    Generic,
    Private,
    Other(u16),

    // Messages
    Ping,
    FindNodes,
    FindValues,
    Store,
    NodesFound,
    ValuesFound,
    NoResult,
}

pub mod kinds {
    pub const NONE          : u16 = 0x0000;

    // Page Kinds
    pub const PEER          : u16 = 0x0001;
    pub const GENERIC       : u16 = 0x0002;
    pub const PRIVATE       : u16 = 0x0FFF;

    // Message Kinds
    pub const PING          : u16 = 0x8000;
    pub const FIND_NODES    : u16 = 0x8001;
    pub const FIND_VALUES   : u16 = 0x8002;
    pub const STORE         : u16 = 0x8003;
    pub const NODES_FOUND   : u16 = 0x8004;
    pub const VALUES_FOUND  : u16 = 0x8005;
    pub const NO_RESULT     : u16 = 0x8006;
}

impl From<u16> for Kind {
    fn from(val: u16) -> Kind {
        match val {
            kinds::NONE         => Kind::None,
            kinds::PEER         => Kind::Peer,
            kinds::GENERIC      => Kind::Generic,
            kinds::PRIVATE      => Kind::Private,
            kinds::PING         => Kind::Ping,
            kinds::FIND_NODES   => Kind::FindNodes,
            kinds::FIND_VALUES  => Kind::FindValues,
            kinds::STORE        => Kind::Store,
            kinds::NODES_FOUND  => Kind::NodesFound,
            kinds::VALUES_FOUND => Kind::ValuesFound,
            kinds::NO_RESULT    => Kind::NoResult,
            _ => {
                if val & 0x8000 == 0 {
                    Kind::Other(val)
                } else {
                    Kind::None
                }
            },
        }
    }
}

impl Into<u16> for Kind {
    fn into(self) -> u16 {
        match self {
            Kind::None          => kinds::NONE,
            Kind::Peer          => kinds::PEER,
            Kind::Generic       => kinds::GENERIC,
            Kind::Private       => kinds::PRIVATE,
            Kind::Other(v)      => v,

            Kind::Ping          => kinds::PING,
            Kind::FindNodes     => kinds::FIND_NODES,
            Kind::FindValues    => kinds::FIND_VALUES,
            Kind::Store         => kinds::STORE,
            Kind::NodesFound    => kinds::NODES_FOUND,
            Kind::ValuesFound   => kinds::VALUES_FOUND,
            Kind::NoResult      => kinds::NO_RESULT,
        }
    }
}


/// Page and Message Flags.
/// 
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Flags(pub(crate) u8);

pub mod flags {
    pub const NONE            : u8 = 0;
    pub const SECONDARY       : u8 = (1 << 0);
    pub const ENCRYPTED       : u8 = (1 << 1);
    pub const ADDRESS_REQUEST : u8 = (1 << 2);
}

impl Flags {
    pub fn encrypted(&self) -> bool {
        self.0 & flags::ENCRYPTED as u8 != 0
    }

    pub fn set_encrypted(&mut self, encrypted: bool) {
        match encrypted {
            true => self.0 |= flags::ENCRYPTED as u8,
            false => self.0 &= !(flags::ENCRYPTED as u8)
        };
    }

    pub fn secondary(&self) -> bool {
        self.0 & flags::SECONDARY as u8 != 0
    }

    pub fn set_secondary(&mut self, secondary: bool) {
        match secondary {
            true => self.0 |= flags::SECONDARY as u8,
            false => self.0 &= !(flags::SECONDARY as u8)
        };
    }

    pub fn address_request(&self) -> bool {
        self.0 & flags::ADDRESS_REQUEST as u8 != 0
    }

    pub fn set_address_request(&mut self, address_request: bool) {
        match address_request {
            true => self.0 |= flags::ADDRESS_REQUEST as u8,
            false => self.0 &= !(flags::ADDRESS_REQUEST as u8)
        };
    }
}

impl Default for Flags {
    fn default() -> Flags {
        Flags(0)
    }
}

impl From<u8> for Flags {
    fn from(v: u8) -> Flags {
        Flags(v)
    }
}

impl Into<u8> for Flags {
    fn into(self) -> u8 {
        self.0
    }
}

#[derive(Debug)]
pub enum Error {
    IO(IoError),
    Time(SystemTimeError),
    InvalidOption,
    InvalidOptionLength,
    InvalidPageLength,
    InvalidPageKind,
    CryptoError,
    UnexpectedPageType,
    UnexpectedServiceId,
    InvalidServiceVersion,
    NoPrivateKey,
    NoPublicKey,
    ExpectedPrimaryPage,
    KeyIdMismatch,
    PublicKeyChanged,
    Unimplemented,
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Error {
        Error::IO(e)
    }
}
impl From<SystemTimeError> for Error {
    fn from(e: SystemTimeError) -> Error {
        Error::Time(e)
    }
}
