
use std::time::SystemTimeError;
use std::io::Error as IoError;

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

newtype_array!(pub struct Array64(pub 64));

/// Page Kinds.
/// 
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    None,
    Peer,
    Generic,
    Private,
    Other(u16),
}

pub mod kinds {
    pub const NONE    : u16 = 0x0000;
    pub const PEER    : u16 = 0x0001;
    pub const GENERIC : u16 = 0x0002;
    pub const PRIVATE : u16 = 0xFFFE;
}

impl From<u16> for Kind {
    fn from(val: u16) -> Kind {
        match val {
            kinds::NONE     => Kind::None,
            kinds::PEER     => Kind::Peer,
            kinds::GENERIC  => Kind::Generic,
            kinds::PRIVATE  => Kind::Private,
            _ => Kind::Other(val),
        }
    }
}

impl Into<u16> for Kind {
    fn into(self) -> u16 {
        match self {
            Kind::None      => kinds::NONE,
            Kind::Peer      => kinds::PEER,
            Kind::Generic   => kinds::GENERIC,
            Kind::Private   => kinds::PRIVATE,
            Kind::Other(v)  => v,
        }
    }
}


/// Page and Message Flags.
/// 
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Flags(pub(crate) u8);

pub mod flags {
    pub const NONE           : u8 = 0;
    pub const SECONDARY      : u8 = (1 << 0);
    pub const ENCRYPTED      : u8 = (1 << 1);
    pub const ADDRESSREQUEST : u8 = (1 << 2);
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
