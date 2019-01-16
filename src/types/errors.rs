
use std::time::SystemTimeError;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    IO(IoErrorKind),
    Time,
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
    SendError,
    NoRequestId,
    InvalidMessageType,
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Error {
        Error::IO(e.kind())
    }
}
impl From<SystemTimeError> for Error {
    fn from(_e: SystemTimeError) -> Error {
        Error::Time
    }
}
