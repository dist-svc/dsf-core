
use std::time::SystemTimeError;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use crate::protocol::base::BaseError;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    IO(IoErrorKind),
    Time,
    InvalidOption,
    InvalidOptionLength,
    InvalidPageLength,
    InvalidPageKind,
    InvalidMessageKind,
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
    InvalidJson,
    NoPeersFound,
    NotFound,
    InvalidResponse,
    InvalidSignature,
    Base(BaseError),
    Timeout,
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

impl From<BaseError> for Error {
    fn from(e: BaseError) -> Error {
        Error::Base(e)
    }
}