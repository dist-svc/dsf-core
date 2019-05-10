
use std::time::SystemTimeError;
use std::io::Error as IoError;

use crate::protocol::base::BaseError;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Error {
    IO,
    Time,
    InvalidOption,
    InvalidOptionLength,
    InvalidPageLength,
    InvalidPageKind,
    InvalidMessageKind,
    CryptoError,
    UnexpectedPageType,
    UnexpectedServiceId,
    UnexpectedApplicationId,
    InvalidServiceVersion,
    NoPrivateKey,
    NoPublicKey,
    NoSignature,
    ExpectedPrimaryPage,
    ExpectedSecondaryPage,
    ExpectedDataObject,
    UnexpectedPeerId,
    NoPeerId,
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
    UnknownService,
    InvalidSignature,
    Base(BaseError),
    Timeout,
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Error {
        error!("io error: {}", e);
        Error::IO
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