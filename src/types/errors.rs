
use std::time::SystemTimeError;
use std::io::Error as IoError;

use crate::base::BaseError;
use crate::options::OptionsError;

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
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
    UnexpectedPageKind,
    NoReplicasFound,
    UnknownPeer,
    Base(BaseError),
    Options(OptionsError),
    Timeout, 
    Unknown,
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
impl From<OptionsError> for Error {
    fn from(e: OptionsError) -> Error {
        Error::Options(e)
    }
}