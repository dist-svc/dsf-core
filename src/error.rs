#[cfg(feature = "std")]
use std::io::Error as IoError;
#[cfg(feature = "std")]
use std::time::SystemTimeError;

use strum_macros::Display;

#[derive(PartialEq, Debug, Clone, Display)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
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
    NoSecretKey,
    SecretKeyMismatch,
    NoSymmetricKeys,
    Timeout,
    Unknown,
}

#[cfg(feature = "std")]
impl From<IoError> for Error {
    fn from(e: IoError) -> Error {
        error!("io error: {}", e);
        Error::IO
    }
}

#[cfg(feature = "std")]
impl From<SystemTimeError> for Error {
    fn from(_e: SystemTimeError) -> Error {
        Error::Time
    }
}
