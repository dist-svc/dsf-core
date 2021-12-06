//! Error types for DSF Core

use std::convert::Infallible;
#[cfg(feature = "std")]
use std::io::Error as IoError;
#[cfg(feature = "std")]
use std::time::SystemTimeError;

/// Error enum represents possible core errors
/// 
/// For serialisation add `serde`, `thiserror`, `strum`, and/or `defmt` features
#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
#[cfg_attr(feature = "strum", derive(strum_macros::Display))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    UnsupportedSignatureMode,
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

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}