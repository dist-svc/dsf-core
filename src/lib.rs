//#![feature(try_from)]
//#![feature(test)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "alloc", feature(alloc_prelude))]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

extern crate base64;
extern crate byteorder;
extern crate bytes;
extern crate rand;
extern crate sodiumoxide;
extern crate slice_ext;
extern crate async_trait;
extern crate managed;

#[cfg(feature = "serde")]
extern crate serde;

#[macro_use]
extern crate log;

#[macro_use]
extern crate bitflags;

#[cfg(feature = "std")]
extern crate chrono;

#[macro_use]
extern crate strum_macros;


pub mod types;

pub mod error;

pub mod crypto;

pub mod options;

pub mod base;

pub mod service;

pub mod wire;

pub mod page;

pub mod net;

#[cfg(feature = "std")]
pub mod api;

#[cfg(feature = "std")]
pub mod prelude;
