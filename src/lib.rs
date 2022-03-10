#![cfg_attr(not(feature = "std"), no_std)]

#![feature(test)]
#![feature(const_generics_defaults)]
#![feature(generic_associated_types)]
#![feature(associated_type_defaults)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

#[cfg(feature = "libc")]
extern crate libc;

#[cfg(feature = "cty")]
extern crate cty as libc;

extern crate async_trait;
extern crate base64;
extern crate byteorder;
extern crate bytes;
extern crate managed;
extern crate slice_ext;

#[cfg(feature = "serde")]
extern crate serde;

#[macro_use]
extern crate log;

#[macro_use]
extern crate bitflags;

#[cfg(feature = "std")]
extern crate chrono;

pub mod types;

pub mod error;

pub mod crypto;

pub mod options;

pub mod base;

pub mod service;

pub mod wire;

pub mod page;

pub mod net;

pub mod keys;

pub mod api;

pub mod prelude;
