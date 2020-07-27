use core::str;

#[cfg(feature = "alloc")]
use alloc::prelude::v1::*;

use byteorder::{ByteOrder, NetworkEndian};

use super::OptionsError;
use crate::base::{Encode, Parse};
use crate::types::DateTime;

impl Parse for String {
    type Output = String;
    type Error = OptionsError;

    fn parse<'a>(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let length = NetworkEndian::read_u16(&data[0..2]) as usize;
        let value = str::from_utf8(&data[2..2 + length]).unwrap().to_owned();

        Ok((value, length + 2))
    }
}

impl Encode for String {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let value = self.as_bytes();

        NetworkEndian::write_u16(&mut data[0..], value.len() as u16);
        &mut data[2..value.len() + 2].copy_from_slice(value);

        Ok(value.len() + 2)
    }
}

impl Parse for Vec<u8> {
    type Output = Vec<u8>;
    type Error = OptionsError;

    fn parse<'a>(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let length = NetworkEndian::read_u16(&data) as usize;
        let value = Vec::from(&data[2..2 + length]);

        Ok((value, length + 2))
    }
}

impl Encode for Vec<u8> {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[..], self.len() as u16);
        &mut data[2..self.len() + 2].copy_from_slice(self);

        Ok(self.len() + 2)
    }
}

impl Parse for DateTime {
    type Output = DateTime;
    type Error = OptionsError;

    fn parse<'a>(data: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        let raw = NetworkEndian::read_u64(&data[0..]);
        let when = DateTime::from_secs(raw);

        Ok((when, 10))
    }
}

impl Encode for DateTime {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[..], 8);
        let time_s = self.as_secs();

        NetworkEndian::write_u64(&mut data[2..], time_s);

        Ok(10)
    }
}
