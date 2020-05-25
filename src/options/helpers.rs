use core::ops::Add;
use core::str;

use std::io::{Cursor, Error as IoError, Write};
use std::time::{Duration, SystemTime};

use byteorder::{ByteOrder, NetworkEndian, ReadBytesExt, WriteBytesExt};

use crate::base::{Encode, Parse};

impl Parse for String {
    type Output = String;
    type Error = IoError;

    fn parse<'a>(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let length = NetworkEndian::read_u16(&data[0..2]) as usize;
        let value = str::from_utf8(&data[2..2 + length]).unwrap().to_owned();

        Ok((value, length + 2))
    }
}

impl Encode for String {
    type Error = IoError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let value = self.as_bytes();

        NetworkEndian::write_u16(&mut data[0..], value.len() as u16);
        &mut data[2..value.len() + 2].copy_from_slice(value);

        Ok(value.len() + 2)
    }
}

impl Parse for Vec<u8> {
    type Output = Vec<u8>;
    type Error = IoError;

    fn parse<'a>(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let length = NetworkEndian::read_u16(&data) as usize;
        let value = Vec::from(&data[2..2 + length]);

        Ok((value, length + 2))
    }
}

impl Encode for Vec<u8> {
    type Error = IoError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {

        NetworkEndian::write_u16(&mut data, self.len() as u16);
        &mut data[2..self.len()+2].copy_from_slice(self);

        Ok(self.len() + 2)
    }
}

impl Parse for SystemTime {
    type Output = SystemTime;
    type Error = IoError;

    fn parse<'a>(data: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut r = Cursor::new(data);

        let raw = NetworkEndian::read_u64(&data[0..]);
        let duration = Duration::from_secs(raw);
        let when = SystemTime::UNIX_EPOCH.add(duration);

        Ok((when, 10))
    }
}

impl Encode for SystemTime {
    type Error = IoError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        NetworkEndian::write_u16(&mut data[..], 8);
        let time_ms = self.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        NetworkEndian::write_u64(&mut data[2..], time_ms.as_secs());

        Ok(10)
    }
}
