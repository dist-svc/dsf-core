use std::io::{Cursor, Write, Error as IoError};
use std::ops::Add;
use std::str;
use std::time::{SystemTime, Duration};

use byteorder::{ByteOrder, NetworkEndian, ReadBytesExt, WriteBytesExt};

use crate::protocol::{Encode, Parse};

impl Parse for String {
    type Output = String;
    type Error = IoError;

    fn parse<'a>(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut c = Cursor::new(data);

        let length = c.read_u16::<NetworkEndian>()? as usize;
        let value = str::from_utf8(&data[2..2 + length]).unwrap().to_owned();
        
        Ok((value, c.position() as usize))
    }
}

impl Encode for String {
    type Error = IoError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        let value = self.as_bytes();
        w.write_u16::<NetworkEndian>(value.len() as u16)?;
        w.write(value)?;

        Ok(w.position() as usize)
    }
}

impl Parse for Vec<u8> {
    type Output = Vec<u8>;
    type Error = IoError;

    fn parse<'a>(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut c = Cursor::new(data);

        let length = c.read_u16::<NetworkEndian>()? as usize;
        let value = Vec::from(&data[2..2 + length]);

        Ok((value, c.position() as usize))
    }
}

impl Encode for Vec<u8> {
    type Error = IoError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(8)?;
        w.write(self)?;

        Ok(w.position() as usize)
    }
}

impl Parse for SystemTime {
    type Output = SystemTime;
    type Error = IoError;

    fn parse<'a>(data: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut r = Cursor::new(data);

        let raw = r.read_u64::<NetworkEndian>()?;
        let duration = Duration::from_secs(raw);
        let when = SystemTime::UNIX_EPOCH.add(duration);

        Ok((when, r.position() as usize))
    }
}

impl Encode for SystemTime {
    type Error = IoError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(8)?;
        let time_ms = self.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        w.write_u64::<NetworkEndian>(time_ms.as_secs())?;

        Ok(w.position() as usize)
    }
}
