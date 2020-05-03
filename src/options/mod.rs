//! Options are used to support extension of protocol objects
//! with DSF and application-specific optional fields.

use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str;

use byteorder::{ByteOrder, NetworkEndian, ReadBytesExt, WriteBytesExt};

use crate::base::{Encode, Parse};
use crate::types::{
    DateTime, Id, ImmutableData, PublicKey, Signature, ID_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};

mod helpers;

/// DSF defined options fields
#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum Options {
    None,
    PubKey(PubKey),
    PeerId(PeerId),
    PrevSig(PrevSig),
    Kind(Kind),
    Name(Name),
    IPv4(SocketAddrV4),
    IPv6(SocketAddrV6),
    Issued(Issued),
    Expiry(Expiry),
    Limit(Limit),
    Metadata(Metadata),
}

/// Generic list of options over generic buffers
#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum OptionsList<C: AsRef<[Options]>, E: ImmutableData> {
    Cleartext(C),
    Encrypted(E),
    None,
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum OptionsError {
    IO,
    InvalidMetadata,
    InvalidOptionLength,
    InvalidOptionKind,
    Unimplemented,
}

impl From<std::io::Error> for OptionsError {
    fn from(e: std::io::Error) -> OptionsError {
        error!("io error: {}", e);
        OptionsError::IO
    }
}

pub struct OptionsIter<T> {
    index: usize,
    buff: T,
}

impl<T> OptionsIter<T>
where
    T: AsRef<[u8]>,
{
    pub(crate) fn new(buff: T) -> Self {
        Self { index: 0, buff }
    }
}

impl<T> Iterator for OptionsIter<T>
where
    T: AsRef<[u8]>,
{
    type Item = Options;

    fn next(&mut self) -> Option<Options> {
        // Fetch remaining data
        let rem = &self.buff.as_ref()[self.index..];

        // Short circuit if we're too short
        if rem.len() < OPTION_HEADER_LEN {
            return None;
        }

        let (o, n) = match Options::parse(&rem) {
            Ok(v) => v,
            Err(e) => {
                error!("Option parsing error: {:?}", e);
                return None;
            }
        };

        self.index += n;

        Some(o)
    }
}

/// D-IoT Option kind identifiers
pub mod option_kinds {
    pub const PUBKEY: u16 = 0x0000; // Public Key
    pub const PEER_ID: u16 = 0x0001; // ID of Peer responsible for secondary page
    pub const PREV_SIG: u16 = 0x0002; // Previous object signature
    pub const KIND: u16 = 0x0003; // Service KIND in utf-8
    pub const NAME: u16 = 0x0004; // Service NAME in utf-8
    pub const ADDR_IPV4: u16 = 0x0005; // IPv4 service address
    pub const ADDR_IPV6: u16 = 0x0006; // IPv6 service address
    pub const ISSUED: u16 = 0x0007; // ISSUED option defines object creation time
    pub const EXPIRY: u16 = 0x0008; // EXPIRY option defines object expiry time
    pub const LIMIT: u16 = 0x0009; // LIMIT option defines maximum number of objects to return
    pub const META: u16 = 0x000a; // META option supports generic metadata key:value pairs

    pub const APP: u16 = 0x8000; // APP flag indictates option is application specific and should not be parsed here
}

/// Option header length
const OPTION_HEADER_LEN: usize = 4;

impl Options {
    /// Parse a bounded list of options into a vector
    pub fn parse_vec(data: &[u8]) -> Result<(Vec<Options>, usize), OptionsError> {
        let mut options = Vec::new();
        let mut rem = &data[..];
        let mut i = 0;

        while rem.len() >= OPTION_HEADER_LEN {
            let (o, n) = Options::parse(&rem)?;
            i += n;

            options.push(o);
            rem = &data[i..];
        }

        Ok((options, i))
    }

    /// Encode a vector of options
    pub fn encode_vec(options: &[Options], data: &mut [u8]) -> Result<usize, OptionsError> {
        let mut i = 0;

        for o in options.iter() {
            i += o.encode(&mut data[i..])?;
        }

        Ok(i)
    }
}

impl Options {
    // Helper to generate name metadata
    pub fn name(value: &str) -> Options {
        Options::Name(Name::new(value))
    }

    pub fn kind(value: &str) -> Options {
        Options::Kind(Kind::new(value))
    }

    pub fn prev_sig(value: &Signature) -> Options {
        Options::PrevSig(PrevSig::new(value.clone()))
    }

    pub fn meta(key: &str, value: &str) -> Options {
        Options::Metadata(Metadata::new(key, value))
    }

    pub fn issued<T>(now: T) -> Options
    where
        T: Into<DateTime>,
    {
        Options::Issued(Issued::new(now))
    }

    pub fn expiry<T>(when: T) -> Options
    where
        T: Into<DateTime>,
    {
        Options::Expiry(Expiry::new(when))
    }

    pub fn peer_id(id: Id) -> Options {
        Options::PeerId(PeerId::new(id))
    }

    pub fn public_key(public_key: PublicKey) -> Options {
        Options::PubKey(PubKey::new(public_key))
    }

    pub fn address<T>(address: T) -> Options
    where
        T: Into<SocketAddr>,
    {
        match address.into() {
            SocketAddr::V4(v4) => Options::IPv4(v4),
            SocketAddr::V6(v6) => Options::IPv6(v6),
        }
    }

    pub fn pub_key(public_key: PublicKey) -> Options {
        Options::PubKey(PubKey::new(public_key))
    }
}

/// Parse parses a control option from the given scope
impl Parse for Options {
    type Output = Options;
    type Error = OptionsError;

    fn parse<'a>(data: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        if data.len() < OPTION_HEADER_LEN {
            return Err(OptionsError::InvalidOptionLength);
        }

        let option_kind = NetworkEndian::read_u16(&data[0..2]);
        let option_len = NetworkEndian::read_u16(&data[2..4]) as usize;

        let d = &data[OPTION_HEADER_LEN..OPTION_HEADER_LEN + option_len];

        match option_kind {
            option_kinds::PUBKEY => {
                let (opt, n) = PubKey::parse(d)?;
                Ok((Options::PubKey(opt), n + OPTION_HEADER_LEN))
            }
            option_kinds::PEER_ID => {
                let (opt, n) = PeerId::parse(d)?;
                Ok((Options::PeerId(opt), n + OPTION_HEADER_LEN))
            }
            option_kinds::PREV_SIG => {
                let (opt, n) = PrevSig::parse(d)?;
                Ok((Options::PrevSig(opt), n + OPTION_HEADER_LEN))
            }
            option_kinds::KIND => {
                let (opt, n) = Kind::parse(d)?;
                Ok((Options::Kind(opt), n + OPTION_HEADER_LEN))
            }
            option_kinds::NAME => {
                let (opt, n) = Name::parse(d)?;
                Ok((Options::Name(opt), n + OPTION_HEADER_LEN))
            }
            option_kinds::ADDR_IPV4 => {
                let (opt, n) = SocketAddrV4::parse(d)?;
                Ok((Options::IPv4(opt), n + OPTION_HEADER_LEN))
            }
            option_kinds::ADDR_IPV6 => {
                let (opt, n) = SocketAddrV6::parse(d)?;
                Ok((Options::IPv6(opt), n + OPTION_HEADER_LEN))
            }
            option_kinds::META => {
                let (opt, n) = Metadata::parse(d)?;
                Ok((Options::Metadata(opt), n + OPTION_HEADER_LEN))
            }
            option_kinds::ISSUED => {
                let (opt, n) = Issued::parse(d)?;
                Ok((Options::Issued(opt), n + OPTION_HEADER_LEN))
            }
            option_kinds::EXPIRY => {
                let (opt, n) = Expiry::parse(d)?;
                Ok((Options::Expiry(opt), n + OPTION_HEADER_LEN))
            }
            option_kinds::LIMIT => {
                let (opt, n) = Limit::parse(d)?;
                Ok((Options::Limit(opt), n + OPTION_HEADER_LEN))
            }
            _ => {
                // Unrecognised option types (and None) are skipped
                Ok((Options::None, OPTION_HEADER_LEN + option_len))
            }
        }
    }
}

impl Encode for Options {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        match *self {
            Options::PubKey(ref o) => Ok(o.encode(data)?),
            Options::PeerId(ref o) => Ok(o.encode(data)?),
            Options::PrevSig(ref o) => Ok(o.encode(data)?),
            Options::Kind(ref o) => Ok(o.encode(data)?),
            Options::Name(ref o) => Ok(o.encode(data)?),
            Options::IPv4(ref o) => Ok(o.encode(data)?),
            Options::IPv6(ref o) => Ok(o.encode(data)?),
            Options::Metadata(ref o) => Ok(o.encode(data)?),
            Options::Issued(ref o) => Ok(o.encode(data)?),
            Options::Expiry(ref o) => Ok(o.encode(data)?),
            Options::Limit(ref o) => Ok(o.encode(data)?),
            _ => {
                println!("Option encoding not implemented for object {:?}", *self);
                unimplemented!();
            }
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PubKey {
    pub public_key: PublicKey,
}

impl PubKey {
    pub fn new(public_key: PublicKey) -> PubKey {
        PubKey { public_key }
    }
}

impl Parse for PubKey {
    type Output = PubKey;
    type Error = OptionsError;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(&data[..PUBLIC_KEY_LEN]);

        Ok((
            PubKey {
                public_key: public_key.into(),
            },
            PUBLIC_KEY_LEN,
        ))
    }
}

impl Encode for PubKey {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(option_kinds::PUBKEY)?;
        w.write_u16::<NetworkEndian>(PUBLIC_KEY_LEN as u16)?;
        w.write_all(&self.public_key)?;

        Ok(w.position() as usize)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PeerId {
    pub peer_id: Id,
}

impl PeerId {
    pub fn new(peer_id: Id) -> PeerId {
        PeerId { peer_id }
    }
}

impl Parse for PeerId {
    type Output = PeerId;
    type Error = OptionsError;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut peer_id = [0u8; ID_LEN];
        peer_id.copy_from_slice(&data[..ID_LEN]);
        Ok((
            PeerId {
                peer_id: peer_id.into(),
            },
            ID_LEN,
        ))
    }
}

impl Encode for PeerId {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(option_kinds::PEER_ID)?;
        w.write_u16::<NetworkEndian>(ID_LEN as u16)?;
        w.write_all(&self.peer_id)?;

        Ok(w.position() as usize)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrevSig {
    pub sig: Signature,
}

impl PrevSig {
    pub fn new(sig: Signature) -> Self {
        Self { sig }
    }
}

impl Parse for PrevSig {
    type Output = Self;
    type Error = OptionsError;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut sig = [0u8; SIGNATURE_LEN];
        sig.copy_from_slice(&data[..SIGNATURE_LEN]);
        Ok((Self { sig: sig.into() }, SIGNATURE_LEN))
    }
}

impl Encode for PrevSig {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(option_kinds::PREV_SIG)?;
        w.write_u16::<NetworkEndian>(SIGNATURE_LEN as u16)?;
        w.write_all(&self.sig)?;

        Ok(w.position() as usize)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Kind {
    value: String,
}

impl Kind {
    pub fn new(value: &str) -> Kind {
        Kind {
            value: value.to_owned(),
        }
    }
}

impl Parse for Kind {
    type Output = Kind;
    type Error = OptionsError;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let value = str::from_utf8(&data).unwrap().to_owned();

        Ok((Kind { value }, data.len()))
    }
}

impl Encode for Kind {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(option_kinds::KIND)?;
        w.write_u16::<NetworkEndian>(self.value.len() as u16)?;
        w.write_all(self.value.as_bytes())?;

        Ok(w.position() as usize)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Name {
    value: String,
}

impl Name {
    pub fn new(value: &str) -> Name {
        Name {
            value: value.to_owned(),
        }
    }
}

impl Parse for Name {
    type Output = Name;
    type Error = OptionsError;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let value = str::from_utf8(&data).unwrap().to_owned();

        Ok((Name { value }, data.len()))
    }
}

impl Encode for Name {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(option_kinds::NAME)?;
        w.write_u16::<NetworkEndian>(self.value.len() as u16)?;
        w.write_all(self.value.as_bytes())?;

        Ok(w.position() as usize)
    }
}

impl Parse for SocketAddrV4 {
    type Output = SocketAddrV4;
    type Error = OptionsError;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut r = Cursor::new(data);

        let mut ip = [0u8; 4];
        r.read_exact(&mut ip)?;
        let port = r.read_u16::<NetworkEndian>()?;

        Ok((SocketAddrV4::new(ip.into(), port), data.len()))
    }
}

impl Encode for SocketAddrV4 {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(option_kinds::ADDR_IPV4)?;
        w.write_u16::<NetworkEndian>(6)?;
        w.write_all(&self.ip().octets())?;
        w.write_u16::<NetworkEndian>(self.port())?;

        Ok(w.position() as usize)
    }
}

impl Parse for SocketAddrV6 {
    type Output = SocketAddrV6;
    type Error = OptionsError;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut r = Cursor::new(data);

        let mut ip = [0u8; 16];
        r.read_exact(&mut ip)?;
        let port = r.read_u16::<NetworkEndian>()?;

        Ok((SocketAddrV6::new(ip.into(), port, 0, 0), data.len()))
    }
}

impl Encode for SocketAddrV6 {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(option_kinds::ADDR_IPV6)?;
        w.write_u16::<NetworkEndian>(18)?;
        w.write_all(&self.ip().octets())?;
        w.write_u16::<NetworkEndian>(self.port())?;

        Ok(w.position() as usize)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Metadata {
    key: String,
    value: String,
}

impl Metadata {
    pub fn new(key: &str, value: &str) -> Metadata {
        Metadata {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }
}

impl Parse for Metadata {
    type Output = Metadata;
    type Error = OptionsError;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let kv = str::from_utf8(&data).unwrap().to_owned();
        let split: Vec<_> = kv.split("|").collect();
        if split.len() != 2 {
            return Err(OptionsError::InvalidMetadata);
        }

        Ok((
            Metadata {
                key: split[0].to_owned(),
                value: split[1].to_owned(),
            },
            data.len(),
        ))
    }
}

impl Encode for Metadata {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        let data = format!("{}|{}", self.key, self.value);

        w.write_u16::<NetworkEndian>(option_kinds::META)?;
        w.write_u16::<NetworkEndian>(data.len() as u16)?;
        w.write_all(data.as_bytes())?;

        Ok(w.position() as usize)
    }
}

impl From<Metadata> for Options {
    fn from(m: Metadata) -> Options {
        Options::Metadata(m)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Issued {
    pub when: DateTime,
}

impl Issued {
    pub fn new<T>(when: T) -> Issued
    where
        T: Into<DateTime>,
    {
        Issued { when: when.into() }
    }
}

impl Parse for Issued {
    type Output = Issued;
    type Error = OptionsError;
    fn parse<'a>(data: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut r = Cursor::new(data);

        let raw = r.read_u64::<NetworkEndian>()?;
        let when = DateTime::from_secs(raw);

        Ok((Issued { when }, r.position() as usize))
    }
}

impl Encode for Issued {
    type Error = OptionsError;
    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(option_kinds::ISSUED)?;
        w.write_u16::<NetworkEndian>(8)?;

        w.write_u64::<NetworkEndian>(self.when.as_secs())?;

        Ok(w.position() as usize)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Expiry {
    pub when: DateTime,
}

impl Expiry {
    pub fn new<T>(when: T) -> Expiry
    where
        T: Into<DateTime>,
    {
        Expiry { when: when.into() }
    }
}

impl Parse for Expiry {
    type Output = Expiry;
    type Error = OptionsError;
    fn parse<'a>(data: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut r = Cursor::new(data);

        let raw = r.read_u64::<NetworkEndian>()?;
        let when = DateTime::from_secs(raw);

        Ok((Expiry { when }, r.position() as usize))
    }
}

impl Encode for Expiry {
    type Error = OptionsError;
    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(option_kinds::EXPIRY)?;
        w.write_u16::<NetworkEndian>(8)?;

        w.write_u64::<NetworkEndian>(self.when.as_secs())?;

        Ok(w.position() as usize)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Limit {
    pub n: u32,
}

impl Limit {
    pub fn new(n: u32) -> Self {
        Self { n }
    }
}

impl Parse for Limit {
    type Output = Self;
    type Error = OptionsError;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        Ok((
            Self {
                n: NetworkEndian::read_u32(data),
            },
            4,
        ))
    }
}

impl Encode for Limit {
    type Error = OptionsError;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let mut w = Cursor::new(data);

        w.write_u16::<NetworkEndian>(option_kinds::LIMIT)?;
        w.write_u16::<NetworkEndian>(4)?;
        w.write_u32::<NetworkEndian>(self.n)?;

        Ok(w.position() as usize)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::SystemTime;

    #[test]
    fn encode_decode_option_types() {
        let tests = [
            Options::PubKey(PubKey::new([1u8; PUBLIC_KEY_LEN].into())),
            Options::PeerId(PeerId::new([2u8; ID_LEN].into())),
            Options::Kind(Kind::new("test-kind")),
            Options::Name(Name::new("test-name")),
            Options::IPv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            Options::IPv6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                8080,
                0,
                0,
            )),
            Options::Metadata(Metadata::new("test-key", "test-value")),
            Options::Issued(Issued::new(SystemTime::now())),
            Options::Expiry(Expiry::new(SystemTime::now())),
            Options::Limit(Limit::new(13)),
        ];

        for o in tests.iter() {
            let mut data = vec![0u8; 1024];
            let n1 = o
                .encode(&mut data)
                .expect(&format!("Error encoding {:?}", o));

            let (decoded, n2) = Options::parse(&data).expect(&format!("Error decoding {:?}", o));

            assert_eq!(
                n1, n2,
                "Mismatch between encoded and decoded lengths for object: {:?}",
                o
            );
            assert_eq!(o, &decoded, "Mismatch between original and decode objects");
        }
    }

    #[test]
    fn encode_decode_option_list() {
        let tests = vec![
            Options::PubKey(PubKey::new([1u8; PUBLIC_KEY_LEN].into())),
            Options::PeerId(PeerId::new([2u8; ID_LEN].into())),
            Options::PrevSig(PrevSig::new([3u8; SIGNATURE_LEN].into())),
            Options::Kind(Kind::new("test-kind")),
            Options::Name(Name::new("test-name")),
            Options::IPv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            Options::IPv6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                8080,
                0,
                0,
            )),
            Options::Metadata(Metadata::new("test-key", "test-value")),
            Options::Issued(Issued::new(SystemTime::now())),
            Options::Expiry(Expiry::new(SystemTime::now())),
        ];

        let mut data = vec![0u8; 1024];
        let n1 = Options::encode_vec(&tests, &mut data).expect("Error encoding options vector");

        let encoded = &data[0..n1];
        let (decoded, n2) = Options::parse_vec(encoded).expect("Error decoding options vector");

        assert_eq!(n1, n2, "Mismatch between encoded and decoded length");
        assert_eq!(
            &tests, &decoded,
            "Mismatch between original and decode vectors"
        );
    }
}
