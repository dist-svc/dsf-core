//! Options are used to support extension of protocol objects
//! with DSF and application-specific optional fields.
 
use core::convert::TryFrom;
use core::fmt::Debug;

use num_enum::{IntoPrimitive, TryFromPrimitive};

#[cfg(feature = "alloc")]
use alloc::vec::{Vec};

use byteorder::{ByteOrder, NetworkEndian};

use crate::base::{Encode, Parse};
use crate::error::Error;
use crate::types::{Address, AddressV4, AddressV6, DateTime, ID_LEN, Id, Ip, PUBLIC_KEY_LEN, PublicKey, Queryable, SIGNATURE_LEN, Signature, ImmutableData};

mod helpers;

/// DSF defined options fields
#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Options {
    None,
    PubKey(PubKey),
    PeerId(PeerId),
    PrevSig(PrevSig),
    Kind(Kind),
    Name(Name),

    IPv4(AddressV4),
    IPv6(AddressV6),

    Issued(Issued),
    Expiry(Expiry),
    Limit(Limit),
    Metadata(Metadata),
    Coord(Coordinates),
}

pub struct OptionsIter<T> {
    index: usize,
    buff: T,
}

impl <T: ImmutableData> core::fmt::Debug for OptionsIter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = OptionsIter::new(&self.buff);
        f.debug_list().entries(i).finish()
    }
}

impl <T: ImmutableData + Clone> Clone for OptionsIter<T> {
    fn clone(&self) -> Self {
        Self { index: 0, buff: self.buff.clone() }
    }
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

/// Filter helpers for option iterators
pub trait Filters {
    fn pub_key(&self) -> Option<PublicKey>;
    fn peer_id(&self) -> Option<Id>;
    fn issued(&self) -> Option<DateTime>;
    fn expiry(&self) -> Option<DateTime>;
    fn prev_sig(&self) -> Option<Signature>;
    fn address(&self) -> Option<Address>;
    fn name(&self) -> Option<Name>;
}

impl <'a, T: Iterator<Item=&'a Options> + Clone> Filters for T {
    fn pub_key(&self) -> Option<PublicKey> {
        self.clone().find_map(|o| match o {
            Options::PubKey(pk) => Some(pk.public_key.clone()),
            _ => None,
        })
    }

    fn peer_id(&self) -> Option<Id> {
        self.clone().find_map(|o| match o {
            Options::PeerId(peer_id) => Some(peer_id.peer_id.clone()),
            _ => None,
        })
    }

    fn issued(&self) -> Option<DateTime> {
        self.clone().find_map(|o| match o {
            Options::Issued(t) => Some(t.when),
            _ => None,
        })
    }

    fn expiry(&self) -> Option<DateTime> {
        self.clone().find_map(|o| match o {
            Options::Expiry(t) => Some(t.when),
            _ => None,
        })
    }

    fn prev_sig(&self) -> Option<Signature> {
        self.clone().find_map(|o| match o {
            Options::PrevSig(s) => Some(s.sig.clone()),
            _ => None,
        })
    }

    fn name(&self) -> Option<Name> {
        self.clone().find_map(|o| match o {
            Options::Name(name) => Some(name.clone()),
            _ => None,
        })
    }

    fn address(&self) -> Option<Address> {
        self.clone().find_map(|o| match o {
            Options::IPv4(addr) => Some(addr.clone().into()),
            Options::IPv6(addr) => Some(addr.clone().into()),
            _ => None,
        })
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
    pub const BUILDING: u16 = 0x000b; // Building name / number (string)
    pub const ROOM: u16 = 0x000c;     // Room name / number (string)
    pub const COORD: u16 = 0x000d;    // Coordinates (lat, lng, alt)
    pub const APP: u16 = 0x8000; // APP flag indicates option is application specific and should not be parsed here
}

#[derive(PartialEq, Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "strum_macros", derive(strum_macros::EnumString, strum_macros::Display))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u16)]
pub enum OptionKind {
    PubKey      = 0x0000,   // Public Key
    PeerId      = 0x0001,   // ID of Peer responsible for secondary page
    PrevSig     = 0x0002,   // Previous object signature
    Kind        = 0x0003,   // Service KIND in utf-8
    Name        = 0x0004,   // Service NAME in utf-8
    IpAddrV4    = 0x0005,   // IPv4 service address
    IpAddrV6    = 0x0006,   // IPv6 service address
    Issued      = 0x0007,   // ISSUED option defines object creation time
    Expiry      = 0x0008,   // EXPIRY option defines object expiry time
    Limit       = 0x0009,   // LIMIT option defines maximum number of objects to return
    Meta        = 0x000a,   // META option supports generic metadata key:value pairs
    Building    = 0x000b,   // Building name / number (string)
    Room        = 0x000c,   // Room name / number (string)
    Coord       = 0x000d,   // Coordinates (lat, lng, alt)
}


/// Option header length
const OPTION_HEADER_LEN: usize = 4;

impl Options {
    /// Parse a bounded list of options into a vector
    pub fn parse_vec(data: &[u8]) -> Result<(Vec<Options>, usize), Error> {
        let mut options = Vec::new();
        let mut rem = &data[..];
        let mut i = 0;

        while rem.len() >= OPTION_HEADER_LEN {
            trace!("Parse option {} at offset {}", options.len(), i);

            let (o, n) = Options::parse(&rem)?;
            i += n;

            options.push(o);
            rem = &data[i..];
        }

        Ok((options, i))
    }

    /// Encode a vector of options
    pub fn encode_iter<O: AsRef<[Options]>>(options: O, data: &mut [u8]) -> Result<usize, Error> {
        let mut i = 0;

        for o in options.as_ref() {
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

    pub fn issued<T: Into<DateTime>>(now: T) -> Options {
        Options::Issued(Issued::new(now))
    }

    pub fn expiry<T: Into<DateTime>>(when: T) -> Options {
        Options::Expiry(Expiry::new(when))
    }

    pub fn peer_id(id: Id) -> Options {
        Options::PeerId(PeerId::new(id))
    }

    pub fn public_key(public_key: PublicKey) -> Options {
        Options::PubKey(PubKey::new(public_key))
    }

    pub fn address<T: Into<Address>>(address: T) -> Options {
        let addr: Address = address.into();

        match addr.ip {
            Ip::V4(ip) => Options::IPv4(AddressV4::new(ip, addr.port)),
            Ip::V6(ip) => Options::IPv6(AddressV6::new(ip, addr.port)),
        }
    }

    pub fn address_v4<T: Into<AddressV4>>(address: T) -> Options {
        Options::IPv4(address.into())
    }

    pub fn address_v6<T: Into<AddressV6>>(address: T) -> Options {
        Options::IPv6(address.into())
    }

    pub fn pub_key(public_key: PublicKey) -> Options {
        Options::PubKey(PubKey::new(public_key))
    }
}

/// Parse parses a control option from the given scope
impl Parse for Options {
    type Output = Options;
    type Error = Error;

    fn parse<'a>(data: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        if data.len() < OPTION_HEADER_LEN {
            return Err(Error::InvalidOptionLength);
        }

        trace!("Parse option header: {:02x?}", &data[0..4]);

        let option_kind = NetworkEndian::read_u16(&data[0..2]);
        let option_len = NetworkEndian::read_u16(&data[2..4]) as usize;

        let d = &data[OPTION_HEADER_LEN..OPTION_HEADER_LEN + option_len];

        // Convert to option kind
        let k = match OptionKind::try_from(option_kind) {
            Ok(v) => v,
            Err(_e) => {
                // TODO: return raw / unsupported / applicationoption data
                return Ok((Options::None, option_len + OPTION_HEADER_LEN));
            },
        };

        let (n, o) = match k {
            OptionKind::PubKey => PubKey::parse(d).map(|(o, n) | (n, Options::PubKey(o)) )?,
            OptionKind::PeerId => PeerId::parse(d).map(|(o, n) | (n, Options::PeerId(o)) )?,
            OptionKind::PrevSig => PrevSig::parse(d).map(|(o, n) | (n, Options::PrevSig(o)) )?,
            OptionKind::Kind => Kind::parse(d).map(|(o, n) | (n, Options::Kind(o)) )?,
            OptionKind::Name => Name::parse(d).map(|(o, n) | (n, Options::Name(o)) )?,
            OptionKind::IpAddrV4 => AddressV4::parse(d).map(|(o, n) | (n, Options::IPv4(o)) )?,
            OptionKind::IpAddrV6 => AddressV6::parse(d).map(|(o, n) | (n, Options::IPv6(o)) )?,
            OptionKind::Meta => Metadata::parse(d).map(|(o, n) | (n, Options::Metadata(o)) )?,
            OptionKind::Issued => Issued::parse(d).map(|(o, n) | (n, Options::Issued(o)) )?,
            OptionKind::Expiry => Expiry::parse(d).map(|(o, n) | (n, Options::Expiry(o)) )?,
            OptionKind::Limit => Limit::parse(d).map(|(o, n) | (n, Options::Limit(o)) )?,
            OptionKind::Coord => Coordinates::parse(d).map(|(o, n) | (n, Options::Coord(o)) )?,
            OptionKind::Building => todo!(),
            OptionKind::Room => todo!(),
        };

        Ok((o, n + OPTION_HEADER_LEN))
    }
}

impl Encode for Options {
    type Error = Error;

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
            Options::Coord(ref o) => Ok(o.encode(data)?),
            _ => {
                warn!("Option encoding not implemented for object {:?}", *self);
                unimplemented!();
            }
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    type Error = Error;

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
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[0..2], option_kinds::PUBKEY);
        NetworkEndian::write_u16(&mut data[2..4], PUBLIC_KEY_LEN as u16);

        data[OPTION_HEADER_LEN..OPTION_HEADER_LEN + PUBLIC_KEY_LEN]
            .copy_from_slice(&self.public_key);

        Ok(OPTION_HEADER_LEN + PUBLIC_KEY_LEN)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    type Error = Error;

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
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[0..2], option_kinds::PEER_ID);
        NetworkEndian::write_u16(&mut data[2..4], ID_LEN as u16);

        data[OPTION_HEADER_LEN..][..ID_LEN].copy_from_slice(&self.peer_id);

        Ok(OPTION_HEADER_LEN + ID_LEN)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    type Error = Error;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut sig = [0u8; SIGNATURE_LEN];
        sig.copy_from_slice(&data[..SIGNATURE_LEN]);
        Ok((Self { sig: sig.into() }, SIGNATURE_LEN))
    }
}

impl Encode for PrevSig {
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[0..2], option_kinds::PREV_SIG);
        NetworkEndian::write_u16(&mut data[2..4], SIGNATURE_LEN as u16);

        data[OPTION_HEADER_LEN..][..SIGNATURE_LEN].copy_from_slice(&self.sig);

        Ok(OPTION_HEADER_LEN + SIGNATURE_LEN)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    type Error = Error;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let value = core::str::from_utf8(&data).unwrap().to_owned();

        Ok((Kind { value }, data.len()))
    }
}

impl Encode for Kind {
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let value = self.value.as_bytes();

        NetworkEndian::write_u16(&mut data[0..2], option_kinds::KIND);
        NetworkEndian::write_u16(&mut data[2..4], value.len() as u16);

        data[OPTION_HEADER_LEN..OPTION_HEADER_LEN + value.len()].copy_from_slice(&value);

        Ok(OPTION_HEADER_LEN + value.len())
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Name {
    pub value: String,
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
    type Error = Error;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let value = core::str::from_utf8(&data).unwrap().to_owned();

        Ok((Name { value }, data.len()))
    }
}

impl Encode for Name {
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[0..2], option_kinds::NAME);
        NetworkEndian::write_u16(&mut data[2..4], self.value.len() as u16);

        data[OPTION_HEADER_LEN..][..self.value.len()]
            .copy_from_slice(&self.value.as_bytes());

        Ok(OPTION_HEADER_LEN + self.value.len())
    }
}

impl Queryable for &Name {
    fn hash<H: crate::types::CryptoHasher>(&self, h: &mut H) {
        h.update(&option_kinds::NAME.to_le_bytes());
        h.update(&(self.value.len() as u16).to_le_bytes());
        h.update(self.value.as_bytes());
    }
}

impl Parse for AddressV4 {
    type Output = AddressV4;
    type Error = Error;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut ip = [0u8; 4];

        ip.copy_from_slice(&data[0..4]);
        let port = NetworkEndian::read_u16(&data[4..6]);

        Ok((AddressV4::new(ip, port), 6))
    }
}

impl Encode for AddressV4 {
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[0..2], option_kinds::ADDR_IPV4);
        NetworkEndian::write_u16(&mut data[2..4], 6);

        data[OPTION_HEADER_LEN..OPTION_HEADER_LEN + 4].copy_from_slice(&self.ip);
        NetworkEndian::write_u16(&mut data[OPTION_HEADER_LEN + 4..], self.port);

        Ok(OPTION_HEADER_LEN + 6)
    }
}

impl Parse for AddressV6 {
    type Output = AddressV6;
    type Error = Error;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let mut ip = [0u8; 16];

        ip.copy_from_slice(&data[0..16]);
        let port = NetworkEndian::read_u16(&data[16..18]);

        Ok((AddressV6::new(ip, port), 18))
    }
}

impl Encode for AddressV6 {
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[0..2], option_kinds::ADDR_IPV6);
        NetworkEndian::write_u16(&mut data[2..4], 18);

        data[OPTION_HEADER_LEN..][..16].copy_from_slice(&self.ip);
        NetworkEndian::write_u16(&mut data[OPTION_HEADER_LEN + 16..], self.port);

        Ok(OPTION_HEADER_LEN + 18)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    type Error = Error;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        let kv = core::str::from_utf8(&data).unwrap().to_owned();
        let split: Vec<_> = kv.split("|").collect();
        if split.len() != 2 {
            return Err(Error::InvalidOption);
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
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        let meta = format!("{}|{}", self.key, self.value);

        NetworkEndian::write_u16(&mut data[0..2], option_kinds::META);
        NetworkEndian::write_u16(&mut data[2..4], meta.len() as u16);

        data[OPTION_HEADER_LEN..][..meta.len()]
            .copy_from_slice(meta.as_bytes());

        Ok(OPTION_HEADER_LEN + meta.len())
    }
}

impl From<Metadata> for Options {
    fn from(m: Metadata) -> Options {
        Options::Metadata(m)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    type Error = Error;
    fn parse<'a>(data: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        let raw = NetworkEndian::read_u64(&data[0..8]);
        let when = DateTime::from_secs(raw);

        Ok((Issued { when }, 8))
    }
}

impl Encode for Issued {
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[0..2], option_kinds::ISSUED);
        NetworkEndian::write_u16(&mut data[2..4], 8);

        NetworkEndian::write_u64(&mut data[4..12], self.when.as_secs());

        Ok(OPTION_HEADER_LEN + 8)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    type Error = Error;
    fn parse<'a>(data: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
        let raw = NetworkEndian::read_u64(&data[0..8]);
        let when = DateTime::from_secs(raw);

        Ok((Expiry { when }, 8))
    }
}

impl Encode for Expiry {
    type Error = Error;
    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[0..2], option_kinds::EXPIRY);
        NetworkEndian::write_u16(&mut data[2..4], 8);

        NetworkEndian::write_u64(&mut data[4..12], self.when.as_secs());

        Ok(OPTION_HEADER_LEN + 8)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    type Error = Error;

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
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[0..2], option_kinds::LIMIT);
        NetworkEndian::write_u16(&mut data[2..4], 4);
        NetworkEndian::write_u32(&mut data[4..8], self.n);

        Ok(8)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Coordinates {
    pub lat: f32,
    pub lng: f32,
    pub alt: f32,
}

impl Coordinates {
    pub fn new(lat: f32, lng: f32, alt: f32) -> Self {
        Self { lat, lng, alt }
    }
}

impl Parse for Coordinates {
    type Output = Self;
    type Error = Error;

    fn parse(data: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        Ok((
            Self {
                lat: NetworkEndian::read_f32(&data[0..]),
                lng: NetworkEndian::read_f32(&data[4..]),
                alt: NetworkEndian::read_f32(&data[8..]),
            },
            12,
        ))
    }
}

impl Encode for Coordinates {
    type Error = Error;

    fn encode(&self, data: &mut [u8]) -> Result<usize, Self::Error> {
        NetworkEndian::write_u16(&mut data[0..2], option_kinds::COORD);
        NetworkEndian::write_u16(&mut data[2..4], 12);
        NetworkEndian::write_f32(&mut data[4..8], self.lat);
        NetworkEndian::write_f32(&mut data[8..12], self.lng);
        NetworkEndian::write_f32(&mut data[12..16], self.alt);

        Ok(8)
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use std::time::SystemTime;

    #[test]
    fn encode_decode_option_types() {
        let tests = [
            Options::PubKey(PubKey::new([1u8; PUBLIC_KEY_LEN].into())),
            Options::PeerId(PeerId::new([2u8; ID_LEN].into())),
            Options::Kind(Kind::new("test-kind")),
            Options::Name(Name::new("test-name")),
            Options::address_v4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            Options::address_v6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                8080,
                0,
                0,
            )),
            Options::Metadata(Metadata::new("test-key", "test-value")),
            Options::issued(SystemTime::now()),
            Options::expiry(SystemTime::now()),
            Options::Limit(Limit::new(13)),
        ];

        for o in tests.iter() {
            println!("Encode/Decode: {:?}", o);

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
            Options::address_v4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            Options::address_v6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                8080,
                0,
                0,
            )),
            Options::Metadata(Metadata::new("test-key", "test-value")),
            Options::issued(SystemTime::now()),
            Options::expiry(SystemTime::now()),
        ];

        let mut data = vec![0u8; 1024];
        let n1 = Options::encode_iter(&tests, &mut data).expect("Error encoding options vector");

        let encoded = &data[0..n1];
        let (decoded, n2) = Options::parse_vec(encoded).expect("Error decoding options vector");

        assert_eq!(n1, n2, "Mismatch between encoded and decoded length");
        assert_eq!(
            &tests, &decoded,
            "Mismatch between original and decode vectors"
        );
    }
}
