

use byteorder::{ByteOrder, NetworkEndian};

use crate::types::{ID_LEN, Signature, SIGNATURE_LEN, Flags, Kind};
use crate::protocol::{Encode};
use crate::protocol::options::{Options};

const HEADER_LEN: usize = 16;

/// Container object provides base field accessors over an arbitrary (mutable or immutable) buffers
/// See https://lab.whitequark.org/notes/2016-12-13/abstracting-over-mutability-in-rust/ for details
#[derive(Clone, Debug, PartialEq)]
pub struct Container<T: AsRef<[u8]>> {
    buff: T,
}

use crate::protocol::base::Base;

mod offsets {
    pub const PROTO_VERSION: usize = 0;
    pub const APPLICATION_ID: usize = 2;
    pub const OBJECT_KIND: usize = 4;
    pub const FLAGS: usize = 6;
    pub const INDEX: usize = 8;
    pub const DATA_LEN: usize = 10;
    pub const PRIVATE_OPTIONS_LEN: usize = 12;
    pub const PUBLIC_OPTIONS_LEN: usize = 14;
    pub const ID: usize = 16;
    pub const BODY: usize = 48;
}

impl <'a, T: AsRef<[u8]>> Container<T> {
    /// Create a new container object from an existing buffer
    /// This parses the header and splits the data into fields to simplify access
    pub fn from(buff: T) -> (Self, usize) {
        let c = Container{buff};
        let n = c.len();
        (c, n)
    }

    pub fn protocol_version(&self) -> Kind {
        let data = self.buff.as_ref();
        
        Kind::from(NetworkEndian::read_u16(&data[offsets::PROTO_VERSION..]))
    }

    pub fn application_id(&self) -> Flags {
        let data = self.buff.as_ref();
        
        Flags::from(NetworkEndian::read_u16(&data[offsets::APPLICATION_ID..4]))
    }

    pub fn kind(&self) -> Kind {
        let data = self.buff.as_ref();
        
        Kind::from(NetworkEndian::read_u16(&data[offsets::OBJECT_KIND..]))
    }

    pub fn flags(&self) -> Flags {
        let data = self.buff.as_ref();
        
        Flags::from(NetworkEndian::read_u16(&data[offsets::FLAGS..]))
    }

    pub fn index(&self) -> u16 {
        let data = self.buff.as_ref();
        
        NetworkEndian::read_u16(&data[offsets::INDEX..])
    }

    pub fn data_len(&self) -> usize {
        let data = self.buff.as_ref();
        
        NetworkEndian::read_u16(&data[offsets::DATA_LEN..]) as usize
    }

    pub fn private_options_len(&self) -> usize {
        let data = self.buff.as_ref();
        
        NetworkEndian::read_u16(&data[offsets::PRIVATE_OPTIONS_LEN..]) as usize
    }

    pub fn public_options_len(&self) -> usize {
        let data = self.buff.as_ref();
        
        NetworkEndian::read_u16(&data[offsets::PUBLIC_OPTIONS_LEN..]) as usize
    }

    pub fn id(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        &data[offsets::ID..offsets::BODY]
    }

    pub fn body(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        let n = HEADER_LEN + ID_LEN;
        let s = self.data_len();
        &data[n..n+s]
    }

    pub fn private_options(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        let n = HEADER_LEN + ID_LEN + self.data_len();
        let s = self.private_options_len();
        &data[n..n+s]
    }

    pub fn public_options(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        let n = HEADER_LEN + ID_LEN + self.data_len() + self.private_options_len();
        let s = self.public_options_len();
        &data[n..n+s]
    }

    pub fn signature(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        let n = self.len() - SIGNATURE_LEN;
        let s = SIGNATURE_LEN;

        &data[n..n+s]
    }

    pub fn len(&self) -> usize {
        HEADER_LEN + ID_LEN + self.data_len() + self.private_options_len() + self.public_options_len() + SIGNATURE_LEN
    }


    pub fn verify<V, E>(&self, mut verifier: V) -> Result<bool, E> 
    where
        V: FnMut(&[u8], &[u8], &[u8]) -> Result<bool, E>
    {
        let len = self.len() - SIGNATURE_LEN;
        let id = self.id();
        let data = self.raw();
        let sig = self.signature();

        (verifier)(id, &data[..len], sig)
    }

    pub fn raw(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        &data
    }

}

impl <'a, T: AsRef<[u8]> + AsMut<[u8]>> Container<T> {
    /// Encode a a higher level base object into a container using the provided buffer
    /// This encodes the base object into the buff and constructs a container from this encoded object
    pub fn encode(mut buff: T, base: &Base) -> (Self, usize) {
        let data = buff.as_mut();

        // Skip header until sizes are known
        let mut n = HEADER_LEN;

        // Write ID
        let id = &mut data[n..n+ID_LEN];
        id.clone_from_slice(base.id());
        n += ID_LEN;

        // Write body
        let b = base.body();
        let body_len = b.len();
        let body = &mut data[n..n+body_len];
        body.clone_from_slice(b);
        n += body_len;

        // Write private options
        let private_options_len = { Options::encode_vec(base.private_options(), &mut data[n..]).expect("error encoding private options") };
        n += private_options_len;

        // Write public options
        let public_options_len = { Options::encode_vec(base.public_options(), &mut data[n..]).expect("error encoding public options") };
        n += public_options_len;

        // Write header
        let header = &mut data[..HEADER_LEN];
        // TODO: un-unwrap this and bubble error?
        // OR, change to infallible impl
        base.header().encode(header).expect("error encoding header");

        // Write lengths
        NetworkEndian::write_u16(&mut header[6..8], body_len as u16);
        NetworkEndian::write_u16(&mut header[8..10], private_options_len as u16);
        NetworkEndian::write_u16(&mut header[10..12], public_options_len as u16);

        // Reserve signature (and write if existing)
        let signature = &mut data[n..n+SIGNATURE_LEN];
        if let Some(sig) = base.signature() {
            signature.clone_from_slice(sig);
        }
        n += SIGNATURE_LEN;

        (Container{buff}, n)
    }

    /// Set the signature in the underlying buffer
    fn set_signature(&mut self, signature: &[u8]) {
        let n = self.len() - SIGNATURE_LEN;
        let data = self.buff.as_mut();
        
        let s = SIGNATURE_LEN;

        data[n..n+s].copy_from_slice(signature);
    }

    /// Sign the message with the given signer
    pub fn sign<S, E>(&mut self, mut signer: S) -> Result<Signature, E>
    where
        S: FnMut(&[u8], &[u8]) -> Result<Signature, E>
    {
        let len = self.len() - SIGNATURE_LEN;
        let id = self.id();
        let data = self.raw();

        let sig = (signer)(id, &data[0..len])?;

        self.set_signature(&sig);

        Ok(sig)
    }

}

#[cfg(test)]
mod test {

}

