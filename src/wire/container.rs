
use crate::types::*;

use crate::base::header::{HEADER_LEN, offsets};
use crate::options::{Options, OptionsIter};

use super::header::WireHeader;

/// Container object provides base field accessors over an arbitrary (mutable or immutable) buffers
/// See https://lab.whitequark.org/notes/2016-12-13/abstracting-over-mutability-in-rust/ for details
#[derive(Clone, Debug, PartialEq)]
pub struct Container<T: ImmutableData> {
    /// Internal data buffer
    pub (crate) buff: T,
    /// Length of object in container buffer
    pub (crate) len: usize,
}


impl <'a, T: ImmutableData> Container<T> {
    /// Create a new container object from an existing buffer
    /// This parses the header and splits the data into fields to simplify access
    pub fn from(buff: T) -> (Self, usize) {
        let len = buff.as_ref().len();
        let c = Container{buff, len};
        let n = c.len();
        (c, n)
    }

    /// Fetch wire header
    pub fn header(&self) -> WireHeader<&[u8]> {
        WireHeader{buff: &self.buff.as_ref()[..HEADER_LEN]}
    }

    /// Fetch object ID
    pub fn id(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        &data[offsets::ID..offsets::BODY]
    }

    /// Return the body of data
    pub fn body(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        let n = HEADER_LEN + ID_LEN;
        let s = self.header().data_len();
        &data[n..n+s]
    }

    /// Return the private options section data
    pub fn private_options(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        let n = HEADER_LEN + ID_LEN + self.header().data_len();
        let s = self.header().private_options_len();
        &data[n..n+s]
    }

    /// Return the public options section data
    pub fn public_options(&self) -> impl Iterator<Item=Options> + '_ {
        let data = self.buff.as_ref();
        let header = self.header();
        
        let n = HEADER_LEN + ID_LEN + header.data_len() + header.private_options_len();
        let s = header.public_options_len();
        OptionsIter::new(&data[n..n+s])
    }

    /// Return the signed portion of the message for signing or verification
    pub fn signed(&self) -> &[u8] {
        let data = self.buff.as_ref();
        let n = self.len();

        &data[..n-SIGNATURE_LEN]
    }

    /// Return the signature portion of the message for verification
    pub fn signature(&self) -> &[u8] {
        let data = self.buff.as_ref();
        
        let n = self.len() - SIGNATURE_LEN;
        let s = SIGNATURE_LEN;

        &data[n..n+s]
    }

    /// Return the total length of the object (from the header)
    pub fn len(&self) -> usize {
        let header = self.header();

        HEADER_LEN + ID_LEN + header.data_len() + header.private_options_len() + header.public_options_len() + SIGNATURE_LEN
    }

    /// Verify the contents of a given container
    /// This calls the provided verifier with the id, body, and signature and forwards the result to the caller
    pub fn verify<V, E>(&self, mut verifier: V) -> Result<bool, E> 
    where
        V: FnMut(&Id, &Signature, &[u8]) -> Result<bool, E>
    {
        let id: Id = self.id().into();
        let data = self.signed();
        let sig: Signature = self.signature().into();

        (verifier)(&id, &sig, &data)
    }

    /// Fetch the raw data using internal header length
    pub fn raw(&self) -> &[u8] {
        let data = self.buff.as_ref();
        let len = self.len();
        
        &data[0..len]
    }
}
