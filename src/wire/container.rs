use crate::prelude::{DsfError, KeySource};
use crate::types::*;

use crate::options::{Options, OptionsIter};

use super::header::WireHeader;
use super::{offsets, HEADER_LEN};

/// Container object provides base field accessors over an arbitrary (mutable or immutable) buffers
/// See <https://lab.whitequark.org/notes/2016-12-13/abstracting-over-mutability-in-rust/> for details
#[derive(Clone, Debug, PartialEq)]
pub struct Container<T: ImmutableData> {
    /// Internal data buffer
    pub(crate) buff: T,
    /// Length of object in container buffer
    pub(crate) len: usize,
    // Signals data / private options are encrypted
    //pub(crate) encrypted: bool,
    // Signals container has been verified
    //pub(crate) verified: bool,
}

impl<'a, T: ImmutableData> Container<T> {
    /// Create a new container object, providing field accessors over the provided buffer
    pub fn from(buff: T) -> (Self, usize) {
        let len = buff.as_ref().len();
        let c = Container { buff, len };
        let n = c.len();
        (c, n)
    }

    /// Fetch wire header
    pub fn header(&self) -> WireHeader<&[u8]> {
        WireHeader {
            buff: &self.buff.as_ref()[..HEADER_LEN],
        }
    }

    /// Fetch object ID
    pub fn id_raw(&self) -> &[u8] {
        let data = self.buff.as_ref();

        &data[offsets::ID..offsets::BODY]
    }

    /// Fetch object ID
    pub fn id(&self) -> Id {
        Id::from(self.id_raw())
    }

    /// Return the body of data
    pub fn body(&self) -> &[u8] {
        let data = self.buff.as_ref();

        let s = self.header().data_len();
        &data[offsets::BODY..][..s]
    }

    /// Return the private options section data, note this may be encrypted
    pub fn private_options(&self) -> &[u8] {
        let data = self.buff.as_ref();

        let n = offsets::BODY + self.header().data_len();
        let s = self.header().private_options_len();
        &data[n..n + s]
    }

    /// Iterate over private options
    /// NOTE: ONLY VALID FOR DECRYPTED OBJECTS
    pub fn private_options_iter(&self) -> impl Iterator<Item = Options> + '_ {
        let data = self.buff.as_ref();
        let n = offsets::BODY + self.header().data_len();
        let s = self.header().private_options_len();

        OptionsIter::new(&data[n..n + s])
    }

    /// Return public options section data
    pub fn public_options(&self) -> &[u8] {
        let h = self.header();
        let data = self.buff.as_ref();

        let tag_len = if h.flags().contains(Flags::ENCRYPTED) {
            SECRET_KEY_TAG_LEN
        } else {
            0
        };

        let n = offsets::BODY + h.data_len()
                + h.private_options_len() + tag_len;
        let s = h.public_options_len();
        &data[n..n + s]
    }

    /// Ciphertext for encrypted objects (body + private options fields)
    pub fn cyphertext(&self) -> &[u8] {
        let data = self.buff.as_ref();

        let s = self.header().data_len() + self.header().private_options_len();

        &data[offsets::BODY..][..s]
    }

    /// Tag for secret key encryption
    pub fn tag(&self) -> &[u8] {
        let h = self.header();
        let data = self.buff.as_ref();

        if !h.flags().contains(Flags::ENCRYPTED) {
            return &[];
        }

        let n = HEADER_LEN + ID_LEN + h.data_len()
                + h.private_options_len();

        &data[n..n + SECRET_KEY_TAG_LEN]
    }

    /// Return the public options section data
    pub fn public_options_iter(&self) -> impl Iterator<Item = Options> + '_ {
        let data = self.buff.as_ref();
        let header = self.header();

        let tag_len = if header.flags().contains(Flags::ENCRYPTED) {
            SECRET_KEY_TAG_LEN
        } else {
            0
        };

        let n = HEADER_LEN + ID_LEN + header.data_len() + header.private_options_len() + tag_len;
        let s = header.public_options_len();
        OptionsIter::new(&data[n..n + s])
    }

    /// Return the signed portion of the message for signing or verification
    pub fn signed(&self) -> &[u8] {
        let data = self.buff.as_ref();
        let n = self.len();

        &data[..n - SIGNATURE_LEN]
    }

    /// Return the signature portion of the message for verification
    pub fn signature_raw(&self) -> &[u8] {
        let data = self.buff.as_ref();

        let n = self.len() - SIGNATURE_LEN;
        let s = SIGNATURE_LEN;

        &data[n..n + s]
    }

    /// Fetch the message signature
    pub fn signature(&self) -> Signature {
        let r = self.signature_raw();
        Signature::from(r)
    }

    /// Return the total length of the object (from the header)
    pub fn len(&self) -> usize {
        let header = self.header();

        let tag_len = if header.flags().contains(Flags::ENCRYPTED) {
            SECRET_KEY_TAG_LEN
        } else {
            0
        };

        HEADER_LEN
            + ID_LEN
            + header.data_len()
            + header.private_options_len()
            + tag_len
            + header.public_options_len()
            + SIGNATURE_LEN
    }

    /// Verify the contents of a given container
    /// This calls the provided verifier with the id, body, and signature and forwards the result to the caller
    pub fn verify<V, E>(&self, mut verifier: V) -> Result<bool, E>
    where
        V: FnMut(&Id, &Signature, &[u8]) -> Result<bool, E>,
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

impl<'a, T: ImmutableData> AsRef<[u8]> for  Container<T> {
    fn as_ref(&self) -> &[u8] {
        let n = self.len;
        &self.buff.as_ref()[..n]
    }
}
