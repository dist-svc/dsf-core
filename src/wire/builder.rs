
use core::marker::PhantomData;

use crate::types::*;
use crate::base::{NewBody, Encode};
use crate::base::header::{Header, HEADER_LEN, offsets};
use crate::options::{Options, OptionsList};
use crate::crypto;

use super::header::WireHeader;
use super::container::Container;

/// Init state, no data set
pub struct Init;

/// SetBody state, has header and ID
pub struct SetBody;

/// SetPrivateOptions state, has Body and previous (SetBody)
pub struct SetPrivateOptions;

/// SetPublicOptions state, has PrivateOptions and previous (SetPrivateOptions)
pub struct SetPublicOptions;

/// Sign state, has PublicOptions and previous (SetPublicOptions)
pub struct Sign;

/// Internal trait to support encoding of optionally encrypted objects in a generic buffer
pub trait EncodeEncrypted {
    fn encode<B: MutableData>(&self, buf: B, secret_key: Option<&SecretKey>) -> Result<usize, Error>;
}

/// Builder provides a low-level wire protocol builder object.
/// This is generic over buffer types and uses type-state mutation to ensure created objects are valid
pub struct Builder<S, T: MutableData> {
    /// internal data buffer
    buf: T,
    /// Current index count
    n: usize,
    /// Local index count
    c: usize,

    _s: PhantomData<S>,
}

// Implementations that are always available
impl <S, T: MutableData> Builder<S, T> {
    /// Set the object id
    pub fn id(mut self, id: &Id) -> Self {
        
        let d = self.buf.as_mut();

        d[HEADER_LEN..HEADER_LEN+ID_LEN].clone_from_slice(id);

        self
    }

    /// Fetch a mutable instance of the object header
    pub fn header_mut(&mut self) -> WireHeader<&mut [u8]> {
        WireHeader::new(&mut self.buf.as_mut()[..HEADER_LEN])
    }
}


impl <T: MutableData> Builder<Init, T> {
    /// Create a new base builder object
    pub fn new(buf: T) -> Self {
        Builder{buf, n: 0, c: 0, _s: PhantomData}
    }

    /// Set the object header.
    /// Note that length fields will be overwritten by actual lengths
    pub fn header(mut self, header: &Header) -> Self {
        let d = self.buf.as_mut();

        self.header_mut().encode(header);

        self
    }

    /// Add body data, mutating the state of the builder
    pub fn body<B: ImmutableData>(mut self, body: &NewBody<B>, secret_key: Option<&SecretKey>) -> Result<Builder<SetPrivateOptions, T>, Error> {
        let b = self.buf.as_mut();

        self.n = offsets::BODY;
        
        let body_len = body.encode(&mut b[self.n..], secret_key)?;
        self.n += body_len;

        self.header_mut().set_data_len(body_len);

        Ok(Builder{buf: self.buf, n: self.n, c: 0, _s: PhantomData})
    }
}

impl <T: MutableData> Builder<SetPrivateOptions, T> {
    /// Encode private options
    /// This must be done in one pass as the entire options block is encrypted
    pub fn private_options<C: AsRef<[Options]>, E: ImmutableData>(mut self, options: &OptionsList<C, E>, secret_key: Option<&SecretKey>) -> Result<Builder<SetPublicOptions, T>, Error> {
        let b = self.buf.as_mut();

        let n = options.encode(&mut b[self.n..], secret_key)?;
        self.n += n;

        self.header_mut().set_private_options_len(n);

        Ok(Builder{buf: self.buf, n: self.n, c: 0,  _s: PhantomData})
    }
}

impl <T: MutableData> Builder<SetPublicOptions, T> {
    /// Encode a list of public options
    pub fn public_options<C: AsRef<[Options]>, E: ImmutableData>(mut self, options: &OptionsList<C, E>) -> Result<Builder<SetPublicOptions, T>, Error> {
        let b = self.buf.as_mut();

        let n = options.encode(&mut b[self.n..], None)?;
        self.n += n;
        self.c += n;
        let c = self.c;

        self.header_mut().set_public_options_len(c);

        Ok(self)
    }

    /// Add a single public option
    pub fn public_option(&mut self, option: &Options) -> Result<(), Error> {
        let b = self.buf.as_mut();

        let n = option.encode(&mut b[self.n..])?;
        self.n += n;
        self.c += n;
        let c = self.c;

        self.header_mut().set_public_options_len(c);

        Ok(())
    }

    // Sign the builder object, returning a new base object
    pub fn sign(mut self, signing_key: &PrivateKey) -> Result<Container<T>, Error> {
        let b = self.buf.as_mut();

        // Generate signature
        let sig = crypto::pk_sign(signing_key, &b[..self.n]).unwrap();

        // Write to object
        &b[self.n..self.n + SIGNATURE_LEN].copy_from_slice(&sig);
        self.n += SIGNATURE_LEN;

        // Return base object
        Ok(Container{buff: self.buf, len: self.n})
    }
}


impl <T: ImmutableData> EncodeEncrypted for NewBody<T> {
    /// Encode and optionally encrypt body
    fn encode<B: MutableData>(&self, mut buf: B, secret_key: Option<&SecretKey>) -> Result<usize, Error> {
        let b = buf.as_mut();

        let n = match self {
            NewBody::Cleartext(clear) => {
                let c = clear.as_ref();

                b[..c.len()].copy_from_slice(c);

                if let Some(sk) = secret_key {
                    crypto::sk_encrypt2(sk, b, c.len()).unwrap()
                } else {
                    c.len()
                }
            },
            NewBody::Encrypted(enc) => {
                let e = enc.as_ref();

                b[..e.len()].copy_from_slice(e);

                e.len()
            },
            NewBody::None => 0,
        };

        Ok(n)
    }
}

impl <C: AsRef<[Options]>, E: ImmutableData> EncodeEncrypted for OptionsList<C, E> {
    /// Encode and optionally encrypt options
    fn encode<B: MutableData>(&self, mut buf: B, secret_key: Option<&SecretKey>) -> Result<usize, Error> {
        
        let n = match self {
            OptionsList::Cleartext(opts) => {
                // Encode options into buffer
                let mut n = Options::encode_vec(opts.as_ref(), buf.as_mut())?;
            
                // Encrypt if required
                if let Some(sk) = secret_key {
                    n = crypto::sk_encrypt2(sk, buf.as_mut(), n).unwrap();
                }
            
                n
            },
            OptionsList::Encrypted(enc) => {
                // Write options directly to buffer
                let b = buf.as_mut();
                let e = enc.as_ref();

                b[..e.len()].copy_from_slice(e.as_ref());
                e.as_ref().len()
            },
            OptionsList::None => {
                0
            }
        };

        Ok(n)
    }
}
