
use std::net::SocketAddr;

pub const ID_LEN: usize = 32;
pub type Id = [u8; ID_LEN];

pub const REQUEST_ID_LEN: usize = 8;
pub type RequestId = u64;

pub const PUBLIC_KEY_LEN: usize = 32;
pub type PublicKey = [u8; PUBLIC_KEY_LEN];

pub const PRIVATE_KEY_LEN: usize = 64;
pub type PrivateKey = [u8; PRIVATE_KEY_LEN];

pub const SIGNATURE_LEN: usize = 64;
//pub struct Signature([u8; SIGNATURE_LEN]);
pub type Signature = Array64<u8>;

pub const SECRET_KEY_LEN: usize = 32;
pub type SecretKey = [u8; SECRET_KEY_LEN];

pub const HASH_LEN: usize = 32;
pub type Hash = [u8; HASH_LEN];

pub const ENCRYPTED_META_LEN: usize = 64;
pub type EncryptedMeta = Array64<u8>;

pub type Address = SocketAddr;

newtype_array!(pub struct Array64(pub 64));

pub mod kinds;
pub use self::kinds::*;

pub mod flags;
pub use self::flags::*;

pub mod errors;
pub use self::errors::*;
