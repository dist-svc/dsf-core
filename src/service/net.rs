use crate::base::Base;
use crate::error::Error;
use crate::net::Message;
use crate::service::Service;

pub trait Net {
    /// Encode and sign a message
    fn encode_message<M: Into<Message>, T: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        msg: M,
        buff: T,
    ) -> Result<usize, Error>;

    /// Helper to encode and sign a message using fixed size buffer
    fn encode_message_buff<M: Into<Message>, const N: usize>(
        &self,
        msg: M,
    ) -> Result<(usize, [u8; N]), Error> {
        let mut buff = [0u8; N];
        let n = self.encode_message(msg, &mut buff)?;
        Ok((n, buff))
    }
}

impl Net for Service {
    /// Encode a message
    fn encode_message<M: Into<Message>, T: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        msg: M,
        buff: T,
    ) -> Result<usize, Error> {
        let msg: Message = msg.into();
        let mut b: Base = msg.into();

        let keys = self.keys();
        let n = b.encode(Some(&keys), buff)?;

        Ok(n)
    }
}
