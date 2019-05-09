
/// Page and Message Flags.
/// 
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Flags(pub u16);

pub mod flags {
    pub const NONE            : u16 = 0;
    pub const SECONDARY       : u16 = (1 << 0);
    pub const ENCRYPTED       : u16 = (1 << 1);
    pub const ADDRESS_REQUEST : u16 = (1 << 2);
    pub const PUB_KEY_REQUEST : u16 = (1 << 3);
}

impl Flags {
    pub fn encrypted(&self) -> bool {
        self.0 & flags::ENCRYPTED != 0
    }

    pub fn set_encrypted(&mut self, encrypted: bool) -> Flags {
        match encrypted {
            true => self.0 |= flags::ENCRYPTED,
            false => self.0 &= !(flags::ENCRYPTED)
        };
        *self
    }

    pub fn primary(&self) -> bool {
        self.0 & flags::SECONDARY == 0
    }

    pub fn secondary(&self) -> bool {
        self.0 & flags::SECONDARY != 0
    }

    pub fn set_secondary(&mut self, secondary: bool) -> Flags {
        match secondary {
            true => self.0 |= flags::SECONDARY,
            false => self.0 &= !(flags::SECONDARY)
        };
        *self
    }

    pub fn address_request(&self) -> bool {
        self.0 & flags::ADDRESS_REQUEST != 0
    }

    pub fn set_address_request(&mut self, address_request: bool) -> Flags {
        match address_request {
            true => self.0 |= flags::ADDRESS_REQUEST,
            false => self.0 &= !(flags::ADDRESS_REQUEST)
        };
        *self
    }

    pub fn pub_key_request(&self) -> bool {
        self.0 & flags::PUB_KEY_REQUEST != 0
    }

    pub fn set_pub_key_request(&mut self, pub_key_request: bool) -> Flags {
        match pub_key_request {
            true => self.0 |= flags::PUB_KEY_REQUEST,
            false => self.0 &= !(flags::PUB_KEY_REQUEST)
        };
        *self
    }
}

impl Default for Flags {
    fn default() -> Flags {
        Flags(0)
    }
}

impl From<u16> for Flags {
    fn from(v: u16) -> Flags {
        Flags(v)
    }
}

impl Into<u16> for Flags {
    fn into(self) -> u16 {
        self.0
    }
}