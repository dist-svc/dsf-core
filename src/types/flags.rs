bitflags! {

    /// Page and Message Flags.
    #[derive(Default)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    pub struct Flags: u16 {
        const SECONDARY       = (1 << 0);
        const ENCRYPTED       = (1 << 1);

        const ADDRESS_REQUEST = (1 << 2);
        const PUB_KEY_REQUEST = (1 << 3);
        
        const SYMMETRIC_MODE = (1 << 4);
        const SYMMETRIC_DIR = (1 << 5);
    }
}
