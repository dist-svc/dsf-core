bitflags! {

    /// Page and Message Flags.
    #[derive(Default)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    pub struct Flags: u16 {
        const SECONDARY       = (1 << 0);
        /// Signal an object is encrypted
        const ENCRYPTED       = (1 << 1);

        /// Request that the response contains a service address (messages_only)
        const ADDRESS_REQUEST = (1 << 2);
        /// Request that the response contains a public key (messages_only)
        const PUB_KEY_REQUEST = (1 << 3);

        /// Signal symmetric encryption is enabled (messages only)
        const SYMMETRIC_MODE = (1 << 4);
        /// Set direction flag for symmetric encryption
        const SYMMETRIC_DIR  = (1 << 5);

        /// Signal a device is constrained (requests are delegation, not for use as DHT peer)
        const CONSTRAINED = (1 << 6);
    }
}
