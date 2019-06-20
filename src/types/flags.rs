
bitflags! {

    /// Page and Message Flags.
    #[derive(Default)]
    pub struct Flags: u16 {
        const SECONDARY       = (1 << 0);
        const ENCRYPTED       = (1 << 1);

        const ADDRESS_REQUEST = (1 << 2);
        const PUB_KEY_REQUEST = (1 << 3);
    }
}
