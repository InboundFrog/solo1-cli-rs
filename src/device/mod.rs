/// USB HID communication layer for Solo 1 devices.
///
/// Implements the CTAP HID protocol framing and the Solo-specific
/// vendor commands on top of it.
pub mod frame;
pub mod hid;
pub mod protocol;

/// Trait abstracting the send/receive interface of a CTAP HID device.
///
/// All command functions accept `&impl HidDevice` (or `&mut impl HidDevice`)
/// instead of a concrete `&SoloHid`, making them testable with `MockDevice`
/// without a physical device attached.
pub trait HidDevice {
    /// Send a command with payload, receive and return the response payload.
    fn send_recv(&self, cmd: u8, data: &[u8]) -> crate::error::Result<Vec<u8>>;

    /// Send a vendor (bootloader) command and return the response payload.
    fn send_bootloader_cmd(&self, cmd: u8, addr: u32, data: &[u8])
        -> crate::error::Result<Vec<u8>>;

    /// Send a command with payload without waiting for a response.
    fn send(&self, cmd: u8, data: &[u8]) -> crate::error::Result<()>;
}

// Re-export everything that was previously public in device.rs so that
// all existing `use crate::device::*` import sites continue to work
// without modification.

// USB / protocol constants
pub use protocol::{
    CMD_BOOT, CMD_CHECK, CMD_DISABLE_BOOTLOADER, CMD_DONE, CMD_ENTER_BOOT, CMD_ENTER_DFU,
    CMD_ENTER_ST_BOOT, CMD_ERASE, CMD_GET_VERSION, CMD_KEYBOARD, CMD_PROBE, CMD_REBOOT, CMD_RNG,
    CMD_SET_VERSION, CMD_VERSION, CMD_WRITE, CTAPHID_BROADCAST_CID, CTAPHID_CBOR, CTAPHID_INIT,
    CTAPHID_MSG, CTAPHID_PING, CTAPHID_VENDOR_FIRST, CTAPHID_WINK, HID_REPORT_SIZE, SOLO_DFU_PID,
    SOLO_PID, SOLO_TAG, SOLO_VID,
};

// Frame types and helpers
pub use frame::{
    build_bootloader_packet, build_ctaphid_frames, dfu_block_index, reassemble_frames,
    CtapHidFrame, FramePayload, DFU_CHUNK_SIZE, FLASH_BASE,
};

// Device communication
pub use hid::{list_solo_devices, SoloDevice, SoloHid};

#[cfg(test)]
pub mod mock {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::HidDevice;

    /// A mock HID device for unit testing.
    ///
    /// Responses are queued at construction time and returned in order from
    /// `send_recv` and `send_bootloader_cmd`. When the queue is exhausted,
    /// `Err(SoloError::Timeout)` is returned. `send` always succeeds.
    pub struct MockDevice {
        pub responses: RefCell<VecDeque<crate::error::Result<Vec<u8>>>>,
    }

    impl MockDevice {
        pub fn new(responses: Vec<crate::error::Result<Vec<u8>>>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
            }
        }
    }

    impl HidDevice for MockDevice {
        fn send_recv(&self, _cmd: u8, _data: &[u8]) -> crate::error::Result<Vec<u8>> {
            self.responses
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(crate::error::SoloError::Timeout))
        }

        fn send_bootloader_cmd(
            &self,
            _cmd: u8,
            _addr: u32,
            _data: &[u8],
        ) -> crate::error::Result<Vec<u8>> {
            self.responses
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(crate::error::SoloError::Timeout))
        }

        fn send(&self, _cmd: u8, _data: &[u8]) -> crate::error::Result<()> {
            Ok(())
        }
    }
}
