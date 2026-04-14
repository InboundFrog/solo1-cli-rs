/// USB HID communication layer for Solo 1 devices.
///
/// Implements the CTAP HID protocol framing and the Solo-specific
/// vendor commands on top of it.

pub mod frame;
pub mod hid;
pub mod protocol;

// Re-export everything that was previously public in device.rs so that
// all existing `use crate::device::*` import sites continue to work
// without modification.

// USB / protocol constants
pub use protocol::{
    SOLO_VID,
    SOLO_PID,
    SOLO_DFU_PID,
    HID_REPORT_SIZE,
    CTAPHID_INIT,
    CTAPHID_MSG,
    CTAPHID_CBOR,
    CTAPHID_PING,
    CTAPHID_WINK,
    CTAPHID_VENDOR_FIRST,
    CMD_WRITE,
    CMD_DONE,
    CMD_CHECK,
    CMD_ERASE,
    CMD_VERSION,
    CMD_REBOOT,
    CMD_ENTER_DFU,
    CMD_DISABLE_BOOTLOADER,
    CMD_BOOT,
    CMD_ENTER_BOOT,
    CMD_ENTER_ST_BOOT,
    CMD_RNG,
    CMD_GET_VERSION,
    CMD_SET_VERSION,
    CMD_PROBE,
    SOLO_TAG,
    CTAPHID_BROADCAST_CID,
};

// Frame types and helpers
pub use frame::{
    CtapHidFrame,
    FramePayload,
    build_ctaphid_frames,
    reassemble_frames,
    build_bootloader_packet,
    FLASH_BASE,
    DFU_CHUNK_SIZE,
    dfu_block_index,
};

// Device communication
pub use hid::{
    SoloDevice,
    SoloHid,
    list_solo_devices,
};
