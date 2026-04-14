/// CTAPHID protocol constants and USB device identifiers.

// USB identifiers
pub const SOLO_VID: u16 = 0x0483;
pub const SOLO_PID: u16 = 0xA2CA;
pub const SOLO_DFU_PID: u16 = 0xDF11;

// HID report size
pub const HID_REPORT_SIZE: usize = 64;

// CTAPHID commands
pub const CTAPHID_INIT: u8 = 0x86;
pub const CTAPHID_MSG: u8 = 0x83;
pub const CTAPHID_CBOR: u8 = 0x90;
pub const CTAPHID_PING: u8 = 0x81;
pub const CTAPHID_WINK: u8 = 0x88;
pub const CTAPHID_VENDOR_FIRST: u8 = 0x40;

// Solo vendor commands (offset from CTAPHID_VENDOR_FIRST or absolute)
pub const CMD_WRITE: u8 = 0x40;
pub const CMD_DONE: u8 = 0x41;
pub const CMD_CHECK: u8 = 0x42;
pub const CMD_ERASE: u8 = 0x43;
pub const CMD_VERSION: u8 = 0x44;
pub const CMD_REBOOT: u8 = 0x45;
pub const CMD_ENTER_DFU: u8 = 0x46;
pub const CMD_DISABLE_BOOTLOADER: u8 = 0x47;
pub const CMD_BOOT: u8 = 0x50;
pub const CMD_ENTER_BOOT: u8 = 0x51;
pub const CMD_ENTER_ST_BOOT: u8 = 0x52;

// Firmware-mode custom commands
pub const CMD_RNG: u8 = 0x60;
pub const CMD_GET_VERSION: u8 = 0x61;
pub const CMD_SET_VERSION: u8 = 0x62;
pub const CMD_PROBE: u8 = 0x70;

// Solo bootloader magic tag
pub const SOLO_TAG: [u8; 4] = [0x8C, 0x27, 0x90, 0xF6];

// Broadcast channel for CTAPHID_INIT
pub const CTAPHID_BROADCAST_CID: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
