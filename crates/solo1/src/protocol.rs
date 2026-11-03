// Solo 1 USB identifiers and vendor command codes.
//
// Solo 1 is built on an STM32L432, so it enumerates with the
// STMicroelectronics vendor ID and, in ST DFU mode, the ST DFU product ID.

// USB identifiers
pub const SOLO_VID: u16 = 0x0483;
pub const SOLO_PID: u16 = 0xA2CA;
pub const SOLO_DFU_PID: u16 = 0xDF11;

// Solo bootloader commands, sent wrapped in a `CMD_BOOT` packet
// (see `crate::bootloader`).
pub const CMD_WRITE: u8 = 0x40;
pub const CMD_DONE: u8 = 0x41;
pub const CMD_CHECK: u8 = 0x42;
pub const CMD_ERASE: u8 = 0x43;
pub const CMD_VERSION: u8 = 0x44;
pub const CMD_REBOOT: u8 = 0x45;
pub const CMD_ENTER_DFU: u8 = 0x46;
pub const CMD_DISABLE_BOOTLOADER: u8 = 0x47;

// Vendor CTAPHID commands handled by the firmware directly.
pub const CMD_BOOT: u8 = 0x50;
pub const CMD_ENTER_BOOT: u8 = 0x51;
pub const CMD_ENTER_ST_BOOT: u8 = 0x52;
pub const CMD_KEYBOARD: u8 = 0x53;

// Firmware-mode custom commands
pub const CMD_RNG: u8 = 0x60;
pub const CMD_GET_VERSION: u8 = 0x61;
pub const CMD_SET_VERSION: u8 = 0x62;
pub const CMD_PROBE: u8 = 0x70;

// Solo bootloader magic tag
pub const SOLO_TAG: [u8; 4] = [0x8C, 0x27, 0x90, 0xF6];
