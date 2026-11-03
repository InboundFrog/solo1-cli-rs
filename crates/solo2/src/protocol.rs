// Solo 2 USB identifiers and admin-app vendor command codes.
//
// Sources:
// - USB IDs: https://pid.codes/1209/BEEE/ ("Solo 2"),
//   https://pid.codes/1209/B000/ ("Solo 2 Bootloader"), and the udev rules
//   in solokeys/solo2-cli (70-solo2.rules).
// - Commands: solokeys/admin-app src/admin.rs (firmware side) and
//   solokeys/solo2-cli src/apps/admin.rs (host side).
//
// The legacy admin commands below are sent as raw CTAPHID vendor commands
// (the code is the CTAPHID frame command byte). Several codes collide with
// Solo 1 vendor commands that mean something else (e.g. 0x53 is "program
// keyboard" on Solo 1 but "reboot" here), so callers must know which model
// they are talking to before sending any of them.

// USB identifiers
pub const SOLO2_VID: u16 = 0x1209;
pub const SOLO2_PID: u16 = 0xBEEE;
/// Solo 2's LPC55 ROM bootloader, re-branded with the Solo 2 vendor ID.
pub const SOLO2_BOOTLOADER_PID: u16 = 0xB000;
/// An LPC55 ROM bootloader with NXP's default identifiers.
pub const NXP_LPC55_BOOTLOADER_VID: u16 = 0x1FC9;
pub const NXP_LPC55_BOOTLOADER_PID: u16 = 0x0021;

// Admin-app vendor commands
/// Reboot into the bootloader for a firmware update. Needs a touch within
/// 15 s. A payload of `[0x01]` selects a destructive variant; never send it
/// by accident.
pub const CMD_UPDATE: u8 = 0x51;
/// Reboot. Needs a touch within 15 s; no response is sent.
pub const CMD_REBOOT: u8 = 0x53;
/// 57 random bytes.
pub const CMD_RNG: u8 = 0x60;
/// Firmware version: a big-endian `u32` (see [`crate::Version`]), or the
/// full version string when the payload is `[0x01]`.
pub const CMD_VERSION: u8 = 0x61;
/// 16-byte device UUID. Not implemented over CTAPHID by early firmware.
pub const CMD_UUID: u8 = 0x62;
/// One byte: `1` if the device is locked.
pub const CMD_LOCKED: u8 = 0x63;
/// Namespace for newer admin commands; the sub-command is the first
/// payload byte.
pub const CMD_ADMIN: u8 = 0x72;
