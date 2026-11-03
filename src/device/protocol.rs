// CTAPHID protocol constants (FIDO CTAP 2.x, section 11.2 "USB HID").
//
// Everything here is device-neutral. Vendor command codes and USB
// identifiers for specific authenticators live in their device modules
// (e.g. `crate::solo1::protocol`).

// HID report size
pub const HID_REPORT_SIZE: usize = 64;

// CTAPHID commands
pub const CTAPHID_INIT: u8 = 0x86;
pub const CTAPHID_MSG: u8 = 0x83;
pub const CTAPHID_CBOR: u8 = 0x90;
pub const CTAPHID_PING: u8 = 0x81;
pub const CTAPHID_WINK: u8 = 0x88;
pub const CTAPHID_VENDOR_FIRST: u8 = 0x40;

// Broadcast channel for CTAPHID_INIT
pub const CTAPHID_BROADCAST_CID: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
