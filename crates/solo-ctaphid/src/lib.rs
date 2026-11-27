//! CTAPHID (FIDO CTAP over USB HID) framing and transport.
//!
//! Device-neutral. Vendor commands for specific authenticators are built on
//! top of [`HidDevice`] in their own crates (e.g. `solo1`).
//!
//! With the `test-util` feature, `mock::MockDevice` is available to other
//! crates' tests.
pub mod error;
pub mod frame;
pub mod hid;
pub mod protocol;

/// Trait abstracting the send/receive interface of a CTAP HID device.
///
/// Command functions take `&impl HidDevice` (or `&mut impl HidDevice`)
/// instead of a concrete `&HidTransport`. This lets tests use `MockDevice`
/// without a physical device.
pub trait HidDevice {
    /// Send a command with payload, receive and return the response payload.
    ///
    /// # Errors
    /// Returns an error if the device transaction fails, e.g. an I/O error or a
    /// timeout waiting for the response.
    fn send_recv(&self, cmd: u8, data: &[u8]) -> crate::Result<Vec<u8>>;

    /// Send a command with payload without waiting for a response.
    ///
    /// # Errors
    /// Returns an error if sending the command to the device fails.
    fn send(&self, cmd: u8, data: &[u8]) -> crate::Result<()>;
}

// CTAPHID protocol constants
pub use protocol::{
    CTAPHID_BROADCAST_CID, CTAPHID_CBOR, CTAPHID_INIT, CTAPHID_MSG, CTAPHID_PING, CTAPHID_VENDOR_FIRST, CTAPHID_WINK,
    FIDO_USAGE, FIDO_USAGE_PAGE, HID_REPORT_SIZE,
};

// Frame types and helpers
pub use frame::{CTAPHID_MAX_PAYLOAD, CtapHidFrame, FramePayload, build_ctaphid_frames, reassemble_frames};

// Device communication
pub use hid::{DeviceFilter, HidDeviceInfo, HidIds, HidTransport, list_devices};

pub use error::{Error, Result};

#[cfg(any(test, feature = "test-util"))]
pub mod mock {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::HidDevice;

    /// A mock HID device for unit testing.
    ///
    /// Responses are queued when the mock is created. `send_recv` returns them
    /// in order. When the queue is empty, `send_recv` returns
    /// `Err(Error::Timeout)`. `send` always succeeds.
    pub struct MockDevice {
        pub responses: RefCell<VecDeque<crate::Result<Vec<u8>>>>,
    }

    impl MockDevice {
        #[must_use]
        pub fn new(responses: Vec<crate::Result<Vec<u8>>>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
            }
        }
    }

    impl HidDevice for MockDevice {
        fn send_recv(&self, _cmd: u8, _data: &[u8]) -> crate::Result<Vec<u8>> {
            self.responses
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(crate::Error::Timeout))
        }

        fn send(&self, _cmd: u8, _data: &[u8]) -> crate::Result<()> {
            Ok(())
        }
    }
}
