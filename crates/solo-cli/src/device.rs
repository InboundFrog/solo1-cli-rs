//! Which Solo model a connected key is, and opening any supported one.
//!
//! Generic CTAPHID and CTAP2 commands work on every model. Vendor commands
//! do not: Solo 1 and Solo 2 reuse some vendor command codes for different
//! operations, so the CLI checks the model before sending one.
use std::fmt;
use std::time::Duration;

use solo_ctaphid::{DeviceFilter, HidDeviceInfo, HidTransport, list_devices};

use crate::error::{Result, SoloError};

/// A supported Solo model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Model {
    Solo1,
    Solo2,
}

impl Model {
    /// Identify a model from its USB vendor and product ID.
    #[must_use]
    pub const fn of(vendor_id: u16, product_id: u16) -> Option<Self> {
        if solo1::is_solo1(vendor_id, product_id) {
            Some(Self::Solo1)
        } else if solo2::is_solo2(vendor_id, product_id) {
            Some(Self::Solo2)
        } else {
            None
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Solo1 => "Solo 1",
            Self::Solo2 => "Solo 2",
        }
    }
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Matches any supported Solo model.
pub const SUPPORTED: DeviceFilter = DeviceFilter::AnyOf(&[solo1::DEVICE_FILTER, solo2::DEVICE_FILTER]);

/// An open key and the model it was identified as.
pub struct Key {
    pub model: Model,
    pub hid: HidTransport,
}

impl Key {
    /// Open any supported key by serial number (or the only one present).
    ///
    /// # Errors
    /// Returns an error if no supported key is found, the serial does not
    /// match, several keys are present without `serial`, or opening fails.
    pub fn open(serial: Option<&str>, timeout: Duration) -> Result<Self> {
        let hid = HidTransport::open(SUPPORTED, serial, timeout)?;
        let model = Model::of(hid.info.vendor_id, hid.info.product_id).ok_or_else(|| {
            SoloError::DeviceError(format!(
                "Unrecognised device {:04x}:{:04x}",
                hid.info.vendor_id, hid.info.product_id
            ))
        })?;
        Ok(Self { model, hid })
    }

    /// Fail with [`SoloError::Unsupported`] unless this key is `model`.
    ///
    /// # Errors
    /// Returns [`SoloError::Unsupported`] naming `command` if the key is a
    /// different model.
    pub fn require(&self, model: Model, command: &'static str) -> Result<()> {
        if self.model == model {
            Ok(())
        } else {
            Err(SoloError::Unsupported {
                command,
                model: self.model.name(),
            })
        }
    }
}

/// List connected keys of every supported model.
///
/// # Errors
/// Returns an error if the HID API cannot be initialized.
pub fn list() -> Result<Vec<(Model, HidDeviceInfo)>> {
    Ok(list_devices(SUPPORTED)?
        .into_iter()
        .filter_map(|d| Model::of(d.vendor_id, d.product_id).map(|m| (m, d)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_of() {
        assert_eq!(Model::of(0x0483, 0xA2CA), Some(Model::Solo1));
        assert_eq!(Model::of(0x1209, 0xBEEE), Some(Model::Solo2));
        assert_eq!(Model::of(0x1209, 0xB000), None); // Solo 2 bootloader
        assert_eq!(Model::of(0x1050, 0x0407), None); // some other FIDO key
    }

    #[test]
    fn test_require_names_command_and_model() {
        let err = SoloError::Unsupported {
            command: "key keyboard",
            model: Model::Solo2.name(),
        };
        assert_eq!(err.to_string(), "`key keyboard` is not supported on Solo 2 yet");
    }
}
