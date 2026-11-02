//! Which kind of installer stick this boot came from, read from the kernel command line.

/// Mount point of the Ventoy stick's data partition (exFAT), set up by the initrd.
pub const VENTOY_MOUNT: &str = "/run/mastersos-ventoy";
/// File the initrd writes with the device path of that exFAT partition.
pub const VENTOY_PART_FILE: &str = "/run/mastersos-ventoy.part";
/// Folder on the Ventoy stick that holds `seed.toml` and the system file.
pub const VENTOY_FOLDER: &str = "MastersOS";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Whole-stick installer: the seed lives on the GPT partition labelled `mastersos-usb-seed`.
    Stick,
    /// Ventoy stick: the seed lives in the `MastersOS` folder of the exFAT partition.
    Ventoy { version: String },
}

/// `mastersos.ventoy=<version>` (non-empty) on the command line selects [`Mode::Ventoy`].
pub fn mode_from_cmdline(cmdline: &str) -> Mode {
    cmdline
        .split_whitespace()
        .find_map(|w| w.strip_prefix("mastersos.ventoy="))
        .filter(|v| !v.is_empty())
        .map_or(Mode::Stick, |v| Mode::Ventoy {
            version: v.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_stick_by_default() {
        assert_eq!(mode_from_cmdline("root=tmpfs quiet"), Mode::Stick);
    }

    #[test]
    fn mode_ventoy() {
        assert_eq!(
            mode_from_cmdline("quiet mastersos.ventoy=20261028.4 x=1"),
            Mode::Ventoy {
                version: "20261028.4".into()
            }
        );
    }

    #[test]
    fn mode_ventoy_empty_is_stick() {
        assert_eq!(mode_from_cmdline("mastersos.ventoy="), Mode::Stick);
        assert_eq!(mode_from_cmdline("mastersos.ventoy_size=123"), Mode::Stick);
        assert_eq!(
            mode_from_cmdline("quiet mastersos.ventoy_sha256=abcdef0123"),
            Mode::Stick
        );
        assert_eq!(mode_from_cmdline("xmastersos.ventoy=1"), Mode::Stick);
    }
}
