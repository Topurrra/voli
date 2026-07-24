//! voli-core: shared library for the voli package manager.
//!
//! Phase 1 step 3: the manifest schema (§4) plus the transactional local
//! install/uninstall engine (§3, §11 step 3) and its state ledger. No network.

pub mod install;
pub mod manifest;
pub mod paths;
pub mod state;

pub use install::{
    Action, DirRole, InstallError, InstallReport, UninstallReport, install_local, uninstall,
};
pub use manifest::{Bin, Kind, Manifest, ManifestError, Source};
pub use paths::Paths;
pub use state::{InstalledPkg, State};
