//! voli-core: shared library for the voli package manager.
//!
//! Phase 1 step 3: the manifest schema (§4) plus the transactional local
//! install/uninstall engine (§3, §11 step 3) and its state ledger. No network.

pub mod config;
#[cfg(windows)]
pub mod env;
pub mod fetch;
pub mod index;
#[cfg(windows)]
pub mod install;
pub mod manifest;
pub mod paths;
#[cfg(windows)]
pub mod remote;
#[cfg(windows)]
pub mod selfinstall;
#[cfg(windows)]
pub mod state;

pub use config::Config;
pub use fetch::{FetchError, download};
#[cfg(windows)]
pub use install::{
    Action, DirRole, EnvConsent, InstallError, InstallReport, UninstallReport, UpgradeReport,
    cleanup_versions, dir_size, install_local, install_manifest, skip_env, uninstall,
    uninstall_env, upgrade_install,
};
pub use manifest::{Bin, ExtraSource, Kind, Manifest, ManifestError, Shortcut, Source, WriteFile};
pub use paths::Paths;
#[cfg(windows)]
pub use remote::{
    RemoteError, RemoteReport, Step, UpgradeOutcome, install_remote, install_remote_env, upgrade,
};
#[cfg(windows)]
pub use selfinstall::{SelfInstallError, SelfInstallReport, self_install};
#[cfg(windows)]
pub use state::{InstalledPkg, State};
