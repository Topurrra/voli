//! voli-core: shared library for the voli package manager.
//!
//! Phase 1 step 3: the manifest schema (§4) plus the transactional local
//! install/uninstall engine (§3, §11 step 3) and its state ledger. No network.

pub mod config;
pub mod env;
pub mod fetch;
pub mod index;
pub mod install;
pub mod manifest;
pub mod paths;
pub mod remote;
pub mod selfinstall;
pub mod shim_icon;
pub mod skill;
pub mod state;
pub mod uninstall_reg;

pub use config::Config;
pub use fetch::{FetchError, download};
pub use install::{
    Action, DirRole, EnvConsent, InstallError, InstallReport, UninstallReport, UpgradeReport,
    cleanup_versions, dir_size, host_arch, install_local, install_manifest, skip_env, uninstall,
    uninstall_env, upgrade_install,
};
pub use manifest::{
    Arch, ArchFallback, Bin, ExtraSource, Kind, Manifest, ManifestError, PackageRef,
    PackageRefError, SelectedSource, Shortcut, Source, SourceKind, WriteFile,
};
pub use paths::{Paths, SKILL_TARGET_IDS, SkillScope, SkillTarget, SkillTargetError};
pub use remote::{
    RemoteError, RemoteReport, SkillRemoteReport, SkillStep, Step, UpgradeOutcome, install_remote,
    install_remote_env, install_skill_remote, install_skill_remote_many, upgrade,
};
pub use selfinstall::{SelfInstallError, SelfInstallReport, self_install};
pub use skill::{
    SkillError, SkillInstallReport, SkillUninstallReport, install_skill_archive,
    install_skill_archive_many, install_skill_archive_scoped, uninstall_installed_skill,
    uninstall_skill, uninstall_skill_scoped,
};
pub use state::{InstalledPkg, InstalledSkill, SkillAction, State};
