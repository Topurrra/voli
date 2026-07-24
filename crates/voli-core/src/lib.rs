//! voli-core: shared library for the voli package manager.
//!
//! Phase 1 step 2: the package manifest schema (§4 of the spec) plus parsing
//! and validation. No network, no install engine yet.

pub mod manifest;

pub use manifest::{Bin, Kind, Manifest, ManifestError, Source};
