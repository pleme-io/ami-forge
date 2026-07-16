//! ami-forge library — shared AMI build pipeline logic.
//!
//! `main.rs` is a thin CLI shell over these modules: it parses argv into a
//! `clap::Args` struct per subcommand and calls straight through to the
//! matching module's `run()`. Exposing the modules here (rather than as
//! private `mod` items in the bin crate) lets a second consumer call the
//! same, already-proven logic in-process instead of shelling out to the
//! `ami-forge` binary or re-deriving it.
//!
//! The first such consumer is igata's `amazon-import` builder
//! (`pleme-io/igata::builder::amazon_import`), which depends on this crate
//! by path and calls [`build::run`] directly so `igata build <template>`
//! becomes the single front door for building AMIs from pre-built Nix disk
//! images — no separate manual `ami-forge build` invocation needed
//! afterward.

pub mod attic;
pub mod aws;
pub mod boot_check;
pub mod build;
pub mod cluster_test;
pub mod hardening_gate;
pub mod manifest;
pub mod multi_layer;
pub mod pipeline;
pub mod promote;
pub mod reaper;
pub mod rotate;
pub mod status;
pub mod trigger;
pub mod wg;
