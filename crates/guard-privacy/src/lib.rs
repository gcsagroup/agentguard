//! Privacy engine: GuardContract enforcement + OP/TR/FM scoring.
//!
//! Algorithmic reference: MyPhoneBench (arXiv:2604.00986) PrivacyEvaluator.
//! This crate is a clean-room Rust rewrite — no MyPhoneBench source is vendored.

pub mod anomaly;
pub mod classify;
pub mod entity;
pub mod field;
pub mod firewall;
pub mod isolation;
pub mod logsafe;
pub mod scoring;
pub mod session;
pub mod taint;

pub use anomaly::*;
pub use classify::*;
pub use entity::*;
pub use field::*;
pub use firewall::*;
pub use isolation::*;
pub use logsafe::*;
pub use scoring::*;
pub use session::*;
pub use taint::*;
