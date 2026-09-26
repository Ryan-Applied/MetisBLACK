//! Pure, bounded web-surface discovery contracts and deterministic parsers.
//!
//! This crate performs no I/O and does not create findings. Callers acquire
//! documents under central policy, seal receipts, and submit observations here.

mod contract;
mod parse;
mod state;

pub use contract::*;
pub use state::DiscoverySession;
