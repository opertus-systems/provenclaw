pub mod actions;
pub mod app;
pub mod components;
pub mod event_loop;
pub mod services;
pub mod state;
pub mod theme;
pub mod views;

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone, Default)]
pub struct TuiOptions {
    pub read_only: bool,
    pub snapshot: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("host error: {0}")]
    Host(#[from] provenclaw_host::HostError),
}

pub fn run_tui(options: TuiOptions) -> Result<(), TuiError> {
    event_loop::run(options)
}
