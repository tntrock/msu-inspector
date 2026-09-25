//! 核心邏輯：不依賴 GUI，可單獨測試。

pub mod analyze;
pub mod container;
pub mod delta;
pub mod error;
pub mod export;
pub mod local;
pub mod manifest;
pub mod model;
pub mod progress;
pub mod risk;
pub mod signature;
pub mod sys;

pub use error::CoreError;
