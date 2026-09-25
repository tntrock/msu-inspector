//! 核心邏輯：不依賴 GUI，可單獨測試。

pub mod error;
pub mod manifest;
pub mod model;
pub mod progress;

pub use error::CoreError;
