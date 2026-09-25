//! core 的錯誤型別；Display 為英文（CLI / 記錄用），GUI 經 i18n 轉成在地化訊息。

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("unsupported file format: {0}")]
    UnsupportedFormat(String),
    #[error("cannot unpack {path}: {detail}")]
    Container { path: String, detail: String },
    #[error("administrator rights required: {0}")]
    NeedsElevation(String),
    #[error("delta decompression failed: {0}")]
    Delta(String),
    #[error("XML error: {0}")]
    Xml(String),
    #[error("no update package (.mum / .manifest) found")]
    NoPackageFound,
    #[error("cancelled")]
    Cancelled,
    #[error("Windows API error: {0}")]
    Win32(String),
}

impl CoreError {
    pub fn io(path: &Path, source: std::io::Error) -> Self {
        CoreError::Io {
            path: path.display().to_string(),
            source,
        }
    }
}
