//! 背景分析的進度回報與取消旗標。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::CoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    Hashing,
    Verifying,
    Unpacking { container: String },
    Decoding { done: usize, total: usize },
    Comparing { done: usize, total: usize },
}

type ProgressFn = dyn Fn(Progress) + Send + Sync;

/// 分析流程共用的環境：進度回呼 + 取消旗標。可 clone 給工作執行緒。
#[derive(Clone)]
pub struct Ctx {
    cancel: Arc<AtomicBool>,
    progress: Arc<ProgressFn>,
}

impl Ctx {
    pub fn new(progress: impl Fn(Progress) + Send + Sync + 'static) -> Self {
        Ctx {
            cancel: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(progress),
        }
    }

    /// 不回報進度（CLI、測試）。
    pub fn silent() -> Self {
        Ctx::new(|_| {})
    }

    pub fn report(&self, p: Progress) {
        (self.progress)(p);
    }

    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// 已取消時回傳 `Err(CoreError::Cancelled)`，供各階段之間檢查。
    pub fn check(&self) -> Result<(), CoreError> {
        if self.is_cancelled() {
            Err(CoreError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn reports_and_cancels() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let ctx = Ctx::new(move |p| s.lock().unwrap().push(p));
        ctx.report(Progress::Hashing);
        assert!(ctx.check().is_ok());
        ctx.cancel_flag().store(true, Ordering::Relaxed);
        assert!(matches!(ctx.check(), Err(CoreError::Cancelled)));
        assert_eq!(*seen.lock().unwrap(), vec![Progress::Hashing]);
    }
}
