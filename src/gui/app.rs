//! 主視窗：工具列、模式、拖放、背景分析與進度。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;

use eframe::egui;

use super::export_dialog::ExportDialog;
use super::results::Results;
use super::startup::{self, Choice};
use crate::core::analyze::{analyze, AnalyzeOptions};
use crate::core::export::SizeModel;
use crate::core::model::AnalysisReport;
use crate::core::progress::{Ctx, Progress};
use crate::core::CoreError;
use crate::elevation;
use crate::i18n::{error_text, progress_text, Lang};

enum JobMsg {
    Progress(Progress),
    Done(Box<Result<(AnalysisReport, SizeModel), CoreError>>),
}

struct Job {
    file: PathBuf,
    rx: Receiver<JobMsg>,
    cancel: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<()>,
    progress: Option<Progress>,
}

impl Job {
    /// 要求背景工作緒取消並等待它真正結束，確保 `analyze()` 建立的暫存資料夾
    /// 在呼叫端（視窗關閉、以系統管理員重新啟動）讓行程結束之前已經刪除；
    /// 工作緒本來就會在下一個 `ctx.check()` 檢查點停止，這裡只是等它跑到那裡。
    fn cancel_and_join(self) {
        self.cancel.store(true, Ordering::Relaxed);
        let _ = self.handle.join();
    }
}

pub struct App {
    lang: Lang,
    elevated: bool,
    /// 非管理員啟動時，使用者是否已在選擇框做出決定
    mode_chosen: bool,
    pending: Option<PathBuf>,
    job: Option<Job>,
    results: Option<Results>,
    export: Option<ExportDialog>,
    error: Option<String>,
}

impl App {
    pub fn new(file: Option<PathBuf>) -> Self {
        let elevated = elevation::is_elevated();
        App {
            lang: Lang::detect(),
            elevated,
            mode_chosen: elevated,
            pending: file,
            job: None,
            results: None,
            export: None,
            error: None,
        }
    }

    /// 開始分析；已有工作時先取消舊的。
    ///
    /// 這裡只設定取消旗標、不等待（不 join）舊工作緒：join 會卡住 UI 執行緒，
    /// 直到舊工作緒跑到下一個 `ctx.check()` 檢查點（取消的偵測粒度是「每解完
    /// 一個解壓出來的檔案／manifest」）為止。舊工作緒被取代後仍會繼續在背景
    /// 跑到那個檢查點、正常清掉自己的暫存資料夾，只要行程還活著就不會外洩；
    /// 只有在使用者連續開好幾個檔案、又在最舊那個工作緒還沒跑到檢查點前就
    /// 關閉視窗這種邊界情況，才可能因為 `on_exit` 只 join「目前」這個工作而
    /// 沒等到它，如上面 Task 16 fix round 1 的討論，這裡選擇不處理。
    fn start(&mut self, file: PathBuf, ctx: &egui::Context) {
        if let Some(j) = &self.job {
            j.cancel.store(true, Ordering::Relaxed);
        }
        let (tx, rx) = mpsc::channel();
        let progress_tx = tx.clone();
        let repaint = ctx.clone();
        let core_ctx = Ctx::new(move |p| {
            let _ = progress_tx.send(JobMsg::Progress(p));
            repaint.request_repaint();
        });
        let cancel = core_ctx.cancel_flag();
        let opts = AnalyzeOptions {
            compare_local: self.elevated,
            temp_root: None,
        };
        let path = file.clone();
        let done_repaint = ctx.clone();
        let handle = std::thread::spawn(move || {
            let result = analyze(&path, &opts, &core_ctx).map(|r| {
                let model = SizeModel::build(&r);
                (r, model)
            });
            let _ = tx.send(JobMsg::Done(Box::new(result)));
            done_repaint.request_repaint();
        });
        self.results = None;
        self.export = None;
        self.error = None;
        self.job = Some(Job {
            file,
            rx,
            cancel,
            handle,
            progress: None,
        });
    }

    fn poll_job(&mut self) {
        let Some(job) = &mut self.job else {
            return;
        };
        let mut finished = None;
        while let Ok(msg) = job.rx.try_recv() {
            match msg {
                JobMsg::Progress(p) => job.progress = Some(p),
                JobMsg::Done(r) => finished = Some(*r),
            }
        }
        let Some(result) = finished else {
            return;
        };
        let file = job.file.clone();
        self.job = None;
        match result {
            Ok((report, model)) => self.results = Some(Results::new(report, model, file)),
            Err(CoreError::Cancelled) => {}
            Err(e) => self.error = Some(error_text(&e, self.lang)),
        }
    }

    fn current_file(&self) -> Option<PathBuf> {
        self.job
            .as_ref()
            .map(|j| j.file.clone())
            .or_else(|| self.results.as_ref().map(|r| r.path.clone()))
            .or_else(|| self.pending.clone())
    }

    fn relaunch(&mut self, ctx: &egui::Context, file: Option<PathBuf>) {
        match elevation::relaunch_elevated(file.as_deref()) {
            Ok(()) => {
                // 成功叫出新的系統管理員行程後，等目前這個工作緒真正結束（若有），
                // 確保它的暫存資料夾在這個行程關閉前已經刪除，再關閉視窗。
                if let Some(job) = self.job.take() {
                    job.cancel_and_join();
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Err(e) => self.error = Some(format!("{}: {e}", self.lang.strings().elevate_failed)),
        }
    }

    fn open(&mut self, file: PathBuf, ctx: &egui::Context) {
        if self.mode_chosen {
            self.start(file, ctx);
        } else {
            self.pending = Some(file);
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let t = self.lang.strings();
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button(t.open_file).clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter(t.file_filter_name, &["msu", "cab"])
                        .pick_file()
                    {
                        self.open(p, ctx);
                    }
                }
                if ui
                    .add_enabled(self.results.is_some(), egui::Button::new(t.export_json))
                    .clicked()
                {
                    self.export = Some(ExportDialog::new());
                }
                ui.separator();
                ui.label(if self.elevated {
                    t.mode_local
                } else {
                    t.mode_static
                });
                if !self.elevated && ui.button(t.elevate).clicked() {
                    let f = self.current_file();
                    self.relaunch(ctx, f);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::ComboBox::from_id_salt("lang")
                        .selected_text(self.lang.native_name())
                        .show_ui(ui, |ui| {
                            for l in Lang::ALL {
                                ui.selectable_value(&mut self.lang, l, l.native_name());
                            }
                        });
                });
            });
            ui.add_space(4.0);
        });
    }
}

impl eframe::App for App {
    /// 視窗即將關閉（含使用者按 X、或收到 `ViewportCommand::Close`）時，
    /// eframe 在行程真正結束前呼叫一次：取消並等待背景分析工作緒結束，
    /// 讓 `analyze()` 建立的暫存資料夾在行程退出前被刪除。
    fn on_exit(&mut self) {
        if let Some(job) = self.job.take() {
            job.cancel_and_join();
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let t = self.lang.strings();
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(t.app_title.into()));
        self.poll_job();

        if !self.mode_chosen {
            match startup::show(&ctx, t) {
                Some(Choice::Static) => self.mode_chosen = true,
                Some(Choice::Elevate) => {
                    self.mode_chosen = true;
                    let f = self.pending.clone();
                    self.relaunch(&ctx, f);
                }
                None => {}
            }
        }
        if self.mode_chosen && self.job.is_none() {
            if let Some(f) = self.pending.take() {
                self.start(f, &ctx);
            }
        }
        if let Some(p) = ctx.input(|i| i.raw.dropped_files.first().map(|f| f.path().to_path_buf()))
        {
            self.open(p, &ctx);
        }

        self.toolbar(ui, &ctx);
        let lang = self.lang;

        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                if let Some(job) = &self.job {
                    ui.spinner();
                    ui.label(
                        job.progress
                            .as_ref()
                            .map(|p| progress_text(p, lang))
                            .unwrap_or_default(),
                    );
                    if ui.button(t.cancel).clicked() {
                        job.cancel.store(true, Ordering::Relaxed);
                    }
                } else if let Some(r) = &mut self.results {
                    r.status_bar(ui, lang);
                }
            });
        });

        if let Some(r) = &self.results {
            egui::Panel::top("summary").show(ui, |ui| r.summary_bar(ui, lang));
        }

        egui::CentralPanel::default_margins().show(ui, |ui| {
            if let Some(err) = &self.error {
                ui.colored_label(ui.visuals().error_fg_color, err);
                ui.separator();
            }
            if self.job.is_some() {
                ui.centered_and_justified(|ui| ui.spinner());
            } else if let Some(r) = &mut self.results {
                r.ui(ui, lang);
            } else {
                ui.centered_and_justified(|ui| ui.heading(t.drop_hint));
            }
        });

        let mut close_export = false;
        if let (Some(dialog), Some(results)) = (&mut self.export, &self.results) {
            dialog.show(&ctx, lang, results);
            close_export = !dialog.is_open();
        }
        if close_export {
            self.export = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// `cancel_and_join` 是 Task 16 fix round 1 新增的核心行為：它必須真的
    /// 等到背景工作緒看到取消旗標、實際結束之後才回傳，這樣呼叫端（視窗
    /// 關閉、重新啟動為系統管理員）才能保證工作緒建立的資源（實際上是
    /// `analyze()` 的 `TempDir`）在行程繼續之前已經釋放。這裡用一個只會在
    /// 取消旗標被設定後才結束的執行緒取代真正的 `analyze()`，隔離測試
    /// `cancel_and_join`，不必跑完整分析流程或準備 .msu 檔案。
    #[test]
    fn cancel_and_join_waits_for_worker_thread_to_finish() {
        let cancel = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let worker_finished = finished.clone();
        let handle = std::thread::spawn(move || {
            // 模擬 analyze() 在檢查點之間反覆呼叫 ctx.check()。
            while !worker_cancel.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(5));
            }
            worker_finished.store(true, Ordering::Relaxed);
        });
        let (_tx, rx) = mpsc::channel::<JobMsg>();
        let job = Job {
            file: PathBuf::from("dummy.msu"),
            rx,
            cancel,
            handle,
            progress: None,
        };

        let start = Instant::now();
        job.cancel_and_join();

        assert!(
            finished.load(Ordering::Relaxed),
            "cancel_and_join returned before the worker thread finished"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "cancel_and_join took unexpectedly long; the worker may not have observed the cancel flag"
        );
    }
}
