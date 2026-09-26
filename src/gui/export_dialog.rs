//! 匯出 JSON 對話框：類別勾選、細節程度、即時預估大小、存檔、複製到剪貼簿。

use std::collections::BTreeSet;

use eframe::egui;

use super::results::Results;
use crate::core::export::{build, now_rfc3339, to_json_string, Detail, ExportOptions};
use crate::core::model::{ActionKind, AnalysisReport};
use crate::i18n::{detail_name, kind_name, Lang};

pub(crate) fn human_size(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{bytes} B")
    } else if b < KB * KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{:.1} MB", b / KB / KB)
    }
}

pub(crate) fn default_file_name(report: &AnalysisReport, detail: Detail) -> String {
    let stem = report.package.kb.clone().unwrap_or_else(|| {
        std::path::Path::new(&report.source.file)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "report".into())
    });
    format!(
        "{stem}-{}-{}.json",
        report.mode.code().replace('+', "-"),
        detail.code()
    )
}

pub struct ExportDialog {
    open: bool,
    kinds: BTreeSet<ActionKind>,
    detail: Detail,
    message: Option<String>,
}

impl Default for ExportDialog {
    fn default() -> Self {
        Self::new()
    }
}

impl ExportDialog {
    pub fn new() -> Self {
        ExportDialog {
            open: true,
            kinds: ActionKind::ALL.into_iter().collect(),
            detail: Detail::Risk,
            message: None,
        }
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn show(&mut self, ctx: &egui::Context, lang: Lang, results: &Results) {
        let t = lang.strings();
        let mut open = self.open;
        egui::Window::new(t.export_title)
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.strong(t.export_kinds);
                ui.horizontal(|ui| {
                    if ui.small_button(t.select_all).clicked() {
                        self.kinds = ActionKind::ALL.into_iter().collect();
                    }
                    if ui.small_button(t.select_none).clicked() {
                        self.kinds.clear();
                    }
                });
                egui::Grid::new("export-kinds")
                    .num_columns(3)
                    .show(ui, |ui| {
                        for (i, k) in ActionKind::ALL.into_iter().enumerate() {
                            let mut on = self.kinds.contains(&k);
                            let label =
                                format!("{} ({})", kind_name(k, lang), results.kind_count(k));
                            if ui.checkbox(&mut on, label).changed() {
                                if on {
                                    self.kinds.insert(k);
                                } else {
                                    self.kinds.remove(&k);
                                }
                            }
                            if i % 3 == 2 {
                                ui.end_row();
                            }
                        }
                    });
                ui.separator();
                ui.strong(t.export_detail);
                for d in Detail::ALL {
                    ui.radio_value(&mut self.detail, d, detail_name(d, lang));
                }
                let opts = ExportOptions {
                    kinds: self.kinds.clone(),
                    detail: self.detail,
                    lang,
                };
                ui.label(format!(
                    "{} {}",
                    t.estimated_size,
                    human_size(results.size_model.estimate(&opts))
                ));
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button(t.export_save).clicked() {
                        self.save(results, &opts);
                    }
                    if ui.button(t.export_copy).clicked() {
                        let summary = ExportOptions::all(Detail::Risk, lang);
                        ctx.copy_text(to_json_string(&build(
                            &results.report,
                            &summary,
                            &now_rfc3339(),
                        )));
                        self.message = Some(t.copied.to_string());
                    }
                });
                if let Some(m) = &self.message {
                    ui.label(m);
                }
            });
        self.open = open;
    }

    fn save(&mut self, results: &Results, opts: &ExportOptions) {
        let t = opts.lang.strings();
        let Some(path) = rfd::FileDialog::new()
            .add_filter("JSON", &["json"])
            .set_file_name(default_file_name(&results.report, opts.detail))
            .save_file()
        else {
            return;
        };
        let json = to_json_string(&build(&results.report, opts, &now_rfc3339()));
        self.message = Some(match std::fs::write(&path, json) {
            Ok(()) => format!("{} {}", t.saved_to, path.display()),
            Err(e) => format!("{}: {e}", path.display()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{AnalysisReport, Mode};

    #[test]
    fn formats_sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KB");
        assert_eq!(human_size(5 * 1024 * 1024 + 300 * 1024), "5.3 MB");
    }

    #[test]
    fn builds_default_file_names() {
        let mut r = AnalysisReport::default();
        r.package.kb = Some("KB5129195".into());
        r.mode = Mode::StaticLocal;
        assert_eq!(
            default_file_name(&r, Detail::Risk),
            "KB5129195-static-local-risk.json"
        );
        r.package.kb = None;
        r.source.file = "windows11.0-x64.msu".into();
        r.mode = Mode::Static;
        assert_eq!(
            default_file_name(&r, Detail::Full),
            "windows11.0-x64-static-full.json"
        );
    }
}
