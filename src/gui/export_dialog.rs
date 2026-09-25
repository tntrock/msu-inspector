//! 匯出 JSON 對話框。

use eframe::egui;

use super::results::Results;
use crate::i18n::Lang;

pub struct ExportDialog {
    open: bool,
}

impl Default for ExportDialog {
    fn default() -> Self {
        Self::new()
    }
}

impl ExportDialog {
    pub fn new() -> Self {
        ExportDialog { open: true }
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn show(&mut self, ctx: &egui::Context, lang: Lang, _results: &Results) {
        let mut open = self.open;
        egui::Window::new(lang.strings().export_title)
            .open(&mut open)
            .show(ctx, |_ui| {});
        self.open = open;
    }
}
