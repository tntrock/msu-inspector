//! 分析結果檢視。

use std::path::PathBuf;

use eframe::egui;

use crate::core::export::SizeModel;
use crate::core::model::AnalysisReport;
use crate::i18n::Lang;

pub struct Results {
    pub path: PathBuf,
    pub report: AnalysisReport,
    pub size_model: SizeModel,
}

impl Results {
    pub fn new(report: AnalysisReport, size_model: SizeModel, path: PathBuf) -> Self {
        Results {
            path,
            report,
            size_model,
        }
    }

    pub fn summary_bar(&self, ui: &mut egui::Ui, _lang: Lang) {
        ui.label(self.report.package.kb.as_deref().unwrap_or("-"));
    }

    pub fn status_bar(&mut self, _ui: &mut egui::Ui, _lang: Lang) {}

    pub fn ui(&mut self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        ui.label(format!(
            "{}: {}",
            t.components,
            self.report.components.len()
        ));
    }
}
