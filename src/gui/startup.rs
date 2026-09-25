//! 非管理員啟動時的模式選擇框。

use eframe::egui;

use crate::i18n::Strings;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Static,
    Elevate,
}

/// 每個影格呼叫；使用者做出選擇時回傳 Some。按 Esc 或點外面視為選擇靜態分析。
pub fn show(ctx: &egui::Context, t: &Strings) -> Option<Choice> {
    let mut choice = None;
    let resp = egui::Modal::new(egui::Id::new("startup-mode")).show(ctx, |ui| {
        ui.set_max_width(460.0);
        ui.heading(t.startup_title);
        ui.add_space(6.0);
        ui.label(t.startup_body);
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button(t.startup_static).clicked() {
                choice = Some(Choice::Static);
            }
            if ui.button(t.startup_elevate).clicked() {
                choice = Some(Choice::Elevate);
            }
        });
    });
    if choice.is_none() && resp.should_close() {
        choice = Some(Choice::Static);
    }
    choice
}
