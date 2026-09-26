//! 圖形介面（egui / eframe）。

mod app;
mod elevated_drop;
pub mod export_dialog;
pub mod results;
mod startup;

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;

/// 開啟 GUI 直到視窗關閉；`file` 為啟動時要分析的檔案（例如從提升權限重新啟動）。
pub fn run(file: Option<PathBuf>) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 760.0])
            .with_min_inner_size([860.0, 520.0])
            // 提升權限時 OLE 拖放會被 UIPI 擋下，改由 elevated_drop 以 WM_DROPFILES 接收
            .with_drag_and_drop(!crate::elevation::is_elevated()),
        ..Default::default()
    };
    eframe::run_native(
        "msu-inspector",
        options,
        Box::new(move |cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(app::App::new(file)))
        }),
    )
}

/// 載入系統中文字型作為備援字型，不把字型檔塞進 exe。
fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let candidates = [
        r"C:\Windows\Fonts\msjh.ttc",
        r"C:\Windows\Fonts\msjhl.ttc",
        r"C:\Windows\Fonts\mingliu.ttc",
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simsun.ttc",
    ];
    if let Some(bytes) = candidates.iter().find_map(|p| std::fs::read(p).ok()) {
        fonts.font_data.insert(
            "cjk".to_owned(),
            Arc::new(egui::FontData::from_owned(bytes)),
        );
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push("cjk".to_owned());
        }
    }
    ctx.set_fonts(fonts);
}
