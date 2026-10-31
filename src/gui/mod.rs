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

/// GUI 測試共用：不開視窗，只跑 egui 的版面配置，讓繪製程式碼實際執行。
#[cfg(test)]
pub(crate) mod testutil {
    use eframe::egui;

    use crate::core::model::*;

    pub fn frame(ctx: &egui::Context, f: impl FnMut(&mut egui::Ui)) {
        // 沒有繪圖後端：材質更新直接丟棄
        ctx.run_ui(egui::RawInput::default(), f)
            .textures_delta
            .clear();
    }

    /// 兩個元件、高／低風險動作、本機比對結果與警告。
    pub fn report() -> AnalysisReport {
        let local = |state| {
            Some(LocalStatus {
                state,
                current: Some("10.0.1".into()),
                incoming: Some("10.0.2".into()),
            })
        };
        let driver = Action {
            risk: Risk::High,
            rules: vec!["DRV_BOOT_START"],
            local: local(LocalState::Replace),
            ..Action::new(ActionDetail::Driver(DriverAction {
                name: "testdrv".into(),
                ..Default::default()
            }))
        };
        let file = Action {
            risk: Risk::Low,
            ..Action::new(ActionDetail::File(FileAction {
                name: "a.dll".into(),
                destination: "$(runtime.system32)".into(),
                ..Default::default()
            }))
        };
        AnalysisReport {
            mode: Mode::StaticLocal,
            local_context: Some(LocalContext {
                applicable: false,
                not_applicable_reason: Some("arch_mismatch".into()),
                ..Default::default()
            }),
            source: SourceInfo {
                file: "kb.msu".into(),
                signature: SignatureInfo {
                    status: SignatureStatus::Valid,
                    signer: Some("Microsoft".into()),
                },
                ..Default::default()
            },
            package: PackageInfo {
                kb: Some("KB1".into()),
                ..Default::default()
            },
            components: vec![
                Component {
                    identity: AssemblyIdentity {
                        name: "Kernel".into(),
                        ..Default::default()
                    },
                    categories: vec!["boot".into()],
                    local: local(LocalState::NotInStore),
                    actions: vec![driver],
                    ..Default::default()
                },
                Component {
                    actions: vec![file],
                    ..Default::default()
                },
            ],
            warnings: vec![Warning::new(WarningCode::ContainerFailed, "x", "y")],
        }
    }

    #[test]
    fn loads_fonts() {
        let ctx = egui::Context::default();
        super::setup_fonts(&ctx);
        frame(&ctx, |ui| {
            ui.label("繁體中文");
        });
    }
}
