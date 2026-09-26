//! 分析結果檢視：概要列、分類樹、虛擬捲動表格、詳細資料、警告視窗。

use std::collections::BTreeMap;
use std::path::PathBuf;

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::core::export::{warning_message, SizeModel};
use crate::core::model::*;
use crate::core::risk;
use crate::i18n::{kind_name, local_name, not_applicable_text, risk_name, signature_name, Lang};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeSel {
    All,
    HighRisk,
    Kind(ActionKind),
}

/// 篩選條件：分類樹選擇、風險勾選（依 `Risk::ALL` 順序）、搜尋字串（已轉小寫）。
pub(crate) fn row_matches(
    c: &Component,
    a: &Action,
    tree: TreeSel,
    risks: &[bool; 4],
    needle: &str,
) -> bool {
    let tree_ok = match tree {
        TreeSel::All => true,
        TreeSel::HighRisk => a.risk == Risk::High,
        TreeSel::Kind(k) => a.kind() == k,
    };
    let risk_idx = Risk::ALL.iter().position(|r| *r == a.risk).unwrap_or(0);
    tree_ok
        && risks[risk_idx]
        && (needle.is_empty()
            || a.detail.target().to_lowercase().contains(needle)
            || c.identity.name.to_lowercase().contains(needle))
}

fn risk_color(r: Risk, ui: &egui::Ui) -> egui::Color32 {
    match r {
        Risk::High => ui.visuals().error_fg_color,
        Risk::Medium => ui.visuals().warn_fg_color,
        Risk::Low => ui.visuals().text_color(),
        Risk::Info => ui.visuals().weak_text_color(),
    }
}

pub struct Results {
    pub path: PathBuf,
    pub report: AnalysisReport,
    pub size_model: SizeModel,
    rows: Vec<(u32, u32)>,
    filtered: Vec<usize>,
    tree: TreeSel,
    search: String,
    risks: [bool; 4],
    selected: Option<usize>,
    dirty: bool,
    show_warnings: bool,
    kind_counts: BTreeMap<ActionKind, usize>,
    high_count: usize,
}

impl Results {
    pub fn new(report: AnalysisReport, size_model: SizeModel, path: PathBuf) -> Self {
        let mut rows = Vec::with_capacity(report.action_count());
        let mut kind_counts = BTreeMap::new();
        let mut high_count = 0;
        for (ci, c) in report.components.iter().enumerate() {
            for (ai, a) in c.actions.iter().enumerate() {
                rows.push((ci as u32, ai as u32));
                *kind_counts.entry(a.kind()).or_default() += 1;
                if a.risk == Risk::High {
                    high_count += 1;
                }
            }
        }
        let filtered = (0..rows.len()).collect();
        Results {
            path,
            report,
            size_model,
            rows,
            filtered,
            tree: TreeSel::All,
            search: String::new(),
            risks: [true; 4],
            selected: None,
            dirty: false,
            show_warnings: false,
            kind_counts,
            high_count,
        }
    }

    pub fn kind_count(&self, k: ActionKind) -> usize {
        self.kind_counts.get(&k).copied().unwrap_or(0)
    }

    fn row(&self, i: usize) -> (&Component, &Action) {
        let (ci, ai) = self.rows[i];
        let c = &self.report.components[ci as usize];
        (c, &c.actions[ai as usize])
    }

    fn refilter(&mut self) {
        let needle = self.search.trim().to_lowercase();
        self.filtered = (0..self.rows.len())
            .filter(|&i| {
                let (c, a) = self.row(i);
                row_matches(c, a, self.tree, &self.risks, &needle)
            })
            .collect();
        if self.selected.is_some_and(|s| !self.filtered.contains(&s)) {
            self.selected = None;
        }
        self.dirty = false;
    }

    pub fn summary_bar(&self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        let r = &self.report;
        let p = &r.package;
        ui.horizontal_wrapped(|ui| {
            ui.strong(p.kb.as_deref().unwrap_or("-"));
            ui.label(format!("· {}", p.release_type.as_deref().unwrap_or("-")));
            ui.label(format!("· {}", p.identity.arch));
            ui.label(format!(
                "· {}: {}",
                t.restart,
                p.restart.as_deref().unwrap_or("-")
            ));
            ui.label(format!("· {} {}", t.components, r.components.len()));
            ui.label(format!("· {} {}", t.actions, self.rows.len()));
            ui.colored_label(
                ui.visuals().error_fg_color,
                format!("· ⚠ {} {}", t.high_risk, self.high_count),
            );
            let sig = &r.source.signature;
            let sig_text = format!(
                "· {}: {}{}",
                t.signature,
                signature_name(sig.status, lang),
                sig.signer
                    .as_deref()
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default()
            );
            if sig.status == SignatureStatus::Valid {
                ui.label(sig_text);
            } else {
                ui.colored_label(ui.visuals().error_fg_color, sig_text);
            }
        });
        if let Some(ctx) = &r.local_context {
            if !ctx.applicable {
                let reason = ctx.not_applicable_reason.as_deref().unwrap_or("");
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    not_applicable_text(reason, lang),
                );
            }
        }
    }

    pub fn status_bar(&mut self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        ui.label(format!(
            "{} · {} · {}",
            self.report.source.file,
            self.report.source.format,
            self.report.mode.code()
        ));
        ui.separator();
        let n = self.report.warnings.len();
        let label = format!("{} {n}", t.warnings);
        if n == 0 {
            ui.label(label);
        } else if ui.link(label).clicked() {
            self.show_warnings = true;
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, lang: Lang) {
        if self.dirty {
            self.refilter();
        }
        self.tree_panel(ui, lang);
        egui::Panel::right("details")
            .resizable(true)
            .default_size(360.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| self.details(ui, lang));
            });
        egui::CentralPanel::default_margins().show(ui, |ui| {
            self.filter_bar(ui, lang);
            self.table(ui, lang);
        });
        self.warnings_window(ui.ctx(), lang);
    }

    fn tree_panel(&mut self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        egui::Panel::left("tree")
            .resizable(true)
            .default_size(200.0)
            .show(ui, |ui| {
                let mut sel = self.tree;
                ui.selectable_value(
                    &mut sel,
                    TreeSel::All,
                    format!("{} ({})", t.tree_all, self.rows.len()),
                );
                ui.selectable_value(
                    &mut sel,
                    TreeSel::HighRisk,
                    format!("⚠ {} ({})", t.high_risk, self.high_count),
                );
                ui.separator();
                for k in ActionKind::ALL {
                    let n = self.kind_count(k);
                    if n > 0 {
                        ui.selectable_value(
                            &mut sel,
                            TreeSel::Kind(k),
                            format!("{} ({n})", kind_name(k, lang)),
                        );
                    }
                }
                if sel != self.tree {
                    self.tree = sel;
                    self.dirty = true;
                }
            });
    }

    fn filter_bar(&mut self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text(t.search_hint)
                    .desired_width(260.0),
            );
            if resp.changed() {
                self.dirty = true;
            }
            ui.separator();
            ui.label(t.col_risk);
            for (i, r) in Risk::ALL.iter().enumerate() {
                if ui
                    .checkbox(&mut self.risks[i], risk_name(*r, lang))
                    .changed()
                {
                    self.dirty = true;
                }
            }
            ui.label(format!("{} / {}", self.filtered.len(), self.rows.len()));
        });
        ui.add_space(4.0);
    }

    fn table(&mut self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        let mut clicked = None;
        let local_mode = self.report.mode == Mode::StaticLocal;
        let mut builder = TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .column(Column::initial(60.0).at_least(40.0))
            .column(Column::initial(110.0).at_least(60.0))
            .column(Column::remainder().at_least(200.0).clip(true))
            .column(Column::initial(240.0).at_least(80.0).clip(true));
        if local_mode {
            builder = builder.column(Column::initial(110.0).at_least(60.0));
        }
        builder
            .header(20.0, |mut h| {
                h.col(|ui| {
                    ui.strong(t.col_risk);
                });
                h.col(|ui| {
                    ui.strong(t.col_kind);
                });
                h.col(|ui| {
                    ui.strong(t.col_target);
                });
                h.col(|ui| {
                    ui.strong(t.col_component);
                });
                if local_mode {
                    h.col(|ui| {
                        ui.strong(t.col_local);
                    });
                }
            })
            .body(|body| {
                body.rows(18.0, self.filtered.len(), |mut row| {
                    let i = self.filtered[row.index()];
                    let (c, a) = self.row(i);
                    row.set_selected(self.selected == Some(i));
                    row.col(|ui| {
                        ui.colored_label(risk_color(a.risk, ui), risk_name(a.risk, lang));
                    });
                    row.col(|ui| {
                        ui.label(kind_name(a.kind(), lang));
                    });
                    row.col(|ui| {
                        ui.label(egui::RichText::new(a.detail.target()).monospace());
                    });
                    row.col(|ui| {
                        ui.label(&c.identity.name);
                    });
                    if local_mode {
                        row.col(|ui| {
                            if let Some(l) = &a.local {
                                ui.label(local_name(l.state, lang));
                            }
                        });
                    }
                    if row.response().clicked() {
                        clicked = Some(i);
                    }
                });
            });
        if clicked.is_some() {
            self.selected = clicked;
        }
    }

    fn details(&self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        let Some(i) = self.selected else {
            ui.label(t.details_none);
            return;
        };
        let (c, a) = self.row(i);
        ui.heading(kind_name(a.kind(), lang));
        ui.label(egui::RichText::new(a.detail.target()).monospace());
        ui.colored_label(
            risk_color(a.risk, ui),
            format!("{}: {}", t.col_risk, risk_name(a.risk, lang)),
        );
        if !a.rules.is_empty() {
            ui.add_space(6.0);
            ui.strong(t.details_rules);
            for id in &a.rules {
                if let Some(r) = risk::rule(id) {
                    ui.label(format!("• {} — {}", r.id, r.reason(lang)));
                }
            }
        }
        if let Some(l) = &a.local {
            ui.add_space(6.0);
            ui.label(format!(
                "{}: {}  {} → {}",
                t.col_local,
                local_name(l.state, lang),
                l.current.as_deref().unwrap_or("-"),
                l.incoming.as_deref().unwrap_or("-")
            ));
        }
        ui.add_space(6.0);
        ui.strong(t.details_component);
        ui.label(c.identity.display());
        ui.label(egui::RichText::new(&c.manifest).small());
        if !c.categories.is_empty() {
            ui.label(c.categories.join(", "));
        }
        if let Some(l) = &c.local {
            ui.label(local_name(l.state, lang));
        }
        ui.add_space(6.0);
        ui.strong(t.details_fields);
        let json = serde_json::to_string_pretty(&a.detail).unwrap_or_default();
        ui.add(
            egui::TextEdit::multiline(&mut json.as_str())
                .code_editor()
                .desired_width(f32::INFINITY),
        );
    }

    fn warnings_window(&mut self, ctx: &egui::Context, lang: Lang) {
        let t = lang.strings();
        let mut open = self.show_warnings;
        egui::Window::new(t.warnings)
            .open(&mut open)
            .default_size([640.0, 360.0])
            .show(ctx, |ui| {
                if self.report.warnings.is_empty() {
                    ui.label(t.no_warnings);
                }
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for w in &self.report.warnings {
                        ui.strong(warning_message(w.code, lang));
                        ui.label(
                            egui::RichText::new(format!("{}\n{}", w.subject, w.detail))
                                .small()
                                .monospace(),
                        );
                        ui.separator();
                    }
                });
            });
        self.show_warnings = open;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comp() -> Component {
        Component {
            identity: AssemblyIdentity {
                name: "Microsoft-Windows-Kernel".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn action(kind_file: bool, risk: Risk) -> Action {
        let detail = if kind_file {
            ActionDetail::File(FileAction {
                name: "ntoskrnl.exe".into(),
                destination: "$(runtime.system32)".into(),
                ..Default::default()
            })
        } else {
            ActionDetail::Service(ServiceAction {
                name: "EventLog".into(),
                ..Default::default()
            })
        };
        Action {
            risk,
            ..Action::new(detail)
        }
    }

    #[test]
    fn filters_by_tree_risk_and_search() {
        let c = comp();
        let all_risks = [true; 4];
        let file_high = action(true, Risk::High);
        let svc_low = action(false, Risk::Low);
        assert!(row_matches(&c, &file_high, TreeSel::All, &all_risks, ""));
        assert!(row_matches(
            &c,
            &file_high,
            TreeSel::HighRisk,
            &all_risks,
            ""
        ));
        assert!(!row_matches(
            &c,
            &svc_low,
            TreeSel::HighRisk,
            &all_risks,
            ""
        ));
        assert!(row_matches(
            &c,
            &svc_low,
            TreeSel::Kind(ActionKind::Service),
            &all_risks,
            ""
        ));
        assert!(!row_matches(
            &c,
            &svc_low,
            TreeSel::Kind(ActionKind::File),
            &all_risks,
            ""
        ));
        // Risk::ALL 順序為 High、Medium、Low、Info
        assert!(!row_matches(
            &c,
            &svc_low,
            TreeSel::All,
            &[true, true, false, true],
            ""
        ));
        assert!(row_matches(
            &c,
            &file_high,
            TreeSel::All,
            &all_risks,
            "ntoskrnl"
        ));
        assert!(
            row_matches(&c, &svc_low, TreeSel::All, &all_risks, "kernel"),
            "matches component name"
        );
        assert!(!row_matches(&c, &svc_low, TreeSel::All, &all_risks, "zzz"));
    }
}
