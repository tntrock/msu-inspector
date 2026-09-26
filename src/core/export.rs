//! JSON 匯出（給 AI 分析）與大小預估。鍵名一律英文；說明文字依匯出語言。

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use super::model::*;
use super::risk;
use crate::i18n::Lang;

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Detail {
    Summary,
    Risk,
    Full,
}

impl Detail {
    pub const ALL: [Detail; 3] = [Detail::Summary, Detail::Risk, Detail::Full];

    pub fn code(self) -> &'static str {
        match self {
            Detail::Summary => "summary",
            Detail::Risk => "risk",
            Detail::Full => "full",
        }
    }

    pub fn parse(s: &str) -> Option<Detail> {
        Detail::ALL
            .into_iter()
            .find(|d| d.code().eq_ignore_ascii_case(s.trim()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOptions {
    pub kinds: BTreeSet<ActionKind>,
    pub detail: Detail,
    pub lang: Lang,
}

impl ExportOptions {
    pub fn all(detail: Detail, lang: Lang) -> Self {
        ExportOptions {
            kinds: ActionKind::ALL.into_iter().collect(),
            detail,
            lang,
        }
    }
}

pub fn warning_message(code: WarningCode, lang: Lang) -> &'static str {
    let (zh, en) = match code {
        WarningCode::ManifestDecodeFailed => (
            "manifest 解壓失敗，未納入分析",
            "Manifest could not be decompressed and was not analyzed",
        ),
        WarningCode::ManifestParseFailed => (
            "manifest 格式錯誤，未納入分析",
            "Manifest is malformed and was not analyzed",
        ),
        WarningCode::MumParseFailed => (
            "套件描述檔（.mum）格式錯誤",
            "Package manifest (.mum) is malformed",
        ),
        WarningCode::ContainerFailed => (
            "內層容器無法展開，其內容未納入分析",
            "A nested container could not be unpacked; its contents were not analyzed",
        ),
        WarningCode::PsfFailed => (
            "PSF 差異封裝無法讀取",
            "PSF patch storage could not be read",
        ),
        WarningCode::SignatureNotValid => (
            "更新檔的數位簽章無效或不存在",
            "The update package signature is missing or invalid",
        ),
        WarningCode::LocalCompareFailed => (
            "無法讀取本機狀態，未做本機比對",
            "Local state could not be read; no local comparison was made",
        ),
        WarningCode::TempCleanupFailed => (
            "暫存資料夾無法完全刪除，請手動刪除",
            "The temporary folder could not be fully removed; delete it manually",
        ),
    };
    match lang {
        Lang::ZhTw => zh,
        Lang::En => en,
    }
}

fn high_risk_entry(c: &Component, a: &Action) -> Value {
    json!({
        "component": c.identity.display(),
        "manifest": c.manifest,
        "target": a.detail.target(),
        "action": a,
    })
}

pub fn build(report: &AnalysisReport, opts: &ExportOptions, generated_at: &str) -> Value {
    let included = |a: &Action| opts.kinds.contains(&a.kind());

    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_risk: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_local: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_store: BTreeMap<&str, usize> = BTreeMap::new();
    let mut rule_ids: BTreeSet<&'static str> = BTreeSet::new();
    let mut high = Vec::new();
    let mut total = 0usize;
    for c in &report.components {
        if let Some(l) = &c.local {
            *by_store.entry(l.state.code()).or_default() += 1;
        }
        for a in c.actions.iter().filter(|a| included(a)) {
            total += 1;
            *by_kind.entry(a.kind().code()).or_default() += 1;
            *by_risk.entry(a.risk.code()).or_default() += 1;
            if let Some(l) = &a.local {
                *by_local.entry(l.state.code()).or_default() += 1;
            }
            if a.risk == Risk::High {
                high.push(high_risk_entry(c, a));
                rule_ids.extend(a.rules.iter().copied());
            }
        }
    }

    let mut summary = json!({
        "components": report.components.len(),
        "actions": total,
        "by_kind": by_kind,
        "by_risk": by_risk,
    });
    if report.mode == Mode::StaticLocal {
        summary["by_local_status"] = json!(by_local);
        summary["components_by_store_status"] = json!(by_store);
    }

    let mut package = serde_json::to_value(&report.package).unwrap_or(Value::Null);
    package["restart_required"] = json!(report
        .package
        .restart
        .as_deref()
        .is_some_and(|r| r.eq_ignore_ascii_case("required")));

    let warnings: Vec<Value> = report
        .warnings
        .iter()
        .map(|w| {
            json!({
                "code": w.code,
                "subject": w.subject,
                "detail": w.detail,
                "message": warning_message(w.code, opts.lang),
            })
        })
        .collect();

    let mut root = Map::new();
    root.insert("schema_version".into(), json!(SCHEMA_VERSION));
    root.insert(
        "tool".into(),
        json!({"name": "msu-inspector", "version": env!("CARGO_PKG_VERSION")}),
    );
    root.insert("generated_at".into(), json!(generated_at));
    root.insert("mode".into(), json!(report.mode.code()));
    if let Some(ctx) = &report.local_context {
        root.insert("local_context".into(), json!(ctx));
    }
    root.insert("source".into(), json!(report.source));
    root.insert("package".into(), package);
    root.insert("summary".into(), summary);
    if opts.detail >= Detail::Risk {
        if opts.detail == Detail::Full {
            for c in &report.components {
                for a in c.actions.iter().filter(|a| included(a)) {
                    rule_ids.extend(a.rules.iter().copied());
                }
            }
        }
        let rules: Map<String, Value> = rule_ids
            .iter()
            .filter_map(|id| risk::rule(id))
            .map(|r| {
                (
                    r.id.to_string(),
                    json!({"level": r.level, "reason": r.reason(opts.lang)}),
                )
            })
            .collect();
        root.insert("rules".into(), Value::Object(rules));
        root.insert("high_risk".into(), Value::Array(high));
    }
    if opts.detail == Detail::Full {
        let comps: Vec<Value> = report
            .components
            .iter()
            .filter_map(|c| {
                let actions: Vec<&Action> = c.actions.iter().filter(|a| included(a)).collect();
                (!actions.is_empty()).then(|| {
                    json!({
                        "identity": c.identity,
                        "manifest": c.manifest,
                        "categories": c.categories,
                        "local": c.local,
                        "actions": actions,
                    })
                })
            })
            .collect();
        root.insert("components".into(), Value::Array(comps));
    }
    root.insert("warnings".into(), Value::Array(warnings));
    root.insert(
        "export_filter".into(),
        json!({
            "kinds": opts.kinds.iter().map(|k| k.code()).collect::<Vec<_>>(),
            "detail": opts.detail.code(),
            "language": opts.lang.code(),
        }),
    );
    Value::Object(root)
}

pub fn to_json_string(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_utc(secs)
}

/// Unix 秒 → `YYYY-MM-DDTHH:MM:SSZ`（Howard Hinnant 的 civil_from_days）。
pub fn rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// 匯出大小預估：先量測每個動作的 JSON 大小，勾選變動時只做加總。
pub struct SizeModel {
    base: usize,
    per_kind_full: BTreeMap<ActionKind, usize>,
    per_kind_high: BTreeMap<ActionKind, usize>,
    comps_per_kind: BTreeMap<ActionKind, usize>,
    comp_overhead: usize,
}

/// 以 to_string_pretty 量測，再補上在輸出中巢狀位置多出的縮排。
fn pretty_len<T: serde::Serialize>(v: &T, extra_indent: usize) -> usize {
    let s = serde_json::to_string_pretty(v).unwrap_or_default();
    s.len() + (s.matches('\n').count() + 1) * extra_indent + 2
}

impl SizeModel {
    pub fn build(report: &AnalysisReport) -> Self {
        let base = to_json_string(&build(
            report,
            &ExportOptions::all(Detail::Summary, Lang::En),
            &now_rfc3339(),
        ))
        .len();
        let mut per_kind_full = BTreeMap::new();
        let mut per_kind_high = BTreeMap::new();
        let mut comps_per_kind: BTreeMap<ActionKind, usize> = BTreeMap::new();
        let mut overhead_total = 0usize;
        for c in &report.components {
            let mut kinds = BTreeSet::new();
            for a in &c.actions {
                let k = a.kind();
                *per_kind_full.entry(k).or_default() += pretty_len(a, 8);
                if a.risk == Risk::High {
                    *per_kind_high.entry(k).or_default() += pretty_len(&high_risk_entry(c, a), 4);
                }
                kinds.insert(k);
            }
            for k in kinds {
                *comps_per_kind.entry(k).or_default() += 1;
            }
            overhead_total += pretty_len(&c.identity, 6) + c.manifest.len() + 120;
        }
        let comp_overhead = overhead_total / report.components.len().max(1);
        SizeModel {
            base,
            per_kind_full,
            per_kind_high,
            comps_per_kind,
            comp_overhead,
        }
    }

    pub fn estimate(&self, opts: &ExportOptions) -> usize {
        let sum = |m: &BTreeMap<ActionKind, usize>| -> usize {
            opts.kinds.iter().filter_map(|k| m.get(k)).sum()
        };
        let mut size = self.base;
        if opts.detail >= Detail::Risk {
            size += sum(&self.per_kind_high) + 600;
        }
        if opts.detail == Detail::Full {
            size += sum(&self.per_kind_full);
            let comps = opts
                .kinds
                .iter()
                .filter_map(|k| self.comps_per_kind.get(k))
                .max()
                .copied()
                .unwrap_or(0);
            size += comps * self.comp_overhead;
        }
        size
    }
}
