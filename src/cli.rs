//! CLI：`msu-inspector analyze <FILE> [--json OUT|-] [--detail ...] [--kinds ...] [--compare-local] [--lang ...]`

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::core::analyze::{analyze, AnalyzeOptions};
use crate::core::export::{
    build, now_rfc3339, to_json_string, warning_message, Detail, ExportOptions,
};
use crate::core::model::{ActionKind, AnalysisReport, Risk};
use crate::core::progress::Ctx;
use crate::core::risk;
use crate::core::sys::is_elevated;
use crate::i18n::{error_text, kind_name, risk_name, signature_name, Lang};

pub const EXIT_OK: i32 = 0;
pub const EXIT_WARNINGS: i32 = 1;
pub const EXIT_FAILED: i32 = 2;

#[derive(Parser)]
#[command(
    name = "msu-inspector",
    version,
    about = "Pre-deployment review of Windows update packages (.msu / .cab)"
)]
struct Cli {
    /// Interface language: zh-TW or en
    #[arg(long, global = true)]
    lang: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze an update package without installing it
    Analyze(AnalyzeArgs),
}

#[derive(Args)]
struct AnalyzeArgs {
    /// .msu or .cab file
    file: PathBuf,
    /// Write JSON to this file ("-" for stdout); without it a text summary is printed
    #[arg(long)]
    json: Option<PathBuf>,
    /// summary, risk or full
    #[arg(long, default_value = "risk")]
    detail: String,
    /// Comma-separated action kinds to export (default: all)
    #[arg(long, value_delimiter = ',')]
    kinds: Vec<String>,
    /// Compare against this machine (requires administrator)
    #[arg(long)]
    compare_local: bool,
}

pub fn run(args: Vec<OsString>) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { EXIT_FAILED } else { EXIT_OK };
        }
    };
    let lang = cli
        .lang
        .as_deref()
        .and_then(Lang::parse)
        .unwrap_or_else(Lang::detect);
    match cli.command {
        Command::Analyze(a) => run_analyze(a, lang),
    }
}

fn run_analyze(a: AnalyzeArgs, lang: Lang) -> i32 {
    let t = lang.strings();
    let Some(detail) = Detail::parse(&a.detail) else {
        eprintln!("{}", t.cli_bad_detail);
        return EXIT_FAILED;
    };
    let mut kinds = BTreeSet::new();
    for k in &a.kinds {
        match ActionKind::parse(k) {
            Some(kind) => {
                kinds.insert(kind);
            }
            None => {
                eprintln!("{}: {k}", t.cli_bad_kind);
                return EXIT_FAILED;
            }
        }
    }
    if kinds.is_empty() {
        kinds = ActionKind::ALL.into_iter().collect();
    }
    if a.compare_local && !is_elevated() {
        eprintln!("{}", t.cli_needs_admin);
        return EXIT_FAILED;
    }
    let opts = AnalyzeOptions {
        compare_local: a.compare_local,
        temp_root: None,
    };
    let report = match analyze(&a.file, &opts, &Ctx::silent()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", error_text(&e, lang));
            return EXIT_FAILED;
        }
    };
    let export = ExportOptions {
        kinds,
        detail,
        lang,
    };
    match &a.json {
        Some(p) if p.as_os_str() == "-" => {
            println!(
                "{}",
                to_json_string(&build(&report, &export, &now_rfc3339()))
            );
        }
        Some(p) => {
            let json = to_json_string(&build(&report, &export, &now_rfc3339()));
            if let Err(e) = std::fs::write(p, json) {
                eprintln!("{}: {e}", p.display());
                return EXIT_FAILED;
            }
            eprintln!("{} {}", t.cli_written, p.display());
        }
        None => print!("{}", summary_text(&report, lang)),
    }
    if report.warnings.is_empty() {
        EXIT_OK
    } else {
        EXIT_WARNINGS
    }
}

/// 終端機用的文字摘要。
pub fn summary_text(report: &AnalysisReport, lang: Lang) -> String {
    let t = lang.strings();
    let mut s = String::new();
    let p = &report.package;
    let _ = writeln!(
        s,
        "{} · {} · {} · {}: {}",
        p.kb.as_deref().unwrap_or("-"),
        p.release_type.as_deref().unwrap_or("-"),
        p.identity.arch,
        t.restart,
        p.restart.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        s,
        "{}: {} ({}, SHA-256 {}) · {}: {}{}",
        t.cli_source,
        report.source.file,
        report.source.format,
        report.source.sha256,
        t.signature,
        signature_name(report.source.signature.status, lang),
        report
            .source
            .signature
            .signer
            .as_deref()
            .map(|n| format!(" ({n})"))
            .unwrap_or_default()
    );
    let _ = writeln!(s, "{}: {}", t.cli_mode, report.mode.code());
    let _ = writeln!(
        s,
        "{}: {} · {}: {}",
        t.components,
        report.components.len(),
        t.actions,
        report.action_count()
    );
    let all = || {
        report
            .components
            .iter()
            .flat_map(|c| c.actions.iter().map(move |a| (c, a)))
    };
    let risks: Vec<String> = Risk::ALL
        .iter()
        .map(|r| {
            format!(
                "{} {}",
                risk_name(*r, lang),
                all().filter(|(_, a)| a.risk == *r).count()
            )
        })
        .collect();
    let _ = writeln!(s, "{}: {}", t.col_risk, risks.join(" · "));
    let kinds: Vec<String> = ActionKind::ALL
        .iter()
        .filter_map(|k| {
            let n = all().filter(|(_, a)| a.kind() == *k).count();
            (n > 0).then(|| format!("{} {n}", kind_name(*k, lang)))
        })
        .collect();
    let _ = writeln!(s, "{}: {}", t.cli_by_kind, kinds.join(", "));
    let _ = writeln!(s, "{}:", t.cli_top_high_risk);
    for (c, a) in all().filter(|(_, a)| a.risk == Risk::High).take(50) {
        let reasons: Vec<String> = a
            .rules
            .iter()
            .filter_map(|id| risk::rule(id))
            .map(|r| format!("{} {}", r.id, r.reason(lang)))
            .collect();
        let _ = writeln!(
            s,
            "  [{}] {} — {} ({})",
            kind_name(a.kind(), lang),
            a.detail.target(),
            reasons.join("; "),
            c.identity.name
        );
    }
    let _ = writeln!(s, "{}: {}", t.warnings, report.warnings.len());
    for w in &report.warnings {
        let _ = writeln!(
            s,
            "  {}: {} ({})",
            warning_message(w.code, lang),
            w.subject,
            w.detail
        );
    }
    s
}
