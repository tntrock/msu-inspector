//! 真實樣本測試：設定 MSU_INSPECTOR_SAMPLES 才執行（見 docs/samples.md）。

use msu_inspector::core::analyze::{analyze, AnalyzeOptions};
use msu_inspector::core::export::{build, now_rfc3339, to_json_string, Detail, ExportOptions};
use msu_inspector::core::model::{Risk, WarningCode};
use msu_inspector::core::progress::Ctx;
use msu_inspector::core::CoreError;
use msu_inspector::i18n::Lang;

#[test]
fn analyzes_real_samples() {
    let Ok(dir) = std::env::var("MSU_INSPECTOR_SAMPLES") else {
        eprintln!("skipping: MSU_INSPECTOR_SAMPLES not set");
        return;
    };
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("msu") || e.eq_ignore_ascii_case("cab"))
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .msu / .cab in {dir}");
    for f in files {
        let started = std::time::Instant::now();
        let report = match analyze(&f, &AnalyzeOptions::default(), &Ctx::silent()) {
            Ok(r) => r,
            Err(CoreError::NeedsElevation(e)) => {
                eprintln!(
                    "{}: needs elevation ({e}); rerun as administrator",
                    f.display()
                );
                continue;
            }
            Err(e) => panic!("{}: {e}", f.display()),
        };
        let decode_fail = report
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w.code,
                    WarningCode::ManifestDecodeFailed | WarningCode::ManifestParseFailed
                )
            })
            .count();
        let high = report
            .components
            .iter()
            .flat_map(|c| &c.actions)
            .filter(|a| a.risk == Risk::High)
            .count();
        eprintln!(
            "{}: {} · {} components · {} actions · {high} high · {} warnings · {:?}",
            f.display(),
            report.source.format,
            report.components.len(),
            report.action_count(),
            report.warnings.len(),
            started.elapsed()
        );
        assert!(
            !report.components.is_empty(),
            "{}: no components",
            f.display()
        );
        assert!(
            decode_fail * 100 <= report.components.len(),
            "{}: >1% manifests failed",
            f.display()
        );
        let json = to_json_string(&build(
            &report,
            &ExportOptions::all(Detail::Full, Lang::En),
            &now_rfc3339(),
        ));
        std::fs::write(f.with_extension("full.json"), json).unwrap();
    }
}
