mod common;

use assert_cmd::Command;

fn build_msu(dir: &std::path::Path) -> std::path::PathBuf {
    let inner = common::make_cab(
        dir,
        "kb.cab",
        &[
            (
                "Package_for_RollupFix.mum",
                common::fixture("rollup.mum").as_bytes(),
            ),
            (
                "amd64_test-actions.manifest",
                common::fixture("actions.manifest").as_bytes(),
            ),
        ],
        false,
    );
    common::make_cab(
        dir,
        "Windows11.0-KB5129195-x64.msu",
        &[("kb.cab", &std::fs::read(inner).unwrap())],
        false,
    )
}

fn cmd() -> Command {
    Command::cargo_bin("msu-inspector").unwrap()
}

#[test]
fn writes_full_json_and_returns_warning_code() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let out = t.path().join("out.json");
    cmd()
        .args(["analyze"])
        .arg(&msu)
        .args(["--json"])
        .arg(&out)
        .args(["--detail", "full", "--lang", "en"])
        .assert()
        .code(1); // 測試檔未簽章 → 有警告
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(v["schema_version"], "1.0");
    assert_eq!(v["package"]["kb"], "KB5129195");
    assert!(!v["components"].as_array().unwrap().is_empty());
}

#[test]
fn prints_json_to_stdout_with_kind_filter() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let output = cmd()
        .arg("analyze")
        .arg(&msu)
        .args([
            "--json",
            "-",
            "--kinds",
            "driver,service",
            "--detail",
            "full",
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        v["export_filter"]["kinds"],
        serde_json::json!(["service", "driver"])
    );
}

#[test]
fn prints_text_summary_by_default() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let output = cmd()
        .arg("analyze")
        .arg(&msu)
        .args(["--lang", "zh-TW"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("KB5129195"), "{text}");
    assert!(text.contains("DRV_BOOT_START"), "{text}");
    let expected = msu_inspector::core::export::warning_message(
        msu_inspector::core::model::WarningCode::SignatureNotValid,
        msu_inspector::i18n::Lang::ZhTw,
    );
    assert!(text.contains(expected), "{text}");
}

#[test]
fn rejects_bad_arguments() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    cmd()
        .arg("analyze")
        .arg(&msu)
        .args(["--detail", "huge"])
        .assert()
        .code(2);
    cmd()
        .arg("analyze")
        .arg(&msu)
        .args(["--kinds", "nope"])
        .assert()
        .code(2);
    cmd()
        .arg("analyze")
        .arg(t.path().join("missing.msu"))
        .assert()
        .code(2);
    cmd().args(["--version"]).assert().code(0);
}

#[test]
fn compare_local_requires_admin() {
    if msu_inspector::elevation::is_elevated() {
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    cmd()
        .arg("analyze")
        .arg(&msu)
        .arg("--compare-local")
        .assert()
        .code(2);
}

#[test]
fn analyzes_bare_relative_path() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let output = cmd()
        .current_dir(t.path())
        .arg("analyze")
        .arg(msu.file_name().unwrap())
        .args(["--json", "-", "--lang", "en"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["package"]["kb"], "KB5129195");
}
