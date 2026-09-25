use std::collections::BTreeSet;

use msu_inspector::core::export::*;
use msu_inspector::core::model::*;
use msu_inspector::core::risk;
use msu_inspector::i18n::Lang;

fn sample_report(components: usize) -> AnalysisReport {
    let mut comps = Vec::new();
    for i in 0..components {
        let actions = vec![
            ActionDetail::File(FileAction {
                name: format!("f{i}.dll"),
                destination: "$(runtime.system32)\\".into(),
                hash_alg: Some("sha256".into()),
                hash: Some("q83vEjRWeJA=".into()),
                is_pe: true,
                ..Default::default()
            }),
            ActionDetail::Registry(RegistryAction {
                key: format!("HKEY_LOCAL_MACHINE\\SOFTWARE\\Contoso\\K{i}"),
                value_name: Some("V".into()),
                value_type: Some("REG_SZ".into()),
                data: Some("some value data".into()),
                operation: "replace".into(),
                ..Default::default()
            }),
            ActionDetail::Driver(DriverAction {
                name: format!("drv{i}"),
                start: Some(if i % 3 == 0 { "boot" } else { "demand" }.into()),
                image_path: Some(format!("System32\\drivers\\drv{i}.sys")),
                origin: "service".into(),
                ..Default::default()
            }),
        ];
        comps.push(Component {
            identity: AssemblyIdentity {
                name: format!("Microsoft-Windows-Component-{i}"),
                version: "10.0.26100.1742".into(),
                arch: "amd64".into(),
                language: "neutral".into(),
                public_key_token: "31bf3856ad364e35".into(),
            },
            manifest: format!("amd64_microsoft-windows-component-{i}_31bf3856ad364e35_10.0.26100.1742_none_0.manifest"),
            actions: actions.into_iter().map(Action::new).collect(),
            ..Default::default()
        });
    }
    let mut r = AnalysisReport {
        source: SourceInfo {
            file: "x.msu".into(),
            sha256: "00".repeat(32),
            format: "msu-cab".into(),
            ..Default::default()
        },
        package: PackageInfo {
            kb: Some("KB1".into()),
            restart: Some("required".into()),
            ..Default::default()
        },
        components: comps,
        warnings: vec![Warning::new(
            WarningCode::SignatureNotValid,
            "x.msu",
            "unsigned",
        )],
        ..Default::default()
    };
    risk::apply(&mut r);
    r
}

#[test]
fn builds_summary_json() {
    let r = sample_report(3);
    let v = build(
        &r,
        &ExportOptions::all(Detail::Summary, Lang::En),
        "2026-09-25T00:00:00Z",
    );
    assert_eq!(v["schema_version"], SCHEMA_VERSION);
    assert_eq!(v["tool"]["name"], "msu-inspector");
    assert_eq!(v["mode"], "static");
    assert!(v.get("local_context").is_none());
    assert_eq!(v["package"]["kb"], "KB1");
    assert_eq!(v["package"]["restart_required"], true);
    assert_eq!(v["summary"]["components"], 3);
    assert_eq!(v["summary"]["actions"], 9);
    assert_eq!(v["summary"]["by_kind"]["driver"], 3);
    assert_eq!(v["summary"]["by_risk"]["high"], 1);
    assert!(v.get("high_risk").is_none() && v.get("components").is_none());
    assert_eq!(v["warnings"][0]["code"], "signature_not_valid");
    assert!(!v["warnings"][0]["message"].as_str().unwrap().is_empty());
    assert_eq!(v["export_filter"]["detail"], "summary");
    assert_eq!(v["export_filter"]["language"], "en");
}

#[test]
fn risk_detail_lists_high_risk_with_rule_reasons() {
    let r = sample_report(6);
    let v = build(&r, &ExportOptions::all(Detail::Risk, Lang::ZhTw), "t");
    let high = v["high_risk"].as_array().unwrap();
    assert_eq!(high.len(), 2, "drv0 and drv3 start at boot");
    assert_eq!(high[0]["action"]["kind"], "driver");
    assert_eq!(high[0]["target"], "drv0");
    assert_eq!(
        high[0]["component"],
        "Microsoft-Windows-Component-0 10.0.26100.1742 (amd64, neutral)"
    );
    assert_eq!(v["rules"]["DRV_BOOT_START"]["level"], "high");
    assert_eq!(
        v["rules"]["DRV_BOOT_START"]["reason"],
        risk::rule("DRV_BOOT_START").unwrap().reason(Lang::ZhTw)
    );
    assert!(v.get("components").is_none());
}

#[test]
fn full_detail_respects_kind_filter() {
    let r = sample_report(4);
    let opts = ExportOptions {
        kinds: BTreeSet::from([ActionKind::Registry]),
        detail: Detail::Full,
        lang: Lang::En,
    };
    let v = build(&r, &opts, "t");
    let comps = v["components"].as_array().unwrap();
    assert_eq!(comps.len(), 4);
    for c in comps {
        let actions = c["actions"].as_array().unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["kind"], "registry");
    }
    assert_eq!(v["summary"]["actions"], 4);
    assert_eq!(v["high_risk"].as_array().unwrap().len(), 0);
    assert_eq!(v["export_filter"]["kinds"], serde_json::json!(["registry"]));
}

#[test]
fn estimates_size_within_fifteen_percent() {
    let r = sample_report(80);
    let model = SizeModel::build(&r);
    let cases = [
        ExportOptions::all(Detail::Summary, Lang::En),
        ExportOptions::all(Detail::Risk, Lang::En),
        ExportOptions::all(Detail::Full, Lang::En),
        ExportOptions {
            kinds: BTreeSet::from([ActionKind::File, ActionKind::Driver]),
            detail: Detail::Full,
            lang: Lang::En,
        },
    ];
    for opts in cases {
        let actual = to_json_string(&build(&r, &opts, &now_rfc3339())).len() as f64;
        let est = model.estimate(&opts) as f64;
        let err = (est - actual).abs() / actual;
        assert!(
            err < 0.15,
            "{:?}/{:?}: estimate {est} vs actual {actual}",
            opts.detail,
            opts.kinds
        );
    }
}

#[test]
fn formats_rfc3339() {
    assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(rfc3339_utc(1_790_000_000), "2026-09-21T14:13:20Z");
    assert!(now_rfc3339().ends_with('Z'));
}

#[test]
fn parses_detail_codes() {
    for d in Detail::ALL {
        assert_eq!(Detail::parse(d.code()), Some(d));
    }
    assert!(Detail::Summary < Detail::Risk && Detail::Risk < Detail::Full);
}
