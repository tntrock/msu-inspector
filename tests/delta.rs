use msu_inspector::core::delta::{is_dcm, DcmDecoder, DeltaEngine};
use msu_inspector::core::sys;

fn msdelta() -> DeltaEngine {
    DeltaEngine::system("msdelta.dll").expect("msdelta.dll")
}

#[test]
fn applies_null_source_delta_round_trip() {
    let e = msdelta();
    let target = b"<assembly>hello</assembly>".repeat(20);
    let d = e.create(b"", &target).unwrap();
    assert!(d.starts_with(b"PA30"));
    assert_eq!(e.apply(b"", &d).unwrap(), target);
}

#[test]
fn applies_delta_against_source() {
    let e = msdelta();
    let src = b"version=1 ".repeat(100);
    let tgt = b"version=2 ".repeat(100);
    let d = e.create(&src, &tgt).unwrap();
    assert_eq!(e.apply(&src, &d).unwrap(), tgt);
}

#[test]
fn rejects_garbage_delta() {
    assert!(msdelta().apply(b"", b"not a delta").is_err());
}

#[test]
fn applies_empty_target_round_trip() {
    // msdelta.dll 的 CreateDeltaB 接受空目標（回傳成功、輸出 0 位元組，start 為 NULL）；
    // ApplyDeltaB 同樣以 NULL start、size 0 成功回傳，驗證 apply()/create() 對此情形不會
    // 對 NULL 指標呼叫 from_raw_parts。
    let e = msdelta();
    let d = e.create(b"", b"").expect("msdelta accepts an empty target");
    assert_eq!(e.apply(b"", &d).unwrap(), Vec::<u8>::new());
}

#[test]
fn selected_engine_applies_msdelta_output() {
    let sel = DeltaEngine::select(None).unwrap();
    assert!(sel.label().starts_with("system:"), "{}", sel.label());
    let d = msdelta().create(b"", b"abc").unwrap();
    assert_eq!(sel.apply(b"", &d).unwrap(), b"abc");
}

#[test]
fn dcm_round_trip_with_system_base() {
    let e = msdelta();
    let dcm = DcmDecoder::from_system().expect("wcp.dll base");
    assert!(dcm.base().starts_with(b"<?xml"));
    let xml = b"<?xml version=\"1.0\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v3\"/>";
    let mut bytes = b"DCM\x01".to_vec();
    bytes.extend(e.create(dcm.base(), xml).unwrap());
    assert!(is_dcm(&bytes));
    assert_eq!(dcm.decode(&e, &bytes).unwrap(), xml);
}

#[test]
fn non_dcm_passes_through() {
    let dcm = DcmDecoder::with_base(Vec::new());
    assert_eq!(
        dcm.decode(&msdelta(), b"<assembly/>").unwrap(),
        b"<assembly/>"
    );
}

#[test]
fn decodes_real_winsxs_manifest() {
    let dir = sys::windows_dir().join("WinSxS").join("Manifests");
    let entry = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| std::fs::read(e.path()).map(|b| is_dcm(&b)).unwrap_or(false))
        .expect("a DCM manifest in WinSxS");
    let bytes = std::fs::read(entry.path()).unwrap();
    let out = DcmDecoder::from_system()
        .unwrap()
        .decode(&msdelta(), &bytes)
        .unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("<assembly"),
        "{}",
        &text[..text.len().min(200)]
    );
}

#[test]
fn reports_native_arch() {
    assert!(["amd64", "arm64", "x86"].contains(&sys::native_arch()));
    assert!(sys::windows_dir().join("System32").is_dir());
}
