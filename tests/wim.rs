use std::sync::atomic::AtomicBool;

use msu_inspector::core::container::{wim, Role};
use msu_inspector::core::CoreError;

/// 建立 WIM；若本機 wimgapi 不允許非管理員擷取，回傳 None 並略過測試。
fn make_wim(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("amd64_comp_10.0.1.1_none_abc")).unwrap();
    std::fs::write(src.join("update.mum"), b"<mum/>").unwrap();
    std::fs::write(
        src.join("amd64_comp_10.0.1.1_none_abc").join("a.manifest"),
        b"<assembly/>",
    )
    .unwrap();
    std::fs::write(src.join("payload.dll"), vec![0u8; 4096]).unwrap();
    std::fs::write(src.join("big.psf"), b"PSF").unwrap();
    let wim_path = dir.join("t.wim");
    match wim::capture_for_tests(&src, &wim_path) {
        Ok(()) => Some(wim_path),
        Err(e) => {
            eprintln!("skipping: cannot capture WIM without elevation: {e}");
            None
        }
    }
}

#[test]
fn extracts_wanted_files_only() {
    let t = tempfile::tempdir().unwrap();
    let Some(w) = make_wim(t.path()) else { return };
    let out = t.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let want = |r: Role| r != Role::Psf;
    let ex = wim::extract(&w, "t.wim", &out, &AtomicBool::new(false), &want).unwrap();
    let mut names: Vec<&str> = ex.items.iter().map(|i| i.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["a.manifest", "update.mum"]);
    assert!(
        !out.join("1").join("payload.dll").exists(),
        "payload must be skipped"
    );
    let m = ex.items.iter().find(|i| i.name == "a.manifest").unwrap();
    assert_eq!(m.vpath, "t.wim/amd64_comp_10.0.1.1_none_abc/a.manifest");
    assert_eq!(&*m.bytes().unwrap(), b"<assembly/>");
    assert!(ex
        .skipped
        .iter()
        .any(|(p, r)| p.ends_with("big.psf") && *r == Role::Psf));
}

#[test]
fn cancel_aborts_apply() {
    let t = tempfile::tempdir().unwrap();
    let Some(w) = make_wim(t.path()) else { return };
    let r = wim::extract(&w, "t.wim", t.path(), &AtomicBool::new(true), &|_| true);
    assert!(matches!(r, Err(CoreError::Cancelled)), "{r:?}");
}

#[test]
fn rejects_non_wim() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("x.wim");
    std::fs::write(&p, b"MSWIM\0\0\0garbage").unwrap();
    let r = wim::extract(&p, "x.wim", t.path(), &AtomicBool::new(false), &|_| true);
    assert!(r.is_err());
}

#[test]
fn maps_privilege_errors_to_needs_elevation() {
    assert!(matches!(
        wim::map_error(1314, "apply"),
        CoreError::NeedsElevation(_)
    ));
    assert!(matches!(
        wim::map_error(5, "apply"),
        CoreError::NeedsElevation(_)
    ));
    assert!(matches!(
        wim::map_error(2, "apply"),
        CoreError::Container { .. }
    ));
}
