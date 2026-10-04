use std::sync::atomic::AtomicBool;

use msu_inspector::core::container::wim;
use msu_inspector::core::CoreError;

#[test]
fn rejects_non_wim() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("x.wim");
    std::fs::write(&p, b"MSWIM\0\0\0garbage").unwrap();
    let r = wim::extract(&p, "x.wim", t.path(), &AtomicBool::new(false));
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

/// 以 `mklink /J` 建立目錄連接（不需要系統管理員權限）。
fn junction(link: &std::path::Path, target: &std::path::Path) {
    let out = std::process::Command::new("cmd")
        .arg("/c")
        .arg("mklink")
        .arg("/J")
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "mklink failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn collect_files_does_not_follow_junctions() {
    let t = tempfile::tempdir().unwrap();
    let outside = t.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("victim.manifest"), b"<assembly/>").unwrap();
    std::fs::write(outside.join("victim.mum"), b"<mum/>").unwrap();
    let out = t.path().join("out");
    let image = out.join("1");
    std::fs::create_dir_all(&image).unwrap();
    std::fs::write(image.join("own.manifest"), b"<assembly/>").unwrap();
    junction(&image.join("link"), &outside);

    let mut items = Vec::new();
    wim::collect_files(&out, &out, "t.wim", &mut items).unwrap();
    let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, vec!["own.manifest"]);
    assert!(
        outside.join("victim.manifest").exists(),
        "outside file deleted"
    );
    assert!(outside.join("victim.mum").exists(), "outside file deleted");
}

#[test]
fn is_within_resolves_junctions() {
    use msu_inspector::core::container::is_within;
    let t = tempfile::tempdir().unwrap();
    let outside = t.path().join("outside");
    let work = t.path().join("work");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(outside.join("x.cab"), b"MSCF").unwrap();
    std::fs::write(work.join("own.cab"), b"MSCF").unwrap();
    junction(&work.join("link"), &outside);
    assert!(is_within(&work.join("own.cab"), &work));
    assert!(!is_within(&work.join("link").join("x.cab"), &work));
    assert!(!is_within(&work.join("missing.cab"), &work));
}
