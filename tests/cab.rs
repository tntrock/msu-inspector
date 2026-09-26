mod common;

use std::sync::atomic::AtomicBool;

use msu_inspector::core::container::{cab, role_of, ItemData, Role};
use msu_inspector::core::CoreError;

fn all(_: Role) -> bool {
    true
}

#[test]
fn classifies_entry_names() {
    assert_eq!(role_of("amd64_x_10.0.1_none_abc.manifest"), Role::Manifest);
    assert_eq!(role_of("update.MUM"), Role::Mum);
    assert_eq!(
        role_of("Windows10.0-KB5005565-x64-pkgProperties.txt"),
        Role::PkgProperties
    );
    assert_eq!(
        role_of("Windows11.0-KB5043080-x64-pkgProperties_PSFX.txt"),
        Role::PkgProperties
    );
    assert_eq!(role_of("express.psf.cix.xml"), Role::PsfIndex);
    assert_eq!(role_of("inner.cab"), Role::NestedCab);
    assert_eq!(role_of("Windows11.0-KB1-x64.wim"), Role::NestedWim);
    assert_eq!(role_of("Windows11.0-KB1-x64.psf"), Role::Psf);
    assert_eq!(role_of("UpdateCompression.dll"), Role::PackageDll);
    assert_eq!(role_of("ntoskrnl.exe"), Role::Ignore);
    assert!(Role::NestedCab.to_disk() && !Role::Manifest.to_disk());
}

#[test]
fn extracts_wanted_files_only() {
    let t = tempfile::tempdir().unwrap();
    let cab_path = common::make_cab(
        t.path(),
        "a.cab",
        &[
            ("update.mum", b"<mum/>"),
            ("a.manifest", b"<assembly/>"),
            ("payload.dll", b"MZ...."),
            ("inner.cab", b"MSCF-fake"),
        ],
        false,
    );
    let out = t.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let ex = cab::extract(&cab_path, "a.cab", &out, &AtomicBool::new(false), &all).unwrap();
    let mut names: Vec<&str> = ex.items.iter().map(|i| i.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["a.manifest", "inner.cab", "update.mum"]);
    let m = ex.items.iter().find(|i| i.name == "a.manifest").unwrap();
    assert_eq!(m.vpath, "a.cab/a.manifest");
    assert_eq!(&*m.bytes().unwrap(), b"<assembly/>");
    let inner = ex.items.iter().find(|i| i.name == "inner.cab").unwrap();
    let ItemData::File(p) = &inner.data else {
        panic!("nested cab must go to disk")
    };
    assert_eq!(std::fs::read(p).unwrap(), b"MSCF-fake");
}

#[test]
fn extracts_lzx_folder_with_many_files() {
    let t = tempfile::tempdir().unwrap();
    let bodies: Vec<(String, Vec<u8>)> = (0..400)
        .map(|i| {
            (
                format!("c{i}.manifest"),
                format!("<assembly id=\"{i}\"/>").repeat(50).into_bytes(),
            )
        })
        .collect();
    let files: Vec<(&str, &[u8])> = bodies
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let cab_path = common::make_cab(t.path(), "big.cab", &files, true);
    let started = std::time::Instant::now();
    let ex = cab::extract(
        &cab_path,
        "big.cab",
        t.path(),
        &AtomicBool::new(false),
        &all,
    )
    .unwrap();
    assert_eq!(ex.items.len(), 400);
    assert!(
        started.elapsed().as_secs() < 10,
        "single pass extraction should be fast"
    );
    let c7 = ex.items.iter().find(|i| i.name == "c7.manifest").unwrap();
    assert_eq!(&*c7.bytes().unwrap(), bodies[7].1.as_slice());
}

#[test]
fn keeps_subdirectory_in_vpath() {
    let t = tempfile::tempdir().unwrap();
    let cab_path = common::make_cab(
        t.path(),
        "s.cab",
        &[("amd64_x\\b.manifest", b"<assembly/>")],
        false,
    );
    let ex = cab::extract(&cab_path, "s.cab", t.path(), &AtomicBool::new(false), &all).unwrap();
    assert_eq!(ex.items[0].name, "b.manifest");
    assert_eq!(ex.items[0].vpath, "s.cab/amd64_x/b.manifest");
}

#[test]
fn extracts_from_non_ascii_path() {
    let t = tempfile::tempdir().unwrap();
    let cab_path = common::make_cab(t.path(), "u.cab", &[("x.manifest", b"<assembly/>")], false);
    let dir = t.path().join("下載 測試");
    std::fs::create_dir_all(&dir).unwrap();
    let moved = dir.join("更新.cab");
    std::fs::copy(&cab_path, &moved).unwrap();
    let ex = cab::extract(&moved, "更新.cab", &dir, &AtomicBool::new(false), &all).unwrap();
    assert_eq!(ex.items.len(), 1);
}

#[test]
fn honors_want_filter_and_reports_skipped() {
    let t = tempfile::tempdir().unwrap();
    let cab_path = common::make_cab(
        t.path(),
        "p.cab",
        &[("a.manifest", b"<assembly/>"), ("big.psf", b"PSF")],
        false,
    );
    let want = |r: Role| r != Role::Psf;
    let ex = cab::extract(&cab_path, "p.cab", t.path(), &AtomicBool::new(false), &want).unwrap();
    assert_eq!(ex.items.len(), 1);
    assert_eq!(ex.skipped, vec![("p.cab/big.psf".to_string(), Role::Psf)]);
}

#[test]
fn cancel_aborts_extraction() {
    let t = tempfile::tempdir().unwrap();
    let cab_path = common::make_cab(t.path(), "c.cab", &[("a.manifest", b"<assembly/>")], false);
    let r = cab::extract(&cab_path, "c.cab", t.path(), &AtomicBool::new(true), &all);
    assert!(matches!(r, Err(CoreError::Cancelled)));
}

#[test]
fn rejects_non_cab() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("fake.cab");
    std::fs::write(&p, b"MSCF but truncated").unwrap();
    let r = cab::extract(&p, "fake.cab", t.path(), &AtomicBool::new(false), &all);
    assert!(matches!(r, Err(CoreError::Container { .. })), "{r:?}");
}

/// 可壓縮但不重複的文字內容：MSZIP 會產生 Huffman 壓縮區塊，
/// 中段損毀會讓解壓失敗（未壓縮區塊的損毀 FDI 不會察覺）。
fn text_body(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2654435761).max(1);
    let mut out = Vec::with_capacity(len + 64);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out.extend_from_slice(
            format!("<file name=\"f{}\" size=\"{}\"/>\n", x % 9973, x >> 20).as_bytes(),
        );
    }
    out.truncate(len);
    out
}

/// 只列出結果種類，避免失敗訊息印出整個檔案內容。
fn summary(r: &Result<msu_inspector::core::container::Extracted, CoreError>) -> String {
    match r {
        Ok(ex) => format!("Ok({} items)", ex.items.len()),
        Err(e) => format!("Err({e})"),
    }
}

/// 覆寫 CAB 中段的位元組（位於 CFDATA 內），模擬資料區損毀。
fn corrupt_middle(path: &std::path::Path) {
    let mut bytes = std::fs::read(path).unwrap();
    let mid = bytes.len() / 2;
    for b in &mut bytes[mid..mid + 4096] {
        *b = 0xFF;
    }
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn corrupt_cfdata_in_memory_item_fails_cleanly() {
    let t = tempfile::tempdir().unwrap();
    let body = text_body(1 << 20, 1);
    let cab_path = common::make_cab(t.path(), "bad.cab", &[("big.manifest", &body)], false);
    corrupt_middle(&cab_path);
    let out = t.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let r = cab::extract(&cab_path, "bad.cab", &out, &AtomicBool::new(false), &all);
    assert!(
        matches!(r, Err(CoreError::Container { .. })),
        "{}",
        summary(&r)
    );
}

#[test]
fn corrupt_cfdata_with_multiple_files_fails_cleanly_and_removes_partial_output() {
    let t = tempfile::tempdir().unwrap();
    let a = text_body(300_000, 2);
    let inner = text_body(600_000, 3);
    let b = text_body(300_000, 4);
    let cab_path = common::make_cab(
        t.path(),
        "multi.cab",
        &[
            ("a.manifest", &a),
            ("inner.cab", &inner),
            ("b.manifest", &b),
        ],
        false,
    );
    corrupt_middle(&cab_path);
    let out = t.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let r = cab::extract(&cab_path, "multi.cab", &out, &AtomicBool::new(false), &all);
    assert!(
        matches!(r, Err(CoreError::Container { .. })),
        "{}",
        summary(&r)
    );
    let left: Vec<_> = std::fs::read_dir(&out).unwrap().collect();
    assert!(left.is_empty(), "partial output left behind: {left:?}");
}

#[test]
fn oversized_in_memory_item_is_rejected() {
    let t = tempfile::tempdir().unwrap();
    let body = vec![b'x'; (cab::MAX_MEMORY_ITEM + 1) as usize];
    let cab_path = common::make_cab(t.path(), "huge.cab", &[("huge.manifest", &body)], false);
    let r = cab::extract(
        &cab_path,
        "huge.cab",
        t.path(),
        &AtomicBool::new(false),
        &all,
    );
    let Err(CoreError::Container { detail, .. }) = r else {
        panic!("{}", summary(&r))
    };
    assert!(detail.contains("too large"), "{detail}");
}

#[test]
fn component_payload_containers_are_ignored() {
    use msu_inspector::core::container::role_at;
    let comp =
        "amd64_microsoft-windows-ptp-bootos_31bf3856ad364e35_10.0.19041.7725_none_4a9456e64d9847d8";
    assert_eq!(
        role_at(&format!("x.msu/kb.cab/{comp}/bootos.wim")),
        Role::Ignore
    );
    assert_eq!(role_at(&format!("{comp}/sub/inner.cab")), Role::Ignore);
    assert_eq!(role_at(&format!("{comp}/f/x.psf")), Role::Ignore);
    // 元件資料夾外的容器與 manifest 照常
    assert_eq!(role_at("x.msu/Windows10.0-KB1-x64.cab"), Role::NestedCab);
    assert_eq!(role_at("x.msu/Cab_1_for_KB1.cab"), Role::NestedCab);
    assert_eq!(
        role_at(&format!("{comp}/f/application.manifest")),
        Role::Ignore
    );
    assert_eq!(role_at("x.msu/kb.cab/amd64_foo.manifest"), Role::Manifest);
    assert_eq!(role_at("SSU-19041.1-x64.cab"), Role::NestedCab);
}
