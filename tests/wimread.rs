//! 無壓縮 WIM 的純 Rust 讀取器（24H2 起的 .msu），不需要系統管理員權限。

mod common;

use std::sync::atomic::AtomicBool;

use common::wimbuild::{build_wim, WimEntry};
use msu_inspector::core::container::{wim, ItemData, Role};
use msu_inspector::core::CoreError;

const COMP: &str =
    "amd64_microsoft-windows-ptp-bootos_31bf3856ad364e35_10.0.26100.1_none_4a9456e64d9847d8";

fn entry<'a>(path: &'a str, data: &'a [u8]) -> WimEntry<'a> {
    WimEntry {
        path,
        data,
        reparse: false,
    }
}

#[test]
fn reads_uncompressed_wim_without_elevation() {
    let t = tempfile::tempdir().unwrap();
    let payload = format!("{COMP}/bootos.wim");
    let w = build_wim(
        t.path(),
        "x.msu",
        &[
            entry("update.mum", b"<mum/>"),
            entry("a.manifest", b"<assembly id=\"a\"/>"),
            entry("Manifests/b.manifest", b"<assembly id=\"b\"/>"),
            entry("Windows11.0-KB1-x64.cab", b"MSCF-fake"),
            entry("Windows11.0-KB1-x64.psf", b"PSTR"),
            entry(&payload, b"MSWIM\0\0\0payload"),
            WimEntry {
                path: "evil.manifest",
                data: b"<assembly/>",
                reparse: true,
            },
            entry("readme.txt", b"hi"),
        ],
    );
    let out = t.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let want = |r: Role| r != Role::Psf;
    let ex = wim::extract(&w, "x.msu", &out, &AtomicBool::new(false), &want).unwrap();
    let mut names: Vec<&str> = ex.items.iter().map(|i| i.name.as_str()).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "Windows11.0-KB1-x64.cab",
            "a.manifest",
            "b.manifest",
            "update.mum"
        ]
    );
    let b = ex.items.iter().find(|i| i.name == "b.manifest").unwrap();
    assert_eq!(b.vpath, "x.msu/Manifests/b.manifest");
    assert_eq!(&*b.bytes().unwrap(), b"<assembly id=\"b\"/>");
    let cab = ex.items.iter().find(|i| i.name.ends_with(".cab")).unwrap();
    let ItemData::File(p) = &cab.data else {
        panic!("nested cab must go to disk")
    };
    assert_eq!(std::fs::read(p).unwrap(), b"MSCF-fake");
    assert!(p.starts_with(&out));
    assert_eq!(
        ex.skipped,
        vec![("x.msu/Windows11.0-KB1-x64.psf".to_string(), Role::Psf)]
    );
}

#[test]
fn cancel_stops_reading() {
    let t = tempfile::tempdir().unwrap();
    let w = build_wim(t.path(), "x.msu", &[entry("a.manifest", b"<a/>")]);
    let r = wim::extract(&w, "x.msu", t.path(), &AtomicBool::new(true), &|_| true);
    assert!(matches!(r, Err(CoreError::Cancelled)), "{r:?}");
}

#[test]
fn rejects_truncated_uncompressed_wim() {
    let t = tempfile::tempdir().unwrap();
    let w = build_wim(t.path(), "x.msu", &[entry("a.manifest", b"<a/>")]);
    let good = std::fs::read(&w).unwrap();
    std::fs::write(&w, &good[..good.len() - 10]).unwrap(); // lookup table 超出檔尾
    let r = wim::extract(&w, "x.msu", t.path(), &AtomicBool::new(false), &|_| true);
    assert!(matches!(r, Err(CoreError::Container { .. })), "{r:?}");
}

#[test]
fn survives_self_referencing_directory() {
    let t = tempfile::tempdir().unwrap();
    let w = build_wim(t.path(), "x.msu", &[entry("a.manifest", b"<a/>")]);
    let mut bad = std::fs::read(&w).unwrap();
    // 第 2 筆 lookup 項目是 metadata；把 root 區塊的第一個項目改成指回同一區塊的目錄
    let lookup_off = u64::from_le_bytes(bad[56..64].try_into().unwrap()) as usize;
    let meta_entry = lookup_off + 50;
    let meta_off =
        u64::from_le_bytes(bad[meta_entry + 8..meta_entry + 16].try_into().unwrap()) as usize;
    let root = meta_off + 8;
    let block = u64::from_le_bytes(bad[root + 16..root + 24].try_into().unwrap());
    let first = meta_off + block as usize;
    bad[first + 8..first + 12].copy_from_slice(&0x10u32.to_le_bytes());
    bad[first + 16..first + 24].copy_from_slice(&block.to_le_bytes());
    std::fs::write(&w, &bad).unwrap();
    let r = wim::extract(&w, "x.msu", t.path(), &AtomicBool::new(false), &|_| true);
    assert!(
        r.is_ok() || matches!(r, Err(CoreError::Container { .. })),
        "{r:?}"
    );
}
