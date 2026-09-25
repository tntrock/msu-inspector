use std::fs::File;
use std::io::Write;

use msu_inspector::core::container::psf::{self, SourceType};
use msu_inspector::core::delta::DeltaEngine;

const PAYLOAD_BASE: u64 = 0x10000;

struct Built {
    path: std::path::PathBuf,
    index_xml: String,
    manifest: Vec<u8>,
    mum: Vec<u8>,
}

/// 產生 PSF：payload 從 0x10000 開始（一筆 RAW、一筆 PA30）；`embed` 為 true 時把索引放在檔頭。
fn build(dir: &std::path::Path, embed: bool) -> Built {
    let e = DeltaEngine::system("msdelta.dll").unwrap();
    let manifest = b"<assembly id=\"raw\"/>".to_vec();
    let mum = b"<assembly id=\"pa30\"/>".repeat(10);
    let mum_delta = e.create(b"", &mum).unwrap();
    let raw_off = PAYLOAD_BASE;
    let pa_off = raw_off + manifest.len() as u64;
    let index_xml = format!(
        "<?xml version=\"1.0\"?><Container type=\"PSF\" version=\"2.0\"><Files>\
         <File id=\"1\" name=\"amd64_x_10.0.1.1_none_abc\\a.manifest\" length=\"{}\" time=\"0\" attr=\"128\">\
         <Delta><Source type=\"RAW\" offset=\"{raw_off}\" length=\"{}\"/></Delta></File>\
         <File id=\"2\" name=\"update.mum\" length=\"{}\" time=\"0\" attr=\"128\">\
         <Delta><Source type=\"PA30\" offset=\"{pa_off}\" length=\"{}\"/></Delta></File>\
         </Files></Container>",
        manifest.len(),
        manifest.len(),
        mum.len(),
        mum_delta.len()
    );
    let mut buf = vec![0u8; PAYLOAD_BASE as usize];
    buf[..4].copy_from_slice(b"PSTR");
    if embed {
        let idx = e.create(b"", index_xml.as_bytes()).unwrap();
        buf[4..8].copy_from_slice(&(idx.len() as u32).to_le_bytes());
        buf[0x80..0x80 + idx.len()].copy_from_slice(&idx);
    }
    buf.extend_from_slice(&manifest);
    buf.extend_from_slice(&mum_delta);
    let path = dir.join(if embed { "embedded.psf" } else { "sidecar.psf" });
    File::create(&path).unwrap().write_all(&buf).unwrap();
    Built {
        path,
        index_xml,
        manifest,
        mum,
    }
}

#[test]
fn parses_index_xml() {
    let t = tempfile::tempdir().unwrap();
    let b = build(t.path(), false);
    let entries = psf::parse_index(&b.index_xml).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "amd64_x_10.0.1.1_none_abc\\a.manifest");
    assert_eq!(entries[0].source, SourceType::Raw);
    assert_eq!(entries[0].offset, PAYLOAD_BASE);
    assert_eq!(entries[1].source, SourceType::Pa30);
}

#[test]
fn reads_embedded_index_and_entries() {
    let t = tempfile::tempdir().unwrap();
    let b = build(t.path(), true);
    let e = DeltaEngine::select(None).unwrap();
    let entries = psf::load_index(&b.path, None, &e).unwrap();
    let mut f = File::open(&b.path).unwrap();
    assert_eq!(
        psf::read_entry(&mut f, &entries[0], &e).unwrap(),
        b.manifest
    );
    assert_eq!(psf::read_entry(&mut f, &entries[1], &e).unwrap(), b.mum);
}

#[test]
fn uses_sidecar_index() {
    let t = tempfile::tempdir().unwrap();
    let b = build(t.path(), false);
    let e = DeltaEngine::select(None).unwrap();
    let entries = psf::load_index(&b.path, Some(b.index_xml.as_bytes()), &e).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        psf::load_index(&b.path, None, &e).is_err(),
        "no embedded index in sidecar PSF"
    );
}

#[test]
fn rejects_out_of_range_entries() {
    let t = tempfile::tempdir().unwrap();
    let b = build(t.path(), false);
    let e = DeltaEngine::select(None).unwrap();
    let bad = psf::PsfEntry {
        name: "x.manifest".into(),
        source: SourceType::Raw,
        offset: 1 << 40,
        length: 10,
    };
    let mut f = File::open(&b.path).unwrap();
    assert!(psf::read_entry(&mut f, &bad, &e).is_err());
}
