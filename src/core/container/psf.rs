//! PSF（Patch Storage File）：依索引（`*.psf.cix.xml` 或檔頭內嵌）取出指定檔案。
//!
//! 索引格式（見 spec 第 11 節）：
//! `<Container type="PSF"><Files><File name=".."><Delta><Source type="RAW|PA30|PA19" offset length/>`

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::core::delta::{apply_pa19, DeltaEngine};
use crate::core::manifest::{attr, child, decode_text, elements, is_el, parse_doc};
use crate::core::CoreError;

/// 單一項目大小上限：manifest / .mum 不會超過這個大小，超過視為索引錯誤。
const MAX_ENTRY: u64 = 256 * 1024 * 1024;
const EMBEDDED_INDEX_OFFSET: u64 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    Raw,
    Pa30,
    Pa19,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsfEntry {
    pub name: String,
    pub source: SourceType,
    pub offset: u64,
    pub length: u64,
}

pub fn parse_index(xml: &str) -> Result<Vec<PsfEntry>, CoreError> {
    let doc = parse_doc(xml)?;
    let root = doc.root_element();
    if !is_el(root, "Container") {
        return Err(CoreError::Xml("PSF index root is not <Container>".into()));
    }
    let files =
        child(root, "Files").ok_or_else(|| CoreError::Xml("PSF index has no <Files>".into()))?;
    let mut out = Vec::new();
    for f in elements(files, "File") {
        let Some(src) = child(f, "Delta").and_then(|d| child(d, "Source")) else {
            continue;
        };
        let source = match attr(src, "type")
            .unwrap_or_default()
            .to_ascii_uppercase()
            .as_str()
        {
            "RAW" => SourceType::Raw,
            "PA30" => SourceType::Pa30,
            "PA19" => SourceType::Pa19,
            other => return Err(CoreError::Xml(format!("unknown PSF source type {other}"))),
        };
        let num = |name: &str| -> Result<u64, CoreError> {
            attr(src, name)
                .and_then(|v| v.trim().parse().ok())
                .ok_or_else(|| CoreError::Xml(format!("PSF entry missing {name}")))
        };
        out.push(PsfEntry {
            name: attr(f, "name").unwrap_or_default(),
            source,
            offset: num("offset")?,
            length: num("length")?,
        });
    }
    Ok(out)
}

fn read_at(file: &mut File, offset: u64, length: u64) -> Result<Vec<u8>, CoreError> {
    let size = file
        .metadata()
        .map_err(|e| CoreError::Container {
            path: "psf".into(),
            detail: e.to_string(),
        })?
        .len();
    if length > MAX_ENTRY || offset.checked_add(length).is_none_or(|end| end > size) {
        return Err(CoreError::Container {
            path: "psf".into(),
            detail: format!("entry out of range (offset {offset}, length {length}, file {size})"),
        });
    }
    let mut buf = vec![0u8; length as usize];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut buf))
        .map_err(|e| CoreError::Container {
            path: "psf".into(),
            detail: e.to_string(),
        })?;
    Ok(buf)
}

/// 24H2 起的 PSF：偏移 4 為 u32 索引長度，偏移 0x80 起為 PA30（null-source）壓縮的索引 XML。
pub fn read_embedded_index(psf: &Path, engine: &DeltaEngine) -> Result<String, CoreError> {
    let mut f = File::open(psf).map_err(|e| CoreError::io(psf, e))?;
    let head = read_at(&mut f, 0, 8)?;
    let len = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as u64;
    if len == 0 {
        return Err(CoreError::Container {
            path: psf.display().to_string(),
            detail: "no embedded PSF index".into(),
        });
    }
    let delta = read_at(&mut f, EMBEDDED_INDEX_OFFSET, len)?;
    decode_text(&engine.apply(&[], &delta)?)
}

/// 有獨立索引檔時使用之，否則讀檔頭內嵌索引。
pub fn load_index(
    psf: &Path,
    sidecar: Option<&[u8]>,
    engine: &DeltaEngine,
) -> Result<Vec<PsfEntry>, CoreError> {
    let xml = match sidecar {
        Some(bytes) => decode_text(bytes)?,
        None => read_embedded_index(psf, engine)?,
    };
    parse_index(&xml)
}

pub fn read_entry(
    file: &mut File,
    entry: &PsfEntry,
    engine: &DeltaEngine,
) -> Result<Vec<u8>, CoreError> {
    let raw = read_at(file, entry.offset, entry.length)?;
    match entry.source {
        SourceType::Raw => Ok(raw),
        SourceType::Pa30 => engine.apply(&[], &raw),
        SourceType::Pa19 => apply_pa19(&raw),
    }
}
