//! 完整流程：雜湊 → 簽章 → 拆包 →（PSF）→ DCM 解壓與解析 → 套件資訊 →（本機比對）→ 風險。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

use super::container::{self, Item};
use super::delta::{is_dcm, DcmDecoder, DeltaEngine};
use super::local::{self, LocalEnv};
use super::manifest::decode_text;
use super::manifest::package::{
    kb_from_file_name, parse_mum, parse_pkg_properties, select_package,
};
use super::manifest::parse::parse_component;
use super::model::*;
use super::progress::{Ctx, Progress};
use super::{risk, signature, CoreError};

#[derive(Debug, Clone, Default)]
pub struct AnalyzeOptions {
    pub compare_local: bool,
    /// 暫存資料夾的上層位置；None 時用系統暫存資料夾
    pub temp_root: Option<PathBuf>,
}

pub fn format_label(outer: Option<ContainerFormat>, file_name: &str, has_psf: bool) -> String {
    let msu = file_name.to_ascii_lowercase().ends_with(".msu");
    let base = match (outer, msu) {
        (Some(ContainerFormat::Wim), true) => "msu-wim",
        (Some(ContainerFormat::Wim), false) => "wim",
        (_, true) => "msu-cab",
        _ => "cab",
    };
    if has_psf {
        format!("{base}+psf")
    } else {
        base.to_string()
    }
}

fn sha256_file(path: &Path, ctx: &Ctx) -> Result<String, CoreError> {
    let mut f = std::fs::File::open(path).map_err(|e| CoreError::io(path, e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        ctx.check()?;
        let n = f.read(&mut buf).map_err(|e| CoreError::io(path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn analyze(path: &Path, opts: &AnalyzeOptions, ctx: &Ctx) -> Result<AnalysisReport, CoreError> {
    // 先轉成絕對路徑：之後的拆包（FDI 需要「目錄 + 檔名」）不依賴目前工作目錄
    let path = &std::path::absolute(path).map_err(|e| CoreError::io(path, e))?;
    let meta = std::fs::metadata(path).map_err(|e| CoreError::io(path, e))?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    ctx.report(Progress::Hashing);
    let sha256 = sha256_file(path, ctx)?;
    ctx.report(Progress::Verifying);
    let signature = signature::verify(path);

    let builder = {
        let mut b = tempfile::Builder::new();
        b.prefix("msu-inspector-");
        b
    };
    let temp = match &opts.temp_root {
        Some(root) => builder.tempdir_in(root),
        None => builder.tempdir(),
    }
    .map_err(|e| CoreError::io(path, e))?;

    let mut collected = container::collect(path, temp.path(), ctx)?;
    let psf_engine = if collected.psfs.is_empty() {
        None
    } else {
        let package_dll = collected
            .package_dll
            .clone()
            .filter(|p| signature::is_microsoft_signed(p));
        let engine = DeltaEngine::select(package_dll.as_deref())?;
        container::resolve_psfs(&mut collected, &engine, ctx)?;
        Some(engine.label().to_string())
    };
    if collected.manifests.is_empty() && collected.mums.is_empty() {
        return Err(CoreError::NoPackageFound);
    }

    let mut warnings = std::mem::take(&mut collected.warnings);
    if signature.status != SignatureStatus::Valid {
        warnings.push(Warning::new(
            WarningCode::SignatureNotValid,
            &file_name,
            signature.status.code(),
        ));
    }
    let (components, parse_warnings) = decode_and_parse(&collected.manifests, ctx)?;
    warnings.extend(parse_warnings);

    let mut mums = Vec::new();
    for item in &collected.mums {
        let parsed = item
            .bytes()
            .and_then(|b| decode_text(&b))
            .and_then(|t| parse_mum(&item.name, &t));
        match parsed {
            Ok(m) => mums.push(m),
            Err(e) => warnings.push(Warning::new(
                WarningCode::MumParseFailed,
                &item.vpath,
                e.to_string(),
            )),
        }
    }
    let properties = collected
        .pkg_properties
        .as_deref()
        .map(parse_pkg_properties)
        .unwrap_or_default();
    let kb_hint = kb_from_file_name(&file_name);
    let package = select_package(&mums, kb_hint.as_deref(), properties);
    let has_psf = collected
        .containers
        .iter()
        .any(|c| c.format == ContainerFormat::Psf && c.skipped.is_none());

    let mut report = AnalysisReport {
        mode: Mode::Static,
        local_context: None,
        source: SourceInfo {
            format: format_label(collected.outer, &file_name, has_psf),
            file: file_name,
            size: meta.len(),
            sha256,
            signature,
            containers: std::mem::take(&mut collected.containers),
            delta_engine: psf_engine,
        },
        package,
        components,
        warnings,
    };
    drop(collected);

    if opts.compare_local {
        match LocalEnv::detect() {
            Ok(env) => local::compare(&mut report, &env, ctx)?,
            Err(e) => report.warnings.push(Warning::new(
                WarningCode::LocalCompareFailed,
                "local",
                e.to_string(),
            )),
        }
    }
    risk::apply(&mut report);
    temp.close().map_err(|e| CoreError::io(path, e))?;
    Ok(report)
}

type DcmTools = (DeltaEngine, Result<DcmDecoder, CoreError>);

fn decode_one(item: &Item, dcm: Option<&DcmTools>) -> Result<String, CoreError> {
    let bytes = item.bytes()?;
    if !is_dcm(&bytes) {
        return decode_text(&bytes);
    }
    let (engine, decoder) =
        dcm.ok_or_else(|| CoreError::Delta("DCM decoder unavailable".into()))?;
    let decoder = decoder
        .as_ref()
        .map_err(|e| CoreError::Delta(e.to_string()))?;
    decode_text(&decoder.decode(engine, &bytes)?)
}

/// 以多執行緒解壓並解析所有 manifest；單一檔案失敗只記警告。
fn decode_and_parse(
    items: &[Item],
    ctx: &Ctx,
) -> Result<(Vec<Component>, Vec<Warning>), CoreError> {
    let needs_dcm = items
        .iter()
        .any(|i| matches!(&i.data, container::ItemData::Bytes(b) if is_dcm(b)));
    let dcm: Option<DcmTools> = if needs_dcm {
        Some((
            DeltaEngine::system("msdelta.dll")?,
            DcmDecoder::from_system(),
        ))
    } else {
        None
    };
    let total = items.len();
    let done = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 16);
    let chunk = total.div_ceil(threads).max(1);
    let results: Vec<(Vec<Component>, Vec<Warning>)> = std::thread::scope(|s| {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|part| {
                let dcm = dcm.as_ref();
                let done = &done;
                s.spawn(move || {
                    let mut comps = Vec::new();
                    let mut warns = Vec::new();
                    for item in part {
                        if ctx.is_cancelled() {
                            break;
                        }
                        match decode_one(item, dcm) {
                            Ok(text) => match parse_component(&item.name, &text) {
                                Ok(c) => comps.push(c),
                                Err(e) => warns.push(Warning::new(
                                    WarningCode::ManifestParseFailed,
                                    &item.vpath,
                                    e.to_string(),
                                )),
                            },
                            Err(e) => warns.push(Warning::new(
                                WarningCode::ManifestDecodeFailed,
                                &item.vpath,
                                e.to_string(),
                            )),
                        }
                        let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                        if d.is_multiple_of(250) || d == total {
                            ctx.report(Progress::Decoding { done: d, total });
                        }
                    }
                    (comps, warns)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("manifest worker panicked"))
            .collect()
    });
    ctx.check()?;
    let mut comps = Vec::with_capacity(total);
    let mut warns = Vec::new();
    for (c, w) in results {
        comps.extend(c);
        warns.extend(w);
    }
    comps.sort_by(|a, b| {
        a.identity
            .name
            .to_ascii_lowercase()
            .cmp(&b.identity.name.to_ascii_lowercase())
            .then_with(|| a.identity.cmp(&b.identity))
    });
    Ok((comps, warns))
}
