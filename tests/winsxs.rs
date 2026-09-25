//! 以本機 WinSxS 的真實 manifest 驗證解析器：前 3000 個一般測試執行，全部則用 --ignored。

use msu_inspector::core::delta::{is_dcm, DcmDecoder, DeltaEngine};
use msu_inspector::core::manifest::{decode_text, parse::parse_component};
use msu_inspector::core::model::ActionKind;
use msu_inspector::core::sys;

fn run(limit: usize) {
    let engine = DeltaEngine::system("msdelta.dll").unwrap();
    let dcm = DcmDecoder::from_system().unwrap();
    let dir = sys::windows_dir().join("WinSxS").join("Manifests");
    let (mut parsed, mut failed, mut actions, mut unknown) = (0usize, Vec::new(), 0usize, 0usize);
    for e in std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .take(limit)
    {
        let bytes = std::fs::read(e.path()).unwrap();
        if !is_dcm(&bytes) {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let text = decode_text(&dcm.decode(&engine, &bytes).unwrap()).unwrap();
        match parse_component(&name, &text) {
            Ok(c) => {
                parsed += 1;
                actions += c.actions.len();
                unknown += c
                    .actions
                    .iter()
                    .filter(|a| a.kind() == ActionKind::Unknown)
                    .count();
            }
            Err(err) => failed.push(format!("{name}: {err}")),
        }
    }
    eprintln!(
        "parsed {parsed}, failed {}, actions {actions}, unknown {unknown}",
        failed.len()
    );
    assert!(failed.is_empty(), "{:#?}", &failed[..failed.len().min(20)]);
    assert!(
        unknown * 100 <= actions.max(1),
        "unknown actions exceed 1%: {unknown}/{actions}"
    );
}

#[test]
fn parses_local_winsxs_manifests() {
    run(3000);
}

#[test]
#[ignore = "解析整個 WinSxS，約需一分鐘"]
fn parses_all_local_winsxs_manifests() {
    run(usize::MAX);
}
