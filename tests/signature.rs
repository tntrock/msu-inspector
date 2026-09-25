use msu_inspector::core::model::SignatureStatus;
use msu_inspector::core::signature::{is_microsoft_signed, status_from_code, verify};
use msu_inspector::core::sys;

#[test]
fn maps_trust_codes() {
    assert_eq!(status_from_code(0), SignatureStatus::Valid);
    assert_eq!(status_from_code(0x800B_0100), SignatureStatus::Unsigned);
    assert_eq!(status_from_code(0x800B_0003), SignatureStatus::Unsigned);
    assert_eq!(status_from_code(0x8009_6010), SignatureStatus::Invalid);
}

#[test]
fn unsigned_file_is_unsigned() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("x.msu");
    std::fs::write(&p, b"MSCF not signed").unwrap();
    let info = verify(&p);
    assert_eq!(info.status, SignatureStatus::Unsigned);
    assert_eq!(info.signer, None);
    assert!(!is_microsoft_signed(&p));
}

#[test]
fn embedded_microsoft_signature_is_valid() {
    // MpSigStub.exe 使用內嵌 Authenticode（多數系統檔只有目錄簽章）
    let p = sys::windows_dir().join("System32").join("MpSigStub.exe");
    if !p.exists() {
        eprintln!("skipping: {} not present", p.display());
        return;
    }
    let info = verify(&p);
    assert_eq!(info.status, SignatureStatus::Valid);
    assert!(
        info.signer.as_deref().unwrap_or("").contains("Microsoft"),
        "{info:?}"
    );
    assert!(is_microsoft_signed(&p));
}

#[test]
fn missing_file_is_not_valid() {
    assert_ne!(
        verify(std::path::Path::new("Z:\\no\\such.msu")).status,
        SignatureStatus::Valid
    );
}
