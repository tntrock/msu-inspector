//! Authenticode 驗證（WinVerifyTrust），沿用 code-signer 的作法；離線、不查撤銷。

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::*;

use super::model::{SignatureInfo, SignatureStatus};

pub fn status_from_code(code: u32) -> SignatureStatus {
    match code {
        0 => SignatureStatus::Valid,
        // TRUST_E_NOSIGNATURE、TRUST_E_SUBJECT_FORM_UNKNOWN、TRUST_E_PROVIDER_UNKNOWN
        0x800B_0100 | 0x800B_0003 | 0x800B_0001 => SignatureStatus::Unsigned,
        _ => SignatureStatus::Invalid,
    }
}

pub fn verify(path: &Path) -> SignatureInfo {
    let wpath: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wpath.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_NONE,
        ..Default::default()
    };
    data.Anonymous.pFile = &mut file_info;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let no_ui = HWND(-1isize as *mut c_void);
    // SAFETY: data / file_info / wpath 在兩次呼叫期間有效；狀態資料在 CLOSE 時釋放。
    unsafe {
        let code = WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut c_void) as u32;
        let status = status_from_code(code);
        let signer = if status == SignatureStatus::Valid {
            signer_name(data.hWVTStateData)
        } else {
            None
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut c_void);
        SignatureInfo { status, signer }
    }
}

/// SAFETY: `state` 必須是 VERIFY 之後、CLOSE 之前的狀態控制代碼。
unsafe fn signer_name(state: windows::Win32::Foundation::HANDLE) -> Option<String> {
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() {
            return None;
        }
        let pc = WTHelperGetProvCertFromChain(sgnr, 0);
        if pc.is_null() || (*pc).pCert.is_null() {
            return None;
        }
        let mut buf = [0u16; 256];
        let n = CertGetNameStringW(
            (*pc).pCert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut buf),
        );
        (n > 1).then(|| String::from_utf16_lossy(&buf[..n as usize - 1]))
    }
}

pub fn is_microsoft_signed(path: &Path) -> bool {
    let info = verify(path);
    info.status == SignatureStatus::Valid
        && info
            .signer
            .as_deref()
            .is_some_and(|s| s.contains("Microsoft"))
}
