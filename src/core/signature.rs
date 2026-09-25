//! Authenticode 驗證（WinVerifyTrust），沿用 code-signer 的作法；離線、不查撤銷。

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::Cryptography::{
    CertGetNameStringW, CertVerifyCertificateChainPolicy, CERT_CHAIN_POLICY_MICROSOFT_ROOT,
    CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
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

/// 以 WinVerifyTrust 驗證 `path`，在 VERIFY 與 CLOSE 之間把結果碼與狀態代號交給 `f`。
fn with_trust<R>(path: &Path, f: impl FnOnce(u32, HANDLE) -> R) -> R {
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
    // SAFETY: data / file_info / wpath 在兩次呼叫期間有效；狀態資料在 CLOSE 時釋放，
    // `f` 只在 CLOSE 之前使用狀態代號。
    unsafe {
        let code = WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut c_void) as u32;
        let r = f(code, data.hWVTStateData);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut c_void);
        r
    }
}

pub fn verify(path: &Path) -> SignatureInfo {
    with_trust(path, |code, state| {
        let status = status_from_code(code);
        let signer = if status == SignatureStatus::Valid {
            // SAFETY: state 為 VERIFY 之後、CLOSE 之前的狀態代號。
            unsafe { signer_name(state) }
        } else {
            None
        };
        SignatureInfo { status, signer }
    })
}

/// SAFETY: `state` 必須是 VERIFY 之後、CLOSE 之前的狀態控制代碼。
unsafe fn primary_signer(state: HANDLE) -> Option<*mut CRYPT_PROVIDER_SGNR> {
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        (!sgnr.is_null()).then_some(sgnr)
    }
}

/// SAFETY: `state` 必須是 VERIFY 之後、CLOSE 之前的狀態控制代碼。
unsafe fn signer_name(state: HANDLE) -> Option<String> {
    unsafe {
        let sgnr = primary_signer(state)?;
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

/// 簽章有效，且簽章者的憑證鏈通過 `CERT_CHAIN_POLICY_MICROSOFT_ROOT`（根憑證為 Microsoft 根）。
pub fn chains_to_microsoft_root(path: &Path) -> bool {
    with_trust(path, |code, state| {
        if code != 0 {
            return false;
        }
        // SAFETY: state 為 VERIFY 之後、CLOSE 之前的狀態代號；鏈結內容由 WinTrust 持有，
        // 在 CLOSE 前有效，policy para / status 為本函式的區域變數。
        unsafe {
            let Some(sgnr) = primary_signer(state) else {
                return false;
            };
            let chain = (*sgnr).pChainContext;
            if chain.is_null() {
                return false;
            }
            let para = CERT_CHAIN_POLICY_PARA {
                cbSize: size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
                ..Default::default()
            };
            let mut status = CERT_CHAIN_POLICY_STATUS {
                cbSize: size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
                ..Default::default()
            };
            CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_MICROSOFT_ROOT,
                chain,
                &para,
                &mut status,
            )
            .as_bool()
                && status.dwError == 0
        }
    })
}

/// 可信任的 Microsoft 檔案：簽章有效、簽章者名稱含 `Microsoft`，且憑證鏈到 Microsoft 根。
pub fn is_microsoft_signed(path: &Path) -> bool {
    let info = verify(path);
    info.status == SignatureStatus::Valid
        && info
            .signer
            .as_deref()
            .is_some_and(|s| s.contains("Microsoft"))
        && chains_to_microsoft_root(path)
}
