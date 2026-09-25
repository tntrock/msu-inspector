//! 建置腳本：在 Windows 目標上把 assets/icon.ico 與版本資訊嵌入 exe。
//!
//! build.rs 在「主機」上執行，所以用 CARGO_CFG_TARGET_OS 判斷目標平台，而不是 cfg!(target_os)。

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // 相依 DLL 只從 System32 載入（LOAD_LIBRARY_SEARCH_SYSTEM32），
        // 避免 exe 所在資料夾（例如下載資料夾）被植入同名 DLL
        if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
            println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
        }
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "msu-inspector");
        res.set(
            "FileDescription",
            "msu-inspector - Windows 更新套件部署前審查工具",
        );
        // 缺 rc.exe 等工具時只警告，不中斷建置
        if let Err(e) = res.compile() {
            println!("cargo:warning=嵌入 Windows 資源失敗: {e}");
        }
    }
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");
}
