//! 檢查建置出的 exe：相依 DLL 只從 System32 搜尋（/DEPENDENTLOADFLAG:0x800）。

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// 讀出 PE32+ 載入設定目錄中的 DependentLoadFlags。
fn dependent_load_flags(pe: &[u8]) -> Option<u16> {
    let nt = u32_at(pe, 0x3C) as usize;
    assert_eq!(&pe[nt..nt + 4], b"PE\0\0");
    let file_header = nt + 4;
    let sections = u16_at(pe, file_header + 2) as usize;
    let opt_size = u16_at(pe, file_header + 16) as usize;
    let opt = file_header + 20;
    assert_eq!(u16_at(pe, opt), 0x20B, "expected PE32+");
    // 資料目錄從選用標頭 +112 開始；第 10 項是載入設定
    let dir = opt + 112 + 10 * 8;
    let rva = u32_at(pe, dir) as usize;
    if rva == 0 {
        return None;
    }
    let table = opt + opt_size;
    let offset = (0..sections).find_map(|i| {
        let s = table + i * 40;
        let va = u32_at(pe, s + 12) as usize;
        let vsize = u32_at(pe, s + 8) as usize;
        let raw = u32_at(pe, s + 20) as usize;
        (va..va + vsize).contains(&rva).then(|| rva - va + raw)
    })?;
    // IMAGE_LOAD_CONFIG_DIRECTORY64.DependentLoadFlags 位於 +0x4E
    (u32_at(pe, offset) as usize > 0x4E).then(|| u16_at(pe, offset + 0x4E))
}

#[test]
fn binary_searches_dependent_dlls_in_system32_only() {
    let exe = assert_cmd::cargo::cargo_bin("msu-inspector");
    let pe = std::fs::read(&exe).unwrap();
    assert_eq!(dependent_load_flags(&pe), Some(0x800), "{}", exe.display());
}
