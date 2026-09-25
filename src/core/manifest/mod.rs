//! manifest / .mum 的共用工具：文字解碼、XML 取值。

pub mod parse;

use roxmltree::{Document, Node, ParsingOptions};

use super::model::AssemblyIdentity;
use super::CoreError;

/// 依 BOM 解碼；沒有 BOM 視為 UTF-8，不合法時以替代字元保留內容。
pub fn decode_text(bytes: &[u8]) -> Result<String, CoreError> {
    fn utf16(body: &[u8], le: bool) -> Result<String, CoreError> {
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16(&units).map_err(|e| CoreError::Xml(e.to_string()))
    }
    let text = if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(rest).into_owned()
    } else if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        utf16(rest, true)?
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        utf16(rest, false)?
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    Ok(text)
}

/// 解析 XML；允許 DTD，並略過開頭殘留的 BOM 字元。
pub(crate) fn parse_doc(text: &str) -> Result<Document<'_>, CoreError> {
    let text = text.trim_start_matches('\u{feff}');
    let opts = ParsingOptions {
        allow_dtd: true,
        ..ParsingOptions::default()
    };
    Document::parse_with_options(text, opts).map_err(|e| CoreError::Xml(e.to_string()))
}

/// 元素的本地名稱（忽略命名空間前綴）是否為 `name`。
pub(crate) fn is_el(n: Node, name: &str) -> bool {
    n.is_element() && n.tag_name().name() == name
}

pub(crate) fn child<'a, 'i>(n: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| is_el(*c, name))
}

pub(crate) fn elements<'a, 'i: 'a>(
    n: Node<'a, 'i>,
    name: &'a str,
) -> impl Iterator<Item = Node<'a, 'i>> + 'a {
    n.children().filter(move |c| is_el(*c, name))
}

pub(crate) fn attr(n: Node, name: &str) -> Option<String> {
    n.attribute(name).map(str::to_string)
}

/// 讀取 `assemblyIdentity` 元素。
pub(crate) fn identity_of(n: Node) -> AssemblyIdentity {
    AssemblyIdentity {
        name: attr(n, "name").unwrap_or_default(),
        version: attr(n, "version").unwrap_or_default(),
        arch: attr(n, "processorArchitecture").unwrap_or_default(),
        language: attr(n, "language").unwrap_or_default(),
        public_key_token: attr(n, "publicKeyToken").unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_boms() {
        assert_eq!(decode_text(b"\xEF\xBB\xBFabc").unwrap(), "abc");
        assert_eq!(decode_text(b"\xFF\xFEa\x00b\x00").unwrap(), "ab");
        assert_eq!(decode_text(b"\xFE\xFF\x00a\x00b").unwrap(), "ab");
        assert_eq!(decode_text(b"plain").unwrap(), "plain");
    }
}
