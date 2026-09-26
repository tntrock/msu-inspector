"""產生 assets/icon.ico（只用 Python 標準函式庫）。

圖案：藍色圓角方塊上的白色放大鏡，代表「檢視更新內容」。
執行：python assets/gen_icon.py
"""
import math
import struct
import zlib
from pathlib import Path

SIZES = [16, 32, 48, 256]
BG = (0x1F, 0x6F, 0xEB)
FG = (0xFF, 0xFF, 0xFF)


def pixel(u, v):
    """u, v ∈ [0,1)；回傳 RGBA。"""
    r = 0.2  # 圓角半徑
    cx = min(max(u, r), 1 - r)
    cy = min(max(v, r), 1 - r)
    if math.hypot(u - cx, v - cy) > r:
        return (0, 0, 0, 0)
    # 鏡片：圓環
    d = math.hypot(u - 0.43, v - 0.43)
    if 0.17 <= d <= 0.25:
        return FG + (255,)
    # 握把：從右下沿 45 度延伸的線段
    t = ((u - 0.58) + (v - 0.58)) / 2
    if 0.0 <= t <= 0.2 and abs((u - 0.58) - (v - 0.58)) < 0.09:
        return FG + (255,)
    return BG + (255,)


def png(size):
    rows = b""
    for y in range(size):
        rows += b"\x00" + b"".join(
            bytes(pixel((x + 0.5) / size, (y + 0.5) / size)) for x in range(size)
        )

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(rows, 9))
        + chunk(b"IEND", b"")
    )


def main():
    images = [png(s) for s in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    for s, img in zip(SIZES, images):
        dim = 0 if s == 256 else s
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(img), offset)
        offset += len(img)
    out = Path(__file__).with_name("icon.ico")
    out.write_bytes(header + entries + b"".join(images))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
