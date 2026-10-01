
import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import rdpcap
from scapy.layers.inet import UDP
import struct
import numpy as np
import cv2
import os
from collections import defaultdict
from datetime import datetime

# --------- Mono/Bayer unpackers (same as before) ----------
def unpack_mono12_packed(data: bytes) -> np.ndarray:
    if len(data) % 3 != 0:
        data = data[:-(len(data) % 3)]
    arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)
    pixel0 = (arr[:, 0].astype(np.uint16) << 4) | ((arr[:, 1] & 0x0F).astype(np.uint16))
    pixel1 = ((arr[:, 1] & 0xF0).astype(np.uint16) >> 4) | (arr[:, 2].astype(np.uint16) << 4)
    out = np.empty(arr.shape[0] * 2, dtype=np.uint16)
    out[0::2] = pixel0
    out[1::2] = pixel1
    return out

def unpack_mono10_packed(data: bytes) -> np.ndarray:
    if len(data) % 3 != 0:
        data = data[:-(len(data) % 3)]
    arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)
    pixel0 = (arr[:, 0].astype(np.uint16) << 2) | (arr[:, 1] & 0b00000011).astype(np.uint16)
    pixel1 = ((arr[:, 1] & 0b11111100).astype(np.uint16) >> 2) | (arr[:, 2].astype(np.uint16) << 6)
    out = np.empty(arr.shape[0] * 2, dtype=np.uint16)
    out[0::2] = pixel0
    out[1::2] = pixel1
    return out

def unpack_mono10_unpacked(data: bytes) -> np.ndarray:
    raw = np.frombuffer(data, dtype=np.uint16)
    return raw & 0x03FF

def unpack_mono12_unpacked(data: bytes) -> np.ndarray:
    raw = np.frombuffer(data, dtype=np.uint16)
    return raw & 0x0FFF

def unpack_mono14_unpacked(data: bytes) -> np.ndarray:
    raw = np.frombuffer(data, dtype=np.uint16)
    return raw & 0x3FFF

def unpack_mono16_unpacked(data: bytes) -> np.ndarray:
    return np.frombuffer(data, dtype=np.uint16)

# ---------- Mono/Bayer mapping ----------
PIXEL_UNPACKERS = {
    0x01080001: lambda d: np.frombuffer(d, dtype=np.uint8),        # Mono8
    0x01080002: lambda d: np.frombuffer(d, dtype=np.uint8),        # Mono8s
    0x01100003: unpack_mono10_unpacked,                            # Mono10
    0x010C0004: unpack_mono10_packed,                              # Mono10Packed
    0x01100005: unpack_mono12_unpacked,                            # Mono12
    0x010C0006: unpack_mono12_packed,                              # Mono12Packed
    0x01100025: unpack_mono14_unpacked,                            # Mono14
    0x01100007: unpack_mono16_unpacked,                            # Mono16
}

# Add Bayer formats that share mono layout
for fmt in [
    # 8‑bit
    0x01080008, 0x01080009, 0x0108000A, 0x0108000B,
    # 10‑bit unpacked
    0x0110000C, 0x0110000D, 0x0110000E, 0x0110000F,
    # 12‑bit unpacked
    0x01100010, 0x01100011, 0x01100012, 0x01100013,
    # 16‑bit unpacked
    0x0110002E, 0x0110002F, 0x01100030, 0x01100031,
]:
    if fmt & 0x00FF0000 == 0x00080000:
        PIXEL_UNPACKERS[fmt] = lambda d: np.frombuffer(d, dtype=np.uint8)
    elif fmt in (0x0110000C, 0x0110000D, 0x0110000E, 0x0110000F):
        PIXEL_UNPACKERS[fmt] = unpack_mono10_unpacked
    elif fmt in (0x01100010, 0x01100011, 0x01100012, 0x01100013):
        PIXEL_UNPACKERS[fmt] = unpack_mono12_unpacked
    else:
        PIXEL_UNPACKERS[fmt] = unpack_mono16_unpacked

# Bayer packed
for fmt in [0x010C0026, 0x010C0027, 0x010C0028, 0x010C0029]:
    PIXEL_UNPACKERS[fmt] = unpack_mono10_packed
for fmt in [0x010C002A, 0x010C002B, 0x010C002C, 0x010C002D]:
    PIXEL_UNPACKERS[fmt] = unpack_mono12_packed

# ---------- Color expand helper ----------
def expand_color_channels(raw: bytes, width: int, height: int, channels: int, bytes_per_channel: int):
    if bytes_per_channel == 1:
        dtype = np.uint8
    else:
        dtype = np.dtype('<u2')  # little‑endian uint16
    arr = np.frombuffer(raw, dtype=dtype)
    expected = width * height * channels
    if arr.size < expected:
        arr = np.pad(arr, (0, expected - arr.size), 'constant')
    arr = arr[:expected].reshape((height, width, channels))
    out = arr.reshape((height, width * channels))  # flatten channels horizontally
    return out

def process_color_format(fmt: int, raw: bytes, w: int, h: int):
    bits_per_pixel = (fmt >> 16) & 0xFF
    bytes_per_pixel = bits_per_pixel // 8
    if bytes_per_pixel in (3, 4):
        bytes_per_channel = 1
        channels = bytes_per_pixel
    elif bytes_per_pixel in (6, 8):
        bytes_per_channel = 2
        channels = bytes_per_pixel // 2
    else:
        # unsupported / fallback
        raise ValueError("Unsupported bytes per pixel for expand: %d" % bytes_per_pixel)
    return expand_color_channels(raw, w, h, channels, bytes_per_channel)

def category_of(fmt: int):
    return (fmt >> 24) & 0xFF

# --------- GVSP processing ----------
def process_file(pcap_path: str, prefix: str, log_cb):
    try:
        log = log_cb
        log("📦 pcap 파일 불러오는 중…")
        packets = rdpcap(pcap_path)

        meta = {}
        buffers = defaultdict(bytearray)
        state = defaultdict(lambda: {"last": None, "payload_len": None})

        for pkt in packets:
            if UDP not in pkt:
                continue
            data = bytes(pkt[UDP].payload)
            if len(data) < 8:
                continue

            gvsp_fmt = data[4]
            pkt_id   = data[5]
            blk_id   = struct.unpack_from('>H', data, 2)[0]

            # Leader
            if gvsp_fmt == 0x01 and pkt_id == 0:
                fmt = struct.unpack_from('>I', data, 20)[0]
                w   = struct.unpack_from('>H', data, 26)[0]
                h   = struct.unpack_from('>H', data, 30)[0]
                meta[blk_id] = {"fmt": fmt, "w": w, "h": h}
                log(f"📝 block {blk_id}: {w}×{h}, pixelFormat=0x{fmt:08X}")
                continue

            # Payload
            if gvsp_fmt == 0x03:
                payload = data[8:]
                st = state[blk_id]
                if st["payload_len"] is None:
                    st["payload_len"] = len(payload)
                if st["last"] is not None and pkt_id - st["last"] > 1:
                    gap = pkt_id - st["last"] - 1
                    buffers[blk_id].extend(b"\x00" * gap * st["payload_len"])
                st["last"] = pkt_id
                buffers[blk_id].extend(payload)

        if not meta:
            log("❌ 리더 패킷을 찾지 못했습니다.")
            return

        # Output dir
        tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.splitext(os.path.basename(prefix))[0]
        out_dir = f"{base}_blocks_{tag}"
        os.makedirs(out_dir, exist_ok=True)
        log(f"📂 출력 폴더: {out_dir}")

        # Process blocks
        for blk_id, raw in buffers.items():
            if blk_id not in meta:
                log(f"⚠️ block {blk_id}: 메타 없음 – 스킵")
                continue
            info = meta[blk_id]
            w, h, fmt = info["w"], info["h"], info["fmt"]

            try:
                if fmt in PIXEL_UNPACKERS:
                    img_data = PIXEL_UNPACKERS[fmt](bytes(raw))
                elif category_of(fmt) == 0x02:  # RGB/BGR/RGBA/BGRA etc.
                    img_data = process_color_format(fmt, bytes(raw), w, h)
                else:
                    # fallback: average to mono
                    img_data = expand_color_channels(bytes(raw), w, h, 1, 1).reshape((h, w))
            except Exception as e:
                log(f"❌ block {blk_id}: 변환 실패 – {e}")
                continue

            # Determine final shape
            if img_data.ndim == 1:
                expected = w * h
                if img_data.size < expected:
                    img_data = np.pad(img_data, (0, expected - img_data.size), 'constant')
                img = img_data[:expected].reshape((h, w))
            else:
                img = img_data  # already 2D (h, w*channels)

            out_path = os.path.join(out_dir, f"{base}_block{blk_id}.tiff")
            cv2.imwrite(out_path, img)
            log(f"💾 block {blk_id} → {out_path}")

        log("✅ 모든 block 저장 완료!")
    except Exception as e:
        log_cb(f"❌ 오류: {e}")

# -------------- UI --------------
def select_pcap():
    p = filedialog.askopenfilename(filetypes=[("PCAPNG/PCAP files", "*.pcapng *.pcap")])
    if p:
        pcap_var.set(p)
        prefix_var.set(os.path.splitext(os.path.basename(p))[0])

def run():
    pcap = pcap_var.get().strip()
    prefix = prefix_var.get().strip()
    if not pcap or not prefix:
        messagebox.showwarning("입력 오류", "PCAP 파일과 prefix를 입력하세요.")
        return
    log.delete(1.0, tk.END)
    process_file(pcap, prefix, lambda m: log.insert(tk.END, m + "\n"))

root = tk.Tk()
root.title("GVSP Extractor – RGB Channels Expand")
root.geometry("660x400")

pcap_var = tk.StringVar()
prefix_var = tk.StringVar()

tk.Label(root, text="PCAPNG 파일").pack()
tk.Entry(root, textvariable=pcap_var, width=85).pack()
tk.Button(root, text="파일 선택", command=select_pcap).pack(pady=4)

tk.Label(root, text="파일 prefix").pack()
tk.Entry(root, textvariable=prefix_var, width=85).pack()

tk.Button(root, text="실행", command=run, bg="green", fg="white").pack(pady=8)

log = tk.Text(root, height=12, width=100)
log.pack()

root.mainloop()
