# -*- coding: utf-8 -*-
"""
GVSP Extractor – TRUE FINAL VERSION
정확한 pkt_id 위치 기반 조립 (데이터 몰림 문제 완전 해결)

기능:
 - pkt_id 정확한 위치에 재배치 (missing → 0 패딩)
 - Trailer 기반 last payload = trailer_id - 1
 - 마지막 payload는 수정하지 않음
 - empty/all-zero/resend은 출력 없이 처리만
 - GUI Log = missing count only
 - missing packet Excel 저장
"""

import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import rdpcap
from scapy.layers.inet import UDP
import struct
import numpy as np
import pandas as pd
import cv2
import os
from datetime import datetime


# --------------------------------------------------
# Pixel unpackers (same as before)
# --------------------------------------------------

def unpack_mono12_packed(data: bytes) -> np.ndarray:
    if len(data) % 3 != 0:
        data = data[:-(len(data) % 3)]
    arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)
    pixel0 = (arr[:, 0].astype(np.uint16) << 4) | ((arr[:, 1] & 0x0F).astype(np.uint16))
    pixel1 = ((arr[:, 1] & 0xF0) >> 4) | (arr[:, 2].astype(np.uint16) << 4)
    out = np.empty(arr.shape[0] * 2, dtype=np.uint16)
    out[0::2] = pixel0
    out[1::2] = pixel1
    return out

def unpack_mono10_packed(data: bytes) -> np.ndarray:
    if len(data) % 3 != 0:
        data = data[:-(len(data) % 3)]
    arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)
    pixel0 = (arr[:, 0].astype(np.uint16) << 2) | (arr[:, 1] & 0b11)
    pixel1 = ((arr[:, 1] & 0b11111100) >> 2) | (arr[:, 2].astype(np.uint16) << 6)
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

PIXEL_UNPACKERS = {
    0x01080001: lambda d: np.frombuffer(d, dtype=np.uint8),
    0x01080002: lambda d: np.frombuffer(d, dtype=np.uint8),
    0x01100003: unpack_mono10_unpacked,
    0x010C0004: unpack_mono10_packed,
    0x01100005: unpack_mono12_unpacked,
    0x010C0006: unpack_mono12_packed,
    0x01100025: unpack_mono14_unpacked,
    0x01100007: unpack_mono16_unpacked,
}

def category_of(fmt: int):
    return (fmt >> 24) & 0xFF


# --------------------------------------------------
# Main processor
# --------------------------------------------------

def process_file(pcap_path: str, prefix: str, logcb):
    try:
        log = logcb
        log("📦 PCAP 불러오는 중…")

        pkts = rdpcap(pcap_path)
        blocks = {}
        excel_missing = {}

        # ------------------------------------------
        # Packet collect
        # ------------------------------------------
        for pkt in pkts:
            if UDP not in pkt:
                continue

            data = bytes(pkt[UDP].payload)
            if len(data) < 8:
                continue

            gvsp_fmt = data[4]
            if gvsp_fmt not in (0x01, 0x02, 0x03):
                continue

            blk_id = struct.unpack_from(">H", data, 2)[0]
            pkt_id = (data[5] << 16) | (data[6] << 8) | data[7]

            if blk_id not in blocks:
                blocks[blk_id] = {
                    "fmt": None,
                    "w": None,
                    "h": None,
                    "payloads": {},
                    "trailer_id": None,
                }

            blk = blocks[blk_id]

            # Leader
            if gvsp_fmt == 0x01 and pkt_id == 0:
                if len(data) < 32:
                    continue
                blk["fmt"] = struct.unpack_from(">I", data, 20)[0]
                blk["w"] = struct.unpack_from(">H", data, 26)[0]
                blk["h"] = struct.unpack_from(">H", data, 30)[0]
                log(f"📝 block {blk_id}: {blk['w']}x{blk['h']}, fmt=0x{blk['fmt']:08X}")
                continue

            # Trailer
            if gvsp_fmt == 0x02:
                blk["trailer_id"] = pkt_id
                log(f"📘 block {blk_id}: trailer pkt_id={pkt_id}")
                continue

            # Payload (로그 출력 없음)
            if gvsp_fmt == 0x03:
                blk["payloads"][pkt_id] = data[8:]
                continue

        # ------------------------------------------
        # Output directory
        # ------------------------------------------
        tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.splitext(os.path.basename(prefix))[0]
        out_dir = f"{base}_blocks_{tag}"
        os.makedirs(out_dir, exist_ok=True)

        # ------------------------------------------
        # Reassembly
        # ------------------------------------------
        for blk_id, blk in blocks.items():
            fmt, w, h = blk["fmt"], blk["w"], blk["h"]
            if fmt is None or not blk["payloads"]:
                continue

            received_ids = sorted(blk["payloads"].keys())

            # determine last payload id
            if blk["trailer_id"] is None:
                last_payload = received_ids[-1]
            else:
                last_payload = blk["trailer_id"] - 1

            # payload chunk size
            standard_size = len(blk["payloads"][received_ids[0]])

            # expected range based on pkt_id positions
            expected_start = received_ids[0]
            expected_end = last_payload
            expected_range = range(expected_start, expected_end + 1)

            # missing packets
            missing_list = [pid for pid in expected_range if pid not in blk["payloads"]]

            if missing_list:
                log(f"⚠ block {blk_id}: missing packets = {len(missing_list)}")
                excel_missing[blk_id] = missing_list
            else:
                log(f"✔ block {blk_id}: no missing packets")

            # ------------------------------------------
            # TRUE CORRECT REASSEMBLY (no more shift!)
            # ------------------------------------------
            parts = []
            for pid in expected_range:
                if pid in blk["payloads"]:
                    # payload present
                    payload = blk["payloads"][pid]

                    # last payload → do not modify
                    if pid == last_payload:
                        parts.append(payload)
                    else:
                        # empty/zero payload → 0 padding
                        if len(payload) == 0 or all(b == 0 for b in payload):
                            parts.append(b"\x00" * standard_size)
                        else:
                            parts.append(payload)

                else:
                    # missing → zero padding
                    parts.append(b"\x00" * standard_size)

            raw = b"".join(parts)

            # size control
            bpp = (fmt >> 16) & 0xFF
            bytes_per_pixel = max(1, bpp // 8)
            expected_bytes = w * h * bytes_per_pixel

            if len(raw) < expected_bytes:
                raw += b"\x00" * (expected_bytes - len(raw))
            raw = raw[:expected_bytes]

            # unpack
            if fmt in PIXEL_UNPACKERS:
                img_data = PIXEL_UNPACKERS[fmt](raw)
            elif category_of(fmt) == 0x02:
                img_data = raw.reshape((h, w, -1))
            else:
                img_data = np.frombuffer(raw, dtype=np.uint8).reshape(h, w)

            img = img_data.reshape(h, w) if img_data.ndim == 1 else img_data

            out_path = os.path.join(out_dir, f"{base}_block{blk_id}.tiff")
            cv2.imwrite(out_path, img)
            log(f"💾 block {blk_id} 저장 완료 → {out_path}")

        # ------------------------------------------
        # Save Excel
        # ------------------------------------------
        if excel_missing:
            excel_path = os.path.join(out_dir, f"{base}_missing_packets.xlsx")
            with pd.ExcelWriter(excel_path) as writer:
                for blk_id, lst in excel_missing.items():
                    df = pd.DataFrame({"missing_packet_id": lst})
                    df.to_excel(writer, sheet_name=f"block_{blk_id}", index=False)

            log(f"📘 누락 packet Excel 저장 완료 → {excel_path}")

        log("🎉 모든 block 저장 완료!")

    except Exception as e:
        logcb(f"❌ 오류: {e}")


# --------------------------------------------------
# GUI
# --------------------------------------------------

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
root.title("GVSP Extractor – TRUE FINAL VERSION")
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
