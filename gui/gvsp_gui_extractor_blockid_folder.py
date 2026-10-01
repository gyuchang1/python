
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

# ---------- Pixel‑format unpackers ----------
def unpack_mono12_packed(data: bytes) -> np.ndarray:
    if len(data) % 3 != 0:
        data = data[:-(len(data) % 3)]
    arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)
    pixel0 = (arr[:, 0].astype(np.uint16) << 4) | ((arr[:, 1] & 0x0F).astype(np.uint16))
    pixel1 = ((arr[:, 1] & 0xF0).astype(np.uint16) >> 4) | (arr[:, 2].astype(np.uint16) << 4)
    unpacked = np.empty(arr.shape[0] * 2, dtype=np.uint16)
    unpacked[0::2] = pixel0
    unpacked[1::2] = pixel1
    return unpacked

def unpack_mono10_packed(data: bytes) -> np.ndarray:
    if len(data) % 3 != 0:
        data = data[:-(len(data) % 3)]
    arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)
    pixel0 = (arr[:, 0].astype(np.uint16) << 2) | (arr[:, 1] & 0b00000011).astype(np.uint16)
    pixel1 = ((arr[:, 1] & 0b11111100).astype(np.uint16) >> 2) | (arr[:, 2].astype(np.uint16) << 6)
    unpacked = np.empty(arr.shape[0] * 2, dtype=np.uint16)
    unpacked[0::2] = pixel0
    unpacked[1::2] = pixel1
    return unpacked

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
    0x01080001: lambda d: np.frombuffer(d, dtype=np.uint8),       # Mono8
    0x01100003: unpack_mono10_unpacked,  # Mono10
    0x010C0004: unpack_mono10_packed,    # Mono10Packed
    0x01100005: unpack_mono12_unpacked,  # Mono12
    0x010C0006: unpack_mono12_packed,    # Mono12Packed
    0x01100025: unpack_mono14_unpacked,  # Mono14
    0x01100007: unpack_mono16_unpacked,  # Mono16
}

# ---------- Main processing ----------
def process_file(pcap_path: str, prefix: str, log_cb):
    try:
        log = log_cb
        log("📦 pcap 파일 불러오는 중...")
        packets = rdpcap(pcap_path)

        meta = {}
        buffers = defaultdict(bytearray)
        state = defaultdict(lambda: {"last": None, "payload_len": None})

        for pkt in packets:
            if UDP not in pkt:
                continue
            udp_payload = bytes(pkt[UDP].payload)
            if len(udp_payload) < 8:
                continue

            gvsp_fmt = udp_payload[4]
            pkt_id   = udp_payload[5]
            block_id = struct.unpack_from('>H', udp_payload, 2)[0]

            if gvsp_fmt == 0x01 and pkt_id == 0:
                pixel_fmt = struct.unpack_from('>I', udp_payload, 20)[0]
                width  = struct.unpack_from('>H', udp_payload, 26)[0]
                height = struct.unpack_from('>H', udp_payload, 30)[0]
                meta[block_id] = {"fmt": pixel_fmt, "w": width, "h": height}
                log(f"📝 block {block_id}: {width}×{height}, pixelFormat=0x{pixel_fmt:08X}")
                continue

            if gvsp_fmt == 0x03:
                payload = udp_payload[8:]
                st = state[block_id]
                if st["payload_len"] is None:
                    st["payload_len"] = len(payload)
                if st["last"] is not None and pkt_id - st["last"] > 1:
                    gap = pkt_id - st["last"] - 1
                    buffers[block_id].extend(b"\x00" * gap * st["payload_len"])
                st["last"] = pkt_id
                buffers[block_id].extend(payload)

        if not meta:
            log("❌ 리더 패킷을 찾지 못했습니다.")
            return

        # ---- 새 폴더 생성 ----
        time_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(os.path.basename(prefix))[0]
        out_dir = f"{base_name}_blocks_{time_tag}"
        os.makedirs(out_dir, exist_ok=True)
        log(f"📂 출력 폴더: {out_dir}")

        # ---- block 별 저장 ----
        for blk_id, raw in buffers.items():
            if blk_id not in meta:
                log(f"⚠️ block {blk_id}: 메타 정보 없음 → 스킵")
                continue

            info = meta[blk_id]
            w, h, fmt = info["w"], info["h"], info["fmt"]
            unpacker = PIXEL_UNPACKERS.get(fmt)
            if not unpacker:
                log(f"❓ block {blk_id}: 알 수 없는 포맷 0x{fmt:08X}")
                continue

            unpacked = unpacker(bytes(raw))
            exp_px = w * h
            if unpacked.size < exp_px:
                unpacked = np.pad(unpacked, (0, exp_px - unpacked.size), 'constant')
            img = unpacked[:exp_px].reshape((h, w))
            out_path = os.path.join(out_dir, f"{base_name}_block{blk_id}.tiff")
            cv2.imwrite(out_path, img)
            log(f"💾 block {blk_id} 저장 완료 → {out_path}")

        log("✅ 작업 완료!")
    except Exception as e:
        log_cb(f"❌ 오류: {e}")

# ---------- UI ----------
def select_pcap():
    path = filedialog.askopenfilename(filetypes=[("PCAPNG files", "*.pcapng")])
    if path:
        pcap_var.set(path)
        prefix_var.set(os.path.splitext(os.path.basename(path))[0])

def run():
    pcap = pcap_var.get()
    prefix = prefix_var.get().strip()
    if not pcap or not prefix:
        messagebox.showwarning("입력 오류", "PCAP 파일과 prefix를 입력하세요.")
        return
    log.delete(1.0, tk.END)
    process_file(pcap, prefix, lambda msg: log.insert(tk.END, msg + "\n"))

root = tk.Tk()
root.title("GVSP Extractor – Block Save to Folder")
root.geometry("600x360")

pcap_var = tk.StringVar()
prefix_var = tk.StringVar()

tk.Label(root, text="PCAPNG 파일").pack()
tk.Entry(root, textvariable=pcap_var, width=70).pack()
tk.Button(root, text="파일 선택", command=select_pcap).pack(pady=4)

tk.Label(root, text="폴더/파일 prefix (영문/숫자)").pack()
tk.Entry(root, textvariable=prefix_var, width=70).pack()

tk.Button(root, text="실행", command=run, bg="green", fg="white").pack(pady=8)

log = tk.Text(root, height=12, width=80)
log.pack()

root.mainloop()
