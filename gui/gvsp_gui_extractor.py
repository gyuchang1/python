import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import rdpcap
from scapy.layers.inet import UDP
import struct
import numpy as np
import cv2
import os

def unpack_mono12_packed(data: bytes) -> np.ndarray:
    if len(data) % 3 != 0:
        data = data[:-(len(data) % 3)]
    arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)

    # 리틀엔디안 방식
    pixel0 = (arr[:, 0].astype(np.uint16) << 4) | ((arr[:, 1] & 0x0F).astype(np.uint16))
    pixel1 = (arr[:, 1] & 0xF0).astype(np.uint16)>>4 | (arr[:, 2].astype(np.uint16)<<4)

    unpacked = np.empty(arr.shape[0] * 2, dtype=np.uint16)
    unpacked[0::2] = pixel0
    unpacked[1::2] = pixel1
    return unpacked
def unpack_mono10_packed(data: bytes) -> np.ndarray:
    # 3 bytes → 2 pixels (12 bits per pixel)
    if len(data) % 3 != 0:
        data = data[:-(len(data) % 3)]  # 3바이트 정렬

    arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)

    pixel0 = (arr[:, 0].astype(np.uint16) << 2) | ((arr[:, 1] & 0b00000011).astype(np.uint16))
    pixel1 = ((arr[:, 1] & 0b00110000).astype(np.uint16)>>4) | (arr[:, 2].astype(np.uint16)<< 2)

    # 순서대로 이어붙이기
    unpacked = np.empty(arr.shape[0] * 2, dtype=np.uint16)
    unpacked[0::2] = pixel0
    unpacked[1::2] = pixel1

    return unpacked

def unpack_mono10_unpacked(data: bytes) -> np.ndarray:
    # 2바이트씩 → 16bit 정렬된 값들
    raw = np.frombuffer(data, dtype=np.uint16)

    # 하위 10비트만 추출
    unpacked = raw & 0x03FF  # 0000001111111111

    return unpacked

def unpack_mono12_unpacked(data: bytes) -> np.ndarray:
    # 2바이트씩 → 16bit 정렬된 값들
    raw = np.frombuffer(data, dtype=np.uint16)

    # 하위 10비트만 추출
    unpacked = raw & 0x0FFF  # 0000111111111111

    return unpacked
def unpack_mono14_unpacked(data: bytes) -> np.ndarray:
    # 2바이트씩 → 16bit 정렬된 값들
    raw = np.frombuffer(data, dtype=np.uint16)

    # 하위 10비트만 추출
    unpacked = raw & 0x3FFF  # 0000111111111111

    return unpacked
def unpack_mono16_unpacked(data: bytes) -> np.ndarray:
    # 2바이트씩 → 16bit 정렬된 값들
    raw = np.frombuffer(data, dtype=np.uint16)

    # 하위 10비트만 추출
    unpacked = raw & 0xfFFF  # 0000111111111111

    return unpacked
def process_file(pcap_path, output_path, log_callback):
    try:
        log_callback("📦 pcap 파일 불러오는 중...")
        packets = rdpcap(pcap_path)

        width, height = None, None
        for pkt in packets:
            if UDP in pkt:
                udp_payload = bytes(pkt[UDP].payload)
                if len(udp_payload) >= 32:
                    gvsp_format = udp_payload[4]
                    packet_id = udp_payload[5]
                    if gvsp_format == 0x01 and packet_id == 0:
                        pixel_format = struct.unpack_from('>I', udp_payload, 20)[0]
                        width = struct.unpack_from('>H', udp_payload, 26)[0]
                        height = struct.unpack_from('>H', udp_payload, 30)[0]
                        break

        if not width or not height:
            log_callback("❌ 해상도 추출 실패")
            return

        log_callback(f"✅ 해상도: {width} x {height}")

        raw_data = bytearray()
        for pkt in packets:
            if UDP in pkt:
                udp_payload = bytes(pkt[UDP].payload)
                if len(udp_payload) > 8:
                    gvsp_format = udp_payload[4]
                    if gvsp_format == 0x03:
                        raw_data.extend(udp_payload[8:])

        log_callback(f"✅ 수집된 바이트 수: {len(raw_data)}")
        
        if pixel_format == 0x01080001:
            # Mono8
            unpacked = np.frombuffer(raw_data, dtype=np.uint8)
        elif pixel_format == 0x01100003:
             # Mono10
            unpacked = unpack_mono10_unpacked(bytes(raw_data))
        elif pixel_format == 0x010C0004:
            # Mono10Packed
            unpacked = unpack_mono10_packed(bytes(raw_data))
        elif pixel_format == 0x01100005:
            # Mono12
            unpacked = unpack_mono12_unpacked(bytes(raw_data))
        elif pixel_format == 0x010C0006:
            # Mono12Packed
            unpacked = unpack_mono12_packed(bytes(raw_data))
        elif pixel_format == 0x01100025:
            # Mono14
            unpacked = unpack_mono12_unpacked(bytes(raw_data))
        elif pixel_format == 0x01100007:
            # Mono16
            unpacked = unpack_mono12_unpacked(bytes(raw_data))
        elif pixel_format == 0x01080009:
            # BayerRG8
            pass
        else:
            print(f"❓ 알 수 없는 포맷: 0x{pixel_format:08X}")
        
        
        expected_pixels = width * height
        if unpacked.size < expected_pixels:
            log_callback("⚠️ 픽셀 수 부족. 패딩 추가")
            unpacked = np.pad(unpacked, (0, expected_pixels - unpacked.size), 'constant')

        image = unpacked[:expected_pixels].reshape((height, width))
        cv2.imwrite(output_path, image)
        log_callback(f"✅ 저장 완료: {output_path}")

    except Exception as e:
        log_callback(f"❌ 오류 발생: {str(e)}")

# ----------- UI -----------

def select_file():
    path = filedialog.askopenfilename(filetypes=[("PCAPNG files", "*.pcapng")])
    if path:
        file_path_var.set(path)
        output_name_var.set(os.path.splitext(os.path.basename(path))[0] + ".tiff")

def run_process():
    pcap = file_path_var.get()
    output = output_name_var.get()
    if not pcap or not output:
        messagebox.showwarning("입력 오류", "파일과 출력 이름을 모두 입력해주세요.")
        return
    log_text.delete(1.0, tk.END)
    process_file(pcap, output, lambda msg: log_text.insert(tk.END, msg + "\n"))

# Tkinter 창
root = tk.Tk()
root.title("GVSP 추출기")
root.geometry("520x300")

file_path_var = tk.StringVar()
output_name_var = tk.StringVar()

tk.Label(root, text="PCAPNG 파일 선택").pack()
tk.Entry(root, textvariable=file_path_var, width=60).pack()
tk.Button(root, text="파일 선택", command=select_file).pack(pady=5)

tk.Label(root, text="출력 파일 이름 (.tiff)").pack()
tk.Entry(root, textvariable=output_name_var, width=60).pack()

tk.Button(root, text="실행하기", command=run_process, bg="green", fg="white").pack(pady=10)

log_text = tk.Text(root, height=10, width=70)
log_text.pack()

root.mainloop()
