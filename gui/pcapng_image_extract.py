from scapy.all import rdpcap
from scapy.layers.inet import UDP
import struct
import numpy as np
import cv2

# 1. PCAP 열기
packets = rdpcap("5.pcapng")

# 2. Leader 패킷에서 width/height 추출 (offset 26, 30 / big endian)
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

if width is None or height is None:
    print("⚠️ 해상도 추출 실패")
    exit()

print(f"✅ 해상도: {width} x {height}")

# 3. Payload 수집 (GVSP PAYLOAD = 0x03)
raw_data = bytearray()
for pkt in packets:
    if UDP in pkt:
        udp_payload = bytes(pkt[UDP].payload)
        if len(udp_payload) > 8:
            gvsp_format = udp_payload[4]
            if gvsp_format == 0x03:
                raw_data.extend(udp_payload[8:])
print(f"✅ 수집된 packed 바이트 수: {len(raw_data)}")

# 4. Unpack Mono12 Packed (3 bytes → 2 pixels)
def unpack_mono12_packed(data: bytes) -> np.ndarray:
    # 3 bytes → 2 pixels (12 bits per pixel)
    if len(data) % 3 != 0:
        data = data[:-(len(data) % 3)]  # 3바이트 정렬

    arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)

    pixel0 = (arr[:, 0].astype(np.uint16) << 8) | ((arr[:, 1] & 0x0F).astype(np.uint16) << 4)
    pixel1 = (arr[:, 1] & 0xF0).astype(np.uint16) | (arr[:, 2].astype(np.uint16)<<8)

    # 순서대로 이어붙이기
    unpacked = np.empty(arr.shape[0] * 2, dtype=np.uint16)
    unpacked[0::2] = pixel0
    unpacked[1::2] = pixel1

    return unpacked
def unpack_mono10_packed(data: bytes) -> np.ndarray:
    # 3 bytes → 2 pixels (12 bits per pixel)
    if len(data) % 3 != 0:
        data = data[:-(len(data) % 3)]  # 3바이트 정렬

    arr = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)

    pixel0 = (arr[:, 0].astype(np.uint16) << 8) | ((arr[:, 1] & 0b00000011).astype(np.uint16) << 6)
    pixel1 = ((arr[:, 1] & 0b00110000).astype(np.uint16)<<2) | (arr[:, 2].astype(np.uint16)<<8)

    # 순서대로 이어붙이기
    unpacked = np.empty(arr.shape[0] * 2, dtype=np.uint16)
    unpacked[0::2] = pixel0
    unpacked[1::2] = pixel1

    return unpacked
unpacked_data = unpack_mono10_packed(bytes(raw_data))
print(f"✅ 언팩된 픽셀 수: {unpacked_data.size}")

# 5. Shape 확인 후 reshape
expected_pixels = width * height
if unpacked_data.size < expected_pixels:
    print(f"⚠️ 픽셀 수 부족: {unpacked_data.size} < {expected_pixels}")
    unpacked_data = np.pad(unpacked_data, (0, expected_pixels - unpacked_data.size), 'constant')

img_array = unpacked_data[:expected_pixels].reshape((height, width))

# 6. OpenCV로 저장 (16bit grayscale)
cv2.imwrite("unpacked_mono12.tiff", img_array)
print("✅ 저장 완료: unpacked_mono12.tiff")
