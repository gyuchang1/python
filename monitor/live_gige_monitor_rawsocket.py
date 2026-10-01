# -*- coding: utf-8 -*-
"""
live_gige_monitor_rawsocket.py
- tshark 없이 raw socket으로 GigE Vision (GVCP, GVSP) 직접 캡처
- GVCP Resend 명령(0x0040) 감지
- GVSP Leader / Payload / Trailer 카운팅
- 누락 패킷 CSV 저장
- 초당 수십만 패킷 실시간 처리 가능
"""

import socket
import struct
import time
import threading
import csv
from collections import deque

# ====== 포트 구성 ======
GVSP_DATA_PORT   = 49152
GVSP_HOST_PORT   = 50707
GVCP_CAMERA_PORT = 3956
GVCP_HOST_PORT   = 3957

GVCP_CMD_RESEND  = 0x40
RESP_TIMEOUT_SEC = 0.5

pending_resends = deque()
received_packet_ids = set()
gvsp_counts = {"Leader": 0, "Payload": 0, "Trailer": 0, "Unknown": 0}
lost_packets = []
stop_flag = False


def parse_gvcp(payload: bytes):
    """GVCP Resend 명령 파싱"""
    if len(payload) < 20:
        return None
    cmd = (payload[2] << 8) | payload[3]
    if cmd == GVCP_CMD_RESEND:
        start_pkt = (payload[13] << 16) | (payload[14] << 8) | payload[15]
        end_pkt   = (payload[17] << 16) | (payload[18] << 8) | payload[19]
        resend_block_id = (payload[10] << 8) | payload[11]
        return start_pkt, end_pkt, resend_block_id
    return None


def parse_gvsp(payload: bytes):
    """GVSP 헤더에서 (packet_id, type, block_id) 추출"""
    if len(payload) < 8:
        return None, None, None
    block_id = (payload[2] << 8) | payload[3]
    packet_type = payload[4]
    packet_id = (payload[5] << 16) | (payload[6] << 8) | payload[7]
    type_map = {0x01: "Leader", 0x02: "Trailer", 0x03: "Payload"}
    return packet_id, type_map.get(packet_type, "Unknown"), block_id


def monitor_resends():
    """Resend 요청 후 timeout 내 미수신 패킷을 누락으로 판정"""
    global stop_flag
    while not stop_flag:
        now = time.time()
        while pending_resends and now - pending_resends[0][3] > RESP_TIMEOUT_SEC:
            start, end, resend_block_id, _ = pending_resends.popleft()
            for pkt_id in range(start, end + 1):
                if pkt_id not in received_packet_ids:
                    lost_packets.append((pkt_id, resend_block_id))
        time.sleep(0.05)


def save_lost_packets_to_csv(filename="lost_packets.csv"):
    if not lost_packets:
        return
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Packet ID", "Block ID"])
        for pkt_id, blk_id in lost_packets:
            writer.writerow([pkt_id, blk_id])
    print(f"[저장됨] 누락된 패킷 → {filename}")


def run_raw_monitor(interface_ip="192.168.0.1"):
    """
    interface_ip: 현재 PC의 GigE 인터페이스 IP (예: 192.168.0.1)
    """
    global stop_flag

    # === Raw socket 생성 ===
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.bind((interface_ip, 0))  # 해당 인터페이스에서만 수신
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)  # 4MB 버퍼
    sock.settimeout(0.1)

    print(f"[INFO] Raw socket 캡처 시작 ({interface_ip})")
    threading.Thread(target=monitor_resends, daemon=True).start()

    try:
        while not stop_flag:
            try:
                packet, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                stop_flag = True
                break

            # --- UDP 헤더 추출 ---
            ip_header = packet[0:20]
            udp_header = packet[20:28]
            udp_payload = packet[28:]

            src_port, dst_port, length, checksum = struct.unpack("!HHHH", udp_header)

            # === GVCP ===
            if dst_port in (GVCP_CAMERA_PORT, GVCP_HOST_PORT) or src_port in (GVCP_CAMERA_PORT, GVCP_HOST_PORT):
                resend_info = parse_gvcp(udp_payload)
                if resend_info:
                    start, end, resend_block_id = resend_info
                    pending_resends.append((start, end, resend_block_id, time.time()))
                    print(f"[GVCP] Resend 요청 감지: {start}~{end} (Block {resend_block_id})")

            # === GVSP ===
            elif dst_port in (GVSP_DATA_PORT, GVSP_HOST_PORT) or src_port in (GVSP_DATA_PORT, GVSP_HOST_PORT):
                pkt_id, pkt_type, block_id = parse_gvsp(udp_payload)
                if pkt_id is not None:
                    received_packet_ids.add(pkt_id)
                    gvsp_counts[pkt_type] += 1
                    if pkt_type == "Trailer":
                        print(f"[GVSP] Block {block_id}: Trailer 감지")
                        print(f"    Leader: {gvsp_counts['Leader']}, "
                              f"Payload: {gvsp_counts['Payload']}, "
                              f"Trailer: {gvsp_counts['Trailer']}, "
                              f"Unknown: {gvsp_counts['Unknown']}")

    except KeyboardInterrupt:
        print("\n[수동 종료] Ctrl+C 입력됨, 종료 중...")
        stop_flag = True
    finally:
        sock.close()
        if lost_packets:
            save_lost_packets_to_csv()
        print("[완료] 종료되었습니다.")


if __name__ == "__main__":
    # 자신의 GigE 인터페이스 IP 지정 (예: "192.168.0.1")
    run_raw_monitor("192.168.0.1")
