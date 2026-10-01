# -*- coding: utf-8 -*-
"""
live_gige_monitor_debug_v3_fast_resend.py
- GVCP Resend 감지 (payload 62 bytes까지만 캡처)
- GVSP Leader/Payload/Trailer 카운팅
- 누락 패킷 CSV 저장
- tshark 실시간 stdout 처리 최적화
"""

import subprocess
import struct
import threading
import time
import csv
import signal
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


# === GVCP Resend 명령 파싱 ===
def parse_gvcp(payload: bytes):
    """GVCP 페이로드에서 Resend 요청 범위를 추출"""
    if len(payload) < 20:
        return None
    cmd = (payload[2] << 8) | payload[3]
    if cmd == GVCP_CMD_RESEND:
        start_pkt = (payload[13] << 16) | (payload[14] << 8) | payload[15]
        end_pkt   = (payload[17] << 16) | (payload[18] << 8) | payload[19]
        resend_block_id = (payload[10] << 8) | payload[11]
        return start_pkt, end_pkt, resend_block_id
    return None


# === GVSP 헤더 파싱 ===
def parse_gvsp(payload: bytes):
    """GVSP 페이로드에서 (packet_id, 타입, block_id) 추출"""
    if len(payload) < 8:
        return None, None, None
    packet_type = payload[4]
    packet_id = (payload[5] << 16) | (payload[6] << 8) | payload[7]
    block_id = (payload[2] << 8) | payload[3]
    type_map = {0x01: "Leader", 0x02: "Trailer", 0x03: "Payload"}
    return packet_id, type_map.get(packet_type, "Unknown"), block_id


# === resend 모니터 ===
def monitor_resends():
    global stop_flag
    while not stop_flag:
        now = time.time()
        while pending_resends and now - pending_resends[0][3] > RESP_TIMEOUT_SEC:
            start, end, resend_block_id, _ = pending_resends.popleft()
            for pkt_id in range(start, end + 1):
                if pkt_id not in received_packet_ids:
                    lost_packets.append((pkt_id, resend_block_id))
        time.sleep(0.05)


# === 누락 CSV 저장 ===
def save_lost_packets_to_csv(filename="lost_packets.csv"):
    if not lost_packets:
        return
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Packet ID", "Block ID"])
        for pkt_id, blk_id in lost_packets:
            writer.writerow([pkt_id, blk_id])
    print(f"[저장됨] 누락된 패킷 정보 → {filename}")


def run_live_monitor(interface="이더넷 14"):
    global stop_flag

    # Display filter: GVSP + GVCP 모두
    display_filter = (
        f"(udp.port == {GVSP_DATA_PORT} || udp.port == {GVSP_HOST_PORT} || "
        f"udp.port == {GVCP_CAMERA_PORT} || udp.port == {GVCP_HOST_PORT})"
    )

    cmd = [
        "tshark",
        "-i", interface,
        "-l",
        "-n",
        "-s", "62",              # Resend 포함, payload 최소 캡처
        "-T", "fields",
        "-E", "separator=,",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "udp.payload",
        "-Y", display_filter
    ]

    print(f"[INFO] 실행 명령어: {' '.join(cmd)}")

    try:
        tshark_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
        print("[INFO] TShark 시작됨. 실시간 수신 중...\n")
    except Exception as e:
        print(f"[ERROR] TShark 실행 실패: {e}")
        return

    threading.Thread(target=monitor_resends, daemon=True).start()

    try:
        for line in tshark_proc.stdout:
            if stop_flag:
                break

            line = line.strip()
            if not line:
                continue

            parts = line.split(",", 2)
            if len(parts) < 3:
                continue

            sport, dport, payload_hex = parts
            if not payload_hex:
                continue

            # === payload 디코딩 ===
            try:
                payload = bytes.fromhex(payload_hex)
            except ValueError:
                continue

            # === GVCP Resend 감지 ===
            if (dport in (str(GVCP_CAMERA_PORT), str(GVCP_HOST_PORT)) or
                sport in (str(GVCP_CAMERA_PORT), str(GVCP_HOST_PORT))):
                resend_info = parse_gvcp(payload)
                if resend_info:
                    start, end, resend_block_id = resend_info
                    pending_resends.append((start, end, resend_block_id, time.time()))
                    print(f"[GVCP] Resend 요청 감지: {start}~{end} (Block {resend_block_id})")

            # === GVSP 카운트 ===
            elif (dport in (str(GVSP_DATA_PORT), str(GVSP_HOST_PORT)) or
                  sport in (str(GVSP_DATA_PORT), str(GVSP_HOST_PORT))):
                pkt_id, pkt_type, block_id = parse_gvsp(payload)
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
        try:
            tshark_proc.send_signal(signal.SIGINT)
            tshark_proc.terminate()
            tshark_proc.wait(timeout=2)
        except Exception:
            tshark_proc.kill()

        if lost_packets:
            save_lost_packets_to_csv()
        print("[완료] 종료되었습니다.")


if __name__ == "__main__":
    # 'tshark -D'로 인터페이스 번호 또는 이름 확인
    run_live_monitor("이더넷 14")
