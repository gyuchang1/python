# -*- coding: utf-8 -*-
"""
live_gige_monitor_debug_v3_fixed.py
- GVCP 재전송(Resend) 감지
- GVSP Leader/Payload/Trailer 카운팅
- 누락 패킷 탐지 시 CSV 저장
- Windows 콘솔 인코딩(cp949) 문제 회피
- 실제 장치 포트 구성(스크린샷 기준) 반영:
    GVSP  : 50707 (camera) -> 49152 (host)
    GVCP  : 51904 (host)   -> 3957  (camera)
"""

import subprocess
import struct
import threading
import time
import csv
from collections import deque

# ====== 포트 구성 (올려주신 스크린샷 기준) ======
GVSP_DATA_PORT      = 49152    # 카메라 → 호스트 (스트림 송신 포트, camera side)
GVSP_HOST_PORT      = 50707  # 호스트가 GVSP를 수신하는 포트 (host side)
GVCP_CAMERA_PORT    = 3956    # 카메라가 GVCP를 수신하는 포트 (camera control port)
GVCP_HOST_PORT      = 3957   # 호스트가 GVCP를 수신하는 포트 (host control port)

GVCP_CMD_RESEND     = 0x40
RESP_TIMEOUT_SEC    = 0.5

pending_resends = deque()
received_packet_ids = set()
packet_id_to_block_id = dict()
gvsp_counts = {
    "Leader": 0,
    "Payload": 0,
    "Trailer": 0,
    "Unknown": 0
}
stop_flag = False
lost_packets = []


def parse_gvcp(payload: bytes):
    """GVCP 페이로드에서 Resend 요청 범위를 추출"""
    if len(payload) < 16:
        return None
    #cmd = struct.unpack(">H", payload[1:3])[0]
    cmd = (payload[2] << 8) | payload[3]
    if cmd == GVCP_CMD_RESEND:
        start_pkt = (payload[13] << 16) | (payload[14] << 8) | payload[15]
        end_pkt = (payload[17] << 16) | (payload[18] << 8) | payload[19]
        resend_block_id = (payload[10] << 8) | payload[11]
        return (start_pkt, end_pkt, resend_block_id)
    return None


def parse_gvsp(payload: bytes):
    """GVSP 페이로드에서 (packet_id, 타입, block_id) 추출"""
    if len(payload) < 8:
        return None, None, None
    packet_type = payload[4]
    packet_id = (payload[5] << 16) | (payload[6] << 8) | payload[7]
    block_id = (payload[2] << 8) | payload[3]
    if packet_type == 0x01:
        pkt_type = "Leader"
    elif packet_type == 0x02:
        pkt_type = "Trailer"
    elif packet_type == 0x03:
        pkt_type = "Payload"
    else:
        pkt_type = "Unknown"

    return packet_id, pkt_type, block_id


def monitor_resends():
    """Resend 요청 후 타임아웃 내 미수신 패킷을 누락으로 판정"""
    global stop_flag
    while not stop_flag:
        now = time.time()
        while pending_resends and now - pending_resends[0][3] > RESP_TIMEOUT_SEC:
            start, end,resend_block_id, _ = pending_resends.popleft()
            for pkt_id in range(start, end + 1):
                if pkt_id not in received_packet_ids:
                    #block_id = packet_id_to_block_id.get(pkt_id, -1)
                    block_id = resend_block_id
                    #print(f"[실시간 이슈] 누락된 Packet {pkt_id} (Block ID: {block_id})")
                    lost_packets.append((pkt_id, block_id))
                    stop_flag = False
        time.sleep(0.1)


def save_lost_packets_to_csv(filename="lost_packets.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Packet ID", "Block ID"])
        for pkt_id, blk_id in lost_packets:
            writer.writerow([pkt_id, blk_id])
    print(f"[저장됨] 누락된 패킷 정보 → {filename}")


def run_live_monitor(interface="13"):
    """
    interface:
      - Windows에선 '13' 처럼 숫자 인터페이스 권장 (tshark -D 로 목록 확인)
      - 예: run_live_monitor("13")
    """
    global stop_flag

    # tshark 필터:
    #  - GVSP 데이터 포트 (camera/host 어느 쪽이든 해당 포트 포함 패킷 캡처)
    #  - GVCP 제어 포트 (카메라/호스트 쌍 모두 포함)
    display_filter = (
        f"udp.port == {GVSP_DATA_PORT} || "
        f"udp.port == {GVSP_HOST_PORT} || "
        f"udp.port == {GVCP_CAMERA_PORT} || "
        f"udp.port == {GVCP_HOST_PORT}"
    )

    cmd = [
        "tshark",
        "-i", interface,
        "-l",            # 라인 단위로 flush (실시간 출력)
        "-n",            # 이름 해석 비활성화 (성능/안정성)
        "-s", "62",      # 버퍼 64MB (드롭 완화)
        "-T", "fields",
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
            encoding="utf-8",  # UTF-8 고정
            errors="ignore"    # 깨지는 문자는 무시 (Windows cp949 문제 회피)
        )
        print("[INFO] TShark 시작됨. 패킷 수신 대기 중...\n")
    except Exception as e:
        print(f"[ERROR] TShark 실행 실패: {e}")
        return

    threading.Thread(target=monitor_resends, daemon=True).start()

    try:
        while not stop_flag:
            line = tshark_proc.stdout.readline()
            if not line:
                break

            parts = line.strip().split('\t')
            if len(parts) < 3:
                continue
            try:
                # src/dst 포트와 페이로드 추출
                sport = int(parts[0]) if parts[0] else 0
                dport = int(parts[1]) if parts[1] else 0
                payload_hex = parts[2]
                payload = bytes.fromhex(payload_hex)

                # === GVCP (카메라/호스트 제어 포트) ===
                if dport in (GVCP_CAMERA_PORT, GVCP_HOST_PORT) or sport in (GVCP_CAMERA_PORT, GVCP_HOST_PORT):
                    resend_info = parse_gvcp(payload)
                    if resend_info:
                        start, end, resend_block_id = resend_info
                        pending_resends.append((start, end,resend_block_id, time.time()))
                        #print(f"[감지] Resend 요청 Packet {start}~{end}")

                # === GVSP (데이터 스트림 포트) ===
                if dport in (GVSP_DATA_PORT, GVSP_HOST_PORT) or sport in (GVSP_DATA_PORT, GVSP_HOST_PORT):
                    pkt_id, pkt_type, block_id = parse_gvsp(payload)
                    if pkt_id is not None:
                        received_packet_ids.add(pkt_id)
                        #packet_id_to_block_id[pkt_id] = block_id
                        gvsp_counts[pkt_type] += 1
                        if pkt_type == 'Trailer':
                            
                            print(f"[GVSP] Packet ID: {pkt_id}, Type: {pkt_type}, Block ID: {block_id}")
                            print(f"    Leader: {gvsp_counts['Leader']}, "
                                  f"Payload: {gvsp_counts['Payload']}, "
                                  f"Trailer: {gvsp_counts['Trailer']}, "
                                  f"Unknown: {gvsp_counts['Unknown']}")

            except Exception:
                # 라인 파싱 실패 시 스킵
                continue

        # 종료 처리
        if stop_flag and tshark_proc.poll() is None:
            tshark_proc.terminate()
            print("[INFO] TShark 정상 종료됨")
            if lost_packets:
                save_lost_packets_to_csv()

    except KeyboardInterrupt:
        if lost_packets:
            save_lost_packets_to_csv()
        tshark_proc.terminate()
        print("[수동 종료] TShark 종료됨")
        
        

    # TShark 요약(표준에러)에 찍히는 캡처 결과 표시
    try:
        stderr_output = tshark_proc.stderr.read()
        if stderr_output:
            print("[TShark 요약]:")
            print(stderr_output)
    except Exception:
        pass


if __name__ == "__main__":
    # 인터페이스 번호는 'tshark -D'로 확인 후 입력
    # 예) run_live_monitor("13")
    run_live_monitor("이더넷 14")
