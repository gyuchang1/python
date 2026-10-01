import subprocess
import struct
import threading
import time
from collections import defaultdict, deque

GVCP_CMD_RESEND = 0x42
GVSP_DATA_PORT = 3956
RESP_TIMEOUT_SEC = 0.5  # 재응답을 기다릴 시간

pending_resends = deque()
received_packet_ids = set()
stop_flag = False

def parse_gvcp(payload):
    if len(payload) < 16:
        return None
    cmd = struct.unpack(">H", payload[4:6])[0]
    if cmd == GVCP_CMD_RESEND:
        offset = struct.unpack(">I", payload[8:12])[0]
        length = struct.unpack(">I", payload[12:16])[0]
        start_pkt = offset // 1440
        end_pkt = (offset + length) // 1440
        return (start_pkt, end_pkt)
    return None

def parse_gvsp(payload):
    if len(payload) < 4:
        return None
    packet_id = struct.unpack(">H", payload[2:4])[0]
    return packet_id

def monitor_resends():
    global stop_flag
    while not stop_flag:
        now = time.time()
        while pending_resends and now - pending_resends[0][2] > RESP_TIMEOUT_SEC:
            start, end, _ = pending_resends.popleft()
            for pkt_id in range(start, end + 1):
                if pkt_id not in received_packet_ids:
                    print(f"[실시간 이슈] Resend 요청된 Packet {pkt_id}가 재전송되지 않음")
                    print("[조치] Wireshark 캡처 중단 요청")
                    stop_flag = True
                    return
        time.sleep(0.1)

def run_live_monitor(interface="Ethernet"):
    global stop_flag
    cmd = [
        "tshark",
        "-i", interface,
        "-l",
        "-T", "fields",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "data",
        "-Y", "udp.port == 3956 || udp.port == 48654"
    ]
    
    print(f"[INFO] 실행 명령어: {' '.join(cmd)}")

    try:
        tshark_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,  # 표준 에러도 잡기 위해
            text=True
        )
        print("[INFO] TShark 시작됨. 패킷 수신 대기 중...\n")
    except Exception as e:
        print(f"[ERROR] TShark 실행 실패: {e}")
        return

    # 스레드로 resend timeout 감시 시작
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
                sport = int(parts[0]) if parts[0] else 0
                dport = int(parts[1]) if parts[1] else 0
                payload_hex = parts[2]
                payload = bytes.fromhex(payload_hex)

                if dport != GVSP_DATA_PORT:
                    resend_info = parse_gvcp(payload)
                    if resend_info:
                        start, end = resend_info
                        pending_resends.append((start, end, time.time()))
                        print(f"[감지] Resend 요청 Packet {start}~{end}")
                elif dport == GVSP_DATA_PORT:
                    pkt_id = parse_gvsp(payload)
                    if pkt_id is not None:
                        received_packet_ids.add(pkt_id)
            except Exception as e:
                continue

        if stop_flag:
            tshark_proc.terminate()
            print("[INFO] TShark 정상 종료됨")

    except KeyboardInterrupt:
        tshark_proc.terminate()
        print("[수동 종료] TShark 종료됨")

    # tshark stderr 확인
    stderr_output = tshark_proc.stderr.read()
    if stderr_output:
        print("[TShark 오류 출력]:")
        print(stderr_output)

if __name__ == "__main__":
    run_live_monitor("이더넷 14")  # 이더넷 이름을 맞춰주세요 (tshark -D 로 확인)
