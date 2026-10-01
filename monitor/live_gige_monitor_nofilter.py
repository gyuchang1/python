
import subprocess
import struct
import threading
import time
import csv
from collections import deque, defaultdict

GVCP_CMD_RESEND = 0x42
GVSP_DATA_PORT = 3956
RESP_TIMEOUT_SEC = 0.5

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
    if len(payload) < 8:
        return None, None, None
    packet_type = payload[0]
    packet_id = struct.unpack(">H", payload[2:4])[0]
    block_id = struct.unpack(">I", payload[4:8])[0]

    if packet_type == 0x00:
        pkt_type = "Leader"
    elif packet_type == 0x01:
        pkt_type = "Payload"
    elif packet_type == 0x02:
        pkt_type = "Trailer"
    else:
        pkt_type = "Unknown"

    return packet_id, pkt_type, block_id

def monitor_resends():
    global stop_flag
    while not stop_flag:
        now = time.time()
        while pending_resends and now - pending_resends[0][2] > RESP_TIMEOUT_SEC:
            start, end, _ = pending_resends.popleft()
            for pkt_id in range(start, end + 1):
                if pkt_id not in received_packet_ids:
                    block_id = packet_id_to_block_id.get(pkt_id, -1)
                    print(f"[실시간 이슈] 누락된 Packet {pkt_id} (Block ID: {block_id})")
                    lost_packets.append((pkt_id, block_id))
                    stop_flag = True
        time.sleep(0.1)

def save_lost_packets_to_csv(filename="lost_packets.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Packet ID", "Block ID"])
        for pkt_id, blk_id in lost_packets:
            writer.writerow([pkt_id, blk_id])
    print(f"[저장됨] 누락된 패킷 정보 → {filename}")

def run_live_monitor(interface="Ethernet"):
    global stop_flag
    cmd = [
        "tshark",
        "-i", interface,
        "-l",
        "-T", "fields",
        "-e", "data"
    ]

    print(f"[INFO] 실행 명령어: {' '.join(cmd)}")

    try:
        tshark_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
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
                    pkt_id, pkt_type, block_id = parse_gvsp(payload)
                    if pkt_id is not None:
                        received_packet_ids.add(pkt_id)
                        packet_id_to_block_id[pkt_id] = block_id
                        gvsp_counts[pkt_type] += 1

                        print(f"[GVSP] Packet ID: {pkt_id}, Type: {pkt_type}, Block ID: {block_id}")
                        print(f"    Leader: {gvsp_counts['Leader']}, "
                              f"Payload: {gvsp_counts['Payload']}, "
                              f"Trailer: {gvsp_counts['Trailer']}, "
                              f"Unknown: {gvsp_counts['Unknown']}")

            except Exception:
                continue

        if stop_flag:
            tshark_proc.terminate()
            print("[INFO] TShark 정상 종료됨")
            save_lost_packets_to_csv()

    except KeyboardInterrupt:
        tshark_proc.terminate()
        print("[수동 종료] TShark 종료됨")

    stderr_output = tshark_proc.stderr.read()
    if stderr_output:
        print("[TShark 오류 출력]:")
        print(stderr_output)

if __name__ == "__main__":
    run_live_monitor("이더넷 13")
