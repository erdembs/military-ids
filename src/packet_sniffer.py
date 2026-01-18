from scapy.all import sniff, IP, TCP
import time

TIME_WINDOW = 10
PORT_SCAN_THRESHOLD = 5
SSH_THRESHOLD = 6

scan_tracker = {}
ssh_tracker = {}

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        now = time.time()

        # PORT SCAN DETECTION
        if src_ip not in scan_tracker:
            scan_tracker[src_ip] = {
                "ports": set(),
                "start": now,
                "alerted": False
            }

        scan_tracker[src_ip]["ports"].add(dst_port)

        if now - scan_tracker[src_ip]["start"] <= TIME_WINDOW:
            if len(scan_tracker[src_ip]["ports"]) >= PORT_SCAN_THRESHOLD and not scan_tracker[src_ip]["alerted"]:
                print(f"[ALERT] Port scan detected from {src_ip}")
                print(f"        Ports: {scan_tracker[src_ip]['ports']}")
                scan_tracker[src_ip]["alerted"] = True
        else:
            scan_tracker[src_ip] = {
                "ports": {dst_port},
                "start": now,
                "alerted": False
            }

        # SSH BRUTE FORCE DETECTION
        if dst_port == 22 and flags == "S":
            if src_ip not in ssh_tracker:
                ssh_tracker[src_ip] = {
                    "count": 0,
                    "start": now,
                    "alerted": False
                }

            ssh_tracker[src_ip]["count"] += 1

            if now - ssh_tracker[src_ip]["start"] <= TIME_WINDOW:
                if ssh_tracker[src_ip]["count"] >= SSH_THRESHOLD and not ssh_tracker[src_ip]["alerted"]:
                    print(f"[ALERT] SSH brute-force detected from {src_ip}")
                    print(f"        Attempts: {ssh_tracker[src_ip]['count']}")
                    ssh_tracker[src_ip]["alerted"] = True
            else:
                ssh_tracker[src_ip] = {
                    "count": 1,
                    "start": now,
                    "alerted": False
                }

def start_ids():
    sniff(iface="eth0", prn=packet_callback, store=False)

if __name__ == "__main__":
    start_ids()

