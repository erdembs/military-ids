# Military IDS (Intrusion Detection System)

This project is a **Python-based host IDS** that detects common reconnaissance
and attack patterns using live network traffic.

## 🚨 Detected Attacks

- Port Scanning (TCP based)
- SSH Brute-force Attempts

## 🧠 Detection Logic

- Uses time-window based behavioral analysis
- No payload inspection (works with encrypted traffic)
- Detects abnormal connection patterns

## 📁 Project Structure

military-ids/
├── src/
│   └── packet_sniffer.py   # Core IDS logic (packet capture & detection)
├── tests/                  # Test cases (to be extended)
├── docs/                   # Architecture & documentation
├── README.md               # Project overview
├── requirements.txt        # Python dependencies
├── .gitignore              # Git ignore rules

