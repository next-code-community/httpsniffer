---
# **HTTP Sniffer**
## **Description**  
HTTP Sniffer is a Python program that captures HTTP packets in real-time and displays useful information on the screen.  
It supports saving packets to a file for later analysis and allows reading previously saved packet dumps, with extensive filtering and output options.
---
## **Requirements**  
✅ **Language**: Python 3  
✅ **Required modules**:  
- `os`
- `pickle`
- `scapy`
- `datetime`
- `optparse`
- `colorama`
- `time`
- `re`
- `json`
- `csv`
- `sys`
- `socket` (for DNS resolution)

You can install the missing modules with:  
```bash
pip install scapy colorama
```
---
## **Usage**  
Run the program with the following parameters:  
```bash
python3 main.py -i <interface> [options]
```
### **Available Options**:
| Option | Description |
|--------|-------------|
| `-i, --iface` | Specifies the network interface on which to capture packets |
| `-v, --verbose` | Show detailed information about captured packets (`True`/`False`, Default: `True`) |
| `-w, --write` | Save the captured packets to a file for future analysis |
| `-r, --read` | Read packets from a dump file and display the information |
| `-f, --filter-ip` | Filter packets by source or destination IP address |
| `-p, --filter-port` | Filter packets by source or destination port number |
| `-l, --limit` | Limit the number of packets to capture |
| `-o, --output` | Set output format (`text`, `json`, `csv`) |
| `-s, --stats` | Show statistics every N seconds |
| `-d, --dns` | Resolve IP addresses to hostnames |
| `-n, --no-raw` | Hide raw packet data |
| `-g, --log` | Log output to a file |
| `-F, --format` | Save format (`pickle`, `json`) |
| `-c, --count` | Just count packets, don't store them |
| `-m, --mode` | Capture mode (`http`, `all`, `tcp`, `udp`) |
---
## **Output**  
The program displays:  
✅ **IP addresses** involved in the HTTP communication  
✅ **HTTP method** used (`GET`, `POST`, etc.)  
✅ **Requested URL** by the remote host  
✅ **Raw Data (RAW Data)** if present in the captured packet  
✅ **Statistics** about captured packets  

Example of output in **verbose** mode:
```
[+] [2025-01-31 14:30:45] 192.168.1.10 : GET => http://example.com/login
[*] [2025-01-31 14:30:45] RAW Data: b'username=admin&password=12345'
```

Example of statistics:
```
[:] [2025-01-31 14:35:12] Statistics:
[ ] [2025-01-31 14:35:12] - Total packets: 152
[ ] [2025-01-31 14:35:12] - HTTP packets: 48 (31.6%)
[ ] [2025-01-31 14:35:12] - TCP packets: 123 (80.9%)
[ ] [2025-01-31 14:35:12] - UDP packets: 29 (19.1%)
```
---
## **`requirements.txt` File**  
```plaintext
scapy
colorama
```
---
### **How to use the `requirements.txt` file**  
To install all dependencies, run the following command:  
```bash
pip install -r requirements.txt
```
If you're using a virtual environment (`venv`), activate it before installing:  
```bash
python -m venv venv
source venv/bin/activate  # On Linux/macOS
venv\Scripts\activate     # On Windows
pip install -r requirements.txt
```
---
## **Usage Examples**  
1️⃣ **Capture packets on a specific interface (e.g., eth0)**:  
```bash
sudo python3 main.py -i eth0
```

2️⃣ **Capture packets without detailed output (verbose disabled)**:  
```bash
sudo python3 main.py -i wlan0 -v False
```

3️⃣ **Save the captured packets to a file**:  
```bash
sudo python3 main.py -i eth0 -w packets.dump
```

4️⃣ **Read packets from a previously saved file**:  
```bash
python3 main.py -r packets.dump
```

5️⃣ **Filter packets from a specific IP address**:  
```bash
sudo python3 main.py -i eth0 -f 192.168.1.10
```

6️⃣ **Capture only HTTP traffic and save as JSON**:  
```bash
sudo python3 main.py -i eth0 -m http -F json -w http_packets.json
```

7️⃣ **Limit capture to 1000 packets with DNS resolution**:  
```bash
sudo python3 main.py -i eth0 -l 1000 -d
```

8️⃣ **Output in CSV format and log to a file**:  
```bash
sudo python3 main.py -i eth0 -o csv -g capture.log
```

9️⃣ **Filter packets on port 80 and hide raw data**:  
```bash
sudo python3 main.py -i eth0 -p 80 -n
```

🔟 **Just count packets, don't store them**:  
```bash
sudo python3 main.py -i eth0 -c
```
---
## **Notes**  
⚠️ **You must run the program with root privileges** to capture packets:  
```bash
sudo python3 main.py -i eth0
```
🔹 Make sure you have the necessary permissions to sniff the network. On some systems, it may be necessary to enable `CAP_NET_RAW`.

🔹 When using JSON save format, note that not all packet information can be serialized. Only basic HTTP information will be saved.

🔹 The log file will contain the output without ANSI color codes.

🔹 When using DNS resolution (-d), the sniffing process might be slower due to DNS lookups.
---
## **Author**  
✍ **Created by**: bobi.exe & NebulastudioTM  
📅 **Last update**: 31/01/2025  
---
