---

# **HTTP Sniffer**

## **Description**  
HTTP Sniffer is a Python program that captures HTTP packets in real-time and displays useful information on the screen.  
It supports saving packets to a file for later analysis and allows reading previously saved packet dumps.

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

You can install the missing modules with:  
```bash
pip install scapy colorama
```

---

## **Usage**  

Run the program with the following parameters:  
```bash
python3 main.py -i <interface> [-v True/False] [-w <file>] [-r <file>]
```

### **Available Options**:
| Option | Description |
|--------|-------------|
| `-i, --iface` | Specifies the network interface on which to capture packets |
| `-v, --verbose` | Show detailed information about captured packets (`True`/`False`, Default: `True`) |
| `-w, --write` | Save the captured packets to a file for future analysis |
| `-r, --read` | Read packets from a dump file and display the information |

---

## **Output**  
The program displays:  
✅ **IP addresses** involved in the HTTP communication  
✅ **HTTP method** used (`GET`, `POST`, etc.)  
✅ **Requested URL** by the remote host  
✅ **Raw Data (RAW Data)** if present in the captured packet  

Example of output in **verbose** mode:
```
[+] [2025-01-31 14:30:45] 192.168.1.10 : GET => http://example.com/login
[*] [2025-01-31 14:30:45] RAW Data: b'username=admin&password=12345'
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

---

## **Notes**  
⚠️ **You must run the program with root privileges** to capture packets:  
```bash
sudo python3 main.py -i eth0
```

🔹 Make sure you have the necessary permissions to sniff the network. On some systems, it may be necessary to enable `CAP_NET_RAW`.

---

## **Author**  
✍ **Created by**: bobi.exe & NebulastudioTM  
📅 **Last update**: 31/01/2025  

---
