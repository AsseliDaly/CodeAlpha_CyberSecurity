
# 🔐 CodeAlpha_NetworkSniffer — Cyber Security Internship Project

## 🧑‍💻 Author
**Assali Mohamed Ali**

## 🏢 Internship Program
**Cyber Security Internship - CodeAlpha M3.1**  
Website: [www.codealpha.tech](https://www.codealpha.tech)

---

## 📌 Project Overview

This repository contains my completed submission for the **"Basic Network Sniffer"** task as part of the Cyber Security Internship at CodeAlpha. The project focuses on real-time packet sniffing, protocol analysis, ARP spoofing, and basic MITM (Man-in-the-Middle) interception on a local network.

---

## ✅ Task Objective

As per the [internship instructions]:

> **TASK 1: Basic Network Sniffer**
>
> - Build a Python program to capture network traffic packets.
> - Analyze captured packets to understand their structure and content.
> - Learn how data flows through the network and the basics of protocols.
> - Use libraries like `scapy` or `socket` for packet capturing.
> - Display useful information such as source/destination IPs, protocols and payloads.

This project fulfills the required Task 1 in its entirety and includes **extra features** for deeper learning and network monitoring.

---

## 🛠 Features

✅ Real-time packet sniffing with protocol filtering  
✅ Logs DNS queries, HTTP requests, and TLS SNI  
✅ Detects devices on local network with hostnames  
✅ ARP spoofing to perform MITM traffic redirection  
✅ Auto detection of default gateway (Windows)  
✅ Cross-layer packet dissection using `scapy`  
✅ Logs stored in `logs.txt` with timestamps

---

## 📁 File Structure

```
.
├──| Task-1          
   └── task1.py.py                # Basic packet sniffer and analyzer (minimal version)
├── additional task.py             # Main ARP spoofing + sniffer script (Task 1 Extended)
├── logs.txt                      # Real-time logs of HTTP, DNS, TLS packets
└── README.md                     # Project description and documentation
```

---

## ▶️ How to Run

### Requirements

- Python 3.x
- Administrator privileges (Windows)
- Required libraries:
```bash
pip install scapy
```

### For Basic Packet Analyzer

```bash
python Task-1\task1.py
```

### For Full MITM Sniffer with ARP Spoofing (Windows only)

```bash
python "additional task.py"
```

Then select a target from the scanned devices. The script will:
- Start sniffing packets.
- Spoof ARP to redirect traffic through your machine.
- Log traffic in real-time to `logs.txt`.

> **Warning:** This script is for educational purposes only. Do not use it on unauthorized networks.

---

## 📜 Logs Format (Sample)

```log
[2025-08-02 12:34:56] [DNS] 192.168.1.5 queried www.google.com
[2025-08-02 12:35:01] [HTTP] 192.168.1.5 -> 142.250.190.68 Host: www.google.com | Req: GET /search?q=...
[2025-08-02 12:35:10] [TLS SNI] 192.168.1.5 -> 172.217.0.0 SNI: mail.google.com
```

---

## 💡 Learning Outcomes

- Gained hands-on experience in packet sniffing and traffic analysis.
- Understood protocol headers and packet dissection using Scapy.
- Implemented ARP spoofing and monitored real user traffic (DNS, HTTP, TLS).
- Learned about ethical hacking practices and MITM detection techniques.

---

## 📤 Submission Checklist

✅ Project hosted on GitHub in correct format  
✅ Task 1 (Basic Network Sniffer) completed  
✅ README and task documentation included  
✅ Code explained and functional  
✅ Logs and test results included

---

## 📞 Contact / Support

- Email: bentaherdaly123@gmail.com
- Internship Support: services@codealpha.tech  
- Project supervised under: CodeAlpha Cyber Security Team

---

## ⚠️ Disclaimer

This project is developed solely for academic and ethical cybersecurity training. Do **NOT** use this on any public or private network without explicit authorization.
