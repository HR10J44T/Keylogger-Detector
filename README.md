# 🛡️ Keylogger Detector

A lightweight **Python-based security tool** that detects and blocks potential keylogger activity on a local system using **process scanning** and **signature-based detection**.

---

## 📌 Overview

Keyloggers are malicious programs that secretly record keystrokes to steal sensitive data (like passwords & credit card numbers).
This tool helps defend against such threats by:

* 🔍 Scanning running processes
* 🧠 Matching against **known malicious signatures** (`signatures.json`)
* 🚨 Alerting the user or terminating suspicious processes
* 📄 Logging results for auditing and security review

---

## 🎯 Features

* 🔍 **Real-time process scanning** using `psutil`
* 🧠 **Signature-based detection** against known keyloggers
* 🚫 Option to **terminate suspicious processes** automatically
* 📄 **Log generation** (with timestamped log files in `/logs/`)
* ⚡ **Lightweight & offline** – no external data sharing

---

## 🧠 Concepts Used

* Process & memory analysis (`psutil`)
* Static signature matching (name, behavior)
* Basic heuristic checks (hidden processes, runtime anomalies)
* Secure logging (`logger.py`)
* Utility-based process handling (`utils.py`)

---

## ⚙️ Project Structure

```
keylogger-detector/
│
├── detector.py          # Main detection script
├── logger.py            # Logging functionality (file + console)
├── utils.py             # Safe process info extraction
├── signatures.json      # Known malicious process names
├── requirements.txt     # Python dependencies
└── logs/                # Auto-generated log files
```

---

## 🚀 Getting Started

### ✅ Prerequisites

* Python **3.7+**
* OS: **Windows / Linux / macOS**

### 📥 Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/keylogger-detector.git
cd keylogger-detector

# Install dependencies
pip install -r requirements.txt
```

### ▶️ Usage

Run the detector:

```bash
python detector.py
```

---

## 📖 Example Output

```bash
[!] Suspicious process detected:
    Name: keylog32.exe
    PID: 1432
    Action: Terminated

[+] Scan complete. 1 threat removed. Log saved to logs/2025-08-24_201045.log
```

---

## 🧪 Disclaimer

This tool is for **educational & ethical purposes only**.
Do not use it for malicious activities or reverse-engineering legitimate software.

---

## 👨‍💻 Author

**Your Name** – [@HR10J44T](https://github.com/HR10J44T)

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.
