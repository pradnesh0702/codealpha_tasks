# 🔍 NetSniff — Network Packet Sniffer

NetSniff is a modern, lightweight, and cross-platform desktop application for real-time network packet analysis. Built with a sleek dark-themed **PyQt5** graphical user interface and powered by the robust **Scapy** packet manipulation engine, NetSniff allows developers, network engineers, and cybersecurity enthusiasts to capture, filter, and inspect network traffic effortlessly.

---

## ✨ Features

- **Real-Time Packet Capturing:** Capture incoming and outgoing IP packets smoothly in a background thread without freezing the UI.
- **Dynamic Protocol Breakdown:** Color-coded protocol categorization (TCP, UDP, ICMP, DNS, and more) for clear structural visibility.
- **BPF Filtering:** Built-in support for standard Berkeley Packet Filter (BPF) syntax (e.g., `tcp`, `udp port 53`, `host 8.8.8.8`).
- **Live Statistics Dashboard:** Active counters monitoring the total packet volume alongside dedicated trackers for major protocols.
- **Deep Packet Inspection:** Click any recorded packet to view a detailed breakdown, including hardware headers, TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`), network routes, and string-sanitized payload extractions.
- **Automated Windows Elevation:** Includes an automated batch script to securely handle necessary administrator/root permission elevations required for raw packet sniffing.
- **Cross-Platform Compatibility:** Native interface mappings fallback across Windows (`Npcap`/`WinPcap`), macOS, and Linux.

---

## 🛠️ Tech Stack & Core Libraries

- **Frontend Core:** `PyQt5` (Python bindings for Qt5)
- **Packet Engineering Backend:** `Scapy` (Interactive packet manipulation framework)
- **Styling Architecture:** Custom CSS / Qt Style Sheets (QSS) Dark Theme
- **Multithreading:** `QThread` and asynchronous `pyqtSignal` event streaming

---

## 📂 Project Architecture

```text
├── app.py          # Application entrypoint & PyQt5 MainWindow layout/styling
├── sniffer.py      # Background worker thread (QThread) handling asynchronous Scapy sniffing
└── run.bat         # Windows automated administration privilege escalation script
```

---

## 🚀 Installation & Prerequisites

### 1. Requirements

Before running the application, make sure you have the required system dependencies and libraries installed:

- **Python 3.7+**
- **Packet Capture Driver:**
  - **Windows:** Install [Npcap](https://npcap.com/) (Make sure to check *"Install Npcap in WinPcap API-compatible Mode"* during installation).
  - **Linux:** `libpcap` (Usually pre-installed, or run `sudo apt-get install libpcap-dev`).
  - **macOS:** Native system captures are supported out-of-the-box.

### 2. Setup Environment

Clone the repository and install the required Python packages:

```bash
# Clone this repository
git clone https://github.com/yourusername/NetSniff.git
cd NetSniff

# Install dependencies
pip install PyQt5 scapy
```

---

## 🖥️ Usage Guide

### Windows (Recommended Automation)
Simply double-click `run.bat` or execute it from the Command Prompt. The script automatically requests administrative privileges (required for capturing raw socket data):

```cmd
run.bat
```

### macOS & Linux
To bind to raw network interfaces, launch the main application directly with root permissions using `sudo`:

```bash
sudo python app.py
```

---

## ⚙️ How It Works

1. **Interface Mapping:** Upon startup, `app.py` cross-references OS network interface guides (via Scapy's Windows API wrappers or Linux `/proc/net/dev`) to fetch human-readable interfaces.
2. **Asynchronous Sniffing Worker:** When you press **Start**, `SnifferThread` (inheriting from `QThread`) instantiates an isolated collection loop using Scapy's `sniff()` pipeline. This avoids UI thread blocking.
3. **Data Emitting:** Packets are parsed on-the-fly inside `sniffer.py`, structuring timestamps, protocol labels, flags, and payloads into dictionary models before passing them to the UI thread via `pyqtSignal`.
4. **Interactive Inspection:** Clicking an item on the `QTableWidget` maps to structural arrays parsing human-readable hex-to-ASCII payload dumps safely inside the detailed preview inspector panel.

---

##👨‍💻 Author
Pradnesh Shingrupe
---
## 🛡️ License

This project is open-source and available under the [MIT License](LICENSE).
