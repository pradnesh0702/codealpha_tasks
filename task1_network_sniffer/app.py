"""
app.py — NetSniff GUI (PyQt5)
"""

import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QLineEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QSplitter, QFrame,
    QStatusBar
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from sniffer import SnifferThread

PROTO_COLORS = {
    "TCP":   "#3a9fea",
    "UDP":   "#2ecc8e",
    "ICMP":  "#e8a12a",
    "DNS":   "#b07fe8",
    "OTHER": "#555e6e",
}

COLUMNS = ["#", "Time", "Protocol", "Source IP", "Src Port",
           "Dest IP", "Dst Port", "Size", "Flags"]


def get_interfaces():
    """
    Returns list of (display_name, device_name) tuples.
    On Windows scapy uses \\Device\\NPF_{...} strings.
    We map those to friendly names via psutil or iface_name_to_description.
    """
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        result = []
        for i in ifaces:
            name   = i.get("name", "")
            desc   = i.get("description", "") or i.get("win_index", "")
            npf    = i.get("guid", "") 
            # scapy's get_windows_if_list returns 'name' as the NPF path
            # and 'description' as the human name
            label  = desc if desc else name
            device = name
            if device:
                result.append((label, device))
        if result:
            return result
    except Exception:
        pass

    # fallback for Linux/macOS
    try:
        with open("/proc/net/dev") as f:
            ifaces = [l.split(":")[0].strip() for l in f.readlines()[2:] if ":" in l]
        return [(i, i) for i in ifaces]
    except Exception:
        pass

    return [("eth0", "eth0"), ("wlan0", "wlan0"), ("lo", "lo")]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSniff — Network Packet Sniffer")
        self.setMinimumSize(1100, 680)
        self.thread  = None
        self.packets = []
        self.counter = 0
        self._iface_map = {}   # display name → device path
        self._build_ui()
        self._apply_style()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # ── toolbar ──────────────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        toolbar.addWidget(self._lbl("Interface"))
        self.iface_combo = QComboBox()
        self.iface_combo.setFixedWidth(200)
        ifaces = get_interfaces()
        for label, device in ifaces:
            self._iface_map[label] = device
            self.iface_combo.addItem(label)
        toolbar.addWidget(self.iface_combo)

        toolbar.addWidget(self._lbl("Filter"))
        self.filter_box = QLineEdit()
        self.filter_box.setPlaceholderText("tcp  /  udp port 53  /  host 8.8.8.8")
        self.filter_box.setText("ip")
        self.filter_box.setFixedWidth(240)
        toolbar.addWidget(self.filter_box)

        toolbar.addStretch()

        self.btn_start = QPushButton("▶  Start")
        self.btn_start.setObjectName("btn-start")
        self.btn_start.clicked.connect(self.start_capture)
        toolbar.addWidget(self.btn_start)

        self.btn_stop = QPushButton("■  Stop")
        self.btn_stop.setObjectName("btn-stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_capture)
        toolbar.addWidget(self.btn_stop)

        self.btn_clear = QPushButton("✕  Clear")
        self.btn_clear.setObjectName("btn-clear")
        self.btn_clear.clicked.connect(self.clear_table)
        toolbar.addWidget(self.btn_clear)

        root.addLayout(toolbar)

        # ── stats ─────────────────────────────────────────────────────────────
        stats = QHBoxLayout()
        stats.setSpacing(16)
        self.stat_labels = {}
        for key in ["Total", "TCP", "UDP", "ICMP", "DNS"]:
            lbl = QLabel(f"{key}  0")
            lbl.setObjectName(f"stat-{key.lower()}")
            stats.addWidget(lbl)
            self.stat_labels[key] = lbl
        stats.addStretch()
        root.addLayout(stats)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setObjectName("divider")
        root.addWidget(line)

        # ── splitter ──────────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Vertical)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setHighlightSections(False)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Interactive)
        for i, w in enumerate([40, 80, 80, 130, 75, 130, 75, 65, 100]):
            self.table.setColumnWidth(i, w)
        hh.setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._on_row_select)
        splitter.addWidget(self.table)

        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setObjectName("detail")
        self.detail.setPlaceholderText("Click a row to inspect the packet.")
        self.detail.setFixedHeight(130)
        splitter.addWidget(self.detail)

        splitter.setSizes([480, 130])
        root.addWidget(splitter)

        self.status = QStatusBar()
        self.status.showMessage("Ready — select an interface and press Start.")
        self.setStatusBar(self.status)

    def _lbl(self, text):
        l = QLabel(text)
        l.setObjectName("toolbar-label")
        return l

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background:#0f1117; color:#c8cdd6;
                font-family:'Segoe UI',Arial,sans-serif; font-size:13px;
            }
            QLabel#toolbar-label { color:#555e6e; font-size:12px; }
            QComboBox, QLineEdit {
                background:#1c2030; border:1px solid #2a3040;
                border-radius:5px; padding:5px 9px; color:#c8cdd6;
            }
            QComboBox:focus, QLineEdit:focus { border-color:#3a7bd5; }
            QComboBox QAbstractItemView { background:#1c2030; selection-background-color:#2a3a55; }
            QPushButton { border-radius:5px; padding:6px 14px; font-size:12px; font-weight:600; }
            QPushButton#btn-start { background:#1a6fc4; color:#fff; border:none; }
            QPushButton#btn-start:hover { background:#2280d8; }
            QPushButton#btn-start:disabled { background:#1a3a5a; color:#555; }
            QPushButton#btn-stop { background:#c0392b; color:#fff; border:none; }
            QPushButton#btn-stop:hover { background:#d44637; }
            QPushButton#btn-stop:disabled { background:#3a1a1a; color:#555; }
            QPushButton#btn-clear { background:#1c2030; color:#888; border:1px solid #2a3040; }
            QPushButton#btn-clear:hover { background:#252a3a; color:#aaa; }
            QLabel#stat-total  { color:#c8cdd6; font-weight:600; }
            QLabel#stat-tcp    { color:#3a9fea; }
            QLabel#stat-udp    { color:#2ecc8e; }
            QLabel#stat-icmp   { color:#e8a12a; }
            QLabel#stat-dns    { color:#b07fe8; }
            QFrame#divider { color:#1e2535; }
            QTableWidget {
                background:#0f1117; alternate-background-color:#131720;
                border:none; gridline-color:transparent; outline:none;
            }
            QTableWidget::item { padding:4px 6px; border:none; }
            QTableWidget::item:selected { background:#1a2a45; color:#fff; }
            QHeaderView::section {
                background:#131720; color:#555e6e; border:none;
                border-bottom:1px solid #1e2535; padding:5px 6px;
                font-size:11px; font-weight:600;
            }
            QTextEdit#detail {
                background:#0a0d13; border:none; border-top:1px solid #1e2535;
                color:#8da0b8; font-family:'Cascadia Code','Consolas',monospace;
                font-size:12px; padding:8px 12px;
            }
            QStatusBar { background:#090c12; color:#3a4455; font-size:11px; }
            QScrollBar:vertical { background:#0f1117; width:6px; border:none; }
            QScrollBar::handle:vertical { background:#2a3040; border-radius:3px; min-height:20px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
        """)

    def start_capture(self):
        label  = self.iface_combo.currentText()
        device = self._iface_map.get(label, label)
        filt   = self.filter_box.text().strip()

        self.thread = SnifferThread(device, filt)
        self.thread.packet_received.connect(self._add_packet)
        self.thread.status_changed.connect(self._on_status)
        self.thread.start()

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.filter_box.setEnabled(False)
        self.status.showMessage(f"Capturing on {label} ...")

    def stop_capture(self):
        if self.thread:
            self.thread.stop()
            self.thread.wait(2000)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.filter_box.setEnabled(True)
        self.status.showMessage(f"Stopped. {self.counter} packets captured.")

    def clear_table(self):
        self.table.setRowCount(0)
        self.packets.clear()
        self.counter = 0
        self.detail.clear()
        for key in self.stat_labels:
            self.stat_labels[key].setText(f"{key}  0")

    def _add_packet(self, pkt):
        self.counter += 1
        self.packets.append(pkt)
        row = self.table.rowCount()
        self.table.insertRow(row)
        color = QColor(PROTO_COLORS.get(pkt["proto"], "#888"))
        values = [
            str(self.counter), pkt["time"], pkt["proto"],
            pkt["src_ip"], pkt["src_port"],
            pkt["dst_ip"], pkt["dst_port"],
            f"{pkt['size']} B", pkt["flags"],
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            if col == 2:
                item.setForeground(color)
            self.table.setItem(row, col, item)
        self.table.setRowHeight(row, 26)
        self.table.scrollToBottom()
        self._update_stats()

    def _update_stats(self):
        counts = {"Total": len(self.packets)}
        for p in self.packets:
            counts[p["proto"]] = counts.get(p["proto"], 0) + 1
        for key, lbl in self.stat_labels.items():
            lbl.setText(f"{key}  {counts.get(key, 0)}")

    def _on_row_select(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.packets):
            return
        p = self.packets[row]
        lines = [
            f"  Time      {p['time']}",
            f"  Protocol  {p['proto']}" + (f"   Flags: {p['flags']}" if p['flags'] else ""),
            f"  Source    {p['src_ip']} : {p['src_port']}",
            f"  Dest      {p['dst_ip']} : {p['dst_port']}",
            f"  Size      {p['size']} bytes",
            "",
            f"  Payload   {p['payload'] or '(no printable payload)'}",
        ]
        self.detail.setText("\n".join(lines))

    def _on_status(self, msg):
        if msg.startswith("error"):
            self.status.showMessage(f"Error: {msg}")
            self.stop_capture()

    def closeEvent(self, e):
        self.stop_capture()
        e.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
