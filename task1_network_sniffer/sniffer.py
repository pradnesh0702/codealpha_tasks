from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
from PyQt5.QtCore import QThread, pyqtSignal
from datetime import datetime


def parse_packet(pkt):
    if IP not in pkt:
        return None

    if DNS in pkt:
        proto = "DNS"
    elif TCP in pkt:
        proto = "TCP"
    elif UDP in pkt:
        proto = "UDP"
    elif ICMP in pkt:
        proto = "ICMP"
    else:
        proto = "OTHER"

    layer = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    src_port = str(layer.sport) if layer else "—"
    dst_port = str(layer.dport) if layer else "—"

    flags = ""
    if TCP in pkt:
        f = pkt[TCP].flags
        parts = []
        if f & 0x02: parts.append("SYN")
        if f & 0x10: parts.append("ACK")
        if f & 0x01: parts.append("FIN")
        if f & 0x04: parts.append("RST")
        if f & 0x08: parts.append("PSH")
        flags = "/".join(parts)

    payload = ""
    if Raw in pkt:
        raw = bytes(pkt[Raw])
        payload = "".join(chr(b) if 32 <= b < 127 else "." for b in raw[:80])
        if len(raw) > 80:
            payload += "…"

    return {
        "time":     datetime.now().strftime("%H:%M:%S"),
        "proto":    proto,
        "src_ip":   pkt[IP].src,
        "src_port": src_port,
        "dst_ip":   pkt[IP].dst,
        "dst_port": dst_port,
        "size":     len(pkt),
        "flags":    flags,
        "payload":  payload,
    }


class SnifferThread(QThread):
    packet_received = pyqtSignal(dict)
    status_changed  = pyqtSignal(str)

    def __init__(self, iface, bpf_filter=""):
        super().__init__()
        self.iface      = iface
        self.bpf_filter = bpf_filter
        self._running   = False

    def run(self):
        self._running = True
        self.status_changed.emit("capturing")
        kwargs = dict(
            iface=self.iface,
            prn=self._handle,
            store=False,
            stop_filter=lambda _: not self._running,
        )
        # only pass filter if non-empty — avoids libpcap errors on Windows
        if self.bpf_filter.strip():
            kwargs["filter"] = self.bpf_filter.strip()

        try:
            sniff(**kwargs)
        except Exception as e:
            self.status_changed.emit(f"error: {e}")
            return
        self.status_changed.emit("stopped")

    def _handle(self, pkt):
        data = parse_packet(pkt)
        if data:
            self.packet_received.emit(data)

    def stop(self):
        self._running = False
