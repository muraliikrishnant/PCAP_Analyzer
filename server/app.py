from __future__ import annotations

import datetime as dt
import tempfile
from collections import Counter, defaultdict

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import rdpcap
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6

app = FastAPI(title="Wireshark AI Agent Parser")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _iso_time(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()


def _packet_src_dst(pkt) -> tuple[str | None, str | None]:
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None


def _protocol_tags(pkt) -> list[str]:
    tags = []
    if pkt.haslayer(TCP):
        tags.append("TCP")
    if pkt.haslayer(UDP):
        tags.append("UDP")
    if pkt.haslayer(ICMP):
        tags.append("ICMP")
    if pkt.haslayer(DNS):
        tags.append("DNS")
    if pkt.haslayer(IPv6):
        tags.append("IPv6")
    if pkt.haslayer(IP):
        tags.append("IPv4")
    return tags or ["Other"]


def _alert_rules(summary, protocol_counts, talkers):
    alerts = []
    packet_count = summary.get("packet_count", 0)
    if packet_count > 100_000:
        alerts.append("Large capture: more than 100k packets.")

    dns_count = protocol_counts.get("DNS", 0)
    if packet_count and dns_count / packet_count > 0.35:
        alerts.append("High DNS volume relative to total traffic.")

    if talkers:
        top = max(talkers.values())
        total = sum(talkers.values())
        if total and top / total > 0.6:
            alerts.append("Single host dominates traffic volume.")

    return alerts


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/pcap/parse")
async def parse_pcap(pcap: UploadFile = File(...)):
    with tempfile.NamedTemporaryFile(delete=True, suffix=".pcap") as tmp:
        content = await pcap.read()
        tmp.write(content)
        tmp.flush()

        packets = rdpcap(tmp.name)

    packet_count = len(packets)
    total_bytes = sum(len(pkt) for pkt in packets)

    capture_start = _iso_time(packets[0].time) if packet_count else None
    capture_end = _iso_time(packets[-1].time) if packet_count else None

    protocol_counts = Counter()
    talkers = defaultdict(int)
    unique_hosts = set()
    flows = defaultdict(lambda: {"packets": 0, "bytes": 0})

    for pkt in packets:
        for tag in _protocol_tags(pkt):
            protocol_counts[tag] += 1

        src, dst = _packet_src_dst(pkt)
        if src:
            talkers[src] += len(pkt)
            unique_hosts.add(src)
        if dst:
            unique_hosts.add(dst)

        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Other"
        flow_key = (src or "unknown", dst or "unknown", proto)
        flows[flow_key]["packets"] += 1
        flows[flow_key]["bytes"] += len(pkt)

    top_talkers = [
        {"ip": host, "bytes": bytes_}
        for host, bytes_ in sorted(talkers.items(), key=lambda item: item[1], reverse=True)[:12]
    ]

    flow_items = []
    for (src, dst, proto), stats in sorted(
        flows.items(), key=lambda item: item[1]["bytes"], reverse=True
    )[:12]:
        flow_items.append(
            {
                "src": src,
                "dst": dst,
                "protocol": proto,
                "bytes": stats["bytes"],
                "packets": stats["packets"],
            }
        )

    summary = {
        "capture_start": capture_start,
        "capture_end": capture_end,
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "unique_hosts": len(unique_hosts),
        "protocols": [
            {"name": name, "count": count}
            for name, count in protocol_counts.most_common()
        ],
        "top_talkers": top_talkers,
    }

    summary["alerts"] = _alert_rules(summary, protocol_counts, talkers)

    return {"summary": summary, "flows": flow_items}
