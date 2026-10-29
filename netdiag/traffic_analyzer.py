"""
Live Bandwidth, Protocol Telemetry & Broadcast Storm Analyzer (--mode traffic)
วิเคราะห์ความเร็วรับ-ส่งข้อมูลแบบเรียลไทม์, สัดส่วนโปรโตคอล และตรวจจับอาการ Broadcast Storm / Switching Loop:
  - อ่าน Kernel Interface Counters (/sys/class/net/<iface>/statistics)
  - ดึงสถิติ Socket ปัจจุบันจาก `ss -s`
  - ดักจับและจำแนกโปรโตคอลในสายด้วย `tshark` (เมื่อมีสิทธิ์ดักฟังแพ็กเกจ)
"""

import os
import re
import shutil
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from . import CheckResult, CheckStatus, InterfaceDiagReport


def _read_stat_int(iface: str, stat_name: str) -> int:
    path = Path(f"/sys/class/net/{iface}/statistics/{stat_name}")
    try:
        return int(path.read_text().strip())
    except Exception:
        return 0


def _read_interface_counters(iface: str) -> Dict[str, int]:
    return {
        "rx_bytes": _read_stat_int(iface, "rx_bytes"),
        "tx_bytes": _read_stat_int(iface, "tx_bytes"),
        "rx_packets": _read_stat_int(iface, "rx_packets"),
        "tx_packets": _read_stat_int(iface, "tx_packets"),
        "multicast": _read_stat_int(iface, "multicast"),
        "rx_dropped": _read_stat_int(iface, "rx_dropped"),
        "tx_dropped": _read_stat_int(iface, "tx_dropped"),
    }


def _get_socket_telemetry() -> Dict[str, int]:
    """ดึงจำนวนการเชื่อมต่อ TCP/UDP ปัจจุบันของเครื่องผ่านคำสั่ง ss -s"""
    stats = {"tcp_estab": 0, "tcp_total": 0, "udp_total": 0}
    if not shutil.which("ss"):
        return stats
    try:
        proc = subprocess.run(["ss", "-s"], capture_output=True, text=True, timeout=2)
        for line in proc.stdout.splitlines():
            m_tcp = re.search(r"TCP:\s+(\d+)\s+\(estab\s+(\d+)", line)
            if m_tcp:
                stats["tcp_total"] = int(m_tcp.group(1))
                stats["tcp_estab"] = int(m_tcp.group(2))
            m_udp = re.search(r"UDP:\s+(\d+)", line)
            if m_udp:
                stats["udp_total"] = int(m_udp.group(1))
    except Exception:
        pass
    return stats


def _sniff_live_protocols_tshark(iface: str, duration_sec: int = 2) -> List[Dict[str, Any]]:
    """
    ใช้ tshark ดักฟังโปรโตคอลที่วิ่งผ่านการ์ดแลนในช่วงสั้นๆ (กรณีรันด้วย sudo หรือมีสิทธิ์ dumpcap)
    """
    if not shutil.which("tshark") or os.geteuid() != 0:
        return []
    try:
        proc = subprocess.run(
            [
                "tshark",
                "-i",
                iface,
                "-a",
                f"duration:{duration_sec}",
                "-T",
                "fields",
                "-e",
                "_ws.col.Protocol",
            ],
            capture_output=True,
            text=True,
            timeout=duration_sec + 3,
        )
        counts: Counter = Counter()
        for line in proc.stdout.splitlines():
            proto = line.strip()
            if proto:
                counts[proto] += 1
        total = sum(counts.values()) or 1
        return [
            {"protocol": p, "packets": c, "pct": round((c / total) * 100.0, 1)}
            for p, c in counts.most_common(6)
        ]
    except Exception:
        return []


def sample_interface_traffic(iface: str, duration_sec: float = 2.0) -> Dict[str, Any]:
    """
    วัดความเร็วรับ-ส่งข้อมูล (Throughput), อัตราแพ็กเกจต่อวินาที (PPS),
    และอัตรา Multicast/Broadcast เพื่อตรวจจับ Broadcast Storm
    """
    c1 = _read_interface_counters(iface)
    t1 = time.monotonic()

    # หากเป็น root ให้รัน tshark ควบคู่กันไปในช่วงเวลานี้
    proto_breakdown = _sniff_live_protocols_tshark(iface, duration_sec=int(max(duration_sec, 1)))
    elapsed = time.monotonic() - t1
    if elapsed < duration_sec:
        time.sleep(duration_sec - elapsed)

    c2 = _read_interface_counters(iface)
    dt = max(time.monotonic() - t1, 0.1)

    rx_bytes_sec = max(c2["rx_bytes"] - c1["rx_bytes"], 0) / dt
    tx_bytes_sec = max(c2["tx_bytes"] - c1["tx_bytes"], 0) / dt
    rx_pps = round(max(c2["rx_packets"] - c1["rx_packets"], 0) / dt, 1)
    tx_pps = round(max(c2["tx_packets"] - c1["tx_packets"], 0) / dt, 1)
    mcast_pps = round(max(c2["multicast"] - c1["multicast"], 0) / dt, 1)
    dropped_delta = max((c2["rx_dropped"] - c1["rx_dropped"]) + (c2["tx_dropped"] - c1["tx_dropped"]), 0)

    rx_kbps = round((rx_bytes_sec * 8.0) / 1000.0, 1)
    tx_kbps = round((tx_bytes_sec * 8.0) / 1000.0, 1)
    rx_mbps = round(rx_kbps / 1000.0, 2)
    tx_mbps = round(tx_kbps / 1000.0, 2)

    avg_rx_pkt_size = round(rx_bytes_sec / rx_pps, 1) if rx_pps > 0 else 0.0

    # ประเมินอาการ Broadcast Storm หรือ ARP Flood
    is_storm = bool(mcast_pps >= 300.0 or (rx_pps >= 4000.0 and 0 < avg_rx_pkt_size <= 96.0))
    sock_stats = _get_socket_telemetry()

    return {
        "interface": iface,
        "sample_sec": round(dt, 2),
        "rx_kbps": rx_kbps,
        "tx_kbps": tx_kbps,
        "rx_mbps": rx_mbps,
        "tx_mbps": tx_mbps,
        "rx_pps": rx_pps,
        "tx_pps": tx_pps,
        "mcast_pps": mcast_pps,
        "avg_rx_pkt_bytes": avg_rx_pkt_size,
        "dropped_delta": dropped_delta,
        "total_rx_mb": round(c2["rx_bytes"] / (1024 * 1024), 1),
        "total_tx_mb": round(c2["tx_bytes"] / (1024 * 1024), 1),
        "total_mcast_pkts": c2["multicast"],
        "total_dropped_pkts": c2["rx_dropped"] + c2["tx_dropped"],
        "is_broadcast_storm": is_storm,
        "socket_stats": sock_stats,
        "protocols": proto_breakdown,
    }


def run_traffic_and_storm_checks(report: InterfaceDiagReport) -> None:
    """
    รันการวิเคราะห์ความเร็วทราฟฟิกและตรวจจับ Broadcast Storm / Network Loop (--mode traffic)
    """
    iface = report.interface
    t_data = sample_interface_traffic(iface, duration_sec=2.0)
    report.raw_context["traffic_data"] = t_data

    rx_kbps = t_data["rx_kbps"]
    tx_kbps = t_data["tx_kbps"]
    rx_pps = t_data["rx_pps"]
    tx_pps = t_data["tx_pps"]
    mcast_pps = t_data["mcast_pps"]
    dropped_delta = t_data["dropped_delta"]
    is_storm = t_data["is_broadcast_storm"]

    # 1. รายงานอัตราการวิ่งของทราฟฟิกปัจจุบัน
    report.add_check(
        CheckResult(
            layer="L1-L4 (Live Traffic Telemetry)",
            name="Real-Time Bandwidth & Packet Rate",
            status=CheckStatus.PASS,
            summary=(
                f"📡 ทราฟฟิกปัจจุบัน: ดาวน์โหลด (RX) = {rx_kbps} Kbps ({rx_pps} pkt/s) | "
                f"อัปโหลด (TX) = {tx_kbps} Kbps ({tx_pps} pkt/s)"
            ),
            details=(
                f"ปริมาณข้อมูลสะสมตั้งแต่เปิดเครื่อง: RX={t_data['total_rx_mb']} MB, TX={t_data['total_tx_mb']} MB | "
                f"การเชื่อมต่อ TCP ปัจจุบัน: {t_data['socket_stats']['tcp_estab']} Established"
            ),
        )
    )

    # 2. ตรวจจับ Broadcast Storm / Switching Loop / Packet Drop
    if is_storm:
        report.add_check(
            CheckResult(
                layer="L2 (Broadcast Storm Detector)",
                name="Broadcast / Multicast Storm Check",
                status=CheckStatus.FAIL,
                summary=(
                    f"🚨 ตรวจพบแพ็กเกจ Broadcast/Multicast พุ่งสูงผิดปกติ ({mcast_pps} pkt/s, RX={rx_pps} pkt/s)! "
                    "เสี่ยงเกิดลูปในสวิตช์ (Switching Loop) หรือ ARP Storm!"
                ),
                details=f"Multicast Rate={mcast_pps} pps, Avg Packet Size={t_data['avg_rx_pkt_bytes']} bytes",
                recommendation=(
                    "วิธีแก้ไขปัญหา Broadcast Storm / ลูปในวงแลน:\n"
                    "1. ตรวจสอบว่ามีใครเสียบสายแลนย้อนกลับเข้าหากันเองบน Hub/Switch ย่อยในห้องหรือไม่\n"
                    "2. เปิดใช้งาน **STP (Spanning Tree Protocol)** และ **Loop Guard / Storm Control** บน Managed Switch"
                ),
            )
        )
    elif dropped_delta > 10:
        report.add_check(
            CheckResult(
                layer="L2 (Broadcast Storm Detector)",
                name="Packet Drop & Storm Check",
                status=CheckStatus.WARN,
                summary=f"⚠️ ตรวจพบแพ็กเกจถูกทิ้ง (Dropped Packets) เพิ่มขึ้น +{dropped_delta} แพ็กเกจในช่วง 2 วินาที!",
                details=f"Multicast Rate={mcast_pps} pps, Total Dropped={t_data['total_dropped_pkts']}",
                recommendation="การ์ดแลนหรือบัฟเฟอร์อาจประมวลผลไม่ทัน หรือมีแพ็กเกจขยะ/VLAN ที่ไม่รู้จักวิ่งเข้ามาในพอร์ต",
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L2 (Broadcast Storm Detector)",
                name="Broadcast / Multicast Storm Check",
                status=CheckStatus.PASS,
                summary=f"สภาวะทราฟฟิกในสายปกติ ไม่พบ Broadcast Storm หรือลูปในวงแลน (Multicast Rate = {mcast_pps} pkt/s)",
                details=f"Total Multicast={t_data['total_mcast_pkts']} pkts, Dropped Delta={dropped_delta}",
            )
        )
