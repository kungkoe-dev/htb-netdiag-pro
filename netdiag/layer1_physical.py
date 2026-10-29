"""
Layer 1 - Physical & Cable Diagnostics
ตรวจสอบการ์ดแลน, สถานะสายแลน (Carrier), ความเร็ว (Speed/Duplex) และสถิติ Error ของสายสัญญาณ
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import CheckResult, CheckStatus, InterfaceDiagReport


def _read_sysfs(iface: str, attr: str) -> Optional[str]:
    path = Path(f"/sys/class/net/{iface}/{attr}")
    try:
        if path.exists():
            return path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        pass
    return None


def classify_interface(iface: str) -> str:
    """แยกประเภท Interface: ethernet, wifi, loopback, virtual"""
    if iface == "lo":
        return "loopback"
    sys_path = Path(f"/sys/class/net/{iface}")
    if (sys_path / "wireless").exists() or (sys_path / "phy80211").exists():
        return "wifi"
    # Check if virtual device (docker, veth, virbr, tun, tap, br-)
    try:
        real_path = os.path.realpath(str(sys_path))
        if "/virtual/" in real_path or iface.startswith(("docker", "veth", "br-", "virbr", "tun", "tap", "wg")):
            return "virtual"
    except OSError:
        pass
    return "ethernet"


def discover_interfaces(include_virtual: bool = False) -> List[Tuple[str, str]]:
    """ค้นหา Network Interfaces ทั้งหมดในเครื่อง เรียงลำดับ Ethernet มาก่อน"""
    net_dir = Path("/sys/class/net")
    if not net_dir.exists():
        return []
    result: List[Tuple[str, str]] = []
    for item in sorted(net_dir.iterdir(), key=lambda p: p.name):
        iface = item.name
        if_type = classify_interface(iface)
        if if_type == "loopback":
            continue
        if if_type == "virtual" and not include_virtual:
            continue
        result.append((iface, if_type))

    # เรียงให้ ethernet มาก่อน ตามด้วย wifi และ virtual
    priority = {"ethernet": 0, "wifi": 1, "virtual": 2}
    result.sort(key=lambda x: (priority.get(x[1], 99), x[0]))
    return result


def get_ethtool_info(iface: str) -> Dict[str, str]:
    """ดึงข้อมูลจากคำสั่ง ethtool"""
    info: Dict[str, str] = {}
    try:
        proc = subprocess.run(
            ["ethtool", iface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        output = proc.stdout
        for line in output.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip()] = v.strip()
    except Exception:
        pass
    return info


def get_driver_info(iface: str) -> str:
    """ดึงชื่อ Driver ของการ์ดแลน"""
    try:
        proc = subprocess.run(
            ["ethtool", "-i", iface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in proc.stdout.splitlines():
            if line.lower().startswith("driver:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def get_nic_error_stats(iface: str) -> Dict[str, int]:
    """อ่านค่าสถิติ Error ระดับฮาร์ดแวร์จาก /sys/class/net/<iface>/statistics"""
    stats_dir = Path(f"/sys/class/net/{iface}/statistics")
    keys = [
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
        "rx_errors",
        "tx_errors",
        "rx_crc_errors",
        "rx_frame_errors",
        "rx_fifo_errors",
        "rx_dropped",
        "tx_dropped",
        "tx_carrier_errors",
        "collisions",
    ]
    stats: Dict[str, int] = {}
    for k in keys:
        val = _read_sysfs(iface, f"statistics/{k}")
        if val is not None and val.isdigit():
            stats[k] = int(val)
        else:
            stats[k] = 0

    # ดึงค่า carrier_changes (จำนวนครั้งที่สายแลนหลุด/กระพริบ)
    cc = _read_sysfs(iface, "carrier_changes")
    if cc and cc.isdigit():
        stats["carrier_changes"] = int(cc)
    else:
        stats["carrier_changes"] = 0
    return stats


def run_layer1_checks(report: InterfaceDiagReport) -> bool:
    """
    รันการตรวจสอบ Layer 1 (Physical Layer)
    คืนค่า True หากมีสัญญาณไฟ (Carrier Up) และพร้อมตรวจ Layer ถัดไป
    """
    iface = report.interface
    report.mac_address = _read_sysfs(iface, "address") or "unknown"
    report.driver = get_driver_info(iface)

    flags_hex = _read_sysfs(iface, "flags") or "0x0"
    try:
        flags_int = int(flags_hex, 16)
    except ValueError:
        flags_int = 0
    admin_up = bool(flags_int & 0x1)  # IFF_UP

    operstate = _read_sysfs(iface, "operstate") or "unknown"
    carrier_str = _read_sysfs(iface, "carrier")
    carrier_up = carrier_str == "1"

    ethtool_data = get_ethtool_info(iface)
    link_detected = ethtool_data.get("Link detected", "").lower()
    if link_detected == "yes":
        carrier_up = True
    elif link_detected == "no":
        carrier_up = False

    report.raw_context["admin_up"] = admin_up
    report.raw_context["operstate"] = operstate
    report.raw_context["carrier_up"] = carrier_up
    report.raw_context["ethtool"] = ethtool_data

    # 1. Check Admin State & Physical Carrier (Link Status)
    if not admin_up:
        report.add_check(
            CheckResult(
                layer="L1 (Physical)",
                name="Interface Admin State",
                status=CheckStatus.FAIL,
                summary=f"พอร์ต {iface} ถูกสั่งปิดการทำงาน (Admin DOWN)",
                details=f"flags={flags_hex}, operstate={operstate}",
                recommendation=f"เปิดใช้งานพอร์ตด้วยคำสั่ง: sudo ip link set {iface} up",
            )
        )
        return False

    if not carrier_up:
        if report.if_type == "ethernet":
            report.add_check(
                CheckResult(
                    layer="L1 (Physical)",
                    name="Physical Cable / Link Carrier",
                    status=CheckStatus.FAIL,
                    summary=f"ไม่พบสัญญาณไฟจากสายแลนบนพอร์ต {iface} (NO-CARRIER)",
                    details=f"operstate={operstate}, Link detected=no, MAC={report.mac_address}",
                    recommendation=(
                        "1. ตรวจสอบว่าเสียบสายแลนแน่นทั้งฝั่งคอมพิวเตอร์และฝั่ง Switch/Router (ดูไฟ LED ที่พอร์ต)\n"
                        "2. ทดลองสลับสายแลนเส้นใหม่ (สายอาจขาดใน)\n"
                        "3. หากเสียบสายแล้วไฟไม่ติด พอร์ตบน Switch ต้นทางอาจถูกสั่ง Shutdown หรืออุปกรณ์ต้นทางไม่จ่ายไฟ"
                    ),
                )
            )
        else:
            report.add_check(
                CheckResult(
                    layer="L1 (Physical)",
                    name="Wireless Carrier Status",
                    status=CheckStatus.FAIL,
                    summary=f"พอร์ตไร้สาย {iface} ยังไม่ได้เชื่อมต่อสัญญาณ (NO-CARRIER)",
                    details=f"operstate={operstate}",
                    recommendation="ตรวจสอบการเชื่อมต่อ Wi-Fi ผ่าน nmcli หรือตั้งค่า SSID/Password",
                )
            )
        return False

    report.add_check(
        CheckResult(
            layer="L1 (Physical)",
            name="Physical Link Carrier",
            status=CheckStatus.PASS,
            summary=f"เชื่อมต่อสัญญาณระดับกายภาพสำเร็จ (Carrier UP / Link Detected)",
            details=f"operstate={operstate}, MAC={report.mac_address}, Driver={report.driver}",
        )
    )

    # 2. Check Speed & Duplex (สำหรับสายแลน Ethernet)
    if report.if_type == "ethernet":
        speed_sys = _read_sysfs(iface, "speed")
        duplex_sys = _read_sysfs(iface, "duplex")
        speed_eth = ethtool_data.get("Speed", f"{speed_sys}Mb/s" if speed_sys else "Unknown")
        duplex_eth = ethtool_data.get("Duplex", duplex_sys.capitalize() if duplex_sys else "Unknown")
        autoneg = ethtool_data.get("Auto-negotiation", "Unknown")

        speed_mbps = 0
        m = re.search(r"(\d+)", speed_eth)
        if m:
            speed_mbps = int(m.group(1))

        report.raw_context["speed_mbps"] = speed_mbps
        report.raw_context["duplex"] = duplex_eth

        if duplex_eth.lower() == "half":
            report.add_check(
                CheckResult(
                    layer="L1 (Physical)",
                    name="Link Speed & Duplex",
                    status=CheckStatus.FAIL,
                    summary=f"ตรวจพบ Half-Duplex ({speed_eth} / {duplex_eth}) ทำให้เน็ตช้าและเกิด Collision!",
                    details=f"Speed={speed_eth}, Duplex={duplex_eth}, Auto-Neg={autoneg}",
                    recommendation=(
                        "เกิดปัญหา Duplex Mismatch หรือสายแลนมีปัญหา:\n"
                        "1. ตรวจสอบการตั้งค่า Speed/Duplex บนพอร์ต Switch ให้เป็น Auto-Negotiation ทั้งสองฝั่ง\n"
                        "2. เช็กหัวสาย RJ45 หรือเปลี่ยนสายแลนใหม่"
                    ),
                )
            )
        elif 0 < speed_mbps <= 100:
            report.add_check(
                CheckResult(
                    layer="L1 (Physical)",
                    name="Link Speed & Duplex",
                    status=CheckStatus.WARN,
                    summary=f"สายแลนซิงก์ความเร็วได้เพียง {speed_mbps} Mbps ({duplex_eth}-Duplex)",
                    details=f"Speed={speed_eth}, Duplex={duplex_eth}, Auto-Neg={autoneg}",
                    recommendation=(
                        "ปกติการ์ดแลนยุคใหม่ควรวิ่งที่ 1000 Mbps (1 Gbps):\n"
                        "1. หาก Switch ต้นทางเป็น Gigabit แต่ขึ้นแค่ 100 Mbps แปลว่า **สายแลนเข้าหัวไม่ครบ 8 เส้น (ติดแค่คู่สาย 1,2,3,6)** หรือสายแลนเป็นมาตรฐานเก่า (Cat5) หรือสายชำรุด\n"
                        "2. ลองขยับหัวสาย RJ45 หรือเปลี่ยนสายแลนเป็น Cat5e / Cat6"
                    ),
                )
            )
        else:
            report.add_check(
                CheckResult(
                    layer="L1 (Physical)",
                    name="Link Speed & Duplex",
                    status=CheckStatus.PASS,
                    summary=f"ความเร็วสายแลนปกติ: {speed_eth} ({duplex_eth}-Duplex)",
                    details=f"Auto-negotiation={autoneg}",
                )
            )

    # 3. Check Hardware & Cable Error Counters (CRC / Frame / Carrier Flaps)
    stats = get_nic_error_stats(iface)
    report.raw_context["nic_stats"] = stats

    crc_err = stats.get("rx_crc_errors", 0)
    frame_err = stats.get("rx_frame_errors", 0)
    rx_err = stats.get("rx_errors", 0)
    tx_err = stats.get("tx_errors", 0)
    carrier_err = stats.get("tx_carrier_errors", 0)
    collisions = stats.get("collisions", 0)
    flaps = stats.get("carrier_changes", 0)

    total_phy_err = crc_err + frame_err + rx_err + tx_err + carrier_err + collisions
    stat_detail = (
        f"CRC={crc_err}, Frame={frame_err}, RX_Err={rx_err}, TX_Err={tx_err}, "
        f"Collisions={collisions}, Link_Flaps={flaps}"
    )

    if crc_err > 0 or frame_err > 0 or collisions > 0 or total_phy_err > 10:
        report.add_check(
            CheckResult(
                layer="L1 (Physical)",
                name="Cable Signal Integrity (CRC/Errors)",
                status=CheckStatus.WARN if total_phy_err < 100 else CheckStatus.FAIL,
                summary=f"พบ Packet เสียระดับสายสัญญาณ (Physical Errors = {total_phy_err})",
                details=stat_detail,
                recommendation=(
                    "พบสัญญาณรบกวนหรือสายแลนเสื่อมสภาพ (CRC / Frame Error):\n"
                    "1. หัว RJ45 อาจสกปรก หลวม หรือเข้าหัวไม่แน่น\n"
                    "2. สายแลนอาจเดินผ่านจุดที่มีคลื่นแม่เหล็กไฟฟ้ารบกวน (EMI) หรือสายยาวเกิน 100 เมตร"
                ),
            )
        )
    elif flaps > 20:
        report.add_check(
            CheckResult(
                layer="L1 (Physical)",
                name="Cable Stability (Link Flapping)",
                status=CheckStatus.WARN,
                summary=f"พบประวัติสายแลนหลุด/ต่อใหม่บ่อยผิดปกติ ({flaps} ครั้ง)",
                details=stat_detail,
                recommendation="ขั้วสายแลนอาจหลวม หรือพอร์ต Switch จ่ายไฟ PoE/สัญญาณไม่เสถียร",
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L1 (Physical)",
                name="Cable Signal Integrity (CRC/Errors)",
                status=CheckStatus.PASS,
                summary="คุณภาพสัญญาณในสายดีเยี่ยม (ไม่พบ CRC/Frame Error)",
                details=stat_detail,
            )
        )

    return True
