"""
Subnet IP Exhaustion & Network-Wide IP Conflict Scanner
ตรวจสอบว่าไอพีในวงแลนเต็มหรือยัง (DHCP/Subnet Exhaustion) และมีคอมพิวเตอร์เครื่องไหนแย่งไอพีกันอยู่บ้าง (Duplicate IP / MAC Flapping)
"""

import ipaddress
import os
import re
import subprocess
import time
from collections import defaultdict
from typing import Any, Dict, List, Set

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .layer2_datalink import get_arp_neighbors
from .layer3_network import check_duplicate_ip, get_ip_addresses


def _run_fping_sweep(network_str: str, timeout_sec: int = 6) -> Set[str]:
    """ใช้ fping กวาดปิงทั้งวงแลนอย่างรวดเร็วเพื่อกระตุ้นตาราง ARP และเช็กเครื่องที่ออนไลน์"""
    alive_ips: Set[str] = set()
    try:
        proc = subprocess.run(
            ["fping", "-a", "-q", "-g", network_str, "-r", "1", "-t", "100", "-i", "1"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        for line in proc.stdout.splitlines():
            ip_str = line.strip()
            if ip_str:
                alive_ips.add(ip_str)
    except Exception:
        pass
    return alive_ips


def _run_arp_scan_root(iface: str, network_str: str, timeout_sec: int = 8) -> Dict[str, Set[str]]:
    """
    เมื่อรันด้วย sudo จะใช้ arp-scan สแกนระดับ Layer 2 โดยตรง
    สามารถจับกรณี 1 IP มีหลาย MAC ตอบกลับพร้อมกันได้ทันที
    """
    ip_to_macs: Dict[str, Set[str]] = defaultdict(set)
    if os.geteuid() != 0:
        return ip_to_macs
    try:
        proc = subprocess.run(
            ["arp-scan", f"--interface={iface}", "--retry=2", "--timeout=150", network_str],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        for line in proc.stdout.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\b", line.strip())
            if m:
                ip_addr, mac_addr = m.group(1), m.group(2).lower()
                ip_to_macs[ip_addr].add(mac_addr)
    except Exception:
        pass
    return ip_to_macs


def scan_subnet_hosts(
    iface: str,
    cidr_str: str,
    self_ip: str,
    self_mac: str,
) -> Dict[str, Any]:
    """
    สแกนวงแลนเพื่อรวบรวมรายการ IP ที่ถูกใช้งานทั้งหมด และจับคู่ IP <-> MAC Address
    เพื่อหาทั้งจำนวนเครื่องออนไลน์และเครื่องที่แย่ง IP กัน
    """
    iface_obj = ipaddress.ip_interface(cidr_str)
    network = iface_obj.network
    network_str = str(network)
    total_usable = max(network.num_addresses - 2, 1)

    ip_to_macs: Dict[str, Set[str]] = defaultdict(set)
    mac_to_ips: Dict[str, Set[str]] = defaultdict(set)

    # บันทึก IP และ MAC ของเครื่องเราเองเป็นฐาน
    if self_ip and self_mac and self_mac != "unknown":
        ip_to_macs[self_ip].add(self_mac.lower())

    # 1. อ่านตาราง ARP รอบที่ 1 (ก่อนเริ่มกวาดปิง)
    for n in get_arp_neighbors(iface):
        if n.get("mac"):
            ip_to_macs[n["ip"]].add(n["mac"].lower())

    # 2. หากเป็น root ให้ใช้ arp-scan กวาดระดับ Layer 2 ด้วย
    root_arp = _run_arp_scan_root(iface, network_str)
    for ip_k, mac_set in root_arp.items():
        ip_to_macs[ip_k].update(mac_set)

    # 3. กวาดปิงด้วย fping เพื่อปลุกเครื่องในวงให้เข้ามาใน ARP Table (กรณีไม่ได้รัน sudo หรือเครื่องตอบ ICMP)
    alive_icmp = _run_fping_sweep(network_str)
    for ip_k in alive_icmp:
        if ip_k not in ip_to_macs:
            ip_to_macs[ip_k] = set()

    # 4. อ่านตาราง ARP รอบที่ 2 (หลังกวาดปิงเสร็จทันที)
    for n in get_arp_neighbors(iface):
        if n.get("mac"):
            ip_to_macs[n["ip"]].add(n["mac"].lower())

    # 5. รอ 0.3 วินาทีแล้วอ่านตาราง ARP รอบที่ 3 เพื่อจับอาการ ARP/MAC Flapping (กรณี 2 เครื่องแย่ง IP เดียวกันแล้วส่ง Gratuitous ARP ทับกัน)
    time.sleep(0.3)
    for n in get_arp_neighbors(iface):
        if n.get("mac"):
            ip_to_macs[n["ip"]].add(n["mac"].lower())

    # 6. เช็กว่ามีใครแย่ง IP ของเครื่องเราเองหรือไม่ (กรณีรัน sudo)
    dup_self_mac = check_duplicate_ip(iface, self_ip)
    if dup_self_mac and dup_self_mac.lower() != self_mac.lower():
        ip_to_macs[self_ip].add(dup_self_mac.lower())

    # กรองเฉพาะ IP ที่อยู่ใน Subnet นี้ และไม่ใช่ Broadcast/Network address
    valid_hosts: Dict[str, List[str]] = {}
    for ip_k, macs in ip_to_macs.items():
        try:
            ip_obj = ipaddress.ip_address(ip_k)
            if ip_obj not in network or ip_obj in (network.network_address, network.broadcast_address):
                continue
        except ValueError:
            continue
        # นับเฉพาะเครื่องที่มี MAC ใน ARP หรือตอบ fping หรือเป็นเครื่องเราเอง
        if macs or ip_k in alive_icmp or ip_k == self_ip:
            sorted_macs = sorted(macs)
            valid_hosts[ip_k] = sorted_macs
            for m in sorted_macs:
                mac_to_ips[m].add(ip_k)

    # ค้นหา IP ที่มีมากกว่า 1 MAC (คอมพิวเตอร์แย่ง IP กัน!)
    duplicate_ips: Dict[str, List[str]] = {
        ip_k: macs for ip_k, macs in valid_hosts.items() if len(macs) > 1
    }

    # ค้นหา MAC ที่ถือครองมากกว่า 1 IP
    multi_ip_macs: Dict[str, List[str]] = {
        mac_k: sorted(ips) for mac_k, ips in mac_to_ips.items() if len(ips) > 1
    }

    active_count = len(valid_hosts)
    free_count = max(total_usable - active_count, 0)
    usage_pct = round((active_count / total_usable) * 100.0, 1)

    return {
        "subnet": network_str,
        "total_usable": total_usable,
        "active_count": active_count,
        "free_count": free_count,
        "usage_pct": usage_pct,
        "hosts": dict(sorted(valid_hosts.items(), key=lambda x: ipaddress.ip_address(x[0]))),
        "duplicate_ips": duplicate_ips,
        "multi_ip_macs": multi_ip_macs,
    }


def run_ip_exhaustion_and_conflict_checks(report: InterfaceDiagReport) -> None:
    """
    รันการตรวจเช็กความจุวงแลน (IP เต็มหรือยัง) และตรวจจับคอมพิวเตอร์แย่ง IP กันทั้งวงแลน
    """
    iface = report.interface
    ipv4_list, _ = get_ip_addresses(iface)

    if not ipv4_list or ipv4_list[0].get("local", "").startswith("169.254."):
        report.add_check(
            CheckResult(
                layer="L3 (IP Pool & Conflict)",
                name="Subnet IP Exhaustion Scan",
                status=CheckStatus.FAIL,
                summary=f"พอร์ต {iface} ยังไม่มี IP ในวงแลน จึงไม่สามารถสแกนความจุวงแลนผ่านพอร์ตนี้ได้โดยตรง",
                details="พอร์ตนี้อาจไม่ได้รับ IP เพราะ DHCP Pool ในวงแลนเต็มหมดแล้ว หรือพอร์ตถูกบล็อก",
                recommendation=(
                    "1. หากสงสัยว่า DHCP IP เต็ม ให้เลือกสแกนผ่านพอร์ตที่ได้รับ IP อยู่แล้ว (เช่น พอร์ต Wi-Fi ในวงเดียวกัน)\n"
                    f"2. หรือรันด้วย sudo เพื่อดักฟัง ARP บนพอร์ตนี้: sudo arp-scan --interface={iface} --localnet"
                ),
            )
        )
        return

    primary_v4 = ipv4_list[0]
    self_ip = primary_v4.get("local", "")
    prefix_len = primary_v4.get("prefixlen", 24)
    cidr_str = f"{self_ip}/{prefix_len}"

    scan_res = scan_subnet_hosts(
        iface=iface,
        cidr_str=cidr_str,
        self_ip=self_ip,
        self_mac=report.mac_address,
    )
    report.raw_context["subnet_scan"] = scan_res

    subnet = scan_res["subnet"]
    total = scan_res["total_usable"]
    active = scan_res["active_count"]
    free = scan_res["free_count"]
    pct = scan_res["usage_pct"]
    dup_ips = scan_res["duplicate_ips"]
    multi_macs = scan_res["multi_ip_macs"]

    # 1. ประเมินผลเรื่อง "ไอพีเต็มหรือยัง (Subnet / DHCP Pool Exhaustion)"
    if pct >= 90.0 or free <= 5:
        report.add_check(
            CheckResult(
                layer="L3 (IP Pool & Conflict)",
                name="Subnet / DHCP Pool Capacity",
                status=CheckStatus.FAIL,
                summary=f"🚨 ไอพีในวงแลน {subnet} ใกล้เต็มวิกฤต! ถูกใช้ไปแล้ว {active}/{total} IPs ({pct}%) เหลือว่างแค่ {free} IPs!",
                details=f"Subnet={subnet}, Active Hosts={active}, Free IPs={free}",
                recommendation=(
                    "วงแลนนี้แทบไม่เหลือ IP ว่างให้เครื่องใหม่เข้ามาใช้งานแล้ว:\n"
                    "1. **ขยายขนาด Subnet** (เช่น เปลี่ยนจาก /24 เป็น /23 เพื่อเพิ่มเป็น 510 IPs) หรือเพิ่ม VLAN ใหม่\n"
                    "2. **ลดเวลา DHCP Lease Time** บน Router/DHCP Server (เช่น เหลือ 1-2 ชั่วโมง) เพื่อคืน IP จากเครื่องที่ออกไปแล้วเร็วขึ้น"
                ),
            )
        )
    elif pct >= 70.0 or active >= 100:
        report.add_check(
            CheckResult(
                layer="L3 (IP Pool & Conflict)",
                name="Subnet / DHCP Pool Capacity",
                status=CheckStatus.WARN,
                summary=f"⚠️ มีอุปกรณ์ออนไลน์หนาแน่นในวง {subnet}: ใช้ไปแล้ว {active}/{total} IPs ({pct}%), ว่าง {free} IPs",
                details="หมายเหตุ: หาก DHCP Server ตั้งช่วงแจก IP (DHCP Pool) ไว้แคบกว่าทั้งวง (เช่น แจกแค่ 100 เบอร์) ช่วง DHCP อาจเต็มแล้ว!",
                recommendation=(
                    "หากมีเครื่องเสียบสายแล้วไม่ได้ IP ทั้งที่ในวงยังเหลือที่ว่าง:\n"
                    "1. ตรวจสอบขนาด **DHCP Scope / Pool Range** บน DHCP Server ว่าตั้งช่วงเริ่ม-สิ้นสุดแคบเกินไปหรือไม่\n"
                    "2. ล้างรายการ DHCP Lease ที่หมดอายุหรือค้างอยู่บน DHCP Server"
                ),
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L3 (IP Pool & Conflict)",
                name="Subnet / DHCP Pool Capacity",
                status=CheckStatus.PASS,
                summary=f"ความจุ IP ในวงแลน {subnet} ปกติ: ตรวจพบเครื่องออนไลน์ {active}/{total} IPs ({pct}%), เหลือว่าง {free} IPs",
                details=f"สแกนพบอุปกรณ์ที่ตอบสนองในวงแลนจำนวน {active} เครื่อง",
            )
        )

    # 2. ประเมินผลเรื่อง "คอมพิวเตอร์แย่งไอพีกัน (Network-Wide IP Conflict)"
    if dup_ips:
        conflict_list = [f"IP {ip} ถูกแย่งกันโดย MAC: {', '.join(macs)}" for ip, macs in dup_ips.items()]
        report.add_check(
            CheckResult(
                layer="L3 (IP Pool & Conflict)",
                name="Network-Wide IP Conflict Scan",
                status=CheckStatus.FAIL,
                summary=f"💥 ตรวจพบคอมพิวเตอร์แย่ง IP กันในวงแลน จำนวน {len(dup_ips)} เบอร์!",
                details=" | ".join(conflict_list),
                recommendation=(
                    "พบเครื่องในวงแลนใช้ IP ซ้ำกัน (ทำให้เน็ตของเครื่องคู่นั้นหลุดๆ ติดๆ สลับกัน):\n"
                    + "\n".join(f"• {item}" for item in conflict_list)
                    + "\nวิธีแก้: นำ MAC Address ด้านบนไปค้นหาเครื่องที่ตั้ง Static IP ซ้ำซ้อน หรือตั้ง DHCP Reservation แยกกัน"
                ),
            )
        )
    else:
        scan_method = "Active L2 ARP Scan + fping" if os.geteuid() == 0 else "Fast ICMP Sweep + Multi-pass ARP Flapping Check"
        report.add_check(
            CheckResult(
                layer="L3 (IP Pool & Conflict)",
                name="Network-Wide IP Conflict Scan",
                status=CheckStatus.PASS,
                summary=f"ไม่พบคอมพิวเตอร์แย่ง IP กันในวงแลน {subnet} (ทุก IP มี MAC Address ไม่ซ้ำกัน)",
                details=f"ตรวจสอบจาก {active} เครื่องที่ออนไลน์ด้วยวิธี: {scan_method}",
            )
        )

    # 3. แจ้งข้อมูลหากพบ 1 MAC ถือครองหลาย IP (Multi-IP MAC)
    if multi_macs:
        multi_list = [f"MAC {mac} ถือครอง IP: {', '.join(ips)}" for mac, ips in multi_macs.items()]
        report.add_check(
            CheckResult(
                layer="L3 (IP Pool & Conflict)",
                name="Multi-IP per MAC Check",
                status=CheckStatus.WARN,
                summary=f"ตรวจพบอุปกรณ์ที่ใช้ MAC Address เดียวแต่ถือครองหลาย IP จำนวน {len(multi_macs)} เครื่อง",
                details=" | ".join(multi_list[:3]),
                recommendation=(
                    "อาจเป็นเซิร์ฟเวอร์ที่ผูก Virtual IP (Secondary IP), อุปกรณ์ทำ Proxy ARP, "
                    "หรือเครื่องที่สลับเปลี่ยน IP ไปมาเพิ่งเสร็จ"
                ),
            )
        )
