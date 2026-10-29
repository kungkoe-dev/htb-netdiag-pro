"""
Root Cause Engine & Full/Targeted OSI Diagnostic Pipeline
ประมวลผลผลการตรวจเช็กตามโหมดที่เลือก:
  - all:        ตรวจเช็กครบทุกจุด (Full OSI Layer 1 - Layer 7)
  - cable:      เช็กปัญหาสายแลนและการ์ดแลน (Layer 1)
  - switch:     เช็กปัญหาสวิตช์, VLAN, 802.1X และ ARP (Layer 2)
  - ip:         เช็กปัญหาไม่ได้รับ IP / DHCP / ปิง Gateway ไม่เจอ (Layer 3)
  - internet:   เช็กปัญหาเล่นเน็ตไม่ได้ / เว็บไม่ขึ้น / DNS / Captive Portal (Layer 4-7)
  - conflict:   เช็กไอพีเต็ม (DHCP Exhaustion) & คอมพิวเตอร์แย่งไอพีกันในวงแลน
  - bottleneck: วิเคราะห์จุดคอขวดทำไมเน็ตช้า/กระตุก (3-Tier Latency, Jitter & Hop-by-Hop)
  - target:     ทดสอบเจาะจงเครื่องปลายทาง Server/Printer & เช็กพอร์ต Firewall
  - dhcp:       ตรวจจับ Rogue DHCP & วิเคราะห์ข้อมูล DHCP Server เชิงลึก
  - freeip:     เช็กรายการ IP ว่างทั้งหมด & แยกโซน IP ที่ไม่ถูกแจกด้วย DHCP (Static IP Zone)
"""

from typing import List, Optional

from . import CheckStatus, InterfaceDiagReport
from .cyber_recon import run_cyber_recon_checks
from .free_ip_finder import run_free_ip_and_dhcp_scope_checks
from .ip_conflict_scanner import run_ip_exhaustion_and_conflict_checks
from .layer1_physical import classify_interface, run_layer1_checks
from .layer2_datalink import run_layer2_checks
from .layer3_network import run_layer3_checks
from .layer4_7_internet import run_layer4_7_checks
from .path_bottleneck import run_bottleneck_checks
from .rogue_dhcp_checker import run_dhcp_audit_checks
from .target_port_checker import run_target_and_port_checks
from .traffic_analyzer import run_traffic_and_storm_checks


MODE_LABELS = {
    "all": "ตรวจเช็กครบทุกจุด (Full OSI Layer 1 - Layer 7)",
    "cable": "เช็กปัญหาสายแลนและการ์ดแลน (Layer 1: Physical & Cable)",
    "switch": "เช็กปัญหาสวิตช์, VLAN, 802.1X และ ARP (Layer 2: Data Link)",
    "ip": "เช็กปัญหาไม่ได้รับ IP / DHCP / ปิง Gateway ไม่เจอ (Layer 3: Network)",
    "internet": "เช็กปัญหาเล่นเน็ตไม่ได้ / เว็บไม่ขึ้น / DNS / Captive Portal (Layer 4-7)",
    "conflict": "เช็กไอพีเต็ม (DHCP Exhaustion) & คอมพิวเตอร์แย่งไอพีกันในวงแลน (IP Conflict Scan)",
    "bottleneck": "วิเคราะห์จุดคอขวดทำไมเน็ตช้า/กระตุก (3-Tier Latency, Jitter & Traceroute)",
    "target": "ทดสอบเจาะจงเครื่องปลายทาง Server/Printer & สแกนพอร์ตเชิงลึกด้วย HTB Tools",
    "dhcp": "ตรวจจับ Rogue DHCP & วิเคราะห์ข้อมูล DHCP Server เชิงลึก",
    "freeip": "เช็กรายการ IP ว่าง (Free IP List) & โซนปลอดภัยที่ไม่ถูกแจกด้วย DHCP (Static IP Zone)",
    "recon": "เรดาร์สแกนทรัพย์สินเครือข่าย ชื่อเครื่อง และยี่ห้ออุปกรณ์ (HTB Cyber Asset Radar)",
    "traffic": "วิเคราะห์ความเร็วทราฟฟิกสด & ตรวจจับ Broadcast Storm ในสายแลน (Live Traffic & Storm)",
}


def synthesize_root_cause(report: InterfaceDiagReport, mode: str = "all") -> None:
    """สรุปสถานะภาพรวม (Overall Status), สาเหตุหลัก (Root Causes) และแผนการแก้ไข (Action Plan)"""
    fails = [c for c in report.checks if c.status == CheckStatus.FAIL]
    warns = [c for c in report.checks if c.status == CheckStatus.WARN]

    if fails:
        report.overall_status = CheckStatus.FAIL
    elif warns:
        report.overall_status = CheckStatus.WARN
    else:
        report.overall_status = CheckStatus.PASS

    root_causes: List[str] = []
    actions: List[str] = []

    for c in fails:
        root_causes.append(f"[{c.layer}] {c.summary}")
        if c.recommendation and c.recommendation not in actions:
            actions.append(c.recommendation)

    for c in warns:
        root_causes.append(f"[{c.layer} - คำเตือน] {c.summary}")
        if c.recommendation and c.recommendation not in actions:
            actions.append(c.recommendation)

    mode_desc = MODE_LABELS.get(mode, mode)
    if not root_causes:
        root_causes.append(
            f"✅ ผลการตรวจ [{mode_desc}] บนพอร์ต {report.interface} ปกติสมบูรณ์ ไม่พบปัญหาใดๆ"
        )

    report.root_causes = root_causes
    report.action_plan = actions


def diagnose_interface(
    iface: str,
    listen_lldp: bool = False,
    mode: str = "all",
    target_host: Optional[str] = None,
    custom_ports: Optional[List[int]] = None,
    custom_dhcp_range: Optional[str] = None,
) -> InterfaceDiagReport:
    """รันการตรวจสอบสำหรับ Interface ตามโหมดที่เลือก"""
    if_type = classify_interface(iface)
    report = InterfaceDiagReport(interface=iface, if_type=if_type)
    report.raw_context["diag_mode"] = mode

    # Layer 1 ต้องเช็กเสมอ เพราะถ้าสายไม่เสียบ Layer อื่นจะทำงานไม่ได้
    l1_ok = run_layer1_checks(report)
    if mode == "cable" or not l1_ok:
        synthesize_root_cause(report, mode=mode)
        return report

    if mode == "conflict":
        run_ip_exhaustion_and_conflict_checks(report)
        synthesize_root_cause(report, mode=mode)
        return report

    if mode == "bottleneck":
        run_bottleneck_checks(report)
        synthesize_root_cause(report, mode=mode)
        return report

    if mode == "target":
        run_target_and_port_checks(report, target_host=target_host, custom_ports=custom_ports)
        synthesize_root_cause(report, mode=mode)
        return report

    if mode == "dhcp":
        run_dhcp_audit_checks(report)
        synthesize_root_cause(report, mode=mode)
        return report

    if mode == "freeip":
        run_free_ip_and_dhcp_scope_checks(report, custom_dhcp_range=custom_dhcp_range)
        synthesize_root_cause(report, mode=mode)
        return report

    if mode == "recon":
        run_cyber_recon_checks(report)
        synthesize_root_cause(report, mode=mode)
        return report

    if mode == "traffic":
        run_traffic_and_storm_checks(report)
        synthesize_root_cause(report, mode=mode)
        return report

    # Layer 2
    if mode in ("all", "switch", "ip"):
        run_layer2_checks(report, listen_lldp=listen_lldp or (mode == "switch"))
        if mode == "switch":
            synthesize_root_cause(report, mode=mode)
            return report

    # Layer 3
    if mode in ("all", "ip", "internet"):
        if mode == "internet" and "nmcli" not in report.raw_context:
            from .layer2_datalink import get_nmcli_device_info
            report.raw_context["nmcli"] = get_nmcli_device_info(iface)
        l3_ok = run_layer3_checks(report)
        if mode == "ip" or not l3_ok:
            synthesize_root_cause(report, mode=mode)
            return report

    # Layer 4-7
    if mode in ("all", "internet"):
        run_layer4_7_checks(report)

    synthesize_root_cause(report, mode=mode)
    return report
