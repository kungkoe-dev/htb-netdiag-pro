"""
DHCP Server Deep Audit & Rogue DHCP Hunter
วิเคราะห์ข้อมูลสัญญาเช่า DHCP เชิงลึก (DHCP Server ID, DHCP Relay/IP Helper, Lease Time, Domain, Options)
และตรวจจับ Rogue DHCP Server (กรณีมีคนนำ Router บ้านมาเสียบแจก IP ซ้อนในวงแลนองค์กร)
"""

import ipaddress
import os
import re
import subprocess
from typing import Any, Dict, List

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .layer2_datalink import get_nmcli_device_info
from .layer3_network import get_ip_addresses, ping_host


def parse_nmcli_dhcp_options(nm_info: Dict[str, str]) -> Dict[str, str]:
    """แปลงค่า DHCP4.OPTION[x] จาก nmcli เป็น Dictionary ที่อ่านง่าย"""
    opts: Dict[str, str] = {}
    for k, v in nm_info.items():
        if k.startswith("DHCP4.OPTION") and "=" in v:
            opt_k, opt_v = v.split("=", 1)
            opts[opt_k.strip()] = opt_v.strip()
    return opts


def format_lease_duration(seconds_str: str) -> str:
    """แปลงวินาทีเป็นข้อความชั่วโมง/วัน"""
    if not seconds_str.isdigit():
        return seconds_str or "Unknown"
    sec = int(seconds_str)
    if sec >= 86400:
        days = round(sec / 86400, 1)
        return f"{sec:,} วินาที (~{days} วัน)"
    elif sec >= 3600:
        hours = round(sec / 3600, 1)
        return f"{sec:,} วินาที (~{hours} ชั่วโมง)"
    elif sec >= 60:
        mins = round(sec / 60, 1)
        return f"{sec:,} วินาที (~{mins} นาที)"
    return f"{sec} วินาที"


def probe_active_dhcp_servers_root(iface: str, timeout_sec: int = 6) -> List[Dict[str, str]]:
    """
    เมื่อรันด้วย sudo จะใช้ nmap broadcast-dhcp-discover ส่งแพ็กเกจ DHCP Discover
    เพื่อตรวจว่ามี DHCP Server กี่ตัวที่ตอบกลับมาในวงแลน
    """
    servers: List[Dict[str, str]] = []
    if os.geteuid() != 0:
        return servers
    try:
        proc = subprocess.run(
            ["nmap", "--script", "broadcast-dhcp-discover", "-e", iface],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        out = proc.stdout
        current: Dict[str, str] = {}
        for line in out.splitlines():
            if "IP Offered:" in line:
                current["ip_offered"] = line.split("IP Offered:", 1)[1].strip()
            elif "Server Identifier:" in line:
                current["server_id"] = line.split("Server Identifier:", 1)[1].strip()
            elif "Router:" in line:
                current["router"] = line.split("Router:", 1)[1].strip()
            elif "Domain Name:" in line:
                current["domain"] = line.split("Domain Name:", 1)[1].strip()
            if "Server Identifier:" in line and current.get("server_id"):
                servers.append(dict(current))
                current = {}
    except Exception:
        pass
    return servers


def run_dhcp_audit_checks(report: InterfaceDiagReport) -> None:
    """
    ตรวจสอบรายละเอียดสัญญาเช่า DHCP และตรวจหา Rogue DHCP Server
    """
    iface = report.interface
    nm_info = report.raw_context.get("nmcli") or get_nmcli_device_info(iface)
    dhcp_opts = parse_nmcli_dhcp_options(nm_info)
    ipv4_list, _ = get_ip_addresses(iface)

    server_id = dhcp_opts.get("dhcp_server_identifier", "")
    offered_ip = dhcp_opts.get("ip_address", "") or (ipv4_list[0].get("local", "") if ipv4_list else "")
    subnet_mask = dhcp_opts.get("subnet_mask", "")
    router_gw = dhcp_opts.get("routers", "") or nm_info.get("IP4.GATEWAY", "")
    dns_str = dhcp_opts.get("domain_name_servers", "")
    domain_name = dhcp_opts.get("domain_name", "") or nm_info.get("IP4.DOMAIN[1]", "")
    lease_raw = dhcp_opts.get("dhcp_lease_time", "")
    lease_human = format_lease_duration(lease_raw)

    # ตรวจสอบว่า DHCP Server อยู่คนละวงแลนกับเครื่องเราหรือไม่ (แสดงว่าใช้งานผ่าน DHCP Relay / IP Helper)
    is_relay = False
    if server_id and offered_ip and ipv4_list:
        try:
            plen = ipv4_list[0].get("prefixlen", 24)
            my_net = ipaddress.ip_interface(f"{offered_ip}/{plen}").network
            srv_ip = ipaddress.ip_address(server_id)
            if srv_ip not in my_net:
                is_relay = True
        except ValueError:
            pass

    # ทดสอบปิงไปยัง DHCP Server (หากทราบเลข IP)
    srv_reachable = None
    srv_avg_ms = None
    if server_id:
        p_res = ping_host(server_id, iface=iface, count=2, timeout_sec=1)
        srv_reachable = p_res["reachable"]
        srv_avg_ms = p_res["avg_ms"]

    # หากรันด้วย sudo ให้ส่ง Broadcast DHCP Discover เพื่อล่า Rogue DHCP
    active_offers = probe_active_dhcp_servers_root(iface)

    audit_data: Dict[str, Any] = {
        "has_dhcp": bool(dhcp_opts or server_id),
        "server_id": server_id or "ไม่พบ (Static IP หรือยังไม่ได้รับ Lease)",
        "offered_ip": offered_ip or "-",
        "subnet_mask": subnet_mask or "-",
        "router": router_gw or "-",
        "dns_servers": dns_str or "-",
        "domain_name": domain_name or "-",
        "lease_time": lease_human,
        "is_dhcp_relay": is_relay,
        "server_reachable": srv_reachable,
        "server_latency_ms": srv_avg_ms,
        "active_offers": active_offers,
    }
    report.raw_context["dhcp_audit"] = audit_data

    if not ipv4_list and not dhcp_opts:
        report.add_check(
            CheckResult(
                layer="L3-L7 (DHCP Audit)",
                name="DHCP Lease & Server Status",
                status=CheckStatus.FAIL,
                summary=f"พอร์ต {iface} ไม่ได้รับข้อมูลสัญญาเช่า DHCP (No DHCP Lease)",
                details="ไม่พบทั้ง IPv4 Address และ DHCP4 Options ในระบบ",
                recommendation=(
                    "1. พอร์ต Switch อาจอยู่ใน VLAN ที่ไม่ได้ตั้งค่า IP Helper Address (DHCP Relay)\n"
                    "2. DHCP Server ต้นทางอาจล่ม หรือ IP Pool เต็ม\n"
                    f"3. หากต้องการส่งแพ็กเกจค้นหา DHCP Server สดๆ ให้รัน: sudo ./netdiag.py --mode dhcp -i {iface}"
                ),
            )
        )
        return

    # 1. ประเมินความถูกต้องของ DHCP Server (ตรวจจับ Router บ้านแปลกปลอมในเครือข่ายองค์กร)
    is_suspicious_rogue = False
    if offered_ip.startswith(("192.168.0.", "192.168.1.", "192.168.100.")) and not domain_name:
        is_suspicious_rogue = True

    if is_suspicious_rogue:
        report.add_check(
            CheckResult(
                layer="L3-L7 (DHCP Audit)",
                name="Rogue DHCP Heuristic Check",
                status=CheckStatus.WARN,
                summary=f"⚠️ ได้รับ IP วง Router บ้าน ({offered_ip}) จาก DHCP Server {server_id} (ไม่มีชื่อโดเมนองค์กร)!",
                details=f"Server={server_id}, Gateway={router_gw}, Domain=None",
                recommendation=(
                    "มีความเป็นไปได้สูงที่มีคนนำ Router/Access Point บ้านมาเสียบสายแลนเข้าช่อง LAN แจก IP ทับวงองค์กร (Rogue DHCP)!\n"
                    f"แนะนำให้เช็ก MAC Address ของ {server_id} ในตาราง ARP เพื่อตามหาพอร์ต Switch ต้นทาง"
                ),
            )
        )
    else:
        relay_text = (
            f"ผ่าน DHCP Relay (IP Helper ที่ Gateway {router_gw})"
            if is_relay
            else "อยู่ในวงแลนเดียวกัน (Local Broadcast)"
        )
        report.add_check(
            CheckResult(
                layer="L3-L7 (DHCP Audit)",
                name="DHCP Server Configuration",
                status=CheckStatus.PASS,
                summary=f"ได้รับ IP จาก DHCP Server มาตรฐาน: {server_id} ({relay_text})",
                details=f"Domain={domain_name or '-'}, Lease Time={lease_human}, DNS={dns_str}",
            )
        )

    # 2. ตรวจสอบการติดต่อกับ DHCP Server
    if server_id:
        if srv_reachable:
            report.add_check(
                CheckResult(
                    layer="L3-L7 (DHCP Audit)",
                    name="DHCP Server Reachability",
                    status=CheckStatus.PASS,
                    summary=f"ติดต่อ DHCP Server ({server_id}) ได้ปกติ (Latency เฉลี่ย {srv_avg_ms} ms) พร้อมต่ออายุ Lease อัตโนมัติ",
                )
            )
        else:
            report.add_check(
                CheckResult(
                    layer="L3-L7 (DHCP Audit)",
                    name="DHCP Server Reachability",
                    status=CheckStatus.WARN,
                    summary=f"ไม่พบการตอบ Ping จาก DHCP Server ({server_id}) โดยตรง",
                    details="DHCP Server อาจบล็อก ICMP หรือรับเฉพาะแพ็กเกจที่ส่งผ่าน DHCP Relay ของ Switch เท่านั้น",
                )
            )

    # 3. ตรวจสอบผลการกวาดหา Rogue DHCP (กรณีรัน sudo)
    unique_srv_ids = {o.get("server_id") for o in active_offers if o.get("server_id")}
    if len(unique_srv_ids) > 1:
        report.add_check(
            CheckResult(
                layer="L3-L7 (DHCP Audit)",
                name="Active Rogue DHCP Discovery",
                status=CheckStatus.FAIL,
                summary=f"🚨 ตรวจพบ DHCP Server ตอบกลับซ้อนกัน {len(unique_srv_ids)} ตัวในวงแลนเดียวกัน! ({', '.join(unique_srv_ids)})",
                recommendation="มี Rogue DHCP แจก IP แข่งกันในระบบ ต้องเปิดฟีเจอร์ DHCP Snooping บน Switch เพื่อบล็อกพอร์ตเถื่อนทันที",
            )
        )
    elif len(unique_srv_ids) == 1:
        report.add_check(
            CheckResult(
                layer="L3-L7 (DHCP Audit)",
                name="Active Rogue DHCP Discovery",
                status=CheckStatus.PASS,
                summary=f"ทดสอบส่ง Broadcast DHCP Discover แล้ว พบ DHCP Server ที่ถูกต้องเพียงตัวเดียว ({next(iter(unique_srv_ids))})",
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L3-L7 (DHCP Audit)",
                name="Rogue DHCP Security Status",
                status=CheckStatus.PASS,
                summary="ไม่พบความผิดปกติของสัญญาเช่า DHCP ปัจจุบัน (หากต้องการส่ง Broadcast ล่า Rogue DHCP สดๆ ให้รันด้วย sudo)",
            )
        )
