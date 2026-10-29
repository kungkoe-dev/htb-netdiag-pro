"""
Layer 3 - Network Layer (IP Configuration, DHCP Analysis, Same-Subnet Conflict, IP Conflict & Gateway Reachability)
ตรวจสอบการได้รับ IP Address, วิเคราะห์ปัญหา DHCP, เช็กวงแลนซ้อนกับ Wi-Fi, เช็ก IP ชนกัน และทดสอบปิงหา Default Gateway
"""

import ipaddress
import json
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from . import CheckResult, CheckStatus, InterfaceDiagReport


def get_ip_addresses(iface: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """ดึงรายการ IPv4 และ IPv6 ของ Interface ด้วย ip -j addr"""
    ipv4_list: List[Dict[str, Any]] = []
    ipv6_list: List[Dict[str, Any]] = []
    try:
        proc = subprocess.run(
            ["ip", "-j", "addr", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        data = json.loads(proc.stdout)
        if data and isinstance(data, list):
            for addr_info in data[0].get("addr_info", []):
                family = addr_info.get("family")
                if family == "inet":
                    ipv4_list.append(addr_info)
                elif family == "inet6":
                    ipv6_list.append(addr_info)
    except Exception:
        pass
    return ipv4_list, ipv6_list


def get_all_interfaces_ipv4() -> Dict[str, List[str]]:
    """ดึง IPv4 Address (พร้อม prefix) ของทุก Interface ในเครื่อง เพื่อเช็กวงแลนซ้อนกัน"""
    result: Dict[str, List[str]] = {}
    try:
        proc = subprocess.run(
            ["ip", "-j", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        data = json.loads(proc.stdout)
        for dev in data:
            ifname = dev.get("ifname", "")
            if ifname == "lo":
                continue
            cidrs: List[str] = []
            for addr_info in dev.get("addr_info", []):
                if addr_info.get("family") == "inet":
                    local = addr_info.get("local")
                    plen = addr_info.get("prefixlen")
                    if local and plen is not None:
                        cidrs.append(f"{local}/{plen}")
            if cidrs:
                result[ifname] = cidrs
    except Exception:
        pass
    return result


def find_same_subnet_interfaces(iface: str, cidr: str) -> List[Tuple[str, str]]:
    """ตรวจสอบว่ามี Interface อื่นในเครื่องที่ต่อเข้า Subnet เดียวกันหรือไม่"""
    overlaps: List[Tuple[str, str]] = []
    try:
        my_net = ipaddress.ip_interface(cidr).network
    except ValueError:
        return overlaps

    all_v4 = get_all_interfaces_ipv4()
    for other_if, cidrs in all_v4.items():
        if other_if == iface:
            continue
        for other_cidr in cidrs:
            try:
                other_net = ipaddress.ip_interface(other_cidr).network
                if my_net.overlaps(other_net):
                    overlaps.append((other_if, other_cidr))
            except ValueError:
                pass
    return overlaps


def get_interface_routes(iface: str) -> List[Dict[str, Any]]:
    """ดึง Routing Table ของ Interface"""
    try:
        proc = subprocess.run(
            ["ip", "-j", "route", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return json.loads(proc.stdout)
    except Exception:
        return []


def check_duplicate_ip(iface: str, ip_addr: str) -> Optional[str]:
    """
    ตรวจสอบว่ามีเครื่องอื่นใช้ IP ซ้ำกับเราหรือไม่ (Duplicate Address Detection ด้วย arping)
    คืนค่า MAC Address ของเครื่องที่ชน หากพบว่าซ้ำ
    """
    if os.geteuid() != 0:
        return None
    try:
        proc = subprocess.run(
            ["arping", "-D", "-I", iface, "-c", "2", "-w", "2", ip_addr],
            capture_output=True,
            text=True,
            timeout=4,
        )
        if proc.returncode == 1:
            m = re.search(r"\[([0-9a-fA-F:]{17})\]", proc.stdout)
            return m.group(1) if m else "Unknown MAC"
    except Exception:
        pass
    return None


def ping_host(target: str, iface: Optional[str] = None, count: int = 3, timeout_sec: int = 2) -> Dict[str, Any]:
    """รันคำสั่ง ping และแปลงผลลัพธ์ (Packet Loss %, Avg Latency ms)"""
    cmd = ["ping", "-n", "-c", str(count), "-W", str(timeout_sec)]
    if iface:
        cmd.extend(["-I", iface])
    cmd.append(target)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=count * timeout_sec + 3)
        out = proc.stdout
        loss_pct = 100.0
        avg_ms = None

        m_loss = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", out)
        if m_loss:
            loss_pct = float(m_loss.group(1))

        m_rtt = re.search(r"=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)\s*ms", out)
        if m_rtt:
            avg_ms = float(m_rtt.group(2))

        return {
            "reachable": loss_pct < 100.0,
            "loss_pct": loss_pct,
            "avg_ms": avg_ms,
            "raw": out.strip(),
        }
    except Exception as e:
        return {
            "reachable": False,
            "loss_pct": 100.0,
            "avg_ms": None,
            "raw": str(e),
        }


def run_layer3_checks(report: InterfaceDiagReport) -> bool:
    """
    รันการตรวจสอบ Layer 3 (IP, DHCP, Same-Subnet Conflict, Default Gateway)
    คืนค่า True หากมี IP และติดต่อ Default Gateway ได้สำเร็จ
    """
    iface = report.interface
    ipv4_list, ipv6_list = get_ip_addresses(iface)
    report.raw_context["ipv4"] = ipv4_list
    report.raw_context["ipv6"] = ipv6_list

    nm_info = report.raw_context.get("nmcli", {})
    nm_state = nm_info.get("GENERAL.STATE", "")
    dhcp_server = ""
    dns_servers: List[str] = []
    for k, v in nm_info.items():
        if "dhcp_server_identifier" in v:
            dhcp_server = v.split("=", 1)[-1].strip()
        if k.startswith("IP4.DNS"):
            dns_servers.append(v)

    report.raw_context["dhcp_server"] = dhcp_server
    report.raw_context["dns_servers"] = dns_servers

    # 1. Check IPv4 Address Assignment & DHCP Status
    if not ipv4_list:
        link_local_v6 = [a.get("local") for a in ipv6_list if a.get("scope") == "link"]
        v6_note = f"พบเฉพาะ IPv6 Link-Local ({link_local_v6[0]})" if link_local_v6 else "ไม่มีทั้ง IPv4 และ IPv6"

        # ตรวจจับอาการ Ghost Connection (NetworkManager ขึ้นว่า connected และจำค่า DNS ไว้ แต่ IPv4 บนพอร์ตหายไป)
        if "connected" in nm_state.lower() and dns_servers:
            report.add_check(
                CheckResult(
                    layer="L3 (Network)",
                    name="IPv4 / DHCP Address Assignment",
                    status=CheckStatus.FAIL,
                    summary=f"พอร์ต {iface} เคยเชื่อมต่อสำเร็จ (มี DNS {', '.join(dns_servers)} ค้างอยู่) แต่ปัจจุบัน IPv4 Address หลุดหายไป!",
                    details=f"NM State={nm_state}, {v6_note}",
                    recommendation=(
                        "อาการนี้เกิดจาก IPv4 ถูกลบออกหรือ DHCP Lease หลุดหลังจากเชื่อมต่อไปแล้ว:\n"
                        "1. สัญญาณ DHCP Renew อาจไม่ผ่าน หรือชนกับพอร์ตอื่นที่อยู่วงเดียวกัน\n"
                        "2. มีการสั่งลบ IP/Route ออกด้วยคำสั่ง ip addr/route หรือ DHCP Server ปฏิเสธการต่ออายุ (DHCP NAK)\n"
                        f"💡 หากต้องการขอ IP ใหม่ให้รัน: sudo nmcli device reapply {iface}"
                    ),
                )
            )
            return False

        report.add_check(
            CheckResult(
                layer="L3 (Network)",
                name="IPv4 / DHCP Address Assignment",
                status=CheckStatus.FAIL,
                summary=f"พอร์ต {iface} ไม่ได้รับ IPv4 Address!",
                details=v6_note,
                recommendation=(
                    "สาเหตุที่เสียบสายติดไฟแล้วแต่ไม่ได้รับ IP (DHCP Timeout):\n"
                    "1. **DHCP Server ในระบบล่ม หรือ IP ใน Pool เต็มหมดแล้ว**\n"
                    "2. พอร์ต Switch ต้นทางตั้งค่า **VLAN ผิด** (ไปอยู่ใน VLAN ที่ไม่มี DHCP Server หรือลืมตั้ง IP Helper/DHCP Relay)\n"
                    "3. พอร์ต Switch เปิด **Spanning Tree (STP)** แบบไม่ได้เปิด PortFast ทำให้พอร์ตบล็อกแพ็กเกจช่วง 30 วินาทีแรก\n"
                    "4. เครือข่ายนี้เป็นวง **Static IP** (ไม่ได้เปิดแจก DHCP อัตโนมัติ ต้องตั้งค่า IP/Subnet/Gateway เอง)\n"
                    f"💡 ทดลองขอ IP ใหม่ด้วยคำสั่ง: sudo nmcli device reapply {iface} หรือ sudo dhclient -v {iface}"
                ),
            )
        )
        return False

    primary_v4 = ipv4_list[0]
    ip_str = primary_v4.get("local", "")
    prefix_len = primary_v4.get("prefixlen", "")
    is_dynamic = primary_v4.get("dynamic", False)
    cidr_str = f"{ip_str}/{prefix_len}"

    report.raw_context["primary_ipv4"] = ip_str
    report.raw_context["prefixlen"] = prefix_len

    # ตรวจสอบ APIPA (169.254.x.x)
    if ip_str.startswith("169.254."):
        report.add_check(
            CheckResult(
                layer="L3 (Network)",
                name="IPv4 / DHCP Address Assignment",
                status=CheckStatus.FAIL,
                summary=f"ได้รับ IP แบบ APIPA ({cidr_str}) แปลว่าติดต่อ DHCP Server ไม่ได้!",
                details="เครื่องสุ่ม IP 169.254.x.x ขึ้นมาเองเพราะส่ง DHCP Discover ไปแล้วไม่มีใครตอบ",
                recommendation=(
                    "เครื่องพยายามขอ IP แล้วแต่ไม่มี DHCP Server ตอบกลับ:\n"
                    "1. เช็กว่าสายแลนเสียบเข้าพอร์ต VLAN ที่ถูกต้องหรือไม่\n"
                    "2. เช็กว่า DHCP Server / Router ต้นทางเปิดทำงานอยู่หรือไม่\n"
                    "3. หากเป็นวงแลนที่ไม่มี DHCP ให้ตั้งค่า Static IP ด้วยตัวเอง"
                ),
            )
        )
        return False

    mode_str = f"DHCP (Server: {dhcp_server})" if (is_dynamic or dhcp_server) else "Static / Manual"
    report.add_check(
        CheckResult(
            layer="L3 (Network)",
            name="IPv4 / DHCP Address Assignment",
            status=CheckStatus.PASS,
            summary=f"ได้รับ IPv4 Address เรียบร้อย: {cidr_str} ({mode_str})",
            details=f"Broadcast={primary_v4.get('broadcast', '-')}, DNS={', '.join(dns_servers) if dns_servers else 'None'}",
        )
    )

    # 2. Check Same-Subnet Multi-Interface Conflict (เช่น เสียบสายแลนและต่อ Wi-Fi วงเดียวกัน)
    overlaps = find_same_subnet_interfaces(iface, cidr_str)
    if overlaps:
        overlap_desc = ", ".join(f"{o_if} ({o_cidr})" for o_if, o_cidr in overlaps)
        report.add_check(
            CheckResult(
                layer="L3 (Network)",
                name="Same-Subnet Multi-Interface Check",
                status=CheckStatus.WARN,
                summary=f"พอร์ต {iface} ({cidr_str}) เชื่อมต่ออยู่วงแลน (Subnet) เดียวกันกับพอร์ต {overlap_desc}!",
                details="การต่อ 2 พอร์ต (เช่น LAN + Wi-Fi) เข้าวงเดียวกันพร้อมกัน อาจทำให้เกิด ARP Flux หรือแพ็กเกจวิ่งผิดพอร์ต",
                recommendation=(
                    "เมื่อเชื่อมต่อทั้งสายแลนและ Wi-Fi ในวงเดียวกัน:\n"
                    "1. Linux Kernel อาจเลือกใช้ Local Subnet Route ของพอร์ตใดพอร์ตหนึ่งเพียงพอร์ตเดียว\n"
                    "2. หากต้องการทดสอบหรือใช้งานสายแลนอย่างเต็มประสิทธิภาพ แนะนำให้ปิด Wi-Fi ชั่วคราว หรือแยก VLAN"
                ),
            )
        )

    # 3. Check Duplicate IP (IP Conflict)
    dup_mac = check_duplicate_ip(iface, ip_str)
    if dup_mac:
        report.add_check(
            CheckResult(
                layer="L3 (Network)",
                name="IP Conflict (Duplicate IP)",
                status=CheckStatus.FAIL,
                summary=f"ตรวจพบ IP ชนกันในวงแลน! มีอุปกรณ์อื่น ({dup_mac}) กำลังใช้ IP {ip_str} อยู่",
                details=f"Conflicting MAC Address: {dup_mac}",
                recommendation=(
                    "เมื่อเกิด IP ชนกัน จะทำให้เน็ตหลุดๆ ติดๆ หรือใช้งานไม่ได้เลย:\n"
                    "1. หากตั้ง Static IP ไว้ ให้เปลี่ยนเป็นเลขอื่นที่ไม่ซ้ำ\n"
                    "2. หากรับมาจาก DHCP แปลว่ามีคนตั้ง Static IP ทับช่วง DHCP Pool หรือมี Rogue DHCP แจกซ้ำ"
                ),
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L3 (Network)",
                name="IP Conflict Check",
                status=CheckStatus.PASS,
                summary=f"ไม่พบปัญหา IP {ip_str} ชนกับเครื่องอื่นในระบบ",
                details="Verified via ARP/DAD" if os.geteuid() == 0 else "Checked via local neighbor state (รัน sudo เพื่อทำ Active ARP Probe)",
            )
        )

    # 4. Check Default Gateway & Subnet Routing Table
    routes = get_interface_routes(iface)
    default_routes = [r for r in routes if r.get("dst") == "default"]
    subnet_routes = [r for r in routes if r.get("dst") != "default" and r.get("scope") == "link"]
    gateway = default_routes[0].get("gateway") if default_routes else nm_info.get("IP4.GATEWAY", "")

    report.raw_context["gateway"] = gateway

    if not subnet_routes:
        report.add_check(
            CheckResult(
                layer="L3 (Network)",
                name="Local Subnet Route Check",
                status=CheckStatus.WARN,
                summary=f"ไม่พบเส้นทาง Local Subnet Route (scope link) บนพอร์ต {iface}!",
                details="อาจเกิดจากพอร์ตอื่นที่อยู่วงเดียวกันแย่งถือ Subnet Route หรือถูกลบ Route ออก",
                recommendation=f"ทำให้การปิงระบุพอร์ต (-I {iface}) หาเครื่องในวงเดียวกันหรือ Gateway ไม่ผ่าน",
            )
        )

    if not gateway or gateway == "--":
        report.add_check(
            CheckResult(
                layer="L3 (Network)",
                name="Default Gateway Configuration",
                status=CheckStatus.FAIL,
                summary=f"พอร์ต {iface} มี IP ({ip_str}) แต่ไม่มี Default Gateway!",
                details=f"Routes on {iface}: {len(routes)} entries, no default route",
                recommendation=(
                    "เมื่อไม่มี Default Gateway เครื่องจะคุยได้เฉพาะในวงแลนเดียวกัน แต่จะออกอินเทอร์เน็ตไม่ได้:\n"
                    "1. หากตั้งค่า Static IP ลืมใส่ช่อง Gateway หรือไม่?\n"
                    "2. หากรับจาก DHCP ให้เช็กการตั้งค่า Option 3 (Router/Gateway) บน DHCP Server"
                ),
            )
        )
        return False

    # 5. Ping Default Gateway
    gw_ping = ping_host(gateway, iface=iface, count=3, timeout_sec=1)
    report.raw_context["gateway_ping"] = gw_ping

    if not gw_ping["reachable"]:
        extra_hint = ""
        if overlaps and not subnet_routes:
            extra_hint = (
                f"\n💡 หมายเหตุสำคัญ: เนื่องจากพอร์ต {iface} อยู่วงเดียวกับ {overlaps[0][0]} และไม่มี Local Subnet Route "
                f"จึงทำให้คำสั่ง ping -I {iface} ส่งแพ็กเกจออกไปหา Gateway ไม่ได้ (แม้สายแลนจะปกติ)"
            )
        report.add_check(
            CheckResult(
                layer="L3 (Network)",
                name="Default Gateway Reachability",
                status=CheckStatus.FAIL,
                summary=f"ปิงไปหา Default Gateway ({gateway}) ผ่านพอร์ต {iface} ไม่สำเร็จ! (Packet Loss 100%)",
                details=f"Gateway IP: {gateway}",
                recommendation=(
                    "เครื่องมี IP แล้วแต่คุยกับ Router/Gateway ผ่านพอร์ตนี้ไม่ได้:\n"
                    "1. ตั้งค่า IP/Subnet/Gateway ผิดวง หรือพอร์ต Switch อยู่คนละ VLAN กับ Gateway\n"
                    "2. ตัว Router/Firewall ต้นทางล่ม หรือบล็อก ICMP\n"
                    "3. ชนกับพอร์ตอื่นในเครื่องที่เชื่อมต่อวงแลนเดียวกัน" + extra_hint
                ),
            )
        )
        return False
    elif gw_ping["loss_pct"] > 0 or (gw_ping["avg_ms"] and gw_ping["avg_ms"] > 50):
        report.add_check(
            CheckResult(
                layer="L3 (Network)",
                name="Default Gateway Reachability",
                status=CheckStatus.WARN,
                summary=f"ติดต่อ Gateway ({gateway}) ได้ แต่มีค่า Loss ({gw_ping['loss_pct']}%) หรือ Latency สูง ({gw_ping['avg_ms']} ms)",
                details="ปกติการปิง Gateway ในวงแลนควรใช้เวลา < 5 ms และ Loss 0%",
                recommendation="ตรวจสอบสายแลน, ปัญหา Loop ในระบบเครือข่าย (Broadcast Storm) หรือแบนด์วิดท์ในวงแลนเต็ม",
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L3 (Network)",
                name="Default Gateway Reachability",
                status=CheckStatus.PASS,
                summary=f"ติดต่อ Default Gateway ({gateway}) ได้ปกติ (Latency เฉลี่ย {gw_ping['avg_ms']} ms, Loss 0%)",
            )
        )

    return True
