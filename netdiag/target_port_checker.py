"""
Custom Target Host (Server / Printer / Website) & Service Port / Firewall Blocker Checker
ตรวจสอบเครื่องปลายทางที่ระบุ (หรือเซิร์ฟเวอร์หลักของระบบ) และสแกนพอร์ตบริการสำคัญเพื่อแยกแยะว่า:
  - OPEN: พอร์ตเปิดและพร้อมให้บริการ
  - CLOSED (Refused): ไปถึงเครื่องปลายทางแล้ว (ไม่ติด Firewall) แต่เครื่องไม่ได้รันบริการพอร์ตนี้
  - FILTERED (Timeout): ถูก Firewall บล็อกระหว่างทาง หรือเครื่องปลายทางดับ
"""

import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .htb_arsenal import (
    lookup_mac_vendor,
    run_nbtscan_lookup,
    run_nmap_service_banners,
    run_reverse_dns_ptr,
    run_sslscan_summary,
    run_whatweb_summary,
)
from .layer2_datalink import get_arp_neighbors, get_nmcli_device_info
from .layer3_network import get_interface_routes, ping_host


COMMON_ENTERPRISE_PORTS: Dict[int, str] = {
    21: "FTP (File Transfer)",
    22: "SSH (Linux/Network Admin)",
    23: "Telnet (Legacy CLI)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Server)",
    443: "HTTPS (Secure Web)",
    445: "SMB (Windows File Share)",
    3306: "MySQL / MariaDB Database",
    3389: "RDP (Windows Remote Desktop)",
    5432: "PostgreSQL Database",
    8080: "HTTP-Alt (Web App / Proxy)",
    9100: "JetDirect (Network Printer)",
}


def probe_tcp_port(ip_addr: str, port: int, timeout: float = 1.5) -> Dict[str, Any]:
    """
    ทดสอบเชื่อมต่อไปยังพอร์ต TCP เพื่อแยกแยะสถานะ:
      - OPEN: เชื่อมต่อสำเร็จ
      - CLOSED: เครื่องปลายทางตอบ RST (Connection Refused) แปลว่าไม่ติด Firewall แต่ไม่ได้เปิดพอร์ตนี้
      - FILTERED: เงียบหายจนหมดเวลา (Timeout) แปลว่าถูก Firewall ดรอปแพ็กเกจ หรือไปไม่ถึง
    """
    desc = COMMON_ENTERPRISE_PORTS.get(port, f"Custom TCP Port {port}")
    start = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        err = sock.connect_ex((ip_addr, port))
        elapsed_ms = round((time.monotonic() - start) * 1000.0, 1)
        if err == 0:
            return {"port": port, "service": desc, "state": "OPEN", "latency_ms": elapsed_ms}
        elif err == errno.ECONNREFUSED:
            return {"port": port, "service": desc, "state": "CLOSED", "latency_ms": elapsed_ms}
        else:
            return {"port": port, "service": desc, "state": "FILTERED", "latency_ms": None}
    except socket.timeout:
        return {"port": port, "service": desc, "state": "FILTERED", "latency_ms": None}
    except Exception:
        return {"port": port, "service": desc, "state": "FILTERED", "latency_ms": None}
    finally:
        sock.close()


def scan_target_ports(
    ip_addr: str,
    ports: Optional[List[int]] = None,
    timeout: float = 1.5,
) -> List[Dict[str, Any]]:
    """สแกนพอร์ตหลายพอร์ตพร้อมกันด้วย ThreadPoolExecutor"""
    target_ports = ports if ports else list(COMMON_ENTERPRISE_PORTS.keys())
    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(len(target_ports), 16)) as executor:
        future_map = {executor.submit(probe_tcp_port, ip_addr, p, timeout): p for p in target_ports}
        for fut in as_completed(future_map):
            results.append(fut.result())
    results.sort(key=lambda x: x["port"])
    return results


def run_target_and_port_checks(
    report: InterfaceDiagReport,
    target_host: Optional[str] = None,
    custom_ports: Optional[List[int]] = None,
) -> None:
    """
    ตรวจสอบเครื่องปลายทาง (Server / Printer / Gateway / Website) และสแกนพอร์ตบริการ
    """
    iface = report.interface
    nm_info = report.raw_context.get("nmcli") or get_nmcli_device_info(iface)
    routes = get_interface_routes(iface)
    default_routes = [r for r in routes if r.get("dst") == "default"]
    gateway = default_routes[0].get("gateway") if default_routes else nm_info.get("IP4.GATEWAY", "")

    # หากผู้ใช้ไม่ได้ระบุ target_host ให้เลือก DNS Server หลักขององค์กร หรือ Gateway เป็นเป้าหมายเริ่มต้น
    if not target_host:
        for k, v in nm_info.items():
            if k.startswith("IP4.DNS") and v:
                target_host = v
                break
        if not target_host:
            target_host = gateway if (gateway and gateway != "--") else "1.1.1.1"

    # 1. แปลงชื่อ Hostname เป็น IP (กรณีผู้ใช้ระบุเป็นชื่อโดเมน)
    resolved_ip = target_host
    try:
        resolved_ip = socket.gethostbyname(target_host)
    except Exception:
        report.add_check(
            CheckResult(
                layer="L4-L7 (Target & Ports)",
                name="Target Host Resolution",
                status=CheckStatus.FAIL,
                summary=f"ไม่สามารถแปลงชื่อเครื่องปลายทาง '{target_host}' เป็น IP Address ได้!",
                recommendation="ตรวจสอบว่าสะกดชื่อ Hostname/Domain ถูกต้อง หรือลองระบุเป็นเลข IP Address โดยตรง",
            )
        )
        return

    # 2. ทดสอบ Ping ไปยังเครื่องปลายทาง และเช็กตาราง ARP + MAC Vendor + ชื่อเครื่อง
    ping_res = ping_host(resolved_ip, iface=iface, count=3, timeout_sec=1)
    arp_mac = ""
    for n in get_arp_neighbors(iface):
        if n.get("ip") == resolved_ip and n.get("mac"):
            arp_mac = n["mac"]
            break

    mac_vendor = lookup_mac_vendor(arp_mac) if arp_mac else ""
    nbt_map = run_nbtscan_lookup(resolved_ip, timeout_sec=2)
    detected_hostname = nbt_map.get(resolved_ip) or run_reverse_dns_ptr(resolved_ip) or ""

    # 3. สแกนพอร์ตบริการบนเครื่องปลายทาง
    port_results = scan_target_ports(resolved_ip, ports=custom_ports, timeout=1.5)
    open_ports = [p for p in port_results if p["state"] == "OPEN"]
    closed_ports = [p for p in port_results if p["state"] == "CLOSED"]
    filtered_ports = [p for p in port_results if p["state"] == "FILTERED"]

    # 3.1 ดึงข้อมูลเชิงลึกด้วยเครื่องมือใน HTB OS (nmap -sV, whatweb, sslscan) เฉพาะเมื่อมีพอร์ตเปิดอยู่
    open_port_nums = [p["port"] for p in open_ports]
    nmap_banners = run_nmap_service_banners(resolved_ip, open_port_nums, timeout_sec=8) if open_port_nums else {}
    for p in port_results:
        p["banner"] = nmap_banners.get(p["port"], "")

    web_fingerprint = ""
    for wp in (80, 443, 8080, 8443):
        if wp in open_port_nums:
            web_fingerprint = run_whatweb_summary(resolved_ip, port=wp, timeout_sec=5)
            if web_fingerprint:
                break

    ssl_info: Dict[str, str] = {}
    for sp in (443, 8443):
        if sp in open_port_nums:
            ssl_info = run_sslscan_summary(resolved_ip, port=sp, timeout_sec=5)
            if ssl_info:
                break

    # เดาประเภทอุปกรณ์จากพอร์ตที่เปิด
    device_roles: List[str] = []
    open_port_set = set(open_port_nums)
    if 9100 in open_port_set:
        device_roles.append("🖨️ เครื่องปริ้นเตอร์เครือข่าย (Network Printer)")
    if 53 in open_port_set:
        device_roles.append("🖧 DNS Server / Domain Controller")
    if 80 in open_port_set or 443 in open_port_set or 8080 in open_port_set:
        device_roles.append("🌐 Web Server / หน้าเว็บจัดการอุปกรณ์")
    if 445 in open_port_set or 3389 in open_port_set:
        device_roles.append("🪟 Windows Server / PC (SMB/RDP)")
    if 22 in open_port_set:
        device_roles.append("🐧 Linux Server / Network Appliance (SSH)")
    if 3306 in open_port_set or 5432 in open_port_set:
        device_roles.append("🗄️ Database Server (MySQL/PostgreSQL)")

    report.raw_context["target_scan"] = {
        "target_input": target_host,
        "resolved_ip": resolved_ip,
        "arp_mac": arp_mac,
        "mac_vendor": mac_vendor,
        "detected_hostname": detected_hostname,
        "ping_reachable": ping_res["reachable"],
        "ping_avg_ms": ping_res["avg_ms"],
        "ping_loss_pct": ping_res["loss_pct"],
        "device_roles": device_roles,
        "ports": port_results,
        "web_fingerprint": web_fingerprint,
        "ssl_info": ssl_info,
    }

    host_reachable_any = ping_res["reachable"] or bool(open_ports) or bool(closed_ports) or bool(arp_mac)

    if not host_reachable_any:
        report.add_check(
            CheckResult(
                layer="L4-L7 (Target & Ports)",
                name=f"Target Reachability ({target_host})",
                status=CheckStatus.FAIL,
                summary=f"ไม่สามารถติดต่อเครื่องปลายทาง {target_host} ({resolved_ip}) ได้เลย (ทั้ง Ping และทุกพอร์ตเงียบสนิท)",
                details=f"IP={resolved_ip}, Ping Loss=100%, All {len(port_results)} ports FILTERED/Timeout",
                recommendation=(
                    f"สาเหตุที่ติดต่อเครื่อง {target_host} ({resolved_ip}) ไม่ได้:\n"
                    "1. เครื่องปลายทางปิดอยู่ สายแลนหลุด หรือเปลี่ยนเลข IP ไปแล้ว\n"
                    "2. มี Firewall กั้นระหว่างวงแลนของคุณกับวงของเครื่องปลายทาง (บล็อกทั้ง ICMP และ TCP)"
                ),
            )
        )
        return

    reach_note = (
        f"Ping ตอบกลับเฉลี่ย {ping_res['avg_ms']} ms"
        if ping_res["reachable"]
        else "บล็อก Ping (ICMP) แต่ตรวจพบการตอบสนองทางพอร์ต TCP/ARP"
    )
    if arp_mac:
        reach_note += f", MAC={arp_mac}"

    report.add_check(
        CheckResult(
            layer="L4-L7 (Target & Ports)",
            name=f"Target Host Status ({target_host})",
            status=CheckStatus.PASS,
            summary=f"เครื่องปลายทาง {target_host} ({resolved_ip}) ออนไลน์และติดต่อได้ ({reach_note})",
            details="บทบาทที่ตรวจพบ: " + (", ".join(device_roles) if device_roles else "อุปกรณ์ทั่วไป / ปิดพอร์ตมาตรฐาน"),
        )
    )

    if open_ports:
        open_str = ", ".join(f"{p['port']} ({p['service'].split()[0]})" for p in open_ports)
        report.add_check(
            CheckResult(
                layer="L4-L7 (Target & Ports)",
                name="Service Ports & Firewall Check",
                status=CheckStatus.PASS,
                summary=f"พบพอร์ตบริการเปิดใช้งาน (OPEN) จำนวน {len(open_ports)} พอร์ต: {open_str}",
                details=(
                    f"OPEN={len(open_ports)}, CLOSED (ไม่เปิดบริการ)={len(closed_ports)}, "
                    f"FILTERED (ติด Firewall)={len(filtered_ports)}"
                ),
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L4-L7 (Target & Ports)",
                name="Service Ports & Firewall Check",
                status=CheckStatus.WARN,
                summary=f"เครื่อง {resolved_ip} ออนไลน์ แต่ไม่มีพอร์ตบริการที่ระบุเปิดอยู่เลย (OPEN=0)",
                details=(
                    f"CLOSED (ไปถึงเครื่องแต่เซอร์วิสปิดอยู่)={len(closed_ports)} พอร์ต, "
                    f"FILTERED (ถูก Firewall บล็อก)={len(filtered_ports)} พอร์ต"
                ),
                recommendation=(
                    "• หากพอร์ตขึ้นว่า CLOSED แปลว่าเครือข่ายไม่บล็อก แต่โปรแกรมบนเครื่องปลายทางยังไม่ได้เปิดทำงาน\n"
                    "• หากพอร์ตขึ้นว่า FILTERED แปลว่าติด Firewall ขององค์กรหรือ Windows Firewall บนเครื่องปลายทาง"
                ),
            )
        )
