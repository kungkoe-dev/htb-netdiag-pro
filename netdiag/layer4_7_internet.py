"""
Layer 4-7 - Internet Reachability, MTU Path, DNS Resolution & Captive Portal Detection
ตรวจสอบการออกอินเทอร์เน็ต, แยกแยะปัญหา Routing vs DNS, เช็กขนาด MTU และตรวจจับหน้าล็อกอิน Captive Portal
"""

import socket
import subprocess
import time
from typing import Dict, List, Optional

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .layer3_network import ping_host


def tcp_connect_check(host: str, port: int = 443, timeout: float = 2.5) -> bool:
    """ทดสอบเปิด TCP Socket ไปยังปลายทาง (ใช้กรณีองค์กรบล็อก Ping/ICMP)"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_path_mtu(iface: str, target: str = "1.1.1.1") -> Dict[str, object]:
    """
    ตรวจสอบว่าสามารถส่ง Packet ขนาดมาตรฐาน MTU 1500 (Payload 1472 bytes + 28 bytes IP/ICMP header)
    โดยห้าม Fragment (-M do) ผ่านออกอินเทอร์เน็ตได้หรือไม่
    """
    for payload_size in (1472, 1452, 1400, 1300):
        try:
            proc = subprocess.run(
                ["ping", "-n", "-I", iface, "-M", "do", "-s", str(payload_size), "-c", "1", "-W", "2", target],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if proc.returncode == 0:
                return {"ok": payload_size == 1472, "max_mtu": payload_size + 28}
        except Exception:
            pass
    return {"ok": False, "max_mtu": 0}


def test_dns_server(domain: str, server: Optional[str] = None, timeout_sec: int = 2) -> Dict[str, object]:
    """ทดสอบแปลงชื่อโดเมนด้วยคำสั่ง dig"""
    cmd = ["dig", "+short", f"+time={timeout_sec}", "+tries=1"]
    if server:
        cmd.append(f"@{server}")
    cmd.append(domain)
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec + 2)
        elapsed_ms = round((time.monotonic() - start) * 1000, 1)
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip() and not ln.startswith(";")]
        if proc.returncode == 0 and lines:
            return {"ok": True, "ips": lines, "latency_ms": elapsed_ms}
    except Exception:
        pass
    return {"ok": False, "ips": [], "latency_ms": None}


def check_captive_portal_and_http(iface: str) -> Dict[str, str]:
    """
    ใช้ curl ผูกกับ Interface เพื่อตรวจเช็ก Captive Portal และ HTTPS
    ใช้ URL มาตรฐานของ Google Connectivity Check (ซึ่งปกติจะตอบ HTTP 204 No Content)
    หากถูก Redirect (301/302) หรือได้หน้าเว็บ 200 แปลว่าติดหน้า Captive Portal (หน้าเว็บล็อกอิน)
    """
    url = "http://connectivitycheck.gstatic.com/generate_204"
    try:
        proc = subprocess.run(
            [
                "curl",
                "--interface",
                iface,
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}|%{redirect_url}",
                "--max-time",
                "4",
                url,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        out = (proc.stdout or "").strip()
        if "|" in out:
            code, redir = out.split("|", 1)
            return {"http_code": code, "redirect_url": redir}
    except Exception:
        pass
    return {"http_code": "000", "redirect_url": ""}


def run_layer4_7_checks(report: InterfaceDiagReport) -> None:
    """รันการตรวจสอบ Layer 4 ถึง Layer 7 (Internet, MTU, DNS, HTTP/Captive Portal)"""
    iface = report.interface

    # 1. External IP Reachability (Ping 1.1.1.1 & 8.8.8.8)
    ping_cf = ping_host("1.1.1.1", iface=iface, count=2, timeout_sec=2)
    ping_gg = ping_host("8.8.8.8", iface=iface, count=2, timeout_sec=2)

    icmp_ok = ping_cf["reachable"] or ping_gg["reachable"]
    best_ping = ping_cf if ping_cf["reachable"] else ping_gg

    tcp_ok = False
    if not icmp_ok:
        # เผื่อองค์กรบล็อก ICMP Ping ให้ลองเช็ก TCP Port 443 ไปยัง 1.1.1.1
        tcp_ok = tcp_connect_check("1.1.1.1", 443) or tcp_connect_check("8.8.8.8", 53)

    report.raw_context["internet_ip_ok"] = icmp_ok or tcp_ok

    if icmp_ok:
        report.add_check(
            CheckResult(
                layer="L4 (Transport/WAN)",
                name="Internet IP Reachability",
                status=CheckStatus.PASS,
                summary=f"เชื่อมต่อออกสู่อินเทอร์เน็ตระดับ IP ได้สำเร็จ (Ping 1.1.1.1/8.8.8.8 เฉลี่ย {best_ping['avg_ms']} ms)",
                details=f"1.1.1.1 Loss={ping_cf['loss_pct']}%, 8.8.8.8 Loss={ping_gg['loss_pct']}%",
            )
        )
    elif tcp_ok:
        report.add_check(
            CheckResult(
                layer="L4 (Transport/WAN)",
                name="Internet IP Reachability",
                status=CheckStatus.PASS,
                summary="เชื่อมต่ออินเทอร์เน็ตผ่าน TCP Port 443/53 ได้ (แต่ระบบ Firewall บล็อกคำสั่ง Ping/ICMP)",
                details="ICMP blocked, TCP 443 reachable",
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L4 (Transport/WAN)",
                name="Internet IP Reachability",
                status=CheckStatus.FAIL,
                summary="ปิงหา Gateway เจอ แต่ไม่สามารถออกสู่อินเทอร์เน็ตภายนอก (1.1.1.1 / 8.8.8.8) ได้!",
                details="Ping 1.1.1.1 & 8.8.8.8 Failed (100% loss) และเชื่อมต่อ TCP 443 ไม่ได้",
                recommendation=(
                    "เครื่องของคุณคุยกับ Router (Gateway) ได้แล้ว แต่ติดอยู่ที่ตัว Router ออกเน็ตไม่ได้:\n"
                    "1. **ลิงก์อินเทอร์เน็ตต้นทาง (WAN / Fiber ของ ISP) ล่มหรือหลุด**\n"
                    "2. Router ต้นทางไม่ได้ทำ **NAT (Masquerade)** ให้กับวงแลน/VLAN ของคุณ\n"
                    "3. ติด **Firewall Rule / ACL** หรือยังไม่ได้ล็อกอินหน้า **Captive Portal / Web Auth**"
                ),
            )
        )
        return

    # 2. Path MTU Check (เฉพาะเมื่อ ICMP ใช้งานได้)
    if icmp_ok:
        mtu_res = check_path_mtu(iface, "1.1.1.1")
        if mtu_res["ok"]:
            report.add_check(
                CheckResult(
                    layer="L4 (Transport/WAN)",
                    name="Path MTU Discovery",
                    status=CheckStatus.PASS,
                    summary="ขนาดแพ็กเกจมาตรฐาน MTU 1500 วิ่งออกอินเทอร์เน็ตได้เต็มขนาดโดยไม่ถูกตัดทิ้ง",
                )
            )
        elif int(mtu_res.get("max_mtu", 0)) > 0:
            max_mtu = mtu_res["max_mtu"]
            report.add_check(
                CheckResult(
                    layer="L4 (Transport/WAN)",
                    name="Path MTU Discovery",
                    status=CheckStatus.WARN,
                    summary=f"ตรวจพบคอขวด MTU! แพ็กเกจขนาด 1500 วิ่งไม่ผ่าน (วิ่งได้สูงสุด ~{max_mtu} bytes)",
                    details="อาการนี้จะทำให้ปิงผ่าน แต่เข้าเว็บส่วนใหญ่แล้วค้างหรือโหลดหน้าเว็บไม่ขึ้น (MTU Blackhole)",
                    recommendation=(
                        f"ปรับลดค่า MTU ของการ์ดแลน หรือเปิด TCP MSS Clamping ที่ Router:\n"
                        f"คำสั่งแก้เฉพาะหน้า: sudo ip link set dev {iface} mtu {max_mtu}"
                    ),
                )
            )

    # 3. DNS Resolution Check (เปรียบเทียบ DNS ของระบบ กับ Public DNS 1.1.1.1)
    dns_servers: List[str] = report.raw_context.get("dns_servers", [])
    sys_dns = test_dns_server("google.com", server=dns_servers[0] if dns_servers else None)
    pub_dns = test_dns_server("google.com", server="1.1.1.1")

    if sys_dns["ok"]:
        dns_label = dns_servers[0] if dns_servers else "System Resolver"
        report.add_check(
            CheckResult(
                layer="L7 (Application)",
                name="DNS Name Resolution",
                status=CheckStatus.PASS,
                summary=f"ระบบ DNS ({dns_label}) แปลงชื่อเว็บไซต์ได้ปกติ ({sys_dns['latency_ms']} ms)",
                details=f"google.com -> {', '.join(sys_dns['ips'][:2])}",
            )
        )
    elif pub_dns["ok"]:
        bad_dns = ", ".join(dns_servers) if dns_servers else "ไม่ได้ตั้งค่า DNS"
        report.add_check(
            CheckResult(
                layer="L7 (Application)",
                name="DNS Name Resolution",
                status=CheckStatus.FAIL,
                summary=f"ออกเน็ตด้วย IP ได้ แต่เข้าเว็บไม่ได้เพราะ DNS Server ({bad_dns}) ไม่ตอบสนอง!",
                details="ทดสอบ 1.1.1.1 ใช้งานได้ปกติ แต่ DNS ที่ได้รับจากเครือข่ายพัง",
                recommendation=(
                    "แก้ไขได้ทันทีด้วยการเปลี่ยน DNS ของเครื่องไปใช้ Cloudflare (1.1.1.1) หรือ Google (8.8.8.8):\n"
                    f"คำสั่ง: sudo nmcli device modify {iface} ipv4.dns '1.1.1.1,8.8.8.8' ipv4.ignore-auto-dns yes"
                ),
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L7 (Application)",
                name="DNS Name Resolution",
                status=CheckStatus.FAIL,
                summary="ไม่สามารถแปลงชื่อโดเมน (DNS Lookup) ได้เลย ทั้ง DNS ของระบบและ 1.1.1.1!",
                details="UDP/TCP Port 53 อาจถูก Firewall บล็อก หรือติดหน้า Captive Portal",
                recommendation="ตรวจสอบว่าเครือข่ายบล็อกพอร์ต 53 หรือบังคับใช้ DNS ภายในองค์กรเท่านั้นหรือไม่",
            )
        )

    # 4. Captive Portal & HTTP/HTTPS Check
    portal = check_captive_portal_and_http(iface)
    code = portal.get("http_code", "000")
    redir = portal.get("redirect_url", "")

    if code == "204":
        report.add_check(
            CheckResult(
                layer="L7 (Application)",
                name="HTTP / Captive Portal Check",
                status=CheckStatus.PASS,
                summary="ใช้งานเว็บไซต์ (HTTP/HTTPS) ได้สมบูรณ์ ไม่ติดหน้าล็อกอิน Captive Portal",
                details="HTTP 204 No Content verified via connectivitycheck.gstatic.com",
            )
        )
    elif code in ("301", "302", "303", "307", "308", "200") and redir:
        report.add_check(
            CheckResult(
                layer="L7 (Application)",
                name="Captive Portal Detection",
                status=CheckStatus.FAIL,
                summary=f"ตรวจพบหน้าล็อกอินเครือข่าย (Captive Portal / Web Authentication)!",
                details=f"HTTP {code} Redirect ไปยัง: {redir}",
                recommendation=(
                    f"คุณต้องเปิดเบราว์เซอร์แล้วล็อกอินเข้าใช้งานอินเทอร์เน็ตก่อนที่ลิงก์:\n"
                    f"👉 {redir}"
                ),
            )
        )
    elif code == "000":
        report.add_check(
            CheckResult(
                layer="L7 (Application)",
                name="HTTP / Web Connectivity",
                status=CheckStatus.WARN,
                summary="เชื่อมต่อเว็บไซต์ผ่าน HTTP ไม่สำเร็จ (อาจต้องตั้งค่า Proxy ขององค์กร หรือ DNS มีปัญหา)",
                details="curl connectivitycheck returned 000",
                recommendation="หากอยู่ในเครือข่ายองค์กร ให้ตรวจสอบว่าต้องตั้งค่า HTTP/HTTPS Proxy หรือไม่",
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L7 (Application)",
                name="HTTP / Captive Portal Check",
                status=CheckStatus.INFO,
                summary=f"ผลการทดสอบ HTTP Connectivity ตอบกลับด้วยรหัส HTTP {code}",
                details=f"Redirect={redir or 'None'}",
            )
        )
