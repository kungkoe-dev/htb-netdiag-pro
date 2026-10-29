"""
Hack The Box OS (Parrot Security) Arsenal Integration Engine
เชื่อมต่อและดึงขุมพลังเครื่องมือที่ติดตั้งอยู่ใน HTB OS มาใช้ร่วมกับระบบวิเคราะห์เครือข่าย:
  - IEEE OUI MAC Vendor Database (/usr/share/nmap/nmap-mac-prefixes & /usr/share/arp-scan/ieee-oui.txt)
  - nbtscan (NetBIOS Computer Name / Windows Workgroup Discovery)
  - avahi-browse (mDNS / Bonjour Zero-Config Host & Printer Discovery)
  - dig (Fast Reverse DNS PTR Lookup)
  - nmap -sV (Service Banner & Version Fingerprinting)
  - whatweb (Web Server & Admin Console Technology Fingerprinting)
  - sslscan (TLS/SSL Certificate & Cipher Inspection)
"""

import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

_OUI_CACHE: Optional[Dict[str, str]] = None

OUI_DB_PATHS = [
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/usr/share/arp-scan/ieee-oui.txt"),
]

HTB_TOOLS = [
    "nmap",
    "fping",
    "arp-scan",
    "nbtscan",
    "avahi-browse",
    "whatweb",
    "sslscan",
    "tshark",
    "dig",
    "snmpwalk",
]


def _load_oui_database() -> Dict[str, str]:
    """โหลดฐานข้อมูล IEEE OUI MAC Prefix จากไฟล์ในเครื่อง HTB OS เข้าสู่หน่วยความจำ"""
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE

    db: Dict[str, str] = {}
    for path in OUI_DB_PATHS:
        if not path.is_file():
            continue
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2 and len(parts[0]) == 6:
                        prefix = parts[0].upper()
                        if prefix not in db:
                            db[prefix] = parts[1].strip()
        except Exception:
            pass

    _OUI_CACHE = db
    return db


def lookup_mac_vendor(mac_addr: str) -> str:
    """
    ค้นหาชื่อบริษัทผู้ผลิตอุปกรณ์ (Hardware Vendor) จากหมายเลข MAC Address
    พร้อมตรวจจับ Locally Administered / Randomized MAC (ของมือถือ iOS/Android สมัยใหม่)
    """
    if not mac_addr or mac_addr == "unknown":
        return "Unknown"

    clean_hex = re.sub(r"[^0-9A-Fa-f]", "", mac_addr).upper()
    if len(clean_hex) < 6:
        return "Unknown"

    oui_prefix = clean_hex[:6]
    db = _load_oui_database()
    vendor = db.get(oui_prefix)
    if vendor:
        # ย่อชื่อบริษัทที่ยาวเกินไปให้กระชับอ่านง่ายในตาราง
        short_vendor = re.sub(
            r"\b(Incorporated|Corporation|Co\.,?\s*Ltd\.?|Ltd\.?|Inc\.?|GmbH|LLC|S\.A\.|B\.V\.|International|Technologies|Technology)\b",
            "",
            vendor,
            flags=re.IGNORECASE,
        )
        short_vendor = re.sub(r"\s{2,}", " ", short_vendor).strip(" ,.")
        return short_vendor or vendor

    # ตรวจสอบบิต Locally Administered Address (LAA) ในตัวอักษรที่ 2 ของ MAC (2, 6, A, E)
    second_char = oui_prefix[1]
    if second_char in ("2", "6", "A", "E"):
        return "Private/Random MAC (มือถือ/OS)"

    return "Unknown Vendor"


def get_htb_arsenal_status() -> Dict[str, bool]:
    """ตรวจสอบว่าเครื่องมือในคลังแสง HTB OS ตัวใดพร้อมใช้งานบ้าง"""
    status: Dict[str, bool] = {}
    for tool in HTB_TOOLS:
        status[tool] = shutil.which(tool) is not None
    status["oui_db"] = any(p.is_file() for p in OUI_DB_PATHS)
    return status


def run_nbtscan_lookup(target_cidr_or_ip: str, timeout_sec: int = 4) -> Dict[str, str]:
    """
    ใช้ nbtscan กวาดค้นหาชื่อเครื่อง NetBIOS (Windows PC / File Server / NAS / Printer)
    คืนค่าเป็น Dict[ip_address, netbios_name]
    """
    results: Dict[str, str] = {}
    if not shutil.which("nbtscan"):
        return results
    try:
        proc = subprocess.run(
            ["nbtscan", "-q", "-t", "800", "-s", ":", target_cidr_or_ip],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        for line in proc.stdout.splitlines():
            parts = [p.strip() for p in line.split(":")]
            if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                ip_addr = parts[0]
                nb_name = parts[1]
                if nb_name and nb_name != "<unknown>":
                    results[ip_addr] = nb_name
    except Exception:
        pass
    return results


def run_mdns_lookup(timeout_sec: int = 3) -> Dict[str, str]:
    """
    ใช้ avahi-browse ค้นหาชื่อเครื่องและบริการผ่าน mDNS / Bonjour (.local)
    คืนค่าเป็น Dict[ip_address, mdns_hostname]
    """
    results: Dict[str, str] = {}
    if not shutil.which("avahi-browse"):
        return results
    try:
        proc = subprocess.run(
            ["avahi-browse", "-a", "-r", "-p", "-t"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        for line in proc.stdout.splitlines():
            if not line.startswith("="):
                continue
            fields = line.split(";")
            # รูปแบบพาร์สของ avahi-browse -p: =;iface;proto;name;type;domain;hostname;address;port;txt
            if len(fields) >= 8:
                hostname = fields[6].strip()
                ip_addr = fields[7].strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_addr) and hostname:
                    results[ip_addr] = hostname
    except Exception:
        pass
    return results


def run_reverse_dns_ptr(ip_addr: str, dns_server: Optional[str] = None) -> str:
    """ใช้ dig -x เพื่อถามชื่อเครื่องย้อนกลับ (Reverse DNS PTR Record) อย่างรวดเร็ว"""
    if not shutil.which("dig"):
        return ""
    cmd = ["dig", "+time=1", "+tries=1", "+short", "-x", ip_addr]
    if dns_server and re.match(r"^\d+\.\d+\.\d+\.\d+$", dns_server):
        cmd.append(f"@{dns_server}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        for line in proc.stdout.splitlines():
            line = line.strip().rstrip(".")
            if line and not line.startswith(";;") and "connection timed out" not in line.lower():
                return line
    except Exception:
        pass
    return ""


def run_nmap_service_banners(ip_addr: str, open_ports: List[int], timeout_sec: int = 10) -> Dict[int, str]:
    """
    ใช้ nmap -sV --version-light เพื่อดึงชื่อซอฟต์แวร์และเวอร์ชันจริงของพอร์ตที่เปิดอยู่
    """
    banners: Dict[int, str] = {}
    if not open_ports or not shutil.which("nmap"):
        return banners

    ports_arg = ",".join(str(p) for p in open_ports)
    try:
        proc = subprocess.run(
            [
                "nmap",
                "-Pn",
                "-n",
                "-sT",
                "-sV",
                "--version-light",
                "--host-timeout",
                f"{timeout_sec}s",
                "-p",
                ports_arg,
                ip_addr,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_sec + 2,
        )
        for line in proc.stdout.splitlines():
            # ตัวอย่าง: 80/tcp open  http    Apache httpd 2.4.58 ((Debian))
            m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", line.strip())
            if m:
                port_num = int(m.group(1))
                srv_name = m.group(2).strip()
                srv_ver = m.group(3).strip()
                banners[port_num] = f"{srv_name} ({srv_ver})" if srv_ver else srv_name
    except Exception:
        pass
    return banners


def run_whatweb_summary(ip_addr: str, port: int = 80, timeout_sec: int = 6) -> str:
    """
    ใช้ whatweb สแกนหาเทคโนโลยีของ Web Server / หน้า Admin อุปกรณ์เครือข่าย
    """
    if not shutil.which("whatweb"):
        return ""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip_addr}:{port}" if port not in (80, 443) else f"{scheme}://{ip_addr}"
    try:
        proc = subprocess.run(
            ["whatweb", "--color=never", "--no-errors", "-a", "1", "--max-threads=2", url],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        if not lines:
            return ""
        # เอาบรรทัดสุดท้ายที่เป็นผลลัพธ์ของ URL เป้าหมาย
        last = lines[-1]
        # ตัดส่วน URL ข้างหน้าออกเพื่อให้กระชับ
        idx = last.find("[")
        return last[idx:] if idx != -1 else last
    except Exception:
        return ""


def run_sslscan_summary(ip_addr: str, port: int = 443, timeout_sec: int = 6) -> Dict[str, str]:
    """
    ใช้ sslscan ตรวจสอบใบรับรองความปลอดภัย SSL/TLS และเวอร์ชันโปรโตคอลที่รองรับ
    """
    info: Dict[str, str] = {}
    if not shutil.which("sslscan"):
        return info
    try:
        proc = subprocess.run(
            [
                "sslscan",
                "--no-colour",
                "--no-heartbleed",
                "--no-compression",
                "--no-renegotiation",
                "--no-fallback",
                "--timeout=3",
                f"{ip_addr}:{port}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        enabled_tls: List[str] = []
        for line in proc.stdout.splitlines():
            s = line.strip()
            if s.startswith("Subject:"):
                info["subject"] = s.replace("Subject:", "").strip()
            elif s.startswith("Issuer:"):
                info["issuer"] = s.replace("Issuer:", "").strip()
            elif s.startswith("Not valid after:"):
                info["expires"] = s.replace("Not valid after:", "").strip()
            elif re.match(r"^(SSLv2|SSLv3|TLSv1\.\d)\s+enabled$", s):
                enabled_tls.append(s.split()[0])
        if enabled_tls:
            info["tls_versions"] = ", ".join(enabled_tls)
    except Exception:
        pass
    return info
