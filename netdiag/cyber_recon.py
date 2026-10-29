"""
HTB Cyber Asset & Hostname Radar (--mode recon)
เรดาร์สแกนทรัพย์สินเครือข่ายความเร็วสูงโดยผสานเครื่องมือใน Hack The Box OS:
  - fping + ARP Cache (ค้นหาเครื่องออนไลน์ทั้งวงแลน)
  - IEEE OUI Database (ระบุยี่ห้อผู้ผลิตอุปกรณ์จาก MAC Address)
  - nbtscan (ดึงชื่อเครื่อง Windows / NetBIOS Name)
  - avahi-browse (ดึงชื่อเครื่อง Mac / Linux / Printer ผ่าน mDNS)
  - dig -x (ดึงชื่อ Reverse DNS PTR จาก DNS Server ขององค์กร)
"""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .htb_arsenal import (
    lookup_mac_vendor,
    run_mdns_lookup,
    run_nbtscan_lookup,
    run_reverse_dns_ptr,
)
from .ip_conflict_scanner import scan_subnet_hosts
from .layer2_datalink import get_nmcli_device_info
from .layer3_network import get_interface_routes, get_ip_addresses


def _classify_asset_profile(
    ip_addr: str,
    vendor: str,
    hostname: str,
    name_source: str,
    is_self: bool,
    is_gateway: bool,
) -> str:
    """ประเมินประเภทอุปกรณ์จาก MAC Vendor, ชื่อเครื่อง และบทบาทในเครือข่าย"""
    if is_self:
        return "💻 เครื่องของคุณ (This PC)"
    if is_gateway:
        return "🚪 Default Gateway / Router"

    v_low = vendor.lower()
    h_low = hostname.lower()

    if any(k in v_low for k in ("cisco", "juniper", "mikrotik", "ubiquiti", "aruba", "ruckus", "fortinet", "tp-link", "huawei", "ruijie", "d-link", "netgear")):
        return "🖧 อุปกรณ์เครือข่าย (Switch/AP/Router)"
    if any(k in v_low for k in ("synology", "qnap", "asustor")) or h_low.startswith("nas"):
        return "🗄️ เซิร์ฟเวอร์เก็บข้อมูล (NAS Storage)"
    if any(k in v_low for k in ("brother", "canon", "epson", "ricoh", "fuji xerox", "kyocera")) or (
        any(k in v_low for k in ("hewlett packard", "hp"))
        and any(p in h_low for p in ("prn", "np", "jet", "laser"))
    ):
        return "🖨️ เครื่องปริ้นเตอร์ (Printer)"
    if any(k in v_low for k in ("hikvision", "dahua", "axis")):
        return "📹 กล้องวงจรปิด (IP Camera/NVR)"
    if any(k in v_low for k in ("vmware", "proxmox", "qemu", "xensource", "PCS Systemtechnik")):
        return "☁️ เซิร์ฟเวอร์จำลอง (VM/Hypervisor)"
    if "apple" in v_low:
        return "🍎 อุปกรณ์ Apple (Mac/iPhone/iPad)"
    if name_source == "NetBIOS":
        return "🪟 คอมพิวเตอร์ Windows / SMB"
    if "private/random mac" in v_low:
        return "📱 มือถือ/โน้ตบุ๊ก (Private MAC)"
    if any(k in v_low for k in ("intel", "realtek", "dell", "lenovo", "asus", "acer", "liteon", "azurewave", "chongqing fugui")):
        return "🖥️ คอมพิวเตอร์ PC / Notebook"

    return "🖧 อุปกรณ์ในวงแลน (Network Host)"


def scan_cyber_assets(
    iface: str,
    cidr_str: str,
    self_ip: str,
    self_mac: str,
    gateway_ip: str = "",
    dns_server: Optional[str] = None,
) -> Dict[str, Any]:
    """
    รวบรวมข้อมูลทรัพย์สินเครือข่าย (IP, MAC, ยี่ห้อ Vendor, ชื่อเครื่อง Hostname/NetBIOS/mDNS, ประเภทอุปกรณ์)
    """
    base_scan = scan_subnet_hosts(
        iface=iface,
        cidr_str=cidr_str,
        self_ip=self_ip,
        self_mac=self_mac,
    )
    subnet = base_scan["subnet"]
    hosts_map: Dict[str, List[str]] = base_scan["hosts"]

    # 1. กวาดหาชื่อเครื่องด้วย nbtscan และ mDNS พร้อมกัน
    nbt_names = run_nbtscan_lookup(subnet, timeout_sec=4)
    mdns_names = run_mdns_lookup(timeout_sec=3)

    # 2. กวาดถาม Reverse DNS PTR สำหรับทุก IP ที่ออนไลน์แบบขนาน
    ptr_names: Dict[str, str] = {}
    active_ips = list(hosts_map.keys())
    if active_ips:
        with ThreadPoolExecutor(max_workers=min(len(active_ips), 16)) as executor:
            fut_map = {executor.submit(run_reverse_dns_ptr, ip, dns_server): ip for ip in active_ips}
            for fut in as_completed(fut_map):
                ip_k = fut_map[fut]
                try:
                    ptr_val = fut.result()
                    if ptr_val:
                        ptr_names[ip_k] = ptr_val
                except Exception:
                    pass

    assets: List[Dict[str, Any]] = []
    vendor_counter: Counter = Counter()
    named_count = 0

    for ip_addr, mac_list in hosts_map.items():
        primary_mac = mac_list[0] if mac_list else ""
        vendor = lookup_mac_vendor(primary_mac) if primary_mac else "ไม่ทราบ (รอ ARP)"
        if primary_mac:
            vendor_counter[vendor] += 1

        is_self = ip_addr == self_ip
        is_gw = ip_addr == gateway_ip

        hostname = "-"
        name_source = "-"
        if ip_addr in nbt_names:
            hostname = nbt_names[ip_addr]
            name_source = "NetBIOS"
        elif ip_addr in mdns_names:
            hostname = mdns_names[ip_addr]
            name_source = "mDNS"
        elif ip_addr in ptr_names:
            hostname = ptr_names[ip_addr]
            name_source = "DNS PTR"
        elif is_self:
            import socket
            hostname = socket.gethostname()
            name_source = "Localhost"

        if hostname != "-":
            named_count += 1

        profile = _classify_asset_profile(
            ip_addr=ip_addr,
            vendor=vendor,
            hostname=hostname,
            name_source=name_source,
            is_self=is_self,
            is_gateway=is_gw,
        )

        assets.append(
            {
                "ip": ip_addr,
                "mac": ", ".join(mac_list) if mac_list else "-",
                "vendor": vendor,
                "hostname": hostname,
                "name_source": name_source,
                "profile": profile,
                "is_conflict": ip_addr in base_scan["duplicate_ips"],
            }
        )

    top_vendors = [{"vendor": v, "count": c} for v, c in vendor_counter.most_common(8)]

    return {
        "subnet": subnet,
        "total_usable": base_scan["total_usable"],
        "active_count": base_scan["active_count"],
        "named_count": named_count,
        "assets": assets,
        "top_vendors": top_vendors,
        "duplicate_ips": base_scan["duplicate_ips"],
    }


def run_cyber_recon_checks(report: InterfaceDiagReport) -> None:
    """
    รันโหมดเรดาร์สแกนทรัพย์สินเครือข่าย ชื่อเครื่อง และยี่ห้ออุปกรณ์ (--mode recon)
    """
    iface = report.interface
    ipv4_list, _ = get_ip_addresses(iface)

    if not ipv4_list or ipv4_list[0].get("local", "").startswith("169.254."):
        report.add_check(
            CheckResult(
                layer="L2-L7 (HTB Cyber Recon)",
                name="Cyber Asset & Hostname Radar",
                status=CheckStatus.FAIL,
                summary=f"พอร์ต {iface} ยังไม่มี IPv4 ในวงแลน จึงไม่สามารถเปิดเรดาร์สแกนวงแลนผ่านพอร์ตนี้ได้",
                recommendation="กรุณาเลือกพอร์ตที่เชื่อมต่อและได้รับ IP แล้ว (เช่น wlp4s0 หรือพอร์ตสายแลนที่มีสัญญาณ)",
            )
        )
        return

    primary_v4 = ipv4_list[0]
    self_ip = primary_v4.get("local", "")
    prefix_len = primary_v4.get("prefixlen", 24)
    cidr_str = f"{self_ip}/{prefix_len}"

    nm_info = report.raw_context.get("nmcli") or get_nmcli_device_info(iface)
    routes = get_interface_routes(iface)
    default_routes = [r for r in routes if r.get("dst") == "default"]
    gateway_ip = default_routes[0].get("gateway") if default_routes else nm_info.get("IP4.GATEWAY", "")

    dns_srv = None
    for k, v in nm_info.items():
        if k.startswith("IP4.DNS") and v:
            dns_srv = v
            break

    recon_data = scan_cyber_assets(
        iface=iface,
        cidr_str=cidr_str,
        self_ip=self_ip,
        self_mac=report.mac_address,
        gateway_ip=gateway_ip or "",
        dns_server=dns_srv,
    )
    report.raw_context["cyber_recon"] = recon_data

    active_cnt = recon_data["active_count"]
    named_cnt = recon_data["named_count"]
    top_v_str = ", ".join(f"{x['vendor']} ({x['count']})" for x in recon_data["top_vendors"][:5])

    report.add_check(
        CheckResult(
            layer="L2-L7 (HTB Cyber Recon)",
            name="HTB Cyber Asset & Vendor Radar",
            status=CheckStatus.PASS,
            summary=(
                f"🛰️ สแกนพบอุปกรณ์ออนไลน์ {active_cnt} เครื่อง ในวง {recon_data['subnet']} "
                f"(ระบุชื่อเครื่องได้ {named_cnt} เครื่อง)"
            ),
            details=(
                f"เครื่องมือที่ใช้: fping + IEEE OUI Vendor DB + nbtscan + avahi mDNS + dig PTR\n"
                f"สัดส่วนยี่ห้ออุปกรณ์สูงสุด: {top_v_str or '-'}"
            ),
        )
    )
