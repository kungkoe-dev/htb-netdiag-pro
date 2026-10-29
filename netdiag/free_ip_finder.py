"""
Free IP Finder & DHCP Scope / Static IP Exclusion Zone Analyzer
ตรวจสอบว่ามี IP ไหนว่างบ้างในวงแลน (Unused / Free IPs List)
และแยกแยะว่า IP ไหนไม่ถูกแจกด้วย DHCP (ปลอดภัยสำหรับนำไปตั้ง Static/Fix IP)
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .ip_conflict_scanner import scan_subnet_hosts
from .layer2_datalink import get_nmcli_device_info
from .layer3_network import get_interface_routes, get_ip_addresses


def compress_ip_ranges(ip_strs: List[str]) -> List[Dict[str, Any]]:
    """
    แปลงรายการ IP ที่เรียงกันให้เป็นช่วง (Contiguous Ranges)
    เช่น ['10.8.70.2', '10.8.70.3', '10.8.70.4'] -> [{'start': '10.8.70.2', 'end': '10.8.70.4', 'count': 3, 'ips': [...]}]
    """
    if not ip_strs:
        return []
    sorted_ips = sorted((ipaddress.ip_address(x) for x in ip_strs), key=int)
    ranges: List[Dict[str, Any]] = []

    start_ip = sorted_ips[0]
    prev_ip = sorted_ips[0]
    current_list = [str(start_ip)]

    for ip_obj in sorted_ips[1:]:
        if int(ip_obj) == int(prev_ip) + 1:
            prev_ip = ip_obj
            current_list.append(str(ip_obj))
        else:
            ranges.append(
                {
                    "start": str(start_ip),
                    "end": str(prev_ip),
                    "count": len(current_list),
                    "ips": current_list,
                }
            )
            start_ip = ip_obj
            prev_ip = ip_obj
            current_list = [str(start_ip)]

    ranges.append(
        {
            "start": str(start_ip),
            "end": str(prev_ip),
            "count": len(current_list),
            "ips": current_list,
        }
    )
    return ranges


def parse_custom_dhcp_range(
    network: ipaddress.IPv4Network,
    dhcp_range_str: Optional[str],
) -> Optional[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]:
    """
    แปลงข้อความช่วง DHCP เช่น '10.8.70.20-10.8.70.250' หรือ '20-250'
    ให้เป็น (start_ip, end_ip)
    """
    if not dhcp_range_str or not dhcp_range_str.strip():
        return None
    s = dhcp_range_str.strip()
    if "-" not in s:
        return None
    left, right = [p.strip() for p in s.split("-", 1)]
    base_parts = str(network.network_address).split(".")

    try:
        if left.isdigit() and len(base_parts) == 4:
            start_ip = ipaddress.IPv4Address(".".join(base_parts[:3] + [left]))
        else:
            start_ip = ipaddress.IPv4Address(left)

        if right.isdigit() and len(base_parts) == 4:
            end_ip = ipaddress.IPv4Address(".".join(base_parts[:3] + [right]))
        else:
            end_ip = ipaddress.IPv4Address(right)

        if int(start_ip) > int(end_ip):
            start_ip, end_ip = end_ip, start_ip
        return start_ip, end_ip
    except ValueError:
        return None


def infer_dhcp_pool_bounds(
    network: ipaddress.IPv4Network,
    used_ips: List[str],
    gateway_ip: str,
    self_ip: str,
    is_self_dhcp: bool,
) -> Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address, str]:
    """
    วิเคราะห์ขอบเขตช่วง DHCP Pool อัตโนมัติจากข้อมูลจริงในวงแลน:
    ดูจากการกระจายตัวของเครื่องลูกข่าย (ที่ไม่ใช่ Gateway .1/.254) และ IP ที่เครื่องเราได้รับจาก DHCP
    """
    usable_hosts = list(network.hosts())
    if not usable_hosts:
        return network.network_address, network.broadcast_address, "Unknown"

    first_usable = usable_hosts[0]
    last_usable = usable_hosts[-1]

    # คัดกรองเฉพาะเครื่องลูกข่ายทั่วไป (ตัด Gateway เช่น .1 หรือ .254 ออกจากการคำนวณขอบเขต DHCP Client)
    client_ips: List[ipaddress.IPv4Address] = []
    for ip_str in used_ips:
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
            last_octet = int(str(ip_obj).split(".")[-1])
            if ip_str == gateway_ip or last_octet in (1, 254):
                continue
            client_ips.append(ip_obj)
        except ValueError:
            pass

    if is_self_dhcp and self_ip:
        try:
            s_obj = ipaddress.IPv4Address(self_ip)
            if s_obj not in client_ips:
                client_ips.append(s_obj)
        except ValueError:
            pass

    if not client_ips:
        # กรณีไม่มีเครื่องอื่นออนไลน์เลย ให้ใช้ค่ามาตรฐานองค์กรทั่วไป (กัน .1 - .19 และ .250 - .254 ไว้เป็น Static)
        if network.prefixlen == 24 and len(usable_hosts) >= 250:
            base = ".".join(str(network.network_address).split(".")[:3])
            return (
                ipaddress.IPv4Address(f"{base}.20"),
                ipaddress.IPv4Address(f"{base}.249"),
                "ประเมินตามมาตรฐานองค์กร (.20 - .249)",
            )
        return first_usable, last_usable, "ทั้งวงแลน"

    min_client = min(client_ips, key=int)
    max_client = max(client_ips, key=int)

    if network.prefixlen == 24:
        base = ".".join(str(network.network_address).split(".")[:3])
        min_oct = int(str(min_client).split(".")[-1])
        max_oct = int(str(max_client).split(".")[-1])

        # ปรับขอบเขตเข้าหา Boundary มาตรฐานที่ผู้ดูแลระบบนิยมตั้ง (เช่น 10, 15, 20, 50, 100 ... ถึง 200, 240, 250, 253)
        if min_oct > 2:
            est_start_oct = min_oct
        else:
            est_start_oct = 2

        est_end_oct = max(max_oct, 200 if max_oct > 150 else max_oct)
        est_start = ipaddress.IPv4Address(f"{base}.{est_start_oct}")
        est_end = ipaddress.IPv4Address(f"{base}.{est_end_oct}")
        reason = (
            f"วิเคราะห์จากการกระจายตัวของเครื่องลูกข่ายในวงจริง "
            f"(ตรวจพบ DHCP/Client ตั้งแต่ .{est_start_oct} ถึง .{max_oct})"
        )
        return est_start, est_end, reason

    return min_client, max_client, "วิเคราะห์จากขอบเขตเครื่องลูกข่ายที่ออนไลน์ในวง"


def run_free_ip_and_dhcp_scope_checks(
    report: InterfaceDiagReport,
    custom_dhcp_range: Optional[str] = None,
) -> None:
    """
    สแกนวงแลนเพื่อแสดง List ของ:
      1. IP ที่ว่างทั้งหมด (Free / Unused IPs)
      2. IP ที่ว่างและไม่ถูกแจกด้วย DHCP (Static / Exclusion Zone — แนะนำให้ใช้ตั้ง Fix IP)
      3. IP ที่ว่างแต่อยู่ในช่วง DHCP Pool (Free Inside DHCP Scope)
    """
    iface = report.interface
    ipv4_list, _ = get_ip_addresses(iface)

    if not ipv4_list or ipv4_list[0].get("local", "").startswith("169.254."):
        report.add_check(
            CheckResult(
                layer="L3 (Free IP & DHCP Scope)",
                name="Free IP & Static Zone Scanner",
                status=CheckStatus.FAIL,
                summary=f"พอร์ต {iface} ยังไม่มี IPv4 Address ในวงแลน จึงไม่สามารถสแกนหารายการ IP ว่างผ่านพอร์ตนี้ได้",
                recommendation="กรุณาเลือกพอร์ตที่เชื่อมต่อและได้รับ IP แล้ว (เช่น พอร์ต Wi-Fi หรือสายแลนที่ออนไลน์)",
            )
        )
        return

    primary_v4 = ipv4_list[0]
    self_ip = primary_v4.get("local", "")
    prefix_len = primary_v4.get("prefixlen", 24)
    is_dynamic = bool(primary_v4.get("dynamic", False))
    cidr_str = f"{self_ip}/{prefix_len}"

    nm_info = report.raw_context.get("nmcli") or get_nmcli_device_info(iface)
    routes = get_interface_routes(iface)
    default_routes = [r for r in routes if r.get("dst") == "default"]
    gateway_ip = default_routes[0].get("gateway") if default_routes else nm_info.get("IP4.GATEWAY", "")
    if any("dhcp_server_identifier" in v for v in nm_info.values()):
        is_dynamic = True

    scan_res = scan_subnet_hosts(
        iface=iface,
        cidr_str=cidr_str,
        self_ip=self_ip,
        self_mac=report.mac_address,
    )

    network = ipaddress.IPv4Network(scan_res["subnet"], strict=False)
    used_hosts_dict: Dict[str, List[str]] = scan_res["hosts"]
    used_ip_set = set(used_hosts_dict.keys())
    if gateway_ip and gateway_ip != "--":
        used_ip_set.add(gateway_ip)

    all_usable_ips = [str(ip) for ip in network.hosts()]
    free_ips = [ip for ip in all_usable_ips if ip not in used_ip_set]
    used_ips_sorted = [ip for ip in all_usable_ips if ip in used_ip_set]

    # คำนวณช่วง DHCP Pool (จากค่าที่ผู้ใช้ระบุ หรือวิเคราะห์อัตโนมัติ)
    custom_bounds = parse_custom_dhcp_range(network, custom_dhcp_range)
    if custom_bounds:
        dhcp_start, dhcp_end = custom_bounds
        scope_method = f"ระบุช่วง DHCP Pool เอง ({dhcp_start} - {dhcp_end})"
    else:
        dhcp_start, dhcp_end, scope_method = infer_dhcp_pool_bounds(
            network=network,
            used_ips=used_ips_sorted,
            gateway_ip=gateway_ip,
            self_ip=self_ip,
            is_self_dhcp=is_dynamic,
        )

    # แยก IP ออกเป็น 2 โซน: นอกช่วง DHCP (Static Zone) vs ในช่วง DHCP (DHCP Pool Zone)
    free_static_zone: List[str] = []
    free_dhcp_zone: List[str] = []
    used_static_zone: List[str] = []
    used_dhcp_zone: List[str] = []

    for ip_str in all_usable_ips:
        ip_obj = ipaddress.IPv4Address(ip_str)
        in_dhcp_pool = int(dhcp_start) <= int(ip_obj) <= int(dhcp_end)
        if ip_str in used_ip_set:
            if in_dhcp_pool:
                used_dhcp_zone.append(ip_str)
            else:
                used_static_zone.append(ip_str)
        else:
            if in_dhcp_pool:
                free_dhcp_zone.append(ip_str)
            else:
                free_static_zone.append(ip_str)

    # คัดเลือก Top 10 เบอร์ IP แนะนำสำหรับนำไปตั้ง Fix/Static IP (เน้นเบอร์ว่างที่อยู่นอกช่วง DHCP Pool)
    recommended_static_ips = free_static_zone[:12] if free_static_zone else free_dhcp_zone[:10]

    free_ip_data: Dict[str, Any] = {
        "subnet": str(network),
        "gateway_ip": gateway_ip or "-",
        "total_usable": len(all_usable_ips),
        "used_count": len(used_ips_sorted),
        "free_count": len(free_ips),
        "dhcp_pool_start": str(dhcp_start),
        "dhcp_pool_end": str(dhcp_end),
        "scope_method": scope_method,
        "free_static_zone_ips": free_static_zone,
        "free_static_ranges": compress_ip_ranges(free_static_zone),
        "free_dhcp_zone_ips": free_dhcp_zone,
        "free_dhcp_ranges": compress_ip_ranges(free_dhcp_zone),
        "all_free_ranges": compress_ip_ranges(free_ips),
        "used_static_zone_ips": used_static_zone,
        "used_dhcp_zone_ips": used_dhcp_zone,
        "recommended_static_ips": recommended_static_ips,
    }
    report.raw_context["free_ip_data"] = free_ip_data

    # บันทึกผลการตรวจเช็ก
    report.add_check(
        CheckResult(
            layer="L3 (Free IP & DHCP Scope)",
            name="Unused / Free IP Discovery",
            status=CheckStatus.PASS if free_ips else CheckStatus.FAIL,
            summary=(
                f"พบ IP ว่างที่ยังไม่ถูกใช้งานทั้งหมด {len(free_ips)} เบอร์ "
                f"(จากทั้งหมด {len(all_usable_ips)} เบอร์ ในวง {network})"
            ),
            details=f"ถูกใช้งานอยู่ (In-Use) = {len(used_ips_sorted)} IPs, ว่าง (Free) = {len(free_ips)} IPs",
        )
    )

    if free_static_zone:
        sample_rec = ", ".join(recommended_static_ips[:6])
        report.add_check(
            CheckResult(
                layer="L3 (Free IP & DHCP Scope)",
                name="Non-DHCP / Static IP Zone",
                status=CheckStatus.PASS,
                summary=(
                    f"พบ IP ว่างที่อยู่นอกช่วงแจก DHCP จำนวน {len(free_static_zone)} เบอร์ "
                    f"(ช่วง DHCP ที่ตรวจพบคือ {dhcp_start} - {dhcp_end})"
                ),
                details=f"วิธีวิเคราะห์: {scope_method}\nเบอร์ IP แนะนำสำหรับตั้ง Static IP: {sample_rec}",
                recommendation=(
                    f"หากต้องการตั้งค่า Fix/Static IP ให้กับ Server, Printer หรืออุปกรณ์ใหม่ แนะนำให้เลือกจากโซนนอกช่วง DHCP:\n"
                    f"👉 แนะนำเบอร์: {', '.join(recommended_static_ips[:8])}"
                ),
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L3 (Free IP & DHCP Scope)",
                name="Non-DHCP / Static IP Zone",
                status=CheckStatus.WARN,
                summary=f"ช่วงแจก DHCP ครอบคลุมเกือบทั้งวงแลน ({dhcp_start} - {dhcp_end}) ไม่มีโซนว่างนอกช่วง DHCP",
                details=f"มี IP ว่างภายในช่วง DHCP จำนวน {len(free_dhcp_zone)} เบอร์",
                recommendation=(
                    "หากนำ IP ที่ว่างไปตั้ง Static IP โดยตรง อาจถูก DHCP แจกซ้ำให้เครื่องอื่นในอนาคต:\n"
                    "แนะนำให้ตั้งค่า **DHCP Reservation (ผูก MAC Address กับ IP)** บน DHCP Server แทนการ Fix ที่ตัวเครื่อง"
                ),
            )
        )
