"""
Network Baseline Snapshot & Anomaly Diff (--mode baseline)
บันทึกภาพจำสภาวะเครือข่ายปกติ (Baseline) และเปรียบเทียบความผิดปกติในวันถัดมา:
  - ตรวจจับ Gateway MAC Address เปลี่ยนแปลง (ARP Spoofing / Rogue Gateway)
  - ตรวจจับอุปกรณ์แปลกปลอมที่เพิ่งเข้ามาในวงแลนใหม่ (New Unknown Hosts + MAC Vendor)
  - ตรวจจับเครื่อง/Server ที่เคยออนไลน์แต่หายไป (Missing Hosts)
  - ตรวจจับการเปลี่ยนแปลงของ DNS / DHCP Server
"""

import datetime
import json
from pathlib import Path
from typing import Any, Dict, List

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .htb_arsenal import lookup_mac_vendor
from .ip_conflict_scanner import scan_subnet_hosts
from .layer2_datalink import get_arp_neighbors, get_nmcli_device_info
from .layer3_network import get_interface_routes, get_ip_addresses

BASELINE_DIR = Path(__file__).resolve().parent.parent / "reports" / "baselines"


def _get_baseline_path(subnet: str) -> Path:
    safe_name = subnet.replace("/", "_").replace(":", "_")
    return BASELINE_DIR / f"baseline_{safe_name}.json"


def capture_current_snapshot(iface: str, report: InterfaceDiagReport) -> Dict[str, Any]:
    """เก็บข้อมูลสภาพเครือข่ายปัจจุบันทั้งหมดสำหรับทำ Baseline หรือเปรียบเทียบ"""
    ipv4_list, _ = get_ip_addresses(iface)
    primary_v4 = ipv4_list[0]
    self_ip = primary_v4.get("local", "")
    prefix_len = primary_v4.get("prefixlen", 24)
    cidr_str = f"{self_ip}/{prefix_len}"

    nm_info = report.raw_context.get("nmcli") or get_nmcli_device_info(iface)
    routes = get_interface_routes(iface)
    default_routes = [r for r in routes if r.get("dst") == "default"]
    gateway_ip = default_routes[0].get("gateway") if default_routes else nm_info.get("IP4.GATEWAY", "")

    gateway_mac = ""
    if gateway_ip:
        for n in get_arp_neighbors(iface):
            if n.get("ip") == gateway_ip and n.get("mac"):
                gateway_mac = n["mac"].lower()
                break

    dns_servers = sorted(
        v.strip() for k, v in nm_info.items() if k.startswith("IP4.DNS") and v and v != "--"
    )
    dhcp_server = ""
    for k, v in nm_info.items():
        if k.startswith("DHCP4.OPTION") and "dhcp_server_identifier" in v:
            dhcp_server = v.split("=", 1)[-1].strip()
            break

    scan_res = scan_subnet_hosts(
        iface=iface,
        cidr_str=cidr_str,
        self_ip=self_ip,
        self_mac=report.mac_address,
    )

    hosts_with_vendor: Dict[str, Dict[str, Any]] = {}
    for ip_k, macs in scan_res["hosts"].items():
        primary_mac = macs[0] if macs else ""
        hosts_with_vendor[ip_k] = {
            "macs": macs,
            "vendor": lookup_mac_vendor(primary_mac) if primary_mac else "-",
        }

    return {
        "captured_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "interface": iface,
        "subnet": scan_res["subnet"],
        "gateway_ip": gateway_ip or "",
        "gateway_mac": gateway_mac,
        "dns_servers": dns_servers,
        "dhcp_server": dhcp_server,
        "hosts": hosts_with_vendor,
    }


def compare_snapshots(baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """เปรียบเทียบภาพจำเดิม (Baseline) กับสถานะปัจจุบัน (Current) เพื่อหาสิ่งผิดปกติ"""
    base_hosts: Dict[str, Dict[str, Any]] = baseline.get("hosts", {})
    curr_hosts: Dict[str, Dict[str, Any]] = current.get("hosts", {})

    new_hosts: List[Dict[str, Any]] = []
    for ip_k, info in curr_hosts.items():
        if ip_k not in base_hosts:
            new_hosts.append({"ip": ip_k, "macs": info["macs"], "vendor": info["vendor"]})

    missing_hosts: List[Dict[str, Any]] = []
    for ip_k, info in base_hosts.items():
        if ip_k not in curr_hosts:
            missing_hosts.append({"ip": ip_k, "macs": info["macs"], "vendor": info["vendor"]})

    mac_changed_hosts: List[Dict[str, Any]] = []
    for ip_k, info in curr_hosts.items():
        if ip_k in base_hosts:
            old_macs = set(base_hosts[ip_k].get("macs", []))
            new_macs = set(info.get("macs", []))
            if old_macs and new_macs and old_macs != new_macs:
                mac_changed_hosts.append(
                    {
                        "ip": ip_k,
                        "old_mac": ", ".join(sorted(old_macs)),
                        "new_mac": ", ".join(sorted(new_macs)),
                        "new_vendor": info["vendor"],
                    }
                )

    gw_mac_changed = bool(
        baseline.get("gateway_mac")
        and current.get("gateway_mac")
        and baseline["gateway_mac"] != current["gateway_mac"]
    )
    dns_changed = baseline.get("dns_servers", []) != current.get("dns_servers", [])
    dhcp_changed = bool(
        baseline.get("dhcp_server")
        and current.get("dhcp_server")
        and baseline["dhcp_server"] != current["dhcp_server"]
    )

    return {
        "baseline_time": baseline.get("captured_at", "-"),
        "current_time": current.get("captured_at", "-"),
        "subnet": current.get("subnet", ""),
        "gw_mac_changed": gw_mac_changed,
        "old_gw_mac": baseline.get("gateway_mac", "-"),
        "new_gw_mac": current.get("gateway_mac", "-"),
        "dns_changed": dns_changed,
        "old_dns": baseline.get("dns_servers", []),
        "new_dns": current.get("dns_servers", []),
        "dhcp_changed": dhcp_changed,
        "old_dhcp": baseline.get("dhcp_server", "-"),
        "new_dhcp": current.get("dhcp_server", "-"),
        "new_hosts": new_hosts,
        "missing_hosts": missing_hosts,
        "mac_changed_hosts": mac_changed_hosts,
    }


def run_baseline_and_diff_checks(report: InterfaceDiagReport, reset_baseline: bool = False) -> None:
    """บันทึกหรือเปรียบเทียบ Network Baseline เพื่อตรวจจับความผิดปกติและผู้บุกรุก (--mode baseline)"""
    iface = report.interface
    ipv4_list, _ = get_ip_addresses(iface)

    if not ipv4_list or ipv4_list[0].get("local", "").startswith("169.254."):
        report.add_check(
            CheckResult(
                layer="L2-L3 (Baseline & Diff)",
                name="Network Baseline Snapshot",
                status=CheckStatus.FAIL,
                summary=f"พอร์ต {iface} ยังไม่มี IPv4 ในวงแลน จึงไม่สามารถสร้างหรือเทียบ Baseline ได้",
            )
        )
        return

    current = capture_current_snapshot(iface, report)
    b_path = _get_baseline_path(current["subnet"])

    if reset_baseline or not b_path.is_file():
        b_path.parent.mkdir(parents=True, exist_ok=True)
        b_path.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
        report.raw_context["baseline_data"] = {
            "mode": "saved",
            "path": str(b_path),
            "snapshot": current,
        }
        report.add_check(
            CheckResult(
                layer="L2-L3 (Baseline & Diff)",
                name="Baseline Snapshot Saved",
                status=CheckStatus.PASS,
                summary=(
                    f"💾 บันทึกภาพจำเครือข่ายปกติ (Baseline) ของวง {current['subnet']} สำเร็จ! "
                    f"(พบ {len(current['hosts'])} เครื่อง)"
                ),
                details=f"Gateway={current['gateway_ip']} ({current['gateway_mac'] or '-'}), DNS={', '.join(current['dns_servers']) or '-'}",
                recommendation="ในครั้งถัดไปเมื่อรันโหมดนี้ ระบบจะนำข้อมูลล่าสุดมาเทียบกับไฟล์นี้เพื่อหาอุปกรณ์แปลกปลอมให้อัตโนมัติ",
            )
        )
        return

    baseline = json.loads(b_path.read_text(encoding="utf-8"))
    diff = compare_snapshots(baseline, current)
    report.raw_context["baseline_data"] = {
        "mode": "diff",
        "path": str(b_path),
        "diff": diff,
    }

    if diff["gw_mac_changed"] or diff["dhcp_changed"]:
        report.add_check(
            CheckResult(
                layer="L2-L3 (Security Anomaly)",
                name="Gateway / DHCP Integrity Diff",
                status=CheckStatus.FAIL,
                summary="🚨 อันตราย! ตรวจพบ Gateway MAC หรือ DHCP Server เปลี่ยนไปจาก Baseline เดิม (เสี่ยง ARP Spoofing / Rogue Device)!",
                details=f"Gateway MAC: {diff['old_gw_mac']} -> {diff['new_gw_mac']} | DHCP: {diff['old_dhcp']} -> {diff['new_dhcp']}",
                recommendation="ตรวจสอบทันทีว่ามีการเปลี่ยน Router/Switch หรือมีผู้ไม่หวังดีปลอมเป็น Gateway ในวงแลนหรือไม่",
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L2-L3 (Security Anomaly)",
                name="Gateway / DHCP Integrity Diff",
                status=CheckStatus.PASS,
                summary="Gateway MAC, DHCP Server และ DNS ตรงกับ Baseline ปกติทุกประการ",
                details=f"เปรียบเทียบกับ Baseline เมื่อ {diff['baseline_time']}",
            )
        )

    new_cnt = len(diff["new_hosts"])
    miss_cnt = len(diff["missing_hosts"])
    chg_cnt = len(diff["mac_changed_hosts"])

    if new_cnt > 0 or chg_cnt > 0:
        report.add_check(
            CheckResult(
                layer="L2-L3 (Host Inventory Diff)",
                name="New / Changed Devices Alert",
                status=CheckStatus.WARN,
                summary=f"🆕 พบอุปกรณ์ใหม่เข้าวงแลน {new_cnt} เครื่อง, เปลี่ยน MAC {chg_cnt} เครื่อง และออฟไลน์ไป {miss_cnt} เครื่อง",
                details=f"ดูรายชื่อ IP, MAC และยี่ห้ออุปกรณ์ที่เปลี่ยนแปลงได้ในตารางด้านล่าง",
                recommendation="ตรวจสอบรายชื่อเครื่องใหม่ว่าได้รับอนุญาตเข้าใช้งานเครือข่ายหรือไม่ (หากต้องการยึดสภาพปัจจุบันเป็นฐานใหม่ ให้ใช้ `--save-baseline`)",
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L2-L3 (Host Inventory Diff)",
                name="Host Inventory Diff",
                status=CheckStatus.PASS,
                summary=f"ไม่พบอุปกรณ์แปลกปลอมใหม่ในวงแลน (ออนไลน์ {len(current['hosts'])} เครื่อง, ออฟไลน์ไป {miss_cnt} เครื่อง)",
                details=f"Baseline={diff['baseline_time']} -> Current={diff['current_time']}",
            )
        )
