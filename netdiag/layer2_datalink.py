"""
Layer 2 - Data Link, Switch Discovery (LLDP/CDP), 802.1X & ARP Table
ตรวจสอบการเชื่อมต่อระดับ Data Link, สถานะ 802.1X, ข้อมูลจาก Switch และตาราง ARP
"""

import os
import subprocess
from typing import Dict, List

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .htb_arsenal import lookup_mac_vendor


def get_nmcli_device_info(iface: str) -> Dict[str, str]:
    """ดึงข้อมูลสถานะพอร์ตจาก NetworkManager (nmcli)"""
    info: Dict[str, str] = {}
    try:
        proc = subprocess.run(
            ["nmcli", "-t", "-f", "GENERAL,IP4,DHCP4,WIFI-PROPERTIES", "device", "show", iface],
            capture_output=True,
            text=True,
            timeout=4,
        )
        for line in proc.stdout.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip()] = v.strip()
    except Exception:
        pass
    return info


def get_arp_neighbors(iface: str) -> List[Dict[str, str]]:
    """ดึงตาราง ARP / Neighbor ของ Interface"""
    neighbors: List[Dict[str, str]] = []
    try:
        proc = subprocess.run(
            ["ip", "neigh", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            ip_addr = parts[0]
            mac = ""
            state = parts[-1] if parts else "UNKNOWN"
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    mac = parts[idx + 1]
            neighbors.append({"ip": ip_addr, "mac": mac, "state": state})
    except Exception:
        pass
    return neighbors


def sniff_lldp_cdp_brief(iface: str, timeout_sec: int = 3) -> Dict[str, str]:
    """
    หากรันด้วยสิทธิ์ root (หรือมีสิทธิ์ดักแพ็กเกจ) จะลองฟังแพ็กเกจ LLDP/CDP/STP สั้นๆ
    เพื่อดูข้อมูล Switch ต้นทาง
    """
    if os.geteuid() != 0:
        return {"status": "no_root"}
    try:
        proc = subprocess.run(
            [
                "tcpdump",
                "-i",
                iface,
                "-nn",
                "-v",
                "-c",
                "1",
                "ether proto 0x88cc or ether[20:2] == 0x2000",
            ],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        out = (proc.stdout or "").strip()
        if out:
            return {"status": "captured", "raw": out}
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except Exception:
        pass
    return {"status": "none"}


def run_layer2_checks(report: InterfaceDiagReport, listen_lldp: bool = False) -> None:
    """รันการตรวจสอบ Layer 2 (Data Link Layer)"""
    iface = report.interface
    nm_info = get_nmcli_device_info(iface)
    report.raw_context["nmcli"] = nm_info

    nm_state = nm_info.get("GENERAL.STATE", "unknown")
    nm_reason = nm_info.get("GENERAL.REASON", "")
    nm_conn = nm_info.get("GENERAL.CONNECTION", "--")

    # 1. ตรวจสอบ NetworkManager State & 802.1X / Port Authentication
    if "need-auth" in nm_state.lower() or "802.1x" in nm_reason.lower():
        report.add_check(
            CheckResult(
                layer="L2 (Data Link)",
                name="Port Security / 802.1X Auth",
                status=CheckStatus.FAIL,
                summary=f"พอร์ตแลนติดระบบยืนยันตัวตน (802.1X / Port Authentication)",
                details=f"State={nm_state}, Reason={nm_reason}, Profile={nm_conn}",
                recommendation=(
                    "เครือข่ายองค์กรนี้บังคับใช้ 802.1X (NAC) หรือต้องลงทะเบียน MAC Address:\n"
                    f"1. แจ้ง MAC Address ({report.mac_address}) ให้ทีม IT/Network ลงทะเบียน (MAB)\n"
                    "2. หรือตั้งค่า 802.1X Credentials (Username/Certificate) ใน NetworkManager"
                ),
            )
        )
    elif "connecting (getting ip configuration)" in nm_state.lower():
        report.add_check(
            CheckResult(
                layer="L2 (Data Link)",
                name="NetworkManager Link State",
                status=CheckStatus.WARN,
                summary=f"เชื่อมต่อ Layer 2 แล้ว แต่กำลังรอรับ IP (State: {nm_state})",
                details=f"Connection={nm_conn}, Reason={nm_reason}",
                recommendation="สายสัญญาณเชื่อมต่อแล้ว แต่ขั้นตอนขอรับ IP (DHCP) กำลังค้างหรือไม่ได้รับการตอบกลับ",
            )
        )
    elif "connected" in nm_state.lower():
        report.add_check(
            CheckResult(
                layer="L2 (Data Link)",
                name="Data Link Connection State",
                status=CheckStatus.PASS,
                summary=f"สถานะโปรไฟล์เชื่อมต่อสำเร็จ (Profile: {nm_conn})",
                details=f"State={nm_state}",
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L2 (Data Link)",
                name="Data Link Connection State",
                status=CheckStatus.INFO,
                summary=f"สถานะการจัดการพอร์ต: {nm_state}",
                details=f"Connection={nm_conn}, Reason={nm_reason}",
            )
        )

    # 2. ตรวจสอบตาราง ARP / Neighbor Cache
    neighbors = get_arp_neighbors(iface)
    report.raw_context["neighbors"] = neighbors

    reachable = [n for n in neighbors if n["mac"] and n["state"] in ("REACHABLE", "STALE", "DELAY", "PERMANENT")]
    failed_arp = [n for n in neighbors if n["state"] in ("FAILED", "INCOMPLETE")]

    if reachable:
        sample = ", ".join(
            f"{n['ip']} ({n['mac']} [{lookup_mac_vendor(n['mac'])}])" for n in reachable[:3]
        )
        report.add_check(
            CheckResult(
                layer="L2 (Data Link)",
                name="ARP / Neighbor Resolution",
                status=CheckStatus.PASS,
                summary=f"มองเห็นอุปกรณ์ในวงแลนระดับ MAC Address จำนวน {len(reachable)} รายการ",
                details=f"ตัวอย่าง: {sample}",
            )
        )
    elif failed_arp:
        sample = ", ".join(f"{n['ip']} [{n['state']}]" for n in failed_arp[:3])
        report.add_check(
            CheckResult(
                layer="L2 (Data Link)",
                name="ARP / Neighbor Resolution",
                status=CheckStatus.FAIL,
                summary=f"ส่ง ARP ถามหา MAC Address ในวงแลนแล้วไม่มีใครตอบกลับ ({sample})",
                details="ARP State = FAILED / INCOMPLETE",
                recommendation=(
                    "เครื่องไม่สามารถสื่อสารระดับ Layer 2 กับ Gateway หรือเครื่องในวงได้:\n"
                    "1. พอร์ต Switch อาจตั้งค่า **VLAN ผิดวง** กับ IP ที่ตั้งไว้\n"
                    "2. พอร์ต Switch อาจติด **Port Security** (บล็อก MAC Address ของเครื่องคุณ)\n"
                    "3. ระบบเปิด Client Isolation หรือสายไฟเบอร์/Uplink ของ Switch ขาด"
                ),
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L2 (Data Link)",
                name="ARP / Neighbor Resolution",
                status=CheckStatus.WARN,
                summary="ยังไม่พบรายการ MAC Address ในตาราง ARP ของพอร์ตนี้",
                details="ARP Cache ว่างเปล่า (อาจเพิ่งเสียบสาย หรือยังไม่ได้รับ IP เพื่อคุยกับ Gateway)",
            )
        )

    # 3. Switch Discovery (LLDP / CDP) เมื่อเปิดโหมด listen_lldp
    if listen_lldp:
        lldp_res = sniff_lldp_cdp_brief(iface)
        if lldp_res.get("status") == "captured":
            report.add_check(
                CheckResult(
                    layer="L2 (Data Link)",
                    name="Switch Discovery (LLDP/CDP)",
                    status=CheckStatus.PASS,
                    summary="ตรวจพบข้อมูลประกาศตัวตนจาก Switch ต้นทาง (LLDP/CDP)",
                    details=lldp_res.get("raw", "")[:300],
                )
            )
        elif lldp_res.get("status") == "no_root":
            report.add_check(
                CheckResult(
                    layer="L2 (Data Link)",
                    name="Switch Discovery (LLDP/CDP)",
                    status=CheckStatus.INFO,
                    summary="ข้ามการดักฟัง LLDP/CDP (ต้องรันด้วย sudo หากต้องการดูชื่อ Switch/VLAN)",
                )
            )
        else:
            report.add_check(
                CheckResult(
                    layer="L2 (Data Link)",
                    name="Switch Discovery (LLDP/CDP)",
                    status=CheckStatus.INFO,
                    summary="ไม่พบแพ็กเกจ LLDP/CDP ในช่วงเวลาสั้นๆ (ปกติจะส่งทุก 30-60 วินาที)",
                )
            )
