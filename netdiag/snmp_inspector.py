"""
Switch, Router & Printer SNMP Deep Inspector (--mode snmp)
ดึงข้อมูลเชิงลึกจาก Switch, Router, NAS หรือ Network Printer ด้วยโปรโตคอล SNMP (Read-Only v1/v2c):
  - ใช้ `snmpwalk` (มีใน HTB OS) เพื่ออ่าน sysName, sysDescr, sysUpTime
  - อ่านตารางพอร์ต IF-MIB (ifDescr, ifOperStatus, ifSpeed, ifInErrors, ifOutErrors)
  - ช่วยให้ Network Engineer เห็นพอร์ต Switch ที่เกิด Error หรือ Link Down ได้ทันทีจาก CLI
"""

import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .layer2_datalink import get_nmcli_device_info
from .layer3_network import get_interface_routes


def _run_snmpwalk_oid(target_ip: str, community: str, oid: str, timeout_sec: int = 3) -> List[str]:
    """รันคำสั่ง snmpwalk แบบ Read-Only ไปยังอุปกรณ์เป้าหมาย"""
    if not shutil.which("snmpwalk"):
        return []
    try:
        proc = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, "-t", "1", "-r", "1", "-Oqv", target_ip, oid],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        if proc.returncode != 0:
            return []
        return [ln.strip().strip('"') for ln in proc.stdout.splitlines() if ln.strip()]
    except Exception:
        return []


def inspect_snmp_device(target_ip: str, community: str = "public") -> Dict[str, Any]:
    """ดึงข้อมูลระบบและสถานะพอร์ตทั้งหมดจากอุปกรณ์ผ่าน SNMPv2c"""
    sys_descr = _run_snmpwalk_oid(target_ip, community, "1.3.6.1.2.1.1.1.0")
    if not sys_descr:
        return {"reachable": False, "target_ip": target_ip, "community": community}

    sys_uptime = _run_snmpwalk_oid(target_ip, community, "1.3.6.1.2.1.1.3.0")
    sys_name = _run_snmpwalk_oid(target_ip, community, "1.3.6.1.2.1.1.5.0")

    if_descrs = _run_snmpwalk_oid(target_ip, community, "1.3.6.1.2.1.2.2.1.2", timeout_sec=5)
    if_speeds = _run_snmpwalk_oid(target_ip, community, "1.3.6.1.2.1.2.2.1.5", timeout_sec=5)
    if_opers = _run_snmpwalk_oid(target_ip, community, "1.3.6.1.2.1.2.2.1.8", timeout_sec=5)
    if_in_errs = _run_snmpwalk_oid(target_ip, community, "1.3.6.1.2.1.2.2.1.14", timeout_sec=5)
    if_out_errs = _run_snmpwalk_oid(target_ip, community, "1.3.6.1.2.1.2.2.1.20", timeout_sec=5)

    ports: List[Dict[str, Any]] = []
    for idx, name in enumerate(if_descrs[:32]):
        oper = if_opers[idx] if idx < len(if_opers) else "unknown"
        raw_speed = if_speeds[idx] if idx < len(if_speeds) else "0"
        speed_mbps = 0
        if raw_speed.isdigit():
            speed_mbps = round(int(raw_speed) / 1_000_000)

        in_err = int(if_in_errs[idx]) if idx < len(if_in_errs) and if_in_errs[idx].isdigit() else 0
        out_err = int(if_out_errs[idx]) if idx < len(if_out_errs) and if_out_errs[idx].isdigit() else 0

        ports.append(
            {
                "index": idx + 1,
                "name": name,
                "status": "UP" if "up" in oper.lower() or oper == "1" else "DOWN",
                "speed_mbps": speed_mbps,
                "in_errors": in_err,
                "out_errors": out_err,
            }
        )

    return {
        "reachable": True,
        "target_ip": target_ip,
        "community": community,
        "sys_name": sys_name[0] if sys_name else "-",
        "sys_descr": sys_descr[0],
        "sys_uptime": sys_uptime[0] if sys_uptime else "-",
        "ports": ports,
    }


def run_snmp_inspector(
    report: InterfaceDiagReport,
    target_host: Optional[str] = None,
    community: str = "public",
) -> None:
    """รันการตรวจสอบอุปกรณ์เครือข่ายผ่าน SNMP (--mode snmp)"""
    iface = report.interface
    if not target_host:
        nm_info = report.raw_context.get("nmcli") or get_nmcli_device_info(iface)
        routes = get_interface_routes(iface)
        default_routes = [r for r in routes if r.get("dst") == "default"]
        target_host = (
            default_routes[0].get("gateway")
            if default_routes
            else nm_info.get("IP4.GATEWAY", "10.8.70.1")
        )

    if not shutil.which("snmpwalk"):
        report.add_check(
            CheckResult(
                layer="L7 (SNMP Inspector)",
                name="SNMP Tool Availability",
                status=CheckStatus.WARN,
                summary="ไม่พบคำสั่ง snmpwalk ในระบบ",
                recommendation="ติดตั้งแพ็กเกจ snmp เพื่อเปิดใช้งานโหมดตรวจสอบ Switch/Router ผ่าน SNMP",
            )
        )
        return

    snmp_data = inspect_snmp_device(target_host or "127.0.0.1", community=community or "public")
    report.raw_context["snmp_data"] = snmp_data

    if not snmp_data["reachable"]:
        report.add_check(
            CheckResult(
                layer="L7 (SNMP Inspector)",
                name=f"SNMP Query ({target_host})",
                status=CheckStatus.WARN,
                summary=f"อุปกรณ์ {target_host} ไม่ตอบสนอง SNMP (Community='{community}' หรือปิด UDP Port 161 ไว้)",
                details="อุปกรณ์องค์กรส่วนใหญ่ปิด SNMP หรือเปลี่ยนชื่อ Community String จาก 'public' เพื่อความปลอดภัย",
                recommendation=(
                    f"1. ลองระบุ Community String ที่ถูกต้องขององค์กรด้วย `--snmp-community <string>`\n"
                    f"2. หรือสแกนเช็กพอร์ต/หน้าเว็บจัดการแทนด้วย: `./netdiag.py --mode target --target {target_host}`"
                ),
            )
        )
        return

    err_ports = [p for p in snmp_data["ports"] if p["in_errors"] > 0 or p["out_errors"] > 0]
    up_ports = [p for p in snmp_data["ports"] if p["status"] == "UP"]

    report.add_check(
        CheckResult(
            layer="L7 (SNMP Inspector)",
            name=f"SNMP Device Audit ({snmp_data['sys_name']})",
            status=CheckStatus.WARN if err_ports else CheckStatus.PASS,
            summary=(
                f"🖧 ดึงข้อมูล SNMP สำเร็จ: {snmp_data['sys_name']} ({target_host}) | "
                f"พอร์ต UP={len(up_ports)}/{len(snmp_data['ports'])}"
                + (f" | ⚠️ พบพอร์ตที่มี Error={len(err_ports)}" if err_ports else " | ไม่พบ Port Error")
            ),
            details=f"Uptime: {snmp_data['sys_uptime']} | รุ่น/OS: {snmp_data['sys_descr'][:140]}",
        )
    )
