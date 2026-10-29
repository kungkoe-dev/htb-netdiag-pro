"""
Hop-by-Hop Latency, Jitter & Bottleneck Analyzer
วิเคราะห์ว่าทำไมเน็ตช้า/กระตุก โดยแยกแยะระหว่าง:
  ด่านที่ 1: วงแลน/Wi-Fi ตึกเรา (Local Access -> Default Gateway)
  ด่านที่ 2: เครือข่ายหลัก/ห้องเซิร์ฟเวอร์องค์กร (Internal Core -> DNS/DHCP Server)
  ด่านที่ 3: อินเทอร์เน็ตภายนอก (External WAN/ISP -> 1.1.1.1)
พร้อมตาราง Hop-by-Hop Traceroute
"""

import re
import subprocess
from typing import Any, Dict, List, Optional

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .layer2_datalink import get_nmcli_device_info
from .layer3_network import get_interface_routes, get_ip_addresses


def measure_jitter_and_loss(
    target: str,
    iface: Optional[str] = None,
    count: int = 6,
    interval: float = 0.2,
    timeout_sec: int = 1,
) -> Dict[str, Any]:
    """
    ส่งแพ็กเกจ Ping ต่อเนื่องเพื่อวัดค่า Min/Avg/Max Latency (ms), Jitter (ความแกว่งของสัญญาณ ms) และ Packet Loss (%)
    """
    cmd = ["ping", "-n", "-c", str(count), "-i", str(interval), "-W", str(timeout_sec)]
    if iface:
        cmd.extend(["-I", iface])
    cmd.append(target)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=int(count * timeout_sec + 4))
        out = proc.stdout

        rtts: List[float] = []
        for line in out.splitlines():
            m_time = re.search(r"time=([\d\.]+)\s*ms", line)
            if m_time:
                rtts.append(float(m_time.group(1)))

        loss_pct = 100.0
        m_loss = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", out)
        if m_loss:
            loss_pct = float(m_loss.group(1))

        if not rtts:
            return {
                "target": target,
                "reachable": False,
                "loss_pct": loss_pct,
                "min_ms": None,
                "avg_ms": None,
                "max_ms": None,
                "jitter_ms": None,
            }

        min_ms = round(min(rtts), 2)
        avg_ms = round(sum(rtts) / len(rtts), 2)
        max_ms = round(max(rtts), 2)

        # คำนวณค่า Jitter (ค่าเฉลี่ยความต่างของเวลาระหว่างแพ็กเกจลูกติดกัน ตามนิยาม RFC 3550 / IPDV)
        if len(rtts) >= 2:
            diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
            jitter_ms = round(sum(diffs) / len(diffs), 2)
        else:
            jitter_ms = 0.0

        return {
            "target": target,
            "reachable": True,
            "loss_pct": loss_pct,
            "min_ms": min_ms,
            "avg_ms": avg_ms,
            "max_ms": max_ms,
            "jitter_ms": jitter_ms,
        }
    except Exception:
        return {
            "target": target,
            "reachable": False,
            "loss_pct": 100.0,
            "min_ms": None,
            "avg_ms": None,
            "max_ms": None,
            "jitter_ms": None,
        }


def run_hop_traceroute(target: str = "1.1.1.1", iface: Optional[str] = None, max_hops: int = 10) -> List[Dict[str, Any]]:
    """รัน traceroute เพื่อดูเวลาตอบสนองในแต่ละด่าน (Hop-by-Hop)"""
    cmd = ["traceroute", "-n", "-w", "1", "-q", "2", "-m", str(max_hops)]
    if iface:
        cmd.extend(["-i", iface])
    cmd.append(target)

    hops: List[Dict[str, Any]] = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops * 2 + 4)
        for line in proc.stdout.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            m_hop = re.match(r"^(\d+)\s+(.*)$", line)
            if not m_hop:
                continue
            hop_num = int(m_hop.group(1))
            rest = m_hop.group(2).strip()

            if rest.replace("*", "").strip() == "":
                hops.append(
                    {
                        "hop": hop_num,
                        "ip": "* (ไม่ตอบ ICMP / ปิดซ่อนตัว)",
                        "avg_ms": None,
                        "status": "timeout",
                    }
                )
                continue

            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
            hop_ip = ip_match.group(1) if ip_match else "unknown"
            times = [float(x) for x in re.findall(r"([\d\.]+)\s*ms", rest)]
            avg_t = round(sum(times) / len(times), 2) if times else None
            hops.append(
                {
                    "hop": hop_num,
                    "ip": hop_ip,
                    "avg_ms": avg_t,
                    "status": "ok" if avg_t is not None else "timeout",
                }
            )
    except Exception:
        pass
    return hops


def run_bottleneck_checks(report: InterfaceDiagReport) -> None:
    """
    วิเคราะห์จุดคอขวดของสัญญาณเครือข่าย (3-Tier Latency/Jitter & Hop-by-Hop Traceroute)
    """
    iface = report.interface
    ipv4_list, _ = get_ip_addresses(iface)
    if not ipv4_list:
        report.add_check(
            CheckResult(
                layer="L3-L4 (Path & Bottleneck)",
                name="Bottleneck & Jitter Analysis",
                status=CheckStatus.FAIL,
                summary=f"พอร์ต {iface} ยังไม่มี IPv4 Address จึงไม่สามารถทดสอบวัดความหน่วงและจุดคอขวดได้",
                recommendation="ตรวจสอบให้พอร์ตได้รับ IP ก่อน หรือสลับไปตรวจพอร์ตที่ออนไลน์อยู่",
            )
        )
        return

    nm_info = report.raw_context.get("nmcli") or get_nmcli_device_info(iface)
    routes = get_interface_routes(iface)
    default_routes = [r for r in routes if r.get("dst") == "default"]
    gateway = default_routes[0].get("gateway") if default_routes else nm_info.get("IP4.GATEWAY", "")

    dns_servers: List[str] = []
    for k, v in nm_info.items():
        if k.startswith("IP4.DNS") and v:
            dns_servers.append(v)

    core_target = dns_servers[0] if dns_servers else ""
    if core_target == gateway:
        core_target = dns_servers[1] if len(dns_servers) > 1 else ""

    tiers: List[Dict[str, Any]] = []

    # ด่านที่ 1: Local Access (Default Gateway)
    gw_metrics = None
    if gateway and gateway != "--":
        gw_metrics = measure_jitter_and_loss(gateway, iface=iface, count=6)
        tiers.append(
            {
                "tier": "ด่านที่ 1: วงแลน/Wi-Fi ตึกเรา (Local Access -> Gateway)",
                "target": gateway,
                **gw_metrics,
            }
        )

    # ด่านที่ 2: Internal Core / Enterprise Server (DNS / Core Switch)
    core_metrics = None
    if core_target:
        core_metrics = measure_jitter_and_loss(core_target, iface=iface, count=6)
        tiers.append(
            {
                "tier": "ด่านที่ 2: ระบบกลางองค์กร (Core Network / Internal DNS)",
                "target": core_target,
                **core_metrics,
            }
        )

    # ด่านที่ 3: External Internet (Cloudflare 1.1.1.1)
    wan_metrics = measure_jitter_and_loss("1.1.1.1", iface=iface, count=6)
    tiers.append(
        {
            "tier": "ด่านที่ 3: อินเทอร์เน็ตภายนอก (External WAN / ISP)",
            "target": "1.1.1.1",
            **wan_metrics,
        }
    )

    # รัน Hop-by-Hop Traceroute
    hops = run_hop_traceroute("1.1.1.1", iface=iface, max_hops=10)

    report.raw_context["bottleneck_data"] = {
        "tiers": tiers,
        "hops": hops,
    }

    # วิเคราะห์ผลด่านที่ 1 (Gateway)
    if gw_metrics:
        if not gw_metrics["reachable"]:
            report.add_check(
                CheckResult(
                    layer="L3-L4 (Path & Bottleneck)",
                    name="Tier 1: Local LAN / Wi-Fi Quality",
                    status=CheckStatus.FAIL,
                    summary=f"ติดต่อด่านแรก (Gateway {gateway}) ไม่ได้เลย (Loss 100%)",
                    recommendation="ปัญหาอยู่ที่สายแลน, พอร์ต Switch ในตึก หรือการชนกันของวงแลน",
                )
            )
            return
        elif gw_metrics["loss_pct"] > 0 or (gw_metrics["avg_ms"] or 0) > 15 or (gw_metrics["jitter_ms"] or 0) > 10:
            report.add_check(
                CheckResult(
                    layer="L3-L4 (Path & Bottleneck)",
                    name="Tier 1: Local LAN / Wi-Fi Quality",
                    status=CheckStatus.WARN,
                    summary=(
                        f"⚠️ พบอาการหน่วง/แกว่งตั้งแต่ด่านแรกในตึก! (Gateway {gateway}: "
                        f"Avg={gw_metrics['avg_ms']} ms, Jitter={gw_metrics['jitter_ms']} ms, Loss={gw_metrics['loss_pct']}%)"
                    ),
                    details="ปกติการคุยกับ Gateway ในตึกควรมี Latency < 5 ms และ Jitter < 3 ms",
                    recommendation=(
                        "จุดคอขวดอยู่ในวงแลนหรือ Wi-Fi ของคุณเอง:\n"
                        "1. หากใช้ Wi-Fi: สัญญาณอาจอ่อนหรือมีคลื่นรบกวนสูง\n"
                        "2. หากใช้สายแลน: อาจมีเครื่องในวงทำ Broadcast Storm / โหลดบิตเต็มพอร์ต Switch"
                    ),
                )
            )
        else:
            report.add_check(
                CheckResult(
                    layer="L3-L4 (Path & Bottleneck)",
                    name="Tier 1: Local LAN / Wi-Fi Quality",
                    status=CheckStatus.PASS,
                    summary=(
                        f"สัญญาณภายในวงแลน/ตึกเสถียรดีมาก (Gateway {gateway}: "
                        f"Avg={gw_metrics['avg_ms']} ms, Jitter={gw_metrics['jitter_ms']} ms, Loss=0%)"
                    ),
                )
            )

    # วิเคราะห์ผลด่านที่ 2 (Internal Core Server)
    if core_metrics:
        if not core_metrics["reachable"]:
            report.add_check(
                CheckResult(
                    layer="L3-L4 (Path & Bottleneck)",
                    name="Tier 2: Enterprise Core / Server Link",
                    status=CheckStatus.WARN,
                    summary=f"ปิงหาเซิร์ฟเวอร์กลาง ({core_target}) ไม่ตอบกลับ (อาจบล็อก ICMP หรือลิงก์ระหว่างตึกมีปัญหา)",
                )
            )
        elif core_metrics["loss_pct"] > 0 or (core_metrics["avg_ms"] or 0) > 30 or (core_metrics["jitter_ms"] or 0) > 15:
            report.add_check(
                CheckResult(
                    layer="L3-L4 (Path & Bottleneck)",
                    name="Tier 2: Enterprise Core / Server Link",
                    status=CheckStatus.WARN,
                    summary=(
                        f"⚠️ พบคอขวดระหว่างตึกไปหา Core Server ({core_target})! "
                        f"(Avg={core_metrics['avg_ms']} ms, Jitter={core_metrics['jitter_ms']} ms, Loss={core_metrics['loss_pct']}%)"
                    ),
                    recommendation="ตรวจสอบลิงก์ Fiber Uplink ระหว่างอาคาร หรือภาระงานบน Core Switch ขององค์กร",
                )
            )
        else:
            report.add_check(
                CheckResult(
                    layer="L3-L4 (Path & Bottleneck)",
                    name="Tier 2: Enterprise Core / Server Link",
                    status=CheckStatus.PASS,
                    summary=(
                        f"ลิงก์เชื่อมต่อไปยังระบบกลางขององค์กร ({core_target}) รวดเร็วปกติ "
                        f"(Avg={core_metrics['avg_ms']} ms, Jitter={core_metrics['jitter_ms']} ms, Loss=0%)"
                    ),
                )
            )

    # วิเคราะห์ผลด่านที่ 3 (External WAN / ISP)
    if not wan_metrics["reachable"]:
        report.add_check(
            CheckResult(
                layer="L3-L4 (Path & Bottleneck)",
                name="Tier 3: External Internet / ISP Quality",
                status=CheckStatus.FAIL,
                summary="ไม่สามารถเชื่อมต่อออกสู่อินเทอร์เน็ตภายนอก (1.1.1.1) ได้ (Loss 100%)",
                recommendation="ระบบภายในตึกปกติ แต่ลิงก์ออกอินเทอร์เน็ตภายนอก (Firewall / WAN ISP) ขาดหรือบล็อกการเชื่อมต่อ",
            )
        )
    elif wan_metrics["loss_pct"] > 0 or (wan_metrics["avg_ms"] or 0) > 80 or (wan_metrics["jitter_ms"] or 0) > 25:
        report.add_check(
            CheckResult(
                layer="L3-L4 (Path & Bottleneck)",
                name="Tier 3: External Internet / ISP Quality",
                status=CheckStatus.WARN,
                summary=(
                    f"⚠️ พบอาการหน่วง/กระตุกที่ขาออกอินเทอร์เน็ตภายนอก (1.1.1.1: "
                    f"Avg={wan_metrics['avg_ms']} ms, Jitter={wan_metrics['jitter_ms']} ms, Loss={wan_metrics['loss_pct']}%)"
                ),
                recommendation=(
                    "เครือข่ายภายในตึกของคุณปกติ แต่ช้าที่ขาออกอินเทอร์เน็ต (Firewall ขาออกแบนด์วิดท์เต็ม หรือลิงก์ ISP ภายนอกมีปัญหา)"
                ),
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L3-L4 (Path & Bottleneck)",
                name="Tier 3: External Internet / ISP Quality",
                status=CheckStatus.PASS,
                summary=(
                    f"คุณภาพอินเทอร์เน็ตขาออกดีเยี่ยม ไม่พบคอขวด (1.1.1.1: "
                    f"Avg={wan_metrics['avg_ms']} ms, Jitter={wan_metrics['jitter_ms']} ms, Loss=0%)"
                ),
                details=f"ผ่านเส้นทาง Traceroute จำนวน {len(hops)} ด่าน (Hops)",
            )
        )
