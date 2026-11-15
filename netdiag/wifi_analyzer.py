"""
Wi-Fi Signal, Channel Interference & Mesh Roaming Analyzer (--mode wifi)
วิเคราะห์คุณภาพสัญญาณ Wi-Fi, ช่องสัญญาณชนกัน (Co-Channel Interference) และอาการ Sticky Client (ไม่ยอม Roam):
  - ใช้ `iw dev <iface> link` เพื่อดูค่า dBm, Frequency, Channel Width (20/40/80/160MHz) และ RX/TX Bitrate
  - ใช้ `nmcli dev wifi list` เพื่อสแกน Access Point รอบข้างและหาจุดที่สัญญาณแรงกว่าหรือช่องสัญญาณชนกัน
  - ใช้ฐานข้อมูล IEEE OUI เพื่อระบุยี่ห้อของ Access Point (BSSID Vendor)
"""

import re
import shutil
import subprocess
from collections import Counter
from typing import Any, Dict, List

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .htb_arsenal import lookup_mac_vendor
from .layer1_physical import classify_interface


def get_iw_link_info(iface: str) -> Dict[str, Any]:
    """ดึงข้อมูลการเชื่อมต่อ Wi-Fi ปัจจุบันจาก `iw dev <iface> link`"""
    info: Dict[str, Any] = {
        "connected": False,
        "bssid": "",
        "ssid": "",
        "freq_mhz": 0,
        "band": "-",
        "signal_dbm": None,
        "rx_bitrate": "-",
        "tx_bitrate": "-",
        "channel_width": "-",
    }
    if not shutil.which("iw"):
        return info
    try:
        proc = subprocess.run(["iw", "dev", iface, "link"], capture_output=True, text=True, timeout=3)
        out = proc.stdout
        if "Not connected." in out or not out.strip():
            return info

        m_bssid = re.search(r"Connected to\s+([0-9a-fA-F:]{17})", out)
        if m_bssid:
            info["connected"] = True
            info["bssid"] = m_bssid.group(1).lower()

        m_ssid = re.search(r"SSID:\s*(.+)", out)
        if m_ssid:
            info["ssid"] = m_ssid.group(1).strip()

        m_freq = re.search(r"freq:\s*(\d+)", out)
        if m_freq:
            freq = int(m_freq.group(1))
            info["freq_mhz"] = freq
            info["band"] = "5 GHz" if freq >= 5000 else ("6 GHz" if freq >= 5925 else "2.4 GHz")

        m_sig = re.search(r"signal:\s*(-?\d+)\s*dBm", out)
        if m_sig:
            info["signal_dbm"] = int(m_sig.group(1))

        m_rx = re.search(r"rx bitrate:\s*(.+)", out)
        if m_rx:
            info["rx_bitrate"] = m_rx.group(1).strip()
            m_w = re.search(r"(\d+MHz)", info["rx_bitrate"])
            if m_w:
                info["channel_width"] = m_w.group(1)

        m_tx = re.search(r"tx bitrate:\s*(.+)", out)
        if m_tx:
            info["tx_bitrate"] = m_tx.group(1).strip()
    except Exception:
        pass
    return info


def scan_nearby_wifi_aps() -> List[Dict[str, Any]]:
    """สแกน Access Point รอบข้างด้วย `nmcli -t -f ... dev wifi list`"""
    aps: List[Dict[str, Any]] = []
    if not shutil.which("nmcli"):
        return aps
    try:
        proc = subprocess.run(
            [
                "nmcli",
                "-t",
                "-f",
                "IN-USE,SSID,BSSID,MODE,CHAN,FREQ,SIGNAL,SECURITY",
                "dev",
                "wifi",
                "list",
            ],
            capture_output=True,
            text=True,
            timeout=6,
        )
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue
            fields = [f.replace(r"\:", ":") for f in re.split(r"(?<!\\):", line)]
            if len(fields) < 8:
                continue
            in_use = fields[0].strip() == "*"
            ssid = fields[1].strip() or "<Hidden SSID>"
            bssid = fields[2].strip().lower()
            chan = int(fields[4]) if fields[4].strip().isdigit() else 0
            freq_str = fields[5].strip()
            signal_pct = int(fields[6]) if fields[6].strip().isdigit() else 0
            sec = fields[7].strip() or "OPEN"
            aps.append(
                {
                    "in_use": in_use,
                    "ssid": ssid,
                    "bssid": bssid,
                    "vendor": lookup_mac_vendor(bssid),
                    "chan": chan,
                    "freq": freq_str,
                    "signal_pct": signal_pct,
                    "security": sec,
                }
            )
    except Exception:
        pass
    aps.sort(key=lambda x: (not x["in_use"], -x["signal_pct"]))
    return aps


def run_wifi_diagnostics(report: InterfaceDiagReport) -> None:
    """รันการวิเคราะห์สัญญาณ Wi-Fi, ช่องสัญญาณชนกัน และ Mesh Roaming (--mode wifi)"""
    iface = report.interface
    if classify_interface(iface) != "wifi":
        report.add_check(
            CheckResult(
                layer="L1-L2 (Wi-Fi Radio)",
                name="Wi-Fi Interface Check",
                status=CheckStatus.INFO,
                summary=f"พอร์ต {iface} เป็นพอร์ตสายแลน (Ethernet) ไม่ใช่ Wi-Fi จึงข้ามการสแกนคลื่นวิทยุ",
                details="หากต้องการตรวจคลื่น Wi-Fi กรุณาเลือกพอร์ตไร้สาย เช่น wlp4s0",
            )
        )
        return

    link = get_iw_link_info(iface)
    if not link["connected"]:
        report.add_check(
            CheckResult(
                layer="L1-L2 (Wi-Fi Radio)",
                name="Wi-Fi Association Status",
                status=CheckStatus.FAIL,
                summary=f"พอร์ต {iface} ยังไม่ได้เชื่อมต่อกับ Access Point (Wi-Fi) ใดๆ",
                recommendation="ตรวจสอบว่าเปิดสวิตช์ Wi-Fi และเลือกเชื่อมต่อ SSID ที่ถูกต้องแล้ว",
            )
        )
        return

    aps = scan_nearby_wifi_aps()
    current_ap = next((a for a in aps if a["in_use"]), None)
    current_chan = current_ap["chan"] if current_ap else 0
    current_sig_pct = current_ap["signal_pct"] if current_ap else 0
    ap_vendor = lookup_mac_vendor(link["bssid"])

    co_channel_aps = [
        a for a in aps if not a["in_use"] and current_chan and a["chan"] == current_chan
    ]
    better_same_ssid = [
        a
        for a in aps
        if not a["in_use"]
        and a["ssid"] == link["ssid"]
        and a["signal_pct"] >= current_sig_pct + 15
    ]

    sig_dbm = link["signal_dbm"]
    if sig_dbm is not None and sig_dbm >= -67:
        sig_status = CheckStatus.PASS
        sig_desc = f"สัญญาณแรงดีมาก ({sig_dbm} dBm)"
    elif sig_dbm is not None and sig_dbm >= -75:
        sig_status = CheckStatus.WARN
        sig_desc = f"สัญญาณปานกลาง ({sig_dbm} dBm — อาจเริ่มมีอาการช้าเมื่ออยู่ไกล)"
    else:
        sig_status = CheckStatus.FAIL
        sig_desc = f"สัญญาณอ่อนมาก ({sig_dbm} dBm — เสี่ยงเน็ตหลุดและ Packet Loss สูง)"

    report.raw_context["wifi_data"] = {
        "link": link,
        "ap_vendor": ap_vendor,
        "current_chan": current_chan,
        "current_sig_pct": current_sig_pct,
        "co_channel_count": len(co_channel_aps),
        "better_same_ssid": better_same_ssid,
        "nearby_aps": aps[:15],
        "channel_counts": dict(Counter(a["chan"] for a in aps if a["chan"] > 0)),
    }

    report.add_check(
        CheckResult(
            layer="L1-L2 (Wi-Fi Radio)",
            name="Signal Quality & Link Speed",
            status=sig_status,
            summary=(
                f"📶 เชื่อมต่อ '{link['ssid']}' ({link['band']} Ch.{current_chan or '?'}) | "
                f"{sig_desc} | ความเร็ว RX: {link['rx_bitrate'].split()[0]} Mbps"
            ),
            details=(
                f"AP BSSID={link['bssid']} ({ap_vendor}), Width={link['channel_width']}, "
                f"TX={link['tx_bitrate']}"
            ),
        )
    )

    if better_same_ssid:
        best = better_same_ssid[0]
        report.add_check(
            CheckResult(
                layer="L2 (Mesh / Roaming)",
                name="Sticky Client & Mesh Roaming",
                status=CheckStatus.WARN,
                summary=(
                    f"⚠️ พบ Access Point ชื่อ '{best['ssid']}' ตัวอื่นที่สัญญาณแรงกว่า ({best['signal_pct']}% vs {current_sig_pct}%) "
                    "แต่เครื่องยังไม่ยอมสลับไปเกาะ (Sticky Client)!"
                ),
                details=f"AP ที่แรงกว่า: BSSID={best['bssid']} ({best['vendor']}) Ch.{best['chan']} ({best['freq']})",
                recommendation="ลองปิด-เปิด Wi-Fi ใหม่ 1 ครั้งเพื่อให้การ์ดแลน Roam ไปเกาะ Access Point ตัวที่อยู่ใกล้กว่า",
            )
        )
    elif len(co_channel_aps) >= 3:
        report.add_check(
            CheckResult(
                layer="L1 (RF Interference)",
                name="Wi-Fi Channel Congestion",
                status=CheckStatus.WARN,
                summary=(
                    f"⚠️ ช่องสัญญาณ Channel {current_chan} หนาแน่น! มี AP รอบข้างใช้ช่องเดียวกันอีก {len(co_channel_aps)} ตัว"
                ),
                details=f"คลื่นชนกัน (Co-Channel Interference) ทำให้ Latency แกว่งแม้สัญญาณจะเต็มขีด",
                recommendation="หากเป็น Router ส่วนตัว แนะนำย้ายไปใช้คลื่น 5 GHz หรือช่องสัญญาณที่ว่างกว่าในตารางด้านล่าง",
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L1-L2 (RF & Roaming)",
                name="Channel Interference & Roaming",
                status=CheckStatus.PASS,
                summary=f"ช่องสัญญาณ Channel {current_chan or '?'} ปลอดโปร่ง (พบ AP ชนช่อง {len(co_channel_aps)} ตัว) และเกาะ AP ตัวที่ดีที่สุดแล้ว",
                details=f"สแกนพบ AP รอบข้างทั้งหมด {len(aps)} ตัว",
            )
        )
