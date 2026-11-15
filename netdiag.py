#!/usr/bin/env python3
"""
netdiag.py - Principal Network Engineer Diagnostic & Cable Troubleshooter
เครื่องมือตรวจสอบสายแลนและวิเคราะห์ปัญหา Network อัตโนมัติ (OSI Layer 1 - Layer 7)

การใช้งาน:
  ./netdiag.py                                    # เปิดเมนู Interactive เลือกหัวข้อที่ต้องการตรวจเช็ก
  ./netdiag.py --quick                            # รันตรวจเช็กครบทุกจุดทันทีโดยไม่เข้าเมนู
  ./netdiag.py --mode freeip -i wlp4s0            # เช็กรายการ IP ว่าง & โซนที่ไม่ถูกแจกด้วย DHCP
  ./netdiag.py --mode conflict -i wlp4s0          # เช็กไอพีเต็ม & คอมพิวเตอร์แย่งไอพีกันในวงแลน
  ./netdiag.py --mode bottleneck -i wlp4s0        # เช็กจุดคอขวด/ความหน่วง/Jitter 3 ด่าน + Traceroute
  ./netdiag.py --mode target --target 10.8.1.254  # ทดสอบเครื่องปลายทาง Server/Printer & สแกนพอร์ต
  ./netdiag.py --mode dhcp -i wlp4s0              # ตรวจจับ Rogue DHCP & ดูรายละเอียด DHCP Server
  ./netdiag.py --watch                            # โหมดเฝ้าระวัง: ทันทีที่เสียบสายแลน จะรันวิเคราะห์ให้อัตโนมัติ
"""

import argparse
import dataclasses
import datetime
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from netdiag import CheckStatus, InterfaceDiagReport
from netdiag.analyzer import MODE_LABELS, diagnose_interface
from netdiag.htb_arsenal import get_htb_arsenal_status, lookup_mac_vendor
from netdiag.layer1_physical import (
    _read_sysfs,
    classify_interface,
    discover_interfaces,
    get_ethtool_info,
)
from netdiag.layer3_network import get_ip_addresses

console = Console()


def get_htb_arsenal_hud_line() -> str:
    """สร้างแถบสถานะแสดงขุมพลังเครื่องมือ Hack The Box OS ที่เชื่อมต่อกับโปรแกรม"""
    st = get_htb_arsenal_status()
    badges: List[str] = []
    for name, ok in st.items():
        label = "IEEE-OUI-DB" if name == "oui_db" else name
        if ok:
            badges.append(f"[bold bright_green]⚡{label}[/bold bright_green]")
        else:
            badges.append(f"[dim]○{label}[/dim]")
    return "  ".join(badges)


STATUS_BADGE = {
    CheckStatus.PASS: "[bold green]✅ PASS[/bold green]",
    CheckStatus.WARN: "[bold yellow]⚠️ WARN[/bold yellow]",
    CheckStatus.FAIL: "[bold red]❌ FAIL[/bold red]",
    CheckStatus.INFO: "[bold cyan]ℹ️ INFO[/bold cyan]",
    CheckStatus.SKIP: "[dim]⏭️ SKIP[/dim]",
}


def get_quick_interface_overview(include_virtual: bool = False) -> Table:
    """สร้างตารางสรุปสถานะพอร์ตเบื้องต้นสำหรับแสดงในหน้าเมนูหลัก"""
    table = Table(
        title="📡 สถานะพอร์ตเครือข่ายในเครื่องปัจจุบัน (Live Interface Status)",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("พอร์ต (Interface)", style="bold white", overflow="fold")
    table.add_column("ประเภท", style="cyan", overflow="fold")
    table.add_column("สัญญาณสาย (Carrier)", justify="center", overflow="fold")
    table.add_column("ความเร็ว (Speed)", justify="center", overflow="fold")
    table.add_column("IPv4 Address ปัจจุบัน", style="bold", overflow="fold")

    for iface, if_type in discover_interfaces(include_virtual=include_virtual):
        carrier = _read_sysfs(iface, "carrier") == "1"
        ethtool_info = get_ethtool_info(iface) if if_type == "ethernet" else {}
        if ethtool_info.get("Link detected", "").lower() == "yes":
            carrier = True

        carrier_badge = "[bold green]🟢 เชื่อมต่อ (UP)[/bold green]" if carrier else "[bold red]🔴 ไม่พบสาย (NO-CARRIER)[/bold red]"
        speed_str = ethtool_info.get("Speed", "-") if if_type == "ethernet" else ("Wi-Fi" if carrier else "-")

        v4_list, _ = get_ip_addresses(iface)
        if v4_list:
            ips = ", ".join(f"{a.get('local')}/{a.get('prefixlen')}" for a in v4_list)
            ip_badge = f"[green]{ips}[/green]"
        else:
            ip_badge = "[yellow]⚠️ ไม่มี IPv4[/yellow]" if carrier else "[dim]-[/dim]"

        icon = "🔌" if if_type == "ethernet" else ("📶" if if_type == "wifi" else "🖧")
        table.add_row(f"{icon} {iface}", if_type.upper(), carrier_badge, speed_str, ip_badge)

    return table


def render_subnet_scan_details(scan_res: Dict[str, Any], self_mac: str) -> None:
    """แสดงหลอดวัดความจุ IP ในวงแลนและตารางรายชื่อเครื่องที่ออนไลน์ / เครื่องที่แย่ง IP กัน"""
    subnet = scan_res["subnet"]
    total = scan_res["total_usable"]
    active = scan_res["active_count"]
    free = scan_res["free_count"]
    pct = scan_res["usage_pct"]
    hosts: Dict[str, List[str]] = scan_res["hosts"]
    dup_ips: Dict[str, List[str]] = scan_res["duplicate_ips"]
    multi_macs: Dict[str, List[str]] = scan_res["multi_ip_macs"]

    bar_width = 30
    filled = min(int(round((pct / 100.0) * bar_width)), bar_width)
    bar_color = "green" if pct < 70 else ("yellow" if pct < 90 else "red")
    bar_str = f"[{bar_color}]{'█' * filled}[/{bar_color}][dim]{'░' * (bar_width - filled)}[/dim]"

    gauge_text = (
        f"🌐 [bold]วงแลน (Subnet):[/bold] [cyan]{subnet}[/cyan]   "
        f"| 📊 [bold]ใช้งานแล้ว:[/bold] [{bar_color}]{active} / {total} IPs ({pct}%)[/{bar_color}]   "
        f"| 🟢 [bold]IP ว่างคงเหลือ:[/bold] [bold green]{free} IPs[/bold green]\n"
        f"   {bar_str}  "
        f"{'🚨 [bold red]ไอพีใกล้เต็ม![/bold red]' if pct >= 90 else ('⚠️ [bold yellow]ใช้งานหนาแน่น[/bold yellow]' if pct >= 70 else '✅ [bold green]ความจุ IP ปกติ[/bold green]')}"
    )
    console.print(Panel(gauge_text, title="📈 สถานะความจุ IP ในวงแลน (Subnet IP Pool Usage)", border_style=bar_color))

    host_table = Table(
        title=f"🖥️ รายการอุปกรณ์ที่ตรวจพบในวงแลน {subnet} (ทั้งหมด {active} IP)",
        box=box.SIMPLE_HEAVY,
        header_style="bold bright_white on dark_blue",
        expand=True,
        padding=(0, 1),
    )
    host_table.add_column("#", justify="right", style="dim", overflow="fold")
    host_table.add_column("IP Address", style="bold white", no_wrap=True)
    host_table.add_column("MAC Address", style="cyan", no_wrap=True)
    host_table.add_column("ยี่ห้อ (Vendor)", style="yellow", overflow="fold")
    host_table.add_column("สถานะ (Conflict / Role)", overflow="fold")

    for idx, (ip_addr, macs) in enumerate(hosts.items(), 1):
        mac_str = ", ".join(macs) if macs else "[dim]ตอบ Ping (รอ ARP)[/dim]"
        vendor_str = ", ".join(lookup_mac_vendor(m) for m in macs) if macs else "-"
        notes: List[str] = []

        if ip_addr in dup_ips:
            notes.append("[bold red]💥 แย่ง IP กัน! (พบมากกว่า 1 MAC)[/bold red]")
        if self_mac and self_mac.lower() in [m.lower() for m in macs]:
            notes.append("[bold bright_cyan]💻 เครื่องของคุณ[/bold bright_cyan]")
        if ip_addr.endswith(".1") or ip_addr.endswith(".254"):
            notes.append("[bold yellow]🖧 Gateway/Server[/bold yellow]")
        for m in macs:
            if m in multi_macs:
                other_ips = [x for x in multi_macs[m] if x != ip_addr]
                if other_ips:
                    notes.append(f"[yellow]⚠️ ถือ IP อื่นด้วย ({', '.join(other_ips)})[/yellow]")

        if not notes:
            notes.append("[green]🟢 ออนไลน์ปกติ[/green]")

        row_style = "bold red" if ip_addr in dup_ips else ""
        host_table.add_row(str(idx), ip_addr, mac_str, vendor_str, " | ".join(notes), style=row_style)

    console.print(host_table)


def _format_ip_grid(ip_list: List[str], per_row: int = 4) -> str:
    """จัดเรียงรายการ IP เป็นตาราง Grid แถวละ 4 เบอร์ เพื่อให้อ่านง่ายและไม่ล้นจอ 80 คอลัมน์"""
    rows: List[str] = []
    for i in range(0, len(ip_list), per_row):
        chunk = ip_list[i : i + per_row]
        rows.append("  " + "  ".join(f"{ip:<15}" for ip in chunk).rstrip())
    return "\n".join(rows)


def render_free_ip_details(f_data: Dict[str, Any]) -> None:
    """แสดงตารางรายการ IP ว่าง (Free IPs List) และแยกโซนที่ไม่ถูกแจกด้วย DHCP แบบกระชับ 1 บรรทัดต่อแถว ไม่ถูกตัดคำ"""
    subnet = f_data["subnet"]
    total = f_data["total_usable"]
    used_cnt = f_data["used_count"]
    free_cnt = f_data["free_count"]
    dhcp_start = f_data["dhcp_pool_start"]
    dhcp_end = f_data["dhcp_pool_end"]
    scope_method = f_data["scope_method"]
    static_ips: List[str] = f_data["free_static_zone_ips"]
    dhcp_free_ips: List[str] = f_data["free_dhcp_zone_ips"]
    rec_ips: List[str] = f_data["recommended_static_ips"]

    overview_text = (
        f"🌐 [bold]วงแลน (Subnet):[/bold] [cyan]{subnet}[/cyan] (ทั้งหมด {total} IPs)   "
        f"| 🔴 [bold]ถูกใช้แล้ว:[/bold] [red]{used_cnt} IPs[/red]   "
        f"| 🟢 [bold]ว่างทั้งหมด (Unused):[/bold] [bold green]{free_cnt} IPs[/bold green]\n"
        f"🔄 [bold]ช่วงแจก DHCP (Estimated DHCP Pool):[/bold] [yellow]{dhcp_start} - {dhcp_end}[/yellow] [dim]({scope_method})[/dim]\n"
        f"🛡️ [bold]IP ว่างนอกช่วง DHCP (เหมาะตั้ง Fix IP):[/bold] [bold green]{len(static_ips)} IPs[/bold green]   "
        f"| 🟡 [bold]IP ว่างในช่วง DHCP:[/bold] [yellow]{len(dhcp_free_ips)} IPs[/yellow]\n"
        f"⭐ [bold bright_green]เบอร์ IP แนะนำสำหรับตั้ง Static/Fix IP:[/bold bright_green] "
        f"[bold white]{', '.join(rec_ips) if rec_ips else 'ไม่มี'}[/bold white]"
    )
    console.print(Panel(overview_text, title="📋 สรุปโซน IP ว่าง & ขอบเขต DHCP (Free IP & DHCP Scope Summary)", border_style="green"))

    # กล่องที่ 1: แสดงลิสต์เบอร์ IP ว่างที่ไม่ถูกแจกด้วย DHCP แบบเต็มทุกเบอร์ (เรียงแบบ Grid เต็มหน้าจอ ไม่โดนบีบ)
    if static_ips:
        grid_text = (
            "[bold green]รายการเบอร์ IP ที่ว่างและอยู่นอกช่วง DHCP (สามารถนำไปตั้งค่า Static / Fix IP ได้ทันที):[/bold green]\n"
            + _format_ip_grid(static_ips, per_row=4)
        )
        console.print(
            Panel(
                grid_text,
                title=f"🟢 รายการ IP ว่างนอกช่วง DHCP (Safe Static IP List — {len(static_ips)} เบอร์)",
                border_style="bright_green",
            )
        )

    # ตารางที่ 2: รายการช่วง IP ที่ว่างทั้งหมดในวงแลน (กระชับ แถวละ 1 บรรทัด ไม่เว้นห่าง และไม่โดนตัดคำด้วย ...)
    f_table = Table(
        title=f"📋 ตารางช่วง IP ที่ว่างทั้งหมดในวงแลน {subnet} (รวม {free_cnt} เบอร์ที่ยังไม่ถูกใช้งาน)",
        box=box.SIMPLE_HEAVY,
        header_style="bold bright_white on dark_blue",
        expand=True,
        padding=(0, 1),
    )
    f_table.add_column("#", justify="right", style="dim", overflow="fold")
    f_table.add_column("ช่วง IP ที่ว่าง", style="bold white", overflow="fold")
    f_table.add_column("จำนวน", justify="right", style="cyan", overflow="fold")
    f_table.add_column("โซน DHCP", overflow="fold")
    f_table.add_column("รายการเลขท้ายที่ว่าง (Octets)", style="green", overflow="fold")

    static_set = set(static_ips)
    all_free_flat: List[str] = []
    for idx, r in enumerate(f_data["all_free_ranges"], 1):
        range_label = r["start"] if r["count"] == 1 else f"{r['start']} - {r['end']}"
        ips_in_range: List[str] = r["ips"]
        all_free_flat.extend(ips_in_range)
        all_static = all(x in static_set for x in ips_in_range)
        none_static = all(x not in static_set for x in ips_in_range)

        if all_static:
            zone_badge = "[bold green]🟢 นอก DHCP (Fix IP)[/bold green]"
        elif none_static:
            zone_badge = "[yellow]🟡 ในช่วง DHCP[/yellow]"
        else:
            zone_badge = "[cyan]🔵 คาบเกี่ยวโซน[/cyan]"

        octets = [f".{ip.split('.')[-1]}" for ip in ips_in_range]
        if len(octets) <= 8:
            octet_str = ", ".join(octets)
        else:
            octet_str = ", ".join(octets[:5]) + f" .. {octets[-1]} (ครบทุกเบอร์)"

        f_table.add_row(str(idx), range_label, f"{r['count']} IP", zone_badge, octet_str)

    console.print(f_table)

    # กล่องที่ 3: แสดงรายการเบอร์ IP ว่างทั้งหมดทุกเบอร์แบบเต็ม (Full IP List Grid) เพื่อให้ดู/คัดลอกได้ครบทุกเบอร์ไม่ตกหล่น
    if all_free_flat:
        all_grid_text = (
            "[bold yellow]รายการเบอร์ IP ที่ว่างทั้งหมดในวงแลน (เรียงลำดับทุกเบอร์แบบเต็ม ไม่ย่อ):[/bold yellow]\n"
            + _format_ip_grid(all_free_flat, per_row=4)
        )
        console.print(
            Panel(
                all_grid_text,
                title=f"🟡 รายการ IP ว่างทั้งหมดในวงแลน (All Unused IPs Full List — {len(all_free_flat)} เบอร์)",
                border_style="yellow",
            )
        )


def render_bottleneck_details(b_data: Dict[str, Any]) -> None:
    """แสดงตารางเปรียบเทียบ Latency & Jitter 3 ด่าน และตาราง Hop-by-Hop Traceroute"""
    tiers: List[Dict[str, Any]] = b_data.get("tiers", [])
    hops: List[Dict[str, Any]] = b_data.get("hops", [])

    if tiers:
        t_table = Table(
            title="⏱️ ตารางเปรียบเทียบความหน่วง (Latency) และความแกว่งสัญญาณ (Jitter) แยก 3 ด่าน",
            box=box.SIMPLE_HEAVY,
            header_style="bold bright_white on dark_blue",
            expand=True,
            padding=(0, 1),
        )
        t_table.add_column("ด่านที่ตรวจสอบ (Network Tier)", style="bold white", overflow="fold")
        t_table.add_column("IP เป้าหมาย", style="cyan", overflow="fold")
        t_table.add_column("Avg", justify="right", overflow="fold")
        t_table.add_column("Min/Max", justify="right", overflow="fold")
        t_table.add_column("Jitter", justify="right", overflow="fold")
        t_table.add_column("Loss", justify="right", overflow="fold")
        t_table.add_column("คุณภาพสัญญาณ", overflow="fold")

        for t in tiers:
            if not t.get("reachable"):
                t_table.add_row(
                    t["tier"],
                    t["target"],
                    "-",
                    "-",
                    "-",
                    "[bold red]100%[/bold red]",
                    "[bold red]❌ ติดต่อไม่ได้[/bold red]",
                )
            else:
                avg_v = t["avg_ms"] or 0
                jit_v = t["jitter_ms"] or 0
                loss_v = t["loss_pct"] or 0
                if loss_v > 0 or avg_v > 80 or jit_v > 20:
                    qual = "[bold yellow]⚠️ หน่วง/แกว่ง[/bold yellow]"
                else:
                    qual = "[bold green]🟢 เสถียรดี[/bold green]"

                t_table.add_row(
                    t["tier"],
                    t["target"],
                    f"[bold]{avg_v} ms[/bold]",
                    f"{t['min_ms']}/{t['max_ms']} ms",
                    f"{jit_v} ms",
                    f"{loss_v}%",
                    qual,
                )
        console.print(t_table)

    if hops:
        h_table = Table(
            title="🛤️ เส้นทางวิ่งออกอินเทอร์เน็ตทีละด่าน (Hop-by-Hop Traceroute to 1.1.1.1)",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            expand=True,
            padding=(0, 1),
        )
        h_table.add_column("Hop", justify="center", style="bold", overflow="fold")
        h_table.add_column("IP ของ Router / ด่านที่ผ่าน", style="white", overflow="fold")
        h_table.add_column("Latency", justify="right", overflow="fold")
        h_table.add_column("สถานะด่าน", overflow="fold")

        prev_ms = 0.0
        for h in hops:
            avg_ms = h.get("avg_ms")
            if avg_ms is None:
                h_table.add_row(
                    f"Hop {h['hop']}",
                    f"[dim]{h['ip']}[/dim]",
                    "[dim]-[/dim]",
                    "[dim]ℹ️ ไม่ตอบ ICMP (ส่งผ่านแพ็กเกจต่อตามปกติ)[/dim]",
                )
            else:
                jump = round(avg_ms - prev_ms, 2) if prev_ms > 0 else 0.0
                prev_ms = avg_ms
                if jump > 30:
                    note = f"[bold yellow]⚠️ ความหน่วงเพิ่มขึ้น +{jump} ms ที่ด่านนี้![/bold yellow]"
                else:
                    note = "[green]🟢 ปกติ[/green]"
                h_table.add_row(
                    f"Hop {h['hop']}",
                    f"[bold cyan]{h['ip']}[/bold cyan]",
                    f"[bold]{avg_ms} ms[/bold]",
                    note,
                )
        console.print(h_table)


def render_target_scan_details(t_data: Dict[str, Any]) -> None:
    """แสดงตารางผลการสแกนพอร์ตบริการ ข้อมูล nmap -sV, whatweb, sslscan และสถานะ Firewall ของเครื่องปลายทาง"""
    target_in = t_data["target_input"]
    res_ip = t_data["resolved_ip"]
    mac = t_data["arp_mac"] or "อยู่นอกวงแลน (Routed) / ไม่พบใน ARP"
    vendor = t_data.get("mac_vendor") or ""
    mac_display = f"{mac} ([yellow]{vendor}[/yellow])" if vendor else mac
    det_host = t_data.get("detected_hostname") or "-"
    roles = ", ".join(t_data["device_roles"]) if t_data["device_roles"] else "ทั่วไป / ไม่เปิดพอร์ตมาตรฐาน"
    ping_str = (
        f"[bold green]ตอบกลับ ({t_data['ping_avg_ms']} ms)[/bold green]"
        if t_data["ping_reachable"]
        else "[bold yellow]ไม่ตอบ Ping (ICMP Blocked/Timeout)[/bold yellow]"
    )

    info_lines = [
        f"🎯 [bold]เป้าหมายที่ตรวจสอบ:[/bold] [cyan]{target_in}[/cyan] (IP: [bold]{res_ip}[/bold])   | 📡 [bold]สถานะ Ping:[/bold] {ping_str}",
        f"🏷️ [bold]MAC & ยี่ห้อ:[/bold] {mac_display}   | 💻 [bold]ชื่อเครื่อง (NetBIOS/PTR):[/bold] [bold white]{det_host}[/bold white]",
        f"🖥️ [bold]การประเมินชนิดอุปกรณ์:[/bold] [yellow]{roles}[/yellow]",
    ]
    if t_data.get("web_fingerprint"):
        info_lines.append(f"🌐 [bold bright_green]WhatWeb Fingerprint:[/bold bright_green] {t_data['web_fingerprint']}")
    ssl_info = t_data.get("ssl_info") or {}
    if ssl_info:
        ssl_txt = (
            f"Subject={ssl_info.get('subject', '-')}, Issuer={ssl_info.get('issuer', '-')}, "
            f"Expires={ssl_info.get('expires', '-')}, TLS={ssl_info.get('tls_versions', '-')}"
        )
        info_lines.append(f"🔒 [bold bright_cyan]SSLScan Certificate:[/bold bright_cyan] {ssl_txt}")

    console.print(Panel("\n".join(info_lines), title="🎯 ข้อมูลเชิงลึกเครื่องปลายทาง (HTB Target Host Intelligence)", border_style="cyan"))

    p_table = Table(
        title=f"🛡️ ผลการสแกนพอร์ตบริการ & Nmap Service Banner บนเครื่อง {res_ip}",
        box=box.SIMPLE_HEAVY,
        header_style="bold bright_white on dark_blue",
        expand=True,
        padding=(0, 1),
    )
    p_table.add_column("Port", justify="right", style="bold white", overflow="fold")
    p_table.add_column("บริการ (Service)", style="cyan", overflow="fold")
    p_table.add_column("สถานะพอร์ต", justify="center", overflow="fold")
    p_table.add_column("เวลา", justify="right", overflow="fold")
    p_table.add_column("เวอร์ชัน/ความหมาย (Nmap -sV & Firewall Analysis)", overflow="fold")

    for p in t_data["ports"]:
        st = p["state"]
        lat = f"{p['latency_ms']} ms" if p["latency_ms"] is not None else "-"
        banner = p.get("banner", "")
        if st == "OPEN":
            badge = "[bold green]🟢 OPEN (เปิด)[/bold green]"
            meaning = f"[bold bright_green]⚡ {banner}[/bold bright_green] — " if banner else ""
            meaning += "[green]เชื่อมต่อบริการได้สมบูรณ์ ไม่ติด Firewall[/green]"
        elif st == "CLOSED":
            badge = "[white]⚪ CLOSED (ปิด)[/white]"
            meaning = "[dim]ไปถึงเครื่องแล้ว (ไม่ติด Firewall) แต่ไม่ได้รันบริการพอร์ตนี้[/dim]"
        else:
            badge = "[bold red]🔴 FILTERED (บล็อก)[/bold red]"
            meaning = "[yellow]ถูก Firewall บล็อกพอร์ตนี้ไว้ หรือเครื่องไม่ตอบสนอง[/yellow]"

        p_table.add_row(str(p["port"]), p["service"], badge, lat, meaning)

    console.print(p_table)


def render_cyber_recon_details(r_data: Dict[str, Any]) -> None:
    """แสดงตารางเรดาร์ทรัพย์สินเครือข่าย ชื่อเครื่อง และยี่ห้ออุปกรณ์ (HTB Cyber Asset & Hostname Radar)"""
    subnet = r_data["subnet"]
    active_cnt = r_data["active_count"]
    named_cnt = r_data["named_count"]
    top_vendors: List[Dict[str, Any]] = r_data.get("top_vendors", [])
    assets: List[Dict[str, Any]] = r_data.get("assets", [])

    vendor_badges = [f"[bold yellow]{v['vendor']}[/bold yellow]: [cyan]{v['count']} เครื่อง[/cyan]" for v in top_vendors]
    summary_text = (
        f"🌐 [bold]วงแลนที่สแกน:[/bold] [cyan]{subnet}[/cyan]   "
        f"| 🟢 [bold]อุปกรณ์ออนไลน์ทั้งหมด:[/bold] [bold green]{active_cnt} เครื่อง[/bold green]   "
        f"| 🏷️ [bold]ดึงชื่อเครื่องได้:[/bold] [bold bright_cyan]{named_cnt} เครื่อง[/bold bright_cyan]\n"
        f"🏭 [bold]สถิติยี่ห้ออุปกรณ์ในวงแลน (Top Hardware Vendors):[/bold]\n  "
        + ("   |   ".join(vendor_badges) if vendor_badges else "-")
    )
    console.print(
        Panel(
            summary_text,
            title="🛰️ สรุปผลเรดาร์สแกนทรัพย์สินเครือข่าย (HTB Cyber Asset & Vendor Summary)",
            border_style="bright_magenta",
        )
    )

    a_table = Table(
        title=f"🛰️ ตารางเรดาร์อุปกรณ์ ชื่อเครื่อง และยี่ห้อการ์ดแลนในวง {subnet} ({active_cnt} เครื่อง)",
        box=box.SIMPLE_HEAVY,
        header_style="bold bright_white on dark_blue",
        expand=True,
        padding=(0, 1),
    )
    a_table.add_column("#", justify="right", style="dim", overflow="fold")
    a_table.add_column("IP Address", style="bold white", overflow="fold")
    a_table.add_column("MAC Address", style="cyan", overflow="fold")
    a_table.add_column("ยี่ห้อ (Vendor)", style="yellow", overflow="fold")
    a_table.add_column("ชื่อเครื่อง & ประเภทอุปกรณ์ (Hostname & Profile)", style="bold bright_green", overflow="fold")

    for idx, item in enumerate(assets, 1):
        h_name = item["hostname"]
        if h_name != "-" and item["name_source"] != "-":
            h_disp = f"{h_name} [dim]({item['name_source']})[/dim] | [white]{item['profile']}[/white]"
        else:
            h_disp = f"[white]{item['profile']}[/white]"

        row_style = "bold red" if item.get("is_conflict") else ""
        a_table.add_row(
            str(idx),
            item["ip"],
            item["mac"],
            item["vendor"],
            h_disp,
            style=row_style,
        )

    console.print(a_table)


def render_traffic_details(t_data: Dict[str, Any]) -> None:
    """แสดงแผงวัดความเร็วทราฟฟิกสด อัตราแพ็กเกจ และผลตรวจ Broadcast Storm"""
    iface = t_data["interface"]
    rx_kbps = t_data["rx_kbps"]
    tx_kbps = t_data["tx_kbps"]
    rx_pps = t_data["rx_pps"]
    tx_pps = t_data["tx_pps"]
    mcast_pps = t_data["mcast_pps"]
    is_storm = t_data["is_broadcast_storm"]
    sock = t_data["socket_stats"]
    protos: List[Dict[str, Any]] = t_data.get("protocols", [])

    storm_badge = (
        "[bold red]🚨 พบความเสี่ยง Broadcast Storm / Loop![/bold red]"
        if is_storm
        else "[bold green]🟢 ปกติ (ไม่พบ Broadcast Storm / Loop)[/bold green]"
    )

    panel_text = (
        f"🔌 [bold]พอร์ตที่วัดผล:[/bold] [cyan]{iface}[/cyan] (ช่วงเวลาเก็บตัวอย่าง {t_data['sample_sec']} วินาที)\n"
        f"⬇️  [bold]ความเร็วดาวน์โหลด (RX):[/bold] [bold green]{rx_kbps} Kbps[/bold green] ({t_data['rx_mbps']} Mbps | {rx_pps} pkt/s)   "
        f"| ⬆️  [bold]ความเร็วอัปโหลด (TX):[/bold] [bold cyan]{tx_kbps} Kbps[/bold cyan] ({t_data['tx_mbps']} Mbps | {tx_pps} pkt/s)\n"
        f"📢 [bold]อัตราแพ็กเกจ Multicast/Broadcast:[/bold] [yellow]{mcast_pps} pkt/s[/yellow]   "
        f"| 🛡️ [bold]สถานะ Storm/Loop:[/bold] {storm_badge}\n"
        f"📊 [bold]ปริมาณรับ-ส่งสะสม (Total):[/bold] RX = {t_data['total_rx_mb']} MB, TX = {t_data['total_tx_mb']} MB   "
        f"| 🔗 [bold]Active Sockets (`ss -s`):[/bold] TCP Established = {sock['tcp_estab']} (Total TCP={sock['tcp_total']}, UDP={sock['udp_total']})"
    )
    console.print(
        Panel(
            panel_text,
            title="📡 แผงวัดความเร็วทราฟฟิกสด & ตรวจจับ Broadcast Storm (Live Traffic Telemetry)",
            border_style="red" if is_storm else "bright_cyan",
        )
    )

    if protos:
        pr_table = Table(
            title="🔬 สัดส่วนโปรโตคอลที่ดักจับได้สดจากสายด้วย TShark (Live Protocol Breakdown)",
            box=box.SIMPLE_HEAVY,
            header_style="bold bright_white on dark_blue",
            expand=True,
            padding=(0, 1),
        )
        pr_table.add_column("โปรโตคอล (Protocol)", style="bold cyan", overflow="fold")
        pr_table.add_column("จำนวนแพ็กเกจ", justify="right", style="bold white", overflow="fold")
        pr_table.add_column("สัดส่วน (%)", justify="right", style="green", overflow="fold")
        for pr in protos:
            pr_table.add_row(pr["protocol"], str(pr["packets"]), f"{pr['pct']}%")
        console.print(pr_table)


def render_dhcp_audit_details(d_data: Dict[str, Any]) -> None:
    """แสดงตารางรายละเอียดสัญญาเช่า DHCP และผลการตรวจหา Rogue DHCP"""
    d_table = Table(
        title="🕵️ ตารางข้อมูลเชิงลึกของ DHCP Server & สัญญาเช่า IP (DHCP Lease Audit)",
        box=box.SIMPLE_HEAVY,
        header_style="bold bright_white on dark_blue",
        expand=True,
        padding=(0, 1),
    )
    d_table.add_column("รายการข้อมูล (DHCP Parameter)", style="bold cyan", ratio=1, overflow="fold")
    d_table.add_column("ค่าที่ตรวจพบจากระบบ (Value)", style="bold white", ratio=2, overflow="fold")

    relay_badge = (
        "[bold green]ใช่ — ส่งต่อผ่าน DHCP Relay (IP Helper บน Switch/Router)[/bold green]"
        if d_data.get("is_dhcp_relay")
        else "ไม่ใช่ — DHCP Server อยู่ในวงแลนเดียวกันโดยตรง"
    )
    srv_ping_str = (
        f"[green]ติดต่อได้ ({d_data['server_latency_ms']} ms)[/green]"
        if d_data.get("server_reachable")
        else "[yellow]ไม่ตอบ Ping โดยตรง (หรือรับเฉพาะผ่าน Relay)[/yellow]"
    )

    d_table.add_row("🖧 DHCP Server Identifier (ผู้แจก IP)", str(d_data.get("server_id")))
    d_table.add_row("🔄 ลักษณะการแจก IP (Relay / Local)", relay_badge)
    d_table.add_row("📡 สถานะการปิงหา DHCP Server", srv_ping_str)
    d_table.add_row("🏷️ IP Address ที่ได้รับ (Offered IP)", f"{d_data.get('offered_ip')} (Mask: {d_data.get('subnet_mask')})")
    d_table.add_row("🚪 Default Gateway (Option 3 Router)", str(d_data.get("router")))
    d_table.add_row("🌐 DNS Servers (Option 6)", str(d_data.get("dns_servers")))
    d_table.add_row("🏢 ชื่อโดเมนองค์กร (Option 15 Domain)", str(d_data.get("domain_name")))
    d_table.add_row("⏳ อายุสัญญาเช่า IP (Option 51 Lease Time)", str(d_data.get("lease_time")))

    console.print(d_table)


def render_wifi_details(w_data: Dict[str, Any]) -> None:
    """แสดงแผงวิเคราะห์สัญญาณ Wi-Fi, ช่องสัญญาณชนกัน และรายชื่อ AP รอบข้าง"""
    link = w_data["link"]
    aps: List[Dict[str, Any]] = w_data.get("nearby_aps", [])
    better = w_data.get("better_same_ssid", [])

    info_text = (
        f"📶 [bold]SSID ปัจจุบัน:[/bold] [cyan]{link['ssid']}[/cyan]   "
        f"| 📡 [bold]คลื่นความถี่:[/bold] [yellow]{link['band']} (Channel {w_data['current_chan']}, {link['channel_width']})[/yellow]\n"
        f"🏷️ [bold]AP BSSID:[/bold] {link['bssid']} ([yellow]{w_data['ap_vendor']}[/yellow])   "
        f"| 📊 [bold]ความแรงสัญญาณ:[/bold] [bold green]{link['signal_dbm']} dBm ({w_data['current_sig_pct']}%)[/bold green]\n"
        f"⚡ [bold]ความเร็ว Link (RX / TX):[/bold] {link['rx_bitrate']}  |  {link['tx_bitrate']}\n"
        f"🔀 [bold]AP ชนช่องเดียวกัน (Co-Channel):[/bold] {w_data['co_channel_count']} ตัว   "
        f"| 🏃 [bold]Mesh Roaming Status:[/bold] "
        + (f"[bold yellow]⚠️ พบ AP ตัวที่แรงกว่า ({better[0]['signal_pct']}%)[/bold yellow]" if better else "[bold green]🟢 เกาะ AP ตัวที่ดีที่สุดแล้ว[/bold green]")
    )
    console.print(Panel(info_text, title="📶 วิเคราะห์คลื่น Wi-Fi & Mesh Roaming (Wi-Fi Radio Telemetry)", border_style="bright_cyan"))

    if aps:
        w_table = Table(
            title=f"📡 รายการ Access Point รอบข้างที่ตรวจพบ (แสดง {len(aps)} อันดับแรงสุด)",
            box=box.SIMPLE_HEAVY,
            header_style="bold bright_white on dark_blue",
            expand=True,
            padding=(0, 1),
        )
        w_table.add_column("ใช้งาน", justify="center", overflow="fold")
        w_table.add_column("SSID", style="bold white", overflow="fold")
        w_table.add_column("BSSID & ยี่ห้อ AP", style="cyan", overflow="fold")
        w_table.add_column("Ch", justify="right", style="yellow", overflow="fold")
        w_table.add_column("สัญญาณ", justify="right", style="green", overflow="fold")
        w_table.add_column("Security", overflow="fold")

        for a in aps:
            use_badge = "[bold bright_green]★ ใช้[/bold bright_green]" if a["in_use"] else "[dim]-[/dim]"
            bssid_v = f"{a['bssid']} ({a['vendor']})"
            w_table.add_row(use_badge, a["ssid"], bssid_v, str(a["chan"]), f"{a['signal_pct']}%", a["security"])
        console.print(w_table)


def render_dns_details(d_data: Dict[str, Any]) -> None:
    """แสดงตารางเปรียบเทียบความเร็ว DNS และผลตรวจจับ DNS Hijacking"""
    benches: List[Dict[str, Any]] = d_data.get("benchmarks", [])
    b_table = Table(
        title=f"⚡ ตารางเปรียบเทียบความเร็ว DNS Resolver (ทดสอบโดเมน {d_data['test_domain']})",
        box=box.SIMPLE_HEAVY,
        header_style="bold bright_white on dark_blue",
        expand=True,
        padding=(0, 1),
    )
    b_table.add_column("ผู้ให้บริการ DNS (Resolver)", style="bold white", overflow="fold")
    b_table.add_column("IP Address", style="cyan", overflow="fold")
    b_table.add_column("เวลาตอบกลับ", justify="right", overflow="fold")
    b_table.add_column("สถานะ", justify="center", overflow="fold")
    b_table.add_column("ตัวอย่างคำตอบ (A Record)", style="dim", overflow="fold")

    for b in benches:
        if not b["reachable"]:
            b_table.add_row(b["label"], b["server"], "-", "[bold red]❌ TIMEOUT[/bold red]", "-")
        else:
            ms = b["query_ms"] or 0
            ms_str = f"[bold green]{ms} ms[/bold green]" if ms < 60 else (f"[yellow]{ms} ms[/yellow]" if ms < 150 else f"[red]{ms} ms[/red]")
            b_table.add_row(b["label"], b["server"], ms_str, f"[green]{b['status']}[/green]", b["sample_ip"])
    console.print(b_table)


def render_snmp_details(s_data: Dict[str, Any]) -> None:
    """แสดงตารางข้อมูลอุปกรณ์และพอร์ต Switch/Router จากการอ่าน SNMP"""
    if not s_data.get("reachable"):
        return
    info_text = (
        f"🖧 [bold]ชื่ออุปกรณ์ (sysName):[/bold] [cyan]{s_data['sys_name']}[/cyan] ({s_data['target_ip']})   "
        f"| ⏱️ [bold]Uptime:[/bold] [green]{s_data['sys_uptime']}[/green]\n"
        f"📋 [bold]รุ่น/ระบบปฏิบัติการ (sysDescr):[/bold] {s_data['sys_descr']}"
    )
    console.print(Panel(info_text, title="🖧 ข้อมูลอุปกรณ์จาก SNMP (SNMP System Summary)", border_style="cyan"))

    ports: List[Dict[str, Any]] = s_data.get("ports", [])
    if ports:
        s_table = Table(
            title=f"🔌 ตารางสถานะพอร์ตบนอุปกรณ์ {s_data['sys_name']} (แสดงสูงสุด {len(ports)} พอร์ต)",
            box=box.SIMPLE_HEAVY,
            header_style="bold bright_white on dark_blue",
            expand=True,
            padding=(0, 1),
        )
        s_table.add_column("#", justify="right", style="dim", overflow="fold")
        s_table.add_column("ชื่อพอร์ต (ifDescr)", style="bold white", overflow="fold")
        s_table.add_column("สถานะ", justify="center", overflow="fold")
        s_table.add_column("Speed", justify="right", style="cyan", overflow="fold")
        s_table.add_column("In/Out Errors", justify="right", overflow="fold")

        for p in ports:
            st_badge = "[bold green]🟢 UP[/bold green]" if p["status"] == "UP" else "[dim]⚪ DOWN[/dim]"
            err_total = p["in_errors"] + p["out_errors"]
            err_str = f"[bold red]{p['in_errors']}/{p['out_errors']}[/bold red]" if err_total > 0 else "[green]0/0[/green]"
            spd_str = f"{p['speed_mbps']} Mbps" if p["speed_mbps"] > 0 else "-"
            s_table.add_row(str(p["index"]), p["name"], st_badge, spd_str, err_str)
        console.print(s_table)


def render_baseline_details(b_data: Dict[str, Any]) -> None:
    """แสดงตารางเปรียบเทียบ Network Baseline กับสถานะปัจจุบัน"""
    if b_data.get("mode") == "saved":
        snap = b_data["snapshot"]
        console.print(
            Panel(
                f"💾 [bold green]บันทึก Baseline ใหม่เรียบร้อยแล้ว[/bold green]\n"
                f"• ไฟล์ที่บันทึก: [cyan]{b_data['path']}[/cyan]\n"
                f"• เวลาที่บันทึก: {snap['captured_at']} | จำนวนเครื่องฐาน: [bold]{len(snap['hosts'])} เครื่อง[/bold]",
                title="🛡️ Network Baseline Snapshot",
                border_style="green",
            )
        )
        return

    diff = b_data.get("diff", {})
    new_hosts: List[Dict[str, Any]] = diff.get("new_hosts", [])
    missing_hosts: List[Dict[str, Any]] = diff.get("missing_hosts", [])
    mac_changed: List[Dict[str, Any]] = diff.get("mac_changed_hosts", [])

    if new_hosts or missing_hosts or mac_changed:
        d_table = Table(
            title=f"🛡️ ตารางสรุปความเปลี่ยนแปลงจาก Baseline ({diff['baseline_time']} → {diff['current_time']})",
            box=box.SIMPLE_HEAVY,
            header_style="bold bright_white on dark_blue",
            expand=True,
            padding=(0, 1),
        )
        d_table.add_column("ประเภทการเปลี่ยนแปลง", overflow="fold")
        d_table.add_column("IP Address", style="bold white", overflow="fold")
        d_table.add_column("MAC Address", style="cyan", overflow="fold")
        d_table.add_column("ยี่ห้ออุปกรณ์ (Vendor)", style="yellow", overflow="fold")

        for item in mac_changed:
            d_table.add_row(
                "[bold red]⚠️ MAC เปลี่ยน![/bold red]",
                item["ip"],
                f"{item['old_mac']} → {item['new_mac']}",
                item["new_vendor"],
            )
        for item in new_hosts:
            d_table.add_row(
                "[bold bright_yellow]🆕 อุปกรณ์ใหม่[/bold bright_yellow]",
                item["ip"],
                ", ".join(item["macs"]) or "-",
                item["vendor"],
            )
        for item in missing_hosts[:15]:
            d_table.add_row(
                "[dim]📴 ออฟไลน์/หายไป[/dim]",
                item["ip"],
                ", ".join(item["macs"]) or "-",
                item["vendor"],
            )
        console.print(d_table)


def render_report(report: InterfaceDiagReport) -> None:
    """แสดงผลการตรวจเช็กของแต่ละ Interface บน Terminal อย่างสวยงามและไม่ถูกบีบคอลัมน์"""
    status_color = {
        CheckStatus.PASS: "green",
        CheckStatus.WARN: "yellow",
        CheckStatus.FAIL: "red",
        CheckStatus.INFO: "cyan",
    }.get(report.overall_status, "white")

    mode_key = report.raw_context.get("diag_mode", "all")
    mode_title = MODE_LABELS.get(mode_key, mode_key)

    icon = "🔌" if report.if_type == "ethernet" else ("📶" if report.if_type == "wifi" else "🖧")
    title = (
        f"{icon} พอร์ต: [bold]{report.interface}[/bold] "
        f"({report.if_type.upper()} | MAC: {report.mac_address} | Driver: {report.driver})\n"
        f"[dim]โหมดการตรวจ: {mode_title}[/dim]"
    )

    table = Table(
        title=title,
        box=box.ROUNDED,
        header_style="bold bright_white on dark_blue",
        expand=True,
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("OSI Layer", style="bold cyan", ratio=1, overflow="fold")
    table.add_column("รายการตรวจเช็ก", style="bold white", ratio=1, overflow="fold")
    table.add_column("สถานะ", justify="center", overflow="fold")
    table.add_column("ผลการวิเคราะห์และรายละเอียด (Findings)", ratio=3, overflow="fold")

    for chk in report.checks:
        finding_text = f"[bold]{chk.summary}[/bold]"
        if chk.details:
            finding_text += f"\n[dim]{chk.details}[/dim]"
        table.add_row(
            chk.layer,
            chk.name,
            STATUS_BADGE.get(chk.status, chk.status.value),
            finding_text,
        )

    console.print()
    console.print(table)

    # แสดงตารางเจาะลึกตามโหมดพิเศษ
    if "subnet_scan" in report.raw_context:
        render_subnet_scan_details(report.raw_context["subnet_scan"], report.mac_address)
    if "free_ip_data" in report.raw_context:
        render_free_ip_details(report.raw_context["free_ip_data"])
    if "cyber_recon" in report.raw_context:
        render_cyber_recon_details(report.raw_context["cyber_recon"])
    if "traffic_data" in report.raw_context:
        render_traffic_details(report.raw_context["traffic_data"])
    if "bottleneck_data" in report.raw_context:
        render_bottleneck_details(report.raw_context["bottleneck_data"])
    if "target_scan" in report.raw_context:
        render_target_scan_details(report.raw_context["target_scan"])
    if "dhcp_audit" in report.raw_context:
        render_dhcp_audit_details(report.raw_context["dhcp_audit"])
    if "wifi_data" in report.raw_context:
        render_wifi_details(report.raw_context["wifi_data"])
    if "dns_data" in report.raw_context:
        render_dns_details(report.raw_context["dns_data"])
    if "snmp_data" in report.raw_context:
        render_snmp_details(report.raw_context["snmp_data"])
    if "baseline_data" in report.raw_context:
        render_baseline_details(report.raw_context["baseline_data"])

    summary_lines: List[str] = []
    summary_lines.append("[bold underline]🔍 สรุปผลการวินิจฉัย (Root Cause Analysis):[/bold underline]")
    for rc in report.root_causes:
        if report.overall_status == CheckStatus.PASS:
            summary_lines.append(f"  {rc}")
        else:
            summary_lines.append(f"  • [bold]{rc}[/bold]")

    if report.action_plan:
        summary_lines.append("\n[bold underline]🛠️ ขั้นตอนการแก้ไขที่แนะนำ (Recommended Fix):[/bold underline]")
        for idx, act in enumerate(report.action_plan, 1):
            indented = "\n     ".join(act.splitlines())
            summary_lines.append(f"  [bold yellow][{idx}][/bold yellow] {indented}")

    panel_title = (
        f"สรุปสถานะพอร์ต {report.interface}: "
        f"{STATUS_BADGE.get(report.overall_status, report.overall_status.value)}"
    )
    console.print(
        Panel(
            "\n".join(summary_lines),
            title=panel_title,
            border_style=status_color,
            padding=(1, 2),
        )
    )


def save_report_files(reports: List[InterfaceDiagReport], out_dir: Path) -> Path:
    """บันทึกรายงานผลเป็น Markdown และ JSON"""
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    md_path = out_dir / f"netdiag_report_{ts}.md"
    json_path = out_dir / f"netdiag_report_{ts}.json"

    json_data = [dataclasses.asdict(r) for r in reports]
    json_path.write_text(json.dumps(json_data, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# รายงานผลการตรวจสอบเครือข่าย (Network Diagnostic Report)",
        f"- **วัน-เวลาที่ตรวจเช็ก:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    for r in reports:
        lines.append(f"## พอร์ต `{r.interface}` ({r.if_type.upper()}) — สถานะ: **{r.overall_status.value}**")
        lines.append(f"- **MAC Address:** `{r.mac_address}` | **Driver:** `{r.driver}`")
        lines.append("")
        lines.append("| OSI Layer | รายการตรวจเช็ก | สถานะ | ผลการวิเคราะห์ | รายละเอียด |")
        lines.append("|---|---|---|---|---|")
        for c in r.checks:
            lines.append(f"| {c.layer} | {c.name} | **{c.status.value}** | {c.summary} | `{c.details}` |")
        lines.append("")
        lines.append("### สรุปสาเหตุ (Root Causes)")
        for rc in r.root_causes:
            lines.append(f"- {rc}")
        if r.action_plan:
            lines.append("")
            lines.append("### วิธีแก้ไขที่แนะนำ (Action Plan)")
            for act in r.action_plan:
                lines.append(f"- {act}")
        lines.append("\n---\n")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path


def watch_cable_mode(iface: str, listen_lldp: bool = False) -> None:
    """โหมดเฝ้าระวังพอร์ตแลน รันวิเคราะห์อัตโนมัติทันทีที่เสียบสายแลน"""
    console.print(
        Panel(
            f"👀 กำลังเฝ้าดูพอร์ตแลน [bold cyan]{iface}[/bold cyan] แบบเรียลไทม์...\n"
            "• เสียบสายแลนเมื่อไหร่ ระบบจะเริ่มตรวจเช็ก Layer 1 - Layer 7 ให้อัตโนมัติทันที\n"
            "• กด [bold]Ctrl+C[/bold] เพื่อกลับสู่เมนูหรือออกจากโหมดเฝ้าระวัง",
            title="🔌 Auto Cable Watch Mode",
            border_style="cyan",
        )
    )
    last_carrier = None
    try:
        while True:
            carrier = _read_sysfs(iface, "carrier") == "1"
            if carrier != last_carrier:
                now_str = datetime.datetime.now().strftime("%H:%M:%S")
                if carrier:
                    console.print(
                        f"\n[bold green][{now_str}] ⚡ ตรวจพบการเสียบสายแลนที่พอร์ต {iface}! "
                        "รอรับ IP สักครู่ (3 วินาที) แล้วเริ่มวิเคราะห์...[/bold green]"
                    )
                    time.sleep(3)
                    rep = diagnose_interface(iface, listen_lldp=listen_lldp, mode="all")
                    render_report(rep)
                else:
                    if last_carrier is not None:
                        console.print(
                            f"\n[bold red][{now_str}] 🔌 สายแลนที่พอร์ต {iface} ถูกถอดออก หรือสัญญาณไฟหลุด (NO-CARRIER)[/bold red]"
                        )
                    else:
                        console.print(
                            f"[yellow][{now_str}] สถานะเริ่มต้นของ {iface}: ยังไม่ได้เสียบสายแลน (NO-CARRIER) — รอคุณเสียบสาย...[/yellow]"
                        )
                last_carrier = carrier
            time.sleep(1.0)
    except KeyboardInterrupt:
        console.print("\n[bold cyan]ออกจากโหมดเฝ้าระวังเรียบร้อยครับ[/bold cyan]")


def parse_ports_str(ports_str: str) -> Optional[List[int]]:
    """แปลงข้อความพอร์ต เช่น '80,443,9100' เป็น List[int]"""
    if not ports_str or not ports_str.strip():
        return None
    result: List[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if part.isdigit():
            p = int(part)
            if 1 <= p <= 65535:
                result.append(p)
    return result or None


def execute_diagnostics(
    targets: List[str],
    mode: str = "all",
    listen_lldp: bool = False,
    save_report: bool = False,
    target_host: Optional[str] = None,
    custom_ports: Optional[List[int]] = None,
    custom_dhcp_range: Optional[str] = None,
    snmp_community: str = "public",
    reset_baseline: bool = False,
) -> List[InterfaceDiagReport]:
    """รันการตรวจเช็กตามพอร์ตและโหมดที่กำหนด"""
    reports: List[InterfaceDiagReport] = []
    mode_label = MODE_LABELS.get(mode, mode)
    for iface in targets:
        with console.status(f"[bold cyan]กำลังตรวจพอร์ต {iface} — {mode_label}...[/bold cyan]"):
            rep = diagnose_interface(
                iface,
                listen_lldp=listen_lldp,
                mode=mode,
                target_host=target_host,
                custom_ports=custom_ports,
                custom_dhcp_range=custom_dhcp_range,
                snmp_community=snmp_community,
                reset_baseline=reset_baseline,
            )
            reports.append(rep)
        render_report(rep)

    if save_report and reports:
        out_dir = Path(__file__).resolve().parent / "reports"
        md_file = save_report_files(reports, out_dir)
        console.print(f"\n[bold green]📄 บันทึกรายงานผลเรียบร้อยแล้วที่:[/bold green] {md_file}")

    return reports


def interactive_menu(initial_iface: Optional[str] = None, include_virtual: bool = False) -> int:
    """แสดงเมนู Interactive ให้ผู้ใช้เลือกหัวข้อที่ต้องการตรวจสอบได้ตามต้องการ"""
    all_ifaces = [name for name, _ in discover_interfaces(include_virtual=include_virtual)]
    selected_targets: List[str] = [initial_iface] if initial_iface else all_ifaces
    last_reports: List[InterfaceDiagReport] = []

    while True:
        console.print()
        console.print(
            Panel(
                "[bold bright_white]🌐 PRINCIPAL NETWORK ENGINEER — HTB OS CYBER DIAGNOSTIC HUD[/bold bright_white]\n"
                "[dim]ระบบวิเคราะห์ปัญหาสายแลน, Switch/VLAN, DHCP/IP, ไอพีชนกัน, IP ว่าง, จุดคอขวด/Jitter, สแกนพอร์ต และเรดาร์ทรัพย์สินเครือข่าย[/dim]\n"
                f"🛠️  [bold cyan]HTB Arsenal Engines:[/bold cyan] {get_htb_arsenal_hud_line()}",
                border_style="bright_blue",
            )
        )

        # แสดงตารางภาพรวมสถานะพอร์ตปัจจุบัน
        console.print(get_quick_interface_overview(include_virtual=include_virtual))

        target_label = ", ".join(selected_targets) if selected_targets else "ไม่พบพอร์ต"
        menu_text = (
            f"🎯 [bold cyan]พอร์ตเป้าหมายที่เลือกตรวจตอนนี้:[/bold cyan] [bold yellow]{target_label}[/bold yellow]\n\n"
            "  [bold underline]หมวดตรวจเช็กตามโครงสร้าง OSI Layer:[/bold underline]\n"
            "  [bold green][1][/bold green]  🚀 [bold]ตรวจเช็กครบทุกจุด (Full OSI L1-L7)[/bold]              — ไล่เช็กตั้งแต่สายแลน, IP, Gateway จนถึงอินเทอร์เน็ตและ DNS\n"
            "  [bold green][2][/bold green]  🔌 [bold]เช็กปัญหาสายแลน & การ์ดแลน (Layer 1 Cable)[/bold]       — เช็กไฟสัญญาณ Carrier, ความเร็ว 100/1000Mbps, Duplex, สายหลวม/CRC Error\n"
            "  [bold green][3][/bold green]  🖧 [bold]เช็กปัญหาสวิตช์, VLAN, 802.1X & ARP (Layer 2)[/bold]     — เช็กพอร์ตโดนบล็อก, 802.1X, ตาราง MAC + ยี่ห้ออุปกรณ์ และดักฟัง LLDP/CDP\n"
            "  [bold green][4][/bold green]  🏷️  [bold]เช็กปัญหาไม่ได้รับ IP / DHCP / Gateway (Layer 3)[/bold]    — วิเคราะห์ทำไมไม่ได้ IP, ติด 169.254.x.x, วงแลนชน Wi-Fi, ปิง Gateway ไม่เจอ\n"
            "  [bold green][5][/bold green]  🌐 [bold]เช็กปัญหาได้ IP แล้วแต่เล่นเน็ตไม่ได้ (Layer 4-7)[/bold]     — แยกแยะเน็ตล่ม vs DNS พัง, เช็กคอขวด MTU 1500 และหน้าล็อกอิน Captive Portal\n\n"
            "  [bold underline]หมวดเครื่องมือวิเคราะห์เชิงลึก & ขุมพลัง Hack The Box OS (HTB Cyber Arsenal):[/bold underline]\n"
            "  [bold bright_magenta][6][/bold bright_magenta]  💥 [bold]เช็กไอพีเต็ม & คอมพิวเตอร์แย่งไอพีกัน (IP Pool/Conflict)[/bold] — สแกนวงแลนดูว่า IP ใกล้เต็มหรือยัง และมีเครื่องยี่ห้อไหนใช้ IP ชนกันบ้าง\n"
            "  [bold bright_magenta][7][/bold bright_magenta]  🛤️  [bold]วิเคราะห์จุดคอขวดทำไมเน็ตช้า/กระตุก (Latency & Jitter)[/bold] — เทียบความหน่วง 3 ด่าน (ตึกเรา vs Core องค์กร vs เน็ตนอก) + Traceroute\n"
            "  [bold bright_magenta][8][/bold bright_magenta]  🎯 [bold]สแกนเครื่องปลายทาง Server/Printer เชิงลึก (Nmap/WhatWeb/SSL)[/bold] — เช็กพอร์ต Firewall + ดึงเวอร์ชันซอฟต์แวร์ด้วย Nmap -sV, WhatWeb, SSLScan\n"
            "  [bold bright_magenta][9][/bold bright_magenta]  🕵️  [bold]ตรวจจับ Rogue DHCP & วิเคราะห์ DHCP Server เชิงลึก[/bold]   — เช็ก Router เถื่อนแจก IP ซ้อน, ดู DHCP Relay, Domain และอายุ Lease Time\n"
            "  [bold bright_green][10][/bold bright_green] 📋 [bold]เช็กรายการ IP ว่าง & โซนที่ไม่ถูกแจก DHCP (Free IP List)[/bold] — แสดง List เบอร์ IP ที่ว่างทั้งหมด และแนะนำเบอร์นอกช่วง DHCP สำหรับตั้ง Fix IP\n"
            "  [bold bright_green][11][/bold bright_green] 🛰️  [bold]เรดาร์สแกนชื่อเครื่อง & ยี่ห้ออุปกรณ์ทั้งวงแลน (HTB Cyber Recon)[/bold] — ผสาน fping + IEEE OUI + nbtscan + mDNS + dig ดึงชื่อเครื่องและยี่ห้อการ์ดแลน\n"
            "  [bold bright_green][12][/bold bright_green] 📡 [bold]วัดความเร็วทราฟฟิกสด & จับลูปสวิตช์ (Live Traffic & Storm)[/bold] — วัดความเร็ว RX/TX Kbps, อัตราแพ็กเกจ/วินาที และตรวจจับ Broadcast Storm\n"
            "  [bold bright_green][13][/bold bright_green] 📶 [bold]วิเคราะห์คลื่น Wi-Fi, ช่องสัญญาณชน & Mesh Roaming[/bold]      — เช็กความแรง dBm, AP ชนช่องเดียวกัน และอาการ Sticky Client\n"
            "  [bold bright_green][14][/bold bright_green] ⚡ [bold]วัดความเร็ว DNS เทียบ 1.1.1.1/8.8.8.8 & จับ DNS Hijack[/bold] — ทดสอบความเร็ว DNS องค์กร, DoH และตรวจจับการแอบ Redirect DNS\n"
            "  [bold bright_green][15][/bold bright_green] 🖧 [bold]เจาะลึกสถานะพอร์ต Switch/Router/Printer ผ่าน SNMP[/bold]       — อ่านรุ่น, Uptime, สถานะพอร์ต Up/Down และ Port Errors ด้วย snmpwalk\n"
            "  [bold bright_green][16][/bold bright_green] 🛡️  [bold]บันทึก/เทียบ Baseline หาอุปกรณ์แปลกปลอมในวงแลน[/bold]        — จับอุปกรณ์ใหม่เข้าวงแลน, เครื่องหาย และ Gateway MAC เปลี่ยน (ARP Spoof)\n\n"
            "  [bold underline]หมวดเฝ้าระวังและจัดการรายงาน:[/bold underline]\n"
            "  [bold cyan][17][/bold cyan] 👀 [bold]โหมดเฝ้าระวังสายแลนอัตโนมัติ (Watch Mode)[/bold]        — รอจังหวะเสียบ/ถอดสายแลน แล้วรันวิเคราะห์ให้อัตโนมัติทันที\n"
            "  [bold cyan][18][/bold cyan] 🎯 [bold]เปลี่ยนพอร์ตที่ต้องการเช็ก (Select Port)[/bold]           — เลือกตรวจเฉพาะสายแลน (เช่น enp0s31f6), เฉพาะ Wi-Fi หรือทุกพอร์ต\n"
            "  [bold cyan][19][/bold cyan] 📄 [bold]บันทึกรายงานผลล่าสุดเป็นไฟล์ (Save Report)[/bold]        — ส่งออกผลการตรวจล่าสุดเป็นไฟล์ Markdown (.md) และ JSON (.json)\n"
            "  [bold red][0][/bold red]  🚪 [bold]ออกจากโปรแกรม (Exit)[/bold]"
        )
        console.print(Panel(menu_text, title="📋 เลือกหัวข้อที่ต้องการตรวจสอบ", border_style="bright_cyan", padding=(1, 2)))

        try:
            choice = Prompt.ask(
                "[bold yellow]👉 กรุณาเลือกหมายเลขเมนู[/bold yellow]",
                choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19"],
                default="1",
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold cyan]ออกจากโปรแกรมเรียบร้อยครับ[/bold cyan]")
            return 0

        if choice == "0":
            console.print("[bold cyan]ขอบคุณที่ใช้บริการ Principal Network Engineer Diagnostic Tool ครับ![/bold cyan]")
            return 0
        elif choice == "1":
            last_reports = execute_diagnostics(selected_targets, mode="all")
        elif choice == "2":
            last_reports = execute_diagnostics(selected_targets, mode="cable")
        elif choice == "3":
            last_reports = execute_diagnostics(selected_targets, mode="switch", listen_lldp=True)
        elif choice == "4":
            last_reports = execute_diagnostics(selected_targets, mode="ip")
        elif choice == "5":
            last_reports = execute_diagnostics(selected_targets, mode="internet")
        elif choice == "6":
            last_reports = execute_diagnostics(selected_targets, mode="conflict")
        elif choice == "7":
            last_reports = execute_diagnostics(selected_targets, mode="bottleneck")
        elif choice == "8":
            t_host = Prompt.ask(
                "🎯 [bold cyan]ระบุ IP หรือชื่อ Hostname/Website ที่ต้องการทดสอบ (กด Enter เพื่อตรวจ Server/Gateway หลักอัตโนมัติ)[/bold cyan]",
                default="",
            ).strip()
            p_str = Prompt.ask(
                "🛡️ [bold cyan]ระบุหมายเลขพอร์ตคั่นด้วยลูกน้ำ เช่น 80,443,9100 (กด Enter เพื่อสแกน 12 พอร์ตมาตรฐานองค์กร)[/bold cyan]",
                default="",
            ).strip()
            last_reports = execute_diagnostics(
                selected_targets,
                mode="target",
                target_host=t_host or None,
                custom_ports=parse_ports_str(p_str),
            )
        elif choice == "9":
            last_reports = execute_diagnostics(selected_targets, mode="dhcp")
        elif choice == "10":
            d_range = Prompt.ask(
                "📋 [bold cyan]หากทราบช่วง DHCP Pool ให้ระบุ เช่น 20-250 หรือ 10.8.70.20-10.8.70.250 (กด Enter เพื่อให้ระบบวิเคราะห์ขอบเขต DHCP อัตโนมัติ)[/bold cyan]",
                default="",
            ).strip()
            last_reports = execute_diagnostics(
                selected_targets,
                mode="freeip",
                custom_dhcp_range=d_range or None,
            )
        elif choice == "11":
            last_reports = execute_diagnostics(selected_targets, mode="recon")
        elif choice == "12":
            last_reports = execute_diagnostics(selected_targets, mode="traffic")
        elif choice == "13":
            last_reports = execute_diagnostics(selected_targets, mode="wifi")
        elif choice == "14":
            last_reports = execute_diagnostics(selected_targets, mode="dns")
        elif choice == "15":
            s_host = Prompt.ask(
                "🖧 [bold cyan]ระบุ IP ของ Switch / Router / Printer ที่ต้องการตรวจ SNMP (กด Enter เพื่อใช้ Gateway ปัจจุบัน)[/bold cyan]",
                default="",
            ).strip()
            s_comm = Prompt.ask(
                "🔑 [bold cyan]ระบุ SNMP Community String (กด Enter เพื่อใช้ 'public')[/bold cyan]",
                default="public",
            ).strip()
            last_reports = execute_diagnostics(
                selected_targets,
                mode="snmp",
                target_host=s_host or None,
                snmp_community=s_comm or "public",
            )
        elif choice == "16":
            b_action = Prompt.ask(
                "🛡️ [bold cyan]พิมพ์ 'save' เพื่อบันทึก Baseline ใหม่ หรือกด Enter เพื่อเทียบสถานะปัจจุบันกับ Baseline เดิม[/bold cyan]",
                default="diff",
            ).strip().lower()
            last_reports = execute_diagnostics(
                selected_targets,
                mode="baseline",
                reset_baseline=(b_action == "save"),
            )
        elif choice == "17":
            eth_ifaces = [name for name, t in discover_interfaces(include_virtual=include_virtual) if t == "ethernet"]
            watch_if = selected_targets[0] if len(selected_targets) == 1 else (eth_ifaces[0] if eth_ifaces else "enp0s31f6")
            watch_cable_mode(watch_if)
        elif choice == "18":
            all_ifaces = [name for name, _ in discover_interfaces(include_virtual=include_virtual)]
            console.print("\n[bold cyan]เลือกพอร์ตที่ต้องการตรวจสอบ:[/bold cyan]")
            console.print("  [bold green][0][/bold green] ตรวจทุกพอร์ต (" + ", ".join(all_ifaces) + ")")
            for idx, ifname in enumerate(all_ifaces, 1):
                iftype = classify_interface(ifname).upper()
                console.print(f"  [bold green][{idx}][/bold green] เฉพาะพอร์ต [bold]{ifname}[/bold] ({iftype})")

            valid_sub = [str(i) for i in range(len(all_ifaces) + 1)]
            sub_choice = Prompt.ask("เลือกหมายเลขพอร์ต", choices=valid_sub, default="1" if all_ifaces else "0")
            if sub_choice == "0":
                selected_targets = all_ifaces
            else:
                selected_targets = [all_ifaces[int(sub_choice) - 1]]
            console.print(f"[bold green]✅ ตั้งค่าพอร์ตเป้าหมายเป็น: {', '.join(selected_targets)}[/bold green]")
            continue
        elif choice == "19":
            if not last_reports:
                last_reports = execute_diagnostics(selected_targets, mode="all", save_report=True)
            else:
                out_dir = Path(__file__).resolve().parent / "reports"
                md_file = save_report_files(last_reports, out_dir)
                console.print(f"\n[bold green]📄 บันทึกรายงานผลเรียบร้อยแล้วที่:[/bold green] {md_file}")

        try:
            Prompt.ask("\n[dim]กด Enter เพื่อกลับสู่เมนูหลัก (หรือ Ctrl+C เพื่อออก)[/dim]", default="")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold cyan]ออกจากโปรแกรมเรียบร้อยครับ[/bold cyan]")
            return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Principal Network Engineer Diagnostic & Cable Troubleshooter (L1-L7 + HTB OS Arsenal)"
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="ระบุชื่อ Network Interface ที่ต้องการตรวจเช็ก (เช่น enp0s31f6 หรือ wlp4s0)",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=[
            "all",
            "cable",
            "switch",
            "ip",
            "internet",
            "conflict",
            "bottleneck",
            "target",
            "dhcp",
            "freeip",
            "recon",
            "traffic",
            "wifi",
            "dns",
            "snmp",
            "baseline",
        ],
        help="โหมดตรวจเช็กโดยตรง: all, cable, switch, ip, internet, conflict, bottleneck, target, dhcp, freeip, recon, traffic, wifi, dns, snmp, baseline",
    )
    parser.add_argument(
        "--snmp-community",
        default="public",
        help="ระบุ SNMP Community String สำหรับโหมด --mode snmp (ค่าเริ่มต้น: public)",
    )
    parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="บันทึก Baseline ใหม่สำหรับโหมด --mode baseline",
    )
    parser.add_argument(
        "--target",
        help="ระบุ IP หรือ Hostname เป้าหมายสำหรับโหมด --mode target (เช่น 10.8.1.254 หรือ google.com)",
    )
    parser.add_argument(
        "--ports",
        help="ระบุหมายเลขพอร์ตคั่นด้วยลูกน้ำสำหรับโหมด --mode target (เช่น 80,443,22,9100)",
    )
    parser.add_argument(
        "--dhcp-range",
        help="ระบุช่วง DHCP Pool สำหรับโหมด --mode freeip เช่น 20-250 หรือ 10.8.70.20-10.8.70.250",
    )
    parser.add_argument(
        "-q",
        "--quick",
        action="store_true",
        help="รันตรวจเช็กครบทุกจุด (Full Check) ทันทีโดยไม่เปิดหน้าเมนู",
    )
    parser.add_argument(
        "--menu",
        action="store_true",
        help="บังคับเปิดหน้าเมนู Interactive",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="รวม Virtual / Docker Interface ในการตรวจเช็กด้วย",
    )
    parser.add_argument(
        "--lldp",
        action="store_true",
        help="ดักฟังแพ็กเกจ LLDP/CDP เพื่อดูชื่อ Switch และ VLAN ต้นทาง (แนะนำให้รันคู่กับ sudo)",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="โหมดเฝ้าระวังสายแลน: ทันทีที่เสียบสายแลน จะรันวิเคราะห์ปัญหาให้อัตโนมัติ",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="บันทึกรายงานผลการตรวจเช็กเก็บไว้ในโฟลเดอร์ reports/",
    )

    args = parser.parse_args()

    if args.watch:
        target_if = args.interface
        if not target_if:
            eth_ifaces = [name for name, t in discover_interfaces() if t == "ethernet"]
            target_if = eth_ifaces[0] if eth_ifaces else "enp0s31f6"
        watch_cable_mode(target_if, listen_lldp=args.lldp)
        return 0

    use_menu = args.menu or (
        sys.stdin.isatty()
        and not args.mode
        and not args.quick
        and not args.report
        and not args.target
        and not args.dhcp_range
    )
    if use_menu:
        return interactive_menu(initial_iface=args.interface, include_virtual=args.all)

    console.print(
        Panel.fit(
            "[bold bright_white]🌐 PRINCIPAL NETWORK ENGINEER — AUTO DIAGNOSTIC TOOL (OSI L1-L7)[/bold bright_white]\n"
            "[dim]วิเคราะห์ปัญหาสายแลน, Switch/VLAN, DHCP, ไอพีเต็ม/แย่งไอพี, เช็ก IP ว่าง/นอกช่วง DHCP, จุดคอขวด/Jitter, สแกนพอร์ต และล่า Rogue DHCP[/dim]",
            border_style="bright_blue",
        )
    )

    if args.interface:
        targets = [args.interface]
    else:
        targets = [name for name, _ in discover_interfaces(include_virtual=args.all)]

    if not targets:
        console.print("[bold red]ไม่พบ Network Interface ในระบบ![/bold red]")
        return 1

    run_mode = args.mode or ("target" if args.target else ("freeip" if args.dhcp_range else "all"))
    execute_diagnostics(
        targets=targets,
        mode=run_mode,
        listen_lldp=args.lldp,
        save_report=args.report,
        target_host=args.target,
        custom_ports=parse_ports_str(args.ports or ""),
        custom_dhcp_range=args.dhcp_range,
        snmp_community=args.snmp_community,
        reset_baseline=args.save_baseline,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
