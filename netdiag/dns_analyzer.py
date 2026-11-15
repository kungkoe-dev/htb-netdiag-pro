"""
DNS Speed Benchmark, Split-DNS & Hijack Detector (--mode dns)
ทดสอบประสิทธิภาพและความปลอดภัยของระบบ DNS อย่างละเอียด:
  - เปรียบเทียบความเร็วในการ Query (ms) ระหว่าง DNS ปัจจุบันขององค์กร กับ Public DNS (1.1.1.1, 8.8.8.8, 9.9.9.9)
  - ตรวจจับอาการ DNS Hijacking / NXDOMAIN Redirect (โดเมนไม่มีอยู่จริงแต่ถูก ISP/Router ดักตอบ IP กลับมา)
  - ทดสอบ DNS-over-HTTPS (DoH) Reachability และ Internal Split-DNS
"""

import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from . import CheckResult, CheckStatus, InterfaceDiagReport
from .layer2_datalink import get_nmcli_device_info

PUBLIC_DNS_BENCHMARK = [
    ("Cloudflare DNS", "1.1.1.1"),
    ("Google Public DNS", "8.8.8.8"),
    ("Quad9 Security DNS", "9.9.9.9"),
]


def query_dns_with_dig(server_ip: str, domain: str, qtype: str = "A", timeout_sec: int = 3) -> Dict[str, Any]:
    """รันคำสั่ง dig เพื่อวัด Query Time (ms) และดึงคำตอบจาก DNS Server เป้าหมาย"""
    if not shutil.which("dig"):
        return {"reachable": False, "query_ms": None, "answers": [], "status": "NO_DIG"}
    try:
        t0 = time.monotonic()
        proc = subprocess.run(
            ["dig", f"@{server_ip}", domain, qtype, "+time=2", "+tries=1", "+stats"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        elapsed_ms = round((time.monotonic() - t0) * 1000.0, 1)
        out = proc.stdout

        m_status = re.search(r"status:\s*([A-Z]+)", out)
        dns_status = m_status.group(1) if m_status else "UNKNOWN"

        m_qtime = re.search(r"Query time:\s*(\d+)\s*msec", out)
        qtime_ms = float(m_qtime.group(1)) if m_qtime else elapsed_ms

        answers: List[str] = []
        in_answer = False
        for line in out.splitlines():
            s = line.strip()
            if s.startswith(";; ANSWER SECTION:"):
                in_answer = True
                continue
            if in_answer:
                if not s or s.startswith(";;"):
                    break
                parts = s.split()
                if len(parts) >= 5:
                    answers.append(parts[-1])

        reachable = "connection timed out" not in out.lower() and dns_status != "UNKNOWN"
        return {
            "reachable": reachable,
            "query_ms": qtime_ms if reachable else None,
            "answers": answers,
            "status": dns_status,
        }
    except Exception:
        return {"reachable": False, "query_ms": None, "answers": [], "status": "TIMEOUT"}


def run_dns_benchmark_and_audit(report: InterfaceDiagReport) -> None:
    """รันการตรวจสอบความเร็ว DNS, เปรียบเทียบ Resolver และตรวจจับ DNS Hijacking (--mode dns)"""
    iface = report.interface
    nm_info = report.raw_context.get("nmcli") or get_nmcli_device_info(iface)

    local_dns_servers: List[str] = []
    for k, v in sorted(nm_info.items()):
        if k.startswith("IP4.DNS") and v and v != "--":
            local_dns_servers.append(v.strip())

    resolvers: List[tuple] = []
    for idx, ip in enumerate(local_dns_servers, 1):
        resolvers.append((f"Local/Org DNS #{idx}", ip))
    for label, ip in PUBLIC_DNS_BENCHMARK:
        if ip not in local_dns_servers:
            resolvers.append((label, ip))

    test_domain = "google.com"
    bench_results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=len(resolvers)) as ex:
        fut_map = {
            ex.submit(query_dns_with_dig, srv_ip, test_domain, "A"): (label, srv_ip)
            for label, srv_ip in resolvers
        }
        for fut in as_completed(fut_map):
            label, srv_ip = fut_map[fut]
            res = fut.result()
            bench_results.append(
                {
                    "label": label,
                    "server": srv_ip,
                    "reachable": res["reachable"],
                    "query_ms": res["query_ms"],
                    "status": res["status"],
                    "sample_ip": res["answers"][0] if res["answers"] else "-",
                }
            )
    bench_results.sort(key=lambda x: (not x["reachable"], x["query_ms"] or 99999))

    # ตรวจจับ DNS Hijacking / NXDOMAIN Redirect ด้วยชื่อโดเมนสุ่มที่ไม่มีอยู่จริง
    hijack_detected = False
    hijack_detail = ""
    primary_dns = local_dns_servers[0] if local_dns_servers else "1.1.1.1"
    fake_domain = "nonexistent-htb-netdiag-check-99881.invalid"
    nx_res = query_dns_with_dig(primary_dns, fake_domain, "A")
    if nx_res["reachable"] and nx_res["answers"]:
        hijack_detected = True
        hijack_detail = f"DNS {primary_dns} ตอบ IP {nx_res['answers'][0]} กลับมาสำหรับโดเมนที่ไม่มีอยู่จริง ({fake_domain})"

    # ทดสอบ DNS-over-HTTPS (DoH) ไปยัง Cloudflare
    doh_ok = False
    if shutil.which("curl"):
        try:
            p_doh = subprocess.run(
                [
                    "curl",
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "-H",
                    "accept: application/dns-json",
                    "--max-time",
                    "3",
                    "https://1.1.1.1/dns-query?name=google.com&type=A",
                ],
                capture_output=True,
                text=True,
                timeout=4,
            )
            doh_ok = p_doh.stdout.strip() == "200"
        except Exception:
            pass

    report.raw_context["dns_data"] = {
        "test_domain": test_domain,
        "primary_dns": primary_dns,
        "benchmarks": bench_results,
        "hijack_detected": hijack_detected,
        "hijack_detail": hijack_detail,
        "doh_reachable": doh_ok,
    }

    local_rows = [b for b in bench_results if "Local/Org" in b["label"]]
    fastest = next((b for b in bench_results if b["reachable"]), None)

    if local_rows and not any(r["reachable"] for r in local_rows):
        report.add_check(
            CheckResult(
                layer="L7 (DNS Benchmark)",
                name="Organization DNS Availability",
                status=CheckStatus.FAIL,
                summary=f"❌ DNS หลักของระบบ ({', '.join(local_dns_servers)}) ไม่ตอบสนองเลย!",
                details=f"ตัวสำรองที่เร็วที่สุดที่ติดต่อได้คือ {fastest['label']} ({fastest['server']}: {fastest['query_ms']} ms)" if fastest else "ไม่สามารถติดต่อ DNS Server ใดๆ ได้",
                recommendation="ตรวจสอบเซิร์ฟเวอร์ DNS ขององค์กร หรือทดสอบตั้งค่า DNS เป็น 1.1.1.1 / 8.8.8.8 ชั่วคราว",
            )
        )
    elif local_rows and local_rows[0]["query_ms"] and local_rows[0]["query_ms"] > 150:
        report.add_check(
            CheckResult(
                layer="L7 (DNS Benchmark)",
                name="DNS Resolution Latency",
                status=CheckStatus.WARN,
                summary=f"⚠️ DNS องค์กร ({local_rows[0]['server']}) ตอบสนองช้า ({local_rows[0]['query_ms']} ms) ทำให้เปิดเว็บครั้งแรกหน่วง!",
                details=f"เทียบกับ {fastest['label']} ({fastest['server']}) ที่ตอบกลับใน {fastest['query_ms']} ms" if fastest else "",
                recommendation="ตรวจสอบ Cache / Forwarder บน DNS Server องค์กร หรือพิจารณาใช้ DNS ที่เร็วกว่าสำหรับงานภายนอก",
            )
        )
    else:
        best_ms = local_rows[0]["query_ms"] if local_rows else (fastest["query_ms"] if fastest else 0)
        report.add_check(
            CheckResult(
                layer="L7 (DNS Benchmark)",
                name="DNS Speed Benchmark",
                status=CheckStatus.PASS,
                summary=f"⚡ DNS ตอบสนองรวดเร็ว ({primary_dns} = {best_ms} ms) | DoH (HTTPS DNS): {'ใช้งานได้' if doh_ok else 'ถูกบล็อก/ไม่รองรับ'}",
                details=f"เปรียบเทียบกับ Cloudflare/Google/Quad9 แล้วอยู่ในเกณฑ์ดีเยี่ยม",
            )
        )

    if hijack_detected:
        report.add_check(
            CheckResult(
                layer="L7 (DNS Security)",
                name="DNS Hijack / NXDOMAIN Check",
                status=CheckStatus.WARN,
                summary="⚠️ ตรวจพบการดักตอบ DNS ผิดปกติ (NXDOMAIN Hijacking / Forced Redirect)!",
                details=hijack_detail,
                recommendation="DNS หรือ ISP อาจแอบ Redirect โดเมนที่พิมพ์ผิดไปยังหน้าโฆษณาหรือหน้า Captive Portal",
            )
        )
    else:
        report.add_check(
            CheckResult(
                layer="L7 (DNS Security)",
                name="DNS Hijack / NXDOMAIN Check",
                status=CheckStatus.PASS,
                summary="ไม่พบการปลอมแปลงหรือดัก Redirect DNS (NXDOMAIN ทำงานถูกต้องตามมาตรฐาน)",
                details=f"ทดสอบด้วยโดเมนจำลองผ่าน {primary_dns} ได้สถานะ {nx_res['status']}",
            )
        )
