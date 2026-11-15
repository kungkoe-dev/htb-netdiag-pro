# 🌐 htb-netdiag-pro

**Principal Network Engineer Diagnostic, Cable Troubleshooter & HTB Cyber Asset Radar (OSI Layer 1 – Layer 7)**

เครื่องมือตรวจสอบสายแลน วิเคราะห์ปัญหาเครือข่ายระดับวิศวกรเครือข่าย (OSI Layer 1–7) และเรดาร์สแกนทรัพย์สินเครือข่ายอัตโนมัติ ที่ผสานขุมพลังเครื่องมือใน **Hack The Box OS (Parrot Security / Kali / Linux)** เข้าไว้ในหน้าจอ Interactive HUD เดียว

---

## ✨ ฟีเจอร์หลักครบทั้ง 19 เมนู (Interactive Diagnostic HUD)

| เมนู | โหมด (`--mode`) | รายละเอียดการทำงาน |
|---|---|---|
| **[1]** | `all` | 🚀 **ตรวจเช็กครบทุกจุด (Full OSI L1–L7)** — ไล่เช็กตั้งแต่สายแลน, IP, Gateway จนถึงอินเทอร์เน็ตและ DNS |
| **[2]** | `cable` | 🔌 **เช็กปัญหาสายแลน & การ์ดแลน (Layer 1 Cable)** — เช็กสัญญาณไฟ Carrier, ความเร็ว 100/1000Mbps, Duplex, สายหลวม/CRC Error |
| **[3]** | `switch` | 🖧 **เช็กปัญหาสวิตช์, VLAN, 802.1X & ARP (Layer 2)** — เช็กพอร์ตโดนบล็อก, 802.1X, ตาราง MAC + ยี่ห้ออุปกรณ์ และดักฟัง LLDP/CDP |
| **[4]** | `ip` | 🏷️ **เช็กปัญหาไม่ได้รับ IP / DHCP / Gateway (Layer 3)** — วิเคราะห์ทำไมไม่ได้ IP, ติด `169.254.x.x` (APIPA), วงแลนชน Wi-Fi, ปิง Gateway ไม่เจอ |
| **[5]** | `internet` | 🌐 **เช็กปัญหาได้ IP แล้วแต่เล่นเน็ตไม่ได้ (Layer 4–7)** — แยกแยะเน็ตล่ม vs DNS พัง, เช็กคอขวด MTU 1500 และหน้าล็อกอิน Captive Portal |
| **[6]** | `conflict` | 💥 **เช็กไอพีเต็ม & คอมพิวเตอร์แย่งไอพีกัน (IP Pool/Conflict)** — สแกนวงแลนดูความจุ IP และตรวจจับเครื่องที่ใช้ IP ซ้ำกันพร้อมระบุยี่ห้อการ์ดแลน |
| **[7]** | `bottleneck` | 🛤️ **วิเคราะห์จุดคอขวดทำไมเน็ตช้า/กระตุก (Latency & Jitter)** — เทียบความหน่วง 3 ด่าน (Gateway ตึก vs Core Server vs เน็ตนอก) + Hop-by-Hop Traceroute |
| **[8]** | `target` | 🎯 **สแกนเครื่องปลายทาง Server/Printer เชิงลึก** — เช็กพอร์ต `OPEN`/`CLOSED`/`FILTERED` พร้อมดึงเวอร์ชันซอฟต์แวร์ด้วย `nmap -sV`, `whatweb`, `sslscan` |
| **[9]** | `dhcp` | 🕵️ **ตรวจจับ Rogue DHCP & วิเคราะห์ DHCP Server เชิงลึก** — เช็ก Router เถื่อนแจก IP ซ้อน, ดู DHCP Relay (IP Helper), Domain และอายุ Lease Time |
| **[10]** | `freeip` | 📋 **เช็กรายการ IP ว่าง & โซนที่ไม่ถูกแจก DHCP (Free IP List)** — แสดงตาราง Grid เบอร์ IP ที่ว่างทั้งหมด และแนะนำเบอร์นอกช่วง DHCP สำหรับตั้ง Static/Fix IP |
| **[11]** | `recon` | 🛰️ **เรดาร์สแกนชื่อเครื่อง & ยี่ห้ออุปกรณ์ทั้งวงแลน (HTB Cyber Recon)** — ผสาน `fping` + ฐานข้อมูล IEEE OUI + `nbtscan` + `avahi-browse` (mDNS) + `dig -x` |
| **[12]** | `traffic` | 📡 **วัดความเร็วทราฟฟิกสด & จับลูปสวิตช์ (Live Traffic & Storm)** — วัดความเร็ว RX/TX Kbps/Mbps, อัตราแพ็กเกจ/วินาที และตรวจจับ Broadcast Storm |
| **[13]** | `wifi` | 📶 **วิเคราะห์คลื่น Wi-Fi, ช่องสัญญาณชน & Mesh Roaming** — เช็กความแรง dBm, AP ชนช่องเดียวกัน, ยี่ห้อ AP และอาการ Sticky Client |
| **[14]** | `dns` | ⚡ **วัดความเร็ว DNS เทียบ Cloudflare/Google & จับ DNS Hijack** — วัด Query Time องค์กรเทียบ `1.1.1.1`/`8.8.8.8`/`9.9.9.9`, ทดสอบ DoH และ NXDOMAIN Hijack |
| **[15]** | `snmp` | 🖧 **เจาะลึกสถานะพอร์ต Switch/Router/Printer ผ่าน SNMP** — อ่านรุ่น, Uptime, สถานะพอร์ต Up/Down และ Port Errors ด้วย `snmpwalk` |
| **[16]** | `baseline` | 🛡️ **บันทึก/เทียบ Baseline หาอุปกรณ์แปลกปลอมในวงแลน** — จับอุปกรณ์ใหม่เข้าวงแลน, เครื่องหาย และ Gateway MAC เปลี่ยน (ARP Spoofing) |
| **[17]** | `--watch` | 👀 **โหมดเฝ้าระวังสายแลนอัตโนมัติ (Watch Mode)** — รอจังหวะเสียบ/ถอดสายแลน แล้วรันวิเคราะห์ให้อัตโนมัติทันที |
| **[18]** | *(UI)* | 🎯 **เปลี่ยนพอร์ตที่ต้องการเช็ก (Select Port)** — เลือกตรวจเฉพาะสายแลน (เช่น `enp0s31f6`), เฉพาะ Wi-Fi (`wlp4s0`) หรือทุกพอร์ต |
| **[19]** | `--report` | 📄 **บันทึกรายงานผลเป็นไฟล์ (Save Report)** — ส่งออกผลการตรวจเป็นไฟล์ Markdown (`.md`) และ JSON (`.json`) |

---

## 🛠️ ขุมพลังเครื่องมือ HTB OS ที่รองรับ (Arsenal Engines)

โปรแกรมทำงานแบบ **Read-Only 100%** (ไม่รีเซ็ตการ์ดแลน ไม่แก้ไขค่า IP ของเครื่อง) และเชื่อมต่อกับเครื่องมือที่มีในเครื่องโดยอัตโนมัติ:
- `nmap` + `/usr/share/nmap/nmap-mac-prefixes` / `/usr/share/arp-scan/ieee-oui.txt`
- `fping` & `arp-scan`
- `nbtscan` (NetBIOS Computer Name Discovery)
- `avahi-browse` (mDNS / Bonjour Discovery)
- `dig` (Reverse DNS PTR Lookup)
- `whatweb` & `sslscan` (Web & SSL/TLS Fingerprinting)
- `tshark` & `tcpdump` (Live Protocol & LLDP/CDP/DHCP Inspection)
- `ethtool`, `nmcli`, `ip`, `ss`

---

## 🚀 การติดตั้งและใช้งาน (Quick Start)

```bash
# 1. ติดตั้งไลบรารีแสดงผล Terminal UI
pip install -r requirements.txt

# 2. เปิดหน้าเมนูหลักแบบ Interactive (มีครบ 15 เมนู)
./netdiag.py

# 3. ตัวอย่างรันโหมดเฉพาะเจาะจงผ่าน CLI
./netdiag.py --mode freeip -i wlp4s0            # เช็กรายการ IP ว่าง & โซนนอกช่วง DHCP
./netdiag.py --mode recon -i wlp4s0             # เรดาร์สแกนชื่อเครื่อง & ยี่ห้ออุปกรณ์ทั้งวงแลน
./netdiag.py --mode conflict -i wlp4s0          # เช็กไอพีเต็ม & คอมพิวเตอร์แย่งไอพีกัน
./netdiag.py --mode traffic -i wlp4s0           # วัดความเร็วทราฟฟิกสด & จับ Broadcast Storm
./netdiag.py --mode target --target 10.8.1.254  # สแกนพอร์ตและดึงข้อมูล Server/Printer เชิงลึก
./netdiag.py --watch                            # โหมดเฝ้าระวังสายแลนอัตโนมัติเมื่อเสียบสาย
```

---

## 🧪 การรันชุดทดสอบ (Unit Tests)

```bash
python3 tests/test_scenarios.py
```
