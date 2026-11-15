#!/usr/bin/env bash
# Automated Installer & Desktop Shortcut Creator for htb-netdiag-pro

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="HTB NetDiag Pro"
DESKTOP_FILENAME="htb-netdiag-pro.desktop"
DESKTOP_DIR="${XDG_DESKTOP_DIR:-$HOME/Desktop}"
APPS_DIR="$HOME/.local/share/applications"
LOCAL_BIN="$HOME/.local/bin"
ICON_PATH="$APP_DIR/assets/htb-netdiag.svg"
LAUNCHER_PATH="$APP_DIR/launch-netdiag.sh"

if [[ "${1:-}" == "--uninstall" ]]; then
  echo "🗑️ กำลังถอนการติดตั้งทางลัด $APP_NAME..."
  rm -f "$DESKTOP_DIR/$DESKTOP_FILENAME" "$APPS_DIR/$DESKTOP_FILENAME" "$LOCAL_BIN/htb-netdiag"
  echo "✅ ถอนการติดตั้งทางลัดเรียบร้อยแล้ว (โค้ดโปรแกรมใน $APP_DIR ยังอยู่ครบ)"
  exit 0
fi

echo "🚀 กำลังติดตั้ง $APP_NAME..."

# 1. Ensure scripts are executable
chmod +x "$APP_DIR/netdiag.py" "$LAUNCHER_PATH" "$APP_DIR/install.sh"

# 2. Check and install Python dependency (rich) if missing
if ! python3 -c "import rich" >/dev/null 2>&1; then
  echo "📦 กำลังติดตั้ง Python library (rich)..."
  pip3 install --user -r "$APP_DIR/requirements.txt" || pip install --user -r "$APP_DIR/requirements.txt"
else
  echo "✅ พบ Python library 'rich' พร้อมใช้งานแล้ว"
fi

# 3. Create global CLI command ~/.local/bin/htb-netdiag
mkdir -p "$LOCAL_BIN"
ln -sf "$APP_DIR/netdiag.py" "$LOCAL_BIN/htb-netdiag"
echo "✅ สร้างคำสั่งลัด CLI: $LOCAL_BIN/htb-netdiag"

# 4. Generate Desktop Entry with Right-Click Quick Actions
mkdir -p "$DESKTOP_DIR" "$APPS_DIR"

DESKTOP_CONTENT="[Desktop Entry]
Version=1.0
Type=Application
Name=HTB NetDiag Pro
GenericName=Network Engineer Diagnostic HUD
Comment=OSI Layer 1-7 Network Diagnostic, Cable Troubleshooter & Cyber Asset Radar
Exec=$LAUNCHER_PATH --menu
Icon=$ICON_PATH
Terminal=false
Categories=Network;System;Security;
Keywords=network;diagnostic;nmap;wifi;dhcp;ping;htb;
StartupNotify=true
Actions=SudoMenu;CyberRecon;FreeIP;WatchMode;WiFiDiag;

[Desktop Action SudoMenu]
Name=🛡️ เปิดด้วยสิทธิ์ Root (sudo — LLDP / ARP Scan / Rogue DHCP)
Exec=$LAUNCHER_PATH --sudo --menu

[Desktop Action CyberRecon]
Name=🛰️ เรดาร์สแกนชื่อเครื่อง & ยี่ห้อทั้งวงแลน (Cyber Recon)
Exec=$LAUNCHER_PATH --mode recon

[Desktop Action FreeIP]
Name=📋 เช็ก IP ว่าง & โซนนอกช่วง DHCP (Free IP List)
Exec=$LAUNCHER_PATH --mode freeip

[Desktop Action WiFiDiag]
Name=📶 วิเคราะห์คลื่น Wi-Fi & Mesh Roaming
Exec=$LAUNCHER_PATH --mode wifi

[Desktop Action WatchMode]
Name=👀 โหมดเฝ้าระวังสายแลนอัตโนมัติ (Watch Mode)
Exec=$LAUNCHER_PATH --watch
"

printf "%s" "$DESKTOP_CONTENT" > "$DESKTOP_DIR/$DESKTOP_FILENAME"
printf "%s" "$DESKTOP_CONTENT" > "$APPS_DIR/$DESKTOP_FILENAME"

chmod +x "$DESKTOP_DIR/$DESKTOP_FILENAME" "$APPS_DIR/$DESKTOP_FILENAME"

# Mark desktop shortcut as trusted on MATE/XFCE/GNOME/KDE if gio is available
if command -v gio >/dev/null 2>&1; then
  gio set "$DESKTOP_DIR/$DESKTOP_FILENAME" metadata::trusted true 2>/dev/null || true
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi

echo ""
echo "🎉 ติดตั้งเสร็จสมบูรณ์!"
echo "   • ไอคอนหน้า Desktop : $DESKTOP_DIR/$DESKTOP_FILENAME"
echo "   • เมนู Applications : $APPS_DIR/$DESKTOP_FILENAME"
echo "   • คำสั่ง CLI ทั่วระบบ : htb-netdiag (ลองพิมพ์ 'htb-netdiag' ใน Terminal ได้เลย)"
echo ""
echo "💡 เคล็ดลับ: สามารถคลิกขวาที่ไอคอนหน้า Desktop เพื่อเข้าโหมดลัด (sudo / Cyber Recon / Free IP / Wi-Fi / Watch Mode) ได้ทันที!"
