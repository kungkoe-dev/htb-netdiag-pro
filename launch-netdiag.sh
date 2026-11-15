#!/usr/bin/env bash
# Launcher wrapper for HTB NetDiag Pro (opens a wide terminal window for clean tables)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PATH="$SCRIPT_DIR/netdiag.py"

USE_SUDO=0
ARGS=()

for arg in "$@"; do
  if [[ "$arg" == "--sudo" ]]; then
    USE_SUDO=1
  else
    ARGS+=("$arg")
  fi
done

if [[ ${#ARGS[@]} -eq 0 ]]; then
  ARGS=("--menu")
fi

# Build inner command string safely
CMD_STR=""
if [[ $USE_SUDO -eq 1 ]]; then
  CMD_STR="sudo python3 \"$APP_PATH\""
else
  CMD_STR="python3 \"$APP_PATH\""
fi

for a in "${ARGS[@]}"; do
  CMD_STR+=" $(printf '%q' "$a")"
done

INNER_SHELL="cd $(printf '%q' "$SCRIPT_DIR") && $CMD_STR; echo ''; read -r -p 'กด Enter เพื่อปิดหน้าต่าง...'"

if command -v konsole >/dev/null 2>&1; then
  exec konsole --separate --workdir "$SCRIPT_DIR" -p "TerminalColumns=125" -p "TerminalRows=38" -e bash -c "$INNER_SHELL"
elif command -v mate-terminal >/dev/null 2>&1; then
  exec mate-terminal --title="HTB NetDiag Pro — Network Engineer HUD" --geometry=125x38 --working-directory="$SCRIPT_DIR" -e "bash -c $(printf '%q' "$INNER_SHELL")"
elif command -v xfce4-terminal >/dev/null 2>&1; then
  exec xfce4-terminal --title="HTB NetDiag Pro — Network Engineer HUD" --geometry=125x38 --working-directory="$SCRIPT_DIR" -e "bash -c $(printf '%q' "$INNER_SHELL")"
elif command -v x-terminal-emulator >/dev/null 2>&1; then
  exec x-terminal-emulator -e bash -c "$INNER_SHELL"
else
  cd "$SCRIPT_DIR" || exit 1
  if [[ $USE_SUDO -eq 1 ]]; then
    exec sudo python3 "$APP_PATH" "${ARGS[@]}"
  else
    exec python3 "$APP_PATH" "${ARGS[@]}"
  fi
fi
