#!/usr/bin/env bash
#===============================================================================
#  L3DPS.sh - Linux 3D Printing System Driver Finder
#  Part of the CyberCrime-Stoppers toolset (sibling of LINUPA.sh)
#
#  Purpose:
#    1) Detect 3D printers / controller boards connected to this Linux machine
#       (USB serial chips, MCU bootloaders, kernel drivers, /dev tty nodes)
#    2) Check for the classic Linux 3D-printing "silent killers":
#       brltty (grabs CH340 on Ubuntu!) and ModemManager (pollutes ttyUSB*)
#    3) Find matching driver/firmware packages hosted on your personal domain
#    4) Download + verify (SHA256) the matched package
#
#  Author: Scott Dev (CyberCrime-Stoppers)
#  License: GPL-3.0-or-later
#===============================================================================

#-------------------------------------------------------------------------------
# CONFIG - EDIT THESE
#-------------------------------------------------------------------------------
# Your personal domain hosting L3DPS driver/firmware packages.
# Layout expected on the server:
#   https://ld-sos.unixinbox.com/l3dps/drivers/<distro>/<pkg-name>.<ext>
#   https://ld-sos.unixinbox.com/l3dps/drivers/<distro>/SHA256SUMS
DOWNLOAD_DOMAIN=""          # e.g. "https://example.ca"  (leave blank to skip)
DRIVER_PATH="/l3dps/drivers"   # path relative to domain
VERIFY_CHECKSUMS="yes"      # yes/no - verify SHA256SUMS after download
DOWNLOAD_DIR="$HOME/l3dps-downloads"
LOG_FILE="$HOME/.local/share/l3dps/l3dps.log"

#-------------------------------------------------------------------------------
# Constants / helpers
#-------------------------------------------------------------------------------
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly VERSION="0.1.0"

log()   { printf '[INFO] l3dps: %s\n' "$*" | tee -a "$LOG_FILE" >&2; }
warn()  { printf '[WARN] l3dps: %s\n' "$*" | tee -a "$LOG_FILE" >&2; }
err()   { printf '[ERROR] l3dps: %s\n' "$*" | tee -a "$LOG_FILE" >&2; }
die()   { err "$*"; exit 1; }

usage() {
  cat <<EOF
L3DPS v$VERSION - Linux 3D Printing System Driver Finder

Usage:
  $SCRIPT_NAME [OPTIONS]

Options:
  -h, --help        Show this help message
  -s, --scan        Scan for 3D printers & serial interfaces (default)
  -c, --check       Check available driver packages on DOWNLOAD_DOMAIN
  -d, --download    Download a matching driver package from DOWNLOAD_DOMAIN
  -t, --troubleshoot  Check for known blockers (brltty, ModemManager, perms)
  -a, --all         Do scan + troubleshoot + check + download prompt
  -j, --json        Output scan results in JSON (for PDUA/Klipper scripting)
  -q, --quiet       Suppress [INFO] logs, only show results

Examples:
  $SCRIPT_NAME              # quick hardware scan
  $SCRIPT_NAME -t           # why won't my printer connect? (brltty check)
  $SCRIPT_NAME --all        # full flow
  $SCRIPT_NAME -j           # machine-readable output
EOF
}

#-------------------------------------------------------------------------------
# Dependency check
#-------------------------------------------------------------------------------
MISSING_TOOLS=()
need_tool() {
  if ! command -v "$1" &>/dev/null; then
    warn "Missing tool: '$1' - $2"
    MISSING_TOOLS+=("$1")
    return 1
  fi
  return 0
}

check_deps() {
  need_tool lsusb    "install: usbutils (USB device detection)"
  need_tool udevadm  "usually installed via systemd/udev (device perms + driver)"
  need_tool curl     "install: curl (domain connectivity check)"
  need_tool sha256sum "usually in coreutils (package verification)"
  need_tool groups   "coreutils - group membership check (dialout)"
  [ ${#MISSING_TOOLS[@]} -gt 0 ] && warn "Some checks will be skipped."
}

#-------------------------------------------------------------------------------
# Known USB IDs relevant to 3D printing
#-------------------------------------------------------------------------------
# Format: "VID:PIDprefix|Chip/Hardware|Typical boards/printers|driver module"
# PID can be a prefix or full ID; '*' = any PID from this vendor block
declare -a KNOWN_DEVICES=(
  "1a86:7523|WCH CH340/CH341 USB-serial|Ender 3/5, many Creality clones, Anycubic|ch341"
  "1a86:5523|WCH CH9102 USB-serial|newer Creality (Ender 3 S1/V3 era)|ch341"
  "10c4:ea60|Silicon Labs CP2102 USB-UART|Creality silent boards, Prusa MMU, many STM32 boards|cp210x"
  "10c4:ea70|Silicon Labs CP2105|some Octopus/SKR boards|cp210x"
  "10c4:ea71|Silicon Labs CP2101/CP210x variants|SKR / Makerbase boards|cp210x"
  "0403:6001|FTDI FT232 USB-serial|older ramps/Arduino-era boards, some Prusa|ftdi_sio"
  "0403:6015|FTDI FT231X USB-serial|SKR clones, duet-style adapters|ftdi_sio"
  "2341:0042|Arduino Mega 2560|RAMPS 1.4 classic setups|cdc_acm"
  "2341:0043|Arduino Uno|custom Marlin firmware rigs|cdc_acm"
  "1a86:8079|CH340 variant HID|budget clone boards|ch341"
  "0483:df11|STM32 DFU bootloader mode|STM32 boards flashing firmware (SKR, Fly, BTT)|none-flasher"
  "0483:3748|STM32 USB Virtual COM Port|STM32F1 boards (Marlin USB)|cdc_acm"
  "28de:*    |Valve Steam Controller block|unlikely - filtered only|none"
  "03eb:*    |Atmel SAM-BA bootloader|ATmega/SAMD boards in flash mode|none-flasher"
  "2c7c:*    |Quectel modems|filtered out - not a printer|none"
  "27c6:*    |Goodix|filtered out - that's a fingerprint chip (see LINUPA)|none"
)

# Match a detected USB id against KNOWN_DEVICES, echo the matched row
match_known_device() {
  local id="$1" row vidpid vid pid
  while IFS= read -r row; do
    vidpid="${row%%|*}"
    vid="${vidpid%%:*}"
    pid="${vidpid#*:}"
    if [ "$pid" = "*" ]; then
      [[ "$id" == "${vid}:"* ]] && { echo "$row"; return 0; }
    else
      [ "$id" = "$vidpid" ] && { echo "$row"; return 0; }
    fi
  done <<< "$(printf '%s\n' "${KNOWN_DEVICES[@]}")"
  return 1
}

#-------------------------------------------------------------------------------
# Step 1: Hardware detection
#-------------------------------------------------------------------------------
scan_usb_printers() {
  log "Scanning USB bus for 3D printer / serial interface chips..."
  local found=()

  while IFS= read -r line; do
    local id desc
    id=$(awk '{print $6}' <<<"$line")
    desc=$(cut -d':' -f3- <<<"$line" | sed 's/^ //')
    [ -z "$id" ] && continue

    if row=$(match_known_device "$id"); then
      local chip boards driver
      IFS='|' read -r _ chip boards driver <<<"$row"
      [ "$driver" = "none" ] && continue   # filtered vendor block
      found+=("$id|$desc|$chip|$boards|$driver")
    fi
  done < <(lsusb 2>/dev/null || { warn "lsusb unavailable."; true; })

  printf '%s\n' "${found[@]:-}"
}

# Enumerate /dev tty nodes with their backing drivers via udev
list_tty_nodes() {
  log "Enumerating serial devices (/dev/ttyUSB*, /dev/ttyACM*)..."
  local node_count=0
  shopt -s nullglob
  for node in /dev/ttyUSB* /dev/ttyACM*; do
    node_count=$((node_count+1))
    local vid pid serial drv
    vid=$(udevadm info --query=property --name="$node" 2>/dev/null | awk -F= '/^ID_VENDOR_ID=/{print $2; exit}')
    pid=$(udevadm info --query=property --name="$node" 2>/dev/null | awk -F= '/^ID_MODEL_ID=/{print $2; exit}')
    serial=$(udevadm info --query=property --name="$node" 2>/dev/null | awk -F= '/^ID_SERIAL_SHORT=/{print $2; exit}')
    drv=$(udevadm info --query=property --name="$node" 2>/dev/null | awk -F= '/^ID_USB_DRIVER=|^ID_=DRIVER/{print $2; exit}')
    echo "  $node  [${vid:-?}:${pid:-?}]  driver=${drv:-unknown}  serial=${serial:-none}"
  done
  shopt -u nullglob
  [ "$node_count" -eq 0 ] && warn "No /dev/ttyUSB* or /dev/ttyACM* nodes found."
}

check_kernel_modules() {
  log "Checking loaded 3D-printing-relevant kernel modules..."
  local mods=(ch341 ch9102 cp210x ftdi_sio cdc_acm usbserial usblp)
  for m in "${mods[@]}"; do
    if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$m"; then
      log "Loaded: $m"
    else
      echo "  (module not loaded: $m)"
    fi
  done
}

check_group_perms() {
  log "Checking user permissions for serial port access..."
  if groups 2>/dev/null | grep -qw dialout; then
    log "User is in 'dialout' group - serial access OK."
  else
    warn "User NOT in 'dialout' group! Fix with: sudo usermod -aG dialout \$USER  (then re-login)."
  fi
}

#-------------------------------------------------------------------------------
# Step 2: Troubleshoot known Linux 3D-printing blockers
#-------------------------------------------------------------------------------
troubleshoot_blockers() {
  log "Checking known 3D-printing connection blockers..."

  # --- brltty: Ubuntu ships this as accessibility daemon, and it STEALS
  #     CH340/CH341 devices, unplugging them from the ch341 driver.
  #     This is the #1 reason Ender 3s vanish from Cura/OrcaSlicer on Ubuntu.
  if systemctl is-active --quiet brltty 2>/dev/null || command -v brltty &>/dev/null; then
    err "brltty is installed/running and may have CLAIMED your CH340/CH341 printer!"
    echo "  Fix:  sudo apt purge brltty brltty-udev               # Ubuntu/Debian"
    echo "  Fix:  sudo systemctl disable --now brltty            # gentler option"
  else
    log "brltty not present - good (no CH340 conflict)."
  fi

  # --- ModemManager: probes every ttyUSB* at boot looking for modems,
  #     which garbles serial communication with printers for ~30-60s.
  if systemctl is-active --quiet ModemManager 2>/dev/null; then
    warn "ModemManager is running - it probes ttyUSB* ports and can block/garble printer comms."
    echo "  Fix:  sudo systemctl disable --now ModemManager"
    echo "  Alt (Klipper users): blacklist only 3D-printer VID:PIDs in /etc/udev/rules.d/"
  else
    log "ModemManager not running - good."
  fi

  # --- udev rule sanity: does a 3D printer udev rule already exist?
  if ls /etc/udev/rules.d/*printer*.rules /etc/udev/rules.d/*klipper*.rules 2>/dev/null | grep -q .; then
    log "Existing printer udev rules found:"
    ls -1 /etc/udev/rules.d/*printer*.rules /etc/udev/rules.d/*klipper*.rules 2>/dev/null | sed 's/^/    /'
  else
    echo "  (no custom printer udev rules - fine unless you need stable /dev/serial/by-id names)"
  fi

  check_group_perms
}

#-------------------------------------------------------------------------------
# Step 3: Domain check
#-------------------------------------------------------------------------------
build_base_url() {
  [ -n "$DOWNLOAD_DOMAIN" ] || return 1
  local base="${DOWNLOAD_DOMAIN%/}"
  local path="${DRIVER_PATH#/}"
  printf '%s/%s' "$base" "$path"
}

check_domain_drivers() {
  local base_url
  base_url=$(build_base_url) || die "DOWNLOAD_DOMAIN not set - edit CONFIG block at top of $SCRIPT_NAME"

  log "Checking domain for driver index: $base_url"
  if ! curl -fsSL --head --max-time 10 "$base_url/" >/dev/null 2>&1; then
    warn "Could not reach $base_url - check domain, DNS, DoH resolver, or firewall rules."
    return 1
  fi

  local sums_url="$base_url/SHA256SUMS"
  log "Fetching checksum index: $sums_url"
  local sums_content
  if sums_content=$(curl -fsSL --max-time 15 "$sums_url" 2>/dev/null); then
    log "Available driver/firmware packages on your domain:"
    echo "---- SHA256SUMS ----"
    echo "$sums_content"
    echo "--------------------"
  else
    warn "No SHA256SUMS at $sums_url - add one so downloads can be verified."
  fi
}

#-------------------------------------------------------------------------------
# Step 4: Download + verify
#-------------------------------------------------------------------------------
verify_checksums() {
  local file="$1"
  local dir
  dir="$(dirname "$file")"
  local sums_file="$dir/SHA256SUMS"

  if [ ! -f "$sums_file" ]; then
    warn "No SHA256SUMS next to $file - skipping verification."
    return 0
  fi
  log "Verifying $(basename "$file") against SHA256SUMS..."
  if (cd "$dir" && sha256sum --check --strict "$(basename "$sums_file")"); then
    log "Checksum OK."
  else
    err "Checksum MISMATCH for $(basename "$file") - do NOT install this file."
    return 1
  fi
}

download_driver() {
  local pkg_name="$1"
  local base_url
  base_url=$(build_base_url) || die "DOWNLOAD_DOMAIN not set."

  local distro="generic"
  if [ -f /etc/os-release ]; then
    distro=$(. /etc/os-release; echo "${ID:-generic}")
  fi

  local url="$base_url/$distro/$pkg_name"
  mkdir -p "$DOWNLOAD_DIR"

  log "Downloading $url"
  if ! curl -fSL --max-time 300 -o "$DOWNLOAD_DIR/$(basename "$pkg_name")" "$url"; then
    err "Download failed: $url"
    return 1
  fi

  if [ "$VERIFY_CHECKSUMS" = "yes" ]; then
    curl -fsSL --max-time 15 -o "$DOWNLOAD_DIR/SHA256SUMS" "$base_url/$distro/SHA256SUMS" 2>/dev/null \
      || warn "Could not fetch SHA256SUMS - verification skipped."
    verify_checksums "$DOWNLOAD_DIR/$(basename "$pkg_name")" || return 1
  fi

  log "Saved to: $DOWNLOAD_DIR/$(basename "$pkg_name")"
  log "Kernel modules (.ko): install via sudo insmod / dkms; firmware: copy to /lib/firmware/."
}

#-------------------------------------------------------------------------------
# Step 5: Combined flow
#-------------------------------------------------------------------------------
run_full_flow() {
  echo "===================================================="
  echo " L3DPS - Linux 3D Printing System Driver Finder"
  echo " v$VERSION - CyberCrime-Stoppers"
  echo "===================================================="
  check_deps

  echo
  echo "--- [1/5] Hardware Scan ---"
  mapfile -t readers < <(scan_usb_printers)
  if [ ${#readers[@]} -eq 0 ] || [ -z "${readers[0]:-}" ]; then
    warn "No known 3D printer controller boards detected."
    echo "Tips:"
    echo "  * Power the printer ON and plug USB directly into the PC (no cheap hubs)"
    echo "  * Try a different USB cable - charge-only cables are a classic trap"
    echo "  * Run 'lsusb' manually and look for CH340/CP210x/FTDI/Arduino entries"
  else
    echo "Detected 3D printing hardware:"
    for r in "${readers[@]}"; do
      IFS='|' read -r id desc chip boards drv <<<"$r"
      echo "  $id  [$chip]  ->  kernel driver: $drv"
      echo "      boards: $boards"
    done
  fi

  echo
  echo "--- [2/5] Serial Nodes ---"
  list_tty_nodes

  echo
  echo "--- [3/5] Kernel Modules ---"
  check_kernel_modules

  echo
  echo "--- [4/5] Blocker Check (brltty / ModemManager / perms) ---"
  troubleshoot_blockers

  echo
  echo "--- [5/5] Domain Drivers ---"
  if [ -n "$DOWNLOAD_DOMAIN" ]; then
    check_domain_drivers || true
    if [ ${#readers[@]} -gt 0 ] && [ -n "${readers[0]:-}" ]; then
      read -rp "Driver package filename to download (blank to skip): " pkg
      [ -n "$pkg" ] && download_driver "$pkg" || log "Skipping download."
    fi
  else
    warn "DOWNLOAD_DOMAIN not configured - edit CONFIG block at top of script."
  fi

  log "L3DPS flow complete. Log: $LOG_FILE"
}

#-------------------------------------------------------------------------------
# Argument parsing
#-------------------------------------------------------------------------------
QUIET=false
JSON_MODE=false
ACTION="scan"

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    -s|--scan)         ACTION="scan" ;;
    -t|--troubleshoot) ACTION="troubleshoot" ;;
    -c|--check)        ACTION="check" ;;
    -d|--download)     ACTION="download" ;;
    -a|--all)          ACTION="all" ;;
    -j|--json)         JSON_MODE=true ;;
    -q|--quiet)        QUIET=true ;;
    *)                 err "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

case "$ACTION" in
  scan)
    check_deps
    if [ "$JSON_MODE" = "true" ]; then
      echo '{"tool":"l3dps","version":"'"$VERSION"'","devices":['
      first=true
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        IFS='|' read -r id desc chip boards drv <<<"$line"
        $first && first=false || echo ","
        printf '{"usb_id":"%s","chip":"%s","boards":"%s","driver":"%s"}' \
          "$id" "${chip//\"/\\\"}" "${boards//\"/\\\"}" "$drv"
      done < <(scan_usb_printers)
      echo ']}'
    else
      scan_usb_printers
      echo
      list_tty_nodes
      echo
      check_kernel_modules
    fi
    ;;
  troubleshoot) check_deps; troubleshoot_blockers ;;
  check)       check_domain_drivers ;;
  download)
    read -rp "Driver package filename to download: " pkg
    [ -n "$pkg" ] && download_driver "$pkg" || die "No package given."
    ;;
  all) run_full_flow ;;
esac

