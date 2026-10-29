#!/usr/bin/env bash
# LogSentry installer for Debian and Ubuntu servers. Run it from the logsentry folder:
#   sudo ./install.sh              install, or update after a git pull
#   sudo ./install.sh --uninstall  remove LogSentry (asks before deleting stored alerts)
# Options:
#   --phone / --no-phone   answer the phone-alerts question in advance
#   --ntfy-url URL         use this ntfy topic URL instead of a generated one
set -euo pipefail
umask 022 # the service user must be able to read what root installs

APP=/opt/logsentry
PYTHONS=/opt/logsentry-python
UVDIR=/opt/logsentry-uv
STATE=/var/lib/logsentry
ETC=/etc/logsentry
UNITS=(logsentry-tail logsentry-web)
TIMER=logsentry-summary.timer
SRC=$(cd "$(dirname "$0")" && pwd)

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

# ask "question" y|n: returns 0 for yes. With no keyboard (a script, a pipe) it takes the default.
ask() {
  local reply=""
  if (exec </dev/tty) 2>/dev/null; then read -r -p "$1 " reply </dev/tty || reply=""; fi
  [[ ${reply:-$2} =~ ^[Yy] ]]
}

apt_install() {
  # NEEDRESTART_SUSPEND: skip Ubuntu's "services need restarting" report after the install
  apt-get update -qq &&
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get install -y -qq "$@" >/dev/null
}

uninstall() {
  say "Removing LogSentry"
  systemctl disable --now "${UNITS[@]}" "$TIMER" >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/logsentry-{tail,web,summary}.service "/etc/systemd/system/$TIMER"
  systemctl daemon-reload
  rm -rf "$APP" "$PYTHONS" "$UVDIR" /usr/local/bin/logsentry
  if ask "Also delete the stored alerts and phone-alert settings? [y/N]" n; then
    rm -rf "$STATE" "$ETC"
  else
    echo "Kept $STATE (alerts) and $ETC (settings): a reinstall picks them up again."
  fi
  if id logsentry >/dev/null 2>&1; then userdel logsentry; fi
  echo "LogSentry is removed."
}

check_ssh_log() {
  [ -e /var/log/auth.log ] && return
  say "/var/log/auth.log is missing: this server keeps SSH logins only in the journal"
  if ask "Install rsyslog so SSH logins are written to /var/log/auth.log? [Y/n]" y; then
    apt_install rsyslog
    systemctl enable --now rsyslog >/dev/null 2>&1
  else
    echo "Skipped: SSH attacks won't be detected until /var/log/auth.log exists."
  fi
}

install_app() {
  say "Installing LogSentry in $APP"
  if [ ! -x "$UVDIR/uv" ]; then
    command -v curl >/dev/null || apt_install curl
    # uv sets up Python for LogSentry; kept in its own folder, no change to anyone's PATH
    curl -LsSf https://astral.sh/uv/install.sh |
      env UV_INSTALL_DIR="$UVDIR" UV_NO_MODIFY_PATH=1 sh >/dev/null 2>&1
  fi
  [ -x "$UVDIR/uv" ] || die "could not install uv into $UVDIR"
  id logsentry >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin logsentry
  if [ "$SRC" != "$APP" ]; then
    rm -rf "$APP"
    mkdir -p "$APP"
    cp -r "$SRC"/{pyproject.toml,uv.lock,README.md,LICENSE,src,config,deploy} "$APP"/
  fi
  (cd "$APP" && UV_PYTHON_INSTALL_DIR="$PYTHONS" UV_NO_CACHE=1 \
    "$UVDIR/uv" sync --no-dev --frozen --quiet)
  ln -sf "$APP/.venv/bin/logsentry" /usr/local/bin/logsentry
}

setup_phone() {
  if [ -f "$ETC/logsentry.env" ] && [ -z "$ntfy_url" ]; then
    echo "Phone alerts: keeping your settings in $ETC/logsentry.env"
    return
  fi
  if [ "$phone" = ask ]; then
    say "Phone alerts"
    if ask "Send HIGH alerts to your phone with the free ntfy app? [Y/n]" y; then
      phone=yes
    else
      phone=no
    fi
  fi
  if [ "$phone" = no ]; then
    echo "Phone alerts: off. Turn them on later with: sudo ./install.sh --phone"
    return
  fi
  # a long random topic: anyone who knows the name can read the alerts
  local url=${ntfy_url:-https://ntfy.sh/logsentry-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')}
  case $url in https://* | http://*) ;; *) die "--ntfy-url must start with https://" ;; esac
  install -d -m 700 "$ETC"
  (umask 077 && printf 'LOGSENTRY_NTFY_URL=%s\n' "$url" >"$ETC/logsentry.env")
  command -v qrencode >/dev/null || apt_install qrencode || true
  cat <<EOF

On your phone:
  1. Install "ntfy" by Philipp C. Heckel from Google Play (or the App Store).
  2. Tap +, enter this topic, keep the server ntfy.sh, and tap Subscribe:

       ${url##*/}

  Keep this name secret: anyone who knows it can read your alerts.
  You get each HIGH alert right away, plus a short summary every morning at 08:00.
EOF
  if command -v qrencode >/dev/null; then
    echo "  Or scan this code with your phone camera to open the topic:"
    qrencode -t ansiutf8 -m 2 "$url"
  fi
  ask "Press Enter once you are subscribed, to send a test notification." y || true
}

start_services() {
  say "Starting LogSentry"
  cp "$APP"/deploy/systemd/*.service "$APP/deploy/systemd/$TIMER" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable "${UNITS[@]}" "$TIMER" >/dev/null 2>&1
  systemctl restart "${UNITS[@]}" # restart, not start: an update must load the new code
  systemctl start "$TIMER"        # only arms the timer; the first summary comes at 08:00
  sleep 2
}

mode=install phone=ask ntfy_url=""
while [ $# -gt 0 ]; do
  case $1 in
    --uninstall) mode=uninstall ;;
    --phone) phone=yes ;;
    --no-phone) phone=no ;;
    --ntfy-url)
      ntfy_url=${2:-}
      [ -n "$ntfy_url" ] || die "--ntfy-url needs a URL"
      phone=yes
      shift
      ;;
    -h | --help)
      sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown option: $1 (see ./install.sh --help)" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "run it with sudo: sudo ./install.sh"
command -v systemctl >/dev/null || die "this installer needs systemd (Debian or Ubuntu)"
command -v apt-get >/dev/null || die "this installer supports Debian and Ubuntu only"

if [ "$mode" = uninstall ]; then
  uninstall
  exit 0
fi
[ -f "$SRC/pyproject.toml" ] && [ -d "$SRC/deploy/systemd" ] ||
  die "run install.sh from inside the logsentry folder"

check_ssh_log
install_app
setup_phone
start_services
say "Health check"
logsentry doctor || true
cat <<'EOF'

LogSentry is running and starts by itself after a reboot.

  Health check      sudo logsentry doctor
  Live alerts       journalctl -u logsentry-tail -f
  Daily summary     every morning at 08:00; send one now: sudo systemctl start logsentry-summary
  Dashboard         on your PC: ssh -L 8000:127.0.0.1:8000 you@this-server
                    then open http://127.0.0.1:8000
  Update            git pull, then sudo ./install.sh again
  Uninstall         sudo ./install.sh --uninstall
EOF
