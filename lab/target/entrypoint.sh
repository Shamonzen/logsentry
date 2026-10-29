#!/bin/sh
set -eu

# The weak lab password comes from .env at run time, so it is never baked into an image layer.
: "${LAB_PASSWORD:?set LAB_PASSWORD in .env (copy .env.example)}"
echo "labuser:${LAB_PASSWORD}" | chpasswd

ssh-keygen -A
rsyslogd
nginx
# No -e: sshd must log to syslog (/dev/log) so rsyslog writes auth.log with RFC 3339 timestamps.
exec /usr/sbin/sshd -D
