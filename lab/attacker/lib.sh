# Shared helpers for the lab attacker scenarios. Every scenario sources this and calls
# guard_target before doing anything, so attacks can only ever hit the lab target.

# Hard rule (CLAUDE.md): attacks only ever reach the `target` container on the internal lab
# network. guard_target refuses unless the host is literally `target` AND resolves to a private
# address. The `lab` network is `internal: true`, so there is no route off it anyway; this is the
# second lock, in case a script is ever run somewhere it shouldn't be.
guard_target() {
    : "${TARGET:=target}"
    if [ "$TARGET" != "target" ]; then
        echo "guard_target: refusing '$TARGET' — this lab only attacks the 'target' container" >&2
        exit 1
    fi
    ip=$(getent hosts "$TARGET" | awk '{print $1; exit}')
    case "$ip" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;;
        *)
            echo "guard_target: '$TARGET' resolved to '${ip:-nothing}', not a private lab address — refusing" >&2
            exit 1 ;;
    esac
    echo "guard_target: ok, attacking $TARGET ($ip)"
}
