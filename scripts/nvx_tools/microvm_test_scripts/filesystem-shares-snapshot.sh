set -eu
fail() {
    code="$1"
    echo "NVX-FILESYSTEM-SHARES-SNAPSHOT-FAIL code=$code"
    nvx-exit "$code"
    exit "$code"
}

grep -q '^microvm /workspace virtiofs rw' /proc/mounts || fail 80
grep -q '^microvm1 /opt/hostedtoolcache virtiofs ro' /proc/mounts || fail 81
exec 3<>/workspace/journal
printf NVX-BEFORE >&3
echo NVX-FILESYSTEM-SHARES-BEFORE
nvx-snapshot
printf NVX-AFTER >&3
exec 3>&-
[ "$(cat /workspace/journal)" = NVX-BEFORENVX-AFTER ] || fail 82
[ "$(cat /opt/hostedtoolcache/seed)" = NVX-TOOLCACHE ] || fail 83
if touch /opt/hostedtoolcache/mutation 2>/dev/null; then
    fail 84
fi
echo NVX-FILESYSTEM-SHARES-AFTER
nvx-exit 0
