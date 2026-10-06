set -eu
fail() {
    code="$1"
    echo "NVX-FILESYSTEM-SHARES-FAIL code=$code"
    nvx-exit "$code"
    exit "$code"
}

expect_read_only() {
    case "$1" in
        *'Read-only file system'*) ;;
        *)
            echo "NVX-FILESYSTEM-SHARES-ERROR $1"
            fail "$2"
            ;;
    esac
}

# Both fixed slots are discovered, and each share has its own tag.
grep -q 'virtio_mmio.device=0x1000@0xd0001000:6' /proc/cmdline || fail 40
grep -q 'virtio_mmio.device=0x1000@0xd0008000:13' /proc/cmdline || fail 41
grep -q 'virtfs_dir=/workspace virtfs_tag=microvm virtfs_mode=rw' /proc/cmdline || fail 42
grep -q 'virtfs_dir=/opt/hostedtoolcache virtfs_tag=microvm1 virtfs_mode=ro' /proc/cmdline || fail 43
grep -q '^microvm /workspace virtiofs rw' /proc/mounts || fail 44
grep -q '^microvm1 /opt/hostedtoolcache virtiofs ro' /proc/mounts || fail 45
[ "$(cat /workspace/seed)" = NVX-WORKSPACE ] || fail 46
[ "$(cat /opt/hostedtoolcache/seed)" = NVX-TOOLCACHE ] || fail 47
[ "$(cat /opt/hostedtoolcache/tools/node)" = NVX-TOOL ] || fail 48

# Each share hides only its own denied path.
[ ! -e /workspace/secrets ] || fail 49
[ ! -e /opt/hostedtoolcache/credentials ] || fail 50

# The read-write share accepts writes, and the read-only share rejects them,
# also through a link in the read-write share.
printf 'NVX-GUEST-WRITE\n' >/workspace/from-guest || fail 51
mkdir /workspace/guest-directory || fail 52
if touch /opt/hostedtoolcache/mutation 2>/dev/null; then
    fail 53
fi
ln -s /opt/hostedtoolcache/seed /workspace/toolcache-seed || fail 54
if (printf 'overwrite\n' >/workspace/toolcache-seed) 2>/dev/null; then
    fail 55
fi

# OpenVMM, not the guest mount flags, enforces the read-only mode: with the
# share's tag mounted read-write in the guest, the host still rejects every
# mutation with EROFS. A second mount of a tag would reuse the read-only
# superblock, so replace the boot mount instead.
umount /opt/hostedtoolcache || fail 56
mkdir -p /mnt/toolcache-rw
mount -t virtiofs -o rw microvm1 /mnt/toolcache-rw || fail 57
grep -q '^microvm1 /mnt/toolcache-rw virtiofs rw' /proc/mounts || fail 58
[ "$(cat /mnt/toolcache-rw/seed)" = NVX-TOOLCACHE ] || fail 59
if error=$(touch /mnt/toolcache-rw/mutation 2>&1); then
    fail 60
fi
expect_read_only "$error" 61
if error=$(mkdir /mnt/toolcache-rw/directory 2>&1); then
    fail 62
fi
expect_read_only "$error" 63
if error=$( (printf 'append\n' >>/mnt/toolcache-rw/seed) 2>&1); then
    fail 64
fi
expect_read_only "$error" 65
if error=$(rm -f /mnt/toolcache-rw/seed 2>&1); then
    fail 66
fi
expect_read_only "$error" 67
if error=$(mv /mnt/toolcache-rw/seed /mnt/toolcache-rw/moved 2>&1); then
    fail 68
fi
expect_read_only "$error" 69
if error=$(ln -s seed /mnt/toolcache-rw/link 2>&1); then
    fail 70
fi
expect_read_only "$error" 71
if error=$(chmod 0777 /mnt/toolcache-rw/seed 2>&1); then
    fail 72
fi
expect_read_only "$error" 73
[ "$(cat /mnt/toolcache-rw/seed)" = NVX-TOOLCACHE ] || fail 74
umount /mnt/toolcache-rw || fail 75

echo NVX-FILESYSTEM-SHARES-OK
nvx-exit 0
