#!/system/bin/sh
# y52s: give the legacy (Android 10) keystore daemon a writable working copy of
# the device's keystore store, then start it.
#
# Why this exists
# ---------------
# The platform keystore is the only component that can unwrap an auth-bound key
# (the app-clone user 999 escrow entry "synthetic_password_<handle>").  On this
# device the daemon is the Android 10 one, which stores its database as plain
# files under /data/misc/keystore/user_<uid>/.  Recovery must not write into
# /data, so the store is copied into tmpfs and the daemon runs against the copy.
# Nothing here is device specific: the source is whatever the user's own /data
# contains.
#
# Timing matters: this used to be exec'd from "on property:recovery.service=1",
# which fires BEFORE recovery mounts /data.  Measured on device, the script
# logged "no /data/misc/keystore", the daemon was then started anyway and came
# up on an empty database (init.svc.keystore=running, zero aliases).  So wait
# for the mount first, and only then start the daemon.
set -u

SRC=/data/misc/keystore
DST=/tmp/misc/keystore
LOG=/tmp/y52s_ks_prep.log
WAIT_MAX=180

: > "$LOG"
echo "y52s_ks_prep: waiting for $SRC (recovery mounts /data read-only)" >> "$LOG"

i=0
while [ ! -d "$SRC/user_0" ] && [ "$i" -lt "$WAIT_MAX" ]; do
    sleep 1
    i=$((i + 1))
done

if [ ! -d "$SRC/user_0" ]; then
    echo "y52s_ks_prep: timeout after ${i}s, $SRC/user_0 still missing" >> "$LOG"
    exit 0
fi

# vold (or a previous daemon start) may already have created an EMPTY
# user_<uid> directory in the tmpfs path.  Testing "is the destination empty"
# therefore never fires and the daemon would come up on an empty database -
# measured on device: /tmp/misc/keystore held only an empty user_0, so the
# service ran but every alias lookup failed.  Always rebuild the working copy
# from the real store instead.
stop keystore 2>/dev/null
sleep 1
rm -rf "$DST"
mkdir -p "$DST" 2>/dev/null
cp -a "$SRC"/. "$DST"/ 2>/dev/null

echo "y52s_ks_prep: waited=${i}s src=$(ls -A "$SRC" 2>/dev/null | tr '\n' ' ')" >> "$LOG"
echo "y52s_ks_prep: user_0=$(ls -A "$DST/user_0" 2>/dev/null | wc -l) user_999=$(ls -A "$DST/user_999" 2>/dev/null | wc -l)" >> "$LOG"

start keystore
sleep 2
echo "y52s_ks_prep: svc=$(getprop init.svc.keystore) pid=$(pidof keystore)" >> "$LOG"
exit 0
