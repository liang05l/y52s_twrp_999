#!/sbin/sh
# y52s: wait for dynamic-partition mapper nodes (they do NOT exist at 'on init'),
# then mount system/vendor so the FBE HAL binaries and VNDK libs are visible.
i=0
while [ $i -lt 30 ]; do
    [ -e /dev/block/mapper/system ] && [ -e /dev/block/mapper/vendor ] && break
    i=$((i+1))
    sleep 1
done
mkdir -p /system_root /vendor 2>/dev/null
mount | grep -q 'on /system_root type' || \
    mount -t ext4 -o ro /dev/block/mapper/system /system_root 2>/dev/null
mount | grep -q 'on /vendor type' || \
    mount -t ext4 -o ro /dev/block/mapper/vendor /vendor 2>/dev/null
exit 0
