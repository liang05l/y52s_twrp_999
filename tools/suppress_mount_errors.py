#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suppress TWRP's "Failed to mount '/vendor' / '/system_root' / '/persist'" GUI
errors WITHOUT touching the recovery binary.

Why not patch partition.cpp like y73s does
-------------------------------------------
graft_999_precise.py replaces system/bin/recovery with the donor binary at the
end of the build, so any source-level patch to bootable/recovery/partition.cpp
is overwritten. (CI log: "target C++: recovery <= partition.cpp" is compiled,
yet all three images carry the identical b24ddb3b... recovery ELF.)

TWRP's own mechanism is equivalent: the fstab flag `removable` sets
TWPartition::Removable = true, and TWPartition::Mount() only calls
gui_msg(fail_mount=...) when `!Removable && Display_Error`. With Removable=true
it takes the `LOGINFO("Unable to mount ...")` branch instead -- same visual
result as y73s' 0002-Suppress-mount-errors patch, with zero binary changes.

This script keeps kernel / dtbo / dtb / rc / all 999 payload bytes untouched,
only edits three fstab lines, rebuilds the boot image, and re-signs the AVB
vbmeta/footer with the stock template.

Usage:
  python suppress_mount_errors.py --img <in.img> --template <boot_ref.bin> --out <out.img>
"""
import os
import sys
import re
import gzip
import json
import struct
import hashlib
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bootimg import parse_header, layout, build_header, align  # noqa: E402
from cpio import read_cpio, write_cpio  # noqa: E402

PAGE = 0x800
PARTITION = 0x6000000
FSTAB = 'system/etc/recovery.fstab'
SUMS = 'ramdisk-files.sha256sum'
TARGETS = ('/vendor', '/system_root', '/persist')

be64 = lambda b, o: struct.unpack_from('>Q', b, o)[0]
be32 = lambda b, o: struct.unpack_from('>I', b, o)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--img', required=True)
    ap.add_argument('--template', required=True, help='prebuilt/boot_ref.bin')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    src = open(a.img, 'rb').read()
    h = parse_header(src)
    lay = layout(h, len(src))
    parts = {}
    for k in ('kernel', 'ramdisk', 'recovery_dtbo', 'dtb'):
        s, e = lay[k]
        parts[k] = src[s:e]

    # ---------- 1. edit fstab ----------
    raw = parts['ramdisk']
    if raw[:2] == b'\x1f\x8b':
        raw = gzip.decompress(raw)
    entries = read_cpio(raw)
    idx = {e['name']: i for i, e in enumerate(entries)}
    if FSTAB not in idx:
        raise SystemExit('fstab not found: ' + FSTAB)
    text = entries[idx[FSTAB]]['blob'].decode('utf-8', 'replace')
    new_lines = []
    changed = []
    for line in text.split('\n'):
        m = re.match(r'^(/\S+)\s', line)
        if m and m.group(1) in TARGETS and 'flags=' in line:
            if 'removable' not in line:
                line = line.rstrip() + ';removable'
                changed.append(m.group(1))
        new_lines.append(line)
    new_text = '\n'.join(new_lines)
    if sorted(changed) != sorted(TARGETS):
        raise SystemExit('expected to change %s, changed %s' % (TARGETS, changed))
    entries[idx[FSTAB]]['blob'] = new_text.encode('utf-8')
    print('fstab: added ;removable to %s' % ', '.join(changed))

    # keep TWRP's hash manifest in sync
    if SUMS in idx:
        sums = entries[idx[SUMS]]['blob'].decode('utf-8', 'replace').split('\n')
        newhash = hashlib.sha256(entries[idx[FSTAB]]['blob']).hexdigest()
        hit = 0
        for i, l in enumerate(sums):
            if l.rstrip().endswith('./' + FSTAB):
                sums[i] = '%s  ./%s' % (newhash, FSTAB)
                hit += 1
        if hit:
            entries[idx[SUMS]]['blob'] = '\n'.join(sums).encode('utf-8')
            print('  %s: updated %d line(s)' % (SUMS, hit))
        else:
            print('  %s: no fstab entry, left as-is' % SUMS)

    # ---------- 2. rebuild boot image ----------
    parts['ramdisk'] = gzip.compress(write_cpio(entries), mtime=0)
    nh = dict(h)
    for k in ('kernel', 'ramdisk', 'second', 'recovery_dtbo', 'dtb'):
        nh[k + '_size'] = len(parts.get(k, b''))
    nh['recovery_dtbo_offset'] = 0
    out = bytearray(build_header(nh))
    cursor = PAGE
    for k in ('kernel', 'ramdisk', 'second', 'recovery_dtbo', 'dtb'):
        if k not in parts or not parts[k]:
            continue
        cursor = align(cursor, PAGE)
        out.extend(b'\0' * (cursor - len(out)))
        if k == 'recovery_dtbo':
            nh['recovery_dtbo_offset'] = cursor
        out.extend(parts[k])
        cursor += len(parts[k])
    section_end = align(cursor, PAGE)
    out.extend(b'\0' * (section_end - len(out)))
    out[:0x800] = build_header(nh)                       # write dtbo offset back
    vb_off = section_end + PAGE                          # matches stock layout
    out.extend(b'\0' * (vb_off - len(out)))

    # ---------- 3. AVB: stock vbmeta template, recompute hashes ----------
    tpl = open(a.template, 'rb').read()
    if tpl[:8] != b'ANDROID!' or tpl[0x800:0x804] != b'AVB0':
        raise SystemExit('bad boot_ref.bin template')
    vb = bytearray(tpl[0x800:])
    ab, aux = be64(vb, 0x0C), be64(vb, 0x14)
    qd = 256 + ab + 16
    pn, sl, rl, _ = struct.unpack_from('>IIII', vb, qd + 40)
    off = qd + 116
    salt = bytes(vb[off + pn:off + pn + sl])
    struct.pack_into('>Q', vb, qd, section_end)
    vb[off + pn + sl:off + pn + sl + rl] = hashlib.sha256(
        salt + bytes(out[:section_end])).digest()
    vb[256:288] = hashlib.sha256(
        bytes(vb[:256]) + bytes(vb[256 + ab:256 + ab + aux])).digest()
    out.extend(vb)
    out.extend(b'\0' * (PARTITION - 64 - len(out)))
    out.extend(b'AVBf' + struct.pack('>IIQQQ', 1, 0,
                                     section_end, vb_off, len(vb)) + bytes(28))
    d = bytes(out)

    # ---------- 4. self checks ----------
    nh2 = parse_header(d)
    lay2 = layout(nh2, len(d))
    raw2 = d[lay2['ramdisk'][0]:lay2['ramdisk'][1]]
    if raw2[:2] == b'\x1f\x8b':
        raw2 = gzip.decompress(raw2)
    e2 = {x['name']: x['blob'] for x in read_cpio(raw2)}
    f2 = d[-64:]
    sect2, vo2, vs2 = be64(f2, 0x0C), be64(f2, 0x14), be64(f2, 0x1C)
    vb2 = d[vo2:vo2 + vs2]
    alg2, ab2, aux2 = be32(vb2, 0x1C), be64(vb2, 0x0C), be64(vb2, 0x14)
    qd2 = 256 + ab2 + 16
    pn2, sl2, rl2, _ = struct.unpack_from('>IIII', vb2, qd2 + 40)
    o2 = qd2 + 116
    salt2 = vb2[o2 + pn2:o2 + pn2 + sl2]
    dig2 = vb2[o2 + pn2 + sl2:o2 + pn2 + sl2 + rl2]
    checks = [
        ('size == 96 MiB', len(d) == PARTITION),
        ('kernel unchanged', d[lay2['kernel'][0]:lay2['kernel'][1]] == parts['kernel']),
        ('dtbo unchanged', d[lay2['recovery_dtbo'][0]:lay2['recovery_dtbo'][1]] == parts['recovery_dtbo']),
        ('dtb unchanged', d[lay2['dtb'][0]:lay2['dtb'][1]] == parts['dtb']),
        ('recovery binary unchanged', e2.get('system/bin/recovery') ==
         next(x['blob'] for x in entries if x['name'] == 'system/bin/recovery')),
        ('rc unchanged', e2.get('init.recovery.mt6853.rc') ==
         next(x['blob'] for x in entries if x['name'] == 'init.recovery.mt6853.rc')),
        ('999 payload intact', 'system/kslib' in e2),
        ('7 PD2057 firmwares', len([n for n in e2 if n.startswith('vendor/firmware/') and 'PD2057' in n]) == 7),
        ('fstab 3 removable flags', all(
            any(ln.startswith(t + ' ') and 'removable' in ln
                for ln in e2[FSTAB].decode('utf-8', 'replace').split('\n'))
            for t in TARGETS)),
        ('fstab other lines untouched', all(
            new_lines[i] == text.split('\n')[i] or
            (re.match(r'^(/\S+)\s', text.split('\n')[i]) and
             re.match(r'^(/\S+)\s', text.split('\n')[i]).group(1) in TARGETS)
            for i in range(len(new_lines)))),
        ('header cmdline/os_version/dtb_addr', (nh2['cmdline'], nh2['os_version'], nh2['dtb_addr']) ==
         (h['cmdline'], h['os_version'], h['dtb_addr'])),
        ('AVB footer', f2[:4] == b'AVBf' and sect2 == section_end and vo2 == vb_off),
        ('vbmeta algorithm=1 auth=320', alg2 == 1 and ab2 == 320 and vs2 == 1728),
        ('vbmeta salt == stock', salt2[:8] == bytes.fromhex('aee087a5be3b9829')),
        ('root digest', hashlib.sha256(salt2 + d[:sect2]).digest() == dig2),
        ('vbmeta hash', hashlib.sha256(vb2[:256] + vb2[256 + ab2:256 + ab2 + aux2]).digest() == vb2[256:288]),
    ]
    print('\n--- self checks ---')
    for label, ok in checks:
        print('  [%s] %s' % ('OK' if ok else 'FAIL', label))
    if not all(ok for _, ok in checks):
        raise SystemExit('self-check FAILED, refusing to write output')
    open(a.out, 'wb').write(d)
    print('\nwrote %s (%d bytes)' % (a.out, len(d)))
    print('sha256 = %s' % hashlib.sha256(d).hexdigest())


if __name__ == '__main__':
    main()
