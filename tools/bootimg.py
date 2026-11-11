#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal, dependency-free Android boot image (v0-v4) inspector / splitter / builder.
Written for the vivo y73s -> y52s TWRP port. All paths stay inside the workspace.

Usage:
  python bootimg.py info   <img>
  python bootimg.py unpack <img> <outdir>
  python bootimg.py build  <spec.json> <out.img>
"""
import os
import sys
import json
import struct
import hashlib

MAGIC = b'ANDROID!'
V0_SIZE = 0x660


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def u64(b, o):
    return struct.unpack_from('<Q', b, o)[0]


def align(n, p):
    return ((n + p - 1) // p) * p


def cstr(b):
    return b.split(b'\0', 1)[0].decode('utf-8', 'replace')


def parse_header(data):
    if data[:8] != MAGIC:
        raise ValueError('not an ANDROID! boot image')
    h = {}
    h['magic'] = data[:8].hex()
    h['kernel_size'] = u32(data, 0x08)
    h['kernel_addr'] = u32(data, 0x0C)
    h['ramdisk_size'] = u32(data, 0x10)
    h['ramdisk_addr'] = u32(data, 0x14)
    h['second_size'] = u32(data, 0x18)
    h['second_addr'] = u32(data, 0x1C)
    h['tags_addr'] = u32(data, 0x20)
    h['page_size'] = u32(data, 0x24)
    h['header_version'] = u32(data, 0x28)
    h['os_version'] = u32(data, 0x2C)
    h['name'] = cstr(data[0x30:0x40])
    h['cmdline'] = cstr(data[0x40:0x240])
    h['id'] = data[0x240:0x260].hex()
    h['extra_cmdline'] = cstr(data[0x260:0x660])
    h['_header_raw'] = data[:0x800].hex()
    ver = h['header_version']
    if ver >= 1:
        h['recovery_dtbo_size'] = u32(data, 0x660)
        h['recovery_dtbo_offset'] = u64(data, 0x664)
        h['header_size'] = u32(data, 0x66C)
    else:
        h['recovery_dtbo_size'] = 0
        h['recovery_dtbo_offset'] = 0
        h['header_size'] = V0_SIZE
    if ver >= 2:
        h['dtb_size'] = u32(data, 0x670)
        h['dtb_addr'] = u64(data, 0x674)
    else:
        h['dtb_size'] = 0
        h['dtb_addr'] = 0
    return h


def layout(h, total):
    p = h['page_size']
    off = {}
    off['header'] = (0, align(h['header_size'], p) if h['header_size'] else p)
    k_off = p
    off['kernel'] = (k_off, k_off + h['kernel_size'])
    cursor = align(off['kernel'][1], p)
    if h['ramdisk_size']:
        off['ramdisk'] = (cursor, cursor + h['ramdisk_size'])
        cursor = align(off['ramdisk'][1], p)
    if h['second_size']:
        off['second'] = (cursor, cursor + h['second_size'])
        cursor = align(off['second'][1], p)
    if h['recovery_dtbo_size']:
        o = h['recovery_dtbo_offset'] or cursor
        off['recovery_dtbo'] = (o, o + h['recovery_dtbo_size'])
        cursor = align(max(cursor, off['recovery_dtbo'][1]), p)
    if h['dtb_size']:
        off['dtb'] = (cursor, cursor + h['dtb_size'])
        cursor = align(off['dtb'][1], p)
    off['_cursor_end'] = cursor
    off['_total'] = total
    return off


def sniff(b):
    if b.startswith(b'\x1f\x8b'):
        return 'gzip'
    if b.startswith(b'\x02\x21\x4c\x18'):
        return 'lz4_legacy'
    if b.startswith(b'\x04\x22\x4d\x18'):
        return 'lz4_frame'
    if b.startswith(b'\x28\xb5\x2f\xfd'):
        return 'zstd'
    if b.startswith(b'\xd0\x0d\xfe\xed'):
        return 'dtb'
    if b.startswith(b'\x30\x37\x30\x37'):
        return 'cpio_newc'
    if b.startswith(b'\x5d\x00\x00'):
        return 'lzma'
    return 'unknown:' + b[:8].hex()


def cmd_info(path):
    data = open(path, 'rb').read()
    h = parse_header(data)
    off = layout(h, len(data))
    print('file      :', path)
    print('size      :', len(data), '(0x%X)' % len(data))
    for k in ('kernel_size', 'kernel_addr', 'ramdisk_size', 'ramdisk_addr',
              'second_size', 'second_addr', 'tags_addr', 'page_size',
              'header_version', 'os_version', 'header_size',
              'recovery_dtbo_size', 'recovery_dtbo_offset', 'dtb_size', 'dtb_addr'):
        v = h[k]
        print('  %-22s %-12d 0x%X' % (k, v, v))
    print('  name          :', h['name'])
    print('  cmdline       :', h['cmdline'])
    print('  extra_cmdline :', h['extra_cmdline'])
    print('  id(sha1-ish)  :', h['id'])
    print('-- sections --')
    for k, v in off.items():
        if k.startswith('_') or k == 'header':
            continue
        s, e = v
        chunk = data[s:e]
        print('  %-14s off=0x%-9X len=%-10d 0x%-9X magic=%s sha256=%s' %
              (k, s, e - s, e - s, sniff(chunk[:16]) if chunk else '-',
               hashlib.sha256(chunk).hexdigest()[:16]))
    print('  computed end  : 0x%X' % off['_cursor_end'])
    tail_start = off['_cursor_end']
    tail = data[tail_start:]
    nz = [i for i, c in enumerate(tail) if c]
    if nz:
        print('  trailing data : first non-zero at 0x%X, last at 0x%X, %d non-zero bytes' %
              (tail_start + nz[0], tail_start + nz[-1], len(nz)))
        print('  trailing head :', tail[nz[0]:nz[0] + 64].hex())
    else:
        print('  trailing data : all zero padding')
    avb = data[-64:]
    print('  AVB footer    :', 'yes magic=' + repr(avb[:4]) if avb[:4] == b'AVBf' else 'no')
    return h, off


def cmd_unpack(path, outdir):
    data = open(path, 'rb').read()
    h = parse_header(data)
    off = layout(h, len(data))
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, 'header.bin'), 'wb') as f:
        f.write(data[:h['header_size']])
    for k, v in off.items():
        if k.startswith('_') or k == 'header':
            continue
        s, e = v
        with open(os.path.join(outdir, k + '.bin'), 'wb') as f:
            f.write(data[s:e])
    meta = {'header': h,
            'layout': {k: (list(v) if isinstance(v, tuple) else v)
                       for k, v in off.items()},
            'source': os.path.basename(path)}
    with open(os.path.join(outdir, 'meta.json'), 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    print('unpacked ->', outdir)
    for k, v in off.items():
        if k.startswith('_'):
            continue
        s, e = v
        print('  %-14s 0x%X .. 0x%X (%d bytes) %s' %
              (k, s, e, e - s, sniff(data[s:e][:16])))


def build_header(h, id_bytes=None):
    b = bytearray(0x800)
    b[:8] = MAGIC
    struct.pack_into('<I', b, 0x08, h['kernel_size'])
    struct.pack_into('<I', b, 0x0C, h['kernel_addr'])
    struct.pack_into('<I', b, 0x10, h['ramdisk_size'])
    struct.pack_into('<I', b, 0x14, h['ramdisk_addr'])
    struct.pack_into('<I', b, 0x18, h['second_size'])
    struct.pack_into('<I', b, 0x1C, h['second_addr'])
    struct.pack_into('<I', b, 0x20, h['tags_addr'])
    struct.pack_into('<I', b, 0x24, h['page_size'])
    struct.pack_into('<I', b, 0x28, h['header_version'])
    struct.pack_into('<I', b, 0x2C, h['os_version'])
    b[0x30:0x40] = h['name'].encode()[:16].ljust(16, b'\0')
    b[0x40:0x240] = h['cmdline'].encode()[:512].ljust(512, b'\0')
    b[0x240:0x260] = bytes.fromhex(h['id']) if h.get('id') else (id_bytes or bytes(32))
    b[0x260:0x660] = h['extra_cmdline'].encode()[:1024].ljust(1024, b'\0')
    ver = h['header_version']
    if ver >= 1:
        struct.pack_into('<I', b, 0x660, h['recovery_dtbo_size'])
        struct.pack_into('<Q', b, 0x664, h['recovery_dtbo_offset'])
        struct.pack_into('<I', b, 0x66C, h['header_size'])
    if ver >= 2:
        struct.pack_into('<I', b, 0x670, h['dtb_size'])
        struct.pack_into('<Q', b, 0x674, h['dtb_addr'])
    return bytes(b[:h['header_size']]) + bytes(0x800 - h['header_size'])


def cmd_build(spec_path, out_path):
    spec = json.load(open(spec_path, encoding='utf-8'))
    base = os.path.dirname(os.path.abspath(spec_path))
    h = spec['header']
    p = h['page_size']
    parts = {}
    for k in ('kernel', 'ramdisk', 'second', 'recovery_dtbo', 'dtb'):
        rel = spec['parts'].get(k)
        if rel:
            parts[k] = open(os.path.join(base, rel), 'rb').read()
            h[k + '_size'] = len(parts[k])
        else:
            h[k + '_size'] = 0
    h['recovery_dtbo_offset'] = 0
    hdr = build_header(h)
    out = bytearray(hdr)
    cursor = p
    offsets = {}
    for k in ('kernel', 'ramdisk', 'second', 'recovery_dtbo', 'dtb'):
        if k not in parts:
            continue
        cursor = align(cursor, p)
        offsets[k] = cursor
        if k == 'recovery_dtbo':
            h['recovery_dtbo_offset'] = cursor
        out.extend(b'\0' * (cursor - len(out)))
        out.extend(parts[k])
        cursor += len(parts[k])
    # second pass: write the dtbo offset back into the header
    hdr = build_header(h)
    out[:len(hdr)] = hdr
    target = spec.get('pad_to', 0)
    if target:
        if len(out) > target:
            raise ValueError('image larger than pad_to: %d > %d' % (len(out), target))
        out.extend(b'\0' * (target - len(out)))
    open(out_path, 'wb').write(out)
    # mkbootimg computes id as sha1 over (kernel+ramdisk+second+dtb...) with header id zeroed
    print('built ->', out_path, len(out), 'bytes')
    for k, o in offsets.items():
        print('  %-14s 0x%X (%d bytes)' % (k, o, len(parts[k])))
    print('  dtbo_offset  0x%X' % h['recovery_dtbo_offset'])
    print('  header_size  %d' % h['header_size'])


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'info':
        cmd_info(sys.argv[2])
    elif cmd == 'unpack':
        cmd_unpack(sys.argv[2], sys.argv[3])
    elif cmd == 'build':
        cmd_build(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit('unknown command ' + cmd)
