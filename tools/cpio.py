#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dependency-free 'newc' (070701/070702) cpio reader / writer for Android ramdisks.

The archive is kept as an ordered list of entries + separate blobs, so that
symlinks, hard links, device nodes and odd file names survive a Windows host
without ever being materialised on the host filesystem.

Usage:
  python cpio.py extract <in.cpio> <outdir>
  python cpio.py list    <outdir> [pattern]
  python cpio.py cat     <outdir> <archive-path> [outfile]
  python cpio.py rebuild <outdir> <out.cpio> [overrides.json]
"""
import os
import sys
import json
import struct
import hashlib

HDR_LEN = 110
MAGICS = (b'070701', b'070702')
FIELDS = ('ino', 'mode', 'uid', 'gid', 'nlink', 'mtime', 'filesize',
          'devmajor', 'devminor', 'rdevmajor', 'rdevminor', 'namesize', 'check')


def pad4(n):
    return (n + 3) & ~3


def read_cpio(data):
    entries = []
    off = 0
    n = len(data)
    archives = 0
    while off + HDR_LEN <= n:
        hdr = data[off:off + HDR_LEN]
        if hdr[:6] not in MAGICS:
            # trailing padding / zero fill
            if data[off:].strip(b'\0') == b'':
                break
            # concatenated archive aligned with zeros
            nxt = data.find(b'070701', off)
            if nxt < 0:
                break
            off = nxt
            hdr = data[off:off + HDR_LEN]
            if hdr[:6] not in MAGICS:
                break
        archives += 1
        magic = hdr[:6]
        vals = {}
        pos = 6
        for f in FIELDS:
            vals[f] = int(hdr[pos:pos + 8], 16)
            pos += 8
        name_start = off + HDR_LEN
        name_end = name_start + vals['namesize']
        name_b = data[name_start:name_end]
        if not name_b.endswith(b'\0'):
            raise ValueError('bad name at 0x%X' % off)
        name = name_b[:-1].decode('utf-8', 'surrogateescape')
        data_start = pad4(name_start - off + vals['namesize']) + off
        data_end = data_start + vals['filesize']
        blob = data[data_start:data_end]
        next_off = pad4(data_end - off) + off
        entries.append({
            'magic': magic.decode(),
            'vals': vals,
            'name': name,
            'blob': blob,
            'offset': off,
        })
        off = next_off
        if name == 'TRAILER!!!':
            # A cpio archive ends here. Android may concatenate another one,
            # aligned to 4 bytes; skip pure zero padding up to 0x800.
            j = off
            while j < n and data[j] == 0:
                j += 1
            if j < n and data[j:j + 6] in MAGICS:
                off = j
                continue
            break
    return entries


def write_cpio(entries, magic='070701'):
    out = bytearray()
    for e in entries:
        b = bytearray()
        b += magic.encode()
        v = dict(e['vals'])
        name_b = e['name'].encode('utf-8', 'surrogateescape') + b'\0'
        v['namesize'] = len(name_b)
        blob = e['blob']
        v['filesize'] = len(blob) if e.get('has_data', True) else 0
        if e['magic'] == '070702':
            v['check'] = 0  # newc CRC variant: keep explicit 0
        for f in FIELDS:
            b += ('%08x' % (v[f] & 0xFFFFFFFF)).encode()
        b += name_b
        b += b'\0' * (pad4(len(b)) - len(b))
        b += blob if v['filesize'] else b''
        b += b'\0' * (pad4(len(b)) - len(b))
        out += b
    return bytes(out)


def kind_of(mode):
    t = mode & 0o170000
    return {0o040000: 'dir', 0o100000: 'file', 0o120000: 'symlink',
            0o020000: 'chr', 0o060000: 'blk', 0o010000: 'fifo',
            0o140000: 'sock'}.get(t, 'unknown')


def blob_dir(outdir):
    return os.path.join(outdir, 'blobs')


def cmd_extract(cpio_path, outdir):
    data = open(cpio_path, 'rb').read()
    entries = read_cpio(data)
    os.makedirs(blob_dir(outdir), exist_ok=True)
    meta = []
    for i, e in enumerate(entries):
        k = kind_of(e['vals']['mode'])
        has_data = e['vals']['filesize'] > 0
        if has_data:
            with open(os.path.join(blob_dir(outdir), '%05d.bin' % i), 'wb') as f:
                f.write(e['blob'])
        meta.append(dict(index=i, name=e['name'], magic=e['magic'],
                         mode=e['vals']['mode'], kind=k,
                         uid=e['vals']['uid'], gid=e['vals']['gid'],
                         ino=e['vals']['ino'], nlink=e['vals']['nlink'],
                         mtime=e['vals']['mtime'],
                         devmajor=e['vals']['devmajor'],
                         devminor=e['vals']['devminor'],
                         rdevmajor=e['vals']['rdevmajor'],
                         rdevminor=e['vals']['rdevminor'],
                         check=e['vals']['check'],
                         size=len(e['blob']), has_data=has_data,
                         sha256=hashlib.sha256(e['blob']).hexdigest()[:16],
                         offset=e['offset']))
    with open(os.path.join(outdir, 'entries.json'), 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=1, ensure_ascii=False)
    with open(os.path.join(outdir, 'filelist.txt'), 'w', encoding='utf-8',
              errors='surrogateescape') as f:
        for m in meta:
            f.write('%s %8d %s\n' % (m['kind'].ljust(8), m['size'], m['name']))
    print('entries:', len(entries), '->', outdir)
    from collections import Counter
    print('kinds  :', dict(Counter(m['kind'] for m in meta)))
    print('last   :', entries[-1]['name'] if entries else None)


def load_entries(outdir):
    meta = json.load(open(os.path.join(outdir, 'entries.json'), encoding='utf-8'))
    entries = []
    for m in meta:
        blob = b''
        if m['has_data']:
            blob = open(os.path.join(blob_dir(outdir),
                                    '%05d.bin' % m['index']), 'rb').read()
        v = {f: m[f] for f in ('ino', 'uid', 'gid', 'nlink', 'mtime',
                               'devmajor', 'devminor', 'rdevmajor',
                               'rdevminor', 'check')}
        v['mode'] = m['mode']
        v['filesize'] = len(blob)
        v['namesize'] = len(m['name'].encode('utf-8', 'surrogateescape')) + 1
        entries.append({'magic': m['magic'], 'vals': v, 'name': m['name'],
                        'blob': blob, 'has_data': m['has_data']})
    return entries


def cmd_list(outdir, pattern=None):
    meta = json.load(open(os.path.join(outdir, 'entries.json'), encoding='utf-8'))
    for m in meta:
        if pattern and pattern not in m['name']:
            continue
        print('%5d %-8s %9d %04o %s' %
              (m['index'], m['kind'], m['size'], m['mode'] & 0o7777, m['name']))


def cmd_cat(outdir, name, outfile=None):
    for m in json.load(open(os.path.join(outdir, 'entries.json'), encoding='utf-8')):
        if m['name'] == name:
            b = open(os.path.join(blob_dir(outdir),
                                 '%05d.bin' % m['index']), 'rb').read() if m['has_data'] else b''
            if outfile:
                open(outfile, 'wb').write(b)
                print('wrote', outfile, len(b), 'bytes')
            else:
                sys.stdout.buffer.write(b)
            return
    raise SystemExit('not found: ' + name)


def cmd_rebuild(outdir, out_cpio, overrides=None):
    entries = load_entries(outdir)
    ov = json.load(open(overrides, encoding='utf-8')) if overrides else {}
    applied = []
    for e in entries:
        if e['name'] in ov:
            with open(ov[e['name']], 'rb') as f:
                e['blob'] = f.read()
            e['has_data'] = True
            applied.append(e['name'])
    data = write_cpio(entries)
    open(out_cpio, 'wb').write(data)
    print('rebuilt', out_cpio, len(data), 'bytes,', applied, 'overrides')


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    c, a = sys.argv[1], sys.argv[2]
    b = sys.argv[3] if len(sys.argv) > 3 else None
    extra = sys.argv[4] if len(sys.argv) > 4 else None
    if c == 'extract':
        cmd_extract(a, b)
    elif c == 'list':
        cmd_list(a, b)
    elif c == 'cat':
        cmd_cat(a, b, extra)
    elif c == 'rebuild':
        cmd_rebuild(a, b, extra)
    else:
        raise SystemExit('unknown command ' + c)
