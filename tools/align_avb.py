#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Align a source-built recovery image's boot header + AVB footer/vbmeta with a
known-good (FBE decryption working) reference, WITHOUT touching any payload.

Why
---
The Trustonic keymaster TA binds the FBE keyblob to the boot root-of-trust
(vbmeta algorithm / salt / public key / rollback index / dtb load address).
The omni/TWRP BoardConfig uses external/avb/test/data/testkey_rsa4096.pem +
SHA256_RSA4096, so CI produces a vbmeta with algorithm=2, auth=576, aux=1600
and a fresh salt -- different from the stock/v1 root-of-trust. The TA then
returns KM_ERROR_KEY_REQUIRES_UPGRADE (-62) on begin(), and upgradeKey() fails
with KM_ERROR_INVALID_KEY_BLOB (-33). DE decryption never succeeds.

This script keeps kernel / ramdisk / recovery_dtbo / dtb EXACTLY as built and
only replaces:
  * boot header fields that differ from the reference
    (cmdline, second_addr, tags_addr, os_version, dtb_size, dtb_addr)
  * the trailing AVB vbmeta block, reusing the reference template (stock
    algorithm/salt/public key) but recomputing image_size, root digest and
    vbmeta hash for THIS image
  * the AVB footer

Reference can be either a full working image or a small committed template:
  prebuilt/boot_ref.bin = first 0x800 bytes of working image header
                          + working image's vbmeta blob (1728 bytes)

Usage
-----
  python align_avb.py --img <built.img> --ref <working.img> --out <out.img>
  python align_avb.py --img <built.img> --template prebuilt/boot_ref.bin --out <out.img>
"""
import os
import sys
import struct
import hashlib
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bootimg import parse_header, layout  # noqa: E402

be64 = lambda b, o: struct.unpack_from('>Q', b, o)[0]
be32 = lambda b, o: struct.unpack_from('>I', b, o)[0]
le64 = lambda b, o: struct.unpack_from('<Q', b, o)[0]
le32 = lambda b, o: struct.unpack_from('<I', b, o)[0]

PARTITION = 0x6000000
FOOTER_LEN = 64
HDR_RAW_LEN = 0x800


def vbmeta_fields(vb, tag=''):
    if vb[:4] != b'AVB0':
        raise SystemExit(tag + 'vbmeta magic is not AVB0')
    ab, aux, alg = be64(vb, 0x0C), be64(vb, 0x14), be32(vb, 0x1C)
    q = 256 + ab
    qd = q + 16
    pn, sl, rl, _ = struct.unpack_from('>IIII', vb, qd + 40)
    off = qd + 116
    salt = bytes(vb[off + pn:off + pn + sl])
    return dict(vb=bytearray(vb), ab=ab, aux=aux, alg=alg, q=q, qd=qd,
                off=off, pn=pn, sl=sl, rl=rl, salt=salt, vs=len(vb))


def load_source(path):
    d = open(path, 'rb').read()
    f = d[-FOOTER_LEN:]
    if f[:4] != b'AVBf':
        raise SystemExit('no AVB footer in ' + path)
    sect, vo, vs = be64(f, 0x0C), be64(f, 0x14), be64(f, 0x1C)
    h = parse_header(d)
    return dict(data=d, header=h, layout=layout(h, len(d)),
                sect=sect, vo=vo, vs=vs,
                vb=bytearray(d[vo:vo + vs]),
                alg=be32(d, vo + 0x1C),
                ab=be64(d, vo + 0x0C), aux=be64(d, vo + 0x14))


def load_ref_image(path):
    s = load_source(path)
    r = vbmeta_fields(bytes(s['vb']), 'reference: ')
    r['header'] = s['header']
    r['hdr_raw'] = s['data'][:HDR_RAW_LEN]
    return r


def load_ref_template(path):
    t = open(path, 'rb').read()
    if len(t) < HDR_RAW_LEN + 256:
        raise SystemExit('template too small: %d' % len(t))
    hdr = t[:HDR_RAW_LEN]
    if hdr[:8] != b'ANDROID!':
        raise SystemExit('template header magic is not ANDROID!')
    r = vbmeta_fields(t[HDR_RAW_LEN:], 'template: ')
    r['header'] = parse_header(hdr + bytes(HDR_RAW_LEN))
    r['hdr_raw'] = hdr
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--img', required=True, help='source-built image to fix')
    ap.add_argument('--ref', help='known-good full image')
    ap.add_argument('--template', help='small committed reference template')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    if bool(a.ref) == bool(a.template):
        raise SystemExit('exactly one of --ref / --template is required')

    src = load_source(a.img)
    ref = load_ref_image(a.ref) if a.ref else load_ref_template(a.template)
    out = bytearray(src['data'])

    src_salt = vbmeta_fields(bytes(src['vb']), 'source: ')['salt']
    print('source : %s' % a.img)
    print('  vbmeta algorithm=%d auth=%d aux=%d size=%d salt=%s dtb_addr=0x%X' %
          (src['alg'], src['ab'], src['aux'], src['vs'], src_salt[:8].hex(),
           src['header']['dtb_addr']))
    print('ref    : %s' % (a.ref or a.template))
    print('  vbmeta algorithm=%d auth=%d aux=%d size=%d salt=%s dtb_addr=0x%X' %
          (ref['alg'], ref['ab'], ref['aux'], ref['vs'], ref['salt'][:8].hex(),
           ref['header']['dtb_addr']))

    # ---- 1. boot header: align with the known-good image ----
    hd = ref['hdr_raw']
    out[0x1C:0x20] = hd[0x1C:0x20]          # second_addr
    out[0x20:0x24] = hd[0x20:0x24]          # tags_addr
    out[0x2C:0x30] = hd[0x2C:0x30]          # os_version
    out[0x40:0x240] = hd[0x40:0x240]        # cmdline
    out[0x260:0x660] = hd[0x260:0x660]      # extra_cmdline
    out[0x670:0x674] = hd[0x670:0x674]      # dtb_size (v2)
    out[0x674:0x67C] = hd[0x674:0x67C]      # dtb_addr (v2, 64-bit!)
    print('  header aligned: second_addr=0x%X tags_addr=0x%X os_version=0x%X dtb_addr=0x%X' %
          (le32(out, 0x1C), le32(out, 0x20), le32(out, 0x2C), le64(out, 0x674)))

    # ---- 2. vbmeta: reuse stock template, recompute only hashes ----
    vb = bytearray(ref['vb'])
    ab, aux, qd, off = ref['ab'], ref['aux'], ref['qd'], ref['off']
    sect = src['sect']                       # payload end stays unchanged
    struct.pack_into('>Q', vb, qd, sect)     # descriptor image_size
    digest = hashlib.sha256(ref['salt'] + bytes(out[:sect])).digest()
    vb[off + ref['pn'] + ref['sl']:off + ref['pn'] + ref['sl'] + ref['rl']] = digest
    vb[256:288] = hashlib.sha256(bytes(vb[:256]) + bytes(vb[256 + ab:256 + ab + aux])).digest()

    out[src['vo']:src['vo'] + src['vs']] = bytes(src['vs'])   # clear old vbmeta
    out[src['vo']:src['vo'] + len(vb)] = vb
    out[-FOOTER_LEN:] = (b'AVBf' + struct.pack('>IIQQQ', 1, 0,
                                               sect, src['vo'], len(vb)) +
                         bytes(28))

    # ---- 3. self checks ----
    d = bytes(out)
    nh = parse_header(d)
    nf = d[-FOOTER_LEN:]
    nvb = d[src['vo']:src['vo'] + len(vb)]
    L = src['layout']
    checks = [
        ('size == 96 MiB', len(d) == PARTITION),
        ('kernel unchanged', d[L['kernel'][0]:L['kernel'][1]] ==
         src['data'][L['kernel'][0]:L['kernel'][1]]),
        ('ramdisk unchanged', d[L['ramdisk'][0]:L['ramdisk'][1]] ==
         src['data'][L['ramdisk'][0]:L['ramdisk'][1]]),
        ('recovery_dtbo unchanged', d[L['recovery_dtbo'][0]:L['recovery_dtbo'][1]] ==
         src['data'][L['recovery_dtbo'][0]:L['recovery_dtbo'][1]]),
        ('dtb unchanged', d[L['dtb'][0]:L['dtb'][1]] ==
         src['data'][L['dtb'][0]:L['dtb'][1]]),
        ('cmdline == ref', nh['cmdline'] == ref['header']['cmdline']),
        ('os_version == ref', nh['os_version'] == ref['header']['os_version']),
        ('dtb_addr == ref', nh['dtb_addr'] == ref['header']['dtb_addr']),
        ('second_addr == ref', nh['second_addr'] == ref['header']['second_addr']),
        ('vbmeta algorithm == ref', be32(nvb, 0x1C) == ref['alg']),
        ('vbmeta auth/aux == ref', be64(nvb, 0x0C) == ref['ab'] and be64(nvb, 0x14) == ref['aux']),
        ('vbmeta salt == ref', bytes(nvb[off + ref['pn']:off + ref['pn'] + ref['sl']]) == ref['salt']),
        # 256..288 is the necessarily recomputed vbmeta hash; the rest of the
        # auth block (signature + public key) must remain the stock one.
        ('vbmeta auth block == ref (excl. hash)',
         nvb[288:256 + ab] == ref['vb'][288:256 + ab]),
        ('descriptor image_size == section_end', be64(nvb, qd) == sect),
        ('root digest self-consistent',
         bytes(nvb[off + ref['pn'] + ref['sl']:off + ref['pn'] + ref['sl'] + ref['rl']]) ==
         hashlib.sha256(ref['salt'] + d[:sect]).digest()),
        ('vbmeta hash self-consistent',
         bytes(nvb[256:288]) ==
         hashlib.sha256(nvb[:256] + nvb[256 + ab:256 + ab + aux]).digest()),
        ('footer section_end', be64(nf, 0x0C) == sect),
        ('footer vbmeta offset/size', be64(nf, 0x14) == src['vo'] and be64(nf, 0x1C) == len(vb)),
        ('no leftover old vbmeta bytes',
         all(c == 0 for c in d[src['vo'] + len(vb):src['vo'] + src['vs']])),
    ]
    print('\n--- self checks ---')
    for label, ok in checks:
        print('  [%s] %s' % ('OK' if ok else 'FAIL', label))
    if not all(ok for _, ok in checks):
        raise SystemExit('self-check FAILED, refusing to write output')

    open(a.out, 'wb').write(d)
    print('\nwrote %s (%d bytes)' % (a.out, len(d)))
    print('sha256 = %s' % hashlib.sha256(d).hexdigest())
    print('AVB now: algorithm=%d auth=%d aux=%d size=%d salt=%s' %
          (ref['alg'], ref['ab'], ref['aux'], len(vb), ref['salt'][:8].hex()))


if __name__ == '__main__':
    main()
