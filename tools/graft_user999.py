#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从「能解密用户 999 的同机型 TWRP」把解密补丁移植到我们已验证的 y52s TWRP。

设计原则：最小侵入。
  只替换 ramdisk 里「同名、内容不同、且是 ELF」的解密相关二进制。
  以下内容一律保持基准镜像不动（它们都已真机验证过）：
    * kernel / recovery_dtbo / dtb / boot header
    * prop.default / build.prop / init.recovery.*.rc / fstab / twres XML
    * 7 个 PD2057 触控固件与 vts_app_recovery（除非显式 --include）
    * TEE trustlet（.tlbin/.drbin/.tabin，已排除为 999 失败的变量）
  最后重算清单 SHA256、重建 cpio/gzip、重算 AVB 摘要与 footer。

用法：
  # 先看差异与移植计划，不生成镜像
  python port_tools/graft_user999.py --donor <能解999的TWRP.img> --plan-only

  # 正式移植（默认 crypto 模式）
  python port_tools/graft_user999.py --donor <能解999的TWRP.img> \
      --out y52s_twrp-ported-user999.img

  # 把所有同名 ELF 差异都搬过来（含触控等非解密二进制，谨慎）
  python port_tools/graft_user999.py --donor X.img --mode all-elf --out Y.img

  # 整个 ramdisk 换成供体的（仅当供体本身是完整 y52s TWRP 时用）
  python port_tools/graft_user999.py --donor X.img --mode full-ramdisk --out Y.img

  --include NAME / --exclude NAME 可重复，用于微调计划。
"""
import os
import sys
import gzip
import json
import struct
import hashlib
import argparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from bootimg import parse_header, layout, build_header, align  # noqa: E402
from cpio import read_cpio, write_cpio                          # noqa: E402

PAGE = 0x800
PARTITION = 0x6000000

# 解密链路相关 ELF。优先精确名，其次路径关键词；只有 ELF 会被选中。
CRYPTO_EXACT = {
    'system/bin/recovery', 'system/bin/twrp',
    'system/bin/keystore', 'system/bin/keystore2', 'system/bin/keystore_cli_v2',
    'system/bin/vivofbe', 'system/bin/vivotool',
    'system/bin/guardianangle', 'system/bin/wait_for_keymaster',
    'system/bin/fscryptpolicyget', 'system/bin/ozip_decrypt',
    'system/lib64/libvivofscrypt.so', 'system/lib64/libvivogatekeeper.so',
    'system/lib64/libfscrypttwrp.so', 'system/lib64/libfscrypt.so',
    'system/lib64/libkeymaster4.so', 'system/lib64/libkeymaster4_1support.so',
    'system/lib64/libkeymaster4support.so', 'system/lib64/libkeymaster_messages.so',
    'system/lib64/libkeymaster_portable.so',
    'system/lib64/libgatekeeper.so', 'system/lib64/libgatekeeper_aidl.so',
    'system/lib64/libsoftkeymasterdevice.so',
    'system/lib64/libpuresoftkeymasterdevice.so',
    'system/lib64/android.hardware.keymaster@3.0.so',
    'system/lib64/android.hardware.keymaster@4.0.so',
    'system/lib64/android.hardware.keymaster@4.1.so',
    'system/lib64/android.hardware.gatekeeper@1.0.so',
    'vendor/bin/hw/android.hardware.keymaster@4.0-service.trustonic',
    'vendor/bin/android.hardware.gatekeeper@1.0-service',
    'vendor/lib64/hw/libMcGatekeeper.so',
    'vendor/lib64/hw/android.hardware.gatekeeper@1.0-impl.so',
    'vendor/lib64/libkeymaster4.so',
}
CRYPTO_HINTS = ('keymaster', 'gatekeeper', 'keystore', 'fscrypt',
                'vivofbe', 'vivotool', 'guardianangle', 'spblob')

# 明确不自动搬（即使命中 all-elf），除非用户 --include
PROTECTED = {
    'system/bin/vts_app_recovery',       # 已换成 y52s 原厂，触控固件配套
    'system/bin/adbd', 'system/bin/fastbootd',
    'system/bin/init', 'system/bin/charger',
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def is_elf(b):
    return b[:4] == b'\x7fELF'


def decompress_ramdisk(raw):
    if raw.startswith(b'\x1f\x8b'):
        return gzip.decompress(raw), 'gzip'
    if raw.startswith(b'\x04\x22\x4d\x18'):       # LZ4 frame
        import lz4.frame
        return lz4.frame.decompress(raw), 'lz4_frame'
    if raw.startswith(b'\x02\x21\x4c\x18'):       # LZ4 legacy
        raise SystemExit('供体 ramdisk 是 LZ4 legacy 格式；请先转成 gzip，'
                         '或安装 lz4 CLI 后转换。本工具支持 gzip 与 LZ4 frame。')
    if raw.startswith(b'070701') or raw.startswith(b'070702'):
        return raw, 'raw_cpio'
    raise SystemExit('无法识别供体 ramdisk 压缩格式: ' + raw[:16].hex())


def load_image(path):
    d = open(path, 'rb').read()
    h = parse_header(d)
    if h['header_version'] > 2:
        print('  [警告] 供体 header v%d，本工具按 v2 布局解析；'
              '若解包异常请检查。' % h['header_version'])
    lay = layout(h, len(d))
    cpio, fmt = decompress_ramdisk(d[lay['ramdisk'][0]:lay['ramdisk'][1]])
    entries = read_cpio(cpio)
    return d, h, lay, cpio, entries, fmt


def crypto_match(name):
    return name in CRYPTO_EXACT or any(k in name.lower() for k in CRYPTO_HINTS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--donor', required=True, help='能解密 999 的同机型 TWRP 镜像')
    ap.add_argument('--base', default='y52s_twrp-ported.img')
    ap.add_argument('--out', default='y52s_twrp-ported-user999.img')
    ap.add_argument('--mode', choices=('crypto', 'all-elf', 'full-ramdisk'),
                    default='crypto')
    ap.add_argument('--include', action='append', default=[])
    ap.add_argument('--exclude', action='append', default=[])
    ap.add_argument('--plan-only', action='store_true')
    ap.add_argument('--allow-protected', action='store_true',
                    help='允许 all-elf 模式覆盖 PROTECTED 列表里的条目')
    a = ap.parse_args()

    def P(p):
        return p if os.path.isabs(p) else os.path.join(ROOT, p)

    donor_path, base_path = P(a.donor), P(a.base)
    if not os.path.isfile(donor_path):
        ap.error('找不到供体镜像: ' + donor_path)
    if not os.path.isfile(base_path):
        ap.error('找不到基准镜像: ' + base_path)

    bd, bh, blay, bcpio, bentries, bfmt = load_image(base_path)
    dd, dh, dlay, dcpio, dentries, dfmt = load_image(donor_path)
    BE = {e['name']: e for e in bentries}
    DE = {e['name']: e for e in dentries}
    print('基准 %-40s ramdisk %-10s %d 条目 (v%d)' %
          (os.path.basename(base_path), bfmt, len(bentries), bh['header_version']))
    print('供体 %-40s ramdisk %-10s %d 条目 (v%d)' %
          (os.path.basename(donor_path), dfmt, len(dentries), dh['header_version']))

    only_base = sorted(set(BE) - set(DE))
    only_donor = sorted(set(DE) - set(BE))
    changed = sorted(n for n in set(BE) & set(DE) if BE[n]['blob'] != DE[n]['blob'])
    elf_changed = [n for n in changed
                   if is_elf(BE[n]['blob']) and is_elf(DE[n]['blob'])]

    diff = dict(only_base=only_base, only_donor=only_donor,
                changed=changed, elf_changed=elf_changed,
                only_donor_elf=[n for n in only_donor if is_elf(DE[n]['blob'])])
    os.makedirs(os.path.join(ROOT, 'work', 'out'), exist_ok=True)
    json.dump(diff, open(os.path.join(ROOT, 'work', 'out', 'graft_diff.json'),
                         'w', encoding='utf-8'), indent=2, ensure_ascii=False)
    print('差异: 仅基准 %d / 仅供体 %d / 同名不同 %d (其中 ELF %d)' %
          (len(only_base), len(only_donor), len(changed), len(elf_changed)))

    # ---- 选择替换项 ----
    if a.mode == 'full-ramdisk':
        selected = []          # 特殊处理：整体替换
        print('[full-ramdisk] 整个 ramdisk 将被供体替换（触控/props 适配会丢失）')
    elif a.mode == 'all-elf':
        skipped = [] if a.allow_protected else PROTECTED
        selected = [n for n in elf_changed if n not in skipped]
    else:
        selected = [n for n in elf_changed if crypto_match(n)]
        # 供体新增的解密 ELF 也接进来（新补丁可能带新 .so）
        for n in diff['only_donor_elf']:
            if crypto_match(n):
                selected.append(n)
    selected = [n for n in selected if n not in a.exclude]
    selected += [n for n in a.include if n in DE and n not in selected]
    selected = sorted(set(selected))

    plan = []
    for n in selected:
        plan.append(dict(name=n,
                         action='replace' if n in BE else 'add',
                         is_elf=is_elf(DE[n]['blob']),
                         base_size=len(BE[n]['blob']) if n in BE else None,
                         donor_size=len(DE[n]['blob']),
                         base_sha=sha(BE[n]['blob']) if n in BE else None,
                         donor_sha=sha(DE[n]['blob'])))
    json.dump(dict(mode=a.mode, donor=os.path.basename(donor_path),
                   base=os.path.basename(base_path), plan=plan),
              open(os.path.join(ROOT, 'work', 'out', 'graft_plan.json'),
                   'w', encoding='utf-8'), indent=2, ensure_ascii=False)
    print('计划 %d 项：' % len(plan))
    for x in plan:
        print('   %-7s %-64s %s -> %s' %
              (x['action'], x['name'], x['base_size'], x['donor_size']))
    if not plan and a.mode != 'full-ramdisk':
        print('没有需要移植的条目：供体与基准的解密二进制完全一致。')
        print('（若确认补丁在别的路径，用 --include NAME 或 --mode all-elf）')
        return
    if a.plan_only:
        print('--plan-only：已写出计划，未生成镜像。')
        return

    # ---- 组装 ramdisk ----
    if a.mode == 'full-ramdisk':
        entries = dentries
    else:
        entries = bentries
        BE2 = {e['name']: e for e in entries}
        for n in selected:
            if n in BE2:
                BE2[n]['blob'] = DE[n]['blob']
            else:
                # 新增条目：复制供体元数据，插到 TRAILER!!! 之前
                src = DE[n]
                ne = dict(src)
                ne['vals'] = dict(src['vals'])
                ti = next(i for i, e in enumerate(entries)
                          if e['name'] == 'TRAILER!!!')
                entries.insert(ti, ne)

    EM = {e['name']: e for e in entries}
    added = [x['name'] for x in plan if x['action'] == 'add']
    if a.mode == 'full-ramdisk':
        # 整体换 ramdisk：两份清单按供体条目全新生成
        txt_blob = ('\n'.join(e['name'] for e in entries) + '\n').encode()
        EM['ramdisk-files.txt']['blob'] = txt_blob
        lines = []
        for e in entries:
            n = e['name']
            if not e['blob'] or n in ('ramdisk-files.sha256sum', 'TRAILER!!!'):
                continue
            blob = txt_blob if n == 'ramdisk-files.txt' else e['blob']
            lines.append(sha(blob) + '  ./' + n)
    else:
        # 最小侵入：沿用基准清单的行集合，只刷新被改条目的哈希
        txt_lines = EM['ramdisk-files.txt']['blob'].decode().splitlines()
        for n in added:
            if n not in txt_lines:
                txt_lines.append(n)
        txt_blob = ('\n'.join(txt_lines) + '\n').encode()
        EM['ramdisk-files.txt']['blob'] = txt_blob
        old = EM['ramdisk-files.sha256sum']['blob'].decode().splitlines()
        lines, seen = [], set()
        for line in old:
            if '  ./' not in line:
                continue
            _old, n = line.split('  ./', 1)
            if n not in EM or n == 'ramdisk-files.sha256sum':
                continue
            blob = txt_blob if n == 'ramdisk-files.txt' else EM[n]['blob']
            lines.append(sha(blob) + '  ./' + n)
            seen.add(n)
        for n in added:
            if n not in seen and EM[n]['blob']:
                lines.append(sha(EM[n]['blob']) + '  ./' + n)
    EM['ramdisk-files.sha256sum']['blob'] = ('\n'.join(lines) + '\n').encode()

    out_cpio = write_cpio(entries)
    out_cpio += b'\0' * ((256 - len(out_cpio) % 256) % 256)
    gz = gzip.compress(out_cpio, compresslevel=6, mtime=0)
    print('新 ramdisk: cpio %d, gzip %d, %d 条目' %
          (len(out_cpio), len(gz), len(entries)))

    # ---- boot image（kernel/dtbo/dtb 沿用基准）----
    parts = [
        ('kernel', bd[blay['kernel'][0]:blay['kernel'][1]]),
        ('ramdisk', gz),
        ('recovery_dtbo', bd[blay['recovery_dtbo'][0]:blay['recovery_dtbo'][1]]),
        ('dtb', bd[blay['dtb'][0]:blay['dtb'][1]]),
    ]
    nh = dict(bh)
    nh.pop('_header_raw', None)
    nh['kernel_size'] = len(parts[0][1])
    nh['ramdisk_size'] = len(parts[1][1])
    nh['second_size'] = 0
    nh['recovery_dtbo_size'] = len(parts[2][1])
    nh['dtb_size'] = len(parts[3][1])
    nh['recovery_dtbo_offset'] = 0
    out = bytearray(build_header(nh))
    cursor = PAGE
    for k, blob in parts:
        cursor = align(cursor, PAGE)
        if k == 'recovery_dtbo':
            nh['recovery_dtbo_offset'] = cursor
        out.extend(b'\0' * (cursor - len(out)))
        out.extend(blob)
        cursor += len(blob)
    section_end = align(cursor, PAGE)
    out[:0x800] = build_header(nh)
    out.extend(b'\0' * (section_end - len(out)))

    # ---- AVB ----
    f = bd[-64:]
    vo = struct.unpack_from('>Q', f, 0x14)[0]
    vs = struct.unpack_from('>Q', f, 0x1C)[0]
    vb = bytearray(bd[vo:vo + vs])
    ab = struct.unpack_from('>Q', vb, 0x0C)[0]
    auxsz = struct.unpack_from('>Q', vb, 0x14)[0]
    q = 256 + ab + 16
    if struct.unpack_from('>Q', vb, 256 + ab)[0] != 2:
        raise SystemExit('vbmeta 首个描述符不是 hash descriptor')
    pn, sl, rl, _ = struct.unpack_from('>IIII', vb, q + 40)
    off = q + 116
    salt = bytes(vb[off + pn:off + pn + sl])
    struct.pack_into('>Q', vb, q, section_end)
    vb[off + pn + sl:off + pn + sl + rl] = hashlib.sha256(
        salt + bytes(out[:section_end])).digest()
    vb[256:256 + 32] = hashlib.sha256(
        bytes(vb[:256]) + bytes(vb[256 + ab:256 + ab + auxsz])).digest()
    vbmeta_offset = align(section_end + 1, PAGE)
    out.extend(b'\0' * (vbmeta_offset - len(out)))
    out.extend(vb)
    out.extend(b'\0' * (PARTITION - len(out)))
    out[-64:] = (b'AVBf' + struct.pack('>IIQQQ', 1, 0, section_end,
                                      vbmeta_offset, vs) + bytes(28))
    out_path = P(a.out)
    open(out_path, 'wb').write(out)
    print('输出 %s (%d bytes), section_end 0x%X' %
          (out_path, len(out), section_end))

    # ---- 自检 ----
    d = open(out_path, 'rb').read()
    l2 = layout(parse_header(d), len(d))
    c2 = gzip.decompress(d[l2['ramdisk'][0]:l2['ramdisk'][1]])
    E2 = {e['name']: e['blob'] for e in read_cpio(c2)}
    checks = []
    for n in selected:
        checks.append((n + ' 已来自供体', E2.get(n) == DE[n]['blob']))
    checks.append(('kernel/dtbo/dtb 未变',
                   all(d[l2[k][0]:l2[k][1]] == bd[blay[k][0]:blay[k][1]]
                       for k in ('kernel', 'recovery_dtbo', 'dtb'))))
    checks.append(('props 仍为 PD2057',
                   b'PD2057' in E2.get('prop.default', b'') and
                   b'PD2031' not in E2.get('prop.default', b'')))
    checks.append(('7 个 PD2057 触控固件仍在',
                   sum(1 for n in E2 if n.startswith('vendor/firmware/TP-')
                       and 'PD2057' in n) == 7))
    checks.append(('AVB 长度/摘要自洽',
                   struct.unpack_from('>Q', d[-64:], 0x0C)[0] == section_end and
                   vb[off + pn + sl:off + pn + sl + rl] ==
                   hashlib.sha256(salt + d[:section_end]).digest()))
    # 非选中条目应与基准一致
    unexpected = [n for n in BE if n not in selected
                  and n not in ('ramdisk-files.txt', 'ramdisk-files.sha256sum')
                  and E2.get(n) != BE[n]['blob']]
    if a.mode != 'full-ramdisk':
        checks.append(('非选中条目零改动', not unexpected))
    for label, ok in checks:
        print('  [%s] %s' % ('OK' if ok else 'FAIL', label))
    if not all(ok for _, ok in checks):
        if unexpected:
            print('  非预期改动:', unexpected[:20])
        raise SystemExit('自检失败')
    print('全部自检通过。新镜像 sha256 =', sha(d))


if __name__ == '__main__':
    main()
