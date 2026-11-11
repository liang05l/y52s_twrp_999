#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
精确移植：从 y52s_recovery999.img 只搬「解密用户 999」所需的东西，
其余全部保留 y52s_twrp-ported.img 已真机验证的功能。

供体实测 = OrangeFox 骨架 + 打了 `y52s:` 补丁的 TWRP 二进制。
999 解密依赖四层：
  A. 补丁 ELF      : system/bin/recovery, system/lib64/libtar.so,
                     system/bin/fscryptpolicyget
  B. 新增运行库    : system/kslib/* 共 10 个（Android 10 keystore daemon 需要）
  C. 新增脚本      : system/bin/y52s_ks_prep.sh（等待 /data 挂载后重建 tmpfs
                     keystore 副本并重启 daemon）、sbin/y52s_prepare.sh
  D. rc 行级配置   : LD_LIBRARY_PATH 补 /vendor/lib64、5 个 HAL service 的
                     setenv、keystore service 改指向 /tmp/misc/keystore 且
                     加载 /system/kslib、新增 y52s_ks_prep service 与触发

明确不搬（会破坏既有功能）：
  prop.default（供体 model=V2057A / sdk=29）、system/etc/recovery.fstab
  （OrangeFox 格式，与 TWRP 语法不同）、init.recovery.platform.rc、
  system/etc/init/hw/init.rc、twres/* 主题、system/etc/* 2869 个 OFX 资源、
  sbin/decrypt（OFX fox 命令）、vts_app_recovery（已换 y52s 原厂）、
  触控固件、TEE trustlet、fastbootd 及其库、供体的 kernel/dtbo/dtb/header。
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
from graft_user999 import load_image, sha, is_elf               # noqa: E402

PAGE = 0x800
PARTITION = 0x6000000

ELF_REPLACE = [
    'system/bin/recovery',
    'system/lib64/libtar.so',
    'system/bin/fscryptpolicyget',
]
ADD_FILES = [
    'system/kslib/android.system.wifi.keystore@1.0.so',
    'system/kslib/libkeystore-engine.so',
    'system/kslib/libkeystore_aidl.so',
    'system/kslib/libkeystore_binder.so',
    'system/kslib/libkeystore_parcelables.so',
    'system/kslib/libprotobuf-cpp-lite.so',
    'system/kslib/libwifikeystorehal.so',
    'system/kslib/libwifikeystorehalext.so',
    'system/kslib/vendor.vivo.hardware.wifi.keystore@1.0.so',
    'system/bin/y52s_ks_prep.sh',
    'sbin/y52s_prepare.sh',
] + []  # 10th kslib entry is filled dynamically below (see main)

HAL_SERVICES = [
    'mobicore',
    'vendor.keymaster-4-0-trustonic',
    'gatekeeper-1-0',
    'wait_for_keymaster',
    'guardianangle',
]
LD_HAL = '    setenv LD_LIBRARY_PATH /system/lib64:/vendor/lib64:/vendor/lib64/hw'
LD_KS = '    setenv LD_LIBRARY_PATH /system/kslib:/system/lib64:/vendor/lib64:/vendor/lib64/hw'


def rep_exact(text, old, new, label):
    n = text.count(old)
    if n != 1:
        raise SystemExit('rc 补丁锚点异常 [%s]: 期望 1 处，实际 %d 处' % (label, n))
    return text.replace(old, new, 1)


def service_block_end(lines, start):
    """返回 service 块结束下标（下一个顶格 service/on 或文件末尾）。"""
    i = start + 1
    while i < len(lines):
        s = lines[i]
        if s and not s[0].isspace() and (s.startswith('service ') or
                                         s.startswith('on ')):
            break
        i += 1
    return i


def add_setenv(lines, name):
    starts = [i for i, l in enumerate(lines) if l.startswith('service ' + name + ' ')]
    if len(starts) != 1:
        raise SystemExit('service 定位异常 [%s]: %d 处' % (name, len(starts)))
    end = service_block_end(lines, starts[0])
    # 去掉块尾空行，插在最后一个有效行之后
    while end - 1 > starts[0] and not lines[end - 1].strip():
        end -= 1
    if any('setenv LD_LIBRARY_PATH' in l for l in lines[starts[0]:end]):
        return lines  # 已有则不重复
    lines.insert(end, LD_HAL)
    return lines


def patch_rc(base_rc, donor_rc):
    t = base_rc.decode('utf-8')
    d = donor_rc.decode('utf-8') if donor_rc else ''

    # D1. on init 补 /vendor/lib64（供体 rc 注释实测：缺了 HAL 会 status 1 退出）
    t = rep_exact(t,
                  'on init\n    # 使用 configfs USB 模式',
                  'on init\n'
                  '    # ---- y52s user999 graft: keymaster/gatekeeper HAL 需要 /vendor/lib64 ----\n'
                  '    export LD_LIBRARY_PATH /system/lib64:/vendor/lib64:/vendor/lib64/hw\n'
                  '    # 使用 configfs USB 模式',
                  'on init / export LD_LIBRARY_PATH')

    # D2. 五个 HAL service 补 setenv
    lines = t.split('\n')
    for s in HAL_SERVICES:
        lines = add_setenv(lines, s)
    t = '\n'.join(lines)

    # D3. keystore service 改指向 tmpfs 副本并加载 kslib
    old_ks = ('service keystore /system/bin/keystore /data/misc/keystore\n'
              '    disabled\n'
              '    user root\n'
              '    group root drmrpc readproc\n'
              '    seclabel u:r:recovery:s0')
    new_ks = ('service keystore /system/bin/keystore /tmp/misc/keystore\n'
              '    disabled\n' + LD_KS + '\n'
              '    user root\n'
              '    group root drmrpc readproc\n'
              '    seclabel u:r:recovery:s0')
    t = rep_exact(t, old_ks, new_ks, 'service keystore')

    # D4. 新增 y52s_ks_prep service（插在 keystore_auth 块之后）
    anchor = ('service keystore_auth /system/bin/keystore_auth\n'
              '    disabled\n'
              '    user system\n'
              '    group root system\n'
              '    seclabel u:r:recovery:s0')
    prep = (anchor + '\n\n'
            '# ---- y52s user999 graft: 等 /data 挂载后重建 tmpfs keystore 副本 ----\n'
            'service y52s_ks_prep /system/bin/y52s_ks_prep.sh\n'
            '    class core\n'
            '    disabled\n'
            '    oneshot\n'
            '    user root\n'
            '    seclabel u:r:recovery:s0')
    t = rep_exact(t, anchor, prep, 'service y52s_ks_prep')

    # D5. recovery.service=1 段：保留原有的 start keystore，只在 guardianangle
    # 之后追加 prep 触发。
    #
    # 说明（重要）：v2 曾把这段按供体重排、删掉 start keystore，理由是
    # 「提前起 daemon 会拿到空库、引发挂载失败」。这是仅凭 rc 差异做的推断，
    # 已被真机 recovery.log 推翻（挂载失败的分区是 /vendor、/system_root、
    # /persist，与 /data、keystore 无关），因此这里回退到 v1 行为——
    # v1 保留 start keystore，999 解密实测成功。
    t = rep_exact(t,
                  '    start guardianangle',
                  '    start guardianangle\n'
                  '    # ---- y52s user999 graft: 等 /data 就绪，重建 tmpfs keystore 副本后重启 daemon ----\n'
                  '    chmod 0755 /system/bin/y52s_ks_prep.sh\n'
                  '    start y52s_ks_prep',
                  'recovery.service 触发')

    # 供体独有的 MTP configfs 段不搬 —— 我们的 MTP 已可用，避免动作冲突。
    # 供体的触控权限块缺失，我们的保留（下面自检验证）。
    return t.encode('utf-8')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--donor', default='y52s_recovery999.img')
    ap.add_argument('--donor-dir', default=None,
                    help='从目录读取 999 组件（CI 用），需含 manifest.json')
    ap.add_argument('--base', default='y52s_twrp-ported.img')
    ap.add_argument('--out', default='y52s_twrp-ported-user999.img')
    a = ap.parse_args()

    def P(p):
        return p if os.path.isabs(p) else os.path.join(ROOT, p)
    bd, bh, blay, bcpio, bentries, _ = load_image(P(a.base))
    if a.donor_dir:
        ddir = P(a.donor_dir)
        man = json.load(open(os.path.join(ddir, 'manifest.json'), encoding='utf-8'))
        dentries = []
        for name, meta in man.items():
            is_dir = (meta['vals'].get('mode', 0) & 0o170000) == 0o040000
            fp = os.path.join(ddir, name.replace('/', os.sep))
            if is_dir:
                blob = b''
            else:
                if not os.path.isfile(fp):
                    raise SystemExit('缺少 999 组件: ' + fp)
                blob = open(fp, 'rb').read()
            dentries.append({'name': name, 'blob': blob,
                             'vals': dict(meta['vals']),
                             'offset': 0, 'magic': '070701'})
    else:
        dd, dh, dlay, dcpio, dentries, _ = load_image(P(a.donor))
    BE = {e['name']: e for e in bentries}
    DE = {e['name']: e for e in dentries}

    # 动态补全 kslib 清单（供体里所有 system/kslib/* 都搬）
    adds = sorted({n for n in DE if n.startswith('system/kslib/')} |
                  {'system/kslib',                       # 目录条目，供体有、v1 漏搬
                   'system/bin/y52s_ks_prep.sh',
                   'sbin/y52s_prepare.sh'})
    missing = [n for n in ELF_REPLACE + adds if n not in DE]
    if missing:
        raise SystemExit('供体缺少必要条目: ' + str(missing))
    for n in ELF_REPLACE:
        if not is_elf(DE[n]['blob']):
            raise SystemExit('替换项不是 ELF: ' + n)

    print('基准 %s (%d 条目) / 供体 %s (%d 条目)' %
          (a.base, len(bentries), a.donor, len(dentries)))
    print('替换 ELF %d 项，新增文件 %d 项，rc 行级补丁 5 处' %
          (len(ELF_REPLACE), len(adds)))

    entries = bentries
    EM = {e['name']: e for e in entries}
    for n in ELF_REPLACE:
        EM[n]['blob'] = DE[n]['blob']

    # rc 精确补丁
    EM['init.recovery.mt6853.rc']['blob'] = patch_rc(
        BE['init.recovery.mt6853.rc']['blob'],
        DE['init.recovery.mt6853.rc']['blob'] if 'init.recovery.mt6853.rc' in DE else b'')

    # 新增条目
    ti = next(i for i, e in enumerate(entries) if e['name'] == 'TRAILER!!!')
    maxino = max(e['vals']['ino'] for e in entries)
    for i, n in enumerate(adds):
        if n in EM:
            EM[n]['blob'] = DE[n]['blob']
            continue
        src = DE[n]
        ne = dict(src)
        ne['vals'] = dict(src['vals'])
        ne['vals']['ino'] = maxino + 1 + i
        entries.insert(ti + i, ne)
        EM[n] = ne

    # 清单：基线若有 TWRP 的 ramdisk-files.* 就同步刷新，没有则跳过（源码新构建可能不带）
    if 'ramdisk-files.txt' in BE and 'ramdisk-files.sha256sum' in BE:
        txt_lines = BE['ramdisk-files.txt']['blob'].decode().splitlines()
        for n in adds:
            if n not in txt_lines:
                txt_lines.append(n)
        txt_blob = ('\n'.join(txt_lines) + '\n').encode()
        EM['ramdisk-files.txt']['blob'] = txt_blob
        old_sha = BE['ramdisk-files.sha256sum']['blob'].decode().splitlines()
        new_sha, seen = [], set()
        for line in old_sha:
            if '  ./' not in line:
                continue
            _old, n = line.split('  ./', 1)
            if n not in EM or n == 'ramdisk-files.sha256sum':
                continue
            blob = txt_blob if n == 'ramdisk-files.txt' else EM[n]['blob']
            new_sha.append(sha(blob) + '  ./' + n)
            seen.add(n)
        for n in adds:
            if n not in seen and EM[n]['blob']:      # 目录条目不进 sha 清单
                new_sha.append(sha(EM[n]['blob']) + '  ./' + n)
        EM['ramdisk-files.sha256sum']['blob'] = ('\n'.join(new_sha) + '\n').encode()

    out_cpio = write_cpio(entries)
    out_cpio += b'\0' * ((256 - len(out_cpio) % 256) % 256)
    gz = gzip.compress(out_cpio, compresslevel=6, mtime=0)
    print('新 ramdisk: cpio %d, gzip %d, %d 条目' %
          (len(out_cpio), len(gz), len(entries)))

    # ---- boot image：kernel/dtbo/dtb/header 全沿用基准 ----
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
    E2 = {e['name']: e['blob'] for e in
          read_cpio(gzip.decompress(d[l2['ramdisk'][0]:l2['ramdisk'][1]]))}
    rc = E2['init.recovery.mt6853.rc'].decode('utf-8')
    checks = []
    for n in ELF_REPLACE + adds:
        checks.append(('来自供体: ' + n, E2.get(n) == DE[n]['blob']))
    checks.append(('kernel/dtbo/dtb 未变',
                   all(d[l2[k][0]:l2[k][1]] == bd[blay[k][0]:blay[k][1]]
                       for k in ('kernel', 'recovery_dtbo', 'dtb'))))
    checks.append(('props 仍 PD2057 且未被 V2057A 覆盖',
                   b'ro.product.system.model=PD2057' in E2['prop.default'] and
                   b'V2057A' not in E2['prop.default'] and
                   b'PD2031' not in E2['prop.default']))
    checks.append(('recovery.fstab 保持 TWRP 格式',
                   b'flags=display=data' in E2['system/etc/recovery.fstab']))
    checks.append(('7 个 PD2057 触控固件 + y52s vts_app_recovery 保留',
                   sum(1 for n in E2 if n.startswith('vendor/firmware/TP-')
                       and 'PD2057' in n) == 7 and
                   E2['system/bin/vts_app_recovery'] ==
                   BE['system/bin/vts_app_recovery']['blob']))
    checks.append(('触控 sysfs 权限块保留', 'vivo_ts' in rc and
                   'vts_app_recovery --update' in rc))
    checks.append(('rc: LD_LIBRARY_PATH 补 /vendor/lib64',
                   'export LD_LIBRARY_PATH /system/lib64:/vendor/lib64:/vendor/lib64/hw'
                   in rc))
    checks.append(('rc: 5 个 HAL service 均加 setenv',
                   rc.count('setenv LD_LIBRARY_PATH /system/lib64:/vendor/lib64:/vendor/lib64/hw') >= 5))
    checks.append(('rc: keystore 指向 tmpfs 且加载 kslib',
                   'service keystore /system/bin/keystore /tmp/misc/keystore' in rc and
                   LD_KS.strip() in rc))
    checks.append(('rc: y52s_ks_prep 已定义并触发',
                   'service y52s_ks_prep /system/bin/y52s_ks_prep.sh' in rc and
                   'start y52s_ks_prep' in rc))
    rc_lines = [l.strip() for l in rc.split('\n')]
    checks.append(('rc: 保留原有 start keystore（已回退 v2 的误判改动）',
                   rc_lines.count('start keystore') == 1))
    checks.append(('rc: guardianangle 仍在且 prep 排在其后',
                   rc_lines.count('start guardianangle') == 1 and
                   rc_lines.index('start y52s_ks_prep') >
                   rc_lines.index('start guardianangle')))
    checks.append(('system/kslib 目录条目已补齐', 'system/kslib' in E2))
    checks.append(('fastbootd 等 only-base 条目保留',
                   all(n in E2 and E2[n] == BE[n]['blob'] for n in
                       ['system/bin/fastbootd',
                        'system/lib64/android.hardware.fastboot@1.1.so'])))
    checks.append(('AVB 长度/摘要自洽',
                   struct.unpack_from('>Q', d[-64:], 0x0C)[0] == section_end and
                   vb[off + pn + sl:off + pn + sl + rl] ==
                   hashlib.sha256(salt + d[:section_end]).digest()))
    allowed = set(ELF_REPLACE) | set(adds) | {
        'init.recovery.mt6853.rc', 'ramdisk-files.txt',
        'ramdisk-files.sha256sum'}
    unexpected = [n for n in BE if n not in allowed and E2.get(n) != BE[n]['blob']]
    checks.append(('非计划条目零改动', not unexpected))

    for label, ok in checks:
        print('  [%s] %s' % ('OK' if ok else 'FAIL', label))
    if not all(ok for _, ok in checks):
        if unexpected:
            print('  非预期改动:', unexpected[:20])
        raise SystemExit('自检失败')

    report = dict(output=os.path.basename(out_path), size=len(d),
                  sha256=sha(d), section_end=hex(section_end),
                  replaced=ELF_REPLACE, added=adds,
                  rc_patches=['on init export LD_LIBRARY_PATH',
                              '5 HAL services setenv',
                              'keystore -> /tmp/misc/keystore + kslib',
                              'service y52s_ks_prep',
                              'recovery.service=1 末尾追加 prep 触发'
                              '（保留原有 start keystore）'],
                  preserved=['kernel', 'recovery_dtbo', 'dtb', 'boot header',
                             'prop.default (PD2057)', 'recovery.fstab (TWRP)',
                             'touch perms + 7 PD2057 firmwares',
                             'vts_app_recovery', 'twres theme', 'fastbootd',
                             'TEE trustlets', 'MTP/ADB configfs'],
                  checks={k: bool(v) for k, v in checks})
    os.makedirs(os.path.join(ROOT, 'work', 'out'), exist_ok=True)
    json.dump(report, open(os.path.join(ROOT, 'work', 'out', 'graft_999_result.json'),
                           'w', encoding='utf-8'), indent=2, ensure_ascii=False)
    print('全部自检通过。新镜像 sha256 =', sha(d))


if __name__ == '__main__':
    main()
