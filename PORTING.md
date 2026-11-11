# vivo Y52s (PD2057) TWRP 源码树 — 从 PD2031 移植

基于 [liang05l/android_device_vivo_pd2031](https://github.com/liang05l/android_device_vivo_pd2031)（y73s 设备树，TWRP 12.1），
改成 y52s 可用，并把「解密用户 999」的能力接进构建流程，用 GitHub Actions 出镜像。

> 本仓库是**覆盖层（overlay）**，不是完整设备树。
> CI 会先 `git clone` 上游的完整设备树（拿到 kernel/mcRegistry/avb footer 等大文件），
> 再把本仓库的文件覆盖上去。所以你 push 的体积只有 22 MB。

---

## 1. 你现在需要做什么（3 步）

**方式 A：直接用本仓库（覆盖层，CI 自带 clone 上游）**

```bash
# 1) 在 GitHub 建一个空仓库，比如 y52s-twrp
cd y52s-src
git init -b main
git add -A
git commit -m "vivo Y52s (PD2057) TWRP: device tree overlay + CI + user999"
git remote add origin https://github.com/<你的用户名>/y52s-twrp.git
git push -u origin main
```

2) 仓库页面 → **Actions** → 左侧 `Build TWRP for vivo Y52s (PD2057)` → **Run workflow**。
3) 跑完（约 1.5~3 小时，2 核 runner）后在 run 页面下载 artifact `twrp-y52s-pd2057`，
   里面是 `recovery.img`（可直接刷）和 `recovery.img.source-only`（不含 999 的纯源码版，用于对比）。

**方式 B：fork 上游仓库，再把这个补丁打上去**

上游 `liang05l/android_device_vivo_pd2031` 是 `4accccc/android_device_vivo_pd2031` 的 fork，
两者同一 commit（`2d26aff8`），**只有一个分支 `twrp-12.1`**。想以它为基准，做法是：

```bash
git clone -b twrp-12.1 https://github.com/liang05l/android_device_vivo_pd2031.git
cd android_device_vivo_pd2031
git apply /path/to/y52s-src/patches_y52s/0001-y52s-pd2057-config.patch   # 132 行，只改 3 个 mk
# 再把 y52s-src/device/vivo/k6853v1_64_6360/ 下的二进制覆盖进来：
#   prebuilt/{kernel,dtb.img,dtbo.img}、recovery/root/vendor/firmware/*PD2057*、vivo_avb_footer.bin
```

`0001` 补丁已用 `git apply --check` 在干净的上游文件上验证过，可原样应用。


首次跑之前建议先读第 4 节的「已知风险」。

---

## 2. 相对 y73s 树，改了哪些（逐项有据）

| 项 | y73s (PD2031) | y52s (PD2057) | 依据 |
|---|---|---|---|
| `BOARD_KERNEL_CMDLINE` 的 `product.version` | `PD2031_A_5.12.1` | **`PD2057_A_1.16.4`** | 逐字节取自 `y52s_recovery.bin` 的 boot header 第 64..576 字节 |
| boot header 追加 | `androidboot.selinux=permissive buildvariant=eng` | 同（TWRP 必需） | 移植镜像实机可启动 |
| `PRODUCT_MODEL` / `FOX_DEVICE_MODEL` | `PD2031` | **`PD2057`** | `ro.vendor.product.model=PD2057` |
| `BUILD_FINGERPRINT` | `vivo/PD2031/PD2031:10/QP1A.190711.020/compiler10052108:user/release-keys` | **`vivo/PD2057/PD2057:10/QP1A.190711.020/compiler04181705:user/release-keys`** | y52s 原厂 `system/etc/ramdisk/build.prop` |
| `PLATFORM_SECURITY_PATCH` | `2022-11-01` | **`2023-02-01`** | 从 y52s `super` 里搜到的 `security_patch`（`auto_patchlevel.sh` 日志实测） |
| `prebuilt/kernel` | y73s 的 kernel | **y52s 原厂 kernel**（16,813,372 B） | 从 `y52s_recovery.bin` 段表切出 |
| `prebuilt/dtb.img` | y73s dtb | **y52s dtb**（158,641 B） | 同上 |
| `prebuilt/dtbo.img` | y73s dtbo | **y52s recovery_dtbo**（199,573 B） | 同上 |
| 触控固件 | 2 个 `PD2031` + 1 个汇总 | **7 个 `PD2057` 固件** + 汇总 | y52s 原厂 ramdisk 的 `vendor/firmware/` |
| `vivo_avb_footer.bin` | 上游 51 MB 原厂镜像 | **1,792 B**（1728 B vbmeta + 64 B footer） | 从 `y52s_recovery.bin` 尾部 `0x2CD9000` 取 vbmeta，末尾取 `AVBf` footer |

**没错、保持上游原样**的：`recovery.fstab`（y73s 的 TWRP 分区表与 y52s 原厂分区布局同构，已逐行比对）、
`recovery/root/system/etc/fstab.mt6853`、`init.recovery.mt6853.rc`（触控 sysfs 权限块一致）、
`recovery/root/vendor/**` 的 TEE trustlet 与 HAL（y52s 上实测可用）。

---

## 3. 用户 999 是怎么进去的（以及为什么不是源码补丁）

上游树的解密补丁 `patches/system_vold/0006` 只做到 **user 0**：
它用密码/scrypt token → secdis → gatekeeper → keymaster 解 `spblob`。
用户 999 是**应用分身/原子隐私**这类 profile 用户，它的 CE key 是 **tied key**
（`KM_TAG_USER_SECURE_ID` 指向主用户的 SID），要额外做「用主用户 SP 派生
`sp-gk-authentication` → 铸 SID 令牌 → 带 token 调 keymaster begin()」这一整套。

这套逻辑目前**没有公开源码**，只在 y52s 的 OrangeFox 版 `recovery` 二进制里（作者手写）。
所以我把它当作**预编译组件**接入 CI（`prebuilt-999/`），由 `tools/graft_999_precise.py`
在源码构建出镜像后精确注入：

```
3 个 ELF   : system/bin/recovery, system/lib64/libtar.so, system/bin/fscryptpolicyget
9 个运行库 : system/kslib/*（Android 10 keystore daemon 需要旧版 libprotobuf-cpp-lite）
2 个脚本   : system/bin/y52s_ks_prep.sh, sbin/y52s_prepare.sh
5 处 rc    : LD_LIBRARY_PATH 补 /vendor/lib64、5 个 HAL service 的 setenv、
             keystore 指向 /tmp/misc/keystore 并加载 kslib、新增 y52s_ks_prep service、
             recovery.service=1 段追加触发
```

**这条路径是字节级验证过的**：用目录模式跑 `graft_999_precise.py`，输入
`y52s_twrp-ported.img`，输出 SHA256 = `3580f16c44a718833a527b4364b68ef2ad3d0585eb51cb612f18d40f4c7a127b`，
与已经在你真机上解出 999 的那版镜像**完全一致**。

> 想在源码层重写 999（不再依赖预编译二进制），见第 6 节。

---

## 4. 已知风险（首次跑 CI 前务必读）

1. **磁盘与时长**：TWRP 12.1 全量 sync 约 25~35 GB，本工作流把源码放在 `/mnt/twrp`
   并先清理了 runner 上的 dotnet/android-sdk。2 核 runner 编译 `recoveryimage` 约 1.5~2.5 h，
   在 GitHub 单 job 6 h 上限内，但没有太多余量。想更快就自建 runner 或把 `jobs` 输入调到 `4`。
2. **上游仓库可达性**：第 6 步会 `git clone` `liang05l/android_device_vivo_pd2031`。
   上游若删库/改分支，这一步会失败 —— 届时把它换成你自己的 fork 地址。
3. **`0002` 补丁与挂载提示**：上游 `patches/bootable_recovery/0002` 会**屏蔽**
   `/vendor` `/system_root` `/persist` 三个分区的挂载报错。源码构建版带这个补丁，
   所以**源码版不会有那三条挂载失败**；而注入的 999 `recovery` 二进制来自另一个构建
   （没有 0002），注入后那三条会重新出现在屏幕上 —— 这是已知取舍，不是新故障。
4. **签名**：vivo 的 AVB 私钥拿不到，`make_hybrid.py` 的做法是用**原厂 vbmeta + 原厂 footer**
   拼出「杂交镜像」骗过 TEE 的 patchlevel 校验。刷入前 Bootloader 必须已解锁。
5. **`recovery.img` 里 `source-only` 备份**：CI 会额外保留一份未注入 999 的镜像，
   用来排查「问题到底出在源码构建还是 999 二进制」。

---

## 5. 刷入与验证

```bash
fastboot boot recovery.img                  # 先临时启动，别直接 flash
# 1) 触屏 / 亮度 / ADB / MTP / user 0 解密是否都正常
adb shell grep -nE "Decrypted Successfully|y52s:" /tmp/recovery.log
adb shell ls /data/user/999/
# 2) 期望看到
#    User 0 Decrypted Successfully!
#    y52s: sid token: minted for sid=0x... (user 0)
#    y52s: tied-profile credential recovered (80 bytes)
#    User 999 Decrypted Successfully!
# 3) 全部 OK 再写入
fastboot flash recovery recovery.img
```

**解密确认前不要 wipe data。**

---

## 6. 想把 999 做成源码补丁（后续工作）

需要在这三处改（`system/vold`，即 `patches/system_vold/0006` 之后的增量）：

| 编号 | 位置 | 要做什么 |
|---|---|---|
| 0013 | `Decrypt.cpp` 的 `Decrypt_User_Synth_Pass` | 用 SP 派生 `sp-gk-authentication`，按**真实 userId**（不是 `fakeUid`）铸 SID 令牌 |
| 0014 | `Keymaster.cpp` 参数解析 | keymaster tag 带类型高位（`0xA00001F6`），比较前必须 `tag & 0x0FFFFFFF`，否则 `== 502` 永不成立 |
| 0015 | `Decrypt.cpp` 的 `unwrapSyntheticPasswordBlob` | 在 SP 被派生成 FBE 磁盘密钥**之前**捕获 SP 明文；且 `PersonalizedHashSP800()` 返回的是 hex 文本，AOSP 要原始字节 |

这属于「有设备才能收敛」的工程（每次改动都要刷机验证 gatekeeper 返回码 `code` 与 SID 是否对齐），
所以本仓库先保证「CI 能稳定产出可用镜像」，把源码化作为独立里程碑。

---

## 7. 目录说明

```
.github/workflows/build.yml          CI：sync → overlay → patch → build → graft → hybrid → artifact
device/vivo/k6853v1_64_6360/         y52s 覆盖层（只放与 y73s 不同的文件）
  ├── BoardConfig.mk                 cmdline / 补丁级别 / prebuilt 路径
  ├── omni_k6853v1_64_6360.mk        PRODUCT_MODEL / fingerprint
  ├── device.mk                      7 个 PD2057 触控固件
  ├── prebuilt/{kernel,dtb.img,dtbo.img}   y52s 原厂引导段
  ├── recovery/root/vendor/firmware/ PD2057 触控固件
  └── vivo_avb_footer.bin            make_hybrid.py 用的 vbmeta+footer 模板
prebuilt-999/                        用户 999 解密组件（含 manifest.json 中的 cpio 元数据）
tools/graft_999_precise.py           把 prebuilt-999 精确注入构建产物（自带 30 项自检）
tools/{bootimg,cpio,graft_user999}.py  零依赖的 boot image / cpio 处理库
```

---

## 8. 关于「999 逻辑是否在这个仓库里」

已核实：**不在**。对 `twrp-12.1` 全树（142 个文件）做 `grep -ri "999\|tied\|sp-gk"`，
除了一个 git pack 临时文件外 0 命中；`patches/system_vold/0006`（90 KB，解密主补丁）
里 `tied-profile` / `sid` / `USER_SECURE_ID` / `0x0FFFFFFF` 全部为 0；
`4accccc/android_system_vold` 的 `fox_12.1` 与 `twrp-12.1` 两个分支的 `Decrypt.cpp` 字节相同（都是 50,897 B）。
所以 999 只能来自那个已经编译好的二进制，本仓库用 `prebuilt-999/` 注入的方式承载。

另外：`recovery/root/sbin/decrypt` 只是 OrangeFox 的 `fox decrypt $1` 包装脚本（15 行），不含解密逻辑。
