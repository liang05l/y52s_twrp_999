# y52s-twrp — vivo Y52s (PD2057) TWRP 源码构建

从 y73s（PD2031）设备树移植，带「解密用户 999」组件，用 GitHub Actions 编译。

**快速开始**

```bash
git init -b main && git add -A && git commit -m "y52s twrp"
git remote add origin https://github.com/<你>/y52s-twrp.git
git push -u origin main
```

推上去后在仓库 **Actions → Build TWRP for vivo Y52s (PD2057) → Run workflow**，
约 1.5~3 小时后下载 artifact `twrp-y52s-pd2057`，内含：

| 文件 | 说明 |
|---|---|
| `recovery.img` | **可直接刷**，含 999 解密组件 |
| `recovery.img.source-only` | 纯源码构建、不含 999（用于对比排错） |
| `SHA256SUMS` | 校验和 |

详细说明（改了哪些、为什么、已知风险、验证步骤）见 **[PORTING.md](PORTING.md)**。

> Bootloader 必须已解锁；`fastboot boot recovery.img` 先临时启动验证，确认无误再 `fastboot flash`。
> **解密确认前不要 wipe data。**
