#
# Copyright (C) 2026 The Android Open Source Project
#
# SPDX-License-Identifier: Apache-2.0
#

LOCAL_PATH := device/vivo/k6853v1_64_6360

# 触摸固件 [PD2057] y52s 原厂 7 个 PD2057 固件（y73s 是 2 个 PD2031 固件）
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/recovery/root/vendor/firmware/TP-FW-PD2057-LCMID17-VER0x26.bin:$(TARGET_COPY_OUT_RECOVERY)/root/vendor/firmware/TP-FW-PD2057-LCMID17-VER0x26.bin \
    $(LOCAL_PATH)/recovery/root/vendor/firmware/TP-FW-PD2057-LCMID65-VER0x29.bin:$(TARGET_COPY_OUT_RECOVERY)/root/vendor/firmware/TP-FW-PD2057-LCMID65-VER0x29.bin \
    $(LOCAL_PATH)/recovery/root/vendor/firmware/TP-FW-PD2057-LCMID66-VER0x24.bin:$(TARGET_COPY_OUT_RECOVERY)/root/vendor/firmware/TP-FW-PD2057-LCMID66-VER0x24.bin \
    $(LOCAL_PATH)/recovery/root/vendor/firmware/TP-FW-PD2057-LCMID66-VER0x26.bin:$(TARGET_COPY_OUT_RECOVERY)/root/vendor/firmware/TP-FW-PD2057-LCMID66-VER0x26.bin \
    $(LOCAL_PATH)/recovery/root/vendor/firmware/TP-FW-PD2057-LCMID66-VER0x30.bin:$(TARGET_COPY_OUT_RECOVERY)/root/vendor/firmware/TP-FW-PD2057-LCMID66-VER0x30.bin \
    $(LOCAL_PATH)/recovery/root/vendor/firmware/TP-MP-FW-PD2057-LCMID17-VER0x21.bin:$(TARGET_COPY_OUT_RECOVERY)/root/vendor/firmware/TP-MP-FW-PD2057-LCMID17-VER0x21.bin \
    $(LOCAL_PATH)/recovery/root/vendor/firmware/TP-MP-FW-PD2057-LCMID65-VER0xc02.bin:$(TARGET_COPY_OUT_RECOVERY)/root/vendor/firmware/TP-MP-FW-PD2057-LCMID65-VER0xc02.bin \
    $(LOCAL_PATH)/recovery/root/vendor/firmware/touch_firmwares_recovery.bin:$(TARGET_COPY_OUT_RECOVERY)/root/vendor/firmware/touch_firmwares_recovery.bin

# 添加debug日志记录脚本，顺便加入7zip以应对某些压缩格式刁钻的压缩包
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/recovery/root/system/bin/start_dmesg_log.sh:$(TARGET_COPY_OUT_RECOVERY)/root/system/bin/start_dmesg_log.sh \
    $(LOCAL_PATH)/recovery/root/system/bin/stop_dmesg_log.sh:$(TARGET_COPY_OUT_RECOVERY)/root/system/bin/stop_dmesg_log.sh \
    $(LOCAL_PATH)/recovery/root/system/bin/start_recovery_log.sh:$(TARGET_COPY_OUT_RECOVERY)/root/system/bin/start_recovery_log.sh \
    $(LOCAL_PATH)/recovery/root/system/bin/7zzs:$(TARGET_COPY_OUT_RECOVERY)/root/sbin/7zzs

# Auto patch level detection script - 自动从系统分区读取安全补丁级别
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/recovery/root/system/bin/auto_patchlevel.sh:$(TARGET_COPY_OUT_RECOVERY)/root/system/bin/auto_patchlevel.sh


# fstab (标准Android格式，解密需要)
PRODUCT_COPY_FILES +=     $(LOCAL_PATH)/recovery/root/system/etc/fstab.mt6853:$(TARGET_COPY_OUT_RECOVERY)/root/system/etc/fstab.mt6853

# 触摸屏二进制文件 (原厂提取)
PRODUCT_PACKAGES += vts_app_recovery

# FBE decryption (filenames cipher mode)
PRODUCT_PROPERTY_OVERRIDES += \
    ro.crypto.volume.filenames_mode=aes-256-cts
