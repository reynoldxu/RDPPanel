#!/bin/sh

# 定义包名
PKG_NAME="luci-app-rdp-manager"
IPK_NAME="luci-app-rdp-manager_1.0.0-1_all.ipk"

echo ">>> 开始强制修复并打包..."

# 1. 强行修复 control 文件夹下的所有文件格式
# 使用 tr 命令删除所有 Windows 换行符，这是最彻底的方法
tr -d '\r' < control/control > control/control.tmp && mv control/control.tmp control/control
tr -d '\r' < control/postinst > control/postinst.tmp && mv control/postinst.tmp control/postinst

# 2. 强制赋予执行权限
chmod +x control/postinst

# 3. 确保 control 文件末尾有空行
sed -i -e '$a\' control/control

# 4. 重新打包
rm -f "$IPK_NAME" debian-binary control.tar.gz data.tar.gz
echo "2.0" > debian-binary
tar -czf control.tar.gz -C control .
tar -czf data.tar.gz -C data .
tar -czf "$IPK_NAME" debian-binary control.tar.gz data.tar.gz

# 清理
rm -f debian-binary control.tar.gz data.tar.gz

opkg install luci-app-rdp-manager_1.0.0-1_all.ipk --force-reinstall

echo ">>> 打包安装完成: $IPK_NAME"