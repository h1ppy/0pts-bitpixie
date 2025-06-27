#!/bin/ash

set -e

ALPINE_VERSION="v3.4"
ROOTDIR="/alpine"

apk --arch x86_64 -X http://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main/ -U --allow-untrusted --root ${ROOTDIR} --initdb add alpine-base openssh ethtool
cp /etc/apk/repositories $ROOTDIR/etc/apk/

# boot
for d in hostname procfs sysfs urandom hwdrivers; do
  ln -vs "/etc/init.d/${d}" $ROOTDIR/etc/runlevels/boot/
done

# default
for d in sshd; do
  ln -vs "/etc/init.d/${d}" $ROOTDIR/etc/runlevels/default/
done

# local
ln -vs /etc/init.d/local $ROOTDIR/etc/runlevels/default/

cp -v /init $ROOTDIR/
cp -v /dhcp.start $ROOTDIR/etc/local.d/

echo initrd >> $ROOTDIR/etc/hostname

echo >> $ROOTDIR/etc/ssh/sshd_config
echo PermitRootLogin yes >> $ROOTDIR/etc/ssh/sshd_config
echo PermitEmptyPasswords yes >> "$ROOTDIR"/etc/ssh/sshd_config

#Создаём папку для хранения модулей для нашей версии ядра
mkdir -p $ROOTDIR/lib/modules/5.14.0-1-amd64
#Копируем модули в созданную папку
cp -r lib/modules/5.14.0-1-amd64/* $ROOTDIR/lib/modules/5.14.0-1-amd64/
#Создаём папку для нашего exploit
mkdir -p $ROOTDIR/root/CVE-2024-1086
#Копируем наш exploit для извлечения vmk
cp -r root/CVE-2024-1086/* $ROOTDIR/root/CVE-2024-1086/

# Генерируем зависимости для модулей ядра
chroot $ROOTDIR depmod -a 5.14.0-1-amd64
