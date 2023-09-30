#!/bin/bash
rm -rf _
mkdir -p _/usr/bin
cp -a ios/ldid _/usr/bin/ldid
mkdir -p _/DEBIAN
./control.sh _ >_/DEBIAN/control
mkdir -p debs
ln -sf debs/ldid_$(./version.sh)_iphoneos-arm.deb ldid.deb
dpkg-deb -b _ ldid.deb
readlink ldid.deb
