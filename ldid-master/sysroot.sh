#!/bin/bash
set -e

rm -rf sysroot32 sysroot64
mkdir -p sysroot32 sysroot64

function merge() {
    wget --no-check-certificate "${apt}/$1"
    dpkg-deb -x "$1" .
}

pushd sysroot32
apt=http://apt.saurik.com/debs
merge openssl_0.9.8zg-13_iphoneos-arm.deb
merge libplist_2.0.0-1_iphoneos-arm.deb
popd

pushd sysroot64
apt=https://apt.bingner.com/debs/1443.00
merge libssl1.0_1.0.2q-1_iphoneos-arm.deb
merge libssl-dev_1.0.2q-1_iphoneos-arm.deb
merge libplist_2.0.0-1_iphoneos-arm.deb
popd

for lib in libplist libcrypto; do
    for dylib in sysroot*/usr/lib/"${lib}".*.dylib; do
        echo install_name_tool -id /usr/lib/"${lib}".dylib "${dylib}"
        chmod 755 "${dylib}"
        install_name_tool -id /usr/lib/"${lib}".dylib "${dylib}"
    done
done
