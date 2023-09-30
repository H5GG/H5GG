#!/bin/bash

set -e
shopt -s extglob

if [[ $# == 0 ]]; then
    ios=false
else
    ios=$1
    shift
fi

export DEVELOPER_DIR=/Applications/Xcode-5.1.1.app

os=()

if "${ios}"; then

out=ios
flags=(cycc -- -miphoneos-version-min=2.0 -arch armv6 -arch arm64)

flags+=(-Xarch_armv6 -Isysroot32/usr/include)
flags+=(-Xarch_arm64 -Isysroot64/usr/include)

flags+=(-Xarch_armv6 -Lsysroot32/usr/lib)
flags+=(-Xarch_arm64 -Lsysroot64/usr/lib)

static=false
flags+=(-framework CoreFoundation)

flags+=(-lplist)
flags+=(-lcrypto)

else

out=out

if which xcrun &>/dev/null; then
    flags=(xcrun -sdk macosx g++)
    flags+=(-mmacosx-version-min=10.4)

    for arch in i386 x86_64; do
        flags+=(-arch "${arch}")
    done
else
    flags=(g++)
fi

#flags+=(-L../../lib-osx/openssl)

# XXX: cannot redistribute
static=true
flags+=(-Isysroot64/usr/include)
flags+=(-lcrypto)
#flags+=(-Wl,/usr/lib/libcrypto.42.dylib)

fi

sdk=$(xcodebuild -sdk iphoneos -version Path)

flags+=(-I.)

if ${static}; then

flags+=(-I"${sdk}"/usr/include/libxml2)
flags+=(-Ilibplist/include)
flags+=(-Ilibplist/libcnary/include)

for c in libplist/libcnary/!(cnary).c libplist/src/*.c; do
    o=${c%.c}.o
    o="${out}"/${o##*/}
    os+=("${o}")
    if [[ "${c}" -nt "${o}" ]]; then
        "${flags[@]}" -c -o "${o}" -x c "${c}"
    fi
done

fi

flags+=("$@")

mkdir -p "${out}"
set -x

"${flags[@]}" -O3 -g0 -c -std=c++11 -o "${out}"/ldid.o ldid.cpp
"${flags[@]}" -O3 -g0 -o "${out}"/ldid "${out}"/ldid.o "${os[@]}" -x c lookup2.c -lxml2 -framework Security

if ! "${ios}"; then
    ln -sf out/ldid .
fi
