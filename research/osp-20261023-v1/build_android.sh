#!/bin/sh
set -eu
: "${ANDROID_NDK_HOME:=${ANDROID_NDK_LATEST_HOME:-}}"
if [ -z "$ANDROID_NDK_HOME" ]; then echo 'Android NDK path unavailable' >&2; exit 2; fi
TC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
CC="$TC/aarch64-linux-android28-clang"
mkdir -p out
"$CC" --version > out/toolchain.txt
CFLAGS='-std=c11 -O2 -g -Wall -Wextra -Werror -fno-builtin -fno-omit-frame-pointer -fstack-protector-strong'
"$CC" $CFLAGS -fPIC -shared -Wl,-soname,libosp.so -Wl,-z,relro,-z,now,-z,max-page-size=16384 -Wl,--no-undefined -o out/libosp.so osp.c -ldl
"$CC" $CFLAGS -fno-optimize-sibling-calls -fPIC -shared -Wl,-soname,libosp_fixture.so -Wl,-z,max-page-size=16384 -o out/libosp_fixture.so fixture.c -Lout -Wl,--no-as-needed -losp -ldl
"$CC" $CFLAGS -fPIE -pie -Wl,-z,max-page-size=16384 -o out/test_hook test_hook.c -ldl
"$TC/llvm-readelf" -h -l -d out/libosp.so > out/elf.txt
"$TC/llvm-readelf" --dyn-syms out/libosp.so > out/exports.txt
sha256sum out/libosp.so out/libosp_fixture.so out/test_hook > out/SHA256SUMS
