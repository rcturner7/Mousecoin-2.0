#!/bin/bash

# Environment variables that can be overridden by the user:
#   MXE_PREFIX     - path to the MXE installation prefix
#                    (default: /mnt/mxe)
#   MXE_TARGET     - MXE target triplet
#                    (default: i686-w64-mingw32.static)
#   PROJECT_ROOT   - path to the Mousecoin source tree
#                    (default: directory containing this script)
#   JOBS           - number of parallel jobs for make (default: 16)
#   SECP256K1_LIB_PATH - additional library path for secp256k1
#                    (default: /usr/lib:/usr/local/bin)

MXE_PREFIX=${MXE_PREFIX:-/mnt/mxe}
MXE_TARGET=${MXE_TARGET:-x86_64-w64-mingw32.static}
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=${PROJECT_ROOT:-$SCRIPT_DIR}
JOBS=${JOBS:-16}
SECP256K1_LIB_PATH=${SECP256K1_LIB_PATH:-/usr/lib:/usr/local/bin}

export PATH="$MXE_PREFIX/usr/bin:$PATH"

cd "$PROJECT_ROOT/src/leveldb"
TARGET_OS=NATIVE_WINDOWS make \
    CC="$MXE_PREFIX/usr/bin/${MXE_TARGET}-gcc" \
    CXX="$MXE_PREFIX/usr/bin/${MXE_TARGET}-g++"

cd ../..

"$MXE_PREFIX/usr/bin/${MXE_TARGET}-qmake-qt5" \
        BOOST_LIB_SUFFIX=-mt \
        BOOST_THREAD_LIB_SUFFIX=_win32-mt \
        BOOST_INCLUDE_PATH="$MXE_PREFIX/usr/$MXE_TARGET/include/boost" \
        BOOST_LIB_PATH="$MXE_PREFIX/usr/$MXE_TARGET/lib" \
        OPENSSL_INCLUDE_PATH="$MXE_PREFIX/usr/$MXE_TARGET/include/openssl" \
        OPENSSL_LIB_PATH="$MXE_PREFIX/usr/$MXE_TARGET/lib" \
        BDB_INCLUDE_PATH="$MXE_PREFIX/usr/$MXE_TARGET/include" \
        BDB_LIB_PATH="$MXE_PREFIX/usr/$MXE_TARGET/lib" \
        MINIUPNPC_INCLUDE_PATH="$MXE_PREFIX/usr/$MXE_TARGET/include" \
        MINIUPNPC_LIB_PATH="$MXE_PREFIX/usr/$MXE_TARGET/lib" \
        QMAKE_LRELEASE="$MXE_PREFIX/usr/$MXE_TARGET/qt5/bin/lrelease" Mic3.pro

make -j "$JOBS" -f Makefile.Release
