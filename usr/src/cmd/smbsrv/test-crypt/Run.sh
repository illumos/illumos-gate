#!/bin/sh

#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2018-2021 Tintri by DDN, Inc. All rights reserved.
#

# Helper program to run test-crypt (unit test program)
# using binaries from the proto area.

[ -n "$CODEMGR_WS" ] || {
  echo "Need a buildenv to set CODEMGR_WS=..."
  exit 1;
}

ROOT=${CODEMGR_WS}/proto/root_i386
LD_LIBRARY_PATH=$ROOT/usr/lib:$ROOT/lib
export LD_LIBRARY_PATH
export UMEM_DEBUG=default

PATH_PKCS11_CONF="$ROOT/etc/crypto/pkcs11.conf"
export PATH_PKCS11_CONF

# ldd $ROOT/usr/lib/smbsrv/test-encrypt
set -x

# sudo -s dtrace -s Watch.d -o test-encrypt.dto -c \
$ROOT/usr/lib/smbsrv/test-encrypt

# sudo -s dtrace -s Watch.d -o test-decrypt.dto -c \
$ROOT/usr/lib/smbsrv/test-decrypt
