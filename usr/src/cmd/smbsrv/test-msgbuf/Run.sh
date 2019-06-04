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
# Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
#

# Helper program to run test-msgbuf (unit test program)
# using binaries from the proto area.

[ -n "$CODEMGR_WS" ] || {
  echo "Need a buildenv to set CODEMGR_WS=..."
  exit 1;
}

ROOT=${CODEMGR_WS}/proto/root_i386
LD_LIBRARY_PATH=$ROOT/usr/lib/smbsrv:$ROOT/usr/lib:$ROOT/lib
export LD_LIBRARY_PATH
export UMEM_DEBUG=default

# run with the passed options
exec $ROOT/usr/lib/smbsrv/test-msgbuf "$@"
