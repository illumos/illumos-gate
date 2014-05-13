#!/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2014, Joyent, Inc. All rights reserved.
#

#
# All native executables must be run using the native linker. By default, the
# kernel loads the linker at /lib/ld.so.1, which in an lx zone is the gcc
# linker. Hence when we run the native executable below, we explicitly specify
# /native/lib/ld.so.1 as our 32-bit linker and /native/lib/64/ld.so.1 as our
# 64-bit linker. For convience we define "n" to be the native path prefix. The
# initial lx_native argument is used as a way to tell the brand emulation that
# it needs to set up the process to run as an unbranded process.
#
# If this script gets setup with a mode that makes it suid, then things won't
# work because the script will be running with the incorrect name.
#
# XXX For now, we only do 32-bit
#

n=/native

bname=`/usr/bin/basename $0`
dname=`/usr/bin/dirname $0`
echo $dname | grep "^/" >/dev/null || dname=`/bin/pwd`/$dname
dname=`(cd $dname 2>/dev/null && /bin/pwd 2>/dev/null)`

if [ ! -f $n$dname/$bname ]; then
	echo "Error: \"$dname/$bname\" is not installed in the global zone"
	exit 1
fi

exec $n/usr/lib/brand/lx/lx_native \
    $n/lib/ld.so.1 \
    -e LD_NOENVIRON=1 \
    -e LD_NOCONFIG=1 \
    -e LD_PRELOAD_32=$n/usr/lib/brand/lx/lx_thunk.so.1 \
    -e LD_LIBRARY_PATH_32="$n/lib:$n/usr/lib" \
    $n$dname/$bname "$@"
