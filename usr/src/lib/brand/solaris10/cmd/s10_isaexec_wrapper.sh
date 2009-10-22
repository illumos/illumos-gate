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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# This script is invoked by isaexec-governed executable wrappers from within
# s10-branded zones.  It circumvents the native isaexec so that native wrappers
# will function correctly.
#
# All native executables must be run using the native linker.
# By default, the kernel loads the linker at /lib/ld.so.1, which
# in an s10 zone is the s10 linker.  Hence when we run the native
# executable below, we explicitly specify /.SUNWnative/lib/ld.so.1 as our 32-
# bit linker and /.SUNWnative/lib/64/ld.so.1 as our 64-bit linker.
# For convience we define "n" to be the native path prefix.
#
bname=`/usr/bin/basename $0`
dname=`/usr/bin/dirname $0`
echo $dname | /usr/bin/grep "^/" >/dev/null || dname=`/bin/pwd`/$dname
dname=`(cd $dname 2>/dev/null && /bin/pwd 2>/dev/null)`
arch64=/
LC_ALL=C /usr/bin/file /.SUNWnative/$dname/$bname | /usr/bin/grep "64-bit" \
    >/dev/null && arch64=/64/
n=/.SUNWnative

LD_NOCONFIG=1
LD_LIBRARY_PATH_32=$n/lib:$n/usr/lib:$n/usr/lib/mps
LD_LIBRARY_PATH_64=$n/lib/64:$n/usr/lib/64:$n/usr/lib/mps/64
LD_PRELOAD_32=s10_npreload.so.1
LD_PRELOAD_64=s10_npreload.so.1
export LD_NOCONFIG
export LD_LIBRARY_PATH_32 LD_LIBRARY_PATH_64 LD_PRELOAD_32 LD_PRELOAD_64
exec /.SUNWnative/usr/lib/brand/solaris10/s10_native \
    /.SUNWnative/lib${arch64}ld.so.1 /.SUNWnative$dname/$bname "$@"

