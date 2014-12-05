#! /usr/bin/ksh
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
# Copyright (c) 2014, Joyent, Inc. 
#

#
# Simple wrapper for the classic test.out
#

set -o errexit

btest_root=$(dirname $0)/../..
btest_bin=$btest_root/bin/btest

LD_PRELOAD=libumem.so UMEM_DEBUG=default $btest_bin >/dev/null
