#!/usr/bin/ksh

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

#
# Simple script to run one test, for debug.  Usage:
#  SRV=myserver runone smbfs/mmap/tp_mmap_005
#
# Note: creates/destroys temporary files in the CWD.

export STF_SUITE="/opt/smbclient-tests"
export STF_TOOLS="/opt/test-runner/stf"

PATH=/usr/bin:/usr/sbin:/sbin:$STF_SUITE/bin:$PATH
export PATH

[[ -n "$SRV" ]] || { echo "$0 SRV=... required"; exit 1; }

[[ -x $STF_SUITE/tests/$1 ]] && exec ksh -x $STF_SUITE/tests/$1
exec ksh -x $1
echo "$1: not found"
