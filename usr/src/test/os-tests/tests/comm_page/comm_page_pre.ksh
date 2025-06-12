#!/usr/bin/ksh
#
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
# Copyright 2025 Oxide Computer Company
#

#
# The comm page test(s) require that we are running on a machine platform which
# supports that mechanism and is properly exposing it to userspace.
#

set -o pipefail
. /opt/test-runner/stf/include/stf.shlib

if pauxv $$ | grep -q 'AT_SUN_COMMPAGE'; then
	exit $STF_PASS
fi

echo "comm page is absent, skipping test" >&2
exit $STF_UNSUPPORTED
