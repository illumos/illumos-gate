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
# Copyright 2021 Oxide Computer Company
#

#
# The core tests require that we have per-process core dumps enabled.
# This script is used as the pre-requisite in the test runner to verify
# that fact.
#

set -o pipefail

if coreadm | grep -q 'per-process core dumps: enabled'; then
	exit 0
fi

echo "per -process core dumps are not enabled, skipping test" >&2
exit 1
