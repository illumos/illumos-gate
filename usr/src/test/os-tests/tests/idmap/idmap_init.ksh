#!/bin/ksh

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
# Copyright 2025 MNX Cloud, Inc.
#

# Enable idmap temporarily for this test if it's not already enabled.
# Skip test if it can't be enabled.

SVC=svc:/system/idmap

if svcs -H -o state $SVC >/dev/null 2>&1; then
	pretest_idmap_state=$(svcs -H -o state $SVC)
else
	echo "Unknown service $SVC - skipping idmap tests" | tee /dev/stderr
	exit 4
fi

echo $pretest_idmap_state > /var/run/idmap-test-smf
if [ "$pretest_idmap_state" == "disabled" ]; then
	svcadm enable -st $SVC
	if [ $? != 0 ]; then
		echo "Failed to enable $SVC - skipping idmap tests" | tee /dev/stderr
		exit 4
	fi
	echo "Service $SVC temporarily enabled for idmap tests"
fi
exit 0
