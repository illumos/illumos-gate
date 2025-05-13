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

SVC=svc:/system/idmap

if [ ! -f /var/run/idmap-test-smf ]; then
	echo "No idmap-test-smf state file found" | tee /dev/stderr
	exit 4
fi

pretest_idmap_state=$(cat /var/run/idmap-test-smf)
rm -f /var/run/idmap-test-smf
if [ "$pretest_idmap_state" == "disabled" ]; then
	svcadm disable -s $SVC
	echo "Service $SVC disabled after idmap tests"
fi

exit 0
