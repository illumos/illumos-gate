#!/bin/bash

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
# Copyright (c) 2017 by Delphix. All rights reserved.
#

source ${JENKINS_DIRECTORY}/sh/library/common.sh

check_env RUNFILE

DIR=$(dirname ${BASH_SOURCE[0]})

log_must sudo sed -i "s/timeout = .*/timeout = 10800/" $RUNFILE

#
# When running in the AWS environment, two devices will be exposed for
# each "disk" attached to the VM. If we relied on zfs-tests' "-a" option
# to detect the disks, it would incorrectly use both devices, even
# though they correspond to the same underlying storage, which would
# result in incorrect test results. Thus, we hardcode the disks that
# will be used by the test suite here, to workaround the issue.
#
export DISKS="c4t1d0 c4t2d0 c4t3d0"

#
# Since we can't use the "-a" option as discussed in the comment above,
# we add these two commands such that their output gets captured in the
# Jenkins console log, which can make triaging and debugging easier in
# the event that the disk topology changes (e.g. perhaps due to changes
# to illumos, the base AMI, or even the EC2 hypervisor).
#
log_must sudo diskinfo
log_must echo "$DISKS"

log_must ppriv -s EIP=basic -e \
	/opt/zfs-tests/bin/zfstest -c $RUNFILE 2>&1 | tee results.txt

log_must ${DIR}/zfstest-report.py results.txt
