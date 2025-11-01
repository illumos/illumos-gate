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
# Copyright 2025 Oxide Computer Company
#

#
# Go through and clean up all of the state that a given test may have created.
# In particular we need to destroy all of the devices that we have created and
# then we want to disable the i2csimd instance.
#

export LANG=C.UTF-8
set -o errexit
unalias -a

. $(dirname $0)/common.ksh

i2c_cleanup_devs

if ! svcadm disable -s system/i2csimd; then
	fatal "failed to disable i2csimd"
fi

exit $i2c_exit
