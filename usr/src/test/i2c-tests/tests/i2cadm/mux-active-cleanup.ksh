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
# This test runs from setup-full and covers a development issue where upon mux
# removal we didn't properly clean up the controller's notion of what ports are
# active. Effectively we need to perform I/O to a port under a mux, delete
# everything around that, and then try to perform I/O again.
#

. $(dirname $0)/common.ksh

if ! $I2CADM io -d i2csim0/0/0x70/0/0x71/0/0x72 -w 2 -r 4 0x00 0x00 >/dev/null; then
	fatal "failed to read from at24c at i2csim0/0/0x70/0/0x71/0/0x72"
fi

i2c_cleanup_path i2csim0/0/0x70

if ! $I2CADM io -d i2csim0/0/0x10 -w 2 -r 4 0x00 0x00 >/dev/null; then
	fatal "failed to read from at24c at i2csim0/0/0x10"
fi

printf "All tests passed successfully!\n"
exit $i2c_exit
