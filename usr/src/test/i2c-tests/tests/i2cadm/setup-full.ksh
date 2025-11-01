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
# This is designed to set up all of the expected I2C devices that are being
# simulated. This looks like:
#
#	0x10:	at24c32
#	0x20:	at24c08 (uses 0x20-0x23)
#	0x70:	pca9548
#		mux 0:	0x71: pca9548
#			mux 0: at24c32: 0x72
#			mux 1: at24c32: 0x72
#			mux 2: at24c32: 0x72
#			mux 3: at24c32: 0x72
#			mux 4: at24c32: 0x72
#			mux 5: at24c32: 0x72
#			mux 6: at24c32: 0x72
#			mux 7: at24c32: 0x72
#		mux 1:	0x71: at24c32
#		mux 2:	0x71: ts5111
#			0x72: ts5111
#		mux 3:	0x71: ts5111
#			0x72: ts5111
#

. $(dirname $0)/common.ksh

#
# Start a fresh instance of i2csimd.
#
if ! svcadm disable -s system/i2csimd; then
	fatal "failed to disable i2csimd"
fi

if ! svcadm enable -st system/i2csimd; then
	fatal "failed to enable i2csimd"
fi

#
# Create all of our devices.
#
if ! i2cadm device add i2csim0/0 at24c32 0x10; then
	fatal "failed to add device i2csim0/0/0x10"
fi

if ! i2cadm device add i2csim0/0 at24c08 0x20; then
	fatal "failed to add device i2csim0/0/0x20"
fi

if ! i2cadm device add i2csim0/0 pca9548 0x70; then
	fatal "failed to add device i2csim0/0/0x70"
fi

if ! i2cadm device add i2csim0/0/0x70/0 pca9548 0x71; then
	fatal "failed to add device i2csim0/0/0x70/0/0x71"
fi

for i in {0..7}; do
	if ! i2cadm device add i2csim0/0/0x70/0/0x71/$i at24c32 0x72; then
		fatal "failed to add device i2csim0/0/0x70/0/0x71/$i/0x72"
	fi
done

if ! i2cadm device add i2csim0/0/0x70/1 at24c32 0x71; then
	fatal "failed to add device i2csim0/0/0x70/1/0x71"
fi

for i in {2..3}; do
	if ! i2cadm device add i2csim0/0/0x70/$i ts5111 0x71; then
		fatal "failed to add device i2csim0/0/0x70/$i/0x71"
	fi

	if ! i2cadm device add i2csim0/0/0x70/$i ts5111 0x72; then
		fatal "failed to add device i2csim0/0/0x70/$i/0x72"
	fi
done

exit $i2c_exit
