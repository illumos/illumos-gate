#!/usr/bin/ksh -p
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
# Copyright 2026 Oxide Computer Company
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/zvol/zvol_common.shlib

#
# DESCRIPTION:
# Verify that DKIOCFREE adds dfl_offset to the start of each extent, and
# that it fails with EINVAL if that sum overflows.
#
# STRATEGY:
# 1. Create a zvol and fill it with random data.
# 2. Issue DKIOCFREE with a nonzero dfl_offset and two extents.  Verify
#    that exactly the two ranges at dfl_offset + dfle_start read back as
#    zeros, and the rest of the data is unchanged.
# 3. Issue DKIOCFREE where dfl_offset + dfle_start overflows.  Verify that
#    it fails with EINVAL and changes nothing.
#

verify_runnable "global"

REGVOL=$TESTPOOL/freeoff_vol
DATA=$TEST_BASE_DIR/freeoff.data
OUT=$TEST_BASE_DIR/freeoff.out
EXPECT=$TEST_BASE_DIR/freeoff.expect
VOL_MB=64
MB=1048576
EINVAL=22

function cleanup
{
	datasetexists $REGVOL && destroy_dataset $REGVOL
	rm -f $DATA $OUT $EXPECT
}

# Verify that MB [first, last) of the device match the data written to it.
function check_data # <device> <first MB> <last MB>
{
	typeset -i count=$(($3 - $2))
	log_must dd if=$1 of=$OUT bs=1024k iseek=$2 count=$count
	log_must dd if=$DATA of=$EXPECT bs=1024k iseek=$2 count=$count
	log_must cmp $EXPECT $OUT
}

# Verify that MB [first, last) of the device are zeros.
function check_zeros # <device> <first MB> <last MB>
{
	typeset -i count=$(($3 - $2))
	log_must dd if=$1 of=$OUT bs=1024k iseek=$2 count=$count
	log_must dd if=/dev/zero of=$EXPECT bs=1024k count=$count
	log_must cmp $EXPECT $OUT
}

function test_dev # <device>
{
	typeset dev=$1

	log_note "Testing $dev"
	log_must dd if=/dev/urandom of=$DATA bs=1024k count=$VOL_MB
	log_must dd if=$DATA of=$dev bs=1024k count=$VOL_MB
	check_data $dev 0 $VOL_MB

	# Frees MB [20, 24) and [28, 30).
	log_must dkiocfree -o $((16 * MB)) $dev $((4 * MB)) $((4 * MB)) \
	    $((12 * MB)) $((2 * MB))
	check_data $dev 0 20
	check_zeros $dev 20 24
	check_data $dev 24 28
	check_zeros $dev 28 30
	check_data $dev 30 $VOL_MB

	# dfl_offset + dfle_start wraps around to 1 MB.
	dkiocfree -o 18446744073708503040 $dev $((2 * MB)) $((4 * MB))
	typeset -i err=$?
	((err == EINVAL)) || \
	    log_fail "overflowing DKIOCFREE returned $err, not EINVAL"
	check_data $dev 0 20
	check_zeros $dev 20 24
	check_data $dev 24 28
	check_zeros $dev 28 30
	check_data $dev 30 $VOL_MB
}

log_assert "DKIOCFREE honors dfl_offset"
log_onexit cleanup

log_must zfs create -V ${VOL_MB}m $REGVOL

test_dev $ZVOL_RDEVDIR/$REGVOL

log_pass "DKIOCFREE honors dfl_offset"
