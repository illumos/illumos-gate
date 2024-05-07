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
# Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
#

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
#	Automated auto-spare selects lowest capacity suitable device
#
# STRATEGY:
#	1. Create a redundant pool with two spare devices of different sizes,
#	   one that matches the size of the other devices in the pool, and one
#	   twice as large.
#	2. Manually fault a device, wait for the hot-spare and verify that
#	   the smallest device is selected.
#	3. Repeat with the devices added to the pool in the opposite order.
#	4. Repeat with the faulted vdev being the same size as the larger
#	   spare and verify that the larger spare is selected.
#

verify_runnable "global"

function cleanup {
	log_must zinject -c all
	poolexists $TESTPOOL && destroy_pool $TESTPOOL
	log_must rm -f ${DATA_DEVS[*]} ${SPARE_DEVS[*]}
}

log_assert "Automated auto-spare selects lowest capacity suitable device"
log_onexit cleanup

typeset -a DATA_DEVS SPARE_DEVS
typeset DEV
TMPDIR='/var/tmp'
for d in {1..4}; do
	DEV="$TMPDIR/data-dev$d"
	typeset -r "DATA_DEV$d"="$DEV"
	DATA_DEVS+=($DEV)
done
for d in {1..2}; do
	DEV="$TMPDIR/data-dev$d"
	typeset -r "SPARE_DEV$d"="$TMPDIR/spare-dev$d"
	SPARE_DEVS+=($DEV)
done

function run {
	typeset type="$1"; shift
	typeset ddevsize="$1"; shift	# Data dev size
	typeset spare1="$1"; shift	# First spare to add
	typeset spare2="$1"; shift	# Second spare to add
	typeset spare="$1"; shift	# Expected spare that gets picked

	truncate -s $ddevsize ${DATA_DEVS[*]}
	truncate -s $SPA_MINDEVSIZE $SPARE_DEV1
	truncate -s $((SPA_MINDEVSIZE * 2)) $SPARE_DEV2

	log_must zpool create $TESTPOOL $type ${DATA_DEVS[*]}
	log_must zpool add $TESTPOOL spare "$spare1"
	log_must zpool add $TESTPOOL spare "$spare2"

	# Fault a device, verify the right spare is kicked in
	log_must zinject -d $DATA_DEV1 -e nxio -T all -f 100 $TESTPOOL
	log_must zpool scrub $TESTPOOL
	log_must wait_vdev_state $TESTPOOL $DATA_DEV1 "UNAVAIL" 60
	log_must wait_vdev_state $TESTPOOL $spare "ONLINE" 60
	log_must wait_hotspare_state $TESTPOOL $spare "INUSE"
	log_must check_state $TESTPOOL "$type-0" "DEGRADED"
	cleanup
}

for type in mirror raidz1 raidz2 raidz3; do
	# All vdevs and spare1 are the same size, spare2 is double the size.
	# Regardless of whether spare1 or spare2 is added to the pool first, we
	# expect spare1 to be used for the replacement.
	run $type $SPA_MINDEVSIZE $SPARE_DEV1 $SPARE_DEV2 $SPARE_DEV1
	run $type $SPA_MINDEVSIZE $SPARE_DEV2 $SPARE_DEV1 $SPARE_DEV1

	# All vdevs and spare2 are the same size, spare1 is half the size.
	# Regardless of whether spare1 or spare2 is added to the pool first, we
	# expect spare2 to be used for the replacement. spare1 is too small.
	run $type $((SPA_MINDEVSIZE * 2)) $SPARE_DEV1 $SPARE_DEV2 $SPARE_DEV2
	run $type $((SPA_MINDEVSIZE * 2)) $SPARE_DEV2 $SPARE_DEV1 $SPARE_DEV2
done

log_pass "Automated auto-spare selects lowest capacity suitable device"
