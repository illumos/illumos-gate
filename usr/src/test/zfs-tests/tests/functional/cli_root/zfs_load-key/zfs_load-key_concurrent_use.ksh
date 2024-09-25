#!/bin/ksh -p
#
# CDDL HEADER START
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
# CDDL HEADER END
#

#
# Copyright 2026 Oxide Computer Company
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zfs_load-key/zfs_load-key_common.kshlib

#
# DESCRIPTION:
# Concurrent first users of a loaded key should all succeed.
#
# When nothing holds a dataset's key, the next user reads it from disk.
# Several users can do that at once; all but the first must drop their
# copy.  This used to trip an assertion on DEBUG kernels.
#
# STRATEGY:
# 1. Create an encrypted dataset with a few snapshots
# 2. Unmount it, so that nothing holds its key
# 3. Repeatedly start several non-raw sends of its snapshots at once
# 4. Verify that every send succeeds
#

verify_runnable "both"

typeset -i iters=500
typeset -i par=8

function cleanup
{
	datasetexists $TESTPOOL/$TESTFS1 && \
		log_must zfs destroy -r $TESTPOOL/$TESTFS1
}
log_onexit cleanup

log_assert "Concurrent first users of a loaded key should all succeed"

log_must eval "echo $PASSPHRASE | zfs create -o encryption=on" \
	"-o keyformat=passphrase -o keylocation=prompt $TESTPOOL/$TESTFS1"
log_must mkfile 128k /$TESTPOOL/$TESTFS1/file
for i in $(seq 1 $par); do
	log_must zfs snapshot $TESTPOOL/$TESTFS1@snap$i
done
log_must zfs unmount $TESTPOOL/$TESTFS1
log_must key_available $TESTPOOL/$TESTFS1

typeset -i iter=1
while (( iter <= iters )); do
	typeset pids=""
	for i in $(seq 1 $par); do
		zfs send $TESTPOOL/$TESTFS1@snap$i >/dev/null &
		pids="$pids $!"
	done
	for pid in $pids; do
		wait $pid || log_fail "zfs send failed in iteration $iter"
	done
	(( iter += 1 ))
done

log_pass "Concurrent first users of a loaded key all succeeded"
