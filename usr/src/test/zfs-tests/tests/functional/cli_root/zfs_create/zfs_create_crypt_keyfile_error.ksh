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
# When 'zfs create' fails after the key has been read from a keylocation
# file, the reported error must be the real one and not a stale error
# left behind by the key location handling.
#
# STRATEGY:
# 1. Write a passphrase to a key file.
# 2. Attempt to create an encrypted filesystem and an encrypted volume
#    using that key file, each with a reservation that cannot be
#    satisfied.
# 3. Verify that each attempt fails, reporting 'out of space'.
#

verify_runnable "global"

typeset keyfile=/$TESTPOOL/pkey
typeset fs=$TESTPOOL/$TESTFS1.nospc
typeset vol=$TESTPOOL/$TESTVOL.nospc

function cleanup
{
	datasetexists $fs && log_must zfs destroy -r $fs
	datasetexists $vol && log_must zfs destroy -r $vol
	rm -f $keyfile
}
log_onexit cleanup

#
# Run 'zfs create' with the supplied arguments and verify that it fails
# because the pool is out of space.
#
function verify_nospc
{
	typeset out

	out=$(zfs create "$@" 2>&1)
	if (( $? == 0 )); then
		log_fail "'zfs create $*' unexpectedly succeeded"
	fi
	log_note "'zfs create $*': $out"
	if [[ $out != *"out of space"* ]]; then
		log_fail "'zfs create $*' reported the wrong error"
	fi
}

log_assert "'zfs create' should report the real error when it fails" \
	"after reading a key from a file"

log_must eval "echo $PASSPHRASE > $keyfile"

# A reservation of 1EiB cannot be satisfied by any pool that a test
# machine will have.
verify_nospc -o encryption=on -o keyformat=passphrase \
	-o keylocation=file://$keyfile -o refreservation=1e $fs
verify_nospc -V 1e -o encryption=on -o keyformat=passphrase \
	-o keylocation=file://$keyfile $vol

log_pass "'zfs create' reports the real error when it fails after" \
	"reading a key from a file"
