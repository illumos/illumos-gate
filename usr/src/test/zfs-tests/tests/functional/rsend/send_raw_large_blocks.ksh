#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or https://opensource.org/licenses/CDDL-1.0.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2022, George Amanakis. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/rsend/rsend.kshlib

#
# Description:
# Receiving a snapshot with large blocks and raw sending it succeeds.
#
# Strategy:
# 1) Create a file with large blocks in a filesystem with recordsize=1m.
# 2) Snapshot and send with large_blocks enabled to a new encrypted
#	filesystem.
# 3) Verify that the large_blocks feature is active on the received
#	filesystem and its snapshot.
# 4) Raw send the received snapshot. If the large_blocks feature is not
#	active on that snapshot, the large blocks are split and the raw send
#	dereferences a NULL block pointer.
#

verify_runnable "both"

log_assert "Receiving and raw sending a snapshot with large blocks succeeds"

sendds=$POOL/sendlb
recvds=$POOL/recvlb
keyfile=$BACKDIR/keylb
backup=$BACKDIR/backuplb
raw_backup=$BACKDIR/raw_backuplb

function cleanup
{
	datasetexists $recvds && log_must zfs destroy -r $recvds
	datasetexists $sendds && log_must zfs destroy -r $sendds
	log_must rm -f $keyfile $backup $raw_backup
}

log_onexit cleanup

#
# Fail if the per-dataset large_blocks feature is not active on the given
# dataset, as recorded on disk in its DSL dataset object.
#
function check_large_blocks_active
{
	typeset ds=$1
	typeset dsobj=$(get_prop objsetid $ds)

	if ! zdb -dddd $POOL $dsobj | grep -q 'org.open-zfs:large_blocks'; then
		log_fail "large_blocks feature not active on $ds (object $dsobj)"
	fi
	log_note "large_blocks feature active on $ds (object $dsobj)"
}

log_must eval "echo 'password' > $keyfile"

log_must zfs create -o recordsize=1m $sendds
log_must dd if=/dev/urandom of=/$sendds/file bs=1024k count=2
log_must zfs snapshot $sendds@snap1

log_must eval "zfs send -L $sendds@snap1 > $backup"
log_must eval "zfs recv -o encryption=on -o keyformat=passphrase \
    -o keylocation=file://$keyfile -o primarycache=none \
    -o recordsize=1m $recvds < $backup"

sync_pool $POOL
check_large_blocks_active $recvds
check_large_blocks_active $recvds@snap1

log_must eval "zfs send -w $recvds@snap1 > $raw_backup"

log_pass "Receiving and raw sending a snapshot with large blocks succeeds"
