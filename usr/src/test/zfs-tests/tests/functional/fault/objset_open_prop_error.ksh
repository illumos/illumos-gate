#!/bin/ksh -p
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

#
# DESCRIPTION:
#	When dmu_objset_open_impl() fails to register one of a dataset's
#	property callbacks after it has registered others, it must remove
#	the ones it registered before it frees the objset.  Otherwise the
#	dataset keeps callbacks for the freed objset, and evicting the
#	dataset panics a DEBUG kernel in dsl_dataset_evict_async().
#
# STRATEGY:
#	1. Create a file system with primarycache set locally, under a
#	   parent with no properties set.  Registering the first callback
#	   (primarycache) then reads only the child's property ZAP, and
#	   registering the second (secondarycache) also reads the parent's.
#	   Disable embedded_data, so that the parent's small property ZAP
#	   is stored in a block of its own rather than in its block pointer.
#	2. Turn off the dbuf caches, so that blocks are not kept in memory
#	   after use.  Import the pool read-only and without mounting, so
#	   that no objset stays open.
#	3. Inject read errors on the parent's property ZAP, flush the ARC,
#	   and open the child's objset.  The open must fail.  The dataset
#	   is evicted when the open releases it.
#	4. Clear the injection, and check that the child can be opened.
#
#	This test detects the bug only on a DEBUG kernel, where it relies on
#	the assertion in list_destroy().  On a non-DEBUG kernel the stale
#	callbacks are simply leaked, and the test passes even without the
#	fix.
#

. $STF_SUITE/include/libtest.shlib

verify_runnable "global"

DISK=${DISKS%% *}
PARENT=$TESTPOOL/parent
CHILD=$PARENT/child
DBUF_CACHE=$(get_tunable dbuf_cache_max_bytes)
DBUF_MD_CACHE=$(get_tunable dbuf_metadata_cache_max_bytes)

function cleanup
{
	zinject -c all >/dev/null 2>&1
	set_tunable64 dbuf_cache_max_bytes $DBUF_CACHE >/dev/null
	set_tunable64 dbuf_metadata_cache_max_bytes $DBUF_MD_CACHE >/dev/null
	if poolexists $TESTPOOL && \
	    [[ $(get_pool_prop readonly $TESTPOOL) == "on" ]]; then
		zpool export $TESTPOOL
		zpool import $TESTPOOL
	fi
	destroy_pool $TESTPOOL
}

#
# Print the object number of the property ZAP of a dataset's DSL directory.
#
function props_zapobj # dataset
{
	typeset pool=${1%%/*}
	typeset dsobj=$(get_prop objsetid $1)
	typeset dirobj=$(zdb -dddd $pool $dsobj | \
	    nawk '$1 == "dir_obj" {print $3}')

	zdb -dddd $pool $dirobj | nawk '$1 == "props_zapobj" {print $3}'
}

log_assert "A failed objset open removes the property callbacks it registered"
log_onexit cleanup

log_must zpool create -f -o feature@embedded_data=disabled $TESTPOOL $DISK
log_must zfs create $PARENT
log_must zfs create -o primarycache=all $CHILD
sync_pool $TESTPOOL

typeset obj=$(props_zapobj $PARENT)
[[ -n $obj ]] || log_fail "cannot find the property ZAP of $PARENT"
log_note "property ZAP of $PARENT is MOS object $obj"

log_must zpool export $TESTPOOL
log_must set_tunable64 dbuf_cache_max_bytes 0
log_must set_tunable64 dbuf_metadata_cache_max_bytes 0
log_must zpool import -o readonly=on -N $TESTPOOL
log_must zinject -b $(printf "0:%x:0:0" $obj) $TESTPOOL
log_must zinject -a

#
# If the failed open leaves property callbacks registered, a DEBUG kernel
# panics when the dataset is evicted.
#
log_mustnot zfs list $CHILD

log_must zinject -c all
log_must zfs list $CHILD

log_pass "A failed objset open removes the property callbacks it registered"
