#!/usr/bin/ksh -p
#
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
# Copyright (c) 2016 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/snapshot/snapshot.cfg

#
# DESCRIPTION:
#
# This test ensures that the following race condition does not
# take place:
#
# 1] A sync thread inserts a new entry in the deadlist of a
#    snapshot. The dle_bpobj at that entry currently is the
#    empty bpobj (our sentinel), so we close it and we are
#    about to reopen it. (see dle_enqueue())
#
# 2] At the same time a thread executing an administrative
#    command that uses dsl_deadlist_space_range() is about
#    to dereference that same bpobj that was just closed
#    and therefore is NULL.
#
# 3] The sync thread loses the race and we dereference the
#    NULL pointer in the kernel.
#
# STRATEGY:
#
# 1. Setup a folder and create a bunch of test files. Take a
#    snapshot right after you create a new test file.
# 2. Start DTrace in the background to put a delay in the
#    sync thread after it closes the empty bpobj and before
#    it reopens it.
# 3. Start a process in the backgroud that runs zfs-destroy
#    dry-runs in an infinite loop. The idea is to keep calling
#    dsl_deadlist_space_range().
# 4. Go ahead and start removing the test files. This should
#    start populating the deadlist of each snapshot with
#    entries and go through the dle_enqueue() target code.
# 5. If the test passes, kill the process running on a loop
#    and dtrace, and cleanup the dataset.
#

verify_runnable "both"


DLDS="dl_race"

function cleanup
{
	log_must kill -9 $DLOOP_PID $DTRACE_PID
	log_must zfs destroy -fR $TESTPOOL/$TESTFS/$DLDS
}

function setup
{
	log_must zfs create $TESTPOOL/$TESTFS/$DLDS
	for i in {1..50}; do
		log_must mkfile 1m /$TESTDIR/$DLDS/dl_test_file$i
		log_must zfs snapshot $TESTPOOL/$TESTFS/$DLDS@snap${i}
	done
}

function destroy_nv_loop
{
	while true; do
		log_must zfs destroy -nv $TESTPOOL/$TESTFS/$DLDS@snap1%snap50
	done
}

log_onexit cleanup

setup
log_must sync

log_must dtrace -qwn "fbt::bpobj_decr_empty:entry { chill(500000000); }" &
DTRACE_PID="$!"
sleep 1

destroy_nv_loop &
DLOOP_PID="$!"
sleep 1

for i in {1..50}; do
	log_must rm /$TESTDIR/$DLDS/dl_test_file$i
done
log_must sync

log_pass "There should be no race condition when an administrative command" \
    " attempts to read a deadlist's entries at the same time a that a sync" \
    " thread is manipulating it."
