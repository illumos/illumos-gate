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

. $STF_SUITE/tests/functional/slog/slog.kshlib

#
# DESCRIPTION:
#	Verify that an unwritten log record for a write to a file that
#	was since freed is not logged against a new object that reuses
#	the file's object number.
#
# STRATEGY:
#	1. Fill the low object numbers of a file system, and reopen it so
#	   that new objects reuse the lowest free object numbers.
#	2. Freeze the pool, so that log records are kept until a commit.
#	3. Write to a file without syncing it, then rename another file
#	   over it.  Renaming over a file does not drop its pending
#	   write records, unlike removing it.
#	4. Let the free of the file's object sync, and create directories
#	   until one reuses the file's object number.
#	5. Commit the log.  Without the fix, the pending write is logged
#	   for the directory.  Replaying it fails with EISDIR, which ends
#	   replay and loses every later record.  For an indirect write
#	   (logbias=throughput), a DEBUG kernel panics in zfs_get_data()
#	   instead.
#	6. Write and sync a new file, export and import to replay the log,
#	   and check the new file, the directory and the renamed file.
#	7. Repeat with logbias=throughput.
#

verify_runnable "global"

function cleanup_reused
{
	pbind -u $$ >/dev/null 2>&1
	cleanup
}

#
# Print the object number of file or directory $1.
#
function objnum
{
	ls -di $1 | awk '{print $1}'
}

#
# Run steps 1-6 with logbias $1 and a pending write of $2 bytes.
#
function reuse_and_replay
{
	typeset logbias=$1
	typeset bs=$2
	typeset fs=/$TESTPOOL/$TESTFS
	typeset cpus=$(psrinfo | awk '$2 == "on-line" {print $1}')
	typeset cpu

	log_note "logbias=$logbias, pending write of $bs bytes"
	log_must zpool create $TESTPOOL $VDEV log mirror $LDEV
	log_must zfs create -o compression=off -o logbias=$logbias \
	    $TESTPOOL/$TESTFS

	#
	# Object numbers are handed out from per-CPU chunks.  Fill the low
	# object numbers from one CPU, so that they have no holes.  After an
	# import, each CPU starts in a new chunk at the beginning and skips
	# to the next free object number, so any CPU that has not allocated
	# since then gets the lowest free object number.
	#
	log_must zpool export $TESTPOOL
	log_must zpool import -d $VDIR $TESTPOOL
	log_must pbind -b ${cpus%%[[:space:]]*} $$
	log_must mkdir $fs/fill
	log_must mkfiles $fs/fill/f 4096
	log_must pbind -u $$
	log_must zpool export $TESTPOOL
	log_must zpool import -d $VDIR $TESTPOOL

	# Make sure the dataset has a ZIL header before freezing.
	log_must dd if=/dev/zero of=$fs/sync oflag=dsync,sync bs=1 count=1
	log_must zpool freeze $TESTPOOL

	log_must eval "echo renamed > $fs/b"
	log_must dd if=/dev/urandom of=$fs/a bs=$bs count=1
	typeset obj=$(objnum $fs/a)
	log_note "sync, b and a are objects $(objnum $fs/sync)," \
	    "$(objnum $fs/b), $obj"
	log_must mv $fs/b $fs/a
	log_must zpool sync $TESTPOOL

	typeset dir=""
	for cpu in $cpus; do
		log_must pbind -b $cpu $$
		log_must mkdir $fs/dir.$cpu
		log_note "dir.$cpu is object $(objnum $fs/dir.$cpu)"
		if [[ $(objnum $fs/dir.$cpu) == $obj ]]; then
			dir=$fs/dir.$cpu
			break
		fi
	done
	log_must pbind -u $$
	[[ -n $dir ]] || log_fail "No new directory reused object $obj"
	log_note "$dir reused object $obj of the freed file"

	# Commit the log, including the pending write to object $obj.
	log_must lockfs -f $fs

	log_must eval "echo synced | dd of=$fs/c oflag=sync"

	log_must zfs unmount $fs
	log_must zpool export $TESTPOOL
	log_must zpool import -f -d $VDIR $TESTPOOL

	log_must eval "echo synced | cmp - $fs/c"
	log_must eval "echo renamed | cmp - $fs/a"
	log_must test -d $dir
	log_must rmdir $dir

	log_must zpool destroy $TESTPOOL
}

log_assert "A write record for a freed file is not logged for a new" \
    "object with the same object number."
log_onexit cleanup_reused
log_must setup

reuse_and_replay latency 4k
reuse_and_replay throughput 128k

log_pass "A write record for a freed file is not logged for a new" \
    "object with the same object number."
