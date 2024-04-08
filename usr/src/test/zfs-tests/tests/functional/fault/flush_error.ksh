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
#	zinject can inject errors into the cache flushes of a device
#	("-T ioctl"), and a failed cache flush, injected or real, does not
#	make ZFS probe or reopen the device.
#
# STRATEGY:
#	1. Create a pool on a file and inject EIO into its flushes.  (A file
#	   vdev is used because the flushes of a disk may fail on their own,
#	   with ENOTSUP, before the injection is checked.)
#	2. Write files and sync the pool a few times, counting with DTrace
#	   the failed flushes and the calls to vdev_probe() and
#	   vdev_reopen() for the pool.
#	3. Verify that flushes failed with EIO, that the device was neither
#	   probed nor reopened, that the pool has no errors and that the
#	   files can be read.
#	4. Repeat 2 and 3 without injection on a pool on a ramdisk, which
#	   does not support cache flushes, so every flush fails with ENOTSUP.
#

. $STF_SUITE/include/libtest.shlib

verify_runnable "global"

VDEV=$TEST_BASE_DIR/flush_error.vdev
RAMDISK=zts_flush_error
RDPOOL=${TESTPOOL}_rd
DOUT=$TEST_BASE_DIR/flush_error.dtrace.out
typeset dtrace_pid=""
typeset -i flusherr eio probe reopen

function cleanup
{
	zinject -c all >/dev/null 2>&1
	if [[ -n $dtrace_pid ]]; then
		kill -TERM $dtrace_pid >/dev/null 2>&1
		wait $dtrace_pid
	fi
	destroy_pool $TESTPOOL
	destroy_pool $RDPOOL
	if [[ -e /dev/ramdisk/$RAMDISK ]]; then
		log_must ramdiskadm -d $RAMDISK
	fi
	rm -f $DOUT $VDEV
}

#
# Count, for one pool, the leaf vdev flushes (ZIO_TYPE_IOCTL zios, 5) that
# failed (in all, and with EIO) and the calls to vdev_probe() and
# vdev_reopen(), while files are written and the pool synced.  Sets
# flusherr, eio, probe and reopen.
#
function count_flush_errors # pool
{
	typeset pool=$1

	rm -f $DOUT
	dtrace -q -o $DOUT -n '
	    BEGIN { printf("ready\n"); }
	    fbt::zio_done:entry
	    /args[0]->io_type == 5 && args[0]->io_vd != NULL &&
	    args[0]->io_vd->vdev_children == 0 && args[0]->io_error != 0 &&
	    stringof(args[0]->io_spa->spa_name) == $$1/
	    { @flusherr = count(); }
	    fbt::zio_done:entry
	    /args[0]->io_type == 5 && args[0]->io_vd != NULL &&
	    args[0]->io_vd->vdev_children == 0 && args[0]->io_error == 5 &&
	    stringof(args[0]->io_spa->spa_name) == $$1/
	    { @eio = count(); }
	    fbt::vdev_probe:entry
	    /stringof(args[0]->vdev_spa->spa_name) == $$1/
	    { @probe = count(); }
	    fbt::vdev_reopen:entry
	    /stringof(args[0]->vdev_spa->spa_name) == $$1/
	    { @reopen = count(); }
	    END {
		printa("flusherr %@d\n", @flusherr);
		printa("eio %@d\n", @eio);
		printa("probe %@d\n", @probe);
		printa("reopen %@d\n", @reopen);
	    }' $pool &
	dtrace_pid=$!

	typeset -i i=0
	while ! grep -q ready $DOUT 2>/dev/null; do
		((i++ < 60)) || log_fail "dtrace did not start"
		sleep 1
	done

	for i in 1 2 3 4 5; do
		log_must dd if=/dev/urandom of=/$pool/file.$i bs=128k count=8 \
		    2>/dev/null
		log_must python -c "import os; \
		    os.fsync(os.open('/$pool/file.$i', os.O_RDONLY))"
		log_must zpool sync $pool
	done
	# Let any probe or reopen requested from the last sync run.
	sleep 5

	# A background job ignores SIGINT, so stop dtrace with SIGTERM.
	kill -TERM $dtrace_pid
	wait $dtrace_pid
	dtrace_pid=""

	flusherr=$(nawk '$1 == "flusherr" {print $2}' $DOUT)
	eio=$(nawk '$1 == "eio" {print $2}' $DOUT)
	probe=$(nawk '$1 == "probe" {print $2}' $DOUT)
	reopen=$(nawk '$1 == "reopen" {print $2}' $DOUT)
	log_note "$pool: failed flushes $flusherr (EIO $eio)," \
	    "probes $probe, reopens $reopen"
}

function check_pool # pool
{
	typeset pool=$1
	typeset -i i

	[[ $(get_pool_prop health $pool) == ONLINE ]] || \
	    log_fail "$pool is not healthy"
	log_mustnot eval "zpool status -v $pool | grep -q 'errors: [1-9]'"
	zpool status $pool | nawk '
	    NF == 5 && $3 ~ /^[0-9]/ &&
	    ($3 != "0" || $4 != "0" || $5 != "0") { bad = 1 }
	    END { exit bad }' || log_fail "$pool has I/O errors"
	for i in 1 2 3 4 5; do
		log_must eval "cat /$pool/file.$i > /dev/null"
	done
}

log_assert "Flush errors can be injected and do not probe or reopen the vdev"
log_onexit cleanup

log_note "Injecting EIO into the flushes of $VDEV"
log_must mkfile $MINVDEVSIZE $VDEV
log_must zpool create -f $TESTPOOL $VDEV
log_must zinject -d $VDEV -e io -T ioctl $TESTPOOL
count_flush_errors $TESTPOOL
((eio > 0)) || log_fail "no flush errors were injected"
((probe == 0 && reopen == 0)) || \
    log_fail "flush errors probed or reopened $VDEV"
log_must zinject -c all
check_pool $TESTPOOL
destroy_pool $TESTPOOL

log_note "Flushing a ramdisk, which does not support cache flushes"
log_must ramdiskadm -a $RAMDISK 256m
log_must zpool create -f $RDPOOL /dev/ramdisk/$RAMDISK
count_flush_errors $RDPOOL
((flusherr > 0)) || log_fail "flushes of the ramdisk did not fail"
((probe == 0 && reopen == 0)) || \
    log_fail "flush errors probed or reopened the ramdisk"
check_pool $RDPOOL

log_pass "Flush errors can be injected and do not probe or reopen the vdev"
