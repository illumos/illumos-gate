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
# Copyright (c) 2015, 2016 by Delphix. All rights reserved.
#

#
# Description:
# Trigger fio runs using the random_writes job file. The number of runs and
# data collected is determined by the PERF_* variables. See do_fio_run for
# details about these variables.
#
# Prior to each fio run the dataset is recreated, and fio writes new files
# into an otherwise empty pool.
#
# Thread/Concurrency settings:
#    PERF_NTHREADS defines the number of files created in the test filesystem,
#    as well as the number of threads that will simultaneously drive IO to
#    those files.  The settings chosen are from measurements in the
#    PerfAutoESX/ZFSPerfESX Environments, selected at concurrency levels that
#    are at peak throughput but lowest latency.  Higher concurrency introduces
#    queue time latency and would reduce the impact of code-induced performance
#    regressions.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/perf/perf.shlib

function cleanup
{
	recreate_perf_pool
}

log_onexit cleanup

recreate_perf_pool
populate_perf_filesystems

# Aim to fill the pool to 50% capacity while accounting for a 3x compressratio.
export TOTAL_SIZE=$(($(get_prop avail $PERFPOOL) * 3 / 2))

# Variables for use by fio.
if [[ -n $PERF_REGRESSION_WEEKLY ]]; then
	export PERF_RUNTIME=${PERF_RUNTIME:-$PERF_RUNTIME_WEEKLY}
	export PERF_RUNTYPE=${PERF_RUNTYPE:-'weekly'}
	export PERF_NTHREADS=${PERF_NTHREADS:-'1 4 8 16 32 64 128'}
	export PERF_NTHREADS_PER_FS=${PERF_NTHREADS_PER_FS:-'0'}
	export PERF_SYNC_TYPES=${PERF_SYNC_TYPES:-'0 1'}
	export PERF_IOSIZES=${PERF_IOSIZES:-'8k 64k 256k'}
elif [[ -n $PERF_REGRESSION_NIGHTLY ]]; then
	export PERF_RUNTIME=${PERF_RUNTIME:-$PERF_RUNTIME_NIGHTLY}
	export PERF_RUNTYPE=${PERF_RUNTYPE:-'nightly'}
	export PERF_NTHREADS=${PERF_NTHREADS:-'32 128'}
	export PERF_NTHREADS_PER_FS=${PERF_NTHREADS_PER_FS:-'0'}
	export PERF_SYNC_TYPES=${PERF_SYNC_TYPES:-'1'}
	export PERF_IOSIZES=${PERF_IOSIZES:-'8k'}
fi

# Set up the scripts and output files that will log performance data.
lun_list=$(pool_to_lun_list $PERFPOOL)
log_note "Collecting backend IO stats with lun list $lun_list"
export collect_scripts=(
    "kstat zfs:0 1"  "kstat"
    "vmstat -T d 1"       "vmstat"
    "mpstat -T d 1"       "mpstat"
    "iostat -T d -xcnz 1" "iostat"
    "dtrace -Cs $PERF_SCRIPTS/io.d $PERFPOOL $lun_list 1" "io"
    "dtrace  -s $PERF_SCRIPTS/profile.d"                  "profile"
)

log_note "Random writes with $PERF_RUNTYPE settings"
do_fio_run random_writes.fio true false
log_pass "Measure IO stats during random write load"
