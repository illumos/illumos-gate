/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2008-2009, Intel Corporation.
 * All Rights Reserved.
 */

#pragma D option aggsize=8m
#pragma D option bufsize=16m
#pragma D option dynvarsize=16m
#pragma D option aggrate=0
#pragma D option stackframes=64

#if defined(ENABLE_SCHED)
#define TRACE_FILTER
#define TRACE_FILTER_COND(a)	/ (a) /
#else
#define TRACE_FILTER	/ pid != 0 /
#define TRACE_FILTER_COND(a)	/ pid != 0 && (a) /
#endif

#define FILTER_THRESHOLD	5000000
/* From thread.h */
#define T_WAKEABLE		2

/*
 * This array is used to store the timestamp when threads are enqueued
 * to dispq.
 * self-> is not accessible when enqueue happens.
 */
unsigned long long lt_timestamps[int, int];

self unsigned int lt_is_block_wakeable;
self unsigned long long lt_sleep_start;
self unsigned long long lt_sleep_duration;
self unsigned long long lt_sch_delay;
self unsigned int lt_counter;		/* only used in low overhead */
self unsigned long long lt_timestamp;	/* only used in low overhead */

/*
 * Make sure we leave nothing behind,
 * otherwise memory will eventually run out.
 */
proc:::lwp-exit
{
	lt_timestamps[curpsinfo->pr_pid, curlwpsinfo->pr_lwpid] = 0;
	self->lt_sleep_start = 0;
	self->lt_is_block_wakeable = 0;
	self->lt_counter = 0;
	self->lt_timestamp = 0;
}

#if !defined(ENABLE_LOW_OVERHEAD)
/*
 * Log timestamp when a thread is off CPU.
 */
sched::resume:off-cpu
TRACE_FILTER_COND(curlwpsinfo->pr_state == SSLEEP)
{
	self->lt_sleep_start = timestamp;
	self->lt_is_block_wakeable = curthread->t_flag & T_WAKEABLE;
	lt_timestamps[curpsinfo->pr_pid, curlwpsinfo->pr_lwpid] =
	    self->lt_sleep_start;
}

/*
 * Log timestamp when a thread is put on a dispatch queue and becomes runnable.
 */
sched:::enqueue
/ lt_timestamps[args[1]->pr_pid, args[0]->pr_lwpid] != 0 /
{
	lt_timestamps[args[1]->pr_pid, args[0]->pr_lwpid] = timestamp;
}

/*
 * Calculate latencies when the thread is actually on CPU.
 * This is necessary to get the right stack().
 */
this unsigned long long end;
this unsigned long long now;
sched::resume:on-cpu
/ self->lt_sleep_start != 0 /
{
	this->end = lt_timestamps[curpsinfo->pr_pid, curlwpsinfo->pr_lwpid];
	this->now = timestamp;
	lt_timestamps[curpsinfo->pr_pid, curlwpsinfo->pr_lwpid] = 0;
	this->end = (this->end != 0 && this->end != self->lt_sleep_start)
	    ? this->end : this->now;
	self->lt_sch_delay = this->now - this->end;
	self->lt_sleep_duration = this->end - self->lt_sleep_start;
	self->lt_sleep_start = 0;
}

/*
 * Filter: drop all "large" latencies when it is wakeable,
 * trying to filter sleep() etc.
 */
#if defined(ENABLE_FILTER)
sched::resume:on-cpu
/ self->lt_sleep_duration > FILTER_THRESHOLD &&
  self->lt_is_block_wakeable != 0 /
{
	self->lt_sch_delay = 0;
	self->lt_sleep_duration = 0;
	self->lt_is_block_wakeable = 0;
}
#endif /* defined(ENABLE_FILTER) */

/*
 * Write sleep time to the aggregation.
 * lt_sleep_duration is from thread off cpu to it is enqueued again.
 */
sched::resume:on-cpu
/ self->lt_sleep_duration != 0 /
{
	@lt_call_count[pid, tid, stack()] = count();
	@lt_call_sum[pid, tid, stack()] = sum(self->lt_sleep_duration);
	@lt_call_max[pid, tid, stack()] = max(self->lt_sleep_duration);
	self->lt_is_block_wakeable = 0;	/* Clean the flag to avoid leak */
	self->lt_sleep_duration = 0;
}

/*
 * Write time spent in queue to the aggregation.
 * lt_sch_delay: the interval between "thread runnable" and "thread on cpu".
 */
sched::resume:on-cpu
/ self->lt_sch_delay != 0 /
{
	@lt_named_count[pid, tid, "Wait for available CPU"] = count();
	@lt_named_sum[pid, tid, "Wait for available CPU"] =
	    sum(self->lt_sch_delay);
	@lt_named_max[pid, tid, "Wait for available CPU"] =
	    max(self->lt_sch_delay);
	self->lt_sch_delay = 0;
}

/*
 * Probes that tracks lock spinning
 */
lockstat:::adaptive-spin
TRACE_FILTER
{
	@lt_named_count[pid, tid, "Adapt. lock spin"] = count();
	@lt_named_sum[pid, tid, "Adapt. lock spin"] = sum(arg1);
	@lt_named_max[pid, tid, "Adapt. lock spin"] = max(arg1);
}

lockstat:::spin-spin
TRACE_FILTER
{
	@lt_named_count[pid, tid, "Spinlock spin"] = count();
	@lt_named_sum[pid, tid, "Spinlock spin"] = sum(arg1);
	@lt_named_max[pid, tid, "Spinlock spin"] = max(arg1);
}

/*
 * Probes that tracks lock blocking
 */
lockstat:::adaptive-block
TRACE_FILTER
{
	@lt_named_count[pid, tid, "#Adapt. lock block"] = count();
	@lt_named_sum[pid, tid, "#Adapt. lock block"] = sum(arg1);
	@lt_named_max[pid, tid, "#Adapt. lock block"] = max(arg1);
}

lockstat:::rw-block
TRACE_FILTER
{
	@lt_named_count[pid, tid, "#RW. lock block"] = count();
	@lt_named_sum[pid, tid, "#RW. lock block"] = sum(arg1);
	@lt_named_max[pid, tid, "#RW. lock block"] = max(arg1);
}

#if defined(ENABLE_SYNCOBJ)
/*
 * Probes that tracks synchronization objects.
 */
this int stype;
this unsigned long long wchan;
this unsigned long long wtime;
sched:::wakeup
/*
 * Currently we are not able to track wakeup from sched, because all lwpid
 * are zero for when we trace sched. That makes lt_timestamps not usable.
 */
/ args[1]->pr_pid != 0 &&
  lt_timestamps[args[1]->pr_pid, args[0]->pr_lwpid] != 0 /
{
	this->stype = args[0]->pr_stype;
	this->wchan = args[0]->pr_wchan;
	/*
	 * We can use lt_timestamps[] here, because
	 * wakeup is always fired before enqueue.
	 * After enqueue, lt_timestamps[] will be overwritten.
	 */
	this->wtime = timestamp -
	    lt_timestamps[args[1]->pr_pid, args[0]->pr_lwpid];
	@lt_sync_count[args[1]->pr_pid, args[0]->pr_lwpid, this->stype,
	    this->wchan] = count();
	@lt_sync_sum[args[1]->pr_pid, args[0]->pr_lwpid, this->stype,
	    this->wchan] = sum(this->wtime);
	@lt_sync_max[args[1]->pr_pid, args[0]->pr_lwpid, this->stype,
	    this->wchan] = max(this->wtime);
}
#endif  /* defined(ENABLE_SYNCOBJ) */

#else /* !defined(ENABLE_LOW_OVERHEAD) */

/*
 * This is the low overhead mode.
 * In order to reduce the number of instructions executed during each
 * off-cpu and on-cpu event, we do:
 * 1. Use sampling, only update aggregations roughly 1/100 times (SAMPLE_TIMES).
 * 2. Do not track anything other than needed for "main" window.
 * 3. Use as few thread local variables as possible.
 */

#define SAMPLE_TIMES		100
#define SAMPLE_THRESHOLD	50000000

/*
 * Log timestamp when a thread is off CPU.
 */
sched::resume:off-cpu
TRACE_FILTER_COND(curlwpsinfo->pr_state == SSLEEP)
{
	self->lt_timestamp = timestamp;
#if defined(ENABLE_FILTER)
	self->lt_is_block_wakeable = curthread->t_flag & T_WAKEABLE;
#endif /* defined(ENABLE_FILTER) */
}

/*
 * Calculate latencies when the thread is actually on CPU.
 */
this int need_skip;
sched::resume:on-cpu
/ self->lt_timestamp != 0 /
{
	self->lt_timestamp = timestamp - self->lt_timestamp;

#if defined(ENABLE_FILTER)
	self->lt_timestamp =
	    (self->lt_timestamp > FILTER_THRESHOLD &&
	    self->lt_is_block_wakeable != 0) ? 0 : self->lt_timestamp;
	self->lt_is_block_wakeable = 0;
#endif /* defined(ENABLE_FILTER) */

	this->need_skip = (self->lt_counter < (SAMPLE_TIMES - 1) &&
	    self->lt_timestamp <= SAMPLE_THRESHOLD) ? 1 : 0;
	self->lt_timestamp = this->need_skip ? 0 : self->lt_timestamp;
	self->lt_counter += this->need_skip;
}

/*
 * Log large ones first.
 */
sched::resume:on-cpu
/ self->lt_timestamp > SAMPLE_THRESHOLD /
{
	@lt_call_count[pid, tid, stack()] = sum(1);
	@lt_call_sum[pid, tid, stack()] = sum(self->lt_timestamp);
	@lt_call_max[pid, tid, stack()] = max(self->lt_timestamp);

	self->lt_timestamp = 0;
}

/*
 * If we fall to this probe, this must be a small latency and counter
 * reaches SAMPLE_TIMES.
 */
sched::resume:on-cpu
/ self->lt_timestamp != 0 /
{
	/* Need +1 because lt_counter has not been updated in this cycle. */
	@lt_call_count[pid, tid, stack()] = sum(self->lt_counter + 1);
	@lt_call_sum[pid, tid, stack()] =
	    sum((self->lt_counter + 1) * self->lt_timestamp);
	@lt_call_max[pid, tid, stack()] = max(self->lt_timestamp);

	self->lt_timestamp = 0;
	self->lt_counter = 0;
}

#endif /* !defined(ENABLE_LOW_OVERHEAD) */
