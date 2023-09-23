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

#define	MAX_TAG		8
#define	MAX_STACK	64

#pragma D option aggsize=8m
#pragma D option bufsize=16m
#pragma D option dynvarsize=16m
#pragma D option aggrate=0
#pragma D option stackframes=MAX_STACK
/*
 * Our D script needs to compile even if some of the TRANSLATE probes cannot
 * be found. Missing probes can be caused by older kernel, different
 * architecture, unloaded modules etc.
 */
#pragma D option zdefs

#if defined(ENABLE_SCHED)
#if defined(TRACE_PID)
#define TRACE_FILTER    / pid == 0 || pid == TRACE_PID /
#define TRACE_FILTER_COND(a)    / (pid == 0 || pid == TRACE_PID) && (a) /
#elif defined(TRACE_PGID)
#define TRACE_FILTER    / pid == 0 || curpsinfo->pr_pgid == TRACE_PGID /
#define TRACE_FILTER_COND(a)
    / (pid == 0 || curpsinfo->pr_pgid == TRACE_PGID) && (a) /
#else
#define TRACE_FILTER
#define TRACE_FILTER_COND(a)	/ (a) /
#endif
#else	/* ENABLE_SCHED */
#if defined(TRACE_PID)
#define TRACE_FILTER    / pid == TRACE_PID /
#define TRACE_FILTER_COND(a)    / (pid == TRACE_PID) && (a) /
#elif defined(TRACE_PGID)
#define TRACE_FILTER    / curpsinfo->pr_pgid == TRACE_PGID /
#define TRACE_FILTER_COND(a)    / (curpsinfo->pr_pgid == TRACE_PGID) && (a) /
#else
#define TRACE_FILTER	/ pid != 0 /
#define TRACE_FILTER_COND(a)    / (pid != 0) && (a) /
#endif
#endif /* ENABLE_SCHED */

/* Threshold to filter WAKEABLE latencies. */
#define FILTER_THRESHOLD	5000000
/* From thread.h */
#define T_WAKEABLE		2

/*
 * This array is used to store timestamp of when threads are enqueued
 * to dispatch queue.
 * self-> is not accessible when enqueue happens.
 */
unsigned long long lt_timestamps[int, int];

self unsigned int lt_is_block_wakeable;
self unsigned long long lt_sleep_start;
self unsigned long long lt_sleep_duration;
self unsigned long long lt_sch_delay;
self unsigned int lt_counter;		/* only used in low overhead */
self unsigned long long lt_timestamp;	/* only used in low overhead */
self unsigned int lt_stackp;
self unsigned int lt_prio[int];
self string lt_cause[int];

this unsigned int priority;
this string cause;

/*
 * Clean up everything, otherwise we will run out of memory.
 */
proc:::lwp-exit
{
	lt_timestamps[curpsinfo->pr_pid, curlwpsinfo->pr_lwpid] = 0;

	self->lt_sleep_start = 0;
	self->lt_is_block_wakeable = 0;
	self->lt_counter = 0;
	self->lt_timestamp = 0;

	/*
	 * Workaround: no way to clear associative array.
	 * We have to manually clear 0 ~ (MAX_TAG-1).
	 */

	self->lt_prio[0] = 0;
	self->lt_prio[1] = 0;
	self->lt_prio[2] = 0;
	self->lt_prio[3] = 0;
	self->lt_prio[4] = 0;
	self->lt_prio[5] = 0;
	self->lt_prio[6] = 0;
	self->lt_prio[7] = 0;

	self->lt_cause[0] = 0;
	self->lt_cause[1] = 0;
	self->lt_cause[2] = 0;
	self->lt_cause[3] = 0;
	self->lt_cause[4] = 0;
	self->lt_cause[5] = 0;
	self->lt_cause[6] = 0;
	self->lt_cause[7] = 0;
}

#if !defined(ENABLE_LOW_OVERHEAD)
/*
 * Log timestamp when a thread is taken off the CPU.
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
/lt_timestamps[args[1]->pr_pid, args[0]->pr_lwpid] != 0/
{
	lt_timestamps[args[1]->pr_pid, args[0]->pr_lwpid] = timestamp;
}

/*
 * Calculate latency when the thread is actually on the CPU.
 * This is necessary in order to get the right stack.
 */
this unsigned long long end;
this unsigned long long now;
sched::resume:on-cpu
/self->lt_sleep_start != 0/
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
 * Filter: drop all "large" latency when it is interruptible, i.e., sleep()
 * etc.
 */
#if defined(ENABLE_FILTER)
sched::resume:on-cpu
/self->lt_sleep_duration > FILTER_THRESHOLD &&
  self->lt_is_block_wakeable != 0/
{
	self->lt_sch_delay = 0;
	self->lt_sleep_duration = 0;
	self->lt_is_block_wakeable = 0;
}
#endif /* defined(ENABLE_FILTER) */

/*
 * Write sleep time to the aggregation.
 * lt_sleep_duration is the duration between the time when a thread is taken
 * off the CPU and the time when it is enqueued again.
 */
sched::resume:on-cpu
/self->lt_sleep_duration != 0/
{
	this->cause = self->lt_stackp > 0 ?
	    self->lt_cause[self->lt_stackp - 1] : "";
	this->priority = self->lt_stackp > 0 ?
	    self->lt_prio[self->lt_stackp - 1] : 0;

	@lt_call_count[pid, tid, stack(), this->cause,
	    this->priority] = count();
	@lt_call_sum[pid, tid, stack(), this->cause,
	    this->priority] = sum(self->lt_sleep_duration);
	@lt_call_max[pid, tid, stack(),  this->cause,
	    this->priority] = max(self->lt_sleep_duration);

	self->lt_is_block_wakeable = 0;	/* Clear the flag to avoid leak */
	self->lt_sleep_duration = 0;
}

/*
 * Write time spent in queue to the aggregation.
 * lt_sch_delay is the interval between the time when a thread becomes
 * runnable and the time when it is actually on the CPU.
 */
sched::resume:on-cpu
/self->lt_sch_delay != 0/
{
	@lt_named_count[pid, tid, "Wait for available CPU"] = count();
	@lt_named_sum[pid, tid, "Wait for available CPU"] =
	    sum(self->lt_sch_delay);
	@lt_named_max[pid, tid, "Wait for available CPU"] =
	    max(self->lt_sch_delay);

	self->lt_sch_delay = 0;
}

/*
 * Probes to track latency caused by spinning on a lock.
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
 * Probes to track latency caused by blocking on a lock.
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
 * Probes to track latency caused by synchronization objects.
 */
this int stype;
this unsigned long long wchan;
this unsigned long long wtime;

sched:::wakeup
/*
 * Currently we are unable to track wakeup from sched, because all its LWP IDs
 * are zero when we trace it and that makes lt_timestamps unusable.
 */
/args[1]->pr_pid != 0 &&
    lt_timestamps[args[1]->pr_pid, args[0]->pr_lwpid] != 0/
{
	this->stype = args[0]->pr_stype;
	this->wchan = args[0]->pr_wchan;
	/*
	 * We can use lt_timestamps[] here, because
	 * wakeup is always fired before enqueue.
	 * After enqueue, lt_timestamps[] will be overwritten.
	 */
	this->wtime = timestamp - lt_timestamps[args[1]->pr_pid,
	    args[0]->pr_lwpid];

	@lt_sync_count[args[1]->pr_pid, args[0]->pr_lwpid, this->stype,
	    this->wchan] = count();
	@lt_sync_sum[args[1]->pr_pid, args[0]->pr_lwpid, this->stype,
	    this->wchan] = sum(this->wtime);
	@lt_sync_max[args[1]->pr_pid, args[0]->pr_lwpid, this->stype,
	    this->wchan] = max(this->wtime);
}
#endif /* defined(ENABLE_SYNCOBJ) */

#else /* !defined(ENABLE_LOW_OVERHEAD) */

/*
 * This is the low overhead mode.
 * In order to reduce the number of instructions executed during each
 * off-cpu and on-cpu event, we do the following:
 *
 *	1. Use sampling and update aggregations only roughly 1/100 times
 *		(SAMPLE_TIMES).
 *	2. Do not track anything other than what is needed for "main" window.
 *	3. Use as few thread local variables as possible.
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
 * Calculate latency when a thread is actually on the CPU.
 */
this int need_skip;
sched::resume:on-cpu
/self->lt_timestamp != 0/
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
 * Track large latency first.
 */
sched::resume:on-cpu
/self->lt_timestamp > SAMPLE_THRESHOLD/
{
	this->cause = self->lt_stackp > 0 ?
	    self->lt_cause[self->lt_stackp - 1] : "";
	this->priority = self->lt_stackp > 0 ?
	    self->lt_prio[self->lt_stackp - 1] : 0;

	@lt_call_count[pid, tid, stack(), this->cause,
	    this->priority] = sum(1);
	@lt_call_sum[pid, tid, stack(), this->cause,
	    this->priority] = sum(self->lt_timestamp);
	@lt_call_max[pid, tid, stack(), this->cause,
	    this->priority] = max(self->lt_timestamp);

	self->lt_timestamp = 0;
}

/*
 * If we fall back to this probe, that means the latency is small and counter
 * has reached SAMPLE_TIMES.
 */
sched::resume:on-cpu
/self->lt_timestamp != 0/
{
	this->cause = self->lt_stackp > 0 ?
	    self->lt_cause[self->lt_stackp - 1] : "";
	this->priority = self->lt_stackp > 0 ?
	    self->lt_prio[self->lt_stackp - 1] : 0;

	/* Need +1 because lt_counter has not been updated in this cycle. */
	@lt_call_count[pid, tid, stack(), this->cause,
	    this->priority] = sum(self->lt_counter + 1);
	@lt_call_sum[pid, tid, stack(), this->cause,
	    this->priority] = sum((self->lt_counter + 1) * self->lt_timestamp);
	@lt_call_max[pid, tid, stack(), this->cause,
	    this->priority] = max(self->lt_timestamp);

	self->lt_timestamp = 0;
	self->lt_counter = 0;
}

#endif /* !defined(ENABLE_LOW_OVERHEAD) */

#define	TRANSLATE(entryprobe, returnprobe, cause, priority)		\
entryprobe								\
TRACE_FILTER_COND(self->lt_stackp == 0 ||				\
    (self->lt_stackp < MAX_TAG &&					\
    self->lt_prio[self->lt_stackp - 1] <= priority) )			\
{									\
	self->lt_prio[self->lt_stackp] = priority;			\
	self->lt_cause[self->lt_stackp] = cause;			\
	++self->lt_stackp;						\
}									\
returnprobe								\
TRACE_FILTER_COND(self->lt_stackp > 0 &&				\
    self->lt_cause[self->lt_stackp - 1] == cause)			\
{									\
	--self->lt_stackp;						\
	self->lt_cause[self->lt_stackp] = NULL;				\
}

/*
 * Syscalls have a priority of 10. This is to make sure that latency is
 * traced to one of the syscalls only if nothing else matches.
 * We put this special probe here because it uses "probefunc" variable instead
 * of a constant string.
 */

TRANSLATE(syscall:::entry, syscall:::return, probefunc, 10)
