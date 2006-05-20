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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <atomic.h>
#include <sys/types.h>
#include <time.h>

#include "sfx4500-disk.h"
#include "fault_mgr.h"
#include "schg_mgr.h"

/* Fault-polling thread data */
static pthread_t	g_fmt_tid;
static thread_state_t	g_fmt_req_state = TS_NOT_RUNNING;
static pthread_cond_t	g_fmt_cvar = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t	g_fmt_mutex = PTHREAD_MUTEX_INITIALIZER;
static boolean_t	g_fmt_spawned = B_FALSE;

static boolean_t
disk_is_faulty(diskmon_t *diskp)
{
	/*
	 * Errors accessing the disk are not counted as faults:
	 */
	return (disk_fault_analyze(diskp) > 0 ? B_TRUE : B_FALSE);
}

static void
setup_fault_injection(diskmon_t *disklistp, int i)
{
	uint_t seed;

	while (disklistp != NULL) {
		/* We just want the low bits of hrtime anyway */
		seed = (uint_t)gethrtime();

		disklistp->fault_inject_count = (rand_r(&seed) % (i + 1)) + 1;

		log_msg(MM_FAULTMGR, "[%s] Injecting a fault every %u "
		    "analyses.\n", disklistp->location,
		    disklistp->fault_inject_count);

		disklistp = disklistp->next;
	}
}

static void
disk_fault_monitor_analyze_disk(diskmon_t *diskp)
{
	atomic_inc_uint(&diskp->analysis_generation);

	log_msg(MM_FAULTMGR, "[%s] Analyzing disk for faults\n",
	    diskp->location);

	if (diskp->fmip && disk_is_faulty(diskp)) {

		diskp->faults_outstanding = B_TRUE;
		log_msg(MM_FAULTMGR, "[%s] Disk fault(s) detected...\n",
			    diskp->location);
		dm_state_change(diskp, HPS_FAULTED);

	} else if (diskp->fault_inject_count != 0 &&
	    (diskp->analysis_generation % diskp->fault_inject_count) == 0) {

		diskp->analysis_generation = 0;

		log_msg(MM_FAULTMGR, "[%s] FAULT INJECTED\n", diskp->location);

		create_fake_faults(diskp);
		dm_state_change(diskp, HPS_FAULTED);

	} else {
		log_msg(MM_FAULTMGR, "[%s] No faults detected\n",
		    diskp->location);
	}
}

/*
 * The fault monitor thread polls each disk in the disk list, at the
 * fault polling frequency specified in the global property (or the default
 * if no such property exists).  This thread is also responsible for injecting
 * fake faults, in accordance with the global fault injection property.
 *
 * When the thread starts, it performs a fault analysis on each disk whose
 * `due' time is 0 (disks that have not yet been analyzed), then sets the
 * due time to the current time + the fault polling interval.
 */
static void
disk_fault_monitor_thread(void *vdisklistp)
{
	diskmon_t *disklistp = (diskmon_t *)vdisklistp;
	diskmon_t *diskp;
	time_t fault_polling_interval = (time_t)DEFAULT_FAULT_POLLING_INTERVAL;
	time_t earliest_due;
	time_t curtime;
	time_t nexttime;
	struct timespec tspec;
	int i;

	if (dm_prop_lookup_int(dm_global_proplist(), GLOBAL_PROP_FAULT_POLL, &i)
	    == 0)
		fault_polling_interval = (time_t)i;

	if (dm_prop_lookup_int(dm_global_proplist(), GLOBAL_PROP_FAULT_INJ, &i)
	    == 0 && i > 0) {
		setup_fault_injection(disklistp, i);
	}

	assert(pthread_mutex_lock(&g_fmt_mutex) == 0);
	while (g_fmt_req_state != TS_EXIT_REQUESTED) {

		/*
		 * Analyze all disks that are due for analysis
		 */
		diskp = disklistp;
		earliest_due = -1;
		while (g_fmt_req_state != TS_EXIT_REQUESTED && diskp != NULL) {

			curtime = time(0);
			assert(pthread_mutex_lock(&diskp->manager_mutex) == 0);

			/*
			 * If the disk is configured (it has a device node
			 * associated with it that we can talk to), and if
			 * there are no faults outstanding (faults that we
			 * previously informed the state-change thread about
			 * but that may not have been consumed yet), and
			 * if we're due for a fault analysis, then do one.
			 */
			if (DISK_STATE(diskp->state) == HPS_CONFIGURED &&
			    !diskp->faults_outstanding &&
			    (diskp->due == 0 || diskp->due <= curtime)) {

				log_msg(MM_FAULTMGR, "Analyzing disk %s...\n",
					    diskp->location);

				disk_fault_monitor_analyze_disk(diskp);
				diskp->due = time(0) + fault_polling_interval;
			}

			/* Keep track of the earliest next due time */
			if (diskp->due > 0)
				earliest_due = (earliest_due < 0) ? diskp->due :
				    MIN(earliest_due, diskp->due);

			assert(pthread_mutex_unlock(&diskp->manager_mutex)
			    == 0);

			diskp = diskp->next;
		}

		/*
		 * earliest_due can be < 0 (if no disks were fault-analyzed)
		 * but it should NEVER be == 0.
		 */
		if (earliest_due < 0) {
			nexttime = time(0) + fault_polling_interval;
			earliest_due = nexttime;
		} else if (earliest_due == 0) {
			nexttime = time(0) + fault_polling_interval;
			log_warn("BUG: earliest_due time is == 0-- resetting "
			    "to %ld\n", nexttime);
			earliest_due = nexttime;
		}

		tspec.tv_sec = earliest_due;
		tspec.tv_nsec = 0;
		(void) pthread_cond_timedwait(&g_fmt_cvar,
		    &g_fmt_mutex, &tspec);
	}
	assert(pthread_mutex_unlock(&g_fmt_mutex) == 0);

	log_msg(MM_FAULTMGR, "Fault monitor polling thread exiting...\n");
}

static int
create_fault_monitor_thread(diskmon_t *disklistp)
{
	/* fmt_thr_create() is guaranteed to succeed or abort */
	g_fmt_tid = fmd_thr_create(g_fm_hdl, disk_fault_monitor_thread,
	    disklistp);
	g_fmt_spawned = B_TRUE;

	return (0);
}

static void
collect_fault_monitor_thread(void)
{
	if (g_fmt_spawned) {

		g_fmt_req_state = TS_EXIT_REQUESTED;
		assert(pthread_mutex_lock(&g_fmt_mutex) == 0);
		assert(pthread_cond_broadcast(&g_fmt_cvar) == 0);
		assert(pthread_mutex_unlock(&g_fmt_mutex) == 0);
		fmd_thr_signal(g_fm_hdl, g_fmt_tid);
		fmd_thr_destroy(g_fm_hdl, g_fmt_tid);
		g_fmt_req_state = TS_NOT_RUNNING;
		g_fmt_tid = NULL;
		g_fmt_spawned = B_FALSE;
	}
}

int
init_fault_manager(cfgdata_t *cfgdatap)
{
	int i;

	if (dm_prop_lookup_int(dm_global_proplist(), GLOBAL_PROP_FAULT_POLL, &i)
	    == 0 && i > 0)
		return (create_fault_monitor_thread(cfgdatap->disk_list));
	else {
		g_fmt_spawned = B_FALSE;
		return (0);
	}
}

/*
 * fault_manager_poke wakes up the fault manager thread so it can
 * perform initial fault analysis on new disks.
 */
void
fault_manager_poke(void)
{
	assert(pthread_mutex_lock(&g_fmt_mutex) == 0);
	assert(pthread_cond_broadcast(&g_fmt_cvar) == 0);
	assert(pthread_mutex_unlock(&g_fmt_mutex) == 0);
}

/*ARGSUSED*/
void
cleanup_fault_manager(cfgdata_t *cfgdatap)
{
	collect_fault_monitor_thread();
}
