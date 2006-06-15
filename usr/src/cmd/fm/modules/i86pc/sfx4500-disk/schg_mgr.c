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

#include <string.h>
#include <inttypes.h>
#include <atomic.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>

#include "sfx4500-disk.h"
#include "schg_mgr.h"
#include "hotplug_mgr.h"
#include "plugin_mgr.h"
#include "fault_mgr.h"
#include "fault_analyze.h"
#include "topo_gather.h"
#include "fm_disk_events.h"

/* State-change event processing thread data */
static pthread_t	g_schg_tid;
static thread_state_t	g_schgt_state = TS_NOT_RUNNING;
static pthread_mutex_t	g_schgt_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	g_schgt_state_cvar = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t	g_schgt_add_mutex = PTHREAD_MUTEX_INITIALIZER;
static qu_t		*g_schg_queue = NULL;

static void dm_state_change_nolock(diskmon_t *diskp, hotplug_state_t newstate);

/*
 * Each disk state change is described by an instance of the following
 * structure (which includes the disk object and the new state)
 */
typedef struct disk_statechg {
	diskmon_t	*diskp;
	hotplug_state_t	newstate;
} disk_statechg_t;

static disk_statechg_t *
new_statechange(diskmon_t *diskp, hotplug_state_t state)
{
	disk_statechg_t *dscp =
	    (disk_statechg_t *)dmalloc(sizeof (disk_statechg_t));

	/*
	 * The states are additive -- we don't need to preserve
	 * the current faulted state in the newstate:
	 */
	dscp->diskp = diskp;
	dscp->newstate = state;

	return (dscp);
}

static void
free_statechange(void *dscp)
{
	dfree(dscp, sizeof (disk_statechg_t));
}

static void
add_to_statechange_queue(diskmon_t *diskp, hotplug_state_t newstate)
{
	queue_add(g_schg_queue, new_statechange(diskp, newstate));
}

static const char *
lookup_action_string(indicator_t *ind_listp, ind_state_t state, char *name)
{
	const char *str = NULL;

	while (ind_listp != NULL) {

		if (state == ind_listp->ind_state &&
		    strcasecmp(ind_listp->ind_name, name) == 0) {

			str = ind_listp->ind_instr_spec;
			break;
		}

		ind_listp = ind_listp->next;
	}

	return (str);
}

void
dm_fault_indicator_set(diskmon_t *diskp, ind_state_t istate)
{
	const char *astring;

	dm_assert(pthread_mutex_lock(&diskp->fault_indicator_mutex) == 0);

	/*
	 * No need to execute redundant indicator actions
	 */
	if (istate == INDICATOR_UNKNOWN ||
	    diskp->fault_indicator_state == istate) {
		dm_assert(pthread_mutex_unlock(&diskp->fault_indicator_mutex)
		    == 0);
		return;
	}

	astring = lookup_action_string(diskp->ind_list, istate,
	    INDICATOR_FAULT_IDENTIFIER);

	if (astring != NULL) {
		log_msg(MM_SCHGMGR, "Executing action `%s'\n", astring);

		if (dm_pm_indicator_execute(astring)
		    != DMPE_SUCCESS) {
			log_warn("[Disk in %s] Action `%s' did not complete "
			    "successfully.\n",
			    diskp->location,
			    astring);
		} else  {

			diskp->fault_indicator_state = istate;

			log_msg(MM_SCHGMGR, "Action `%s' executed "
			    "successfully\n", astring);
		}
	}

	dm_assert(pthread_mutex_unlock(&diskp->fault_indicator_mutex) == 0);
}

static void
schg_execute_state_change_action(diskmon_t *diskp, hotplug_state_t oldstate,
    hotplug_state_t newstate)
{
	indrule_t *rulelist;
	ind_action_t *actions;
	const char *astring;

	log_msg(MM_SCHGMGR, "[Disk in %s] State change action: %s -> %s\n",
	    diskp->location,
	    hotplug_state_string(oldstate),
	    hotplug_state_string(newstate));

	/*
	 * Find the list of actions that correspond to this state change.
	 * If the old state is UNKNOWN, then we'll match to first action
	 * whose transition state is the new state.
	 */
	rulelist = diskp->indrule_list;

	while (rulelist != NULL) {

		if ((oldstate == HPS_UNKNOWN ||
		    rulelist->strans.begin == oldstate) &&
		    rulelist->strans.end == newstate)
			break;

		rulelist = rulelist->next;
	}

	if (rulelist != NULL) {
		/* Now we have a set of actions to perform: */
		actions = rulelist->action_list;

		while (actions != NULL) {

			astring = lookup_action_string(diskp->ind_list,
			    actions->ind_state, actions->ind_name);

			dm_assert(astring != NULL);

			log_msg(MM_SCHGMGR, "Executing action `%s'\n", astring);

			if (dm_pm_indicator_execute(astring)
			    != DMPE_SUCCESS) {
				log_warn("[Disk in %s][State transition from "
				    "%s to %s] Action `%s' did not complete "
				    "successfully.\n",
				    diskp->location,
				    hotplug_state_string(oldstate),
				    hotplug_state_string(newstate),
				    astring);

			} else
				log_msg(MM_SCHGMGR,
				    "Action `%s' executed successfully\n",
				    astring);

			actions = actions->next;
		}
	}

}

static void
schg_send_fru_to_plugin(diskmon_t *diskp, dm_fru_t *frup)
{
	const char *action = dm_prop_lookup(diskp->props, DISK_PROP_FRUACTION);

	if (action == NULL) {
		log_msg(MM_SCHGMGR|MM_NOTE, "No FRU update action for disk "
		    "in %s\n", diskp->location);
		return;
	}

	if (dm_pm_update_fru(action, frup) != DMPE_SUCCESS) {
		log_warn("Error updating FRU information for disk in %s.\n",
		    diskp->location);
	}
}

static void
schg_update_fru_info(diskmon_t *diskp)
{
	if (diskp->initial_configuration ||
	    update_configuration_from_topo(diskp) == TOPO_SUCCESS) {
		diskp->initial_configuration = B_FALSE;
		dm_assert(pthread_mutex_lock(&diskp->fru_mutex) == 0);
		if (diskp->frup != NULL)
			schg_send_fru_to_plugin(diskp, diskp->frup);
		else
			log_warn("frup unexpectedly went away: not updating "
			    "FRU information for disk %s!\n", diskp->location);
		dm_assert(pthread_mutex_unlock(&diskp->fru_mutex) == 0);
	} else {
		log_warn_e("Error retrieving FRU information "
		    "for disk in %s", diskp->location);
	}
}

/*
 * [Lifted from fmd]
 * Create a local ENA value for fmd-generated ereports.  We use ENA Format 1
 * with the low bits of gethrtime() and pthread_self() as the processor ID.
 */
static uint64_t
dm_gen_ena(void)
{
	hrtime_t hrt = gethrtime();

	return ((uint64_t)((FM_ENA_FMT1 & ENA_FORMAT_MASK) |
	    ((pthread_self() << ENA_FMT1_CPUID_SHFT) & ENA_FMT1_CPUID_MASK) |
	    ((hrt << ENA_FMT1_TIME_SHFT) & ENA_FMT1_TIME_MASK)));
}


static void
dm_send_ereport(char *class, uint64_t ena, nvlist_t *detector,
    nvlist_t *payload)
{
	nvlist_t *nvl;
	int e = 0;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) == 0) {
		/*
		 * An ereport nvlist consists of:
		 *
		 * FM_CLASS		class
		 * FM_VERSION		FM_EREPORT_VERSION
		 * FM_EREPORT_ENA	ena
		 * FM_EREPORT_DETECTOR	detector
		 * <Other payload members>
		 *
		 */
		e |= nvlist_add_string(nvl, FM_CLASS, class);
		e |= nvlist_add_uint8(nvl, FM_VERSION, FM_EREPORT_VERSION);
		e |= nvlist_add_uint64(nvl, FM_EREPORT_ENA, ena);
		e |= nvlist_add_nvlist(nvl, FM_EREPORT_DETECTOR, detector);
		e |= nvlist_merge(nvl, payload, 0);

		if (e == 0)
			fmd_xprt_post(g_fm_hdl, g_xprt_hdl, nvl, 0);
		else
			nvlist_free(nvl);
	}
}

static void
schg_consume_faults(diskmon_t *diskp)
{
	struct disk_fault *faults;
	nvlist_t *nvl;
	uint64_t ena;
	char *er_class;
	int e;

	dm_assert(diskp->fmip != NULL);

	/* Use the same ENA for all current faults */
	ena = dm_gen_ena();

	dm_assert(pthread_mutex_lock(&diskp->fmip->fault_data_mutex) == 0);
	faults = diskp->fmip->fault_list;

	/* Go through the list of faults, executing actions if present */
	while (faults != NULL) {

		dm_assert(pthread_mutex_lock(&diskp->disk_faults_mutex) == 0);
		diskp->disk_faults |= faults->fault_src;
		dm_assert(pthread_mutex_unlock(&diskp->disk_faults_mutex) == 0);

		er_class = NULL;
		e = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);

		switch (faults->fault_src) {
		case DISK_FAULT_SOURCE_SELFTEST:
			if (e == 0) {
				er_class = EREPORT_SATA_STFAIL;
				e |= nvlist_add_uint16(nvl,
				    EV_PAYLOAD_STCODE,
				    faults->selftest_code);
			}
			break;

		case DISK_FAULT_SOURCE_OVERTEMP:
			if (e == 0) {
				er_class = EREPORT_SATA_OVERTEMP;
				e |= nvlist_add_uint16(nvl,
				    EV_PAYLOAD_CURTEMP,
				    faults->cur_temp);
				e |= nvlist_add_uint16(nvl,
				    EV_PAYLOAD_THRESH,
				    faults->thresh_temp);
			}
			break;

		case DISK_FAULT_SOURCE_INFO_EXCPT:
			er_class = EREPORT_SATA_PREDFAIL;
			if (e == 0 && faults->sense_valid) {
				e |= nvlist_add_uint16(nvl,
				    EV_PAYLOAD_ASC,
				    faults->asc);
				e |= nvlist_add_uint16(nvl,
				    EV_PAYLOAD_ASCQ,
				    faults->ascq);
			}
			break;

		default:
			break;
		}

		if (e == 0 && er_class != NULL) {
			log_msg(MM_SCHGMGR, "[%s] Sending ereport %s\n",
			    diskp->location, er_class);

			dm_send_ereport(er_class, ena,
			    diskp->disk_res_fmri, nvl);
		}

		if (nvl)
			nvlist_free(nvl);

		faults = faults->next;
	}

	free_disk_fault_list(diskp->fmip);

	dm_assert(pthread_mutex_unlock(&diskp->fmip->fault_data_mutex) == 0);
}

void
block_state_change_events(void)
{
	dm_assert(pthread_mutex_lock(&g_schgt_add_mutex) == 0);
}

void
unblock_state_change_events(void)
{
	dm_assert(pthread_mutex_unlock(&g_schgt_add_mutex) == 0);
}

static void
disk_state_change_first_time(diskmon_t *diskp)
{
	hotplug_state_t firststate;

	/*
	 * Grab the current state of the attachment point to initialize the
	 * initial disk state.  Create a disk state change with this new
	 * state so it will be processed in the loop below.  If we can't get
	 * the initial state for some reason, then we'll just end up doing it
	 * later when we get a state change from the hotplug monitor or the
	 * fault monitor.
	 */
	firststate = disk_ap_state_to_hotplug_state(diskp);
	if (firststate != HPS_UNKNOWN)
		dm_state_change_nolock(diskp, firststate);

	/*
	 * The fault indicators will be updated when faults are replayed
	 * based on the state of the disk as faulty in the fmd resource cache.
	 * A FAULTED state change will come from the _recv function when the
	 * fault component event is replayed.
	 */
}

static void
disk_state_change_thread(void *vdisklistp)
{
	diskmon_t	*disklistp = (diskmon_t *)vdisklistp;
	diskmon_t	*diskp;
	disk_statechg_t	*dscp;
	int		err;
	hotplug_state_t	nextstate;
	boolean_t	poke_fault_manager;
	const char	*pth;

	/*
	 * Perform startup activities to initialize the state of the
	 * indicators for each disk.
	 */
	diskp = disklistp;
	while (diskp != NULL) {
		disk_state_change_first_time(diskp);
		diskp = diskp->next;
	}

	unblock_state_change_events();

	dm_assert(pthread_mutex_lock(&g_schgt_state_mutex) == 0);
	if (g_schgt_state != TS_EXIT_REQUESTED) {
		g_schgt_state = TS_RUNNING;
		dm_assert(pthread_cond_broadcast(&g_schgt_state_cvar) == 0);
	}
	dm_assert(pthread_mutex_unlock(&g_schgt_state_mutex) == 0);

	while (g_schgt_state != TS_EXIT_REQUESTED) {

		if ((dscp = (disk_statechg_t *)queue_remove(g_schg_queue))
		    == NULL) {
			dm_assert(g_schgt_state == TS_EXIT_REQUESTED);
			continue;
		}

		poke_fault_manager = B_FALSE;

		diskp = dscp->diskp;

		/*
		 * If the new state is the faulted state, add that state to
		 * the disk's current state.
		 */
		if (dscp->newstate == HPS_FAULTED) {

			/*
			 * If the disk wasn't previously in the faulted state,
			 * execute the generic fault action.  Even if we're
			 * in the faulted state, accept additional faults.
			 */
			nextstate = DISK_STATE(diskp->state) | HPS_FAULTED;

		} else if (dscp->newstate == HPS_REPAIRED) {
			nextstate = DISK_STATE(diskp->state);

		} else if (dscp->newstate == HPS_ABSENT) {
			/*
			 * If the new state is ABSENT, forget any faults
			 */

			nextstate = HPS_ABSENT;
		} else
			nextstate = dscp->newstate | DISK_FAULTED(diskp->state);

		/*
		 * When a new disk is inserted and reaches the CONFIGURED state,
		 * the following actions must be done in the following order:
		 *
		 * (1) Execute the configuration-specified action on the
		 * state change.
		 * (2) Retreive the FRU information from the disk and execute
		 * the FRU-update action specified,
		 * (3) Initialize the fault monitor state associated with
		 * the new drive.
		 *
		 * Once the disk is no longer "new" (a disk is "new" when it
		 * has not yet reached the CONFIGURED state), subsequent
		 * transitions away and back to CONFIGURED (as long as the
		 * disk is not physically removed) will result in the
		 * execution of the predefined action ONLY.
		 *
		 */

		if (dscp->newstate == HPS_FAULTED) {

			/*
			 * fmip can be NULL here if the DE is processing
			 * replayed faults.  In this case, no need to
			 * do anything.
			 */
			if (diskp->fmip) {
				schg_consume_faults(diskp);

				diskp->faults_outstanding = B_FALSE;
			}

		} else if (dscp->newstate != HPS_FAULTED &&
		    DISK_STATE(nextstate) != HPS_UNKNOWN &&
		    dscp->newstate != HPS_REPAIRED) {

			schg_execute_state_change_action(diskp,
			    DISK_STATE(diskp->state), DISK_STATE(nextstate));
		}

		if (!diskp->configured_yet &&
		    DISK_STATE(nextstate) == HPS_CONFIGURED) {

			schg_update_fru_info(diskp);

			/*
			 * If this state transition is lagging the true
			 * state of the system (e.g. if the true state of
			 * the disk is UNCONFIGURED, there's another
			 * state change somewhere later in the queue), then
			 * it's possible for the disk path property to not
			 * exist -- so check it, and if it doesn't exist,
			 * do not try to do disk_fault_init.
			 */
			if (dm_prop_lookup(diskp->props,
			    DISK_PROP_DEVPATH) == NULL) {

				log_msg(MM_SCHGMGR,
				    "Processed stale state change "
				    "for disk %s\n", diskp->location);

			} else if ((err = disk_fault_init(diskp)) != 0) {

				if (err != IE_NOT_SUPPORTED)
					log_warn("Error initializing fault "
					    "monitor for disk in %s.\n",
					    diskp->location);
			} else {
				diskp->configured_yet = B_TRUE;

				/*
				 * Now that the fault info for the disk is
				 * initialized, we can request that the fault
				 * manager do an analysis immediately.  This is
				 * an initial analysis, so it will only happen
				 * the first time the disk enters the CONFIGURED
				 * state.  After that, it is polled at the
				 * fault-polling interval.
				 * Note that the poking of the fault manager
				 * MUST occur AFTER the disk state is set
				 * (below), otherwise, the fault manager could
				 * ignore the disk if it analyzes it before
				 * this thread can set the state to configured.
				 */
				poke_fault_manager = B_TRUE;
			}

		}

		dm_assert(pthread_mutex_lock(&diskp->manager_mutex) == 0);

		/*
		 * Make the new state visible to all observers
		 */
		diskp->state = nextstate;

		/*
		 * Now, update the diskmon if the disk is now absent -- it's
		 * essential to do this after the state is set (above) so that
		 * state observers in other threads don't try to access the
		 * data structures that we're freeing here.
		 */

		if (diskp->configured_yet &&
		    DISK_STATE(nextstate) == HPS_ABSENT) {
			/*
			 * When the disk is removed, the fault monitor state is
			 * useless, so discard it.
			 */
			dm_assert(DISK_STATE(nextstate) != HPS_CONFIGURED);

			disk_fault_uninit(diskp);

			diskp->configured_yet = B_FALSE;

		} else if (dscp->newstate == HPS_REPAIRED) {
			/*
			 * Drop the current list of faults.  There may be
			 * other faults pending in the fault list, and that's
			 * OK.
			 */
			dm_assert(pthread_mutex_lock(&diskp->disk_faults_mutex)
			    == 0);
			diskp->disk_faults = DISK_FAULT_SOURCE_NONE;
			dm_assert(
			    pthread_mutex_unlock(&diskp->disk_faults_mutex)
			    == 0);
		}
		dm_assert(pthread_mutex_unlock(&diskp->manager_mutex) == 0);


		if (poke_fault_manager) {
			/*
			 * Now we can wake up the fault monitor thread
			 * to do an initial analysis of the disk:
			 */
			poke_fault_manager = B_FALSE;
			fault_manager_poke();
		}

		pth = dm_prop_lookup(diskp->props, DISK_PROP_DEVPATH);

		log_msg(MM_SCHGMGR,
		    "[State change #%d][%s]: Disk path = %s\n",
		    diskp->state_change_count,
		    diskp->location, pth == NULL ? "Unknown" : pth);

		log_msg(MM_SCHGMGR,
		    "[State change #%d][%s]: New state = %s%s\n",
		    diskp->state_change_count, diskp->location,
		    hotplug_state_string(diskp->state),
		    DISK_FAULTED(diskp->state) ? "+FAULTED" : "");

		atomic_inc_uint(&diskp->state_change_count);

		/* The caller is responsible for freeing the state change: */
		free_statechange(dscp);
	}
	dm_assert(pthread_mutex_lock(&g_schgt_state_mutex) == 0);
	g_schgt_state = TS_EXITED;
	dm_assert(pthread_cond_broadcast(&g_schgt_state_cvar) == 0);
	dm_assert(pthread_mutex_unlock(&g_schgt_state_mutex) == 0);

	log_msg(MM_SCHGMGR, "State change thread exiting...\n");
}

static void
dm_state_change_nolock(diskmon_t *diskp, hotplug_state_t newstate)
{
	/* Enqueue a new state change for the state-change thread */
	add_to_statechange_queue(diskp, newstate);
}

void
dm_state_change(diskmon_t *diskp, hotplug_state_t newstate)
{
	dm_assert(pthread_mutex_lock(&g_schgt_add_mutex) == 0);
	dm_state_change_nolock(diskp, newstate);
	dm_assert(pthread_mutex_unlock(&g_schgt_add_mutex) == 0);
}

int
init_state_change_manager(cfgdata_t *cfgdatap)
{
	/* new_queue() is guaranteed to succeed */
	g_schg_queue = new_queue(B_TRUE, dmalloc, dfree, free_statechange);

	dm_assert(pthread_mutex_lock(&g_schgt_state_mutex) == 0);
	g_schg_tid = fmd_thr_create(g_fm_hdl, disk_state_change_thread,
	    cfgdatap->disk_list);

	/*
	 * Now, wait for the thread to enter the TS_RUNNING state.  This
	 * is important because we want the state-change thread to pull the
	 * initial state of the disks on startup (without the wait, we could
	 * have the hotplug event handler race and deliver a state change
	 * before the state-change thread initialized the initial disk state).
	 */

	while (g_schgt_state != TS_RUNNING) {
		(void) pthread_cond_wait(&g_schgt_state_cvar,
		    &g_schgt_state_mutex);
	}

	dm_assert(pthread_mutex_unlock(&g_schgt_state_mutex) == 0);

	return (0);
}

/*ARGSUSED*/
void
cleanup_state_change_manager(cfgdata_t *cfgdatap)
{
	if (g_schgt_state != TS_RUNNING)
		return;

	g_schgt_state = TS_EXIT_REQUESTED;
	queue_add(g_schg_queue, NULL);
	dm_assert(pthread_mutex_lock(&g_schgt_state_mutex) == 0);
	while (g_schgt_state != TS_EXITED)
		dm_assert(pthread_cond_wait(&g_schgt_state_cvar,
		    &g_schgt_state_mutex) == 0);
	dm_assert(pthread_mutex_unlock(&g_schgt_state_mutex) == 0);
	(void) pthread_join(g_schg_tid, NULL);
	fmd_thr_destroy(g_fm_hdl, g_schg_tid);
	queue_free(&g_schg_queue);
	g_schgt_state = TS_NOT_RUNNING;
}
