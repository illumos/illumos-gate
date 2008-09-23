/*
 * Copyright 2008, Intel Corporation
 * Copyright 2008, Sun Microsystems, Inc
 *
 * This file is part of PowerTOP
 *
 * This program file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program in a file named COPYING; if not, write to the
 * Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA
 *
 * Authors:
 *	Arjan van de Ven <arjan@linux.intel.com>
 *	Eric C Saxe <eric.saxe@sun.com>
 *	Aubrey Li <aubrey.li@intel.com>
 */

/*
 * GPL Disclaimer
 *
 * For the avoidance of doubt, except that if any license choice other
 * than GPL or LGPL is available it will apply instead, Sun elects to
 * use only the General Public License version 2 (GPLv2) at this time
 * for any software where a choice of GPL license versions is made
 * available with the language indicating that GPLv2 or any later
 * version may be used, or where a choice of which version of the GPL
 * is applied is otherwise unspecified.
 */

#include <string.h>
#include <dtrace.h>
#include "powertop.h"

static dtrace_hdl_t 	*g_dtp;

/*
 * Buffer containing DTrace program to track CPU idle state transitions
 */
static const char *pt_cpuidle_dtrace_prog =
":::idle-state-transition"
"/arg0 != 0/"
"{"
"	self->start = timestamp;"
"	self->state = arg0;"
"}"
""
":::idle-state-transition"
"/arg0 == 0 && self->start/"
"{"
"	@number[self->state] = count();"
"	@times[self->state] = sum((timestamp - self->start)/1000000);"
"	self->start = 0;"
"	self->state = 0;"
"}";

static int 	pt_cpuidle_dtrace_walk(const dtrace_aggdata_t *, void *);

/*
 * Perform setup necessary to track CPU idle state transitions
 */
int
pt_cpuidle_stat_prepare(void)
{
	dtrace_prog_t 		*prog;
	dtrace_proginfo_t 	info;
	dtrace_optval_t 	statustime;
	int 			err;

	if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
		pt_error("%s : cannot open dtrace library: %s\n", __FILE__,
		    dtrace_errmsg(NULL, err));
		return (-1);
	}
	if ((prog = dtrace_program_strcompile(g_dtp, pt_cpuidle_dtrace_prog,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL) {
		pt_error("%s : C-State DTrace probes unavailable\n", __FILE__);
		return (dtrace_errno(g_dtp));
	}
	if (dtrace_program_exec(g_dtp, prog, &info) == -1) {
		pt_error("%s : failed to enable C State probes\n", __FILE__);
		return (dtrace_errno(g_dtp));
	}
	if (dtrace_setopt(g_dtp, "aggsize", "128k") == -1) {
		pt_error("%s : failed to set C-state 'aggsize'\n", __FILE__);
	}
	if (dtrace_setopt(g_dtp, "aggrate", "0") == -1) {
		pt_error("%s : failed to set C-state'aggrate'\n", __FILE__);
	}
	if (dtrace_setopt(g_dtp, "aggpercpu", 0) == -1) {
		pt_error("%s : failed to set C-state 'aggpercpu'\n", __FILE__);
	}
	if (dtrace_go(g_dtp) != 0) {
		pt_error("%s : failed to start C-state observation", __FILE__);
		return (dtrace_errno(g_dtp));
	}
	if (dtrace_getopt(g_dtp, "statusrate", &statustime) == -1) {
		pt_error("%s : failed to get C-state 'statusrate'\n", __FILE__);
		return (dtrace_errno(g_dtp));
	}
	return (0);
}

/*
 * The DTrace probes have been enabled, and are tracking CPU idle state
 * transitions. Take a snapshot of the aggregations, and invoke the aggregation
 * walker to process any records. The walker does most of the accounting work
 * chalking up time spent into the cstate_info structure.
 */
int
pt_cpuidle_stat_collect(double interval)
{
	int 		i;
	hrtime_t	t = 0;

	/*
	 * Zero out the interval time reported by DTrace for
	 * this interval
	 */
	for (i = 0; i < NSTATES; i++) {
		cstate_info[i].total_time = 0;
		cstate_info[i].events = 0;
	}

	/*
	 * Assume that all the time spent in this interval will
	 * be the default "0" state. The DTrace walker will reallocate
	 * time out of the default bucket as it processes aggregation
	 * records for time spent in other states.
	 */
	cstate_info[0].total_time = (long)(interval * g_ncpus * 1000);

	if (dtrace_status(g_dtp) == -1)
		return (-1);

	if (dtrace_aggregate_snap(g_dtp) != 0)
		pt_error("%s : failed to add to aggregation", __FILE__);

	if (dtrace_aggregate_walk_keyvarsorted(g_dtp, pt_cpuidle_dtrace_walk,
	    NULL) != 0)
		pt_error("%s : failed to sort aggregation", __FILE__);

	dtrace_aggregate_clear(g_dtp);

	/*
	 * Populate cstate_info with the correct amount of time spent
	 * in each C state and update the number of C states in max_cstate
	 */
	total_c_time = 0;
	for (i = 0; i < NSTATES; i++) {
		if (cstate_info[i].total_time > 0) {
			total_c_time += cstate_info[i].total_time;
			if (i > max_cstate)
				max_cstate = i;
			if (cstate_info[i].last_time > t) {
				t = cstate_info[i].last_time;
				longest_cstate = i;
			}
		}
	}

	return (0);
}

/*
 * DTrace aggregation walker that sorts through a snapshot of data records
 * collected during firings of the idle-state-transition probe.
 *
 * XXX A way of querying the current idle state for a CPU is needed in addition
 *     to logic similar to that in cpufreq.c
 */
/*ARGSUSED*/
static int
pt_cpuidle_dtrace_walk(const dtrace_aggdata_t *data, void *arg)
{
	dtrace_aggdesc_t 	*aggdesc = data->dtada_desc;
	dtrace_recdesc_t 	*rec;
	uint64_t 		n = 0;
	int32_t 		state;
	int 			i;

	rec = &aggdesc->dtagd_rec[1];
	/* LINTED - alignment */
	state = *(int32_t *)(data->dtada_data + rec->dtrd_offset);

	if (strcmp(aggdesc->dtagd_name, "number") == 0) {
		for (i = 0; i < g_ncpus; i++) {
			/* LINTED - alignment */
			n += *((uint64_t *)(data->dtada_percpu[i]));
		}
		total_events += n;
		cstate_info[state].events += n;
	}
	else
		if (strcmp(aggdesc->dtagd_name, "times") == 0) {
			for (i = 0; i < g_ncpus; i++) {
				/* LINTED - alignment */
				n += *((uint64_t *)(data->dtada_percpu[i]));
			}
			cstate_info[state].last_time = n;
			cstate_info[state].total_time += n;
			if (cstate_info[0].total_time >= n)
				cstate_info[0].total_time -= n;
		}

	return (DTRACE_AGGWALK_NEXT);
}
