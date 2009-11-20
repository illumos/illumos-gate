/*
 * Copyright 2009, Intel Corporation
 * Copyright 2009, Sun Microsystems, Inc
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

#define	S2NS(x)		((x) * (NANOSEC))

static dtrace_hdl_t 	*dtp;

/*
 * Buffer containing DTrace program to track CPU idle state transitions
 */
static const char *dtp_cpuidle =
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
"	@times[self->state] = sum(timestamp - self->start);"
"	self->start = 0;"
"	self->state = 0;"
"}";

/*
 * Same as above but only for a specific CPU
 */
static const char *dtp_cpuidle_c =
":::idle-state-transition"
"/cpu == $0 &&"
" arg0 != 0/"
"{"
"	self->start = timestamp;"
"	self->state = arg0;"
"}"
""
":::idle-state-transition"
"/cpu == $0 &&"
" arg0 == 0 && self->start/"
"{"
"	@number[self->state] = count();"
"	@times[self->state] = sum(timestamp - self->start);"
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
	char			*prog_ptr;

	if ((dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
		pt_error("cannot open dtrace library for the %s report: %s\n",
		    g_msg_idle_state, dtrace_errmsg(NULL, err));
		return (-1);
	}

	/*
	 * Execute different scripts (defined above) depending on
	 * user specified options.
	 */
	if (PT_ON_CPU)
		prog_ptr = (char *)dtp_cpuidle_c;
	else
		prog_ptr = (char *)dtp_cpuidle;

	if ((prog = dtrace_program_strcompile(dtp, prog_ptr,
	    DTRACE_PROBESPEC_NAME, 0, g_argc, g_argv)) == NULL) {
		pt_error("failed to compile %s program\n", g_msg_idle_state);
		return (dtrace_errno(dtp));
	}

	if (dtrace_program_exec(dtp, prog, &info) == -1) {
		pt_error("failed to enable %s probes\n", g_msg_idle_state);
		return (dtrace_errno(dtp));
	}

	if (dtrace_setopt(dtp, "aggsize", "128k") == -1)
		pt_error("failed to set %s 'aggsize'\n", g_msg_idle_state);

	if (dtrace_setopt(dtp, "aggrate", "0") == -1)
		pt_error("failed to set %s 'aggrate'\n", g_msg_idle_state);

	if (dtrace_setopt(dtp, "aggpercpu", 0) == -1)
		pt_error("failed to set %s 'aggpercpu'\n", g_msg_idle_state);

	if (dtrace_go(dtp) != 0) {
		pt_error("failed to start %s observation\n", g_msg_idle_state);
		return (dtrace_errno(dtp));
	}

	if (dtrace_getopt(dtp, "statusrate", &statustime) == -1) {
		pt_error("failed to get %s 'statusrate'\n", g_msg_idle_state);
		return (dtrace_errno(dtp));
	}

	return (0);
}

/*
 * The DTrace probes have been enabled, and are tracking CPU idle state
 * transitions. Take a snapshot of the aggregations, and invoke the aggregation
 * walker to process any records. The walker does most of the accounting work
 * chalking up time spent into the g_cstate_info structure.
 */
int
pt_cpuidle_stat_collect(double interval)
{
	int i;
	hrtime_t t = 0;

	/*
	 * Assume that all the time spent in this interval will
	 * be the default "0" state. The DTrace walker will reallocate
	 * time out of the default bucket as it processes aggregation
	 * records for time spent in other states.
	 */
	g_cstate_info[0].total_time = (uint64_t)S2NS(interval *
	    g_ncpus_observed);

	if (dtrace_status(dtp) == -1)
		return (-1);

	if (dtrace_aggregate_snap(dtp) != 0)
		pt_error("failed to collect data for %s\n", g_msg_idle_state);

	if (dtrace_aggregate_walk_keyvarsorted(dtp, pt_cpuidle_dtrace_walk,
	    NULL) != 0)
		pt_error("failed to sort %s data\n", g_msg_idle_state);

	dtrace_aggregate_clear(dtp);

	/*
	 * Populate g_cstate_info with the correct amount of time spent
	 * in each C state and update the number of C states in g_max_cstate
	 */
	g_total_c_time = 0;
	for (i = 0; i < NSTATES; i++) {
		if (g_cstate_info[i].total_time > 0) {
			g_total_c_time += g_cstate_info[i].total_time;
			if (i > g_max_cstate)
				g_max_cstate = i;
			if (g_cstate_info[i].last_time > t) {
				t = g_cstate_info[i].last_time;
				g_longest_cstate = i;
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
	uint64_t 		n = 0, state;
	int 			i;

	rec = &aggdesc->dtagd_rec[1];

	switch (g_bit_depth) {
		case 32:
			/* LINTED - alignment */
			state = *(uint32_t *)(data->dtada_data +
			    rec->dtrd_offset);
			break;
		case 64:
			/* LINTED - alignment */
			state = *(uint64_t *)(data->dtada_data +
			    rec->dtrd_offset);
			break;
	}

	if (strcmp(aggdesc->dtagd_name, "number") == 0) {
		for (i = 0; i < g_ncpus; i++) {
			/* LINTED - alignment */
			n += *((uint64_t *)(data->dtada_percpu[i]));
		}
		g_total_events += n;
		g_cstate_info[state].events += n;
	}
	else
		if (strcmp(aggdesc->dtagd_name, "times") == 0) {
			for (i = 0; i < g_ncpus; i++) {
				/* LINTED - alignment */
				n += *((uint64_t *)(data->dtada_percpu[i]));
			}
			g_cstate_info[state].last_time = n;
			g_cstate_info[state].total_time += n;
			if (g_cstate_info[0].total_time >= n)
				g_cstate_info[0].total_time -= n;
			else
				g_cstate_info[0].total_time = 0;
		}

	return (DTRACE_AGGWALK_NEXT);
}
