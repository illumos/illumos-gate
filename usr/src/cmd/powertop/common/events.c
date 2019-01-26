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
#include <stdlib.h>
#include <dtrace.h>
#include "powertop.h"

static dtrace_hdl_t *dtp;
static event_info_t *event;

/*ARGSUSED*/
static int
pt_events_walk(const dtrace_aggdata_t *data, void *arg)
{
	dtrace_aggdesc_t	*aggdesc = data->dtada_desc;
	dtrace_recdesc_t	*rec1, *rec2, *rec3;
	dtrace_syminfo_t	dts;
	GElf_Sym		sym;
	uint64_t		offender_addr;
	uint64_t		n = 0;
	int32_t			*instance, *offender_cpu;
	int			i;
	char			*offense_name;

	if (g_top_events >= EVENT_NUM_MAX)
		return (0);

	rec1 = &aggdesc->dtagd_rec[1];
	rec2 = &aggdesc->dtagd_rec[2];

	/*
	 * Report interrupts
	 */
	if (strcmp(aggdesc->dtagd_name, "interrupts") == 0) {
		offense_name = data->dtada_data + rec1->dtrd_offset;

		/* LINTED - alignment */
		instance = (int32_t *)(data->dtada_data + rec2->dtrd_offset);
		(void) snprintf((char *)(event->offender_name),
		    EVENT_NAME_MAX, "%s", "<interrupt>");
		(void) snprintf((char *)(event->offense_name),
		    EVENT_NAME_MAX, "%s#%d", offense_name, *instance);
	/*
	 * Report kernel events
	 */
	} else if (strcmp(aggdesc->dtagd_name, "events_k") == 0) {

		(void) snprintf((char *)(event->offender_name),
		    EVENT_NAME_MAX, "%s", "<kernel>");

		/*
		 * Casting offender_addr to the wrong type will cause
		 * dtrace_lookup_by_addr to return 0 and the report
		 * to show an address instead of a name.
		 */
		switch (g_bit_depth) {
		case 32:
			/* LINTED - alignment */
			offender_addr = *(uint32_t *)(data->dtada_data +
			    rec1->dtrd_offset);
			break;
		case 64:
			/* LINTED - alignment */
			offender_addr = *(uint64_t *)(data->dtada_data +
			    rec1->dtrd_offset);
			break;
		}

		/*
		 * We have the address of the kernel callout.
		 * Try to resolve it into a meaningful symbol
		 */
		if (offender_addr != 0 && dtrace_lookup_by_addr(dtp,
		    offender_addr, &sym, &dts) == 0) {
			(void) snprintf((char *)(event->offense_name),
			    EVENT_NAME_MAX, "%s`%s", dts.dts_object,
			    dts.dts_name);
		} else {
			(void) snprintf((char *)(event->offense_name),
			    EVENT_NAME_MAX, "0x%llx", offender_addr);
		}
	/*
	 * Report user events
	 */
	} else if (strcmp(aggdesc->dtagd_name, "events_u") == 0) {
		offense_name = data->dtada_data + rec1->dtrd_offset;

		(void) snprintf((char *)(event->offender_name),
		    EVENT_NAME_MAX, "%s", offense_name);
		(void) snprintf((char *)(event->offense_name),
		    EVENT_NAME_MAX, "<scheduled timeout expiration>");
	/*
	 * Report cross calls
	 */
	} else if (strcmp(aggdesc->dtagd_name, "events_x") == 0) {
		offense_name = data->dtada_data + rec1->dtrd_offset;

		(void) snprintf((char *)(event->offender_name),
		    EVENT_NAME_MAX, "%s", offense_name);

		switch (g_bit_depth) {
		case 32:
			/* LINTED - alignment */
			offender_addr = *(uint32_t *)(data->dtada_data +
			    rec2->dtrd_offset);
			break;
		case 64:
			/* LINTED - alignment */
			offender_addr = *(uint64_t *)(data->dtada_data +
			    rec2->dtrd_offset);
			break;
		}

		/*
		 * Try to resolve the address of the cross call function.
		 */
		if (offender_addr != 0 && dtrace_lookup_by_addr(dtp,
		    offender_addr, &sym, &dts) == 0) {
			(void) snprintf((char *)(event->offense_name),
			    EVENT_NAME_MAX, "<xcalls> %s`%s",
			    dts.dts_object, dts.dts_name);
		} else {
			(void) snprintf((char *)(event->offense_name),
			    EVENT_NAME_MAX, "<xcalls>");
		}
	/*
	 * Report cross calls from other CPUs than the one we're observing
	 * with the -C option
	 */
	} else if (strcmp(aggdesc->dtagd_name, "events_xc") == 0) {
		rec3 = &aggdesc->dtagd_rec[3];
		offense_name = data->dtada_data + rec1->dtrd_offset;

		(void) snprintf((char *)(event->offender_name),
		    EVENT_NAME_MAX, "%s", offense_name);

		switch (g_bit_depth) {
		case 32:
			/* LINTED - alignment */
			offender_addr = *(uint32_t *)(data->dtada_data +
			    rec2->dtrd_offset);
			break;
		case 64:
			/* LINTED - alignment */
			offender_addr = *(uint64_t *)(data->dtada_data +
			    rec2->dtrd_offset);
			break;
		}
		/* LINTED - alignment */
		offender_cpu = (int32_t *)(data->dtada_data +
		    rec3->dtrd_offset);

		/*
		 * Try to resolve the address of the cross call function.
		 */
		if (offender_addr != 0 && dtrace_lookup_by_addr(dtp,
		    offender_addr, &sym, &dts) == 0) {
			(void) snprintf((char *)(event->offense_name),
			    EVENT_NAME_MAX, "<xcalls> %s`%s (CPU %d)",
			    dts.dts_object, dts.dts_name, *offender_cpu);
		} else {
			(void) snprintf((char *)(event->offense_name),
			    EVENT_NAME_MAX, "<xcalls> (CPU %d)",
			    *offender_cpu);
		}
	/*
	 * Report unknown events
	 */
	} else {
		(void) snprintf((char *)(event->offender_name),
		    EVENT_NAME_MAX, "%s", "<unknown>");
		(void) snprintf((char *)(event->offense_name),
		    EVENT_NAME_MAX, "%s", "<unknown>");
	}

	for (i = 0; i < g_ncpus; i++) {
		/* LINTED - alignment */
		n += *((uint64_t *)(data->dtada_percpu[i]));
	}

	event->total_count = n;

	event++;
	g_top_events++;

	return (DTRACE_AGGWALK_NEXT);
}

int
pt_events_stat_prepare(void)
{
	dtrace_prog_t		*prog;
	dtrace_proginfo_t	info;
	dtrace_optval_t		statustime;
	int			err;
	char			*prog_ptr;

	event = g_event_info;

	if ((dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
		pt_error("cannot open dtrace library for the event report: "
		    "%s\n", dtrace_errmsg(NULL, err));
		return (-1);
	}

	/*
	 * Execute different scripts (defined in the platform specific file)
	 * depending on user specified options.
	 */
	if (PT_ON_VERBOSE) {
		prog_ptr = (char *)g_dtp_events_v;
	} else {
		if (PT_ON_CPU)
			prog_ptr = (char *)g_dtp_events_c;
		else
			prog_ptr = (char *)g_dtp_events;
	}

	if ((prog = dtrace_program_strcompile(dtp, prog_ptr,
	    DTRACE_PROBESPEC_NAME, 0, g_argc, g_argv)) == NULL) {
		pt_error("failed to compile the event report program\n");
		return (dtrace_errno(dtp));
	}

	if (dtrace_program_exec(dtp, prog, &info) == -1) {
		pt_error("failed to enable probes for the event report\n");
		return (dtrace_errno(dtp));
	}

	if (dtrace_setopt(dtp, "aggsize", "128k") == -1) {
		pt_error("failed to set 'aggsize' for the event report\n");
		return (dtrace_errno(dtp));
	}

	if (dtrace_setopt(dtp, "aggrate", "0") == -1) {
		pt_error("failed to set 'aggrate' for the event report\n");
		return (dtrace_errno(dtp));
	}

	if (dtrace_setopt(dtp, "aggpercpu", 0) == -1) {
		pt_error("failed to set 'aggpercpu' for the event report\n");
		return (dtrace_errno(dtp));
	}

	if (dtrace_go(dtp) != 0) {
		pt_error("failed to start the event report observation\n");
		return (dtrace_errno(dtp));
	}

	if (dtrace_getopt(dtp, "statusrate", &statustime) == -1) {
		pt_error("failed to get 'statusrate' for the event report\n");
		return (dtrace_errno(dtp));
	}

	return (0);
}

int
pt_events_stat_collect(void)
{
	g_top_events = 0;
	event = g_event_info;

	if (dtrace_status(dtp) == -1)
		return (-1);

	if (dtrace_aggregate_snap(dtp) != 0)
		pt_error("failed to collect data for the event report\n");

	if (dtrace_aggregate_walk_keyvarsorted(dtp, pt_events_walk, NULL) != 0)
		pt_error("failed to sort data for the event report\n");

	dtrace_aggregate_clear(dtp);

	return (0);
}
