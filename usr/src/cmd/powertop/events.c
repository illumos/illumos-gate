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
#include <stdlib.h>
#include <dtrace.h>
#include "powertop.h"

static dtrace_hdl_t *g_dtp;
/*
 * DTrace scripts for observing interrupts, callouts and cyclic events
 * that cause CPU activity. Such activity prevents the processor from
 * entering lower power states and reducing power consumption.
 *
 * g_prog is the default script
 */
static const char *g_prog =
"interrupt-complete"
"/arg0 != NULL && arg3 !=0/"
"{"
"	this->devi = (struct dev_info *)arg0;"
"	@interrupts[stringof(`devnamesp[this->devi->devi_major].dn_name),"
"	     this->devi->devi_instance] = count();"
"}"
""
"sdt:::callout-start"
"/(caddr_t)((callout_t *)arg0)->c_func == (caddr_t)&`setrun/"
"{"
"       this->thr = (kthread_t *)(((callout_t *)arg0)->c_arg);"
"       @events_u[stringof(this->thr->t_procp->p_user.u_comm)] = count();"
"}"
""
"sdt:::callout-start"
"/(caddr_t)((callout_t *)arg0)->c_func != (caddr_t)&`setrun/"
"{"
"       @events_k[(caddr_t)((callout_t *)arg0)->c_func] = count();"
"}"
""
"sdt:::cyclic-start"
"/(caddr_t)((cyclic_t *)arg0)->cy_handler == (caddr_t)&`clock/"
"{"
"	@events_k[(caddr_t)((cyclic_t *)arg0)->cy_handler] = count();"
"}"
""
"sysinfo:::xcalls"
"/pid != $pid/"
"{"
"       @events_x[execname] = sum(arg0);"
"}";

/*
 * g_prog_V is enabled through the -v option, it includes cyclic events
 * in the report, allowing a complete view of system activity
 */
static const char *g_prog_v =
"interrupt-complete"
"/arg0 != NULL && arg3 !=0/"
"{"
"	this->devi = (struct dev_info *)arg0;"
"	@interrupts[stringof(`devnamesp[this->devi->devi_major].dn_name),"
"	     this->devi->devi_instance] = count();"
"}"
""
"sdt:::callout-start"
"/(caddr_t)((callout_t *)arg0)->c_func == (caddr_t)&`setrun/"
"{"
"       this->thr = (kthread_t *)(((callout_t *)arg0)->c_arg);"
"       @events_u[stringof(this->thr->t_procp->p_user.u_comm)] = count();"
"}"
""
"sdt:::callout-start"
"/(caddr_t)((callout_t *)arg0)->c_func != (caddr_t)&`setrun/"
"{"
"       @events_k[(caddr_t)((callout_t *)arg0)->c_func] = count();"
"}"
""
"sdt:::cyclic-start"
"/(caddr_t)((cyclic_t *)arg0)->cy_handler != (caddr_t)&`dtrace_state_deadman &&"
" (caddr_t)((cyclic_t *)arg0)->cy_handler != (caddr_t)&`dtrace_state_clean/"
"{"
"	@events_k[(caddr_t)((cyclic_t *)arg0)->cy_handler] = count();"
"}"
""
"sysinfo:::xcalls"
"/pid != $pid/"
"{"
"       @events_x[execname] = sum(arg0);"
"}";

/*ARGSUSED*/
static int
walk(const dtrace_aggdata_t *data, void *arg)
{
	dtrace_aggdesc_t 	*aggdesc = data->dtada_desc;
	dtrace_recdesc_t 	*rec1, *rec2;
	dtrace_syminfo_t 	dts;
	char 			*offense_name;
	uint64_t		offender_addr;
	int32_t 		*instance;
	int 			i;
	uint64_t 		n = 0;
	GElf_Sym 		sym;

	if (top_events >= EVENT_NUM_MAX)
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
		(void) snprintf((char *)(p_event->offender_name),
		    EVENT_NAME_MAX, "%s", "<interrupt>");
		(void) snprintf((char *)(p_event->offense_name), EVENT_NAME_MAX,
		    "%s#%d", offense_name, *instance);
	/*
	 * Report kernel events
	 */
	} else if (strcmp(aggdesc->dtagd_name, "events_k") == 0) {

		(void) snprintf((char *)(p_event->offender_name),
		    EVENT_NAME_MAX, "%s", "<kernel>");

		/*
		 * Casting offender_addr to the wrong type will cause
		 * dtrace_lookup_by_addr to return 0 and the report
		 * to show an address instead of a name.
		 */
		switch (bit_depth) {
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
		if (dtrace_lookup_by_addr(g_dtp, offender_addr,
		    &sym, &dts) == 0) {
			(void) snprintf((char *)(p_event->offense_name),
			    EVENT_NAME_MAX, "%s`%s", dts.dts_object,
			    dts.dts_name);
		} else {
			(void) snprintf((char *)(p_event->offense_name),
			    EVENT_NAME_MAX, "0x%llx", offender_addr);
		}
	/*
	 * Report user events
	 */
	} else if (strcmp(aggdesc->dtagd_name, "events_u") == 0) {
		offense_name = data->dtada_data + rec1->dtrd_offset;

		(void) snprintf((char *)(p_event->offender_name),
		    EVENT_NAME_MAX, "%s", offense_name);
		(void) snprintf((char *)(p_event->offense_name),
		    EVENT_NAME_MAX, "<scheduled timeout expiration>");
	/*
	 * Report cross calls
	 */
	} else if (strcmp(aggdesc->dtagd_name, "events_x") == 0) {
		offense_name = data->dtada_data + rec1->dtrd_offset;

		(void) snprintf((char *)(p_event->offender_name),
		    EVENT_NAME_MAX, "%s", offense_name);
		(void) snprintf((char *)(p_event->offense_name),
		    EVENT_NAME_MAX, "<cross calls>");
	/*
	 * Report unknown events
	 */
	} else {
		(void) snprintf((char *)(p_event->offender_name),
		    EVENT_NAME_MAX, "%s", "<unknown>");
		(void) snprintf((char *)(p_event->offense_name),
		    EVENT_NAME_MAX, "%s", "<unknown>");
	}

	for (i = 0; i < g_ncpus; i++)
		/* LINTED - alignment */
		n += *((uint64_t *)(data->dtada_percpu[i]));

	p_event->total_count = n;

	p_event++;
	top_events++;

	return (DTRACE_AGGWALK_NEXT);
}

int
pt_events_stat_prepare(void)
{
	dtrace_prog_t 		*prog;
	dtrace_proginfo_t 	info;
	int 			err;
	dtrace_optval_t 	statustime;

	p_event = event_info;

	if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
		pt_error("%s : cannot open dtrace library: %s\n", __FILE__,
		    dtrace_errmsg(NULL, err));
		return (-1);
	}

	/*
	 * Execute different scripts (defined above) depending on
	 * user specified options. Default mode has event_mode empty
	 */
	switch (event_mode) {
	default:
		if ((prog = dtrace_program_strcompile(g_dtp, g_prog,
		    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL) {
			pt_error("%s : failed to compile g_prog\n", __FILE__);
			return (dtrace_errno(g_dtp));
		}
		break;
	case 'v':
		if ((prog = dtrace_program_strcompile(g_dtp, g_prog_v,
		    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL) {
			pt_error("%s : failed to compile g_prog_v\n", __FILE__);
			return (dtrace_errno(g_dtp));
		}
		break;
	}

	if (dtrace_program_exec(g_dtp, prog, &info) == -1) {
		pt_error("%s : failed to enable probes\n", __FILE__);
		return (dtrace_errno(g_dtp));
	}
	if (dtrace_setopt(g_dtp, "aggsize", "128k") == -1) {
		pt_error("%s : failed to set 'aggsize'\n", __FILE__);
		return (dtrace_errno(g_dtp));
	}
	if (dtrace_setopt(g_dtp, "aggrate", "0") == -1) {
		pt_error("%s : failed to set 'aggrate'\n", __FILE__);
		return (dtrace_errno(g_dtp));
	}
	if (dtrace_setopt(g_dtp, "aggpercpu", 0) == -1) {
		pt_error("%s : failed to set 'aggpercpu'\n", __FILE__);
		return (dtrace_errno(g_dtp));
	}
	if (dtrace_go(g_dtp) != 0) {
		pt_error("%s : dtrace_go() failed\n", __FILE__);
		return (dtrace_errno(g_dtp));
	}
	if (dtrace_getopt(g_dtp, "statusrate", &statustime) == -1) {
		pt_error("%s : failed to get 'statusrate'\n", __FILE__);
		return (dtrace_errno(g_dtp));
	}
	return (0);
}

int
pt_events_stat_collect(void)
{
	p_event 	= event_info;
	top_events 	= 0;

	if (dtrace_status(g_dtp) == -1)
		return (-1);

	if (dtrace_aggregate_snap(g_dtp) != 0)
		pt_error("%s : failed to add to aggregate", __FILE__);

	if (dtrace_aggregate_walk_keyvarsorted(g_dtp, walk, NULL) != 0)
		pt_error("%s : failed to sort aggregate", __FILE__);

	dtrace_aggregate_clear(g_dtp);

	return (0);
}
