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

#include <stdlib.h>
#include <string.h>
#include <dtrace.h>
#include <kstat.h>
#include <errno.h>
#include "powertop.h"

/*
 * global turbo related variables definitions
 */
boolean_t		g_turbo_supported;
double			g_turbo_ratio;

/*
 * the variables to store kstat snapshot
 */
static turbo_info_t	*cpu_turbo_info = NULL;
static turbo_info_t	*t_new = NULL;

/*
 * Perform setup necessary to enumerate and track CPU turbo information
 */
static int
pt_turbo_init(void)
{
	kstat_ctl_t 		*kc;
	kstat_t 		*ksp;
	kstat_named_t 		*knp;

	/*
	 * check if the CPU turbo is supported
	 */
	if ((kc = kstat_open()) == NULL) {
		g_turbo_supported = B_FALSE;
		return (errno);
	}

	ksp = kstat_lookup(kc, "turbo", 0, NULL);
	if (ksp == NULL) {
		g_turbo_supported = B_FALSE;
		(void) kstat_close(kc);
		return (-1);
	}

	(void) kstat_read(kc, ksp, NULL);

	knp = kstat_data_lookup(ksp, "turbo_supported");
	if (knp == NULL) {
		pt_error("%s : couldn't find item turbo_supported\n", __FILE__);
		g_turbo_supported = B_FALSE;
		(void) kstat_close(kc);
		return (-2);
	}

	/*
	 * initialize turbo information structure if turbo mode is supported
	 */
	if (knp->value.ui32) {
		g_turbo_supported = B_TRUE;
		cpu_turbo_info = calloc((size_t)g_ncpus, sizeof (turbo_info_t));
		t_new = calloc((size_t)g_ncpus, sizeof (turbo_info_t));
	}

	(void) kstat_close(kc);
	return (0);
}

/*
 * Take a snapshot of each CPU's turbo information
 * by looking through the turbo kstats.
 */
static int
pt_turbo_snapshot(turbo_info_t *turbo_snapshot)
{
	kstat_ctl_t 		*kc;
	kstat_t 		*ksp;
	kstat_named_t 		*knp;
	int 			cpu;
	turbo_info_t		*turbo_info;

	if ((kc = kstat_open()) == NULL)
		return (errno);

	for (cpu = 0; cpu < g_ncpus; cpu++) {
		turbo_info = &turbo_snapshot[cpu];
		ksp = kstat_lookup(kc, "turbo", cpu_table[cpu], NULL);
		if (ksp == NULL) {
			pt_error("%s : couldn't find turbo kstat for CPU "
			"%d\n", __FILE__, cpu);
			(void) kstat_close(kc);
			return (-1);
		}

		if (kstat_read(kc, ksp, NULL) == -1) {
			pt_error("%s : couldn't read turbo kstat for "
			    "CPU %d\n", __FILE__, cpu);
			(void) kstat_close(kc);
			return (-2);
		}

		knp = kstat_data_lookup(ksp, "turbo_mcnt");
		if (knp == NULL) {
			pt_error("%s : couldn't find turbo mcnt "
			    "kstat for CPU %d\n", __FILE__, cpu);
			(void) kstat_close(kc);
			return (-3);
		}

		/*
		 * snapshot IA32_MPERF_MSR
		 */
		turbo_info->t_mcnt = knp->value.ui64;

		knp = kstat_data_lookup(ksp, "turbo_acnt");
		if (knp == NULL) {
			pt_error("%s : couldn't find turbo acnt "
			    "kstat for CPU %d\n", __FILE__, cpu);
			(void) kstat_close(kc);
			return (-4);
		}

		/*
		 * snapshot IA32_APERF_MSR
		 */
		turbo_info->t_acnt = knp->value.ui64;
	}

	if (kstat_close(kc) != 0)
		pt_error("%s : couldn't close kstat\n", __FILE__);

	return (0);
}

/*
 * turbo support checking and information initialization
 */
int
pt_turbo_stat_prepare(void)
{
	int	ret;

	ret = pt_turbo_init();

	if (ret != 0) {
		return (ret);
	}

	ret = pt_turbo_snapshot(cpu_turbo_info);

	if (ret != 0) {
		pt_error("%s : turbo snapshot failed\n", __FILE__);
	}

	return (ret);
}

/*
 * when doing the statistics collection, we compare two kstat snapshot
 * and get a delta. the final ratio of performance boost will be worked
 * out according to the kstat delta
 */
int
pt_turbo_stat_collect(void)
{
	int		cpu;
	uint64_t	delta_mcnt, delta_acnt;
	double		ratio;
	int		ret;

	/*
	 * take a snapshot of turbo information to setup turbo_info_t
	 * structure
	 */
	ret = pt_turbo_snapshot(t_new);
	if (ret != 0) {
		pt_error("%s : turbo stat collect failed\n", __FILE__);
		return (ret);
	}

	/*
	 * calculate the kstat delta and work out the performance boost ratio
	 */
	for (cpu = 0; cpu < g_ncpus; cpu++) {
		delta_mcnt = t_new[cpu].t_mcnt - cpu_turbo_info[cpu].t_mcnt;
		delta_acnt = t_new[cpu].t_acnt - cpu_turbo_info[cpu].t_acnt;

		if ((delta_mcnt > delta_acnt) || (delta_mcnt == 0))
			ratio = 1.0;
		else
			ratio = (double)delta_acnt / (double)delta_mcnt;
		g_turbo_ratio += ratio;
	}

	g_turbo_ratio = g_turbo_ratio / (double)g_ncpus;

	/*
	 * update the structure of the kstat for the next time calculation
	 */
	(void) memcpy(cpu_turbo_info, t_new, g_ncpus * (sizeof (turbo_info_t)));

	return (0);
}
