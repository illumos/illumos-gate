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

#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <poll.h>
#include "powertop.h"

/*
 * Global variables, see powertop.h for comments and extern declarations.
 * These are ordered by type, grouped by usage.
 */
int			g_bit_depth;
int 			g_total_events, g_top_events;
int			g_npstates, g_max_cstate, g_longest_cstate;
uint_t			g_features;
uint_t			g_ncpus;
uint_t			g_ncpus_observed;

processorid_t 		*g_cpu_table;

double			g_interval_length;
hrtime_t		g_total_c_time;

uchar_t			g_op_mode;
boolean_t		g_gui;
uint_t			g_observed_cpu;

event_info_t    	g_event_info[EVENT_NUM_MAX];
state_info_t		g_cstate_info[NSTATES];
freq_state_info_t	g_pstate_info[NSTATES];
cpu_power_info_t	*g_cpu_power_states;

boolean_t		g_turbo_supported;
boolean_t		g_sig_resize;

uint_t			g_argc;
char			**g_argv;

static const int	true = 1;

void
pt_sig_handler(int sig)
{
	switch (sig) {
	case SIGWINCH:
		g_sig_resize = B_TRUE;
		break;
	}
}

int
main(int argc, char **argv)
{
	double		interval, interval_usr;
	hrtime_t 	interval_start;
	int		index2 = 0, c, dump_count = 0;
	char		*endptr, key;
	boolean_t	root_user = B_FALSE;
	struct pollfd	pollset;

	static struct option opts[] = {
		{ "dump", 1, NULL, 'd' },
		{ "time", 1, NULL, 't' },
		{ "help", 0, NULL, 'h' },
		{ "cpu", 1, NULL, 'c' },
		{ "verbose", 0, NULL, 'v' },
		{ 0, 0, NULL, 0 }
	};

	pt_set_progname(argv[0]);

	/*
	 * Enumerate the system's CPUs, populate cpu_table, g_ncpus
	 */
	if ((g_ncpus = g_ncpus_observed = pt_enumerate_cpus()) == 0)
		exit(EXIT_FAILURE);

	if ((g_bit_depth = pt_get_bit_depth()) < 0)
		exit(EXIT_FAILURE);

	g_features = 0;
	interval = interval_usr = INTERVAL_DEFAULT;
	g_op_mode = PT_MODE_DEFAULT;
	g_max_cstate = 0;
	g_argv = NULL;
	g_argc = 0;
	g_observed_cpu = 0;
	g_turbo_supported = B_FALSE;
	g_sig_resize = B_FALSE;
	g_curr_sugg = NULL;

	while ((c = getopt_long(argc, argv, "d:t:hvc:", opts, &index2))
	    != EOF) {
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			if (PT_ON_DUMP) {
				pt_usage();
				exit(EXIT_USAGE);
			}

			g_op_mode |= PT_MODE_DUMP;
			g_gui = B_FALSE;
			dump_count = (int)strtod(optarg, &endptr);

			if (dump_count <= 0 || *endptr != NULL) {
				pt_usage();
				exit(EXIT_USAGE);
			}

			break;
		case 't':
			if (PT_ON_TIME) {
				pt_usage();
				exit(EXIT_USAGE);
			}

			g_op_mode |= PT_MODE_TIME;
			interval = interval_usr = (double)strtod(optarg,
			    &endptr);

			if (*endptr != NULL || interval < 1 ||
			    interval > INTERVAL_MAX) {
				pt_usage();
				exit(EXIT_USAGE);
			}

			break;
		case 'v':
			if (PT_ON_CPU || PT_ON_VERBOSE) {
				pt_usage();
				exit(EXIT_USAGE);
			}

			g_op_mode |= PT_MODE_VERBOSE;
			break;
		case 'c':
			if (PT_ON_CPU || PT_ON_VERBOSE) {
				pt_usage();
				exit(EXIT_USAGE);
			}

			g_op_mode |= PT_MODE_CPU;
			g_observed_cpu = (uint_t)strtod(optarg, &endptr);

			if (g_observed_cpu >= g_ncpus) {
				pt_usage();
				exit(EXIT_USAGE);
			}

			g_argc = 1;
			g_ncpus_observed = 1;

			if ((g_argv = malloc(sizeof (char *))) == NULL)
				return (EXIT_FAILURE);

			if ((*g_argv = malloc(sizeof (char) * 5)) == NULL)
				return (EXIT_FAILURE);

			(void) snprintf(*g_argv, 5, "%d\0", g_observed_cpu);
			break;
		case 'h':
			pt_usage();
			exit(EXIT_SUCCESS);
		default:
			pt_usage();
			exit(EXIT_USAGE);
		}
	}

	if (optind < argc) {
		pt_usage();
		exit(EXIT_USAGE);
	}

	(void) printf("%s   %s\n\n", TITLE, COPYRIGHT_INTEL);

	(void) printf("Collecting data for %.2f second(s) \n",
	    (float)interval);

	/* Prepare P-state statistics */
	if (pt_cpufreq_stat_prepare() == 0)
		g_features |= FEATURE_PSTATE;

	/* Prepare C-state statistics */
	if (pt_cpuidle_stat_prepare() == 0)
		g_features |= FEATURE_CSTATE;
	else
		/*
		 * PowerTop was unable to run a DTrace program,
		 * most likely for lack of permissions.
		 */
		exit(EXIT_FAILURE);

	/* Prepare event statistics */
	if (pt_events_stat_prepare() != -1)
		g_features |= FEATURE_EVENTS;

	/*
	 * If the system is running on battery, find out what's
	 * the kstat module for it
	 */
	pt_battery_mod_lookup();

	/* Prepare turbo statistics */
	if (pt_turbo_stat_prepare() == 0)
		g_features |= FEATURE_TURBO;

	/*
	 * Initialize the display.
	 */
	if (!PT_ON_DUMP) {
		pt_display_init_curses();
		pt_display_setup(B_FALSE);
		(void) signal(SIGWINCH, pt_sig_handler);

		pt_display_title_bar();
		pt_display_status_bar();

		g_gui = B_TRUE;
		pollset.fd = STDIN_FILENO;
		pollset.events = POLLIN;
	}

	/*
	 * Installs the initial suggestions, running as root and turning CPU
	 * power management ON.
	 */
	if (geteuid() != 0) {
		pt_sugg_as_root();
	} else {
		root_user = B_TRUE;
		pt_cpufreq_suggest();
	}

	while (true) {
		key = 0;

		if (g_sig_resize)
			pt_display_resize();

		interval_start = gethrtime();

		if (!PT_ON_DUMP) {
			if (poll(&pollset, (nfds_t)1,
			    (int)(interval * MILLISEC)) > 0)
				(void) read(STDIN_FILENO, &key, 1);
		} else {
			(void) sleep((int)interval);
		}

		g_interval_length = (double)(gethrtime() - interval_start)
		    /NANOSEC;

		g_top_events = 0;
		g_total_events = 0;

		(void) memset(g_event_info, 0,
		    EVENT_NUM_MAX * sizeof (event_info_t));
		(void) memset(g_cstate_info, 0,
		    NSTATES * sizeof (state_info_t));

		/* Collect idle state transition stats */
		if (g_features & FEATURE_CSTATE &&
		    pt_cpuidle_stat_collect(g_interval_length) < 0) {
			/* Reinitialize C-state statistics */
			if (pt_cpuidle_stat_prepare() != 0)
				exit(EXIT_FAILURE);

			continue;
		}

		/* Collect frequency change stats */
		if (g_features & FEATURE_PSTATE &&
		    pt_cpufreq_stat_collect(g_interval_length) < 0) {
			/* Reinitialize P-state statistics */
			if (pt_cpufreq_stat_prepare() != 0)
				exit(EXIT_FAILURE);

			continue;
		}

		/* Collect event statistics */
		if (g_features & FEATURE_EVENTS &&
		    pt_events_stat_collect() < 0) {
			/* Reinitialize event statistics */
			if (pt_events_stat_prepare() != 0)
				exit(EXIT_FAILURE);

			continue;
		}

		/* Collect turbo statistics */
		if (g_features & FEATURE_TURBO &&
		    pt_turbo_stat_collect() < 0)
			exit(EXIT_FAILURE);

		/* Show CPU power states */
		pt_display_states();

		/* Show wakeups events affecting PM */
		if (g_features & FEATURE_EVENTS) {
			pt_display_wakeups(g_interval_length);
			pt_display_events(g_interval_length);
		}

		pt_battery_print();

		if (key && !PT_ON_DUMP) {
			switch (toupper(key)) {
			case 'Q':
				exit(EXIT_SUCCESS);
				break;

			case 'R':
				interval = 3;
				break;
			}

			/*
			 * Check if the user has activated the current
			 * suggestion.
			 */
			if (g_curr_sugg != NULL &&
			    toupper(key) == g_curr_sugg->key &&
			    g_curr_sugg->func)
				g_curr_sugg->func();
		}

		if (dump_count)
			dump_count--;

		/* Exits if user requested a dump */
		if (PT_ON_DUMP && !dump_count)
			exit(EXIT_SUCCESS);

		/* No key pressed, will suggest something */
		if (!key && !dump_count)
			pt_sugg_pick();

		/* Refresh display */
		if (!PT_ON_DUMP)
			pt_display_update();

		if (root_user)
			pt_cpufreq_suggest();

		/*
		 * Update the interval based on how long the CPU was in the
		 * longest c-state during the last snapshot. If the user
		 * specified an interval we skip this bit and keep it fixed.
		 */
		if (g_features & FEATURE_CSTATE && !PT_ON_TIME &&
		    g_longest_cstate > 0 &&
		    g_cstate_info[g_longest_cstate].events > 0) {
			double deep_idle_res = (((double)
			    g_cstate_info[g_longest_cstate].total_time/MICROSEC
			    /g_ncpus)/g_cstate_info[g_longest_cstate].events);

			if (deep_idle_res < INTERVAL_DEFAULT ||
			    (g_total_events/interval) < 1)
				interval = INTERVAL_DEFAULT;
			else
				interval = INTERVAL_UPDATE(deep_idle_res);
		} else {
			/*
			 * Restore interval after a refresh.
			 */
			if (key)
				interval = interval_usr;
		}
	}

	return (EXIT_SUCCESS);
}
