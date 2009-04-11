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
#include <string.h>
#include <ctype.h>
#include <locale.h>
#include "powertop.h"

/*
 * Global variables, see powertop.h for comments and extern declarations.
 * These are ordered by type, grouped by usage.
 */
double 			g_ticktime, g_ticktime_usr;
double 			g_interval;
double			g_displaytime;

int			g_bit_depth;
int 			g_total_events, g_tog_p_events;
int			g_npstates, g_max_cstate, g_longest_cstate;
uint_t			g_ncpus;
uint_t			g_ncpus_observed;

processorid_t 		*g_cpu_table;

hrtime_t		g_total_c_time;

uchar_t			g_op_mode;
boolean_t		g_gui;
uint_t			g_observed_cpu;

event_info_t    	g_event_info[EVENT_NUM_MAX];
event_info_t		*g_p_event;
state_info_t		g_cstate_info[NSTATES];
freq_state_info_t	g_pstate_info[NSTATES];
cpu_power_info_t	*g_cpu_power_states;
suggestion_func 	*g_suggestion_activate;

boolean_t		g_turbo_supported;

uint_t			g_argc;
char			**g_argv;

char			*optarg;

static const int	true = 1;

int
main(int argc, char **argv)
{
	hrtime_t 	last, now;
	uint_t		features = 0, user_interval = 0;
	int		ncursesinited = 0, index2 = 0, c, ret, dump_count = 0;
	double		last_time;
	char		*endptr;

	static struct option opts[] = {
		{ "dump", 1, NULL, 'd' },
		{ "time", 1, NULL, 't' },
		{ "help", 0, NULL, 'h' },
		{ "cpu", 1, NULL, 'c' },
		{ "verbose", 0, NULL, 'v' },
		{ 0, 0, NULL, 0 }
	};

	(void) setlocale(LC_ALL, "");
	(void) bindtextdomain("powertop", "/usr/share/locale");
	(void) textdomain("powertop");

	pt_set_progname(argv[0]);

	/*
	 * Enumerate the system's CPUs
	 * Populate cpu_table, g_ncpus
	 */
	if ((g_ncpus = g_ncpus_observed = enumerate_cpus()) == 0)
		exit(EXIT_FAILURE);

	if ((g_bit_depth = get_bit_depth()) < 0)
		exit(EXIT_FAILURE);

	g_ticktime = g_ticktime_usr = INTERVAL_DEFAULT;
	g_displaytime 	= 0.0;
	g_op_mode	= PTOP_MODE_DEFAULT;
	g_gui		= B_FALSE;
	g_max_cstate	= 0;
	g_argv		= NULL;
	g_argc		= 0;
	g_observed_cpu	= 0;
	g_turbo_supported = B_FALSE;

	while ((c = getopt_long(argc, argv, "d:t:h:vc:", opts, &index2))
	    != EOF) {
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			if (PTOP_ON_DUMP)
				usage();

			g_op_mode |= PTOP_MODE_DUMP;
			dump_count = (int)strtod(optarg, &endptr);

			if (dump_count <= 0 || *endptr != NULL)
				usage();
			break;
		case 't':
			if (user_interval)
				usage();

			user_interval = 1;
			g_ticktime = g_ticktime_usr = (double)strtod(optarg,
			    &endptr);

			if (*endptr != NULL || g_ticktime < 1 ||
			    g_ticktime > INTERVAL_MAX)
				usage();
			break;
		case 'v':
			if (PTOP_ON_CPU || PTOP_ON_VERBOSE)
				usage();

			g_op_mode |= PTOP_MODE_VERBOSE;
			break;
		case 'c':
			if (PTOP_ON_CPU || PTOP_ON_VERBOSE)
				usage();

			g_op_mode |= PTOP_MODE_CPU;
			g_observed_cpu = (uint_t)strtod(optarg, &endptr);

			if (g_observed_cpu >= g_ncpus)
				usage();

			g_argc = 1;
			g_ncpus_observed = 1;

			if ((g_argv = malloc(sizeof (char *))) == NULL)
				return (EXIT_FAILURE);

			if ((*g_argv = malloc(sizeof (char) * 5)) == NULL)
				return (EXIT_FAILURE);

			(void) snprintf(*g_argv, 5, "%d\0", g_observed_cpu);
			break;
		case 'h':
		default:
			usage();
			return (EXIT_USAGE);
		}
	}

	if (optind < argc) {
		usage();
	}

	(void) printf("%s   %s\n\n", TITLE, COPYRIGHT_INTEL);

	/*
	 * If the system is running on battery, find out what's
	 * the kstat module for it
	 */
	battery_mod_lookup();

	/* Prepare C-state statistics */
	ret = pt_cpuidle_stat_prepare();
	if (ret == 0)
		features |= FEATURE_CSTATE;
	else
		/*
		 * PowerTop was unable to run a DTrace program,
		 * most likely for lack of permissions.
		 */
		exit(EXIT_FAILURE);

	/* Prepare P-state statistics */
	if (pt_cpufreq_stat_prepare() == 0)
		features |= FEATURE_PSTATE;

	/* Prepare event statistics */
	if (pt_events_stat_prepare() != -1)
		features |= FEATURE_EVENTS;

	/* Prepare turbo statistics */
	if (pt_turbo_stat_prepare() == 0) {
		features |= FEATURE_TURBO;
	}

	(void) printf(_("Collecting data for %.2f second(s) \n"),
	    (float)g_ticktime);

	if (!PTOP_ON_DUMP)
		g_gui = B_TRUE;

	last = gethrtime();

	while (true) {
		fd_set 	rfds;
		struct 	timeval tv;
		int 	key, reinit = 0;
		char 	keychar;

		/*
		 * Sleep for a while waiting either for input (if we're not
		 * in dump mode) or for the timeout to elapse
		 */
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);

		tv.tv_sec 	= (long)g_ticktime;
		tv.tv_usec 	= (long)((g_ticktime - tv.tv_sec) * 1000000);

		if (!PTOP_ON_DUMP)
			key = select(1, &rfds, NULL, NULL, &tv);
		else
			key = select(1, NULL, NULL, NULL, &tv);

		now 		= gethrtime();

		g_interval 	= (double)(now - last)/NANOSEC;
		last 		= now;

		g_tog_p_events 	= 0;
		g_total_events 	= 0;

		(void) memset(g_event_info, 0,
		    EVENT_NUM_MAX * sizeof (event_info_t));
		(void) memset(g_cstate_info, NSTATES
		    * sizeof (state_info_t), 0);

		/* Collect idle state transition stats */
		if (features & FEATURE_CSTATE &&
		    pt_cpuidle_stat_collect(g_interval) < 0) {
			/* Reinitialize C-state statistics */
			if (pt_cpuidle_stat_prepare() != 0)
				exit(EXIT_FAILURE);

			reinit = 1;
		}

		/* Collect frequency change stats */
		if (features & FEATURE_PSTATE &&
		    pt_cpufreq_stat_collect(g_interval) < 0) {
			/* Reinitialize P-state statistics */
			if (pt_cpufreq_stat_prepare() != 0)
				exit(EXIT_FAILURE);

			reinit = 1;
		}

		/* Collect event statistics */
		if (features & FEATURE_EVENTS &&
		    pt_events_stat_collect() < 0) {
			/* Reinitialize event statistics */
			if (pt_events_stat_prepare() != 0)
				exit(EXIT_FAILURE);

			reinit = 1;
		}

		if (reinit)
			continue;

		/* Collect turbo statistics */
		if (features & FEATURE_TURBO &&
		    pt_turbo_stat_collect() < 0) {
			exit(EXIT_FAILURE);
		}

		/*
		 * Initialize curses if we're not dumping and
		 * haven't already done it
		 */
		if (!PTOP_ON_DUMP) {
			if (!ncursesinited) {
				initialize_curses();
				ncursesinited++;
			}
			setup_windows();
			show_title_bar();
		}

		/* Show CPU power states */
		if (features & FEATURE_CSTATE)
			show_cstates();

		/* Show wakeups events affecting PM */
		if (features & FEATURE_EVENTS) {
			show_wakeups(g_interval);
			show_eventstats(g_interval);
		}

		print_battery();

		g_displaytime = g_displaytime - g_ticktime;

		if (key && !PTOP_ON_DUMP) {
			keychar = toupper(fgetc(stdin));

			switch (keychar) {
			case 'Q':
				cleanup_curses();
				exit(EXIT_SUCCESS);
				break;
			case 'R':
				g_ticktime = 3;
				break;
			}
			if (keychar == g_suggestion_key &&
			    g_suggestion_activate) {
				g_suggestion_activate();
				g_displaytime = -1.0;
			}
		}
		reset_suggestions();

		/* suggests PM */
		if (geteuid() == 0) {
			suggest_p_state();
		} else {
			suggest_as_root();
		}

		if (dump_count)
			dump_count--;

		/* Exits if user requested a dump */
		if (PTOP_ON_DUMP && !dump_count) {
			print_all_suggestions();
			exit(EXIT_SUCCESS);
		}

		/* No key pressed, will suggest something */
		if (!key && !dump_count)
			pick_suggestion();

		/* Refresh display */
		if (!PTOP_ON_DUMP) {
			show_title_bar();
			update_windows();
		}

		/*
		 * Update the interval based on how long the CPU was in the
		 * longest c-state during the last snapshot. If the user
		 * specified an interval we skip this bit and keep it fixed.
		 */
		last_time = (((double)g_cstate_info[g_longest_cstate].total_time
		    /g_ncpus)/g_cstate_info[g_longest_cstate].events);

		if (!user_interval)
			if (last_time < INTERVAL_DEFAULT ||
			    (g_total_events/g_ticktime) < 1)
				g_ticktime = INTERVAL_DEFAULT;
			else
				g_ticktime = INTERVAL_UPDATE(last_time);

		/*
		 * Restore user specified interval after a refresh
		 */
		if (keychar == 'R' && user_interval)
			g_ticktime = g_ticktime_usr;
	}
	return (EXIT_SUCCESS);
}

void
suggest_as_root(void)
{
	add_suggestion("Suggestion: run as root to get suggestions"
	    " for reducing system power consumption",  40, NULL, NULL,
	    NULL);
}
