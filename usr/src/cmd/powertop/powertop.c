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

#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>
#include "powertop.h"

int 		g_ncpus;
processorid_t 	*cpu_table;
const int	true = 1;

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
		{ "verbose", 0, NULL, 'v' },
		{ 0, 0, NULL, 0 }
	};

	(void) setlocale(LC_ALL, "");
	(void) bindtextdomain("powertop", "/usr/share/locale");
	(void) textdomain("powertop");

	pt_set_progname(argv[0]);

	if ((bit_depth = get_bit_depth()) < 0)
		exit(EXIT_FAILURE);

	ticktime = ticktime_usr = INTERVAL_DEFAULT;
	displaytime 	= 0.0;
	dump 		= 0;
	event_mode	= ' ';
	max_cstate	= 0;

	while ((c = getopt_long(argc, argv, "d:vt:h", opts, &index2)) != EOF) {
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			if (dump)
				usage();

			dump = 1;
			dump_count = (int)strtod(optarg, &endptr);

			if (dump_count <= 0 || *endptr != NULL)
				usage();
			break;
		case 't':
			if (user_interval)
				usage();

			user_interval = 1;
			ticktime = ticktime_usr = (double)strtod(optarg,
			    &endptr);

			if (*endptr != NULL || ticktime < 1 ||
			    ticktime > INTERVAL_MAX)
				usage();
			break;
		case 'v':
			if (event_mode == 'v')
				usage();

			event_mode = 'v';
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

	(void) printf("%s   (C) 2008 Intel Corporation\n\n", TITLE);

	/*
	 * Enumerate the system's CPUs
	 * Populate cpu_table, g_ncpus
	 */
	enumerate_cpus();

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

	(void) printf(_("Collecting data for %.2f second(s) \n"),
	    (float)ticktime);

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

		tv.tv_sec 	= (long)ticktime;
		tv.tv_usec 	= (long)((ticktime - tv.tv_sec) * 1000000);

		if (!dump)
			key = select(1, &rfds, NULL, NULL, &tv);
		else
			key = select(1, NULL, NULL, NULL, &tv);

		now 		= gethrtime();

		g_interval 	= (double)(now - last)/NANOSEC;
		last 		= now;

		top_events 	= 0;
		total_events 	= 0;

		(void) memset(event_info, EVENT_NUM_MAX * sizeof (event_info_t),
		    0);
		(void) memset(cstate_info, 2 * sizeof (state_info_t), 0);

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

		/*
		 * Initialize curses if we're not dumping and
		 * haven't already done it
		 */
		if (!dump) {
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

		displaytime = displaytime - ticktime;

		if (key && !dump) {
			keychar = toupper(fgetc(stdin));

			switch (keychar) {
			case 'Q':
				cleanup_curses();
				exit(EXIT_SUCCESS);
				break;
			case 'R':
				ticktime = 3;
				break;
			}
			if (keychar == suggestion_key && suggestion_activate) {
				suggestion_activate();
				displaytime = -1.0;
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
		if (dump && !dump_count) {
			print_all_suggestions();
			exit(EXIT_SUCCESS);
		}

		/* No key pressed, will suggest something */
		if (!key && !dump_count)
			pick_suggestion();

		/* Refresh display */
		if (!dump) {
			show_title_bar();
			update_windows();
		}

		/*
		 * Update the interval based on how long the CPU was in the
		 * longest c-state during the last snapshot. If the user
		 * specified an interval we skip this bit and keep it fixed.
		 */
		last_time = (((double)cstate_info[longest_cstate].total_time/
		    g_ncpus)/cstate_info[longest_cstate].events);

		if (!user_interval)
			if (last_time < INTERVAL_DEFAULT ||
			    (total_events/ticktime) < 1)
				ticktime = INTERVAL_DEFAULT;
			else
				ticktime = INTERVAL_UPDATE(last_time);

		/*
		 * Restore user specified interval after a refresh
		 */
		if (keychar == 'R' && user_interval)
			ticktime = ticktime_usr;
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
