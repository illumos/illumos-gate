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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
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
#include <unistd.h>
#include <curses.h>
#include <signal.h>
#include <fcntl.h>
#include "powertop.h"

/*
 * Minimum terminal height and width to run PowerTOP on curses mode.
 */
#define	PT_MIN_COLS		70
#define	PT_MIN_ROWS		15

/*
 * Display colors
 */
#define	PT_COLOR_DEFAULT	1
#define	PT_COLOR_HEADER_BAR	2
#define	PT_COLOR_ERROR		3
#define	PT_COLOR_RED		4
#define	PT_COLOR_YELLOW		5
#define	PT_COLOR_GREEN		6
#define	PT_COLOR_BRIGHT		7
#define	PT_COLOR_BLUE		8

/*
 * Constants for pt_display_setup()
 */
#define	SINGLE_LINE_SW 		1
#define	LENGTH_SUGG_SW		2
#define	TITLE_LINE		1
#define	BLANK_LINE		1
#define	NEXT_LINE		1

#define	print(win, y, x, fmt, args...)				\
	if (PT_ON_DUMP)						\
		(void) printf(fmt, ## args);			\
	else							\
		(void) mvwprintw(win, y, x, fmt, ## args);

enum pt_subwindows {
	SW_TITLE,
	SW_IDLE,
	SW_FREQ,
	SW_WAKEUPS,
	SW_POWER,
	SW_EVENTS,
	SW_SUGG,
	SW_STATUS,
	SW_COUNT
};

typedef struct sb_slot {
	char *msg;
	struct sb_slot *prev;
	struct sb_slot *next;
} sb_slot_t;

static WINDOW *sw[SW_COUNT];
static int win_cols, win_rows;
static sb_slot_t *status_bar;

/*
 * Delete all subwindows and reset the terminal to a non-visual mode. This
 * routine is used during resize events and before exiting.
 */
static void
pt_display_cleanup(void)
{
	int i;

	for (i = 0; i < SW_COUNT; i++) {
		if (sw[i] != NULL) {
			(void) delwin(sw[i]);
			sw[i] = NULL;
		}
	}

	(void) endwin();
	(void) fflush(stdout);
	(void) putchar('\r');
}

static void
pt_display_get_size(void)
{
	getmaxyx(stdscr, win_rows, win_cols);

	if (win_rows < PT_MIN_ROWS || win_cols < PT_MIN_COLS) {
		pt_display_cleanup();
		(void) printf("\n\nPowerTOP cannot run in such a small "
		    "terminal window. Please resize it.\n\n");
		exit(EXIT_FAILURE);
	}
}

void
pt_display_resize(void)
{
	pt_display_cleanup();
	(void) pt_display_init_curses();
	pt_display_setup(B_TRUE);

	pt_display_title_bar();

	pt_display_states();

	if (g_features & FEATURE_EVENTS) {
		pt_display_wakeups(g_interval_length);
		pt_display_events(g_interval_length);
	}

	pt_battery_print();
	pt_sugg_pick();
	pt_display_status_bar();

	pt_display_update();

	g_sig_resize = B_FALSE;
	(void) signal(SIGWINCH, pt_sig_handler);
}

/*
 * This part was re-written to be human readable and easy to modify. Please
 * try to keep it that way and help us save some time.
 *
 * Friendly reminder:
 * 	subwin(WINDOW *orig, int nlines, int ncols, int begin_y, int begin_x)
 */
void
pt_display_setup(boolean_t resized)
{
	/*
	 * These variables are used to properly set the initial y position and
	 * number of lines in each subwindow, as the number of supported CPU
	 * states affects their placement.
	 */
	int cstate_lines, event_lines, pos_y = 0;

	/*
	 * In theory, all systems have at least two idle states. We add two here
	 * since we have to use DTrace to figure out how many this box has.
	 */
	cstate_lines = TITLE_LINE + max((g_max_cstate+2), g_npstates);

	sw[SW_TITLE] = subwin(stdscr, SINGLE_LINE_SW, win_cols, pos_y, 0);

	pos_y += NEXT_LINE + BLANK_LINE;
	sw[SW_IDLE] = subwin(stdscr, cstate_lines, win_cols/2 + 1, pos_y, 0);
	sw[SW_FREQ] = subwin(stdscr, cstate_lines, win_cols/2 - 8, pos_y,
	    win_cols/2 + 8);

	pos_y += cstate_lines + BLANK_LINE;
	sw[SW_WAKEUPS] = subwin(stdscr, SINGLE_LINE_SW, win_cols, pos_y, 0);

	pos_y += NEXT_LINE;
	sw[SW_POWER] = subwin(stdscr, SINGLE_LINE_SW, win_cols, pos_y, 0);

	pos_y += NEXT_LINE + BLANK_LINE;
	event_lines = win_rows - SINGLE_LINE_SW - NEXT_LINE - LENGTH_SUGG_SW -
	    pos_y;

	if (event_lines > 0) {
		sw[SW_EVENTS] = subwin(stdscr, event_lines, win_cols, pos_y, 0);
	} else {
		pt_display_cleanup();
		(void) printf("\n\nPowerTOP cannot run in such a small "
		    "terminal window, please resize it.\n\n");
		exit(EXIT_FAILURE);
	}

	pos_y += event_lines + NEXT_LINE;
	sw[SW_SUGG] = subwin(stdscr, SINGLE_LINE_SW, win_cols, pos_y, 0);

	pos_y += BLANK_LINE + NEXT_LINE;
	sw[SW_STATUS] = subwin(stdscr, SINGLE_LINE_SW, win_cols, pos_y, 0);

	if (!resized) {
		status_bar = NULL;

		pt_display_mod_status_bar("Q - Quit");
		pt_display_mod_status_bar("R - Refresh");
	}
}

/*
 * This routine handles all the necessary curses initialization.
 */
void
pt_display_init_curses(void)
{
	(void) initscr();

	(void) atexit(pt_display_cleanup);

	pt_display_get_size();

	(void) start_color();

	/*
	 * Enable keyboard mapping
	 */
	(void) keypad(stdscr, TRUE);

	/*
	 * Tell curses not to do NL->CR/NL on output
	 */
	(void) nonl();

	/*
	 * Take input chars one at a time, no wait for \n
	 */
	(void) cbreak();

	/*
	 * Dont echo input
	 */
	(void) noecho();

	/*
	 * Turn off cursor
	 */
	(void) curs_set(0);

	(void) init_pair(PT_COLOR_DEFAULT, COLOR_WHITE, COLOR_BLACK);
	(void) init_pair(PT_COLOR_HEADER_BAR, COLOR_BLACK, COLOR_WHITE);
	(void) init_pair(PT_COLOR_ERROR, COLOR_BLACK, COLOR_RED);
	(void) init_pair(PT_COLOR_RED, COLOR_WHITE, COLOR_RED);
	(void) init_pair(PT_COLOR_YELLOW, COLOR_WHITE, COLOR_YELLOW);
	(void) init_pair(PT_COLOR_GREEN, COLOR_WHITE, COLOR_GREEN);
	(void) init_pair(PT_COLOR_BLUE, COLOR_WHITE, COLOR_BLUE);
	(void) init_pair(PT_COLOR_BRIGHT, COLOR_WHITE, COLOR_BLACK);
}

void
pt_display_update(void)
{
	(void) doupdate();
}

void
pt_display_title_bar(void)
{
	char title_pad[10];

	(void) wattrset(sw[SW_TITLE], COLOR_PAIR(PT_COLOR_HEADER_BAR));
	(void) wbkgd(sw[SW_TITLE], COLOR_PAIR(PT_COLOR_HEADER_BAR));
	(void) werase(sw[SW_TITLE]);

	(void) snprintf(title_pad, 10, "%%%ds",
	    (win_cols - strlen(TITLE))/2 + strlen(TITLE));

	/* LINTED: E_SEC_PRINTF_VAR_FMT */
	print(sw[SW_TITLE], 0, 0, title_pad, TITLE);

	(void) wnoutrefresh(sw[SW_TITLE]);
}

void
pt_display_status_bar(void)
{
	sb_slot_t *n = status_bar;
	int x = 0;

	(void) werase(sw[SW_STATUS]);

	while (n && x < win_cols) {
		(void) wattron(sw[SW_STATUS], A_REVERSE);
		print(sw[SW_STATUS], 0, x, "%s", n->msg);
		(void) wattroff(sw[SW_STATUS], A_REVERSE);
		x += strlen(n->msg) + 1;

		n = n->next;
	}

	(void) wnoutrefresh(sw[SW_STATUS]);
}

/*
 * Adds or removes items to the status bar automatically.
 * Only one instance of an item allowed.
 */
void
pt_display_mod_status_bar(char *msg)
{
	sb_slot_t *new, *n;
	boolean_t found = B_FALSE, first = B_FALSE;

	if (msg == NULL) {
		pt_error("can't add an empty status bar item\n");
		return;
	}

	if (status_bar != NULL) {
		/*
		 * Non-empty status bar. Look for an entry matching this msg.
		 */
		for (n = status_bar; n != NULL; n = n->next) {

			if (strcmp(msg, n->msg) == 0) {
				if (n != status_bar)
					n->prev->next = n->next;
				else
					first = B_TRUE;

				if (n->next != NULL) {
					n->next->prev = n->prev;
					if (first)
						status_bar = n->next;
				} else {
					if (first)
						status_bar = NULL;
				}

				free(n);
				found = B_TRUE;
			}
		}

		/*
		 * Found and removed at least one occurrance of msg, refresh
		 * the bar and return.
		 */
		if (found) {
			return;
		} else {
			/*
			 * Inserting a new msg, walk to the end of the bar.
			 */
			for (n = status_bar; n->next != NULL; n = n->next)
				;
		}
	}

	if ((new = calloc(1, sizeof (sb_slot_t))) == NULL) {
		pt_error("failed to allocate a new status bar slot\n");
	} else {
		new->msg = strdup(msg);

		/*
		 * Check if it's the first entry.
		 */
		if (status_bar == NULL) {
			status_bar = new;
			new->prev = NULL;
		} else {
			new->prev = n;
			n->next = new;
		}
		new->next = NULL;
	}
}

void
pt_display_states(void)
{
	char		c[100];
	int		i;
	double		total_pstates = 0.0, avg, res;
	uint64_t	p0_speed, p1_speed;

	print(sw[SW_IDLE], 0, 0, "%s\tAvg\tResidency\n", g_msg_idle_state);

	if (g_features & FEATURE_CSTATE) {
		res =  (((double)g_cstate_info[0].total_time / g_total_c_time))
		    * 100;
		(void) sprintf(c, "C0 (cpu running)\t\t(%.1f%%)\n", (float)res);
		print(sw[SW_IDLE], 1, 0, "%s", c);

		for (i = 1; i <= g_max_cstate; i++) {
			/*
			 * In situations where the load is too intensive, the
			 * system might not transition at all.
			 */
			if (g_cstate_info[i].events > 0)
				avg = (((double)g_cstate_info[i].total_time/
				    MICROSEC)/g_cstate_info[i].events);
			else
				avg = 0;

			res = ((double)g_cstate_info[i].total_time/
			    g_total_c_time) * 100;

			(void) sprintf(c, "C%d\t\t\t%.1fms\t(%.1f%%)\n",
			    i, (float)avg, (float)res);
			print(sw[SW_IDLE], i + 1, 0, "%s", c);
		}
	}

	if (!PT_ON_DUMP)
		(void) wnoutrefresh(sw[SW_IDLE]);

	print(sw[SW_FREQ], 0, 0, "%s\n", g_msg_freq_state);

	if (g_features & FEATURE_PSTATE) {
		for (i = 0; i < g_npstates; i++) {
			total_pstates +=
			    (double)(g_pstate_info[i].total_time/
			    g_ncpus_observed/MICROSEC);
		}

		/*
		 * display ACPI_PSTATE from P(n) to P(1)
		 */
		for (i = 0;  i < g_npstates - 1; i++) {
			(void) sprintf(c, "%4lu Mhz\t%.1f%%",
			    (long)g_pstate_info[i].speed,
			    100 * (g_pstate_info[i].total_time/
			    g_ncpus_observed/MICROSEC/total_pstates));
			print(sw[SW_FREQ], i+1, 0, "%s\n", c);
		}

		/*
		 * Display ACPI_PSTATE P0 according to if turbo
		 * mode is supported
		 */
		if (g_turbo_supported) {
			int p_diff = 1;
			p0_speed = g_pstate_info[g_npstates - 1].speed;
			p1_speed = g_pstate_info[g_npstates - 2].speed;

			/*
			 * AMD systems don't have a visible extra Pstate
			 * indicating turbo mode as Intel does. Use the
			 * actual P0 frequency in that case.
			 */
			if (p0_speed != p1_speed + 1) {
				p1_speed = p0_speed;
				p_diff = 0;
			}

			/*
			 * If g_turbo_ratio <= 1.0, it will be ignored.
			 * we display P(0) as P(1) + p_diff.
			 */
			if (g_turbo_ratio <= 1.0) {
				p0_speed = p1_speed + p_diff;
			} else {
				/*
				 * If g_turbo_ratio > 1.0, that means
				 * turbo mode works. So, P(0) = ratio *
				 *  P(1);
				 */
				p0_speed = (uint64_t)(p1_speed *
				    g_turbo_ratio);
				if (p0_speed < (p1_speed + p_diff))
					p0_speed = p1_speed + p_diff;
			}
			/*
			 * Reset the ratio for the next round
			 */
			g_turbo_ratio = 0.0;

			/*
			 * Setup the string for the display
			 */
			(void) sprintf(c, "%4lu Mhz(turbo)\t%.1f%%",
			    (long)p0_speed,
			    100 * (g_pstate_info[i].total_time/
			    g_ncpus_observed/MICROSEC/total_pstates));
		} else {
			(void) sprintf(c, "%4lu Mhz\t%.1f%%",
			    (long)g_pstate_info[i].speed,
			    100 * (g_pstate_info[i].total_time/
			    g_ncpus_observed/MICROSEC/total_pstates));
		}
		print(sw[SW_FREQ], i+1, 0, "%s\n", c);
	} else {
		if (g_npstates == 1) {
			(void) sprintf(c, "%4lu Mhz\t%.1f%%",
			    (long)g_pstate_info[0].speed, 100.0);
			print(sw[SW_FREQ], 1, 0, "%s\n", c);
		}
	}

	if (!PT_ON_DUMP)
		(void) wnoutrefresh(sw[SW_FREQ]);
}

void
pt_display_acpi_power(uint32_t flag, double rate, double rem_cap, double cap,
    uint32_t state)
{
	char	buffer[1024];

	(void) sprintf(buffer, "no ACPI power usage estimate available");

	if (!PT_ON_DUMP)
		(void) werase(sw[SW_POWER]);

	if (flag) {
		char *c;
		(void) sprintf(buffer, "Power usage (ACPI estimate): %.3fW",
		    rate);
		(void) strcat(buffer, " ");
		c = &buffer[strlen(buffer)];
		switch (state) {
		case 0:
			(void) sprintf(c, "(running on AC power, fully "
			    "charged)");
			break;
		case 1:
			(void) sprintf(c, "(discharging: %3.1f hours)",
			    (uint32_t)rem_cap/rate);
			break;
		case 2:
			(void) sprintf(c, "(charging: %3.1f hours)",
			    (uint32_t)(cap - rem_cap)/rate);
			break;
		case 4:
			(void) sprintf(c, "(##critically low battery power##)");
			break;
		}

	}

	print(sw[SW_POWER], 0, 0, "%s\n", buffer);
	if (!PT_ON_DUMP)
		(void) wnoutrefresh(sw[SW_POWER]);
}

void
pt_display_wakeups(double interval)
{
	char		c[100];
	int		i, event_sum = 0;
	event_info_t	*event = g_event_info;

	if (!PT_ON_DUMP) {
		(void) werase(sw[SW_WAKEUPS]);
		(void) wbkgd(sw[SW_WAKEUPS], COLOR_PAIR(PT_COLOR_RED));
		(void) wattron(sw[SW_WAKEUPS], A_BOLD);
	}

	/*
	 * calculate the actual total event number
	 */
	for (i = 0; i < g_top_events; i++, event++)
		event_sum += event->total_count;

	/*
	 * g_total_events is the sum of the number of Cx->C0 transition,
	 * So when the system is very busy, the idle thread will have no
	 * chance or very seldom to be scheduled, this could cause >100%
	 * event report. Re-assign g_total_events to the actual event
	 * number is a way to avoid this issue.
	 */
	if (event_sum > g_total_events)
		g_total_events = event_sum;

	(void) sprintf(c, "Wakeups-from-idle per second: %4.1f\tinterval: "
	    "%.1fs", (double)(g_total_events/interval), interval);
	print(sw[SW_WAKEUPS], 0, 0, "%s\n", c);

	if (!PT_ON_DUMP)
		(void) wnoutrefresh(sw[SW_WAKEUPS]);
}

void
pt_display_events(double interval)
{
	char		c[100];
	int		i;
	double		events;
	event_info_t	*event = g_event_info;

	if (!PT_ON_DUMP) {
		(void) werase(sw[SW_EVENTS]);
		(void) wbkgd(sw[SW_EVENTS], COLOR_PAIR(PT_COLOR_DEFAULT));
		(void) wattron(sw[SW_EVENTS], COLOR_PAIR(PT_COLOR_DEFAULT));
	}

	/*
	 * Sort the event report list
	 */
	if (g_top_events > EVENT_NUM_MAX)
		g_top_events = EVENT_NUM_MAX;

	qsort((void *)g_event_info, g_top_events, sizeof (event_info_t),
	    pt_event_compare);

	if (PT_ON_CPU)
		(void) sprintf(c, "Top causes for wakeups on CPU %d:\n",
		    g_observed_cpu);
	else
		(void) sprintf(c, "Top causes for wakeups:\n");

	print(sw[SW_EVENTS], 0, 0, "%s", c);

	for (i = 0; i < g_top_events; i++, event++) {

		if (g_total_events > 0 && event->total_count > 0)
			events = (double)event->total_count/
			    (double)g_total_events;
		else
			continue;

		(void) sprintf(c, "%4.1f%% (%5.1f)", 100 * events,
		    (double)event->total_count/interval);
		print(sw[SW_EVENTS], i+1, 0, "%s", c);
		print(sw[SW_EVENTS], i+1, 16, "%20s :",
		    event->offender_name);
		print(sw[SW_EVENTS], i+1, 40, "%-64s\n",
		    event->offense_name);
	}

	if (!PT_ON_DUMP)
		(void) wnoutrefresh(sw[SW_EVENTS]);
}

void
pt_display_suggestions(char *sug)
{
	(void) werase(sw[SW_SUGG]);

	if (sug != NULL)
		print(sw[SW_SUGG], 0, 0, "%s", sug);

	(void) wnoutrefresh(sw[SW_SUGG]);
}
