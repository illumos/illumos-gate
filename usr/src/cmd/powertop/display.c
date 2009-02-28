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

#include <stdlib.h>
#include <string.h>
#include <curses.h>
#include "powertop.h"

static WINDOW 	*title_bar_window;
static WINDOW 	*cstate_window;
static WINDOW 	*wakeup_window;
static WINDOW 	*acpi_power_window;
static WINDOW 	*eventstat_window;
static WINDOW 	*suggestion_window;
static WINDOW 	*status_bar_window;

#define	print(win, y, x, fmt, args...)				\
	if (dump)						\
		(void) printf(fmt, ## args);			\
	else							\
		(void) mvwprintw(win, y, x, fmt, ## args);

char	status_bar_slots[10][40];
int	maxx, maxy;

static void
zap_windows(void)
{
	if (title_bar_window) {
		(void) delwin(title_bar_window);
		title_bar_window = NULL;
	}
	if (cstate_window) {
		(void) delwin(cstate_window);
		cstate_window = NULL;
	}
	if (wakeup_window) {
		(void) delwin(wakeup_window);
		wakeup_window = NULL;
	}
	if (acpi_power_window) {
		(void) delwin(acpi_power_window);
		acpi_power_window = NULL;
	}
	if (eventstat_window) {
		(void) delwin(eventstat_window);
		eventstat_window = NULL;
	}
	if (suggestion_window) {
		(void) delwin(suggestion_window);
		suggestion_window = NULL;
	}
	if (status_bar_window) {
		(void) delwin(status_bar_window);
		status_bar_window = NULL;
	}
}

void
cleanup_curses(void)
{
	(void) endwin();
}

/*
 * This part was re-written to be human readable and easy to modify. Please
 * try to keep it that way and help us save some time.
 *
 * Friendly reminder:
 * 	subwin(WINDOW *orig, int nlines, int ncols, int begin_y, int begin_x)
 */
void
setup_windows(void)
{
	/*
	 * These variables are used to properly set the initial y position and
	 * number of lines in each subwindow, as the number of supported CPU
	 * states affects their placement.
	 */
	int cstate_lines, event_lines, pos_y;

	getmaxyx(stdscr, maxy, maxx);

	zap_windows();

	cstate_lines 	= TITLE_LINE + max((max_cstate+1), npstates);

	pos_y = 0;
	title_bar_window = subwin(stdscr, SINGLE_LINE_SW, maxx, pos_y, 0);

	pos_y += NEXT_LINE + BLANK_LINE;
	cstate_window = subwin(stdscr, cstate_lines, maxx, pos_y, 0);

	pos_y += cstate_lines + BLANK_LINE;
	wakeup_window = subwin(stdscr, SINGLE_LINE_SW, maxx, pos_y, 0);

	pos_y += NEXT_LINE;
	acpi_power_window = subwin(stdscr, SINGLE_LINE_SW, maxx, pos_y, 0);

	pos_y += NEXT_LINE + BLANK_LINE;
	event_lines = maxy - SINGLE_LINE_SW - NEXT_LINE - LENGTH_SUGG_SW -
	    pos_y;
	eventstat_window = subwin(stdscr, event_lines, maxx, pos_y, 0);

	pos_y += event_lines + NEXT_LINE;
	suggestion_window = subwin(stdscr, SINGLE_LINE_SW, maxx, pos_y, 0);

	pos_y += BLANK_LINE + NEXT_LINE;
	status_bar_window = subwin(stdscr, SINGLE_LINE_SW, maxx, pos_y, 0);

	(void) strcpy(status_bar_slots[0], _(" Q - Quit "));
	(void) strcpy(status_bar_slots[1], _(" R - Refresh "));

	(void) werase(stdscr);
	(void) wrefresh(status_bar_window);
}

void
initialize_curses(void)
{
	(void) initscr();
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

	(void) atexit(cleanup_curses);
}

void
show_title_bar(void)
{
	int 	i, x = 0, y = 0;
	char	title_pad[10];

	(void) wattrset(title_bar_window, COLOR_PAIR(PT_COLOR_HEADER_BAR));
	(void) wbkgd(title_bar_window, COLOR_PAIR(PT_COLOR_HEADER_BAR));
	(void) werase(title_bar_window);

	(void) snprintf(title_pad, 10, "%%%ds",
	    (maxx - strlen(TITLE))/2 + strlen(TITLE));
	/* LINTED: E_SEC_PRINTF_VAR_FMT */
	print(title_bar_window, y, x, title_pad, TITLE);

	(void) wrefresh(title_bar_window);
	(void) werase(status_bar_window);

	for (i = 0; i < 10; i++) {
		if (strlen(status_bar_slots[i]) == 0)
			continue;
		(void) wattron(status_bar_window, A_REVERSE);
		print(status_bar_window, y, x, "%s", status_bar_slots[i]);
		(void) wattroff(status_bar_window, A_REVERSE);
		x += strlen(status_bar_slots[i]) + 1;
	}
	(void) wnoutrefresh(status_bar_window);
}

void
show_cstates(void)
{
	char		c[100];
	int		i;
	double		total_pstates = 0.0, avg, res;
	uint64_t	p0_speed, p1_speed;

	if (!dump) {
		(void) werase(cstate_window);
		(void) wattrset(cstate_window, COLOR_PAIR(PT_COLOR_DEFAULT));
		(void) wbkgd(cstate_window, COLOR_PAIR(PT_COLOR_DEFAULT));
	}

	print(cstate_window, 0, 0, "%s", "Cn\t\t\tAvg	residency\n");

	res =  (((double)cstate_info[0].total_time / total_c_time)) * 100;
	(void) sprintf(c, "C0 (cpu running)\t\t(%.1f%%)\n", (float)res);
	print(cstate_window, 1, 0, "%s", c);

	for (i = 1; i <= max_cstate; i++) {
		/*
		 * In situations where the load is too intensive, the system
		 * might not transition at all.
		 */
		if (cstate_info[i].events > 0)
			avg = (((double)cstate_info[i].total_time/g_ncpus)/
			    cstate_info[i].events);
		else
			avg = 0;

		res = ((double)cstate_info[i].total_time/total_c_time) * 100;

		(void) sprintf(c, "C%d\t\t\t%.1fms\t(%.1f%%)\n", i, (float)avg,
		    (float)res);
		print(cstate_window, i + 1, 0, "%s", c);
	}

	print(cstate_window, 0, 48, "%s", "P-states (frequencies)\n");

	if (npstates < 2) {
		(void) sprintf(c, "%4lu Mhz\t%.1f%%",
		    (long)pstate_info[0].speed, 100.0);
		print(cstate_window, 1, 48, "%s\n", c);
	} else {
		for (i = 0; i < npstates; i++) {
			total_pstates += (double)(pstate_info[i].total_time/
			    g_ncpus/1000000);
		}

		/*
		 * display ACPI_PSTATE from P(n) to P(1)
		 */
		for (i = 0;  i < npstates - 1; i++) {
			(void) sprintf(c, "%4lu Mhz\t%.1f%%",
			    (long)pstate_info[i].speed,
			    100 * (pstate_info[i].total_time/g_ncpus/1000000
			    /total_pstates));
			print(cstate_window, i+1, 48, "%s\n", c);
		}

		/*
		 * display ACPI_PSTATE P0 according to if turbo
		 * mode is supported
		 */
		if (g_turbo_supported) {
			p1_speed = pstate_info[npstates - 2].speed;
			/*
			 * if g_turbo_ratio <= 1.0, it will be ignored.
			 * we display P(0) as P(1) + 1.
			 */
			if (g_turbo_ratio <= 1.0) {
				p0_speed = p1_speed + 1;
			}
			/*
			 * if g_turbo_ratio > 1.0, that means turbo mode works.
			 * So, P(0) = ratio * P(1);
			 */
			else {
				p0_speed = (uint64_t)(p1_speed * g_turbo_ratio);
				if (p0_speed < (p1_speed + 1))
				p0_speed = p1_speed + 1;
			}
			/*
			 * reset the ratio for the next round
			 */
			g_turbo_ratio = 0.0;

			/*
			 * setup the string for the display
			 */
			(void) sprintf(c, "%4lu Mhz(turbo)\t%.1f%%",
			    (long)p0_speed,
			    100 * (pstate_info[i].total_time/g_ncpus/1000000
			    /total_pstates));
		} else {
			(void) sprintf(c, "%4lu Mhz\t%.1f%%",
			    (long)pstate_info[i].speed,
			    100 * (pstate_info[i].total_time/g_ncpus/1000000
			    /total_pstates));
		}
		print(cstate_window, i+1, 48, "%s\n", c);

	}
	if (!dump)
		(void) wnoutrefresh(cstate_window);
}

void
show_acpi_power_line(uint32_t flag, double rate, double rem_cap, double cap,
    uint32_t state)
{
	char	buffer[1024];

	(void) sprintf(buffer,  _("no ACPI power usage estimate available"));

	if (!dump)
		(void) werase(acpi_power_window);
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
			    rem_cap/rate);
			break;
		case 2:
			(void) sprintf(c, "(charging: %3.1f hours)",
			    (cap - rem_cap)/rate);
			break;
		case 4:
			(void) sprintf(c, "(##critically low battery power##)");
			break;
		}

	}
	print(acpi_power_window, 0, 0, "%s\n", buffer);
	if (!dump)
		(void) wnoutrefresh(acpi_power_window);
}

void
show_wakeups(double interval)
{
	char 	c[100];

	if (!dump) {
		(void) werase(wakeup_window);
		(void) wbkgd(wakeup_window, COLOR_PAIR(PT_COLOR_RED));
		(void) wattron(wakeup_window, A_BOLD);
	}
	(void) sprintf(c, "Wakeups-from-idle per second: %4.1f\tinterval: "
	    "%.1fs", (double)(total_events/interval), interval);
	print(wakeup_window, 0, 0, "%s\n", c);
	if (!dump)
		(void) wnoutrefresh(wakeup_window);
}

void
show_eventstats(double interval)
{
	char		c[100];
	int		i;
	double		events;
	event_info_t	*p_event = event_info;

	if (!dump) {
		(void) werase(eventstat_window);
		(void) wattrset(eventstat_window, COLOR_PAIR(PT_COLOR_DEFAULT));
		(void) wbkgd(eventstat_window, COLOR_PAIR(PT_COLOR_DEFAULT));
	}

	/*
	 * Sort the event report list
	 */
	if (top_events > EVENT_NUM_MAX)
		top_events = EVENT_NUM_MAX;

	qsort((void *)event_info, top_events, sizeof (event_info_t),
	    event_compare);

	print(eventstat_window, 0, 0, "%s", "Top causes for wakeups:\n");

	for (i = 0; i < top_events; i++, p_event++) {

		if (total_events > 0)
			events = (double)p_event->total_count/
			    (double)total_events;
		else
			events = 0;

		(void) sprintf(c, "%4.1f%% (%5.1f)", 100 * events,
		    (double)p_event->total_count/interval);
		print(eventstat_window, i+1, 0, "%s", c);
		print(eventstat_window, i+1, 16, "%20s :",
		    p_event->offender_name);
		print(eventstat_window, i+1, 40, "%-64s\n",
		    p_event->offense_name);
	}
	if (!dump)
		(void) wnoutrefresh(eventstat_window);
}

void
show_suggestion(char *sug)
{
	(void) werase(suggestion_window);
	print(suggestion_window, 0, 0, "%s", sug);
	(void) wnoutrefresh(suggestion_window);
}

void
update_windows(void)
{
	(void) doupdate();
}
