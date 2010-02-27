/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2008-2009, Intel Corporation.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <dirent.h>
#include <curses.h>
#include <time.h>
#include <wchar.h>
#include <ctype.h>
#include <stdarg.h>
#include <signal.h>

#include "latencytop.h"

#define	LT_WINDOW_X			80
#define	LT_WINDOW_Y			24

#define	LT_COLOR_DEFAULT		1
#define	LT_COLOR_HEADER			2

/* Windows created by libcurses */
static WINDOW	*titlebar = NULL;
static WINDOW	*captionbar = NULL;
static WINDOW	*sysglobal_window = NULL;
static WINDOW	*taskbar = NULL;
static WINDOW	*process_window = NULL;
static WINDOW	*hintbar = NULL;
/* Screen dimension */
static int	screen_width = 1, screen_height = 1;
/* Is display initialized, i.e. are window pointers set up. */
static int	display_initialized = FALSE;
/* Is initscr() called */
static int	curses_inited = FALSE;

/* To handle user key presses */
static pid_t selected_pid = INVALID_PID;
static id_t selected_tid = INVALID_TID;
static lt_sort_t sort_type = LT_SORT_TOTAL;
static int thread_mode = FALSE;
/* Type of list being displayed */
static int current_list_type = LT_LIST_CAUSE;
static int show_help = FALSE;

/* Help functions that append/prepend a blank to the given string */
#define	fill_space_right(a, b, c)	fill_space((a), (b), (c), TRUE)
#define	fill_space_left(a, b, c)	fill_space((a), (b), (c), FALSE)

static void
fill_space(char *buffer, int len, int buffer_limit, int is_right)
{
	int i = 0;
	int tofill;

	if (len >= buffer_limit) {
		len = buffer_limit - 1;
	}

	i = strlen(buffer);

	if (i >= len) {
		return;
	}

	tofill = len - i;

	if (is_right) {
		(void) memset(&buffer[i], ' ', tofill);
		buffer[len] = '\0';
	} else {
		(void) memmove(&buffer[tofill], buffer, i+1);
		(void) memset(buffer, ' ', tofill);
	}
}

/* Convert the nanosecond value to a human readable string */
static const char *
get_time_string(double nanoseconds, char *buffer, int len, int fill_width)
{
	const double ONE_USEC = 1000.0;
	const double ONE_MSEC = 1000000.0;
	const double ONE_SEC  = 1000000000.0;

	if (nanoseconds < (ONE_USEC - .5)) {
		(void) snprintf(buffer, len, "%3.1f nsec", nanoseconds);
	} else if (nanoseconds < (ONE_MSEC - .5 * ONE_USEC)) {
		(void) snprintf(buffer, len,
		    "%3.1f usec", nanoseconds / ONE_USEC);
	} else if (nanoseconds < (ONE_SEC - .5 * ONE_MSEC)) {
		(void) snprintf(buffer, len,
		    "%3.1f msec", nanoseconds / ONE_MSEC);
	} else if (nanoseconds < 999.5 * ONE_SEC) {
		(void) snprintf(buffer, len,
		    "%3.1f  sec", nanoseconds / ONE_SEC);
	} else {
		(void) snprintf(buffer, len,
		    "%.0e sec", nanoseconds / ONE_SEC);
	}

	fill_space_left(buffer, fill_width, len);
	return (buffer);
}

/* Used in print_statistics below */
#define	WIDTH_REASON_STRING	36
#define	WIDTH_COUNT		12
#define	WIDTH_AVG		12
#define	WIDTH_MAX		12
#define	WIDTH_PCT		8
#define	BEGIN_COUNT		WIDTH_REASON_STRING
#define	BEGIN_AVG		(BEGIN_COUNT + WIDTH_COUNT)
#define	BEGIN_MAX		(BEGIN_AVG + WIDTH_AVG)
#define	BEGIN_PCT		(BEGIN_MAX + WIDTH_MAX)

/*
 * Print statistics in global/process pane. Called by print_sysglobal
 * print_process.
 *
 * Parameters:
 *		window - the global or process statistics window.
 *		begin_line - where to start printing.
 *		count - how many lines should be printed.
 *		list - a stat_list.
 */
static void
print_statistics(WINDOW * window, int begin_line, int nlines, void *list)
{
	uint64_t total;
	int i = 0;

	if (!display_initialized) {
		return;
	}

	total = lt_stat_list_get_gtotal(list);

	if (total == 0) {
		return;
	}

	while (i < nlines && lt_stat_list_has_item(list, i)) {

		char tmp[WIDTH_REASON_STRING];
		const char *reason = lt_stat_list_get_reason(list, i);
		uint64_t count = lt_stat_list_get_count(list, i);

		if (count == 0) {
			continue;
		}

		(void) snprintf(tmp, sizeof (tmp), "%s", reason);
		(void) mvwprintw(window, i + begin_line, 0, "%s", tmp);

		(void) snprintf(tmp, sizeof (tmp), "%llu", count);
		fill_space_left(tmp, WIDTH_COUNT, sizeof (tmp));
		(void) mvwprintw(window, i + begin_line, BEGIN_COUNT,
		    "%s", tmp);

		(void) mvwprintw(window, i + begin_line, BEGIN_AVG,
		    "%s", get_time_string(
		    (double)lt_stat_list_get_sum(list, i) / count,
		    tmp, sizeof (tmp), WIDTH_AVG));

		(void) mvwprintw(window, i + begin_line, BEGIN_MAX,
		    "%s", get_time_string(
		    (double)lt_stat_list_get_max(list, i),
		    tmp, sizeof (tmp), WIDTH_MAX));

		if (LT_LIST_SPECIALS != current_list_type) {
			(void) snprintf(tmp, sizeof (tmp), "%.1f %%",
			    (double)lt_stat_list_get_sum(list, i)
			    / total * 100.0);
		} else {
			(void) snprintf(tmp, sizeof (tmp), "--- ");
		}

		fill_space_left(tmp, WIDTH_PCT, sizeof (tmp));

		(void) mvwprintw(window, i + begin_line, BEGIN_PCT,
		    "%s", tmp);
		i++;
	}
}

/*
 * Print statistics in global pane.
 */
static void
print_sysglobal(void)
{
	void *list;
	char header[256];

	if (!display_initialized) {
		return;
	}

	(void) werase(sysglobal_window);

	(void) wattron(sysglobal_window, A_REVERSE);
	(void) snprintf(header, sizeof (header),
	    "%s", "System wide latencies");
	fill_space_right(header, screen_width, sizeof (header));
	(void) mvwprintw(sysglobal_window, 0, 0, "%s", header);
	(void) wattroff(sysglobal_window, A_REVERSE);

	list = lt_stat_list_create(current_list_type,
	    LT_LEVEL_GLOBAL, 0, 0, 10, sort_type);
	print_statistics(sysglobal_window, 1, 10, list);
	lt_stat_list_free(list);

	(void) wrefresh(sysglobal_window);
}

/*
 * Prints current operation mode. Mode is combination of:
 *
 * 	"Process or Thread", and "1 or 2 or 3".
 */
static void
print_current_mode()
{
	char type;

	if (!display_initialized) {
		return;
	}

	switch (current_list_type) {
	case LT_LIST_CAUSE:
		type = '1';
		break;
	case LT_LIST_SPECIALS:
		type = '2';
		break;
	case LT_LIST_SOBJ:
		type = '3';
		break;
	default:
		type = '?';
		break;
	}

	(void) mvwprintw(process_window, 0, screen_width - 8, "View: %c%c",
	    type, thread_mode ? 'T' : 'P');
}

/*
 * Print process window bar when the list is empty.
 */
static void
print_empty_process_bar()
{
	char header[256];

	if (!display_initialized) {
		return;
	}

	(void) werase(process_window);
	(void) wattron(process_window, A_REVERSE);
	(void) snprintf(header, sizeof (header),
	    "No process/thread data is available");
	fill_space_right(header, screen_width, sizeof (header));
	(void) mvwprintw(process_window, 0, 0, "%s", header);

	print_current_mode();
	(void) wattroff(process_window, A_REVERSE);

	(void) wrefresh(process_window);
}

/*
 * Print per-process statistics in process pane.
 * This is called when mode of operation is process.
 */
static void
print_process(unsigned int pid)
{
	void *list;
	char header[256];
	char tmp[30];

	if (!display_initialized) {
		return;
	}

	list = lt_stat_list_create(current_list_type, LT_LEVEL_PROCESS,
	    pid, 0, 8, sort_type);

	(void) werase(process_window);
	(void) wattron(process_window, A_REVERSE);
	(void) snprintf(header, sizeof (header), "Process %s (%i), %d threads",
	    lt_stat_proc_get_name(pid), pid, lt_stat_proc_get_nthreads(pid));
	fill_space_right(header, screen_width, sizeof (header));
	(void) mvwprintw(process_window, 0, 0, "%s", header);

	if (current_list_type != LT_LIST_SPECIALS) {
		(void) mvwprintw(process_window, 0, 48, "Total: %s",
		    get_time_string((double)lt_stat_list_get_gtotal(list),
		    tmp, sizeof (tmp), 12));
	}

	print_current_mode();
	(void) wattroff(process_window, A_REVERSE);
	print_statistics(process_window, 1, 8, list);
	lt_stat_list_free(list);

	(void) wrefresh(process_window);
}

/*
 * Display the list of processes that are tracked, in task bar.
 * This one is called when mode of operation is process.
 */
static void
print_taskbar_process(pid_t *pidlist, int pidlist_len, int pidlist_index)
{
	const int ITEM_WIDTH = 8;

	int number_item;
	int i;
	int xpos = 0;

	if (!display_initialized) {
		return;
	}

	number_item = (screen_width / ITEM_WIDTH) - 1;
	i = pidlist_index - (pidlist_index % number_item);

	(void) werase(taskbar);

	if (i != 0) {
		(void) mvwprintw(taskbar, 0, xpos, "<-");
	}

	xpos = ITEM_WIDTH / 2;

	while (xpos + ITEM_WIDTH <= screen_width && i < pidlist_len) {
		char str[ITEM_WIDTH+1];
		int slen;
		const char *pname = lt_stat_proc_get_name(pidlist[i]);

		if (pname && pname[0]) {
			(void) snprintf(str, sizeof (str) - 1, "%s", pname);
		} else {
			(void) snprintf(str, sizeof (str) - 1,
			    "<%d>", pidlist[i]);
		}

		slen = strlen(str);

		if (slen < ITEM_WIDTH) {
			(void) memset(&str[slen], ' ', ITEM_WIDTH - slen);
		}

		str[sizeof (str) - 1] = '\0';

		if (i == pidlist_index) {
			(void) wattron(taskbar, A_REVERSE);
		}

		(void) mvwprintw(taskbar, 0, xpos, "%s", str);

		if (i == pidlist_index) {
			(void) wattroff(taskbar, A_REVERSE);
		}

		xpos += ITEM_WIDTH;
		i++;
	}

	if (i != pidlist_len) {
		(void) mvwprintw(taskbar, 0, screen_width - 2, "->");
	}

	(void) wrefresh(taskbar);
}

/*
 * Display the list of processes that are tracked, in task bar.
 * This one is called when mode of operation is thread.
 */
static void
print_taskbar_thread(pid_t *pidlist, id_t *tidlist, int list_len,
    int list_index)
{
	const int ITEM_WIDTH = 12;

	int number_item;
	int i;
	int xpos = 0;
	const char *pname = NULL;
	pid_t last_pid = INVALID_PID;


	if (!display_initialized) {
		return;
	}

	number_item = (screen_width - 8) / ITEM_WIDTH;
	i = list_index - (list_index % number_item);

	(void) werase(taskbar);

	if (i != 0) {
		(void) mvwprintw(taskbar, 0, xpos, "<-");
	}

	xpos = 4;

	while (xpos + ITEM_WIDTH <= screen_width && i < list_len) {
		char str[ITEM_WIDTH+1];
		int slen, tlen;

		if (pidlist[i] != last_pid) {
			pname = lt_stat_proc_get_name(pidlist[i]);
			last_pid = pidlist[i];
		}

		/*
		 * Calculate length of thread's ID; use shorter process name
		 * in order to save space on the screen.
		 */
		tlen = snprintf(NULL, 0, "_%d", tidlist[i]);

		if (pname && pname[0]) {
			(void) snprintf(str, sizeof (str) - tlen - 1,
			    "%s", pname);
		} else {
			(void) snprintf(str, sizeof (str) - tlen - 1,
			    "<%d>", pidlist[i]);
		}

		slen = strlen(str);

		(void) snprintf(&str[slen], sizeof (str) - slen,
		    "_%d", tidlist[i]);

		slen += tlen;

		if (slen < ITEM_WIDTH) {
			(void) memset(&str[slen], ' ', ITEM_WIDTH - slen);
		}

		str[sizeof (str) - 1] = '\0';

		if (i == list_index) {
			(void) wattron(taskbar, A_REVERSE);
		}

		(void) mvwprintw(taskbar, 0, xpos, "%s", str);

		if (i == list_index) {
			(void) wattroff(taskbar, A_REVERSE);
		}

		xpos += ITEM_WIDTH;
		i++;
	}

	if (i != list_len) {
		(void) mvwprintw(taskbar, 0, screen_width - 2, "->");
	}

	(void) wrefresh(taskbar);
}

/*
 * Print per-thread statistics in process pane.
 * This is called when mode of operation is thread.
 */
static void
print_thread(pid_t pid, id_t tid)
{
	void *list;
	char header[256];
	char tmp[30];

	if (!display_initialized) {
		return;
	}

	list = lt_stat_list_create(current_list_type, LT_LEVEL_THREAD,
	    pid, tid, 8, sort_type);

	(void) werase(process_window);
	(void) wattron(process_window, A_REVERSE);
	(void) snprintf(header, sizeof (header),
	    "Process %s (%i), LWP %d",
	    lt_stat_proc_get_name(pid), pid, tid);
	fill_space_right(header, screen_width, sizeof (header));
	(void) mvwprintw(process_window, 0, 0, "%s", header);

	if (current_list_type != LT_LIST_SPECIALS) {
		(void) mvwprintw(process_window, 0, 48, "Total: %s",
		    get_time_string(
		    (double)lt_stat_list_get_gtotal(list),
		    tmp, sizeof (tmp), 12));
	}

	print_current_mode();
	(void) wattroff(process_window, A_REVERSE);
	print_statistics(process_window, 1, 8, list);
	lt_stat_list_free(list);
	(void) wrefresh(process_window);
}

/*
 * Update hint string at the bottom line. The message to print is stored in
 * hint. If hint is NULL, the function will display its own message.
 */
static void
print_hint(const char *hint)
{
	const char *HINTS[] =    {
		"Press '<' or '>' to switch between processes.",
		"Press 'q' to exit.",
		"Press 'r' to refresh immediately.",
		"Press 't' to toggle Process/Thread display mode.",
		"Press 'h' for help.",
		"Use 'c', 'a', 'm', 'p' to change sort criteria.",
		"Use '1', '2', '3' to switch between windows."
	};
	const uint64_t update_interval = 5000; /* 5 seconds */

	static int index = 0;
	static uint64_t next_hint = 0;
	uint64_t now = lt_millisecond();

	if (!display_initialized) {
		return;
	}

	if (hint == NULL) {
		if (now < next_hint) {
			return;
		}

		hint = HINTS[index];
		index = (index + 1) % (sizeof (HINTS) / sizeof (HINTS[0]));
		next_hint = now + update_interval;
	} else {
		/*
		 * Important messages are displayed at least every 2 cycles.
		 */
		next_hint = now + update_interval * 2;
	}

	(void) werase(hintbar);
	(void) mvwprintw(hintbar, 0, (screen_width - strlen(hint)) / 2,
	    "%s", hint);
	(void) wrefresh(hintbar);
}

/*
 * Create a PID list or a PID/TID list (if operation mode is thread) from
 * available statistics.
 */
static void
get_plist(pid_t **plist, id_t **tlist, int *list_len, int *list_index)
{
	if (!thread_mode) {
		/* Per-process mode */
		*list_len = lt_stat_proc_list_create(plist, NULL);
		/* Search for previously selected PID */
		for (*list_index = 0; *list_index < *list_len &&
		    (*plist)[*list_index] != selected_pid;
		    ++*list_index) {
		}

		if (*list_index >= *list_len) {
			/*
			 * The previously selected pid is gone.
			 * Select the first one.
			 */
			*list_index = 0;
		}
	} else {
		/* Per-thread mode */
		*list_len = lt_stat_proc_list_create(plist, tlist);

		/* Search for previously selected PID & TID */
		for (*list_index = 0; *list_index < *list_len;
		    ++*list_index) {
			if ((*plist)[*list_index] == selected_pid &&
			    (*tlist)[*list_index] == selected_tid) {
				break;
			}
		}

		if (*list_index >= *list_len) {
			/*
			 * The previously selected pid/tid is gone.
			 * Select the first one.
			 */
			for (*list_index = 0;
			    *list_index < *list_len &&
			    (*plist)[*list_index] != selected_pid;
			    ++*list_index) {
			}
		}

		if (*list_index >= *list_len) {
			/*
			 * The previously selected pid is gone.
			 * Select the first one
			 */
			*list_index = 0;
		}
	}
}

/* Print help message when user presses 'h' hot key */
static void
print_help(void)
{
	const char *HELP[] =    {
		TITLE,
		COPYRIGHT,
		"",
		"These single-character commands are available:",
		"<       - Move to previous process/thread.",
		">       - Move to next process/thread.",
		"q       - Exit.",
		"r       - Refresh.",
		"t       - Toggle process/thread mode.",
		"c       - Sort by count.",
		"a       - Sort by average.",
		"m       - Sort by maximum.",
		"p       - Sort by percent.",
		"1       - Show list by causes.",
		"2       - Show list of special entries.",
		"3       - Show list by synchronization objects.",
		"h       - Show this help.",
		"",
		"Press any key to continue..."
	};
	int i;

	if (!display_initialized) {
		return;
	}

	for (i = 0; i < sizeof (HELP) / sizeof (HELP[0]); ++i) {
		(void) mvwprintw(stdscr, i, 0, "%s", HELP[i]);
	}

	(void) refresh();
}

/*
 * Print title on screen
 */
static void
print_title(void)
{
	if (!display_initialized) {
		return;
	}

	(void) wattrset(titlebar, COLOR_PAIR(LT_COLOR_HEADER));
	(void) wbkgd(titlebar, COLOR_PAIR(LT_COLOR_HEADER));
	(void) werase(titlebar);

	(void) mvwprintw(titlebar, 0, (screen_width - strlen(TITLE)) / 2,
	    "%s", TITLE);
	(void) wrefresh(titlebar);

	(void) werase(captionbar);
	(void) mvwprintw(captionbar, 0, 0, "%s",
	    "               Cause                    "
	    "Count      Average     Maximum   Percent");
	(void) wrefresh(captionbar);

	(void) wattrset(hintbar, COLOR_PAIR(LT_COLOR_HEADER));
	(void) wbkgd(hintbar, COLOR_PAIR(LT_COLOR_HEADER));
}

/*
 * Handle signal from terminal resize
 */
/* ARGSUSED */
static void
on_resize(int sig)
{
	lt_gpipe_break("r");
}

/*
 * Initialize display. Display will be cleared when this function returns.
 */
void
lt_display_init(void)
{
	if (display_initialized) {
		return;
	}

	/* Window resize signal */
	(void) signal(SIGWINCH, on_resize);

	/* Initialize curses library */
	(void) initscr();
	(void) start_color();
	(void) keypad(stdscr, TRUE);
	(void) nonl();
	(void) cbreak();
	(void) noecho();
	(void) curs_set(0);

	/* Set up color pairs */
	(void) init_pair(LT_COLOR_DEFAULT, COLOR_WHITE, COLOR_BLACK);
	(void) init_pair(LT_COLOR_HEADER, COLOR_BLACK, COLOR_WHITE);

	curses_inited = TRUE;
	getmaxyx(stdscr, screen_height, screen_width);

	if (screen_width < LT_WINDOW_X || screen_height < LT_WINDOW_Y) {
		(void) mvwprintw(stdscr, 0, 0, "Terminal size is too small.");
		(void) mvwprintw(stdscr, 1, 0,
		    "Please resize it to 80x24 or larger.");
		(void) mvwprintw(stdscr, 2, 0, "Press q to quit.");
		(void) refresh();
		return;
	}

	/* Set up all window panes */
	titlebar = subwin(stdscr, 1, screen_width, 0, 0);
	captionbar = subwin(stdscr, 1, screen_width, 1, 0);
	sysglobal_window = subwin(stdscr, screen_height / 2 - 1,
	    screen_width, 2, 0);
	process_window = subwin(stdscr, screen_height / 2 - 3,
	    screen_width, screen_height / 2 + 1, 0);
	taskbar = subwin(stdscr, 1, screen_width, screen_height - 2, 0);
	hintbar = subwin(stdscr, 1, screen_width, screen_height - 1, 0);
	(void) werase(stdscr);
	(void) refresh();

	display_initialized = TRUE;

	print_title();
}

/*
 * The event loop for display. It displays data on screen and handles hotkey
 * presses.
 *
 * Parameter :
 *		duration - returns after 'duration'
 *
 * The function also returns if user presses 'q', 'Ctrl+C' or 'r'.
 *
 * Return value:
 *		0 - main() exits
 *		1 - main() calls it again
 */
int
lt_display_loop(int duration)
{
	uint64_t start;
	int remaining;
	struct timeval timeout;
	fd_set read_fd;
	int need_refresh = TRUE;
	pid_t *plist = NULL;
	id_t *tlist = NULL;
	int list_len = 0;
	int list_index = 0;
	int retval = 1;
	int next_snap;
	int gpipe;

	start = lt_millisecond();
	gpipe = lt_gpipe_readfd();

	if (!show_help) {
		print_hint(NULL);
		print_sysglobal();
	}

	get_plist(&plist, &tlist, &list_len, &list_index);

	for (;;) {
		if (need_refresh && !show_help) {
			if (list_len != 0) {
				if (!thread_mode) {
					print_taskbar_process(plist, list_len,
					    list_index);
					print_process(plist[list_index]);
				} else {
					print_taskbar_thread(plist, tlist,
					    list_len, list_index);
					print_thread(plist[list_index],
					    tlist[list_index]);
				}
			} else {
				print_empty_process_bar();
			}
		}

		need_refresh = TRUE;	/* Usually we need refresh. */
		remaining = duration - (int)(lt_millisecond() - start);

		if (remaining <= 0) {
			break;
		}

		/* Embedded dtrace snap action here. */
		next_snap = lt_dtrace_work(0);

		if (next_snap == 0) {
			/*
			 * Just did a snap, check time for the next one.
			 */
			next_snap = lt_dtrace_work(0);
		}

		if (next_snap > 0 && remaining > next_snap) {
			remaining = next_snap;
		}

		timeout.tv_sec = remaining / 1000;
		timeout.tv_usec = (remaining % 1000) * 1000;

		FD_ZERO(&read_fd);
		FD_SET(0, &read_fd);
		FD_SET(gpipe, &read_fd);

		/* Wait for keyboard input, or signal from gpipe */
		if (select(gpipe + 1, &read_fd, NULL, NULL, &timeout) > 0) {
			int k = 0;

			if (FD_ISSET(gpipe, &read_fd)) {
				/* Data from pipe has priority */
				char ch;
				(void) read(gpipe, &ch, 1);
				k = ch; /* Need this for big-endianness */
			} else {
				k = getch();
			}

			/*
			 * Check if we need to update the hint line whenever we
			 * get a chance.
			 * NOTE: current implementation depends on
			 * g_config.lt_cfg_snap_interval, but it's OK because it
			 * doesn't have to be precise.
			 */
			print_hint(NULL);
			/*
			 * If help is on display right now, and a key press
			 * happens, we need to clear the help and continue.
			 */
			if (show_help) {
				(void) werase(stdscr);
				(void) refresh();
				print_title();
				print_sysglobal();
				show_help = FALSE;
				/* Drop this key and continue */
				continue;
			}

			switch (k) {
			case 'Q':
			case 'q':
				retval = 0;
				goto quit;
			case 'R':
			case 'r':
				lt_display_deinit();
				lt_display_init();
				goto quit;
			case 'H':
			case 'h':
				show_help = TRUE;
				(void) werase(stdscr);
				(void) refresh();
				print_help();
				break;
			case ',':
			case '<':
			case KEY_LEFT:
				--list_index;

				if (list_index < 0) {
					list_index = 0;
				}

				break;
			case '.':
			case '>':
			case KEY_RIGHT:
				++list_index;

				if (list_index >= list_len) {
					list_index = list_len - 1;
				}

				break;
			case 'a':
			case 'A':
				sort_type = LT_SORT_AVG;
				print_sysglobal();
				break;
			case 'p':
			case 'P':
				sort_type = LT_SORT_TOTAL;
				print_sysglobal();
				break;
			case 'm':
			case 'M':
				sort_type = LT_SORT_MAX;
				print_sysglobal();
				break;
			case 'c':
			case 'C':
				sort_type = LT_SORT_COUNT;
				print_sysglobal();
				break;
			case 't':
			case 'T':
				if (plist != NULL) {
					selected_pid = plist[list_index];
				}

				selected_tid = INVALID_TID;
				thread_mode = !thread_mode;
				get_plist(&plist, &tlist,
				    &list_len, &list_index);
				break;
			case '1':
			case '!':
				current_list_type = LT_LIST_CAUSE;
				print_sysglobal();
				break;
			case '2':
			case '@':
				if (g_config.lt_cfg_low_overhead_mode) {
					lt_display_error("Switching mode is "
					    "not available for '-f low'.");
				} else {
					current_list_type = LT_LIST_SPECIALS;
					print_sysglobal();
				}

				break;
			case '3':
			case '#':
				if (g_config.lt_cfg_trace_syncobj) {
					current_list_type = LT_LIST_SOBJ;
					print_sysglobal();
				} else if (g_config.lt_cfg_low_overhead_mode) {
					lt_display_error("Switching mode is "
					    "not available for '-f low'.");
				} else {
					lt_display_error("Tracing "
					    "synchronization objects is "
					    "disabled.");
				}

				break;
			default:
				/* Wake up for nothing; no refresh is needed */
				need_refresh = FALSE;
				break;
			}
		} else {
			need_refresh = FALSE;
		}
	}

quit:
	if (plist != NULL) {
		selected_pid = plist[list_index];
	}

	if (tlist != NULL) {
		selected_tid = tlist[list_index];
	}

	lt_stat_proc_list_free(plist, tlist);

	return (retval);
}

/*
 * Clean up display.
 */
void
lt_display_deinit(void)
{
	if (curses_inited) {
		(void) clear();
		(void) refresh();
		(void) endwin();
	}

	titlebar = NULL;
	captionbar = NULL;
	sysglobal_window = NULL;
	taskbar = NULL;
	process_window = NULL;
	hintbar = NULL;
	screen_width = 1;
	screen_height = 1;

	display_initialized = FALSE;
	curses_inited = FALSE;
}

/*
 * Print message when display error happens.
 */
/* ARGSUSED */
void
lt_display_error(const char *fmt, ...)
{
	va_list vl;
	char tmp[81];
	int l;

	va_start(vl, fmt);
	(void) vsnprintf(tmp, sizeof (tmp), fmt, vl);
	va_end(vl);

	l = strlen(tmp);

	while (l > 0 && (tmp[l - 1] == '\n' || tmp[l - 1] == '\r')) {
		tmp[l - 1] = '\0';
		--l;
	}

	if (!display_initialized) {
		(void) fprintf(stderr, "%s\n", tmp);
	} else if (!show_help) {
		print_hint(tmp);
	}

}
