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

#ifndef __INCLUDE_GUARD_POWERTOP_H_
#define	__INCLUDE_GUARD_POWERTOP_H_

#include <sys/types.h>
#include <libintl.h>
#include <sys/processor.h>

#define	max(A, B)		(((A) < (B)) ? (B) : (A))

#define	_(STRING)		gettext(STRING)

#define	TITLE			"OpenSolaris PowerTOP version 1.1"

/*
 * Exit values. stdlib.h defines EXIT_SUCCESS as 0 and
 * EXIT_FAILURE as 1
 */
#define	EXIT_USAGE		2

/*
 * PowerTop Features
 * These may not be available everywhere
 */
#define	FEATURE_CSTATE		0x1
#define	FEATURE_PSTATE		0x2
#define	FEATURE_EVENTS		0x4
#define	FEATURE_TURBO		0x8

#define	BIT_DEPTH_BUF		10

#define	INTERVAL_DEFAULT	5.0
#define	INTERVAL_MAX		100.0
#define	INTERVAL_UPDATE(l)						\
	((l/INTERVAL_DEFAULT) * INTERVAL_DEFAULT + INTERVAL_DEFAULT)

#define	STATE_NAME_MAX		16
#define	EVENT_NAME_MAX 		64
#define	EVENT_NUM_MAX 		100
#define	NSTATES			32

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
 * Constants for setup_windows()
 */
#define	SINGLE_LINE_SW 		1
#define	LENGTH_SUGG_SW		2
#define	TITLE_LINE		1
#define	BLANK_LINE		1
#define	NEXT_LINE		1

/*
 * Structures and typedefs
 */
struct line {
	char		*string;
	int		count;
};

typedef struct event_info {
	char		offender_name[EVENT_NAME_MAX];
	char		offense_name[EVENT_NAME_MAX];
	uint64_t	total_count;
} event_info_t;

/*
 * P/C state information
 */
typedef struct state_info {
	char		name[STATE_NAME_MAX];
	hrtime_t	total_time;
	hrtime_t	last_time;
	double		events;
} state_info_t;

typedef struct pstate_info {
	uint64_t	speed;
	hrtime_t	total_time;
} pstate_info_t;

typedef struct cpu_power_info {
	uint64_t	current_pstate;
	hrtime_t	time_accounted;
	hrtime_t	dtrace_time;
} cpu_power_info_t;

/*
 * turbo information
 */
typedef struct turbo_info {
	uint64_t	t_mcnt;
	uint64_t	t_acnt;
} turbo_info_t;


typedef	void		(suggestion_func)(void);

/*
 * Global variables
 */
double			displaytime;

int			bit_depth;

/*
 * Event accounting
 */
int 			total_events;
int 			top_events;

/*
 * Interval
 */
double 			ticktime, ticktime_usr;
double 			g_interval;

/*
 * Command line arguments
 */
int 			dump;
char			event_mode;

/*
 * Event info array
 */
event_info_t    	event_info[EVENT_NUM_MAX];
event_info_t		*p_event;

/*
 * Lookup table, sequential CPU id to Solaris CPU id
 */
processorid_t 		*cpu_table;

/*
 * Number of idle/frequency states
 */
int			npstates;
int			max_cstate;
int			longest_cstate;

/*
 * Total time, used to display different idle states
 */
hrtime_t		total_c_time;

/*
 * P/C state info arrays
 */
state_info_t		cstate_info[NSTATES];
pstate_info_t		pstate_info[NSTATES];

/*
 * Per CPU power state information
 */
cpu_power_info_t	*cpu_power_states;

/*
 * Turbo mode related information
 */
extern boolean_t	g_turbo_supported;
extern double		g_turbo_ratio;

/*
 * Extern declarations
 */
extern struct line	*lines;
extern int		linehead;
extern int		linesize;
extern int		linectotal;

extern	int		g_ncpus;

/*
 * kstat's battery module
 */
extern char		*kstat_batt_mod[3];
extern uint_t		kstat_batt_idx;

extern int 		topcstate;
extern int 		topfreq;
extern int 		dump;

extern char 		*prog;

extern char 		status_bar_slots[10][40];

extern const int	true, false;

extern char 		suggestion_key;
extern suggestion_func 	*suggestion_activate;

/*
 * Suggestions related
 */
extern void 		suggest_p_state(void);
extern void		suggest_as_root(void);

/*
 * See util.c
 */
extern void 		pt_error(char *, ...);
extern void 		pt_set_progname(char *);
extern void		enumerate_cpus(void);
extern void		usage(void);
extern	int		get_bit_depth(void);
extern void		battery_mod_lookup(void);
extern	int		event_compare(const void *, const void *);

/*
 * Display/curses related
 */
extern	void 		show_title_bar(void);
extern	void 		setup_windows(void);
extern	void 		initialize_curses(void);
extern	void		show_acpi_power_line(uint32_t flag, double rate,
    double rem_cap, double cap, uint32_t state);
extern	void 		show_cstates();
extern	void 		show_wakeups(double interval);
extern	void 		show_eventstats(double interval);
extern	void 		show_suggestion(char *sug);
extern	void 		cleanup_curses(void);
extern	void		update_windows(void);

/*
 * Suggestions
 */
extern	void 		pick_suggestion(void);
extern	void 		add_suggestion(char *text, int weight, char key,
    char *keystring, suggestion_func *func);
extern	void 		reset_suggestions(void);
extern	void 		print_all_suggestions(void);
extern	void 		print_battery(void);

/*
 * DTrace stats
 */
extern	int 		pt_cpufreq_stat_prepare(void);
extern	int 		pt_cpufreq_stat_collect(double interval);
extern	int 		pt_cpuidle_stat_prepare(void);
extern	int 		pt_cpuidle_stat_collect(double interval);
extern	int 		pt_events_stat_prepare(void);
extern	int 		pt_events_stat_collect(void);

/*
 * turbo related
 */
extern	int		pt_turbo_stat_prepare(void);
extern	int		pt_turbo_stat_collect(void);

#endif /* __INCLUDE_GUARD_POWERTOP_H_ */
