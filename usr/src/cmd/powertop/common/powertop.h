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

#ifndef __INCLUDE_GUARD_POWERTOP_H_
#define	__INCLUDE_GUARD_POWERTOP_H_

#include <sys/types.h>
#include <libintl.h>
#include <sys/processor.h>

#define	max(A, B)		(((A) < (B)) ? (B) : (A))

#define	_(STRING)		gettext(STRING)

#define	TITLE			"OpenSolaris PowerTOP version 1.1"
#define	COPYRIGHT_INTEL		"(C) 2009 Intel Corporation"

/*
 * Exit values. stdlib.h defines EXIT_SUCCESS as 0 and
 * EXIT_FAILURE as 1
 */
#define	EXIT_USAGE		2

/*
 * PowerTOP Features
 * These may not be available everywhere
 */
#define	FEATURE_CSTATE		0x01
#define	FEATURE_PSTATE		0x02
#define	FEATURE_EVENTS		0x04
#define	FEATURE_TURBO		0x08

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
#define	PT_BAR_NSLOTS		10
#define	PT_BAR_LENGTH		40

/*
 * Available op modes
 */
#define	PT_MODE_DEFAULT		0x01
#define	PT_MODE_DUMP		0x02
#define	PT_MODE_VERBOSE		0x04
#define	PT_MODE_CPU		0x08

#define	PT_ON_DEFAULT		(g_op_mode & PT_MODE_DEFAULT)
#define	PT_ON_DUMP		(g_op_mode & PT_MODE_DUMP)
#define	PT_ON_VERBOSE		(g_op_mode & PT_MODE_VERBOSE)
#define	PT_ON_CPU		(g_op_mode & PT_MODE_CPU)

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
	uint64_t	events;
} state_info_t;

typedef struct freq_state_info {
	uint64_t	speed;
	hrtime_t	total_time;
} freq_state_info_t;

typedef struct cpu_power_info {
	uint64_t	current_pstate;
	uint64_t	speed_accounted;
	hrtime_t	time_accounted;
	hrtime_t	dtrace_time;
} cpu_power_info_t;

/*
 * Turbo mode information
 */
typedef struct turbo_info {
	uint64_t	t_mcnt;
	uint64_t	t_acnt;
} turbo_info_t;

typedef	void			(suggestion_func)(void);

/*
 * Global variables
 */
extern double			g_displaytime;

extern int			g_bit_depth;

/*
 * Event accounting
 */
extern int 			g_total_events;
extern int 			g_top_events;

/*
 * Interval
 */
extern double 			g_ticktime, g_ticktime_usr;
extern double 			g_interval;

/*
 * Command line arguments
 */
extern uchar_t			g_op_mode;
extern uint_t			g_observed_cpu;
extern boolean_t		g_gui;
/*
 * Event info array
 */
extern event_info_t    		g_event_info[EVENT_NUM_MAX];

/*
 * Lookup table, sequential CPU id to Solaris CPU id
 */
extern processorid_t 		*g_cpu_table;

/*
 * Number of idle/frequency states
 */
extern int			g_npstates;
extern int			g_max_cstate;
extern int			g_longest_cstate;

/*
 * Total time, used to display different idle states
 */
extern hrtime_t			g_total_c_time;

/*
 * P/C state info arrays
 */
extern state_info_t		g_cstate_info[NSTATES];
extern freq_state_info_t	g_pstate_info[NSTATES];

extern uint_t			g_ncpus;
extern uint_t			g_ncpus_observed;

extern char 			g_status_bar_slots[PT_BAR_NSLOTS]
	[PT_BAR_LENGTH];

extern cpu_power_info_t		*g_cpu_power_states;

/*
 * Turbo mode related information
 */
extern boolean_t		g_turbo_supported;
extern double			g_turbo_ratio;

extern char 			g_suggestion_key;
extern suggestion_func 		*g_suggestion_activate;

/*
 * DTrace scripts for the events report
 */
extern const char		*g_dtp_events;
extern const char		*g_dtp_events_v;
extern const char		*g_dtp_events_c;

/*
 * Arguments for dtrace_program_strcompile(). Contents vary according to
 * the specified operation mode.
 */
extern uint_t			g_argc;
extern char			**g_argv;

/*
 * Platform specific messages
 */
extern const char 		*g_msg_idle_state;
extern const char 		*g_msg_freq_state;
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
extern uint_t		enumerate_cpus(void);
extern void		usage(void);
extern int		get_bit_depth(void);
extern void		battery_mod_lookup(void);
extern int		event_compare(const void *, const void *);

/*
 * Display/curses related
 */
extern void 		show_title_bar(void);
extern void 		setup_windows(void);
extern void 		initialize_curses(void);
extern void		show_acpi_power_line(uint32_t, double, double, double,
	uint32_t);
extern void 		show_cstates();
extern void 		show_wakeups(double);
extern void 		show_eventstats(double);
extern void 		show_suggestion(char *);
extern void 		cleanup_curses(void);
extern void		update_windows(void);

/*
 * Suggestions
 */
extern void 		pick_suggestion(void);
extern void 		add_suggestion(char *, int, char, char *,
	suggestion_func *);
extern void 		reset_suggestions(void);
extern void 		print_all_suggestions(void);
extern void 		print_battery(void);

/*
 * DTrace stats
 */
extern int 		pt_cpufreq_stat_prepare(void);
extern int 		pt_cpufreq_stat_collect(double);
extern int 		pt_cpuidle_stat_prepare(void);
extern int 		pt_cpuidle_stat_collect(double);
extern int 		pt_events_stat_prepare(void);
extern int 		pt_events_stat_collect(void);

/*
 * Turbo mode related routines
 */
extern int		pt_turbo_stat_prepare(void);
extern int		pt_turbo_stat_collect(void);

#endif /* __INCLUDE_GUARD_POWERTOP_H_ */
