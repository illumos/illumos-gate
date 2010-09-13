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
#include <sys/processor.h>

#define	max(A, B)		(((A) < (B)) ? (B) : (A))

#define	TITLE			"OpenSolaris PowerTOP version 1.2"
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
#define	INTERVAL_MAX		30.0
#define	INTERVAL_UPDATE(l)						\
	((l/INTERVAL_DEFAULT) * INTERVAL_DEFAULT + INTERVAL_DEFAULT)

#define	STATE_NAME_MAX		16
#define	EVENT_NAME_MAX 		64
#define	EVENT_NUM_MAX 		100
#define	NSTATES			32

/*
 * Available op modes. The PT_ON_* macros allow for a simple way of checking
 * under which mode PowerTOP is operating.
 */
#define	PT_MODE_DEFAULT		0x01
#define	PT_MODE_DUMP		0x02
#define	PT_MODE_VERBOSE		0x04
#define	PT_MODE_CPU		0x08
#define	PT_MODE_TIME		0x10

#define	PT_ON_DEFAULT		(g_op_mode & PT_MODE_DEFAULT)
#define	PT_ON_DUMP		(g_op_mode & PT_MODE_DUMP)
#define	PT_ON_VERBOSE		(g_op_mode & PT_MODE_VERBOSE)
#define	PT_ON_CPU		(g_op_mode & PT_MODE_CPU)
#define	PT_ON_TIME		(g_op_mode & PT_MODE_TIME)

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

/*
 * Suggestions
 */
typedef	void		(sugg_func_t)(void);

typedef struct suggestion {
	char *text;
	char key;
	char *sb_msg;
	int weight;
	int slice;
	sugg_func_t *func;
	struct suggestion *prev;
	struct suggestion *next;
} sugg_t;

extern int			g_bit_depth;

/*
 * Event accounting
 */
extern int 			g_total_events;
extern int 			g_top_events;

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
 * Current interval length
 */
extern double			g_interval_length;

/*
 * P/C state info arrays
 */
extern state_info_t		g_cstate_info[NSTATES];
extern freq_state_info_t	g_pstate_info[NSTATES];

extern uint_t			g_features;
extern uint_t			g_ncpus;
extern uint_t			g_ncpus_observed;

extern cpu_power_info_t		*g_cpu_power_states;

/*
 * Turbo mode related information
 */
extern boolean_t		g_turbo_supported;
extern double			g_turbo_ratio;

extern sugg_t			*g_curr_sugg;

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
extern const char		*g_msg_idle_state;
extern const char		*g_msg_freq_state;
extern const char		*g_msg_freq_enable;

/*
 * Flags for signal handling
 */
extern boolean_t		g_sig_resize;

extern void		pt_sig_handler(int);

/*
 * Suggestions related
 */
extern void 		pt_cpufreq_suggest(void);
extern void		pt_sugg_as_root(void);

/*
 * See util.c
 */
extern void 		pt_error(char *, ...);
extern void 		pt_set_progname(char *);
extern uint_t		pt_enumerate_cpus(void);
extern void		pt_usage(void);
extern int		pt_get_bit_depth(void);
extern void		pt_battery_mod_lookup(void);
extern int		pt_event_compare(const void *, const void *);

/*
 * Display/curses related
 */
extern void		pt_display_setup(boolean_t);
extern void 		pt_display_init_curses(void);
extern void		pt_display_update(void);
extern void 		pt_display_title_bar(void);
extern void		pt_display_status_bar(void);
extern void		pt_display_mod_status_bar(char *);
extern void 		pt_display_states(void);
extern void		pt_display_acpi_power(uint32_t, double, double, double,
	uint32_t);
extern void 		pt_display_wakeups(double);
extern void 		pt_display_events(double);
extern void 		pt_display_suggestions(char *);
extern void		pt_display_resize(void);

/*
 * Suggestions
 */
extern void 		pt_sugg_add(char *, int, char, char *, sugg_func_t *);
extern int		pt_sugg_remove(sugg_func_t *);
extern void 		pt_sugg_pick(void);

/*
 * Battery
 */
extern void 		pt_battery_print(void);

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
