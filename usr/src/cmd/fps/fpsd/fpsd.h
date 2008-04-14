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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FPSD_H
#define	_FPSD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * FPSD structure and global functions
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <door.h>
#include <sys/processor.h>
#include <sys/param.h>

#define	FPS_DAEMON_NAME "fpsd"
#define	FPS_FPUTST_NAME "fptest"

#define	FPS_DIR		"/usr/lib/fps"
#define	FPS_CORE_DIR	"/var/fps/core"

#define	FPU_TST_SRCH_DPTH	4	/* File search depth from FPS_DIR */
#define	DFLT_DBG_LVL  0 /* Default debug level */
#define	FPS_DOOR_COOKIE    ((void *)0xdeadbead)

#define	SMF_PROP_INTVL "interval"
#define	SMF_FPS_PROP_GRP_NAME "config"
#define	SMF_PROP_EXCLD_CPUS	"exclude_cpus"

#define	FPS_LOWTST_SWAP  4   /* Low stress consumes 4 MB */
#define	FPS_SWAP_RESERVE 25  /* Leave atleast 25 MB in the system */

/* (in secs) Delay test on low config m/c for 5min during bootup */
#define	FPS_BOOT_TST_DELAY (3*60)
#define	MAX_RETRIES	2
#define	MAX_FAILURES	3
#define	RETRY_INTVL	2000 /* in milli-seconds */
#define	MIN_INTERVAL	3	/* in seconds */

/* Maximum time fptest is expected to run which is 1s */

#define	MAX_TEST_RUN_TIME	1

typedef struct
{
	processorid_t	cpuid;
	int	frequency;
	char	brand[MAXNAMELEN];
	int	asc;
	int	previous_iteration;
	int	total_iterations; /* For this fpu */
	int	disable_test;
	int	num_failures;	/* Failures to run fptest successfully. */
	char	fptest_path[MAXPATHLEN];

} fps_cpu_t;

typedef struct
{
	char	m_machine[MAXNAMELEN];	/* machine name e.g. sun4u */
	uint_t	m_num_fpus;	/* num of fpus in the system */
	uint_t	m_num_on_fpuids;	/* num of online cpus */
	fps_cpu_t	*m_cpus;	/* array of cpus to test */
	int		m_cpuids_size;	/* size of previous array */
	int	m_num_cpus_to_test;	/* Num cpus to run test */
	int	m_reprobe;	/* flag set if reprobe required: */
					/*   - config changed */
					/*   - fp-test failed to offline */
	int	total_iter;	/* total iterations to run in 24 hr */
} mach_conf_t;

typedef struct fpsd_struct
{
	unsigned	d_fg;	/* "fg" foreground property */
	int			d_daemon; /* running as daemon ? */
	mach_conf_t	*d_conf;	/* machine config information */
	processorid_t	*d_ignore_cpuid;	/* array of cpuids to ignore */
	int		num_ignore_cpus;	/* No. of cpuids to ignore */
	int		d_iteration;	/* iteration number */
	int		d_interval;	/* sleep time between iterations */
	int		d_fpuid_index;	/* Currently testing fpu */
	const char	*d_rootdir;	/* root directory path */
	pid_t		d_pid;	/* Process id */
	/* Timestamp last time HUP was recd */
	volatile	hrtime_t	d_ts_hup;
} fpsd_t;

/*
 * Exit status values used for the few places within fpsd where we exit(2) or
 * return from main().  fpsd only exits if a fatal error occurs during startup;
 * if anything else happens errors are reported and we just keep tracking.
 */
#define	FPSD_NO_EXIT		0	/* continue execution of daemon */
#define	FPSD_EXIT_ERROR		1	/* failed to initialize daemon */
#define	FPSD_EXIT_USAGE		2	/* syntax error on command-line */
#define	FPSD_EXIT_TEST_USAGE	3	/* Invalid args passed to fp-test */

#define	FPSD_INIT_SUCCESS	0	/* To inform parent process that */
				/* initialization was successful, so */
				/* that the parent can detach */

#define	NO_DAEMON	0
#define	DAEMON_EXISTS	1
#define	DAEMON_EXISTS_AND_SAME_PROC	2

#define	NO_CPUS_2_TEST	-2
#define	ZERO_INTERVAL	-1

/* Global Variables */

/* Defined in fpsd_main.c */
extern int 			debug_level;
extern fpsd_t  		fpsd;
extern mutex_t log_mutex;	/* fpsd_log.c */
extern int  is_estar_system;	/* fpsd_esutil.c */
extern int  sys_pm_state;	/* fpsd_esutil.c */


/* Util Functions */

extern  uint64_t  get_free_swap(void);	/* fpsd_util.c */
extern  uint64_t  get_total_swap(void);	/* fpsd_util.c */
extern  uint64_t	get_physmem(void);	/* fpsd_util.c */
extern  void	fps_wait_secs(int secs);	/* fpsd_util.c */

extern  void  *test_fpu_thr(void *arg);	/* in fpsd_sched.c */

extern  void   fps_door_handler(void *cookie, char *argp, size_t asize,
	door_desc_t  *dp, uint_t  n_desc);	/* in fpsd_util.c */

extern  void update_pm_state();	/* fpsd_esutil.c */
extern  int  get_idle_rem_stats(int *min_idle,
		int *min_rem, int *max_rem);	/* fpsd_esutil.c */
extern  void init_estar_db();	/* fpsd_esutil.c */
extern  void wait_for_pm_state_change();	/* fpsd_esutil.c */

/* fpsd_log.c */
extern void fpsd_message(int return_code, int msg_type, char *fmt,  ...);

extern void terminate_process();	/* fpsd_main.c */
extern void fpsd_read_config();	/* fpsd_main.c */

#ifdef __cplusplus
}
#endif

#endif	/* _FPSD_H */
