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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_FMD_H
#define	_FMD_H

#include <libnvpair.h>
#include <pthread.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_list.h>
#include <fmd_time.h>
#include <fmd_api.h>
#include <fmd_trace.h>

struct fmd_conf;			/* see <fmd_conf.h> */
struct fmd_dispq;			/* see <fmd_dispq.h> */
struct fmd_timerq;			/* see <fmd_timerq.h> */
struct fmd_asru_hash;			/* see <fmd_asru.h> */
struct fmd_scheme_hash;			/* see <fmd_fmri.h> */
struct fmd_case_hash;			/* see <fmd_case.h> */
struct fmd_modhash;			/* see <fmd_module.h> */
struct fmd_module;			/* see <fmd_module.h> */
struct fmd_log;				/* see <fmd_log.h> */
struct fmd_idspace;			/* see <fmd_idspace.h> */
struct topo_hdl;			/* see <fm/libtopo.h> */

typedef struct fmd_statistics {
	fmd_stat_t ds_log_replayed;	/* number of events replayed from log */
	fmd_stat_t ds_log_partials;	/* number of events partially commit */
	fmd_stat_t ds_err_enospc;	/* number of events w/ ENOSPC errlog */
	fmd_stat_t ds_flt_enospc;	/* number of events w/ ENOSPC fltlog */
	fmd_stat_t ds_oth_enospc;	/* number of events w/ ENOSPC others */
	fmd_stat_t ds_dr_gen;		/* dynamic reconfiguration generation */
	fmd_stat_t ds_topo_gen;		/* topology snapshot generation */
	fmd_stat_t ds_topo_drgen;	/* topology DR generation */
} fmd_statistics_t;

typedef struct fmd {
	const char *d_version;		/* version string for fmd (see fmd.c) */
	const char *d_pname;		/* basename to use for messages */
	pid_t d_pid;			/* process-ID of current daemon */
	pthread_key_t d_key;		/* key for fmd's thread-specific data */
	volatile int d_signal;		/* signal indicating we should quit */
	volatile int d_running;		/* flag set when fmd_run() succeeds */
	volatile int d_loaded;		/* flag set when all modules loaded */
	volatile int d_booted;		/* flag set when fmd_run() completes */

	uint_t d_fmd_debug;		/* mask of fmd active debugging modes */
	uint_t d_fmd_dbout;		/* fmd debug output sinks (see below) */
	uint_t d_hdl_debug;		/* bool indicating if hdl debug is on */
	uint_t d_hdl_dbout;		/* hdl debug output sinks (see below) */

	char *volatile d_panicstr;	/* pointer to formatted panic message */
	pthread_t d_panictid;		/* tid of thread forcing a panic */
	uint_t d_panicrefs;		/* number of attempts to panic */

	pthread_mutex_t d_xprt_lock;	/* transport suspend lock */
	uint_t d_xprt_suspend;		/* transport suspend count  */
	uint_t d_xprt_ttl;		/* transport default time-to-live */
	struct fmd_idspace *d_xprt_ids;	/* transport id hash */

	const fmd_timeops_t *d_clockops; /* system clock ops vector */
	void *d_clockptr;		/* system clock private data */

	pthread_mutex_t d_thr_lock;	/* lock for d_thr_list */
	fmd_list_t d_thr_list;		/* list of all fmd_thread_t's */
	fmd_tracebuf_f *d_thr_trace;	/* thread trace buffer function */
	int d_thr_sig;			/* cached copy of client.thrsig */

	pthread_mutex_t d_mod_lock;	/* lock for d_mod_list */
	fmd_list_t d_mod_list;		/* list of modules in load order */
	struct fmd_modhash *d_mod_hash;	/* hash of modules by base name */
	fmd_event_t *d_mod_event;	/* boot event for module quiesce */

	uint_t d_alloc_msecs;		/* initial delay time for alloc retry */
	uint_t d_alloc_tries;		/* max # times to retry an allocation */
	uint_t d_str_buckets;		/* def # of buckets for string hashes */

	const char *d_rootdir;		/* root directory path */
	const char *d_platform;		/* platform name (uname -i) */
	const char *d_machine;		/* machine class name (uname -m) */
	const char *d_isaname;		/* processor ISA name (uname -p) */

	void *d_sysev_hdl;		/* legacy sysevent handle */
	nv_alloc_t d_nva;		/* libnvpair allocator handle */
	nvlist_t *d_auth;		/* FMRI authority nvlist */
	pthread_mutex_t d_topo_lock;	/* lock for topo hdl */
	fmd_list_t d_topo_list;		/* list of all topology snapshots */

	struct fmd_conf *d_conf;	/* global configuration properties */
	uint_t d_fg;			/* cached value of "fg" property */

	fmd_statistics_t *d_stats;	/* root module statistics collection */
	pthread_mutex_t d_stats_lock;	/* root module statistics lock */

	struct fmd_module *d_rmod;	/* root module for fmd's main thread */
	struct fmd_module *d_self;	/* self module for fmd's diagnosis */

	pthread_mutex_t d_err_lock;	/* lock for stderr and error stats */
	fmd_stat_t *d_errstats;		/* program-wide error statistics */

	struct fmd_timerq *d_timers;	/* timer queue for module timers */
	struct fmd_dispq *d_disp;	/* dispatch queue for incoming events */
	struct fmd_scheme_hash *d_schemes; /* hash of fmri scheme modules */
	struct fmd_asru_hash *d_asrus;	/* hash of cached asru objects */
	struct fmd_case_hash *d_cases;	/* hash of active cases */

	pthread_rwlock_t d_log_lock;	/* log pointer lock (r=use, w=rotate) */
	struct fmd_log *d_errlog;	/* log file for error events */
	struct fmd_log *d_fltlog;	/* log file for fault events */

	pthread_rwlock_t d_hvilog_lock;	/* log pointer lock (r=use, w=rotate) */
	struct fmd_log *d_hvilog;	/* log file for hi value info events */

	pthread_rwlock_t d_ilog_lock;	/* log pointer lock (r=use, w=rotate) */
	struct fmd_log *d_ilog;		/* log file for info events */

	pthread_cond_t d_fmd_cv;	/* sync startup with rpc */
	pthread_mutex_t d_fmd_lock;	/* sync startup with rpc */
} fmd_t;

/*
 * Exit status values used for the few places within fmd where we exit(2) or
 * return from main().  fmd only exits if a fatal error occurs during startup;
 * if anything else happens errors are reported and we just keep trucking.
 */
#define	FMD_EXIT_SUCCESS	0	/* successful execution of daemon */
#define	FMD_EXIT_ERROR		1	/* failed to initialize daemon */
#define	FMD_EXIT_USAGE		2	/* syntax error on command-line */

/*
 * Values associated with fmd's client.error property, stored as a uint32_t.
 * By default, we unload bad clients; other values are for use by developers.
 */
#define	FMD_CERROR_UNLOAD	0	/* unload module on error (default) */
#define	FMD_CERROR_STOP		1	/* stop fmd for debugger attach */
#define	FMD_CERROR_ABORT	2	/* abort fmd and generate core dump */

/*
 * Values associated with any *dbout (debug output sink) property, stored as
 * a uint32_t.  Currently we permit syslog output and stderr output.
 */
#define	FMD_DBOUT_SYSLOG	0x1	/* output to syslog(LOG_DEBUG) */
#define	FMD_DBOUT_STDERR	0x2	/* output to stderr */

extern const char _fmd_version[];
extern fmd_t fmd;

extern void fmd_door_server(void *);
extern void fmd_create(fmd_t *, const char *, const char *, const char *);
extern void fmd_destroy(fmd_t *);
extern void fmd_run(fmd_t *, int);
extern void fmd_help(fmd_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_H */
