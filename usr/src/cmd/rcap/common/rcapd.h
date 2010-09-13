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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RCAPD_H
#define	_RCAPD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <procfs.h>
#include "rcapd_conf.h"

#define	LC_NAME_LEN			32
#define	RCAP_FMRI			"svc:/system/rcap:default"
#define	CONFIG_PG			"config"
#define	PRESSURE			"pressure"
#define	RECONFIG_INT			"reconfig_interval"
#define	REPORT_INT			"report_interval"
#define	RSS_SAMPLE_INT			"rss_sample_interval"
#define	WALK_INT			"walk_interval"
#define	RCAPD_IGNORED_SET_FLUSH_IVAL	10	/* number of scans between */
						/* flushes of the ignored set */

/*
 * set the buffer length for /proc-based path names based on the actual
 * length of the largest pid
 */
#define	RCAPD__STR(a)		#a
#define	RCAPD_STR(macro)	RCAPD__STR(macro)
#define	PROC_PATH_MAX		(sizeof ("/proc/" RCAPD_STR(PID_MAX) \
				    "/pagedata"))

/*
 * lcollection_insert_update() result flags
 */
#define	LCST_CAP_CHANGED		(1<<0)
#define	LCST_CAP_REMOVED		(1<<1)
#define	LCST_CAP_ZERO			(1<<2)

typedef enum {
	RCIDT_PROJECT,
	RCIDT_ZONE
} rcid_type_t;

typedef struct {
	/*
	 * The following field could just be a rcid_type_t but it gets
	 * written out to a file as binary data for communication between
	 * 64-bit rcapd & 32-bit rcapstat, so we need to force a standard size
	 * and alignment here.
	 */
	uint64_t	rcid_type;
	int64_t		rcid_val;
} rcid_t;

typedef enum {
	LCU_COMPLETE,	/* an enumeration of all possible collections */
	LCU_ACTIVE_ONLY	/* an enumeration of only once-active collections */
} lcollection_update_type_t;

struct lmapping;
struct lprocess;
struct lcollection;
struct prxmap;
struct psinfo;

/*
 * Per-process data.
 */
typedef struct lprocess {
	struct lprocess *lpc_prev;	/* global process list */
	struct lprocess *lpc_next;

	pid_t		lpc_pid;	/* ID of this process */
	int		lpc_unscannable; /* flag indicating zombie or */
					/* other unscannable process */
	uint64_t	lpc_rss;	/* resident set size (kB) */
	uint64_t	lpc_unrm;	/* scannable set size (kB) (est.) */
	uint64_t	lpc_size;	/* process image size (kB) */
	int		lpc_mark;	/* mark-and-sweep flag */
	struct lcollection *lpc_collection; /* owning collection */
	int		lpc_psinfo_fd;	/* cached psinfo fd */
	int		lpc_pgdata_fd;	/* cached pagedata fd */
	int		lpc_xmap_fd;	/* cached xmap fd */
	struct prxmap	*lpc_xmap;	/* xmap corresponding to */
					/* current pagedata */
	int		lpc_nxmap;	/* number of mappings in xmap */
	prpageheader_t *lpc_prpageheader; /* accumulated mask of */
					/* process's ref/mod bits */
	struct lmapping	*lpc_ignore;	/* empirically-unpageable mappings */
} lprocess_t;

/*
 * Collection statistics.
 */
typedef struct {
	uint64_t lcols_scan;		/* scan attempts */
	uint64_t lcols_pg_att;		/* kB attempted to page */
	uint64_t lcols_pg_eff;		/* kB paged out (est.) */
	uint64_t lcols_rss_sample;	/* RSS samplings */
	uint64_t lcols_unenforced_cap;	/* times cap could have been */
					/* enforced, but wasn't (due to low */
					/* global memory pressure, or global */
					/* scanner being activated) */
	uint64_t lcols_rss_sum;		/* sum of sampled RSS values */
	uint64_t lcols_rss_act_sum;	/* sum of sampled, excess RSS values */
	uint64_t lcols_min_rss;		/* minimum RSS (kB), this interval */
	uint64_t lcols_max_rss;		/* maximum RSS (kB), this interval */
	uint64_t lcols_proc_in;		/* processes tracked */
	uint64_t lcols_proc_out;	/* processes freed */
	hrtime_t lcols_scan_time;	/* time spent scanning (ns) */
	hrtime_t lcols_scan_time_complete; /* time spent scanning (ns) */
					/* at last completion */
	uint64_t lcols_scan_count;	/* number of complete scans */
	uint64_t lcols_scan_ineffective; /* number of uninterrupted */
					/* revolutions of clock hand after */
					/* which the excess was not */
					/* completely reduced */
} lcollection_stat_t;

/*
 * Collection.
 */
typedef struct lcollection {
	struct lcollection *lcol_prev;	/* global collection list */
	struct lcollection *lcol_next;

	rcid_t lcol_id;			/* numerical ID for this collection */
	char lcol_name[LC_NAME_LEN];	/* name of this collection, or */
					/* "unknown" */
	uint64_t lcol_rss;		/* RSS of all processes (kB) */
	uint64_t lcol_image_size;	/* image size of all processes (kB) */
	uint64_t lcol_rss_cap;		/* RSS cap (kB) */
	lcollection_stat_t lcol_stat;	/* statistics */
	lcollection_stat_t lcol_stat_old; /* previous interval's statistics */
	lprocess_t *lcol_lprocess;	/* member processes */
	int lcol_mark;			/* mark-and-sweep flag */
	lprocess_t *lcol_victim;	/* victim process to resume scanning */
	void *lcol_resaddr;		/* address to resume scanning from */
} lcollection_t;

/*
 * Collection report.
 */
typedef struct lcollection_report {
	rcid_t lcol_id;			/* numerical ID for this collection */
	char lcol_name[LC_NAME_LEN];	/* name of this collection, or */
					/* "unknown" */
	uint64_t lcol_rss;		/* RSS of all processes (kB) */
	uint64_t lcol_image_size;	/* image size of all processes (kB) */
	uint64_t lcol_rss_cap;		/* RSS limit (kB) */
	lcollection_stat_t lcol_stat;	/* statistics */
} lcollection_report_t;

extern int get_psinfo(pid_t, struct psinfo *, int, int(*)(void *, int), void *,
    lprocess_t *);
extern lcollection_t *lcollection_find(rcid_t *);
extern void lcollection_freq_move(lprocess_t *);
extern lcollection_t *lcollection_insert_update(rcid_t *, uint64_t, char *,
    int *changes);
extern int lcollection_member(lcollection_t *, lprocess_t *);
extern void lcollection_free(lcollection_t *);
extern void lcollection_update(lcollection_update_type_t);
extern void list_walk_collection(int (*)(lcollection_t *, void *), void *);
extern int lprocess_update_psinfo_fd_cb(void *, int);
extern void lprocess_free(lprocess_t *);
extern void scan(lcollection_t *, int64_t);
extern void scan_abort(void);
extern void check_update_statistics(void);

/*
 * Global (in rcapd only) variables.
 */
extern rcfg_t rcfg;
extern uint64_t phys_total;
extern int should_run;

#ifdef	__cplusplus
}
#endif

#endif /* _RCAPD_H */
