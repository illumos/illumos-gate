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
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2009 Chad Mynhier
 */

#ifndef	_PRSTAT_H
#define	_PRSTAT_H

#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <procfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * FRC2PCT macro is used to convert 16-bit binary fractions in the range
 * 0.0 to 1.0 with binary point to the right of the high order bit
 * (i.e. 1.0 == 0x8000) to percentage value.
 */

#define	FRC2PCT(pp)	(((float)(pp))/0x8000*100)

#define	TIME2NSEC(__t)\
(hrtime_t)(((hrtime_t)__t.tv_sec * (hrtime_t)NANOSEC) + (hrtime_t)__t.tv_nsec)
#define	TIME2SEC(__t)\
(hrtime_t)(__t.tv_sec)

/*
 * List of available output modes
 */
#define	OPT_PSINFO	0x0001		/* read process's data from "psinfo" */
#define	OPT_LWPS	0x0002		/* report about all lwps */
#define	OPT_USERS	0x0004		/* report about most active users */
#define	OPT_UNUSED	0x0008		/* reserved for future use */
#define	OPT_REALTIME	0x0010		/* real-time scheduling class flag */
#define	OPT_MSACCT	0x0020		/* microstate accounting flag */
#define	OPT_TERMCAP	0x0040		/* use termcap data to move cursor */
#define	OPT_SPLIT	0x0080		/* split-screen mode flag */
#define	OPT_TTY		0x0100		/* report results to tty or file */
#define	OPT_FULLSCREEN	0x0200		/* full-screen mode flag */
#define	OPT_USEHOME	0x0400		/* use 'home' to move cursor up */
#define	OPT_TASKS	0x0800		/* report about system tasks */
#define	OPT_PROJECTS	0x1000		/* report about system projects */
#define	OPT_ZONES	0x2000		/* report about zones */
#define	OPT_PSETS	0x4000		/* report for specified psets */
#define	OPT_LGRP	0x8000		/* report home lgroups */
#define	OPT_UDATE	0x20000		/* print unix timestamp */
#define	OPT_DDATE	0x40000		/* print timestamp in date(1) format */
#define	OPT_NORESOLVE	0x80000		/* no nsswitch lookups */
#define	OPT_TRUNC	0x100000	/* truncate long names */

/*
 * Flags to keep track of process or lwp status
 */
#define	LWP_ALIVE	0x0008		/* this pid/lwp still exists */
#define	LWP_REPRESENT	0x0010		/* this LWP represents the process */

/*
 * Possible list types
 */
#define	LT_LWPS		0x0001
#define	LT_USERS	0x0002
#define	LT_TASKS	0x0004
#define	LT_PROJECTS	0x0008
#define	LT_ZONES	0x0010
#define	LT_LGRPS	0x0020

/*
 * Linked list of per-process or per-lwp statistics
 */
typedef struct lwp_info {
	psinfo_t	li_info;	/* data read from psinfo file */
	prusage_t	li_usage;	/* data read from usage file */
	ulong_t		li_key;		/* value of the key for this lwp */
	int		li_flags;	/* process/lwp flags */
	float		li_usr;		/* user level CPU time */
	float		li_sys;		/* system call CPU time */
	float		li_trp;		/* other system trap CPU time */
	float		li_tfl;		/* text page fault sleep time */
	float		li_dfl;		/* data page fault sleep time */
	float		li_lck;		/* user lock wait sleep time */
	float		li_slp;		/* all other sleep time */
	float		li_lat;		/* wait-cpu (latency) time */
	ulong_t		li_vcx;		/* voluntary context switches */
	ulong_t		li_icx;		/* involuntary context switches */
	ulong_t		li_scl;		/* system calls */
	ulong_t		li_sig;		/* received signals */
	struct lwp_info *li_next;	/* pointer to next lwp */
	struct lwp_info *li_prev;	/* pointer to previous lwp */
} lwp_info_t;

/*
 * Linked list of collective per-uid, per-taskid, per-projid or per-lgroup
 * statistics
 */
typedef struct id_info {
	uid_t		id_uid;		/* user id */
	taskid_t	id_taskid;	/* task id */
	projid_t	id_projid;	/* project id */
	zoneid_t	id_zoneid;	/* zone id */
	int		id_lgroup;	/* lgroup id */
	uint_t		id_nproc;	/* number of processes */
	boolean_t	id_sizematch;	/* size/rssize from getvmusage() */
	size_t		id_size;	/* memory usage */
	size_t		id_rssize;	/* resident set size */
	ulong_t		id_time;	/* cpu time (in secs) */
	float		id_pctcpu;	/* percentage of cpu usage */
	float		id_pctmem;	/* percentage of memory usage */
	ulong_t		id_key;		/* sort key value */
	struct id_info *id_next;	/* pointer to next entry */
	struct id_info *id_prev;	/* pointer to previous entry */
} id_info_t;

typedef	ulong_t	(*keyfunc_t)(void *);

/*
 * Per-list structure
 */
typedef struct list {
	int		l_type;		/* list type */
	int		l_count;	/* number of entries in the list */
	void		*l_head;	/* pointer to the head of the list */
	void		*l_tail;	/* pointer to the tail of the list */

	int		l_size;		/* number of allocated pointers */
	int		l_used;		/* number of used pointers */
	int		l_sortorder;	/* sorting order for the list */
	keyfunc_t	l_func;		/* pointer to key function */
	void		**l_ptrs;	/* pointer to an array of pointers */
} list_t;

/*
 * Command line options
 */
typedef	struct optdesc {
	int		o_interval;	/* interval between updates */
	int		o_ntop;		/* number of lines in top half */
	int		o_nbottom;	/* number of lines in bottom half */
	int		o_count;	/* number of iterations */
	int		o_outpmode;	/* selected output mode */
	int		o_sortorder;	/* +1 ascending, -1 descending */
} optdesc_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _PRSTAT_H */
