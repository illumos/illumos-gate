/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LGRP_USER_H
#define	_LGRP_USER_H

/*
 * latency group definitions for user
 */

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/inttypes.h>
#include <sys/lgrp.h>
#include <sys/procset.h>
#include <sys/processor.h>
#include <sys/pset.h>
#include <sys/types.h>


/*
 * lgroup interface version
 */
#define	LGRP_VER_NONE		0	/* no lgroup interface version */
#define	LGRP_VER_CURRENT	2	/* current lgroup interface version */


/*
 * lgroup system call subcodes
 */
#define	LGRP_SYS_MEMINFO	0	/* meminfo(2) aka MISYS_MEMINFO */
#define	LGRP_SYS_GENERATION	1	/* lgrp_generation() */
#define	LGRP_SYS_VERSION	2	/* lgrp_version() */
#define	LGRP_SYS_SNAPSHOT	3	/* lgrp_snapshot() */
#define	LGRP_SYS_AFFINITY_GET	4	/* lgrp_affinity_set() */
#define	LGRP_SYS_AFFINITY_SET	5	/* lgrp_affinity_get() */
#define	LGRP_SYS_LATENCY	6	/* lgrp_latency() */
#define	LGRP_SYS_HOME		7	/* lgrp_home() */


/*
 * lgroup resources
 */
#define	LGRP_RSRC_COUNT		2	/* no. of resource types in lgroup */
#define	LGRP_RSRC_CPU		0	/* CPU resources */
#define	LGRP_RSRC_MEM		1	/* memory resources */

typedef int lgrp_rsrc_t;



/*
 * lgroup affinity
 */
#define	LGRP_AFF_NONE		0x0	/* no affinity */
#define	LGRP_AFF_WEAK		0x10	/* weak affinity */
#define	LGRP_AFF_STRONG		0x100	/* strong affinity */

typedef int lgrp_affinity_t;

/*
 * Arguments to lgrp_affinity_{get,set}()
 */
typedef struct lgrp_affinity_args {
	idtype_t	idtype;	/* ID type */
	id_t		id;	/* ID */
	lgrp_id_t	lgrp;	/* lgroup */
	lgrp_affinity_t	aff;	/* affinity */
} lgrp_affinity_args_t;


/*
 * Flags to specify contents of lgroups desired
 */
typedef enum lgrp_content {
	LGRP_CONTENT_ALL,	/* everything in lgroup */
	    /* everything in lgroup's hierarchy (for compatability) */
	LGRP_CONTENT_HIERARCHY = LGRP_CONTENT_ALL,
	LGRP_CONTENT_DIRECT	/* what's directly contained in lgroup */
} lgrp_content_t;


/*
 * Flags for lgrp_latency_cookie() specifying what hardware resources to get
 * latency between
 */
typedef enum lgrp_lat_between {
	LGRP_LAT_CPU_TO_MEM	/* latency between CPU and memory */
} lgrp_lat_between_t;


/*
 * lgroup memory size type
 */
typedef longlong_t	lgrp_mem_size_t;


/*
 * lgroup memory size flags
 */
typedef enum lgrp_mem_size_flag {
	LGRP_MEM_SZ_FREE,		/* free memory */
	LGRP_MEM_SZ_INSTALLED		/* installed memory */
} lgrp_mem_size_flag_t;


/*
 * View of lgroups
 */
typedef enum lgrp_view {
	LGRP_VIEW_CALLER,	/* what's available to the caller */
	LGRP_VIEW_OS		/* what's available to operating system */
} lgrp_view_t;


/*
 * lgroup information needed by user
 */
typedef	struct lgrp_info {
	lgrp_id_t	info_lgrpid;		/* lgroup ID */
	int		info_latency;		/* latency */
	ulong_t		*info_parents;		/* parent lgroups */
	ulong_t		*info_children;		/* children lgroups */
	ulong_t		*info_rset;		/* lgroup resources */
	pgcnt_t		info_mem_free;		/* free memory */
	pgcnt_t		info_mem_install;	/* installed memory */
	processorid_t	*info_cpuids;		/* CPU IDs */
	int		info_ncpus;		/* number of CPUs */
} lgrp_info_t;


/*
 * Type of lgroup cookie to use with interface routines
 */
typedef uintptr_t	lgrp_cookie_t;

#define	LGRP_COOKIE_NONE	0	/* no cookie */


/*
 * Type of lgroup generation number
 */
typedef uint_t	lgrp_gen_t;


/*
 * Format of lgroup hierarchy snapshot
 */
typedef struct lgrp_snapshot_header {
	int		ss_version;	/* lgroup interface version */
	int		ss_levels;	/* levels of hierarchy */
	int		ss_nlgrps;	/* number of lgroups */
	int		ss_nlgrps_os;	/* number of lgroups (OS view) */
	int		ss_nlgrps_max;	/* maximum number of lgroups */
	int		ss_root;	/* root lgroup */
	int		ss_ncpus;	/* total number of CPUs */
	lgrp_view_t	ss_view;	/* view of lgroup hierarchy */
	psetid_t	ss_pset;	/* caller's pset ID */
	lgrp_gen_t	ss_gen;		/* snapshot generation ID */
	size_t		ss_size;	/* total size of snapshot */
	uintptr_t	ss_magic;	/* snapshot magic number */
	lgrp_info_t	*ss_info;	/* lgroup info array */
	processorid_t	*ss_cpuids;	/* lgroup CPU ID array */
	ulong_t		*ss_lgrpset;	/* bit mask of available lgroups */
	ulong_t		*ss_parents;	/* lgroup parent bit masks */
	ulong_t		*ss_children;	/* lgroup children bit masks */
	ulong_t		*ss_rsets;	/* lgroup resource set bit masks */
	int		**ss_latencies;	/* latencies between lgroups */
} lgrp_snapshot_header_t;


#ifdef	_SYSCALL32
/*
 * lgroup information needed by 32-bit user
 */
typedef	struct lgrp_info32 {
	int		info_lgrpid;		/* lgroup ID */
	int		info_latency;		/* latency */
	caddr32_t	info_parents;		/* parent lgroups */
	caddr32_t	info_children;		/* children lgroups */
	caddr32_t	info_rset;		/* lgroup resources */
	uint32_t	info_mem_free;		/* free memory */
	uint32_t	info_mem_install;	/* installed memory */
	caddr32_t	info_cpuids;		/* CPU IDs */
	int		info_ncpus;		/* number of CPUs */
} lgrp_info32_t;


/*
 * Format of lgroup hierarchy snapshot for 32-bit programs
 */
typedef struct lgrp_snapshot_header32 {
	int		ss_version;	/* lgroup interface version */
	int		ss_levels;	/* levels of hierarchy */
	int		ss_nlgrps;	/* number of lgroups */
	int		ss_nlgrps_os;	/* number of lgroups (OS view) */
	int		ss_nlgrps_max;	/* maximum number of lgroups */
	int		ss_root;	/* root lgroup */
	int		ss_ncpus;	/* total number of CPUs */
	int		ss_view;	/* view of lgroup hierarchy */
	int		ss_pset;	/* caller's pset ID */
	uint_t		ss_gen;		/* snapshot generation ID */
	size32_t	ss_size;	/* total size of snapshot */
	uint32_t	ss_magic;	/* snapshot magic number */
	caddr32_t	ss_info;	/* lgroup info array */
	caddr32_t	ss_cpuids;	/* lgroup CPU ID array */
	caddr32_t	ss_lgrpset;	/* bit mask of available lgroups */
	caddr32_t	ss_parents;	/* lgroup parent bit masks */
	caddr32_t	ss_children;	/* lgroup children bit masks */
	caddr32_t	ss_rsets;	/* lgroup resource set bit masks */
	caddr32_t	ss_latencies;	/* latencies between lgroups */
} lgrp_snapshot_header32_t;

#endif	/* _SYSCALL32 */


#if (!defined(_KERNEL) && !defined(_KMEMUSER))

lgrp_affinity_t	lgrp_affinity_get(idtype_t idtype, id_t id, lgrp_id_t lgrp);

int		lgrp_affinity_set(idtype_t idtype, id_t id, lgrp_id_t lgrp,
    lgrp_affinity_t aff);

int		lgrp_children(lgrp_cookie_t cookie, lgrp_id_t lgrp,
    lgrp_id_t *children, uint_t count);

int		lgrp_cookie_stale(lgrp_cookie_t cookie);

int		lgrp_cpus(lgrp_cookie_t cookie, lgrp_id_t lgrp,
    processorid_t *cpuids, uint_t count, lgrp_content_t content);

int		lgrp_fini(lgrp_cookie_t cookie);

int		lgrp_latency(lgrp_id_t from, lgrp_id_t to);

int		lgrp_latency_cookie(lgrp_cookie_t cookie, lgrp_id_t from,
    lgrp_id_t to, lgrp_lat_between_t between);

lgrp_id_t	lgrp_home(idtype_t idtype, id_t id);

lgrp_cookie_t	lgrp_init(lgrp_view_t view);

lgrp_mem_size_t	lgrp_mem_size(lgrp_cookie_t cookie, lgrp_id_t lgrp,
    lgrp_mem_size_flag_t type, lgrp_content_t content);

int		lgrp_nlgrps(lgrp_cookie_t cookie);

int		lgrp_parents(lgrp_cookie_t cookie, lgrp_id_t lgrp,
    lgrp_id_t *parents, uint_t count);

int		lgrp_resources(lgrp_cookie_t cookie, lgrp_id_t lgrp,
    lgrp_id_t *lgrps, uint_t count, lgrp_rsrc_t type);

lgrp_id_t	lgrp_root(lgrp_cookie_t cookie);

int		lgrp_version(int version);

lgrp_view_t	lgrp_view(lgrp_cookie_t cookie);

#endif	/* !_KERNEL && !_KMEMUSER */

#ifdef	__cplusplus
}
#endif

#endif /* _LGRP_USER_H */
