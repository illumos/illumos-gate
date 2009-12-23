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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CMT_H
#define	_CMT_H

/*
 * CMT PG class
 */

#ifdef	__cplusplus
extern "C" {
#endif

#if (defined(_KERNEL) || defined(_KMEMUSER))
#include <sys/group.h>
#include <sys/pghw.h>
#include <sys/lgrp.h>
#include <sys/types.h>

/*
 * CMT related dispatcher policies
 */
#define	CMT_NO_POLICY	0x0
#define	CMT_BALANCE	0x1
#define	CMT_COALESCE	0x2
#define	CMT_AFFINITY	0x4

typedef uint_t pg_cmt_policy_t;

/*
 * CMT pg structure
 */
typedef struct pg_cmt {
	struct pghw	cmt_pg;			/* physical grouping */
	struct group	*cmt_siblings;		/* CMT PGs to balance with */
	struct pg_cmt	*cmt_parent;		/* Parent CMT PG */
	struct group	*cmt_children;		/* Active children CMT PGs */
	pg_cmt_policy_t	cmt_policy;		/* Dispatcher policies to use */
	uint32_t	cmt_utilization;	/* Group's utilization */
	int		cmt_nchildren;		/* # of children CMT PGs */
	struct group	cmt_cpus_actv;
	struct bitset	cmt_cpus_actv_set;	/* bitset of active CPUs */
	kstat_t		*cmt_kstat;		/* cmt kstats exported */
} pg_cmt_t;

/*
 * CMT lgroup structure
 */
typedef struct cmt_lgrp {
	group_t		cl_pgs;		/* Top level group of active CMT PGs */
	int		cl_npgs;	/* # of top level PGs in the lgroup */
	lgrp_handle_t	cl_hand;	/* lgroup's platform handle */
	struct cmt_lgrp	*cl_next;	/* next cmt_lgrp */
} cmt_lgrp_t;

/*
 * Change the number of running threads on the pg
 */
#define	PG_NRUN_UPDATE(cp, n)		(pg_cmt_load((cp), (n)))

/*
 * Indicate that the given logical CPU is (or isn't) currently utilized
 */
#define	CMT_CPU_UTILIZED(cp)		(pg_cmt_load((cp), 1))
#define	CMT_CPU_NOT_UTILIZED(cp)	(pg_cmt_load((cp), -1))

/*
 * CMT PG's capacity
 *
 * Currently, this is defined to be the number of active
 * logical CPUs in the group.
 *
 * This will be used in conjunction with the utilization, which is defined
 * to be the number of threads actively running on CPUs in the group.
 */
#define	CMT_CAPACITY(pg)	(GROUP_SIZE(&((pg_cmt_t *)pg)->cmt_cpus_actv))

void		pg_cmt_load(cpu_t *, int);
void		pg_cmt_cpu_startup(cpu_t *);
int		pg_cmt_can_migrate(cpu_t *, cpu_t *);

/*
 * CMT platform interfaces
 */
pg_cmt_policy_t	pg_plat_cmt_policy(pghw_type_t);
int		pg_plat_cmt_rank(pg_cmt_t *, pg_cmt_t *);

/*
 * CMT dispatcher policy
 */
cpu_t		*cmt_balance(kthread_t *, cpu_t *);

/*
 * Power Aware Dispatcher Interfaces
 */
int		cmt_pad_enable(pghw_type_t);
int		cmt_pad_disable(pghw_type_t);

#endif	/* !_KERNEL && !_KMEMUSER */

#ifdef	__cplusplus
}
#endif

#endif /* _CMT_H */
