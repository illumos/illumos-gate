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
#include <sys/types.h>

/*
 * CMT pg structure
 */
typedef struct pg_cmt {
	struct pghw	cmt_pg;			/* physical grouping */
	struct group	*cmt_siblings;		/* CMT PGs to balance with */
	struct pg_cmt	*cmt_parent;		/* Parent CMT PG */
	struct group	*cmt_children;		/* Active children CMT PGs */
	int		cmt_nchildren;		/* # of children CMT PGs */
	uint32_t	cmt_nrunning;		/* # of running threads */
	struct group	cmt_cpus_actv;
	struct bitset	cmt_cpus_actv_set;	/* bitset of active CPUs */
} pg_cmt_t;

/*
 * Change the number of running threads on the pg
 */
#define	PG_NRUN_UPDATE(cp, n)	(pg_cmt_load((cp), (n)))

void		pg_cmt_load(cpu_t *, int);
void		pg_cmt_cpu_startup(cpu_t *);
int		pg_cmt_can_migrate(cpu_t *, cpu_t *);

int		pg_plat_cmt_load_bal_hw(pghw_type_t);
int		pg_plat_cmt_affinity_hw(pghw_type_t);

cpu_t		*cmt_balance(kthread_t *, cpu_t *);

#endif	/* !_KERNEL && !_KMEMUSER */

#ifdef	__cplusplus
}
#endif

#endif /* _CMT_H */
