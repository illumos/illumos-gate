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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_PG_H
#define	_PG_H

/*
 * Processor Groups
 */

#ifdef	__cplusplus
extern "C" {
#endif

#if (defined(_KERNEL) || defined(_KMEMUSER))
#include <sys/cpuvar.h>
#include <sys/group.h>
#include <sys/processor.h>
#include <sys/bitset.h>
#include <sys/atomic.h>
#include <sys/types.h>
#include <sys/kstat.h>

typedef int		pgid_t;		/* processor group id */
typedef uint_t		pg_cid_t;	/* processor group class id */

struct pg;

/*
 * Nature of CPU relationships
 */
typedef enum pg_relation {
	PGR_LOGICAL,
	PGR_PHYSICAL
} pg_relation_t;

/*
 * Processor Group callbacks ops vector
 * These provide a mechanism allowing per PG routines to invoked
 * in response to events.
 */
typedef struct pg_cb_ops {
	void		(*thread_swtch)(struct pg *, struct cpu *, hrtime_t,
			    kthread_t *, kthread_t *);
	void		(*thread_remain)(struct pg *, struct cpu *,
			    kthread_t *);
} pg_cb_ops_t;

/*
 * Processor group structure
 */
typedef struct pg {
	pgid_t			pg_id;		/* seq id */
	pg_relation_t		pg_relation;	/* grouping relationship */
	struct pg_class		*pg_class;	/* pg class */
	struct group		pg_cpus;	/* group of CPUs */
	pg_cb_ops_t		pg_cb;		/* pg events ops vector */
} pg_t;

/*
 * PG class callbacks
 */
struct pg_ops {
	struct pg	*(*alloc)();
	void		(*free)(struct pg *);
	void		(*cpu_init)(struct cpu *, struct cpu_pg *);
	void		(*cpu_fini)(struct cpu *, struct cpu_pg *);
	void		(*cpu_active)(struct cpu *);
	void		(*cpu_inactive)(struct cpu *);
	void		(*cpupart_in)(struct cpu *, struct cpupart *);
	void		(*cpupart_out)(struct cpu *, struct cpupart *);
	void		(*cpupart_move)(struct cpu *, struct cpupart *,
			    struct cpupart *);
	int		(*cpu_belongs)(struct pg *, struct cpu *);
	char		*(*policy_name)(struct pg *);
};

#define	PG_CLASS_NAME_MAX 32

/*
 * PG class structure
 */
typedef struct pg_class {
	pg_cid_t	pgc_id;
	char		pgc_name[PG_CLASS_NAME_MAX];
	struct pg_ops	*pgc_ops;
	pg_relation_t	pgc_relation;
} pg_class_t;

/*
 * Per CPU processor group data
 */
typedef struct cpu_pg {
	struct group	pgs;		/* All the CPU's PGs */
	struct group	cmt_pgs;	/* CMT load balancing lineage */
					/* (Group hierarchy ordered) */
	struct pg	*cmt_lineage;	/* Ascending lineage chain */
} cpu_pg_t;

/*
 * PG cpu iterator cookie
 */
typedef struct	pg_cpu_itr {
	pg_t		*pg;
	group_iter_t	position;
} pg_cpu_itr_t;

/*
 * Initialize a PG CPU iterator cookie
 */
#define	PG_CPU_ITR_INIT(pgrp, itr)		\
{						\
	group_iter_init(&(itr).position);	\
	(itr).pg = ((pg_t *)pgrp);		\
}

/*
 * Return the first CPU in a PG
 */
#define	PG_CPU_GET_FIRST(pgrp)			\
	(GROUP_SIZE(&((pg_t *)pgrp)->pg_cpus) > 0 ?	\
	    GROUP_ACCESS(&((pg_t *)pgrp)->pg_cpus, 0) : NULL)

/*
 * Return the number of CPUs in a PG
 */
#define	PG_NUM_CPUS(pgrp)			\
	(GROUP_SIZE(&(pgrp)->pg_cpus))

/*
 * Framework routines
 */
void		pg_init(void);
pg_cid_t	pg_class_register(char *, struct pg_ops *, pg_relation_t);

/*
 * PG CPU reconfiguration hooks
 */
void		pg_cpu0_init(void);
cpu_pg_t	*pg_cpu_init(cpu_t *, boolean_t deferred_init);
void		pg_cpu_fini(cpu_t *, cpu_pg_t *cpu_pg_deferred);
void		pg_cpu_active(cpu_t *);
void		pg_cpu_inactive(cpu_t *);
void		pg_cpu_startup(cpu_t *);
void		pg_cpu_bootstrap(cpu_t *);
int		pg_cpu_is_bootstrapped(cpu_t *);

/*
 * PG cpupart service hooks
 */
void		pg_cpupart_in(cpu_t *, struct cpupart *);
void		pg_cpupart_out(cpu_t *, struct cpupart *);
void		pg_cpupart_move(cpu_t *, struct cpupart *, struct cpupart *);

/*
 * PG CPU utility routines
 */
pg_t		*pg_create(pg_cid_t);
void		pg_destroy(pg_t *);
void		pg_cpu_add(pg_t *, cpu_t *, cpu_pg_t *);
void		pg_cpu_delete(pg_t *, cpu_t *, cpu_pg_t *);
pg_t		*pg_cpu_find_pg(cpu_t *, group_t *);
cpu_t		*pg_cpu_next(pg_cpu_itr_t *);
boolean_t	pg_cpu_find(pg_t *, cpu_t *);

/*
 * PG Event callbacks
 */
void		pg_callback_set_defaults(pg_t *);
void		pg_ev_thread_swtch(cpu_t *, hrtime_t, kthread_t *, kthread_t *);
void		pg_ev_thread_remain(cpu_t *, kthread_t *);

/*
 * PG Observability interfaces
 */
char		*pg_policy_name(pg_t *);

#endif	/* !_KERNEL && !_KMEMUSER */

#ifdef	__cplusplus
}
#endif

#endif /* _PG_H */
