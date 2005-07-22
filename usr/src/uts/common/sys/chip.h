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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CHIP_H
#define	_CHIP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * generic kernel CMT processor support
 */

#ifdef	__cplusplus
extern "C" {
#endif

#if (defined(_KERNEL) || defined(_KMEMUSER))
#include <sys/cpuvar.h>
#include <sys/processor.h>
#include <sys/bitmap.h>
#include <sys/atomic.h>
#include <sys/types.h>

/*
 * Chip types
 */
typedef enum chip_type {
	CHIP_DEFAULT,			/* Default, non CMT processor */
	CHIP_SMT,			/* SMT, single core */
	CHIP_CMP_SPLIT_CACHE,		/* CMP with split caches */
	CHIP_CMP_SHARED_CACHE,		/* CMP with shared caches */
	CHIP_NUM_TYPES
} chip_type_t;


/*
 * Balancing is possible if multiple chips exist in the lgroup
 * but only necessary if the chip has multiple online logical CPUs
 */
#define	CHIP_SHOULD_BALANCE(chp)		\
	(((chp)->chip_ncpu > 1) && ((chp)->chip_next_lgrp != (chp)))

/*
 * Platform's definition of a chip's properties
 */
typedef struct	chip_def {
	chip_type_t		chipd_type;
	int			chipd_rechoose_adj;
} chip_def_t;

/*
 * Per chip kstats
 */
typedef enum chip_stat_types {
	CHIP_ID,		/* chip "id" */
	CHIP_NCPUS,		/* number of active cpus */
	CHIP_NRUNNING,		/* number of running threads on chip */
	CHIP_RECHOOSE,		/* chip's rechoose_interval */
	CHIP_NUM_STATS		/* always last */
} chip_stat_t;

#define	CHIP_KSTAT_NAMES		\
static char *chip_kstat_names[] = {	\
					\
	"chip_id",			\
	"logical_cpus",			\
	"chip_nrunning",       		\
	"chip_rechoose_interval",	\
}

/*
 * Physical processor (chip) structure.
 */
typedef struct chip {
	chipid_t	chip_id;		/* chip's "id" */
	chipid_t	chip_seqid;		/* sequential id */
	struct chip	*chip_prev;		/* previous chip on list */
	struct chip	*chip_next;		/* next chip on list */
	struct chip	*chip_prev_lgrp;	/* prev chip in lgroup */
	struct chip	*chip_next_lgrp;	/* next chip in lgroup */
	chip_type_t	chip_type;		/* type of chip */
	uint16_t	chip_ncpu;		/* number of active cpus */
	uint16_t	chip_ref;		/* chip's reference count */
	struct cpu	*chip_cpus;		/* per chip cpu list */
	struct lgrp	*chip_lgrp;		/* chip lives in this lgroup */
	int		chip_rechoose_adj;	/* chip specific adjustment */

	/*
	 * chip kstats
	 */
	kstat_t			*chip_kstat;
	kmutex_t		chip_kstat_mutex;
	struct kstat_named	chip_kstat_data[CHIP_NUM_STATS];

	struct chip	*chip_balance;		/* chip to balance against */
	uint32_t	chip_nrunning;		/* # of running threads */
} chip_t;

/*
 * Change the number of running threads on the chip
 */
#define	CHIP_NRUNNING(chp, n) {						\
	atomic_add_32(&((chp)->chip_nrunning), (n));			\
}

/*
 * True if this CPU is active on the chip
 */
#define	CHIP_CPU_ACTIVE(cp)	((cp)->cpu_next_chip != NULL)

/*
 * Sets of chips
 * The "id" used here should be a chip's sequential id.
 * (chip_seqid)
 */
#if defined(_MACHDEP)

#define	CHIP_MAX_CHIPS	NCPU
#define	CHIP_SET_WORDS	BT_BITOUL(CHIP_MAX_CHIPS)

typedef struct chip_set {
	ulong_t csb[CHIP_SET_WORDS];
} chip_set_t;

extern	int	chip_set_isnull(chip_set_t *);

#define	CHIP_SET_ISNULL(set)		chip_set_isnull(&(set))
#define	CHIP_SET_TEST(set, id)		BT_TEST((set).csb, id)
#define	CHIP_SET_REMOVE(set, id)	BT_CLEAR((set).csb, id)
#define	CHIP_SET_ADD(set, id)		BT_SET((set).csb, id)

#define	CHIP_SET_ZERO(set) {				\
	int	_i;					\
	for (_i = 0; _i < CHIP_SET_WORDS; _i++)		\
		(set).csb[_i] = 0;			\
}

#define	CHIP_IN_CPUPART(chp, cp)			\
	(CHIP_SET_TEST((cp)->cp_chipset, (chp)->chip_seqid))

#endif	/* _MACHDEP */

/*
 * Common kernel chip operations
 */
void		chip_cpu_init(cpu_t *);
void		chip_cpu_fini(cpu_t *);
void		chip_cpu_assign(cpu_t *);
void		chip_cpu_unassign(cpu_t *);
void		chip_cpu_startup(cpu_t *);
void		chip_bootstrap_cpu(cpu_t *);

void		chip_cpu_move_part(cpu_t *, struct cpupart *,
			struct cpupart *);

void		chip_kstat_create(chip_t *);

/*
 * Platform chip operations
 */
chipid_t	chip_plat_get_chipid(cpu_t *);
#ifdef	sun4v
id_t		chip_plat_get_pipeid(cpu_t *);
#endif /* sun4v */

void		chip_plat_define_chip(cpu_t *, chip_def_t *);
int		chip_plat_get_clogid(cpu_t *);

#endif	/* !_KERNEL && !_KMEMUSER */

#ifdef	__cplusplus
}
#endif

#endif /* _CHIP_H */
