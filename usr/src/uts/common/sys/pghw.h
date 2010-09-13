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

#ifndef	_PGHW_H
#define	_PGHW_H

#ifdef	__cplusplus
extern "C" {
#endif

#if (defined(_KERNEL) || defined(_KMEMUSER))
#include <sys/cpuvar.h>
#include <sys/group.h>
#include <sys/processor.h>
#include <sys/bitmap.h>
#include <sys/atomic.h>
#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/pg.h>

/*
 * Hardware that may be shared by a group of processors
 */
typedef enum pghw_type {
	PGHW_START,
	PGHW_IPIPE,	/* Instruction Pipeline */
	PGHW_CACHE,	/* Cache (generally last level) */
	PGHW_FPU,	/* Floating Point Unit / Pipeline */
	PGHW_MPIPE,	/* Pipe to Memory */
	PGHW_CHIP,	/* Socket */
	PGHW_MEMORY,
	PGHW_POW_ACTIVE,	/* Active Power Management Domain */
	PGHW_POW_IDLE,		/* Idle Power Management Domain */
	PGHW_NUM_COMPONENTS
} pghw_type_t;

/*
 * See comments in usr/src/uts/i86pc/os/cpuid.c
 * for description of processor nodes
 *
 * From sharing point of view processor nodes are
 * very similar to memory pipes, hence the #define below.
 */
#define	PGHW_PROCNODE	PGHW_MPIPE

/*
 * Returns true if the hardware is a type of power management domain
 */
#define	PGHW_IS_PM_DOMAIN(hw)	\
	(hw == PGHW_POW_ACTIVE || hw == PGHW_POW_IDLE)

/*
 * Anonymous instance id
 */
#define	PGHW_INSTANCE_ANON ((id_t)0xdecafbad)

/*
 * Max length of PGHW kstat strings
 */
#define	PGHW_KSTAT_STR_LEN_MAX	32


/*
 * Platform specific handle
 */
typedef uintptr_t pghw_handle_t;

/*
 * Representation of PG hardware utilization NOTE: All the sums listed below are
 * the sums of running total of each item for each CPU in the PG (eg.
 * sum(utilization) is sum of running total utilization of each CPU in PG)
 */
typedef struct pghw_util {
	uint64_t	pghw_util;	/* sum(utilization) */
	uint64_t	pghw_rate;	/* Last observed utilization rate */
	uint64_t	pghw_rate_max;	/* Max observed rate (in units/sec) */
	hrtime_t	pghw_time_stamp; /* Timestamp of last snapshot */
	/*
	 * sum(time utilization counters on)
	 */
	hrtime_t	pghw_time_running;
	/*
	 * sum(time utilization counters off)
	 */
	hrtime_t	pghw_time_stopped;
} pghw_util_t;


/*
 * Processor Group (physical sharing relationship)
 */
typedef struct pghw {
	pg_t		pghw_pg;	/* processor group */
	pghw_type_t	pghw_hw;	/* HW sharing relationship */
	id_t		pghw_instance;	/* sharing instance identifier */
	pghw_handle_t	pghw_handle;	/* hw specific opaque handle */
	kstat_t		*pghw_kstat;	/* physical kstats exported */
	kstat_t		*pghw_cu_kstat;  /* for capacity and utilization */
	/*
	 * pghw_generation should be updated by superclasses whenever PG changes
	 * significanly (e.g.  new CPUs join or leave PG).
	 */
	uint_t		pghw_generation; /* generation number */

	/*
	 * The following fields are used by PGHW cu kstats
	 */
	char		*pghw_cpulist;	/* list of CPUs */
	size_t		pghw_cpulist_len;	/* length of the list */
	/*
	 * Generation number at kstat update time
	 */
	uint_t		pghw_kstat_gen;
	pghw_util_t	pghw_stats;	/* Utilization data */
} pghw_t;

/*
 * IDs associating a CPU with various physical hardware
 */
typedef struct cpu_physid {
	id_t		cpu_chipid;	/* CPU's physical processor */
	id_t		cpu_coreid;	/* CPU's physical core */
	id_t		cpu_cacheid;	/* CPU's cache id */
} cpu_physid_t;

/*
 * Physical PG initialization / CPU service hooks
 */
extern void		pghw_init(pghw_t *, cpu_t *, pghw_type_t);
extern void		pghw_fini(pghw_t *);
extern void		pghw_cpu_add(pghw_t *, cpu_t *);
extern pghw_t		*pghw_place_cpu(cpu_t *, pghw_type_t);
extern void		pghw_cmt_fini(pghw_t *);

/*
 * Physical ID cache creation / destruction
 */
extern void		pghw_physid_create(cpu_t *);
extern void		pghw_physid_destroy(cpu_t *);

/*
 * CPU / PG hardware related seach operations
 */
extern pghw_t		*pghw_find_pg(cpu_t *, pghw_type_t);
extern pghw_t		*pghw_find_by_instance(id_t, pghw_type_t);
extern group_t		*pghw_set_lookup(pghw_type_t);

/* Hardware sharing relationship platform interfaces */
extern int		pg_plat_hw_shared(cpu_t *, pghw_type_t);
extern int		pg_plat_cpus_share(cpu_t *, cpu_t *, pghw_type_t);
extern id_t		pg_plat_hw_instance_id(cpu_t *, pghw_type_t);
extern pghw_type_t	pg_plat_hw_rank(pghw_type_t, pghw_type_t);

/*
 * String representation of the hardware type
 */
extern char		*pghw_type_string(pghw_type_t);

/*
 * What comprises a "core" may vary across processor implementations,
 * and so the term itself is somewhat unstable. For this reason, there
 * is no PGHW_CORE type, but we provide an interface here to allow platforms
 * to express cpu <=> core mappings.
 */
extern id_t		pg_plat_get_core_id(cpu_t *);

#endif	/* !_KERNEL && !_KMEMUSER */

#ifdef	__cplusplus
}
#endif

#endif /* _PGHW_H */
