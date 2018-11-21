/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Use a cpu_uarray_t for an array of uint64_t values that are written on a
 * per-CPU basis.  We align each CPU on a 128-byte boundary (so two cachelines).
 * It's not clear why, but this can have a significant effect in multi-socket
 * systems running certain benchmarks on a relatively current Intel system.
 *
 * So the layout is like this, for example:
 *
 * 0:	STAT1 for CPU 0
 * 8:	STAT2 for CPU 0
 * 16:	STAT3 for CPU 0
 * 24:	padding
 * 128: STAT1 for CPU 1
 * 136: STAT2 for CPU 1
 * ...
 *
 * At collection time, cpu_uarray_sum() can be used to sum the given value index
 * across all CPUs, or cpu_uarray_sum_all() sums all stats across all CPUs.
 * The summation is done such that it saturates at UINT64_MAX.
 */

#ifndef	_SYS_CPU_UARRAY_H
#define	_SYS_CPU_UARRAY_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Trying to include sysmacros.h for P2ROUNDUP() here is just too painful.
 */
#define	CUA_ROUNDUP(x, align) (-(-(x) & -(align)))
#define	CUA_ALIGN (128)
#define	CUA_CPU_STRIDE(nr_items) \
	CUA_ROUNDUP((nr_items), CUA_ALIGN / sizeof (uint64_t))
#define	CUA_INDEX(nr_items, c, i) (((c) * CUA_CPU_STRIDE(nr_items)) + (i))

#define	CPU_UARRAY_VAL(cua, cpu_index, stat_index) \
	((cua)->cu_vals[CUA_INDEX((cua)->cu_nr_items, cpu_index, stat_index)])

typedef struct {
	uint64_t cu_nr_items;
	char cu_pad[CUA_ALIGN - sizeof (uint64_t)];
#ifdef	__lint
	volatile uint64_t cu_vals[1];
#else
	volatile uint64_t cu_vals[];
#endif
} cpu_uarray_t __aligned(CUA_ALIGN);

extern cpu_uarray_t *cpu_uarray_zalloc(size_t, int);
extern void cpu_uarray_free(cpu_uarray_t *);
extern uint64_t cpu_uarray_sum(cpu_uarray_t *, size_t);
extern uint64_t cpu_uarray_sum_all(cpu_uarray_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CPU_UARRAY_H */
