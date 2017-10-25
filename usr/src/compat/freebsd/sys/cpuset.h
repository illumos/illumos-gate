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
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_SYS_CPUSET_H_
#define	_COMPAT_FREEBSD_SYS_CPUSET_H_

#define	NOCPU			-1

#ifdef	_KERNEL

#include <sys/_cpuset.h>

#define	CPU_SET(cpu, set)		cpuset_add((set), (cpu))
#define	CPU_SETOF(cpu, set)		cpuset_only((set), (cpu))
#define	CPU_ZERO(set)			cpuset_zero((cpuset_t *)(set))
#define	CPU_CLR(cpu, set)		cpuset_del((set), (cpu))
#define	CPU_FFS(set)			cpusetobj_ffs(set)
#define	CPU_ISSET(cpu, set)		cpu_in_set((cpuset_t *)(set), (cpu))
#define	CPU_AND(dst, src)		cpuset_and(			\
						(cpuset_t *)(dst),	\
						(cpuset_t *)(src))
#define	CPU_CMP(set1, set2)		(cpuset_isequal(		\
						(cpuset_t *)(set1),	\
						(cpuset_t *)(set2)) == 0)
#define	CPU_SET_ATOMIC(cpu, set)	cpuset_atomic_add(		\
						(cpuset_t *)(set),	\
						(cpu))
#define	CPU_CLR_ATOMIC(cpu, set)	cpuset_atomic_del(		\
						(cpuset_t *)(set),	\
						(cpu))

/* XXXJOY: The _ACQ variants appear to imply a membar too. Is that an issue? */
#define	CPU_SET_ATOMIC_ACQ(cpu, set)	cpuset_atomic_add((set), (cpu))


int	cpusetobj_ffs(const cpuset_t *set);

#else

#include <sys/bitmap.h>
#include <machine/atomic.h>

/* For now, assume NCPU of 256 */
#define	CPU_SETSIZE			(256)

typedef struct {
	ulong_t _bits[BT_BITOUL(CPU_SETSIZE)];
} cpuset_t;

static __inline int cpuset_empty(const cpuset_t *set)
{
	uint_t i;

	for (i = 0; i < BT_BITOUL(CPU_SETSIZE); i++) {
		if (set->_bits[i] != 0)
			return (0);
	}
	return (1);
}


#define	CPU_ISSET(cpu, setp)		BT_TEST((setp)->_bits, cpu)
#define	CPU_EMPTY(setp)			cpuset_empty((setp))
#define	CPU_SET_ATOMIC(cpu, setp)	\
	atomic_set_long(&(BT_WIM((setp)->_bits, cpu)), BT_BIW(cpu))
#define	CPU_CLR_ATOMIC(cpu, setp)	\
	atomic_clear_long(&(BT_WIM((setp)->_bits, cpu)), BT_BIW(cpu))

#endif

#endif	/* _COMPAT_FREEBSD_SYS_CPUSET_H_ */
