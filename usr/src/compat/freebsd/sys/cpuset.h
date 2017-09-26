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
 */

#ifndef _COMPAT_FREEBSD_SYS_CPUSET_H_
#define	_COMPAT_FREEBSD_SYS_CPUSET_H_

#define	NOCPU			-1

#ifdef	_KERNEL
#define	CPU_SET(cpu, set)		CPUSET_ADD(*(set), cpu)
#define	CPU_SETOF(cpu, set)		CPUSET_ONLY(*(set), cpu)
#define	CPU_ZERO(set)			CPUSET_ZERO(*(set))
#define	CPU_CLR(cpu, set)		CPUSET_DEL(*(set), cpu)
#define	CPU_FFS(set)			cpusetobj_ffs(set)
#define	CPU_ISSET(cpu, set)		CPU_IN_SET(*(set), cpu)
#define	CPU_CMP(set1, set2)		CPUSET_ISEQUAL(*(set1), *(set2))
#define	CPU_SET_ATOMIC(cpu, set)	CPUSET_ATOMIC_ADD(*(set), cpu)

#include <sys/cpuvar.h>

int	cpusetobj_ffs(const cpuset_t *set);
#else
#include <machine/atomic.h>

typedef int cpuset_t;

#define	CPUSET(cpu)			(1UL << (cpu))

#define	CPU_SET_ATOMIC(cpu, set)	atomic_set_int((set), CPUSET(cpu))
#endif

#endif	/* _COMPAT_FREEBSD_SYS_CPUSET_H_ */
