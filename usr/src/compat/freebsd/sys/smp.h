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

#ifndef _COMPAT_FREEBSD_SYS_SMP_H_
#define	_COMPAT_FREEBSD_SYS_SMP_H_

#include <sys/cpuset.h>

void	smp_rendezvous(void (*)(void *),
		       void (*)(void *),
		       void (*)(void *),
		       void *arg);

void	ipi_cpu(int cpu, u_int ipi);

#endif	/* _COMPAT_FREEBSD_SYS_SMP_H_ */
