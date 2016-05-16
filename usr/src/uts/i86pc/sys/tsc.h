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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _TSC_H
#define	_TSC_H

/*
 * flags to patch tsc_read routine.
 */
#define	TSC_NONE		0x0
#define	TSC_RDTSC_CPUID		0x1
#define	TSC_RDTSC_MFENCE	0x2
#define	TSC_RDTSC_LFENCE	0x3
#define	TSC_TSCP		0x4

#endif /* _TSC_H */
