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
 * Copyright 2013 Pluribus Networks Inc.
 */

#ifndef _COMPAT_FREEBSD_AMD64_MACHINE_CLOCK_H_
#define	_COMPAT_FREEBSD_AMD64_MACHINE_CLOCK_H_

extern uint64_t cpu_freq_hz;

#define	tsc_freq	cpu_freq_hz

#endif	/* _COMPAT_FREEBSD_AMD64_MACHINE_CLOCK_H_ */
