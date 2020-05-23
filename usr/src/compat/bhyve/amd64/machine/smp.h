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
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_AMD64_MACHINE_SMP_H_
#define	_COMPAT_FREEBSD_AMD64_MACHINE_SMP_H_

#ifdef _KERNEL

/*
 * APIC-related functions are replaced with native calls rather than shims
 * which attempt to replicate the FreeBSD interfaces.  This is empty, but will
 * remain present to appease sources which wish to include the path.
 */

#endif /* _KERNEL */

#endif	/* _COMPAT_FREEBSD_AMD64_MACHINE_SMP_H_ */
