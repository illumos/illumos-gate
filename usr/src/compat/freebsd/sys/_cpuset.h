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
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_SYS__CPUSET_H_
#define	_COMPAT_FREEBSD_SYS__CPUSET_H_

#ifdef _KERNEL
/*
 * The sys/_cpuset.h header is used to communicate the layout of cpuset_t while
 * sys/cpuset.h contains the manipulation routines.
 *
 * The explicit guard definition below is necessary as other contrib headers
 * change their behavior based on its presence.
 */
#define	_SYS__CPUSET_H_

#include <sys/cpuvar.h>

#endif /* _KERNEL */

#endif	/* _COMPAT_FREEBSD_SYS__CPUSET_H_ */
