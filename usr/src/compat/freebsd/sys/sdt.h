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
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_SYS_SDT_H_
#define	_COMPAT_FREEBSD_SYS_SDT_H_

/* Empty macros to cover FreeBSD's SDT linker tricks */

#define	SDT_PROVIDER_DECLARE(mod)
#define	SDT_PROVIDER_DEFINE(mod)

#define	SDT_PROBE_DEFINE1(...)
#define	SDT_PROBE_DEFINE2(...)
#define	SDT_PROBE_DEFINE3(...)
#define	SDT_PROBE_DEFINE4(...)
#define	SDT_PROBE_DEFINE5(...)
#define	SDT_PROBE1(...)
#define	SDT_PROBE2(...)
#define	SDT_PROBE3(...)
#define	SDT_PROBE4(...)
#define	SDT_PROBE5(...)

#include_next <sys/sdt.h>

#endif /* _COMPAT_FREEBSD_SYS_SDT_H_ */
