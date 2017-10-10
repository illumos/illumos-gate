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

#ifndef _COMPAT_FREEBSD_SYS_KERNEL_H_
#define	_COMPAT_FREEBSD_SYS_KERNEL_H_

#define	TUNABLE_INT_FETCH(path, var)

#include <sys/linker_set.h>

typedef void (*sysinit_func_t)(const void *);

struct sysinit {
	const sysinit_func_t func;
	const void *data;
};

#define	SYSINIT(uniquifier, subsystem, order, func, ident) \
	static struct sysinit uniquifier ## _sys_init = {  \
		(const sysinit_func_t)func,		   \
		(const void *)&(ident)			   \
	};						   \
	DATA_SET(sysinit_set, uniquifier ## _sys_init);

extern void sysinit(void);

#define	ticks	ddi_get_lbolt()

#endif	/* _COMPAT_FREEBSD_SYS_KERNEL_H_ */
