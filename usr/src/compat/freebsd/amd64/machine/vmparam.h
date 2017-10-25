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
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_AMD64_MACHINE_VMPARAM_H_
#define	_COMPAT_FREEBSD_AMD64_MACHINE_VMPARAM_H_

extern caddr_t kpm_vbase;
extern size_t kpm_size;

#define	PHYS_TO_DMAP(x)	({ 			\
	ASSERT((uintptr_t)(x) < kpm_size);	\
	(uintptr_t)(x) | (uintptr_t)kpm_vbase; })

#define	DMAP_TO_PHYS(x)	({				\
	ASSERT((uintptr_t)(x) >= (uintptr_t)kpm_vbase);		\
	ASSERT((uintptr_t)(x) < ((uintptr_t)kpm_vbase + kpm_size));	\
	(uintptr_t)(x) & ~(uintptr_t)kpm_vbase; })	\


#endif	/* _COMPAT_FREEBSD_AMD64_MACHINE_VMPARAM_H_ */
