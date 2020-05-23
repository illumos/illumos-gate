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
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_AMD64_MACHINE_VMPARAM_H_
#define	_COMPAT_FREEBSD_AMD64_MACHINE_VMPARAM_H_

extern caddr_t kpm_vbase;
extern size_t kpm_size;

static inline uintptr_t
phys_to_dmap(uintptr_t pa)
{
	ASSERT3U(pa, <, kpm_size);
	return ((uintptr_t)kpm_vbase + pa);
}

static inline uintptr_t
dmap_to_phys(uintptr_t kva)
{
	const uintptr_t base = (uintptr_t)kpm_vbase;

	ASSERT3U(kva, >=, base);
	ASSERT3U(kva, <, base + kpm_size);

	return (kva - base);
}

#define	PHYS_TO_DMAP(x)	phys_to_dmap(x)
#define	DMAP_TO_PHYS(x)	dmap_to_phys(x)


#endif	/* _COMPAT_FREEBSD_AMD64_MACHINE_VMPARAM_H_ */
