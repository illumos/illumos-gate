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

#ifndef _COMPAT_FREEBSD_SYS_SGLIST_H_
#define	_COMPAT_FREEBSD_SYS_SGLIST_H_

#ifdef _KERNEL

struct sglist;

struct sglist *sglist_alloc(int, int);
void sglist_free(struct sglist *);
int sglist_append_phys(struct sglist *, vm_paddr_t, size_t);

#endif /* _KERNEL */

#endif	/* _COMPAT_FREEBSD_SYS_SGLIST_H_ */
