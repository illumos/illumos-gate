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

#ifndef _COMPAT_FREEBSD_AMD64_MACHINE_PARAM_H_
#define	_COMPAT_FREEBSD_AMD64_MACHINE_PARAM_H_

#ifdef	_KERNEL
#define	MAXCPU		NCPU
#endif	/* _KERNEL */

#define	PAGE_SHIFT	12		/* LOG2(PAGE_SIZE) */
#define	PAGE_SIZE	(1<<PAGE_SHIFT)	/* bytes/page */
#define	PAGE_MASK	(PAGE_SIZE-1)

/* Size of the level 1 page table units */
#define	NPTEPG		(PAGE_SIZE/(sizeof (pt_entry_t)))

/* Size of the level 2 page directory units */
#define	NPDEPG		(PAGE_SIZE/(sizeof (pd_entry_t)))

/* Size of the level 3 page directory pointer table units */
#define	NPDPEPG		(PAGE_SIZE/(sizeof (pdp_entry_t)))

/* Size of the level 4 page-map level-4 table units */
#define	NPML4EPG	(PAGE_SIZE/(sizeof (pml4_entry_t)))

#define	CACHE_LINE_SIZE	64

#endif	/* _COMPAT_FREEBSD_AMD64_MACHINE_PARAM_H_ */
