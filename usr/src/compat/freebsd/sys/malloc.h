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

#ifndef _COMPAT_FREEBSD_SYS_MALLOC_H_
#define	_COMPAT_FREEBSD_SYS_MALLOC_H_

/*
 * flags to malloc.
 */
#define	M_NOWAIT	0x0001		/* do not block */
#define	M_WAITOK	0x0002		/* ok to block */
#define	M_ZERO		0x0100		/* bzero the allocation */

struct malloc_type {
	const char	*ks_shortdesc;	/* Printable type name. */
};

#ifdef	_KERNEL
#define	MALLOC_DEFINE(type, shortdesc, longdesc)			\
	struct malloc_type type[1] = {					\
		{ shortdesc }						\
	}

#define	MALLOC_DECLARE(type)						\
	extern struct malloc_type type[1]

void	free(void *addr, struct malloc_type *type);
void	*malloc(unsigned long size, struct malloc_type *type, int flags);
void	*old_malloc(unsigned long size, struct malloc_type *type , int flags);
void	*contigmalloc(unsigned long, struct malloc_type *, int, vm_paddr_t,
    vm_paddr_t, unsigned long, vm_paddr_t);
void	contigfree(void *, unsigned long, struct malloc_type *);


#endif	/* _KERNEL */

#endif	/* _COMPAT_FREEBSD_SYS_MALLOC_H_ */
