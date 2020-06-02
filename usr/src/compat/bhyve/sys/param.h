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
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_SYS_PARAM_H_
#define	_COMPAT_FREEBSD_SYS_PARAM_H_

#ifndef	_KERNEL
#define	MAXCOMLEN	16
/* default value of the kernel tunable 'maxphys' in i86pc */
#define	MAXPHYS		(56 * 1024)
#endif
#define	MAXHOSTNAMELEN	256
#define	SPECNAMELEN	255

#ifdef	_KERNEL
#include <sys/time.h>

#ifndef	FALSE
#define	FALSE	0
#endif
#ifndef	TRUE
#define	TRUE	1
#endif
#endif

#include <machine/param.h>

#define	nitems(x)	(sizeof((x)) / sizeof((x)[0]))
#define	rounddown(x,y)	(((x)/(y))*(y))
#define	rounddown2(x, y) ((x)&(~((y)-1)))   /* if y is power of two */
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))  /* to any y */
#define	roundup2(x,y)	(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#define	powerof2(x)	((((x)-1)&(x))==0)

/* Macros for min/max. */
#define	MIN(a,b) (((a)<(b))?(a):(b))
#define	MAX(a,b) (((a)>(b))?(a):(b))

#define	trunc_page(x)	((unsigned long)(x) & ~(PAGE_MASK))
#define	ptoa(x)		((unsigned long)(x) << PAGE_SHIFT)

#include_next <sys/param.h>

#endif	/* _COMPAT_FREEBSD_SYS_PARAM_H_ */
