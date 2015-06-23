/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1997-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MON_H
#define	_MON_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Inclusion of <sys/types.h> will break SVID namespace, hence only
 * the size_t type is defined in this header.
 */
#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64) || defined(_I32LPx)
typedef unsigned long size_t;	/* size of something in bytes */
#else
typedef unsigned int  size_t;	/* (historical version) */
#endif
#endif  /* _SIZE_T */

struct hdr {
	char	*lpc;
	char	*hpc;
	size_t	nfns;
};

struct cnt {
	char	*fnpc;
	long	mcnt;
};

typedef unsigned short WORD;

#define	MON_OUT	"mon.out"
#define	MPROGS0	(150 * sizeof (WORD))	/* 300 for pdp11, 600 for 32-bits */
#define	MSCALE0	4

#ifndef NULL
#if defined(_LP64)
#define	NULL	0L
#else
#define	NULL	0
#endif
#endif

extern void monitor(int (*)(void), int (*)(void), WORD *, size_t, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _MON_H */
