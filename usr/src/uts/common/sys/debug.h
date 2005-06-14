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
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_DEBUG_H
#define	_SYS_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ASSERT(ex) causes a panic or debugger entry if expression ex is not
 * true.  ASSERT() is included only for debugging, and is a no-op in
 * production kernels.  VERIFY(ex), on the other hand, behaves like
 * ASSERT on debug kernels but evaluates the expression on non-debug
 * kernels.
 */

#ifdef _KERNEL
#if DEBUG
#define	VERIFY(EX) ((void)((EX) || assfail(#EX, __FILE__, __LINE__)))
#else
#define	VERIFY(EX) ((void)(EX))
#endif
#endif

#if defined(__STDC__)
extern int assfail(const char *, const char *, int);
#if DEBUG
#define	ASSERT(EX) ((void)((EX) || assfail(#EX, __FILE__, __LINE__)))
#else
#define	ASSERT(x)  ((void)0)
#endif
#else	/* defined(__STDC__) */
extern int assfail();
#if DEBUG
#define	ASSERT(EX) ((void)((EX) || assfail("EX", __FILE__, __LINE__)))
#else
#define	ASSERT(x)  ((void)0)
#endif
#endif	/* defined(__STDC__) */

/*
 * Assertion variants sensitive to the compilation data model
 */
#if defined(_LP64)
#define	ASSERT64(x)	ASSERT(x)
#define	ASSERT32(x)
#else
#define	ASSERT64(x)
#define	ASSERT32(x)	ASSERT(x)
#endif

#ifdef	_KERNEL

extern void abort_sequence_enter(char *);
extern void debug_enter(char *);

#endif	/* _KERNEL */

#ifdef MONITOR
#define	MONITOR(id, w1, w2, w3, w4) monitor(id, w1, w2, w3, w4)
#else
#define	MONITOR(id, w1, w2, w3, w4)
#endif

#if defined(DEBUG) && !defined(__sun)
/* CSTYLED */
#define	STATIC
#else
/* CSTYLED */
#define	STATIC static
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DEBUG_H */
