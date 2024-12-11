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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * 4.3BSD setjmp compatibility header
 *
 * 4.3BSD setjmp/longjmp is equivalent to SVR4 sigsetjmp/siglongjmp -
 * 4.3BSD _setjmp/_longjmp is equivalent to SVR4 setjmp/longjmp
 */

#ifndef _SETJMP_H
#define	_SETJMP_H

#include <sys/types.h>
#include <sys/signal.h>
#include <sys/ucontext.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The sizes of the jump-buffer (_JBLEN) and the sigjump-buffer
 * (_SIGJBLEN) are defined by the appropriate, processor specific, ABI.
 */
#if defined(__amd64)
#define	_JBLEN		128	/* must be the same as _SIGJBLEN for libucb */
#define	_SIGJBLEN	128	/* ABI value */
#elif defined(__i386)
#define	_JBLEN		128	/* must be the same as _SIGJBLEN for libucb */
#define	_SIGJBLEN	128	/* ABI value */
#elif defined(__sparcv9)
#define	_JBLEN		19	/* ABI value */
#define	_SIGJBLEN	19	/* ABI value */
#elif defined(__sparc)
#define	_JBLEN		19	/* _SIGJBLEN */
#define	_SIGJBLEN	19	/* ABI value */
#else
#error "ISA not supported"
#endif

#if defined(__i386) || defined(__amd64) || \
	defined(__sparc) || defined(__sparcv9)

#if !defined(_LP64) && defined(__cplusplus)
typedef int jmp_buf[_JBLEN];
#else
typedef long jmp_buf[_JBLEN];
#endif

#else
#error "ISA not supported"
#endif

#if defined(__i386) || defined(__amd64) || \
	defined(__sparc) || defined(__sparcv9)

#if !defined(_LP64) && defined(__cplusplus)
typedef int sigjmp_buf[_SIGJBLEN];
#else
typedef long sigjmp_buf[_SIGJBLEN];
#endif

#else
#error "ISA not supported"
#endif

#define	setjmp(env)		_sigsetjmp((env), 1)
#define	longjmp(env, val)	_siglongjmp((env), (val))
#define	_setjmp(env)		_sigsetjmp((env), 0)
#define	_longjmp(env, val)	_siglongjmp((env), (val))

extern int _sigsetjmp(sigjmp_buf, int) __RETURNS_TWICE;
extern void _siglongjmp(sigjmp_buf, int) __NORETURN;

extern int sigsetjmp(sigjmp_buf, int) __RETURNS_TWICE;
extern void siglongjmp(sigjmp_buf, int) __NORETURN;

#ifdef __cplusplus
}
#endif

#endif /* _SETJMP_H */
