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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in the
 * C Standard.  Any new identifiers specified in future amendments to the
 * C Standard must be placed in this header.  If these new identifiers
 * are required to also be in the C++ Standard "std" namespace, then for
 * anything other than macro definitions, corresponding "using" directives
 * must also be added to <setjmp.h>.
 */

#ifndef _ISO_SETJMP_ISO_H
#define	_ISO_SETJMP_ISO_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _JBLEN

/*
 * The sizes of the jump-buffer (_JBLEN) and the sigjump-buffer
 * (_SIGJBLEN) are defined by the appropriate, processor specific,
 * ABI.
 */
#if defined(__amd64)
#define	_JBLEN		8	/* ABI value */
#define	_SIGJBLEN	128	/* ABI value */
#elif defined(__i386)
#define	_JBLEN		10	/* ABI value */
#define	_SIGJBLEN	128	/* ABI value */
#elif defined(__sparcv9)
#define	_JBLEN		12	/* ABI value */
#define	_SIGJBLEN	19	/* ABI value */
#elif defined(__sparc)
#define	_JBLEN		12	/* ABI value */
#define	_SIGJBLEN	19	/* ABI value */
#else
#error "ISA not supported"
#endif

#if __cplusplus >= 199711L
namespace std {
#endif

#if defined(__i386) || defined(__amd64) || \
	defined(__sparc) || defined(__sparcv9)
#if defined(_LP64) || defined(_I32LPx)
typedef long	jmp_buf[_JBLEN];
#else
typedef int	jmp_buf[_JBLEN];
#endif
#else
#error "ISA not supported"
#endif

extern int setjmp(jmp_buf) __RETURNS_TWICE;
#pragma unknown_control_flow(setjmp)
extern int _setjmp(jmp_buf) __RETURNS_TWICE;
#pragma unknown_control_flow(_setjmp)
extern void longjmp(jmp_buf, int) __NORETURN;
extern void _longjmp(jmp_buf, int) __NORETURN;

#if __cplusplus >= 199711L
}
#endif /* end of namespace std */

#if __cplusplus >= 199711L
using std::setjmp;
#endif

#if defined(_STRICT_STDC) || __cplusplus >= 199711L
#define	setjmp(env)	setjmp(env)
#endif

#endif  /* _JBLEN */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_SETJMP_ISO_H */
