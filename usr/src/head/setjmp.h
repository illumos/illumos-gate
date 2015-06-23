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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SETJMP_H
#define	_SETJMP_H

#include <iso/setjmp_iso.h>

/*
 * Allow global visibility for symbols defined in
 * C++ "std" namespace in <iso/setjmp_iso.h>.
 */
#if __cplusplus >= 199711L
using std::jmp_buf;
using std::longjmp;
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_STRICT_STDC) || defined(__XOPEN_OR_POSIX) || \
	defined(__EXTENSIONS__)
/* non-ANSI standard compilation */

#if defined(_LP64) || defined(_I32LPx)
typedef long sigjmp_buf[_SIGJBLEN];
#else
typedef int sigjmp_buf[_SIGJBLEN];
#endif

extern int sigsetjmp(sigjmp_buf, int) __RETURNS_TWICE;
#pragma unknown_control_flow(sigsetjmp)
extern void siglongjmp(sigjmp_buf, int) __NORETURN;
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SETJMP_H */
