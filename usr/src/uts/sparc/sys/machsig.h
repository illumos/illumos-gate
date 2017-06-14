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
/*	  All Rights Reserved	*/


/*
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_MACHSIG_H
#define	_SYS_MACHSIG_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SPARC Version
 */

/*
 * machsig.h is the machine dependent portion of siginfo.h (and is
 * included by siginfo.h). A version of machsig.h should exist for
 * each architecture. The codes for SIGILL, SIGFPE, SIGSEGV and SIGBUS
 * are in this file. The codes for SIGTRAP, SIGCLD(SIGCHLD), and
 * SIGPOLL are architecture independent and may be found in siginfo.h.
 */

#if !defined(_POSIX_C_SOURCE) || defined(_XPG4_2) || defined(__EXTENSIONS__)

/*
 * SIGILL signal codes
 */

#define	ILL_ILLOPC	1	/* illegal opcode */
#define	ILL_ILLOPN	2	/* illegal operand */
#define	ILL_ILLADR	3	/* illegal addressing mode */
#define	ILL_ILLTRP	4	/* illegal trap */
#define	ILL_PRVOPC	5	/* privileged opcode */
#define	ILL_PRVREG	6	/* privileged register */
#define	ILL_COPROC	7	/* co-processor */
#define	ILL_BADSTK	8	/* bad stack */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	NSIGILL		8
#endif

/*
 * SIGEMT signal codes
 */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	EMT_TAGOVF	1	/* tag overflow */
#define	EMT_CPCOVF	2	/* CPU performance counter overflow */
#define	NSIGEMT		2
#endif

/*
 * SIGFPE signal codes
 */

#define	FPE_INTDIV	1	/* integer divide by zero */
#define	FPE_INTOVF	2	/* integer overflow */
#define	FPE_FLTDIV	3	/* floating point divide by zero */
#define	FPE_FLTOVF	4	/* floating point overflow */
#define	FPE_FLTUND	5	/* floating point underflow */
#define	FPE_FLTRES	6	/* floating point inexact result */
#define	FPE_FLTINV	7	/* invalid floating point operation */
#define	FPE_FLTSUB	8	/* subscript out of range */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	NSIGFPE		8
#endif

/*
 * SIGSEGV signal codes
 */

#define	SEGV_MAPERR	1	/* address not mapped to object */
#define	SEGV_ACCERR	2	/* invalid permissions */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	NSIGSEGV	2
#endif

/*
 * SIGBUS signal codes
 */

#define	BUS_ADRALN	1	/* invalid address alignment */
#define	BUS_ADRERR	2	/* non-existent physical address */
#ifndef BUS_OBJERR		/* also defined in ucbinclude/sys/signal.h */
#define	BUS_OBJERR	3	/* object specific hardware error */
#endif
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	NSIGBUS		3
#endif

#endif	/* _POSIX_C_SOURCE || defined(_XPG4_2) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHSIG_H */
