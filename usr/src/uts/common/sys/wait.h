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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_WAIT_H
#define	_SYS_WAIT_H

#include <sys/feature_tests.h>

#include <sys/types.h>

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || defined(__EXTENSIONS__)
#include <sys/resource.h>	/* Added for XSH4.2 */
#include <sys/siginfo.h>
#include <sys/procset.h>
#endif /* !defined(__XOPEN_OR_POSIX) || (defined(_XPG4_2) ... */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * arguments to wait functions
 */

#define	WUNTRACED	0004	/* wait for processes stopped by signals */
#define	WNOHANG		0100	/* non blocking form of wait	*/


#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	WEXITED		0001	/* wait for processes that have exited	*/
#define	WTRAPPED	0002	/* wait for processes stopped while tracing */
#define	WSTOPPED	WUNTRACED /* backwards compatibility */
#define	WCONTINUED	0010	/* wait for processes continued */
#define	WNOWAIT		0200	/* non destructive form of wait */
#define	WOPTMASK (WEXITED|WTRAPPED|WSTOPPED|WCONTINUED|WNOHANG|WNOWAIT)
#endif /* !defined(__XOPEN_OR_POSIX) || (defined(_XPG4_2) ... */

/*
 * macros for stat return from wait functions
 */

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || defined(__EXTENSIONS__)

#define	WSTOPFLG		0177
#define	WCONTFLG		0177777
#define	WCOREFLG		0200
#define	WSIGMASK		0177

#define	WLOBYTE(stat)		((int)((stat)&0377))
#define	WHIBYTE(stat)		((int)(((stat)>>8)&0377))
#define	WWORD(stat)		((int)((stat))&0177777)

#define	WIFCONTINUED(stat)	(WWORD(stat) == WCONTFLG)
#define	WCOREDUMP(stat)		((stat)&WCOREFLG)

#endif /* !defined(__XOPEN_OR_POSIX) || (defined(_XPG4_2) ... */

#define	WIFEXITED(stat)		((int)((stat)&0xFF) == 0)
#define	WIFSIGNALED(stat)	((int)((stat)&0xFF) > 0 && \
				    (int)((stat)&0xFF00) == 0)
#define	WIFSTOPPED(stat)	((int)((stat)&0xFF) == 0177 && \
				    (int)((stat)&0xFF00) != 0)
#define	WEXITSTATUS(stat)	((int)(((stat)>>8)&0xFF))
#define	WTERMSIG(stat)		((int)((stat)&0x7F))
#define	WSTOPSIG(stat)		((int)(((stat)>>8)&0xFF))


#if !defined(_KERNEL)

extern pid_t wait(int *);
extern pid_t waitpid(pid_t, int *, int);

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || defined(__EXTENSIONS__)
extern int waitid(idtype_t, id_t, siginfo_t *, int);
/* Marked as LEGACY in SUSv2 and removed in SUSv3 */
#if !defined(_XPG6) || defined(__EXTENSIONS__)
extern pid_t wait3(int *, int, struct rusage *);
#endif /* !defined(_XPG6) || defined(__EXTENSIONS__) */
#endif /* !defined(__XOPEN_OR_POSIX) || (defined(_XPG4_2) ... */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
extern pid_t wait4(pid_t, int *, int, struct rusage *);
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_WAIT_H */
