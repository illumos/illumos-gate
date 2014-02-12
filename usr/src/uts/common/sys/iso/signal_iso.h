/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in the
 * C Standard.  Any new identifiers specified in future amendments to the
 * C Standard must be placed in this header.  If these new identifiers
 * are required to also be in the C++ Standard "std" namespace, then for
 * anything other than macro definitions, corresponding "using" directives
 * must also be added to <sys/signal.h.h>.
 */

#ifndef _SYS_SIGNAL_ISO_H
#define	_SYS_SIGNAL_ISO_H

#include <sys/unistd.h>		/* needed for _SC_SIGRT_MIN/MAX */

#ifdef	__cplusplus
extern "C" {
#endif

#define	SIGHUP	1	/* hangup */
#define	SIGINT	2	/* interrupt (rubout) */
#define	SIGQUIT	3	/* quit (ASCII FS) */
#define	SIGILL	4	/* illegal instruction (not reset when caught) */
#define	SIGTRAP	5	/* trace trap (not reset when caught) */
#define	SIGIOT	6	/* IOT instruction */
#define	SIGABRT 6	/* used by abort, replace SIGIOT in the future */
#define	SIGEMT	7	/* EMT instruction */
#define	SIGFPE	8	/* floating point exception */
#define	SIGKILL	9	/* kill (cannot be caught or ignored) */
#define	SIGBUS	10	/* bus error */
#define	SIGSEGV	11	/* segmentation violation */
#define	SIGSYS	12	/* bad argument to system call */
#define	SIGPIPE	13	/* write on a pipe with no one to read it */
#define	SIGALRM	14	/* alarm clock */
#define	SIGTERM	15	/* software termination signal from kill */
#define	SIGUSR1	16	/* user defined signal 1 */
#define	SIGUSR2	17	/* user defined signal 2 */
#define	SIGCLD	18	/* child status change */
#define	SIGCHLD	18	/* child status change alias (POSIX) */
#define	SIGPWR	19	/* power-fail restart */
#define	SIGWINCH 20	/* window size change */
#define	SIGURG	21	/* urgent socket condition */
#define	SIGPOLL 22	/* pollable event occured */
#define	SIGIO	SIGPOLL	/* socket I/O possible (SIGPOLL alias) */
#define	SIGSTOP 23	/* stop (cannot be caught or ignored) */
#define	SIGTSTP 24	/* user stop requested from tty */
#define	SIGCONT 25	/* stopped process has been continued */
#define	SIGTTIN 26	/* background tty read attempted */
#define	SIGTTOU 27	/* background tty write attempted */
#define	SIGVTALRM 28	/* virtual timer expired */
#define	SIGPROF 29	/* profiling timer expired */
#define	SIGXCPU 30	/* exceeded cpu limit */
#define	SIGXFSZ 31	/* exceeded file size limit */
#define	SIGWAITING 32	/* reserved signal no longer used by threading code */
#define	SIGLWP	33	/* reserved signal no longer used by threading code */
#define	SIGFREEZE 34	/* special signal used by CPR */
#define	SIGTHAW 35	/* special signal used by CPR */
#define	SIGCANCEL 36	/* reserved signal for thread cancellation */
#define	SIGLOST	37	/* resource lost (eg, record-lock lost) */
#define	SIGXRES	38	/* resource control exceeded */
#define	SIGJVM1	39	/* reserved signal for Java Virtual Machine */
#define	SIGJVM2	40	/* reserved signal for Java Virtual Machine */
#define	SIGINFO	41	/* information request */

/* insert new signals here, and move _SIGRTM* appropriately */
#define	_SIGRTMIN 42	/* first (highest-priority) realtime signal */
#define	_SIGRTMAX 73	/* last (lowest-priority) realtime signal */
extern long _sysconf(int);	/* System Private interface to sysconf() */
#define	SIGRTMIN ((int)_sysconf(_SC_SIGRT_MIN))	/* first realtime signal */
#define	SIGRTMAX ((int)_sysconf(_SC_SIGRT_MAX))	/* last realtime signal */

#if	defined(__cplusplus)

typedef	void SIG_FUNC_TYP(int);
typedef	SIG_FUNC_TYP *SIG_TYP;
#define	SIG_PF SIG_TYP

#define	SIG_DFL	(SIG_PF)0
#define	SIG_ERR (SIG_PF)-1
#define	SIG_IGN	(SIG_PF)1
#define	SIG_HOLD (SIG_PF)2

#elif	defined(__lint)

#define	SIG_DFL	(void(*)())0
#define	SIG_ERR (void(*)())0
#define	SIG_IGN	(void (*)())0
#define	SIG_HOLD (void(*)())0

#else

#define	SIG_DFL	(void(*)())0
#define	SIG_ERR	(void(*)())-1
#define	SIG_IGN	(void (*)())1
#define	SIG_HOLD (void(*)())2

#endif

#define	SIG_BLOCK	1
#define	SIG_UNBLOCK	2
#define	SIG_SETMASK	3

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SIGNAL_ISO_H */
