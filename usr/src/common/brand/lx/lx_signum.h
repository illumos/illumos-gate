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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _LX_SIGNUM_H
#define	_LX_SIGNUM_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	LX_SIGHUP	1
#define	LX_SIGINT	2
#define	LX_SIGQUIT	3
#define	LX_SIGILL	4
#define	LX_SIGTRAP	5
#define	LX_SIGABRT	6
#define	LX_SIGIOT	6
#define	LX_SIGBUS	7
#define	LX_SIGFPE	8
#define	LX_SIGKILL	9
#define	LX_SIGUSR1	10
#define	LX_SIGSEGV	11
#define	LX_SIGUSR2	12
#define	LX_SIGPIPE	13
#define	LX_SIGALRM	14
#define	LX_SIGTERM	15
#define	LX_SIGSTKFLT	16
#define	LX_SIGCHLD	17
#define	LX_SIGCONT	18
#define	LX_SIGSTOP	19
#define	LX_SIGTSTP	20
#define	LX_SIGTTIN	21
#define	LX_SIGTTOU	22
#define	LX_SIGURG	23
#define	LX_SIGXCPU	24
#define	LX_SIGXFSZ	25
#define	LX_SIGVTALRM	26
#define	LX_SIGPROF	27
#define	LX_SIGWINCH	28
#define	LX_SIGIO	29
#define	LX_SIGPOLL	LX_SIGIO
#define	LX_SIGPWR	30
#define	LX_SIGSYS	31
#define	LX_SIGUNUSED	31

#define	LX_NSIG		64	/* Linux _NSIG */

#define	LX_SIGRTMIN	32
#define	LX_SIGRTMAX	LX_NSIG

extern const int ltos_signo[];
extern const int stol_signo[];

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_SIGNUM_H */
