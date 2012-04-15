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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FORK_H
#define	_SYS_FORK_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)

#if !defined(_KERNEL)

extern pid_t forkx(int);
extern pid_t forkallx(int);
extern pid_t vforkx(int) __RETURNS_TWICE;

#pragma unknown_control_flow(vforkx)

#endif	/* !defined(_KERNEL) */

/*
 * The argument to any of the forkx() functions is a set of flags
 * formed by or-ing together zero or more of the following flags.
 * fork()/forkall()/vfork() are equivalent to the corresponding
 * forkx()/forkallx()/vforkx() functions with a zero argument.
 */

/*
 * Do not post a SIGCHLD signal to the parent when the child terminates,
 * regardless of the disposition of the SIGCHLD signal in the parent.
 * SIGCHLD signals are still possible for job control stop and continue
 * actions (CLD_STOPPED, CLD_CONTINUED) if the parent has requested them.
 */
#define	FORK_NOSIGCHLD	0x0001

/*
 * Do not allow wait-for-multiple-pids by the parent, as in waitid(P_ALL)
 * or waitid(P_PGID), to reap the child and do not allow the child to
 * be reaped automatically due the disposition of the SIGCHLD signal
 * being set to be ignored.  Only a specific wait for the child, as
 * in waitid(P_PID, pid), is allowed and it is required, else when
 * the child exits it will remain a zombie until the parent exits.
 */
#define	FORK_WAITPID	0x0002

#endif	/* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FORK_H */
