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
 * Copyright (c) 1991-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * t_lock.h:	Prototypes for disp_locks, plus include files
 *		that describe the interfaces to kernel synch.
 *		objects.
 */

#ifndef _SYS_T_LOCK_H
#define	_SYS_T_LOCK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_ASM
#include <sys/machlock.h>
#include <sys/param.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/semaphore.h>
#include <sys/condvar.h>
#endif	/* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

/*
 * Mutual exclusion locks described in common/sys/mutex.h.
 *
 * Semaphores described in common/sys/semaphore.h.
 *
 * Readers/Writer locks described in common/sys/rwlock.h.
 *
 * Condition variables described in common/sys/condvar.h
 */

#if defined(_KERNEL)

extern int ncpus;

/*
 * Dispatcher lock type, macros and routines.
 *
 * disp_lock_t is defined in machlock.h
 */
extern	void	disp_lock_enter(disp_lock_t *);
extern	void	disp_lock_exit(disp_lock_t *);
extern	void	disp_lock_exit_nopreempt(disp_lock_t *);
extern	void	disp_lock_enter_high(disp_lock_t *);
extern	void	disp_lock_exit_high(disp_lock_t *);
extern	void	disp_lock_init(disp_lock_t *lp, char *name);
extern	void	disp_lock_destroy(disp_lock_t *lp);

#define	DISP_LOCK_INIT(lp)	LOCK_INIT_CLEAR((lock_t *)(lp))
#define	DISP_LOCK_HELD(lp)	LOCK_HELD((lock_t *)(lp))
#define	DISP_LOCK_DESTROY(lp)	ASSERT(!DISP_LOCK_HELD(lp))

/*
 * The following definitions are for assertions which can be checked
 * statically by tools like lock_lint.  You can also define your own
 * run-time test for each.  If you don't, we define them to 1 so that
 * such assertions simply pass.
 */
#ifndef NO_LOCKS_HELD
#define	NO_LOCKS_HELD	1
#endif
#ifndef NO_COMPETING_THREADS
#define	NO_COMPETING_THREADS	1
#endif

#endif	/* defined(_KERNEL) */

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_T_LOCK_H */
