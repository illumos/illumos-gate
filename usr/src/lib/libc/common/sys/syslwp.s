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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"syslwp.s"

#include "SYS.h"

/*
 * int
 * __lwp_create(ucontext_t *uc, unsigned long flags, lwpid_t *lwpidp)
 */
	ENTRY(__lwp_create)
	SYSTRAP_RVAL1(lwp_create)
	SYSLWPERR
	RET
	SET_SIZE(__lwp_create)

/*
 * int
 * _lwp_continue(lwpid_t lwpid)
 */
	ENTRY(_lwp_continue)
	SYSTRAP_RVAL1(lwp_continue)
	SYSLWPERR
	RET
	SET_SIZE(_lwp_continue)

/*
 * int
 * ___lwp_suspend(lwpid_t lwpid)
 */
	SYSREENTRY(___lwp_suspend)
	SYSTRAP_RVAL1(lwp_suspend)
	SYSINTR_RESTART(.restart____lwp_suspend)
	RET
	SET_SIZE(___lwp_suspend)

/*
 * int
 * _lwp_kill(lwpid_t lwpid, int sig)
 */
	ENTRY(_lwp_kill)
	SYSTRAP_RVAL1(lwp_kill)
	SYSLWPERR
	RET
	SET_SIZE(_lwp_kill)

/*
 * lwpid_t
 * _lwp_self(void)
 */
	ENTRY(_lwp_self)
	SYSTRAP_RVAL1(lwp_self)
	RET
	SET_SIZE(_lwp_self)

/*
 * int
 * __lwp_wait(lwpid_t lwpid, lwpid_t *departed)
 */
	ENTRY(__lwp_wait)
	SYSTRAP_RVAL1(lwp_wait)
	SYSLWPERR
	RET
	SET_SIZE(__lwp_wait)

/*
 * int
 * __lwp_detach(lwpid_t lwpid)
 */
	ENTRY(__lwp_detach)
	SYSTRAP_RVAL1(lwp_detach)
	SYSLWPERR
	RET
	SET_SIZE(__lwp_detach)

/*
 * The ___lwp_mutex_timedlock() and ___lwp_mutex_wakeup() functions
 * are called while holding non-preemptive spin locks and we must
 * not call out of the library while holding such locks in order
 * to avoid invoking the dynamic linker.  For this reason, these
 * functions must never become exported symbols from the library.
 */

/*
 * int
 * ___lwp_mutex_timedlock(lwp_mutex_t *, timespec_t *)
 */
	SYSREENTRY(___lwp_mutex_timedlock)
	SYSTRAP_RVAL1(lwp_mutex_timedlock)
	SYSINTR_RESTART(.restart____lwp_mutex_timedlock)
	RET
	SET_SIZE(___lwp_mutex_timedlock)

/*
 * int
 * ___lwp_mutex_wakeup(lwp_mutex_t *mp, int)
 */
	ENTRY(___lwp_mutex_wakeup)
	SYSTRAP_RVAL1(lwp_mutex_wakeup)
	SYSLWPERR
	RET
	SET_SIZE(___lwp_mutex_wakeup)

/*
 * int
 * _lwp_cond_broadcast(lwp_cond_t *cvp)
 */
	ENTRY(_lwp_cond_broadcast)
	SYSTRAP_RVAL1(lwp_cond_broadcast)
	SYSLWPERR
	RET
	SET_SIZE(_lwp_cond_broadcast)

/*
 * int
 * ___lwp_cond_wait(lwp_cond_t *, lwp_mutex_t *, timespec_t *, int)
 */
	ENTRY(___lwp_cond_wait)
	SYSTRAP_RVAL1(lwp_cond_wait)
	SYSLWPERR
	RET
	SET_SIZE(___lwp_cond_wait)

/*
 * int
 * _lwp_cond_signal(lwp_cond_t *cvp)
 */
	ENTRY(_lwp_cond_signal)
	SYSTRAP_RVAL1(lwp_cond_signal)
	SYSLWPERR
	RET
	SET_SIZE(_lwp_cond_signal)

/*
 * int
 * ___lwp_sema_timedwait(lwp_sema_t *, timespec_t *, int check_park)
 */
	ENTRY(___lwp_sema_timedwait)
	SYSTRAP_RVAL1(lwp_sema_timedwait)
	SYSLWPERR
	RET
	SET_SIZE(___lwp_sema_timedwait)

/*
 * int
 * _lwp_sema_trywait(lwp_sema_t *sp)
 */
	ENTRY(_lwp_sema_trywait)
	SYSTRAP_RVAL1(lwp_sema_trywait)
	SYSLWPERR
	RET
	SET_SIZE(_lwp_sema_trywait)

/*
 * int
 * _lwp_sema_post(lwp_sema_t *sp)
 */
	ENTRY(_lwp_sema_post)
	SYSTRAP_RVAL1(lwp_sema_post)
	SYSLWPERR
	RET
	SET_SIZE(_lwp_sema_post)

/*
 * int
 * _lwp_info(struct lwpinfo *infop)
 */
	ENTRY(_lwp_info)
	SYSTRAP_RVAL1(lwp_info)
	SYSLWPERR
	RET
	SET_SIZE(_lwp_info)

/*
 * sc_shared_t *
 * __schedctl(void)
 */
	SYSCALL2_RVAL1(__schedctl,schedctl)
	RET
	SET_SIZE(__schedctl)

/*
 * int
 * ___lwp_mutex_trylock(lwp_mutex_t *mp)
 */
	ENTRY(___lwp_mutex_trylock)
	SYSTRAP_RVAL1(lwp_mutex_trylock)
	SYSLWPERR
	RET
	SET_SIZE(___lwp_mutex_trylock)

/*
 * int
 * ___lwp_mutex_unlock(lwp_mutex_t *mp)
 */
	ENTRY(___lwp_mutex_unlock)
	SYSTRAP_RVAL1(lwp_mutex_unlock)
	SYSLWPERR
	RET
	SET_SIZE(___lwp_mutex_unlock)

/*
 * int
 * ___lwp_mutex_register(lwp_mutex_t *mp)
 */
	ENTRY(___lwp_mutex_register)
	SYSTRAP_RVAL1(lwp_mutex_register)
	SYSLWPERR
	RET
	SET_SIZE(___lwp_mutex_register)
