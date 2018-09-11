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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_SYS_THREAD_H
#define	_SYS_THREAD_H

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/klwp.h>
#include <sys/signal.h>  /* expected by including code */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The thread object, its states, and the methods by which it
 * is accessed.
 */

/*
 * Values that t_state may assume. Note that t_state cannot have more
 * than one of these flags set at a time.
 */
#define	TS_FREE		0x00	/* Thread at loose ends */
#define	TS_SLEEP	0x01	/* Awaiting an event */
#define	TS_RUN		0x02	/* Runnable, but not yet on a processor */
#define	TS_ONPROC	0x04	/* Thread is being run on a processor */
#define	TS_ZOMB		0x08	/* Thread has died but hasn't been reaped */
#define	TS_STOPPED	0x10	/* Stopped, initial state */
#define	TS_WAIT		0x20	/* Waiting to become runnable */

/* ctxop_t */

/* afd_t needed by sys/file.h via sys/t_lock.h */
typedef struct _afd_not_used afd_t;

struct turnstile;
struct panic_trap_info;
struct upimutex;
struct kproject;
struct on_trap_data;
struct waitq;
struct _kcpc_ctx;
struct _kcpc_set;

/* Definition for kernel thread identifier type */
typedef uint64_t kt_did_t;

struct _kthread;
typedef struct _kthread	*kthread_id_t;

typedef struct _kthread kthread_t;

extern	kthread_t	*_curthread(void);	/* returns thread pointer */
#define	curthread	(_curthread())		/* current thread pointer */

#define	_KTHREAD_INVALID	((void *)(uintptr_t)-1)


struct proc;
extern struct proc	*_curproc(void);
#define	curproc		(_curproc())		/* current proc pointer */

struct zone;
extern struct zone	*_curzone(void);
#define	curzone		(_curzone())		/* current zone pointer */

extern	kthread_t	*thread_create(
	caddr_t		stk,
	size_t		stksize,
	void		(*proc)(),
	void		*arg,
	size_t		len,
	struct proc	*pp,
	int		state,
	pri_t		pri);
extern	void	thread_exit(void) __NORETURN;
extern	void	thread_join(kt_did_t);

extern kthread_t *zthread_create(caddr_t, size_t, void (*)(), void *, size_t,
    pri_t);
extern void zthread_exit(void) __NORETURN;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_THREAD_H */
