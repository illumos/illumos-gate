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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 RackTop Systems.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_PROC_H
#define	_SYS_PROC_H

#include <sys/time.h>
#include <sys/thread.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/signal.h>
#include <sys/list.h>
#include <sys/avl.h>
#include <sys/refstr.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct pool;
struct task;
struct zone;

/*
 * One structure allocated per active process.  It contains all
 * data needed about the process while the process may be swapped
 * out.  Other per-process data (user.h) is also inside the proc structure.
 * Lightweight-process data (lwp.h) and the kernel stack may be swapped out.
 */
typedef struct	proc {

	struct	cred	*p_cred;	/* process credentials */

	struct	pid 	*p_pidp;	/* process ID info */
	struct	pid 	*p_pgidp;	/* process group ID info */

	/*
	 * Per process lwp and kernel thread stuff
	 */

	struct zone	*p_zone;	/* zone in which process lives */

	int do_not_use[10];
	int p_user[10];		/* (see sys/user.h) */
} proc_t;

#define	PROC_T				/* headers relying on proc_t are OK */

/* process ID info */

struct pid {
	unsigned int pid_prinactive :1;
	unsigned int pid_pgorphaned :1;
	unsigned int pid_padding :6;	/* used to be pid_ref, now an int */
	unsigned int pid_prslot :24;
	pid_t pid_id;
	struct proc *pid_pglink;
	struct proc *pid_pgtail;
	struct pid *pid_link;
	uint_t pid_ref;
};

#define	p_pgrp p_pgidp->pid_id
#define	p_pid  p_pidp->pid_id
#define	p_slot p_pidp->pid_prslot
#define	p_detached p_pgidp->pid_pgorphaned

#define	PID_HOLD(pidp)	ASSERT(MUTEX_HELD(&pidlock)); \
			++(pidp)->pid_ref;
#define	PID_RELE(pidp)	ASSERT(MUTEX_HELD(&pidlock)); \
			(pidp)->pid_ref > 1 ? \
				--(pidp)->pid_ref : pid_rele(pidp);

/*
 * Structure containing persistent process lock.  The structure and
 * macro allow "mutex_enter(&p->p_lock)" to continue working.
 */
struct plock {
	kmutex_t pl_lock;
};
#define	p_lock	p_lockp->pl_lock

extern proc_t p0;		/* process 0 */
extern struct plock p0lock;	/* p0's plock */
extern struct pid pid0;		/* p0's pid */

extern int issig(int);
#define	ISSIG(thr, why)	issig(why)

/* Reasons for calling issig() */

#define	FORREAL		0	/* Usual side-effects */
#define	JUSTLOOKING	1	/* Don't stop the process */

extern	void	tsd_create(uint_t *, void (*)(void *));
extern	void	tsd_destroy(uint_t *);
extern	void	*tsd_get(uint_t);
extern	int	tsd_set(uint_t, void *);

/*
 * This is normally in sunddi.h but
 * I didn't want to drag that in here.
 */
pid_t
ddi_get_pid(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PROC_H */
