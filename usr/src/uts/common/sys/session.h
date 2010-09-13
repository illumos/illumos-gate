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
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_SESSION_H
#define	_SYS_SESSION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Session structure overview.
 *
 * Currently, the only structure in the kernel which has a pointer to a
 * session structures is the proc_t via the p_sessp pointer.  To
 * access a session proc_t->p_sessp pointer a caller must hold either
 * pidlock or p_splock.  These locks only protect the p_sessp pointer
 * itself and do not protect any of the contents of the session structure.
 * To prevent the contents of a the session structure from changing the
 * caller must grab s_lock.
 *
 * No callers should ever update the contents of the session structure
 * directly.  Only the session management code should ever modify the
 * contents of the session structure.  When the session code attempts
 * to modify the contents of a session structure it must hold multiple
 * locks.  The locking order for all the locks that may need to be
 * acquired is:
 * 	sd_lock -> pidlock -> p_splock -> s_lock
 *
 * If a caller requires access to a session structure for long
 * periods of time or across operations that may block it should
 * use the tty_hold() and sess_hold() interfaces.
 *
 * sess_hold() returns a pointer to a session structure associated
 * with the proc_t that was passed in.  It also increments the reference
 * count associated with that session structure to ensure that it
 * can't be freed until after the caller is done with it and calls
 * sess_rele().  This hold doesn't actually protect any of the
 * contents of the session structure.
 *
 * tty_hold() returns a pointer to a session structure associated
 * with the curproc.  It also "locks" the contents of the session
 * structure.  This hold should be used when the caller will be
 * doing operations on a controlling tty associated with the session.
 * This operation doesn an implicit sess_hold() so that the session
 * structure can't be free'd until after the caller is done with it
 * and invokes tty_rele().
 *
 * NOTE: Neither of these functions (sess_hold() or tty_hold())
 * prevent a process from changing its session.  Once these functions
 * return a session pointer, that session pointer may no longer be
 * associated with the current process.  If a caller wants to prevent
 * a process from changing its session then it must hold pidlock or
 * p_splock.
 */

typedef struct sess {
	struct pid *s_sidp;		/* session ID info, never changes */

	kmutex_t s_lock;		/* protects everything below */
	uint_t s_ref; 			/* reference count */
	boolean_t s_sighuped;		/* ctty had sighup sent to it */

	boolean_t s_exit;		/* sesion leader is exiting */
	kcondvar_t s_exit_cv;		/* Condvar for s_exit */

	int s_cnt;			/* active users of this ctty */
	kcondvar_t s_cnt_cv;		/* Condvar for s_cnt */

	/*
	 * The following fields can only be updated while s_lock is held
	 * and s_cnt is 0.  (ie, no one has a tty_hold() on this session.)
	 */
	dev_t s_dev;			/* tty's device number */
	struct vnode *s_vp;		/* tty's vnode */
	struct cred *s_cred;		/* allocation credentials */
} sess_t;

#define	s_sid s_sidp->pid_id

#if defined(_KERNEL)

extern sess_t session0;

/* forward referenced structure tags */
struct vnode;
struct proc;
struct stdata;

extern void sess_hold(proc_t *p);
extern void sess_rele(sess_t *, boolean_t);
extern sess_t *tty_hold(void);
extern void tty_rele(sess_t *sp);


extern void sess_create(void);
extern int strctty(struct stdata *);
extern int freectty(boolean_t);
extern dev_t cttydev(struct proc *);
extern void ctty_clear_sighuped(void);

#endif /* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SESSION_H */
