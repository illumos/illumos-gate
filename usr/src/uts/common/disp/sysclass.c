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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/pcb.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/sysinfo.h>
#include <sys/var.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/proc.h>
#include <sys/debug.h>
#include <sys/inline.h>
#include <sys/disp.h>
#include <sys/class.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/priocntl.h>

/*
 * Class specific code for the sys class. There are no
 * class specific data structures associated with
 * the sys class and the scheduling policy is trivially
 * simple. There is no time slicing.
 */

pri_t		sys_init(id_t, int, classfuncs_t **);
static int	sys_getclpri(pcpri_t *);
static int	sys_fork(kthread_t *, kthread_t *, void *);
static int	sys_enterclass(kthread_t *, id_t, void *, cred_t *, void *);
static int	sys_canexit(kthread_t *, cred_t *);
static int	sys_nosys();
static int	sys_donice(kthread_t *, cred_t *, int, int *);
static int	sys_doprio(kthread_t *, cred_t *, int, int *);
static void	sys_forkret(kthread_t *, kthread_t *);
static void	sys_nullsys();
static pri_t	sys_swappri(kthread_t *, int);
static pri_t	sys_globpri(kthread_t *);
static int	sys_alloc(void **, int);

struct classfuncs sys_classfuncs = {
	/* messages to class manager */
	{
		sys_nosys,	/* admin */
		sys_nosys,	/* getclinfo */
		sys_nosys,	/* parmsin */
		sys_nosys,	/* parmsout */
		sys_nosys,	/* vaparmsin */
		sys_nosys,	/* vaparmsout */
		sys_getclpri,	/* getclpri */
		sys_alloc,
		sys_nullsys,	/* free */
	},
	/* operations on threads */
	{
		sys_enterclass,	/* enterclass */
		sys_nullsys,	/* exitclass */
		sys_canexit,
		sys_fork,
		sys_forkret,	/* forkret */
		sys_nullsys,	/* parmsget */
		sys_nosys,	/* parmsset */
		sys_nullsys,	/* stop */
		sys_nullsys,	/* exit */
		sys_nullsys,	/* active */
		sys_nullsys,	/* inactive */
		sys_swappri,	/* swapin */
		sys_swappri,	/* swapout */
		sys_nullsys,	/* trapret */
		setfrontdq,	/* preempt */
		setbackdq,	/* setrun */
		sys_nullsys,	/* sleep */
		sys_nullsys,	/* tick */
		setbackdq,	/* wakeup */
		sys_donice,
		sys_globpri,	/* globpri */
		sys_nullsys,	/* set_process_group */
		sys_nullsys,	/* yield */
		sys_doprio,
	}

};


/* ARGSUSED */
pri_t
sys_init(cid, clparmsz, clfuncspp)
	id_t		cid;
	int		clparmsz;
	classfuncs_t	**clfuncspp;
{
	*clfuncspp = &sys_classfuncs;
	return ((pri_t)v.v_maxsyspri);
}

/*
 * Get maximum and minimum priorities enjoyed by sysclass threads
 */
static int
sys_getclpri(pcpri_t *pcprip)
{
	pcprip->pc_clpmax = maxclsyspri;
	pcprip->pc_clpmin = minclsyspri;
	return (0);
}

/* ARGSUSED */
static int
sys_enterclass(t, cid, parmsp, reqpcredp, bufp)
	kthread_t	*t;
	id_t		cid;
	void		*parmsp;
	cred_t		*reqpcredp;
	void		*bufp;
{
	return (0);
}

/* ARGSUSED */
static int
sys_canexit(kthread_t *t, cred_t *reqpcredp)
{
	return (0);
}

/* ARGSUSED */
static int
sys_fork(t, ct, bufp)
	kthread_t *t;
	kthread_t *ct;
	void	*bufp;
{
	/*
	 * No class specific data structure
	 */
	return (0);
}


/* ARGSUSED */
static void
sys_forkret(t, ct)
	kthread_t *t;
	kthread_t *ct;
{
	register proc_t *pp = ttoproc(t);
	register proc_t *cp = ttoproc(ct);

	ASSERT(t == curthread);
	ASSERT(MUTEX_HELD(&pidlock));

	/*
	 * Grab the child's p_lock before dropping pidlock to ensure
	 * the process does not disappear before we set it running.
	 */
	mutex_enter(&cp->p_lock);
	mutex_exit(&pidlock);
	continuelwps(cp);
	mutex_exit(&cp->p_lock);

	mutex_enter(&pp->p_lock);
	continuelwps(pp);
	mutex_exit(&pp->p_lock);
}

/* ARGSUSED */
static pri_t
sys_swappri(t, flags)
	kthread_t	*t;
	int		flags;
{
	return (-1);
}

/* ARGSUSED */
static pri_t
sys_globpri(kthread_t *t __unused)
{
	return (-1);
}

static int
sys_nosys()
{
	return (ENOSYS);
}


static void
sys_nullsys()
{
}

/* ARGSUSED */
static int
sys_donice(kthread_t *t, cred_t *cr, int incr, int *retvalp)
{
	return (EINVAL);
}

/* ARGSUSED */
static int
sys_doprio(kthread_t *t, cred_t *cr, int incr, int *retvalp)
{
	return (EINVAL);
}

/* ARGSUSED */
static int
sys_alloc(void **p, int flag)
{
	*p = NULL;
	return (0);
}
