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
/*	  All Rights Reserved  	*/


/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/user.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/siginfo.h>
#include <sys/ucontext.h>
#include <sys/prsystm.h>
#include <sys/session.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/debug.h>

/*
 * Return 1 if process pointed to by 'cp' has a parent that would
 * prevent its process group from being orphaned, 0 otherwise
 */

static int
pglinked(cp)
	register proc_t *cp;
{
	register proc_t *pp;

	ASSERT(MUTEX_HELD(&pidlock));

	if ((pp = cp->p_parent) != NULL &&
	    pp->p_pgidp != cp->p_pgidp &&
	    pp->p_sessp == cp->p_sessp)
		return (1);
	return (0);
}

/*
 * Send the specified signal to all processes whose process group ID is
 * equal to 'pgid'
 */

void
pgsignal(pidp, sig)
	register struct pid *pidp;
	int sig;
{
	register proc_t *prp;

	mutex_enter(&pidlock);
	for (prp = pidp->pid_pglink; prp; prp = prp->p_pglink) {
		mutex_enter(&prp->p_lock);
		sigtoproc(prp, NULL, sig);
		mutex_exit(&prp->p_lock);
	}
	mutex_exit(&pidlock);
}

/*
 * similiar to pgsignal in function except that pidlock mutex is assumed
 * to be held by the caller.
 */
void
sigtopg(pidp, sig)
	register struct pid *pidp;
	int sig;
{
	register proc_t *prp;

	ASSERT(MUTEX_HELD(&pidlock));

	for (prp = pidp->pid_pglink; prp; prp = prp->p_pglink) {
		mutex_enter(&prp->p_lock);
		sigtoproc(prp, NULL, sig);
		mutex_exit(&prp->p_lock);
	}
}

/*
 * Add a process to a process group
 */

void
pgjoin(p, pgp)
	register proc_t *p;
	register struct pid *pgp;
{
	ASSERT(MUTEX_HELD(&pidlock));

	p->p_pgidp = pgp;

	if (pgp->pid_pglink == NULL) {
		ASSERT(pgp->pid_pgtail == NULL);
		p->p_ppglink = NULL;
		p->p_pglink = NULL;
		pgp->pid_pglink = p;
		pgp->pid_pgtail = p;
	} else 	{
		ASSERT(pgp->pid_pgtail != NULL);
		if (pglinked(p)) {
			p->p_ppglink = NULL;
			p->p_pglink = pgp->pid_pglink;
			pgp->pid_pglink->p_ppglink = p;
			pgp->pid_pglink = p;
		} else {
			p->p_ppglink = pgp->pid_pgtail;
			p->p_pglink = NULL;
			pgp->pid_pgtail->p_pglink = p;
			pgp->pid_pgtail = p;
		}
	}

	if (pgp->pid_pglink == pgp->pid_pgtail) {
		PID_HOLD(pgp);
		if (pglinked(p))
			pgp->pid_pgorphaned = 0;
		else
			pgp->pid_pgorphaned = 1;
	} else if (pgp->pid_pgorphaned && pglinked(p))
		pgp->pid_pgorphaned = 0;
}

void
pgexit(prp)
	proc_t *prp;
{
	register proc_t *p;
	register struct pid *pgp;

	ASSERT(MUTEX_HELD(&pidlock));

	pgp = prp->p_pgidp;

	if (pgp->pid_pglink == prp) {
		ASSERT(prp->p_ppglink == NULL); /* must be at the front */
		pgp->pid_pglink = prp->p_pglink;
	}
	if (prp->p_ppglink) {
		prp->p_ppglink->p_pglink = prp->p_pglink;
	}
	if (prp->p_pglink) {
		prp->p_pglink->p_ppglink = prp->p_ppglink;
	}
	if (pgp->pid_pgtail == prp) {
		pgp->pid_pgtail = prp->p_ppglink;
	}

	prp->p_pgidp = NULL;
	prp->p_pglink = NULL;
	prp->p_ppglink = NULL;

	if ((p = pgp->pid_pglink) == NULL) {
		PID_RELE(pgp);
	} else if (pgp->pid_pgorphaned == 0) {
		do {
			if (pglinked(p)) {
				return;
			}
		} while ((p = p->p_pglink) != NULL);
		pgp->pid_pgorphaned = 1;
	}
}

/*
 * process 'pp' is exiting - check to see if this will
 * orphan its children's process groups
 */

void
pgdetach(pp)
	proc_t *pp;
{
	int stopped;
	register proc_t *cp;
	register proc_t *mp;
	register struct pid *pgp;

	ASSERT(MUTEX_HELD(&pidlock));

	for (cp = pp->p_child; cp; cp = cp->p_sibling) {
		if ((pgp = cp->p_pgidp)->pid_pgorphaned)
			continue;
		stopped = 0;
		mp = pgp->pid_pglink;
		ASSERT(mp != NULL);
		for (;;) {
			if (mp != pp && mp->p_parent != pp && pglinked(mp))
				break;
			if (!stopped && mp != curproc) {
				mutex_enter(&mp->p_lock);
				stopped = jobstopped(mp);
				mutex_exit(&mp->p_lock);
			}
			if ((mp = mp->p_pglink) == NULL) {
				pgp->pid_pgorphaned = 1;
				if (stopped) {
					sigtopg(pgp, SIGHUP);
					sigtopg(pgp, SIGCONT);
				}
				break;
			}
		}
	}
}

/*
 * Return 1 if pgid is the process group ID of an existing process group
 *	that has members not the process group leader in it.
 *
 * Otherwise, return 0.
 */

int
pgmembers(pgid)
	register pid_t pgid;
{
	register proc_t *prp;

	ASSERT(MUTEX_HELD(&pidlock));

	for (prp = pgfind(pgid); prp; prp = prp->p_pglink)
		if (prp->p_pid != pgid) {
			return (1);
		}
	return (0);
}
