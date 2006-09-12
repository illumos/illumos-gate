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
/*	  All Rights Reserved	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* from SVr4.0 1.78 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/session.h>
#include <sys/debug.h>

/* ARGSUSED */
int
setpgrp(int flag, int pid, int pgid)
{
	proc_t	*p = curproc;
	int	retval = 0;
	int	sid;

	switch (flag) {

	case 1: /* setpgrp() */
		mutex_enter(&pidlock);
		if (p->p_sessp->s_sidp != p->p_pidp && !pgmembers(p->p_pid)) {
			mutex_exit(&pidlock);
			sess_create();
		} else
			mutex_exit(&pidlock);
		mutex_enter(&p->p_splock);
		sid = p->p_sessp->s_sid;
		mutex_exit(&p->p_splock);
		return (sid);

	case 3: /* setsid() */
		mutex_enter(&pidlock);
		if (p->p_pgidp == p->p_pidp || pgmembers(p->p_pid)) {
			mutex_exit(&pidlock);
			return (set_errno(EPERM));
		}
		mutex_exit(&pidlock);
		sess_create();
		mutex_enter(&p->p_splock);
		sid = p->p_sessp->s_sid;
		mutex_exit(&p->p_splock);
		return (sid);

	case 5: /* setpgid() */
	{
		mutex_enter(&pidlock);
		if (pid == 0)
			pid = p->p_pid;
		else if (pid < 0 || pid >= maxpid) {
			mutex_exit(&pidlock);
			return (set_errno(EINVAL));
		} else if (pid != p->p_pid) {
			for (p = p->p_child; /* empty */; p = p->p_sibling) {
				if (p == NULL) {
					mutex_exit(&pidlock);
					return (set_errno(ESRCH));
				}
				if (p->p_pid == pid)
					break;
			}
			if (p->p_flag & SEXECED) {
				mutex_exit(&pidlock);
				return (set_errno(EACCES));
			}
			if (p->p_sessp != ttoproc(curthread)->p_sessp) {
				mutex_exit(&pidlock);
				return (set_errno(EPERM));
			}
		}

		if (p->p_sessp->s_sid == pid) {
			mutex_exit(&pidlock);
			return (set_errno(EPERM));
		}

		if (pgid == 0)
			pgid = p->p_pid;
		else if (pgid < 0 || pgid >= maxpid) {
			mutex_exit(&pidlock);
			return (set_errno(EINVAL));
		}

		if (p->p_pgrp == pgid) {
			mutex_exit(&pidlock);
			break;
		} else if (p->p_pid == pgid) {
			/*
			 * We need to protect p_pgidp with p_lock because
			 * /proc looks at it while holding only p_lock.
			 */
			mutex_enter(&p->p_lock);
			pgexit(p);
			pgjoin(p, p->p_pidp);
			mutex_exit(&p->p_lock);
		} else {
			register proc_t *q;

			if ((q = pgfind(pgid)) == NULL ||
			    q->p_sessp != p->p_sessp) {
				mutex_exit(&pidlock);
				return (set_errno(EPERM));
			}
			/*
			 * See comment above about p_lock and /proc
			 */
			mutex_enter(&p->p_lock);
			pgexit(p);
			pgjoin(p, q->p_pgidp);
			mutex_exit(&p->p_lock);
		}
		mutex_exit(&pidlock);
		break;
	}

	case 0: /* getpgrp() */
		mutex_enter(&pidlock);
		retval = p->p_pgrp;
		mutex_exit(&pidlock);
		break;

	case 2: /* getsid() */
	case 4: /* getpgid() */
		if (pid < 0 || pid >= maxpid) {
			return (set_errno(EINVAL));
		}
		mutex_enter(&pidlock);
		if (pid != 0 && p->p_pid != pid &&
		    ((p = prfind(pid)) == NULL || p->p_stat == SIDL)) {
			mutex_exit(&pidlock);
			return (set_errno(ESRCH));
		}
		if (flag == 2)
			retval = p->p_sessp->s_sid;
		else
			retval = p->p_pgrp;
		mutex_exit(&pidlock);
		break;

	}
	return (retval);
}
