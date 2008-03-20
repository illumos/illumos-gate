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
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* from SVr4.0 1.15 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/debug.h>
#include <sys/class.h>
#include <sys/mutex.h>
#include <sys/schedctl.h>

/*
 * We support the nice system call for compatibility although
 * the priocntl system call supports a superset of nice's functionality.
 * We support nice only for time sharing threads.  It will fail
 * if called by a thread from another class.
 */

int
nice(int niceness)
{
	int error = 0;
	int err, retval;
	kthread_t *t;
	proc_t *p = curproc;

	mutex_enter(&p->p_lock);
	t = p->p_tlist;
	do {
		err = CL_DONICE(t, CRED(), niceness, &retval);
		schedctl_set_cidpri(t);
		if (error == 0 && err)
			error = set_errno(err);
	} while ((t = t->t_forw) != p->p_tlist);
	mutex_exit(&p->p_lock);
	if (error)
		return (error);
	return (retval);
}
