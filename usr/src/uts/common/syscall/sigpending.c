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
 * Copyright 1994-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/fault.h>
#include <sys/signal.h>
#include <sys/schedctl.h>
#include <sys/debug.h>

int
sigpending(int flag, sigset_t *setp)
{
	sigset_t set;
	k_sigset_t kset;
	proc_t *p;

	switch (flag) {
	case 1: /* sigpending */
		p = ttoproc(curthread);
		mutex_enter(&p->p_lock);
		schedctl_finish_sigblock(curthread);
		kset = p->p_sig;
		sigorset(&kset, &curthread->t_sig);
		sigandset(&kset, &curthread->t_hold);
		mutex_exit(&p->p_lock);
		break;
	case 2: /* sigfillset */
		kset = fillset;
		break;
	default:
		return (set_errno(EINVAL));
	}

	sigktou(&kset, &set);
	if (copyout((caddr_t)&set, (caddr_t)setp, sizeof (sigset_t)))
		return (set_errno(EFAULT));
	return (0);
}
