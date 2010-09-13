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
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/thread.h>
#include <sys/disp.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>


/*
 * The calling LWP is preempted in favor of some other LWP.
 */
int
yield()
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);

	thread_lock(t);
	lwp->lwp_ru.nvcsw++;
	THREAD_TRANSITION(t);
	CL_YIELD(t);		/* does setbackdq */
	thread_unlock_nopreempt(t);
	swtch();		/* clears cpu_runrun and cpu_kprunrun */

	return (0);
}
