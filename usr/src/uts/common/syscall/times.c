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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/tuneable.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/debug.h>
#include <sys/msacct.h>

/*
 * Return system and user times.
 */

clock_t
times(struct tms *tp)
{
	proc_t *p = ttoproc(curthread);
	struct tms	p_time;
	clock_t ret_lbolt;

	mutex_enter(&p->p_lock);
	p_time.tms_utime = (clock_t)NSEC_TO_TICK(
	    mstate_aggr_state(p, LMS_USER));
	p_time.tms_stime = (clock_t)NSEC_TO_TICK(
	    mstate_aggr_state(p, LMS_SYSTEM));
	p_time.tms_cutime = p->p_cutime;
	p_time.tms_cstime = p->p_cstime;
	mutex_exit(&p->p_lock);

	if (copyout(&p_time, tp, sizeof (p_time)))
		return (set_errno(EFAULT));

	ret_lbolt = ddi_get_lbolt();

	return (ret_lbolt == -1 ? 0 : ret_lbolt);
}

#ifdef _SYSCALL32_IMPL

/*
 * We deliberately -don't- return EOVERFLOW on type overflow,
 * since the 32-bit kernel simply wraps 'em around.
 */
clock32_t
times32(struct tms32 *tp)
{
	proc_t	*p = ttoproc(curthread);
	struct tms32	p_time;
	clock32_t	ret_lbolt;

	mutex_enter(&p->p_lock);
	p_time.tms_utime = (clock32_t)NSEC_TO_TICK(
	    mstate_aggr_state(p, LMS_USER));
	p_time.tms_stime = (clock32_t)NSEC_TO_TICK(
	    mstate_aggr_state(p, LMS_SYSTEM));
	p_time.tms_cutime = (clock32_t)p->p_cutime;
	p_time.tms_cstime = (clock32_t)p->p_cstime;
	mutex_exit(&p->p_lock);

	if (copyout(&p_time, tp, sizeof (p_time)))
		return (set_errno(EFAULT));

	ret_lbolt = (clock32_t)ddi_get_lbolt();

	return (ret_lbolt == (clock32_t)-1 ? 0 : ret_lbolt);
}

#endif	/* _SYSCALL32_IMPL */
