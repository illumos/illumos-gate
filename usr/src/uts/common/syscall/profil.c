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
 * Copyright (c) 1998, Sun Microsystems, Inc.
 * All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/debug.h>

/*
 * Profiling.
 */
int
profil(unsigned short *bufbase, size_t bufsize, ulong_t pcoffset,
    uint_t pcscale)
{
	struct proc *p = ttoproc(curthread);

	if (pcscale == 1)
		pcscale = 0;

	mutex_enter(&p->p_pflock);
	p->p_prof.pr_base = bufbase;
	p->p_prof.pr_size = bufsize;
	p->p_prof.pr_off = pcoffset;
	p->p_prof.pr_scale = pcscale;

	/* pcsample and profil are mutually exclusive */
	p->p_prof.pr_samples = 0;

	mutex_exit(&p->p_pflock);
	mutex_enter(&p->p_lock);
	set_proc_post_sys(p);	/* activate post_syscall profiling code */
	mutex_exit(&p->p_lock);
	return (0);
}


/*
 * PC Sampling
 */
long
pcsample(void *buf, long nsamples)
{
	struct proc *p = ttoproc(curthread);
	long count = 0;

	if (nsamples < 0 ||
	    ((get_udatamodel() != DATAMODEL_NATIVE) && (nsamples > INT32_MAX)))
		return (set_errno(EINVAL));

	mutex_enter(&p->p_pflock);
	p->p_prof.pr_base = buf;
	p->p_prof.pr_size = nsamples;
	p->p_prof.pr_scale = 1;
	count = p->p_prof.pr_samples;
	p->p_prof.pr_samples = 0;
	mutex_exit(&p->p_pflock);

	mutex_enter(&p->p_lock);
	set_proc_post_sys(p);	/* activate post_syscall profiling code */
	mutex_exit(&p->p_lock);

	return (count);
}
