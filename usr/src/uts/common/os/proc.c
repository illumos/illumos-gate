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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#include <sys/proc.h>
#include <sys/cpuvar.h>
#include <sys/disp.h>

/*
 * Install process context ops for the current process.
 */
void
installpctx(
	proc_t *p,
	void	*arg,
	void	(*save)(void *),
	void	(*restore)(void *),
	void	(*fork)(void *, void *),
	void	(*exit)(void *),
	void	(*free)(void *, int))
{
	struct pctxop *pctx;

	pctx = kmem_alloc(sizeof (struct pctxop), KM_SLEEP);
	pctx->save_op = save;
	pctx->restore_op = restore;
	pctx->fork_op = fork;
	pctx->exit_op = exit;
	pctx->free_op = free;
	pctx->arg = arg;
	pctx->next = p->p_pctx;
	p->p_pctx = pctx;
}

/*
 * Remove a process context ops from the current process.
 */
int
removepctx(
	proc_t *p,
	void	*arg,
	void	(*save)(void *),
	void	(*restore)(void *),
	void	(*fork)(void *, void *),
	void	(*exit)(void *),
	void	(*free)(void *, int))
{
	struct pctxop *pctx, *prev_pctx;

	prev_pctx = NULL;
	kpreempt_disable();
	for (pctx = p->p_pctx; pctx != NULL; pctx = pctx->next) {
		if (pctx->save_op == save && pctx->restore_op == restore &&
		    pctx->fork_op == fork &&
		    pctx->exit_op == exit && pctx->free_op == free &&
		    pctx->arg == arg) {
			if (prev_pctx)
				prev_pctx->next = pctx->next;
			else
				p->p_pctx = pctx->next;
			if (pctx->free_op != NULL)
				(pctx->free_op)(pctx->arg, 0);
			kmem_free(pctx, sizeof (struct pctxop));
			kpreempt_enable();
			return (1);
		}
		prev_pctx = pctx;
	}
	kpreempt_enable();
	return (0);
}

void
savepctx(proc_t *p)
{
	struct pctxop *pctx;

	ASSERT(p == curthread->t_procp);
	for (pctx = p->p_pctx; pctx != 0; pctx = pctx->next)
		if (pctx->save_op != NULL)
			(pctx->save_op)(pctx->arg);
}

void
restorepctx(proc_t *p)
{
	struct pctxop *pctx;

	ASSERT(p == curthread->t_procp);
	for (pctx = p->p_pctx; pctx != 0; pctx = pctx->next)
		if (pctx->restore_op != NULL)
			(pctx->restore_op)(pctx->arg);
}

void
forkpctx(proc_t *p, proc_t *cp)
{
	struct pctxop *pctx;

	for (pctx = p->p_pctx; pctx != NULL; pctx = pctx->next)
		if (pctx->fork_op != NULL)
			(pctx->fork_op)(p, cp);
}

/*
 * exitpctx is called during thread/lwp exit to perform any actions
 * needed when an LWP in the process leaves the processor for the last
 * time. This routine is not intended to deal with freeing memory; freepctx()
 * is used for that purpose during proc_exit(). This routine is provided to
 * allow for clean-up that can't wait until thread_free().
 */
void
exitpctx(proc_t *p)
{
	struct pctxop *pctx;

	for (pctx = p->p_pctx; pctx != NULL; pctx = pctx->next)
		if (pctx->exit_op != NULL)
			(pctx->exit_op)(p);
}

/*
 * freepctx is called from proc_exit() to get rid of the actual context ops.
 */
void
freepctx(proc_t *p, int isexec)
{
	struct pctxop *pctx;

	kpreempt_disable();
	while ((pctx = p->p_pctx) != NULL) {
		p->p_pctx = pctx->next;
		if (pctx->free_op != NULL)
			(pctx->free_op)(pctx->arg, isexec);
		kmem_free(pctx, sizeof (struct pctxop));
	}
	kpreempt_enable();
}

boolean_t
secflag_enabled(proc_t *p, secflag_t flag)
{
	return (secflag_isset(p->p_secflags.psf_effective, flag));
}

void
secflags_promote(proc_t *p)
{
	secflags_copy(&p->p_secflags.psf_effective, &p->p_secflags.psf_inherit);
}
