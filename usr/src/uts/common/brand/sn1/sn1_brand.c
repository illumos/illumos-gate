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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/errno.h>
#include <sys/exec.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/model.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/cmn_err.h>
#include <sys/archsystm.h>

#include <sys/machbrand.h>
#include <sys/brand.h>
#include "sn1_brand.h"

char *sn1_emulation_table = NULL;

void	sn1_init_brand_data(zone_t *);
void	sn1_free_brand_data(zone_t *);
void	sn1_setbrand(proc_t *);
int	sn1_getattr(zone_t *, int, void *, size_t *);
int	sn1_setattr(zone_t *, int, void *, size_t);
int	sn1_brandsys(int, int64_t *, uintptr_t, uintptr_t, uintptr_t,
		uintptr_t, uintptr_t, uintptr_t);
void	sn1_copy_procdata(proc_t *, proc_t *);
void	sn1_proc_exit(struct proc *, klwp_t *);
void	sn1_exec();
int	sn1_initlwp(klwp_t *);
void	sn1_forklwp(klwp_t *, klwp_t *);
void	sn1_freelwp(klwp_t *);
void	sn1_lwpexit(klwp_t *);
int	sn1_elfexec(vnode_t *, execa_t *, uarg_t *, intpdata_t *, int,
	long *, int, caddr_t, cred_t *, int);

/* sn1 brand */
struct brand_ops sn1_brops = {
	sn1_init_brand_data,
	sn1_free_brand_data,
	sn1_brandsys,
	sn1_setbrand,
	sn1_getattr,
	sn1_setattr,
	sn1_copy_procdata,
	sn1_proc_exit,
	sn1_exec,
	lwp_setrval,
	sn1_initlwp,
	sn1_forklwp,
	sn1_freelwp,
	sn1_lwpexit,
	sn1_elfexec
};

#ifdef	sparc

struct brand_mach_ops sn1_mops = {
	sn1_brand_syscall_callback,
	sn1_brand_syscall_callback
};

#else	/* sparc */

#ifdef	__amd64

struct brand_mach_ops sn1_mops = {
	sn1_brand_sysenter_callback,
	NULL,
	sn1_brand_int91_callback,
	sn1_brand_syscall_callback,
	sn1_brand_syscall32_callback,
	NULL
};

#else	/* ! __amd64 */

struct brand_mach_ops sn1_mops = {
	sn1_brand_sysenter_callback,
	NULL,
	NULL,
	sn1_brand_syscall_callback,
	NULL,
	NULL
};
#endif	/* __amd64 */

#endif	/* _sparc */

struct brand	sn1_brand = {
	BRAND_VER_1,
	"sn1",
	&sn1_brops,
	&sn1_mops
};

static struct modlbrand modlbrand = {
	&mod_brandops,		/* type of module */
	"Solaris N-1 Brand",	/* description of module */
	&sn1_brand		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlbrand, NULL
};

void
sn1_setbrand(proc_t *p)
{
	ASSERT(p->p_brand == &sn1_brand);
	ASSERT(p->p_brand_data == NULL);
	p->p_brand_data = NULL;

	/*
	 * We should only be called from exec(), when we know the process
	 * is single-threaded.
	 */
	ASSERT(p->p_tlist == p->p_tlist->t_forw);
	(void) sn1_initlwp(p->p_tlist->t_lwp);
}

/* ARGSUSED */
int
sn1_getattr(zone_t *zone, int attr, void *buf, size_t *bufsize)
{
	return (EINVAL);
}

/* ARGSUSED */
int
sn1_setattr(zone_t *zone, int attr, void *buf, size_t bufsize)
{
	return (EINVAL);
}

/*
 * Get the address of the user-space system call handler from the user
 * process and attach it to the proc structure.
 */
/*ARGSUSED*/
int
sn1_brandsys(int cmd, int64_t *rval, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6)
{
	proc_t *p = curproc;
	*rval = 0;

	/*
	 * There is one operation that is suppored for non-branded
	 * process.  B_EXEC_BRAND.  This brand operaion is redundant
	 * since the kernel assumes a native process doing an exec
	 * in a branded zone is going to run a branded processes.
	 * hence we don't support this operation.
	 */
	if (cmd == B_EXEC_BRAND)
		return (ENOSYS);

	/* For all other operations this must be a branded process. */
	if (p->p_brand == &native_brand)
		return (ENOSYS);

	ASSERT(p->p_brand == &sn1_brand);

	if (cmd == B_REGISTER) {
		ASSERT(p->p_brand_data == NULL);
		p->p_brand_data = (void *)arg1;
		return (0);
	}

	return (EINVAL);
}

/*
 * Copy the per-process brand data from a parent proc to a child.  In the
 * sn1 brand, the only per-process state is the address of the user-space
 * handler.
 */
void
sn1_copy_procdata(proc_t *child, proc_t *parent)
{
	ASSERT(parent->p_brand == &sn1_brand);
	ASSERT(child->p_brand == &sn1_brand);

	child->p_brand_data = NULL;
}

/*ARGSUSED*/
void
sn1_proc_exit(struct proc *p, klwp_t *l)
{
	ASSERT(p->p_brand == &sn1_brand);

	/*
	 * We should only be called from proc_exit(), when we know that
	 * process is single-threaded.
	 */
	ASSERT(p->p_tlist == p->p_tlist->t_forw);

	p->p_brand_data = NULL;
	l->lwp_brand = NULL;
}

void
sn1_exec()
{
	ASSERT(curproc->p_brand == &sn1_brand);
	ASSERT(ttolwp(curthread)->lwp_brand != NULL);

	/*
	 * We should only be called from exec(), when we know the process
	 * is single-threaded.
	 */
	ASSERT(curproc->p_tlist == curproc->p_tlist->t_forw);

	/* upon exec, reset our user-land handler callback entry point */
	curproc->p_brand_data = NULL;
}

/*ARGSUSED*/
int
sn1_initlwp(klwp_t *l)
{
	ASSERT(l->lwp_procp->p_brand == &sn1_brand);
	ASSERT(l->lwp_brand == NULL);
	l->lwp_brand = (void *)-1;
	return (0);
}

/*ARGSUSED*/
void
sn1_forklwp(klwp_t *p, klwp_t *c)
{
	ASSERT(p->lwp_procp->p_brand == &sn1_brand);
	ASSERT(c->lwp_procp->p_brand == &sn1_brand);

	/* Both LWPs have already had been initialized via sn1_initlwp() */
	ASSERT(p->lwp_brand != NULL);
	ASSERT(c->lwp_brand != NULL);
}

/*ARGSUSED*/
void
sn1_freelwp(klwp_t *l)
{
	/* This lwp died during birth */
	ASSERT(l->lwp_procp->p_brand == &sn1_brand);
	ASSERT(l->lwp_brand != NULL);
	l->lwp_brand = NULL;
}

/*ARGSUSED*/
void
sn1_lwpexit(klwp_t *l)
{
	proc_t	*p = l->lwp_procp;

	ASSERT(l->lwp_procp->p_brand == &sn1_brand);
	ASSERT(l->lwp_brand != NULL);

	/*
	 * We should never be called for the last thread in a process.
	 * (That case is handled by sn1_proc_exit().)  There for this lwp
	 * must be exiting from a multi-threaded process.
	 */
	ASSERT(p->p_tlist != p->p_tlist->t_forw);

	l->lwp_brand = NULL;
}

/*ARGSUSED*/
void
sn1_init_brand_data(zone_t *zone)
{
}

/*ARGSUSED*/
void
sn1_free_brand_data(zone_t *zone)
{
}

int
sn1_elfexec(vnode_t *vp, execa_t *uap, uarg_t *args, intpdata_t *idatap,
	int level, long *execsz, int setid, caddr_t exec_file, cred_t *cred,
	int brand_action)
{
	args->brandname = "sn1";
	return ((args->execswp->exec_func)(vp, uap, args, idatap, level + 1,
	    execsz, setid, exec_file, cred, brand_action));
}


int
_init(void)
{
	int err;

	/*
	 * Set up the table indicating which system calls we want to
	 * interpose on.  We should probably build this automatically from
	 * a list of system calls that is shared with the user-space
	 * library.
	 */
	sn1_emulation_table = kmem_zalloc(NSYSCALL, KM_SLEEP);
	sn1_emulation_table[SYS_uname] = 1;

	err = mod_install(&modlinkage);
	if (err) {
		cmn_err(CE_WARN, "Couldn't install brand module");
		kmem_free(sn1_emulation_table, NSYSCALL);
	}

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int err;

	/*
	 * If there are any zones using this brand, we can't allow it to be
	 * unloaded.
	 */
	if (brand_zone_count(&sn1_brand))
		return (EBUSY);

	kmem_free(sn1_emulation_table, NSYSCALL);
	sn1_emulation_table = NULL;

	err = mod_remove(&modlinkage);
	if (err)
		cmn_err(CE_WARN, "Couldn't unload sn1 brand module");

	return (err);
}
