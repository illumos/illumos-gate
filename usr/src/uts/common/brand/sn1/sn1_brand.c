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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#include <sys/pathname.h>

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
	sn1_elfexec,
	NULL,
	NULL,
	NSIG,
	NULL,
	NULL,
};

#ifdef	sparc

struct brand_mach_ops sn1_mops = {
	sn1_brand_syscall_callback,
	sn1_brand_syscall32_callback
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
	&sn1_mops,
	sizeof (brand_proc_data_t),
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
	brand_solaris_setbrand(p, &sn1_brand);
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

/*ARGSUSED*/
int
sn1_brandsys(int cmd, int64_t *rval, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6)
{
	int	res;

	*rval = 0;

	res = brand_solaris_cmd(cmd, arg1, arg2, arg3, &sn1_brand, SN1_VERSION);
	if (res >= 0)
		return (res);

	return (EINVAL);
}

void
sn1_copy_procdata(proc_t *child, proc_t *parent)
{
	brand_solaris_copy_procdata(child, parent, &sn1_brand);
}

void
sn1_proc_exit(struct proc *p, klwp_t *l)
{
	brand_solaris_proc_exit(p, l, &sn1_brand);
}

void
sn1_exec()
{
	brand_solaris_exec(&sn1_brand);
}

int
sn1_initlwp(klwp_t *l)
{
	return (brand_solaris_initlwp(l, &sn1_brand));
}

void
sn1_forklwp(klwp_t *p, klwp_t *c)
{
	brand_solaris_forklwp(p, c, &sn1_brand);
}

void
sn1_freelwp(klwp_t *l)
{
	brand_solaris_freelwp(l, &sn1_brand);
}

void
sn1_lwpexit(klwp_t *l)
{
	brand_solaris_lwpexit(l, &sn1_brand);
}

/*ARGSUSED*/
void
sn1_free_brand_data(zone_t *zone)
{
}

/*ARGSUSED*/
void
sn1_init_brand_data(zone_t *zone)
{
}

int
sn1_elfexec(vnode_t *vp, execa_t *uap, uarg_t *args, intpdata_t *idatap,
	int level, long *execsz, int setid, caddr_t exec_file, cred_t *cred,
	int brand_action)
{
	return (brand_solaris_elfexec(vp, uap, args, idatap, level, execsz,
	    setid, exec_file, cred, brand_action, &sn1_brand, SN1_BRANDNAME,
	    SN1_LIB, SN1_LIB32, SN1_LINKER, SN1_LINKER32));
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
	sn1_emulation_table[SYS_read] = 1;			/*   3 */
	sn1_emulation_table[SYS_write] = 1;			/*   4 */
	sn1_emulation_table[SYS_time] = 1;			/*  13 */
	sn1_emulation_table[SYS_getpid] = 1;			/*  20 */
	sn1_emulation_table[SYS_mount] = 1;			/*  21 */
	sn1_emulation_table[SYS_getuid] = 1;			/*  24 */
	sn1_emulation_table[SYS_times] = 1;			/*  43 */
	sn1_emulation_table[SYS_getgid] = 1;			/*  47 */
	sn1_emulation_table[SYS_utssys] = 1;			/*  57 */
	sn1_emulation_table[SYS_waitid] = 1;			/* 107 */
	sn1_emulation_table[SYS_uname] = 1;			/* 135 */

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
	return (brand_solaris_fini(&sn1_emulation_table, &modlinkage,
	    &sn1_brand));
}
