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
 * Copyright 2015, Joyent, Inc. All rights reserved.
 */

#include <sys/errno.h>
#include <sys/exec.h>
#include <sys/file.h>
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
#include <sys/sunddi.h>

#include <sys/machbrand.h>
#include <sys/brand.h>
#include "sngl_brand.h"

char *sngl_emulation_table = NULL;

void	sngl_init_brand_data(zone_t *);
void	sngl_free_brand_data(zone_t *);
void	sngl_setbrand(proc_t *);
int	sngl_getattr(zone_t *, int, void *, size_t *);
int	sngl_setattr(zone_t *, int, void *, size_t);
int	sngl_brandsys(int, int64_t *, uintptr_t, uintptr_t, uintptr_t,
	uintptr_t, uintptr_t);
void	sngl_copy_procdata(proc_t *, proc_t *);
void	sngl_proc_exit(struct proc *, klwp_t *);
void	sngl_exec();
int	sngl_initlwp(klwp_t *);
void	sngl_forklwp(klwp_t *, klwp_t *);
void	sngl_freelwp(klwp_t *);
void	sngl_lwpexit(klwp_t *);
int	sngl_elfexec(vnode_t *, execa_t *, uarg_t *, intpdata_t *, int,
	long *, int, caddr_t, cred_t *, int);

/* SNGL brand */
struct brand_ops sngl_brops = {
	sngl_init_brand_data,
	sngl_free_brand_data,
	sngl_brandsys,
	sngl_setbrand,
	sngl_getattr,
	sngl_setattr,
	sngl_copy_procdata,
	sngl_proc_exit,
	sngl_exec,
	lwp_setrval,
	sngl_initlwp,
	sngl_forklwp,
	sngl_freelwp,
	sngl_lwpexit,
	sngl_elfexec,
	NULL,
	NULL,
	NULL,
	NSIG,
	NULL,
	NULL,
	NULL,
	NULL
};

#ifdef	__amd64

struct brand_mach_ops sngl_mops = {
	sngl_brand_sysenter_callback,
	sngl_brand_int91_callback,
	sngl_brand_syscall_callback,
	sngl_brand_syscall32_callback,
	NULL
};

#else	/* ! __amd64 */

struct brand_mach_ops sngl_mops = {
	sngl_brand_sysenter_callback,
	NULL,
	sngl_brand_syscall_callback,
	NULL,
	NULL
};
#endif	/* __amd64 */

struct brand	sngl_brand = {
	BRAND_VER_1,
	"sngl",
	&sngl_brops,
	&sngl_mops,
	sizeof (brand_proc_data_t),
};

static struct modlbrand modlbrand = {
	&mod_brandops,		/* type of module */
	"SNGL Brand",		/* description of module */
	&sngl_brand		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlbrand, NULL
};

void
sngl_setbrand(proc_t *p)
{
	brand_solaris_setbrand(p, &sngl_brand);
}

/*ARGSUSED*/
int
sngl_getattr(zone_t *zone, int attr, void *buf, size_t *bufsize)
{
	return (EINVAL);
}

/*ARGSUSED*/
int
sngl_setattr(zone_t *zone, int attr, void *buf, size_t bufsize)
{
	return (EINVAL);
}

/*ARGSUSED*/
int
sngl_brandsys(int cmd, int64_t *rval, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5)
{
	int	res;

	*rval = 0;
	res = brand_solaris_cmd(cmd, arg1, arg2, arg3, &sngl_brand,
	    SNGL_VERSION);
	if (res >= 0)
		return (res);

	return (EINVAL);
}

void
sngl_copy_procdata(proc_t *child, proc_t *parent)
{
	brand_solaris_copy_procdata(child, parent, &sngl_brand);
}

void
sngl_proc_exit(struct proc *p, klwp_t *l)
{
	brand_solaris_proc_exit(p, l, &sngl_brand);
}

void
sngl_exec()
{
	brand_solaris_exec(&sngl_brand);
}

int
sngl_initlwp(klwp_t *l)
{
	return (brand_solaris_initlwp(l, &sngl_brand));
}

void
sngl_forklwp(klwp_t *p, klwp_t *c)
{
	brand_solaris_forklwp(p, c, &sngl_brand);
}

void
sngl_freelwp(klwp_t *l)
{
	brand_solaris_freelwp(l, &sngl_brand);
}

void
sngl_lwpexit(klwp_t *l)
{
	brand_solaris_lwpexit(l, &sngl_brand);
}

void
sngl_free_brand_data(zone_t *zone)
{
}

void
sngl_init_brand_data(zone_t *zone)
{
}

int
sngl_elfexec(vnode_t *vp, execa_t *uap, uarg_t *args, intpdata_t *idatap,
	int level, long *execsz, int setid, caddr_t exec_file, cred_t *cred,
	int brand_action)
{
	return (brand_solaris_elfexec(vp, uap, args, idatap, level, execsz,
	    setid, exec_file, cred, brand_action, &sngl_brand, SNGL_BRANDNAME,
	    SNGL_LIB, SNGL_LIB32));
}

int
_init(void)
{
	int err;

	/*
	 * Set up the table to interpose on open.
	 */
	sngl_emulation_table = kmem_zalloc(NSYSCALL, KM_SLEEP);
	sngl_emulation_table[SYS_open] = 1;			/*   5 */

	err = mod_install(&modlinkage);
	if (err) {
		cmn_err(CE_WARN, "Couldn't install brand module");
		kmem_free(sngl_emulation_table, NSYSCALL);
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
	return (brand_solaris_fini(&sngl_emulation_table, &modlinkage,
	    &sngl_brand));
}
