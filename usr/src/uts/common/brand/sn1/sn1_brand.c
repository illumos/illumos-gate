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
	sn1_elfexec
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

	/*
	 * We should only be called from exec(), when we know the process
	 * is single-threaded.
	 */
	ASSERT(p->p_tlist == p->p_tlist->t_forw);

	p->p_brand_data = kmem_zalloc(sizeof (sn1_proc_data_t), KM_SLEEP);
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
	sn1_proc_data_t	*spd;
	sn1_brand_reg_t	reg;
	proc_t		*p = curproc;
	int		err;

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
	ASSERT(p->p_brand_data != NULL);

	spd = (sn1_proc_data_t *)p->p_brand_data;

	switch (cmd) {
	case B_EXEC_NATIVE:
		err = exec_common(
		    (char *)arg1, (const char **)arg2, (const char **)arg3,
		    EBA_NATIVE);
		return (err);

	case B_REGISTER:
		if (p->p_model == DATAMODEL_NATIVE) {
			if (copyin((void *)arg1, &reg, sizeof (reg)) != 0)
				return (EFAULT);
#if defined(_LP64)
		} else {
			sn1_brand_reg32_t reg32;

			if (copyin((void *)arg1, &reg32, sizeof (reg32)) != 0)
				return (EFAULT);
			reg.sbr_version = reg32.sbr_version;
			reg.sbr_handler = (caddr_t)(uintptr_t)reg32.sbr_handler;
#endif /* _LP64 */
		}

		if (reg.sbr_version != SN1_VERSION)
			return (ENOTSUP);
		spd->spd_handler = reg.sbr_handler;
		return (0);
	case B_ELFDATA:
		if (p->p_model == DATAMODEL_NATIVE) {
			if (copyout(&spd->spd_elf_data, (void *)arg1,
			    sizeof (sn1_elf_data_t)) != 0)
				return (EFAULT);
#if defined(_LP64)
		} else {
			sn1_elf_data32_t sed32;

			sed32.sed_phdr = spd->spd_elf_data.sed_phdr;
			sed32.sed_phent = spd->spd_elf_data.sed_phent;
			sed32.sed_phnum = spd->spd_elf_data.sed_phnum;
			sed32.sed_entry = spd->spd_elf_data.sed_entry;
			sed32.sed_base = spd->spd_elf_data.sed_base;
			sed32.sed_ldentry = spd->spd_elf_data.sed_ldentry;
			sed32.sed_lddata = spd->spd_elf_data.sed_lddata;
			if (copyout(&sed32, (void *)arg1, sizeof (sed32)) != 0)
				return (EFAULT);
#endif /* _LP64 */
		}
		return (0);
	}

	return (EINVAL);
}

/*
 * Copy the per-process brand data from a parent proc to a child.
 */
void
sn1_copy_procdata(proc_t *child, proc_t *parent)
{
	sn1_proc_data_t	*spd;

	ASSERT(parent->p_brand == &sn1_brand);
	ASSERT(child->p_brand == &sn1_brand);
	ASSERT(parent->p_brand_data != NULL);
	ASSERT(child->p_brand_data == NULL);

	/* Just duplicate all the proc data of the parent for the child */
	spd = kmem_alloc(sizeof (sn1_proc_data_t), KM_SLEEP);
	bcopy(parent->p_brand_data, spd, sizeof (sn1_proc_data_t));
	child->p_brand_data = spd;
}

/*ARGSUSED*/
void
sn1_proc_exit(struct proc *p, klwp_t *l)
{
	ASSERT(p->p_brand == &sn1_brand);
	ASSERT(p->p_brand_data != NULL);

	/*
	 * We should only be called from proc_exit(), when we know that
	 * process is single-threaded.
	 */
	ASSERT(p->p_tlist == p->p_tlist->t_forw);

	/* upon exit, free our lwp brand data */
	(void) sn1_freelwp(ttolwp(curthread));

	/* upon exit, free our proc brand data */
	kmem_free(p->p_brand_data, sizeof (sn1_proc_data_t));
	p->p_brand_data = NULL;
}

void
sn1_exec()
{
	sn1_proc_data_t	*spd = curproc->p_brand_data;

	ASSERT(curproc->p_brand == &sn1_brand);
	ASSERT(curproc->p_brand_data != NULL);
	ASSERT(ttolwp(curthread)->lwp_brand != NULL);

	/*
	 * We should only be called from exec(), when we know the process
	 * is single-threaded.
	 */
	ASSERT(curproc->p_tlist == curproc->p_tlist->t_forw);

	/* Upon exec, reset our lwp brand data. */
	(void) sn1_freelwp(ttolwp(curthread));
	(void) sn1_initlwp(ttolwp(curthread));

	/*
	 * Upon exec, reset all the proc brand data, except for the elf
	 * data associated with the executable we are exec'ing.
	 */
	spd->spd_handler = NULL;
}

/*ARGSUSED*/
int
sn1_initlwp(klwp_t *l)
{
	ASSERT(l->lwp_procp->p_brand == &sn1_brand);
	ASSERT(l->lwp_procp->p_brand_data != NULL);
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

	ASSERT(p->lwp_procp->p_brand_data != NULL);
	ASSERT(c->lwp_procp->p_brand_data != NULL);

	/* Both LWPs have already had been initialized via sn1_initlwp() */
	ASSERT(p->lwp_brand != NULL);
	ASSERT(c->lwp_brand != NULL);
}

/*ARGSUSED*/
void
sn1_freelwp(klwp_t *l)
{
	ASSERT(l->lwp_procp->p_brand == &sn1_brand);
	ASSERT(l->lwp_procp->p_brand_data != NULL);
	ASSERT(l->lwp_brand != NULL);
	l->lwp_brand = NULL;
}

/*ARGSUSED*/
void
sn1_lwpexit(klwp_t *l)
{
	proc_t	*p = l->lwp_procp;

	ASSERT(l->lwp_procp->p_brand == &sn1_brand);
	ASSERT(l->lwp_procp->p_brand_data != NULL);
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
sn1_free_brand_data(zone_t *zone)
{
}

/*ARGSUSED*/
void
sn1_init_brand_data(zone_t *zone)
{
}

#if defined(_LP64)
static void
Ehdr32to64(Elf32_Ehdr *src, Ehdr *dst)
{
	bcopy(src->e_ident, dst->e_ident, sizeof (src->e_ident));
	dst->e_type =		src->e_type;
	dst->e_machine =	src->e_machine;
	dst->e_version =	src->e_version;
	dst->e_entry =		src->e_entry;
	dst->e_phoff =		src->e_phoff;
	dst->e_shoff =		src->e_shoff;
	dst->e_flags =		src->e_flags;
	dst->e_ehsize =		src->e_ehsize;
	dst->e_phentsize =	src->e_phentsize;
	dst->e_phnum =		src->e_phnum;
	dst->e_shentsize =	src->e_shentsize;
	dst->e_shnum =		src->e_shnum;
	dst->e_shstrndx =	src->e_shstrndx;
}
#endif /* _LP64 */

int
sn1_elfexec(vnode_t *vp, execa_t *uap, uarg_t *args, intpdata_t *idatap,
	int level, long *execsz, int setid, caddr_t exec_file, cred_t *cred,
	int brand_action)
{
	vnode_t		*nvp;
	Ehdr		ehdr;
	Addr		uphdr_vaddr;
	intptr_t	voffset;
	int		interp;
	int		i, err;
	struct execenv	env;
	struct user	*up = PTOU(curproc);
	sn1_proc_data_t	*spd;
	sn1_elf_data_t	sed, *sedp;
	char		*linker;
	uintptr_t	lddata; /* lddata of executable's linker */

	ASSERT(curproc->p_brand == &sn1_brand);
	ASSERT(curproc->p_brand_data != NULL);

	spd = (sn1_proc_data_t *)curproc->p_brand_data;
	sedp = &spd->spd_elf_data;

	args->brandname = SN1_BRANDNAME;

	/*
	 * We will exec the brand library and then map in the target
	 * application and (optionally) the brand's default linker.
	 */
	if (args->to_model == DATAMODEL_NATIVE) {
		args->emulator = SN1_LIB;
		linker = SN1_LINKER;
#if defined(_LP64)
	} else {
		args->emulator = SN1_LIB32;
		linker = SN1_LINKER32;
#endif /* _LP64 */
	}

	if ((err = lookupname(args->emulator, UIO_SYSSPACE, FOLLOW, NULLVPP,
	    &nvp)) != 0) {
		uprintf("%s: not found.", args->emulator);
		return (err);
	}

	if (args->to_model == DATAMODEL_NATIVE) {
		err = elfexec(nvp, uap, args, idatap, level + 1, execsz,
		    setid, exec_file, cred, brand_action);
#if defined(_LP64)
	} else {
		err = elf32exec(nvp, uap, args, idatap, level + 1, execsz,
		    setid, exec_file, cred, brand_action);
#endif /* _LP64 */
	}
	VN_RELE(nvp);
	if (err != 0)
		return (err);

	/*
	 * The u_auxv vectors are set up by elfexec to point to the brand
	 * emulation library and linker.  Save these so they can be copied to
	 * the specific brand aux vectors.
	 */
	bzero(&sed, sizeof (sed));
	for (i = 0; i < __KERN_NAUXV_IMPL; i++) {
		switch (up->u_auxv[i].a_type) {
		case AT_SUN_LDDATA:
			sed.sed_lddata = up->u_auxv[i].a_un.a_val;
			break;
		case AT_BASE:
			sed.sed_base = up->u_auxv[i].a_un.a_val;
			break;
		case AT_ENTRY:
			sed.sed_entry = up->u_auxv[i].a_un.a_val;
			break;
		case AT_PHDR:
			sed.sed_phdr = up->u_auxv[i].a_un.a_val;
			break;
		case AT_PHENT:
			sed.sed_phent = up->u_auxv[i].a_un.a_val;
			break;
		case AT_PHNUM:
			sed.sed_phnum = up->u_auxv[i].a_un.a_val;
			break;
		default:
			break;
		}
	}
	/* Make sure the emulator has an entry point */
	ASSERT(sed.sed_entry != NULL);
	ASSERT(sed.sed_phdr != NULL);

	bzero(&env, sizeof (env));
	if (args->to_model == DATAMODEL_NATIVE) {
		err = mapexec_brand(vp, args, &ehdr, &uphdr_vaddr, &voffset,
		    exec_file, &interp, &env.ex_bssbase, &env.ex_brkbase,
		    &env.ex_brksize, NULL);
#if defined(_LP64)
	} else {
		Elf32_Ehdr ehdr32;
		Elf32_Addr uphdr_vaddr32;
		err = mapexec32_brand(vp, args, &ehdr32, &uphdr_vaddr32,
		    &voffset, exec_file, &interp, &env.ex_bssbase,
		    &env.ex_brkbase, &env.ex_brksize, NULL);
		Ehdr32to64(&ehdr32, &ehdr);
		if (uphdr_vaddr32 == (Elf32_Addr)-1)
			uphdr_vaddr = (Addr)-1;
		else
			uphdr_vaddr = uphdr_vaddr32;
#endif /* _LP64 */
	}
	if (err != 0)
		return (err);

	/*
	 * Save off the important properties of the executable. The brand
	 * library will ask us for this data later, when it is initializing
	 * and getting ready to transfer control to the brand application.
	 */
	if (uphdr_vaddr == (Addr)-1)
		sedp->sed_phdr = voffset + ehdr.e_phoff;
	else
		sedp->sed_phdr = voffset + uphdr_vaddr;
	sedp->sed_entry = voffset + ehdr.e_entry;
	sedp->sed_phent = ehdr.e_phentsize;
	sedp->sed_phnum = ehdr.e_phnum;

	if (interp) {
		if (ehdr.e_type == ET_DYN) {
			/*
			 * This is a shared object executable, so we need to
			 * pick a reasonable place to put the heap. Just don't
			 * use the first page.
			 */
			env.ex_brkbase = (caddr_t)PAGESIZE;
			env.ex_bssbase = (caddr_t)PAGESIZE;
		}

		/*
		 * If the program needs an interpreter (most do), map it in and
		 * store relevant information about it in the aux vector, where
		 * the brand library can find it.
		 */
		if ((err = lookupname(linker, UIO_SYSSPACE,
		    FOLLOW, NULLVPP, &nvp)) != 0) {
			uprintf("%s: not found.", SN1_LINKER);
			return (err);
		}
		if (args->to_model == DATAMODEL_NATIVE) {
			err = mapexec_brand(nvp, args, &ehdr,
			    &uphdr_vaddr, &voffset, exec_file, &interp,
			    NULL, NULL, NULL, &lddata);
#if defined(_LP64)
		} else {
			Elf32_Ehdr ehdr32;
			Elf32_Addr uphdr_vaddr32;
			err = mapexec32_brand(nvp, args, &ehdr32,
			    &uphdr_vaddr32, &voffset, exec_file, &interp,
			    NULL, NULL, NULL, &lddata);
			Ehdr32to64(&ehdr32, &ehdr);
			if (uphdr_vaddr32 == (Elf32_Addr)-1)
				uphdr_vaddr = (Addr)-1;
			else
				uphdr_vaddr = uphdr_vaddr32;
#endif /* _LP64 */
		}
		VN_RELE(nvp);
		if (err != 0)
			return (err);

		/*
		 * Now that we know the base address of the brand's linker,
		 * place it in the aux vector.
		 */
		sedp->sed_base = voffset;
		sedp->sed_ldentry = voffset + ehdr.e_entry;
		sedp->sed_lddata = voffset + lddata;
	} else {
		/*
		 * This program has no interpreter. The brand library will
		 * jump to the address in the AT_SUN_BRAND_LDENTRY aux vector,
		 * so in this case, put the entry point of the main executable
		 * there.
		 */
		if (ehdr.e_type == ET_EXEC) {
			/*
			 * An executable with no interpreter, this must be a
			 * statically linked executable, which means we loaded
			 * it at the address specified in the elf header, in
			 * which case the e_entry field of the elf header is an
			 * absolute address.
			 */
			sedp->sed_ldentry = ehdr.e_entry;
			sedp->sed_entry = ehdr.e_entry;
			sedp->sed_lddata = NULL;
			sedp->sed_base = NULL;
		} else {
			/*
			 * A shared object with no interpreter, we use the
			 * calculated address from above.
			 */
			sedp->sed_ldentry = sedp->sed_entry;
			sedp->sed_lddata = NULL;
			sedp->sed_base = NULL;
		}
	}

	if (uphdr_vaddr != (Addr)-1) {
		if (ehdr.e_type == ET_DYN) {
			/*
			 * Delay setting the brkbase until the first call to
			 * brk(); see elfexec() for details.
			 */
			env.ex_bssbase = (caddr_t)0;
			env.ex_brkbase = (caddr_t)0;
			env.ex_brksize = 0;
		}
	}

	env.ex_magic = elfmagic;
	env.ex_vp = vp;
	setexecenv(&env);

	/*
	 * It's time to manipulate the process aux vectors.  First
	 * we need to update the AT_SUN_AUXFLAGS aux vector to set
	 * the AF_SUN_NOPLM flag.
	 */
	if (args->to_model == DATAMODEL_NATIVE) {
		auxv_t		auxflags_auxv;

		if (copyin(args->auxp_auxflags, &auxflags_auxv,
		    sizeof (auxflags_auxv)) != 0)
			return (EFAULT);

		ASSERT(auxflags_auxv.a_type == AT_SUN_AUXFLAGS);
		auxflags_auxv.a_un.a_val |= AF_SUN_NOPLM;
		if (copyout(&auxflags_auxv, args->auxp_auxflags,
		    sizeof (auxflags_auxv)) != 0)
			return (EFAULT);
#if defined(_LP64)
	} else {
		auxv32_t	auxflags_auxv32;

		if (copyin(args->auxp_auxflags, &auxflags_auxv32,
		    sizeof (auxflags_auxv32)) != 0)
			return (EFAULT);

		ASSERT(auxflags_auxv32.a_type == AT_SUN_AUXFLAGS);
		auxflags_auxv32.a_un.a_val |= AF_SUN_NOPLM;
		if (copyout(&auxflags_auxv32, args->auxp_auxflags,
		    sizeof (auxflags_auxv32)) != 0)
			return (EFAULT);
#endif /* _LP64 */
	}

	/* Second, copy out the brand specific aux vectors. */
	if (args->to_model == DATAMODEL_NATIVE) {
		auxv_t sn1_auxv[] = {
		    { AT_SUN_BRAND_AUX1, 0 },
		    { AT_SUN_BRAND_AUX2, 0 },
		    { AT_SUN_BRAND_AUX3, 0 }
		};

		ASSERT(sn1_auxv[0].a_type == AT_SUN_BRAND_SN1_LDDATA);
		sn1_auxv[0].a_un.a_val = sed.sed_lddata;

		if (copyout(&sn1_auxv, args->auxp_brand,
		    sizeof (sn1_auxv)) != 0)
			return (EFAULT);
#if defined(_LP64)
	} else {
		auxv32_t sn1_auxv32[] = {
		    { AT_SUN_BRAND_AUX1, 0 },
		    { AT_SUN_BRAND_AUX2, 0 },
		    { AT_SUN_BRAND_AUX3, 0 }
		};

		ASSERT(sn1_auxv32[0].a_type == AT_SUN_BRAND_SN1_LDDATA);
		sn1_auxv32[0].a_un.a_val = (uint32_t)sed.sed_lddata;
		if (copyout(&sn1_auxv32, args->auxp_brand,
		    sizeof (sn1_auxv32)) != 0)
			return (EFAULT);
#endif /* _LP64 */
	}

	/*
	 * Third, the the /proc aux vectors set up by elfexec() point to brand
	 * emulation library and it's linker.  Copy these to the /proc brand
	 * specific aux vector, and update the regular /proc aux vectors to
	 * point to the executable (and it's linker).  This will enable
	 * debuggers to access the executable via the usual /proc or elf notes
	 * aux vectors.
	 *
	 * The brand emulation library's linker will get it's aux vectors off
	 * the stack, and then update the stack with the executable's aux
	 * vectors before jumping to the executable's linker.
	 *
	 * Debugging the brand emulation library must be done from
	 * the global zone, where the librtld_db module knows how to fetch the
	 * brand specific aux vectors to access the brand emulation libraries
	 * linker.
	 */
	for (i = 0; i < __KERN_NAUXV_IMPL; i++) {
		switch (up->u_auxv[i].a_type) {
		case AT_SUN_BRAND_SN1_LDDATA:
			up->u_auxv[i].a_un.a_val = sed.sed_lddata;
			break;
		case AT_BASE:
			if (sedp->sed_base == NULL) {
				/* Hide base for static binaries */
				up->u_auxv[i].a_type = AT_IGNORE;
				up->u_auxv[i].a_un.a_val = NULL;
			} else {
				up->u_auxv[i].a_un.a_val = sedp->sed_base;
			}
			break;
		case AT_ENTRY:
			up->u_auxv[i].a_un.a_val = sedp->sed_entry;
			break;
		case AT_PHDR:
			up->u_auxv[i].a_un.a_val = sedp->sed_phdr;
			break;
		case AT_PHENT:
			up->u_auxv[i].a_un.a_val = sedp->sed_phent;
			break;
		case AT_PHNUM:
			up->u_auxv[i].a_un.a_val = sedp->sed_phnum;
			break;
		case AT_SUN_LDDATA:
			if (sedp->sed_lddata == NULL) {
				/* Hide lddata for static binaries */
				up->u_auxv[i].a_type = AT_IGNORE;
				up->u_auxv[i].a_un.a_val = NULL;
			} else {
				up->u_auxv[i].a_un.a_val = sedp->sed_lddata;
			}
			break;
		default:
			break;
		}
	}

	/*
	 * The last thing we do here is clear spd->spd_handler.  This is
	 * important because if we're already a branded process and if this
	 * exec succeeds, there is a window between when the exec() first
	 * returns to the userland of the new process and when our brand
	 * library get's initialized, during which we don't want system
	 * calls to be re-directed to our brand library since it hasn't
	 * been initialized yet.
	 */
	spd->spd_handler = NULL;

	return (0);
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
	sn1_emulation_table[SYS_wait] = 1;			/*   7 */
	sn1_emulation_table[SYS_time] = 1;			/*  13 */
	sn1_emulation_table[SYS_getpid] = 1;			/*  20 */
	sn1_emulation_table[SYS_mount] = 1;			/*  21 */
	sn1_emulation_table[SYS_getuid] = 1;			/*  24 */
	sn1_emulation_table[SYS_times] = 1;			/*  43 */
	sn1_emulation_table[SYS_getgid] = 1;			/*  47 */
	sn1_emulation_table[SYS_utssys] = 1;			/*  57 */
	sn1_emulation_table[SYS_readlink] = 1;			/*  90 */
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
