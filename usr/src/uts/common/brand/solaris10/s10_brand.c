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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include "s10_brand.h"

char *s10_emulation_table = NULL;

void	s10_init_brand_data(zone_t *);
void	s10_free_brand_data(zone_t *);
void	s10_setbrand(proc_t *);
int	s10_getattr(zone_t *, int, void *, size_t *);
int	s10_setattr(zone_t *, int, void *, size_t);
int	s10_brandsys(int, int64_t *, uintptr_t, uintptr_t, uintptr_t,
		uintptr_t, uintptr_t, uintptr_t);
void	s10_copy_procdata(proc_t *, proc_t *);
void	s10_proc_exit(struct proc *, klwp_t *);
void	s10_exec();
int	s10_initlwp(klwp_t *);
void	s10_forklwp(klwp_t *, klwp_t *);
void	s10_freelwp(klwp_t *);
void	s10_lwpexit(klwp_t *);
int	s10_elfexec(vnode_t *, execa_t *, uarg_t *, intpdata_t *, int,
	long *, int, caddr_t, cred_t *, int);

/* s10 brand */
struct brand_ops s10_brops = {
	s10_init_brand_data,
	s10_free_brand_data,
	s10_brandsys,
	s10_setbrand,
	s10_getattr,
	s10_setattr,
	s10_copy_procdata,
	s10_proc_exit,
	s10_exec,
	lwp_setrval,
	s10_initlwp,
	s10_forklwp,
	s10_freelwp,
	s10_lwpexit,
	s10_elfexec
};

#ifdef	sparc

struct brand_mach_ops s10_mops = {
	s10_brand_syscall_callback,
	s10_brand_syscall32_callback
};

#else	/* sparc */

#ifdef	__amd64

struct brand_mach_ops s10_mops = {
	s10_brand_sysenter_callback,
	NULL,
	s10_brand_int91_callback,
	s10_brand_syscall_callback,
	s10_brand_syscall32_callback,
	NULL
};

#else	/* ! __amd64 */

struct brand_mach_ops s10_mops = {
	s10_brand_sysenter_callback,
	NULL,
	NULL,
	s10_brand_syscall_callback,
	NULL,
	NULL
};
#endif	/* __amd64 */

#endif	/* _sparc */

struct brand	s10_brand = {
	BRAND_VER_1,
	"solaris10",
	&s10_brops,
	&s10_mops
};

static struct modlbrand modlbrand = {
	&mod_brandops,		/* type of module */
	"Solaris 10 Brand",	/* description of module */
	&s10_brand		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlbrand, NULL
};

void
s10_setbrand(proc_t *p)
{
	ASSERT(p->p_brand == &s10_brand);
	ASSERT(p->p_brand_data == NULL);

	/*
	 * We should only be called from exec(), when we know the process
	 * is single-threaded.
	 */
	ASSERT(p->p_tlist == p->p_tlist->t_forw);

	p->p_brand_data = kmem_zalloc(sizeof (s10_proc_data_t), KM_SLEEP);
	(void) s10_initlwp(p->p_tlist->t_lwp);
}

/*ARGSUSED*/
int
s10_getattr(zone_t *zone, int attr, void *buf, size_t *bufsize)
{
	ASSERT(zone->zone_brand == &s10_brand);
	if (attr == S10_EMUL_BITMAP) {
		if (buf == NULL || *bufsize != sizeof (s10_emul_bitmap_t))
			return (EINVAL);
		if (copyout(((s10_zone_data_t *)zone->zone_brand_data)->
		    emul_bitmap, buf, sizeof (s10_emul_bitmap_t)) != 0)
			return (EFAULT);
		return (0);
	}

	return (EINVAL);
}

int
s10_setattr(zone_t *zone, int attr, void *buf, size_t bufsize)
{
	ASSERT(zone->zone_brand == &s10_brand);
	if (attr == S10_EMUL_BITMAP) {
		if (buf == NULL || bufsize != sizeof (s10_emul_bitmap_t))
			return (EINVAL);
		if (copyin(buf, ((s10_zone_data_t *)zone->zone_brand_data)->
		    emul_bitmap, sizeof (s10_emul_bitmap_t)) != 0)
			return (EFAULT);
		return (0);
	}

	return (EINVAL);
}

#ifdef	__amd64
/*
 * The Nevada kernel clears %fs for threads in 64-bit x86 processes but S10's
 * libc expects %fs to be nonzero.  This causes some committed
 * libc/libthread interfaces (e.g., thr_main()) to fail, which impacts several
 * libraries, including libdoor.  This function sets the specified LWP's %fs
 * register to the legacy S10 selector value (LWPFS_SEL).
 *
 * The best solution to the aforementioned problem is backporting CRs
 * 6467491 to Solaris 10 so that 64-bit x86 Solaris 10 processes
 * would accept zero for %fs.  Backporting the CRs is a requirement for running
 * S10 Containers in PV domUs because 64-bit Xen clears %fsbase when %fs is
 * nonzero.  Such behavior breaks 64-bit processes because Xen has to fetch the
 * FS segments' base addresses from the LWPs' GDTs, which are only capable of
 * 32-bit addressing.
 */
/*ARGSUSED*/
static void
s10_amd64_correct_fsreg(klwp_t *l)
{
	if (lwp_getdatamodel(l) == DATAMODEL_NATIVE) {
		kpreempt_disable();
		l->lwp_pcb.pcb_fs = LWPFS_SEL;
		l->lwp_pcb.pcb_rupdate = 1;
		lwptot(l)->t_post_sys = 1;	/* Guarantee update_sregs() */
		kpreempt_enable();
	}
}
#endif	/* __amd64 */

int
s10_native()
{
	struct user	*up = PTOU(curproc);
	char		*args_new, *comm_new, *p;
	int		len;

	len = sizeof (S10_NATIVE_LINKER32 " ") - 1;

	/*
	 * Make sure that the process' interpreter is the native dynamic linker.
	 * Convention dictates that native processes executing within solaris10-
	 * branded zones are interpreted by the native dynamic linker (the
	 * process and its arguments are specified as arguments to the dynamic
	 * linker).  If this convention is violated (i.e.,
	 * brandsys(B_S10_NATIVE, ...) is invoked by a process that shouldn't be
	 * native), then do nothing and silently indicate success.
	 */
	if (strcmp(up->u_comm, S10_LINKER_NAME) != 0)
		return (0);
	if (strncmp(up->u_psargs, S10_NATIVE_LINKER64 " /", len + 4) == 0)
		len += 3;		/* to account for "/64" in the path */
	else if (strncmp(up->u_psargs, S10_NATIVE_LINKER32 " /", len + 1) != 0)
		return (0);

	args_new = strdup(&up->u_psargs[len]);
	if ((p = strchr(args_new, ' ')) != NULL)
		*p = '\0';
	if ((comm_new = strrchr(args_new, '/')) != NULL)
		comm_new = strdup(comm_new + 1);
	else
		comm_new = strdup(args_new);
	if (p != NULL)
		*p = ' ';

	if ((strlen(args_new) != 0) && (strlen(comm_new) != 0)) {
		mutex_enter(&curproc->p_lock);
		(void) strlcpy(up->u_comm, comm_new, MAXCOMLEN+1);
		(void) strlcpy(up->u_psargs, args_new, PSARGSZ);
		mutex_exit(&curproc->p_lock);
	}

	strfree(args_new);
	strfree(comm_new);
	return (0);
}

/*
 * Get the address of the user-space system call handler from the user
 * process and attach it to the proc structure.
 */
/*ARGSUSED*/
int
s10_brandsys(int cmd, int64_t *rval, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6)
{
	s10_proc_data_t	*spd;
	s10_brand_reg_t	reg;
	proc_t		*p = curproc;
	int		err;

	*rval = 0;

	/*
	 * B_EXEC_BRAND is redundant
	 * since the kernel assumes a native process doing an exec
	 * in a branded zone is going to run a branded processes.
	 * hence we don't support this operation.
	 */
	if (cmd == B_EXEC_BRAND)
		return (ENOSYS);

	if (cmd == B_S10_NATIVE)
		return (s10_native());

	/* For all other operations this must be a branded process. */
	if (p->p_brand == &native_brand)
		return (ENOSYS);

	ASSERT(p->p_brand == &s10_brand);
	ASSERT(p->p_brand_data != NULL);

	spd = (s10_proc_data_t *)p->p_brand_data;

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
			s10_brand_reg32_t reg32;

			if (copyin((void *)arg1, &reg32, sizeof (reg32)) != 0)
				return (EFAULT);
			reg.sbr_version = reg32.sbr_version;
			reg.sbr_handler = (caddr_t)(uintptr_t)reg32.sbr_handler;
#endif /* _LP64 */
		}

		if (reg.sbr_version != S10_VERSION)
			return (ENOTSUP);
		spd->spd_handler = reg.sbr_handler;
		return (0);

	case B_ELFDATA:
		if (p->p_model == DATAMODEL_NATIVE) {
			if (copyout(&spd->spd_elf_data, (void *)arg1,
			    sizeof (s10_elf_data_t)) != 0)
				return (EFAULT);
#if defined(_LP64)
		} else {
			s10_elf_data32_t sed32;

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

	case B_S10_PIDINFO:
		/*
		 * The s10 brand needs to be able to get the pid of the
		 * current process and the pid of the zone's init, and it
		 * needs to do this on every process startup.  Early in
		 * brand startup, we can't call getpid() because calls to
		 * getpid() represent a magical signal to some old-skool
		 * debuggers.  By merging all of this into one call, we
		 * make this quite a bit cheaper and easier to handle in
		 * the brand module.
		 */
		if (copyout(&p->p_pid, (void *)arg1, sizeof (pid_t)) != 0)
			return (EFAULT);
		if (copyout(&p->p_zone->zone_proc_initpid, (void *)arg2,
		    sizeof (pid_t)) != 0)
			return (EFAULT);
		return (0);

	case B_S10_TRUSS_POINT:
		/*
		 * This subcommand exists so that we can see truss output
		 * from interposed system calls that return without first
		 * calling any other system call, meaning they would be
		 * invisible to truss(1).
		 *
		 * If the second argument is set non-zero, set errno to that
		 * value as well.
		 *
		 * Arguments are:
		 *
		 *    arg1: syscall number
		 *    arg2: errno
		 */
		return ((arg2 == 0) ? 0 : set_errno((uint_t)arg2));

	case B_S10_ISFDXATTRDIR: {
		/*
		 * This subcommand enables the userland brand emulation library
		 * to determine whether a file descriptor refers to an extended
		 * file attributes directory.  There is no standard syscall or
		 * libc function that can make such a determination.
		 */
		file_t *dir_filep;

		dir_filep = getf((int)arg1);
		if (dir_filep == NULL)
			return (EBADF);
		ASSERT(dir_filep->f_vnode != NULL);
		*rval = IS_XATTRDIR(dir_filep->f_vnode);
		releasef((int)arg1);
		return (0);
	}

#ifdef	__amd64
	case B_S10_FSREGCORRECTION:
		/*
		 * This subcommand exists so that the SYS_lwp_private and
		 * SYS_lwp_create syscalls can manually set the current thread's
		 * %fs register to the legacy S10 selector value for 64-bit x86
		 * processes.
		 */
		s10_amd64_correct_fsreg(ttolwp(curthread));
		return (0);
#endif	/* __amd64 */
	}

	return (EINVAL);
}

/*
 * Copy the per-process brand data from a parent proc to a child.
 */
void
s10_copy_procdata(proc_t *child, proc_t *parent)
{
	s10_proc_data_t	*spd;

	ASSERT(parent->p_brand == &s10_brand);
	ASSERT(child->p_brand == &s10_brand);
	ASSERT(parent->p_brand_data != NULL);
	ASSERT(child->p_brand_data == NULL);

	/* Just duplicate all the proc data of the parent for the child */
	spd = kmem_alloc(sizeof (s10_proc_data_t), KM_SLEEP);
	bcopy(parent->p_brand_data, spd, sizeof (s10_proc_data_t));
	child->p_brand_data = spd;
}

/*ARGSUSED*/
void
s10_proc_exit(struct proc *p, klwp_t *l)
{
	ASSERT(p->p_brand == &s10_brand);
	ASSERT(p->p_brand_data != NULL);

	/*
	 * We should only be called from proc_exit(), when we know that
	 * process is single-threaded.
	 */
	ASSERT(p->p_tlist == p->p_tlist->t_forw);

	/* upon exit, free our lwp brand data */
	(void) s10_freelwp(ttolwp(curthread));

	/* upon exit, free our proc brand data */
	kmem_free(p->p_brand_data, sizeof (s10_proc_data_t));
	p->p_brand_data = NULL;
}

void
s10_exec()
{
	s10_proc_data_t	*spd = curproc->p_brand_data;

	ASSERT(curproc->p_brand == &s10_brand);
	ASSERT(curproc->p_brand_data != NULL);
	ASSERT(ttolwp(curthread)->lwp_brand != NULL);

	/*
	 * We should only be called from exec(), when we know the process
	 * is single-threaded.
	 */
	ASSERT(curproc->p_tlist == curproc->p_tlist->t_forw);

	/* Upon exec, reset our lwp brand data. */
	(void) s10_freelwp(ttolwp(curthread));
	(void) s10_initlwp(ttolwp(curthread));

	/*
	 * Upon exec, reset all the proc brand data, except for the elf
	 * data associated with the executable we are exec'ing.
	 */
	spd->spd_handler = NULL;
}

/*ARGSUSED*/
int
s10_initlwp(klwp_t *l)
{
	ASSERT(l->lwp_procp->p_brand == &s10_brand);
	ASSERT(l->lwp_procp->p_brand_data != NULL);
	ASSERT(l->lwp_brand == NULL);
	l->lwp_brand = (void *)-1;
	return (0);
}

/*ARGSUSED*/
void
s10_forklwp(klwp_t *p, klwp_t *c)
{
	ASSERT(p->lwp_procp->p_brand == &s10_brand);
	ASSERT(c->lwp_procp->p_brand == &s10_brand);

	ASSERT(p->lwp_procp->p_brand_data != NULL);
	ASSERT(c->lwp_procp->p_brand_data != NULL);

	/* Both LWPs have already had been initialized via s10_initlwp() */
	ASSERT(p->lwp_brand != NULL);
	ASSERT(c->lwp_brand != NULL);

#ifdef	__amd64
	/*
	 * Only correct the child's %fs register if the parent's %fs register
	 * is LWPFS_SEL.  If the parent's %fs register is zero, then the Solaris
	 * 10 environment that we're emulating uses a version of libc that
	 * works when %fs is zero (i.e., it contains backports of CRs 6467491
	 * and 6501650).
	 */
	if (p->lwp_pcb.pcb_fs == LWPFS_SEL)
		s10_amd64_correct_fsreg(c);
#endif	/* __amd64 */
}

/*ARGSUSED*/
void
s10_freelwp(klwp_t *l)
{
	ASSERT(l->lwp_procp->p_brand == &s10_brand);
	ASSERT(l->lwp_procp->p_brand_data != NULL);
	ASSERT(l->lwp_brand != NULL);
	l->lwp_brand = NULL;
}

/*ARGSUSED*/
void
s10_lwpexit(klwp_t *l)
{
	ASSERT(l->lwp_procp->p_brand == &s10_brand);
	ASSERT(l->lwp_procp->p_brand_data != NULL);
	ASSERT(l->lwp_brand != NULL);

	/*
	 * We should never be called for the last thread in a process.
	 * (That case is handled by s10_proc_exit().)  There for this lwp
	 * must be exiting from a multi-threaded process.
	 */
	ASSERT(l->lwp_procp->p_tlist != l->lwp_procp->p_tlist->t_forw);

	l->lwp_brand = NULL;
}

void
s10_free_brand_data(zone_t *zone)
{
	kmem_free(zone->zone_brand_data, sizeof (s10_zone_data_t));
}

void
s10_init_brand_data(zone_t *zone)
{
	ASSERT(zone->zone_brand == &s10_brand);
	ASSERT(zone->zone_brand_data == NULL);
	zone->zone_brand_data = kmem_zalloc(sizeof (s10_zone_data_t), KM_SLEEP);
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
s10_elfexec(vnode_t *vp, execa_t *uap, uarg_t *args, intpdata_t *idatap,
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
	s10_proc_data_t	*spd;
	s10_elf_data_t	sed, *sedp;
	char		*linker;
	uintptr_t	lddata; /* lddata of executable's linker */

	ASSERT(curproc->p_brand == &s10_brand);
	ASSERT(curproc->p_brand_data != NULL);

	spd = (s10_proc_data_t *)curproc->p_brand_data;
	sedp = &spd->spd_elf_data;

	args->brandname = S10_BRANDNAME;

	/*
	 * We will exec the brand library and then map in the target
	 * application and (optionally) the brand's default linker.
	 */
	if (args->to_model == DATAMODEL_NATIVE) {
		args->emulator = S10_LIB;
		linker = S10_LINKER;
#if defined(_LP64)
	} else {
		args->emulator = S10_LIB32;
		linker = S10_LINKER32;
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
			uprintf("%s: not found.", S10_LINKER);
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
			sedp->sed_entry = NULL;
			sedp->sed_phdr = NULL;
			sedp->sed_phent = NULL;
			sedp->sed_phnum = NULL;
			sedp->sed_lddata = NULL;
			sedp->sed_base = voffset;

			if (ehdr.e_type == ET_DYN) {
				/*
				 * Delay setting the brkbase until the first
				 * call to brk(); see elfexec() for details.
				 */
				env.ex_bssbase = (caddr_t)0;
				env.ex_brkbase = (caddr_t)0;
				env.ex_brksize = 0;
			}
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
		auxv_t s10_auxv[] = {
		    { AT_SUN_BRAND_AUX1, 0 },
		    { AT_SUN_BRAND_AUX2, 0 },
		    { AT_SUN_BRAND_AUX3, 0 }
		};

		ASSERT(s10_auxv[0].a_type == AT_SUN_BRAND_S10_LDDATA);
		s10_auxv[0].a_un.a_val = sed.sed_lddata;

		if (copyout(&s10_auxv, args->auxp_brand,
		    sizeof (s10_auxv)) != 0)
			return (EFAULT);
#if defined(_LP64)
	} else {
		auxv32_t s10_auxv32[] = {
		    { AT_SUN_BRAND_AUX1, 0 },
		    { AT_SUN_BRAND_AUX2, 0 },
		    { AT_SUN_BRAND_AUX3, 0 }
		};

		ASSERT(s10_auxv32[0].a_type == AT_SUN_BRAND_S10_LDDATA);
		s10_auxv32[0].a_un.a_val = (uint32_t)sed.sed_lddata;
		if (copyout(&s10_auxv32, args->auxp_brand,
		    sizeof (s10_auxv32)) != 0)
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
		ulong_t val;

		switch (up->u_auxv[i].a_type) {
		case AT_SUN_BRAND_S10_LDDATA:
			up->u_auxv[i].a_un.a_val = sed.sed_lddata;
			continue;
		case AT_BASE:
			val = sedp->sed_base;
			break;
		case AT_ENTRY:
			val = sedp->sed_entry;
			break;
		case AT_PHDR:
			val = sedp->sed_phdr;
			break;
		case AT_PHENT:
			val = sedp->sed_phent;
			break;
		case AT_PHNUM:
			val = sedp->sed_phnum;
			break;
		case AT_SUN_LDDATA:
			val = sedp->sed_lddata;
			break;
		default:
			continue;
		}

		up->u_auxv[i].a_un.a_val = val;
		if (val == NULL) {
			/* Hide the entry for static binaries */
			up->u_auxv[i].a_type = AT_IGNORE;
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
	s10_emulation_table = kmem_zalloc(NSYSCALL, KM_SLEEP);
	s10_emulation_table[S10_SYS_forkall] = 1;		/*   2 */
	s10_emulation_table[S10_SYS_open] = 1;			/*   5 */
	s10_emulation_table[S10_SYS_wait] = 1;			/*   7 */
	s10_emulation_table[S10_SYS_creat] = 1;			/*   8 */
	s10_emulation_table[S10_SYS_unlink] = 1;		/*  10 */
	s10_emulation_table[S10_SYS_exec] = 1;			/*  11 */
	s10_emulation_table[S10_SYS_chown] = 1;			/*  16 */
	s10_emulation_table[S10_SYS_stat] = 1;			/*  18 */
	s10_emulation_table[S10_SYS_umount] = 1;		/*  22 */
	s10_emulation_table[S10_SYS_fstat] = 1;			/*  28 */
	s10_emulation_table[S10_SYS_utime] = 1;			/*  30 */
	s10_emulation_table[S10_SYS_access] = 1;		/*  33 */
	s10_emulation_table[S10_SYS_dup] = 1;			/*  41 */
	s10_emulation_table[SYS_ioctl] = 1;			/*  54 */
	s10_emulation_table[SYS_execve] = 1;			/*  59 */
	s10_emulation_table[SYS_acctctl] = 1;			/*  71 */
	s10_emulation_table[S10_SYS_issetugid] = 1;		/*  75 */
	s10_emulation_table[S10_SYS_fsat] = 1;			/*  76 */
	s10_emulation_table[S10_SYS_rmdir] = 1;			/*  79 */
	s10_emulation_table[SYS_getdents] = 1;			/*  81 */
	s10_emulation_table[S10_SYS_poll] = 1;			/*  87 */
	s10_emulation_table[S10_SYS_lstat] = 1;			/*  88 */
	s10_emulation_table[S10_SYS_fchown] = 1;		/*  94 */
#if defined(__x86)
	s10_emulation_table[S10_SYS_xstat] = 1;			/* 123 */
	s10_emulation_table[S10_SYS_lxstat] = 1;		/* 124 */
	s10_emulation_table[S10_SYS_fxstat] = 1;		/* 125 */
	s10_emulation_table[S10_SYS_xmknod] = 1;		/* 126 */
#endif
	s10_emulation_table[S10_SYS_lchown] = 1;		/* 130 */
	s10_emulation_table[S10_SYS_rename] = 1;		/* 134 */
	s10_emulation_table[SYS_uname] = 1;			/* 135 */
	s10_emulation_table[SYS_systeminfo] = 1;		/* 139 */
	s10_emulation_table[S10_SYS_fork1] = 1;			/* 143 */
	s10_emulation_table[S10_SYS_lwp_sema_wait] = 1;		/* 147 */
	s10_emulation_table[S10_SYS_utimes] = 1;		/* 154 */
#if defined(__amd64)
	s10_emulation_table[SYS_lwp_create] = 1;		/* 159 */
	s10_emulation_table[SYS_lwp_private] = 1;		/* 166 */
#endif	/* __amd64 */
	s10_emulation_table[S10_SYS_lwp_mutex_lock] = 1;	/* 169 */
	s10_emulation_table[SYS_pwrite] = 1;			/* 174 */
	s10_emulation_table[SYS_auditsys] = 1;			/* 186 */
	s10_emulation_table[SYS_sigqueue] = 1;			/* 190 */
	s10_emulation_table[SYS_lwp_mutex_timedlock] = 1;	/* 210 */
	s10_emulation_table[SYS_getdents64] = 1;		/* 213 */
	s10_emulation_table[S10_SYS_stat64] = 1;		/* 215 */
	s10_emulation_table[S10_SYS_lstat64] = 1;		/* 216 */
	s10_emulation_table[S10_SYS_fstat64] = 1;		/* 217 */
	s10_emulation_table[SYS_pwrite64] = 1;			/* 223 */
	s10_emulation_table[S10_SYS_creat64] = 1;		/* 224 */
	s10_emulation_table[S10_SYS_open64] = 1;		/* 225 */
	s10_emulation_table[SYS_zone] = 1;			/* 227 */
	s10_emulation_table[SYS_lwp_mutex_trylock] = 1;		/* 251 */

	err = mod_install(&modlinkage);
	if (err) {
		cmn_err(CE_WARN, "Couldn't install brand module");
		kmem_free(s10_emulation_table, NSYSCALL);
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
	if (brand_zone_count(&s10_brand))
		return (EBUSY);

	kmem_free(s10_emulation_table, NSYSCALL);
	s10_emulation_table = NULL;

	err = mod_remove(&modlinkage);
	if (err)
		cmn_err(CE_WARN, "Couldn't unload s10 brand module");

	return (err);
}
