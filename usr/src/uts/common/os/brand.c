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

#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/brand.h>
#include <sys/machbrand.h>
#include <sys/modctl.h>
#include <sys/rwlock.h>
#include <sys/zone.h>
#include <sys/pathname.h>

#define	SUPPORTED_BRAND_VERSION BRAND_VER_1

#if defined(__sparcv9)
/* sparcv9 uses system wide brand interposition hooks */
static void brand_plat_interposition_enable(void);
static void brand_plat_interposition_disable(void);

struct brand_mach_ops native_mach_ops  = {
		NULL, NULL
};
#else /* !__sparcv9 */
struct brand_mach_ops native_mach_ops  = {
		NULL, NULL, NULL, NULL
};
#endif /* !__sparcv9 */

brand_t native_brand = {
		BRAND_VER_1,
		"native",
		NULL,
		&native_mach_ops
};

/*
 * Used to maintain a list of all the brands currently loaded into the
 * kernel.
 */
struct brand_list {
	int			bl_refcnt;
	struct brand_list	*bl_next;
	brand_t			*bl_brand;
};

static struct brand_list *brand_list = NULL;

/*
 * This lock protects the integrity of the brand list.
 */
static kmutex_t brand_list_lock;

void
brand_init()
{
	mutex_init(&brand_list_lock, NULL, MUTEX_DEFAULT, NULL);
	p0.p_brand = &native_brand;
}

int
brand_register(brand_t *brand)
{
	struct brand_list *list, *scan;

	if (brand == NULL)
		return (EINVAL);

	if (brand->b_version != SUPPORTED_BRAND_VERSION) {
		if (brand->b_version < SUPPORTED_BRAND_VERSION) {
			cmn_err(CE_WARN,
			    "brand '%s' was built to run on older versions "
			    "of Solaris.",
			    brand->b_name);
		} else {
			cmn_err(CE_WARN,
			    "brand '%s' was built to run on a newer version "
			    "of Solaris.",
			    brand->b_name);
		}
		return (EINVAL);
	}

	/* Sanity checks */
	if (brand->b_name == NULL || brand->b_ops == NULL ||
	    brand->b_ops->b_brandsys == NULL) {
		cmn_err(CE_WARN, "Malformed brand");
		return (EINVAL);
	}

	list = kmem_alloc(sizeof (struct brand_list), KM_SLEEP);

	/* Add the brand to the list of loaded brands. */
	mutex_enter(&brand_list_lock);

	/*
	 * Check to be sure we haven't already registered this brand.
	 */
	for (scan = brand_list; scan != NULL; scan = scan->bl_next) {
		if (strcmp(brand->b_name, scan->bl_brand->b_name) == 0) {
			cmn_err(CE_WARN,
			    "Invalid attempt to load a second instance of "
			    "brand %s", brand->b_name);
			mutex_exit(&brand_list_lock);
			kmem_free(list, sizeof (struct brand_list));
			return (EINVAL);
		}
	}

#if defined(__sparcv9)
	/* sparcv9 uses system wide brand interposition hooks */
	if (brand_list == NULL)
		brand_plat_interposition_enable();
#endif /* __sparcv9 */

	list->bl_brand = brand;
	list->bl_refcnt = 0;
	list->bl_next = brand_list;
	brand_list = list;

	mutex_exit(&brand_list_lock);

	return (0);
}

/*
 * The kernel module implementing this brand is being unloaded, so remove
 * it from the list of active brands.
 */
int
brand_unregister(brand_t *brand)
{
	struct brand_list *list, *prev;

	/* Sanity checks */
	if (brand == NULL || brand->b_name == NULL) {
		cmn_err(CE_WARN, "Malformed brand");
		return (EINVAL);
	}

	prev = NULL;
	mutex_enter(&brand_list_lock);

	for (list = brand_list; list != NULL; list = list->bl_next) {
		if (list->bl_brand == brand)
			break;
		prev = list;
	}

	if (list == NULL) {
		cmn_err(CE_WARN, "Brand %s wasn't registered", brand->b_name);
		mutex_exit(&brand_list_lock);
		return (EINVAL);
	}

	if (list->bl_refcnt > 0) {
		cmn_err(CE_WARN, "Unregistering brand %s which is still in use",
		    brand->b_name);
		mutex_exit(&brand_list_lock);
		return (EBUSY);
	}

	/* Remove brand from the list */
	if (prev != NULL)
		prev->bl_next = list->bl_next;
	else
		brand_list = list->bl_next;

#if defined(__sparcv9)
	/* sparcv9 uses system wide brand interposition hooks */
	if (brand_list == NULL)
		brand_plat_interposition_disable();
#endif /* __sparcv9 */

	mutex_exit(&brand_list_lock);

	kmem_free(list, sizeof (struct brand_list));

	return (0);
}

/*
 * Record that a zone of this brand has been instantiated.  If the kernel
 * module implementing this brand's functionality is not present, this
 * routine attempts to load the module as a side effect.
 */
brand_t *
brand_register_zone(struct brand_attr *attr)
{
	struct brand_list *l = NULL;
	ddi_modhandle_t	hdl = NULL;
	char *modname;
	int err = 0;

	if (is_system_labeled()) {
		cmn_err(CE_WARN,
		    "Branded zones are not allowed on labeled systems.");
		return (NULL);
	}

	/*
	 * We make at most two passes through this loop.  The first time
	 * through, we're looking to see if this is a new user of an
	 * already loaded brand.  If the brand hasn't been loaded, we
	 * call ddi_modopen() to force it to be loaded and then make a
	 * second pass through the list of brands.  If we don't find the
	 * brand the second time through it means that the modname
	 * specified in the brand_attr structure doesn't provide the brand
	 * specified in the brandname field.  This would suggest a bug in
	 * the brand's config.xml file.  We close the module and return
	 * 'NULL' to the caller.
	 */
	for (;;) {
		/*
		 * Search list of loaded brands
		 */
		mutex_enter(&brand_list_lock);
		for (l = brand_list; l != NULL; l = l->bl_next)
			if (strcmp(attr->ba_brandname,
			    l->bl_brand->b_name) == 0)
				break;
		if ((l != NULL) || (hdl != NULL))
			break;
		mutex_exit(&brand_list_lock);

		/*
		 * We didn't find that the requested brand has been loaded
		 * yet, so we trigger the load of the appropriate kernel
		 * module and search the list again.
		 */
		modname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) strcpy(modname, "brand/");
		(void) strcat(modname, attr->ba_modname);
		hdl = ddi_modopen(modname, KRTLD_MODE_FIRST, &err);
		kmem_free(modname, MAXPATHLEN);

		if (err != 0)
			return (NULL);
	}

	/*
	 * If we found the matching brand, bump its reference count.
	 */
	if (l != NULL)
		l->bl_refcnt++;

	mutex_exit(&brand_list_lock);

	if (hdl != NULL)
		(void) ddi_modclose(hdl);

	return ((l != NULL) ? l->bl_brand : NULL);
}

/*
 * Return the number of zones currently using this brand.
 */
int
brand_zone_count(struct brand *bp)
{
	struct brand_list *l;
	int cnt = 0;

	mutex_enter(&brand_list_lock);
	for (l = brand_list; l != NULL; l = l->bl_next)
		if (l->bl_brand == bp) {
			cnt = l->bl_refcnt;
			break;
		}
	mutex_exit(&brand_list_lock);

	return (cnt);
}

void
brand_unregister_zone(struct brand *bp)
{
	struct brand_list *list;

	mutex_enter(&brand_list_lock);
	for (list = brand_list; list != NULL; list = list->bl_next) {
		if (list->bl_brand == bp) {
			ASSERT(list->bl_refcnt > 0);
			list->bl_refcnt--;
			break;
		}
	}
	mutex_exit(&brand_list_lock);
}

void
brand_setbrand(proc_t *p)
{
	brand_t *bp = p->p_zone->zone_brand;

	ASSERT(bp != NULL);
	ASSERT(p->p_brand == &native_brand);

	/*
	 * We should only be called from exec(), when we know the process
	 * is single-threaded.
	 */
	ASSERT(p->p_tlist == p->p_tlist->t_forw);

	p->p_brand = bp;
	ASSERT(PROC_IS_BRANDED(p));
	BROP(p)->b_setbrand(p);
}

void
brand_clearbrand(proc_t *p, boolean_t no_lwps)
{
	brand_t *bp = p->p_zone->zone_brand;
	klwp_t *lwp = NULL;
	ASSERT(bp != NULL);
	ASSERT(!no_lwps || (p->p_tlist == NULL));

	/*
	 * If called from exec_common() or proc_exit(),
	 * we know the process is single-threaded.
	 * If called from fork_fail, p_tlist is NULL.
	 */
	if (!no_lwps) {
		ASSERT(p->p_tlist == p->p_tlist->t_forw);
		lwp = p->p_tlist->t_lwp;
	}

	ASSERT(PROC_IS_BRANDED(p));
	BROP(p)->b_proc_exit(p, lwp);
	p->p_brand = &native_brand;
}

#if defined(__sparcv9)
/*
 * Currently, only sparc has system level brand syscall interposition.
 * On x86 we're able to enable syscall interposition on a per-cpu basis
 * when a branded thread is scheduled to run on a cpu.
 */

/* Local variables needed for dynamic syscall interposition support */
static uint32_t	syscall_trap_patch_instr_orig;
static uint32_t	syscall_trap32_patch_instr_orig;

/* Trap Table syscall entry hot patch points */
extern void	syscall_trap_patch_point(void);
extern void	syscall_trap32_patch_point(void);

/* Alternate syscall entry handlers used when branded zones are running */
extern void	syscall_wrapper(void);
extern void	syscall_wrapper32(void);

/* Macros used to facilitate sparcv9 instruction generation */
#define	BA_A_INSTR	0x30800000	/* ba,a addr */
#define	DISP22(from, to) \
	((((uintptr_t)(to) - (uintptr_t)(from)) >> 2) & 0x3fffff)

/*ARGSUSED*/
static void
brand_plat_interposition_enable(void)
{
	ASSERT(MUTEX_HELD(&brand_list_lock));

	/*
	 * Before we hot patch the kernel save the current instructions
	 * so that we can restore them later.
	 */
	syscall_trap_patch_instr_orig =
	    *(uint32_t *)syscall_trap_patch_point;
	syscall_trap32_patch_instr_orig =
	    *(uint32_t *)syscall_trap32_patch_point;

	/*
	 * Modify the trap table at the patch points.
	 *
	 * We basically replace the first instruction at the patch
	 * point with a ba,a instruction that will transfer control
	 * to syscall_wrapper or syscall_wrapper32 for 64-bit and
	 * 32-bit syscalls respectively.  It's important to note that
	 * the annul bit is set in the branch so we don't execute
	 * the instruction directly following the one we're patching
	 * during the branch's delay slot.
	 *
	 * It also doesn't matter that we're not atomically updating both
	 * the 64 and 32 bit syscall paths at the same time since there's
	 * no actual branded processes running on the system yet.
	 */
	hot_patch_kernel_text((caddr_t)syscall_trap_patch_point,
	    BA_A_INSTR | DISP22(syscall_trap_patch_point, syscall_wrapper),
	    4);
	hot_patch_kernel_text((caddr_t)syscall_trap32_patch_point,
	    BA_A_INSTR | DISP22(syscall_trap32_patch_point, syscall_wrapper32),
	    4);
}

/*ARGSUSED*/
static void
brand_plat_interposition_disable(void)
{
	ASSERT(MUTEX_HELD(&brand_list_lock));

	/*
	 * Restore the original instructions at the trap table syscall
	 * patch points to disable the brand syscall interposition
	 * mechanism.
	 */
	hot_patch_kernel_text((caddr_t)syscall_trap_patch_point,
	    syscall_trap_patch_instr_orig, 4);
	hot_patch_kernel_text((caddr_t)syscall_trap32_patch_point,
	    syscall_trap32_patch_instr_orig, 4);
}
#endif /* __sparcv9 */

/*
 * The following functions can be shared among kernel brand modules which
 * implement Solaris-derived brands, all of which need to do similar tasks
 * to manage the brand.
 */

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

/*
 * Return -1 if the cmd was not handled by this function.
 */
/*ARGSUSED*/
int
brand_solaris_cmd(int cmd, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
    struct brand *pbrand, int brandvers)
{
	brand_proc_data_t	*spd;
	brand_proc_reg_t	reg;
	proc_t			*p = curproc;
	int			err;

	/*
	 * There is one operation that is supported for a native
	 * process; B_EXEC_BRAND.  This brand operaion is redundant
	 * since the kernel assumes a native process doing an exec
	 * in a branded zone is going to run a branded processes.
	 * hence we don't support this operation.
	 */
	if (cmd == B_EXEC_BRAND)
		return (ENOSYS);

	/* For all other operations this must be a branded process. */
	if (p->p_brand == &native_brand)
		return (ENOSYS);

	ASSERT(p->p_brand == pbrand);
	ASSERT(p->p_brand_data != NULL);

	spd = (brand_proc_data_t *)p->p_brand_data;

	switch ((cmd)) {
	case B_EXEC_NATIVE:
		err = exec_common((char *)arg1, (const char **)arg2,
		    (const char **)arg3, EBA_NATIVE);
		return (err);

	/*
	 * Get the address of the user-space system call handler from
	 * the user process and attach it to the proc structure.
	 */
	case B_REGISTER:
		if (p->p_model == DATAMODEL_NATIVE) {
			if (copyin((void *)arg1, &reg, sizeof (reg)) != 0)
				return (EFAULT);
		}
#if defined(_LP64)
		else {
			brand_common_reg32_t reg32;

			if (copyin((void *)arg1, &reg32, sizeof (reg32)) != 0)
				return (EFAULT);
			reg.sbr_version = reg32.sbr_version;
			reg.sbr_handler = (caddr_t)(uintptr_t)reg32.sbr_handler;
		}
#endif /* _LP64 */

		if (reg.sbr_version != brandvers)
			return (ENOTSUP);
		spd->spd_handler = reg.sbr_handler;
		return (0);

	case B_ELFDATA:
		if (p->p_model == DATAMODEL_NATIVE) {
			if (copyout(&spd->spd_elf_data, (void *)arg1,
			    sizeof (brand_elf_data_t)) != 0)
				return (EFAULT);
		}
#if defined(_LP64)
		else {
			brand_elf_data32_t sed32;

			sed32.sed_phdr = spd->spd_elf_data.sed_phdr;
			sed32.sed_phent = spd->spd_elf_data.sed_phent;
			sed32.sed_phnum = spd->spd_elf_data.sed_phnum;
			sed32.sed_entry = spd->spd_elf_data.sed_entry;
			sed32.sed_base = spd->spd_elf_data.sed_base;
			sed32.sed_ldentry = spd->spd_elf_data.sed_ldentry;
			sed32.sed_lddata = spd->spd_elf_data.sed_lddata;
			if (copyout(&sed32, (void *)arg1, sizeof (sed32))
			    != 0)
				return (EFAULT);
		}
#endif /* _LP64 */
		return (0);

	/*
	 * The B_TRUSS_POINT subcommand exists so that we can see
	 * truss output from interposed system calls that return
	 * without first calling any other system call, meaning they
	 * would be invisible to truss(1).
	 * If the second argument is set non-zero, set errno to that
	 * value as well.
	 *
	 * Common arguments seen with truss are:
	 *
	 *	arg1: syscall number
	 *	arg2: errno
	 */
	case B_TRUSS_POINT:
		return ((arg2 == 0) ? 0 : set_errno((uint_t)arg2));
	}

	return (-1);
}

/*ARGSUSED*/
void
brand_solaris_copy_procdata(proc_t *child, proc_t *parent, struct brand *pbrand)
{
	brand_proc_data_t	*spd;

	ASSERT(parent->p_brand == pbrand);
	ASSERT(child->p_brand == pbrand);
	ASSERT(parent->p_brand_data != NULL);
	ASSERT(child->p_brand_data == NULL);

	/*
	 * Just duplicate all the proc data of the parent for the
	 * child
	 */
	spd = kmem_alloc(sizeof (brand_proc_data_t), KM_SLEEP);
	bcopy(parent->p_brand_data, spd, sizeof (brand_proc_data_t));
	child->p_brand_data = spd;
}

static void
restoreexecenv(struct execenv *ep, stack_t *sp)
{
	klwp_t *lwp = ttolwp(curthread);

	setexecenv(ep);
	lwp->lwp_sigaltstack.ss_sp = sp->ss_sp;
	lwp->lwp_sigaltstack.ss_size = sp->ss_size;
	lwp->lwp_sigaltstack.ss_flags = sp->ss_flags;
}

/*ARGSUSED*/
int
brand_solaris_elfexec(vnode_t *vp, execa_t *uap, uarg_t *args,
    intpdata_t *idatap, int level, long *execsz, int setid, caddr_t exec_file,
    cred_t *cred, int brand_action, struct brand *pbrand, char *bname,
    char *brandlib, char *brandlib32, char *brandlinker, char *brandlinker32)
{

	vnode_t		*nvp;
	Ehdr		ehdr;
	Addr		uphdr_vaddr;
	intptr_t	voffset;
	int		interp;
	int		i, err;
	struct execenv	env;
	struct execenv	origenv;
	stack_t		orig_sigaltstack;
	struct user	*up = PTOU(curproc);
	proc_t		*p = ttoproc(curthread);
	klwp_t		*lwp = ttolwp(curthread);
	brand_proc_data_t	*spd;
	brand_elf_data_t sed, *sedp;
	char		*linker;
	uintptr_t	lddata; /* lddata of executable's linker */

	ASSERT(curproc->p_brand == pbrand);
	ASSERT(curproc->p_brand_data != NULL);

	spd = (brand_proc_data_t *)curproc->p_brand_data;
	sedp = &spd->spd_elf_data;

	args->brandname = bname;

	/*
	 * We will exec the brand library and then map in the target
	 * application and (optionally) the brand's default linker.
	 */
	if (args->to_model == DATAMODEL_NATIVE) {
		args->emulator = brandlib;
		linker = brandlinker;
	}
#if defined(_LP64)
	else {
		args->emulator = brandlib32;
		linker = brandlinker32;
	}
#endif  /* _LP64 */

	if ((err = lookupname(args->emulator, UIO_SYSSPACE, FOLLOW,
	    NULLVPP, &nvp)) != 0) {
		uprintf("%s: not found.", args->emulator);
		return (err);
	}

	/*
	 * The following elf{32}exec call changes the execenv in the proc
	 * struct which includes changing the p_exec member to be the vnode
	 * for the brand library (e.g. /.SUNWnative/usr/lib/s10_brand.so.1).
	 * We will eventually set the p_exec member to be the vnode for the new
	 * executable when we call setexecenv().  However, if we get an error
	 * before that call we need to restore the execenv to its original
	 * values so that when we return to the caller fop_close() works
	 * properly while cleaning up from the failed exec().  Restoring the
	 * original value will also properly decrement the 2nd VN_RELE that we
	 * took on the brand library.
	 */
	origenv.ex_bssbase = p->p_bssbase;
	origenv.ex_brkbase = p->p_brkbase;
	origenv.ex_brksize = p->p_brksize;
	origenv.ex_vp = p->p_exec;
	orig_sigaltstack.ss_sp = lwp->lwp_sigaltstack.ss_sp;
	orig_sigaltstack.ss_size = lwp->lwp_sigaltstack.ss_size;
	orig_sigaltstack.ss_flags = lwp->lwp_sigaltstack.ss_flags;

	if (args->to_model == DATAMODEL_NATIVE) {
		err = elfexec(nvp, uap, args, idatap, INTP_MAXDEPTH + 1, execsz,
		    setid, exec_file, cred, brand_action);
	}
#if defined(_LP64)
	else {
		err = elf32exec(nvp, uap, args, idatap, INTP_MAXDEPTH + 1,
		    execsz, setid, exec_file, cred, brand_action);
	}
#endif  /* _LP64 */
	VN_RELE(nvp);
	if (err != 0) {
		restoreexecenv(&origenv, &orig_sigaltstack);
		return (err);
	}

	/*
	 * The u_auxv veCTors are set up by elfexec to point to the
	 * brand emulation library and linker.  Save these so they can
	 * be copied to the specific brand aux vectors.
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
		err = mapexec_brand(vp, args, &ehdr, &uphdr_vaddr,
		    &voffset, exec_file, &interp, &env.ex_bssbase,
		    &env.ex_brkbase, &env.ex_brksize, NULL);
	}
#if defined(_LP64)
	else {
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
	}
#endif  /* _LP64 */
	if (err != 0) {
		restoreexecenv(&origenv, &orig_sigaltstack);
		return (err);
	}

	/*
	 * Save off the important properties of the executable. The
	 * brand library will ask us for this data later, when it is
	 * initializing and getting ready to transfer control to the
	 * brand application.
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
			 * This is a shared object executable, so we
			 * need to pick a reasonable place to put the
			 * heap. Just don't use the first page.
			 */
			env.ex_brkbase = (caddr_t)PAGESIZE;
			env.ex_bssbase = (caddr_t)PAGESIZE;
		}

		/*
		 * If the program needs an interpreter (most do), map
		 * it in and store relevant information about it in the
		 * aux vector, where the brand library can find it.
		 */
		if ((err = lookupname(linker, UIO_SYSSPACE,
		    FOLLOW, NULLVPP, &nvp)) != 0) {
			uprintf("%s: not found.", brandlinker);
			restoreexecenv(&origenv, &orig_sigaltstack);
			return (err);
		}
		if (args->to_model == DATAMODEL_NATIVE) {
			err = mapexec_brand(nvp, args, &ehdr,
			    &uphdr_vaddr, &voffset, exec_file, &interp,
			    NULL, NULL, NULL, &lddata);
		}
#if defined(_LP64)
		else {
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
		}
#endif  /* _LP64 */
		VN_RELE(nvp);
		if (err != 0) {
			restoreexecenv(&origenv, &orig_sigaltstack);
			return (err);
		}

		/*
		 * Now that we know the base address of the brand's
		 * linker, place it in the aux vector.
		 */
		sedp->sed_base = voffset;
		sedp->sed_ldentry = voffset + ehdr.e_entry;
		sedp->sed_lddata = voffset + lddata;
	} else {
		/*
		 * This program has no interpreter. The brand library
		 * will jump to the address in the AT_SUN_BRAND_LDENTRY
		 * aux vector, so in this case, put the entry point of
		 * the main executable there.
		 */
		if (ehdr.e_type == ET_EXEC) {
			/*
			 * An executable with no interpreter, this must
			 * be a statically linked executable, which
			 * means we loaded it at the address specified
			 * in the elf header, in which case the e_entry
			 * field of the elf header is an absolute
			 * address.
			 */
			sedp->sed_ldentry = ehdr.e_entry;
			sedp->sed_entry = ehdr.e_entry;
			sedp->sed_lddata = NULL;
			sedp->sed_base = NULL;
		} else {
			/*
			 * A shared object with no interpreter, we use
			 * the calculated address from above.
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
				 * Delay setting the brkbase until the
				 * first call to brk(); see elfexec()
				 * for details.
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
	}
#if defined(_LP64)
	else {
		auxv32_t	auxflags_auxv32;

		if (copyin(args->auxp_auxflags, &auxflags_auxv32,
		    sizeof (auxflags_auxv32)) != 0)
			return (EFAULT);

		ASSERT(auxflags_auxv32.a_type == AT_SUN_AUXFLAGS);
		auxflags_auxv32.a_un.a_val |= AF_SUN_NOPLM;
		if (copyout(&auxflags_auxv32, args->auxp_auxflags,
		    sizeof (auxflags_auxv32)) != 0)
			return (EFAULT);
	}
#endif  /* _LP64 */

	/* Second, copy out the brand specific aux vectors. */
	if (args->to_model == DATAMODEL_NATIVE) {
		auxv_t brand_auxv[] = {
		    { AT_SUN_BRAND_AUX1, 0 },
		    { AT_SUN_BRAND_AUX2, 0 },
		    { AT_SUN_BRAND_AUX3, 0 }
		};

		ASSERT(brand_auxv[0].a_type ==
		    AT_SUN_BRAND_COMMON_LDDATA);
		brand_auxv[0].a_un.a_val = sed.sed_lddata;

		if (copyout(&brand_auxv, args->auxp_brand,
		    sizeof (brand_auxv)) != 0)
			return (EFAULT);
	}
#if defined(_LP64)
	else {
		auxv32_t brand_auxv32[] = {
		    { AT_SUN_BRAND_AUX1, 0 },
		    { AT_SUN_BRAND_AUX2, 0 },
		    { AT_SUN_BRAND_AUX3, 0 }
		};

		ASSERT(brand_auxv32[0].a_type == AT_SUN_BRAND_COMMON_LDDATA);
		brand_auxv32[0].a_un.a_val = (uint32_t)sed.sed_lddata;
		if (copyout(&brand_auxv32, args->auxp_brand,
		    sizeof (brand_auxv32)) != 0)
			return (EFAULT);
	}
#endif  /* _LP64 */

	/*
	 * Third, the /proc aux vectors set up by elfexec() point to
	 * brand emulation library and it's linker.  Copy these to the
	 * /proc brand specific aux vector, and update the regular
	 * /proc aux vectors to point to the executable (and it's
	 * linker).  This will enable debuggers to access the
	 * executable via the usual /proc or elf notes aux vectors.
	 *
	 * The brand emulation library's linker will get it's aux
	 * vectors off the stack, and then update the stack with the
	 * executable's aux vectors before jumping to the executable's
	 * linker.
	 *
	 * Debugging the brand emulation library must be done from
	 * the global zone, where the librtld_db module knows how to
	 * fetch the brand specific aux vectors to access the brand
	 * emulation libraries linker.
	 */
	for (i = 0; i < __KERN_NAUXV_IMPL; i++) {
		ulong_t val;

		switch (up->u_auxv[i].a_type) {
		case AT_SUN_BRAND_COMMON_LDDATA:
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
	 * The last thing we do here is clear spd->spd_handler.  This
	 * is important because if we're already a branded process and
	 * if this exec succeeds, there is a window between when the
	 * exec() first returns to the userland of the new process and
	 * when our brand library get's initialized, during which we
	 * don't want system calls to be re-directed to our brand
	 * library since it hasn't been initialized yet.
	 */
	spd->spd_handler = NULL;

	return (0);
}

void
brand_solaris_exec(struct brand *pbrand)
{
	brand_proc_data_t	*spd = curproc->p_brand_data;

	ASSERT(curproc->p_brand == pbrand);
	ASSERT(curproc->p_brand_data != NULL);
	ASSERT(ttolwp(curthread)->lwp_brand != NULL);

	/*
	 * We should only be called from exec(), when we know the process
	 * is single-threaded.
	 */
	ASSERT(curproc->p_tlist == curproc->p_tlist->t_forw);

	/* Upon exec, reset our lwp brand data. */
	(void) brand_solaris_freelwp(ttolwp(curthread), pbrand);
	(void) brand_solaris_initlwp(ttolwp(curthread), pbrand);

	/*
	 * Upon exec, reset all the proc brand data, except for the elf
	 * data associated with the executable we are exec'ing.
	 */
	spd->spd_handler = NULL;
}

int
brand_solaris_fini(char **emul_table, struct modlinkage *modlinkage,
    struct brand *pbrand)
{
	int err;

	/*
	 * If there are any zones using this brand, we can't allow it
	 * to be unloaded.
	 */
	if (brand_zone_count(pbrand))
		return (EBUSY);

	kmem_free(*emul_table, NSYSCALL);
	*emul_table = NULL;

	err = mod_remove(modlinkage);
	if (err)
		cmn_err(CE_WARN, "Couldn't unload brand module");

	return (err);
}

/*ARGSUSED*/
void
brand_solaris_forklwp(klwp_t *p, klwp_t *c, struct brand *pbrand)
{
	ASSERT(p->lwp_procp->p_brand == pbrand);
	ASSERT(c->lwp_procp->p_brand == pbrand);

	ASSERT(p->lwp_procp->p_brand_data != NULL);
	ASSERT(c->lwp_procp->p_brand_data != NULL);

	/*
	 * Both LWPs have already had been initialized via
	 * brand_solaris_initlwp().
	 */
	ASSERT(p->lwp_brand != NULL);
	ASSERT(c->lwp_brand != NULL);
}

/*ARGSUSED*/
void
brand_solaris_freelwp(klwp_t *l, struct brand *pbrand)
{
	ASSERT(l->lwp_procp->p_brand == pbrand);
	ASSERT(l->lwp_procp->p_brand_data != NULL);
	ASSERT(l->lwp_brand != NULL);
	l->lwp_brand = NULL;
}

/*ARGSUSED*/
int
brand_solaris_initlwp(klwp_t *l, struct brand *pbrand)
{
	ASSERT(l->lwp_procp->p_brand == pbrand);
	ASSERT(l->lwp_procp->p_brand_data != NULL);
	ASSERT(l->lwp_brand == NULL);
	l->lwp_brand = (void *)-1;
	return (0);
}

/*ARGSUSED*/
void
brand_solaris_lwpexit(klwp_t *l, struct brand *pbrand)
{
	proc_t  *p = l->lwp_procp;

	ASSERT(l->lwp_procp->p_brand == pbrand);
	ASSERT(l->lwp_procp->p_brand_data != NULL);
	ASSERT(l->lwp_brand != NULL);

	/*
	 * We should never be called for the last thread in a process.
	 * (That case is handled by brand_solaris_proc_exit().)
	 * Therefore this lwp must be exiting from a multi-threaded
	 * process.
	 */
	ASSERT(p->p_tlist != p->p_tlist->t_forw);

	l->lwp_brand = NULL;
}

/*ARGSUSED*/
void
brand_solaris_proc_exit(struct proc *p, klwp_t *l, struct brand *pbrand)
{
	ASSERT(p->p_brand == pbrand);
	ASSERT(p->p_brand_data != NULL);

	/*
	 * When called from proc_exit(), we know that process is
	 * single-threaded and free our lwp brand data.
	 * otherwise just free p_brand_data and return.
	 */
	if (l != NULL) {
		ASSERT(p->p_tlist == p->p_tlist->t_forw);
		ASSERT(p->p_tlist->t_lwp == l);
		(void) brand_solaris_freelwp(l, pbrand);
	}

	/* upon exit, free our proc brand data */
	kmem_free(p->p_brand_data, sizeof (brand_proc_data_t));
	p->p_brand_data = NULL;
}

void
brand_solaris_setbrand(proc_t *p, struct brand *pbrand)
{
	ASSERT(p->p_brand == pbrand);
	ASSERT(p->p_brand_data == NULL);

	/*
	 * We should only be called from exec(), when we know the process
	 * is single-threaded.
	 */
	ASSERT(p->p_tlist == p->p_tlist->t_forw);

	p->p_brand_data = kmem_zalloc(sizeof (brand_proc_data_t), KM_SLEEP);
	(void) brand_solaris_initlwp(p->p_tlist->t_lwp, pbrand);
}
