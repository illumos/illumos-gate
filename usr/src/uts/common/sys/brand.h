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
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#ifndef _SYS_BRAND_H
#define	_SYS_BRAND_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/proc.h>
#include <sys/exec.h>
#include <sys/modctl.h>
#include <sys/types.h>

/*
 * All Brands supported by this kernel must use BRAND_VER_1.
 */
#define	BRAND_VER_1	1

/*
 * sub-commands to brandsys.
 * 1 - 128 are for common commands
 * 128+ are available for brand-specific commands.
 */
#define	B_REGISTER		1
#define	B_TTYMODES		2
#define	B_ELFDATA		3
#define	B_EXEC_NATIVE		4
#define	B_EXEC_BRAND		5
#define	B_TRUSS_POINT		6

/*
 * Structure used by zoneadmd to communicate the name of a brand and the
 * supporting brand module into the kernel.
 */
struct brand_attr {
	char	ba_brandname[MAXNAMELEN];
	char	ba_modname[MAXPATHLEN];
};

/* What we call the native brand. */
#define	NATIVE_BRAND_NAME	"native"

/* What we call the labeled brand. */
#define	LABELED_BRAND_NAME	"labeled"

/*
 * Aux vector containing lddata pointer of brand library linkmap.
 * Used by common {brand}_librtld_db.
 */
#define	AT_SUN_BRAND_COMMON_LDDATA	AT_SUN_BRAND_AUX1

/*
 * Information needed by the brand library to launch an executable.
 */
typedef struct brand_elf_data {
	ulong_t		sed_phdr;
	ulong_t		sed_phent;
	ulong_t		sed_phnum;
	ulong_t		sed_entry;
	ulong_t		sed_base;
	ulong_t		sed_ldentry;
	ulong_t		sed_lddata;
} brand_elf_data_t;

/*
 * Common structure used to register a branded processes
 */
typedef struct brand_proc_reg {
	uint_t		sbr_version;	/* version number */
	caddr_t		sbr_handler;	/* base address of handler */
} brand_proc_reg_t;

#ifdef	_KERNEL

struct proc;
struct uarg;
struct brand_mach_ops;
struct intpdata;
struct execa;

struct brand_ops {
	void	(*b_init_brand_data)(zone_t *);
	void	(*b_free_brand_data)(zone_t *);
	int	(*b_brandsys)(int, int64_t *, uintptr_t, uintptr_t, uintptr_t,
		uintptr_t, uintptr_t);
	void	(*b_setbrand)(struct proc *);
	int	(*b_getattr)(zone_t *, int, void *, size_t *);
	int	(*b_setattr)(zone_t *, int, void *, size_t);
	void	(*b_copy_procdata)(struct proc *, struct proc *);
	void	(*b_proc_exit)(struct proc *, klwp_t *);
	void	(*b_exec)();
	void	(*b_lwp_setrval)(klwp_t *, int, int);
	int	(*b_initlwp)(klwp_t *);
	void	(*b_forklwp)(klwp_t *, klwp_t *);
	void	(*b_freelwp)(klwp_t *);
	void	(*b_lwpexit)(klwp_t *);
	int	(*b_elfexec)(struct vnode *vp, struct execa *uap,
	    struct uarg *args, struct intpdata *idata, int level,
	    long *execsz, int setid, caddr_t exec_file,
	    struct cred *cred, int brand_action);
	void	(*b_sigset_native_to_brand)(sigset_t *);
	void	(*b_sigset_brand_to_native)(sigset_t *);
	void	(*b_psig_to_proc)(proc_t *, kthread_t *, int);
	int	b_nsig;
	void	(*b_exit_with_sig)(proc_t *, sigqueue_t *, void *);
	boolean_t (*b_wait_filter)(proc_t *, proc_t *);
	boolean_t (*b_native_exec)(uint8_t, const char **);
	void (*b_ptrace_exectrap)(proc_t *);
	uint32_t (*b_map32limit)(proc_t *);
};

/*
 * The b_version field must always be the first entry in this struct.
 */
typedef struct brand {
	int			b_version;
	char    		*b_name;
	struct brand_ops	*b_ops;
	struct brand_mach_ops	*b_machops;
	size_t			b_data_size;
} brand_t;

extern brand_t native_brand;

/*
 * Convenience macros
 */
#define	lwptolwpbrand(l)	((l)->lwp_brand)
#define	ttolwpbrand(t)		(lwptolwpbrand(ttolwp(t)))
#define	PROC_IS_BRANDED(p)	((p)->p_brand != &native_brand)
#define	ZONE_IS_BRANDED(z)	((z)->zone_brand != &native_brand)
#define	BROP(p)			((p)->p_brand->b_ops)
#define	ZBROP(z)		((z)->zone_brand->b_ops)
#define	BRMOP(p)		((p)->p_brand->b_machops)
#define	SIGSET_NATIVE_TO_BRAND(sigset)				\
	if (PROC_IS_BRANDED(curproc) &&				\
	    BROP(curproc)->b_sigset_native_to_brand)		\
		BROP(curproc)->b_sigset_native_to_brand(sigset)
#define	SIGSET_BRAND_TO_NATIVE(sigset)				\
	if (PROC_IS_BRANDED(curproc) &&				\
	    BROP(curproc)->b_sigset_brand_to_native)		\
		BROP(curproc)->b_sigset_brand_to_native(sigset)

extern void	brand_init();
extern int	brand_register(brand_t *);
extern int	brand_unregister(brand_t *);
extern brand_t	*brand_register_zone(struct brand_attr *);
extern brand_t	*brand_find_name(char *);
extern void	brand_unregister_zone(brand_t *);
extern int	brand_zone_count(brand_t *);
extern void	brand_setbrand(proc_t *);
extern void	brand_clearbrand(proc_t *, boolean_t);

/*
 * The following functions can be shared among kernel brand modules which
 * implement Solaris-derived brands, all of which need to do similar tasks to
 * manage the brand.
 */
extern int	brand_solaris_cmd(int, uintptr_t, uintptr_t, uintptr_t,
		    struct brand *, int);
extern void	brand_solaris_copy_procdata(proc_t *, proc_t *,
		    struct brand *);
extern int	brand_solaris_elfexec(vnode_t *, execa_t *, uarg_t *,
		    intpdata_t *, int, long *, int, caddr_t, cred_t *, int,
		    struct brand *, char *, char *, char *);
extern void	brand_solaris_exec(struct brand *);
extern int	brand_solaris_fini(char **, struct modlinkage *,
		    struct brand *);
extern void	brand_solaris_forklwp(klwp_t *, klwp_t *, struct brand *);
extern void	brand_solaris_freelwp(klwp_t *, struct brand *);
extern int	brand_solaris_initlwp(klwp_t *, struct brand *);
extern void	brand_solaris_lwpexit(klwp_t *, struct brand *);
extern void	brand_solaris_proc_exit(struct proc *, klwp_t *,
		    struct brand *);
extern void	brand_solaris_setbrand(proc_t *, struct brand *);

#if defined(_SYSCALL32)
typedef struct brand_elf_data32 {
	uint32_t	sed_phdr;
	uint32_t	sed_phent;
	uint32_t	sed_phnum;
	uint32_t	sed_entry;
	uint32_t	sed_base;
	uint32_t	sed_ldentry;
	uint32_t	sed_lddata;
} brand_elf_data32_t;

typedef struct brand_common_reg32 {
	uint32_t	sbr_version;	/* version number */
	caddr32_t	sbr_handler;	/* base address of handler */
} brand_common_reg32_t;
#endif /* _SYSCALL32 */

/*
 * Common information associated with all branded processes
 */
typedef struct brand_proc_data {
	caddr_t		spd_handler;	/* address of user-space handler */
	brand_elf_data_t spd_elf_data;	/* common ELF data for branded app. */
} brand_proc_data_t;

#define	BRAND_NATIVE_DIR	"/.SUNWnative/"
#define	BRAND_NATIVE_LINKER32	BRAND_NATIVE_DIR "lib/ld.so.1"
#define	BRAND_NATIVE_LINKER64	BRAND_NATIVE_DIR "lib/64/ld.so.1"

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BRAND_H */
