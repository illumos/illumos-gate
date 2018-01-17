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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _KVM_H
#define	_KVM_H

/*
 * The kmdb target
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_target.h>
#include <kmdb/kmdb_dpi.h>
#include <kmdb/kvm_isadep.h>

#include <sys/kobj.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	KM_F_PRIMARY		1

#define	KMT_TRAP_NOTENUM	-1	/* Glob for unnamed traps */
#define	KMT_TRAP_ALL		-2	/* Glob for all traps */

typedef struct kmt_module {
	mdb_list_t	km_list;	/* List forward/back pointers */
	char		*km_name;	/* Module name */
	char		km_seen;
	GElf_Ehdr	km_ehdr;

	mdb_gelf_symtab_t *km_symtab;
	Shdr		km_symtab_hdr;
	Shdr		km_strtab_hdr;
	const void	*km_symtab_va;
	const void	*km_strtab_va;

	uintptr_t	km_text_va;
	size_t		km_text_size;
	uintptr_t	km_data_va;
	size_t		km_data_size;
	uintptr_t	km_bss_va;
	size_t		km_bss_size;
	const void	*km_ctf_va;
	size_t		km_ctf_size;

	ctf_file_t	*km_ctfp;
	struct modctl	km_modctl;
	struct module	km_module;
	int		km_flags;
} kmt_module_t;

typedef struct kmt_data {
	const mdb_tgt_regdesc_t	*kmt_rds;	/* Register description table */
	mdb_nv_t	kmt_modules;		/* Hash table of modules */
	mdb_list_t	kmt_modlist;		/* List of mods in load order */
	const char	*kmt_rtld_name;		/* Module containing krtld */
	caddr_t		kmt_writemap;		/* Used to map PAs for writes */
	size_t		kmt_writemapsz;		/* Size of same */
	mdb_map_t	kmt_map;		/* Persistant map for callers */
	ulong_t		*kmt_trapmap;
	size_t		kmt_trapmax;
	int		kmt_symavail;		/* Symbol resolution allowed */
	uint_t		kmt_narmedbpts;		/* Number of armed brkpts */
#if defined(__i386) || defined(__amd64)
	struct {
		GElf_Sym	_kmt_cmnint;
		GElf_Sym	_kmt_cmntrap;
		GElf_Sym	_kmt_sysenter;
		GElf_Sym	_kmt_brand_sysenter;
#if defined(__amd64)
		GElf_Sym	_kmt_syscall;
		GElf_Sym	_kmt_brand_syscall;
#endif
	} kmt_intrsyms;
#endif
} kmt_data_t;

#if defined(__i386) || defined(__amd64)
#define	kmt_cmnint	kmt_intrsyms._kmt_cmnint
#define	kmt_cmntrap	kmt_intrsyms._kmt_cmntrap
#endif

typedef struct kmt_defbp {
	mdb_list_t dbp_bplist;
	char *dbp_objname;
	char *dbp_symname;
	int dbp_ref;
} kmt_defbp_t;

typedef struct kmt_brkpt {
	uintptr_t kb_addr;			/* Breakpoint address */
	mdb_instr_t kb_oinstr;			/* Replaced instruction */
} kmt_brkpt_t;

typedef struct kmt_bparg {
	uintptr_t ka_addr;			/* Explicit address */
	char *ka_symbol;			/* Symbolic name */
	kmt_defbp_t *ka_defbp;
} kmt_bparg_t;

extern void kmt_printregs(const mdb_tgt_gregset_t *gregs);

extern const char *kmt_def_dismode(void);

extern void kmt_init_isadep(mdb_tgt_t *);
extern void kmt_startup_isadep(mdb_tgt_t *);

extern ssize_t kmt_write(mdb_tgt_t *, const void *, size_t, uintptr_t);
extern ssize_t kmt_pwrite(mdb_tgt_t *, const void *, size_t, physaddr_t);
extern ssize_t kmt_rw(mdb_tgt_t *, void *, size_t, uint64_t,
    ssize_t (*)(void *, size_t, uint64_t));
extern ssize_t kmt_writer(void *, size_t, uint64_t);
extern ssize_t kmt_ioread(mdb_tgt_t *, void *, size_t, uintptr_t);
extern ssize_t kmt_iowrite(mdb_tgt_t *, const void *, size_t, uintptr_t);

extern int kmt_step_out(mdb_tgt_t *, uintptr_t *);
extern int kmt_next(mdb_tgt_t *, uintptr_t *);

extern int kmt_stack(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kmt_stackv(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kmt_stackr(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kmt_cpustack(uintptr_t, uint_t, int, const mdb_arg_t *, int, int);

extern const char *kmt_trapname(int);

#ifdef __cplusplus
}
#endif

#endif /* _KVM_H */
