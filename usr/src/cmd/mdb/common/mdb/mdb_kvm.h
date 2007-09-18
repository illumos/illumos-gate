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
 */

#ifndef	_MDB_KVM_H
#define	_MDB_KVM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/machelf.h>
#include <sys/dumphdr.h>
#include <libctf.h>
#include <kvm.h>

#include <mdb/mdb_target.h>
#include <mdb/mdb_list.h>
#include <mdb/mdb_gelf.h>
#include <mdb/mdb_kb.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

typedef struct kt_module {
	mdb_list_t km_list;		/* List forward/back pointers */
	char *km_name;			/* Module name */
	void *km_data;			/* Data buffer (module->symspace) */
	size_t km_datasz;		/* Size of km_data in bytes */
	void *km_symbuf;		/* Base of symbol table in km_data */
	char *km_strtab;		/* Base of string table in km_data */
	mdb_gelf_symtab_t *km_symtab;	/* Symbol table for module */
	uintptr_t km_symspace_va;	/* Kernel VA of krtld symspace */
	uintptr_t km_symtab_va;		/* Kernel VA of krtld symtab */
	uintptr_t km_strtab_va;		/* Kernel VA of krtld strtab */
	Shdr km_symtab_hdr;		/* Native .symtab section header */
	Shdr km_strtab_hdr;		/* Native .strtab section header */
	uintptr_t km_text_va;		/* Kernel VA of start of module text */
	size_t km_text_size;		/* Size of module text */
	uintptr_t km_data_va;		/* Kernel VA of start of module data */
	size_t km_data_size;		/* Size of module data */
	uintptr_t km_bss_va;		/* Kernel VA of start of module BSS */
	size_t km_bss_size;		/* Size of module BSS */
	uintptr_t km_ctf_va;		/* Kernel VA of CTF data */
	size_t km_ctf_size;		/* Size of CTF data */
	void *km_ctf_buf;		/* CTF data for this module */
	ctf_file_t *km_ctfp;		/* CTF container for this module */
} kt_module_t;

typedef struct kt_data {
	mdb_kb_ops_t *k_kb_ops;		/* KVM backend ops */
	void (*k_dump_print_content)();	/* mdb_ks dump_print_content routine */
	int (*k_dump_find_curproc)();	/* mdb_ks dump_find_curproc routine */
	char *k_symfile;		/* Symbol table pathname */
	char *k_kvmfile;		/* Core file pathname */
	int k_xpv_domu;			/* Hypervisor domain dump? */
	const char *k_rtld_name;	/* module containing krtld */
	mdb_map_t k_map;		/* Persistant map for callers */
	void *k_cookie;			/* Cookie for libkvm routines */
	struct as *k_as;		/* Kernel VA of kas struct */
	mdb_io_t *k_fio;		/* File i/o backend */
	mdb_gelf_file_t *k_file;	/* ELF file object */
	mdb_gelf_symtab_t *k_symtab;	/* Standard symbol table */
	mdb_gelf_symtab_t *k_dynsym;	/* Dynamic symbol table */
	mdb_nv_t k_modules;		/* Hash table of modules */
	mdb_list_t k_modlist;		/* List of modules in load order */
	char k_platform[MAXNAMELEN];	/* Platform string */
	const mdb_tgt_regdesc_t *k_rds;	/* Register description table */
	mdb_tgt_gregset_t *k_regs;	/* Representative register set */
	size_t k_regsize;		/* Size of k_regs in bytes */
	mdb_tgt_tid_t k_tid;		/* Pointer to representative thread */
	mdb_dcmd_f *k_dcmd_regs;	/* Dcmd to print registers */
	mdb_dcmd_f *k_dcmd_stack;	/* Dcmd to print stack trace */
	mdb_dcmd_f *k_dcmd_stackv;	/* Dcmd to print verbose stack trace */
	mdb_dcmd_f *k_dcmd_stackr;	/* Dcmd to print stack trace and regs */
	mdb_dcmd_f *k_dcmd_cpustack;	/* Dcmd to print CPU stack trace */
	mdb_dcmd_f *k_dcmd_cpuregs;	/* Dcmd to print CPU registers */
	GElf_Sym k_intr_sym;		/* Kernel locore cmnint symbol */
	GElf_Sym k_trap_sym;		/* Kernel locore cmntrap symbol */
	struct dumphdr *k_dumphdr;	/* Dump header for post-mortem */
	pid_t k_dumpcontent;		/* The pid(s) (if any) in the dump */
	int k_activated;		/* Set if kt_activate called */
	int k_ctfvalid;			/* Set if kernel has a CTF arena */
} kt_data_t;

/* values for k_dumpcontent */
#define	KT_DUMPCONTENT_KERNEL	0
#define	KT_DUMPCONTENT_INVALID	-1
#define	KT_DUMPCONTENT_ALL	-2

extern int kt_setflags(mdb_tgt_t *, int);
extern int kt_setcontext(mdb_tgt_t *, void *);

extern void kt_activate(mdb_tgt_t *);
extern void kt_deactivate(mdb_tgt_t *);
extern void kt_destroy(mdb_tgt_t *);

extern const char *kt_name(mdb_tgt_t *);
extern const char *kt_platform(mdb_tgt_t *);
extern int kt_uname(mdb_tgt_t *, struct utsname *);
extern int kt_dmodel(mdb_tgt_t *);

extern ssize_t kt_aread(mdb_tgt_t *, mdb_tgt_as_t,
    void *, size_t, mdb_tgt_addr_t);

extern ssize_t kt_awrite(mdb_tgt_t *, mdb_tgt_as_t,
    const void *, size_t, mdb_tgt_addr_t);

extern ssize_t kt_vread(mdb_tgt_t *, void *, size_t, uintptr_t);
extern ssize_t kt_vwrite(mdb_tgt_t *, const void *, size_t, uintptr_t);
extern ssize_t kt_pread(mdb_tgt_t *, void *, size_t, physaddr_t);
extern ssize_t kt_pwrite(mdb_tgt_t *, const void *, size_t, physaddr_t);
extern ssize_t kt_fread(mdb_tgt_t *, void *, size_t, uintptr_t);
extern ssize_t kt_fwrite(mdb_tgt_t *, const void *, size_t, uintptr_t);

extern int kt_vtop(mdb_tgt_t *, mdb_tgt_as_t, uintptr_t, physaddr_t *);

extern int kt_lookup_by_name(mdb_tgt_t *, const char *,
    const char *, GElf_Sym *, mdb_syminfo_t *);

extern int kt_lookup_by_addr(mdb_tgt_t *, uintptr_t,
    uint_t, char *, size_t, GElf_Sym *, mdb_syminfo_t *);

extern int kt_symbol_iter(mdb_tgt_t *, const char *, uint_t,
    uint_t, mdb_tgt_sym_f *, void *);

extern int kt_mapping_iter(mdb_tgt_t *, mdb_tgt_map_f *, void *);
extern int kt_object_iter(mdb_tgt_t *, mdb_tgt_map_f *, void *);

extern const mdb_map_t *kt_addr_to_map(mdb_tgt_t *, uintptr_t);
extern const mdb_map_t *kt_name_to_map(mdb_tgt_t *, const char *);

extern struct ctf_file *kt_addr_to_ctf(mdb_tgt_t *, uintptr_t);
extern struct ctf_file *kt_name_to_ctf(mdb_tgt_t *, const char *);

extern int kt_status(mdb_tgt_t *, mdb_tgt_status_t *);

#ifdef __sparc
extern void kt_sparcv9_init(mdb_tgt_t *);
extern void kt_sparcv7_init(mdb_tgt_t *);
#else	/* __sparc */
extern void kt_ia32_init(mdb_tgt_t *);
extern void kt_amd64_init(mdb_tgt_t *);
#endif	/* __sparc */

typedef int (*mdb_name_lookup_fcn_t)(const char *, GElf_Sym *);
typedef int (*mdb_addr_lookup_fcn_t)(uintptr_t, int, char *, size_t,
    GElf_Sym *);
extern void mdb_kvm_add_name_lookup(mdb_name_lookup_fcn_t);
extern void mdb_kvm_add_addr_lookup(mdb_addr_lookup_fcn_t);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_KVM_H */
