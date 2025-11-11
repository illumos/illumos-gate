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
 */

#ifndef _KMDB_MODULE_H
#define	_KMDB_MODULE_H

#include <sys/modctl.h>
#include <sys/kobj.h>

#include <mdb/mdb_gelf.h>
#include <mdb/mdb_module.h>
#include <kmdb/kmdb_wr_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	KMDB_MC_STATE_LOADING	1
#define	KMDB_MC_STATE_LOADED	2
#define	KMDB_MC_STATE_UNLOADING	3

#define	KMDB_MC_FL_NOUNLOAD	0x1

/*
 * The mdb_module_t describes the runtime attributes of dmods - things that
 * matter after the dmod has been loaded.  kmdb needs to track information about
 * modules before they've been loaded, and while they're in the process of
 * being unloaded.  As such, a kmdb_modctl_t is created for each module when the
 * load is requested, and isn't destroyed until the module has completed
 * unloading.
 *
 * This description reflects the sequence of events that occur during the
 * successful loading and unloading of a dmod.
 *
 * 1. Debugger requests a dmod load.
 *
 *    A kmdb_modctl_t is allocated.  kmc_state is set to KMDB_MC_STATE_LOADING.
 *
 * 2. The driver reports the successful loading of the dmod.
 *
 *    kmc_state is set to KMDB_MC_STATE_LOADED, and an mdb_module_t is created
 *    by mdb_module_create.
 *
 * 3. Debugger requests a dmod unload.
 *
 *    The mdb_module_t is destroyed, and kmc_state is set to
 *    KMDB_MC_STATE_UNLOADING.
 *
 * 4. The driver reports the successful unloading of the dmod.
 *
 *    The kmdb_modctl_t is destroyed.
 */
typedef struct kmdb_modctl {
	mdb_module_t *kmc_mod;		/* common dmod state */
	struct modctl *kmc_modctl;	/* kernel's modctl for this dmod */
	int kmc_exported;		/* KOBJ_EXPORTED set when last seen? */
	char *kmc_modname;		/* name of this dmod */
	ushort_t kmc_loadmode;		/* MDB_MOD_* from load request */
	ushort_t kmc_flags;		/* KMDB_MC_FL_* (above) */
	int kmc_dlrefcnt;		/* Counts dlopens/dlcloses */
	int kmc_state;			/* KMDB_MC_STATE_* (above) */
	mdb_gelf_symtab_t *kmc_symtab;	/* This dmod's symbol table */
	GElf_Ehdr kmc_ehdr;		/* Copy of ehdr in gelf format */
} kmdb_modctl_t;

extern boolean_t kmdb_module_loaded(kmdb_wr_load_t *);
extern void kmdb_module_load_ack(kmdb_wr_load_t *);
extern void kmdb_module_load_all_ack(kmdb_wr_t *);
extern boolean_t kmdb_module_unloaded(kmdb_wr_unload_t *);
extern void kmdb_module_unload_ack(kmdb_wr_unload_t *);

extern void kmdb_module_path_set(const char **, size_t);
extern void kmdb_module_path_ack(kmdb_wr_path_t *);

extern int kmdb_module_lookup_by_addr(uintptr_t, uint_t, char *, size_t,
    GElf_Sym *, mdb_syminfo_t *);
extern int kmdb_module_lookup_by_name(const char *, const char *, GElf_Sym *,
    mdb_syminfo_t *);
extern ctf_file_t *kmdb_module_addr_to_ctf(uintptr_t);
extern ctf_file_t *kmdb_module_name_to_ctf(const char *);
extern int kmdb_module_symbol_iter(const char *, uint_t, mdb_tgt_sym_f *,
    void *);
extern void kmdb_module_sync(void);

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_MODULE_H */
