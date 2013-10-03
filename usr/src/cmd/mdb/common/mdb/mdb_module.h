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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */

/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */

#ifndef	_MDB_MODULE_H
#define	_MDB_MODULE_H

#include <mdb/mdb_argvec.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb_disasm.h>

#include <libctf.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

struct mdb_callb;

typedef struct mdb_module {
	mdb_nv_t mod_dcmds;		/* Module dcmds hash */
	mdb_nv_t mod_walkers;		/* Module walkers hash */
	const char *mod_name;		/* Module name */
	void *mod_hdl;			/* Module object handle */
	mdb_modinfo_t *mod_info;	/* Module information */
	const mdb_modinfo_t *(*mod_init)(void);	/* Module load callback */
	void (*mod_fini)(void);		/* Module unload callback */
	mdb_tgt_ctor_f *mod_tgt_ctor;	/* Module target constructor */
	mdb_dis_ctor_f *mod_dis_ctor;	/* Module disassembler constructor */
	struct mdb_module *mod_prev;	/* Previous module on dependency list */
	struct mdb_module *mod_next;	/* Next module on dependency list */
	ctf_file_t *mod_ctfp;		/* CTF container for this module */
	struct mdb_callb *mod_cb;	/* First callback for this module */
} mdb_module_t;

typedef struct mdb_idcmd {
	const char *idc_name;		/* Backpointer to variable name */
	const char *idc_usage;		/* Usage message */
	const char *idc_descr;		/* Description */
	mdb_dcmd_f *idc_funcp;		/* Command function */
	void (*idc_help)(void);		/* Help function */
	mdb_dcmd_tab_f *idc_tabp;	/* Tab completion pointer */
	mdb_module_t *idc_modp;		/* Backpointer to module */
	mdb_var_t *idc_var;		/* Backpointer to global variable */
} mdb_idcmd_t;

typedef struct mdb_iwalker {
	const char *iwlk_name;		/* Walk type name */
	char *iwlk_descr;		/* Walk description */
	int (*iwlk_init)(struct mdb_walk_state *);	/* Walk constructor */
	int (*iwlk_step)(struct mdb_walk_state *);	/* Walk iterator */
	void (*iwlk_fini)(struct mdb_walk_state *);	/* Walk destructor */
	void *iwlk_init_arg;		/* Walk constructor argument */
	mdb_module_t *iwlk_modp;	/* Backpointer to module */
	mdb_var_t *iwlk_var;		/* Backpointer to global variable */
} mdb_iwalker_t;

#define	MDB_MOD_LOCAL		0x00	/* Load module RTLD_LOCAL */
#define	MDB_MOD_GLOBAL		0x01	/* Load module RTLD_GLOBAL */
#define	MDB_MOD_SILENT		0x02	/* Remain silent if no module found */
#define	MDB_MOD_FORCE		0x04	/* Forcibly interpose module defs */
#define	MDB_MOD_BUILTIN		0x08	/* Module is compiled into debugger */
#define	MDB_MOD_DEFER		0x10	/* Defer load/unload (kmdb only) */

extern int mdb_module_load(const char *, int);
extern mdb_module_t *mdb_module_load_builtin(const char *);
extern void mdb_module_load_all(int);

extern int mdb_module_unload(const char *, int);
extern void mdb_module_unload_all(int);
extern int mdb_module_unload_common(const char *);

extern int mdb_module_add_dcmd(mdb_module_t *, const mdb_dcmd_t *, int);
extern int mdb_module_remove_dcmd(mdb_module_t *, const char *);

extern int mdb_module_add_walker(mdb_module_t *, const mdb_walker_t *, int);
extern int mdb_module_remove_walker(mdb_module_t *, const char *);

extern int mdb_module_create(const char *, const char *, int, mdb_module_t **);

extern int mdb_module_validate_name(const char *, const char **);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_MODULE_H */
