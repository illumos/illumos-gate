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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2018, Joyent, Inc.  All rights reserved.
 */

#ifndef	_MDB_TARGET_IMPL_H
#define	_MDB_TARGET_IMPL_H

#include <mdb/mdb_target.h>
#include <mdb/mdb_module.h>
#include <mdb/mdb_list.h>
#include <mdb/mdb_gelf.h>
#include <sys/auxv.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

/*
 * Target Operations
 *
 * This ops vector implements the set of primitives which can be used by the
 * debugger to interact with the target, and encompasses most of the calls
 * found in <mdb/mdb_target.h>.  The remainder of the target interface is
 * implemented by common code that invokes these primitives or manipulates
 * the common target structures directly.
 */

typedef struct mdb_tgt_ops {
	int (*t_setflags)(mdb_tgt_t *, int);
	int (*t_setcontext)(mdb_tgt_t *, void *);

	void (*t_activate)(mdb_tgt_t *);
	void (*t_deactivate)(mdb_tgt_t *);
	void (*t_periodic)(mdb_tgt_t *);
	void (*t_destroy)(mdb_tgt_t *);

	const char *(*t_name)(mdb_tgt_t *);
	const char *(*t_isa)(mdb_tgt_t *);
	const char *(*t_platform)(mdb_tgt_t *);
	int (*t_uname)(mdb_tgt_t *, struct utsname *);
	int (*t_dmodel)(mdb_tgt_t *);

	ssize_t (*t_aread)(mdb_tgt_t *,
	    mdb_tgt_as_t, void *, size_t, mdb_tgt_addr_t);

	ssize_t (*t_awrite)(mdb_tgt_t *,
	    mdb_tgt_as_t, const void *, size_t, mdb_tgt_addr_t);

	ssize_t (*t_vread)(mdb_tgt_t *, void *, size_t, uintptr_t);
	ssize_t (*t_vwrite)(mdb_tgt_t *, const void *, size_t, uintptr_t);
	ssize_t (*t_pread)(mdb_tgt_t *, void *, size_t, physaddr_t);
	ssize_t (*t_pwrite)(mdb_tgt_t *, const void *, size_t, physaddr_t);
	ssize_t (*t_fread)(mdb_tgt_t *, void *, size_t, uintptr_t);
	ssize_t (*t_fwrite)(mdb_tgt_t *, const void *, size_t, uintptr_t);
	ssize_t (*t_ioread)(mdb_tgt_t *, void *, size_t, uintptr_t);
	ssize_t (*t_iowrite)(mdb_tgt_t *, const void *, size_t, uintptr_t);

	int (*t_vtop)(mdb_tgt_t *, mdb_tgt_as_t, uintptr_t, physaddr_t *);

	int (*t_lookup_by_name)(mdb_tgt_t *,
	    const char *, const char *, GElf_Sym *, mdb_syminfo_t *);

	int (*t_lookup_by_addr)(mdb_tgt_t *,
	    uintptr_t, uint_t, char *, size_t, GElf_Sym *, mdb_syminfo_t *);

	int (*t_symbol_iter)(mdb_tgt_t *,
	    const char *, uint_t, uint_t, mdb_tgt_sym_f *, void *);

	int (*t_mapping_iter)(mdb_tgt_t *, mdb_tgt_map_f *, void *);
	int (*t_object_iter)(mdb_tgt_t *, mdb_tgt_map_f *, void *);

	const mdb_map_t *(*t_addr_to_map)(mdb_tgt_t *, uintptr_t);
	const mdb_map_t *(*t_name_to_map)(mdb_tgt_t *, const char *);
	struct ctf_file *(*t_addr_to_ctf)(mdb_tgt_t *, uintptr_t);
	struct ctf_file *(*t_name_to_ctf)(mdb_tgt_t *, const char *);

	int (*t_status)(mdb_tgt_t *, mdb_tgt_status_t *);
	int (*t_run)(mdb_tgt_t *, int, const struct mdb_arg *);
	int (*t_step)(mdb_tgt_t *, mdb_tgt_status_t *);
	int (*t_step_out)(mdb_tgt_t *, uintptr_t *);
	int (*t_next)(mdb_tgt_t *, uintptr_t *);
	int (*t_cont)(mdb_tgt_t *, mdb_tgt_status_t *);
	int (*t_signal)(mdb_tgt_t *, int);

	int (*t_add_vbrkpt)(mdb_tgt_t *, uintptr_t,
	    int, mdb_tgt_se_f *, void *);
	int (*t_add_sbrkpt)(mdb_tgt_t *, const char *,
	    int, mdb_tgt_se_f *, void *);

	int (*t_add_pwapt)(mdb_tgt_t *, physaddr_t, size_t, uint_t,
	    int, mdb_tgt_se_f *, void *);
	int (*t_add_vwapt)(mdb_tgt_t *, uintptr_t, size_t, uint_t,
	    int, mdb_tgt_se_f *, void *);
	int (*t_add_iowapt)(mdb_tgt_t *, uintptr_t, size_t, uint_t,
	    int, mdb_tgt_se_f *, void *);

	int (*t_add_sysenter)(mdb_tgt_t *, int, int, mdb_tgt_se_f *, void *);
	int (*t_add_sysexit)(mdb_tgt_t *, int, int, mdb_tgt_se_f *, void *);
	int (*t_add_signal)(mdb_tgt_t *, int, int, mdb_tgt_se_f *, void *);
	int (*t_add_fault)(mdb_tgt_t *, int, int, mdb_tgt_se_f *, void *);

	int (*t_getareg)(mdb_tgt_t *, mdb_tgt_tid_t, const char *,
	    mdb_tgt_reg_t *);
	int (*t_putareg)(mdb_tgt_t *, mdb_tgt_tid_t, const char *,
	    mdb_tgt_reg_t);

	int (*t_stack_iter)(mdb_tgt_t *, const mdb_tgt_gregset_t *,
	    mdb_tgt_stack_f *, void *);

	int (*t_auxv)(mdb_tgt_t *, const auxv_t **auxvp);
} mdb_tgt_ops_t;

/*
 * Software Event Specifiers
 *
 * The common target layer provides support for the management of software
 * event specifiers, used to describe conditions under which a live executing
 * target program instance will stop and transfer control back to the debugger.
 * Software event management design is discussed in more detail in mdb_target.c.
 */

struct mdb_sespec;			/* Software event specifier */
struct mdb_vespec;			/* Virtual event specifier */

typedef struct mdb_se_ops {
	int (*se_ctor)(mdb_tgt_t *, struct mdb_sespec *, void *);
	void (*se_dtor)(mdb_tgt_t *, struct mdb_sespec *);
	char *(*se_info)(mdb_tgt_t *, struct mdb_sespec *,
	    struct mdb_vespec *, mdb_tgt_spec_desc_t *, char *, size_t);
	int (*se_secmp)(mdb_tgt_t *, struct mdb_sespec *, void *);
	int (*se_vecmp)(mdb_tgt_t *, struct mdb_vespec *, void *);
	int (*se_arm)(mdb_tgt_t *, struct mdb_sespec *);
	int (*se_disarm)(mdb_tgt_t *, struct mdb_sespec *);
	int (*se_cont)(mdb_tgt_t *, struct mdb_sespec *, mdb_tgt_status_t *);
	int (*se_match)(mdb_tgt_t *, struct mdb_sespec *, mdb_tgt_status_t *);
} mdb_se_ops_t;

#define	T_SE_END	((void *)-1L)	/* Sentinel for end of t_matched list */

typedef struct mdb_sespec {
	mdb_list_t se_selist;		/* Sespec list forward/back pointers */
	mdb_list_t se_velist;		/* List of layered virtual specifiers */
	struct mdb_sespec *se_matched;	/* Pointer to next se on matched list */
	const mdb_se_ops_t *se_ops;	/* Pointer to ops vector */
	void *se_data;			/* Private storage for ops vector */
	uint_t se_refs;			/* Reference count */
	int se_state;			/* Event specifier state */
	int se_errno;			/* Last error code (if error state) */
} mdb_sespec_t;

typedef struct mdb_vespec {
	mdb_list_t ve_list;		/* Vespec list forward/back pointers */
	int ve_id;			/* Virtual event specifier ID (VID) */
	int ve_flags;			/* Flags (see mdb_target.h) */
	uint_t ve_refs;			/* Reference count */
	uint_t ve_hits;			/* Count of number of times matched */
	uint_t ve_limit;		/* Limit on number of times matched */
	mdb_sespec_t *ve_se;		/* Backpointer to sespec */
	mdb_tgt_se_f *ve_callback;	/* Callback for event owner */
	void *ve_data;			/* Private storage for callback */
	void *ve_args;			/* Arguments for sespec constructor */
	void (*ve_dtor)(struct mdb_vespec *); /* Destructor for ve_args */
} mdb_vespec_t;

/*
 * Xdata Descriptors
 *
 * Each external data item (xdata) exported by the target has a corresponding
 * descriptor associated with the target.  The descriptor provides the name
 * and description of the data, as well as the routine which is used to
 * retrieve the actual data or its size.
 */

typedef struct mdb_xdata {
	mdb_list_t xd_list;		/* Xdata list forward/back pointers */
	const char *xd_name;		/* Buffer name */
	const char *xd_desc;		/* Buffer description */
	ssize_t (*xd_copy)(mdb_tgt_t *, void *, size_t); /* Copy routine */
} mdb_xdata_t;

/*
 * Target Structure
 *
 * The target itself contains a few common data members, and then a pointer to
 * the underlying ops vector and its private storage pointer.  MDB can manage
 * multiple targets simultaneously, and the list of all constructed targets is
 * pointed to by the mdb_t structure.
 */

struct mdb_tgt {
	mdb_list_t t_tgtlist;		/* Target list forward/back pointers */
	mdb_list_t t_active;		/* List of active event specifiers */
	mdb_list_t t_idle;		/* List of inactive event specifiers */
	mdb_list_t t_xdlist;		/* List of xdata descriptors */
	mdb_module_t *t_module;		/* Backpointer to containing module */
	void *t_pshandle;		/* Proc service handle (if not tgt) */
	const mdb_tgt_ops_t *t_ops;	/* Pointer to target ops vector */
	void *t_data;			/* Private storage for implementation */
	mdb_tgt_status_t t_status;	/* Cached target status */
	mdb_sespec_t *t_matched;	/* List of matched event specifiers */
	uint_t t_flags;			/* Mode flags (see <mdb_target.h>) */
	uint_t t_vecnt;			/* Total number of vespecs */
	int t_vepos;			/* Sequence # for next vespec id > 0 */
	int t_veneg;			/* Sequence # for next vespec id < 0 */
};

/*
 * Special functions which targets can use to fill ops vector slots:
 */
extern long mdb_tgt_notsup();		/* Return -1, errno EMDB_TGTNOTSUP */
extern long mdb_tgt_hwnotsup();		/* return -1, errno EMDB_TGTHWNOTSUP */
extern void *mdb_tgt_null();		/* Return NULL, errno EMDB_TGTNOTSUP */
extern long mdb_tgt_nop();		/* Return 0 for success */

/*
 * Utility structures for target implementations:
 */
#define	MDB_TGT_R_PRIV		0x001	/* Privileged register */
#define	MDB_TGT_R_EXPORT	0x002	/* Export register as a variable */
#define	MDB_TGT_R_ALIAS		0x004	/* Alias for another register name */
#define	MDB_TGT_R_XREG		0x008	/* Extended register */
#define	MDB_TGT_R_FPS		0x010	/* Single-precision floating-point */
#define	MDB_TGT_R_FPD		0x020	/* Double-precision floating-point */
#define	MDB_TGT_R_FPQ		0x040	/* Quad-precision floating-point */
#define	MDB_TGT_R_FPU		0x080	/* FPU control/status register */
#define	MDB_TGT_R_RDONLY	0x100	/* Register is read-only */
#define	MDB_TGT_R_32		0x200	/* 32-bit version of register */
#define	MDB_TGT_R_16		0x400	/* 16-bit version of register */
#define	MDB_TGT_R_8H		0x800	/* upper half of a 16-bit reg */
#define	MDB_TGT_R_8L		0x1000	/* lower half of a 16-bit reg */

#define	MDB_TGT_R_IS_FP(f)	((f) & 0xf0) /* Test MDB_TGT_R_FP* bits */

#define	MDB_TGT_R_NVAL(n, f)	((((ulong_t)(n)) << 16UL) | (f))
#define	MDB_TGT_R_NUM(v)	(((v) >> 16) & 0xffff)
#define	MDB_TGT_R_FLAGS(v)	((v) & 0xffff)

typedef struct mdb_tgt_regdesc {
	const char *rd_name;		/* Register string name */
	ushort_t rd_num;		/* Register index number */
	ushort_t rd_flags;		/* Register flags (see above) */
} mdb_tgt_regdesc_t;

/*
 * Utility functions for target implementations to use in order to simplify
 * the implementation of various routines and to insert and delete xdata
 * specifiers and software event specifiers.  Refer to the associated comments
 * in mdb_target.c for more information about each function.
 */

extern int mdb_tgt_xdata_insert(mdb_tgt_t *, const char *, const char *,
	ssize_t (*)(mdb_tgt_t *, void *, size_t));

extern int mdb_tgt_xdata_delete(mdb_tgt_t *, const char *);

extern int mdb_tgt_sym_match(const GElf_Sym *, uint_t);
extern void mdb_tgt_elf_export(mdb_gelf_file_t *);

extern int mdb_tgt_sespec_activate_one(mdb_tgt_t *t, mdb_sespec_t *);
extern int mdb_tgt_sespec_activate_all(mdb_tgt_t *t);

extern void mdb_tgt_sespec_idle_one(mdb_tgt_t *t, mdb_sespec_t *, int);
extern void mdb_tgt_sespec_idle_all(mdb_tgt_t *t, int, int);

extern void mdb_tgt_sespec_arm_one(mdb_tgt_t *t, mdb_sespec_t *);
extern void mdb_tgt_sespec_arm_all(mdb_tgt_t *t);

extern void mdb_tgt_sespec_idle_one(mdb_tgt_t *t, mdb_sespec_t *, int);
extern void mdb_tgt_sespec_idle_all(mdb_tgt_t *t, int, int);

extern void mdb_tgt_sespec_prune_one(mdb_tgt_t *t, mdb_sespec_t *);
extern void mdb_tgt_sespec_prune_all(mdb_tgt_t *t);

extern mdb_sespec_t *mdb_tgt_sespec_insert(mdb_tgt_t *,
    const mdb_se_ops_t *, mdb_list_t *);

extern mdb_sespec_t *mdb_tgt_sespec_lookup_active(mdb_tgt_t *,
    const mdb_se_ops_t *, void *);

extern mdb_sespec_t *mdb_tgt_sespec_lookup_idle(mdb_tgt_t *,
    const mdb_se_ops_t *, void *);

extern void mdb_tgt_sespec_hold(mdb_tgt_t *, mdb_sespec_t *);
extern void mdb_tgt_sespec_rele(mdb_tgt_t *, mdb_sespec_t *);

extern void mdb_tgt_sespec_prune_one(mdb_tgt_t *t, mdb_sespec_t *);
extern void mdb_tgt_sespec_prune_all(mdb_tgt_t *t);

extern mdb_sespec_t *mdb_tgt_sespec_insert(mdb_tgt_t *,
    const mdb_se_ops_t *, mdb_list_t *);

extern mdb_sespec_t *mdb_tgt_sespec_lookup_active(mdb_tgt_t *,
    const mdb_se_ops_t *, void *);

extern mdb_sespec_t *mdb_tgt_sespec_lookup_idle(mdb_tgt_t *,
    const mdb_se_ops_t *, void *);

extern void mdb_tgt_sespec_hold(mdb_tgt_t *, mdb_sespec_t *);
extern void mdb_tgt_sespec_rele(mdb_tgt_t *, mdb_sespec_t *);

extern int mdb_tgt_vespec_insert(mdb_tgt_t *, const mdb_se_ops_t *,
    int, mdb_tgt_se_f *, void *, void *, void (*)(mdb_vespec_t *));

extern mdb_vespec_t *mdb_tgt_vespec_lookup(mdb_tgt_t *, int);

extern int mdb_tgt_auxv(mdb_tgt_t *, const auxv_t **);

extern void mdb_tgt_vespec_hold(mdb_tgt_t *, mdb_vespec_t *);
extern void mdb_tgt_vespec_rele(mdb_tgt_t *, mdb_vespec_t *);

/*
 * Utility function that target implementations can use to register dcmds,
 * walkers, and to create named variables for registers
 */
extern int mdb_tgt_register_dcmds(mdb_tgt_t *, const mdb_dcmd_t *, int);
extern int mdb_tgt_register_walkers(mdb_tgt_t *, const mdb_walker_t *, int);
extern void mdb_tgt_register_regvars(mdb_tgt_t *, const mdb_tgt_regdesc_t *,
    const mdb_nv_disc_t *, int);

/*
 * Utility functions that target implementations can use to fill in the
 * mdb_se_ops_t structure and vespec destructor.  Each software event specifier
 * must minimally supply its own constructor, info function, and match function.
 */

extern void no_ve_dtor(mdb_vespec_t *);
extern void no_se_dtor(mdb_tgt_t *, mdb_sespec_t *);

extern int no_se_secmp(mdb_tgt_t *, mdb_sespec_t *, void *);
extern int no_se_vecmp(mdb_tgt_t *, mdb_vespec_t *, void *);
extern int no_se_arm(mdb_tgt_t *, mdb_sespec_t *);
extern int no_se_disarm(mdb_tgt_t *, mdb_sespec_t *);
extern int no_se_cont(mdb_tgt_t *, mdb_sespec_t *, mdb_tgt_status_t *);

/*
 * In the initial version of MDB, the data model property is not part of the
 * public API.  However, I am providing this as a hidden part of the ABI as
 * one way we can handle the situation.  If this turns out to be the right
 * decision, we can document it later without having to rev the API version.
 */
#define	MDB_TGT_MODEL_UNKNOWN	0	/* Unknown data model */
#define	MDB_TGT_MODEL_ILP32	1	/* Target data model is ILP32 */
#define	MDB_TGT_MODEL_LP64	2	/* Target data model is LP64 */

#ifdef _LP64
#define	MDB_TGT_MODEL_NATIVE	MDB_TGT_MODEL_LP64
#else
#define	MDB_TGT_MODEL_NATIVE	MDB_TGT_MODEL_ILP32
#endif

extern int mdb_prop_datamodel;

#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_TARGET_IMPL_H */
