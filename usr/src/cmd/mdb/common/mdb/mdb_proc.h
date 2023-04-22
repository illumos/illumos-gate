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
 */

#ifndef	_MDB_PROC_H
#define	_MDB_PROC_H

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_addrvec.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_gelf.h>
#include <mdb/mdb_tdb.h>

#include <sys/param.h>
#include <libproc.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

/*
 * The proc target must provide support for examining multi-threaded processes
 * that use the raw LWP interface, as well as those that use either of the
 * existing libthread.so implementations.  We must also support multiple active
 * instances of the proc target, as well as the notion that a clean process
 * can dlopen() libthread after startup, at which point we need to switch to
 * using libthread_db interfaces to properly debug it.  To satisfy these
 * constraints, we declare an ops vector of functions for obtaining the
 * register sets of each thread.  The proc target will define two versions
 * of this vector, one for the LWP mode and one for the libthread_db mode,
 * and then switch the ops vector pointer as appropriate during debugging.
 * The macros defined below expand to calls to the appropriate entry point.
 */
typedef struct pt_ptl_ops {
	int (*ptl_ctor)(mdb_tgt_t *);
	void (*ptl_dtor)(mdb_tgt_t *, void *);
	mdb_tgt_tid_t (*ptl_tid)(mdb_tgt_t *, void *);
	int (*ptl_iter)(mdb_tgt_t *, void *, mdb_addrvec_t *);
	int (*ptl_getregs)(mdb_tgt_t *, void *, mdb_tgt_tid_t, prgregset_t);
	int (*ptl_setregs)(mdb_tgt_t *, void *, mdb_tgt_tid_t, prgregset_t);
	int (*ptl_getxregs)(mdb_tgt_t *, void *, mdb_tgt_tid_t,
	    prxregset_t **, size_t *);
	void (*ptl_freexregs)(mdb_tgt_t *, void *, prxregset_t *, size_t);
	int (*ptl_setxregs)(mdb_tgt_t *, void *, mdb_tgt_tid_t,
	    const prxregset_t *, size_t);
	int (*ptl_getfpregs)(mdb_tgt_t *, void *, mdb_tgt_tid_t,
	    prfpregset_t *);
	int (*ptl_setfpregs)(mdb_tgt_t *, void *, mdb_tgt_tid_t,
	    const prfpregset_t *);
} pt_ptl_ops_t;

#define	PTL_CTOR(t) \
	(((pt_data_t *)(t)->t_data)->p_ptl_ops->ptl_ctor(t))

#define	PTL_DTOR(t) \
	(((pt_data_t *)(t)->t_data)->p_ptl_ops->ptl_dtor((t), \
	((pt_data_t *)((t)->t_data))->p_ptl_hdl))

#define	PTL_TID(t) \
	(((pt_data_t *)((t)->t_data))->p_ptl_ops->ptl_tid((t), \
	((pt_data_t *)(t)->t_data)->p_ptl_hdl))

#define	PTL_ITER(t, ap) \
	(((pt_data_t *)(t)->t_data)->p_ptl_ops->ptl_iter((t), \
	((pt_data_t *)((t)->t_data))->p_ptl_hdl, (ap)))

#define	PTL_GETREGS(t, tid, gregs) \
	(((pt_data_t *)((t)->t_data))->p_ptl_ops->ptl_getregs((t), \
	((pt_data_t *)((t)->t_data))->p_ptl_hdl, (tid), (gregs)))

#define	PTL_SETREGS(t, tid, gregs) \
	(((pt_data_t *)((t)->t_data))->p_ptl_ops->ptl_setregs((t), \
	((pt_data_t *)((t)->t_data))->p_ptl_hdl, (tid), (gregs)))

#define	PTL_GETXREGS(t, tid, xregs, size) \
	(((pt_data_t *)((t)->t_data))->p_ptl_ops->ptl_getxregs((t), \
	((pt_data_t *)((t)->t_data))->p_ptl_hdl, (tid), (xregs), (size)))

#define	PTL_FREEXREGS(t, xregs, size) \
	(((pt_data_t *)((t)->t_data))->p_ptl_ops->ptl_freexregs((t), \
	((pt_data_t *)((t)->t_data))->p_ptl_hdl, (xregs), (size)))

#define	PTL_SETXREGS(t, tid, xregs, size) \
	(((pt_data_t *)((t)->t_data))->p_ptl_ops->ptl_setxregs((t), \
	((pt_data_t *)((t)->t_data))->p_ptl_hdl, (tid), (xregs), (size)))

#define	PTL_GETFPREGS(t, tid, fpregs) \
	(((pt_data_t *)((t)->t_data))->p_ptl_ops->ptl_getfpregs((t), \
	((pt_data_t *)((t)->t_data))->p_ptl_hdl, (tid), (fpregs)))

#define	PTL_SETFPREGS(t, tid, fpregs) \
	(((pt_data_t *)((t)->t_data))->p_ptl_ops->ptl_setfpregs((t), \
	((pt_data_t *)((t)->t_data))->p_ptl_hdl, (tid), (fpregs)))

/*
 * When we are following children and a vfork(2) occurs, we append the libproc
 * handle for the parent to a list of vfork parents.  We need to keep track of
 * this handle so that when the child subsequently execs or dies, we clear out
 * our breakpoints before releasing the parent.
 */
typedef struct pt_vforkp {
	mdb_list_t p_list;			/* List forward/back pointers */
	struct ps_prochandle *p_pshandle;	/* libproc handle */
} pt_vforkp_t;

/*
 * Private data structure for the proc target.  Among other things, we keep
 * pointers to the various symbol tables and the ELF file for the executable
 * here, along with handles for our ops vector defined above.
 */
typedef struct pt_data {
	struct ps_prochandle *p_idlehandle;	/* idle libproc handle */
	mdb_gelf_symtab_t *p_symtab;		/* Standard symbol table */
	mdb_gelf_symtab_t *p_dynsym;		/* Dynamic symbol table */
	mdb_gelf_file_t *p_file;		/* ELF file object */
	mdb_io_t *p_fio;			/* Current file i/o backend */
	mdb_io_t *p_aout_fio;			/* Original file i/o backend */
	char p_platform[MAXNAMELEN];		/* Platform string */
	char p_symname[MDB_TGT_SYM_NAMLEN];	/* Temporary buffer for syms */
	char p_objname[MDB_TGT_MAPSZ];		/* Temporary buffer for objs */
	mdb_map_t p_map;			/* Persistent map for callers */
	mdb_list_t p_vforkp;			/* List of vfork parents */
	mdb_nv_t p_regs;			/* Register descriptions */
	const mdb_tdb_ops_t *p_tdb_ops;		/* libthread_db ops */
	const pt_ptl_ops_t *p_ptl_ops;		/* Proc thread layer ops */
	void *p_ptl_hdl;			/* Proc thread layer handle */
	rd_agent_t *p_rtld;			/* librtld_db agent handle */
	const char *p_stdin;			/* File for stdin redirect */
	const char *p_stdout;			/* File for stdout redirect */
	int p_oflags;				/* Flags for open(2) */
	int p_gflags;				/* Flags for Pgrab() */
	int p_rflags;				/* Flags for Prelease() */
	int p_signal;				/* Signal to post at next run */
	int p_rtld_finished;			/* Has rtld init completed? */
	int p_rdstate;				/* Dlopen state (see below) */
	int p_maxsig;				/* Maximum valid signal */
	mdb_nv_t p_env;				/* Current environment */
} pt_data_t;

#define	PT_RD_NONE	0			/* No update pending */
#define	PT_RD_ADD	1			/* Dlopen detected */
#define	PT_RD_CONSIST	2			/* Link maps consistent */

/*
 * The mdb_tgt_gregset type is opaque to callers of the target interface.
 * Inside the target we define it explicitly to be a prgregset_t.
 */
struct mdb_tgt_gregset {
	prgregset_t gregs;
};

typedef struct pt_symarg {
	mdb_tgt_t *psym_targ;			/* Target pointer */
	uint_t psym_which;			/* Type of symbol table */
	uint_t psym_type;			/* Type of symbols to match */
	mdb_tgt_sym_f *psym_func;		/* Callback function */
	void *psym_private;			/* Callback data */
	mdb_syminfo_t psym_info;		/* Symbol id and table id */
	const char *psym_obj;			/* Containing object */
} pt_symarg_t;

typedef struct pt_maparg {
	mdb_tgt_t *pmap_targ;			/* Target pointer */
	mdb_tgt_map_f *pmap_func;		/* Callback function */
	void *pmap_private;			/* Callback data */
} pt_maparg_t;

typedef struct pt_stkarg {
	mdb_tgt_stack_f *pstk_func;		/* Callback function */
	void *pstk_private;			/* Callback data */
	uint_t pstk_gotpc;			/* Non-zero pc found */
} pt_stkarg_t;

typedef struct pt_addarg_t {
	pt_data_t *pa_pt;			/* Proc target data */
	mdb_addrvec_t *pa_ap;			/* Addrvec pointer */
} pt_addarg_t;

typedef struct pt_brkpt {
	uintptr_t ptb_addr;			/* Breakpoint address */
	ulong_t ptb_instr;			/* Saved instruction */
} pt_brkpt_t;

typedef struct pt_bparg {
	char *pta_symbol;			/* Symbolic name */
	uintptr_t pta_addr;			/* Explicit address */
} pt_bparg_t;

/*
 * The proc_isadep.c file is expected to define the following
 * ISA-dependent pieces of the proc target:
 */
extern int pt_regs(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int pt_fpregs(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int pt_step_out(mdb_tgt_t *, uintptr_t *);
extern int pt_next(mdb_tgt_t *, uintptr_t *);
extern int pt_getfpreg(mdb_tgt_t *, mdb_tgt_tid_t, ushort_t, ushort_t,
    mdb_tgt_reg_t *);
extern int pt_putfpreg(mdb_tgt_t *, mdb_tgt_tid_t, ushort_t, ushort_t,
    mdb_tgt_reg_t);
extern void pt_addfpregs(mdb_tgt_t *);
extern const char *pt_disasm(const GElf_Ehdr *);
extern int pt_frameregs(void *, uintptr_t, uint_t, const long *,
    const mdb_tgt_gregset_t *, boolean_t);
extern const mdb_tgt_regdesc_t pt_regdesc[];

#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_PROC_H */
