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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MDB_TARGET_H
#define	_MDB_TARGET_H

#include <sys/utsname.h>
#include <sys/types.h>
#include <gelf.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Forward declaration of the target structure: the target itself is defined in
 * mdb_tgt_impl.h and is opaque with respect to callers of this interface.
 */

struct mdb_tgt;
struct mdb_arg;
struct ctf_file;

typedef struct mdb_tgt mdb_tgt_t;

extern void mdb_create_builtin_tgts(void);
extern void mdb_create_loadable_disasms(void);

/*
 * Target Constructors
 *
 * These functions are used to create a complete debugger target.  The
 * constructor is passed as an argument to mdb_tgt_create().
 */

extern int mdb_value_tgt_create(mdb_tgt_t *, int, const char *[]);
#ifndef _KMDB
extern int mdb_kvm_tgt_create(mdb_tgt_t *, int, const char *[]);
extern int mdb_proc_tgt_create(mdb_tgt_t *, int, const char *[]);
extern int mdb_kproc_tgt_create(mdb_tgt_t *, int, const char *[]);
extern int mdb_rawfile_tgt_create(mdb_tgt_t *, int, const char *[]);
#else
extern int kmdb_kvm_create(mdb_tgt_t *, int, const char *[]);
#endif

/*
 * Targets are created by calling mdb_tgt_create() with an optional set of
 * target flags, an argument list, and a target constructor (see above):
 */

#define	MDB_TGT_F_RDWR		0x0001	/* Open for writing (else read-only) */
#define	MDB_TGT_F_ALLOWIO	0x0002	/* Allow I/O mem access (live only) */
#define	MDB_TGT_F_FORCE		0x0004	/* Force open (even if non-exclusive) */
#define	MDB_TGT_F_PRELOAD	0x0008	/* Preload all symbol tables */
#define	MDB_TGT_F_NOLOAD	0x0010	/* Do not do load-object processing */
#define	MDB_TGT_F_NOSTOP	0x0020	/* Do not stop target on attach */
#define	MDB_TGT_F_STEP		0x0040	/* Single-step is pending */
#define	MDB_TGT_F_STEP_OUT	0x0080	/* Step-out is pending */
#define	MDB_TGT_F_STEP_BRANCH	0x0100	/* Step-branch is pending */
#define	MDB_TGT_F_NEXT		0x0200	/* Step-over is pending */
#define	MDB_TGT_F_CONT		0x0400	/* Continue is pending */
#define	MDB_TGT_F_BUSY		0x0800	/* Target is busy executing */
#define	MDB_TGT_F_ASIO		0x1000	/* Use t_aread and t_awrite for i/o */
#define	MDB_TGT_F_UNLOAD	0x2000	/* Unload has been requested */
#define	MDB_TGT_F_ALL		0x3fff	/* Mask of all valid flags */

typedef int mdb_tgt_ctor_f(mdb_tgt_t *, int, const char *[]);

extern mdb_tgt_t *mdb_tgt_create(mdb_tgt_ctor_f *, int, int, const char *[]);
extern void mdb_tgt_destroy(mdb_tgt_t *);

extern int mdb_tgt_getflags(mdb_tgt_t *);
extern int mdb_tgt_setflags(mdb_tgt_t *, int);
extern int mdb_tgt_setcontext(mdb_tgt_t *, void *);

/*
 * Targets are activated and de-activated by the debugger framework.  An
 * activation occurs after construction when the target becomes the current
 * target in the debugger.  A target is de-activated prior to its destructor
 * being called by mdb_tgt_destroy, or when another target is activated.
 * These callbacks are suitable for loading support modules and other tasks.
 */
extern void mdb_tgt_activate(mdb_tgt_t *);

/*
 * Prior to issuing a new command prompt, the debugger framework calls the
 * target's periodic callback to allow it to load new modules or perform
 * other background tasks.
 */
extern void mdb_tgt_periodic(mdb_tgt_t *);

/*
 * Convenience functions for accessing miscellaneous target information.
 */
extern const char *mdb_tgt_name(mdb_tgt_t *);
extern const char *mdb_tgt_isa(mdb_tgt_t *);
extern const char *mdb_tgt_platform(mdb_tgt_t *);
extern int mdb_tgt_uname(mdb_tgt_t *, struct utsname *);
extern int mdb_tgt_dmodel(mdb_tgt_t *);

/*
 * Address Space Interface
 *
 * Each target can provide access to a set of address spaces, which may include
 * a primary virtual address space, a physical address space, an object file
 * address space (where virtual addresses are converted to file offsets in an
 * object file), and an I/O port address space.  Additionally, the target can
 * provide access to alternate address spaces, which are identified by the
 * opaque mdb_tgt_as_t type.  If the 'as' parameter to mdb_tgt_aread or
 * mdb_tgt_awrite is one of the listed constants, these calls are equivalent
 * to mdb_tgt_{v|p|f|io}read or write.
 */

typedef void *		mdb_tgt_as_t;		/* Opaque address space id */
typedef uint64_t	mdb_tgt_addr_t;		/* Generic unsigned address */
typedef uint64_t	physaddr_t;		/* Physical memory address */

#define	MDB_TGT_AS_VIRT	((mdb_tgt_as_t)-1L)	/* Virtual address space */
#define	MDB_TGT_AS_PHYS	((mdb_tgt_as_t)-2L)	/* Physical address space */
#define	MDB_TGT_AS_FILE	((mdb_tgt_as_t)-3L)	/* Object file address space */
#define	MDB_TGT_AS_IO	((mdb_tgt_as_t)-4L)	/* I/o address space */

extern ssize_t mdb_tgt_aread(mdb_tgt_t *, mdb_tgt_as_t,
	void *, size_t, mdb_tgt_addr_t);

extern ssize_t mdb_tgt_awrite(mdb_tgt_t *, mdb_tgt_as_t,
	const void *, size_t, mdb_tgt_addr_t);

extern ssize_t mdb_tgt_vread(mdb_tgt_t *, void *, size_t, uintptr_t);
extern ssize_t mdb_tgt_vwrite(mdb_tgt_t *, const void *, size_t, uintptr_t);
extern ssize_t mdb_tgt_pread(mdb_tgt_t *, void *, size_t, physaddr_t);
extern ssize_t mdb_tgt_pwrite(mdb_tgt_t *, const void *, size_t, physaddr_t);
extern ssize_t mdb_tgt_fread(mdb_tgt_t *, void *, size_t, uintptr_t);
extern ssize_t mdb_tgt_fwrite(mdb_tgt_t *, const void *, size_t, uintptr_t);
extern ssize_t mdb_tgt_ioread(mdb_tgt_t *, void *, size_t, uintptr_t);
extern ssize_t mdb_tgt_iowrite(mdb_tgt_t *, const void *, size_t, uintptr_t);

/*
 * Convert an address-space's virtual address to the corresponding
 * physical address (only useful for kernel targets):
 */
extern int mdb_tgt_vtop(mdb_tgt_t *, mdb_tgt_as_t, uintptr_t, physaddr_t *);

/*
 * Convenience functions for reading and writing null-terminated
 * strings from any of the target address spaces:
 */
extern ssize_t mdb_tgt_readstr(mdb_tgt_t *, mdb_tgt_as_t,
	char *, size_t, mdb_tgt_addr_t);

extern ssize_t mdb_tgt_writestr(mdb_tgt_t *, mdb_tgt_as_t,
	const char *, mdb_tgt_addr_t);

/*
 * Symbol Table Interface
 *
 * Each target can provide access to one or more symbol tables, which can be
 * iterated over, or used to lookup symbols by either name or address.  The
 * target can support a primary executable and primary dynamic symbol table,
 * a symbol table for its run-time link-editor, and symbol tables for one or
 * more loaded objects.  A symbol is uniquely identified by an object name,
 * a symbol table id, and a symbol id.  Symbols can be discovered by iterating
 * over them, looking them up by name, or looking them up by address.
 */

typedef struct mdb_syminfo {
	uint_t sym_table;	/* Symbol table id (see symbol_iter, below) */
	uint_t sym_id;		/* Symbol identifier */
} mdb_syminfo_t;

/*
 * Reserved object names for mdb_tgt_lookup_by_name():
 */
#define	MDB_TGT_OBJ_EXEC	((const char *)0L)	/* Executable symbols */
#define	MDB_TGT_OBJ_RTLD	((const char *)1L)	/* Ldso/krtld symbols */
#define	MDB_TGT_OBJ_EVERY	((const char *)-1L)	/* All known symbols */

extern int mdb_tgt_lookup_by_scope(mdb_tgt_t *, const char *,
	GElf_Sym *, mdb_syminfo_t *);

extern int mdb_tgt_lookup_by_name(mdb_tgt_t *, const char *,
	const char *, GElf_Sym *, mdb_syminfo_t *);

/*
 * Flag bit passed to mdb_tgt_lookup_by_addr():
 */
#define	MDB_TGT_SYM_FUZZY	0	/* Match closest address */
#define	MDB_TGT_SYM_EXACT	1	/* Match exact address only */

#define	MDB_TGT_SYM_NAMLEN	1024	/* Recommended max symbol name length */

extern int mdb_tgt_lookup_by_addr(mdb_tgt_t *, uintptr_t, uint_t,
	char *, size_t, GElf_Sym *, mdb_syminfo_t *);

/*
 * Callback function prototype for mdb_tgt_symbol_iter():
 */
typedef int mdb_tgt_sym_f(void *, const GElf_Sym *, const char *,
	const mdb_syminfo_t *sip, const char *);

/*
 * Values for selecting symbol tables with mdb_tgt_symbol_iter():
 */
#define	MDB_TGT_PRVSYM		0	/* User's private symbol table */
#define	MDB_TGT_SYMTAB		1	/* Normal symbol table (.symtab) */
#define	MDB_TGT_DYNSYM		2	/* Dynamic symbol table (.dynsym) */

/*
 * Values for selecting symbols of interest by binding and type.  These flags
 * can be used to construct a bitmask to pass to mdb_tgt_symbol_iter().  The
 * module API has its own slightly different names for these values.  If you are
 * adding a new flag here, you should consider exposing it in the module API.
 * If you are changing these flags and their meanings, you will need to update
 * the module API implementation to account for those changes.
 */
#define	MDB_TGT_BIND_LOCAL	0x0001	/* Local (static-scope) symbols */
#define	MDB_TGT_BIND_GLOBAL	0x0002	/* Global symbols */
#define	MDB_TGT_BIND_WEAK	0x0004	/* Weak binding symbols */

#define	MDB_TGT_BIND_ANY	0x0007	/* Any of the above */

#define	MDB_TGT_TYPE_NOTYPE	0x0100	/* Symbol has no type */
#define	MDB_TGT_TYPE_OBJECT	0x0200	/* Symbol refers to data */
#define	MDB_TGT_TYPE_FUNC	0x0400	/* Symbol refers to text */
#define	MDB_TGT_TYPE_SECT	0x0800	/* Symbol refers to a section */
#define	MDB_TGT_TYPE_FILE	0x1000	/* Symbol refers to a source file */
#define	MDB_TGT_TYPE_COMMON	0x2000	/* Symbol refers to a common block */
#define	MDB_TGT_TYPE_TLS	0x4000	/* Symbol refers to TLS */

#define	MDB_TGT_TYPE_ANY	0x7f00	/* Any of the above */

extern int mdb_tgt_symbol_iter(mdb_tgt_t *, const char *, uint_t, uint_t,
	mdb_tgt_sym_f *, void *);

/*
 * Convenience functions for reading and writing at the address specified
 * by a given object file and symbol name:
 */
extern ssize_t mdb_tgt_readsym(mdb_tgt_t *, mdb_tgt_as_t, void *, size_t,
	const char *, const char *);

extern ssize_t mdb_tgt_writesym(mdb_tgt_t *, mdb_tgt_as_t, const void *, size_t,
	const char *, const char *);

/*
 * Virtual Address Mapping and Load Object interface
 *
 * These interfaces allow the caller to iterate over the various virtual
 * address space mappings, or only those mappings corresponding to load objects.
 * The mapping name (MDB_TGT_MAPSZ) is defined to be large enough for a string
 * of length MAXPATHLEN, plus space for "LM`<lmid>" where lmid is a hex number.
 */

#define	MDB_TGT_MAPSZ		1048	/* Maximum length of mapping name */

#define	MDB_TGT_MAP_R		0x01	/* Mapping is readable */
#define	MDB_TGT_MAP_W		0x02	/* Mapping is writeable */
#define	MDB_TGT_MAP_X		0x04	/* Mapping is executable */
#define	MDB_TGT_MAP_SHMEM	0x08	/* Mapping is shared memory */
#define	MDB_TGT_MAP_STACK	0x10	/* Mapping is a stack of some kind */
#define	MDB_TGT_MAP_HEAP	0x20	/* Mapping is a heap of some kind */
#define	MDB_TGT_MAP_ANON	0x40	/* Mapping is anonymous memory */

typedef struct mdb_map {
	char map_name[MDB_TGT_MAPSZ];	/* Name of mapped object */
	uintptr_t map_base;		/* Virtual address of base of mapping */
	size_t map_size;		/* Size of mapping in bytes */
	uint_t map_flags;		/* Flags (see above) */
} mdb_map_t;

typedef int mdb_tgt_map_f(void *, const mdb_map_t *, const char *);

extern int mdb_tgt_mapping_iter(mdb_tgt_t *, mdb_tgt_map_f *, void *);
extern int mdb_tgt_object_iter(mdb_tgt_t *, mdb_tgt_map_f *, void *);

extern const mdb_map_t *mdb_tgt_addr_to_map(mdb_tgt_t *, uintptr_t);
extern const mdb_map_t *mdb_tgt_name_to_map(mdb_tgt_t *, const char *);

extern struct ctf_file *mdb_tgt_addr_to_ctf(mdb_tgt_t *, uintptr_t);
extern struct ctf_file *mdb_tgt_name_to_ctf(mdb_tgt_t *, const char *);

/*
 * Execution Control Interface
 *
 * For in-situ debugging, we provide a relatively simple interface for target
 * execution control.  The target can be continued, or the representative
 * thread of control can be single-stepped.  Once the target has stopped, the
 * status of the representative thread is returned (this status can also be
 * obtained using mdb_tgt_status()).  Upon continue, the target's internal list
 * of software event specifiers determines what types of events will cause the
 * target to stop and transfer control back to the debugger.  The target
 * allows any number of virtual event specifiers to be registered, along with
 * an associated callback.  These virtual specifiers are layered on top of
 * underlying software event specifiers that are private to the target.  The
 * virtual event specifier list can be manipulated by the functions described
 * below.  We currently support the following types of traced events:
 * breakpoints, watchpoints, system call entry, system call exit, signals,
 * and machine faults.
 */

typedef uintptr_t mdb_tgt_tid_t;	/* Opaque thread identifier */

typedef struct mdb_tgt_status {
	mdb_tgt_tid_t st_tid;		/* Id of thread in question */
	uintptr_t st_pc;		/* Program counter, if stopped */
	uint_t st_state;		/* Program state (see below) */
	uint_t st_flags;		/* Status flags (see below) */
} mdb_tgt_status_t;

/*
 * Program state (st_state):
 * (MDB_STATE_* definitions in the module API need to be in sync with these)
 */
#define	MDB_TGT_IDLE		0	/* Target is idle (not running yet) */
#define	MDB_TGT_RUNNING		1	/* Target is currently executing */
#define	MDB_TGT_STOPPED		2	/* Target is stopped */
#define	MDB_TGT_UNDEAD		3	/* Target is undead (zombie) */
#define	MDB_TGT_DEAD		4	/* Target is dead (core dump) */
#define	MDB_TGT_LOST		5	/* Target lost by debugger */

/*
 * Status flags (st_flags):
 */
#define	MDB_TGT_ISTOP		0x1	/* Stop on event of interest */
#define	MDB_TGT_DSTOP		0x2	/* Stop directive is pending */
#define	MDB_TGT_BUSY		0x4	/* Busy in debugger */

extern int mdb_tgt_status(mdb_tgt_t *, mdb_tgt_status_t *);
extern int mdb_tgt_run(mdb_tgt_t *, int, const struct mdb_arg *);
extern int mdb_tgt_step(mdb_tgt_t *, mdb_tgt_status_t *);
extern int mdb_tgt_step_out(mdb_tgt_t *, mdb_tgt_status_t *);
extern int mdb_tgt_step_branch(mdb_tgt_t *, mdb_tgt_status_t *);
extern int mdb_tgt_next(mdb_tgt_t *, mdb_tgt_status_t *);
extern int mdb_tgt_continue(mdb_tgt_t *, mdb_tgt_status_t *);
extern int mdb_tgt_signal(mdb_tgt_t *, int);

/*
 * Iterating through the specifier list yields the integer id (VID) and private
 * data pointer for each specifier.
 */
typedef int mdb_tgt_vespec_f(mdb_tgt_t *, void *, int, void *);

/*
 * Each event specifier is defined to be in one of the following states.  The
 * state transitions are discussed in detail in the comments in mdb_target.c.
 */
#define	MDB_TGT_SPEC_IDLE	1	/* Inactive (e.g. object not loaded) */
#define	MDB_TGT_SPEC_ACTIVE	2	/* Active but not armed in target */
#define	MDB_TGT_SPEC_ARMED	3	/* Active and armed (e.g. bkpt set) */
#define	MDB_TGT_SPEC_ERROR	4	/* Failed to arm event */

/*
 * Event specifiers may also have one or more of the following additional
 * properties (spec_flags bits):
 */
#define	MDB_TGT_SPEC_INTERNAL	0x0001	/* Internal to target implementation */
#define	MDB_TGT_SPEC_SILENT	0x0002	/* Do not describe when matched */
#define	MDB_TGT_SPEC_TEMPORARY	0x0004	/* Delete next time target stops */
#define	MDB_TGT_SPEC_MATCHED	0x0008	/* Specifier matched at last stop */
#define	MDB_TGT_SPEC_DISABLED	0x0010	/* Specifier cannot be armed */
#define	MDB_TGT_SPEC_DELETED	0x0020	/* Specifier has been deleted */
#define	MDB_TGT_SPEC_AUTODEL	0x0040	/* Delete when match limit reached */
#define	MDB_TGT_SPEC_AUTODIS	0x0080	/* Disable when match limit reached */
#define	MDB_TGT_SPEC_AUTOSTOP	0x0100	/* Stop when match limit reached */
#define	MDB_TGT_SPEC_STICKY	0x0200	/* Do not delete as part of :z */

#define	MDB_TGT_SPEC_HIDDEN	(MDB_TGT_SPEC_INTERNAL | MDB_TGT_SPEC_SILENT)

typedef struct mdb_tgt_spec_desc {
	int spec_id;			/* Event specifier id (VID) */
	uint_t spec_flags;		/* Flags (see above) */
	uint_t spec_hits;		/* Count of number of times matched */
	uint_t spec_limit;		/* Limit on number of times matched */
	int spec_state;			/* State (see above) */
	int spec_errno;			/* Last error code (if IDLE or ERROR) */
	uintptr_t spec_base;		/* Start of affected memory region */
	size_t spec_size;		/* Size of affected memory region */
	void *spec_data;		/* Callback private data */
} mdb_tgt_spec_desc_t;

/*
 * The target provides functions to convert a VID into the private data pointer,
 * or a complete description of the event specifier and its state.
 */
extern void *mdb_tgt_vespec_data(mdb_tgt_t *, int);
extern char *mdb_tgt_vespec_info(mdb_tgt_t *, int,
    mdb_tgt_spec_desc_t *, char *, size_t);

/*
 * The common target layer provides functions to iterate over the list of
 * registered event specifiers, modify or disable them, and delete them.
 */
extern int mdb_tgt_vespec_iter(mdb_tgt_t *, mdb_tgt_vespec_f *, void *);
extern int mdb_tgt_vespec_modify(mdb_tgt_t *, int, uint_t, uint_t, void *);
extern int mdb_tgt_vespec_enable(mdb_tgt_t *, int);
extern int mdb_tgt_vespec_disable(mdb_tgt_t *, int);
extern int mdb_tgt_vespec_delete(mdb_tgt_t *, int);

/*
 * The mdb_tgt_add_* functions are used to add software event specifiers to the
 * target.  The caller provides a bitmask of flags (spec_flags above), callback
 * function pointer, and callback data as arguments.  Whenever a matching event
 * is detected, a software event callback function is invoked.  The callback
 * receives a pointer to the target, the VID of the corresponding event
 * specifier, and a private data pointer as arguments.  If no callback is
 * desired, the caller can specify a pointer to the no_se_f default callback.
 * Unlike other target layer functions, the mdb_tgt_add_* interfaces return the
 * VID of the new event (which may be positive or negative), or 0 if the new
 * event could not be created.
 */
typedef void mdb_tgt_se_f(mdb_tgt_t *, int, void *);
extern void no_se_f(mdb_tgt_t *, int, void *);

/*
 * Breakpoints can be set at a specified virtual address or using MDB's
 * symbol notation:
 */
extern int mdb_tgt_add_vbrkpt(mdb_tgt_t *, uintptr_t,
    int, mdb_tgt_se_f *, void *);

extern int mdb_tgt_add_sbrkpt(mdb_tgt_t *, const char *,
    int, mdb_tgt_se_f *, void *);

/*
 * Watchpoints can be set at physical, virtual, or I/O port addresses for any
 * combination of read, write, or execute operations.
 */
#define	MDB_TGT_WA_R		0x1	/* Read watchpoint */
#define	MDB_TGT_WA_W		0x2	/* Write watchpoint */
#define	MDB_TGT_WA_X		0x4	/* Execute watchpoint */

#define	MDB_TGT_WA_RWX	(MDB_TGT_WA_R | MDB_TGT_WA_W | MDB_TGT_WA_X)

extern int mdb_tgt_add_pwapt(mdb_tgt_t *, physaddr_t, size_t, uint_t,
    int, mdb_tgt_se_f *, void *);

extern int mdb_tgt_add_vwapt(mdb_tgt_t *, uintptr_t, size_t, uint_t,
    int, mdb_tgt_se_f *, void *);

extern int mdb_tgt_add_iowapt(mdb_tgt_t *, uintptr_t, size_t, uint_t,
    int, mdb_tgt_se_f *, void *);

/*
 * For user process debugging, tracepoints can be set on entry or exit from
 * a system call, or on receipt of a software signal or fault.
 */
extern int mdb_tgt_add_sysenter(mdb_tgt_t *, int, int, mdb_tgt_se_f *, void *);
extern int mdb_tgt_add_sysexit(mdb_tgt_t *, int, int, mdb_tgt_se_f *, void *);
extern int mdb_tgt_add_signal(mdb_tgt_t *, int, int, mdb_tgt_se_f *, void *);
extern int mdb_tgt_add_fault(mdb_tgt_t *, int, int, mdb_tgt_se_f *, void *);

/*
 * Machine Register Interface
 *
 * The machine registers for a given thread can be manipulated using the
 * getareg and putareg interface; the caller must know the naming convention
 * for registers for the given target architecture.  For the purposes of
 * this interface, we declare the register container to be the largest
 * current integer container.
 */

typedef uint64_t mdb_tgt_reg_t;

extern int mdb_tgt_getareg(mdb_tgt_t *, mdb_tgt_tid_t,
	const char *, mdb_tgt_reg_t *);

extern int mdb_tgt_putareg(mdb_tgt_t *, mdb_tgt_tid_t,
	const char *, mdb_tgt_reg_t);

/*
 * Stack Interface
 *
 * The target stack interface provides the ability to iterate backward through
 * the frames of an execution stack.  For the purposes of this interface, the
 * mdb_tgt_gregset (general purpose register set) is an opaque type: there must
 * be an implicit contract between the target implementation and any debugger
 * modules that must interpret the contents of this structure.  The callback
 * function is provided with the only elements of a stack frame which we can
 * reasonably abstract: the virtual address corresponding to a program counter
 * value, and an array of arguments passed to the function call represented by
 * this frame.  The rest of the frame is presumed to be contained within the
 * mdb_tgt_gregset_t, and is architecture-specific.
 */

typedef struct mdb_tgt_gregset mdb_tgt_gregset_t;

typedef int mdb_tgt_stack_f(void *, uintptr_t, uint_t, const long *,
	const mdb_tgt_gregset_t *);
typedef int mdb_tgt_stack_iter_f(mdb_tgt_t *, const mdb_tgt_gregset_t *,
	mdb_tgt_stack_f *, void *);

extern mdb_tgt_stack_iter_f mdb_tgt_stack_iter;

/*
 * External Data Interface
 *
 * The external data interface provides each target with the ability to export
 * a set of named buffers that contain data which is associated with the
 * target, but is somehow not accessible through one of its address spaces and
 * does not correspond to a machine register.  A process credential is an
 * example of such a buffer: the credential is associated with the given
 * process, but is stored in the kernel (not the process's address space) and
 * thus is not accessible through any other target interface.  Since it is
 * exported via /proc, the user process target can export this information as a
 * named buffer for target-specific dcmds to consume.
 */

typedef int mdb_tgt_xdata_f(void *, const char *, const char *, size_t);

extern int mdb_tgt_xdata_iter(mdb_tgt_t *, mdb_tgt_xdata_f *, void *);
extern ssize_t mdb_tgt_getxdata(mdb_tgt_t *, const char *, void *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_TARGET_H */
