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
 *      Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _TNFCTL_INT_H
#define	_TNFCTL_INT_H

/*
 * Interfaces private to libtnfctl
 *	layout of tnfctl handle structure
 *	layout of probe handle structure
 *	other misc. interfaces used across source files
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "tnfctl.h"
#include <sys/types.h>
#include <gelf.h>
#include <libelf.h>
#include "prb_proc.h"
#include <thread.h>
#include <synch.h>

/*
 * global variables used for INTERNAL_MODE synchronization with
 * dlopen's and dlclose's on another thread.
 */
extern mutex_t		_tnfctl_lmap_lock;
extern boolean_t	_tnfctl_libs_changed;

/* Project private interface - function name in target */
#define	TRACE_END_FUNC		"tnf_trace_end"

/* All tnfctl handles are in one of the following 4 modes */
enum proc_mode {
	KERNEL_MODE,		/* kernel tracing */
	DIRECT_MODE,		/* tracing another process (exec or attach) */
	INDIRECT_MODE,		/* client provides /proc functions */
	INTERNAL_MODE		/* tracing probes in the same process */
};

typedef struct prbctlref prbctlref_t;
typedef struct objlist objlist_t;

/* per probe state - transient - freed on dlclose() */
struct prbctlref {
	uintptr_t		addr;		/* probe address in target */
	objlist_t		*obj;		/* obj that this probe is in */
	ulong_t			probe_id;	/* assigned id */
	char			*attr_string;
	tnf_probe_control_t 	wrkprbctl;	/* probe struct from target */
	tnfctl_probe_t		*probe_handle;	/* handle visible to client */
};

/* per object state */
struct objlist {
	boolean_t	new_probe;	/* relative to last library change */
	boolean_t	new;		/* relative to last sync with linker */
	boolean_t	old;		/* relative to last sync with linker */
	char *		objname;
	uintptr_t	baseaddr;
	int		objfd;
	uint_t		min_probe_num;	/* first probe id in object */
	uint_t		probecnt;	/* number of probes in object */
	prbctlref_t	*probes;	/* pointer to an array of probes */
	objlist_t	*next;
};

/* per probe state that is freed only on tnfctl_close() */
struct tnfctl_probe_handle {
	boolean_t	valid;
	prbctlref_t	*probe_p;
	void		*client_registered_data;
	struct tnfctl_probe_handle *next;
};

/*
 * state saved per tnfctl handle
 */
struct tnfctl_handle {
	void		*proc_p;	/* proc handle */
	int		kfd;		/* kernel handle */
	pid_t		targ_pid;	/* pid of target */
	enum proc_mode	mode;		/* mode of handle */
	/* tracing info */
	const char 	*trace_file_name;
	int		trace_buf_size;
	int		trace_min_size;
	tnfctl_bufstate_t	trace_buf_state;
	boolean_t	trace_state;
	boolean_t	kpidfilter_state;
	boolean_t	called_exit;
	/* addresses of functions in target */
	uintptr_t	testfunc;
	uintptr_t	allocfunc;
	uintptr_t	commitfunc;
	uintptr_t	endfunc;
	uintptr_t	rollbackfunc;
	uintptr_t	probelist_head;
	uintptr_t	probelist_valid;
	uintptr_t	trace_error;
	uintptr_t	memseg_p;
	uintptr_t	nonthread_test;
	uintptr_t	thread_test;
	uintptr_t	thread_sync;
	boolean_t	mt_target;
	uint_t		num_probes;	/* number of probes in target */
	tnfctl_probe_t	*probe_handle_list_head;
	/* object info */
	boolean_t	in_objlist;	/* _tnfctl_lmap_lock reentrancy check */
	objlist_t	*objlist;
	/* combination info */
	void		*buildroot;	/* root of built combinations */
	void		*decoderoot;	/* root of decoded combinations */
	/* per probe create/destroy functions */
	void *(*create_func)(tnfctl_handle_t *, tnfctl_probe_t *);
	void (*destroy_func)(void *);
	/* functions to inspect target process */
	int (*p_read)(void *prochandle, uintptr_t addr, void *buf, size_t size);
	int (*p_write)(void *prochandle, uintptr_t addr,
			void *buf, size_t size);
	int (*p_obj_iter)(void *prochandle, tnfctl_ind_obj_f *func,
						void *client_data);
	pid_t (*p_getpid)(void *prochandle);
};

typedef enum comb_op {
	PRB_COMB_CHAIN = 0,	/* call the down, then the next */
	PRB_COMB_COUNT = 1	/* how many? */
} comb_op_t;

enum event_op_t {
	EVT_NONE,
	EVT_OPEN,
	EVT_CLOSE
};


/*
 * interfaces to search for symbols or to search for relocations
 * in an elf file
 */
typedef struct tnfctl_elf_search tnfctl_elf_search_t;

/* prototype for callback for traversing an elf section */
typedef tnfctl_errcode_t
(*tnfctl_traverse_section_func_t) (Elf * elf, char *strs, Elf_Scn * scn,
	GElf_Shdr * shdr, Elf_Data * data, uintptr_t baseaddr,
	tnfctl_elf_search_t * search_info);

/* prototype for callback for traversing records in an elf section */
typedef tnfctl_errcode_t
(*tnfctl_record_func_t) (char *name, uintptr_t addr, void *entry,
	tnfctl_elf_search_t * search_info);

struct tnfctl_elf_search {
	tnfctl_traverse_section_func_t	section_func;
	void				*section_data;
	tnfctl_record_func_t		record_func;
	void				*record_data;
};

/* traverse all the sections in an object */
tnfctl_errcode_t _tnfctl_traverse_object(int objfd, uintptr_t addr,
			tnfctl_elf_search_t *search_info_p);
/* search a .rela section */
tnfctl_errcode_t _tnfctl_traverse_rela(Elf * elf, char *strs, Elf_Scn * rel_scn,
	GElf_Shdr * rel_shdr, Elf_Data * rel_data, uintptr_t baseaddr,
	tnfctl_elf_search_t * search_info_p);
/* search a .dynsym section */
tnfctl_errcode_t _tnfctl_traverse_dynsym(Elf * elf, char *elfstrs,
	Elf_Scn * scn, GElf_Shdr * shdr, Elf_Data * data, uintptr_t baseaddr,
	tnfctl_elf_search_t * search_info_p);

/* prototype of callback for internal probe traversal function */
typedef tnfctl_errcode_t
(*_tnfctl_traverse_probe_func_t)(tnfctl_handle_t *, prbctlref_t *, void *);

/* sync up list of objects with that of the linker */
tnfctl_errcode_t _tnfctl_lmap_update(tnfctl_handle_t *hndl, boolean_t *lmap_ok,
					enum event_op_t *evt);

/* sync up list of objects and probes */
tnfctl_errcode_t _tnfctl_refresh_process(tnfctl_handle_t *, boolean_t *,
				enum event_op_t *);

tnfctl_errcode_t _tnfctl_set_state(tnfctl_handle_t *hndl);
tnfctl_errcode_t _tnfctl_create_tracefile(tnfctl_handle_t *hndl,
		const char *trace_file_name, uint_t trace_file_size);

/* probe interfaces */
tnfctl_errcode_t _tnfctl_find_all_probes(tnfctl_handle_t *hndl);
tnfctl_errcode_t _tnfctl_probes_traverse(tnfctl_handle_t *hndl,
	_tnfctl_traverse_probe_func_t func_p, void *calldata_p);
tnfctl_errcode_t _tnfctl_flush_a_probe(tnfctl_handle_t *hndl,
	prbctlref_t *ref_p, size_t offset, size_t size);

/* combination interfaces */
tnfctl_errcode_t _tnfctl_comb_build(tnfctl_handle_t *hndl, comb_op_t op,
	uintptr_t down, uintptr_t next, uintptr_t *comb_p);
tnfctl_errcode_t _tnfctl_comb_decode(tnfctl_handle_t *hndl, uintptr_t addr,
	char ***func_names, uintptr_t **func_addrs);

/* allocate memory in target process */
tnfctl_errcode_t _tnfctl_targmem_alloc(tnfctl_handle_t *hndl, size_t size,
			uintptr_t *addr_p);

/* inprocess "plug ins" for functions in tnfctl_handle_t structure */
int _tnfctl_read_targ(void *proc_p, uintptr_t addr, void *buf, size_t size);
int _tnfctl_write_targ(void *proc_p, uintptr_t addr, void *buf, size_t size);
int _tnfctl_loadobj_iter(void *proc_p, tnfctl_ind_obj_f *func,
			void *client_data);
pid_t _tnfctl_pid_get(void *proc_p);

/* read a string from the target process */
tnfctl_errcode_t _tnfctl_readstr_targ(tnfctl_handle_t *hndl, uintptr_t addr,
				char **outstr_pp);

/* symbol searching interfaces */
tnfctl_errcode_t _tnfctl_sym_find_in_obj(int objfd, uintptr_t baseaddr,
		const char *symname, uintptr_t *symaddr);
tnfctl_errcode_t _tnfctl_sym_obj_find(tnfctl_handle_t *hndl,
	const char *lib_base_name, const char *symname, uintptr_t *symaddr);
tnfctl_errcode_t _tnfctl_sym_find(tnfctl_handle_t *hndl, const char *symname,
			uintptr_t *symaddr);
tnfctl_errcode_t _tnfctl_sym_findname(tnfctl_handle_t *hndl, uintptr_t symaddr,
	char **symname);
tnfctl_errcode_t _tnfctl_elf_dbgent(tnfctl_handle_t *hndl,
				uintptr_t * entaddr_p);

/* free objs and probes */
void _tnfctl_free_objs_and_probes(tnfctl_handle_t *);

/* locking interfaces */
tnfctl_errcode_t _tnfctl_lock_libs(tnfctl_handle_t *hndl,
	boolean_t *release_lock);
void _tnfctl_unlock_libs(tnfctl_handle_t *hndl, boolean_t release_lock);
tnfctl_errcode_t _tnfctl_sync_lib_list(tnfctl_handle_t *hndl);

/*
 * BugID 1253419
 * The flags that indicate if in/external trace control is active.
 * Used to prevent simultaneous internal and external probe control.
 * For external control keep pid of traced process to handle case
 * where process forks. (child is not under external control)
 */
#define	TNFCTL_INTERNAL_TRACEFLAG	"_tnfctl_internal_tracing_flag"
#define	TNFCTL_EXTERNAL_TRACEDPID	"_tnfctl_externally_traced_pid"
extern boolean_t _tnfctl_internal_tracing_flag;
extern pid_t _tnfctl_externally_traced_pid;
tnfctl_errcode_t _tnfctl_internal_getlock(void);
tnfctl_errcode_t _tnfctl_external_getlock(tnfctl_handle_t *hndl);
tnfctl_errcode_t _tnfctl_internal_releaselock(void);
tnfctl_errcode_t _tnfctl_external_releaselock(tnfctl_handle_t *hndl);

/* error mapping functions */
tnfctl_errcode_t _tnfctl_map_to_errcode(prb_status_t prbstat);
tnfctl_errcode_t tnfctl_status_map(int);


/*
 * LOCK is the macro to lock down the library list so that a dlopen or
 * dlclose by another thread will block waiting for the lock to be released.
 *
 * LOCK_SYNC does the same as LOCK + it syncs up libtnfctl's cache of
 * libraries in target process with that of what the run time linker maintains.
 *
 * These macros do conditional locking because they are needed only by
 * INTERNAL_MODE clients.  There are 2 versions of these macros so that
 * lock_lint won't have to see the conditional locking.
 * CAUTION: Be aware that these macros have a return() embedded in them.
 */
#define	LOCK(hndl, stat, release)					\
	if (hndl->mode == INTERNAL_MODE) {				\
		stat = _tnfctl_lock_libs(hndl, &release);		\
		if (stat)						\
			return (stat);					\
	}								\
	else

#define	LOCK_SYNC(hndl, stat, release)					\
	if (hndl->mode == INTERNAL_MODE) {				\
		stat = _tnfctl_lock_libs(hndl, &release);		\
		if (stat)						\
			return (stat);					\
		stat = _tnfctl_sync_lib_list(hndl);			\
		if (stat) {						\
			_tnfctl_unlock_libs(hndl, release);		\
			return (stat);					\
		}							\
	}								\
	else

#define	UNLOCK(hndl, release)						\
	if (hndl->mode == INTERNAL_MODE)				\
		_tnfctl_unlock_libs(hndl, release_lock);		\
	else

#ifdef __cplusplus
}
#endif

#endif /* _TNFCTL_INT_H */
