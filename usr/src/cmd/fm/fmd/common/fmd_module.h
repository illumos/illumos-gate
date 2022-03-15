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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_FMD_MODULE_H
#define	_FMD_MODULE_H

#include <sys/types.h>
#include <fm/diagcode.h>
#include <pthread.h>
#include <setjmp.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_conf.h>
#include <fmd_list.h>
#include <fmd_serd.h>
#include <fmd_buf.h>
#include <fmd_api.h>
#include <fmd_eventq.h>
#include <fmd_topo.h>

struct fmd_module;			/* see below */
struct fmd_thread;			/* see <fmd_thread.h> */
struct fmd_idspace;			/* see <fmd_idspace.h> */
struct fmd_ustat;			/* see <fmd_ustat.h> */
struct fmd_ustat_snap;			/* see <fmd_ustat.h> */

typedef struct fmd_modops {
	int (*mop_init)(struct fmd_module *);
	int (*mop_fini)(struct fmd_module *);
	void (*mop_dispatch)(struct fmd_module *, struct fmd_event *);
	int (*mop_transport)(struct fmd_module *,
	    fmd_xprt_t *, struct fmd_event *);
} fmd_modops_t;

typedef struct fmd_modhash {
	pthread_rwlock_t mh_lock;	/* r/w lock to protect hash */
	struct fmd_module **mh_hash;	/* hash bucket array */
	uint_t mh_hashlen;		/* size of hash bucket array */
	uint_t mh_nelems;		/* number of modules in hash */
} fmd_modhash_t;

/*
 * Statistics maintained by fmd itself on behalf of all modules for fmstat(8).
 * NOTE: FMD_TYPE_STRING statistics should not be used here.  If they are
 * required in the future, the FMD_ADM_MODDSTAT service routine must change.
 */
typedef struct fmd_modstat {
	fmd_eventqstat_t ms_evqstat;	/* stats for main module event queue */
	fmd_stat_t ms_loadtime;		/* hrtime at which module was loaded */
	fmd_stat_t ms_snaptime;		/* hrtime of recent stats snapshot */
	fmd_stat_t ms_accepted;		/* total events accepted by module */
	fmd_stat_t ms_debugdrop;	/* dropped debug messages */
	fmd_stat_t ms_memtotal;		/* total space allocated by module */
	fmd_stat_t ms_memlimit;		/* limit on space allocated by module */
	fmd_stat_t ms_buftotal;		/* total space consumed by buffers */
	fmd_stat_t ms_buflimit;		/* limit on space consumed by buffers */
	fmd_stat_t ms_thrtotal;		/* total number of auxiliary threads */
	fmd_stat_t ms_thrlimit;		/* limit on auxiliary threads */
	fmd_stat_t ms_doorthrtotal;	/* total number of doorserver threads */
	fmd_stat_t ms_doorthrlimit;	/* limit on doorserver threads */
	fmd_stat_t ms_caseopen;		/* cases currently open */
	fmd_stat_t ms_casesolved;	/* total cases solved by module */
	fmd_stat_t ms_caseclosed;	/* total cases closed by module */
	fmd_stat_t ms_ckpt_save;	/* save checkpoints for module */
	fmd_stat_t ms_ckpt_restore;	/* restore checkpoints for module */
	fmd_stat_t ms_ckpt_zeroed;	/* checkpoint was zeroed at startup */
	fmd_stat_t ms_ckpt_cnt;		/* number of checkpoints taken */
	fmd_stat_t ms_ckpt_time;	/* total checkpoint time */
	fmd_stat_t ms_xprtopen;		/* total number of open transports */
	fmd_stat_t ms_xprtlimit;	/* limit on number of open transports */
	fmd_stat_t ms_xprtqlimit;	/* limit on transport eventq length */
} fmd_modstat_t;

typedef struct fmd_module {
	fmd_list_t mod_list;		/* linked list next/prev pointers */
	pthread_mutex_t mod_lock;	/* lock for mod_cv/owner/flags/refs */
	pthread_cond_t mod_cv;		/* condition variable for waiters */
	pthread_t mod_owner;		/* tid of thread that set MOD_LOCK */
	uint_t mod_refs;		/* module reference count */
	uint_t mod_flags;		/* miscellaneous flags (see below) */
	uint64_t mod_gen;		/* module checkpoint generation */
	int mod_error;			/* error return from module thread */
	jmp_buf mod_jmpbuf;		/* setjmp data for fmd_module_enter() */
	fmd_modhash_t *mod_hash;	/* containing namespace (ro) */
	struct fmd_module *mod_next;	/* next module in fmd_modhash chain */
	char *mod_name;			/* basename of module (ro) */
	char *mod_path;			/* full pathname of module file (ro) */
	char *mod_ckpt;			/* pathname of checkpoint dir (ro) */
	nvlist_t *mod_fmri;		/* fmri for this module */
	const fmd_modops_t *mod_ops;	/* module class ops vector (ro) */
	void *mod_data;			/* data private to module ops vector */
	fmd_hdl_info_t *mod_info;	/* module info registered with handle */
	void *mod_spec;			/* fmd_hdl_get/setspecific data value */
	int mod_argc;			/* size of mod_argv formals array */
	fmd_conf_formal_t *mod_argv; 	/* array of conf file formals */
	fmd_conf_t *mod_conf;		/* configuration properties (ro) */
	struct fm_dc_handle **mod_dictv; /* libdiagcode dictionaries */
	int mod_dictc;			/* size of mod_dictv array */
	size_t mod_codelen;		/* libdiagcode maximum string length */
	struct fmd_eventq *mod_queue;	/* eventq associated with module (ro) */
	struct fmd_ustat *mod_ustat;	/* collection of custom statistics */
	pthread_mutex_t mod_stats_lock;	/* lock protecting mod_stats data */
	fmd_modstat_t *mod_stats;	/* fmd built-in per-module statistics */
	struct fmd_thread *mod_thread;	/* thread associated with module (ro) */
	struct fmd_idspace *mod_threads;  /* idspace for alternate thread ids */
	struct fmd_idspace *mod_timerids; /* idspace for timer identifiers */
	fmd_list_t mod_cases;		/* list of cases owned by this module */
	fmd_buf_hash_t mod_bufs;	/* hash of bufs owned by this module */
	fmd_serd_hash_t mod_serds;	/* hash of serd engs owned by module */
	fmd_list_t mod_transports;	/* list of transports owned by module */
	fmd_list_t mod_topolist;	/* list of held topo handles */
	fmd_topo_t *mod_topo_current;	/* current libtopo snapshot */
	char *mod_vers;			/* a copy of module version string */
	nv_alloc_t mod_nva_sleep;	/* module nvalloc routines (sleep) */
	nv_alloc_t mod_nva_nosleep;	/* module nvalloc routines (nosleep) */
} fmd_module_t;

#define	FMD_MOD_INIT	0x001		/* mod_ops->mop_init() has completed */
#define	FMD_MOD_FINI	0x002		/* mod_ops->mop_fini() has completed */
#define	FMD_MOD_QUIT	0x004		/* module has been requested to quit */
#define	FMD_MOD_FAIL	0x008		/* unrecoverable error has occurred */
#define	FMD_MOD_LOCK	0x010		/* lock bit for fmd_module_lock() */
#define	FMD_MOD_BUSY	0x020		/* module is busy executing a call */
#define	FMD_MOD_MDIRTY	0x040		/* module meta state needs checkpoint */
#define	FMD_MOD_CDIRTY	0x080		/* module case state needs checkpoint */
#define	FMD_MOD_STSUB	0x100		/* stats subscriber is waiting */
#define	FMD_MOD_STPUB	0x200		/* stats publisher is waiting */

typedef struct fmd_modtimer {
	fmd_module_t *mt_mod;		/* module that installed this timer */
	void *mt_arg;			/* module private timer argument */
	id_t mt_id;			/* timer ID (or -1 if still pending) */
} fmd_modtimer_t;

typedef struct fmd_modtopo {
	fmd_list_t mt_link;		/* link on module topo list */
	fmd_topo_t *mt_topo;		/* topo handle */
} fmd_modtopo_t;

extern const fmd_modops_t fmd_bltin_ops; /* see fmd/common/fmd_builtin.c */
extern const fmd_modops_t fmd_rtld_ops;	/* see fmd/common/fmd_rtld.c */
extern const fmd_modops_t fmd_proc_ops;	/* see fmd/common/fmd_proc.c */

extern fmd_module_t *fmd_module_create(const char *, const fmd_modops_t *);
extern void fmd_module_unload(fmd_module_t *);
extern void fmd_module_destroy(fmd_module_t *);

extern void fmd_module_dispatch(fmd_module_t *, fmd_event_t *);
extern int fmd_module_transport(fmd_module_t *, fmd_xprt_t *, fmd_event_t *);
extern void fmd_module_timeout(fmd_modtimer_t *, id_t, hrtime_t);
extern void fmd_module_gc(fmd_module_t *);
extern void fmd_module_trygc(fmd_module_t *);

extern int fmd_module_contains(fmd_module_t *, fmd_event_t *);
extern void fmd_module_setdirty(fmd_module_t *);
extern void fmd_module_setcdirty(fmd_module_t *);
extern void fmd_module_clrdirty(fmd_module_t *);
extern void fmd_module_commit(fmd_module_t *);

extern void fmd_module_lock(fmd_module_t *);
extern void fmd_module_unlock(fmd_module_t *);
extern int fmd_module_trylock(fmd_module_t *);
extern int fmd_module_locked(fmd_module_t *);

extern void fmd_module_unregister(fmd_module_t *);
extern int fmd_module_enter(fmd_module_t *, void (*)(fmd_hdl_t *));
extern void fmd_module_exit(fmd_module_t *);
extern void fmd_module_abort(fmd_module_t *, int) __NORETURN;

extern void fmd_module_hold(fmd_module_t *);
extern void fmd_module_rele(fmd_module_t *);

extern int fmd_module_dc_opendict(fmd_module_t *, const char *);
extern int fmd_module_dc_key2code(fmd_module_t *,
    char *const [], char *, size_t);

extern fmd_modhash_t *fmd_modhash_create(void);
extern void fmd_modhash_destroy(fmd_modhash_t *);

extern fmd_module_t *fmd_modhash_load(fmd_modhash_t *,
    const char *, const fmd_modops_t *);

extern void fmd_modhash_loadall(fmd_modhash_t *,
    const fmd_conf_path_t *, const fmd_modops_t *, const char *);

extern fmd_module_t *fmd_modhash_lookup(fmd_modhash_t *, const char *);
extern int fmd_modhash_unload(fmd_modhash_t *, const char *);

extern void fmd_modhash_apply(fmd_modhash_t *, void (*)(fmd_module_t *));
extern void fmd_modhash_tryapply(fmd_modhash_t *, void (*)(fmd_module_t *));
extern void fmd_modhash_dispatch(fmd_modhash_t *, fmd_event_t *);

extern void fmd_modstat_publish(fmd_module_t *);
extern int fmd_modstat_snapshot(fmd_module_t *, struct fmd_ustat_snap *);

extern struct topo_hdl *fmd_module_topo_hold(fmd_module_t *);
extern int fmd_module_topo_rele(fmd_module_t *, struct topo_hdl *);

extern nv_alloc_ops_t fmd_module_nva_ops_sleep;
extern nv_alloc_ops_t fmd_module_nva_ops_nosleep;

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_MODULE_H */
