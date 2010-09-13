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

#ifndef _KCTL_H
#define	_KCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kmdb/kmdb_auxv.h>
#include <kmdb/kmdb_wr.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kdi.h>
#include <sys/modctl.h>
#include <sys/ksynch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	KCTL_ST_INACTIVE = 0,		/* kmdb is inactive */
	KCTL_ST_DSEG_ALLOCED,		/* kmdb segment has been allocated */
	KCTL_ST_INITIALIZED,		/* kmdb_init has been called */
	KCTL_ST_KCTL_PREACTIVATED,	/* kctl preactivation completed */
	KCTL_ST_MOD_NOTIFIERS,		/* krtld module notifiers registered */
	KCTL_ST_THREAD_STARTED,		/* WR queue thread started */
	KCTL_ST_DBG_ACTIVATED,		/* kmdb activated */
	KCTL_ST_ACTIVE,			/* kernel is aware of kmdb activation */
	KCTL_ST_DEACTIVATING		/* debugger is being deactivated */
} kctl_state_t;

typedef enum {
	KCTL_WR_ST_RUN,			/* WR queue thread is running */
	KCTL_WR_ST_STOP,		/* WR queue thread is stopping */
	KCTL_WR_ST_STOPPED		/* WR queue thread has stopped */
} kctl_wr_state_t;

typedef struct kctl {
	dev_info_t *kctl_drv_dip;	/* Driver's device info structure */
	size_t kctl_memgoalsz;		/* Desired size of debugger memory */
	caddr_t	kctl_dseg;		/* Debugger segment (Oz) address */
	size_t kctl_dseg_size;		/* Debugger segment (Oz) size */
	caddr_t kctl_mrbase;		/* Add'l Oz memory range base address */
	size_t kctl_mrsize;		/* Add'l Oz memory range size */
	vnode_t kctl_vp;		/* vnode used to allocate dbgr seg */
	kctl_state_t kctl_state;	/* State of debugger */
	uint_t kctl_boot_loaded;	/* Set if debugger loaded at boot */
	struct bootops *kctl_boot_ops;	/* Boot operations (during init only) */
	const char *kctl_execname;	/* Path of this module */
	uint_t kctl_wr_avail;		/* Work available on the WR queue */
	ksema_t kctl_wr_avail_sem;	/* For WR thr: Work avail on WR queue */
	kthread_t *kctl_wr_thr;		/* Thread that processes WR queue */
	kctl_wr_state_t kctl_wr_state;	/* State of WR queue thread */
	kmutex_t kctl_lock;		/* serializes (de)activation */
	kcondvar_t kctl_wr_cv;		/* WR queue thread completion */
	kmutex_t kctl_wr_lock;		/* WR queue thread completion */
	uint_t kctl_flags;		/* KMDB_F_* from kmdb.h */
#ifdef __sparc
	caddr_t kctl_tba;		/* kmdb's native trap table */
#endif
} kctl_t;

extern kctl_t kctl;

struct bootops;

extern void kctl_dprintf(const char *, ...);
extern void kctl_warn(const char *, ...);

extern int kctl_preactivate_isadep(void);
extern void kctl_activate_isadep(kdi_debugvec_t *);
extern void kctl_depreactivate_isadep(void);
extern void kctl_cleanup(void);

extern void *kctl_boot_tmpinit(void);
extern void kctl_boot_tmpfini(void *);

extern void kctl_auxv_init(kmdb_auxv_t *, const char *, const char **, void *);
extern void kctl_auxv_init_isadep(kmdb_auxv_t *, void *);
extern void kctl_auxv_fini(kmdb_auxv_t *);
extern void kctl_auxv_fini_isadep(kmdb_auxv_t *);
#ifdef sun4v
extern void kctl_auxv_set_promif(kmdb_auxv_t *);
extern void kctl_switch_promif(void);
#endif

extern void kctl_wrintr(void);
extern void kctl_wrintr_fire(void);
extern void kctl_wr_thr_start(void);
extern void kctl_wr_thr_stop(void);
extern void kctl_wr_thr_join(void);

extern int kctl_mod_decompress(struct modctl *);
extern void kctl_mod_loaded(struct modctl *);
extern void kctl_mod_changed(uint_t, struct modctl *);
extern void kctl_mod_notify_reg(void);
extern void kctl_mod_notify_unreg(void);

extern void kctl_dmod_init(void);
extern void kctl_dmod_fini(void);
extern void kctl_dmod_sync(void);
extern void kctl_dmod_autoload(const char *);
extern void kctl_dmod_unload_all(void);
extern void kctl_dmod_path_reset(void);

extern int kctl_wr_process(void);
extern void kctl_wr_unload(void);

extern char *kctl_basename(char *);
extern char *kctl_strdup(const char *);
extern void kctl_strfree(char *);

#if defined(__sparc)
extern kthread_t *kctl_curthread_set(kthread_t *);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _KCTL_H */
