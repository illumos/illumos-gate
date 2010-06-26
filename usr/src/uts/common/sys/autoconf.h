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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_AUTOCONF_H
#define	_SYS_AUTOCONF_H

/* Derived from autoconf.h, SunOS 4.1.1 1.15 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This defines a parallel structure to the devops list.
 */

#include <sys/dditypes.h>
#include <sys/devops.h>
#include <sys/mutex.h>
#include <sys/thread.h>
#include <sys/obpdefs.h>
#include <sys/systm.h>
#include <sys/hwconf.h>

struct devnames {
	char		*dn_name;	/* Name of this driver */
	int		dn_flags;	/* per-driver flags, see below */
	struct par_list	*dn_pl;		/* parent list, for making devinfos */
	kmutex_t	dn_lock;	/* Per driver lock (see below) */
	dev_info_t	*dn_head;	/* Head of instance list */
	int		dn_instance;	/* Next instance no. to assign */
	void		*dn_inlist;	/* instance # nodes for this driver */
	ddi_prop_list_t	*dn_global_prop_ptr; /* per-driver global properties */
	kcondvar_t	dn_wait;	/* for ddi_hold_installed_driver */
	kthread_id_t	dn_busy_thread;	/* for debugging only */
	struct mperm	*dn_mperm;	/* minor permissions */
	struct mperm	*dn_mperm_wild;	/* default minor permission */
	struct mperm	*dn_mperm_clone; /* minor permission, clone use */
	int		dn_pinstance;	/* Preassign instance boundary */
};

/*
 * dn_lock is used to protect the driver initialization/loading
 * from fini/unloading. It also protects each drivers devops
 * reference count, the dn_flags, and the dn_head linked list of
 * driver instances. The busy_changing bit is used to avoid
 * recursive calls to ddi_hold_installed_driver to hold the
 * same driver.
 */

/*
 * Defines for dn_flags.
 */
#define	DN_CONF_PARSED		0x0001
#define	DN_DRIVER_BUSY		0x0002	/* for ddi_hold_installed_driver */
#define	DN_DRIVER_INACTIVE	0x0004	/* driver not active */
#define	DN_DRIVER_HELD		0x0020	/* held via ddi_hold_installed_driver */
#define	DN_TAKEN_GETUDEV	0x0040	/* getudev() used this entry */
#define	DN_DRIVER_REMOVED	0x0080	/* driver entry removed */

#define	DN_FORCE_ATTACH		0x0100	/* DDI_FORCEATTACH prop */
#define	DN_LEAF_DRIVER		0x0200	/* this is a leaf driver */
#define	DN_NETWORK_DRIVER	0x0400	/* network interface driver */
#define	DN_NO_AUTODETACH	0x0800	/* no autodetach */
#define	DN_GLDV3_DRIVER		0x1000	/* gldv3 (Nemo) driver */
#define	DN_PHCI_DRIVER		0x2000	/* pHCI driver */
#define	DN_OPEN_RETURNS_EINTR	0x4000	/* DDI_OPEN_RETURNS_EINTR prop */
#define	DN_SCSI_SIZE_CLEAN	0x8000	/* driver is scsi_size_clean() */
#define	DN_NETWORK_PHYSDRIVER	0x10000	/* physical network driver */
#define	DN_DEVID_REGISTRANT	0x20000	/* ddi-devid-registrant prop */

#ifdef _KERNEL

/*
 * Debugging flags and macros
 */
#define	DDI_AUDIT		0x0001
#define	DDI_DEBUG		0x0002
#define	DDI_MTCONFIG		0x0004
#define	DDI_DEBUG_BOOTMOD	0x0008	/* module loading to mount root */
#define	DDI_DEBUG_COMPAT	0x0010	/* ddi_hold_install_driver */
#define	LDI_DBG_OPENCLOSE	0x0020	/* ldi open/close info */
#define	LDI_DBG_ALLOCFREE	0x0040	/* ldi ident alloc/free info */
#define	LDI_DBG_STREAMS		0x0080	/* ldi streams link/unlink */
#define	LDI_DBG_EVENTCB		0x0100	/* ldi event callback info */
#define	DDI_INTR_API		0x0200	/* interrupt interface messages  */
#define	DDI_INTR_IMPL		0x0400	/* interrupt implementation msgs */
#define	DDI_INTR_NEXUS		0x0800	/* interrupt messages from nexuses */
#define	DDI_DBG_RETIRE		0x1000	/* Retire related messages */
#define	DDI_DBG_RTR_VRBOSE	0x2000	/* Verbose Retire messages */
#define	DDI_DBG_RTR_TRACE	0x4000	/* Trace Retire messages */
#define	LDI_EV_DEBUG		0x8000  /* LDI events debug messages */
#define	LDI_EV_TRACE		0x10000 /* LDI events trace messages */
#define	DDI_INTR_IRM		0x20000 /* interrupt resource management */
#define	DDI_HP_API		0x40000	/* Hotplug interface messages  */
#define	DDI_HP_IMPL		0x80000	/* Hotplug implementation msgs */
#define	DDI_HP_NEXUS		0x100000 /* Hotplug messages from nexuses */
#define	DDI_MP_DEBUG		0x200000 /* ddi-mp translations */

extern int ddidebug;

#ifdef	DEBUG
#define	NDI_CONFIG_DEBUG(args)	if (ddidebug & DDI_DEBUG) cmn_err args
#define	BMDPRINTF(args)		if (ddidebug & DDI_DEBUG_BOOTMOD) printf args
#define	DCOMPATPRINTF(args)	if (ddidebug & DDI_DEBUG_COMPAT) cmn_err args
#define	LDI_OPENCLOSE(args)	if (ddidebug & LDI_DBG_OPENCLOSE) cmn_err args
#define	LDI_ALLOCFREE(args)	if (ddidebug & LDI_DBG_ALLOCFREE) cmn_err args
#define	LDI_STREAMS_LNK(args)	if (ddidebug & LDI_DBG_STREAMS) cmn_err args
#define	LDI_EVENTCB(args)	if (ddidebug & LDI_DBG_EVENTCB) cmn_err args
#define	DDI_INTR_APIDBG(args)	if (ddidebug & DDI_INTR_API) cmn_err args
#define	DDI_INTR_IMPLDBG(args)	if (ddidebug & DDI_INTR_IMPL) cmn_err args
#define	DDI_INTR_NEXDBG(args)	if (ddidebug & DDI_INTR_NEXUS) cmn_err args
#define	RIO_DEBUG(args)		if (ddidebug & DDI_DBG_RETIRE) cmn_err args
#define	RIO_VERBOSE(args)	if (ddidebug & DDI_DBG_RTR_VRBOSE) cmn_err args
#define	RIO_TRACE(args)		if (ddidebug & DDI_DBG_RTR_TRACE) cmn_err args
#define	LDI_EVDBG(args)		if (ddidebug & LDI_EV_DEBUG) cmn_err args
#define	LDI_EVTRC(args)		if (ddidebug & LDI_EV_TRACE) cmn_err args
#define	DDI_INTR_IRMDBG(args)	if (ddidebug & DDI_INTR_IRM) cmn_err args
#define	DDI_HP_APIDBG(args)	if (ddidebug & DDI_HP_API) cmn_err args
#define	DDI_HP_IMPLDBG(args)	if (ddidebug & DDI_HP_IMPL) cmn_err args
#define	DDI_HP_NEXDBG(args)	if (ddidebug & DDI_HP_NEXUS) cmn_err args
#else
#define	NDI_CONFIG_DEBUG(args)
#define	BMDPRINTF(args)
#define	DCOMPATPRINTF(args)
#define	LDI_OPENCLOSE(args)
#define	LDI_ALLOCFREE(args)
#define	LDI_STREAMS_LNK(args)
#define	LDI_EVENTCB(args)
#define	DDI_INTR_APIDBG(args)
#define	DDI_INTR_IMPLDBG(args)
#define	DDI_INTR_NEXDBG(args)
#define	RIO_DEBUG(args)		if (ddidebug & DDI_DBG_RETIRE) cmn_err args
#define	RIO_VERBOSE(args)	if (ddidebug & DDI_DBG_RTR_VRBOSE) cmn_err args
#define	RIO_TRACE(args)		if (ddidebug & DDI_DBG_RTR_TRACE) cmn_err args
#define	LDI_EVDBG(args)		if (ddidebug & LDI_EV_DEBUG) cmn_err args
#define	LDI_EVTRC(args)		if (ddidebug & LDI_EV_TRACE) cmn_err args
#define	DDI_INTR_IRMDBG(args)
#define	DDI_HP_APIDBG(args)
#define	DDI_HP_IMPLDBG(args)
#define	DDI_HP_NEXDBG(args)
#endif
#define	DDI_MP_DBG(args)	if (ddidebug & DDI_MP_DEBUG) cmn_err args


/*
 * DDI configuration logs
 */
#define	DDI_STACK_DEPTH		14

typedef struct devinfo_audit {
	dev_info_t		*da_devinfo;	/* address of devinfo node */
	hrtime_t		da_timestamp;	/* audit time */
	kthread_id_t		da_thread;	/* thread of transaction */
	struct devinfo_audit	*da_lastlog;	/* last log of state change */
	ddi_node_state_t	da_node_state;	/* devinfo state at log time */
	int			da_device_state;	/* device state */
	int			da_depth;
	pc_t			da_stack[DDI_STACK_DEPTH];
} devinfo_audit_t;

typedef struct {
	kmutex_t	dh_lock;
	int		dh_max;
	int		dh_curr;
	int		dh_hits;
	devinfo_audit_t	dh_entry[1];
} devinfo_log_header_t;

struct di_cache {
	uint32_t	cache_valid;	/* no lock needed - field atomic updt */
	kmutex_t	cache_lock;	/* protects fields below */
	void		*cache_data;
	size_t		cache_size;
};

extern struct di_cache di_cache;
extern int di_cache_debug;
extern volatile ulong_t devtree_gen;

/*
 * Special dev_info nodes
 */
#define	PSEUDO_PATH	"/"DEVI_PSEUDO_NEXNAME
#define	CLONE_PATH	PSEUDO_PATH"/clone@0"

#define	DI_CACHE_FILE	"/etc/devices/snapshot_cache"
#define	DI_CACHE_TEMP	DI_CACHE_FILE".tmp"

extern dev_info_t *options_dip;
extern dev_info_t *pseudo_dip;
extern dev_info_t *clone_dip;
extern major_t clone_major;
extern major_t mm_major;
extern major_t nulldriver_major;

extern struct devnames *devnamesp;
extern struct devnames orphanlist;

extern struct dev_ops nodev_ops, mod_nodev_ops;

/*
 * Obsolete interface, no longer used, to be removed.
 * Retained only for driver compatibility.
 */
extern krwlock_t devinfo_tree_lock;		/* obsolete */

/*
 * Acquires dn_lock, as above.
 */
#define	LOCK_DEV_OPS(lp)	mutex_enter((lp))
#define	UNLOCK_DEV_OPS(lp)	mutex_exit((lp))

/*
 * Not to be used without obtaining the per-driver lock.
 */
#define	INCR_DEV_OPS_REF(opsp)	(opsp)->devo_refcnt++
#define	DECR_DEV_OPS_REF(opsp)	(opsp)->devo_refcnt--
#define	CB_DRV_INSTALLED(opsp)	((opsp) != &nodev_ops && \
				(opsp) != &mod_nodev_ops)
#define	DRV_UNLOADABLE(opsp)	((opsp)->devo_refcnt == 0)
#define	DEV_OPS_HELD(opsp)	((opsp)->devo_refcnt > 0)
#define	NEXUS_DRV(opsp)		((opsp)->devo_bus_ops != NULL)
#define	NETWORK_DRV(maj)	(devnamesp[(maj)].dn_flags & DN_NETWORK_DRIVER)
#define	GLDV3_DRV(maj)		(devnamesp[(maj)].dn_flags & DN_GLDV3_DRIVER)
#define	NETWORK_PHYSDRV(maj)	\
			(devnamesp[(maj)].dn_flags & DN_NETWORK_PHYSDRIVER)

extern void impl_rem_dev_props(dev_info_t *);
extern void add_class(char *, char *);

extern int make_mbind(char *, int, char *, struct bind **);
extern void delete_mbind(char *, struct bind **);
extern void purge_mbind(int, struct bind **);

extern void configure(void);
#if defined(__sparc)
extern void setcputype(void);
#endif
extern void devtree_freeze(void);
extern void reset_leaves(void);
extern void quiesce_devices(dev_info_t *, void *);

extern void setup_ddi(void);
extern void setup_ddi_poststartup(void);
extern void impl_ddi_callback_init(void);
extern void impl_fix_props(dev_info_t *, dev_info_t *, char *, int, caddr_t);
extern int impl_check_cpu(dev_info_t *);
extern int check_status(int, char *, dev_info_t *);

extern int exclude_settrap(int);
extern int exclude_level(int);

extern major_t path_to_major(char *);
extern void i_ddi_node_cache_init(void);
extern dev_info_t *i_ddi_alloc_node(dev_info_t *, char *, pnode_t, int,
    ddi_prop_t *, int);
extern void i_ddi_forceattach_drivers(void);
extern int i_ddi_io_initialized(void);
extern dev_info_t *i_ddi_create_branch(dev_info_t *, int);
extern void i_ddi_add_devimap(dev_info_t *dip);
extern void i_ddi_di_cache_invalidate(void);
extern void i_ddi_di_cache_free(struct di_cache *cache);

/* devname_state - for /dev to denote reconfig and system available */
#define	DS_RECONFIG	0x01		/* reconfig boot */
#define	DS_SYSAVAIL	0x02		/* implicit reconfig enabled */

extern int i_ddi_sysavail(void);
extern int i_ddi_reconfig(void);
extern void i_ddi_set_sysavail(void);
extern void i_ddi_set_reconfig(void);

/* I/O retire related */
extern int e_ddi_retire_device(char *path, char **cons_array);
extern int e_ddi_unretire_device(char *path);
extern int e_ddi_mark_retiring(dev_info_t *dip, void *arg);
extern int e_ddi_retire_notify(dev_info_t *dip, void *arg);
extern int e_ddi_retire_finalize(dev_info_t *dip, void *arg);
extern void e_ddi_degrade_finalize(dev_info_t *dip);
extern void e_ddi_undegrade_finalize(dev_info_t *dip);

extern int check_driver_quiesce(dev_info_t *dip, void *arg);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_AUTOCONF_H */
