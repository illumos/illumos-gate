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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#ifndef _SYS_DDI_IMPLDEFS_H
#define	_SYS_DDI_IMPLDEFS_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/ddipropdefs.h>
#include <sys/devops.h>
#include <sys/autoconf.h>
#include <sys/mutex.h>
#include <vm/page.h>
#include <sys/dacf_impl.h>
#include <sys/ndifm.h>
#include <sys/epm.h>
#include <sys/ddidmareq.h>
#include <sys/ddi_intr.h>
#include <sys/ddi_hp.h>
#include <sys/ddi_hp_impl.h>
#include <sys/ddi_isa.h>
#include <sys/id_space.h>
#include <sys/modhash.h>
#include <sys/bitset.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The device id implementation has been switched to be based on properties.
 * For compatibility with di_devid libdevinfo interface the following
 * must be defined:
 */
#define	DEVID_COMPATIBILITY	((ddi_devid_t)-1)

/*
 * Definitions for node class.
 * DDI_NC_PROM: a node with a nodeid that may be used in a promif call.
 * DDI_NC_PSEUDO: a software created node with a software assigned nodeid.
 */
typedef enum {
	DDI_NC_PROM = 0,
	DDI_NC_PSEUDO
} ddi_node_class_t;

/*
 * Definitions for generic callback mechanism.
 */
typedef enum {
	DDI_CB_INTR_ADD,		/* More available interrupts */
	DDI_CB_INTR_REMOVE		/* Fewer available interrupts */
} ddi_cb_action_t;

typedef enum {
	DDI_CB_FLAG_INTR = 0x1		/* Driver is IRM aware */
} ddi_cb_flags_t;

#define	DDI_CB_FLAG_VALID(f)	((f) & DDI_CB_FLAG_INTR)

typedef int	(*ddi_cb_func_t)(dev_info_t *dip, ddi_cb_action_t action,
		    void *cbarg, void *arg1, void *arg2);

typedef struct ddi_cb {
	uint64_t	cb_flags;
	dev_info_t	*cb_dip;
	ddi_cb_func_t	cb_func;
	void		*cb_arg1;
	void		*cb_arg2;
} ddi_cb_t;

/*
 * dev_info:	The main device information structure this is intended to be
 *		opaque to drivers and drivers should use ddi functions to
 *		access *all* driver accessible fields.
 *
 * devi_parent_data includes property lists (interrupts, registers, etc.)
 * devi_driver_data includes whatever the driver wants to place there.
 */
struct devinfo_audit;

typedef struct devi_port {
	union {
		struct {
			uint32_t type;
			uint32_t pad;
		} port;
		uint64_t type64;
	} info;
	void	*priv_p;
} devi_port_t;

typedef struct devi_bus_priv {
	devi_port_t port_up;
	devi_port_t port_down;
} devi_bus_priv_t;

#if defined(__x86)
struct iommulib_unit;
typedef struct iommulib_unit *iommulib_handle_t;
struct iommulib_nex;
typedef struct iommulib_nex *iommulib_nexhandle_t;
#endif

typedef uint8_t	ndi_flavor_t;
struct ddi_hp_cn_handle;

struct in_node;

struct dev_info  {

	struct dev_info *devi_parent;	/* my parent node in tree	*/
	struct dev_info *devi_child;	/* my child list head		*/
	struct dev_info *devi_sibling;	/* next element on my level	*/

	char	*devi_binding_name;	/* name used to bind driver:	*/
					/* shared storage, points to	*/
					/* devi_node_name, devi_compat_names */
					/* or devi_rebinding_name	*/

	char	*devi_addr;		/* address part of name		*/

	int	devi_nodeid;		/* device nodeid		*/
	int	devi_instance;		/* device instance number	*/

	struct dev_ops *devi_ops;	/* driver operations		*/

	void	*devi_parent_data;	/* parent private data		*/
	void	*devi_driver_data;	/* driver private data		*/

	ddi_prop_t *devi_drv_prop_ptr;	/* head of driver prop list */
	ddi_prop_t *devi_sys_prop_ptr;	/* head of system prop list */

	struct ddi_minor_data *devi_minor;	/* head of minor list */
	struct dev_info *devi_next;	/* Next instance of this device */
	kmutex_t devi_lock;		/* Protects per-devinfo data */

	/* logical parents for busop primitives */

	struct dev_info *devi_bus_map_fault;	/* bus_map_fault parent	 */
	void		*devi_obsolete;		/* obsolete placeholder */
	struct dev_info *devi_bus_dma_allochdl; /* bus_dma_newhdl parent */
	struct dev_info *devi_bus_dma_freehdl;  /* bus_dma_freehdl parent */
	struct dev_info *devi_bus_dma_bindhdl;  /* bus_dma_bindhdl parent */
	struct dev_info *devi_bus_dma_unbindhdl; /* bus_dma_unbindhdl parent */
	struct dev_info *devi_bus_dma_flush;    /* bus_dma_flush parent	 */
	struct dev_info *devi_bus_dma_win;	/* bus_dma_win parent	 */
	struct dev_info *devi_bus_dma_ctl;	/* bus_dma_ctl parent	 */
	struct dev_info	*devi_bus_ctl;		/* bus_ctl parent	 */

	ddi_prop_t *devi_hw_prop_ptr;		/* head of hw prop list */

	char	*devi_node_name;		/* The 'name' of the node */
	char	*devi_compat_names;		/* A list of driver names */
	size_t	devi_compat_length;		/* Size of compat_names */

	int (*devi_bus_dma_bindfunc)(dev_info_t *, dev_info_t *,
	    ddi_dma_handle_t, struct ddi_dma_req *, ddi_dma_cookie_t *,
	    uint_t *);
	int (*devi_bus_dma_unbindfunc)(dev_info_t *, dev_info_t *,
	    ddi_dma_handle_t);

	char		*devi_devid_str;	/* registered device id */

	/*
	 * power management entries
	 * components exist even if the device is not currently power managed
	 */
	struct pm_info *devi_pm_info;		/* 0 => dev not power managed */
	uint_t		devi_pm_flags;		/* pm flags */
	int		devi_pm_num_components;	/* number of components */
	size_t		devi_pm_comp_size;	/* size of devi_components */
	struct pm_component *devi_pm_components; /* array of pm components */
	struct dev_info *devi_pm_ppm;		/* ppm attached to this one */
	void		*devi_pm_ppm_private;	/* for use by ppm driver */
	int		devi_pm_dev_thresh;	/* "device" threshold */
	uint_t		devi_pm_kidsupcnt;	/* # of kids powered up */
	struct pm_scan	*devi_pm_scan;		/* pm scan info */
	uint_t		devi_pm_noinvolpm;	/* # of descendents no-invol */
	uint_t		devi_pm_volpmd;		/* # of voluntarily pm'ed */
	kmutex_t	devi_pm_lock;		/* pm lock for state */
	kmutex_t	devi_pm_busy_lock;	/* for component busy count */

	uint_t		devi_state;		/* device/bus state flags */
						/* see below for definitions */
	kcondvar_t	devi_cv;		/* cv */
	int		devi_ref;		/* reference count */

	dacf_rsrvlist_t *devi_dacf_tasks;	/* dacf reservation queue */

	ddi_node_class_t devi_node_class;	/* Node class */
	int		devi_node_attributes;	/* Node attributes: See below */

	char		*devi_device_class;

	/*
	 * New mpxio kernel hooks entries
	 */
	int		devi_mdi_component;	/* mpxio component type */
	void		*devi_mdi_client;	/* mpxio client information */
	void		*devi_mdi_xhci;		/* vhci/phci info */

	ddi_prop_list_t	*devi_global_prop_list;	/* driver global properties */
	major_t		devi_major;		/* driver major number */
	ddi_node_state_t devi_node_state;	/* state of node */
	uint_t		devi_flags;		/* configuration flags */
	int		devi_circular;		/* for recursive operations */
	void		*devi_busy_thread;	/* thread operating on node */
	void		*devi_taskq;		/* hotplug taskq */

	/* device driver statistical and audit info */
	struct devinfo_audit *devi_audit;		/* last state change */

	/*
	 * FMA support for resource caches and error handlers
	 */
	struct i_ddi_fmhdl	*devi_fmhdl;

	uint_t		devi_cpr_flags;

	/* Owned by DDI interrupt framework */
	devinfo_intr_t	*devi_intr_p;

	void		*devi_nex_pm;		/* nexus PM private */

	char		*devi_addr_buf;		/* buffer for devi_addr */

	char		*devi_rebinding_name;	/* binding_name of rebind */

	/* For device contracts that have this dip's minor node as resource */
	kmutex_t	devi_ct_lock;		/* contract lock */
	kcondvar_t	devi_ct_cv;		/* contract cv */
	int		devi_ct_count;		/* # of outstanding responses */
	int		devi_ct_neg;		/* neg. occurred on dip */
	list_t		devi_ct;

	/* owned by bus framework */
	devi_bus_priv_t	devi_bus;		/* bus private data */

	/* Declarations of the pure dynamic properties to snapshot */
	struct i_ddi_prop_dyn	*devi_prop_dyn_driver;	/* prop_op */
	struct i_ddi_prop_dyn	*devi_prop_dyn_parent;	/* bus_prop_op */

#if defined(__x86)
	/* For x86 (Intel and AMD) IOMMU support */
	void		*devi_iommu;
	iommulib_handle_t	devi_iommulib_handle;
	iommulib_nexhandle_t	devi_iommulib_nex_handle;
#endif

	/* Generic callback mechanism */
	ddi_cb_t	*devi_cb_p;

	/* ndi 'flavors' */
	ndi_flavor_t	devi_flavor;		/* flavor assigned by parent */
	ndi_flavor_t	devi_flavorv_n;		/* number of child-flavors */
	void		**devi_flavorv;		/* child-flavor specific data */

	/* Owned by hotplug framework */
	struct ddi_hp_cn_handle *devi_hp_hdlp;   /* hotplug handle list */

	struct in_node  *devi_in_node; /* pointer to devinfo node's in_node_t */

	/* detach event data */
	char	*devi_ev_path;
	int	devi_ev_instance;
};

#define	DEVI(dev_info_type)	((struct dev_info *)(dev_info_type))

/*
 * NB: The 'name' field, for compatibility with old code (both existing
 * device drivers and userland code), is now defined as the name used
 * to bind the node to a device driver, and not the device node name.
 * If the device node name does not define a binding to a device driver,
 * and the framework uses a different algorithm to create the binding to
 * the driver, the node name and binding name will be different.
 *
 * Note that this implies that the node name plus instance number does
 * NOT create a unique driver id; only the binding name plus instance
 * number creates a unique driver id.
 *
 * New code should not use 'devi_name'; use 'devi_binding_name' or
 * 'devi_node_name' and/or the routines that access those fields.
 */

#define	devi_name devi_binding_name

/*
 * DDI_CF1, DDI_CF2 and DDI_DRV_UNLOADED are obsolete. They are kept
 * around to allow legacy drivers to to compile.
 */
#define	DDI_CF1(devi)		(DEVI(devi)->devi_addr != NULL)
#define	DDI_CF2(devi)		(DEVI(devi)->devi_ops != NULL)
#define	DDI_DRV_UNLOADED(devi)	(DEVI(devi)->devi_ops == &mod_nodev_ops)

/*
 * The device state flags (devi_state) contains information regarding
 * the state of the device (Online/Offline/Down).  For bus nexus
 * devices, the device state also contains state information regarding
 * the state of the bus represented by this nexus node.
 *
 * Device state information is stored in bits [0-7], bus state in bits
 * [8-15].
 *
 * NOTE: all devi_state updates should be protected by devi_lock.
 */
#define	DEVI_DEVICE_OFFLINE	0x00000001
#define	DEVI_DEVICE_DOWN	0x00000002
#define	DEVI_DEVICE_DEGRADED	0x00000004
#define	DEVI_DEVICE_REMOVED	0x00000008 /* hardware removed */

#define	DEVI_BUS_QUIESCED	0x00000100
#define	DEVI_BUS_DOWN		0x00000200
#define	DEVI_NDI_CONFIG		0x00000400 /* perform config when attaching */

#define	DEVI_S_ATTACHING	0x00010000
#define	DEVI_S_DETACHING	0x00020000
#define	DEVI_S_ONLINING		0x00040000
#define	DEVI_S_OFFLINING	0x00080000

#define	DEVI_S_INVOKING_DACF	0x00100000 /* busy invoking a dacf task */

#define	DEVI_S_UNBOUND		0x00200000
#define	DEVI_S_REPORT		0x08000000 /* report status change */

#define	DEVI_S_EVADD		0x10000000 /* state of devfs event */
#define	DEVI_S_EVREMOVE		0x20000000 /* state of devfs event */
#define	DEVI_S_NEED_RESET	0x40000000 /* devo_reset should be called */

/*
 * Device state macros.
 * o All SET/CLR/DONE users must protect context with devi_lock.
 * o DEVI_SET_DEVICE_ONLINE users must do their own DEVI_SET_REPORT.
 * o DEVI_SET_DEVICE_{DOWN|DEGRADED|UP} should only be used when !OFFLINE.
 * o DEVI_SET_DEVICE_UP clears DOWN and DEGRADED.
 */
#define	DEVI_IS_DEVICE_OFFLINE(dip)					\
	((DEVI(dip)->devi_state & DEVI_DEVICE_OFFLINE) == DEVI_DEVICE_OFFLINE)

#define	DEVI_SET_DEVICE_ONLINE(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	if (DEVI(dip)->devi_state & DEVI_DEVICE_DEGRADED) {		\
		mutex_exit(&DEVI(dip)->devi_lock);			\
		e_ddi_undegrade_finalize(dip);				\
		mutex_enter(&DEVI(dip)->devi_lock);			\
	}								\
	/* setting ONLINE clears DOWN, DEGRADED, OFFLINE */		\
	DEVI(dip)->devi_state &= ~(DEVI_DEVICE_DOWN |			\
	    DEVI_DEVICE_DEGRADED | DEVI_DEVICE_OFFLINE);		\
	}

#define	DEVI_SET_DEVICE_OFFLINE(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= (DEVI_DEVICE_OFFLINE | DEVI_S_REPORT);	\
	}

#define	DEVI_IS_DEVICE_DOWN(dip)					\
	((DEVI(dip)->devi_state & DEVI_DEVICE_DOWN) == DEVI_DEVICE_DOWN)

#define	DEVI_SET_DEVICE_DOWN(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	ASSERT(!DEVI_IS_DEVICE_OFFLINE(dip));				\
	DEVI(dip)->devi_state |= (DEVI_DEVICE_DOWN | DEVI_S_REPORT);	\
	}

#define	DEVI_IS_DEVICE_DEGRADED(dip)					\
	((DEVI(dip)->devi_state &					\
	    (DEVI_DEVICE_DEGRADED|DEVI_DEVICE_DOWN)) == DEVI_DEVICE_DEGRADED)

#define	DEVI_SET_DEVICE_DEGRADED(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	ASSERT(!DEVI_IS_DEVICE_OFFLINE(dip));				\
	mutex_exit(&DEVI(dip)->devi_lock);				\
	e_ddi_degrade_finalize(dip);					\
	mutex_enter(&DEVI(dip)->devi_lock);				\
	DEVI(dip)->devi_state |= (DEVI_DEVICE_DEGRADED | DEVI_S_REPORT); \
	}

#define	DEVI_SET_DEVICE_UP(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	ASSERT(!DEVI_IS_DEVICE_OFFLINE(dip));				\
	if (DEVI(dip)->devi_state & DEVI_DEVICE_DEGRADED) {		\
		mutex_exit(&DEVI(dip)->devi_lock);			\
		e_ddi_undegrade_finalize(dip);				\
		mutex_enter(&DEVI(dip)->devi_lock);			\
	}								\
	DEVI(dip)->devi_state &= ~(DEVI_DEVICE_DEGRADED | DEVI_DEVICE_DOWN); \
	DEVI(dip)->devi_state |= DEVI_S_REPORT;				\
	}

/* Device removal and insertion */
#define	DEVI_IS_DEVICE_REMOVED(dip)					\
	((DEVI(dip)->devi_state & DEVI_DEVICE_REMOVED) == DEVI_DEVICE_REMOVED)

#define	DEVI_SET_DEVICE_REMOVED(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= DEVI_DEVICE_REMOVED | DEVI_S_REPORT;	\
	}

#define	DEVI_SET_DEVICE_REINSERTED(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_DEVICE_REMOVED;			\
	DEVI(dip)->devi_state |= DEVI_S_REPORT;				\
	}

/* Bus state change macros */
#define	DEVI_IS_BUS_QUIESCED(dip)					\
	((DEVI(dip)->devi_state & DEVI_BUS_QUIESCED) == DEVI_BUS_QUIESCED)

#define	DEVI_SET_BUS_ACTIVE(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_BUS_QUIESCED;			\
	DEVI(dip)->devi_state |= DEVI_S_REPORT;				\
	}

#define	DEVI_SET_BUS_QUIESCE(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= (DEVI_BUS_QUIESCED | DEVI_S_REPORT);	\
	}

#define	DEVI_IS_BUS_DOWN(dip)						\
	((DEVI(dip)->devi_state & DEVI_BUS_DOWN) == DEVI_BUS_DOWN)

#define	DEVI_SET_BUS_UP(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_BUS_DOWN;			\
	DEVI(dip)->devi_state |= DEVI_S_REPORT;				\
	}

#define	DEVI_SET_BUS_DOWN(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= (DEVI_BUS_DOWN | DEVI_S_REPORT);	\
	}

/* Status change report needed */
#define	DEVI_NEED_REPORT(dip)						\
	((DEVI(dip)->devi_state & DEVI_S_REPORT) == DEVI_S_REPORT)

#define	DEVI_SET_REPORT(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= DEVI_S_REPORT;				\
	}

#define	DEVI_REPORT_DONE(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_S_REPORT;			\
	}

/* Do an NDI_CONFIG for its children */
#define	DEVI_NEED_NDI_CONFIG(dip)					\
	((DEVI(dip)->devi_state & DEVI_NDI_CONFIG) == DEVI_NDI_CONFIG)

#define	DEVI_SET_NDI_CONFIG(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= DEVI_NDI_CONFIG;			\
	}

#define	DEVI_CLR_NDI_CONFIG(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_NDI_CONFIG;			\
	}

/* Attaching or detaching state */
#define	DEVI_IS_ATTACHING(dip)						\
	((DEVI(dip)->devi_state & DEVI_S_ATTACHING) == DEVI_S_ATTACHING)

#define	DEVI_SET_ATTACHING(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= DEVI_S_ATTACHING;			\
	}

#define	DEVI_CLR_ATTACHING(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_S_ATTACHING;			\
	}

#define	DEVI_IS_DETACHING(dip)						\
	((DEVI(dip)->devi_state & DEVI_S_DETACHING) == DEVI_S_DETACHING)

#define	DEVI_SET_DETACHING(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= DEVI_S_DETACHING;			\
	}

#define	DEVI_CLR_DETACHING(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_S_DETACHING;			\
	}

/* Onlining or offlining state */
#define	DEVI_IS_ONLINING(dip)						\
	((DEVI(dip)->devi_state & DEVI_S_ONLINING) == DEVI_S_ONLINING)

#define	DEVI_SET_ONLINING(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= DEVI_S_ONLINING;			\
	}

#define	DEVI_CLR_ONLINING(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_S_ONLINING;			\
	}

#define	DEVI_IS_OFFLINING(dip)						\
	((DEVI(dip)->devi_state & DEVI_S_OFFLINING) == DEVI_S_OFFLINING)

#define	DEVI_SET_OFFLINING(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= DEVI_S_OFFLINING;			\
	}

#define	DEVI_CLR_OFFLINING(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_S_OFFLINING;			\
	}

#define	DEVI_IS_IN_RECONFIG(dip)					\
	(DEVI(dip)->devi_state & (DEVI_S_OFFLINING | DEVI_S_ONLINING))

/* Busy invoking a dacf task against this node */
#define	DEVI_IS_INVOKING_DACF(dip)					\
	((DEVI(dip)->devi_state & DEVI_S_INVOKING_DACF) == DEVI_S_INVOKING_DACF)

#define	DEVI_SET_INVOKING_DACF(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= DEVI_S_INVOKING_DACF;			\
	}

#define	DEVI_CLR_INVOKING_DACF(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_S_INVOKING_DACF;			\
	}

/* Events for add/remove */
#define	DEVI_EVADD(dip)							\
	((DEVI(dip)->devi_state & DEVI_S_EVADD) == DEVI_S_EVADD)

#define	DEVI_SET_EVADD(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_S_EVREMOVE;			\
	DEVI(dip)->devi_state |= DEVI_S_EVADD;				\
	}

#define	DEVI_EVREMOVE(dip)						\
	((DEVI(dip)->devi_state & DEVI_S_EVREMOVE) == DEVI_S_EVREMOVE)

#define	DEVI_SET_EVREMOVE(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_S_EVADD;				\
	DEVI(dip)->devi_state |= DEVI_S_EVREMOVE;			\
	}

#define	DEVI_SET_EVUNINIT(dip)		{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~(DEVI_S_EVADD | DEVI_S_EVREMOVE);	\
	}

/* Need to call the devo_reset entry point for this device at shutdown */
#define	DEVI_NEED_RESET(dip)						\
	((DEVI(dip)->devi_state & DEVI_S_NEED_RESET) == DEVI_S_NEED_RESET)

#define	DEVI_SET_NEED_RESET(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state |= DEVI_S_NEED_RESET;			\
	}

#define	DEVI_CLR_NEED_RESET(dip)	{				\
	ASSERT(mutex_owned(&DEVI(dip)->devi_lock));			\
	DEVI(dip)->devi_state &= ~DEVI_S_NEED_RESET;			\
	}

/*
 * devi_flags bits
 *
 * NOTE: all devi_state updates should be protected by devi_lock.
 */
#define	DEVI_BUSY		0x00000001 /* busy configuring children */
#define	DEVI_MADE_CHILDREN	0x00000002 /* children made from specs */
#define	DEVI_ATTACHED_CHILDREN	0x00000004 /* attached all existing children */
#define	DEVI_BRANCH_HELD	0x00000008 /* branch rooted at this dip held */
#define	DEVI_NO_BIND		0x00000010 /* prevent driver binding */
#define	DEVI_CACHED_DEVID	0x00000020 /* devid cached in devid cache */
#define	DEVI_PHCI_SIGNALS_VHCI	0x00000040 /* pHCI ndi_devi_exit signals vHCI */
#define	DEVI_REBIND		0x00000080 /* post initchild driver rebind */
#define	DEVI_RETIRED		0x00000100 /* device is retired */
#define	DEVI_RETIRING		0x00000200 /* being evaluated for retire */
#define	DEVI_R_CONSTRAINT	0x00000400 /* constraints have been applied  */
#define	DEVI_R_BLOCKED		0x00000800 /* constraints block retire  */
#define	DEVI_CT_NOP		0x00001000 /* NOP contract event occurred */
#define	DEVI_PCI_DEVICE		0x00002000 /* dip is PCI */

#define	DEVI_BUSY_CHANGING(dip)	(DEVI(dip)->devi_flags & DEVI_BUSY)
#define	DEVI_BUSY_OWNED(dip)	(DEVI_BUSY_CHANGING(dip) &&	\
	((DEVI(dip))->devi_busy_thread == curthread))

#define	DEVI_IS_PCI(dip)	(DEVI(dip)->devi_flags & DEVI_PCI_DEVICE)
#define	DEVI_SET_PCI(dip)	(DEVI(dip)->devi_flags |= (DEVI_PCI_DEVICE))

char	*i_ddi_devi_class(dev_info_t *);
int	i_ddi_set_devi_class(dev_info_t *, char *, int);

/*
 * This structure represents one piece of bus space occupied by a given
 * device. It is used in an array for devices with multiple address windows.
 */
struct regspec {
	uint_t regspec_bustype;		/* cookie for bus type it's on */
	uint_t regspec_addr;		/* address of reg relative to bus */
	uint_t regspec_size;		/* size of this register set */
};

/*
 * This structure represents one piece of nexus bus space.
 * It is used in an array for nexi with multiple bus spaces
 * to define the childs offsets in the parents bus space.
 */
struct rangespec {
	uint_t rng_cbustype;		/* Child's address, hi order */
	uint_t rng_coffset;		/* Child's address, lo order */
	uint_t rng_bustype;		/* Parent's address, hi order */
	uint_t rng_offset;		/* Parent's address, lo order */
	uint_t rng_size;		/* size of space for this entry */
};

#ifdef _KERNEL

typedef enum {
	DDI_PRE = 0,
	DDI_POST = 1
} ddi_pre_post_t;

/*
 * This structure represents notification of a child attach event
 * These could both be the same if attach/detach commands were in the
 * same name space.
 * Note that the target dip is passed as an arg already.
 */
struct attachspec {
	ddi_attach_cmd_t cmd;	/* type of event */
	ddi_pre_post_t	when;	/* one of DDI_PRE or DDI_POST */
	dev_info_t	*pdip;	/* parent of attaching node */
	int		result;	/* result of attach op (post command only) */
};

/*
 * This structure represents notification of a child detach event
 * Note that the target dip is passed as an arg already.
 */
struct detachspec {
	ddi_detach_cmd_t cmd;	/* type of event */
	ddi_pre_post_t	when;	/* one of DDI_PRE or DDI_POST */
	dev_info_t	*pdip;	/* parent of detaching node */
	int		result;	/* result of detach op (post command only) */
};

#endif /* _KERNEL */

typedef enum {
	DDM_MINOR = 0,
	DDM_ALIAS,
	DDM_DEFAULT,
	DDM_INTERNAL_PATH
} ddi_minor_type;

/* implementation flags for driver specified device access control */
#define	DM_NO_FSPERM	0x1

struct devplcy;

struct ddi_minor {
	char		*name;		/* name of node */
	dev_t		dev;		/* device number */
	int		spec_type;	/* block or char */
	int		flags;		/* access flags */
	char		*node_type;	/* block, byte, serial, network */
	struct devplcy	*node_priv;	/* privilege for this minor */
	mode_t		priv_mode;	/* default apparent privilege mode */
};

/*
 * devi_node_attributes contains node attributes private to the
 * ddi implementation. As a consumer, do not use these bit definitions
 * directly, use the ndi functions that check for the existence of the
 * specific node attributes.
 *
 * DDI_PERSISTENT indicates a 'persistent' node; one that is not
 * automatically freed by the framework if the driver is unloaded
 * or the driver fails to attach to this node.
 *
 * DDI_AUTO_ASSIGNED_NODEID indicates that the nodeid was auto-assigned
 * by the framework and should be auto-freed if the node is removed.
 *
 * DDI_VHCI_NODE indicates that the node type is VHCI. This flag
 * must be set by ndi_devi_config_vhci() routine only.
 *
 * DDI_HIDDEN_NODE indicates that the node should not show up in snapshots
 * or in /devices.
 *
 * DDI_HOTPLUG_NODE indicates that the node created by nexus hotplug.
 */
#define	DDI_PERSISTENT			0x01
#define	DDI_AUTO_ASSIGNED_NODEID	0x02
#define	DDI_VHCI_NODE			0x04
#define	DDI_HIDDEN_NODE			0x08
#define	DDI_HOTPLUG_NODE		0x10

#define	DEVI_VHCI_NODE(dip)						\
	(DEVI(dip)->devi_node_attributes & DDI_VHCI_NODE)

/*
 * The ddi_minor_data structure gets filled in by ddi_create_minor_node.
 * It then gets attached to the devinfo node as a property.
 */
struct ddi_minor_data {
	struct ddi_minor_data *next;	/* next one in the chain */
	dev_info_t	*dip;		/* pointer to devinfo node */
	ddi_minor_type	type;		/* Following data type */
	struct ddi_minor d_minor;	/* Actual minor node data */
};

#define	ddm_name	d_minor.name
#define	ddm_dev		d_minor.dev
#define	ddm_flags	d_minor.flags
#define	ddm_spec_type	d_minor.spec_type
#define	ddm_node_type	d_minor.node_type
#define	ddm_node_priv	d_minor.node_priv
#define	ddm_priv_mode	d_minor.priv_mode

/*
 * parent private data structure contains register, interrupt, property
 * and range information.
 */
struct ddi_parent_private_data {
	int par_nreg;			/* number of regs */
	struct regspec *par_reg;	/* array of regs */
	int par_nintr;			/* number of interrupts */
	struct intrspec *par_intr;	/* array of possible interrupts */
	int par_nrng;			/* number of ranges */
	struct rangespec *par_rng;	/* array of ranges */
};
#define	DEVI_PD(d)	\
	((struct ddi_parent_private_data *)DEVI((d))->devi_parent_data)

#define	sparc_pd_getnreg(dev)		(DEVI_PD(dev)->par_nreg)
#define	sparc_pd_getnintr(dev)		(DEVI_PD(dev)->par_nintr)
#define	sparc_pd_getnrng(dev)		(DEVI_PD(dev)->par_nrng)
#define	sparc_pd_getreg(dev, n)		(&DEVI_PD(dev)->par_reg[(n)])
#define	sparc_pd_getintr(dev, n)	(&DEVI_PD(dev)->par_intr[(n)])
#define	sparc_pd_getrng(dev, n)		(&DEVI_PD(dev)->par_rng[(n)])

#ifdef _KERNEL
/*
 * This data structure is private to the indexed soft state allocator.
 */
typedef struct i_ddi_soft_state {
	void		**array;	/* the array of pointers */
	kmutex_t	lock;		/* serialize access to this struct */
	size_t		size;		/* how many bytes per state struct */
	size_t		n_items;	/* how many structs herein */
	struct i_ddi_soft_state *next;	/* 'dirty' elements */
} i_ddi_soft_state;

/*
 * This data structure is private to the stringhashed soft state allocator.
 */
typedef struct i_ddi_soft_state_bystr {
	size_t		ss_size;	/* how many bytes per state struct */
	mod_hash_t	*ss_mod_hash;	/* hash implementation */
} i_ddi_soft_state_bystr;

/*
 * This data structure is private to the ddi_strid_* implementation
 */
typedef struct i_ddi_strid {
	size_t		strid_chunksz;
	size_t		strid_spacesz;
	id_space_t	*strid_space;
	mod_hash_t	*strid_byid;
	mod_hash_t	*strid_bystr;
} i_ddi_strid;
#endif /* _KERNEL */

/*
 * Solaris DDI DMA implementation structure and function definitions.
 *
 * Note: no callers of DDI functions must depend upon data structures
 * declared below. They are not guaranteed to remain constant.
 */

/*
 * Implementation DMA mapping structure.
 *
 * The publicly visible ddi_dma_req structure is filled
 * in by a caller that wishes to map a memory object
 * for DMA. Internal to this implementation of the public
 * DDI DMA functions this request structure is put together
 * with bus nexus specific functions that have additional
 * information and constraints as to how to go about doing
 * the requested mapping function
 *
 * In this implementation, some of the information from the
 * original requester is retained throughout the lifetime
 * of the I/O mapping being active.
 */

/*
 * This is the implementation specific description
 * of how we've mapped an object for DMA.
 */
#if defined(__sparc)
typedef struct ddi_dma_impl {
	/*
	 * DMA mapping information
	 */
	ulong_t	dmai_mapping;	/* mapping cookie */

	/*
	 * Size of the current mapping, in bytes.
	 *
	 * Note that this is distinct from the size of the object being mapped
	 * for DVMA. We might have only a portion of the object mapped at any
	 * given point in time.
	 */
	uint_t	dmai_size;

	/*
	 * Offset, in bytes, into object that is currently mapped.
	 */
	off_t	dmai_offset;

	/*
	 * Information gathered from the original DMA mapping
	 * request and saved for the lifetime of the mapping.
	 */
	uint_t		dmai_minxfer;
	uint_t		dmai_burstsizes;
	uint_t		dmai_ndvmapages;
	uint_t		dmai_pool;	/* cached DVMA space */
	uint_t		dmai_rflags;	/* requester's flags + ours */
	uint_t		dmai_inuse;	/* active handle? */
	uint_t		dmai_nwin;
	uint_t		dmai_winsize;
	caddr_t		dmai_nexus_private;
	void		*dmai_iopte;
	uint_t		*dmai_sbi;
	void		*dmai_minfo;	/* random mapping information */
	dev_info_t	*dmai_rdip;	/* original requester's dev_info_t */
	ddi_dma_obj_t	dmai_object;	/* requester's object */
	ddi_dma_attr_t	dmai_attr;	/* DMA attributes */
	ddi_dma_cookie_t *dmai_cookie;	/* pointer to first DMA cookie */

	int		(*dmai_fault_check)(struct ddi_dma_impl *handle);
	void		(*dmai_fault_notify)(struct ddi_dma_impl *handle);
	int		dmai_fault;
	ndi_err_t	dmai_error;

} ddi_dma_impl_t;

#elif defined(__x86)

/*
 * ddi_dma_impl portion that genunix (sunddi.c) depends on. x86 rootnex
 * implementation specific state is in dmai_private.
 */
typedef struct ddi_dma_impl {
	ddi_dma_cookie_t *dmai_cookie; /* array of DMA cookies */
	void		*dmai_private;

	/*
	 * Information gathered from the original dma mapping
	 * request and saved for the lifetime of the mapping.
	 */
	uint_t		dmai_minxfer;
	uint_t		dmai_burstsizes;
	uint_t		dmai_rflags;	/* requester's flags + ours */
	int		dmai_nwin;
	dev_info_t	*dmai_rdip;	/* original requester's dev_info_t */

	ddi_dma_attr_t	dmai_attr;	/* DMA attributes */

	int		(*dmai_fault_check)(struct ddi_dma_impl *handle);
	void		(*dmai_fault_notify)(struct ddi_dma_impl *handle);
	int		dmai_fault;
	ndi_err_t	dmai_error;
} ddi_dma_impl_t;

#else
#error "struct ddi_dma_impl not defined for this architecture"
#endif  /* defined(__sparc) */

/*
 * For now DMA segments share state with the DMA handle
 */
typedef ddi_dma_impl_t ddi_dma_seg_impl_t;

/*
 * These flags use reserved bits from the dma request flags.
 *
 * A note about the DMP_NOSYNC flags: the root nexus will
 * set these as it sees best. If an intermediate nexus
 * actually needs these operations, then during the unwind
 * from the call to ddi_dma_bind, the nexus driver *must*
 * clear the appropriate flag(s). This is because, as an
 * optimization, ddi_dma_sync(9F) looks at these flags before
 * deciding to spend the time going back up the tree.
 */

#define	_DMCM1	DDI_DMA_RDWR|DDI_DMA_REDZONE|DDI_DMA_PARTIAL
#define	_DMCM2	DDI_DMA_CONSISTENT|DMP_VMEREQ
#define	DMP_DDIFLAGS	(_DMCM1|_DMCM2)
#define	DMP_SHADOW	0x20
#define	DMP_LKIOPB	0x40
#define	DMP_LKSYSV	0x80
#define	DMP_IOCACHE	0x100
#define	DMP_USEHAT	0x200
#define	DMP_PHYSADDR	0x400
#define	DMP_INVALID	0x800
#define	DMP_NOLIMIT	0x1000
#define	DMP_VMEREQ	0x10000000
#define	DMP_BYPASSNEXUS	0x20000000
#define	DMP_NODEVSYNC	0x40000000
#define	DMP_NOCPUSYNC	0x80000000
#define	DMP_NOSYNC	(DMP_NODEVSYNC|DMP_NOCPUSYNC)

/*
 * In order to complete a device to device mapping that
 * has percolated as high as an IU nexus (gone that high
 * because the DMA request is a VADDR type), we define
 * structure to use with the DDI_CTLOPS_DMAPMAPC request
 * that re-traverses the request tree to finish the
 * DMA 'mapping' for a device.
 */
struct dma_phys_mapc {
	struct ddi_dma_req *dma_req;	/* original request */
	ddi_dma_impl_t *mp;		/* current handle, or none */
	int nptes;			/* number of ptes */
	void *ptes;			/* ptes already read */
};

#define	MAXCALLBACK		20

/*
 * Callback definitions
 */
struct ddi_callback {
	struct ddi_callback	*c_nfree;
	struct ddi_callback	*c_nlist;
	int			(*c_call)();
	int			c_count;
	caddr_t			c_arg;
	size_t			c_size;
};

/*
 * Pure dynamic property declaration. A pure dynamic property is a property
 * for which a driver's prop_op(9E) implementation will return a value on
 * demand, but the property name does not exist on a property list (global,
 * driver, system, or hardware) - the person asking for the value must know
 * the name and type information.
 *
 * For a pure dynamic property to show up in a di_init() devinfo shapshot, the
 * devinfo driver must know name and type. The i_ddi_prop_dyn_t mechanism
 * allows a driver to define an array of the name/type information of its
 * dynamic properties. When a driver declares its dynamic properties in a
 * i_ddi_prop_dyn_t array, and registers that array using
 * i_ddi_prop_dyn_driver_set() the devinfo driver has sufficient information
 * to represent the properties in a snapshot - calling the driver's
 * prop_op(9E) to obtain values.
 *
 * The last element of a i_ddi_prop_dyn_t is detected via a NULL dp_name value.
 *
 * A pure dynamic property name associated with a minor_node/dev_t should be
 * defined with a dp_spec_type of S_IFCHR or S_IFBLK, as appropriate.  The
 * driver's prop_op(9E) entry point will be called for all
 * ddi_create_minor_node(9F) nodes of the specified spec_type. For a driver
 * where not all minor_node/dev_t combinations support the same named
 * properties, it is the responsibility of the prop_op(9E) implementation to
 * sort out what combinations are appropriate.
 *
 * A pure dynamic property of a devinfo node should be defined with a
 * dp_spec_type of 0.
 *
 * NB: Public DDI property interfaces no longer support pure dynamic
 * properties, but they are still still used.  A prime example is the cmlb
 * implementation of size(9P) properties. Using pure dynamic properties
 * reduces the space required to maintain per-partition information. Since
 * there are no public interfaces to create pure dynamic properties,
 * the i_ddi_prop_dyn_t mechanism should remain private.
 */
typedef struct i_ddi_prop_dyn {
	char	*dp_name;		/* name of dynamic property */
	int	dp_type;		/* DDI_PROP_TYPE_ of property */
	int	dp_spec_type;		/* 0, S_IFCHR, S_IFBLK */
} i_ddi_prop_dyn_t;
void			i_ddi_prop_dyn_driver_set(dev_info_t *,
			    i_ddi_prop_dyn_t *);
i_ddi_prop_dyn_t	*i_ddi_prop_dyn_driver_get(dev_info_t *);
void			i_ddi_prop_dyn_parent_set(dev_info_t *,
			    i_ddi_prop_dyn_t *);
i_ddi_prop_dyn_t	*i_ddi_prop_dyn_parent_get(dev_info_t *);
void			i_ddi_prop_dyn_cache_invalidate(dev_info_t *,
			    i_ddi_prop_dyn_t *);

/*
 * Device id - Internal definition.
 */
#define	DEVID_MAGIC_MSB		0x69
#define	DEVID_MAGIC_LSB		0x64
#define	DEVID_REV_MSB		0x00
#define	DEVID_REV_LSB		0x01
#define	DEVID_HINT_SIZE		4

typedef struct impl_devid {
	uchar_t	did_magic_hi;			/* device id magic # (msb) */
	uchar_t	did_magic_lo;			/* device id magic # (lsb) */
	uchar_t	did_rev_hi;			/* device id revision # (msb) */
	uchar_t	did_rev_lo;			/* device id revision # (lsb) */
	uchar_t	did_type_hi;			/* device id type (msb) */
	uchar_t	did_type_lo;			/* device id type (lsb) */
	uchar_t	did_len_hi;			/* length of devid data (msb) */
	uchar_t	did_len_lo;			/* length of devid data (lsb) */
	char	did_driver[DEVID_HINT_SIZE];	/* driver name - HINT */
	char	did_id[1];			/* start of device id data */
} impl_devid_t;

#define	DEVID_GETTYPE(devid)		((ushort_t) \
					    (((devid)->did_type_hi << NBBY) + \
					    (devid)->did_type_lo))

#define	DEVID_FORMTYPE(devid, type)	(devid)->did_type_hi = hibyte((type)); \
					(devid)->did_type_lo = lobyte((type));

#define	DEVID_GETLEN(devid)		((ushort_t) \
					    (((devid)->did_len_hi << NBBY) + \
					    (devid)->did_len_lo))

#define	DEVID_FORMLEN(devid, len)	(devid)->did_len_hi = hibyte((len)); \
					(devid)->did_len_lo = lobyte((len));

/*
 * Per PSARC/1995/352, a binary devid contains fields for <magic number>,
 * <revision>, <driver_hint>, <type>, <id_length>, and the <id> itself.
 * This proposal would encode the binary devid into a string consisting
 * of "<magic><revision>,<driver_hint>@<type><id>" as indicated below
 * (<id_length> is rederived from the length of the string
 * representation of the <id>):
 *
 *	<magic>		->"id"
 *
 *	<rev>		->"%d"	// "0" -> type of DEVID_NONE  "id0"
 *				// NOTE: PSARC/1995/352 <revision> is "1".
 *				// NOTE: support limited to 10 revisions
 *				//	in current implementation
 *
 *	<driver_hint>	->"%s"	// "sd"/"ssd"
 *				// NOTE: driver names limited to 4
 *				//	characters for <revision> "1"
 *
 *	<type>		->'w' |	// DEVID_SCSI3_WWN	<hex_id>
 *			'W' |	// DEVID_SCSI3_WWN	<ascii_id>
 *			't' |	// DEVID_SCSI3_VPD_T10	<hex_id>
 *			'T' |	// DEVID_SCSI3_VPD_T10	<ascii_id>
 *			'x' |	// DEVID_SCSI3_VPD_EUI	<hex_id>
 *			'X' |	// DEVID_SCSI3_VPD_EUI	<ascii_id>
 *			'n' |	// DEVID_SCSI3_VPD_NAA	<hex_id>
 *			'N' |	// DEVID_SCSI3_VPD_NAA	<ascii_id>
 *			's' |	// DEVID_SCSI_SERIAL	<hex_id>
 *			'S' |	// DEVID_SCSI_SERIAL	<ascii_id>
 *			'f' |	// DEVID_FAB		<hex_id>
 *			'F' |	// DEVID_FAB		<ascii_id>
 *			'e' |	// DEVID_ENCAP		<hex_id>
 *			'E' |	// DEVID_ENCAP		<ascii_id>
 *			'a' |	// DEVID_ATA_SERIAL	<hex_id>
 *			'A' |	// DEVID_ATA_SERIAL	<ascii_id>
 *			'u' |	// unknown		<hex_id>
 *			'U'	// unknown		<ascii_id>
 *				// NOTE:lower case -> <hex_id>
 *				//	upper case -> <ascii_id>
 *				// NOTE:this covers all types currently
 *				//	defined for <revision> 1.
 *				// NOTE:a <type> can be added
 *				//	without changing the <revision>.
 *
 *	<id>		-> <ascii_id> |	// <type> is upper case
 *			<hex_id>	// <type> is lower case
 *
 *	<ascii_id>	// only if all bytes of binary <id> field
 *			// are in the set:
 *			//	[A-Z][a-z][0-9]+-.= and space and 0x00
 *			// the encoded form is:
 *			//	[A-Z][a-z][0-9]+-.= and _ and ~
 *			//	NOTE: ' ' <=> '_', 0x00 <=> '~'
 *			// these sets are chosen to avoid shell
 *			// and conflicts with DDI node names.
 *
 *	<hex_id>	// if not <ascii_id>; each byte of binary
 *			// <id> maps a to 2 digit ascii hex
 *			// representation in the string.
 *
 * This encoding provides a meaningful correlation between the /devices
 * path and the devid string where possible.
 *
 *   Fibre:
 *	sbus@6,0/SUNW,socal@d,10000/sf@1,0/ssd@w21000020370bb488,0:c,raw
 *	id1,ssd@w20000020370bb488:c,raw
 *
 *   Copper:
 *	sbus@7,0/SUNW,fas@3,8800000/sd@a,0:c
 *	id1,sd@SIBM_____1XY210__________:c
 */
/* determine if a byte of an id meets ASCII representation requirements */
#define	DEVID_IDBYTE_ISASCII(b)		(				\
	(((b) >= 'a') && ((b) <= 'z')) ||				\
	(((b) >= 'A') && ((b) <= 'Z')) ||				\
	(((b) >= '0') && ((b) <= '9')) ||				\
	(b == '+') || (b == '-') || (b == '.') || (b == '=') ||		\
	(b == ' ') || (b == 0x00))

/* set type to lower case to indicate that the did_id field is ascii */
#define	DEVID_TYPE_SETASCII(c)	(c - 0x20)	/* 'a' -> 'A' */

/* determine from type if did_id field is binary or ascii */
#define	DEVID_TYPE_ISASCII(c)	(((c) >= 'A') && ((c) <= 'Z'))

/* convert type field from binary to ascii */
#define	DEVID_TYPE_BINTOASCII(b)	(				\
	((b) == DEVID_SCSI3_WWN)	? 'w' :				\
	((b) == DEVID_SCSI3_VPD_T10)	? 't' :				\
	((b) == DEVID_SCSI3_VPD_EUI)	? 'x' :				\
	((b) == DEVID_SCSI3_VPD_NAA)	? 'n' :				\
	((b) == DEVID_SCSI_SERIAL)	? 's' :				\
	((b) == DEVID_FAB)		? 'f' :				\
	((b) == DEVID_ENCAP)		? 'e' :				\
	((b) == DEVID_ATA_SERIAL)	? 'a' :				\
	'u')						/* unknown */

/* convert type field from ascii to binary */
#define	DEVID_TYPE_ASCIITOBIN(c)	(				\
	(((c) == 'w') || ((c) == 'W'))	? DEVID_SCSI3_WWN :		\
	(((c) == 't') || ((c) == 'T'))	? DEVID_SCSI3_VPD_T10 :		\
	(((c) == 'x') || ((c) == 'X'))	? DEVID_SCSI3_VPD_EUI :		\
	(((c) == 'n') || ((c) == 'N'))	? DEVID_SCSI3_VPD_NAA :		\
	(((c) == 's') || ((c) == 'S'))	? DEVID_SCSI_SERIAL :		\
	(((c) == 'f') || ((c) == 'F'))	? DEVID_FAB :			\
	(((c) == 'e') || ((c) == 'E'))	? DEVID_ENCAP :			\
	(((c) == 'a') || ((c) == 'A'))	? DEVID_ATA_SERIAL :		\
	DEVID_MAXTYPE +1)				/* unknown */

/* determine if the type should be forced to hex encoding (non-ascii) */
#define	DEVID_TYPE_BIN_FORCEHEX(b) (	\
	((b) == DEVID_SCSI3_WWN) ||	\
	((b) == DEVID_SCSI3_VPD_EUI) ||	\
	((b) == DEVID_SCSI3_VPD_NAA) ||	\
	((b) == DEVID_FAB))

/* determine if the type is from a scsi3 vpd */
#define	IS_DEVID_SCSI3_VPD_TYPE(b) (	\
	((b) == DEVID_SCSI3_VPD_T10) ||	\
	((b) == DEVID_SCSI3_VPD_EUI) ||	\
	((b) == DEVID_SCSI3_VPD_NAA))

/* convert rev field from binary to ascii (only supports 10 revs) */
#define	DEVID_REV_BINTOASCII(b) (b + '0')

/* convert rev field from ascii to binary (only supports 10 revs) */
#define	DEVID_REV_ASCIITOBIN(c) (c - '0')

/* name of devid property */
#define	DEVID_PROP_NAME	"devid"

/*
 * prop_name used by pci_{save,restore}_config_regs()
 */
#define	SAVED_CONFIG_REGS "pci-config-regs"
#define	SAVED_CONFIG_REGS_MASK "pcie-config-regs-mask"
#define	SAVED_CONFIG_REGS_CAPINFO "pci-cap-info"

typedef struct pci_config_header_state {
	uint16_t	chs_command;
	uint8_t		chs_cache_line_size;
	uint8_t		chs_latency_timer;
	uint8_t		chs_header_type;
	uint8_t		chs_sec_latency_timer;
	uint8_t		chs_bridge_control;
	uint32_t	chs_base0;
	uint32_t	chs_base1;
	uint32_t	chs_base2;
	uint32_t	chs_base3;
	uint32_t	chs_base4;
	uint32_t	chs_base5;
} pci_config_header_state_t;

#ifdef _KERNEL

typedef struct pci_cap_save_desc {
	uint16_t	cap_offset;
	uint16_t	cap_id;
	uint32_t	cap_nregs;
} pci_cap_save_desc_t;

typedef struct pci_cap_entry {
	uint16_t		cap_id;
	uint16_t		cap_reg;
	uint16_t		cap_mask;
	uint32_t		cap_ndwords;
	uint32_t (*cap_save_func)(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
	    uint32_t *regbuf, uint32_t ndwords);
} pci_cap_entry_t;

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_IMPLDEFS_H */
