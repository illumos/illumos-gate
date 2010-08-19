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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_SUNNDI_H
#define	_SYS_SUNNDI_H

/*
 * Sun Specific NDI definitions
 */

#include <sys/esunddi.h>
#include <sys/sunddi.h>
#include <sys/obpdefs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	NDI_SUCCESS	DDI_SUCCESS	/* successful return */
#define	NDI_FAILURE	DDI_FAILURE	/* unsuccessful return */
#define	NDI_NOMEM	-2		/* failed to allocate resources */
#define	NDI_BADHANDLE	-3		/* bad handle passed to in function */
#define	NDI_FAULT	-4		/* fault during copyin/copyout */
#define	NDI_BUSY	-5		/* device busy - could not offline */
#define	NDI_UNBOUND	-6		/* device not bound to a driver */
#define	NDI_EINVAL	-7		/* invalid request or arguments */
#define	NDI_ENOTSUP	-8		/* operation or event not supported */
#define	NDI_CLAIMED	NDI_SUCCESS	/* event is claimed */
#define	NDI_UNCLAIMED	-9		/* event is not claimed */

/*
 * Property functions:   See also, ddipropdefs.h.
 *			In general, the underlying driver MUST be held
 *			to call it's property functions.
 */

/*
 * Used to create boolean properties
 */
int
ndi_prop_create_boolean(dev_t match_dev, dev_info_t *dip, char *name);

/*
 * Used to create, modify, and lookup integer properties
 */
int
ndi_prop_update_int(dev_t match_dev, dev_info_t *dip, char *name, int data);

int
ndi_prop_update_int_array(dev_t match_dev, dev_info_t *dip, char *name,
    int *data, uint_t nelements);

int
ndi_prop_update_int64(dev_t match_dev, dev_info_t *dip, char *name,
    int64_t data);

int
ndi_prop_update_int64_array(dev_t match_dev, dev_info_t *dip, char *name,
    int64_t *data, uint_t nelements);

/*
 * Used to create, modify, and lookup string properties
 */
int
ndi_prop_update_string(dev_t match_dev, dev_info_t *dip, char *name,
    char *data);

int
ndi_prop_update_string_array(dev_t match_dev, dev_info_t *dip,
    char *name, char **data, uint_t nelements);

/*
 * Used to create, modify, and lookup byte properties
 */
int
ndi_prop_update_byte_array(dev_t match_dev, dev_info_t *dip,
    char *name, uchar_t *data, uint_t nelements);

/*
 * Used to remove properties
 */
int
ndi_prop_remove(dev_t dev, dev_info_t *dip, char *name);

void
ndi_prop_remove_all(dev_info_t *dip);

/*
 * Nexus Driver Functions
 */
/*
 * Allocate and initialize a new dev_info structure.
 * This routine will often be called at interrupt time by a nexus in
 * response to a hotplug event, therefore memory allocations are
 * not allowed to sleep.
 */
int
ndi_devi_alloc(dev_info_t *parent, char *node_name, pnode_t nodeid,
    dev_info_t **ret_dip);

void
ndi_devi_alloc_sleep(dev_info_t *parent, char *node_name, pnode_t nodeid,
    dev_info_t **ret_dip);

/*
 * Remove an initialized (but not yet attached) dev_info
 * node from it's parent.
 */
int
ndi_devi_free(dev_info_t *dip);

/* devinfo locking: use DEVI_BUSY_OWNED in ASSERTs to verify */
void ndi_devi_enter(dev_info_t *dip, int *circ);
void ndi_devi_exit(dev_info_t *dip, int circ);
int ndi_devi_tryenter(dev_info_t *dip, int *circ);

/* devinfo ref counting */
void ndi_hold_devi(dev_info_t *dip);
void ndi_rele_devi(dev_info_t *dip);

/* driver ref counting */
struct dev_ops *ndi_hold_driver(dev_info_t *dip);
void ndi_rele_driver(dev_info_t *dip);

/*
 * Change the node name
 */
int
ndi_devi_set_nodename(dev_info_t *dip, char *name, int flags);

/*
 * Place the devinfo in the DS_BOUND state,
 * binding a driver to the device
 *
 * Flags:
 *	all flags are ignored.
 */
int
ndi_devi_bind_driver(dev_info_t *dip, uint_t flags);

/*
 * Asynchronous version of ndi_devi_bind_driver, callable from
 * interrupt context. The dip must be a persistent node.
 */
int
ndi_devi_bind_driver_async(dev_info_t *dip, uint_t flags);

/*
 * Return devctl state of the child addressed by "name@addr".
 * For use by a driver's DEVCTL_DEVICE_GETSTATE handler.
 */
int
ndi_devctl_device_getstate(dev_info_t *parent, struct devctl_iocdata *dcp,
	uint_t *state);

/*
 * Transition the child addressed by "name@addr" to the online state.
 * For use by a driver's DEVCTL_DEVICE_ONLINE handler.
 */
int
ndi_devctl_device_online(dev_info_t *dip, struct devctl_iocdata *dcp,
	uint_t flags);

/*
 * Transition the child addressed by "name@addr" to the offline state.
 * For use by a driver's DEVCTL_DEVICE_OFFLINE handler.
 */
int
ndi_devctl_device_offline(dev_info_t *dip, struct devctl_iocdata *dcp,
	uint_t flags);

/*
 * Remove the child addressed by name@addr.
 * For use by a driver's DEVCTL_DEVICE_REMOVE handler.
 */
int
ndi_devctl_device_remove(dev_info_t *dip, struct devctl_iocdata *dcp,
	uint_t flags);

/*
 * Bus get state
 * For use by a driver's DEVCTL_BUS_GETSTATE handler.
 */
int
ndi_devctl_bus_getstate(dev_info_t *dip, struct devctl_iocdata *dcp,
	uint_t *state);

/*
 * Place the devinfo in the ONLINE state
 */
int
ndi_devi_online(dev_info_t *dip, uint_t flags);

/*
 * Generic devctl ioctl handler
 */
int
ndi_devctl_ioctl(dev_info_t *dip, int cmd, intptr_t arg, int mode,
	uint_t flags);

/*
 * Asynchronous version of ndi_devi_online, callable from interrupt
 * context. The dip must be a persistent node.
 */
int
ndi_devi_online_async(dev_info_t *dip, uint_t flags);


/*
 * Configure children of a nexus node.
 *
 * Flags:
 *	NDI_ONLINE_ATTACH - Attach driver to devinfo node when placing
 *			    the device Online.
 *	NDI_CONFIG - Recursively configure children if child is nexus node
 */
int
ndi_devi_config(dev_info_t *dip, int flags);

int
ndi_devi_config_driver(dev_info_t *dip, int flags, major_t major);

int
ndi_devi_config_one(dev_info_t *dip, char *devnm, dev_info_t **dipp, int flags);

/*
 * Unconfigure children of a nexus node.
 *
 * Flags:
 *	NDI_DEVI_REMOVE - Remove child devinfo nodes
 *
 *	NDI_UNCONFIG - Put child devinfo nodes to uninitialized state,
 *			release resources held by child nodes.
 */
int
ndi_devi_unconfig(dev_info_t *dip, int flags);

int
e_ddi_devi_unconfig(dev_info_t *dip, dev_info_t **dipp, int flags);

int
ndi_devi_unconfig_one(dev_info_t *dip, char *devnm, dev_info_t **dipp,
    int flags);

int
ndi_devi_unconfig_driver(dev_info_t *dip, int flags, major_t major);

void
ndi_set_bus_private(dev_info_t *dip, boolean_t up, uint32_t port_type,
    void *data);

void *
ndi_get_bus_private(dev_info_t *dip, boolean_t up);

boolean_t
ndi_port_type(dev_info_t *dip, boolean_t up, uint32_t port_type);

/*
 * Interrupt Resource Management (IRM) Pools.
 */
int
ndi_irm_create(dev_info_t *dip, ddi_irm_params_t *paramsp,
    ddi_irm_pool_t **pool_retp);

int
ndi_irm_destroy(ddi_irm_pool_t *poolp);

int
ndi_irm_resize_pool(ddi_irm_pool_t *poolp, uint_t newsize);

/*
 * Take a device node "Offline".
 *
 * Offline means to detach the device instance from the bound
 * driver and setting the devinfo state to prevent deferred attach
 * from re-attaching the device instance.
 *
 * Flags:
 *	NDI_DEVI_REMOVE	- Remove the node from the devinfo tree after
 *			  first taking it Offline.
 */

#define	NDI_DEVI_REMOVE		0x00000001 /* remove after unconfig */
#define	NDI_ONLINE_ATTACH	0x00000002 /* online/attach after config */
#define	NDI_MDI_FALLBACK	0x00000004 /* Leadville to fallback to phci */
#define	NDI_CONFIG		0x00000008 /* recursively config descendants */
#define	NDI_UNCONFIG		0x00000010 /* unconfig to uninitialized state */
#define	NDI_DEVI_BIND		0x00000020 /* transition to DS_BOUND state */
#define	NDI_DEVI_PERSIST	0x00000040 /* do not config offlined nodes */
#define	NDI_PROMNAME		0x00000080 /* name comes from prom */
#define	NDI_DEVFS_CLEAN		0x00001000 /* clean dv_nodes only, no detach */
#define	NDI_AUTODETACH		0x00002000 /* moduninstall daemon */
#define	NDI_NO_EVENT		0x00004000 /* don't devfs add/remove events */
#define	NDI_DEVI_DEBUG		0x00008000 /* turn on observability */
#define	NDI_CONFIG_REPROBE	0x00010000 /* force reprobe (deferred attach) */
#define	NDI_DEVI_ONLINE		0x00020000 /* force offlined device to online */
#define	NDI_DEVI_OFFLINE	0x00040000 /* set detached device to offline */
#define	NDI_POST_EVENT		0x00080000 /* Post NDI events before remove */
#define	NDI_BRANCH_EVENT_OP	0x01000000 /* branch op needs branch event */
#define	NDI_NO_EVENT_STATE_CHNG	0x02000000 /* don't change the event state */
#define	NDI_DRV_CONF_REPROBE	0x04000000 /* reprobe conf-enum'd nodes only */
#define	NDI_DETACH_DRIVER	0x08000000 /* performing driver_detach */
#define	NDI_MTC_OFF		0x10000000 /* disable multi-threading */
#define	NDI_USER_REQ		0x20000000 /* user requested operation */

/* ndi interface flag values */
#define	NDI_SLEEP		0x000000
#define	NDI_NOSLEEP		0x100000
#define	NDI_EVENT_NOPASS	0x200000 /* do not pass event req up the tree */

int
ndi_devi_offline(dev_info_t *dip, uint_t flags);

/*
 * Find the child dev_info node of parent nexus 'p' whose name
 * matches "cname"@"caddr".  Use ndi_devi_findchild() instead.
 */
dev_info_t *
ndi_devi_find(dev_info_t *p, char *cname, char *caddr);

/*
 * Find the child dev_info node of parent nexus 'p' whose name
 * matches device name "name"@"addr".
 */
dev_info_t *
ndi_devi_findchild(dev_info_t *p, char *devname);

/*
 * Find the child dev_info node of parent nexus 'p' whose name
 * matches "dname"@"ua". If a child doesn't have a "ua"
 * value, it calls the function "make_ua" to create it.
 */
dev_info_t *
ndi_devi_findchild_by_callback(dev_info_t *p, char *dname, char *ua,
    int (*make_ua)(dev_info_t *, char *, int));

/*
 * Maintain DEVI_DEVICE_REMOVED hotplug devi_state for remove/reinsert hotplug
 * of open devices.
 */
int
ndi_devi_device_isremoved(dev_info_t *dip);
int
ndi_devi_device_remove(dev_info_t *dip);
int
ndi_devi_device_insert(dev_info_t *dip);

/*
 * generate debug msg via NDI_DEVI_DEBUG flag
 */
#define	NDI_DEBUG(flags, args)	\
	if (flags & NDI_DEVI_DEBUG) cmn_err args

/*
 * Copy in the devctl IOCTL data structure and the strings referenced
 * by the structure.
 *
 * Convenience functions for use by nexus drivers as part of the
 * implementation of devctl IOCTL handling.
 */
int
ndi_dc_allochdl(void *iocarg, struct devctl_iocdata **rdcp);

void
ndi_dc_freehdl(struct devctl_iocdata *dcp);

char *
ndi_dc_getpath(struct devctl_iocdata *dcp);

char *
ndi_dc_getname(struct devctl_iocdata *dcp);

char *
ndi_dc_getaddr(struct devctl_iocdata *dcp);

nvlist_t *
ndi_dc_get_ap_data(struct devctl_iocdata *dcp);

char *
ndi_dc_getminorname(struct devctl_iocdata *dcp);

int
ndi_dc_return_dev_state(dev_info_t *dip, struct devctl_iocdata *dcp);

int
ndi_dc_return_ap_state(devctl_ap_state_t *ap, struct devctl_iocdata *dcp);

int
ndi_dc_return_bus_state(dev_info_t *dip, struct devctl_iocdata *dcp);

int
ndi_dc_devi_create(struct devctl_iocdata *dcp, dev_info_t *pdip, int flags,
    dev_info_t **rdip);

int
ndi_get_bus_state(dev_info_t *dip, uint_t *rstate);

int
ndi_set_bus_state(dev_info_t *dip, uint_t state);

/*
 * Post an event notification up the device tree hierarchy to the
 * parent nexus, until claimed by a bus nexus driver or the top
 * of the dev_info tree is reached.
 */
int
ndi_post_event(dev_info_t *dip, dev_info_t *rdip, ddi_eventcookie_t eventhdl,
    void *impl_data);

/*
 * Called by the NDI Event Framework to deliver a registration request to the
 * appropriate bus nexus driver.
 */
int
ndi_busop_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventhdl, void (*callback)(), void *arg,
    ddi_callback_id_t *cb_id);

/*
 * Called by the NDI Event Framework to deliver an unregister request to the
 * appropriate bus nexus driver.
 */
int
ndi_busop_remove_eventcall(dev_info_t *ddip, ddi_callback_id_t id);

/*
 * Called by the NDI Event Framework and/or a bus nexus driver's
 * implementation of the (*bus_get_eventcookie)() interface up the device tree
 * hierarchy, until claimed by a bus nexus driver or the top of the dev_info
 * tree is reached.  The NDI Event Framework will skip nexus drivers which are
 * not configured to handle NDI events.
 */
int
ndi_busop_get_eventcookie(dev_info_t *dip, dev_info_t *rdip, char *name,
    ddi_eventcookie_t *event_cookiep);

/*
 * ndi event callback support routines:
 *
 * these functions require an opaque ndi event handle
 */
typedef struct ndi_event_hdl *ndi_event_hdl_t;

/*
 * structure for maintaining each registered callback
 */
typedef struct ndi_event_callbacks {
	struct ndi_event_callbacks *ndi_evtcb_next;
	struct ndi_event_callbacks *ndi_evtcb_prev;
	dev_info_t	*ndi_evtcb_dip;
	char		*devname; /* name of device defining this callback */
	void		(*ndi_evtcb_callback)();
	void		*ndi_evtcb_arg;
	ddi_eventcookie_t	ndi_evtcb_cookie;
} ndi_event_callbacks_t;

/*
 * a nexus driver defines events that it can support using the
 * following structure
 */
typedef struct ndi_event_definition {
	int			ndi_event_tag;
	char			*ndi_event_name;
	ddi_plevel_t		ndi_event_plevel;
	uint_t			ndi_event_attributes;
} ndi_event_definition_t;

typedef struct ndi_event_cookie {
	ndi_event_definition_t	*definition;	/* Event Description */
	dev_info_t		*ddip;		/* Devi defining this event */
	ndi_event_callbacks_t	*callback_list; /* Cb's reg'd to w/ this evt */
	struct ndi_event_cookie *next_cookie;	/* Next cookie def'd in hdl */
} ndi_event_cookie_t;


#define	NDI_EVENT(cookie) ((struct ndi_event_cookie *)(void *)(cookie))
#define	NDI_EVENT_NAME(cookie) (NDI_EVENT(cookie)->definition->ndi_event_name)
#define	NDI_EVENT_TAG(cookie) (NDI_EVENT(cookie)->definition->ndi_event_tag)
#define	NDI_EVENT_ATTRIBUTES(cookie) \
	(NDI_EVENT(cookie)->definition->ndi_event_attributes)
#define	NDI_EVENT_PLEVEL(cookie) \
	(NDI_EVENT(cookie)->definition->ndi_event_plevel)
#define	NDI_EVENT_DDIP(cookie) (NDI_EVENT(cookie)->ddip)

/* ndi_event_attributes */
#define	NDI_EVENT_POST_TO_ALL	0x0 /* broadcast: post to all handlers */
#define	NDI_EVENT_POST_TO_TGT	0x1 /* call only specific child's hdlr */

typedef struct ndi_event_set {
	ushort_t		ndi_events_version;
	ushort_t		ndi_n_events;
	ndi_event_definition_t	*ndi_event_defs;
} ndi_event_set_t;


#define	NDI_EVENTS_REV0			0
#define	NDI_EVENTS_REV1			1

/*
 * allocate an ndi event handle
 */
int
ndi_event_alloc_hdl(dev_info_t *dip, ddi_iblock_cookie_t cookie,
	ndi_event_hdl_t *ndi_event_hdl, uint_t flag);

/*
 * free the ndi event handle
 */
int
ndi_event_free_hdl(ndi_event_hdl_t handle);

/*
 * bind or unbind a set of events to/from the event handle
 */
int
ndi_event_bind_set(ndi_event_hdl_t	handle,
	ndi_event_set_t		*ndi_event_set,
	uint_t			flag);

int
ndi_event_unbind_set(ndi_event_hdl_t	handle,
	ndi_event_set_t		*ndi_event_set,
	uint_t			flag);

/*
 * get an event cookie
 */
int
ndi_event_retrieve_cookie(ndi_event_hdl_t	handle,
	dev_info_t		*child_dip,
	char			*eventname,
	ddi_eventcookie_t	*cookiep,
	uint_t			flag);

/*
 * add an event callback info to the ndi event handle
 */
int
ndi_event_add_callback(ndi_event_hdl_t	handle,
	dev_info_t		*child_dip,
	ddi_eventcookie_t	cookie,
	void			(*event_callback)
					(dev_info_t *,
					ddi_eventcookie_t,
					void *arg,
					void *impldata),
	void			*arg,
	uint_t			flag,
	ddi_callback_id_t *cb_id);

/*
 * remove an event callback registration from the ndi event handle
 */
int
ndi_event_remove_callback(ndi_event_hdl_t handle, ddi_callback_id_t id);

/*
 * perform callbacks for a specified cookie
 */
int
ndi_event_run_callbacks(ndi_event_hdl_t	handle, dev_info_t *child_dip,
    ddi_eventcookie_t cookie, void *bus_impldata);

/*
 * do callback for just one child_dip, regardless of attributes
 */
int ndi_event_do_callback(ndi_event_hdl_t handle, dev_info_t *child_dip,
	ddi_eventcookie_t cookie, void *bus_impldata);

/*
 * ndi_event_tag_to_cookie: utility function to find an event cookie
 * given an event tag
 */
ddi_eventcookie_t
ndi_event_tag_to_cookie(ndi_event_hdl_t handle, int event_tag);

/*
 * ndi_event_cookie_to_tag: utility function to find an event tag
 * given an event_cookie
 */
int
ndi_event_cookie_to_tag(ndi_event_hdl_t handle,
	ddi_eventcookie_t cookie);

/*
 * ndi_event_cookie_to_name: utility function to find an event
 * name given an event_cookie
 */
char *
ndi_event_cookie_to_name(ndi_event_hdl_t handle,
	ddi_eventcookie_t cookie);

/*
 * ndi_event_tag_to_name: utility function to find an event
 * name given an event_tag
 */
char *
ndi_event_tag_to_name(ndi_event_hdl_t	handle, int event_tag);

dev_info_t *
ndi_devi_config_vhci(char *, int);

#ifdef DEBUG
/*
 * ndi_event_dump_hdl: debug functionality used to display event handle
 */
void
ndi_event_dump_hdl(struct ndi_event_hdl *hdl, char *location);
#endif

/*
 * Default busop bus_config helper functions
 */
int
ndi_busop_bus_config(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **child, clock_t reset_delay);

int
ndi_busop_bus_unconfig(dev_info_t *dip, uint_t flags, ddi_bus_config_op_t op,
    void *arg);

/*
 * Called by the Nexus/HPC drivers to register, unregister and interact
 * with the hotplug framework for the specified hotplug connection.
 */
int
ndi_hp_register(dev_info_t *dip, ddi_hp_cn_info_t *info_p);

int
ndi_hp_unregister(dev_info_t *dip, char *cn_name);

int
ndi_hp_state_change_req(dev_info_t *dip, char *cn_name,
    ddi_hp_cn_state_t state, uint_t flag);

void
ndi_hp_walk_cn(dev_info_t *dip, int (*f)(ddi_hp_cn_info_t *, void *),
    void *arg);

/*
 * Bus Resource allocation structures and function prototypes exported
 * by busra module
 */

/* structure for specifying a request */
typedef struct ndi_ra_request {
	uint_t		ra_flags;	/* General flags		*/
					/* see bit definitions below	*/

	uint64_t	ra_len;		/* Requested allocation length	*/

	uint64_t	ra_addr;	/* Specific base address requested */

	uint64_t	ra_boundbase;	/* Base address of the area for	*/
					/* the allocated resource to be	*/
					/* restricted to		*/

	uint64_t	ra_boundlen;	/* Length of the area, starting	*/
					/* from ra_boundbase, for the	*/
					/* allocated resource to be	*/
					/* restricted to.   		*/

	uint64_t	ra_align_mask;	/* Alignment mask used for	*/
					/* allocated base address	*/
} ndi_ra_request_t;


/* ra_flags bit definitions */
#define	NDI_RA_ALIGN_SIZE	0x0001	/* Set the alignment of the	*/
					/* allocated resource address	*/
					/* according to the ra_len	*/
					/* value (alignment mask will	*/
					/* be (ra_len - 1)). Value of	*/
					/* ra_len has to be power of 2.	*/
					/* If this flag is set, value of */
					/* ra_align_mask will be ignored. */


#define	NDI_RA_ALLOC_BOUNDED	0x0002	/* Indicates that the resource	*/
					/* should be restricted to the	*/
					/* area specified by ra_boundbase */
					/* and ra_boundlen */

#define	NDI_RA_ALLOC_SPECIFIED	0x0004	/* Indicates that a specific	*/
					/* address (ra_addr value) is	*/
					/* requested.			*/

#define	NDI_RA_ALLOC_PARTIAL_OK	0x0008  /* Indicates if requested size	*/
					/* (ra_len) chunk is not available */
					/* then allocate as big chunk as */
					/* possible which is less than or */
					/* equal to ra_len size. */


/* return values specific to bus resource allocator */
#define	NDI_RA_PARTIAL_REQ		-7




/* Predefined types for generic type of resources */
#define	NDI_RA_TYPE_MEM			"memory"
#define	NDI_RA_TYPE_IO			"io"
#define	NDI_RA_TYPE_PCI_BUSNUM		"pci_bus_number"
#define	NDI_RA_TYPE_PCI_PREFETCH_MEM	"pci_prefetchable_memory"
#define	NDI_RA_TYPE_INTR		"interrupt"

/* flag bit definition */
#define	NDI_RA_PASS	0x0001		/* pass request up the dev tree */

/*
 * Prototype definitions for functions exported
 */

int
ndi_ra_map_setup(dev_info_t *dip, char *type);

int
ndi_ra_map_destroy(dev_info_t *dip, char *type);

int
ndi_ra_alloc(dev_info_t *dip, ndi_ra_request_t *req, uint64_t *basep,
	uint64_t *lenp, char *type, uint_t flag);

int
ndi_ra_free(dev_info_t *dip, uint64_t base, uint64_t len, char *type,
	uint_t flag);

/*
 * ndi_dev_is_prom_node: Return non-zero if the node is a prom node
 */
int ndi_dev_is_prom_node(dev_info_t *);

/*
 * ndi_dev_is_pseudo_node: Return non-zero if the node is a pseudo node.
 * NB: all non-prom nodes are pseudo nodes.
 * c.f. ndi_dev_is_persistent_node
 */
int ndi_dev_is_pseudo_node(dev_info_t *);

/*
 * ndi_dev_is_persistent_node: Return non-zero if the node has the
 * property of persistence.
 */
int ndi_dev_is_persistent_node(dev_info_t *);

/*
 * ndi_dev_is_hotplug_node: Return non-zero if the node was created by hotplug.
 */
int ndi_dev_is_hotplug_node(dev_info_t *);

/*
 * ndi_dev_is_hidden_node: Return non-zero if the node is hidden.
 */
int ndi_dev_is_hidden_node(dev_info_t *);

/*
 * ndi_devi_set_hidden: mark a node as hidden
 * ndi_devi_clr_hidden: mark a node as visible
 */
void ndi_devi_set_hidden(dev_info_t *);
void ndi_devi_clr_hidden(dev_info_t *);

/*
 * Event posted when a fault is reported
 */
#define	DDI_DEVI_FAULT_EVENT	"DDI:DEVI_FAULT"

struct ddi_fault_event_data {
	dev_info_t		*f_dip;
	ddi_fault_impact_t	f_impact;
	ddi_fault_location_t	f_location;
	const char		*f_message;
	ddi_devstate_t		f_oldstate;
};

/*
 * Access handle/DMA handle fault flag setting/clearing functions for nexi
 */
void ndi_set_acc_fault(ddi_acc_handle_t ah);
void ndi_clr_acc_fault(ddi_acc_handle_t ah);
void ndi_set_dma_fault(ddi_dma_handle_t dh);
void ndi_clr_dma_fault(ddi_dma_handle_t dh);

/* Driver.conf property merging */
int	ndi_merge_node(dev_info_t *, int (*)(dev_info_t *, char *, int));
void	ndi_merge_wildcard_node(dev_info_t *);

/*
 * Ndi 'flavor' support: These interfaces are to support a nexus driver
 * with multiple 'flavors' of children (devi_flavor of child), coupled
 * with a child flavor-specifc private data mechanism (via devi_flavor_v
 * of parent). This is provided as an extension to ddi_[sg]et_driver_private,
 * where the vanilla 'flavor' is what is stored or retrieved via
 * ddi_[sg]et_driver_private.
 *
 * Flavors are indexed with a small integer. The first flavor, flavor
 * zero, is always present and reserved as the 'vanilla' flavor.
 * Space for extra flavors can be allocated and private pointers
 * with respect to each flavor set and retrieved.
 *
 * NOTE:For a nexus driver, if the need to support multiple flavors of
 *	children is understood from the begining, then a private 'flavor'
 *	mechanism can be implemented via ddi_[sg]et_driver_private.
 *
 *	With SCSA, the need to support multiple flavors of children was not
 *	anticipated, and ddi_get_driver_private(9F) of an initiator port
 *	devinfo node was publicly defined in the DDI to return a
 *	scsi_device(9S) child-flavor specific value: a pointer to
 *	scsi_hba_tran(9S).  Over the years, each time the need to support
 *	a new flavor of child has occurred, a new form of overload/kludge
 *	has been devised. The ndi 'flavors' interfaces provide a simple way
 *	to address this issue that can be used by both SCSA nexus support,
 *	and by other nexus drivers.
 */

/*
 * Interfaces to maintain flavor-specific private data for children of self
 */
#define	NDI_FLAVOR_VANILLA	0

void	ndi_flavorv_alloc(dev_info_t *self, int nflavors);
void	ndi_flavorv_set(dev_info_t *self, ndi_flavor_t child_flavor, void *);
void	*ndi_flavorv_get(dev_info_t *self, ndi_flavor_t child_flavor);

/* Interfaces for 'self' nexus driver to get/set flavor of child */
void		ndi_flavor_set(dev_info_t *child, ndi_flavor_t child_flavor);
ndi_flavor_t	ndi_flavor_get(dev_info_t *child);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SUNNDI_H */
