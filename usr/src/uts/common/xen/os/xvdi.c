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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2014 by Delphix. All rights reserved.
 */

/*
 * Xen virtual device driver interfaces
 */

/*
 * todo:
 * + name space clean up:
 *	xvdi_* - public xen interfaces, for use by all leaf drivers
 *	xd_* - public xen data structures
 *	i_xvdi_* - implementation private functions
 *	xendev_* - xendev driver interfaces, both internal and in cb_ops/bus_ops
 * + add mdb dcmds to dump ring status
 * + implement xvdi_xxx to wrap xenbus_xxx read/write function
 * + convert (xendev_ring_t *) into xvdi_ring_handle_t
 */
#include <sys/conf.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <vm/seg_kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sunldi.h>
#include <sys/fs/dv_node.h>
#include <sys/avintr.h>
#include <sys/psm.h>
#include <sys/spl.h>
#include <sys/promif.h>
#include <sys/list.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#include <sys/bootinfo.h>
#include <sys/note.h>
#include <sys/sysmacros.h>
#ifdef XPV_HVM_DRIVER
#include <sys/xpv_support.h>
#include <sys/hypervisor.h>
#include <public/grant_table.h>
#include <public/xen.h>
#include <public/io/xenbus.h>
#include <public/io/xs_wire.h>
#include <public/event_channel.h>
#include <public/io/xenbus.h>
#else /* XPV_HVM_DRIVER */
#include <sys/hypervisor.h>
#include <sys/xen_mmu.h>
#include <xen/sys/xenbus_impl.h>
#include <sys/evtchn_impl.h>
#endif /* XPV_HVM_DRIVER */
#include <sys/gnttab.h>
#include <xen/sys/xendev.h>
#include <vm/hat_i86.h>
#include <sys/scsi/generic/inquiry.h>
#include <util/sscanf.h>
#include <xen/public/io/xs_wire.h>


#define	isdigit(ch)	((ch) >= '0' && (ch) <= '9')
#define	isxdigit(ch)	(isdigit(ch) || ((ch) >= 'a' && (ch) <= 'f') || \
			((ch) >= 'A' && (ch) <= 'F'))

static void xvdi_ring_init_sring(xendev_ring_t *);
static void xvdi_ring_init_front_ring(xendev_ring_t *, size_t, size_t);
#ifndef XPV_HVM_DRIVER
static void xvdi_ring_init_back_ring(xendev_ring_t *, size_t, size_t);
#endif
static void xvdi_reinit_ring(dev_info_t *, grant_ref_t *, xendev_ring_t *);

static int i_xvdi_add_watches(dev_info_t *);
static void i_xvdi_rem_watches(dev_info_t *);

static int i_xvdi_add_watch_oestate(dev_info_t *);
static void i_xvdi_rem_watch_oestate(dev_info_t *);
static void i_xvdi_oestate_cb(struct xenbus_device *, XenbusState);
static void i_xvdi_oestate_handler(void *);

static int i_xvdi_add_watch_hpstate(dev_info_t *);
static void i_xvdi_rem_watch_hpstate(dev_info_t *);
static void i_xvdi_hpstate_cb(struct xenbus_watch *, const char **,
    unsigned int);
static void i_xvdi_hpstate_handler(void *);

static int i_xvdi_add_watch_bepath(dev_info_t *);
static void i_xvdi_rem_watch_bepath(dev_info_t *);
static void i_xvdi_bepath_cb(struct xenbus_watch *, const char **,
    unsigned in);

static void xendev_offline_device(void *);

static void i_xvdi_probe_path_cb(struct xenbus_watch *, const char **,
    unsigned int);
static void i_xvdi_probe_path_handler(void *);

typedef struct oestate_evt {
	dev_info_t *dip;
	XenbusState state;
} i_oestate_evt_t;

typedef struct xd_cfg {
	xendev_devclass_t devclass;
	char *xsdev;
	char *xs_path_fe;
	char *xs_path_be;
	char *node_fe;
	char *node_be;
	char *device_type;
	int xd_ipl;
	int flags;
} i_xd_cfg_t;

#define	XD_DOM_ZERO	0x01	/* dom0 only. */
#define	XD_DOM_GUEST	0x02	/* Guest domains (i.e. non-dom0). */
#define	XD_DOM_IO	0x04	/* IO domains. */

#define	XD_DOM_ALL	(XD_DOM_ZERO | XD_DOM_GUEST)

static i_xd_cfg_t xdci[] = {
#ifndef XPV_HVM_DRIVER
	{ XEN_CONSOLE, NULL, NULL, NULL, "xencons", NULL,
	    "console", IPL_CONS, XD_DOM_ALL, },
#endif

	{ XEN_VNET, "vif", "device/vif", "backend/vif", "xnf", "xnb",
	    "network", IPL_VIF, XD_DOM_ALL, },

	{ XEN_VBLK, "vbd", "device/vbd", "backend/vbd", "xdf", "xdb",
	    "block", IPL_VBD, XD_DOM_ALL, },

	{ XEN_BLKTAP, "tap", NULL, "backend/tap", NULL, "xpvtap",
	    "block", IPL_VBD, XD_DOM_ALL, },

#ifndef XPV_HVM_DRIVER
	{ XEN_XENBUS, NULL, NULL, NULL, "xenbus", NULL,
	    NULL, 0, XD_DOM_ALL, },

	{ XEN_DOMCAPS, NULL, NULL, NULL, "domcaps", NULL,
	    NULL, 0, XD_DOM_ALL, },

	{ XEN_BALLOON, NULL, NULL, NULL, "balloon", NULL,
	    NULL, 0, XD_DOM_ALL, },
#endif

	{ XEN_EVTCHN, NULL, NULL, NULL, "evtchn", NULL,
	    NULL, 0, XD_DOM_ZERO, },

	{ XEN_PRIVCMD, NULL, NULL, NULL, "privcmd", NULL,
	    NULL, 0, XD_DOM_ZERO, },
};
#define	NXDC	(sizeof (xdci) / sizeof (xdci[0]))

static void i_xvdi_enum_fe(dev_info_t *, i_xd_cfg_t *);
static void i_xvdi_enum_be(dev_info_t *, i_xd_cfg_t *);
static void i_xvdi_enum_worker(dev_info_t *, i_xd_cfg_t *, char *);

/*
 * Xen device channel device access and DMA attributes
 */
static ddi_device_acc_attr_t xendev_dc_accattr = {
	DDI_DEVICE_ATTR_V0, DDI_NEVERSWAP_ACC, DDI_STRICTORDER_ACC
};

static ddi_dma_attr_t xendev_dc_dmaattr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	MMU_PAGESIZE,		/* alignment in bytes */
	0x7ff,			/* bitmap of burst sizes */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffffffffffULL,	/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

static dev_info_t *xendev_dip = NULL;

#define	XVDI_DBG_STATE	0x01
#define	XVDI_DBG_PROBE	0x02

#ifdef DEBUG
int i_xvdi_debug = 0;

#define	XVDI_DPRINTF(flag, format, ...)			\
{							\
	if (i_xvdi_debug & (flag))			\
		prom_printf((format), __VA_ARGS__);	\
}
#else
#define	XVDI_DPRINTF(flag, format, ...)
#endif /* DEBUG */

static i_xd_cfg_t *
i_xvdi_devclass2cfg(xendev_devclass_t devclass)
{
	i_xd_cfg_t *xdcp;
	int i;

	for (i = 0, xdcp = xdci; i < NXDC; i++, xdcp++)
		if (xdcp->devclass == devclass)
			return (xdcp);

	return (NULL);
}

int
xvdi_init_dev(dev_info_t *dip)
{
	xendev_devclass_t devcls;
	int vdevnum;
	domid_t domid;
	struct xendev_ppd *pdp;
	i_xd_cfg_t *xdcp;
	boolean_t backend;
	char xsnamebuf[TYPICALMAXPATHLEN];
	char *xsname;
	void *prop_str;
	unsigned int prop_len;
	char unitaddr[8];

	devcls = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "devclass", XEN_INVAL);
	vdevnum = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "vdev", VDEV_NOXS);
	domid = (domid_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "domain", DOMID_SELF);

	backend = (domid != DOMID_SELF);
	xdcp = i_xvdi_devclass2cfg(devcls);
	if (xdcp->device_type != NULL)
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "device_type", xdcp->device_type);

	pdp = kmem_zalloc(sizeof (*pdp), KM_SLEEP);
	pdp->xd_domain = domid;
	pdp->xd_vdevnum = vdevnum;
	pdp->xd_devclass = devcls;
	pdp->xd_evtchn = INVALID_EVTCHN;
	list_create(&pdp->xd_xb_watches, sizeof (xd_xb_watches_t),
	    offsetof(xd_xb_watches_t, xxw_list));
	mutex_init(&pdp->xd_evt_lk, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pdp->xd_ndi_lk, NULL, MUTEX_DRIVER, NULL);
	ddi_set_parent_data(dip, pdp);

	/*
	 * devices that do not need to interact with xenstore
	 */
	if (vdevnum == VDEV_NOXS) {
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "unit-address", "0");
		if (devcls == XEN_CONSOLE)
			(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
			    "pm-hardware-state", "needs-suspend-resume");
		return (DDI_SUCCESS);
	}

	/*
	 * PV devices that need to probe xenstore
	 */

	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "pm-hardware-state", "needs-suspend-resume");

	xsname = xsnamebuf;
	if (!backend)
		(void) snprintf(xsnamebuf, sizeof (xsnamebuf),
		    "%s/%d", xdcp->xs_path_fe, vdevnum);
	else
		(void) snprintf(xsnamebuf, sizeof (xsnamebuf),
		    "%s/%d/%d", xdcp->xs_path_be, domid, vdevnum);
	if ((xenbus_read_driver_state(xsname) >= XenbusStateClosing)) {
		/* Don't try to init a dev that may be closing */
		mutex_destroy(&pdp->xd_ndi_lk);
		mutex_destroy(&pdp->xd_evt_lk);
		kmem_free(pdp, sizeof (*pdp));
		ddi_set_parent_data(dip, NULL);
		return (DDI_FAILURE);
	}

	pdp->xd_xsdev.nodename = i_ddi_strdup(xsname, KM_SLEEP);
	pdp->xd_xsdev.devicetype = xdcp->xsdev;
	pdp->xd_xsdev.frontend = (backend ? 0 : 1);
	pdp->xd_xsdev.data = dip;
	pdp->xd_xsdev.otherend_id = (backend ? domid : -1);
	if (i_xvdi_add_watches(dip) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xvdi_init_dev: "
		    "cannot add watches for %s", xsname);
		xvdi_uninit_dev(dip);
		return (DDI_FAILURE);
	}

	if (backend)
		return (DDI_SUCCESS);

	/*
	 * The unit-address for frontend devices is the name of the
	 * of the xenstore node containing the device configuration
	 * and is contained in the 'vdev' property.
	 * VIF devices are named using an incrementing integer.
	 * VBD devices are either named using the 16-bit dev_t value
	 * for linux 'hd' and 'xvd' devices, or a simple integer value
	 * in the range 0..767.  768 is the base value of the linux
	 * dev_t namespace, the dev_t value for 'hda'.
	 */
	(void) snprintf(unitaddr, sizeof (unitaddr), "%d", vdevnum);
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip, "unit-address",
	    unitaddr);

	switch (devcls) {
	case XEN_VNET:
		if (xenbus_read(XBT_NULL, xsname, "mac", (void *)&prop_str,
		    &prop_len) != 0)
			break;
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip, "mac",
		    prop_str);
		kmem_free(prop_str, prop_len);
		break;
	case XEN_VBLK:
		/*
		 * cache a copy of the otherend name
		 * for ease of observeability
		 */
		if (xenbus_read(XBT_NULL, pdp->xd_xsdev.otherend, "dev",
		    &prop_str, &prop_len) != 0)
			break;
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "dev-address", prop_str);
		kmem_free(prop_str, prop_len);
		break;
	default:
		break;
	}

	return (DDI_SUCCESS);
}

void
xvdi_uninit_dev(dev_info_t *dip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);

	if (pdp != NULL) {
		/* Remove any registered callbacks. */
		xvdi_remove_event_handler(dip, NULL);

		/* Remove any registered watches. */
		i_xvdi_rem_watches(dip);

		/* tell other end to close */
		if (pdp->xd_xsdev.otherend_id != (domid_t)-1)
			(void) xvdi_switch_state(dip, XBT_NULL,
			    XenbusStateClosed);

		if (pdp->xd_xsdev.nodename != NULL)
			kmem_free((char *)(pdp->xd_xsdev.nodename),
			    strlen(pdp->xd_xsdev.nodename) + 1);

		ddi_set_parent_data(dip, NULL);

		mutex_destroy(&pdp->xd_ndi_lk);
		mutex_destroy(&pdp->xd_evt_lk);
		kmem_free(pdp, sizeof (*pdp));
	}
}

/*
 * Bind the event channel for this device instance.
 * Currently we only support one evtchn per device instance.
 */
int
xvdi_bind_evtchn(dev_info_t *dip, evtchn_port_t evtchn)
{
	struct xendev_ppd *pdp;
	domid_t oeid;
	int r;

	pdp = ddi_get_parent_data(dip);
	ASSERT(pdp != NULL);
	ASSERT(pdp->xd_evtchn == INVALID_EVTCHN);

	mutex_enter(&pdp->xd_evt_lk);
	if (pdp->xd_devclass == XEN_CONSOLE) {
		if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
			pdp->xd_evtchn = xen_info->console.domU.evtchn;
		} else {
			pdp->xd_evtchn = INVALID_EVTCHN;
			mutex_exit(&pdp->xd_evt_lk);
			return (DDI_SUCCESS);
		}
	} else {
		oeid = pdp->xd_xsdev.otherend_id;
		if (oeid == (domid_t)-1) {
			mutex_exit(&pdp->xd_evt_lk);
			return (DDI_FAILURE);
		}

		if ((r = xen_bind_interdomain(oeid, evtchn, &pdp->xd_evtchn))) {
			xvdi_dev_error(dip, r, "bind event channel");
			mutex_exit(&pdp->xd_evt_lk);
			return (DDI_FAILURE);
		}
	}
#ifndef XPV_HVM_DRIVER
	pdp->xd_ispec.intrspec_vec = ec_bind_evtchn_to_irq(pdp->xd_evtchn);
#endif
	mutex_exit(&pdp->xd_evt_lk);

	return (DDI_SUCCESS);
}

/*
 * Allocate an event channel for this device instance.
 * Currently we only support one evtchn per device instance.
 */
int
xvdi_alloc_evtchn(dev_info_t *dip)
{
	struct xendev_ppd *pdp;
	domid_t oeid;
	int rv;

	pdp = ddi_get_parent_data(dip);
	ASSERT(pdp != NULL);
	ASSERT(pdp->xd_evtchn == INVALID_EVTCHN);

	mutex_enter(&pdp->xd_evt_lk);
	if (pdp->xd_devclass == XEN_CONSOLE) {
		if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
			pdp->xd_evtchn = xen_info->console.domU.evtchn;
		} else {
			pdp->xd_evtchn = INVALID_EVTCHN;
			mutex_exit(&pdp->xd_evt_lk);
			return (DDI_SUCCESS);
		}
	} else {
		oeid = pdp->xd_xsdev.otherend_id;
		if (oeid == (domid_t)-1) {
			mutex_exit(&pdp->xd_evt_lk);
			return (DDI_FAILURE);
		}

		if ((rv = xen_alloc_unbound_evtchn(oeid, &pdp->xd_evtchn))) {
			xvdi_dev_error(dip, rv, "bind event channel");
			mutex_exit(&pdp->xd_evt_lk);
			return (DDI_FAILURE);
		}
	}
#ifndef XPV_HVM_DRIVER
	pdp->xd_ispec.intrspec_vec = ec_bind_evtchn_to_irq(pdp->xd_evtchn);
#endif
	mutex_exit(&pdp->xd_evt_lk);

	return (DDI_SUCCESS);
}

/*
 * Unbind the event channel for this device instance.
 * Currently we only support one evtchn per device instance.
 */
void
xvdi_free_evtchn(dev_info_t *dip)
{
	struct xendev_ppd *pdp;

	pdp = ddi_get_parent_data(dip);
	ASSERT(pdp != NULL);

	mutex_enter(&pdp->xd_evt_lk);
	if (pdp->xd_evtchn != INVALID_EVTCHN) {
#ifndef XPV_HVM_DRIVER
		ec_unbind_irq(pdp->xd_ispec.intrspec_vec);
		pdp->xd_ispec.intrspec_vec = 0;
#endif
		pdp->xd_evtchn = INVALID_EVTCHN;
	}
	mutex_exit(&pdp->xd_evt_lk);
}

#ifndef XPV_HVM_DRIVER
/*
 * Map an inter-domain communication ring for a virtual device.
 * This is used by backend drivers.
 */
int
xvdi_map_ring(dev_info_t *dip, size_t nentry, size_t entrysize,
    grant_ref_t gref, xendev_ring_t **ringpp)
{
	domid_t oeid;
	gnttab_map_grant_ref_t mapop;
	gnttab_unmap_grant_ref_t unmapop;
	caddr_t ringva;
	ddi_acc_hdl_t *ap;
	ddi_acc_impl_t *iap;
	xendev_ring_t *ring;
	int err;
	char errstr[] = "mapping in ring buffer";

	ring = kmem_zalloc(sizeof (xendev_ring_t), KM_SLEEP);
	oeid = xvdi_get_oeid(dip);

	/* alloc va in backend dom for ring buffer */
	ringva = vmem_xalloc(heap_arena, PAGESIZE, PAGESIZE,
	    0, 0, 0, 0, VM_SLEEP);

	/* map in ring page */
	hat_prepare_mapping(kas.a_hat, ringva, NULL);
	mapop.host_addr = (uint64_t)(uintptr_t)ringva;
	mapop.flags = GNTMAP_host_map;
	mapop.ref = gref;
	mapop.dom = oeid;
	err = xen_map_gref(GNTTABOP_map_grant_ref, &mapop, 1, B_FALSE);
	if (err) {
		xvdi_fatal_error(dip, err, errstr);
		goto errout1;
	}

	if (mapop.status != 0) {
		xvdi_fatal_error(dip, err, errstr);
		goto errout2;
	}
	ring->xr_vaddr = ringva;
	ring->xr_grant_hdl = mapop.handle;
	ring->xr_gref = gref;

	/*
	 * init an acc handle and associate it w/ this ring
	 * this is only for backend drivers. we get the memory by calling
	 * vmem_xalloc(), instead of calling any ddi function, so we have
	 * to init an acc handle by ourselves
	 */
	ring->xr_acc_hdl = impl_acc_hdl_alloc(KM_SLEEP, NULL);
	ap = impl_acc_hdl_get(ring->xr_acc_hdl);
	ap->ah_vers = VERS_ACCHDL;
	ap->ah_dip = dip;
	ap->ah_xfermodes = DDI_DMA_CONSISTENT;
	ap->ah_acc = xendev_dc_accattr;
	iap = (ddi_acc_impl_t *)ap->ah_platform_private;
	iap->ahi_acc_attr |= DDI_ACCATTR_CPU_VADDR;
	impl_acc_hdl_init(ap);
	ap->ah_offset = 0;
	ap->ah_len = (off_t)PAGESIZE;
	ap->ah_addr = ring->xr_vaddr;

	/* init backend ring */
	xvdi_ring_init_back_ring(ring, nentry, entrysize);

	*ringpp = ring;

	return (DDI_SUCCESS);

errout2:
	/* unmap ring page */
	unmapop.host_addr = (uint64_t)(uintptr_t)ringva;
	unmapop.handle = ring->xr_grant_hdl;
	unmapop.dev_bus_addr = NULL;
	(void) HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmapop, 1);
	hat_release_mapping(kas.a_hat, ringva);
errout1:
	vmem_xfree(heap_arena, ringva, PAGESIZE);
	kmem_free(ring, sizeof (xendev_ring_t));
	return (DDI_FAILURE);
}

/*
 * Unmap a ring for a virtual device.
 * This is used by backend drivers.
 */
void
xvdi_unmap_ring(xendev_ring_t *ring)
{
	gnttab_unmap_grant_ref_t unmapop;

	ASSERT((ring != NULL) && (ring->xr_vaddr != NULL));

	impl_acc_hdl_free(ring->xr_acc_hdl);
	unmapop.host_addr = (uint64_t)(uintptr_t)ring->xr_vaddr;
	unmapop.handle = ring->xr_grant_hdl;
	unmapop.dev_bus_addr = NULL;
	(void) HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmapop, 1);
	hat_release_mapping(kas.a_hat, ring->xr_vaddr);
	vmem_xfree(heap_arena, ring->xr_vaddr, PAGESIZE);
	kmem_free(ring, sizeof (xendev_ring_t));
}
#endif /* XPV_HVM_DRIVER */

/*
 * Re-initialise an inter-domain communications ring for the backend domain.
 * ring will be re-initialized after re-grant succeed
 * ring will be freed if fails to re-grant access to backend domain
 * so, don't keep useful data in the ring
 * used only in frontend driver
 */
static void
xvdi_reinit_ring(dev_info_t *dip, grant_ref_t *gref, xendev_ring_t *ringp)
{
	paddr_t rpaddr;
	maddr_t rmaddr;

	ASSERT((ringp != NULL) && (ringp->xr_paddr != 0));
	rpaddr = ringp->xr_paddr;

	rmaddr = DOMAIN_IS_INITDOMAIN(xen_info) ? rpaddr : pa_to_ma(rpaddr);
	gnttab_grant_foreign_access_ref(ringp->xr_gref, xvdi_get_oeid(dip),
	    rmaddr >> PAGESHIFT, 0);
	*gref = ringp->xr_gref;

	/* init frontend ring */
	xvdi_ring_init_sring(ringp);
	xvdi_ring_init_front_ring(ringp, ringp->xr_sring.fr.nr_ents,
	    ringp->xr_entry_size);
}

/*
 * allocate Xen inter-domain communications ring for Xen virtual devices
 * used only in frontend driver
 * if *ringpp is not NULL, we'll simply re-init it
 */
int
xvdi_alloc_ring(dev_info_t *dip, size_t nentry, size_t entrysize,
    grant_ref_t *gref, xendev_ring_t **ringpp)
{
	size_t len;
	xendev_ring_t *ring;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;
	grant_ref_t ring_gref;
	domid_t oeid;
	maddr_t rmaddr;

	if (*ringpp) {
		xvdi_reinit_ring(dip, gref, *ringpp);
		return (DDI_SUCCESS);
	}

	*ringpp = ring = kmem_zalloc(sizeof (xendev_ring_t), KM_SLEEP);
	oeid = xvdi_get_oeid(dip);

	/*
	 * Allocate page for this ring buffer
	 */
	if (ddi_dma_alloc_handle(dip, &xendev_dc_dmaattr, DDI_DMA_SLEEP,
	    0, &ring->xr_dma_hdl) != DDI_SUCCESS)
		goto err;

	if (ddi_dma_mem_alloc(ring->xr_dma_hdl, PAGESIZE,
	    &xendev_dc_accattr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &ring->xr_vaddr, &len, &ring->xr_acc_hdl) != DDI_SUCCESS) {
		ddi_dma_free_handle(&ring->xr_dma_hdl);
		goto err;
	}

	if (ddi_dma_addr_bind_handle(ring->xr_dma_hdl, NULL,
	    ring->xr_vaddr, len, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, &dma_cookie, &ncookies) != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&ring->xr_acc_hdl);
		ring->xr_vaddr = NULL;
		ddi_dma_free_handle(&ring->xr_dma_hdl);
		goto err;
	}
	ASSERT(ncookies == 1);
	ring->xr_paddr = dma_cookie.dmac_laddress;
	rmaddr = DOMAIN_IS_INITDOMAIN(xen_info) ? ring->xr_paddr :
	    pa_to_ma(ring->xr_paddr);

	if ((ring_gref = gnttab_grant_foreign_access(oeid,
	    rmaddr >> PAGESHIFT, 0)) == (grant_ref_t)-1) {
		(void) ddi_dma_unbind_handle(ring->xr_dma_hdl);
		ddi_dma_mem_free(&ring->xr_acc_hdl);
		ring->xr_vaddr = NULL;
		ddi_dma_free_handle(&ring->xr_dma_hdl);
		goto err;
	}
	*gref = ring->xr_gref = ring_gref;

	/* init frontend ring */
	xvdi_ring_init_sring(ring);
	xvdi_ring_init_front_ring(ring, nentry, entrysize);

	return (DDI_SUCCESS);

err:
	kmem_free(ring, sizeof (xendev_ring_t));
	return (DDI_FAILURE);
}

/*
 * Release ring buffers allocated for Xen devices
 * used for frontend driver
 */
void
xvdi_free_ring(xendev_ring_t *ring)
{
	ASSERT((ring != NULL) && (ring->xr_vaddr != NULL));

	(void) gnttab_end_foreign_access_ref(ring->xr_gref, 0);
	(void) ddi_dma_unbind_handle(ring->xr_dma_hdl);
	ddi_dma_mem_free(&ring->xr_acc_hdl);
	ddi_dma_free_handle(&ring->xr_dma_hdl);
	kmem_free(ring, sizeof (xendev_ring_t));
}

dev_info_t *
xvdi_create_dev(dev_info_t *parent, xendev_devclass_t devclass,
    domid_t dom, int vdev)
{
	dev_info_t *dip;
	boolean_t backend;
	i_xd_cfg_t *xdcp;
	char xsnamebuf[TYPICALMAXPATHLEN];
	char *type, *node = NULL, *xsname = NULL;
	unsigned int tlen;
	int ret;

	ASSERT(DEVI_BUSY_OWNED(parent));

	backend = (dom != DOMID_SELF);
	xdcp = i_xvdi_devclass2cfg(devclass);
	ASSERT(xdcp != NULL);

	if (vdev != VDEV_NOXS) {
		if (!backend) {
			(void) snprintf(xsnamebuf, sizeof (xsnamebuf),
			    "%s/%d", xdcp->xs_path_fe, vdev);
			xsname = xsnamebuf;
			node = xdcp->node_fe;
		} else {
			(void) snprintf(xsnamebuf, sizeof (xsnamebuf),
			    "%s/%d/%d", xdcp->xs_path_be, dom, vdev);
			xsname = xsnamebuf;
			node = xdcp->node_be;
		}
	} else {
		node = xdcp->node_fe;
	}

	/* Must have a driver to use. */
	if (node == NULL)
		return (NULL);

	/*
	 * We need to check the state of this device before we go
	 * further, otherwise we'll end up with a dead loop if
	 * anything goes wrong.
	 */
	if ((xsname != NULL) &&
	    (xenbus_read_driver_state(xsname) >= XenbusStateClosing))
		return (NULL);

	ndi_devi_alloc_sleep(parent, node, DEVI_SID_NODEID, &dip);

	/*
	 * Driver binding uses the compatible property _before_ the
	 * node name, so we set the node name to the 'model' of the
	 * device (i.e. 'xnb' or 'xdb') and, if 'type' is present,
	 * encode both the model and the type in a compatible property
	 * (i.e. 'xnb,netfront' or 'xnb,SUNW_mac').  This allows a
	 * driver binding based on the <model,type> pair _before_ a
	 * binding based on the node name.
	 */
	if ((xsname != NULL) &&
	    (xenbus_read(XBT_NULL, xsname, "type", (void *)&type, &tlen)
	    == 0)) {
		size_t clen;
		char *c[1];

		clen = strlen(node) + strlen(type) + 2;
		c[0] = kmem_alloc(clen, KM_SLEEP);
		(void) snprintf(c[0], clen, "%s,%s", node, type);

		(void) ndi_prop_update_string_array(DDI_DEV_T_NONE,
		    dip, "compatible", (char **)c, 1);

		kmem_free(c[0], clen);
		kmem_free(type, tlen);
	}

	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "devclass", devclass);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "domain", dom);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "vdev", vdev);

	if (i_ddi_devi_attached(parent))
		ret = ndi_devi_online(dip, 0);
	else
		ret = ndi_devi_bind_driver(dip, 0);
	if (ret != NDI_SUCCESS)
		(void) ndi_devi_offline(dip, NDI_DEVI_REMOVE);

	return (dip);
}

/*
 * xendev_enum_class()
 */
void
xendev_enum_class(dev_info_t *parent, xendev_devclass_t devclass)
{
	boolean_t dom0 = DOMAIN_IS_INITDOMAIN(xen_info);
	boolean_t domU = !dom0;
	i_xd_cfg_t *xdcp;

	xdcp = i_xvdi_devclass2cfg(devclass);
	ASSERT(xdcp != NULL);

	if (dom0 && !(xdcp->flags & XD_DOM_ZERO))
		return;

	if (domU && !(xdcp->flags & XD_DOM_GUEST))
		return;

	if (xdcp->xsdev == NULL) {
		int circ;

		/*
		 * Don't need to probe this kind of device from the
		 * store, just create one if it doesn't exist.
		 */

		ndi_devi_enter(parent, &circ);
		if (xvdi_find_dev(parent, devclass, DOMID_SELF, VDEV_NOXS)
		    == NULL)
			(void) xvdi_create_dev(parent, devclass,
			    DOMID_SELF, VDEV_NOXS);
		ndi_devi_exit(parent, circ);
	} else {
		/*
		 * Probe this kind of device from the store, both
		 * frontend and backend.
		 */
		if (xdcp->node_fe != NULL) {
			i_xvdi_enum_fe(parent, xdcp);
		}
		if (xdcp->node_be != NULL) {
			i_xvdi_enum_be(parent, xdcp);
		}
	}
}

/*
 * xendev_enum_all()
 */
void
xendev_enum_all(dev_info_t *parent, boolean_t store_unavailable)
{
	int i;
	i_xd_cfg_t *xdcp;
	boolean_t dom0 = DOMAIN_IS_INITDOMAIN(xen_info);

	for (i = 0, xdcp = xdci; i < NXDC; i++, xdcp++) {
		/*
		 * Dom0 relies on watchpoints to create non-soft
		 * devices - don't attempt to iterate over the store.
		 */
		if (dom0 && (xdcp->xsdev != NULL))
			continue;

		/*
		 * If the store is not yet available, don't attempt to
		 * iterate.
		 */
		if (store_unavailable && (xdcp->xsdev != NULL))
			continue;

		xendev_enum_class(parent, xdcp->devclass);
	}
}

xendev_devclass_t
xendev_nodename_to_devclass(char *nodename)
{
	int i;
	i_xd_cfg_t *xdcp;

	/*
	 * This relies on the convention that variants of a base
	 * driver share the same prefix and that there are no drivers
	 * which share a common prefix with the name of any other base
	 * drivers.
	 *
	 * So for a base driver 'xnb' (which is the name listed in
	 * xdci) the variants all begin with the string 'xnb' (in fact
	 * they are 'xnbe', 'xnbo' and 'xnbu') and there are no other
	 * base drivers which have the prefix 'xnb'.
	 */
	ASSERT(nodename != NULL);
	for (i = 0, xdcp = xdci; i < NXDC; i++, xdcp++) {
		if (((xdcp->node_fe != NULL) &&
		    (strncmp(nodename, xdcp->node_fe,
		    strlen(xdcp->node_fe)) == 0)) ||
		    ((xdcp->node_be != NULL) &&
		    (strncmp(nodename, xdcp->node_be,
		    strlen(xdcp->node_be)) == 0)))

			return (xdcp->devclass);
	}
	return (XEN_INVAL);
}

int
xendev_devclass_ipl(xendev_devclass_t devclass)
{
	i_xd_cfg_t *xdcp;

	xdcp = i_xvdi_devclass2cfg(devclass);
	ASSERT(xdcp != NULL);

	return (xdcp->xd_ipl);
}

/*
 * Determine if a devinfo instance exists of a particular device
 * class, domain and xenstore virtual device number.
 */
dev_info_t *
xvdi_find_dev(dev_info_t *parent, xendev_devclass_t devclass,
    domid_t dom, int vdev)
{
	dev_info_t *dip;

	ASSERT(DEVI_BUSY_OWNED(parent));

	switch (devclass) {
	case XEN_CONSOLE:
	case XEN_XENBUS:
	case XEN_DOMCAPS:
	case XEN_BALLOON:
	case XEN_EVTCHN:
	case XEN_PRIVCMD:
		/* Console and soft devices have no vdev. */
		vdev = VDEV_NOXS;
		break;
	default:
		break;
	}

	for (dip = ddi_get_child(parent); dip != NULL;
	    dip = ddi_get_next_sibling(dip)) {
		int *vdevnump, *domidp, *devclsp, vdevnum;
		uint_t ndomid, nvdevnum, ndevcls;
		xendev_devclass_t devcls;
		domid_t domid;
		struct xendev_ppd *pdp = ddi_get_parent_data(dip);

		if (pdp == NULL) {
			if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "domain", &domidp, &ndomid) !=
			    DDI_PROP_SUCCESS)
				continue;
			ASSERT(ndomid == 1);
			domid = (domid_t)*domidp;
			ddi_prop_free(domidp);

			if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "vdev", &vdevnump, &nvdevnum) !=
			    DDI_PROP_SUCCESS)
				continue;
			ASSERT(nvdevnum == 1);
			vdevnum = *vdevnump;
			ddi_prop_free(vdevnump);

			if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "devclass", &devclsp,
			    &ndevcls) != DDI_PROP_SUCCESS)
				continue;
			ASSERT(ndevcls == 1);
			devcls = (xendev_devclass_t)*devclsp;
			ddi_prop_free(devclsp);
		} else {
			domid = pdp->xd_domain;
			vdevnum = pdp->xd_vdevnum;
			devcls = pdp->xd_devclass;
		}

		if ((domid == dom) && (vdevnum == vdev) && (devcls == devclass))
			return (dip);
	}
	return (NULL);
}

int
xvdi_get_evtchn(dev_info_t *xdip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(xdip);

	ASSERT(pdp != NULL);
	return (pdp->xd_evtchn);
}

int
xvdi_get_vdevnum(dev_info_t *xdip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(xdip);

	ASSERT(pdp != NULL);
	return (pdp->xd_vdevnum);
}

char *
xvdi_get_xsname(dev_info_t *xdip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(xdip);

	ASSERT(pdp != NULL);
	return ((char *)(pdp->xd_xsdev.nodename));
}

char *
xvdi_get_oename(dev_info_t *xdip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(xdip);

	ASSERT(pdp != NULL);
	if (pdp->xd_devclass == XEN_CONSOLE)
		return (NULL);
	return ((char *)(pdp->xd_xsdev.otherend));
}

struct xenbus_device *
xvdi_get_xsd(dev_info_t *xdip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(xdip);

	ASSERT(pdp != NULL);
	return (&pdp->xd_xsdev);
}

domid_t
xvdi_get_oeid(dev_info_t *xdip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(xdip);

	ASSERT(pdp != NULL);
	if (pdp->xd_devclass == XEN_CONSOLE)
		return ((domid_t)-1);
	return ((domid_t)(pdp->xd_xsdev.otherend_id));
}

void
xvdi_dev_error(dev_info_t *dip, int errno, char *errstr)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);

	ASSERT(pdp != NULL);
	xenbus_dev_error(&pdp->xd_xsdev, errno, errstr);
}

void
xvdi_fatal_error(dev_info_t *dip, int errno, char *errstr)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);

	ASSERT(pdp != NULL);
	xenbus_dev_fatal(&pdp->xd_xsdev, errno, errstr);
}

static void
i_xvdi_oestate_handler(void *arg)
{
	i_oestate_evt_t *evt = (i_oestate_evt_t *)arg;
	dev_info_t *dip = evt->dip;
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);
	XenbusState oestate = pdp->xd_xsdev.otherend_state;
	XenbusState curr_oestate = evt->state;
	ddi_eventcookie_t evc;

	/* evt is alloc'ed in i_xvdi_oestate_cb */
	kmem_free(evt, sizeof (i_oestate_evt_t));

	/*
	 * If the oestate we're handling is not the latest one,
	 * it does not make any sense to continue handling it.
	 */
	if (curr_oestate != oestate)
		return;

	mutex_enter(&pdp->xd_ndi_lk);

	if (pdp->xd_oe_ehid != NULL) {
		/* send notification to driver */
		if (ddi_get_eventcookie(dip, XS_OE_STATE,
		    &evc) == DDI_SUCCESS) {
			mutex_exit(&pdp->xd_ndi_lk);
			(void) ndi_post_event(dip, dip, evc, &oestate);
			mutex_enter(&pdp->xd_ndi_lk);
		}
	} else {
		/*
		 * take default action, if driver hasn't registered its
		 * event handler yet
		 */
		if (oestate == XenbusStateClosing) {
			(void) xvdi_switch_state(dip, XBT_NULL,
			    XenbusStateClosed);
		} else if (oestate == XenbusStateClosed) {
			(void) xvdi_switch_state(dip, XBT_NULL,
			    XenbusStateClosed);
			(void) xvdi_post_event(dip, XEN_HP_REMOVE);
		}
	}

	mutex_exit(&pdp->xd_ndi_lk);

	/*
	 * We'll try to remove the devinfo node of this device if the
	 * other end has closed.
	 */
	if (oestate == XenbusStateClosed)
		(void) ddi_taskq_dispatch(DEVI(ddi_get_parent(dip))->devi_taskq,
		    xendev_offline_device, dip, DDI_SLEEP);
}

static void
i_xvdi_hpstate_handler(void *arg)
{
	dev_info_t *dip = (dev_info_t *)arg;
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);
	ddi_eventcookie_t evc;
	char *hp_status;
	unsigned int hpl;

	mutex_enter(&pdp->xd_ndi_lk);
	if ((ddi_get_eventcookie(dip, XS_HP_STATE, &evc) == DDI_SUCCESS) &&
	    (xenbus_read(XBT_NULL, pdp->xd_hp_watch.node, "",
	    (void *)&hp_status, &hpl) == 0)) {

		xendev_hotplug_state_t new_state = Unrecognized;

		if (strcmp(hp_status, "connected") == 0)
			new_state = Connected;

		mutex_exit(&pdp->xd_ndi_lk);

		(void) ndi_post_event(dip, dip, evc, &new_state);
		kmem_free(hp_status, hpl);
		return;
	}
	mutex_exit(&pdp->xd_ndi_lk);
}

void
xvdi_notify_oe(dev_info_t *dip)
{
	struct xendev_ppd *pdp;

	pdp = ddi_get_parent_data(dip);
	ASSERT(pdp->xd_evtchn != INVALID_EVTCHN);
	ec_notify_via_evtchn(pdp->xd_evtchn);
}

static void
i_xvdi_bepath_cb(struct xenbus_watch *w, const char **vec, unsigned int len)
{
	dev_info_t *dip = (dev_info_t *)w->dev;
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);
	char *be = NULL;
	unsigned int bel;

	ASSERT(len > XS_WATCH_PATH);
	ASSERT(vec[XS_WATCH_PATH] != NULL);

	/*
	 * If the backend is not the same as that we already stored,
	 * re-set our watch for its' state.
	 */
	if ((xenbus_read(XBT_NULL, "", vec[XS_WATCH_PATH], (void *)be, &bel)
	    == 0) && (strcmp(be, pdp->xd_xsdev.otherend) != 0))
		(void) i_xvdi_add_watch_oestate(dip);

	if (be != NULL) {
		ASSERT(bel > 0);
		kmem_free(be, bel);
	}
}

static void
i_xvdi_xb_watch_free(xd_xb_watches_t *xxwp)
{
	ASSERT(xxwp->xxw_ref == 0);
	strfree((char *)xxwp->xxw_watch.node);
	kmem_free(xxwp, sizeof (*xxwp));
}

static void
i_xvdi_xb_watch_release(xd_xb_watches_t *xxwp)
{
	ASSERT(MUTEX_HELD(&xxwp->xxw_xppd->xd_ndi_lk));
	ASSERT(xxwp->xxw_ref > 0);
	if (--xxwp->xxw_ref == 0)
		i_xvdi_xb_watch_free(xxwp);
}

static void
i_xvdi_xb_watch_hold(xd_xb_watches_t *xxwp)
{
	ASSERT(MUTEX_HELD(&xxwp->xxw_xppd->xd_ndi_lk));
	ASSERT(xxwp->xxw_ref > 0);
	xxwp->xxw_ref++;
}

static void
i_xvdi_xb_watch_cb_tq(void *arg)
{
	xd_xb_watches_t		*xxwp = (xd_xb_watches_t *)arg;
	dev_info_t		*dip = (dev_info_t *)xxwp->xxw_watch.dev;
	struct xendev_ppd	*pdp = xxwp->xxw_xppd;

	xxwp->xxw_cb(dip, xxwp->xxw_watch.node, xxwp->xxw_arg);

	mutex_enter(&pdp->xd_ndi_lk);
	i_xvdi_xb_watch_release(xxwp);
	mutex_exit(&pdp->xd_ndi_lk);
}

static void
i_xvdi_xb_watch_cb(struct xenbus_watch *w, const char **vec, unsigned int len)
{
	dev_info_t		*dip = (dev_info_t *)w->dev;
	struct xendev_ppd	*pdp = ddi_get_parent_data(dip);
	xd_xb_watches_t		*xxwp;

	ASSERT(len > XS_WATCH_PATH);
	ASSERT(vec[XS_WATCH_PATH] != NULL);

	mutex_enter(&pdp->xd_ndi_lk);
	for (xxwp = list_head(&pdp->xd_xb_watches); xxwp != NULL;
	    xxwp = list_next(&pdp->xd_xb_watches, xxwp)) {
		if (w == &xxwp->xxw_watch)
			break;
	}

	if (xxwp == NULL) {
		mutex_exit(&pdp->xd_ndi_lk);
		return;
	}

	i_xvdi_xb_watch_hold(xxwp);
	(void) ddi_taskq_dispatch(pdp->xd_xb_watch_taskq,
	    i_xvdi_xb_watch_cb_tq, xxwp, DDI_SLEEP);
	mutex_exit(&pdp->xd_ndi_lk);
}

/*
 * Any watches registered with xvdi_add_xb_watch_handler() get torn down during
 * a suspend operation.  So if a frontend driver want's to use these interfaces,
 * that driver is responsible for re-registering any watches it had before
 * the suspend operation.
 */
int
xvdi_add_xb_watch_handler(dev_info_t *dip, const char *dir, const char *node,
    xvdi_xb_watch_cb_t cb, void *arg)
{
	struct xendev_ppd	*pdp = ddi_get_parent_data(dip);
	xd_xb_watches_t		*xxw_new, *xxwp;
	char			*path;
	int			n;

	ASSERT((dip != NULL) && (dir != NULL) && (node != NULL));
	ASSERT(cb != NULL);

	n = strlen(dir) + 1 + strlen(node) + 1;
	path = kmem_zalloc(n, KM_SLEEP);
	(void) strlcat(path, dir, n);
	(void) strlcat(path, "/", n);
	(void) strlcat(path, node, n);
	ASSERT((strlen(path) + 1) == n);

	xxw_new = kmem_zalloc(sizeof (*xxw_new), KM_SLEEP);
	xxw_new->xxw_ref = 1;
	xxw_new->xxw_watch.node = path;
	xxw_new->xxw_watch.callback = i_xvdi_xb_watch_cb;
	xxw_new->xxw_watch.dev = (struct xenbus_device *)dip;
	xxw_new->xxw_xppd = pdp;
	xxw_new->xxw_cb = cb;
	xxw_new->xxw_arg = arg;

	mutex_enter(&pdp->xd_ndi_lk);

	/*
	 * If this is the first watch we're setting up, create a taskq
	 * to dispatch watch events and initialize the watch list.
	 */
	if (pdp->xd_xb_watch_taskq == NULL) {
		char tq_name[TASKQ_NAMELEN];

		ASSERT(list_is_empty(&pdp->xd_xb_watches));

		(void) snprintf(tq_name, sizeof (tq_name),
		    "%s_xb_watch_tq", ddi_get_name(dip));

		if ((pdp->xd_xb_watch_taskq = ddi_taskq_create(dip, tq_name,
		    1, TASKQ_DEFAULTPRI, 0)) == NULL) {
			i_xvdi_xb_watch_release(xxw_new);
			mutex_exit(&pdp->xd_ndi_lk);
			return (DDI_FAILURE);
		}
	}

	/* Don't allow duplicate watches to be registered */
	for (xxwp = list_head(&pdp->xd_xb_watches); xxwp != NULL;
	    xxwp = list_next(&pdp->xd_xb_watches, xxwp)) {

		ASSERT(strcmp(xxwp->xxw_watch.node, path) != 0);
		if (strcmp(xxwp->xxw_watch.node, path) != 0)
			continue;
		i_xvdi_xb_watch_release(xxw_new);
		mutex_exit(&pdp->xd_ndi_lk);
		return (DDI_FAILURE);
	}

	if (register_xenbus_watch(&xxw_new->xxw_watch) != 0) {
		if (list_is_empty(&pdp->xd_xb_watches)) {
			ddi_taskq_destroy(pdp->xd_xb_watch_taskq);
			pdp->xd_xb_watch_taskq = NULL;
		}
		i_xvdi_xb_watch_release(xxw_new);
		mutex_exit(&pdp->xd_ndi_lk);
		return (DDI_FAILURE);
	}

	list_insert_head(&pdp->xd_xb_watches, xxw_new);
	mutex_exit(&pdp->xd_ndi_lk);
	return (DDI_SUCCESS);
}

/*
 * Tear down all xenbus watches registered by the specified dip.
 */
void
xvdi_remove_xb_watch_handlers(dev_info_t *dip)
{
	struct xendev_ppd	*pdp = ddi_get_parent_data(dip);
	xd_xb_watches_t		*xxwp;
	ddi_taskq_t		*tq;

	mutex_enter(&pdp->xd_ndi_lk);

	while ((xxwp = list_remove_head(&pdp->xd_xb_watches)) != NULL) {
		mutex_exit(&pdp->xd_ndi_lk);
		unregister_xenbus_watch(&xxwp->xxw_watch);
		mutex_enter(&pdp->xd_ndi_lk);
		i_xvdi_xb_watch_release(xxwp);
	}
	ASSERT(list_is_empty(&pdp->xd_xb_watches));

	/*
	 * We can't hold xd_ndi_lk while we destroy the xd_xb_watch_taskq.
	 * This is because if there are currently any executing taskq threads,
	 * we will block until they are finished, and to finish they need
	 * to aquire xd_ndi_lk in i_xvdi_xb_watch_cb_tq() so they can release
	 * their reference on their corresponding xxwp structure.
	 */
	tq = pdp->xd_xb_watch_taskq;
	pdp->xd_xb_watch_taskq = NULL;
	mutex_exit(&pdp->xd_ndi_lk);
	if (tq != NULL)
		ddi_taskq_destroy(tq);
}

static int
i_xvdi_add_watch_oestate(dev_info_t *dip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);

	ASSERT(pdp != NULL);
	ASSERT(pdp->xd_xsdev.nodename != NULL);
	ASSERT(mutex_owned(&pdp->xd_ndi_lk));

	/*
	 * Create taskq for delivering other end state change event to
	 * this device later.
	 *
	 * Set nthreads to 1 to make sure that events can be delivered
	 * in order.
	 *
	 * Note: It is _not_ guaranteed that driver can see every
	 * xenstore change under the path that it is watching. If two
	 * changes happen consecutively in a very short amount of
	 * time, it is likely that the driver will see only the last
	 * one.
	 */
	if (pdp->xd_oe_taskq == NULL)
		if ((pdp->xd_oe_taskq = ddi_taskq_create(dip,
		    "xendev_oe_taskq", 1, TASKQ_DEFAULTPRI, 0)) == NULL)
			return (DDI_FAILURE);

	/*
	 * Watch for changes to the XenbusState of otherend.
	 */
	pdp->xd_xsdev.otherend_state = XenbusStateUnknown;
	pdp->xd_xsdev.otherend_changed = i_xvdi_oestate_cb;

	if (talk_to_otherend(&pdp->xd_xsdev) != 0) {
		i_xvdi_rem_watch_oestate(dip);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
i_xvdi_rem_watch_oestate(dev_info_t *dip)
{
	struct xendev_ppd *pdp;
	struct xenbus_device *dev;

	pdp = ddi_get_parent_data(dip);
	ASSERT(pdp != NULL);
	ASSERT(mutex_owned(&pdp->xd_ndi_lk));

	dev = &pdp->xd_xsdev;

	/* Unwatch for changes to XenbusState of otherend */
	if (dev->otherend_watch.node != NULL) {
		mutex_exit(&pdp->xd_ndi_lk);
		unregister_xenbus_watch(&dev->otherend_watch);
		mutex_enter(&pdp->xd_ndi_lk);
	}

	/* make sure no event handler is running */
	if (pdp->xd_oe_taskq != NULL) {
		mutex_exit(&pdp->xd_ndi_lk);
		ddi_taskq_destroy(pdp->xd_oe_taskq);
		mutex_enter(&pdp->xd_ndi_lk);
		pdp->xd_oe_taskq = NULL;
	}

	/* clean up */
	dev->otherend_state = XenbusStateUnknown;
	dev->otherend_id = (domid_t)-1;
	if (dev->otherend_watch.node != NULL)
		kmem_free((void *)dev->otherend_watch.node,
		    strlen(dev->otherend_watch.node) + 1);
	dev->otherend_watch.node = NULL;
	if (dev->otherend != NULL)
		kmem_free((void *)dev->otherend, strlen(dev->otherend) + 1);
	dev->otherend = NULL;
}

static int
i_xvdi_add_watch_hpstate(dev_info_t *dip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);

	ASSERT(pdp != NULL);
	ASSERT(pdp->xd_xsdev.frontend == 0);
	ASSERT(mutex_owned(&pdp->xd_ndi_lk));

	/*
	 * Create taskq for delivering hotplug status change event to
	 * this device later.
	 *
	 * Set nthreads to 1 to make sure that events can be delivered
	 * in order.
	 *
	 * Note: It is _not_ guaranteed that driver can see every
	 * hotplug status change under the path that it is
	 * watching. If two changes happen consecutively in a very
	 * short amount of time, it is likely that the driver only
	 * sees the last one.
	 */
	if (pdp->xd_hp_taskq == NULL)
		if ((pdp->xd_hp_taskq = ddi_taskq_create(dip,
		    "xendev_hp_taskq", 1, TASKQ_DEFAULTPRI, 0)) == NULL)
			return (DDI_FAILURE);

	if (pdp->xd_hp_watch.node == NULL) {
		size_t len;
		char *path;

		ASSERT(pdp->xd_xsdev.nodename != NULL);

		len = strlen(pdp->xd_xsdev.nodename) +
		    strlen("/hotplug-status") + 1;
		path = kmem_alloc(len, KM_SLEEP);
		(void) snprintf(path, len, "%s/hotplug-status",
		    pdp->xd_xsdev.nodename);

		pdp->xd_hp_watch.node = path;
		pdp->xd_hp_watch.callback = i_xvdi_hpstate_cb;
		pdp->xd_hp_watch.dev = (struct xenbus_device *)dip; /* yuck! */
		if (register_xenbus_watch(&pdp->xd_hp_watch) != 0) {
			i_xvdi_rem_watch_hpstate(dip);
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

static void
i_xvdi_rem_watch_hpstate(dev_info_t *dip)
{
	struct xendev_ppd *pdp;
	pdp = ddi_get_parent_data(dip);

	ASSERT(pdp != NULL);
	ASSERT(pdp->xd_xsdev.frontend == 0);
	ASSERT(mutex_owned(&pdp->xd_ndi_lk));

	/* Unwatch for changes to "hotplug-status" node for backend device. */
	if (pdp->xd_hp_watch.node != NULL) {
		mutex_exit(&pdp->xd_ndi_lk);
		unregister_xenbus_watch(&pdp->xd_hp_watch);
		mutex_enter(&pdp->xd_ndi_lk);
	}

	/* Make sure no event handler is running. */
	if (pdp->xd_hp_taskq != NULL) {
		mutex_exit(&pdp->xd_ndi_lk);
		ddi_taskq_destroy(pdp->xd_hp_taskq);
		mutex_enter(&pdp->xd_ndi_lk);
		pdp->xd_hp_taskq = NULL;
	}

	/* Clean up. */
	if (pdp->xd_hp_watch.node != NULL) {
		kmem_free((void *)pdp->xd_hp_watch.node,
		    strlen(pdp->xd_hp_watch.node) + 1);
		pdp->xd_hp_watch.node = NULL;
	}
}

static int
i_xvdi_add_watches(dev_info_t *dip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);

	ASSERT(pdp != NULL);

	mutex_enter(&pdp->xd_ndi_lk);

	if (i_xvdi_add_watch_oestate(dip) != DDI_SUCCESS) {
		mutex_exit(&pdp->xd_ndi_lk);
		return (DDI_FAILURE);
	}

	if (pdp->xd_xsdev.frontend == 1) {
		/*
		 * Frontend devices must watch for the backend path
		 * changing.
		 */
		if (i_xvdi_add_watch_bepath(dip) != DDI_SUCCESS)
			goto unwatch_and_fail;
	} else {
		/*
		 * Backend devices must watch for hotplug events.
		 */
		if (i_xvdi_add_watch_hpstate(dip) != DDI_SUCCESS)
			goto unwatch_and_fail;
	}

	mutex_exit(&pdp->xd_ndi_lk);

	return (DDI_SUCCESS);

unwatch_and_fail:
	i_xvdi_rem_watch_oestate(dip);
	mutex_exit(&pdp->xd_ndi_lk);

	return (DDI_FAILURE);
}

static void
i_xvdi_rem_watches(dev_info_t *dip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);

	ASSERT(pdp != NULL);

	mutex_enter(&pdp->xd_ndi_lk);

	i_xvdi_rem_watch_oestate(dip);

	if (pdp->xd_xsdev.frontend == 1)
		i_xvdi_rem_watch_bepath(dip);
	else
		i_xvdi_rem_watch_hpstate(dip);

	mutex_exit(&pdp->xd_ndi_lk);

	xvdi_remove_xb_watch_handlers(dip);
}

static int
i_xvdi_add_watch_bepath(dev_info_t *dip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);

	ASSERT(pdp != NULL);
	ASSERT(pdp->xd_xsdev.frontend == 1);

	/*
	 * Frontend devices need to watch for the backend path changing.
	 */
	if (pdp->xd_bepath_watch.node == NULL) {
		size_t len;
		char *path;

		ASSERT(pdp->xd_xsdev.nodename != NULL);

		len = strlen(pdp->xd_xsdev.nodename) + strlen("/backend") + 1;
		path = kmem_alloc(len, KM_SLEEP);
		(void) snprintf(path, len, "%s/backend",
		    pdp->xd_xsdev.nodename);

		pdp->xd_bepath_watch.node = path;
		pdp->xd_bepath_watch.callback = i_xvdi_bepath_cb;
		pdp->xd_bepath_watch.dev = (struct xenbus_device *)dip;
		if (register_xenbus_watch(&pdp->xd_bepath_watch) != 0) {
			kmem_free(path, len);
			pdp->xd_bepath_watch.node = NULL;
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

static void
i_xvdi_rem_watch_bepath(dev_info_t *dip)
{
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);

	ASSERT(pdp != NULL);
	ASSERT(pdp->xd_xsdev.frontend == 1);
	ASSERT(mutex_owned(&pdp->xd_ndi_lk));

	if (pdp->xd_bepath_watch.node != NULL) {
		mutex_exit(&pdp->xd_ndi_lk);
		unregister_xenbus_watch(&pdp->xd_bepath_watch);
		mutex_enter(&pdp->xd_ndi_lk);

		kmem_free((void *)(pdp->xd_bepath_watch.node),
		    strlen(pdp->xd_bepath_watch.node) + 1);
		pdp->xd_bepath_watch.node = NULL;
	}
}

int
xvdi_switch_state(dev_info_t *dip, xenbus_transaction_t xbt,
    XenbusState newState)
{
	int rv;
	struct xendev_ppd *pdp;

	pdp = ddi_get_parent_data(dip);
	ASSERT(pdp != NULL);

	XVDI_DPRINTF(XVDI_DBG_STATE,
	    "xvdi_switch_state: %s@%s's xenbus state moves to %d\n",
	    ddi_binding_name(dip) == NULL ? "null" : ddi_binding_name(dip),
	    ddi_get_name_addr(dip) == NULL ? "null" : ddi_get_name_addr(dip),
	    newState);

	rv = xenbus_switch_state(&pdp->xd_xsdev, xbt, newState);
	if (rv > 0)
		cmn_err(CE_WARN, "xvdi_switch_state: change state failed");

	return (rv);
}

/*
 * Notify hotplug script running in userland
 */
int
xvdi_post_event(dev_info_t *dip, xendev_hotplug_cmd_t hpc)
{
	struct xendev_ppd *pdp;
	nvlist_t *attr_list = NULL;
	i_xd_cfg_t *xdcp;
	sysevent_id_t eid;
	int err;
	char devname[256]; /* XXPV dme: ? */

	pdp = ddi_get_parent_data(dip);
	ASSERT(pdp != NULL);

	xdcp = i_xvdi_devclass2cfg(pdp->xd_devclass);
	ASSERT(xdcp != NULL);

	(void) snprintf(devname, sizeof (devname) - 1, "%s%d",
	    ddi_driver_name(dip),  ddi_get_instance(dip));

	err = nvlist_alloc(&attr_list, NV_UNIQUE_NAME, KM_NOSLEEP);
	if (err != DDI_SUCCESS)
		goto failure;

	err = nvlist_add_int32(attr_list, "domain", pdp->xd_domain);
	if (err != DDI_SUCCESS)
		goto failure;
	err = nvlist_add_int32(attr_list, "vdev", pdp->xd_vdevnum);
	if (err != DDI_SUCCESS)
		goto failure;
	err = nvlist_add_string(attr_list, "devclass", xdcp->xsdev);
	if (err != DDI_SUCCESS)
		goto failure;
	err = nvlist_add_string(attr_list, "device", devname);
	if (err != DDI_SUCCESS)
		goto failure;
	err = nvlist_add_string(attr_list, "fob",
	    ((pdp->xd_xsdev.frontend == 1) ? "frontend" : "backend"));
	if (err != DDI_SUCCESS)
		goto failure;

	switch (hpc) {
	case XEN_HP_ADD:
		err = ddi_log_sysevent(dip, DDI_VENDOR_SUNW, "EC_xendev",
		    "add", attr_list, &eid, DDI_NOSLEEP);
		break;
	case XEN_HP_REMOVE:
		err = ddi_log_sysevent(dip, DDI_VENDOR_SUNW, "EC_xendev",
		    "remove", attr_list, &eid, DDI_NOSLEEP);
		break;
	default:
		err = DDI_FAILURE;
		goto failure;
	}

failure:
	nvlist_free(attr_list);

	return (err);
}

/* ARGSUSED */
static void
i_xvdi_probe_path_cb(struct xenbus_watch *w, const char **vec,
    unsigned int len)
{
	char *path;

	if (xendev_dip == NULL)
		xendev_dip = ddi_find_devinfo("xpvd", -1, 0);

	path = i_ddi_strdup((char *)vec[XS_WATCH_PATH], KM_SLEEP);

	(void) ddi_taskq_dispatch(DEVI(xendev_dip)->devi_taskq,
	    i_xvdi_probe_path_handler, (void *)path, DDI_SLEEP);
}

static void
i_xvdi_watch_device(char *path)
{
	struct xenbus_watch *w;

	ASSERT(path != NULL);

	w = kmem_zalloc(sizeof (*w), KM_SLEEP);
	w->node = path;
	w->callback = &i_xvdi_probe_path_cb;
	w->dev = NULL;

	if (register_xenbus_watch(w) != 0) {
		cmn_err(CE_WARN, "i_xvdi_watch_device: "
		    "cannot set watch on %s", path);
		kmem_free(w, sizeof (*w));
		return;
	}
}

void
xvdi_watch_devices(int newstate)
{
	int devclass;

	/*
	 * Watch for devices being created in the store.
	 */
	if (newstate == XENSTORE_DOWN)
		return;
	for (devclass = 0; devclass < NXDC; devclass++) {
		if (xdci[devclass].xs_path_fe != NULL)
			i_xvdi_watch_device(xdci[devclass].xs_path_fe);
		if (xdci[devclass].xs_path_be != NULL)
			i_xvdi_watch_device(xdci[devclass].xs_path_be);
	}
}

/*
 * Iterate over the store looking for backend devices to create.
 */
static void
i_xvdi_enum_be(dev_info_t *parent, i_xd_cfg_t *xdcp)
{
	char **domains;
	unsigned int ndomains;
	int ldomains, i;

	if ((domains = xenbus_directory(XBT_NULL, xdcp->xs_path_be, "",
	    &ndomains)) == NULL)
		return;

	for (i = 0, ldomains = 0; i < ndomains; i++) {
		ldomains += strlen(domains[i]) + 1 + sizeof (char *);

		i_xvdi_enum_worker(parent, xdcp, domains[i]);
	}
	kmem_free(domains, ldomains);
}

/*
 * Iterate over the store looking for frontend devices to create.
 */
static void
i_xvdi_enum_fe(dev_info_t *parent, i_xd_cfg_t *xdcp)
{
	i_xvdi_enum_worker(parent, xdcp, NULL);
}

static void
i_xvdi_enum_worker(dev_info_t *parent, i_xd_cfg_t *xdcp,
    char *domain)
{
	char *path, *domain_path, *ep;
	char **devices;
	unsigned int ndevices;
	int ldevices, j, circ;
	domid_t dom;
	long tmplong;

	if (domain == NULL) {
		dom = DOMID_SELF;
		path = xdcp->xs_path_fe;
		domain_path = "";
	} else {
		(void) ddi_strtol(domain, &ep, 0, &tmplong);
		dom = tmplong;
		path = xdcp->xs_path_be;
		domain_path = domain;
	}

	if ((devices = xenbus_directory(XBT_NULL, path, domain_path,
	    &ndevices)) == NULL)
		return;

	for (j = 0, ldevices = 0; j < ndevices; j++) {
		int vdev;

		ldevices += strlen(devices[j]) + 1 + sizeof (char *);
		(void) ddi_strtol(devices[j], &ep, 0, &tmplong);
		vdev = tmplong;

		ndi_devi_enter(parent, &circ);

		if (xvdi_find_dev(parent, xdcp->devclass, dom, vdev) == NULL)
			(void) xvdi_create_dev(parent, xdcp->devclass,
			    dom, vdev);

		ndi_devi_exit(parent, circ);
	}
	kmem_free(devices, ldevices);
}

/*
 * Leaf drivers should call this in their detach() routine during suspend.
 */
void
xvdi_suspend(dev_info_t *dip)
{
	i_xvdi_rem_watches(dip);
}

/*
 * Leaf drivers should call this in their attach() routine during resume.
 */
int
xvdi_resume(dev_info_t *dip)
{
	return (i_xvdi_add_watches(dip));
}

/*
 * Add event handler for the leaf driver
 * to handle event triggered by the change in xenstore
 */
int
xvdi_add_event_handler(dev_info_t *dip, char *name,
    void (*evthandler)(dev_info_t *, ddi_eventcookie_t, void *, void *),
    void *arg)
{
	ddi_eventcookie_t ecv;
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);
	ddi_callback_id_t *cbid;
	boolean_t call_handler;
	i_oestate_evt_t *evt = NULL;
	XenbusState oestate;

	ASSERT(pdp != NULL);

	mutex_enter(&pdp->xd_ndi_lk);

	if (strcmp(name, XS_OE_STATE) == 0) {
		ASSERT(pdp->xd_xsdev.otherend != NULL);

		cbid = &pdp->xd_oe_ehid;
	} else if (strcmp(name, XS_HP_STATE) == 0) {
		if (pdp->xd_xsdev.frontend == 1) {
			mutex_exit(&pdp->xd_ndi_lk);
			return (DDI_FAILURE);
		}

		ASSERT(pdp->xd_hp_watch.node != NULL);

		cbid = &pdp->xd_hp_ehid;
	} else {
		/* Unsupported watch. */
		mutex_exit(&pdp->xd_ndi_lk);
		return (DDI_FAILURE);
	}

	/*
	 * No event handler provided, take default action to handle
	 * event.
	 */
	if (evthandler == NULL) {
		mutex_exit(&pdp->xd_ndi_lk);
		return (DDI_SUCCESS);
	}

	ASSERT(*cbid == NULL);

	if (ddi_get_eventcookie(dip, name, &ecv) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "failed to find %s cookie for %s@%s",
		    name, ddi_get_name(dip), ddi_get_name_addr(dip));
		mutex_exit(&pdp->xd_ndi_lk);
		return (DDI_FAILURE);
	}
	if (ddi_add_event_handler(dip, ecv, evthandler, arg, cbid)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "failed to add %s event handler for %s@%s",
		    name, ddi_get_name(dip), ddi_get_name_addr(dip));
		*cbid = NULL;
		mutex_exit(&pdp->xd_ndi_lk);
		return (DDI_FAILURE);
	}

	/*
	 * if we're adding an oe state callback, and the ring has already
	 * transitioned out of Unknown, call the handler after we release
	 * the mutex.
	 */
	call_handler = B_FALSE;
	if ((strcmp(name, XS_OE_STATE) == 0) &&
	    (pdp->xd_xsdev.otherend_state != XenbusStateUnknown)) {
		oestate = pdp->xd_xsdev.otherend_state;
		call_handler = B_TRUE;
	}

	mutex_exit(&pdp->xd_ndi_lk);

	if (call_handler) {
		evt = kmem_alloc(sizeof (i_oestate_evt_t), KM_SLEEP);
		evt->dip = dip;
		evt->state = oestate;
		(void) ddi_taskq_dispatch(pdp->xd_oe_taskq,
		    i_xvdi_oestate_handler, (void *)evt, DDI_SLEEP);
	}

	return (DDI_SUCCESS);
}

/*
 * Remove event handler for the leaf driver and unwatch xenstore
 * so, driver will not be notified when xenstore entry changed later
 */
void
xvdi_remove_event_handler(dev_info_t *dip, char *name)
{
	struct xendev_ppd *pdp;
	boolean_t rem_oe = B_FALSE, rem_hp = B_FALSE;
	ddi_callback_id_t oeid = NULL, hpid = NULL;

	pdp = ddi_get_parent_data(dip);
	ASSERT(pdp != NULL);

	if (name == NULL) {
		rem_oe = B_TRUE;
		rem_hp = B_TRUE;
	} else if (strcmp(name, XS_OE_STATE) == 0) {
		rem_oe = B_TRUE;
	} else if (strcmp(name, XS_HP_STATE) == 0) {
		rem_hp = B_TRUE;
	} else {
		cmn_err(CE_WARN, "event %s not supported, cannot remove", name);
		return;
	}

	mutex_enter(&pdp->xd_ndi_lk);

	if (rem_oe && (pdp->xd_oe_ehid != NULL)) {
		oeid = pdp->xd_oe_ehid;
		pdp->xd_oe_ehid = NULL;
	}

	if (rem_hp && (pdp->xd_hp_ehid != NULL)) {
		hpid = pdp->xd_hp_ehid;
		pdp->xd_hp_ehid = NULL;
	}

	mutex_exit(&pdp->xd_ndi_lk);

	if (oeid != NULL)
		(void) ddi_remove_event_handler(oeid);
	if (hpid != NULL)
		(void) ddi_remove_event_handler(hpid);
}


/*
 * common ring interfaces
 */

#define	FRONT_RING(_ringp)	(&(_ringp)->xr_sring.fr)
#define	BACK_RING(_ringp)	(&(_ringp)->xr_sring.br)
#define	GET_RING_SIZE(_ringp)	RING_SIZE(FRONT_RING(ringp))
#define	GET_RING_ENTRY_FE(_ringp, _idx)		\
	(FRONT_RING(_ringp)->sring->ring +	\
	(_ringp)->xr_entry_size * ((_idx) & (GET_RING_SIZE(_ringp) - 1)))
#define	GET_RING_ENTRY_BE(_ringp, _idx)		\
	(BACK_RING(_ringp)->sring->ring +	\
	(_ringp)->xr_entry_size * ((_idx) & (GET_RING_SIZE(_ringp) - 1)))

unsigned int
xvdi_ring_avail_slots(xendev_ring_t *ringp)
{
	comif_ring_fe_t *frp;
	comif_ring_be_t *brp;

	if (ringp->xr_frontend) {
		frp = FRONT_RING(ringp);
		return (GET_RING_SIZE(ringp) -
		    (frp->req_prod_pvt - frp->rsp_cons));
	} else {
		brp = BACK_RING(ringp);
		return (GET_RING_SIZE(ringp) -
		    (brp->rsp_prod_pvt - brp->req_cons));
	}
}

int
xvdi_ring_has_unconsumed_requests(xendev_ring_t *ringp)
{
	comif_ring_be_t *brp;

	ASSERT(!ringp->xr_frontend);
	brp = BACK_RING(ringp);
	return ((brp->req_cons !=
	    ddi_get32(ringp->xr_acc_hdl, &brp->sring->req_prod)) &&
	    ((brp->req_cons - brp->rsp_prod_pvt) != RING_SIZE(brp)));
}

int
xvdi_ring_has_incomp_request(xendev_ring_t *ringp)
{
	comif_ring_fe_t *frp;

	ASSERT(ringp->xr_frontend);
	frp = FRONT_RING(ringp);
	return (frp->req_prod_pvt !=
	    ddi_get32(ringp->xr_acc_hdl, &frp->sring->rsp_prod));
}

int
xvdi_ring_has_unconsumed_responses(xendev_ring_t *ringp)
{
	comif_ring_fe_t *frp;

	ASSERT(ringp->xr_frontend);
	frp = FRONT_RING(ringp);
	return (frp->rsp_cons !=
	    ddi_get32(ringp->xr_acc_hdl, &frp->sring->rsp_prod));
}

/* NOTE: req_event will be increased as needed */
void *
xvdi_ring_get_request(xendev_ring_t *ringp)
{
	comif_ring_fe_t *frp;
	comif_ring_be_t *brp;

	if (ringp->xr_frontend) {
		/* for frontend ring */
		frp = FRONT_RING(ringp);
		if (!RING_FULL(frp))
			return (GET_RING_ENTRY_FE(ringp, frp->req_prod_pvt++));
		else
			return (NULL);
	} else {
		/* for backend ring */
		brp = BACK_RING(ringp);
		/* RING_FINAL_CHECK_FOR_REQUESTS() */
		if (xvdi_ring_has_unconsumed_requests(ringp))
			return (GET_RING_ENTRY_BE(ringp, brp->req_cons++));
		else {
			ddi_put32(ringp->xr_acc_hdl, &brp->sring->req_event,
			    brp->req_cons + 1);
			membar_enter();
			if (xvdi_ring_has_unconsumed_requests(ringp))
				return (GET_RING_ENTRY_BE(ringp,
				    brp->req_cons++));
			else
				return (NULL);
		}
	}
}

int
xvdi_ring_push_request(xendev_ring_t *ringp)
{
	RING_IDX old, new, reqevt;
	comif_ring_fe_t *frp;

	/* only frontend should be able to push request */
	ASSERT(ringp->xr_frontend);

	/* RING_PUSH_REQUEST_AND_CHECK_NOTIFY() */
	frp = FRONT_RING(ringp);
	old = ddi_get32(ringp->xr_acc_hdl, &frp->sring->req_prod);
	new = frp->req_prod_pvt;
	ddi_put32(ringp->xr_acc_hdl, &frp->sring->req_prod, new);
	membar_enter();
	reqevt = ddi_get32(ringp->xr_acc_hdl, &frp->sring->req_event);
	return ((RING_IDX)(new - reqevt) < (RING_IDX)(new - old));
}

/* NOTE: rsp_event will be increased as needed */
void *
xvdi_ring_get_response(xendev_ring_t *ringp)
{
	comif_ring_fe_t *frp;
	comif_ring_be_t *brp;

	if (!ringp->xr_frontend) {
		/* for backend ring */
		brp = BACK_RING(ringp);
		return (GET_RING_ENTRY_BE(ringp, brp->rsp_prod_pvt++));
	} else {
		/* for frontend ring */
		frp = FRONT_RING(ringp);
		/* RING_FINAL_CHECK_FOR_RESPONSES() */
		if (xvdi_ring_has_unconsumed_responses(ringp))
			return (GET_RING_ENTRY_FE(ringp, frp->rsp_cons++));
		else {
			ddi_put32(ringp->xr_acc_hdl, &frp->sring->rsp_event,
			    frp->rsp_cons + 1);
			membar_enter();
			if (xvdi_ring_has_unconsumed_responses(ringp))
				return (GET_RING_ENTRY_FE(ringp,
				    frp->rsp_cons++));
			else
				return (NULL);
		}
	}
}

int
xvdi_ring_push_response(xendev_ring_t *ringp)
{
	RING_IDX old, new, rspevt;
	comif_ring_be_t *brp;

	/* only backend should be able to push response */
	ASSERT(!ringp->xr_frontend);

	/* RING_PUSH_RESPONSE_AND_CHECK_NOTIFY() */
	brp = BACK_RING(ringp);
	old = ddi_get32(ringp->xr_acc_hdl, &brp->sring->rsp_prod);
	new = brp->rsp_prod_pvt;
	ddi_put32(ringp->xr_acc_hdl, &brp->sring->rsp_prod, new);
	membar_enter();
	rspevt = ddi_get32(ringp->xr_acc_hdl, &brp->sring->rsp_event);
	return ((RING_IDX)(new - rspevt) < (RING_IDX)(new - old));
}

static void
xvdi_ring_init_sring(xendev_ring_t *ringp)
{
	ddi_acc_handle_t acchdl;
	comif_sring_t *xsrp;
	int i;

	xsrp = (comif_sring_t *)ringp->xr_vaddr;
	acchdl = ringp->xr_acc_hdl;

	/* shared ring initialization */
	ddi_put32(acchdl, &xsrp->req_prod, 0);
	ddi_put32(acchdl, &xsrp->rsp_prod, 0);
	ddi_put32(acchdl, &xsrp->req_event, 1);
	ddi_put32(acchdl, &xsrp->rsp_event, 1);
	for (i = 0; i < sizeof (xsrp->pad); i++)
		ddi_put8(acchdl, xsrp->pad + i, 0);
}

static void
xvdi_ring_init_front_ring(xendev_ring_t *ringp, size_t nentry, size_t entrysize)
{
	comif_ring_fe_t *xfrp;

	xfrp = &ringp->xr_sring.fr;
	xfrp->req_prod_pvt = 0;
	xfrp->rsp_cons = 0;
	xfrp->nr_ents = nentry;
	xfrp->sring = (comif_sring_t *)ringp->xr_vaddr;

	ringp->xr_frontend = 1;
	ringp->xr_entry_size = entrysize;
}

#ifndef XPV_HVM_DRIVER
static void
xvdi_ring_init_back_ring(xendev_ring_t *ringp, size_t nentry, size_t entrysize)
{
	comif_ring_be_t *xbrp;

	xbrp = &ringp->xr_sring.br;
	xbrp->rsp_prod_pvt = 0;
	xbrp->req_cons = 0;
	xbrp->nr_ents = nentry;
	xbrp->sring = (comif_sring_t *)ringp->xr_vaddr;

	ringp->xr_frontend = 0;
	ringp->xr_entry_size = entrysize;
}
#endif /* XPV_HVM_DRIVER */

static void
xendev_offline_device(void *arg)
{
	dev_info_t *dip = (dev_info_t *)arg;
	char devname[MAXNAMELEN] = {0};

	/*
	 * This is currently the only chance to delete a devinfo node, which
	 * is _not_ always successful.
	 */
	(void) ddi_deviname(dip, devname);
	(void) devfs_clean(ddi_get_parent(dip), devname + 1, DV_CLEAN_FORCE);
	(void) ndi_devi_offline(dip, NDI_DEVI_REMOVE);
}

static void
i_xvdi_oestate_cb(struct xenbus_device *dev, XenbusState oestate)
{
	dev_info_t *dip = (dev_info_t *)dev->data;
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);
	i_oestate_evt_t *evt = NULL;
	boolean_t call_handler;

	XVDI_DPRINTF(XVDI_DBG_STATE,
	    "i_xvdi_oestate_cb: %s@%s sees oestate change to %d\n",
	    ddi_binding_name(dip) == NULL ? "null" : ddi_binding_name(dip),
	    ddi_get_name_addr(dip) == NULL ? "null" : ddi_get_name_addr(dip),
	    oestate);

	/* only call the handler if our state has changed */
	call_handler = B_FALSE;
	mutex_enter(&pdp->xd_ndi_lk);
	if (dev->otherend_state != oestate) {
		dev->otherend_state = oestate;
		call_handler = B_TRUE;
	}
	mutex_exit(&pdp->xd_ndi_lk);

	if (call_handler) {
		/*
		 * Try to deliver the oestate change event to the dip
		 */
		evt = kmem_alloc(sizeof (i_oestate_evt_t), KM_SLEEP);
		evt->dip = dip;
		evt->state = oestate;
		(void) ddi_taskq_dispatch(pdp->xd_oe_taskq,
		    i_xvdi_oestate_handler, (void *)evt, DDI_SLEEP);
	}
}

/*ARGSUSED*/
static void
i_xvdi_hpstate_cb(struct xenbus_watch *w, const char **vec,
    unsigned int len)
{
	dev_info_t *dip = (dev_info_t *)w->dev;
	struct xendev_ppd *pdp = ddi_get_parent_data(dip);

#ifdef DEBUG
	char *hp_status = NULL;
	unsigned int hpl = 0;

	(void) xenbus_read(XBT_NULL, pdp->xd_hp_watch.node, "",
	    (void *)&hp_status, &hpl);
	XVDI_DPRINTF(XVDI_DBG_STATE,
	    "i_xvdi_hpstate_cb: %s@%s sees hpstate change to %s\n",
	    ddi_binding_name(dip) == NULL ?  "null" : ddi_binding_name(dip),
	    ddi_get_name_addr(dip) == NULL ?  "null" : ddi_get_name_addr(dip),
	    hp_status == NULL ? "null" : hp_status);
	if (hp_status != NULL)
		kmem_free(hp_status, hpl);
#endif /* DEBUG */

	(void) ddi_taskq_dispatch(pdp->xd_hp_taskq,
	    i_xvdi_hpstate_handler, (void *)dip, DDI_SLEEP);
}

static void
i_xvdi_probe_path_handler(void *arg)
{
	dev_info_t *parent;
	char *path = arg, *p = NULL;
	int i, vdev, circ;
	i_xd_cfg_t *xdcp;
	boolean_t frontend;
	domid_t dom;

	for (i = 0, xdcp = &xdci[0]; i < NXDC; i++, xdcp++) {

		if ((xdcp->xs_path_fe != NULL) &&
		    (strncmp(path, xdcp->xs_path_fe, strlen(xdcp->xs_path_fe))
		    == 0)) {

			frontend = B_TRUE;
			p = path + strlen(xdcp->xs_path_fe);
			break;
		}

		if ((xdcp->xs_path_be != NULL) &&
		    (strncmp(path, xdcp->xs_path_be, strlen(xdcp->xs_path_be))
		    == 0)) {

			frontend = B_FALSE;
			p = path + strlen(xdcp->xs_path_be);
			break;
		}

	}

	if (p == NULL) {
		cmn_err(CE_WARN, "i_xvdi_probe_path_handler: "
		    "unexpected path prefix in %s", path);
		goto done;
	}

	if (frontend) {
		dom = DOMID_SELF;
		if (sscanf(p, "/%d/", &vdev) != 1) {
			XVDI_DPRINTF(XVDI_DBG_PROBE,
			    "i_xvdi_probe_path_handler: "
			    "cannot parse frontend path %s",
			    path);
			goto done;
		}
	} else {
		if (sscanf(p, "/%hu/%d/", &dom, &vdev) != 2) {
			XVDI_DPRINTF(XVDI_DBG_PROBE,
			    "i_xvdi_probe_path_handler: "
			    "cannot parse backend path %s",
			    path);
			goto done;
		}
	}

	/*
	 * This is an oxymoron, so indicates a bogus configuration we
	 * must check for.
	 */
	if (vdev == VDEV_NOXS) {
		cmn_err(CE_WARN, "i_xvdi_probe_path_handler: "
		    "invalid path %s", path);
		goto done;
	}

	parent = xendev_dip;
	ASSERT(parent != NULL);

	ndi_devi_enter(parent, &circ);

	if (xvdi_find_dev(parent, xdcp->devclass, dom, vdev) == NULL) {
		XVDI_DPRINTF(XVDI_DBG_PROBE,
		    "i_xvdi_probe_path_handler: create for %s", path);
		(void) xvdi_create_dev(parent, xdcp->devclass, dom, vdev);
	} else {
		XVDI_DPRINTF(XVDI_DBG_PROBE,
		    "i_xvdi_probe_path_handler: %s already exists", path);
	}

	ndi_devi_exit(parent, circ);

done:
	kmem_free(path, strlen(path) + 1);
}
