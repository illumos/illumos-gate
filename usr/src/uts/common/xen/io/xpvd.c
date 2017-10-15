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
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.
 */

/*
 *	Host to hypervisor virtual devices nexus driver
 *
 * TODO:
 * - Add watchpoints on vbd/vif and enumerate/offline on watch callback
 * - Add DR IOCTLs
 * - Filter/restrict property lookups into xenstore
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/avintr.h>
#include <sys/psm.h>
#include <sys/spl.h>
#include <sys/promif.h>
#include <sys/list.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#include <util/sscanf.h>
#include <sys/mach_intr.h>
#include <sys/bootinfo.h>
#ifdef XPV_HVM_DRIVER
#include <sys/xpv_support.h>
#include <sys/hypervisor.h>
#include <sys/archsystm.h>
#include <sys/cpu.h>
#include <public/xen.h>
#include <public/event_channel.h>
#include <public/io/xenbus.h>
#else
#include <sys/hypervisor.h>
#include <sys/evtchn_impl.h>
#include <sys/xen_mmu.h>
#endif
#include <xen/sys/xenbus_impl.h>
#include <xen/sys/xendev.h>

/*
 * DDI dev_ops entrypoints
 */
static int xpvd_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int xpvd_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int xpvd_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);


/*
 * NDI bus_ops entrypoints
 */
static int xpvd_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
	void *);
static int xpvd_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
	ddi_intr_handle_impl_t *, void *);
static int xpvd_prop_op(dev_t, dev_info_t *, dev_info_t *, ddi_prop_op_t,
	int, char *, caddr_t, int *);
static int xpvd_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t,
	void *, dev_info_t **);
static int xpvd_bus_unconfig(dev_info_t *, uint_t, ddi_bus_config_op_t,
    void *);
static int xpvd_get_eventcookie(dev_info_t *, dev_info_t *,
    char *, ddi_eventcookie_t *);
static int xpvd_add_eventcall(dev_info_t *, dev_info_t *,
    ddi_eventcookie_t, void (*)(dev_info_t *,
    ddi_eventcookie_t, void *, void *),
    void *, ddi_callback_id_t *);
static int xpvd_remove_eventcall(dev_info_t *, ddi_callback_id_t);
static int xpvd_post_event(dev_info_t *, dev_info_t *,
    ddi_eventcookie_t, void *);

/*
 * misc functions
 */
static int xpvd_enable_intr(dev_info_t *, ddi_intr_handle_impl_t *, int);
static void xpvd_disable_intr(dev_info_t *, ddi_intr_handle_impl_t *, int);
static int xpvd_removechild(dev_info_t *);
static int xpvd_initchild(dev_info_t *);
static int xpvd_name_child(dev_info_t *, char *, int);
static boolean_t i_xpvd_parse_devname(char *, xendev_devclass_t *,
    domid_t *, int *);


/* Extern declarations */
extern int (*psm_intr_ops)(dev_info_t *, ddi_intr_handle_impl_t *,
    psm_intr_op_t, int *);

struct bus_ops xpvd_bus_ops = {
	BUSO_REV,
	i_ddi_bus_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	NULL,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	xpvd_ctlops,
	xpvd_prop_op,
	xpvd_get_eventcookie,
	xpvd_add_eventcall,
	xpvd_remove_eventcall,
	xpvd_post_event,
	0,		/* (*bus_intr_ctl)(); */
	xpvd_bus_config,
	xpvd_bus_unconfig,
	NULL,		/* (*bus_fm_init)(); */
	NULL,		/* (*bus_fm_fini)(); */
	NULL,		/* (*bus_fm_access_enter)(); */
	NULL,		/* (*bus_fm_access_exit)(); */
	NULL,		/* (*bus_power)(); */
	xpvd_intr_ops	/* (*bus_intr_op)(); */
};

struct dev_ops xpvd_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	xpvd_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	xpvd_attach,		/* attach */
	xpvd_detach,		/* detach */
	nulldev,		/* reset */
	(struct cb_ops *)0,	/* driver operations */
	&xpvd_bus_ops,		/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};


dev_info_t *xpvd_dip;

#define	CF_DBG		0x1
#define	ALL_DBG		0xff

static ndi_event_definition_t xpvd_ndi_event_defs[] = {
	{ 0, XS_OE_STATE, EPL_KERNEL, NDI_EVENT_POST_TO_TGT },
	{ 1, XS_HP_STATE, EPL_KERNEL, NDI_EVENT_POST_TO_TGT },
};

#define	XENDEV_N_NDI_EVENTS \
	(sizeof (xpvd_ndi_event_defs) / sizeof (xpvd_ndi_event_defs[0]))

static ndi_event_set_t xpvd_ndi_events = {
	NDI_EVENTS_REV1, XENDEV_N_NDI_EVENTS, xpvd_ndi_event_defs
};

static ndi_event_hdl_t xpvd_ndi_event_handle;

/*
 * Hypervisor interrupt capabilities
 */
#define	XENDEV_INTR_CAPABILITIES \
	(DDI_INTR_FLAG_EDGE | DDI_INTR_FLAG_MASKABLE | DDI_INTR_FLAG_PENDING)

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"virtual device nexus driver",
	&xpvd_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
xpvd_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)xpvd_dip;
		return (DDI_SUCCESS);
	}
}

/*ARGSUSED*/
static int
xpvd_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	extern void xvdi_watch_devices(int);
#ifdef XPV_HVM_DRIVER
	extern dev_info_t *xpv_dip;

	if (xpv_dip == NULL) {
		if (ddi_hold_installed_driver(ddi_name_to_major("xpv")) ==
		    NULL) {
			cmn_err(CE_WARN, "Couldn't initialize xpv framework");
			return (DDI_FAILURE);
		}
	}
#endif /* XPV_HVM_DRIVER */

	if (ndi_event_alloc_hdl(devi, 0, &xpvd_ndi_event_handle,
	    NDI_SLEEP) != NDI_SUCCESS) {
		xpvd_dip = NULL;
		return (DDI_FAILURE);
	}
	if (ndi_event_bind_set(xpvd_ndi_event_handle, &xpvd_ndi_events,
	    NDI_SLEEP) != NDI_SUCCESS) {
		(void) ndi_event_free_hdl(xpvd_ndi_event_handle);
		xpvd_dip = NULL;
		return (DDI_FAILURE);
	}
	if (ddi_create_minor_node(devi, "devctl", S_IFCHR,
	    ddi_get_instance(devi), DDI_PSEUDO, 0) != DDI_SUCCESS) {
		(void) ndi_event_unbind_set(xpvd_ndi_event_handle,
		    &xpvd_ndi_events, NDI_SLEEP);
		(void) ndi_event_free_hdl(xpvd_ndi_event_handle);
		xpvd_dip = NULL;
		return (DDI_FAILURE);
	}

#ifdef XPV_HVM_DRIVER
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, devi, DDI_NO_AUTODETACH, 1);

	/*
	 * Report our version to dom0.
	 */
	if (xenbus_printf(XBT_NULL, "guest/xpvd", "version", "%d",
	    HVMPV_XPVD_VERS))
		cmn_err(CE_WARN, "xpvd: couldn't write version\n");
#endif /* XPV_HVM_DRIVER */

	/* watch both frontend and backend for new devices */
	if (DOMAIN_IS_INITDOMAIN(xen_info))
		(void) xs_register_xenbus_callback(xvdi_watch_devices);
	else
		xvdi_watch_devices(XENSTORE_UP);

	xpvd_dip = devi;
	ddi_report_dev(devi);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
xpvd_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	return (DDI_FAILURE);
}

/*
 * xpvd_prop_op()
 *
 * Query xenstore for the value of properties if DDI_PROP_NOTPROM
 * is not set.  Xenstore property values are represented as ascii strings.
 */
static int
xpvd_prop_op(dev_t dev, dev_info_t *dip, dev_info_t *ch_dip,
    ddi_prop_op_t prop_op, int mod_flags, char *name, caddr_t valuep,
    int *lengthp)
{
	caddr_t buff;
	struct xendev_ppd *pdp;
	void *prop_str;
	size_t prop_len;
	unsigned int len;
	int rv;

	pdp = (struct xendev_ppd *)ddi_get_parent_data(ch_dip);

	if ((pdp == NULL) || !(mod_flags & (DDI_PROP_CANSLEEP)) ||
	    (mod_flags & DDI_PROP_NOTPROM) || (pdp->xd_xsdev.nodename == NULL))
		goto toss_off;
	/*
	 * First try reading the property off the the frontend. if that
	 * fails, try and read it from the backend node.  If that
	 * also fails, pass the request on the DDI framework
	 */
	prop_str = NULL;
	if ((xenbus_read(XBT_NULL, pdp->xd_xsdev.nodename, name, &prop_str,
	    &len) == 0) && (prop_str != NULL) && (strlen(prop_str) != 0))
		goto got_xs_prop;

	prop_str = NULL;
	if ((pdp->xd_xsdev.otherend != NULL) &&
	    (xenbus_read(XBT_NULL, pdp->xd_xsdev.otherend, name, &prop_str,
	    &len) == 0) && (prop_str != NULL) && (strlen(prop_str) != 0))
		goto got_xs_prop;

toss_off:
	return (ddi_bus_prop_op(dev, dip, ch_dip, prop_op,
	    mod_flags | DDI_PROP_NOTPROM, name, valuep, lengthp));

got_xs_prop:
	prop_len = strlen(prop_str) + 1;
	rv = DDI_PROP_SUCCESS;

	switch (prop_op) {
	case PROP_LEN:
		*lengthp = prop_len;
		break;

	case PROP_LEN_AND_VAL_ALLOC:
		buff = kmem_alloc((size_t)prop_len, KM_SLEEP);
		*(caddr_t *)valuep = (caddr_t)buff;
		break;
	case PROP_LEN_AND_VAL_BUF:
		buff = (caddr_t)valuep;
		if (*lengthp < prop_len)
			rv = DDI_PROP_BUF_TOO_SMALL;
		break;
	default:
		rv = DDI_PROP_INVAL_ARG;
		break;
	}

	if ((rv == DDI_PROP_SUCCESS) && (prop_len > 0)) {
		bcopy(prop_str, buff, prop_len);
		*lengthp = prop_len;
	}
	kmem_free(prop_str, len);
	return (rv);
}


/*
 * return address of the device's interrupt spec structure.
 */
/*ARGSUSED*/
struct intrspec *
xpvd_get_ispec(dev_info_t *rdip, uint_t inumber)
{
	struct xendev_ppd *pdp;

	ASSERT(inumber == 0);

	if ((pdp = ddi_get_parent_data(rdip)) == NULL)
		return (NULL);

	return (&pdp->xd_ispec);
}

/*
 * return (and determine) the interrupt priority of the device.
 */
/*ARGSUSED*/
static int
xpvd_get_priority(dev_info_t *dip, int inum, int *pri)
{
	struct xendev_ppd *pdp;
	struct intrspec *ispec;
	int	*intpriorities;
	uint_t	num_intpriorities;

	DDI_INTR_NEXDBG((CE_CONT, "xpvd_get_priority: dip = 0x%p\n",
	    (void *)dip));

	ASSERT(inum == 0);

	if ((pdp = ddi_get_parent_data(dip)) == NULL)
		return (DDI_FAILURE);

	ispec = &pdp->xd_ispec;

	/*
	 * Set the default priority based on the device class.  The
	 * "interrupt-priorities" property can be used to override
	 * the default.
	 */
	if (ispec->intrspec_pri == 0) {
		ispec->intrspec_pri = xendev_devclass_ipl(pdp->xd_devclass);
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
		    "interrupt-priorities", &intpriorities,
		    &num_intpriorities) == DDI_PROP_SUCCESS) {
			ispec->intrspec_pri = intpriorities[0];
			ddi_prop_free(intpriorities);
		}
	}
	*pri = ispec->intrspec_pri;
	return (DDI_SUCCESS);
}


/*
 * xpvd_intr_ops: bus_intr_op() function for interrupt support
 */
/* ARGSUSED */
static int
xpvd_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int priority = 0;
	struct intrspec *ispec;
	struct xendev_ppd *pdp;

	DDI_INTR_NEXDBG((CE_CONT,
	    "xpvd_intr_ops: pdip 0x%p, rdip 0x%p, op %x handle 0x%p\n",
	    (void *)pdip, (void *)rdip, intr_op, (void *)hdlp));

	/* Process the request */
	switch (intr_op) {
	case DDI_INTROP_SUPPORTED_TYPES:
		/* Fixed supported by default */
		*(int *)result = DDI_INTR_TYPE_FIXED;
		break;

	case DDI_INTROP_NINTRS:
		*(int *)result = 1;
		break;

	case DDI_INTROP_ALLOC:
		/*
		 * FIXED interrupts: just return available interrupts
		 */
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
			/*
			 * event channels are edge-triggered, maskable,
			 * and support int pending.
			 */
			hdlp->ih_cap |= XENDEV_INTR_CAPABILITIES;
			*(int *)result = 1;	/* DDI_INTR_TYPE_FIXED */
		} else {
			return (DDI_FAILURE);
		}
		break;

	case DDI_INTROP_FREE:
		ispec = xpvd_get_ispec(rdip, (int)hdlp->ih_inum);
		if (ispec == NULL)
			return (DDI_FAILURE);
		ispec->intrspec_pri = 0; /* mark as un-initialized */
		break;

	case DDI_INTROP_GETPRI:
		if (xpvd_get_priority(rdip, hdlp->ih_inum, &priority) !=
		    DDI_SUCCESS)
			return (DDI_FAILURE);
		DDI_INTR_NEXDBG((CE_CONT, "xpvd_intr_ops: priority = 0x%x\n",
		    priority));
		*(int *)result = priority;
		break;

	case DDI_INTROP_SETPRI:
		/* Validate the interrupt priority passed */
		if (*(int *)result > LOCK_LEVEL)
			return (DDI_FAILURE);

		/* Ensure that PSM is all initialized */
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		/* Change the priority */
		if ((*psm_intr_ops)(rdip, hdlp, PSM_INTR_OP_SET_PRI, result) ==
		    PSM_FAILURE)
			return (DDI_FAILURE);

		ispec = xpvd_get_ispec(rdip, (int)hdlp->ih_inum);
		if (ispec == NULL)
			return (DDI_FAILURE);
		ispec->intrspec_pri = *(int *)result;
		break;

	case DDI_INTROP_ADDISR:
		/* update ispec */
		ispec = xpvd_get_ispec(rdip, (int)hdlp->ih_inum);
		if (ispec == NULL)
			return (DDI_FAILURE);
		ispec->intrspec_func = hdlp->ih_cb_func;

		break;

	case DDI_INTROP_REMISR:
		ispec = xpvd_get_ispec(rdip, (int)hdlp->ih_inum);
		pdp = (struct xendev_ppd *)ddi_get_parent_data(rdip);

		ASSERT(pdp != NULL);
		ASSERT(pdp->xd_evtchn != INVALID_EVTCHN);

		if (ispec) {
			ispec->intrspec_vec = 0;
			ispec->intrspec_func = (uint_t (*)()) 0;
		}
		pdp->xd_evtchn = INVALID_EVTCHN;
		break;

	case DDI_INTROP_GETCAP:
		if (hdlp->ih_type ==  DDI_INTR_TYPE_FIXED) {
			/*
			 * event channels are edge-triggered, maskable,
			 * and support int pending.
			 */
			*(int *)result = XENDEV_INTR_CAPABILITIES;
		} else {
			*(int *)result = 0;
			return (DDI_FAILURE);
		}
		DDI_INTR_NEXDBG((CE_CONT, "xpvd: GETCAP returned = %x\n",
		    *(int *)result));
		break;
	case DDI_INTROP_SETCAP:
		DDI_INTR_NEXDBG((CE_CONT, "xpvd_intr_ops: SETCAP cap=0x%x\n",
		    *(int *)result));
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		if ((*psm_intr_ops)(rdip, hdlp, PSM_INTR_OP_SET_CAP, result)) {
			DDI_INTR_NEXDBG((CE_CONT, "GETCAP: psm_intr_ops"
			    " returned failure\n"));
			return (DDI_FAILURE);
		}
		break;

	case DDI_INTROP_ENABLE:
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		if (xpvd_enable_intr(rdip, hdlp, (int)hdlp->ih_inum) !=
		    DDI_SUCCESS)
			return (DDI_FAILURE);

		DDI_INTR_NEXDBG((CE_CONT, "xpvd_intr_ops: ENABLE vec=0x%x\n",
		    hdlp->ih_vector));
		break;

	case DDI_INTROP_DISABLE:
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);
		xpvd_disable_intr(rdip, hdlp, hdlp->ih_inum);
		DDI_INTR_NEXDBG((CE_CONT, "xpvd_intr_ops: DISABLE vec = %x\n",
		    hdlp->ih_vector));
		break;

	case DDI_INTROP_BLOCKENABLE:
	case DDI_INTROP_BLOCKDISABLE:
		return (DDI_FAILURE);

	case DDI_INTROP_SETMASK:
	case DDI_INTROP_CLRMASK:
#ifdef XPV_HVM_DRIVER
		return (DDI_ENOTSUP);
#else
		/*
		 * Handle this here
		 */
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (DDI_FAILURE);
		if (intr_op == DDI_INTROP_SETMASK) {
			ec_disable_irq(hdlp->ih_vector);
		} else {
			ec_enable_irq(hdlp->ih_vector);
		}
		break;
#endif
	case DDI_INTROP_GETPENDING:
#ifdef XPV_HVM_DRIVER
		return (DDI_ENOTSUP);
#else
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (DDI_FAILURE);
		*(int *)result = ec_pending_irq(hdlp->ih_vector);
		DDI_INTR_NEXDBG((CE_CONT, "xpvd: GETPENDING returned = %x\n",
		    *(int *)result));
		break;
#endif

	case DDI_INTROP_NAVAIL:
		*(int *)result = 1;
		DDI_INTR_NEXDBG((CE_CONT, "xpvd: NAVAIL returned = %x\n",
		    *(int *)result));
		break;

	default:
		return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
	}

	return (DDI_SUCCESS);
}


static int
xpvd_enable_intr(dev_info_t *rdip, ddi_intr_handle_impl_t *hdlp, int inum)
{
	int		vector;
	ihdl_plat_t	*ihdl_plat_datap = (ihdl_plat_t *)hdlp->ih_private;

	DDI_INTR_NEXDBG((CE_CONT, "xpvd_enable_intr: hdlp %p inum %x\n",
	    (void *)hdlp, inum));

	ihdl_plat_datap->ip_ispecp = xpvd_get_ispec(rdip, inum);
	if (ihdl_plat_datap->ip_ispecp == NULL)
		return (DDI_FAILURE);

	/* translate the interrupt if needed */
	(void) (*psm_intr_ops)(rdip, hdlp, PSM_INTR_OP_XLATE_VECTOR, &vector);
	DDI_INTR_NEXDBG((CE_CONT, "xpvd_enable_intr: priority=%x vector=%x\n",
	    hdlp->ih_pri, vector));

	/* Add the interrupt handler */
	if (!add_avintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func,
	    DEVI(rdip)->devi_name, vector, hdlp->ih_cb_arg1,
	    hdlp->ih_cb_arg2, NULL, rdip))
		return (DDI_FAILURE);

	/* Note this really is an irq. */
	hdlp->ih_vector = (ushort_t)vector;

	return (DDI_SUCCESS);
}


static void
xpvd_disable_intr(dev_info_t *rdip, ddi_intr_handle_impl_t *hdlp, int inum)
{
	int		vector;
	ihdl_plat_t	*ihdl_plat_datap = (ihdl_plat_t *)hdlp->ih_private;

	DDI_INTR_NEXDBG((CE_CONT, "xpvd_disable_intr: \n"));
	ihdl_plat_datap->ip_ispecp = xpvd_get_ispec(rdip, inum);
	if (ihdl_plat_datap->ip_ispecp == NULL)
		return;

	/* translate the interrupt if needed */
	(void) (*psm_intr_ops)(rdip, hdlp, PSM_INTR_OP_XLATE_VECTOR, &vector);

	/* Disable the interrupt handler */
	rem_avintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func, vector);
	ihdl_plat_datap->ip_ispecp = NULL;
}

/*ARGSUSED*/
static int
xpvd_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?%s@%s, %s%d\n", ddi_node_name(rdip),
		    ddi_get_name_addr(rdip), ddi_driver_name(rdip),
		    ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (xpvd_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		return (xpvd_removechild((dev_info_t *)arg));

	case DDI_CTLOPS_SIDDEV:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		return (DDI_FAILURE);

	case DDI_CTLOPS_POWER: {
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	/* NOTREACHED */

}

/*
 * Assign the address portion of the node name
 */
static int
xpvd_name_child(dev_info_t *child, char *addr, int addrlen)
{
	int *domain, *vdev;
	uint_t ndomain, nvdev;
	char *prop_str;

	/*
	 * i_xpvd_parse_devname() knows the formats used by this
	 * routine.  If this code changes, so must that.
	 */

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "domain", &domain, &ndomain) != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);
	ASSERT(ndomain == 1);

	/*
	 * Use "domain" and "vdev" properties (backend drivers).
	 */
	if (*domain != DOMID_SELF) {
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "vdev", &vdev, &nvdev)
		    != DDI_PROP_SUCCESS) {
			ddi_prop_free(domain);
			return (DDI_FAILURE);
		}
		ASSERT(nvdev == 1);

		(void) snprintf(addr, addrlen, "%d,%d", domain[0], vdev[0]);
		ddi_prop_free(vdev);
		ddi_prop_free(domain);
		return (DDI_SUCCESS);
	}
	ddi_prop_free(domain);

	/*
	 * Use "unit-address" property (frontend/softdev drivers).
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "unit-address", &prop_str) != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);
	(void) strlcpy(addr, prop_str, addrlen);
	ddi_prop_free(prop_str);
	return (DDI_SUCCESS);
}

static int
xpvd_initchild(dev_info_t *child)
{
	char addr[80];

	/*
	 * Pseudo nodes indicate a prototype node with per-instance
	 * properties to be merged into the real h/w device node.
	 */
	if (ndi_dev_is_persistent_node(child) == 0) {
		ddi_set_parent_data(child, NULL);

		/*
		 * Try to merge the properties from this prototype
		 * node into real h/w nodes.
		 */
		if (ndi_merge_node(child, xpvd_name_child) == DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			ddi_set_name_addr(child, NULL);
			return (DDI_FAILURE);
		}

		/*
		 * The child was not merged into a h/w node,
		 * but there's not much we can do with it other
		 * than return failure to cause the node to be removed.
		 */
		cmn_err(CE_WARN, "!%s@%s: %s.conf properties not merged",
		    ddi_get_name(child), ddi_get_name_addr(child),
		    ddi_get_name(child));
		ddi_set_name_addr(child, NULL);
		return (DDI_NOT_WELL_FORMED);
	}

	if (xvdi_init_dev(child) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (xpvd_name_child(child, addr, sizeof (addr)) != DDI_SUCCESS) {
		xvdi_uninit_dev(child);
		return (DDI_FAILURE);
	}
	ddi_set_name_addr(child, addr);

	return (DDI_SUCCESS);
}

static int
xpvd_removechild(dev_info_t *dip)
{
	xvdi_uninit_dev(dip);

	ddi_set_name_addr(dip, NULL);

	/*
	 * Strip the node to properly convert it back to prototype
	 * form.
	 */
	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

static int
xpvd_bus_unconfig(dev_info_t *parent, uint_t flag, ddi_bus_config_op_t op,
    void *device_name)
{
	return (ndi_busop_bus_unconfig(parent, flag, op, device_name));
}

/*
 * Given the name of a child of xpvd, determine the device class,
 * domain and vdevnum to which it refers.
 */
static boolean_t
i_xpvd_parse_devname(char *name, xendev_devclass_t *devclassp,
    domid_t *domp, int *vdevp)
{
	int len = strlen(name) + 1;
	char *device_name = i_ddi_strdup(name, KM_SLEEP);
	char *cname = NULL, *caddr = NULL;
	boolean_t ret;

	i_ddi_parse_name(device_name, &cname, &caddr, NULL);

	if ((cname == NULL) || (strlen(cname) == 0) ||
	    (caddr == NULL) || (strlen(caddr) == 0)) {
		ret = B_FALSE;
		goto done;
	}

	*devclassp = xendev_nodename_to_devclass(cname);
	if (*devclassp < 0) {
		ret = B_FALSE;
		goto done;
	}

	/*
	 * Parsing the address component requires knowledge of how
	 * xpvd_name_child() works.  If that code changes, so must
	 * this.
	 */

	/* Backend format is "<domain>,<vdev>". */
	if (sscanf(caddr, "%hu,%d", domp, vdevp) == 2) {
		ret = B_TRUE;
		goto done;
	}

	/* Frontend format is "<vdev>". */
	*domp = DOMID_SELF;
	if (sscanf(caddr, "%d", vdevp) == 1)
		ret = B_TRUE;
done:
	kmem_free(device_name, len);
	return (ret);
}

/*
 * xpvd_bus_config()
 *
 * BUS_CONFIG_ONE:
 *	Enumerate the exact instance of a driver.
 *
 * BUS_CONFIG_ALL:
 *	Enumerate all the instances of all the possible children (seen before
 *	and never seen before).
 *
 * BUS_CONFIG_DRIVER:
 *	Enumerate all the instances of a particular driver.
 */
static int
xpvd_bus_config(dev_info_t *parent, uint_t flag, ddi_bus_config_op_t op,
	void *arg, dev_info_t **childp)
{
	int circ;
	char *cname = NULL;

	ndi_devi_enter(parent, &circ);

	switch (op) {
	case BUS_CONFIG_ONE: {
		xendev_devclass_t devclass;
		domid_t dom;
		int vdev;

		if (!i_xpvd_parse_devname(arg, &devclass, &dom, &vdev)) {
			ndi_devi_exit(parent, circ);
			return (NDI_FAILURE);
		}

		*childp = xvdi_find_dev(parent, devclass, dom, vdev);
		if (*childp == NULL)
			*childp = xvdi_create_dev(parent, devclass, dom, vdev);

		ndi_devi_exit(parent, circ);

		if (*childp == NULL)
			return (NDI_FAILURE);
		else
			return (ndi_busop_bus_config(parent, flag,
			    op, arg, childp, 0));
	}

	case BUS_CONFIG_DRIVER: {
		xendev_devclass_t devclass = XEN_INVAL;

		cname = ddi_major_to_name((major_t)(uintptr_t)arg);
		if (cname != NULL)
			devclass = xendev_nodename_to_devclass(cname);

		if (devclass == XEN_INVAL) {
			ndi_devi_exit(parent, circ);
			return (NDI_FAILURE);
		} else {
			xendev_enum_class(parent, devclass);
			ndi_devi_exit(parent, circ);
			return (ndi_busop_bus_config(parent, flag, op,
			    arg, childp, 0));
		}
		/* NOTREACHED */
	}

	case BUS_CONFIG_ALL:
		xendev_enum_all(parent, B_FALSE);
		ndi_devi_exit(parent, circ);

		return (ndi_busop_bus_config(parent, flag, op,
		    arg, childp, 0));

	default:
		ndi_devi_exit(parent, circ);
		return (NDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
xpvd_get_eventcookie(dev_info_t *dip, dev_info_t *rdip,
    char *eventname, ddi_eventcookie_t *cookie)
{
	return (ndi_event_retrieve_cookie(xpvd_ndi_event_handle,
	    rdip, eventname, cookie, NDI_EVENT_NOPASS));
}

/*ARGSUSED*/
static int
xpvd_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t cookie, void (*callback)(dev_info_t *dip,
    ddi_eventcookie_t cookie, void *arg, void *bus_impldata),
    void *arg, ddi_callback_id_t *cb_id)
{
	return (ndi_event_add_callback(xpvd_ndi_event_handle,
	    rdip, cookie, callback, arg, NDI_SLEEP, cb_id));
}

/*ARGSUSED*/
static int
xpvd_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{
	return (ndi_event_remove_callback(xpvd_ndi_event_handle,
	    cb_id));
}

/*ARGSUSED*/
static int
xpvd_post_event(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t cookie, void *bus_impldata)
{
	return (ndi_event_run_callbacks(xpvd_ndi_event_handle, rdip,
	    cookie, bus_impldata));
}
