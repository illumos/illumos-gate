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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * The Ethernet Over Infiniband Nexus driver is a bus nexus driver
 * that enumerates all the EoIB nodes.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

#include <sys/ib/clients/eoib/enx_impl.h>

/*
 * Global per-instance EoIB Nexus data.  Only one instance
 * of EoIB Nexus is supported
 */
eibnx_t *enx_global_ss = NULL;

/*
 * Static function declarations
 */
static int eibnx_attach(dev_info_t *, ddi_attach_cmd_t);
static int eibnx_detach(dev_info_t *, ddi_detach_cmd_t);
static int eibnx_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int eibnx_bus_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
    void *, void *);

static int eibnx_get_eventcookie(dev_info_t *, dev_info_t *, char *,
    ddi_eventcookie_t *);
static int eibnx_add_eventcall(dev_info_t *, dev_info_t *, ddi_eventcookie_t,
    void (*)(dev_info_t *, ddi_eventcookie_t, void *, void *),
    void *, ddi_callback_id_t *);
static int eibnx_remove_eventcall(dev_info_t *, ddi_callback_id_t);
static int eibnx_post_event(dev_info_t *, dev_info_t *,
    ddi_eventcookie_t, void *);

static int eibnx_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t,
    void *, dev_info_t **);
static int eibnx_bus_unconfig(dev_info_t *, uint_t, ddi_bus_config_op_t,
    void *);
static int eibnx_config_all_children(dev_info_t *);
static void eibnx_unconfig_all_children(dev_info_t *);
static int eibnx_config_child(char *, dev_info_t **);
static int eibnx_unconfig_child(char *);

/*
 * Cbops
 */
static struct cb_ops enx_cb_ops = {
	eibnx_devctl_open,	/* cb_open */
	eibnx_devctl_close,	/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	eibnx_devctl_ioctl,	/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_str */
	D_MP,			/* cb_flag */
	CB_REV, 		/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

/*
 * Busops
 */
static struct bus_ops enx_bus_ops = {
	BUSO_REV,
	nullbusmap,		/* bus_map */
	NULL,			/* bus_get_intrspec */
	NULL,			/* bus_add_intrspec */
	NULL,			/* bus_remove_intrspec */
	i_ddi_map_fault,	/* bus_map_fault */
	ddi_no_dma_map,		/* bus_dma_map */
	NULL,			/* bus_dma_allochdl */
	NULL,			/* bus_dma_freehdl */
	NULL,			/* bus_dma_bindhdl */
	NULL,			/* bus_dma_unbindhdl */
	NULL,			/* bus_dma_flush */
	NULL,			/* bus_dma_win */
	NULL,			/* bus_dma_ctl */
	eibnx_bus_ctl,		/* bus_ctl */
	ddi_bus_prop_op,	/* bus_prop_op */
	eibnx_get_eventcookie,	/* bus_get_eventcookie */
	eibnx_add_eventcall,	/* bus_add_eventcall */
	eibnx_remove_eventcall,	/* bus_remove_eventcall */
	eibnx_post_event,	/* bus_post_event */
	NULL,			/* bus_intr_ctl */
	eibnx_bus_config,	/* bus_config */
	eibnx_bus_unconfig,	/* bus_unconfig */
};

/*
 * Nexus ops
 */
static struct dev_ops enx_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* devo_refcnt  */
	eibnx_getinfo,		/* devo_info */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	eibnx_attach,		/* devo_attach */
	eibnx_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&enx_cb_ops,		/* devo_cb_ops */
	&enx_bus_ops,		/* devo_bus_ops */
	nulldev,		/* devo_power */
	ddi_quiesce_not_needed	/* devo_quiesce */
};

/*
 * Module linkage information for the kernel
 */
static struct modldrv enx_modldrv = {
	&mod_driverops,		/* Driver module */
	"EoIB Nexus",		/* Driver name and version */
	&enx_ops,		/* Driver ops */
};

static struct modlinkage enx_modlinkage = {
	MODREV_1, (void *)&enx_modldrv, NULL
};

/*
 * EoIB NDI events
 */
static ndi_event_definition_t enx_ndi_event_defs[] = {
	{ ENX_EVENT_TAG_GW_INFO_UPDATE, EIB_NDI_EVENT_GW_INFO_UPDATE,
		EPL_KERNEL, NDI_EVENT_POST_TO_TGT },
	{ ENX_EVENT_TAG_GW_AVAILABLE, EIB_NDI_EVENT_GW_AVAILABLE,
		EPL_KERNEL, NDI_EVENT_POST_TO_TGT },
	{ ENX_EVENT_TAG_LOGIN_ACK, EIB_NDI_EVENT_LOGIN_ACK,
		EPL_KERNEL, NDI_EVENT_POST_TO_TGT }
};
#define	ENX_NUM_NDI_EVENTS		\
	(sizeof (enx_ndi_event_defs) / sizeof (enx_ndi_event_defs[0]))

static ndi_event_set_t enx_ndi_events = {
	NDI_EVENTS_REV1,
	ENX_NUM_NDI_EVENTS,
	enx_ndi_event_defs
};
ndi_event_hdl_t enx_ndi_event_hdl;


/*
 * Common loadable module entry points _init, _fini, _info
 */

int
_init(void)
{
	int ret;

	if ((ret = mod_install(&enx_modlinkage)) == 0)
		eibnx_debug_init();

	return (ret);
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&enx_modlinkage)) == 0)
		eibnx_debug_fini();

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&enx_modlinkage, modinfop));
}

/*
 * Autoconfiguration entry points: attach, detach, getinfo
 */

static int
eibnx_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	eibnx_t *ss;
	int instance;

	if (cmd == DDI_RESUME)
		return (DDI_SUCCESS);
	else if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * Don't allow more than one instance to attach
	 */
	if (enx_global_ss)
		return (DDI_FAILURE);

	/*
	 * Alloc this instance's softstate
	 */
	ss = kmem_zalloc(sizeof (eibnx_t), KM_SLEEP);
	ss->nx_dip = dip;

	enx_global_ss = ss;

	/*
	 * Allocate our NDI event handle and bind our event set
	 */
	if (ndi_event_alloc_hdl(dip, 0, &enx_ndi_event_hdl,
	    NDI_SLEEP) != NDI_SUCCESS) {
		ENX_DPRINTF_ERR("ndi_event_alloc_hdl(dip=0x%llx) "
		    "failed", dip);

		kmem_free(enx_global_ss, sizeof (eibnx_t));
		enx_global_ss = NULL;
		return (DDI_FAILURE);
	}
	if (ndi_event_bind_set(enx_ndi_event_hdl, &enx_ndi_events,
	    NDI_SLEEP) != NDI_SUCCESS) {
		ENX_DPRINTF_ERR("ndi_event_bind_set(ndi_event_hdl=0x%llx) "
		    "failed", enx_ndi_event_hdl);

		(void) ndi_event_free_hdl(enx_ndi_event_hdl);
		enx_ndi_event_hdl = NULL;
		kmem_free(enx_global_ss, sizeof (eibnx_t));
		enx_global_ss = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * Create "devctl" minor node for general ioctl interface to the
	 * eoib nexus. If we cannot, it isn't fatal - we'll operate without
	 * the support for devctl (but issue a warning).
	 */
	instance = ddi_get_instance(dip);
	if (ddi_create_minor_node(dip, "devctl", S_IFCHR, instance,
	    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
		ENX_DPRINTF_WARN("could not create devctl minor node "
		    "for instance %d", instance);
	}

	/*
	 * Do IBTF related initializations. If we fail, we cannot operate,
	 * so fail the attach.
	 */
	if (eibnx_ibt_init(ss) != ENX_E_SUCCESS) {
		(void) ddi_remove_minor_node(dip, NULL);
		(void) ndi_event_unbind_set(enx_ndi_event_hdl,
		    &enx_ndi_events, NDI_SLEEP);
		(void) ndi_event_free_hdl(enx_ndi_event_hdl);
		enx_ndi_event_hdl = NULL;
		kmem_free(enx_global_ss, sizeof (eibnx_t));
		enx_global_ss = NULL;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
eibnx_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	eibnx_t *ss = enx_global_ss;

	if (cmd == DDI_SUSPEND)
		return (DDI_SUCCESS);
	else if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	/*
	 * If there's no instance of eibnx attached, fail
	 */
	if (ss == NULL)
		return (DDI_FAILURE);

	/*
	 * Before we do anything, we need to stop the port monitors
	 * we may have started earlier.
	 */
	eibnx_terminate_monitors();

	/*
	 * If eibnx_ibt_fini() fails, it could be because one of the
	 * HCA's pd could not be freed, the hca could not be closed
	 * or the IBTF detach wasn't successful.  If this is the case,
	 * we have to return failure, but cannot do much about the
	 * port monitors we've already terminated.
	 */
	if (eibnx_ibt_fini(ss) == ENX_E_FAILURE)
		return (DDI_FAILURE);

	/*
	 * Cleanup any devctl minor node we may have created, unbind and
	 * free ndi event handle and free the instance softstate.
	 */
	(void) ddi_remove_minor_node(dip, NULL);
	(void) ndi_event_unbind_set(enx_ndi_event_hdl,
	    &enx_ndi_events, NDI_SLEEP);
	(void) ndi_event_free_hdl(enx_ndi_event_hdl);
	enx_ndi_event_hdl = NULL;
	kmem_free(enx_global_ss, sizeof (eibnx_t));
	enx_global_ss = NULL;

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
eibnx_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	eibnx_t *ss = enx_global_ss;
	int ret;

	if (cmd == DDI_INFO_DEVT2DEVINFO) {
		*resultp = (ss) ? ss->nx_dip : NULL;
		ret = (ss) ? DDI_SUCCESS : DDI_FAILURE;
	} else if (cmd == DDI_INFO_DEVT2INSTANCE) {
		*resultp = 0;
		ret = DDI_SUCCESS;
	} else {
		ret = DDI_FAILURE;
	}

	return (ret);
}

/*
 * Busops: bus_ctl, bus_config, bus_unconfig
 */

/*ARGSUSED*/
static int
eibnx_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	dev_info_t *child = arg;
	int ret;
	char name[MAXNAMELEN];

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		ENX_DPRINTF_DEBUG("EoIB device: %s@%s, %s%d",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		/*FALLTHROUGH*/

	case DDI_CTLOPS_ATTACH:
	case DDI_CTLOPS_DETACH:
	case DDI_CTLOPS_POWER:
	case DDI_CTLOPS_SIDDEV:
	case DDI_CTLOPS_IOMIN:
		ret = DDI_SUCCESS;
		break;

	case DDI_CTLOPS_INITCHILD:
		if ((ret = eibnx_name_child(child, name,
		    sizeof (name))) == DDI_SUCCESS) {
			ddi_set_name_addr(child, name);
		}
		break;

	case DDI_CTLOPS_UNINITCHILD:
		ddi_set_name_addr(child, NULL);
		ret = DDI_SUCCESS;
		break;

	default:
		ret = ddi_ctlops(dip, rdip, ctlop, arg, result);
		break;
	}

	return (ret);
}

/*ARGSUSED*/
static int
eibnx_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	eibnx_t *ss = enx_global_ss;
	int ret = NDI_SUCCESS;

	switch (op) {
	case BUS_CONFIG_ONE:
		eibnx_busop_inprog_enter(ss);
		ret = eibnx_config_child(arg, childp);
		eibnx_busop_inprog_exit(ss);
		break;

	case BUS_CONFIG_ALL:
	case BUS_CONFIG_DRIVER:
		eibnx_busop_inprog_enter(ss);
		if ((ss->nx_busop_flags & NX_FL_BUSCFG_COMPLETE) == 0) {
			ret = eibnx_config_all_children(parent);
			if (ret == NDI_SUCCESS)
				ss->nx_busop_flags |= NX_FL_BUSCFG_COMPLETE;
		}
		eibnx_busop_inprog_exit(ss);
		break;

	default:
		ret = NDI_FAILURE;
	}

	if (ret == NDI_SUCCESS)
		ret = ndi_busop_bus_config(parent, flags, op, arg, childp, 0);

	return (ret);
}

static int
eibnx_bus_unconfig(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	eibnx_t *ss = enx_global_ss;
	int ret;

	ret = ndi_busop_bus_unconfig(parent, flags, op, arg);
	if (ret != NDI_SUCCESS)
		return (ret);

	switch (op) {
	case BUS_UNCONFIG_ONE:
		if (flags & (NDI_UNCONFIG | NDI_DEVI_REMOVE)) {
			eibnx_busop_inprog_enter(ss);

			if ((ret = eibnx_unconfig_child(arg)) == ENX_E_SUCCESS)
				ss->nx_busop_flags &= (~NX_FL_BUSCFG_COMPLETE);
			else {
				ENX_DPRINTF_DEBUG("eibnx_bus_config: "
				    "unconfig child %s failed", (char *)arg);
			}

			eibnx_busop_inprog_exit(ss);
		}
		break;

	case BUS_UNCONFIG_ALL:
	case BUS_UNCONFIG_DRIVER:
		if (flags & (NDI_UNCONFIG | NDI_DEVI_REMOVE)) {
			eibnx_busop_inprog_enter(ss);

			eibnx_unconfig_all_children(parent);
			ss->nx_busop_flags &= (~NX_FL_BUSCFG_COMPLETE);

			eibnx_busop_inprog_exit(ss);
		}
		break;

	default:
		break;
	}

	return (ret);
}

/*
 * Event Handling: bus_get_eventcookie, bus_add_eventcall, bus_remove_eventcall
 * and bus_post_event
 */

/*ARGSUSED*/
static int
eibnx_get_eventcookie(dev_info_t *dip, dev_info_t *rdip,
    char *name, ddi_eventcookie_t *cookiep)
{
	return (ndi_event_retrieve_cookie(enx_ndi_event_hdl, rdip, name,
	    cookiep, NDI_EVENT_NOPASS));
}

/*ARGSUSED*/
static int
eibnx_add_eventcall(dev_info_t *dip, dev_info_t *rdip, ddi_eventcookie_t cookie,
    void (*callback)(dev_info_t *cb_dip, ddi_eventcookie_t cb_cookie,
    void *cb_arg, void *cb_impl_data),
    void *arg, ddi_callback_id_t *cb_id)
{
	return (ndi_event_add_callback(enx_ndi_event_hdl, rdip, cookie,
	    callback, arg, NDI_SLEEP, cb_id));
}

/*ARGSUSED*/
static int
eibnx_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{
	return (ndi_event_remove_callback(enx_ndi_event_hdl, cb_id));
}

/*ARGSUSED*/
static int
eibnx_post_event(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t cookie, void *impl_data)
{
	return (ndi_event_run_callbacks(enx_ndi_event_hdl, rdip, cookie,
	    impl_data));
}

/*
 * Routines to configure/unconfigure EoIB node(s) on a system.
 */

/*ARGSUSED*/
static int
eibnx_config_all_children(dev_info_t *parent)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_hca_t *hca;
	eibnx_port_t *port;
	eibnx_thr_info_t *ti;
	eibnx_thr_info_t *ti_tail;
	eibnx_gw_info_t *gwi;

	/*
	 * Go through each port of each hca and create a thread to solicit,
	 * monitor, receive advertisements, create eoib nodes and attach eoib
	 * driver instances.
	 */
	mutex_enter(&ss->nx_lock);
	if (!ss->nx_monitors_up) {
		ss->nx_thr_info = ti_tail = NULL;
		for (hca = ss->nx_hca; hca; hca = hca->hc_next) {
			for (port = hca->hc_port; port; port = port->po_next) {
				ti = eibnx_start_port_monitor(hca, port);
				if (ti_tail) {
					ti_tail->ti_next = ti;
				} else {
					ss->nx_thr_info = ti;
				}
				ti_tail = ti;
			}
		}

		ss->nx_monitors_up = B_TRUE;
		mutex_exit(&ss->nx_lock);

		return (NDI_SUCCESS);
	}
	mutex_exit(&ss->nx_lock);

	while (eibnx_locate_unconfigured_node(&ti, &gwi) == ENX_E_SUCCESS)
		(void) eibnx_configure_node(ti, gwi, NULL);

	return (NDI_SUCCESS);
}

/*
 * Routine to unconfigure all the EoIB nodes on a system. This terminates
 * all the per-port monitor threads and releases any resources allocated.
 */

/*ARGSUSED*/
static void
eibnx_unconfig_all_children(dev_info_t *parent)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_thr_info_t *ti;
	eibnx_child_t *ch;

	mutex_enter(&ss->nx_lock);
	for (ti = ss->nx_thr_info; ti; ti = ti->ti_next) {
		mutex_enter(&ti->ti_child_lock);
		for (ch = ti->ti_child; ch; ch = ch->ch_next) {
			ch->ch_dip = NULL;
		}
		mutex_exit(&ti->ti_child_lock);
	}
	mutex_exit(&ss->nx_lock);
}

/*ARGSUSED*/
static int
eibnx_config_child(char *devname, dev_info_t **childp)
{
	eibnx_thr_info_t *ti;
	eibnx_gw_info_t *gwi;

	if (eibnx_locate_node_name(devname, &ti, &gwi) == ENX_E_FAILURE) {
		ENX_DPRINTF_DEBUG("eibnx_config_child: invalid eoib "
		    "nodename %s, no such address", devname);
		return (ENX_E_FAILURE);
	}

	return (eibnx_configure_node(ti, gwi, childp));
}

/*ARGSUSED*/
static int
eibnx_unconfig_child(char *devname)
{
	eibnx_thr_info_t *ti;
	eibnx_gw_info_t *gwi;

	if (eibnx_locate_node_name(devname, &ti, &gwi) == ENX_E_FAILURE) {
		ENX_DPRINTF_DEBUG("eibnx_unconfig_child: invalid eoib "
		    "nodename %s, no such address", devname);
		return (ENX_E_FAILURE);
	}

	return (eibnx_unconfigure_node(ti, gwi));
}
