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
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

/*
 * nx1394.c
 *    1394 Services Layer Nexus Support Routines
 *    Routines in this file implement nexus bus_ops.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/types.h>
#include <sys/ddi_impldefs.h>
#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>

static int nx1394_dma_allochdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_attr_t *attr, int (*waitfnp)(caddr_t), caddr_t arg,
    ddi_dma_handle_t *handlep);

static int nx1394_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op,
    void *arg, void *result);

static int nx1394_get_event_cookie(dev_info_t *dip, dev_info_t *rdip,
    char *name, ddi_eventcookie_t *event_cookiep);

static int nx1394_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventhdl, void (*callback)(), void *arg,
    ddi_callback_id_t *cb_id);

static int nx1394_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id);

static int nx1394_post_event(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventhdl, void *impl_data);

struct bus_ops nx1394_busops = {
	BUSO_REV,
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_intrspec */
	NULL,				/* bus_remove_intrspec */
	i_ddi_map_fault,		/* XXXX bus_map_fault */
	NULL,				/* bus_dma_map */
	nx1394_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,			/* bus_dma_ctl */
	nx1394_bus_ctl,			/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	nx1394_get_event_cookie,	/* (*bus_get_eventcookie() */
	nx1394_add_eventcall,		/* (*bus_add_eventcall)(); */
	nx1394_remove_eventcall,	/* (*bus_remove_eventcall)(); */
	nx1394_post_event,		/* (*bus_post_event)(); */
	0,				/* (*interrupt control)();	*/
	0,				/* (*bus_config)();	*/
	0,				/* (*bus_unconfig)();	*/
	0,				/* (*bus_fm_init)();	*/
	0,				/* (*bus_fm_fini)();	*/
	0,				/* (*bus_fm_access_enter)();	*/
	0,				/* (*bus_fm_access_exit)();	*/
	0,				/* (*bus_power)();	*/
	i_ddi_intr_ops			/* (*bus_intr_op)();	*/
};

/*
 * removal/insertion/reset events
 */
#define	NX1394_EVENT_TAG_HOT_REMOVAL		0
#define	NX1394_EVENT_TAG_HOT_INSERTION		1
#define	NX1394_EVENT_TAG_BUS_RESET		2

static ndi_event_definition_t nx1394_event_defs[] = {
	{NX1394_EVENT_TAG_HOT_REMOVAL, DDI_DEVI_REMOVE_EVENT, EPL_KERNEL,
	    NDI_EVENT_POST_TO_TGT},
	{NX1394_EVENT_TAG_HOT_INSERTION, DDI_DEVI_INSERT_EVENT, EPL_KERNEL,
	    NDI_EVENT_POST_TO_TGT},
	{NX1394_EVENT_TAG_BUS_RESET, DDI_DEVI_BUS_RESET_EVENT, EPL_KERNEL,
	    NDI_EVENT_POST_TO_ALL},
};

#define	NX1394_N_EVENTS \
	(sizeof (nx1394_event_defs) / sizeof (ndi_event_definition_t))

static ndi_event_set_t nx1394_events = {
	NDI_EVENTS_REV1, NX1394_N_EVENTS, nx1394_event_defs
};

/*
 * nx1394_bus_ctl()
 *    This routine implements nexus bus ctl operations. Of importance are
 *    DDI_CTLOPS_REPORTDEV, DDI_CTLOPS_INITCHILD, DDI_CTLOPS_UNINITCHILD
 *    and DDI_CTLOPS_POWER. For DDI_CTLOPS_INITCHILD, it tries to lookup
 *    reg property on the child node and builds and sets the name
 *    (name is of the form GGGGGGGGGGGGGGGG[,AAAAAAAAAAAA], where
 *    GGGGGGGGGGGGGGGG is the GUID and AAAAAAAAAAAA is the optional unit
 *    address).
 */
static int
nx1394_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op, void *arg,
    void *result)
{
	int status;

	switch (op) {
	case DDI_CTLOPS_REPORTDEV: {
		dev_info_t *pdip = ddi_get_parent(rdip);
		cmn_err(CE_CONT, "?%s%d at %s%d",
		    ddi_node_name(rdip), ddi_get_instance(rdip),
		    ddi_node_name(pdip), ddi_get_instance(pdip));
		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_INITCHILD: {
		dev_info_t *ocdip, *cdip = (dev_info_t *)arg;
		dev_info_t *pdip = ddi_get_parent(cdip);
		int reglen, i;
		uint32_t *regptr;
		char addr[MAXNAMELEN];

		i = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS, "reg", (int **)&regptr,
		    (uint_t *)&reglen);

		if (i != DDI_PROP_SUCCESS) {
			cmn_err(CE_NOTE, "!%s(%d): \"reg\" property not found",
			    ddi_node_name(cdip), ddi_get_instance(cdip));
			return (DDI_NOT_WELL_FORMED);
		}

		ASSERT(reglen != 0);

		/*
		 * addr is of the format GGGGGGGGGGGGGGGG[,AAAAAAAAAAAA]
		 */
		if (regptr[2] || regptr[3]) {
			(void) sprintf(addr, "%08x%08x,%04x%08x", regptr[0],
			    regptr[1], regptr[2], regptr[3]);
		} else {
			(void) sprintf(addr, "%08x%08x", regptr[0], regptr[1]);
		}
		ddi_prop_free(regptr);
		ddi_set_name_addr(cdip, addr);

		/*
		 * Check for a node with the same name & addr as the current
		 * node. If such a node exists, return failure.
		 */
		if ((ocdip = ndi_devi_find(pdip, ddi_node_name(cdip), addr)) !=
		    NULL && ocdip != cdip) {
			cmn_err(CE_NOTE,
			    "!%s(%d): Duplicate dev_info node found %s@%s",
			    ddi_node_name(cdip), ddi_get_instance(cdip),
			    ddi_node_name(ocdip), addr);
			ddi_set_name_addr(cdip, NULL);
			return (DDI_NOT_WELL_FORMED);
		}

		/*
		 * If HAL (parent dip) has "active-dma-flush" property, then
		 * add property to child as well.  Workaround for active
		 * context flushing bug in Schizo rev 2.1 and 2.2.
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, pdip, DDI_PROP_DONTPASS,
		    "active-dma-flush") != 0) {
			status = ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
			    "active-dma-flush", 1);
			if (status != NDI_SUCCESS) {
				cmn_err(CE_NOTE, "!%s(%d): Unable to add "
				    "\"active-dma-flush\" property",
				    ddi_node_name(cdip),
				    ddi_get_instance(cdip));
				ddi_set_name_addr(cdip, NULL);
				return (DDI_NOT_WELL_FORMED);
			}
		}

		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_UNINITCHILD: {
		ddi_prop_remove_all((dev_info_t *)arg);
		ddi_set_name_addr((dev_info_t *)arg, NULL);
		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_IOMIN: {
		status = ddi_ctlops(dip, rdip, op, arg, result);
		return (status);
	}

	case DDI_CTLOPS_POWER: {
		return (DDI_SUCCESS);
	}

	/*
	 * These ops correspond to functions that "shouldn't" be called
	 * by a 1394 client driver.
	 */
	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_REPORTINT:
	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
	case DDI_CTLOPS_SIDDEV:
	case DDI_CTLOPS_SLAVEONLY:
	case DDI_CTLOPS_AFFINITY:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK: {
		cmn_err(CE_CONT, "!%s(%d): invalid op (%d) from %s(%d)",
		    ddi_node_name(dip), ddi_get_instance(dip),
		    op, ddi_node_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);
	}

	/*
	 * Everything else (e.g. PTOB/BTOP/BTOPR requests) we pass up
	 */
	default: {
		status = ddi_ctlops(dip, rdip, op, arg, result);
		return (status);
	}
	}
}

/*
 * nx1394_dma_allochdl()
 *    Merges the ddi_dma_attr_t passed in by the target (using
 *    ddi_dma_alloc_handle() call) with that of the hal and passes the alloc
 *    handle request up the device by calling ddi_dma_allochdl().
 */
static int
nx1394_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
    int (*waitfnp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	s1394_hal_t *hal;
	ddi_dma_attr_t *hal_attr;
	int status;

	_NOTE(SCHEME_PROTECTS_DATA("unique (per thread)", ddi_dma_attr_t))

	/*
	 * If hal calls ddi_dma_alloc_handle, dip == rdip == hal dip.
	 * Unfortunately, we cannot verify this (by way of looking up for hal
	 * dip) here because h1394_attach() may happen much later.
	 */
	if (dip != rdip) {
		hal = s1394_dip_to_hal(ddi_get_parent(rdip));
		ASSERT(hal);
		hal_attr = &hal->halinfo.dma_attr;
		ASSERT(hal_attr);
		ddi_dma_attr_merge(attr, hal_attr);
	}
	status = ddi_dma_allochdl(dip, rdip, attr, waitfnp, arg, handlep);
	return (status);
}

/*
 * nx1394_get_event_cookie()
 *    Called when a child node calls ddi_get_eventcookie().
 *    Returns event cookie corresponding to event "name".
 */
static int
nx1394_get_event_cookie(dev_info_t *dip, dev_info_t *rdip, char *name,
    ddi_eventcookie_t *event_cookiep)
{
	int ret;
	s1394_hal_t *hal;

	hal = s1394_dip_to_hal(dip);
	ASSERT(hal);

	ret = ndi_event_retrieve_cookie(hal->hal_ndi_event_hdl,
	    rdip, name, event_cookiep, 0);

	return (ret);

}

/*
 * nx1394_add_eventcall()
 *    This gets called when a child node calls ddi_add_eventcall(). Registers
 *    the specified callback for the requested event cookie with the ndi
 *    event framework.
 *    dip is the hal dip. This routine calls ndi_event_add_callback(),
 *    allowing requests for events we don't generate to pass up the tree.
 */
static int
nx1394_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t cookie, void (*callback)(), void *arg,
    ddi_callback_id_t *cb_id)
{
	int ret;
	s1394_hal_t *hal;
#if defined(DEBUG)
	char *event_name = NULL;
#endif

	hal = s1394_dip_to_hal(dip);
	ASSERT(hal);

	ret = ndi_event_add_callback(hal->hal_ndi_event_hdl, rdip, cookie,
	    callback, arg, NDI_NOSLEEP, cb_id);
#if defined(DEBUG)
	event_name = ndi_event_cookie_to_name(hal->hal_ndi_event_hdl, cookie);
	if (event_name == NULL)
		event_name = "";
#endif

	return (ret);
}

/*
 * nx1394_remove_eventcall()
 *    Called as a result of a child node calling ddi_remove_eventcall().
 *    Unregisters the callback corresponding to the callback id passed in.
 */
static int
nx1394_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{
	int ret;
	s1394_hal_t *hal;
	ddi_eventcookie_t cookie;
#if defined(DEBUG)
	char *event_name = NULL;
#endif

	ASSERT(cb_id);
	cookie = ((ndi_event_callbacks_t *)cb_id)->ndi_evtcb_cookie;

	hal = s1394_dip_to_hal(dip);
	ASSERT(hal);

	ret = ndi_event_remove_callback(hal->hal_ndi_event_hdl, cb_id);

#if defined(DEBUG)
	event_name = ndi_event_cookie_to_name(hal->hal_ndi_event_hdl, cookie);
	if (event_name == NULL)
		event_name = "";

#endif

	return (ret);
}

/*
 * nx1394_post_event()
 *    Called when a child node calls ddi_post_event. If the event is one of
 *    the events supported by us (bus reset/insert/remove, for now), builds
 *    a t1394_localinfo_t structure and calls ndi_event_run_callbacks(). This
 *    will result in all registered callbacks being invoked with
 *    t1394_localinfo_t as the impl_data. (see ddi_add_eventcall for callback
 *    arguments.) If the event is not defined by us, the request is
 *    propagated up the device tree by calling ndi_post_event().
 */
static int
nx1394_post_event(dev_info_t *dip, dev_info_t *rdip, ddi_eventcookie_t cookie,
    void *impl_data)
{
	int ret;
	char *name;
	s1394_hal_t *hal;
	t1394_localinfo_t localinfo;

	hal = s1394_dip_to_hal(dip);
	ASSERT(hal);

	name = ndi_event_cookie_to_name(hal->hal_ndi_event_hdl, cookie);
	/* name is NULL if we don't generate the event */
	if (name != NULL) {

		mutex_enter(&hal->topology_tree_mutex);
		localinfo.bus_generation = hal->generation_count;
		localinfo.local_nodeID = hal->node_id;
		mutex_exit(&hal->topology_tree_mutex);
		impl_data = &localinfo;

		ret = ndi_event_run_callbacks(hal->hal_ndi_event_hdl,
		    rdip, cookie, impl_data);

		return (ret);

	} else {
		ret = ndi_post_event(ddi_get_parent(dip), rdip, cookie,
		    impl_data);
		return (ret);
	}
}

/*
 * nx1394_define_events()
 *    Allocates event handle for the hal dip and binds event set to it.
 */
int
nx1394_define_events(s1394_hal_t *hal)
{
	int ret;

	/* get event handle */
	ret = ndi_event_alloc_hdl(hal->halinfo.dip, hal->halinfo.hw_interrupt,
	    &hal->hal_ndi_event_hdl, NDI_SLEEP);
	if (ret == NDI_SUCCESS) {
		/* and bind to it */
		ret = ndi_event_bind_set(hal->hal_ndi_event_hdl, &nx1394_events,
		    NDI_SLEEP);
		if (ret != NDI_SUCCESS) {
			(void) ndi_event_free_hdl(hal->hal_ndi_event_hdl);
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * nx1394_undefine_events()
 *    Unbinds event set bound to the hal and frees the event handle.
 */
void
nx1394_undefine_events(s1394_hal_t *hal)
{
	int ret;

	ret = ndi_event_unbind_set(hal->hal_ndi_event_hdl, &nx1394_events,
	    NDI_SLEEP);
	if (ret == NDI_SUCCESS)
		ret = ndi_event_free_hdl(hal->hal_ndi_event_hdl);
}
