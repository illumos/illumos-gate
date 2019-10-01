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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c)  * Copyright (c) 2001 Tadpole Technology plc
 * All rights reserved.
 * From "@(#)pcicfg.c   1.31    99/06/18 SMI"
 */

/*
 * Cardbus module
 */

#include <sys/conf.h>
#include <sys/modctl.h>

#include <sys/pci.h>

#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>

#include <sys/hotplug/hpcsvc.h>

#include <sys/pctypes.h>
#include <sys/pcmcia.h>
#include <sys/sservice.h>
#include <sys/note.h>

#include <sys/pci/pci_types.h>
#include <sys/pci/pci_sc.h>

#include <sys/pcic_reg.h>
#include <sys/pcic_var.h>
#include <sys/pcmcia.h>

#ifdef sparc
#include <sys/ddi_subrdefs.h>
#elif defined(__x86) || defined(__amd64)
#include <sys/pci_intr_lib.h>
#include <sys/mach_intr.h>
#endif

#include "cardbus.h"
#include "cardbus_parse.h"
#include "cardbus_hp.h"
#include "cardbus_cfg.h"

static int cardbus_command_default = PCI_COMM_SERR_ENABLE |
				PCI_COMM_WAIT_CYC_ENAB |
				PCI_COMM_PARITY_DETECT |
				PCI_COMM_ME | PCI_COMM_MAE |
				PCI_COMM_IO;

static int cardbus_next_instance = 0;
static int cardbus_count = 0;
int number_of_cardbus_cards = 0;

static int cardbus_bus_map(dev_info_t *dip, dev_info_t *rdip,
		ddi_map_req_t *mp, off_t offset, off_t len, caddr_t *vaddrp);
static void pcirp2rp(const pci_regspec_t *pci_rp, struct regspec *rp);

static int cardbus_ctlops(dev_info_t *, dev_info_t *,
			ddi_ctl_enum_t, void *arg, void *);
static void cardbus_init_child_regs(dev_info_t *child);
static int cardbus_initchild(dev_info_t *, dev_info_t *,
			dev_info_t *, void *);
static int cardbus_name_child(dev_info_t *, char *, int);
static void cardbus_removechild(dev_info_t *dip);

static int cardbus_dma_allochdl(dev_info_t *dip, dev_info_t *rdip,
		ddi_dma_attr_t *attr, int (*waitfp)(caddr_t), caddr_t arg,
		ddi_dma_handle_t *handlep);
static int cardbus_dma_freehdl(dev_info_t *dip, dev_info_t *rdip,
		ddi_dma_handle_t handle);
static int cardbus_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
		ddi_dma_handle_t handle, struct ddi_dma_req *dmareq,
		ddi_dma_cookie_t *cp, uint_t *ccountp);
static int cardbus_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
		ddi_dma_handle_t handle);
static int cardbus_dma_flush(dev_info_t *dip, dev_info_t *rdip,
		ddi_dma_handle_t handle, off_t off, size_t len,
		uint_t cache_flags);
static int cardbus_dma_win(dev_info_t *dip, dev_info_t *rdip,
		ddi_dma_handle_t handle, uint_t win, off_t *offp,
		size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp);
static int cardbus_dma_map(dev_info_t *dip, dev_info_t *rdip,
		struct ddi_dma_req *dmareqp, ddi_dma_handle_t *handlep);

static int cardbus_prop_op(dev_t dev, dev_info_t *dip, dev_info_t *ch_dip,
		ddi_prop_op_t prop_op, int mod_flags,
		char *name, caddr_t valuep, int *lengthp);

static int cardbus_get_eventcookie(dev_info_t *dip, dev_info_t *rdip,
		char *eventname, ddi_eventcookie_t *cookiep);
static int cardbus_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
		ddi_eventcookie_t cookie, void (*callback)(dev_info_t *dip,
		ddi_eventcookie_t cookie, void *arg, void *bus_impldata),
		void *arg, ddi_callback_id_t *cb_id);
static int cardbus_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id);
static int cardbus_post_event(dev_info_t *dip, dev_info_t *rdip,
		ddi_eventcookie_t cookie, void *bus_impldata);

static int cardbus_intr_ops(dev_info_t *dip, dev_info_t *rdip,
		ddi_intr_op_t intr_op,
		ddi_intr_handle_impl_t *hdlp, void *result);

static int check_token(char *token, int *len);
static char *find_token(char **cp, int *l, char *endc);
static int parse_token(char *token);
static int token_to_hex(char *token, unsigned *val, int len);
static int token_to_dec(char *token, unsigned *val, int len);
static void cardbus_add_prop(struct cb_deviceset_props *cdsp, int type,
		char *name, caddr_t vp, int len);
static void cardbus_add_stringprop(struct cb_deviceset_props *cdsp,
		char *name, char *vp, int len);
static void cardbus_prop_free(ddi_prop_t *propp);
static void cardbus_devprops_free(struct cb_deviceset_props *cbdp);
static int cardbus_parse_devprop(cbus_t *cbp, char *cp);
static void cardbus_device_props(cbus_t *cbp);

static void cardbus_expand_busrange(dev_info_t *dip);

static int cardbus_convert_properties(dev_info_t *dip);
static void cardbus_revert_properties(dev_info_t *dip);

/*
 * driver global data
 */
kmutex_t cardbus_list_mutex; /* Protects the probe handle list */
void *cardbus_state;
int cardbus_latency_timer = 0x40;
int cardbus_debug = 0;

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_miscops;
static struct modlmisc modlmisc = {
	&mod_miscops,
	"Cardbus Configurator support",
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlmisc,
	NULL
};

int
_init(void)
{
	int error;

	error =  ddi_soft_state_init(&cardbus_state, sizeof (cbus_t), 0);
	if (error != 0)
		return (error);

	mutex_init(&cardbus_list_mutex, NULL, MUTEX_DRIVER, NULL);
	if ((error = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&cardbus_list_mutex);
	}

	return (error);
}

int
_fini(void)
{
	int error;
	if ((error = mod_remove(&modlinkage)) == 0) {
		mutex_destroy(&cardbus_list_mutex);
		ddi_soft_state_fini(&cardbus_state);
	}
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static
struct bus_ops cardbusbus_ops = {
	BUSO_REV,
	cardbus_bus_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	cardbus_dma_map,
	cardbus_dma_allochdl,
	cardbus_dma_freehdl,
	cardbus_dma_bindhdl,
	cardbus_dma_unbindhdl,
	cardbus_dma_flush,
	cardbus_dma_win,
	ddi_dma_mctl,
	cardbus_ctlops,			/* (*bus_ctl)();		*/
	cardbus_prop_op,
	cardbus_get_eventcookie,	/* (*bus_get_eventcookie)();	*/
	cardbus_add_eventcall,		/* (*bus_add_eventcall)();	*/
	cardbus_remove_eventcall,	/* (*bus_remove_eventcall)();	*/
	cardbus_post_event,		/* (*bus_post_event)();		*/
	NULL,				/* (*bus_intr_ctl)();		*/
	NULL,				/* (*bus_config)();		*/
	NULL,				/* (*bus_unconfig)();		*/
	NULL,				/* (*bus_fm_init)();		*/
	NULL,				/* (*bus_fm_fini)();		*/
	NULL,				/* (*bus_enter)();		*/
	NULL,				/* (*bus_exit)();		*/
	NULL,				/* (*bus_power)();		*/
	cardbus_intr_ops		/* (*bus_intr_op)();		*/
};

#define	CB_EVENT_TAG_INSERT	0
#define	CB_EVENT_TAG_REMOVE	1

static ndi_event_definition_t cb_ndi_event_defs[] = {
	{ CB_EVENT_TAG_INSERT, DDI_DEVI_INSERT_EVENT, EPL_INTERRUPT, 0 },
	{ CB_EVENT_TAG_REMOVE, DDI_DEVI_REMOVE_EVENT, EPL_INTERRUPT, 0 }
};

#define	CB_N_NDI_EVENTS \
	(sizeof (cb_ndi_event_defs) / sizeof (cb_ndi_event_defs[0]))

#ifdef sparc
struct busnum_ctrl {
	int	rv;
	dev_info_t *dip;
	cardbus_bus_range_t *range;
};

static int
cardbus_claim_pci_busnum(dev_info_t *dip, void *arg)
{
	cardbus_bus_range_t pci_bus_range;
	struct busnum_ctrl *ctrl;
	ndi_ra_request_t req;
	char bus_type[16] = "(unknown)";
	int len;
	uint64_t base;
	uint64_t retlen;

	ctrl = (struct busnum_ctrl *)arg;

	/* check if this is a PCI bus node */
	len = sizeof (bus_type);
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "device_type",
	    (caddr_t)&bus_type, &len) != DDI_SUCCESS)
		return (0);	/* (DDI_WALK_PRUNECHILD); */

	if ((strcmp(bus_type, "pci") != 0) &&
	    (strcmp(bus_type, "pciex") != 0)) /* it is not a pci bus type */
		return (0);	/* (DDI_WALK_PRUNECHILD); */

	/* look for the bus-range property */
	len = sizeof (struct cardbus_bus_range);
	if (ddi_getlongprop_buf(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
	    "bus-range", (caddr_t)&pci_bus_range, &len) == DDI_SUCCESS) {
		cardbus_err(dip, 1, "cardbus_claim_pci_busnum: %u -> %u \n",
		    pci_bus_range.lo, pci_bus_range.hi);
		if ((pci_bus_range.lo >= ctrl->range->lo) &&
		    (pci_bus_range.hi <= ctrl->range->hi)) {
			cardbus_err(dip, 1,
			    "cardbus_claim_pci_busnum: claim %u -> %u \n",
			    pci_bus_range.lo, pci_bus_range.hi);

			/* claim the bus range from the bus resource map */
			bzero((caddr_t)&req, sizeof (req));
			req.ra_addr = (uint64_t)pci_bus_range.lo;
			req.ra_flags |= NDI_RA_ALLOC_SPECIFIED;
			req.ra_len = (uint64_t)pci_bus_range.hi -
			    (uint64_t)pci_bus_range.lo + 1;

			if (ndi_ra_alloc(ctrl->dip, &req, &base, &retlen,
			    NDI_RA_TYPE_PCI_BUSNUM, 0) == NDI_SUCCESS)
				return (0);	/* (DDI_WALK_PRUNECHILD); */
		}
	}

	/*
	 * never Error return.
	 */
	ctrl->rv = DDI_SUCCESS;
	return (DDI_WALK_TERMINATE);
}

static void
cardbus_walk_node_child(dev_info_t *parent,
    int (*f)(dev_info_t *, void *), void *arg)
{
	dev_info_t *dip;
	int ret;

	for (dip = ddi_get_child(parent); dip;
	    dip = ddi_get_next_sibling(dip)) {

		ret = (*f) (dip, arg);
		if (ret)
			return;
	}
}

static void cardbus_fix_hostbridge_busrange(dev_info_t *dip)
{
	cardbus_bus_range_t bus_range;
	struct busnum_ctrl ctrl;

	uint64_t next_bus;
	uint64_t blen;
	ndi_ra_request_t req;
	int	len;

	cardbus_err(dip, 1, "cardbus_fix_hostbridge_busrange\n");

	bzero((caddr_t)&req, sizeof (ndi_ra_request_t));
	req.ra_len = 1;
	if (ndi_ra_alloc(dip, &req,
	    &next_bus, &blen, NDI_RA_TYPE_PCI_BUSNUM,
	    0) != NDI_SUCCESS) {
		(void) ndi_ra_map_destroy(dip, NDI_RA_TYPE_PCI_BUSNUM);

		if (ndi_ra_map_setup(dip, NDI_RA_TYPE_PCI_BUSNUM)
		    == NDI_FAILURE) {
			cardbus_err(dip, 1, "cardbus_fix_hostbridge_busrange "
			    "NDI_RA_TYPE_PCI_BUSNUM setup fail\n");
			return;
		}

		bus_range.lo = 0;
		(void) ddi_getlongprop_buf(DDI_DEV_T_NONE, dip,
		    DDI_PROP_DONTPASS, "bus-range", (caddr_t)&bus_range, &len);
		bus_range.hi = 255;

		(void) ndi_ra_free(dip,
		    (uint64_t)bus_range.lo + 1,
		    (uint64_t)bus_range.hi - (uint64_t)bus_range.lo,
		    NDI_RA_TYPE_PCI_BUSNUM, 0);

		ctrl.rv = DDI_SUCCESS;
		ctrl.dip = dip;
		ctrl.range = &bus_range;

		cardbus_walk_node_child(dip, cardbus_claim_pci_busnum,
		    (void*)&ctrl);

		if (ctrl.rv != DDI_SUCCESS)
			cardbus_err(dip, 1, "cardbus_fix_hostbridge_busrange "
			    "cardbus_walk_node_child fails\n");

		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
		    "bus-range", (int *)&bus_range, 2);

	} else {
		cardbus_err(dip, 1, "cardbus_fix_hostbridge_busrange "
		    "already set up %x\n", (int)next_bus);
		(void) ndi_ra_free(dip, next_bus, (uint64_t)1,
		    NDI_RA_TYPE_PCI_BUSNUM, 0);
	}
}

static dev_info_t *
cardbus_find_hsbridge_dip(dev_info_t *dip)
{
	dev_info_t *pdip;

	pdip = ddi_get_parent(dip);
	while (pdip) {
		if (ddi_get_parent(pdip) == ddi_root_node())
			break;
		pdip = ddi_get_parent(pdip);
	}

	return (pdip);
}
#endif /* sparc */

/*
 * Attach a device to the cardbus infrastructure.
 */
int
cardbus_attach(dev_info_t *dip, cb_nexus_cb_t *nex_ops)
{
	cbus_t *cbp;
	int cb_instance;
	anp_t *anp = (anp_t *)ddi_get_driver_private(dip);
	struct dev_info *devi = DEVI(dip);

	mutex_enter(&cardbus_list_mutex);

	/*
	 * Make sure that it is not already initialized.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
	    "cbus-instance") == 1) {
		cmn_err(CE_WARN,
		    "%s%d: cardbus instance already initialized!\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
			mutex_exit(&cardbus_list_mutex);
		return (DDI_FAILURE);
	}

	/*
	 * initialize soft state structure for the bus instance.
	 */
	cb_instance = cardbus_next_instance++;

	if (ddi_soft_state_zalloc(cardbus_state, cb_instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: can't allocate cardbus soft state\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		mutex_exit(&cardbus_list_mutex);
		return (DDI_FAILURE);
	}

	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state, cb_instance);
	cbp->cb_instance = cb_instance;
	cbp->cb_dip = dip;
	mutex_init(&cbp->cb_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Save the instance number of the soft state structure for
	 * this bus as a devinfo property.
	 */
	if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    "cbus-instance", (caddr_t)&cb_instance,
	    sizeof (cb_instance)) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s%d: failed to add the property 'cbus-instance'",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		ddi_soft_state_free(cardbus_state, cb_instance);
		mutex_exit(&cardbus_list_mutex);
		return (DDI_FAILURE);
	}

	cbp->cb_nex_ops = nex_ops;
	/*
	 * TODO - Should probably be some sort of locking on the devinfo here.
	 */
	cbp->orig_dopsp = devi->devi_ops;
	cbp->orig_bopsp = devi->devi_ops->devo_bus_ops;
	cbp->cb_dops = *devi->devi_ops;
	devi->devi_ops = &cbp->cb_dops;

	if (ndi_event_alloc_hdl(dip, *anp->an_iblock, &cbp->cb_ndi_event_hdl,
	    NDI_SLEEP) == NDI_SUCCESS) {
		cbp->cb_ndi_events.ndi_n_events = CB_N_NDI_EVENTS;
		cbp->cb_ndi_events.ndi_events_version = NDI_EVENTS_REV1;
		cbp->cb_ndi_events.ndi_event_defs = cb_ndi_event_defs;
		if (ndi_event_bind_set(cbp->cb_ndi_event_hdl,
		    &cbp->cb_ndi_events,
		    NDI_SLEEP) != NDI_SUCCESS) {
			cardbus_err(dip, 1,
			    "cardbus_attach: ndi_event_bind_set failed\n");
		}
	}

	/*
	 * Check for device initialization property.
	 */
	cardbus_device_props(cbp);

	if (cardbus_init_hotplug(cbp) != DDI_SUCCESS) {
		ddi_soft_state_free(cardbus_state, cb_instance);
		mutex_exit(&cardbus_list_mutex);
		return (DDI_FAILURE);
	}

#ifdef sparc
	/* a hack to fix the bus-range problem on pci root nodes */
	{
		dev_info_t *hs_dip;

		hs_dip = cardbus_find_hsbridge_dip(dip);
		cardbus_fix_hostbridge_busrange(hs_dip);
	}
#endif

	cardbus_expand_busrange(dip);
	cardbus_count++;
	mutex_exit(&cardbus_list_mutex);
	return (DDI_SUCCESS);
}

#ifdef TODO
static int
cardbus_detach(dev_info_t *dip)
{
	int cb_instance;
	cbus_t *cbp;

	mutex_enter(&cardbus_list_mutex);
	/* get the instance number for the cardbus soft state data */
	cb_instance = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cbus-instance", -1);
	if (cb_instance < 0) {
		mutex_exit(&cardbus_list_mutex);
		return (DDI_FAILURE); /* no instance is setup for this bus */
	}

	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state, cb_instance);

	if (cbp->cb_dsp) {
		struct cb_deviceset_props *cbdp, *ncbdp;

		cbdp = cbp->cb_dsp;
		while (cbdp) {
			ncbdp = cbdp->next;
			cardbus_devprops_free(cbdp);
			cbdp = ncbdp;
		}
	}
	/*
	 * Unregister the bus with the HPS.
	 *
	 * (Note: It is assumed that the HPS framework uninstalls
	 *  event handlers for all the hot plug slots on this bus.)
	 */
	(void) hpc_nexus_unregister_bus(dip);

	if (cbp->cb_ndi_event_hdl != NULL) {
		(void) ndi_event_unbind_set(cbp->cb_ndi_event_hdl,
		    &cbp->cb_ndi_events, NDI_SLEEP);
		ndi_event_free_hdl(cbp->cb_ndi_event_hdl);
	}

	mutex_destroy(&cbp->cb_mutex);
	if (cbp->nexus_path)
		kmem_free(cbp->nexus_path, strlen(cbp->nexus_path) + 1);
	if (cbp->name)
		kmem_free(cbp->name, strlen(cbp->name) + 1);

	ddi_soft_state_free(cardbus_state, cb_instance);

	/* remove the 'cbus-instance' property from the devinfo node */
	(void) ddi_prop_remove(DDI_DEV_T_ANY, dip, "cbus-instance");

	ASSERT(cardbus_count != 0);
	--cardbus_count;

	mutex_exit(&cardbus_list_mutex);
	return (DDI_SUCCESS);
}
#endif

boolean_t
cardbus_load_cardbus(dev_info_t *dip, uint_t socket, uint32_t pc_base)
{
#ifndef HOTPLUG
	struct cardbus_config_ctrl ctrl;
	int circular_count;
#endif
	int cb_instance;
	cbus_t *cbp;
	struct dev_info *devi = DEVI(dip);

	_NOTE(ARGUNUSED(socket, pc_base))

#if defined(CARDBUS_DEBUG)
	cardbus_err(dip, 6, "cardbus_load_cardbus\n");
#endif

	cb_instance = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cbus-instance", -1);
	ASSERT(cb_instance >= 0);
	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state, cb_instance);

	if (cbp->fatal_problem)
		return (B_FALSE);

	if (cardbus_convert_properties(dip) == DDI_FAILURE)
		return (B_FALSE);

	number_of_cardbus_cards++;
	devi->devi_ops->devo_bus_ops = &cardbusbus_ops;

#ifdef HOTPLUG
	mutex_enter(&cbp->cb_mutex);
	cbp->card_present = B_TRUE;

	(void) hpc_slot_event_notify(cbp->slot_handle,
	    HPC_EVENT_SLOT_INSERTION, 0);
	(void) hpc_slot_event_notify(cbp->slot_handle,
	    HPC_EVENT_SLOT_POWER_ON, 0);
	(void) hpc_slot_event_notify(cbp->slot_handle,
	    HPC_EVENT_SLOT_CONFIGURE, 0);

	mutex_exit(&cbp->cb_mutex);
#else
	if (cardbus_configure(cbp) != PCICFG_SUCCESS) {
#if defined(CARDBUS_DEBUG)
		cardbus_err(dip, 6, "cardbus_configure failed\n");
#endif
		return (B_FALSE);
	}

	ctrl.rv = NDI_SUCCESS;
	ctrl.busno = cardbus_primary_busno(dip);
	ctrl.op = PCICFG_OP_ONLINE;
	ctrl.dip = NULL;
	ctrl.flags = PCICFG_FLAGS_CONTINUE;

	/*
	 * The child of the dip is the cardbus dip. The child of the
	 * cardbus dip is the device itself
	 */
#if defined(CARDBUS_DEBUG)
	cardbus_err(dip, 8, "cardbus_load_cardbus: calling cbus_configure\n");
#endif
	ndi_devi_enter(dip, &circular_count);
	ddi_walk_devs(ddi_get_child(dip), cbus_configure, (void *)&ctrl);
	ndi_devi_exit(dip, circular_count);

	if (ctrl.rv != NDI_SUCCESS) {
		cardbus_err(dip, 1,
		    "cardbus_load_cardbus (%s%d): failed to attach (%d)\n",
		    ctrl.dip ? ddi_driver_name(ctrl.dip) : "Unknown",
		    ctrl.dip ? ddi_get_instance(ctrl.dip) : 0,
		    ctrl.rv);

		/*
		 * Returning error here will cause the pcic_load_cardbus() call
		 * to fail. This will invoke pcic_unload_cardbus() which calls
		 * cardbus_unload_cardbus() below.
		 */
		return (B_FALSE);
	}
#endif

#if defined(CARDBUS_DEBUG)
	cardbus_err(dip, 7, "cardbus_load_cardbus: returning TRUE\n");
#endif

	return (B_TRUE);
}

/*
 * Unload the cardbus module
 */
void
cardbus_unload_cardbus(dev_info_t *dip)
{
	int	cb_instance;
#ifndef HOTPLUG
	int	prim_bus = cardbus_primary_busno(dip);
	int	rval;
#endif
	cbus_t *cbp;

	cardbus_err(dip, 6, "cardbus_unload_cardbus\n");

	cb_instance = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cbus-instance", -1);
	ASSERT(cb_instance >= 0);
	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state, cb_instance);

	if (number_of_cardbus_cards == 0)
		return;

#ifdef HOTPLUG
	mutex_enter(&cbp->cb_mutex);
	cbp->card_present = B_FALSE;

	(void) hpc_slot_event_notify(cbp->slot_handle,
	    HPC_EVENT_SLOT_POWER_OFF, 0);
	(void) hpc_slot_event_notify(cbp->slot_handle,
	    HPC_EVENT_SLOT_UNCONFIGURE, 0);
	(void) hpc_slot_event_notify(cbp->slot_handle,
	    HPC_EVENT_SLOT_REMOVAL, 0);

	mutex_exit(&cbp->cb_mutex);
#else

	cardbus_err(dip, 8,
	    "cardbus_unload_cardbus: calling cardbus_unconfigure_node\n");

	rval = cardbus_unconfigure_node(dip, prim_bus, B_TRUE);

	if (rval != NDI_SUCCESS) {
		cardbus_err(dip, 4,
		    "cardbus_unload_cardbus: "
		    "cardbus_unconfigure_node failed\n");
		number_of_cardbus_cards--;
		cbp->fatal_problem = B_TRUE;
		cmn_err(CE_WARN,
		    "cardbus(%s%d): Failed to remove device tree: "
		    "Slot disabled",
		    ddi_get_name(dip), ddi_get_instance(dip));
		return;
	}

	(void) cardbus_unconfigure(cbp);
#endif

	/*
	 * Inform the lower drivers that the card has been removed
	 */
	if (cbp->cb_ndi_event_hdl != NULL) {
		ddi_eventcookie_t cookie;
		if (ndi_event_retrieve_cookie(cbp->cb_ndi_event_hdl, dip,
		    DDI_DEVI_REMOVE_EVENT, &cookie, 0) == NDI_SUCCESS) {
			(void) ndi_event_run_callbacks(cbp->cb_ndi_event_hdl,
			    dip, cookie, NULL);
		}
	}

	cardbus_revert_properties(dip);
}

static boolean_t
is_32bit_pccard(dev_info_t *dip)
{
	int len;
	char bus_type[16];

	len = sizeof (bus_type);
	if (ddi_prop_op(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    PROP_LEN_AND_VAL_BUF, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "device_type", (caddr_t)&bus_type, &len) != DDI_SUCCESS)
		return (B_FALSE);

	if ((strcmp(bus_type, "pci") != 0) &&
	    (strcmp(bus_type, "pciex") != 0) &&
	    (strcmp(bus_type, "cardbus") != 0)) /* not of pci type */
		return (B_FALSE);

	return (B_TRUE);
}

void
cardbus_save_children(dev_info_t *dip)
{
	for (; dip != NULL; dip = ddi_get_next_sibling(dip)) {
		cardbus_save_children(ddi_get_child(dip));

		if (strcmp("pcs", ddi_node_name(dip)) == 0)
			continue;
		if (!is_32bit_pccard(dip))
			continue;
		cardbus_err(dip, 1, "Saving device\n");
		(void) pci_save_config_regs(dip);
	}

}

void
cardbus_restore_children(dev_info_t *dip)
{
	for (; dip != NULL; dip = ddi_get_next_sibling(dip)) {
		cardbus_restore_children(ddi_get_child(dip));

		if (strcmp("pcs", ddi_node_name(dip)) == 0)
			continue;
		if (!is_32bit_pccard(dip))
			continue;
		cardbus_err(dip, 1, "restoring device\n");
		(void) pci_restore_config_regs(dip);
	}

}

static int
cardbus_convert_properties(dev_info_t *dip)
{
	struct pcm_regs *pcic_avail_p, *old_avail_p;
	pci_regspec_t *cb_avail_p, *new_avail_p;
	pcic_ranges_t *pcic_range_p, *old_range_p;
	cardbus_range_t *cb_range_p, *new_range_p;
	int range_len, range_entries, i;
	int avail_len, avail_entries;

#if defined(CARDBUS_DEBUG)
	cardbus_err(dip, 6, "cardbus_convert_properties\n");
#endif

	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#address-cells", 3) != DDI_SUCCESS) {
		cardbus_err(dip, 1, "cardbus_convert_properties: "
		    "failed to update #address-cells property\n");
		return (DDI_FAILURE);
	}
	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#size-cells", 2) != DDI_SUCCESS) {
		cardbus_err(dip, 1, "cardbus_convert_properties: "
		    "failed to update #size-cells property\n");
		return (DDI_FAILURE);
	}

	if (ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS, "available",
	    (caddr_t)&pcic_avail_p, &avail_len) != DDI_PROP_SUCCESS) {
		cardbus_err(dip, 1, "cardbus_convert_properties: "
		    "no available property for pcmcia\n");
	} else {
		avail_entries = avail_len / sizeof (struct pcm_regs);
		cb_avail_p = kmem_alloc(sizeof (pci_regspec_t) * avail_entries,
		    KM_SLEEP);

		old_avail_p = pcic_avail_p;
		new_avail_p = cb_avail_p;
		for (i = 0; i < avail_entries;
		    i++, old_avail_p++, new_avail_p++) {
			new_avail_p->pci_phys_hi = old_avail_p->phys_hi;
			new_avail_p->pci_phys_mid = 0;
			new_avail_p->pci_phys_low = old_avail_p->phys_lo;
			new_avail_p->pci_size_hi = 0;
			new_avail_p->pci_size_low = old_avail_p->phys_len;
		}

		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
		    "available",
		    (int *)cb_avail_p,
		    (sizeof (pci_regspec_t) * avail_entries)/sizeof (int));

		kmem_free(pcic_avail_p, avail_len);
		kmem_free(cb_avail_p, sizeof (pci_regspec_t) * avail_entries);
	}

	if (ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS, "ranges",
	    (caddr_t)&pcic_range_p, &range_len) != DDI_PROP_SUCCESS) {
		cardbus_err(dip, 1, "cardbus_convert_properties: "
		    "no ranges property for pcmcia\n");
	} else {
		range_entries = range_len / sizeof (pcic_ranges_t);
		cb_range_p = kmem_alloc(
		    sizeof (cardbus_range_t) * range_entries, KM_SLEEP);

		old_range_p = pcic_range_p;
		new_range_p = cb_range_p;
		for (i = 0; i < range_entries;
		    i++, old_range_p++, new_range_p++) {
			new_range_p->child_hi =
			    old_range_p->pcic_range_caddrhi;
			new_range_p->child_mid = 0;
			new_range_p->child_lo =
			    old_range_p->pcic_range_caddrlo;
			new_range_p->parent_hi =
			    old_range_p->pcic_range_paddrhi;
			new_range_p->parent_mid =
			    old_range_p->pcic_range_paddrmid;
			new_range_p->parent_lo =
			    old_range_p->pcic_range_paddrlo;
			new_range_p->size_hi = 0;
			new_range_p->size_lo = old_range_p->pcic_range_size;
		}

		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "ranges",
		    (int *)cb_range_p,
		    (sizeof (cardbus_range_t) * range_entries)/sizeof (int));

		kmem_free(pcic_range_p, range_len);
		kmem_free(cb_range_p, sizeof (cardbus_range_t) * range_entries);
	}

	return (DDI_SUCCESS);
}

static void
cardbus_revert_properties(dev_info_t *dip)
{
#if defined(CARDBUS_DEBUG)
	cardbus_err(dip, 6, "cardbus_revert_properties\n");
#endif

	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "#address-cells");

	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "#size-cells");

	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "available");
}

static int
cardbus_prop_op(dev_t dev, dev_info_t *dip, dev_info_t *ch_dip,
    ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
#if defined(CARDBUS_DEBUG)
	if ((ch_dip != dip) || (cardbus_debug >= 9))
		cardbus_err(dip, 6,
		    "cardbus_prop_op(%s) (dip=0x%p, op=%d, name=%s)\n",
		    ddi_driver_name(ch_dip), (void *) dip, prop_op, name);
#endif
	return (impl_ddi_bus_prop_op(dev, dip, ch_dip, prop_op,
	    mod_flags, name, valuep, lengthp));
}

static int
cardbus_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	pci_regspec_t *regs;
	int	totreg, reglen;
	const char	*dname = ddi_driver_name(dip);

	ASSERT(number_of_cardbus_cards != 0);

	cardbus_err(dip, 6,
	    "cardbus_ctlops(%p, %p, %d, %p, %p)\n",
	    (void *)dip, (void *)rdip, ctlop, (void *)arg, (void *)result);

	switch (ctlop) {
	case DDI_CTLOPS_UNINITCHILD:
		cardbus_removechild((dev_info_t *)arg);
		return (DDI_SUCCESS);
	case DDI_CTLOPS_POWER:
		return (DDI_SUCCESS);

	default:
		/*
		 * Do Nothing
		 */
		cardbus_err(dip, 8,
		    "cardbus_ctlops: Unsupported DDI_CTLOP %d\n", ctlop);
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));

	case DDI_CTLOPS_SIDDEV:		/* see ddi_dev_is_sid(9F) */
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SLAVEONLY:	/* see ddi_slaveonly(9F) */
		return (DDI_FAILURE);	/* cardbus */

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		if (rdip == (dev_info_t *)NULL) {
			*(int *)result = 0;
			return (DDI_FAILURE);
		}
		break;

	case DDI_CTLOPS_IOMIN:
		/*
		 * If we are using the streaming cache, align at
		 * least on a cache line boundary. Otherwise use
		 * whatever alignment is passed in.
		 */

		if (arg) {
			int	val = *((int *)result);

#ifdef  PCI_SBUF_LINE_SIZE
			val = maxbit(val, PCI_SBUF_LINE_SIZE);
#else
			val = maxbit(val, 64);
#endif
			*((int *)result) = val;
		}
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (cardbus_initchild(rdip, dip, (dev_info_t *)arg,
		    result));

	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);

		if (strcmp("pcs", ddi_node_name(rdip)) == 0)
			cardbus_err(dip, 1,
			    "cardbus_ctlops: PCCard socket %d at %s@%s\n",
			    ddi_get_instance(rdip),
			    dname, ddi_get_name_addr(dip));
		else {
			pci_regspec_t *pci_rp;
			dev_info_t *next;
			int	length;

			if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip,
			    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp,
			    (uint_t *)&length) != DDI_PROP_SUCCESS)
				return (DDI_FAILURE);

			if (pci_rp->pci_phys_hi == 0)
				cardbus_err(dip, 1, "%s%d at %s@%s\n",
				    ddi_driver_name(rdip),
				    ddi_get_instance(rdip),
				    dname, ddi_get_name_addr(dip));
			else {
				uint8_t bus, device, function;
				int32_t val32;
				char	*ptr, buf[128];

				bus = PCI_REG_BUS_G(pci_rp->pci_phys_hi);
				device = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
				function = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

				ptr = buf;
				(void) sprintf(ptr, "  "
				    "Bus %3d Device %2d Function %2d",
				    bus, device, function);
				ptr = &ptr[strlen(ptr)];

				val32 = ddi_getprop(DDI_DEV_T_ANY, rdip,
				    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
				    "vendor-id", -1);
				if (val32 != -1) {
					(void) sprintf(ptr, " Vendor 0x%04x",
					    val32);
					ptr = &ptr[strlen(ptr)];
				}
				val32 = ddi_getprop(DDI_DEV_T_ANY, rdip,
				    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
				    "device-id", -1);
				if (val32 != -1) {
					(void) sprintf(ptr, " Device 0x%04x",
					    val32);
					ptr = &ptr[strlen(ptr)];
				}
				val32 = ddi_getprop(DDI_DEV_T_ANY, rdip,
				    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
				    "class-code", -1);
				if (val32 != -1) {
					const char	*name;

					if ((name = ddi_get_name(rdip)) !=
					    NULL)
						(void) sprintf(ptr, " Name %s",
						    name);
					else
						(void) sprintf(ptr,
						    " Class 0x%x", val32 >> 8);
					ptr = &ptr[strlen(ptr)];
				}

				*ptr++ = '\n';
				ASSERT(((caddr_t)ptr - (caddr_t)buf) <
				    sizeof (buf));
				*ptr = '\0';

				cardbus_err(dip, 1, buf);
			}
			ddi_prop_free(pci_rp);

			for (next = ddi_get_child(rdip); next;
			    next = ddi_get_next_sibling(next))
				(void) cardbus_ctlops(next, next,
				    DDI_CTLOPS_REPORTDEV, arg, result);
		}
		return (DDI_SUCCESS);
	}
	*(int *)result = 0;

	if (ddi_getlongprop(DDI_DEV_T_NONE, rdip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "reg",
	    (caddr_t)&regs, &reglen) != DDI_SUCCESS)
		return (DDI_FAILURE);

	totreg = reglen / sizeof (pci_regspec_t);
	if (ctlop == DDI_CTLOPS_NREGS) {
		cardbus_err(dip, 6,
		    "cardbus_ctlops, returning NREGS = %d\n", totreg);
		*(int *)result = totreg;
	} else if (ctlop == DDI_CTLOPS_REGSIZE) {
		const int	rn = *(int *)arg;
		if (rn > totreg)
			return (DDI_FAILURE);
		cardbus_err(dip, 6,
		    "cardbus_ctlops, returning REGSIZE(%d) = %d\n",
		    rn, regs[rn].pci_size_low);
		*(off_t *)result = regs[rn].pci_size_low;
	}
	kmem_free(regs, reglen);
	return (DDI_SUCCESS);
}

static void
cardbus_init_child_regs(dev_info_t *child)
{
	ddi_acc_handle_t config_handle;
	uint16_t command_preserve, command;
#if !defined(__i386) && !defined(__amd64)
	uint8_t bcr;
#endif
	uint8_t header_type;
	uint8_t min_gnt, latency_timer;
	uint_t n;

	/*
	 * Map the child configuration space to for initialization.
	 *
	 *  Set the latency-timer register to values appropriate
	 *  for the devices on the bus (based on other devices
	 *  MIN_GNT and MAX_LAT registers.
	 *
	 *  Set the fast back-to-back enable bit in the command
	 *  register if it's supported and all devices on the bus
	 *  have the capability.
	 *
	 */
	if (pci_config_setup(child, &config_handle) != DDI_SUCCESS)
		return;

	cardbus_err(child, 6, "cardbus_init_child_regs()\n");

	/*
	 * Determine the configuration header type.
	 */
	header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);

	/*
	 * Support for "command-preserve" property.  Note that we
	 * add PCI_COMM_BACK2BACK_ENAB to the bits to be preserved
	 * since the obp will set this if the device supports and
	 * all targets on the same bus support it.  Since psycho
	 * doesn't support PCI_COMM_BACK2BACK_ENAB, it will never
	 * be set.  This is just here in case future revs do support
	 * PCI_COMM_BACK2BACK_ENAB.
	 */
	command_preserve = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS,
	    "command-preserve", 0);
	command = pci_config_get16(config_handle, PCI_CONF_COMM);
	command &= (command_preserve | PCI_COMM_BACK2BACK_ENAB);
	command |= (cardbus_command_default & ~command_preserve);
	pci_config_put16(config_handle, PCI_CONF_COMM, command);
	command = pci_config_get16(config_handle, PCI_CONF_COMM);

#if !defined(__i386) && !defined(__amd64)
	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		bcr = pci_config_get8(config_handle, PCI_BCNF_BCNTRL);
		if (cardbus_command_default & PCI_COMM_PARITY_DETECT)
			bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if (cardbus_command_default & PCI_COMM_SERR_ENABLE)
			bcr |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		bcr |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(config_handle, PCI_BCNF_BCNTRL, bcr);
	}
#endif

	/*
	 * Initialize cache-line-size configuration register if needed.
	 */
	if (ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "cache-line-size", 0) == 0) {

		pci_config_put8(config_handle, PCI_CONF_CACHE_LINESZ,
		    PCI_CACHE_LINE_SIZE);
		n = pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ);
		if (n != 0)
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
			    "cache-line-size", n);
	}

	/*
	 * Initialize latency timer registers if needed.
	 */
	if (ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "latency-timer", 0) == 0) {

		if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
			latency_timer = cardbus_latency_timer;
			pci_config_put8(config_handle, PCI_BCNF_LATENCY_TIMER,
			    latency_timer);
		} else {
			min_gnt = pci_config_get8(config_handle,
			    PCI_CONF_MIN_G);

			/*
			 * Cardbus os only 33Mhz
			 */
			if (min_gnt != 0) {
				latency_timer = min_gnt * 8;
			}
		}
		pci_config_put8(config_handle, PCI_CONF_LATENCY_TIMER,
		    latency_timer);
		n = pci_config_get8(config_handle, PCI_CONF_LATENCY_TIMER);
		if (n != 0)
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
			"latency-timer", n);
	}

	pci_config_teardown(&config_handle);
}

static int
cardbus_initchild(dev_info_t *rdip, dev_info_t *dip, dev_info_t *child,
    void *result)
{
	char	name[MAXNAMELEN];
	const char	*dname = ddi_driver_name(dip);
	const struct cb_ops *cop;

	_NOTE(ARGUNUSED(rdip, result))

	cardbus_err(child, 6, "cardbus_initchild\n");

	/*
	 * Name the child
	 */
	if (cardbus_name_child(child, name, MAXNAMELEN) != DDI_SUCCESS)
		return (DDI_FAILURE);

	ddi_set_name_addr(child, name);
	ddi_set_parent_data(child, NULL);

	if (ndi_dev_is_persistent_node(child) == 0) {
		/*
		 * Try to merge the properties from this prototype
		 * node into real h/w nodes.
		 */
		if (ndi_merge_node(child, cardbus_name_child) == DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			cardbus_removechild(child);
			return (DDI_FAILURE);
		}
		/*
		 * The child was not merged into a h/w node,
		 * but there's not much we can do with it other
		 * than return failure to cause the node to be removed.
		 */
		cmn_err(CE_WARN, "!%s@%s: %s.conf properties not merged",
		    ddi_driver_name(child), ddi_get_name_addr(child),
		    ddi_driver_name(child));
		cardbus_removechild(child);
		return (DDI_NOT_WELL_FORMED);
	}
	cop = DEVI(dip)->devi_ops->devo_cb_ops;

	if ((cop == NULL) || (!(cop->cb_flag & D_HOTPLUG))) {
		cmn_err(CE_WARN, "%s: driver doesn't support HOTPLUG\n", dname);
		return (DDI_FAILURE);
	}

	cardbus_init_child_regs(child);

	/*
	 * Create ppd if needed.
	 */
	if (ddi_get_parent_data(child) == NULL) {
		struct cardbus_parent_private_data *ppd;

#ifdef sparc
		ppd = (struct cardbus_parent_private_data *)
		    kmem_zalloc(sizeof (struct cardbus_parent_private_data),
		    KM_SLEEP);

#elif defined(__x86) || defined(__amd64)
		ppd = (struct cardbus_parent_private_data *)
		    kmem_zalloc(sizeof (struct cardbus_parent_private_data)
		    + sizeof (struct intrspec), KM_SLEEP);

		ppd->ppd.par_intr = (struct intrspec *)(ppd + 1);
		(ppd->ppd.par_intr)->intrspec_pri = 0;
		(ppd->ppd.par_intr)->intrspec_vec = 0;
		(ppd->ppd.par_intr)->intrspec_func = (uint_t (*)()) 0;
#endif

		if (ddi_getprop(DDI_DEV_T_NONE, child, DDI_PROP_DONTPASS,
		    "interrupts", -1) != -1)
			ppd->ppd.par_nintr = 1;

		ppd->code = CB_PPD_CODE;

		cardbus_err(child, 5,
		    "cardbus_initchild: Creating empty ppd\n");
		ppd->ppd.par_nreg = 0;
		ppd->ppd.par_reg = NULL;

		ddi_set_parent_data(child, (caddr_t)ppd);
	}

	return (DDI_SUCCESS);
}

static int
cardbus_name_child(dev_info_t *child, char *name, int namelen)
{
	pci_regspec_t *pci_rp;
	char	**unit_addr;
	uint_t n;
	int	bus, device, func;

	/*
	 * Pseudo nodes indicate a prototype node with per-instance
	 * properties to be merged into the real h/w device node.
	 * The interpretation of the unit-address is DD[,F]
	 * where DD is the device id and F is the function.
	 */
	if (ndi_dev_is_persistent_node(child) == 0) {
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS,
		    "unit-address", &unit_addr, &n) != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "cannot name node from %s.conf",
			    ddi_driver_name(child));
			return (DDI_FAILURE);
		}
		if (n != 1 || *unit_addr == NULL || **unit_addr == 0) {
			cmn_err(CE_WARN, "unit-address property in %s.conf"
			    " not well-formed", ddi_driver_name(child));
			ddi_prop_free(unit_addr);
			return (DDI_FAILURE);
		}
		(void) snprintf(name, namelen, "%s", *unit_addr);
		ddi_prop_free(unit_addr);
		return (DDI_SUCCESS);
	}

	/*
	 * Get the address portion of the node name based on
	 * the function and device number.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "reg", (int **)&pci_rp, &n) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	bus = PCI_REG_BUS_G(pci_rp->pci_phys_hi);
	device = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	func = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);
	ddi_prop_free(pci_rp);

	if (func != 0)
		(void) snprintf(name, namelen, "%x,%x", device, func);
	else
		(void) snprintf(name, namelen, "%x", device);

	cardbus_err(child, 8,
	    "cardbus_name_child: system init done [%x][%x][%x]"
	    " for %s [%s] nodeid: %x @%s\n",
	    bus, device, func,
	    ddi_get_name(child), ddi_get_name_addr(child),
	    DEVI(child)->devi_nodeid, name);

	return (DDI_SUCCESS);
}

static void
cardbus_removechild(dev_info_t *dip)
{
	struct cardbus_parent_private_data *ppd;

	ddi_set_name_addr(dip, NULL);
	impl_rem_dev_props(dip);
	ppd = (struct cardbus_parent_private_data *)ddi_get_parent_data(dip);
	if (ppd && (ppd->code == CB_PPD_CODE)) {
		if (ppd->ppd.par_reg && (ppd->ppd.par_nreg > 0))
			kmem_free((caddr_t)ppd->ppd.par_reg,
			    ppd->ppd.par_nreg * sizeof (struct regspec));
#ifdef sparc
		kmem_free(ppd, sizeof (struct cardbus_parent_private_data));
#elif defined(__x86) || defined(__amd64)
		kmem_free(ppd, sizeof (struct cardbus_parent_private_data) +
		    sizeof (struct intrspec));
#endif
		cardbus_err(dip, 5,
		    "cardbus_removechild: ddi_set_parent_data(NULL)\n");
		ddi_set_parent_data(dip, NULL);
	}
}


static char	cb_bnamestr[] = "binding_name";
static char	cb_venidstr[] = "VendorID";
static char	cb_devidstr[] = "DeviceID";
static char	cb_nnamestr[] = "nodename";

static cb_props_parse_tree_t cb_props_parse_tree[] = {
	{ cb_bnamestr, PT_STATE_STRING_VAR },
	{ cb_venidstr, PT_STATE_HEX_VAR },
	{ cb_devidstr, PT_STATE_HEX_VAR } };

static int
check_token(char *token, int *len)
{
	int	state = PT_STATE_DEC_VAR;
	int	sl = strlen(token), il = 1;
	char	c;

	if (token[0] == '0' && token[2] && (token[1] == 'x' || token[1] ==
	    'X')) {
		state = PT_STATE_HEX_VAR;
		token += 2;
	}

	while (c = *token++) {
		if (isdigit(c))
			continue;
		if (c == PARSE_COMMA) {
			il++;
			if (token[0] == '0' && token[2] && isx(token[1])) {
				state = PT_STATE_HEX_VAR;
				token += 2;
			}
			continue;
		}
		if (!isxdigit(c)) {
			*len = sl;
			return (PT_STATE_STRING_VAR);
		}
		state = PT_STATE_HEX_VAR;
	}
	*len = il;
	return (state);
}


static char *
find_token(char **cp, int *l, char *endc)
{
	char	*cpp = *cp;

	while ((**cp && (isalpha(**cp) || isxdigit(**cp) ||
	    (**cp == PARSE_UNDERSCORE) ||
	    (**cp == PARSE_COMMA) ||
	    (**cp == PARSE_DASH)))) {
		(*cp)++;
		(*l)++;
	}

	*endc = **cp;
	**cp = '\0';

	return (cpp);
}

static int
parse_token(char *token)
{
	cb_props_parse_tree_t *pt = cb_props_parse_tree;
	int	k = sizeof (cb_props_parse_tree) /
	    sizeof (cb_props_parse_tree_t);

	while (k--) {
		if (strcmp((char *)token, pt->token) == 0)
			return (pt->state);
		pt++;
	}

	return (PT_STATE_UNKNOWN);
}

static int
token_to_hex(char *token, unsigned *val, int len)
{
	uchar_t c;

	*val = 0;
	if (token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
		token += 2;
	}

	while (*token) {
		if (!isxdigit(*token)) {
			if (*token == PARSE_COMMA) {
				if (!(--len))
					return (1);
				val++;
				*val = 0;
				token++;
				if (token[0] == '0' && (token[1] == 'x' ||
				    token[1] == 'X')) {
					token += 2;
				}
				continue;
			}
			return (0);
		}
		c = toupper(*token);
		if (c >= 'A')
			c = c - 'A' + 10 + '0';
		*val = ((*val * 16) + (c - '0'));
		token++;
	}

	return (1);
}

static int
token_to_dec(char *token, unsigned *val, int len)
{
	*val = 0;

	while (*token) {
		if (!isdigit(*token)) {
			if (*token == PARSE_COMMA) {
				if (!(--len))
					return (1);
				val++;
				*val = 0;
				token++;
				continue;
			}
			return (0);
		}
		*val = ((*val * 10) + (*token - '0'));
		token++;
	}

	return (1);
}

static void
cardbus_add_prop(struct cb_deviceset_props *cdsp, int type, char *name,
    caddr_t vp, int len)
{
	ddi_prop_t *propp;
	int	pnlen = strlen(name) + 1;

	propp = (ddi_prop_t *)kmem_zalloc(sizeof (ddi_prop_t), KM_SLEEP);
	propp->prop_name = (char *)kmem_alloc(pnlen, KM_SLEEP);
	propp->prop_val = vp;
	bcopy(name, propp->prop_name, pnlen);
	propp->prop_len = len;
	propp->prop_flags = type;
	propp->prop_next = cdsp->prop_list;
	cdsp->prop_list = propp;
}

static void
cardbus_add_stringprop(struct cb_deviceset_props *cdsp, char *name,
    char *vp, int len)
{
	char	*nstr = kmem_zalloc(len + 1, KM_SLEEP);

	bcopy(vp, nstr, len);
	cardbus_add_prop(cdsp, DDI_PROP_TYPE_STRING, name, (caddr_t)nstr,
	    len + 1);
}

static void
cardbus_prop_free(ddi_prop_t *propp)
{
	if (propp->prop_len) {
		switch (propp->prop_flags) {
		case DDI_PROP_TYPE_STRING:
			kmem_free(propp->prop_val, propp->prop_len);
			break;
		case DDI_PROP_TYPE_INT:
			kmem_free(propp->prop_val,
			    propp->prop_len * sizeof (int));
			break;
		}
	}
	kmem_free(propp->prop_name, strlen(propp->prop_name) + 1);
	kmem_free(propp, sizeof (ddi_prop_t *));
}

static void
cardbus_devprops_free(struct cb_deviceset_props *cbdp)
{
	ddi_prop_t *propp, *npropp;

	propp = cbdp->prop_list;
	while (propp) {
		npropp = propp->prop_next;
		cardbus_prop_free(propp);
		propp = npropp;
	}
	if (cbdp->nodename)
		kmem_free(cbdp->nodename, strlen(cbdp->nodename) + 1);
	if (cbdp->binding_name)
		kmem_free(cbdp->binding_name, strlen(cbdp->binding_name) +
		    1);
	kmem_free(cbdp, sizeof (*cbdp));
}

/*
 * Format of "cb-device-init-props" property:
 * Anything before the semi-colon is an identifying equate, anything
 * after the semi-colon is a setting equate.
 *
 * "binding_name=xXxXxX VendorID=NNNN DeviceID=NNNN; nodename=NewName
 *					Prop=PropVal"
 *
 */
static int
cardbus_parse_devprop(cbus_t *cbp, char *cp)
{
	int	state = PT_STATE_TOKEN, qm = 0, em = 0, smc = 0, l = 0;
	int	length;
	char	*token = "beginning of line";
	char	*ptoken = NULL, *quote;
	char	eq = '\0';
	struct cb_deviceset_props *cdsp;

	cdsp = kmem_zalloc(sizeof (*cdsp), KM_SLEEP);
	length = strlen(cp);

	while ((*cp) && (l < length)) {
		/*
		 * Check for escaped characters
		 */
		if (*cp == PARSE_ESCAPE) {
			char	*cpp = cp, *cppp = cp + 1;

			em = 1;

			if (!qm) {
				cmn_err(CE_CONT, "cardbus_parse_devprop: "
				    "escape not allowed outside "
				    "of quotes at [%s]\n", token);
				return (DDI_FAILURE);

			} /* if (!qm) */

			while (*cppp)
				*cpp++ = *cppp++;

			l++;

			*cpp = '\0';
		} /* PARSE_ESCAPE */

		/*
		 * Check for quoted strings
		 */
		if (!em && (*cp == PARSE_QUOTE)) {
			qm ^= 1;
			if (qm) {
				quote = cp + 1;
			} else {
				*cp = '\0';
				if (state == PT_STATE_CHECK) {
					if (strcmp(token, cb_nnamestr) == 0) {
						cdsp->nodename = kmem_alloc(
						    strlen(quote) + 1,
						    KM_SLEEP);
						(void) strcpy(cdsp->nodename,
						    quote);
					} else
						cardbus_add_stringprop(cdsp,
						    token, quote,
						    strlen(quote));
				} else if (state != PT_STATE_STRING_VAR) {
					cmn_err(CE_CONT,
					    "cardbus_parse_devprop: "
					    "unexpected string [%s] after "
					    "[%s]\n", quote, token);
					return (DDI_FAILURE);
				} else {
					if (strcmp(token, cb_bnamestr) == 0) {
						cdsp->binding_name = kmem_alloc(
						    strlen(quote) + 1,
						    KM_SLEEP);
						(void) strcpy(
						    cdsp->binding_name, quote);
					}
				}
				state = PT_STATE_TOKEN;
			} /* if (qm) */
		} /* PARSE_QUOTE */

		em = 0;

		if (!qm && (*cp == PARSE_SEMICOLON)) {
			smc = 1;
		}

		/*
		 * Check for tokens
		 */
		else if (!qm && (isalpha(*cp) || isxdigit(*cp))) {
			int	tl;
			unsigned	*intp;
			ptoken = token;
			token = find_token(&cp, &l, &eq);

			switch (state) {
			case PT_STATE_TOKEN:
				if (smc) {
					if (eq == PARSE_EQUALS)
						state = PT_STATE_CHECK;
					else
						cardbus_add_prop(cdsp,
						    DDI_PROP_TYPE_ANY,
						    token,
						    NULL, 0);
				} else if (eq == PARSE_EQUALS)
					switch (state = parse_token(token)) {
					case PT_STATE_UNKNOWN:
						cmn_err(CE_CONT,
						    "cardbus_parse_devprop: "
						    "unknown token [%s]\n",
						    token);
						state = PT_STATE_TOKEN;
					} /* switch (parse_token) */
				else
					state = PT_STATE_TOKEN;
				break;

			case PT_STATE_CHECK:
				switch (check_token(token, &tl)) {
				case PT_STATE_DEC_VAR:
					intp = (unsigned *)kmem_alloc(
					    sizeof (int)*tl,
					    KM_SLEEP);
					if (token_to_dec(token, intp, tl))
						cardbus_add_prop(cdsp,
						    DDI_PROP_TYPE_INT, ptoken,
						    (caddr_t)intp, tl);
					else
						kmem_free(intp,
						    sizeof (int)*tl);
					break;
				case PT_STATE_HEX_VAR:
					intp = (unsigned *)kmem_alloc(
					    sizeof (int)*tl,
					    KM_SLEEP);
					if (token_to_hex(token, intp, tl))
						cardbus_add_prop(cdsp,
						    DDI_PROP_TYPE_INT,
						    ptoken,
						    (caddr_t)intp, tl);
					else
						kmem_free(intp,
						    sizeof (int)*tl);
					break;
				case PT_STATE_STRING_VAR:
					if (strcmp(ptoken, cb_nnamestr) == 0) {
						cdsp->nodename = kmem_alloc(
						    tl + 1, KM_SLEEP);
						(void) strcpy(cdsp->nodename,
						    token);
					} else
						cardbus_add_stringprop(cdsp,
						    ptoken, token, tl);
					break;
				}
				state = PT_STATE_TOKEN;
				break;

			case PT_STATE_HEX_VAR:
				if (strcmp(ptoken, cb_venidstr) == 0) {
					uint_t val;
					if (token_to_hex(token, &val, 1))
						cdsp->venid = val;
				} else if (strcmp(ptoken, cb_devidstr) == 0) {
					uint_t val;
					if (token_to_hex(token, &val, 1))
						cdsp->devid = val;
				}
				state = PT_STATE_TOKEN;
				break;

			case PT_STATE_DEC_VAR:
				if (strcmp(ptoken, cb_venidstr) == 0) {
					uint_t val;
					if (token_to_dec(token, &val, 1))
						cdsp->venid = val;
				} else if (strcmp(ptoken, cb_devidstr) == 0) {
					uint_t val;
					if (token_to_dec(token, &val, 1))
						cdsp->devid = val;
				}
				state = PT_STATE_TOKEN;
				break;

			case PT_STATE_STRING_VAR:
				if (strcmp(ptoken, cb_bnamestr) == 0) {
					cdsp->binding_name = kmem_alloc(
					    strlen(token) + 1, KM_SLEEP);
					(void) strcpy(cdsp->binding_name,
					    token);
				}
				state = PT_STATE_TOKEN;
				break;

			default:
				cmn_err(CE_CONT, "cardbus_parse_devprop: "
				    "unknown state machine state = %d\n",
				    state);

				cardbus_devprops_free(cdsp);
				return (DDI_FAILURE);
			} /* switch (state) */
			if (eq == PARSE_SEMICOLON)
				smc = 1;
		}
		cp++;
		l++;
	} /* while (*cp) */

	if (qm) {
		cmn_err(CE_CONT, "cb_props_parse_line: unterminated "
		    "string = [%s]\n", quote);
		cardbus_devprops_free(cdsp);
		return (DDI_FAILURE);
	}

	if (state != PT_STATE_TOKEN) {
		cmn_err(CE_CONT, "cardbus_parse_devprop: token [%s] "
		    "requires value\n", token);
		cardbus_devprops_free(cdsp);
		return (DDI_FAILURE);
	}

	if (cdsp->venid == 0 || cdsp->devid == 0) {
		cmn_err(CE_CONT, "cardbus_parse_devprop: Entry "
		    "requires VendorID and DeviceID\n");
		cardbus_devprops_free(cdsp);
		return (DDI_FAILURE);
	}

	cdsp->next = cbp->cb_dsp;
	cbp->cb_dsp = cdsp;
	return (DDI_SUCCESS);
}

static void
cardbus_device_props(cbus_t *cbp)
{
	char	**prop_array;
	uint_t i, n;

	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, cbp->cb_dip,
	    DDI_PROP_DONTPASS,
	    "cb-device-init-props", &prop_array,
	    &n) != DDI_PROP_SUCCESS)
		return;

	for (i = 0; i < n; i++)
		(void) cardbus_parse_devprop(cbp, prop_array[i]);

	ddi_prop_free(prop_array);
}

static int
cardbus_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	register dev_info_t *pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	int	rc;

	cardbus_err(dip, 9,
	    "cardbus_bus_map(dip=0x%p, rdip=0x%p)\n",
	    (void *) dip, (void *) rdip);

	if (pdip == NULL)
		return (DDI_FAILURE);

	/* A child has asked us to set something up */
	cardbus_err(dip, 9,
	    "cardbus_bus_map(%s) calling %s - 0x%p, "
	    "offset 0x%x, len 0x%x\n",
	    ddi_driver_name(rdip),
	    ddi_driver_name(pdip),
	    (void *) DEVI(pdip)->devi_ops->devo_bus_ops->bus_map,
	    (int)offset, (int)len);

	rc = (DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)
	    (pdip, rdip, mp, offset, len, vaddrp);
	/* rc = ddi_map(dip, mp, offset, len, vaddrp); */

	if (rc != DDI_SUCCESS) {
		cardbus_err(rdip, 8, "cardbus_bus_map failed, rc = %d\n", rc);
		return (DDI_FAILURE);
	} else {
		cardbus_err(rdip, 9, "cardbus_bus_map OK\n");
		return (DDI_SUCCESS);
	}
}

static void
pcirp2rp(const pci_regspec_t *pci_rp, struct regspec *rp)
{
	/* bus = PCI_REG_BUS_G(pci_rp->pci_phys_hi); */
	if (PCI_REG_ADDR_G(pci_rp->pci_phys_hi) ==
	    PCI_REG_ADDR_G(PCI_ADDR_IO)) {
		/* I/O */
		rp->regspec_bustype = 1;
	} else {
		/* memory */
		rp->regspec_bustype = 0;
	}
	rp->regspec_addr = pci_rp->pci_phys_low;
	rp->regspec_size = pci_rp->pci_size_low;
}

static int
cardbus_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg,
    ddi_dma_handle_t *handlep)
{
	dev_info_t *pdip = ddi_get_parent(dip);

	cardbus_err(dip, 10,
	    "cardbus_dma_allochdl(dip=0x%p, rdip=0x%p)\n",
	    (void *) dip, (void *) rdip);

	if (pdip == NULL)
		return (DDI_FAILURE);

	cardbus_err(dip, 11,
	    "cardbus_dma_allochdl calling %s - 0x%p\n",
	    ddi_driver_name(pdip),
	    (void *) DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_allochdl);

	return (ddi_dma_allochdl(dip, rdip, attr, waitfp, arg, handlep));
}

static int
cardbus_dma_freehdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle)
{
	dev_info_t *pdip = ddi_get_parent(dip);

	cardbus_err(dip, 10,
	    "cardbus_dma_freehdl(dip=0x%p, rdip=0x%p)\n",
	    (void *) dip, (void *) rdip);

	if (pdip == NULL)
		return (DDI_FAILURE);

	cardbus_err(dip, 11,
	    "cardbus_dma_freehdl calling %s - 0x%p\n",
	    ddi_driver_name(pdip),
	    (void *) DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_freehdl);

	return (ddi_dma_freehdl(dip, rdip, handle));
}

static int
cardbus_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, struct ddi_dma_req *dmareq,
    ddi_dma_cookie_t *cp, uint_t *ccountp)
{
	dev_info_t *pdip = ddi_get_parent(dip);

	cardbus_err(dip, 10,
	    "cardbus_dma_bindhdl(dip=0x%p, rdip=0x%p)\n",
	    (void *) dip, (void *) rdip);

	if (pdip == NULL)
		return (DDI_FAILURE);

	cardbus_err(dip, 11,
	    "cardbus_dma_bindhdl calling %s - 0x%p\n",
	    ddi_driver_name(pdip),
	    (void *) DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_bindhdl);

	return (DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_bindhdl(pdip,
	    rdip, handle, dmareq, cp, ccountp));
}

static int
cardbus_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle)
{
	dev_info_t *pdip = ddi_get_parent(dip);

	cardbus_err(dip, 10,
	    "cardbus_dma_unbindhdl(dip=0x%p, rdip=0x%p)\n",
	    (void *) dip, (void *) rdip);

	if (pdip == NULL)
		return (DDI_FAILURE);

	cardbus_err(dip, 11,
	    "cardbus_dma_unbindhdl calling %s - 0x%p\n",
	    ddi_driver_name(pdip),
	    (void *) DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_unbindhdl);

	return (DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_unbindhdl(pdip,
	    rdip, handle));
}

static int
cardbus_dma_flush(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, off_t off, size_t len,
    uint_t cache_flags)
{
	dev_info_t *pdip = ddi_get_parent(dip);

	cardbus_err(dip, 10,
	    "cardbus_dma_flush(dip=0x%p, rdip=0x%p)\n",
	    (void *) dip, (void *) rdip);

	if (pdip == NULL)
		return (DDI_FAILURE);

	cardbus_err(dip, 11,
	    "cardbus_dma_flush calling %s - 0x%p\n",
	    ddi_driver_name(pdip),
	    (void *) DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_flush);

	return (DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_flush(pdip, rdip,
	    handle, off, len, cache_flags));
}

static int
cardbus_dma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, uint_t win, off_t *offp,
    size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	dev_info_t *pdip = ddi_get_parent(dip);
	cardbus_err(dip, 6,
	    "cardbus_dma_win(dip=0x%p, rdip=0x%p)\n",
	    (void *) dip, (void *) rdip);

	if (pdip == NULL)
		return (DDI_FAILURE);

	cardbus_err(dip, 8,
	    "cardbus_dma_win calling %s - 0x%p\n",
	    ddi_driver_name(pdip),
	    (void *) DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_win);

	return (DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_win(pdip, rdip,
	    handle, win, offp, lenp, cookiep, ccountp));
}

static int
cardbus_dma_map(dev_info_t *dip, dev_info_t *rdip,
    struct ddi_dma_req *dmareqp, ddi_dma_handle_t *handlep)
{
	dev_info_t *pdip = ddi_get_parent(dip);

	cardbus_err(dip, 10,
	    "cardbus_dma_map(dip=0x%p, rdip=0x%p)\n",
	    (void *) dip, (void *) rdip);

	if (pdip == NULL)
		return (DDI_FAILURE);

	cardbus_err(dip, 11,
	    "cardbus_dma_map calling %s - 0x%p\n",
	    ddi_driver_name(pdip),
	    (void *) DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_map);

	return (DEVI(pdip)->devi_ops->devo_bus_ops->bus_dma_map(pdip, rdip,
	    dmareqp, handlep));
}

static int
cardbus_get_eventcookie(dev_info_t *dip, dev_info_t *rdip,
    char *eventname, ddi_eventcookie_t *cookiep)
{
	cbus_t *cbp;
	int	cb_instance;
	int	rc;

	/*
	 * get the soft state structure for the bus instance.
	 */
	cb_instance = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cbus-instance", -1);
	ASSERT(cb_instance >= 0);
	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state, cb_instance);

	cardbus_err(dip, 6, "cardbus_get_eventcookie %s\n", eventname);

	ASSERT(number_of_cardbus_cards != 0);

	if (cbp->cb_ndi_event_hdl == NULL) {
		/*
		 * We can't handle up (probably called at the attachment
		 * point) so pass it on up
		 */
		dev_info_t *pdip = ddi_get_parent(dip);
		cardbus_err(dip, 8,
		    "cardbus_get_eventcookie calling %s - 0x%p\n",
		    ddi_driver_name(pdip),
		    (void *)
		    DEVI(pdip)->devi_ops->devo_bus_ops->bus_get_eventcookie);
		return (DEVI(pdip)->devi_ops->devo_bus_ops->
		    bus_get_eventcookie(pdip, rdip, eventname, cookiep));
	}

	cardbus_err(dip, 8,
	    "cardbus_get_eventcookie calling ndi_event_retrieve_cookie\n");

	rc = ndi_event_retrieve_cookie(cbp->cb_ndi_event_hdl, rdip, eventname,
	    cookiep, NDI_EVENT_NOPASS);

	cardbus_err(dip, 7,
	    "cardbus_get_eventcookie rc %d cookie %p\n", rc, (void *)*cookiep);
	return (rc);
}

static int
cardbus_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t cookie, void (*callback)(dev_info_t *dip,
    ddi_eventcookie_t cookie, void *arg, void *bus_impldata),
    void *arg, ddi_callback_id_t *cb_id)
{
	cbus_t *cbp;
	int	cb_instance;
	int	rc;

	/*
	 * get the soft state structure for the bus instance.
	 */
	cb_instance = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cbus-instance", -1);
	ASSERT(cb_instance >= 0);
	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state, cb_instance);

	cardbus_err(dip, 6, "cardbus_add_eventcall\n");

	ASSERT(number_of_cardbus_cards != 0);

	if (cbp->cb_ndi_event_hdl == NULL) {
		/*
		 * We can't handle up (probably called at the attachment
		 * point) so pass it on up
		 */
		dev_info_t *pdip = ddi_get_parent(dip);
		cardbus_err(dip, 8,
		    "cardbus_add_eventcall calling %s - 0x%p\n",
		    ddi_driver_name(pdip),
		    (void *)
		    DEVI(pdip)->devi_ops->devo_bus_ops->bus_add_eventcall);
		return (DEVI(pdip)->devi_ops->devo_bus_ops->
		    bus_add_eventcall(pdip, rdip, cookie, callback,
		    arg, cb_id));
	}

	cardbus_err(dip, 8,
	    "cardbus_add_eventcall calling ndi_event_add_callback\n");

	rc = ndi_event_add_callback(cbp->cb_ndi_event_hdl, rdip, cookie,
	    callback, arg, NDI_EVENT_NOPASS, cb_id);
	cardbus_err(dip, 7,
	    "cardbus_add_eventcall rc %d cookie %p\n", rc, (void *)cookie);
	return (rc);
}

static int
cardbus_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{
	cbus_t *cbp;
	int	cb_instance;

	/*
	 * get the soft state structure for the bus instance.
	 */
	cb_instance = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cbus-instance", -1);
	ASSERT(cb_instance >= 0);
	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state, cb_instance);

	cardbus_err(dip, 6, "cardbus_remove_eventcall\n");

	ASSERT(number_of_cardbus_cards != 0);

	if (cbp->cb_ndi_event_hdl == NULL) {
		/*
		 * We can't handle up (probably called at the attachment
		 * point) so pass it on up
		 */
		dev_info_t *pdip = ddi_get_parent(dip);
		cardbus_err(dip, 8,
		    "cardbus_remove_eventcall calling %s - 0x%p\n",
		    ddi_driver_name(pdip),
		    (void *)
		    DEVI(pdip)->devi_ops->devo_bus_ops->bus_remove_eventcall);
		return (DEVI(pdip)->devi_ops->devo_bus_ops->
		    bus_remove_eventcall(pdip, cb_id));
	}

	return (ndi_event_remove_callback(cbp->cb_ndi_event_hdl, cb_id));
}

static int
cardbus_post_event(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t cookie, void *bus_impldata)
{
	_NOTE(ARGUNUSED(rdip, cookie, bus_impldata))
	cardbus_err(dip, 1, "cardbus_post_event()\n");
	return (DDI_FAILURE);
}

static int cardbus_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip,
		ddi_intr_handle_impl_t *hdlp);
static int cardbus_add_intr_impl(dev_info_t *dip, dev_info_t *rdip,
		ddi_intr_handle_impl_t *hdlp);
static int cardbus_enable_intr_impl(dev_info_t *dip, dev_info_t *rdip,
		ddi_intr_handle_impl_t *hdlp);
static int cardbus_disable_intr_impl(dev_info_t *dip, dev_info_t *rdip,
		ddi_intr_handle_impl_t *hdlp);

static int
cardbus_get_pil(dev_info_t *dip)
{
	return ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupt-priorities", 6);
}

static int
cardbus_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int ret = DDI_SUCCESS;

#if defined(CARDBUS_DEBUG)
	cardbus_err(dip, 8, "cardbus_intr_ops() intr_op=%d\n", (int)intr_op);
#endif

	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		*(int *)result = DDI_INTR_FLAG_LEVEL;
		break;
	case DDI_INTROP_ALLOC:
		*(int *)result = hdlp->ih_scratch1;
		break;
	case DDI_INTROP_FREE:
		break;
	case DDI_INTROP_GETPRI:
		*(int *)result = hdlp->ih_pri ?
		    hdlp->ih_pri : cardbus_get_pil(dip);
		break;
	case DDI_INTROP_SETPRI:
		break;
	case DDI_INTROP_ADDISR:
	case DDI_INTROP_REMISR:
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED) {
			cardbus_err(dip, 1, "Only fixed interrupts\n");
			return (DDI_FAILURE);
		}
		break;
	case DDI_INTROP_ENABLE:
		ret = cardbus_enable_intr_impl(dip, rdip, hdlp);
		break;
	case DDI_INTROP_DISABLE:
		ret = cardbus_disable_intr_impl(dip, rdip, hdlp);
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
#ifdef sparc
		*(int *)result = i_ddi_get_intx_nintrs(rdip);
#else
		*(int *)result = 1;
#endif
		break;
	case DDI_INTROP_SUPPORTED_TYPES:
		*(int *)result = DDI_INTR_TYPE_FIXED;
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

static int
cardbus_enable_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	anp_t *anp = (anp_t *)ddi_get_driver_private(dip);
	set_irq_handler_t sih;
	uint_t socket = 0; /* We only support devices */
			    /* with one socket per function */

	ASSERT(anp != NULL);

	cardbus_err(dip, 9,
	    "cardbus_enable_intr_impl, intr=0x%p, arg1=0x%p, arg2=0x%p"
	    "rdip=0x%p(%s)\n",
	    (void *) hdlp->ih_cb_func,
	    hdlp->ih_cb_arg1, hdlp->ih_cb_arg2,
	    (void *) rdip, ddi_driver_name(rdip));

	if (hdlp->ih_type != DDI_INTR_TYPE_FIXED) {
		cardbus_err(dip, 1, "Only fixed interrupts\n");
		return (DDI_FAILURE);
	}

	sih.socket = socket;
	sih.handler_id = (unsigned)(long)rdip;
	sih.handler = (f_tt *)(uintptr_t)hdlp->ih_cb_func;
	sih.arg1 = hdlp->ih_cb_arg1;
	sih.arg2 = hdlp->ih_cb_arg2;
	sih.irq = cardbus_get_pil(dip);

	if ((*anp->an_if->pcif_set_interrupt)(dip, &sih) != SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static int
cardbus_disable_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	anp_t *anp = (anp_t *)ddi_get_driver_private(dip);
	clear_irq_handler_t cih;
	uint_t socket = 0; /* We only support devices with 1 socket per */
			    /* function. */

	ASSERT(anp != NULL);

	cardbus_err(dip, 9,
	    "cardbus_disable_intr_impl, intr=0x%p, arg1=0x%p, arg2=0x%p"
	    "rdip=0x%p(%s%d)\n",
	    (void *) hdlp->ih_cb_func,
	    hdlp->ih_cb_arg1, hdlp->ih_cb_arg2,
	    (void *) rdip, ddi_driver_name(rdip), ddi_get_instance(rdip));

	if (hdlp->ih_type != DDI_INTR_TYPE_FIXED) {
		cardbus_err(dip, 1, "Only fixed interrupts\n");
		return (DDI_FAILURE);
	}

	cih.socket = socket;
	cih.handler_id = (unsigned)(long)rdip;
	cih.handler = (f_tt *)(uintptr_t)hdlp->ih_cb_func;

	if ((*anp->an_if->pcif_clr_interrupt)(dip, &cih) != SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

#if defined(CARDBUS_DEBUG)
static int	cardbus_do_pprintf = 0;
#endif

/*PRINTFLIKE3*/
void
cardbus_err(dev_info_t *dip, int level, const char *fmt, ...)
{
	if (cardbus_debug && (level <= cardbus_debug)) {
		va_list adx;
		int	instance;
		char	buf[256];
		const char	*name;
		char	*nl = "";
#if !defined(CARDBUS_DEBUG)
		int	ce;
		char	qmark = 0;

		if (level <= 3)
			ce = CE_WARN;
		else
			ce = CE_CONT;
		if (level == 4)
			qmark = 1;
#endif

		if (dip) {
			instance = ddi_get_instance(dip);
			/* name = ddi_binding_name(dip); */
			name = ddi_driver_name(dip);
		} else {
			instance = 0;
			name = "";
		}

		va_start(adx, fmt);
		/* vcmn_err(ce, fmt, adx); */
		/* vprintf(fmt, adx); */
		/* prom_vprintf(fmt, adx); */
		(void) vsprintf(buf, fmt, adx);
		va_end(adx);

		if (buf[strlen(buf) - 1] != '\n')
			nl = "\n";

#if defined(CARDBUS_DEBUG)
		if (cardbus_do_pprintf) {
			if (dip) {
				if (instance >= 0)
					prom_printf("%s(%d),0x%p: %s%s",
					    name, instance, (void *)dip,
					    buf, nl);
				else
					prom_printf("%s,0x%p: %s%s", name,
					    (void *)dip, buf, nl);
			} else
				prom_printf("%s%s", buf, nl);
		} else {
			if (dip) {
				if (instance >= 0)
					cmn_err(CE_CONT, "%s(%d),0x%p: %s%s",
					    name, instance, (void *)dip,
					    buf, nl);
				else
					cmn_err(CE_CONT, "%s,0x%p: %s%s",
					    name, (void *)dip, buf, nl);
			} else
				cmn_err(CE_CONT, "%s%s", buf, nl);
		}
#else
		if (dip)
			cmn_err(ce, qmark ? "?%s%d: %s%s" : "%s%d: %s%s",
			    name, instance, buf, nl);
		else
			cmn_err(ce, qmark ? "?%s%s" : "%s%s", buf, nl);
#endif
	}
}

static void cardbus_expand_busrange(dev_info_t *dip)
{
	dev_info_t *pdip;
	cardbus_bus_range_t *bus_range;
	int len;

	pdip = ddi_get_parent(dip);

	if (ddi_getlongprop(DDI_DEV_T_ANY, pdip, DDI_PROP_DONTPASS, "bus-range",
	    (caddr_t)&bus_range, &len) == DDI_PROP_SUCCESS) {
		ndi_ra_request_t req;
		uint64_t next_bus, blen;
		uint32_t ret;
		ddi_acc_handle_t handle;

		if (bus_range->lo != bus_range->hi)
			cardbus_err(pdip, 1, "cardbus_expand_busrange: "
			    "%u -> %u\n", bus_range->lo, bus_range->hi);
		else {

			bzero((caddr_t)&req, sizeof (ndi_ra_request_t));
			req.ra_addr = bus_range->lo + 1;
			req.ra_flags = NDI_RA_ALLOC_SPECIFIED;
			req.ra_len = 12;

			while ((req.ra_len > 0) &&
			    (ret = ndi_ra_alloc(ddi_get_parent(pdip), &req,
			    &next_bus, &blen, NDI_RA_TYPE_PCI_BUSNUM,
			    NDI_RA_PASS)) != NDI_SUCCESS)
				req.ra_len--;

			if (ret != NDI_SUCCESS) {
				cardbus_err(pdip, 1, "cardbus_expand_busrange: "
				    "fail to allocate bus number\n");
				goto exit;
			}

			bus_range->hi = bus_range->lo + req.ra_len;
			if (ndi_prop_update_int_array(DDI_DEV_T_NONE, pdip,
			    "bus-range", (int *)bus_range, 2) != DDI_SUCCESS) {
				cardbus_err(pdip, 1, "cardbus_expand_busrange: "
				    "fail to update bus-range property\n");
				goto exit;
			}

			if (pci_config_setup(pdip, &handle) != DDI_SUCCESS) {
				cardbus_err(pdip, 1, "cardbus_expand_busrange: "
				    "fail to pci_config_setup\n");
				goto exit;
			}

			pci_config_put8(handle, PCI_BCNF_SECBUS, bus_range->lo);
			pci_config_put8(handle, PCI_BCNF_SUBBUS, bus_range->hi);

			cardbus_err(pdip, 1, "cardbus_expand_busrange: "
			    "parent dip %u -> %u\n",
			    pci_config_get8(handle, PCI_BCNF_SECBUS),
			    pci_config_get8(handle, PCI_BCNF_SUBBUS));
			pci_config_teardown(&handle);

			if (ndi_ra_map_setup(pdip, NDI_RA_TYPE_PCI_BUSNUM)
			    != NDI_SUCCESS) {
				cardbus_err(pdip, 1, "cardbus_expand_busrange: "
				    "fail to ndi_ra_map_setup of bus number\n");
				goto exit;
			}

			(void) ndi_ra_free(pdip,
			    (uint64_t)bus_range->lo + 1, req.ra_len,
			    NDI_RA_TYPE_PCI_BUSNUM, 0);
		}

		bzero((caddr_t)&req, sizeof (ndi_ra_request_t));
		req.ra_len = 2;

		while ((req.ra_len > 0) &&
		    (ret = ndi_ra_alloc(pdip, &req,
		    &next_bus, &blen, NDI_RA_TYPE_PCI_BUSNUM,
		    0)) != NDI_SUCCESS)
			req.ra_len--;

		cardbus_err(dip, 1, "cardbus_expand_busrange: "
		    "cardbus dip base %u length %d\n",
		    (int)next_bus, (int)req.ra_len);

		if (ret != NDI_SUCCESS) {
			cardbus_err(dip, 1, "cardbus_expand_busrange: "
			    "fail to allocate bus number of length %d "
			    "from parent\n",
			    (int)req.ra_len);
			goto exit;
		}

		if (ndi_ra_map_setup(dip, NDI_RA_TYPE_PCI_BUSNUM)
		    != NDI_SUCCESS) {
			cardbus_err(dip, 1, "cardbus_expand_busrange: "
			    "fail to ndi_ra_map_setup of bus numbers\n");
			goto exit;
		}

		(void) ndi_ra_free(dip,
		    (uint64_t)next_bus, req.ra_len,
		    NDI_RA_TYPE_PCI_BUSNUM, 0);
exit:
		kmem_free(bus_range, len);

	} else
		cardbus_err(pdip, 1, "cardbus_expand_busrange: "
		    "parent dip doesn't have busrange prop\n");
}
