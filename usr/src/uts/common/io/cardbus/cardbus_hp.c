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
 * Cardbus hotplug module
 */

#include <sys/open.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunndi.h>

#include <sys/note.h>

#include <sys/pci.h>

#include <sys/hotplug/hpcsvc.h>
#include <sys/hotplug/pci/pcicfg.h>
#include <sys/pcic_reg.h>

#include "cardbus.h"
#include "cardbus_hp.h"
#include "cardbus_cfg.h"

/*
 * ************************************************************************
 * *** Implementation specific data structures/definitions.             ***
 * ************************************************************************
 */

#ifndef HPC_MAX_OCCUPANTS
#define	HPC_MAX_OCCUPANTS 8
typedef struct hpc_occupant_info {
	int	i;
	char	*id[HPC_MAX_OCCUPANTS];
} hpc_occupant_info_t;
#endif

#define	PCICFG_FLAGS_CONTINUE   0x1

#define	PCICFG_OP_ONLINE	0x1
#define	PCICFG_OP_OFFLINE	0x0

#define	CBHP_DEVCTL_MINOR	255

#define	AP_MINOR_NUM_TO_CB_INSTANCE(x)	((x) & 0xFF)
#define	AP_MINOR_NUM(x)		(((uint_t)(3) << 8) | ((x) & 0xFF))
#define	AP_IS_CB_MINOR(x)	(((x)>>8) == (3))

extern int cardbus_debug;
extern int number_of_cardbus_cards;

static int cardbus_autocfg_enabled = 1;	/* auto config is enabled by default */

/* static functions */
static int cardbus_event_handler(caddr_t slot_arg, uint_t event_mask);
static int cardbus_pci_control(caddr_t ops_arg, hpc_slot_t slot_hdl,
				int request, caddr_t arg);
static int cardbus_new_slot_state(dev_info_t *dip, hpc_slot_t hdl,
				hpc_slot_info_t *slot_info, int slot_state);
static int cardbus_list_occupants(dev_info_t *dip, void *hdl);
static void create_occupant_props(dev_info_t *self, dev_t dev);
static void delete_occupant_props(dev_info_t *dip, dev_t dev);
static int cardbus_configure_ap(cbus_t *cbp);
static int cardbus_unconfigure_ap(cbus_t *cbp);
static int cbus_unconfigure(dev_info_t *devi, int prim_bus);
void cardbus_dump_pci_config(dev_info_t *dip);
void cardbus_dump_pci_node(dev_info_t *dip);

int
cardbus_init_hotplug(cbus_t *cbp)
{
	char tbuf[MAXNAMELEN];
	hpc_slot_info_t	slot_info;
	hpc_slot_ops_t	*slot_ops;
	hpc_slot_t	slhandle;	/* HPS slot handle */

	/*
	 *  register the bus instance with the HPS framework.
	 */
	if (hpc_nexus_register_bus(cbp->cb_dip,
	    cardbus_new_slot_state, 0) != 0) {
		cmn_err(CE_WARN, "%s%d: failed to register the bus with HPS\n",
		    ddi_driver_name(cbp->cb_dip), cbp->cb_instance);
		return (DDI_FAILURE);
	}

	(void) sprintf(cbp->ap_id, "slot%d", cbp->cb_instance);
	(void) ddi_pathname(cbp->cb_dip, tbuf);
	cbp->nexus_path = kmem_alloc(strlen(tbuf) + 1, KM_SLEEP);
	(void) strcpy(cbp->nexus_path, tbuf);
	cardbus_err(cbp->cb_dip, 8,
	    "cardbus_init_hotplug: nexus_path set to %s", cbp->nexus_path);

	slot_ops = hpc_alloc_slot_ops(KM_SLEEP);
	cbp->slot_ops = slot_ops;

	/*
	 * Fill in the slot information structure that
	 * describes the slot.
	 */
	slot_info.version = HPC_SLOT_INFO_VERSION;
	slot_info.slot_type = HPC_SLOT_TYPE_PCI;
	slot_info.slot.pci.device_number = 0;
	slot_info.slot.pci.slot_capabilities = 0;

	(void) strcpy(slot_info.slot.pci.slot_logical_name, cbp->ap_id);

	slot_ops->hpc_version = HPC_SLOT_OPS_VERSION;
	slot_ops->hpc_op_connect = NULL;
	slot_ops->hpc_op_disconnect = NULL;
	slot_ops->hpc_op_insert = NULL;
	slot_ops->hpc_op_remove = NULL;
	slot_ops->hpc_op_control = cardbus_pci_control;

	if (hpc_slot_register(cbp->cb_dip, cbp->nexus_path, &slot_info,
	    &slhandle, slot_ops, (caddr_t)cbp, 0) != 0) {
		/*
		 * If the slot can not be registered,
		 * then the slot_ops need to be freed.
		 */
		cmn_err(CE_WARN,
		    "cbp%d Unable to Register Slot %s", cbp->cb_instance,
		    slot_info.slot.pci.slot_logical_name);

		(void) hpc_nexus_unregister_bus(cbp->cb_dip);
		hpc_free_slot_ops(slot_ops);
		cbp->slot_ops = NULL;
		return (DDI_FAILURE);
	}

	ASSERT(slhandle == cbp->slot_handle);

	cardbus_err(cbp->cb_dip, 8,
	    "cardbus_init_hotplug: slot_handle 0x%p", cbp->slot_handle);
	return (DDI_SUCCESS);
}

static int
cardbus_event_handler(caddr_t slot_arg, uint_t event_mask)
{
	int ap_minor = (int)((uintptr_t)slot_arg);
	cbus_t *cbp;
	int cb_instance;
	int rv = HPC_EVENT_CLAIMED;

	cb_instance = AP_MINOR_NUM_TO_CB_INSTANCE(ap_minor);

	ASSERT(cb_instance >= 0);
	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state, cb_instance);
	mutex_enter(&cbp->cb_mutex);

	switch (event_mask) {

	case HPC_EVENT_SLOT_INSERTION:
		/*
		 * A card is inserted in the slot. Just report this
		 * event and return.
		 */
		cardbus_err(cbp->cb_dip, 7,
		    "cardbus_event_handler(%s%d): card is inserted",
		    ddi_driver_name(cbp->cb_dip), cbp->cb_instance);

		break;

	case HPC_EVENT_SLOT_CONFIGURE:
		/*
		 * Configure the occupant that is just inserted in the slot.
		 * The receptacle may or may not be in the connected state. If
		 * the receptacle is not connected and the auto configuration
		 * is enabled on this slot then connect the slot. If auto
		 * configuration is enabled then configure the card.
		 */
		if (!(cbp->auto_config)) {
			/*
			 * auto configuration is disabled.
			 */
			cardbus_err(cbp->cb_dip, 7,
			    "cardbus_event_handler(%s%d): "
			    "SLOT_CONFIGURE event occured (slot %s)",
			    ddi_driver_name(cbp->cb_dip), cbp->cb_instance,
			    cbp->name);

			break;
		}

		cardbus_err(cbp->cb_dip, 7,
		    "cardbus_event_handler(%s%d): configure event",
		    ddi_driver_name(cbp->cb_dip), cbp->cb_instance);

		if (cbp->ostate != AP_OSTATE_UNCONFIGURED) {
			cmn_err(CE_WARN, "!slot%d already configured\n",
			    cbp->cb_instance);
			break;
		}

		/*
		 * Auto configuration is enabled. First, make sure the
		 * receptacle is in the CONNECTED state.
		 */
		if ((rv = hpc_nexus_connect(cbp->slot_handle,
		    NULL, 0)) == HPC_SUCCESS) {
			cbp->rstate = AP_RSTATE_CONNECTED; /* record rstate */
		}

		if (cardbus_configure_ap(cbp) == HPC_SUCCESS)
			create_occupant_props(cbp->cb_dip, makedevice(
			    ddi_driver_major((cbp->cb_dip)), ap_minor));
		else
			rv = HPC_ERR_FAILED;

		break;

	case HPC_EVENT_SLOT_UNCONFIGURE:
		/*
		 * Unconfigure the occupant in this slot.
		 */
		if (!(cbp->auto_config)) {
			/*
			 * auto configuration is disabled.
			 */
			cardbus_err(cbp->cb_dip, 7,
			    "cardbus_event_handler(%s%d): "
			    "SLOT_UNCONFIGURE event"
			    " occured - auto-conf disabled (slot %s)",
			    ddi_driver_name(cbp->cb_dip), cbp->cb_instance,
			    cbp->name);

			break;
		}

		cardbus_err(cbp->cb_dip, 7,
		    "cardbus_event_handler(%s%d): SLOT_UNCONFIGURE event"
		    " occured (slot %s)",
		    ddi_driver_name(cbp->cb_dip), cbp->cb_instance,
		    cbp->name);

		if (cardbus_unconfigure_ap(cbp) != HPC_SUCCESS)
			rv = HPC_ERR_FAILED;

		DEVI(cbp->cb_dip)->devi_ops->devo_bus_ops = cbp->orig_bopsp;
		--number_of_cardbus_cards;
		break;

	case HPC_EVENT_SLOT_REMOVAL:
		/*
		 * Card is removed from the slot. The card must have been
		 * unconfigured before this event.
		 */
		if (cbp->ostate != AP_OSTATE_UNCONFIGURED) {
			cardbus_err(cbp->cb_dip, 1,
			    "cardbus_event_handler(%s%d): "
			    "card is removed from"
			    " the slot %s before doing unconfigure!!",
			    ddi_driver_name(cbp->cb_dip), cbp->cb_instance,
			    cbp->name);

			break;
		}

		cardbus_err(cbp->cb_dip, 7,
		    "cardbus_event_handler(%s%d): "
		    "card is removed from the slot %s",
		    ddi_driver_name(cbp->cb_dip), cbp->cb_instance,
		    cbp->name);

		break;

	case HPC_EVENT_SLOT_POWER_ON:
		/*
		 * Slot is connected to the bus. i.e the card is powered
		 * on.
		 */
		cardbus_err(cbp->cb_dip, 7,
		    "cardbus_event_handler(%s%d): "
		    "card is powered on in the slot %s",
		    ddi_driver_name(cbp->cb_dip), cbp->cb_instance,
		    cbp->name);

		cbp->rstate = AP_RSTATE_CONNECTED; /* record rstate */

		break;

	case HPC_EVENT_SLOT_POWER_OFF:
		/*
		 * Slot is disconnected from the bus. i.e the card is powered
		 * off.
		 */
		cardbus_err(cbp->cb_dip, 7,
		    "cardbus_event_handler(%s%d): "
		    "card is powered off in the slot %s",
		    ddi_driver_name(cbp->cb_dip), cbp->cb_instance,
		    cbp->name);

		cbp->rstate = AP_RSTATE_DISCONNECTED; /* record rstate */

		break;

	default:
		cardbus_err(cbp->cb_dip, 4,
		    "cardbus_event_handler(%s%d): "
		    "unknown event %x for this slot %s",
		    ddi_driver_name(cbp->cb_dip), cbp->cb_instance,
		    event_mask, cbp->name);

		break;
	}

	mutex_exit(&cbp->cb_mutex);

	return (rv);
}

static int
cardbus_pci_control(caddr_t ops_arg, hpc_slot_t slot_hdl, int request,
    caddr_t arg)
{
	cbus_t *cbp;
	int rval = HPC_SUCCESS;
	hpc_led_info_t *hpc_led_info;

	_NOTE(ARGUNUSED(slot_hdl))

	cbp = (cbus_t *)ops_arg;
	ASSERT(mutex_owned(&cbp->cb_mutex));

	switch (request) {

	case HPC_CTRL_GET_SLOT_STATE: {
		hpc_slot_state_t	*hpc_slot_state;

		hpc_slot_state = (hpc_slot_state_t *)arg;

		cardbus_err(cbp->cb_dip, 7,
		    "cardbus_pci_control() - "
		    "HPC_CTRL_GET_SLOT_STATE hpc_slot_state=0x%p",
		    (void *) hpc_slot_state);

		if (cbp->card_present)
			*hpc_slot_state = HPC_SLOT_CONNECTED;
		else
			*hpc_slot_state = HPC_SLOT_EMPTY;

		break;
	}

	case HPC_CTRL_GET_BOARD_TYPE: {
		hpc_board_type_t	*hpc_board_type;

		hpc_board_type = (hpc_board_type_t *)arg;

		cardbus_err(cbp->cb_dip, 7,
		    "cardbus_pci_control() - HPC_CTRL_GET_BOARD_TYPE");

		/*
		 * The HPC driver does not know what board type
		 * is plugged in.
		 */
		*hpc_board_type = HPC_BOARD_PCI_HOTPLUG;

		break;
	}

	case HPC_CTRL_DEV_CONFIGURED:
	case HPC_CTRL_DEV_UNCONFIGURED:
		cardbus_err(cbp->cb_dip, 5,
		    "cardbus_pci_control() - HPC_CTRL_DEV_%sCONFIGURED",
		    request == HPC_CTRL_DEV_UNCONFIGURED ? "UN" : "");
		break;

	case HPC_CTRL_GET_LED_STATE:
		hpc_led_info = (hpc_led_info_t *)arg;
		cardbus_err(cbp->cb_dip, 5,
		    "cardbus_pci_control() - HPC_CTRL_GET_LED_STATE "
		    "led %d is %d",
		    hpc_led_info->led, cbp->leds[hpc_led_info->led]);

		hpc_led_info->state = cbp->leds[hpc_led_info->led];
		break;

	case HPC_CTRL_SET_LED_STATE:
		hpc_led_info = (hpc_led_info_t *)arg;

		cardbus_err(cbp->cb_dip, 4,
		    "cardbus_pci_control() - HPC_CTRL_SET_LED_STATE "
		    "led %d to %d",
		    hpc_led_info->led, hpc_led_info->state);

		cbp->leds[hpc_led_info->led] = hpc_led_info->state;
		break;

	case HPC_CTRL_ENABLE_AUTOCFG:
		cardbus_err(cbp->cb_dip, 5,
		    "cardbus_pci_control() - HPC_CTRL_ENABLE_AUTOCFG");

		/*
		 * Cardbus ALWAYS does auto config, from the slots point of
		 * view this is turning on the card and making sure it's ok.
		 * This is all done by the bridge driver before we see any
		 * indication.
		 */
		break;

	case HPC_CTRL_DISABLE_AUTOCFG:
		cardbus_err(cbp->cb_dip, 5,
		    "cardbus_pci_control() - HPC_CTRL_DISABLE_AUTOCFG");
		break;

	case HPC_CTRL_DISABLE_ENUM:
	case HPC_CTRL_ENABLE_ENUM:
	default:
		rval = HPC_ERR_NOTSUPPORTED;
		break;
	}

	return (rval);
}

/*
 * cardbus_new_slot_state()
 *
 * This function is called by the HPS when it finds a hot plug
 * slot is added or being removed from the hot plug framework.
 * It returns 0 for success and HPC_ERR_FAILED for errors.
 */
static int
cardbus_new_slot_state(dev_info_t *dip, hpc_slot_t hdl,
    hpc_slot_info_t *slot_info, int slot_state)
{
	int cb_instance;
	cbus_t *cbp;
	int ap_minor;
	int rv = 0;

	cardbus_err(dip, 8,
	    "cardbus_new_slot_state: slot_handle 0x%p", hdl);

	/*
	 * get the soft state structure for the bus instance.
	 */
	cb_instance = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cbus-instance", -1);
	ASSERT(cb_instance >= 0);
	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state, cb_instance);

	mutex_enter(&cbp->cb_mutex);

	switch (slot_state) {

	case HPC_SLOT_ONLINE:
		/*
		 * Make sure the slot is not already ONLINE
		 */
		if (cbp->slot_handle != NULL) {
			cardbus_err(dip, 4,
			    "cardbus_new_slot_state: "
			    "cardbus already ONLINE!!");
			rv = HPC_ERR_FAILED;
			break;
		}

		/*
		 * Add the hot plug slot to the bus.
		 */

		/* create the AP minor node */
		ap_minor = AP_MINOR_NUM(cb_instance);
		if (ddi_create_minor_node(dip, slot_info->pci_slot_name,
		    S_IFCHR, ap_minor,
		    DDI_NT_PCI_ATTACHMENT_POINT,
		    0) == DDI_FAILURE) {
			cardbus_err(dip, 4,
			    "cardbus_new_slot_state: "
			    "ddi_create_minor_node failed");
			rv = HPC_ERR_FAILED;
			break;
		}

		/* save the slot handle */
		cbp->slot_handle = hdl;

		/* setup event handler for all hardware events on the slot */
		if (hpc_install_event_handler(hdl, -1, cardbus_event_handler,
		    (caddr_t)((long)ap_minor)) != 0) {
			cardbus_err(dip, 4,
			    "cardbus_new_slot_state: "
			    "install event handler failed");
			rv = HPC_ERR_FAILED;
			break;
		}
		cbp->event_mask = (uint32_t)0xFFFFFFFF;
		create_occupant_props(dip,
		    makedevice(ddi_name_to_major(ddi_get_name(dip)),
		    ap_minor));

		/* set default auto configuration enabled flag for this slot */
		cbp->auto_config = cardbus_autocfg_enabled;

		/* copy the slot information */
		cbp->name = (char *)kmem_alloc(strlen(slot_info->pci_slot_name)
		    + 1, KM_SLEEP);
		(void) strcpy(cbp->name, slot_info->pci_slot_name);
		cardbus_err(cbp->cb_dip, 10,
		    "cardbus_new_slot_state: cbp->name set to %s", cbp->name);

		cardbus_err(dip, 4,
		    "Cardbus slot \"%s\" ONLINE\n", slot_info->pci_slot_name);

		cbp->ostate = AP_OSTATE_UNCONFIGURED;
		cbp->rstate = AP_RSTATE_EMPTY;

		break;

	case HPC_SLOT_OFFLINE:
		/*
		 * A hot plug slot is being removed from the bus.
		 * Make sure there is no occupant configured on the
		 * slot before removing the AP minor node.
		 */
		if (cbp->ostate != AP_OSTATE_UNCONFIGURED) {
			cmn_err(CE_WARN,
			    "cardbus: Card is still in configured state");
			rv = HPC_ERR_FAILED;
			break;
		}

		/*
		 * If the AP device is in open state then return
		 * error.
		 */
		if (cbp->soft_state != PCIHP_SOFT_STATE_CLOSED) {
			rv = HPC_ERR_FAILED;
			break;
		}

		/* remove the minor node */
		ddi_remove_minor_node(dip, cbp->name);
		/* free up the memory for the name string */
		kmem_free(cbp->name, strlen(cbp->name) + 1);

		/* update the slot info data */
		cbp->name = NULL;
		cbp->slot_handle = NULL;

		cardbus_err(dip, 6,
		    "cardbus_new_slot_state: Cardbus slot OFFLINE");
		break;

	default:
		cmn_err(CE_WARN,
		    "cardbus_new_slot_state: unknown slot_state %d\n",
		    slot_state);
		rv = HPC_ERR_FAILED;
	}

	mutex_exit(&cbp->cb_mutex);

	return (rv);
}

static int
cardbus_list_occupants(dev_info_t *dip, void *hdl)
{
	hpc_occupant_info_t *occupant = (hpc_occupant_info_t *)hdl;
	char pn[MAXPATHLEN];

	/*
	 * Ignore the attachment point and pcs.
	 */
	if (strcmp(ddi_binding_name(dip), "pcs") == 0) {
		return (DDI_WALK_CONTINUE);
	}

	(void) ddi_pathname(dip, pn);

	occupant->id[occupant->i] = kmem_alloc(strlen(pn) + 1, KM_SLEEP);
	(void) strcpy(occupant->id[occupant->i], pn);

	occupant->i++;

	/*
	 * continue the walk to the next sibling to look for a match
	 * or to find other nodes if this card is a multi-function card.
	 */
	return (DDI_WALK_PRUNECHILD);
}

static void
create_occupant_props(dev_info_t *self, dev_t dev)
{
	hpc_occupant_info_t occupant;
	int i;
	int circular;

	occupant.i = 0;

	ndi_devi_enter(self, &circular);
	ddi_walk_devs(ddi_get_child(self), cardbus_list_occupants,
	    (void *)&occupant);
	ndi_devi_exit(self, circular);

	if (occupant.i == 0) {
		char *c[] = { "" };
		cardbus_err(self, 1, "create_occupant_props: no occupant\n");
		(void) ddi_prop_update_string_array(dev, self, "pci-occupant",
		    c, 1);
	} else {
		cardbus_err(self, 1,
		    "create_occupant_props: %d occupant\n", occupant.i);
		(void) ddi_prop_update_string_array(dev, self, "pci-occupant",
		    occupant.id, occupant.i);
	}

	for (i = 0; i < occupant.i; i++) {
		kmem_free(occupant.id[i], strlen(occupant.id[i]) + 1);
	}
}

static void
delete_occupant_props(dev_info_t *dip, dev_t dev)
{
	if (ddi_prop_remove(dev, dip, "pci-occupant")
	    != DDI_PROP_SUCCESS)
		return; /* add error handling */

}

/*
 * **************************************
 * CONFIGURE the occupant in the slot.
 * **************************************
 */
static int
cardbus_configure_ap(cbus_t *cbp)
{
	dev_info_t *self = cbp->cb_dip;
	int rv = HPC_SUCCESS;
	hpc_slot_state_t rstate;
	struct cardbus_config_ctrl ctrl;
	int circular_count;

	/*
	 * check for valid request:
	 *  1. It is a hotplug slot.
	 *  2. The receptacle is in the CONNECTED state.
	 */
	if (cbp->slot_handle == NULL || cbp->disabled) {
		return (ENXIO);
	}

	/*
	 * If the occupant is already in (partially) configured
	 * state then call the ndi_devi_online() on the device
	 * subtree(s) for this attachment point.
	 */

	if (cbp->ostate == AP_OSTATE_CONFIGURED) {
		ctrl.flags = PCICFG_FLAGS_CONTINUE;
		ctrl.busno = cardbus_primary_busno(self);
		ctrl.rv = NDI_SUCCESS;
		ctrl.dip = NULL;
		ctrl.op = PCICFG_OP_ONLINE;

		ndi_devi_enter(self, &circular_count);
		ddi_walk_devs(ddi_get_child(self),
		    cbus_configure, (void *)&ctrl);
		ndi_devi_exit(self, circular_count);

		if (cardbus_debug) {
			cardbus_dump_pci_config(self);
			cardbus_dump_pci_node(self);
		}

		if (ctrl.rv != NDI_SUCCESS) {
			/*
			 * one or more of the devices are not
			 * onlined.
			 */
			cmn_err(CE_WARN, "cardbus(%s%d): failed to attach "
			    "one or more drivers for the card in the slot %s",
			    ddi_driver_name(self), cbp->cb_instance,
			    cbp->name);
		}

		/* tell HPC driver that the occupant is configured */
		(void) hpc_nexus_control(cbp->slot_handle,
		    HPC_CTRL_DEV_CONFIGURED, NULL);
		return (rv);
	}

	/*
	 * Occupant is in the UNCONFIGURED state.
	 */

	/* Check if the receptacle is in the CONNECTED state. */
	if (hpc_nexus_control(cbp->slot_handle,
	    HPC_CTRL_GET_SLOT_STATE, (caddr_t)&rstate) != 0) {
		return (ENXIO);
	}

	if (rstate != HPC_SLOT_CONNECTED) {
		/* error. either the slot is empty or connect failed */
		return (ENXIO);
	}

	cbp->rstate = AP_RSTATE_CONNECTED; /* record rstate */

	/*
	 * Call the configurator to configure the card.
	 */
	if (cardbus_configure(cbp) != PCICFG_SUCCESS) {
		return (EIO);
	}

	/* record the occupant state as CONFIGURED */
	cbp->ostate = AP_OSTATE_CONFIGURED;
	cbp->condition = AP_COND_OK;

	/* now, online all the devices in the AP */
	ctrl.flags = PCICFG_FLAGS_CONTINUE;
	ctrl.busno = cardbus_primary_busno(self);
	ctrl.rv = NDI_SUCCESS;
	ctrl.dip = NULL;
	ctrl.op = PCICFG_OP_ONLINE;

	ndi_devi_enter(self, &circular_count);
	ddi_walk_devs(ddi_get_child(self), cbus_configure, (void *)&ctrl);
	ndi_devi_exit(self, circular_count);

	if (cardbus_debug) {
		cardbus_dump_pci_config(self);
		cardbus_dump_pci_node(self);
	}
	if (ctrl.rv != NDI_SUCCESS) {
		/*
		 * one or more of the devices are not
		 * ONLINE'd.
		 */
		cmn_err(CE_WARN, "cbhp (%s%d): failed to attach one or"
		    " more drivers for the card in the slot %s",
		    ddi_driver_name(cbp->cb_dip),
		    cbp->cb_instance, cbp->name);
		/* rv = EFAULT; */
	}

	/* tell HPC driver that the occupant is configured */
	(void) hpc_nexus_control(cbp->slot_handle,
	    HPC_CTRL_DEV_CONFIGURED, NULL);

	return (rv);
}

/*
 * **************************************
 * UNCONFIGURE the occupant in the slot.
 * **************************************
 */
static int
cardbus_unconfigure_ap(cbus_t *cbp)
{
	dev_info_t *self = cbp->cb_dip;
	int rv = HPC_SUCCESS, nrv;

	/*
	 * check for valid request:
	 *  1. It is a hotplug slot.
	 *  2. The occupant is in the CONFIGURED state.
	 */

	if (cbp->slot_handle == NULL || cbp->disabled) {
		return (ENXIO);
	}

	/*
	 * If the occupant is in the CONFIGURED state then
	 * call the configurator to unconfigure the slot.
	 */
	if (cbp->ostate == AP_OSTATE_CONFIGURED) {
		/*
		 * Detach all the drivers for the devices in the
		 * slot.
		 */
		nrv = cardbus_unconfigure_node(self,
		    cardbus_primary_busno(self),
		    B_TRUE);

		if (nrv != NDI_SUCCESS) {
			/*
			 * Failed to detach one or more drivers.
			 * Restore the status for the drivers
			 * which are offlined during this step.
			 */
			cmn_err(CE_WARN,
			    "cbhp (%s%d): Failed to offline all devices"
			    " (slot %s)", ddi_driver_name(cbp->cb_dip),
			    cbp->cb_instance, cbp->name);
			rv = EBUSY;
		} else {

			if (cardbus_unconfigure(cbp) == PCICFG_SUCCESS) {
				/*
				 * Now that resources are freed,
				 * clear EXT and Turn LED ON.
				 */
				cbp->ostate = AP_OSTATE_UNCONFIGURED;
				cbp->condition = AP_COND_UNKNOWN;
				/*
				 * send the notification of state change
				 * to the HPC driver.
				 */
				(void) hpc_nexus_control(cbp->slot_handle,
				    HPC_CTRL_DEV_UNCONFIGURED, NULL);
			} else {
				rv = EIO;
			}
		}
	}

	return (rv);
}

int
cbus_configure(dev_info_t *dip, void *hdl)
{
	pci_regspec_t *pci_rp;
	int length, rc;
	struct cardbus_config_ctrl *ctrl = (struct cardbus_config_ctrl *)hdl;
	uint8_t bus, device, function;

	/*
	 * Ignore the attachment point and pcs.
	 */
	if (strcmp(ddi_binding_name(dip), "hp_attachment") == 0 ||
	    strcmp(ddi_binding_name(dip), "pcs") == 0) {
		cardbus_err(dip, 8, "cbus_configure: Ignoring\n");
		return (DDI_WALK_CONTINUE);
	}

	cardbus_err(dip, 6, "cbus_configure\n");

	ASSERT(ctrl->op == PCICFG_OP_ONLINE);

	/*
	 * Get the PCI device number information from the devinfo
	 * node. Since the node may not have the address field
	 * setup (this is done in the DDI_INITCHILD of the parent)
	 * we look up the 'reg' property to decode that information.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp,
	    (uint_t *)&length) != DDI_PROP_SUCCESS) {
		/* Porbably not a real device, like PCS for example */
		if (ddi_get_child(dip) == NULL)
			return (DDI_WALK_PRUNECHILD);

		cardbus_err(dip, 1, "cubs_configure: Don't configure device\n");
		ctrl->rv = DDI_FAILURE;
		ctrl->dip = dip;
		return (DDI_WALK_TERMINATE);
	}

	if (pci_rp->pci_phys_hi == 0)
		return (DDI_WALK_CONTINUE);

	/* get the pci device id information */
	bus = PCI_REG_BUS_G(pci_rp->pci_phys_hi);
	device = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	function = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(pci_rp);

	if (bus <= ctrl->busno)
		return (DDI_WALK_CONTINUE);

	cardbus_err(dip, 8,
	    "cbus_configure on-line device at: "
	    "[0x%x][0x%x][0x%x]\n", bus, device, function);

	rc = ndi_devi_online(dip, NDI_ONLINE_ATTACH|NDI_CONFIG);

	cardbus_err(dip, 7,
	    "cbus_configure %s\n",
	    rc == NDI_SUCCESS ? "Success": "Failure");

	if (rc != NDI_SUCCESS)
		return (DDI_WALK_PRUNECHILD);

	return (DDI_WALK_CONTINUE);
}

int
cardbus_unconfigure_node(dev_info_t *dip, int prim_bus, boolean_t top_bridge)
{
	dev_info_t *child, *next;

	cardbus_err(dip, 6, "cardbus_unconfigure_node\n");

	/*
	 * Ignore pcs.
	 */
	if (strcmp(ddi_binding_name(dip), "pcs") == 0) {
		cardbus_err(dip, 8, "cardbus_unconfigure_node: Ignoring\n");
		return (NDI_SUCCESS);
	}

	/*
	 * bottom up off-line
	 */
	for (child = ddi_get_child(dip); child; child = next) {
		int rc;
		next = ddi_get_next_sibling(child);
		rc = cardbus_unconfigure_node(child, prim_bus, B_FALSE);
		if (rc != NDI_SUCCESS)
			return (rc);
	}

	/*
	 * Don't unconfigure the bridge itself.
	 */
	if (top_bridge)
		return (NDI_SUCCESS);

	if (cbus_unconfigure(dip, prim_bus) != NDI_SUCCESS) {
		cardbus_err(dip, 1,
		    "cardbus_unconfigure_node: cardbus_unconfigure failed\n");
		return (NDI_FAILURE);
	}
	return (NDI_SUCCESS);
}

/*
 * This will turn  resources allocated by cbus_configure()
 * and remove the device tree from the attachment point
 * and below.  The routine assumes the devices have their
 * drivers detached.
 */
static int
cbus_unconfigure(dev_info_t *devi, int prim_bus)
{
	pci_regspec_t *pci_rp;
	uint_t bus, device, func, length;
	int ndi_flags = NDI_UNCONFIG;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp,
	    &length) != DDI_PROP_SUCCESS) {
		/*
		 * This cannot be one of our devices. If it's something like a
		 * SCSI device then the attempt to offline the HBA
		 * (which probably is one of our devices)
		 * will also do bottom up offlining. That
		 * will fail if this device is busy. So always
		 * return success here
		 * so that the walk will continue.
		 */
		return (NDI_SUCCESS);
	}

	if (pci_rp->pci_phys_hi == 0)
		return (NDI_FAILURE);

	bus = PCI_REG_BUS_G(pci_rp->pci_phys_hi);

	if (bus <= prim_bus)
		return (NDI_SUCCESS);

	device = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	func = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);
	ddi_prop_free(pci_rp);

	cardbus_err(devi, 8,
	    "cbus_unconfigure: "
	    "offline bus [0x%x] device [0x%x] function [%x]\n",
	    bus, device, func);
	if (ndi_devi_offline(devi, ndi_flags) != NDI_SUCCESS) {
		cardbus_err(devi, 1,
		    "Device [0x%x] function [%x] is busy\n", device, func);
		return (NDI_FAILURE);
	}

	cardbus_err(devi, 9,
	    "Tearing down device [0x%x] function [0x%x]\n", device, func);

	if (cardbus_teardown_device(devi) != PCICFG_SUCCESS) {
		cardbus_err(devi, 1,
		    "Failed to tear down "
		    "device [0x%x] function [0x%x]\n", device, func);
		return (NDI_FAILURE);
	}

	return (NDI_SUCCESS);
}

boolean_t
cardbus_is_cb_minor(dev_t dev)
{
	return (AP_IS_CB_MINOR(getminor(dev)) ? B_TRUE : B_FALSE);
}

int
cardbus_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	cbus_t *cbp;
	int minor;

	_NOTE(ARGUNUSED(credp))

	minor = getminor(*devp);

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
	return (EINVAL);

	/*
	 * Get the soft state structure for the 'devctl' device.
	 */
	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state,
	    AP_MINOR_NUM_TO_CB_INSTANCE(minor));
	if (cbp == NULL)
		return (ENXIO);

	mutex_enter(&cbp->cb_mutex);

	/*
	 * Handle the open by tracking the device state.
	 *
	 * Note: Needs review w.r.t exclusive access to AP or the bus.
	 * Currently in the pci plug-in we don't use EXCL open at all
	 * so the code below implements EXCL access on the bus.
	 */

	/* enforce exclusive access to the bus */
	if ((cbp->soft_state == PCIHP_SOFT_STATE_OPEN_EXCL) ||
	    ((flags & FEXCL) &&
	    (cbp->soft_state != PCIHP_SOFT_STATE_CLOSED))) {
		mutex_exit(&cbp->cb_mutex);
		return (EBUSY);
	}

	if (flags & FEXCL)
		cbp->soft_state = PCIHP_SOFT_STATE_OPEN_EXCL;
	else
		cbp->soft_state = PCIHP_SOFT_STATE_OPEN;

	mutex_exit(&cbp->cb_mutex);
	return (0);
}

/*ARGSUSED*/
int
cardbus_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	cbus_t *cbp;
	int minor;

	_NOTE(ARGUNUSED(credp))

	minor = getminor(dev);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state,
	    AP_MINOR_NUM_TO_CB_INSTANCE(minor));
	if (cbp == NULL)
		return (ENXIO);

	mutex_enter(&cbp->cb_mutex);
	cbp->soft_state = PCIHP_SOFT_STATE_CLOSED;
	mutex_exit(&cbp->cb_mutex);
	return (0);
}

/*
 * cardbus_ioctl: devctl hotplug controls
 */
/*ARGSUSED*/
int
cardbus_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	cbus_t *cbp;
	dev_info_t *self;
	dev_info_t *child_dip = NULL;
	struct devctl_iocdata *dcp;
	uint_t bus_state;
	int rv = 0;
	int nrv = 0;
	int ap_minor;
	hpc_slot_state_t rstate;
	devctl_ap_state_t ap_state;
	struct hpc_control_data hpc_ctrldata;
	struct hpc_led_info led_info;

	_NOTE(ARGUNUSED(credp))

	ap_minor = getminor(dev);
	cbp = (cbus_t *)ddi_get_soft_state(cardbus_state,
	    AP_MINOR_NUM_TO_CB_INSTANCE(ap_minor));
	if (cbp == NULL)
		return (ENXIO);

	self = cbp->cb_dip;
	/*
	 * read devctl ioctl data
	 */
	if ((cmd != DEVCTL_AP_CONTROL) && ndi_dc_allochdl((void *)arg,
	    &dcp) != NDI_SUCCESS)
		return (EFAULT);

#ifdef CARDBUS_DEBUG
{
	char *cmd_name;

	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE: cmd_name = "DEVCTL_DEVICE_GETSTATE"; break;
	case DEVCTL_DEVICE_ONLINE: cmd_name = "DEVCTL_DEVICE_ONLINE"; break;
	case DEVCTL_DEVICE_OFFLINE: cmd_name = "DEVCTL_DEVICE_OFFLINE"; break;
	case DEVCTL_DEVICE_RESET: cmd_name = "DEVCTL_DEVICE_RESET"; break;
	case DEVCTL_BUS_QUIESCE: cmd_name = "DEVCTL_BUS_QUIESCE"; break;
	case DEVCTL_BUS_UNQUIESCE: cmd_name = "DEVCTL_BUS_UNQUIESCE"; break;
	case DEVCTL_BUS_RESET: cmd_name = "DEVCTL_BUS_RESET"; break;
	case DEVCTL_BUS_RESETALL: cmd_name = "DEVCTL_BUS_RESETALL"; break;
	case DEVCTL_BUS_GETSTATE: cmd_name = "DEVCTL_BUS_GETSTATE"; break;
	case DEVCTL_AP_CONNECT: cmd_name = "DEVCTL_AP_CONNECT"; break;
	case DEVCTL_AP_DISCONNECT: cmd_name = "DEVCTL_AP_DISCONNECT"; break;
	case DEVCTL_AP_INSERT: cmd_name = "DEVCTL_AP_INSERT"; break;
	case DEVCTL_AP_REMOVE: cmd_name = "DEVCTL_AP_REMOVE"; break;
	case DEVCTL_AP_CONFIGURE: cmd_name = "DEVCTL_AP_CONFIGURE"; break;
	case DEVCTL_AP_UNCONFIGURE: cmd_name = "DEVCTL_AP_UNCONFIGURE"; break;
	case DEVCTL_AP_GETSTATE: cmd_name = "DEVCTL_AP_GETSTATE"; break;
	case DEVCTL_AP_CONTROL: cmd_name = "DEVCTL_AP_CONTROL"; break;
	default: cmd_name = "Unknown"; break;
	}
	cardbus_err(cbp->cb_dip, 7,
	    "cardbus_ioctl: cmd = 0x%x, \"%s\"", cmd, cmd_name);
}
#endif

	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_BUS_GETSTATE:
		rv = ndi_devctl_ioctl(self, cmd, arg, mode, 0);
		ndi_dc_freehdl(dcp);
		return (rv);
	default:
		break;
	}

	switch (cmd) {
	case DEVCTL_DEVICE_RESET:
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_QUIESCE:
		if (ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_QUIESCED)
				break;
		(void) ndi_set_bus_state(self, BUS_QUIESCED);
		break;

	case DEVCTL_BUS_UNQUIESCE:
		if (ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_ACTIVE)
				break;
		(void) ndi_set_bus_state(self, BUS_ACTIVE);
		break;

	case DEVCTL_BUS_RESET:
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_RESETALL:
		rv = ENOTSUP;
		break;

	case DEVCTL_AP_CONNECT:
	case DEVCTL_AP_DISCONNECT:
		/*
		 * CONNECT(DISCONNECT) the hot plug slot to(from) the bus.
		 */
	case DEVCTL_AP_INSERT:
	case DEVCTL_AP_REMOVE:
		/*
		 * Prepare the slot for INSERT/REMOVE operation.
		 */

		/*
		 * check for valid request:
		 *	1. It is a hotplug slot.
		 *	2. The slot has no occupant that is in
		 *	the 'configured' state.
		 *
		 * The lower 8 bits of the minor number is the PCI
		 * device number for the slot.
		 */
		if ((cbp->slot_handle == NULL) || cbp->disabled) {
			rv = ENXIO;
			break;
		}

		/* the slot occupant must be in the UNCONFIGURED state */
		if (cbp->ostate != AP_OSTATE_UNCONFIGURED) {
			rv = EINVAL;
			break;
		}

		/*
		 * Call the HPC driver to perform the operation on the slot.
		 */
		mutex_enter(&cbp->cb_mutex);
		switch (cmd) {
		case DEVCTL_AP_INSERT:
			rv = hpc_nexus_insert(cbp->slot_handle, NULL, 0);
			break;
		case DEVCTL_AP_REMOVE:
			rv = hpc_nexus_remove(cbp->slot_handle, NULL, 0);
			break;
		case DEVCTL_AP_CONNECT:
			if ((rv = hpc_nexus_connect(cbp->slot_handle,
			    NULL, 0)) == 0)
				cbp->rstate = AP_RSTATE_CONNECTED;
			break;
		case DEVCTL_AP_DISCONNECT:
			if ((rv = hpc_nexus_disconnect(cbp->slot_handle,
			    NULL, 0)) == 0)
				cbp->rstate = AP_RSTATE_DISCONNECTED;
			break;
		}
		mutex_exit(&cbp->cb_mutex);

		switch (rv) {
		case HPC_ERR_INVALID:
			rv = ENXIO;
			break;
		case HPC_ERR_NOTSUPPORTED:
			rv = ENOTSUP;
			break;
		case HPC_ERR_FAILED:
			rv = EIO;
			break;
		}

		break;

	case DEVCTL_AP_CONFIGURE:
		/*
		 * **************************************
		 * CONFIGURE the occupant in the slot.
		 * **************************************
		 */

		mutex_enter(&cbp->cb_mutex);
		if ((nrv = cardbus_configure_ap(cbp)) == HPC_SUCCESS) {
			create_occupant_props(cbp->cb_dip, dev);
		} else
			rv = nrv;
		mutex_exit(&cbp->cb_mutex);
		break;

	case DEVCTL_AP_UNCONFIGURE:
		/*
		 * **************************************
		 * UNCONFIGURE the occupant in the slot.
		 * **************************************
		 */

		mutex_enter(&cbp->cb_mutex);
		if ((nrv = cardbus_unconfigure_ap(cbp)) == HPC_SUCCESS) {
			delete_occupant_props(cbp->cb_dip, dev);
		} else
			rv = nrv;
		mutex_exit(&cbp->cb_mutex);
		break;

	case DEVCTL_AP_GETSTATE:
	    {
		int mutex_held;

		/*
		 * return the state of Attachment Point.
		 *
		 * If the occupant is in UNCONFIGURED state then
		 * we should get the receptacle state from the
		 * HPC driver because the receptacle state
		 * maintained in the nexus may not be accurate.
		 */

		/*
		 * check for valid request:
		 *	1. It is a hotplug slot.
		 */
		if (cbp->slot_handle == NULL) {
			rv = ENXIO;
			break;
		}

		/* try to acquire the slot mutex */
		mutex_held = mutex_tryenter(&cbp->cb_mutex);

		if (cbp->ostate == AP_OSTATE_UNCONFIGURED) {
			if (hpc_nexus_control(cbp->slot_handle,
			    HPC_CTRL_GET_SLOT_STATE,
			    (caddr_t)&rstate) != 0) {
				rv = ENXIO;
				if (mutex_held)
					mutex_exit(&cbp->cb_mutex);
				break;
			}
			cbp->rstate = (ap_rstate_t)rstate;
		}

		ap_state.ap_rstate = cbp->rstate;
		ap_state.ap_ostate = cbp->ostate;
		ap_state.ap_condition = cbp->condition;
		ap_state.ap_last_change = 0;
		ap_state.ap_error_code = 0;
		if (mutex_held)
			ap_state.ap_in_transition = 0; /* AP is not busy */
		else
			ap_state.ap_in_transition = 1; /* AP is busy */

		if (mutex_held)
			mutex_exit(&cbp->cb_mutex);

		/* copy the return-AP-state information to the user space */
		if (ndi_dc_return_ap_state(&ap_state, dcp) != NDI_SUCCESS)
			rv = ENXIO;

		break;

	    }

	case DEVCTL_AP_CONTROL:
		/*
		 * HPC control functions:
		 *	HPC_CTRL_ENABLE_SLOT/HPC_CTRL_DISABLE_SLOT
		 *		Changes the state of the slot and preserves
		 *		the state across the reboot.
		 *	HPC_CTRL_ENABLE_AUTOCFG/HPC_CTRL_DISABLE_AUTOCFG
		 *		Enables or disables the auto configuration
		 *		of hot plugged occupant if the hardware
		 *		supports notification of the hot plug
		 *		events.
		 *	HPC_CTRL_GET_LED_STATE/HPC_CTRL_SET_LED_STATE
		 *		Controls the state of an LED.
		 *	HPC_CTRL_GET_SLOT_INFO
		 *		Get slot information data structure
		 *		(hpc_slot_info_t).
		 *	HPC_CTRL_GET_BOARD_TYPE
		 *		Get board type information (hpc_board_type_t).
		 *	HPC_CTRL_GET_CARD_INFO
		 *		Get card information (hpc_card_info_t).
		 *
		 * These control functions are used by the cfgadm plug-in
		 * to implement "-x" and "-v" options.
		 */

		/* copy user ioctl data first */
#ifdef _MULTI_DATAMODEL
		if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
			struct hpc_control32_data hpc_ctrldata32;

			if (copyin((void *)arg, (void *)&hpc_ctrldata32,
			    sizeof (struct hpc_control32_data)) != 0) {
				rv = EFAULT;
				break;
			}
			hpc_ctrldata.cmd = hpc_ctrldata32.cmd;
			hpc_ctrldata.data =
			    (void *)(intptr_t)hpc_ctrldata32.data;
		}
#else
		if (copyin((void *)arg, (void *)&hpc_ctrldata,
		    sizeof (struct hpc_control_data)) != 0) {
			rv = EFAULT;
			break;
		}
#endif

#ifdef CARDBUS_DEBUG
{
		char *hpc_name;
		switch (hpc_ctrldata.cmd) {
		case HPC_CTRL_GET_LED_STATE:
			hpc_name = "HPC_CTRL_GET_LED_STATE";
			break;
		case HPC_CTRL_SET_LED_STATE:
			hpc_name = "HPC_CTRL_SET_LED_STATE";
			break;
		case HPC_CTRL_ENABLE_SLOT:
			hpc_name = "HPC_CTRL_ENABLE_SLOT";
			break;
		case HPC_CTRL_DISABLE_SLOT:
			hpc_name = "HPC_CTRL_DISABLE_SLOT";
			break;
		case HPC_CTRL_ENABLE_AUTOCFG:
			hpc_name = "HPC_CTRL_ENABLE_AUTOCFG";
			break;
		case HPC_CTRL_DISABLE_AUTOCFG:
			hpc_name = "HPC_CTRL_DISABLE_AUTOCFG";
			break;
		case HPC_CTRL_GET_BOARD_TYPE:
			hpc_name = "HPC_CTRL_GET_BOARD_TYPE";
			break;
		case HPC_CTRL_GET_SLOT_INFO:
			hpc_name = "HPC_CTRL_GET_SLOT_INFO";
			break;
		case HPC_CTRL_GET_CARD_INFO:
			hpc_name = "HPC_CTRL_GET_CARD_INFO";
			break;
		default: hpc_name = "Unknown"; break;
		}
		cardbus_err(cbp->cb_dip, 7,
		    "cardbus_ioctl: HP Control cmd 0x%x - \"%s\"",
		    hpc_ctrldata.cmd, hpc_name);
}
#endif
		/*
		 * check for valid request:
		 *	1. It is a hotplug slot.
		 */
		if (cbp->slot_handle == NULL) {
			rv = ENXIO;
			break;
		}

		mutex_enter(&cbp->cb_mutex);
		switch (hpc_ctrldata.cmd) {
		case HPC_CTRL_GET_LED_STATE:
			/* copy the led info from the user space */
			if (copyin(hpc_ctrldata.data, (void *)&led_info,
			    sizeof (hpc_led_info_t)) != 0) {
				rv = ENXIO;
				break;
			}

			/* get the state of LED information */
			if (hpc_nexus_control(cbp->slot_handle,
			    HPC_CTRL_GET_LED_STATE,
			    (caddr_t)&led_info) != 0) {
				rv = ENXIO;
				break;
			}

			/* copy the led info to the user space */
			if (copyout((void *)&led_info, hpc_ctrldata.data,
			    sizeof (hpc_led_info_t)) != 0) {
				rv = ENXIO;
				break;
			}
			break;

		case HPC_CTRL_SET_LED_STATE:
			/* copy the led info from the user space */
			if (copyin(hpc_ctrldata.data, (void *)&led_info,
			    sizeof (hpc_led_info_t)) != 0) {
				rv = ENXIO;
				break;
			}

			/* set the state of an LED */
			if (hpc_nexus_control(cbp->slot_handle,
			    HPC_CTRL_SET_LED_STATE,
			    (caddr_t)&led_info) != 0) {
				rv = ENXIO;
				break;
			}

			break;

		case HPC_CTRL_ENABLE_SLOT:
			/*
			 * Enable the slot for hotplug operations.
			 */
			cbp->disabled = B_FALSE;

			/* tell the HPC driver also */
			(void) hpc_nexus_control(cbp->slot_handle,
				HPC_CTRL_ENABLE_SLOT, NULL);

			break;

		case HPC_CTRL_DISABLE_SLOT:
			/*
			 * Disable the slot for hotplug operations.
			 */
			cbp->disabled = B_TRUE;

			/* tell the HPC driver also */
			(void) hpc_nexus_control(cbp->slot_handle,
				HPC_CTRL_DISABLE_SLOT, NULL);

			break;

		case HPC_CTRL_ENABLE_AUTOCFG:
			/*
			 * Enable auto configuration on this slot.
			 */
			cbp->auto_config = B_TRUE;

			/* tell the HPC driver also */
			(void) hpc_nexus_control(cbp->slot_handle,
				HPC_CTRL_ENABLE_AUTOCFG, NULL);
			break;

		case HPC_CTRL_DISABLE_AUTOCFG:
			/*
			 * Disable auto configuration on this slot.
			 */
			cbp->auto_config = B_FALSE;

			/* tell the HPC driver also */
			(void) hpc_nexus_control(cbp->slot_handle,
				HPC_CTRL_DISABLE_AUTOCFG, NULL);

			break;

		case HPC_CTRL_GET_BOARD_TYPE:
		    {
			hpc_board_type_t board_type;

			/*
			 * Get board type data structure, hpc_board_type_t.
			 */
			if (hpc_nexus_control(cbp->slot_handle,
			    HPC_CTRL_GET_BOARD_TYPE,
			    (caddr_t)&board_type) != 0) {
				rv = ENXIO;
				break;
			}

			/* copy the board type info to the user space */
			if (copyout((void *)&board_type, hpc_ctrldata.data,
			    sizeof (hpc_board_type_t)) != 0) {
				rv = ENXIO;
				break;
			}

			break;
		    }

		case HPC_CTRL_GET_SLOT_INFO:
		    {
			hpc_slot_info_t slot_info;

			/*
			 * Get slot information structure, hpc_slot_info_t.
			 */
			slot_info.version = HPC_SLOT_INFO_VERSION;
			slot_info.slot_type = 0;
			slot_info.pci_slot_capabilities = 0;
			slot_info.pci_dev_num =
				(uint16_t)AP_MINOR_NUM_TO_CB_INSTANCE(ap_minor);
			(void) strcpy(slot_info.pci_slot_name, cbp->name);

			/* copy the slot info structure to the user space */
			if (copyout((void *)&slot_info, hpc_ctrldata.data,
			    sizeof (hpc_slot_info_t)) != 0) {
				rv = ENXIO;
				break;
			}

			break;
		    }

		case HPC_CTRL_GET_CARD_INFO:
		    {
			hpc_card_info_t card_info;
			ddi_acc_handle_t handle;

			/*
			 * Get card information structure, hpc_card_info_t.
			 */

			if (cbp->card_present == B_FALSE) {
				rv = ENXIO;
				break;
			}
			/* verify that the card is configured */
			if (cbp->ostate != AP_OSTATE_CONFIGURED) {
				/* either the card is not present or */
				/* it is not configured. */
				rv = ENXIO;
				break;
			}

			/* get the information from the PCI config header */
			/* for the function 0. */
			for (child_dip = ddi_get_child(cbp->cb_dip); child_dip;
			    child_dip = ddi_get_next_sibling(child_dip))
				if (strcmp("pcs", ddi_get_name(child_dip)))
					break;

			if (!child_dip) {
				rv = ENXIO;
				break;
			}

			if (pci_config_setup(child_dip, &handle)
			    != DDI_SUCCESS) {
				rv = EIO;
				break;
			}
			card_info.prog_class = pci_config_get8(handle,
							PCI_CONF_PROGCLASS);
			card_info.base_class = pci_config_get8(handle,
							PCI_CONF_BASCLASS);
			card_info.sub_class = pci_config_get8(handle,
							PCI_CONF_SUBCLASS);
			card_info.header_type = pci_config_get8(handle,
							PCI_CONF_HEADER);
			pci_config_teardown(&handle);

			/* copy the card info structure to the user space */
			if (copyout((void *)&card_info, hpc_ctrldata.data,
			    sizeof (hpc_card_info_t)) != 0) {
				rv = ENXIO;
				break;
			}

			break;
		    }

		default:
			rv = EINVAL;
			break;
		}

		mutex_exit(&cbp->cb_mutex);
		break;

	default:
		rv = ENOTTY;
	}

	if (cmd != DEVCTL_AP_CONTROL)
		ndi_dc_freehdl(dcp);

	cardbus_err(cbp->cb_dip, 7,
	    "cardbus_ioctl: rv = 0x%x", rv);

	return (rv);
}

struct cardbus_pci_desc {
	char	*name;
	ushort_t	offset;
	int	(*cfg_get_func)();
	char	*fmt;
};

#define	CFG_GET(f)	((int(*)())(uintptr_t)f)

static struct cardbus_pci_desc generic_pci_cfg[] = {
	    { "VendorId    =", 0, CFG_GET(pci_config_get16), "%s 0x%04x" },
	    { "DeviceId    =", 2, CFG_GET(pci_config_get16), "%s 0x%04x" },
	    { "Command     =", 4, CFG_GET(pci_config_get16), "%s 0x%04x" },
	    { "Status      =", 6, CFG_GET(pci_config_get16), "%s 0x%04x" },
	    { "Latency     =", 0xd, CFG_GET(pci_config_get8), "%s 0x%02x" },
	    { "BASE0       =", 0x10, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "BASE1       =", 0x14, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "BASE2       =", 0x18, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "BASE3       =", 0x1c, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "BASE4       =", 0x20, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "CIS Pointer =", 0x28, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "ILINE       =", 0x3c, CFG_GET(pci_config_get8), "%s 0x%02x" },
	    { "IPIN        =", 0x3d, CFG_GET(pci_config_get8), "%s 0x%02x" },
	    { NULL, 0, NULL, NULL }
};

static struct cardbus_pci_desc cardbus_pci_cfg[] = {
	    { "VendorId    =", 0, CFG_GET(pci_config_get16), "%s 0x%04x" },
	    { "DeviceId    =", 2, CFG_GET(pci_config_get16), "%s 0x%04x" },
	    { "Command     =", 4, CFG_GET(pci_config_get16), "%s 0x%04x" },
	    { "Status      =", 6, CFG_GET(pci_config_get16), "%s 0x%04x" },
	    { "CacheLineSz =", 0xc, CFG_GET(pci_config_get8), "%s 0x%02x" },
	    { "Latency     =", 0xd, CFG_GET(pci_config_get8), "%s 0x%02x" },
	    { "MemBase Addr=", 0x10, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "Pri Bus     =", 0x18, CFG_GET(pci_config_get8), "%s 0x%02x" },
	    { "Sec Bus     =", 0x19, CFG_GET(pci_config_get8), "%s 0x%02x" },
	    { "Sub Bus     =", 0x1a, CFG_GET(pci_config_get8), "%s 0x%02x" },
	    { "CBus Latency=", 0x1b, CFG_GET(pci_config_get8), "%s 0x%02x" },
	    { "Mem0 Base   =", 0x1c, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "Mem0 Limit  =", 0x20, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "Mem1 Base   =", 0x24, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "Mem1 Limit  =", 0x28, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "I/O0 Base   =", 0x2c, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "I/O0 Limit  =", 0x30, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "I/O1 Base   =", 0x34, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "I/O1 Limit  =", 0x38, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { "ILINE       =", 0x3c, CFG_GET(pci_config_get8), "%s 0x%02x" },
	    { "IPIN        =", 0x3d, CFG_GET(pci_config_get8), "%s 0x%02x" },
	    { "Bridge Ctrl =", 0x3e, CFG_GET(pci_config_get16), "%s 0x%04x" },
	    { "Legacy Addr =", 0x44, CFG_GET(pci_config_get32), "%s 0x%08x" },
	    { NULL, 0, NULL, NULL }
};

static void
cardbus_dump(struct cardbus_pci_desc *spcfg, ddi_acc_handle_t handle)
{
	int	i;
	for (i = 0; spcfg[i].name; i++) {

		cmn_err(CE_NOTE, spcfg[i].fmt, spcfg[i].name,
		    spcfg[i].cfg_get_func(handle, spcfg[i].offset));
	}

}

void
cardbus_dump_pci_node(dev_info_t *dip)
{
	dev_info_t *next;
	struct cardbus_pci_desc *spcfg;
	ddi_acc_handle_t config_handle;
	uint32_t VendorId;

	cmn_err(CE_NOTE, "\nPCI leaf node of dip 0x%p:\n", (void *)dip);
	for (next = ddi_get_child(dip); next;
	    next = ddi_get_next_sibling(next)) {

		VendorId = ddi_getprop(DDI_DEV_T_ANY, next,
		    DDI_PROP_CANSLEEP|DDI_PROP_DONTPASS,
		    "vendor-id", -1);
		if (VendorId == -1) {
			/* not a pci device */
			continue;
		}

		if (pci_config_setup(next, &config_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "!pcic child: non pci device\n");
			continue;
		}

		spcfg = generic_pci_cfg;
		cardbus_dump(spcfg, config_handle);
		pci_config_teardown(&config_handle);

	}

}

void
cardbus_dump_pci_config(dev_info_t *dip)
{
	struct cardbus_pci_desc *spcfg;
	ddi_acc_handle_t config_handle;

	if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "!pci_config_setup() failed on 0x%p", (void *)dip);
		return;
	}

	spcfg = cardbus_pci_cfg;
	cardbus_dump(spcfg, config_handle);

	pci_config_teardown(&config_handle);
}

void
cardbus_dump_socket(dev_info_t *dip)
{
	ddi_acc_handle_t	iohandle;
	caddr_t		ioaddr;
	ddi_device_acc_attr_t attr;
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	if (ddi_regs_map_setup(dip, 1,
	    (caddr_t *)&ioaddr,
	    0,
	    4096,
	    &attr, &iohandle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed to map address for 0x%p", (void *)dip);
		return;
	}

	cmn_err(CE_NOTE, "////////////////////////////////////////");
	cmn_err(CE_NOTE, "SOCKET_EVENT  = [0x%x]",
	    ddi_get32(iohandle, (uint32_t *)(ioaddr+CB_STATUS_EVENT)));
	cmn_err(CE_NOTE, "SOCKET_MASK   = [0x%x]",
	    ddi_get32(iohandle, (uint32_t *)(ioaddr+CB_STATUS_MASK)));
	cmn_err(CE_NOTE, "SOCKET_STATE  = [0x%x]",
	    ddi_get32(iohandle, (uint32_t *)(ioaddr+CB_PRESENT_STATE)));
	cmn_err(CE_NOTE, "////////////////////////////////////////");

	ddi_regs_map_free(&iohandle);

}
