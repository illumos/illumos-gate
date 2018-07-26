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
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * ACPI interface related functions used in PCIEHPC driver module.
 *
 * NOTE: This file is compiled and delivered through misc/pcie module.
 */

#include <sys/note.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/varargs.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/pci_impl.h>
#include <sys/pcie_acpi.h>
#include <sys/hotplug/pci/pcie_hp.h>
#include <sys/hotplug/pci/pciehpc_acpi.h>

/* local static functions */
static int pciehpc_acpi_hpc_init(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_acpi_hpc_uninit(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_acpi_slotinfo_init(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_acpi_slotinfo_uninit(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_acpi_enable_intr(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_acpi_disable_intr(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_acpi_slot_poweron(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t *result);
static int pciehpc_acpi_slot_poweroff(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t *result);
static void pciehpc_acpi_setup_ops(pcie_hp_ctrl_t *ctrl_p);

static ACPI_STATUS pciehpc_acpi_install_event_handler(pcie_hp_ctrl_t *ctrl_p);
static void pciehpc_acpi_uninstall_event_handler(pcie_hp_ctrl_t *ctrl_p);
static ACPI_STATUS pciehpc_acpi_power_on_slot(pcie_hp_ctrl_t *ctrl_p);
static ACPI_STATUS pciehpc_acpi_power_off_slot(pcie_hp_ctrl_t *ctrl_p);
static void pciehpc_acpi_notify_handler(ACPI_HANDLE device, uint32_t val,
	void *context);
static ACPI_STATUS pciehpc_acpi_get_dev_state(ACPI_HANDLE obj, int *statusp);

/*
 * Update ops vector with platform specific (ACPI, CK8-04,...) functions.
 */
void
pciehpc_update_ops(pcie_hp_ctrl_t *ctrl_p)
{
	boolean_t hp_native_mode = B_FALSE;
	uint32_t osc_flags = OSC_CONTROL_PCIE_NAT_HP;

	/*
	 * Call _OSC method to determine if hotplug mode is native or ACPI.
	 * If _OSC method succeeds hp_native_mode below will be set according to
	 * if native hotplug control was granted or not by BIOS.
	 *
	 * If _OSC method fails for any reason or if native hotplug control was
	 * not granted assume it's ACPI mode and update platform specific
	 * (ACPI, CK8-04,...) impl. ops
	 */

	if (pcie_acpi_osc(ctrl_p->hc_dip, &osc_flags) == DDI_SUCCESS) {
		hp_native_mode = (osc_flags & OSC_CONTROL_PCIE_NAT_HP) ?
		    B_TRUE : B_FALSE;
	}

	if (!hp_native_mode) {
		pcie_bus_t *bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		/* update ops vector for ACPI mode */
		pciehpc_acpi_setup_ops(ctrl_p);
		bus_p->bus_hp_sup_modes |= PCIE_ACPI_HP_MODE;
		bus_p->bus_hp_curr_mode = PCIE_ACPI_HP_MODE;
	}
}

void
pciehpc_acpi_setup_ops(pcie_hp_ctrl_t *ctrl_p)
{
	ctrl_p->hc_ops.init_hpc_hw = pciehpc_acpi_hpc_init;
	ctrl_p->hc_ops.uninit_hpc_hw = pciehpc_acpi_hpc_uninit;
	ctrl_p->hc_ops.init_hpc_slotinfo = pciehpc_acpi_slotinfo_init;
	ctrl_p->hc_ops.uninit_hpc_slotinfo = pciehpc_acpi_slotinfo_uninit;
	ctrl_p->hc_ops.poweron_hpc_slot = pciehpc_acpi_slot_poweron;
	ctrl_p->hc_ops.poweroff_hpc_slot = pciehpc_acpi_slot_poweroff;
	ctrl_p->hc_ops.disable_hpc_intr = pciehpc_acpi_disable_intr;
	ctrl_p->hc_ops.enable_hpc_intr = pciehpc_acpi_enable_intr;
}

/*
 * Intialize hot plug control for ACPI mode.
 */
static int
pciehpc_acpi_hpc_init(pcie_hp_ctrl_t *ctrl_p)
{
	ACPI_HANDLE pcibus_obj;
	int status = AE_ERROR;
	ACPI_HANDLE slot_dev_obj;
	ACPI_HANDLE hdl;
	pciehpc_acpi_t *acpi_p;
	uint16_t bus_methods = 0;
	uint16_t slot_methods = 0;

	/* get the ACPI object for the bus node */
	status = acpica_get_handle(ctrl_p->hc_dip, &pcibus_obj);
	if (status != AE_OK)
		return (DDI_FAILURE);

	/* get the ACPI object handle for the child node */
	status = AcpiGetNextObject(ACPI_TYPE_DEVICE, pcibus_obj,
	    NULL, &slot_dev_obj);
	if (status != AE_OK) {
		PCIE_DBG("pciehpc_acpi_hpc_init: Get ACPI object failed\n");
		return (DDI_FAILURE);
	}

	/*
	 * gather the info about the ACPI methods present on the bus node
	 * and the child nodes.
	 */
	if (AcpiGetHandle(pcibus_obj, "_OSC", &hdl) == AE_OK)
		bus_methods |= PCIEHPC_ACPI_OSC_PRESENT;
	if (AcpiGetHandle(pcibus_obj, "_OSHP", &hdl) == AE_OK)
		bus_methods |= PCIEHPC_ACPI_OSHP_PRESENT;
	if (AcpiGetHandle(pcibus_obj, "_HPX", &hdl) == AE_OK)
		bus_methods |= PCIEHPC_ACPI_HPX_PRESENT;
	if (AcpiGetHandle(pcibus_obj, "_HPP", &hdl) == AE_OK)
		bus_methods |= PCIEHPC_ACPI_HPP_PRESENT;
	if (AcpiGetHandle(pcibus_obj, "_DSM", &hdl) == AE_OK)
		bus_methods |= PCIEHPC_ACPI_DSM_PRESENT;
	if (AcpiGetHandle(slot_dev_obj, "_SUN", &hdl) == AE_OK)
		slot_methods |= PCIEHPC_ACPI_SUN_PRESENT;
	if (AcpiGetHandle(slot_dev_obj, "_PS0", &hdl) == AE_OK)
		slot_methods |= PCIEHPC_ACPI_PS0_PRESENT;
	if (AcpiGetHandle(slot_dev_obj, "_EJ0", &hdl) == AE_OK)
		slot_methods |= PCIEHPC_ACPI_EJ0_PRESENT;
	if (AcpiGetHandle(slot_dev_obj, "_STA", &hdl) == AE_OK)
		slot_methods |= PCIEHPC_ACPI_STA_PRESENT;

	/* save ACPI object handles, etc. */
	acpi_p = kmem_zalloc(sizeof (pciehpc_acpi_t), KM_SLEEP);
	acpi_p->bus_obj = pcibus_obj;
	acpi_p->slot_dev_obj = slot_dev_obj;
	acpi_p->bus_methods = bus_methods;
	acpi_p->slot_methods = slot_methods;
	ctrl_p->hc_misc_data = acpi_p;

	return (DDI_SUCCESS);
}

/*
 * Uninitialize HPC.
 */
static int
pciehpc_acpi_hpc_uninit(pcie_hp_ctrl_t *ctrl_p)
{
	/* free up buffer used for misc_data */
	if (ctrl_p->hc_misc_data) {
		kmem_free(ctrl_p->hc_misc_data, sizeof (pciehpc_acpi_t));
		ctrl_p->hc_misc_data = NULL;
	}

	return (DDI_SUCCESS);
}

/*
 * Enable interrupts. For ACPI hot plug this is a NOP.
 * Just return DDI_SUCCESS.
 */
/*ARGSUSED*/
static int
pciehpc_acpi_enable_intr(pcie_hp_ctrl_t *ctrl_p)
{
	return (DDI_SUCCESS);
}

/*
 * Disable interrupts. For ACPI hot plug this is a NOP.
 * Just return DDI_SUCCESS.
 */
/*ARGSUSED*/
static int
pciehpc_acpi_disable_intr(pcie_hp_ctrl_t *ctrl_p)
{
	return (DDI_SUCCESS);
}

/*
 * This function is similar to pciehpc_slotinfo_init() with some
 * changes:
 *	- no need for kernel thread to handle ATTN button events
 *	- function ops for connect/disconnect are different
 *
 * ASSUMPTION: No conflict in doing reads to HP registers directly.
 * Otherwise, there are no ACPI interfaces to do LED control or to get
 * the hot plug capabilities (ATTN button, MRL, etc.).
 */
static int
pciehpc_acpi_slotinfo_init(pcie_hp_ctrl_t *ctrl_p)
{
	uint32_t	slot_capabilities;
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

	mutex_enter(&ctrl_p->hc_mutex);
	/*
	 * setup DDI HP framework slot information structure
	 */
	slot_p->hs_device_num = 0;
	slot_p->hs_info.cn_type = DDI_HP_CN_TYPE_PCIE;
	slot_p->hs_info.cn_type_str = PCIE_ACPI_HP_TYPE;
	slot_p->hs_info.cn_child = NULL;

	slot_p->hs_minor =
	    PCI_MINOR_NUM(ddi_get_instance(ctrl_p->hc_dip),
	    slot_p->hs_device_num);

	/* read Slot Capabilities Register */
	slot_capabilities = pciehpc_reg_get32(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCAP);

	/* setup slot number/name */
	pciehpc_set_slot_name(ctrl_p);

	/* check if Attn Button present */
	ctrl_p->hc_has_attn = (slot_capabilities &
	    PCIE_SLOTCAP_ATTN_BUTTON) ? B_TRUE : B_FALSE;

	/* check if Manual Retention Latch sensor present */
	ctrl_p->hc_has_mrl = (slot_capabilities & PCIE_SLOTCAP_MRL_SENSOR) ?
	    B_TRUE : B_FALSE;

	/*
	 * PCI-E (draft) version 1.1 defines EMI Lock Present bit
	 * in Slot Capabilities register. Check for it.
	 */
	ctrl_p->hc_has_emi_lock = (slot_capabilities &
	    PCIE_SLOTCAP_EMI_LOCK_PRESENT) ? B_TRUE : B_FALSE;

	/* get current slot state from the hw */
	pciehpc_get_slot_state(slot_p);
	if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_ENABLED)
		slot_p->hs_condition = AP_COND_OK;

	mutex_exit(&ctrl_p->hc_mutex);

	/* setup Notify() handler for hot plug events from ACPI BIOS */
	if (pciehpc_acpi_install_event_handler(ctrl_p) != AE_OK)
		return (DDI_FAILURE);

	PCIE_DBG("ACPI hot plug is enabled for slot #%d\n",
	    slot_p->hs_phy_slot_num);

	return (DDI_SUCCESS);
}

/*
 * This function is similar to pciehcp_slotinfo_uninit() but has ACPI
 * specific cleanup.
 */
static int
pciehpc_acpi_slotinfo_uninit(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];

	/* uninstall Notify() event handler */
	pciehpc_acpi_uninstall_event_handler(ctrl_p);
	if (slot_p->hs_info.cn_name)
		kmem_free(slot_p->hs_info.cn_name,
		    strlen(slot_p->hs_info.cn_name) + 1);

	return (DDI_SUCCESS);
}

/*
 * This function is same as pciehpc_slot_poweron() except that it
 * uses ACPI method PS0 to enable power to the slot. If no PS0 method
 * is present then it returns DDI_FAILURE.
 */
/*ARGSUSED*/
static int
pciehpc_acpi_slot_poweron(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	status, control;

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	/* check if the slot is already in the 'ENABLED' state */
	if (slot_p->hs_info.cn_state == DDI_HP_CN_STATE_ENABLED) {
		/* slot is already in the 'connected' state */
		PCIE_DBG("slot %d already connected\n",
		    slot_p->hs_phy_slot_num);

		*result = slot_p->hs_info.cn_state;
		return (DDI_SUCCESS);
	}

	/* read the Slot Status Register */
	status =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);

	/* make sure the MRL switch is closed if present */
	if ((ctrl_p->hc_has_mrl) && (status & PCIE_SLOTSTS_MRL_SENSOR_OPEN)) {
		/* MRL switch is open */
		cmn_err(CE_WARN, "MRL switch is open on slot %d",
		    slot_p->hs_phy_slot_num);
		goto cleanup;
	}

	/* make sure the slot has a device present */
	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED)) {
		/* slot is empty */
		PCIE_DBG("slot %d is empty\n", slot_p->hs_phy_slot_num);
		goto cleanup;
	}

	/* get the current state of Slot Control Register */
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	/* check if the slot's power state is ON */
	if (!(control & PCIE_SLOTCTL_PWR_CONTROL)) {
		/* slot is already powered up */
		PCIE_DBG("slot %d already connected\n",
		    slot_p->hs_phy_slot_num);

		*result = slot_p->hs_info.cn_state;
		return (DDI_SUCCESS);
	}

	/* turn on power to the slot using ACPI method (PS0) */
	if (pciehpc_acpi_power_on_slot(ctrl_p) != AE_OK)
		goto cleanup;

	*result = slot_p->hs_info.cn_state = DDI_HP_CN_STATE_POWERED;
	return (DDI_SUCCESS);

cleanup:
	return (DDI_FAILURE);
}

/*
 * This function is same as pciehpc_slot_poweroff() except that it
 * uses ACPI method EJ0 to disable power to the slot. If no EJ0 method
 * is present then it returns DDI_FAILURE.
 */
/*ARGSUSED*/
static int
pciehpc_acpi_slot_poweroff(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	status;

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	/* check if the slot is already in the state less than 'powered' */
	if (slot_p->hs_info.cn_state < DDI_HP_CN_STATE_POWERED) {
		/* slot is in the 'disconnected' state */
		PCIE_DBG("slot %d already disconnected\n",
		    slot_p->hs_phy_slot_num);
		ASSERT(slot_p->hs_power_led_state == PCIE_HP_LED_OFF);

		*result = slot_p->hs_info.cn_state;
		return (DDI_SUCCESS);
	}

	/* read the Slot Status Register */
	status =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);

	/* make sure the slot has a device present */
	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED)) {
		/* slot is empty */
		PCIE_DBG("slot %d is empty", slot_p->hs_phy_slot_num);
		goto cleanup;
	}

	/* turn off power to the slot using ACPI method (EJ0) */
	if (pciehpc_acpi_power_off_slot(ctrl_p) != AE_OK)
		goto cleanup;

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	*result = slot_p->hs_info.cn_state;

	return (DDI_SUCCESS);

cleanup:
	return (DDI_FAILURE);
}

/*
 * Install event handler for the hot plug events on the bus node as well
 * as device function (dev=0,func=0).
 */
static ACPI_STATUS
pciehpc_acpi_install_event_handler(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];
	int status = AE_OK;
	pciehpc_acpi_t *acpi_p;

	PCIE_DBG("install event handler for slot %d\n",
	    slot_p->hs_phy_slot_num);
	acpi_p = ctrl_p->hc_misc_data;
	if (acpi_p->slot_dev_obj == NULL)
		return (AE_NOT_FOUND);

	/*
	 * Install event hanlder for events on the bus object.
	 * (Note: Insert event (hot-insert) is delivered on this object)
	 */
	status = AcpiInstallNotifyHandler(acpi_p->slot_dev_obj,
	    ACPI_SYSTEM_NOTIFY, pciehpc_acpi_notify_handler, (void *)ctrl_p);
	if (status != AE_OK)
		goto cleanup;

	/*
	 * Install event hanlder for events on the device function object.
	 * (Note: Eject device event (hot-remove) is delivered on this object)
	 *
	 * NOTE: Here the assumption is that Notify events are delivered
	 * on all of the 8 possible device functions so, subscribing to
	 * one of them is sufficient.
	 */
	status = AcpiInstallNotifyHandler(acpi_p->bus_obj,
	    ACPI_SYSTEM_NOTIFY, pciehpc_acpi_notify_handler, (void *)ctrl_p);
	return (status);

cleanup:
	(void) AcpiRemoveNotifyHandler(acpi_p->slot_dev_obj,
	    ACPI_SYSTEM_NOTIFY, pciehpc_acpi_notify_handler);
	return (status);
}

/*ARGSUSED*/
static void
pciehpc_acpi_notify_handler(ACPI_HANDLE device, uint32_t val, void *context)
{
	pcie_hp_ctrl_t *ctrl_p = context;
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];
	pciehpc_acpi_t *acpi_p;
	ddi_hp_cn_state_t curr_state;
	int dev_state = 0;

	PCIE_DBG("received Notify(%d) event on slot #%d\n",
	    val, slot_p->hs_phy_slot_num);

	mutex_enter(&ctrl_p->hc_mutex);

	/*
	 * get the state of the device (from _STA method)
	 */
	acpi_p = ctrl_p->hc_misc_data;
	if (pciehpc_acpi_get_dev_state(acpi_p->slot_dev_obj,
	    &dev_state) != AE_OK) {
		cmn_err(CE_WARN, "failed to get device status on slot %d",
		    slot_p->hs_phy_slot_num);
	}
	PCIE_DBG("(1)device state on slot #%d: 0x%x\n",
	    slot_p->hs_phy_slot_num, dev_state);

	curr_state = slot_p->hs_info.cn_state;
	pciehpc_get_slot_state(slot_p);

	switch (val) {
	case 0: /* (re)enumerate the device */
	case 3: /* Request Eject */
	{
		ddi_hp_cn_state_t target_state;

		/*
		 * Ignore the event if ATTN button is not present (ACPI BIOS
		 * problem).
		 *
		 * NOTE: This situation has been observed on some platforms
		 * where the ACPI BIOS is generating the event for some other
		 * (non hot-plug) operations (bug).
		 */
		if (ctrl_p->hc_has_attn == B_FALSE) {
			PCIE_DBG("Ignore the unexpected event "
			    "on slot #%d (state 0x%x)",
			    slot_p->hs_phy_slot_num, dev_state);
			break;
		}

		/* send the event to DDI Hotplug framework */
		if (curr_state < DDI_HP_CN_STATE_POWERED) {
			/* Insertion. Upgrade state to ENABLED */
			target_state = DDI_HP_CN_STATE_ENABLED;

			/*
			 * When pressing ATTN button to enable a card, the slot
			 * could be powered. Keep the slot state on PWOERED
			 * other than ENABLED.
			 */
			if (slot_p->hs_info.cn_state == DDI_HP_CN_STATE_ENABLED)
				slot_p->hs_info.cn_state =
				    DDI_HP_CN_STATE_POWERED;
		} else {
			/* Want to remove; Power off Connection */
			target_state = DDI_HP_CN_STATE_EMPTY;
		}

		(void) ndi_hp_state_change_req(slot_p->hs_ctrl->hc_dip,
		    slot_p->hs_info.cn_name,
		    target_state, DDI_HP_REQ_ASYNC);

		break;
	}
	default:
		cmn_err(CE_NOTE, "Unknown Notify() event %d on slot #%d\n",
		    val, slot_p->hs_phy_slot_num);
		break;
	}
	mutex_exit(&ctrl_p->hc_mutex);
}

static void
pciehpc_acpi_uninstall_event_handler(pcie_hp_ctrl_t *ctrl_p)
{
	pciehpc_acpi_t *acpi_p = ctrl_p->hc_misc_data;
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];

	PCIE_DBG("Uninstall event handler for slot #%d\n",
	    slot_p->hs_phy_slot_num);
	(void) AcpiRemoveNotifyHandler(acpi_p->slot_dev_obj,
	    ACPI_SYSTEM_NOTIFY, pciehpc_acpi_notify_handler);
	(void) AcpiRemoveNotifyHandler(acpi_p->bus_obj,
	    ACPI_SYSTEM_NOTIFY, pciehpc_acpi_notify_handler);
}

/*
 * Run _PS0 method to turn on power to the slot.
 */
static ACPI_STATUS
pciehpc_acpi_power_on_slot(pcie_hp_ctrl_t *ctrl_p)
{
	int status = AE_OK;
	pciehpc_acpi_t *acpi_p = ctrl_p->hc_misc_data;
	int dev_state = 0;
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];

	PCIE_DBG("turn ON power to the slot #%d\n", slot_p->hs_phy_slot_num);

	status = AcpiEvaluateObject(acpi_p->slot_dev_obj, "_PS0", NULL, NULL);

	/* get the state of the device (from _STA method) */
	if (status == AE_OK) {
		if (pciehpc_acpi_get_dev_state(acpi_p->slot_dev_obj,
		    &dev_state) != AE_OK)
			cmn_err(CE_WARN, "failed to get device status "
			    "on slot #%d", slot_p->hs_phy_slot_num);
	}

	PCIE_DBG("(3)device state on slot #%d: 0x%x\n",
	    slot_p->hs_phy_slot_num, dev_state);

	pciehpc_get_slot_state(slot_p);

	if (slot_p->hs_info.cn_state < DDI_HP_CN_STATE_POWERED) {
		cmn_err(CE_WARN, "failed to power on the slot #%d"
		    "(dev_state 0x%x, ACPI_STATUS 0x%x)",
		    slot_p->hs_phy_slot_num, dev_state, status);
		return (AE_ERROR);
	}

	return (status);
}

/*
 * Run _EJ0 method to turn off power to the slot.
 */
static ACPI_STATUS
pciehpc_acpi_power_off_slot(pcie_hp_ctrl_t *ctrl_p)
{
	int status = AE_OK;
	pciehpc_acpi_t *acpi_p = ctrl_p->hc_misc_data;
	int dev_state = 0;
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];

	PCIE_DBG("turn OFF power to the slot #%d\n", slot_p->hs_phy_slot_num);

	status = AcpiEvaluateObject(acpi_p->slot_dev_obj, "_EJ0", NULL, NULL);

	/* get the state of the device (from _STA method) */
	if (status == AE_OK) {
		if (pciehpc_acpi_get_dev_state(acpi_p->slot_dev_obj,
		    &dev_state) != AE_OK)
			cmn_err(CE_WARN, "failed to get device status "
			    "on slot #%d", slot_p->hs_phy_slot_num);
	}

	PCIE_DBG("(2)device state on slot #%d: 0x%x\n",
	    slot_p->hs_phy_slot_num, dev_state);

	pciehpc_get_slot_state(slot_p);

	if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_POWERED) {
		cmn_err(CE_WARN, "failed to power OFF the slot #%d"
		    "(dev_state 0x%x, ACPI_STATUS 0x%x)",
		    slot_p->hs_phy_slot_num, dev_state, status);
		return (AE_ERROR);
	}

	return (status);
}

/*
 * Get the status info (as returned by _STA method) for the device.
 */
static ACPI_STATUS
pciehpc_acpi_get_dev_state(ACPI_HANDLE obj, int *statusp)
{
	int status;
	ACPI_STATUS ret;

	ret = acpica_get_object_status(obj, &status);
	if (ACPI_SUCCESS(ret)) {
		*statusp = status;
	}

	return (ret);
}
