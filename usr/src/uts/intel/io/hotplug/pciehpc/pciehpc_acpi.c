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
 *  Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 *  Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ACPI interface related functions used in PCIEHPC driver module.
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
#include "pciehpc_acpi.h"

/* local static functions */
static int pciehpc_acpi_hpc_init(pciehpc_t *ctrl_p);
static int pciehpc_acpi_hpc_uninit(pciehpc_t *ctrl_p);
static int pciehpc_acpi_slotinfo_init(pciehpc_t *ctrl_p);
static int pciehpc_acpi_slotinfo_uninit(pciehpc_t *ctrl_p);
static int pciehpc_acpi_enable_intr(pciehpc_t *ctrl_p);
static int pciehpc_acpi_disable_intr(pciehpc_t *ctrl_p);
static int pciehpc_acpi_slot_connect(caddr_t ops_arg, hpc_slot_t slot_hdl,
	void *data, uint_t flags);
static int pciehpc_acpi_slot_disconnect(caddr_t ops_arg, hpc_slot_t slot_hdl,
	void *data, uint_t flags);

static ACPI_STATUS pciehpc_acpi_install_event_handler(pciehpc_t *ctrl_p);
static void pciehpc_acpi_uninstall_event_handler(pciehpc_t *ctrl_p);
static ACPI_STATUS pciehpc_acpi_power_on_slot(pciehpc_t *ctrl_p);
static ACPI_STATUS pciehpc_acpi_power_off_slot(pciehpc_t *ctrl_p);
static void pciehpc_acpi_notify_handler(ACPI_HANDLE device, uint32_t val,
	void *context);
static ACPI_STATUS pciehpc_acpi_ej0_present(ACPI_HANDLE pcibus_obj);
static ACPI_STATUS pciehpc_acpi_get_dev_state(ACPI_HANDLE obj, int *statusp);
ACPI_STATUS pciehpc_acpi_eval_osc(ACPI_HANDLE osc_hdl, uint32_t *hp_mode);
static ACPI_STATUS pciehpc_acpi_find_osc(ACPI_HANDLE busobj,
	ACPI_HANDLE *osc_hdlp);

#ifdef DEBUG
static void pciehpc_dump_acpi_obj(ACPI_HANDLE pcibus_obj);
static ACPI_STATUS pciehpc_walk_obj_namespace(ACPI_HANDLE hdl, uint32_t nl,
	void *context, void **ret);
static ACPI_STATUS pciehpc_print_acpi_name(ACPI_HANDLE hdl, uint32_t nl,
	void *context, void **ret);
static void print_acpi_pathname(ACPI_HANDLE hdl);
#endif

/* UUID for for PCI/PCI-X/PCI-Exp hierarchy as defined in PCI fw ver 3.0 */
static uint8_t pcie_uuid[16] =
	{0x5b, 0x4d, 0xdb, 0x33, 0xf7, 0x1f, 0x1c, 0x40,
	0x96, 0x57, 0x74, 0x41, 0xc0, 0x3d, 0xd7, 0x66};
/*
 * Function to check if ACPI hot plug is enabled on this bridge device.
 * Since there is no absolute way to figure out if ACPI BIOS has hot plug
 * control, the following approach is necessary:
 *
 *	1) If _OSC method is present then it is straight forward.
 *	2) Otherwise, we need platform specific way to determine
 *	   whether ACPI BIOS has hot plug control or not.
 *	   (e.g: using .conf file property)
 *
 * NOTE: As per the PCI FW 3.0 spec, in the absence of _OSC method OS
 * should not try to do native hot plug control.
 *
 * Returns 0 if the current mode is not ACPI hot plug.
 */
int
pciehpc_acpi_hotplug_enabled(dev_info_t *dip)
{
	int *hotplug_mode;
	uint_t count;
	ACPI_HANDLE pcibus_obj;
	int status = AE_ERROR;
	ACPI_HANDLE osc_hdl;
	int use_native_hotplug = 0;
	uint32_t hp_mode;

	/*
	 * (1)  Find the ACPI device node for this bus node.
	 */
	status = acpica_get_handle(dip, &pcibus_obj);
	if (status != AE_OK) {
		/*
		 * No ACPI device for this bus node. Assume there is
		 * no ACPI hot plug support on this bus.
		 */
		PCIEHPC_DEBUG((CE_CONT, "No ACPI device found (dip %p)\n",
		    (void *)dip));
		PCIEHPC_DEBUG((CE_CONT, "Assuming native Hot-Plug mode\n"));
		return (0);
	}


	/*
	 * NOTE: Without _OSC method there is no reliable way to know if the
	 * platform implements ACPI hot plug or native hot plug. But, if it is
	 * present then it may be possible to use either mode (i.e ACPI or
	 * native-hotplug) if the platform supports both.
	 */

	/*
	 * (2)	Check if _OSC method is present.
	 */
	if (pciehpc_acpi_find_osc(pcibus_obj, &osc_hdl) != AE_OK) {
		/* no _OSC method present; we need to guess here! */
		PCIEHPC_DEBUG((CE_NOTE, "no _OSC method present\n"));
		/*
		 * If "use-native-hotplug-mode" property set then it means
		 * the platform supports only native hot-plug mode.
		 */
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "use-native-hotplug-mode",
		    &hotplug_mode, &count) == DDI_PROP_SUCCESS) {
			if (hotplug_mode[0] == 1)
				use_native_hotplug = 1;
			ddi_prop_free(hotplug_mode);
		}
		if (use_native_hotplug) {
			PCIEHPC_DEBUG((CE_NOTE,
			    "Assuming native Hot-Plug mode\n"));
			return (0); /* assume native hot plug mode */
		} else {
			PCIEHPC_DEBUG((CE_NOTE,
			    "Assuming legacy ACPI Hot-Plug mode\n"));
			return (1); /* assume ACPI hot plug mode */
		}
	}

	/*
	 * (3)	_OSC method exists; evaluate _OSC to use native hot-plug mode.
	 *
	 * Note: The default policy is to use native hot-plug mode if the
	 * platform supports it.
	 */
	if (pciehpc_acpi_eval_osc(osc_hdl, &hp_mode) != AE_OK) {
		/* failed to evaluate _OSC method; assume ACPI hot plug */
		PCIEHPC_DEBUG((CE_NOTE, "Failed to evaluate _OSC; "
		    "Assuming legacy ACPI Hot-Plug mode\n"));
		return (1);
	}

#ifdef DEBUG
	if (pciehpc_debug > 1)
		pciehpc_dump_acpi_obj(pcibus_obj);
#endif
	if (hp_mode == NATIVE_HP_MODE) {
		PCIEHPC_DEBUG((CE_NOTE, "Native Hot-Plug mode enabled\n"));
		return (0); /* it is in native hp mode! */
	}

	PCIEHPC_DEBUG((CE_NOTE, "ACPI Hot-Plug mode enabled\n"));
	return (1); /* use ACPI mode */
}

void
pciehpc_acpi_setup_ops(pciehpc_t *ctrl_p)
{
	ctrl_p->ops.init_hpc_hw = pciehpc_acpi_hpc_init;
	ctrl_p->ops.init_hpc_slotinfo = pciehpc_acpi_slotinfo_init;
	ctrl_p->ops.disable_hpc_intr = pciehpc_acpi_disable_intr;
	ctrl_p->ops.enable_hpc_intr = pciehpc_acpi_enable_intr;
	ctrl_p->ops.uninit_hpc_hw = pciehpc_acpi_hpc_uninit;
	ctrl_p->ops.uninit_hpc_slotinfo = pciehpc_acpi_slotinfo_uninit;
}

/*
 * Intialize hot plug control for ACPI mode.
 */
static int
pciehpc_acpi_hpc_init(pciehpc_t *ctrl_p)
{
	ACPI_HANDLE pcibus_obj;
	int status = AE_ERROR;
	ACPI_HANDLE slot_dev_obj;
	ACPI_HANDLE hdl;
	pciehpc_acpi_t *acpi_p;
	uint16_t bus_methods = 0;
	uint16_t slot_methods = 0;

	/* get the ACPI object for the bus node */
	status = acpica_get_handle(ctrl_p->dip, &pcibus_obj);
	if (status != AE_OK)
		return (DDI_FAILURE);

	/* get the ACPI object handle for the child node */
	status = AcpiGetNextObject(ACPI_TYPE_DEVICE, pcibus_obj,
			NULL, &slot_dev_obj);
	if (status != AE_OK)
		return (DDI_FAILURE);

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
	ctrl_p->misc_data = acpi_p;
	ctrl_p->hp_mode = PCIEHPC_ACPI_HP_MODE;

	/* initialize the slot mutex */
	mutex_init(&ctrl_p->pciehpc_mutex, NULL, MUTEX_DRIVER,
		(void *)PCIEHPC_INTR_PRI);

	return (DDI_SUCCESS);
}

/*
 * Uninitialize HPC.
 */
static int
pciehpc_acpi_hpc_uninit(pciehpc_t *ctrl_p)
{
	/* free up buffer used for misc_data */
	if (ctrl_p->misc_data) {
		kmem_free(ctrl_p->misc_data, sizeof (pciehpc_acpi_t));
		ctrl_p->misc_data = NULL;
	}

	/* destroy the mutex */
	mutex_destroy(&ctrl_p->pciehpc_mutex);

	return (DDI_SUCCESS);
}

/*
 * Enable interrupts. For ACPI hot plug this is a NOP.
 * Just return DDI_SUCCESS.
 */
/*ARGSUSED*/
static int
pciehpc_acpi_enable_intr(pciehpc_t *ctrl_p)
{
	return (DDI_SUCCESS);
}

/*
 * Disable interrupts. For ACPI hot plug this is a NOP.
 * Just return DDI_SUCCESS.
 */
/*ARGSUSED*/
static int
pciehpc_acpi_disable_intr(pciehpc_t *ctrl_p)
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
pciehpc_acpi_slotinfo_init(pciehpc_t *ctrl_p)
{
	uint32_t slot_capabilities;
	pciehpc_slot_t *p = &ctrl_p->slot;

	/*
	 * setup HPS framework slot ops structure
	 */
	p->slot_ops.hpc_version = HPC_SLOT_OPS_VERSION;
	p->slot_ops.hpc_op_connect = pciehpc_acpi_slot_connect;
	p->slot_ops.hpc_op_disconnect = pciehpc_acpi_slot_disconnect;
	p->slot_ops.hpc_op_insert = NULL;
	p->slot_ops.hpc_op_remove = NULL;
	p->slot_ops.hpc_op_control = pciehpc_slot_control;

	/*
	 * setup HPS framework slot information structure
	 */
	p->slot_info.version = HPC_SLOT_OPS_VERSION;
	p->slot_info.slot_type = HPC_SLOT_TYPE_PCIE;
	p->slot_info.slot_flags =
		HPC_SLOT_CREATE_DEVLINK | HPC_SLOT_NO_AUTO_ENABLE;
	p->slot_info.pci_slot_capabilities = HPC_SLOT_64BITS;
	/* the device number is fixed as 0 as per the spec  */
	p->slot_info.pci_dev_num = 0;

	/* read Slot Capabilities Register */
	slot_capabilities = pciehpc_reg_get32(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCAP);

	/* setup slot number/name */
	pciehpc_set_slot_name(ctrl_p);

	/* check if Attn Button present */
	ctrl_p->has_attn = (slot_capabilities & PCIE_SLOTCAP_ATTN_BUTTON) ?
		B_TRUE : B_FALSE;

	/* check if Manual Retention Latch sensor present */
	ctrl_p->has_mrl = (slot_capabilities & PCIE_SLOTCAP_MRL_SENSOR) ?
		B_TRUE : B_FALSE;

	/*
	 * PCI-E (draft) version 1.1 defines EMI Lock Present bit
	 * in Slot Capabilities register. Check for it.
	 */
	ctrl_p->has_emi_lock = (slot_capabilities &
		PCIE_SLOTCAP_EMI_LOCK_PRESENT) ? B_TRUE : B_FALSE;

	/* initialize synchronization conditional variable */
	cv_init(&ctrl_p->slot.cmd_comp_cv, NULL, CV_DRIVER, NULL);
	ctrl_p->slot.command_pending = B_FALSE;

	/* get current slot state from the hw */
	pciehpc_get_slot_state(ctrl_p);

	/* setup Notify() handler for hot plug events from ACPI BIOS */
	if (pciehpc_acpi_install_event_handler(ctrl_p) != AE_OK)
		return (DDI_FAILURE);

	PCIEHPC_DEBUG((CE_NOTE, "ACPI hot plug is enabled for slot #%d\n",
		    ctrl_p->slot.slotNum));

	return (DDI_SUCCESS);
}

/*
 * This function is similar to pciehcp_slotinfo_uninit() but has ACPI
 * specific cleanup.
 */
static int
pciehpc_acpi_slotinfo_uninit(pciehpc_t *ctrl_p)
{
	/* uninstall Notify() event handler */
	pciehpc_acpi_uninstall_event_handler(ctrl_p);

	cv_destroy(&ctrl_p->slot.cmd_comp_cv);

	return (DDI_SUCCESS);
}

/*
 * This function is same as pciehpc_slot_connect() except that it
 * uses ACPI method PS0 to enable power to the slot. If no PS0 method
 * is present then it returns HPC_ERR_FAILED.
 */
/*ARGSUSED*/
static int
pciehpc_acpi_slot_connect(caddr_t ops_arg, hpc_slot_t slot_hdl,
	void *data, uint_t flags)
{
	uint16_t status;
	uint16_t control;

	pciehpc_t *ctrl_p = (pciehpc_t *)ops_arg;

	ASSERT(slot_hdl == ctrl_p->slot.slot_handle);

	mutex_enter(&ctrl_p->pciehpc_mutex);

	/* get the current state of the slot */
	pciehpc_get_slot_state(ctrl_p);

	/* check if the slot is already in the 'connected' state */
	if (ctrl_p->slot.slot_state == HPC_SLOT_CONNECTED) {
		/* slot is already in the 'connected' state */
		PCIEHPC_DEBUG((CE_NOTE, "slot %d already connected\n",
		    ctrl_p->slot.slotNum));
		mutex_exit(&ctrl_p->pciehpc_mutex);
		return (HPC_SUCCESS);
	}

	/* read the Slot Status Register */
	status =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);

	/* make sure the MRL switch is closed if present */
	if ((ctrl_p->has_mrl) && (status & PCIE_SLOTSTS_MRL_SENSOR_OPEN)) {
		/* MRL switch is open */
		cmn_err(CE_WARN, "MRL switch is open on slot %d",
			ctrl_p->slot.slotNum);
		goto cleanup;
	}

	/* make sure the slot has a device present */
	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED)) {
		/* slot is empty */
		PCIEHPC_DEBUG((CE_NOTE, "slot %d is empty\n",
		    ctrl_p->slot.slotNum));
		goto cleanup;
	}

	/* get the current state of Slot Control Register */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	/* check if the slot's power state is ON */
	if (!(control & PCIE_SLOTCTL_PWR_CONTROL)) {
		/* slot is already powered up */
		PCIEHPC_DEBUG((CE_NOTE, "slot %d already connected\n",
		    ctrl_p->slot.slotNum));
		ctrl_p->slot.slot_state = HPC_SLOT_CONNECTED;
		mutex_exit(&ctrl_p->pciehpc_mutex);
		return (HPC_SUCCESS);
	}

	/* turn on power to the slot using ACPI method (PS0) */
	if (pciehpc_acpi_power_on_slot(ctrl_p) != AE_OK)
		goto cleanup;

	ctrl_p->slot.slot_state = HPC_SLOT_CONNECTED;
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_SUCCESS);

cleanup:
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_ERR_FAILED);
}

/*
 * This function is same as pciehpc_slot_disconnect() except that it
 * uses ACPI method EJ0 to disable power to the slot. If no EJ0 method
 * is present then it returns HPC_ERR_FAILED.
 */
/*ARGSUSED*/
static int
pciehpc_acpi_slot_disconnect(caddr_t ops_arg, hpc_slot_t slot_hdl,
	void *data, uint_t flags)
{
	uint16_t status;

	pciehpc_t *ctrl_p = (pciehpc_t *)ops_arg;

	ASSERT(slot_hdl == ctrl_p->slot.slot_handle);

	mutex_enter(&ctrl_p->pciehpc_mutex);

	/* get the current state of the slot */
	pciehpc_get_slot_state(ctrl_p);

	/* check if the slot is already in the 'disconnected' state */
	if (ctrl_p->slot.slot_state == HPC_SLOT_DISCONNECTED) {
		/* slot is in the 'disconnected' state */
		PCIEHPC_DEBUG((CE_NOTE, "slot %d already disconnected\n",
		    ctrl_p->slot.slotNum));
		ASSERT(ctrl_p->slot.power_led_state == HPC_LED_OFF);
		mutex_exit(&ctrl_p->pciehpc_mutex);
		return (HPC_SUCCESS);
	}

	/* read the Slot Status Register */
	status =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);

	/* make sure the slot has a device present */
	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED)) {
		/* slot is empty */
		PCIEHPC_DEBUG((CE_WARN, "slot %d is empty",
		    ctrl_p->slot.slotNum));
		goto cleanup;
	}

	/* turn off power to the slot using ACPI method (EJ0) */
	if (pciehpc_acpi_power_off_slot(ctrl_p) != AE_OK)
		goto cleanup;

	ctrl_p->slot.slot_state = HPC_SLOT_DISCONNECTED;
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_SUCCESS);

cleanup:
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_ERR_FAILED);
}

/*
 * Install event handler for the hot plug events on the bus node as well
 * as device function (dev=0,func=0).
 */
static ACPI_STATUS
pciehpc_acpi_install_event_handler(pciehpc_t *ctrl_p)
{
	int status = AE_OK;
	pciehpc_acpi_t *acpi_p;

	PCIEHPC_DEBUG3((CE_CONT, "install event handler for slot %d\n",
		ctrl_p->slot.slotNum));
	acpi_p = ctrl_p->misc_data;
	if (acpi_p->slot_dev_obj == NULL)
		return (AE_NOT_FOUND);

	/*
	 * Install event hanlder for events on the bus object.
	 * (Note: Insert event (hot-insert) is delivered on this object)
	 */
	status = AcpiInstallNotifyHandler(acpi_p->slot_dev_obj,
		ACPI_SYSTEM_NOTIFY,
		pciehpc_acpi_notify_handler, (void *)ctrl_p);
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
		ACPI_SYSTEM_NOTIFY,
		pciehpc_acpi_notify_handler, (void *)ctrl_p);
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
	pciehpc_t *ctrl_p = context;
	pciehpc_acpi_t *acpi_p;
	int dev_state = 0;

	PCIEHPC_DEBUG((CE_CONT, "received Notify(%d) event on slot #%d\n",
	    val, ctrl_p->slot.slotNum));

	mutex_enter(&ctrl_p->pciehpc_mutex);

	/*
	 * get the state of the device (from _STA method)
	 */
	acpi_p = ctrl_p->misc_data;
	if (pciehpc_acpi_get_dev_state(acpi_p->slot_dev_obj,
		&dev_state) != AE_OK) {
		cmn_err(CE_WARN, "failed to get device status on slot %d",
			ctrl_p->slot.slotNum);
	}
	PCIEHPC_DEBUG((CE_CONT, "(1)device state on slot #%d: 0x%x\n",
				ctrl_p->slot.slotNum, dev_state));

	pciehpc_get_slot_state(ctrl_p);

	switch (val) {
	case 0: /* (re)enumerate the device */
	case 3: /* Request Eject */
		if (ctrl_p->slot.slot_state != HPC_SLOT_CONNECTED) {
		    /* unexpected slot state; surprise removal? */
		    cmn_err(CE_WARN, "Unexpected event on slot #%d"
			"(state 0x%x)", ctrl_p->slot.slotNum, dev_state);
		}
		/* send the ATTN button event to HPS framework */
		(void) hpc_slot_event_notify(ctrl_p->slot.slot_handle,
			HPC_EVENT_SLOT_ATTN, HPC_EVENT_NORMAL);
		break;
	default:
		cmn_err(CE_NOTE, "Unknown Notify() event %d on slot #%d\n",
			val, ctrl_p->slot.slotNum);
		break;
	}
	mutex_exit(&ctrl_p->pciehpc_mutex);
}

static void
pciehpc_acpi_uninstall_event_handler(pciehpc_t *ctrl_p)
{
	pciehpc_acpi_t *acpi_p = ctrl_p->misc_data;

	PCIEHPC_DEBUG((CE_CONT, "Uninstall event handler for slot #%d\n",
		ctrl_p->slot.slotNum));
	(void) AcpiRemoveNotifyHandler(acpi_p->slot_dev_obj,
		ACPI_SYSTEM_NOTIFY, pciehpc_acpi_notify_handler);
	(void) AcpiRemoveNotifyHandler(acpi_p->bus_obj,
		ACPI_SYSTEM_NOTIFY, pciehpc_acpi_notify_handler);
}

/*
 * Run _PS0 method to turn on power to the slot.
 */
static ACPI_STATUS
pciehpc_acpi_power_on_slot(pciehpc_t *ctrl_p)
{
	int status = AE_OK;
	pciehpc_acpi_t *acpi_p = ctrl_p->misc_data;
	int dev_state = 0;

	PCIEHPC_DEBUG((CE_CONT, "turn ON power to the slot #%d\n",
		ctrl_p->slot.slotNum));

	status = AcpiEvaluateObject(acpi_p->slot_dev_obj, "_PS0", NULL, NULL);

	/* get the state of the device (from _STA method) */
	if (status == AE_OK) {
	    if (pciehpc_acpi_get_dev_state(acpi_p->slot_dev_obj,
		&dev_state) != AE_OK)
		cmn_err(CE_WARN, "failed to get device status on slot #%d",
			ctrl_p->slot.slotNum);
	}
	PCIEHPC_DEBUG((CE_CONT, "(3)device state on slot #%d: 0x%x\n",
				ctrl_p->slot.slotNum, dev_state));

	pciehpc_get_slot_state(ctrl_p);

	if (ctrl_p->slot.slot_state != HPC_SLOT_CONNECTED) {
		cmn_err(CE_WARN, "failed to power on the slot #%d"
			"(dev_state 0x%x, ACPI_STATUS 0x%x)",
			ctrl_p->slot.slotNum, dev_state, status);
		return (AE_ERROR);
	}

	return (status);
}

/*
 * Run _EJ0 method to turn off power to the slot.
 */
static ACPI_STATUS
pciehpc_acpi_power_off_slot(pciehpc_t *ctrl_p)
{
	int status = AE_OK;
	pciehpc_acpi_t *acpi_p = ctrl_p->misc_data;
	int dev_state = 0;

	PCIEHPC_DEBUG((CE_CONT, "turn OFF power to the slot #%d\n",
		ctrl_p->slot.slotNum));

	status = AcpiEvaluateObject(acpi_p->slot_dev_obj, "_EJ0", NULL, NULL);

	/* get the state of the device (from _STA method) */
	if (status == AE_OK) {
	    if (pciehpc_acpi_get_dev_state(acpi_p->slot_dev_obj,
		&dev_state) != AE_OK)
		cmn_err(CE_WARN, "failed to get device status on slot #%d",
			ctrl_p->slot.slotNum);
	}
	PCIEHPC_DEBUG((CE_CONT, "(2)device state on slot #%d: 0x%x\n",
				ctrl_p->slot.slotNum, dev_state));

	pciehpc_get_slot_state(ctrl_p);

	if (ctrl_p->slot.slot_state == HPC_SLOT_CONNECTED) {
		cmn_err(CE_WARN, "failed to power OFF the slot #%d"
			"(dev_state 0x%x, ACPI_STATUS 0x%x)",
			ctrl_p->slot.slotNum, dev_state, status);
		return (AE_ERROR);
	}

	return (status);
}

/*
 * Check if the child device node of the bus object has _EJ0 method
 * present.
 */
static ACPI_STATUS
pciehpc_acpi_ej0_present(ACPI_HANDLE pcibus_obj)
{
	int status = AE_OK;
	ACPI_HANDLE d0f0_obj;
	ACPI_HANDLE ej0_hdl;

	if ((status = AcpiGetNextObject(ACPI_TYPE_DEVICE, pcibus_obj,
		NULL, &d0f0_obj)) == AE_OK) {
		/* child device node(s) are present; check for _EJ0 method */
		status = AcpiGetHandle(d0f0_obj, "_EJ0", &ej0_hdl);
	}

	return (status);
}


/*
 * Get the status info (as returned by _STA method) for the device.
 */
static ACPI_STATUS
pciehpc_acpi_get_dev_state(ACPI_HANDLE obj, int *statusp)
{
	ACPI_BUFFER	rb;
	ACPI_DEVICE_INFO *info = NULL;
	int ret = AE_OK;

	/*
	 * Get device info object
	 */
	rb.Length = ACPI_ALLOCATE_BUFFER;
	rb.Pointer = NULL;
	if ((ret = AcpiGetObjectInfo(obj, &rb)) != AE_OK)
		return (ret);
	info = (ACPI_DEVICE_INFO *)rb.Pointer;

	if (info->Valid & ACPI_VALID_STA) {
		*statusp = info->CurrentStatus;
	} else {
		/*
		 * no _STA present; assume the device status is normal
		 * (i.e present, enabled, shown in UI and functioning).
		 * See section 6.3.7 of ACPI 3.0 spec.
		 */
		*statusp = STATUS_NORMAL;
	}

	AcpiOsFree(info);

	return (ret);
}

/*
 * Evaluate _OSC method to use native hot-plug mode if platform supports it.
 * If platform doesn't support native hot-plug then hp_mode will be set
 * to ACPI_HP_MODE.
 */
ACPI_STATUS
pciehpc_acpi_eval_osc(ACPI_HANDLE osc_hdl, uint32_t *hp_mode)
{
	ACPI_STATUS		status;
	ACPI_OBJECT_LIST	arglist;
	ACPI_OBJECT		args[4];
	UINT32			caps_buffer[3];
	ACPI_BUFFER		rb;
	ACPI_OBJECT		*rv;
	UINT32			*rbuf;

	/* construct argument list */
	arglist.Count = 4;
	arglist.Pointer = args;

	/* arg0 - UUID */
	args[0].Type = ACPI_TYPE_BUFFER;
	args[0].Buffer.Length = 16; /* size of UUID string */
	args[0].Buffer.Pointer = pcie_uuid;

	/* arg1 - Revision ID */
	args[1].Type = ACPI_TYPE_INTEGER;
	args[1].Integer.Value = PCIE_OSC_REVISION_ID;

	/* arg2 - Count */
	args[2].Type = ACPI_TYPE_INTEGER;
	args[2].Integer.Value = 3; /* no. of DWORDS in caps_buffer */

	/* arg3 - Capabilities Buffer */
	args[3].Type = ACPI_TYPE_BUFFER;
	args[3].Buffer.Length = 12;
	args[3].Buffer.Pointer = (void *)caps_buffer;

	/* Initialize Capabilities Buffer */

	/* DWORD1: no query flag set */
	caps_buffer[0] = 0;
	/* DWORD2: Support Field */
	caps_buffer[1] = OSC_SUPPORT_FIELD_INIT;
	/* DWORD3: Control Field */
	caps_buffer[2] = OSC_CONTROL_FIELD_INIT;

	rb.Length = ACPI_ALLOCATE_BUFFER;
	rb.Pointer = NULL;

	status = AcpiEvaluateObject(osc_hdl, NULL, &arglist, &rb);

	if (status != AE_OK) {
		PCIEHPC_DEBUG((CE_CONT,
		    "Failed to execute _OSC method (status %d)\n", status));
		return (status);
	}

	rv = rb.Pointer;
	if (rv == NULL || rv->Type != ACPI_TYPE_BUFFER) {
		PCIEHPC_DEBUG((CE_CONT,
		    "Failed to execute _OSC method -- bad status\n"));
		return (AE_ERROR);
	}
	rbuf = (UINT32 *)rv->Buffer.Pointer;

	/* check the STATUS word in the capability buffer */
	if (rbuf[0] & OSC_STATUS_ERRORS) {
		PCIEHPC_DEBUG((CE_CONT, "_OSC method failed (STATUS %d)\n",
		    rbuf[0]));
		AcpiOsFree(rv);
		return (AE_ERROR);
	}

	PCIEHPC_DEBUG((CE_CONT, "_OSC method evaluation completed: "
	    "STATUS 0x%x SUPPORT 0x%x CONTROL 0x%x\n",
	    rbuf[0], rbuf[1], rbuf[2]));

	/* check if the Native Hot-Plug Control is granted */
	if (rbuf[2] & OSC_CONTROL_PCIE_NAT_HP)
		*hp_mode = NATIVE_HP_MODE;
	else
		*hp_mode = ACPI_HP_MODE;

	AcpiOsFree(rv);

	return (AE_OK);
}

#ifdef DEBUG
static void
pciehpc_dump_acpi_obj(ACPI_HANDLE pcibus_obj)
{
	int status;
	ACPI_BUFFER retbuf;

	if (pcibus_obj == NULL)
		return;

	/* print the full path name */
	retbuf.Pointer = NULL;
	retbuf.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiGetName(pcibus_obj, ACPI_FULL_PATHNAME, &retbuf);
	if (status != AE_OK)
		return;
	cmn_err(CE_CONT, "PCIE BUS PATHNAME: %s\n", (char *)retbuf.Pointer);
	AcpiOsFree(retbuf.Pointer);

	/* dump all the methods for this bus node */
	cmn_err(CE_CONT, "  METHODS: \n");
	status = AcpiWalkNamespace(ACPI_TYPE_METHOD, pcibus_obj, 1,
			pciehpc_print_acpi_name, "  ", NULL);
	/* dump all the child devices */
	status = AcpiWalkNamespace(ACPI_TYPE_DEVICE, pcibus_obj, 1,
			pciehpc_walk_obj_namespace, NULL, NULL);
}

/*ARGSUSED*/
static ACPI_STATUS
pciehpc_walk_obj_namespace(ACPI_HANDLE hdl, uint32_t nl, void *context,
	void **ret)
{
	int status;
	ACPI_BUFFER retbuf;
	char buf[32];

	/* print the full path name */
	retbuf.Pointer = NULL;
	retbuf.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiGetName(hdl, ACPI_FULL_PATHNAME, &retbuf);
	if (status != AE_OK)
		return (status);
	buf[0] = 0;
	while (nl--)
	    (void) strcat(buf, "  ");
	cmn_err(CE_CONT, "%sDEVICE: %s\n", buf, (char *)retbuf.Pointer);
	AcpiOsFree(retbuf.Pointer);

	/* dump all the methods for this device */
	cmn_err(CE_CONT, "%s  METHODS: \n", buf);
	status = AcpiWalkNamespace(ACPI_TYPE_METHOD, hdl, 1,
			pciehpc_print_acpi_name, (void *)buf, NULL);
	return (status);
}

/*ARGSUSED*/
static ACPI_STATUS
pciehpc_print_acpi_name(ACPI_HANDLE hdl, uint32_t nl, void *context, void **ret)
{
	int status;
	ACPI_BUFFER retbuf;
	char name[16];

	retbuf.Pointer = name;
	retbuf.Length = 16;
	status = AcpiGetName(hdl, ACPI_SINGLE_NAME, &retbuf);
	if (status == AE_OK)
		cmn_err(CE_CONT, "%s    %s \n", (char *)context, name);
	return (AE_OK);
}

static void
print_acpi_pathname(ACPI_HANDLE hdl)
{
	int status;
	ACPI_BUFFER retbuf;

	retbuf.Pointer = NULL;
	retbuf.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiGetName(hdl, ACPI_FULL_PATHNAME, &retbuf);
	if (status == AE_OK) {
		cmn_err(CE_CONT, "%s \n", (char *)retbuf.Pointer);
		AcpiOsFree(retbuf.Pointer);
	}
}
#endif

static ACPI_STATUS
pciehpc_acpi_find_osc(ACPI_HANDLE busobj, ACPI_HANDLE *osc_hdlp)
{
	ACPI_HANDLE parentobj = busobj;
	ACPI_STATUS status = AE_NOT_FOUND;

	*osc_hdlp = NULL;

	/*
	 * Walk up the ACPI device tree looking for _OSC method.
	 */
	do {
		busobj = parentobj;
		if ((status = AcpiGetHandle(busobj, "_OSC", osc_hdlp)) == AE_OK)
			break;
	} while (AcpiGetParent(busobj, &parentobj) == AE_OK);

	if (*osc_hdlp == NULL)
		status = AE_NOT_FOUND;

	return (status);
}
