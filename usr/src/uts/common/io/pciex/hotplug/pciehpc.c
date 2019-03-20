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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains Standard PCI Express HotPlug functionality that is
 * compatible with the PCI Express ver 1.1 specification.
 *
 * NOTE: This file is compiled and delivered through misc/pcie module.
 */

#include <sys/types.h>
#include <sys/note.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/autoconf.h>
#include <sys/varargs.h>
#include <sys/ddi_impldefs.h>
#include <sys/time.h>
#include <sys/callb.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sysevent/dr.h>
#include <sys/pci_impl.h>
#include <sys/hotplug/pci/pcie_hp.h>
#include <sys/hotplug/pci/pciehpc.h>

typedef struct pciehpc_prop {
	char	*prop_name;
	char	*prop_value;
} pciehpc_prop_t;

static pciehpc_prop_t	pciehpc_props[] = {
	{ PCIEHPC_PROP_LED_FAULT,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_LED_POWER,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_LED_ATTN,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_LED_ACTIVE,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_CARD_TYPE,	PCIEHPC_PROP_VALUE_TYPE },
	{ PCIEHPC_PROP_BOARD_TYPE,	PCIEHPC_PROP_VALUE_TYPE },
	{ PCIEHPC_PROP_SLOT_CONDITION,	PCIEHPC_PROP_VALUE_TYPE }
};

/* Local functions prototype */
static int pciehpc_hpc_init(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_hpc_uninit(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_slotinfo_init(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_slotinfo_uninit(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_enable_intr(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_disable_intr(pcie_hp_ctrl_t *ctrl_p);
static pcie_hp_ctrl_t *pciehpc_create_controller(dev_info_t *dip);
static void pciehpc_destroy_controller(dev_info_t *dip);
static int pciehpc_register_slot(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_unregister_slot(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_slot_get_property(pcie_hp_slot_t *slot_p,
    ddi_hp_property_t *arg, ddi_hp_property_t *rval);
static int pciehpc_slot_set_property(pcie_hp_slot_t *slot_p,
    ddi_hp_property_t *arg, ddi_hp_property_t *rval);
static void pciehpc_issue_hpc_command(pcie_hp_ctrl_t *ctrl_p, uint16_t control);
static void pciehpc_attn_btn_handler(pcie_hp_ctrl_t *ctrl_p);
static pcie_hp_led_state_t pciehpc_led_state_to_hpc(uint16_t state);
static pcie_hp_led_state_t pciehpc_get_led_state(pcie_hp_ctrl_t *ctrl_p,
    pcie_hp_led_t led);
static void pciehpc_set_led_state(pcie_hp_ctrl_t *ctrl_p, pcie_hp_led_t led,
    pcie_hp_led_state_t state);

static int pciehpc_upgrade_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state);
static int pciehpc_downgrade_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state);
static int pciehpc_change_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state);
static int
    pciehpc_slot_poweron(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result);
static int
    pciehpc_slot_poweroff(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result);
static int pciehpc_slot_probe(pcie_hp_slot_t *slot_p);
static int pciehpc_slot_unprobe(pcie_hp_slot_t *slot_p);
static void pciehpc_handle_power_fault(dev_info_t *dip);
static void pciehpc_power_fault_handler(void *arg);

#ifdef	DEBUG
static void pciehpc_dump_hpregs(pcie_hp_ctrl_t *ctrl_p);
#endif	/* DEBUG */

/*
 * Global functions (called by other drivers/modules)
 */

/*
 * Initialize Hot Plug Controller if present. The arguments are:
 *	dip	- Devinfo node pointer to the hot plug bus node
 *	regops	- register ops to access HPC registers for non-standard
 *		  HPC hw implementations (e.g: HPC in host PCI-E brdiges)
 *		  This is NULL for standard HPC in PCIe bridges.
 * Returns:
 *	DDI_SUCCESS for successful HPC initialization
 *	DDI_FAILURE for errors or if HPC hw not found
 */
int
pciehpc_init(dev_info_t *dip, caddr_t arg)
{
	pcie_hp_regops_t	*regops = (pcie_hp_regops_t *)(void *)arg;
	pcie_hp_ctrl_t		*ctrl_p;

	PCIE_DBG("pciehpc_init() called (dip=%p)\n", (void *)dip);

	/* Make sure that it is not already initialized */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) != NULL) {
		PCIE_DBG("%s%d: pciehpc instance already initialized!\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_SUCCESS);
	}

	/* Allocate a new hotplug controller and slot structures */
	ctrl_p = pciehpc_create_controller(dip);

	/* setup access handle for HPC regs */
	if (regops != NULL) {
		/* HPC access is non-standard; use the supplied reg ops */
		ctrl_p->hc_regops = *regops;
	}

	/*
	 * Setup resource maps for this bus node.
	 */
	(void) pci_resource_setup(dip);

	PCIE_DISABLE_ERRORS(dip);

	/*
	 * Set the platform specific hot plug mode.
	 */
	ctrl_p->hc_ops.init_hpc_hw = pciehpc_hpc_init;
	ctrl_p->hc_ops.uninit_hpc_hw = pciehpc_hpc_uninit;
	ctrl_p->hc_ops.init_hpc_slotinfo = pciehpc_slotinfo_init;
	ctrl_p->hc_ops.uninit_hpc_slotinfo = pciehpc_slotinfo_uninit;
	ctrl_p->hc_ops.poweron_hpc_slot = pciehpc_slot_poweron;
	ctrl_p->hc_ops.poweroff_hpc_slot = pciehpc_slot_poweroff;

	ctrl_p->hc_ops.enable_hpc_intr = pciehpc_enable_intr;
	ctrl_p->hc_ops.disable_hpc_intr = pciehpc_disable_intr;

#if	defined(__i386) || defined(__amd64)
	pciehpc_update_ops(ctrl_p);
#endif

	/* initialize hot plug controller hw */
	if ((ctrl_p->hc_ops.init_hpc_hw)(ctrl_p) != DDI_SUCCESS)
		goto cleanup1;

	/* initialize slot information soft state structure */
	if ((ctrl_p->hc_ops.init_hpc_slotinfo)(ctrl_p) != DDI_SUCCESS)
		goto cleanup2;

	/* register the hot plug slot with DDI HP framework */
	if (pciehpc_register_slot(ctrl_p) != DDI_SUCCESS)
		goto cleanup3;

	/* create minor node for this slot */
	if (pcie_create_minor_node(ctrl_p, 0) != DDI_SUCCESS)
		goto cleanup4;

	/* HPC initialization is complete now */
	ctrl_p->hc_flags = PCIE_HP_INITIALIZED_FLAG;

#ifdef	DEBUG
	/* For debug, dump the HPC registers */
	pciehpc_dump_hpregs(ctrl_p);
#endif	/* DEBUG */

	return (DDI_SUCCESS);
cleanup4:
	(void) pciehpc_unregister_slot(ctrl_p);
cleanup3:
	(void) (ctrl_p->hc_ops.uninit_hpc_slotinfo)(ctrl_p);

cleanup2:
	(void) (ctrl_p->hc_ops.uninit_hpc_hw)(ctrl_p);

cleanup1:
	PCIE_ENABLE_ERRORS(dip);
	(void) pci_resource_destroy(dip);

	pciehpc_destroy_controller(dip);
	return (DDI_FAILURE);
}

/*
 * Uninitialize HPC soft state structure and free up any resources
 * used for the HPC instance.
 */
int
pciehpc_uninit(dev_info_t *dip)
{
	pcie_hp_ctrl_t *ctrl_p;

	PCIE_DBG("pciehpc_uninit() called (dip=%p)\n", (void *)dip);

	/* get the soft state structure for this dip */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	pcie_remove_minor_node(ctrl_p, 0);

	/* unregister the slot */
	(void) pciehpc_unregister_slot(ctrl_p);

	/* uninit any slot info data structures */
	(void) (ctrl_p->hc_ops.uninit_hpc_slotinfo)(ctrl_p);

	/* uninitialize hpc, remove interrupt handler, etc. */
	(void) (ctrl_p->hc_ops.uninit_hpc_hw)(ctrl_p);

	PCIE_ENABLE_ERRORS(dip);

	/*
	 * Destroy resource maps for this bus node.
	 */
	(void) pci_resource_destroy(dip);

	/* destroy the soft state structure */
	pciehpc_destroy_controller(dip);

	return (DDI_SUCCESS);
}

/*
 * pciehpc_intr()
 *
 * Interrupt handler for PCI-E Hot plug controller interrupts.
 *
 * Note: This is only for native mode hot plug. This is called
 * by the nexus driver at interrupt context. Interrupt Service Routine
 * registration is done by the nexus driver for both hot plug and
 * non-hot plug interrupts. This function is called from the ISR
 * of the nexus driver to handle hot-plug interrupts.
 */
int
pciehpc_intr(dev_info_t *dip)
{
	pcie_hp_ctrl_t	*ctrl_p;
	pcie_hp_slot_t	*slot_p;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint16_t	status, control;

	/* get the soft state structure for this dip */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL)
		return (DDI_INTR_UNCLAIMED);

	mutex_enter(&ctrl_p->hc_mutex);

	/* make sure the controller soft state is initialized */
	if (!(ctrl_p->hc_flags & PCIE_HP_INITIALIZED_FLAG)) {
		mutex_exit(&ctrl_p->hc_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	/* if it is not NATIVE hot plug mode then return */
	if (bus_p->bus_hp_curr_mode != PCIE_NATIVE_HP_MODE) {
		mutex_exit(&ctrl_p->hc_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	slot_p = ctrl_p->hc_slots[0];

	/* read the current slot status register */
	status = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);

	/* check if there are any hot plug interrupts occurred */
	if (!(status & PCIE_SLOTSTS_STATUS_EVENTS)) {
		/* no hot plug events occurred */
		mutex_exit(&ctrl_p->hc_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	/* clear the interrupt status bits */
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS, status);

	/* check for CMD COMPLETE interrupt */
	if (status & PCIE_SLOTSTS_COMMAND_COMPLETED) {
		PCIE_DBG("pciehpc_intr(): CMD COMPLETED interrupt received\n");
		/* wake up any one waiting for Command Completion event */
		cv_signal(&ctrl_p->hc_cmd_comp_cv);
	}

	/* check for ATTN button interrupt */
	if (status & PCIE_SLOTSTS_ATTN_BTN_PRESSED) {
		PCIE_DBG("pciehpc_intr(): ATTN BUTTON interrupt received\n");

		/* if ATTN button event is still pending then cancel it */
		if (slot_p->hs_attn_btn_pending == B_TRUE)
			slot_p->hs_attn_btn_pending = B_FALSE;
		else
			slot_p->hs_attn_btn_pending = B_TRUE;

		/* wake up the ATTN event handler */
		cv_signal(&slot_p->hs_attn_btn_cv);
	}

	/* check for power fault interrupt */
	if (status & PCIE_SLOTSTS_PWR_FAULT_DETECTED) {

		PCIE_DBG("pciehpc_intr(): POWER FAULT interrupt received"
		    " on slot %d\n", slot_p->hs_phy_slot_num);
		control =  pciehpc_reg_get16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTCTL);

		if (control & PCIE_SLOTCTL_PWR_FAULT_EN) {
			slot_p->hs_condition = AP_COND_FAILED;

			/* disable power fault detction interrupt */
			pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off +
			    PCIE_SLOTCTL, control & ~PCIE_SLOTCTL_PWR_FAULT_EN);

			pciehpc_handle_power_fault(dip);
		}
	}

	/* check for MRL SENSOR CHANGED interrupt */
	if (status & PCIE_SLOTSTS_MRL_SENSOR_CHANGED) {
		/* For now (phase-I), no action is taken on this event */
		PCIE_DBG("pciehpc_intr(): MRL SENSOR CHANGED interrupt received"
		    " on slot %d\n", slot_p->hs_phy_slot_num);
	}

	/* check for PRESENCE CHANGED interrupt */
	if (status & PCIE_SLOTSTS_PRESENCE_CHANGED) {

		PCIE_DBG("pciehpc_intr(): PRESENCE CHANGED interrupt received"
		    " on slot %d\n", slot_p->hs_phy_slot_num);

		if (status & PCIE_SLOTSTS_PRESENCE_DETECTED) {
			/*
			 * card is inserted into the slot, ask DDI Hotplug
			 * framework to change state to Present.
			 */
			cmn_err(CE_NOTE, "pciehpc (%s%d): card is inserted"
			    " in the slot %s",
			    ddi_driver_name(dip),
			    ddi_get_instance(dip),
			    slot_p->hs_info.cn_name);

			(void) ndi_hp_state_change_req(dip,
			    slot_p->hs_info.cn_name,
			    DDI_HP_CN_STATE_PRESENT,
			    DDI_HP_REQ_ASYNC);
		} else { /* card is removed from the slot */
			cmn_err(CE_NOTE, "pciehpc (%s%d): card is removed"
			    " from the slot %s",
			    ddi_driver_name(dip),
			    ddi_get_instance(dip),
			    slot_p->hs_info.cn_name);

			if (slot_p->hs_info.cn_state ==
			    DDI_HP_CN_STATE_ENABLED) {
				/* Card is removed when slot is enabled */
				slot_p->hs_condition = AP_COND_FAILED;
			} else {
				slot_p->hs_condition = AP_COND_UNKNOWN;
			}
			/* make sure to disable power fault detction intr */
			control =  pciehpc_reg_get16(ctrl_p,
			    bus_p->bus_pcie_off + PCIE_SLOTCTL);

			if (control & PCIE_SLOTCTL_PWR_FAULT_EN)
				pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off +
				    PCIE_SLOTCTL,
				    control & ~PCIE_SLOTCTL_PWR_FAULT_EN);

			/*
			 * Ask DDI Hotplug framework to change state to Empty
			 */
			(void) ndi_hp_state_change_req(dip,
			    slot_p->hs_info.cn_name,
			    DDI_HP_CN_STATE_EMPTY,
			    DDI_HP_REQ_ASYNC);
		}
	}

	/* check for DLL state changed interrupt */
	if (ctrl_p->hc_dll_active_rep &&
	    (status & PCIE_SLOTSTS_DLL_STATE_CHANGED)) {
		PCIE_DBG("pciehpc_intr(): DLL STATE CHANGED interrupt received"
		    " on slot %d\n", slot_p->hs_phy_slot_num);

		cv_signal(&slot_p->hs_dll_active_cv);
	}

	mutex_exit(&ctrl_p->hc_mutex);

	return (DDI_INTR_CLAIMED);
}

/*
 * Handle hotplug commands
 *
 * Note: This function is called by DDI HP framework at kernel context only
 */
/* ARGSUSED */
int
pciehpc_hp_ops(dev_info_t *dip, char *cn_name, ddi_hp_op_t op,
    void *arg, void *result)
{
	pcie_hp_ctrl_t	*ctrl_p;
	pcie_hp_slot_t	*slot_p;
	int		ret = DDI_SUCCESS;

	PCIE_DBG("pciehpc_hp_ops: dip=%p cn_name=%s op=%x arg=%p\n",
	    dip, cn_name, op, arg);

	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL)
		return (DDI_FAILURE);

	slot_p = ctrl_p->hc_slots[0];

	if (strcmp(cn_name, slot_p->hs_info.cn_name) != 0)
		return (DDI_EINVAL);

	switch (op) {
	case DDI_HPOP_CN_GET_STATE:
	{
		mutex_enter(&slot_p->hs_ctrl->hc_mutex);

		/* get the current slot state */
		pciehpc_get_slot_state(slot_p);

		*((ddi_hp_cn_state_t *)result) = slot_p->hs_info.cn_state;

		mutex_exit(&slot_p->hs_ctrl->hc_mutex);
		break;
	}
	case DDI_HPOP_CN_CHANGE_STATE:
	{
		ddi_hp_cn_state_t target_state = *(ddi_hp_cn_state_t *)arg;

		mutex_enter(&slot_p->hs_ctrl->hc_mutex);

		ret = pciehpc_change_slot_state(slot_p, target_state);
		*(ddi_hp_cn_state_t *)result = slot_p->hs_info.cn_state;

		mutex_exit(&slot_p->hs_ctrl->hc_mutex);
		break;
	}
	case DDI_HPOP_CN_PROBE:

		ret = pciehpc_slot_probe(slot_p);

		break;
	case DDI_HPOP_CN_UNPROBE:
		ret = pciehpc_slot_unprobe(slot_p);

		break;
	case DDI_HPOP_CN_GET_PROPERTY:
		ret = pciehpc_slot_get_property(slot_p,
		    (ddi_hp_property_t *)arg, (ddi_hp_property_t *)result);
		break;
	case DDI_HPOP_CN_SET_PROPERTY:
		ret = pciehpc_slot_set_property(slot_p,
		    (ddi_hp_property_t *)arg, (ddi_hp_property_t *)result);
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

/*
 * Get the current state of the slot from the hw.
 *
 * The slot state should have been initialized before this function gets called.
 */
void
pciehpc_get_slot_state(pcie_hp_slot_t *slot_p)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	control, status;
	ddi_hp_cn_state_t curr_state = slot_p->hs_info.cn_state;

	/* read the Slot Control Register */
	control = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	slot_p->hs_fault_led_state = PCIE_HP_LED_OFF; /* no fault led */
	slot_p->hs_active_led_state = PCIE_HP_LED_OFF; /* no active led */

	/* read the current Slot Status Register */
	status = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);

	/* get POWER led state */
	slot_p->hs_power_led_state =
	    pciehpc_led_state_to_hpc(pcie_slotctl_pwr_indicator_get(control));

	/* get ATTN led state */
	slot_p->hs_attn_led_state =
	    pciehpc_led_state_to_hpc(pcie_slotctl_attn_indicator_get(control));

	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED)) {
		/* no device present; slot is empty */
		slot_p->hs_info.cn_state = DDI_HP_CN_STATE_EMPTY;

		return;
	}

	/* device is present */
	slot_p->hs_info.cn_state = DDI_HP_CN_STATE_PRESENT;

	if (!(control & PCIE_SLOTCTL_PWR_CONTROL)) {
		/*
		 * Device is powered on. Set to "ENABLED" state (skip
		 * POWERED state) because there is not a explicit "enable"
		 * action exists for PCIe.
		 * If it is already in "POWERED" state, then keep it until
		 * user explicitly change it to other states.
		 */
		if (curr_state == DDI_HP_CN_STATE_POWERED) {
			slot_p->hs_info.cn_state = curr_state;
		} else {
			slot_p->hs_info.cn_state = DDI_HP_CN_STATE_ENABLED;
		}
	}
}

/*
 * setup slot name/slot-number info.
 */
void
pciehpc_set_slot_name(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uchar_t		*slotname_data;
	int		*slotnum;
	uint_t		count;
	int		len;
	int		invalid_slotnum = 0;
	uint32_t	slot_capabilities;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, ctrl_p->hc_dip,
	    DDI_PROP_DONTPASS, "physical-slot#", &slotnum, &count) ==
	    DDI_PROP_SUCCESS) {
		slot_p->hs_phy_slot_num = slotnum[0];
		ddi_prop_free(slotnum);
	} else {
		slot_capabilities = pciehpc_reg_get32(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTCAP);
		slot_p->hs_phy_slot_num =
		    PCIE_SLOTCAP_PHY_SLOT_NUM(slot_capabilities);
	}

	/* platform may not have initialized it */
	if (!slot_p->hs_phy_slot_num) {
		PCIE_DBG("%s#%d: Invalid slot number!\n",
		    ddi_driver_name(ctrl_p->hc_dip),
		    ddi_get_instance(ctrl_p->hc_dip));
		slot_p->hs_phy_slot_num = pciehpc_reg_get8(ctrl_p,
		    PCI_BCNF_SECBUS);
		invalid_slotnum = 1;
	}
	slot_p->hs_info.cn_num = slot_p->hs_phy_slot_num;
	slot_p->hs_info.cn_num_dpd_on = DDI_HP_CN_NUM_NONE;

	/*
	 * construct the slot_name:
	 *	if "slot-names" property exists then use that name
	 *	else if valid slot number exists then it is "pcie<slot-num>".
	 *	else it will be "pcie<sec-bus-number>dev0"
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, ctrl_p->hc_dip, DDI_PROP_DONTPASS,
	    "slot-names", (caddr_t)&slotname_data, &len) == DDI_PROP_SUCCESS) {
		char tmp_name[256];

		/*
		 * Note: for PCI-E slots, the device number is always 0 so the
		 * first (and only) string is the slot name for this slot.
		 */
		(void) snprintf(tmp_name, sizeof (tmp_name),
		    (char *)slotname_data + 4);
		slot_p->hs_info.cn_name = ddi_strdup(tmp_name, KM_SLEEP);
		kmem_free(slotname_data, len);
	} else {
		if (invalid_slotnum) {
			/* use device number ie. 0 */
			slot_p->hs_info.cn_name = ddi_strdup("pcie0",
			    KM_SLEEP);
		} else {
			char tmp_name[256];

			(void) snprintf(tmp_name, sizeof (tmp_name), "pcie%d",
			    slot_p->hs_phy_slot_num);
			slot_p->hs_info.cn_name = ddi_strdup(tmp_name,
			    KM_SLEEP);
		}
	}
}

/*
 * Read/Write access to HPC registers. If platform nexus has non-standard
 * HPC access mechanism then regops functions are used to do reads/writes.
 */
uint8_t
pciehpc_reg_get8(pcie_hp_ctrl_t *ctrl_p, uint_t off)
{
	if (ctrl_p->hc_regops.get != NULL) {
		return ((uint8_t)ctrl_p->hc_regops.get(
		    ctrl_p->hc_regops.cookie, (off_t)off));
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		return (pci_config_get8(bus_p->bus_cfg_hdl, off));
	}
}

uint16_t
pciehpc_reg_get16(pcie_hp_ctrl_t *ctrl_p, uint_t off)
{
	if (ctrl_p->hc_regops.get != NULL) {
		return ((uint16_t)ctrl_p->hc_regops.get(
		    ctrl_p->hc_regops.cookie, (off_t)off));
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		return (pci_config_get16(bus_p->bus_cfg_hdl, off));
	}
}

uint32_t
pciehpc_reg_get32(pcie_hp_ctrl_t *ctrl_p, uint_t off)
{
	if (ctrl_p->hc_regops.get != NULL) {
		return ((uint32_t)ctrl_p->hc_regops.get(
		    ctrl_p->hc_regops.cookie, (off_t)off));
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		return (pci_config_get32(bus_p->bus_cfg_hdl, off));
	}
}

void
pciehpc_reg_put8(pcie_hp_ctrl_t *ctrl_p, uint_t off, uint8_t val)
{
	if (ctrl_p->hc_regops.put != NULL) {
		ctrl_p->hc_regops.put(ctrl_p->hc_regops.cookie,
		    (off_t)off, (uint_t)val);
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		pci_config_put8(bus_p->bus_cfg_hdl, off, val);
	}
}

void
pciehpc_reg_put16(pcie_hp_ctrl_t *ctrl_p, uint_t off, uint16_t val)
{
	if (ctrl_p->hc_regops.put != NULL) {
		ctrl_p->hc_regops.put(ctrl_p->hc_regops.cookie,
		    (off_t)off, (uint_t)val);
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		pci_config_put16(bus_p->bus_cfg_hdl, off, val);
	}
}

void
pciehpc_reg_put32(pcie_hp_ctrl_t *ctrl_p, uint_t off, uint32_t val)
{
	if (ctrl_p->hc_regops.put != NULL) {
		ctrl_p->hc_regops.put(ctrl_p->hc_regops.cookie,
		    (off_t)off, (uint_t)val);
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		pci_config_put32(bus_p->bus_cfg_hdl, off, val);
	}
}

/*
 * ************************************************************************
 * ***	Local functions (called within this file)
 * ***	PCIe Native Hotplug mode specific functions
 * ************************************************************************
 */

/*
 * Initialize HPC hardware, install interrupt handler, etc. It doesn't
 * enable hot plug interrupts.
 *
 * (Note: It is called only from pciehpc_init().)
 */
static int
pciehpc_hpc_init(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	reg;

	/* read the Slot Control Register */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	/* disable all interrupts */
	reg &= ~(PCIE_SLOTCTL_INTR_MASK);
	pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off +
	    PCIE_SLOTCTL, reg);

	/* clear any interrupt status bits */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS, reg);

	return (DDI_SUCCESS);
}

/*
 * Uninitialize HPC hardware, uninstall interrupt handler, etc.
 *
 * (Note: It is called only from pciehpc_uninit().)
 */
static int
pciehpc_hpc_uninit(pcie_hp_ctrl_t *ctrl_p)
{
	/* disable interrupts */
	(void) pciehpc_disable_intr(ctrl_p);

	return (DDI_SUCCESS);
}

/*
 * Setup slot information for use with DDI HP framework.
 */
static int
pciehpc_slotinfo_init(pcie_hp_ctrl_t *ctrl_p)
{
	uint32_t	slot_capabilities, link_capabilities;
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

	mutex_enter(&ctrl_p->hc_mutex);
	/*
	 * setup DDI HP framework slot information structure
	 */
	slot_p->hs_device_num = 0;

	slot_p->hs_info.cn_type = DDI_HP_CN_TYPE_PCIE;
	slot_p->hs_info.cn_type_str = (ctrl_p->hc_regops.get == NULL) ?
	    PCIE_NATIVE_HP_TYPE : PCIE_PROP_HP_TYPE;
	slot_p->hs_info.cn_child = NULL;

	slot_p->hs_minor =
	    PCI_MINOR_NUM(ddi_get_instance(ctrl_p->hc_dip),
	    slot_p->hs_device_num);
	slot_p->hs_condition = AP_COND_UNKNOWN;

	/* read Slot Capabilities Register */
	slot_capabilities = pciehpc_reg_get32(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCAP);

	/* set slot-name/slot-number info */
	pciehpc_set_slot_name(ctrl_p);

	/* check if Attn Button present */
	ctrl_p->hc_has_attn = (slot_capabilities & PCIE_SLOTCAP_ATTN_BUTTON) ?
	    B_TRUE : B_FALSE;

	/* check if Manual Retention Latch sensor present */
	ctrl_p->hc_has_mrl = (slot_capabilities & PCIE_SLOTCAP_MRL_SENSOR) ?
	    B_TRUE : B_FALSE;

	/*
	 * PCI-E version 1.1 defines EMI Lock Present bit
	 * in Slot Capabilities register. Check for it.
	 */
	ctrl_p->hc_has_emi_lock = (slot_capabilities &
	    PCIE_SLOTCAP_EMI_LOCK_PRESENT) ? B_TRUE : B_FALSE;

	link_capabilities = pciehpc_reg_get32(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_LINKCAP);
	ctrl_p->hc_dll_active_rep = (link_capabilities &
	    PCIE_LINKCAP_DLL_ACTIVE_REP_CAPABLE) ? B_TRUE : B_FALSE;
	if (ctrl_p->hc_dll_active_rep)
		cv_init(&slot_p->hs_dll_active_cv, NULL, CV_DRIVER, NULL);

	/* setup thread for handling ATTN button events */
	if (ctrl_p->hc_has_attn) {
		PCIE_DBG("pciehpc_slotinfo_init: setting up ATTN button event "
		    "handler thread for slot %d\n", slot_p->hs_phy_slot_num);

		cv_init(&slot_p->hs_attn_btn_cv, NULL, CV_DRIVER, NULL);
		slot_p->hs_attn_btn_pending = B_FALSE;
		slot_p->hs_attn_btn_threadp = thread_create(NULL, 0,
		    pciehpc_attn_btn_handler,
		    (void *)ctrl_p, 0, &p0, TS_RUN, minclsyspri);
		slot_p->hs_attn_btn_thread_exit = B_FALSE;
	}

	/* get current slot state from the hw */
	slot_p->hs_info.cn_state = DDI_HP_CN_STATE_EMPTY;
	pciehpc_get_slot_state(slot_p);
	if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_ENABLED)
		slot_p->hs_condition = AP_COND_OK;

	mutex_exit(&ctrl_p->hc_mutex);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pciehpc_slotinfo_uninit(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];

	if (slot_p->hs_attn_btn_threadp != NULL) {
		mutex_enter(&ctrl_p->hc_mutex);
		slot_p->hs_attn_btn_thread_exit = B_TRUE;
		cv_signal(&slot_p->hs_attn_btn_cv);
		PCIE_DBG("pciehpc_slotinfo_uninit: "
		    "waiting for ATTN thread exit\n");
		cv_wait(&slot_p->hs_attn_btn_cv, &ctrl_p->hc_mutex);
		PCIE_DBG("pciehpc_slotinfo_uninit: ATTN thread exit\n");
		cv_destroy(&slot_p->hs_attn_btn_cv);
		slot_p->hs_attn_btn_threadp = NULL;
		mutex_exit(&ctrl_p->hc_mutex);
	}

	if (ctrl_p->hc_dll_active_rep)
		cv_destroy(&slot_p->hs_dll_active_cv);
	if (slot_p->hs_info.cn_name)
		kmem_free(slot_p->hs_info.cn_name,
		    strlen(slot_p->hs_info.cn_name) + 1);

	return (DDI_SUCCESS);
}

/*
 * Enable hot plug interrupts.
 * Note: this is only for Native hot plug mode.
 */
static int
pciehpc_enable_intr(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	reg;

	/* clear any interrupt status bits */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS, reg);

	/* read the Slot Control Register */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	/*
	 * enable interrupts: power fault detection interrupt is enabled
	 * only when the slot is powered ON
	 */
	if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_POWERED)
		pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off +
		    PCIE_SLOTCTL, reg | PCIE_SLOTCTL_INTR_MASK);
	else
		pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off +
		    PCIE_SLOTCTL, reg | (PCIE_SLOTCTL_INTR_MASK &
		    ~PCIE_SLOTCTL_PWR_FAULT_EN));

	return (DDI_SUCCESS);
}

/*
 * Disable hot plug interrupts.
 * Note: this is only for Native hot plug mode.
 */
static int
pciehpc_disable_intr(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	reg;

	/* read the Slot Control Register */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	/* disable all interrupts */
	reg &= ~(PCIE_SLOTCTL_INTR_MASK);
	pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTCTL, reg);

	/* clear any interrupt status bits */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS, reg);

	return (DDI_SUCCESS);
}

/*
 * Allocate a new hotplug controller and slot structures for HPC
 * associated with this dip.
 */
static pcie_hp_ctrl_t *
pciehpc_create_controller(dev_info_t *dip)
{
	pcie_hp_ctrl_t	*ctrl_p;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	ctrl_p = kmem_zalloc(sizeof (pcie_hp_ctrl_t), KM_SLEEP);
	ctrl_p->hc_dip = dip;

	/* Allocate a new slot structure. */
	ctrl_p->hc_slots[0] = kmem_zalloc(sizeof (pcie_hp_slot_t), KM_SLEEP);
	ctrl_p->hc_slots[0]->hs_num = 0;
	ctrl_p->hc_slots[0]->hs_ctrl = ctrl_p;

	/* Initialize the interrupt mutex */
	mutex_init(&ctrl_p->hc_mutex, NULL, MUTEX_DRIVER,
	    (void *)PCIE_INTR_PRI);

	/* Initialize synchronization conditional variable */
	cv_init(&ctrl_p->hc_cmd_comp_cv, NULL, CV_DRIVER, NULL);
	ctrl_p->hc_cmd_pending = B_FALSE;

	bus_p->bus_hp_curr_mode = PCIE_NATIVE_HP_MODE;
	PCIE_SET_HP_CTRL(dip, ctrl_p);

	return (ctrl_p);
}

/*
 * Remove the HPC controller and slot structures
 */
static void
pciehpc_destroy_controller(dev_info_t *dip)
{
	pcie_hp_ctrl_t	*ctrl_p;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	/* get the soft state structure for this dip */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL)
		return;

	PCIE_SET_HP_CTRL(dip, NULL);
	bus_p->bus_hp_curr_mode = PCIE_NONE_HP_MODE;

	mutex_destroy(&ctrl_p->hc_mutex);
	cv_destroy(&ctrl_p->hc_cmd_comp_cv);
	kmem_free(ctrl_p->hc_slots[0], sizeof (pcie_hp_slot_t));
	kmem_free(ctrl_p, sizeof (pcie_hp_ctrl_t));
}

/*
 * Register the PCI-E hot plug slot with DDI HP framework.
 */
static int
pciehpc_register_slot(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	dev_info_t	*dip = ctrl_p->hc_dip;

	/* register the slot with DDI HP framework */
	if (ndi_hp_register(dip, &slot_p->hs_info) != NDI_SUCCESS) {
		PCIE_DBG("pciehpc_register_slot() failed to register slot %d\n",
		    slot_p->hs_phy_slot_num);
		return (DDI_FAILURE);
	}

	pcie_hp_create_occupant_props(dip, makedevice(ddi_driver_major(dip),
	    slot_p->hs_minor), slot_p->hs_device_num);

	PCIE_DBG("pciehpc_register_slot(): registered slot %d\n",
	    slot_p->hs_phy_slot_num);

	return (DDI_SUCCESS);
}

/*
 * Unregister the PCI-E hot plug slot from DDI HP framework.
 */
static int
pciehpc_unregister_slot(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];
	dev_info_t	*dip = ctrl_p->hc_dip;

	pcie_hp_delete_occupant_props(dip, makedevice(ddi_driver_major(dip),
	    slot_p->hs_minor));

	/* unregister the slot with DDI HP framework */
	if (ndi_hp_unregister(dip, slot_p->hs_info.cn_name) != NDI_SUCCESS) {
		PCIE_DBG("pciehpc_unregister_slot() "
		    "failed to unregister slot %d\n", slot_p->hs_phy_slot_num);
		return (DDI_FAILURE);
	}

	PCIE_DBG("pciehpc_unregister_slot(): unregistered slot %d\n",
	    slot_p->hs_phy_slot_num);

	return (DDI_SUCCESS);
}

/*
 * pciehpc_slot_poweron()
 *
 * Poweron/Enable the slot.
 *
 * Note: This function is called by DDI HP framework at kernel context only
 */
/*ARGSUSED*/
static int
pciehpc_slot_poweron(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	status, control;

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	/* check if the slot is already in the 'enabled' state */
	if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_POWERED) {
		/* slot is already in the 'enabled' state */
		PCIE_DBG("pciehpc_slot_poweron() slot %d already enabled\n",
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
		cmn_err(CE_WARN, "MRL switch is open on slot %d\n",
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

	/*
	 * Enable power to the slot involves:
	 *	1. Set power LED to blink and ATTN led to OFF.
	 *	2. Set power control ON in Slot Control Reigster and
	 *	   wait for Command Completed Interrupt or 1 sec timeout.
	 *	3. If Data Link Layer State Changed events are supported
	 *	   then wait for the event to indicate Data Layer Link
	 *	   is active. The time out value for this event is 1 second.
	 *	   This is specified in PCI-E version 1.1.
	 *	4. Set power LED to be ON.
	 */

	/* 1. set power LED to blink & ATTN led to OFF */
	pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED, PCIE_HP_LED_BLINK);
	pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED, PCIE_HP_LED_OFF);

	/* 2. set power control to ON */
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);
	control &= ~PCIE_SLOTCTL_PWR_CONTROL;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/* 3. wait for DLL State Change event, if it's supported */
	if (ctrl_p->hc_dll_active_rep) {
		status =  pciehpc_reg_get16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_LINKSTS);

		if (!(status & PCIE_LINKSTS_DLL_LINK_ACTIVE)) {
			/* wait 1 sec for the DLL State Changed event */
			(void) cv_timedwait(&slot_p->hs_dll_active_cv,
			    &ctrl_p->hc_mutex,
			    ddi_get_lbolt() +
			    SEC_TO_TICK(PCIE_HP_DLL_STATE_CHANGE_TIMEOUT));

			/* check Link status */
			status =  pciehpc_reg_get16(ctrl_p,
			    bus_p->bus_pcie_off +
			    PCIE_LINKSTS);
			if (!(status & PCIE_LINKSTS_DLL_LINK_ACTIVE))
				goto cleanup2;
		}
	}

	/* wait 1 sec for link to come up */
	delay(drv_usectohz(1000000));

	/* check power is really turned ON */
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	if (control & PCIE_SLOTCTL_PWR_CONTROL) {
		PCIE_DBG("slot %d fails to turn on power on connect\n",
		    slot_p->hs_phy_slot_num);

		goto cleanup1;
	}

	/* clear power fault status */
	status =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);
	status |= PCIE_SLOTSTS_PWR_FAULT_DETECTED;
	pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTSTS,
	    status);

	/* enable power fault detection interrupt */
	control |= PCIE_SLOTCTL_PWR_FAULT_EN;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/* 4. Set power LED to be ON */
	pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED, PCIE_HP_LED_ON);

	/* if EMI is present, turn it ON */
	if (ctrl_p->hc_has_emi_lock) {
		status =  pciehpc_reg_get16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTSTS);

		if (!(status & PCIE_SLOTSTS_EMI_LOCK_SET)) {
			control =  pciehpc_reg_get16(ctrl_p,
			    bus_p->bus_pcie_off + PCIE_SLOTCTL);
			control |= PCIE_SLOTCTL_EMI_LOCK_CONTROL;
			pciehpc_issue_hpc_command(ctrl_p, control);

			/* wait 1 sec after toggling the state of EMI lock */
			delay(drv_usectohz(1000000));
		}
	}

	*result = slot_p->hs_info.cn_state =
	    DDI_HP_CN_STATE_POWERED;

	return (DDI_SUCCESS);

cleanup2:
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	/* if power is ON, set power control to OFF */
	if (!(control & PCIE_SLOTCTL_PWR_CONTROL)) {
		control |= PCIE_SLOTCTL_PWR_CONTROL;
		pciehpc_issue_hpc_command(ctrl_p, control);
	}

cleanup1:
	/* set power led to OFF */
	pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED, PCIE_HP_LED_OFF);

cleanup:
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
pciehpc_slot_poweroff(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	status, control;

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	/* check if the slot is not in the "enabled' state */
	if (slot_p->hs_info.cn_state < DDI_HP_CN_STATE_POWERED) {
		/* slot is in the 'disabled' state */
		PCIE_DBG("pciehpc_slot_poweroff(): "
		    "slot %d already disabled\n", slot_p->hs_phy_slot_num);
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
		PCIE_DBG("pciehpc_slot_poweroff(): slot %d is empty\n",
		    slot_p->hs_phy_slot_num);
		goto cleanup;
	}

	/*
	 * Disable power to the slot involves:
	 *	1. Set power LED to blink.
	 *	2. Set power control OFF in Slot Control Reigster and
	 *	   wait for Command Completed Interrupt or 1 sec timeout.
	 *	3. Set POWER led and ATTN led to be OFF.
	 */

	/* 1. set power LED to blink */
	pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED, PCIE_HP_LED_BLINK);

	/* disable power fault detection interrupt */
	control = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);
	control &= ~PCIE_SLOTCTL_PWR_FAULT_EN;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/* 2. set power control to OFF */
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);
	control |= PCIE_SLOTCTL_PWR_CONTROL;
	pciehpc_issue_hpc_command(ctrl_p, control);

#ifdef DEBUG
	/* check for power control bit to be OFF */
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);
	ASSERT(control & PCIE_SLOTCTL_PWR_CONTROL);
#endif

	/* 3. Set power LED to be OFF */
	pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED, PCIE_HP_LED_OFF);
	pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED, PCIE_HP_LED_OFF);

	/* if EMI is present, turn it OFF */
	if (ctrl_p->hc_has_emi_lock) {
		status =  pciehpc_reg_get16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTSTS);

		if (status & PCIE_SLOTSTS_EMI_LOCK_SET) {
			control =  pciehpc_reg_get16(ctrl_p,
			    bus_p->bus_pcie_off + PCIE_SLOTCTL);
			control |= PCIE_SLOTCTL_EMI_LOCK_CONTROL;
			pciehpc_issue_hpc_command(ctrl_p, control);

			/* wait 1 sec after toggling the state of EMI lock */
			delay(drv_usectohz(1000000));
		}
	}

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	*result = slot_p->hs_info.cn_state;

	return (DDI_SUCCESS);

cleanup:
	return (DDI_FAILURE);
}

/*
 * pciehpc_slot_probe()
 *
 * Probe the slot.
 *
 * Note: This function is called by DDI HP framework at kernel context only
 */
/*ARGSUSED*/
static int
pciehpc_slot_probe(pcie_hp_slot_t *slot_p)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	int		ret = DDI_SUCCESS;

	mutex_enter(&ctrl_p->hc_mutex);

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	/*
	 * Probe a given PCIe Hotplug Connection (CN).
	 */
	PCIE_DISABLE_ERRORS(ctrl_p->hc_dip);
	ret = pcie_hp_probe(slot_p);

	if (ret != DDI_SUCCESS) {
		PCIE_DBG("pciehpc_slot_probe() failed\n");

		/* turn the ATTN led ON for configure failure */
		pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED, PCIE_HP_LED_ON);

		/* if power to the slot is still on then set Power led to ON */
		if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_POWERED)
			pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED,
			    PCIE_HP_LED_ON);

		mutex_exit(&ctrl_p->hc_mutex);
		return (DDI_FAILURE);
	}

	PCIE_ENABLE_ERRORS(ctrl_p->hc_dip);

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	mutex_exit(&ctrl_p->hc_mutex);
	return (DDI_SUCCESS);
}

/*
 * pciehpc_slot_unprobe()
 *
 * Unprobe the slot.
 *
 * Note: This function is called by DDI HP framework at kernel context only
 */
/*ARGSUSED*/
static int
pciehpc_slot_unprobe(pcie_hp_slot_t *slot_p)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	int		ret;

	mutex_enter(&ctrl_p->hc_mutex);

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	/*
	 * Unprobe a given PCIe Hotplug Connection (CN).
	 */
	PCIE_DISABLE_ERRORS(ctrl_p->hc_dip);
	ret = pcie_hp_unprobe(slot_p);

	if (ret != DDI_SUCCESS) {
		PCIE_DBG("pciehpc_slot_unprobe() failed\n");

		/* if power to the slot is still on then set Power led to ON */
		if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_POWERED)
			pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED,
			    PCIE_HP_LED_ON);

		PCIE_ENABLE_ERRORS(ctrl_p->hc_dip);

		mutex_exit(&ctrl_p->hc_mutex);
		return (DDI_FAILURE);
	}

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	mutex_exit(&ctrl_p->hc_mutex);
	return (DDI_SUCCESS);
}

static int
pciehpc_upgrade_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t curr_state;
	int rv = DDI_SUCCESS;

	if (target_state > DDI_HP_CN_STATE_ENABLED) {
		return (DDI_EINVAL);
	}

	curr_state = slot_p->hs_info.cn_state;
	while ((curr_state < target_state) && (rv == DDI_SUCCESS)) {

		switch (curr_state) {
		case DDI_HP_CN_STATE_EMPTY:
			/*
			 * From EMPTY to PRESENT, just check the hardware
			 * slot state.
			 */
			pciehpc_get_slot_state(slot_p);
			curr_state = slot_p->hs_info.cn_state;
			if (curr_state < DDI_HP_CN_STATE_PRESENT)
				rv = DDI_FAILURE;
			break;
		case DDI_HP_CN_STATE_PRESENT:
			rv = (slot_p->hs_ctrl->hc_ops.poweron_hpc_slot)(slot_p,
			    &curr_state);

			break;
		case DDI_HP_CN_STATE_POWERED:
			curr_state = slot_p->hs_info.cn_state =
			    DDI_HP_CN_STATE_ENABLED;
			break;
		default:
			/* should never reach here */
			ASSERT("unknown devinfo state");
		}
	}

	return (rv);
}

static int
pciehpc_downgrade_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t curr_state;
	int rv = DDI_SUCCESS;


	curr_state = slot_p->hs_info.cn_state;
	while ((curr_state > target_state) && (rv == DDI_SUCCESS)) {

		switch (curr_state) {
		case DDI_HP_CN_STATE_PRESENT:
			/*
			 * From PRESENT to EMPTY, just check hardware slot
			 * state.
			 */
			pciehpc_get_slot_state(slot_p);
			curr_state = slot_p->hs_info.cn_state;
			if (curr_state >= DDI_HP_CN_STATE_PRESENT)
				rv = DDI_FAILURE;
			break;
		case DDI_HP_CN_STATE_POWERED:
			rv = (slot_p->hs_ctrl->hc_ops.poweroff_hpc_slot)(
			    slot_p, &curr_state);

			break;
		case DDI_HP_CN_STATE_ENABLED:
			curr_state = slot_p->hs_info.cn_state =
			    DDI_HP_CN_STATE_POWERED;

			break;
		default:
			/* should never reach here */
			ASSERT("unknown devinfo state");
		}
	}

	return (rv);
}

/* Change slot state to a target state */
static int
pciehpc_change_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t curr_state;
	int rv;

	pciehpc_get_slot_state(slot_p);
	curr_state = slot_p->hs_info.cn_state;

	if (curr_state == target_state) {
		return (DDI_SUCCESS);
	}
	if (curr_state < target_state) {

		rv = pciehpc_upgrade_slot_state(slot_p, target_state);
	} else {
		rv = pciehpc_downgrade_slot_state(slot_p, target_state);
	}

	return (rv);
}

int
pciehpc_slot_get_property(pcie_hp_slot_t *slot_p, ddi_hp_property_t *arg,
    ddi_hp_property_t *rval)
{
	ddi_hp_property_t request, result;
#ifdef _SYSCALL32_IMPL
	ddi_hp_property32_t request32, result32;
#endif
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	nvlist_t	*prop_list;
	nvlist_t	*prop_rlist; /* nvlist for return values */
	nvpair_t	*prop_pair;
	char		*name, *value;
	int		ret = DDI_SUCCESS;
	int		i, n;
	boolean_t	get_all_prop = B_FALSE;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(arg, &request, sizeof (ddi_hp_property_t)) ||
		    copyin(rval, &result, sizeof (ddi_hp_property_t)))
			return (DDI_FAILURE);
	}
#ifdef _SYSCALL32_IMPL
	else {
		bzero(&request, sizeof (request));
		bzero(&result, sizeof (result));
		if (copyin(arg, &request32, sizeof (ddi_hp_property32_t)) ||
		    copyin(rval, &result32, sizeof (ddi_hp_property32_t)))
			return (DDI_FAILURE);
		request.nvlist_buf = (char *)(uintptr_t)request32.nvlist_buf;
		request.buf_size = request32.buf_size;
		result.nvlist_buf = (char *)(uintptr_t)result32.nvlist_buf;
		result.buf_size = result32.buf_size;
	}
#endif

	if ((ret = pcie_copyin_nvlist(request.nvlist_buf, request.buf_size,
	    &prop_list)) != DDI_SUCCESS)
		return (ret);

	if (nvlist_alloc(&prop_rlist, NV_UNIQUE_NAME, 0)) {
		ret = DDI_ENOMEM;
		goto get_prop_cleanup;
	}

	/* check whether the requested property is "all" or "help" */
	prop_pair = nvlist_next_nvpair(prop_list, NULL);
	if (prop_pair && !nvlist_next_nvpair(prop_list, prop_pair)) {
		name = nvpair_name(prop_pair);
		n = sizeof (pciehpc_props) / sizeof (pciehpc_prop_t);

		if (strcmp(name, PCIEHPC_PROP_ALL) == 0) {
			(void) nvlist_remove_all(prop_list, PCIEHPC_PROP_ALL);

			/*
			 * Add all properties into the request list, so that we
			 * will get the values in the following for loop.
			 */
			for (i = 0; i < n; i++) {
				if (nvlist_add_string(prop_list,
				    pciehpc_props[i].prop_name, "") != 0) {
					ret = DDI_FAILURE;
					goto get_prop_cleanup1;
				}
			}
			get_all_prop = B_TRUE;
		} else if (strcmp(name, PCIEHPC_PROP_HELP) == 0) {
			/*
			 * Empty the request list, and add help strings into the
			 * return list. We will pass the following for loop.
			 */
			(void) nvlist_remove_all(prop_list, PCIEHPC_PROP_HELP);

			for (i = 0; i < n; i++) {
				if (nvlist_add_string(prop_rlist,
				    pciehpc_props[i].prop_name,
				    pciehpc_props[i].prop_value) != 0) {
					ret = DDI_FAILURE;
					goto get_prop_cleanup1;
				}
			}
		}
	}

	mutex_enter(&ctrl_p->hc_mutex);

	/* get the current slot state */
	pciehpc_get_slot_state(slot_p);

	/* for each requested property, get the value and add it to nvlist */
	prop_pair = NULL;
	while (prop_pair = nvlist_next_nvpair(prop_list, prop_pair)) {
		name = nvpair_name(prop_pair);

		if (strcmp(name, PCIEHPC_PROP_LED_FAULT) == 0) {
			value = pcie_led_state_text(
			    slot_p->hs_fault_led_state);
		} else if (strcmp(name, PCIEHPC_PROP_LED_POWER) == 0) {
			value = pcie_led_state_text(
			    slot_p->hs_power_led_state);
		} else if (strcmp(name, PCIEHPC_PROP_LED_ATTN) == 0) {
			value = pcie_led_state_text(
			    slot_p->hs_attn_led_state);
		} else if (strcmp(name, PCIEHPC_PROP_LED_ACTIVE) == 0) {
			value = pcie_led_state_text(
			    slot_p->hs_active_led_state);
		} else if (strcmp(name, PCIEHPC_PROP_CARD_TYPE) == 0) {
			ddi_acc_handle_t handle;
			dev_info_t	*cdip;
			uint8_t		prog_class, base_class, sub_class;
			int		i;

			mutex_exit(&ctrl_p->hc_mutex);
			cdip = pcie_hp_devi_find(
			    ctrl_p->hc_dip, slot_p->hs_device_num, 0);
			mutex_enter(&ctrl_p->hc_mutex);

			if ((slot_p->hs_info.cn_state
			    != DDI_HP_CN_STATE_ENABLED) || (cdip == NULL)) {
				/*
				 * When getting all properties, just ignore the
				 * one that's not available under certain state.
				 */
				if (get_all_prop)
					continue;

				ret = DDI_ENOTSUP;
				goto get_prop_cleanup2;
			}

			if (pci_config_setup(cdip, &handle) != DDI_SUCCESS) {
				ret = DDI_FAILURE;
				goto get_prop_cleanup2;
			}

			prog_class = pci_config_get8(handle,
			    PCI_CONF_PROGCLASS);
			base_class = pci_config_get8(handle, PCI_CONF_BASCLASS);
			sub_class = pci_config_get8(handle, PCI_CONF_SUBCLASS);
			pci_config_teardown(&handle);

			for (i = 0; i < class_pci_items; i++) {
				if ((base_class == class_pci[i].base_class) &&
				    (sub_class == class_pci[i].sub_class) &&
				    (prog_class == class_pci[i].prog_class)) {
					value = class_pci[i].short_desc;
					break;
				}
			}
			if (i == class_pci_items)
				value = PCIEHPC_PROP_VALUE_UNKNOWN;
		} else if (strcmp(name, PCIEHPC_PROP_BOARD_TYPE) == 0) {
			if (slot_p->hs_info.cn_state <= DDI_HP_CN_STATE_EMPTY)
				value = PCIEHPC_PROP_VALUE_UNKNOWN;
			else
				value = PCIEHPC_PROP_VALUE_PCIHOTPLUG;
		} else if (strcmp(name, PCIEHPC_PROP_SLOT_CONDITION) == 0) {
			value = pcie_slot_condition_text(slot_p->hs_condition);
		} else {
			/* unsupported property */
			PCIE_DBG("Unsupported property: %s\n", name);

			ret = DDI_ENOTSUP;
			goto get_prop_cleanup2;
		}
		if (nvlist_add_string(prop_rlist, name, value) != 0) {
			ret = DDI_FAILURE;
			goto get_prop_cleanup2;
		}
	}

	/* pack nvlist and copyout */
	if ((ret = pcie_copyout_nvlist(prop_rlist, result.nvlist_buf,
	    &result.buf_size)) != DDI_SUCCESS) {
		goto get_prop_cleanup2;
	}
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyout(&result, rval, sizeof (ddi_hp_property_t)))
			ret = DDI_FAILURE;
	}
#ifdef _SYSCALL32_IMPL
	else {
		if (result.buf_size > UINT32_MAX) {
			ret = DDI_FAILURE;
		} else {
			result32.buf_size = (uint32_t)result.buf_size;
			if (copyout(&result32, rval,
			    sizeof (ddi_hp_property32_t)))
				ret = DDI_FAILURE;
		}
	}
#endif

get_prop_cleanup2:
	mutex_exit(&ctrl_p->hc_mutex);
get_prop_cleanup1:
	nvlist_free(prop_rlist);
get_prop_cleanup:
	nvlist_free(prop_list);
	return (ret);
}

int
pciehpc_slot_set_property(pcie_hp_slot_t *slot_p, ddi_hp_property_t *arg,
    ddi_hp_property_t *rval)
{
	ddi_hp_property_t	request, result;
#ifdef _SYSCALL32_IMPL
	ddi_hp_property32_t	request32, result32;
#endif
	pcie_hp_ctrl_t		*ctrl_p = slot_p->hs_ctrl;
	nvlist_t		*prop_list;
	nvlist_t		*prop_rlist;
	nvpair_t		*prop_pair;
	char			*name, *value;
	pcie_hp_led_state_t	led_state;
	int			ret = DDI_SUCCESS;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(arg, &request, sizeof (ddi_hp_property_t)))
			return (DDI_FAILURE);
		if (rval &&
		    copyin(rval, &result, sizeof (ddi_hp_property_t)))
			return (DDI_FAILURE);
	}
#ifdef _SYSCALL32_IMPL
	else {
		bzero(&request, sizeof (request));
		bzero(&result, sizeof (result));
		if (copyin(arg, &request32, sizeof (ddi_hp_property32_t)))
			return (DDI_FAILURE);
		if (rval &&
		    copyin(rval, &result32, sizeof (ddi_hp_property32_t)))
			return (DDI_FAILURE);
		request.nvlist_buf = (char *)(uintptr_t)request32.nvlist_buf;
		request.buf_size = request32.buf_size;
		if (rval) {
			result.nvlist_buf =
			    (char *)(uintptr_t)result32.nvlist_buf;
			result.buf_size = result32.buf_size;
		}
	}
#endif

	if ((ret = pcie_copyin_nvlist(request.nvlist_buf, request.buf_size,
	    &prop_list)) != DDI_SUCCESS)
		return (ret);

	/* check whether the requested property is "help" */
	prop_pair = nvlist_next_nvpair(prop_list, NULL);
	if (prop_pair && !nvlist_next_nvpair(prop_list, prop_pair) &&
	    (strcmp(nvpair_name(prop_pair), PCIEHPC_PROP_HELP) == 0)) {
		if (!rval) {
			ret = DDI_ENOTSUP;
			goto set_prop_cleanup;
		}

		if (nvlist_alloc(&prop_rlist, NV_UNIQUE_NAME, 0)) {
			ret = DDI_ENOMEM;
			goto set_prop_cleanup;
		}
		if (nvlist_add_string(prop_rlist, PCIEHPC_PROP_LED_ATTN,
		    PCIEHPC_PROP_VALUE_LED) != 0) {
			ret = DDI_FAILURE;
			goto set_prop_cleanup1;
		}

		if ((ret = pcie_copyout_nvlist(prop_rlist, result.nvlist_buf,
		    &result.buf_size)) != DDI_SUCCESS) {
			goto set_prop_cleanup1;
		}
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&result, rval,
			    sizeof (ddi_hp_property_t))) {
				ret =  DDI_FAILURE;
				goto set_prop_cleanup1;
			}
		}
#ifdef _SYSCALL32_IMPL
		else {
			if (result.buf_size > UINT32_MAX) {
				ret =  DDI_FAILURE;
				goto set_prop_cleanup1;
			} else {
				result32.buf_size = (uint32_t)result.buf_size;
				if (copyout(&result32, rval,
				    sizeof (ddi_hp_property32_t))) {
					ret =  DDI_FAILURE;
					goto set_prop_cleanup1;
				}
			}
		}
#endif
set_prop_cleanup1:
		nvlist_free(prop_rlist);
		nvlist_free(prop_list);
		return (ret);
	}

	/* Validate the request */
	prop_pair = NULL;
	while (prop_pair = nvlist_next_nvpair(prop_list, prop_pair)) {
		name = nvpair_name(prop_pair);
		if (nvpair_type(prop_pair) != DATA_TYPE_STRING) {
			PCIE_DBG("Unexpected data type of setting "
			    "property %s.\n", name);
			ret = DDI_EINVAL;
			goto set_prop_cleanup;
		}
		if (nvpair_value_string(prop_pair, &value)) {
			PCIE_DBG("Get string value failed for property %s.\n",
			    name);
			ret = DDI_FAILURE;
			goto set_prop_cleanup;
		}

		if (strcmp(name, PCIEHPC_PROP_LED_ATTN) == 0) {
			if ((strcmp(value, PCIEHPC_PROP_VALUE_ON) != 0) &&
			    (strcmp(value, PCIEHPC_PROP_VALUE_OFF) != 0) &&
			    (strcmp(value, PCIEHPC_PROP_VALUE_BLINK) != 0)) {
				PCIE_DBG("Unsupported value of setting "
				    "property %s\n", name);
				ret = DDI_ENOTSUP;
				goto set_prop_cleanup;
			}
		} else {
			PCIE_DBG("Unsupported property: %s\n", name);
			ret = DDI_ENOTSUP;
			goto set_prop_cleanup;
		}
	}
	mutex_enter(&ctrl_p->hc_mutex);

	/* get the current slot state */
	pciehpc_get_slot_state(slot_p);

	/* set each property */
	prop_pair = NULL;
	while (prop_pair = nvlist_next_nvpair(prop_list, prop_pair)) {
		name = nvpair_name(prop_pair);

		if (strcmp(name, PCIEHPC_PROP_LED_ATTN) == 0) {
			if (strcmp(value, PCIEHPC_PROP_VALUE_ON) == 0)
				led_state = PCIE_HP_LED_ON;
			else if (strcmp(value, PCIEHPC_PROP_VALUE_OFF) == 0)
				led_state = PCIE_HP_LED_OFF;
			else if (strcmp(value, PCIEHPC_PROP_VALUE_BLINK) == 0)
				led_state = PCIE_HP_LED_BLINK;

			pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED,
			    led_state);
		}
	}
	if (rval) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			result.buf_size = 0;
			if (copyout(&result, rval, sizeof (ddi_hp_property_t)))
				ret =  DDI_FAILURE;
		}
#ifdef _SYSCALL32_IMPL
		else {
			result32.buf_size = 0;
			if (copyout(&result32, rval,
			    sizeof (ddi_hp_property32_t)))
				ret =  DDI_FAILURE;
		}
#endif
	}

	mutex_exit(&ctrl_p->hc_mutex);
set_prop_cleanup:
	nvlist_free(prop_list);
	return (ret);
}

/*
 * Send a command to the PCI-E Hot Plug Controller.
 *
 * NOTES: The PCI-E spec defines the following semantics for issuing hot plug
 * commands.
 * 1) If Command Complete events/interrupts are supported then software
 *    waits for Command Complete event after issuing a command (i.e writing
 *    to the Slot Control register). The command completion could take as
 *    long as 1 second so software should be prepared to wait for 1 second
 *    before issuing another command.
 *
 * 2) If Command Complete events/interrupts are not supported then
 *    software could issue multiple Slot Control writes without any delay
 *    between writes.
 */
static void
pciehpc_issue_hpc_command(pcie_hp_ctrl_t *ctrl_p, uint16_t control)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	status;
	uint32_t	slot_cap;

	/*
	 * PCI-E version 1.1 spec defines No Command Completed
	 * Support bit (bit#18) in Slot Capabilities register. If this
	 * bit is set then slot doesn't support notification of command
	 * completion events.
	 */
	slot_cap =  pciehpc_reg_get32(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCAP);

	/*
	 * If no Command Completion event is supported or it is ACPI
	 * hot plug mode then just issue the command and return.
	 */
	if ((slot_cap & PCIE_SLOTCAP_NO_CMD_COMP_SUPP) ||
	    (bus_p->bus_hp_curr_mode == PCIE_ACPI_HP_MODE)) {
		pciehpc_reg_put16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTCTL, control);
		return;
	}

	/*
	 * **************************************
	 * Command Complete events are supported.
	 * **************************************
	 */

	/*
	 * If HPC is not yet initialized then just poll for the Command
	 * Completion interrupt.
	 */
	if (!(ctrl_p->hc_flags & PCIE_HP_INITIALIZED_FLAG)) {
		int retry = PCIE_HP_CMD_WAIT_RETRY;

		/* write the command to the HPC */
		pciehpc_reg_put16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTCTL, control);

		/* poll for status completion */
		while (retry--) {
			/* wait for 10 msec before checking the status */
			delay(drv_usectohz(PCIE_HP_CMD_WAIT_TIME));

			status = pciehpc_reg_get16(ctrl_p,
			    bus_p->bus_pcie_off + PCIE_SLOTSTS);

			if (status & PCIE_SLOTSTS_COMMAND_COMPLETED) {
				/* clear the status bits */
				pciehpc_reg_put16(ctrl_p,
				    bus_p->bus_pcie_off + PCIE_SLOTSTS, status);
				break;
			}
		}
		return;
	}

	/* HPC is already initialized */

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	/*
	 * If previous command is still pending then wait for its
	 * completion. i.e cv_wait()
	 */

	while (ctrl_p->hc_cmd_pending == B_TRUE)
		cv_wait(&ctrl_p->hc_cmd_comp_cv, &ctrl_p->hc_mutex);

	/*
	 * Issue the command and wait for Command Completion or
	 * the 1 sec timeout.
	 */
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL, control);

	ctrl_p->hc_cmd_pending = B_TRUE;

	if (cv_timedwait(&ctrl_p->hc_cmd_comp_cv, &ctrl_p->hc_mutex,
	    ddi_get_lbolt() + SEC_TO_TICK(1)) == -1) {

		/* it is a timeout */
		PCIE_DBG("pciehpc_issue_hpc_command: Command Complete"
		    " interrupt is not received for slot %d\n",
		    slot_p->hs_phy_slot_num);

		/* clear the status info in case interrupts are disabled? */
		status = pciehpc_reg_get16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTSTS);

		if (status & PCIE_SLOTSTS_COMMAND_COMPLETED) {
			/* clear the status bits */
			pciehpc_reg_put16(ctrl_p,
			    bus_p->bus_pcie_off + PCIE_SLOTSTS, status);
		}
	}

	ctrl_p->hc_cmd_pending = B_FALSE;

	/* wake up any one waiting for issuing another command to HPC */
	cv_signal(&ctrl_p->hc_cmd_comp_cv);
}

/*
 * pciehcp_attn_btn_handler()
 *
 * This handles ATTN button pressed event as per the PCI-E 1.1 spec.
 */
static void
pciehpc_attn_btn_handler(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t		*slot_p = ctrl_p->hc_slots[0];
	pcie_hp_led_state_t	power_led_state;
	callb_cpr_t		cprinfo;

	PCIE_DBG("pciehpc_attn_btn_handler: thread started\n");

	CALLB_CPR_INIT(&cprinfo, &ctrl_p->hc_mutex, callb_generic_cpr,
	    "pciehpc_attn_btn_handler");

	mutex_enter(&ctrl_p->hc_mutex);

	/* wait for ATTN button event */
	cv_wait(&slot_p->hs_attn_btn_cv, &ctrl_p->hc_mutex);

	while (slot_p->hs_attn_btn_thread_exit == B_FALSE) {
		if (slot_p->hs_attn_btn_pending == B_TRUE) {
			/* get the current state of power LED */
			power_led_state = pciehpc_get_led_state(ctrl_p,
			    PCIE_HP_POWER_LED);

			/* Blink the Power LED while we wait for 5 seconds */
			pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED,
			    PCIE_HP_LED_BLINK);

			/* wait for 5 seconds before taking any action */
			if (cv_timedwait(&slot_p->hs_attn_btn_cv,
			    &ctrl_p->hc_mutex,
			    ddi_get_lbolt() + SEC_TO_TICK(5)) == -1) {
				/*
				 * It is a time out; make sure the ATTN pending
				 * flag is still ON before sending the event to
				 * DDI HP framework.
				 */
				if (slot_p->hs_attn_btn_pending == B_TRUE) {
					int hint;

					slot_p->hs_attn_btn_pending = B_FALSE;
					pciehpc_get_slot_state(slot_p);

					if (slot_p->hs_info.cn_state <=
					    DDI_HP_CN_STATE_PRESENT) {
						/*
						 * Insertion.
						 */
						hint = SE_INCOMING_RES;
					} else {
						/*
						 * Want to remove;
						 */
						hint = SE_OUTGOING_RES;
					}

					/*
					 * We can't call ddihp_cn_gen_sysevent
					 * here since it's not a DDI interface.
					 */
					pcie_hp_gen_sysevent_req(
					    slot_p->hs_info.cn_name,
					    hint,
					    ctrl_p->hc_dip,
					    KM_SLEEP);
				}
			}

			/* restore the power LED state */
			pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED,
			    power_led_state);
			continue;
		}

		/* wait for another ATTN button event */
		cv_wait(&slot_p->hs_attn_btn_cv, &ctrl_p->hc_mutex);
	}

	PCIE_DBG("pciehpc_attn_btn_handler: thread exit\n");
	cv_signal(&slot_p->hs_attn_btn_cv);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

/*
 * convert LED state from PCIE HPC definition to pcie_hp_led_state_t
 * definition.
 */
static pcie_hp_led_state_t
pciehpc_led_state_to_hpc(uint16_t state)
{
	switch (state) {
	case PCIE_SLOTCTL_INDICATOR_STATE_ON:
		return (PCIE_HP_LED_ON);
	case PCIE_SLOTCTL_INDICATOR_STATE_BLINK:
		return (PCIE_HP_LED_BLINK);
	case PCIE_SLOTCTL_INDICATOR_STATE_OFF:
	default:
		return (PCIE_HP_LED_OFF);
	}
}

/*
 * Get the state of an LED.
 */
static pcie_hp_led_state_t
pciehpc_get_led_state(pcie_hp_ctrl_t *ctrl_p, pcie_hp_led_t led)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	control, state;

	/* get the current state of Slot Control register */
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	switch (led) {
	case PCIE_HP_POWER_LED:
		state = pcie_slotctl_pwr_indicator_get(control);
		break;
	case PCIE_HP_ATTN_LED:
		state = pcie_slotctl_attn_indicator_get(control);
		break;
	default:
		PCIE_DBG("pciehpc_get_led_state() invalid LED %d\n", led);
		return (PCIE_HP_LED_OFF);
	}

	switch (state) {
	case PCIE_SLOTCTL_INDICATOR_STATE_ON:
		return (PCIE_HP_LED_ON);

	case PCIE_SLOTCTL_INDICATOR_STATE_BLINK:
		return (PCIE_HP_LED_BLINK);

	case PCIE_SLOTCTL_INDICATOR_STATE_OFF:
	default:
		return (PCIE_HP_LED_OFF);
	}
}

/*
 * Set the state of an LED. It updates both hw and sw state.
 */
static void
pciehpc_set_led_state(pcie_hp_ctrl_t *ctrl_p, pcie_hp_led_t led,
    pcie_hp_led_state_t state)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	control;

	/* get the current state of Slot Control register */
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	switch (led) {
	case PCIE_HP_POWER_LED:
		/* clear led mask */
		control &= ~PCIE_SLOTCTL_PWR_INDICATOR_MASK;
		slot_p->hs_power_led_state = state;
		break;
	case PCIE_HP_ATTN_LED:
		/* clear led mask */
		control &= ~PCIE_SLOTCTL_ATTN_INDICATOR_MASK;
		slot_p->hs_attn_led_state = state;
		break;
	default:
		PCIE_DBG("pciehpc_set_led_state() invalid LED %d\n", led);
		return;
	}

	switch (state) {
	case PCIE_HP_LED_ON:
		if (led == PCIE_HP_POWER_LED)
			control = pcie_slotctl_pwr_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_ON);
		else if (led == PCIE_HP_ATTN_LED)
			control = pcie_slotctl_attn_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_ON);
		break;
	case PCIE_HP_LED_OFF:
		if (led == PCIE_HP_POWER_LED)
			control = pcie_slotctl_pwr_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_OFF);
		else if (led == PCIE_HP_ATTN_LED)
			control = pcie_slotctl_attn_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_OFF);
		break;
	case PCIE_HP_LED_BLINK:
		if (led == PCIE_HP_POWER_LED)
			control = pcie_slotctl_pwr_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_BLINK);
		else if (led == PCIE_HP_ATTN_LED)
			control = pcie_slotctl_attn_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_BLINK);
		break;

	default:
		PCIE_DBG("pciehpc_set_led_state() invalid LED state %d\n",
		    state);
		return;
	}

	/* update the Slot Control Register */
	pciehpc_issue_hpc_command(ctrl_p, control);

#ifdef DEBUG
	/* get the current state of Slot Control register */
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	PCIE_DBG("pciehpc_set_led_state: slot %d power-led %s attn-led %s\n",
	    slot_p->hs_phy_slot_num, pcie_led_state_text(
	    pciehpc_led_state_to_hpc(pcie_slotctl_pwr_indicator_get(control))),
	    pcie_led_state_text(pciehpc_led_state_to_hpc(
	    pcie_slotctl_attn_indicator_get(control))));
#endif
}

static void
pciehpc_handle_power_fault(dev_info_t *dip)
{
	/*
	 * Hold the parent's ref so that it won't disappear when the taskq is
	 * scheduled to run.
	 */
	ndi_hold_devi(dip);

	if (taskq_dispatch(system_taskq, pciehpc_power_fault_handler, dip,
	    TQ_NOSLEEP) == TASKQID_INVALID) {
		ndi_rele_devi(dip);
		PCIE_DBG("pciehpc_intr(): "
		    "Failed to dispatch power fault handler, dip %p\n", dip);
	}
}

static void
pciehpc_power_fault_handler(void *arg)
{
	dev_info_t *dip = (dev_info_t *)arg;
	pcie_hp_ctrl_t  *ctrl_p;
	pcie_hp_slot_t  *slot_p;

	/* get the soft state structure for this dip */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL) {
		ndi_rele_devi(dip);
		return;
	}
	slot_p = ctrl_p->hc_slots[0];

	/*
	 * Send the event to DDI Hotplug framework, power off
	 * the slot
	 */
	(void) ndi_hp_state_change_req(dip,
	    slot_p->hs_info.cn_name,
	    DDI_HP_CN_STATE_EMPTY, DDI_HP_REQ_SYNC);

	mutex_enter(&ctrl_p->hc_mutex);
	pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED,
	    PCIE_HP_LED_ON);
	mutex_exit(&ctrl_p->hc_mutex);
	ndi_rele_devi(dip);
}

#ifdef DEBUG
/*
 * Dump PCI-E Hot Plug registers.
 */
static void
pciehpc_dump_hpregs(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	control;
	uint32_t	capabilities;

	if (!pcie_debug_flags)
		return;

	capabilities = pciehpc_reg_get32(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCAP);

	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	PCIE_DBG("pciehpc_dump_hpregs: Found PCI-E hot plug slot %d\n",
	    slot_p->hs_phy_slot_num);

	PCIE_DBG("Attention Button Present = %s\n",
	    capabilities & PCIE_SLOTCAP_ATTN_BUTTON ? "Yes":"No");

	PCIE_DBG("Power controller Present = %s\n",
	    capabilities & PCIE_SLOTCAP_POWER_CONTROLLER ? "Yes":"No");

	PCIE_DBG("MRL Sensor Present	   = %s\n",
	    capabilities & PCIE_SLOTCAP_MRL_SENSOR ? "Yes":"No");

	PCIE_DBG("Attn Indicator Present   = %s\n",
	    capabilities & PCIE_SLOTCAP_ATTN_INDICATOR ? "Yes":"No");

	PCIE_DBG("Power Indicator Present  = %s\n",
	    capabilities & PCIE_SLOTCAP_PWR_INDICATOR ? "Yes":"No");

	PCIE_DBG("HotPlug Surprise	   = %s\n",
	    capabilities & PCIE_SLOTCAP_HP_SURPRISE ? "Yes":"No");

	PCIE_DBG("HotPlug Capable	   = %s\n",
	    capabilities & PCIE_SLOTCAP_HP_CAPABLE ? "Yes":"No");

	PCIE_DBG("Physical Slot Number	   = %d\n",
	    PCIE_SLOTCAP_PHY_SLOT_NUM(capabilities));

	PCIE_DBG("Attn Button interrupt Enabled  = %s\n",
	    control & PCIE_SLOTCTL_ATTN_BTN_EN ? "Yes":"No");

	PCIE_DBG("Power Fault interrupt Enabled  = %s\n",
	    control & PCIE_SLOTCTL_PWR_FAULT_EN ? "Yes":"No");

	PCIE_DBG("MRL Sensor INTR Enabled   = %s\n",
	    control & PCIE_SLOTCTL_MRL_SENSOR_EN ? "Yes":"No");

	PCIE_DBG("Presence interrupt Enabled	 = %s\n",
	    control & PCIE_SLOTCTL_PRESENCE_CHANGE_EN ? "Yes":"No");

	PCIE_DBG("Cmd Complete interrupt Enabled = %s\n",
	    control & PCIE_SLOTCTL_CMD_INTR_EN ? "Yes":"No");

	PCIE_DBG("HotPlug interrupt Enabled	 = %s\n",
	    control & PCIE_SLOTCTL_HP_INTR_EN ? "Yes":"No");

	PCIE_DBG("Power Indicator LED = %s", pcie_led_state_text(
	    pciehpc_led_state_to_hpc(pcie_slotctl_pwr_indicator_get(control))));

	PCIE_DBG("Attn Indicator LED = %s\n",
	    pcie_led_state_text(pciehpc_led_state_to_hpc(
	    pcie_slotctl_attn_indicator_get(control))));
}
#endif	/* DEBUG */
