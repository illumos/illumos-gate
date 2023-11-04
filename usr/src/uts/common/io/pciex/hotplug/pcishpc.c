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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2019 Joyent, Inc.
 */

/*
 * This file contains PCI HotPlug functionality that is compatible with the
 * PCI SHPC specification 1.x.
 *
 * NOTE: This file is compiled and delivered through misc/pcie module.
 */

#include <sys/note.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/autoconf.h>
#include <sys/varargs.h>
#include <sys/hwconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/callb.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sysevent/dr.h>
#include <sys/ndi_impldefs.h>
#include <sys/pci_impl.h>
#include <sys/hotplug/pci/pcie_hp.h>
#include <sys/hotplug/pci/pcishpc.h>

typedef struct pcishpc_prop {
	char	*prop_name;
	char	*prop_value;
} pcishpc_prop_t;

static pcishpc_prop_t	pcishpc_props[] = {
	{ PCIEHPC_PROP_LED_FAULT,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_LED_POWER,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_LED_ATTN,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_LED_ACTIVE,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_CARD_TYPE,	PCIEHPC_PROP_VALUE_TYPE },
	{ PCIEHPC_PROP_BOARD_TYPE,	PCIEHPC_PROP_VALUE_TYPE },
	{ PCIEHPC_PROP_SLOT_CONDITION,	PCIEHPC_PROP_VALUE_TYPE }
};

/* reset delay to 1 sec. */
static int pcishpc_reset_delay = 1000000;

/* Local function prototype */
static pcie_hp_ctrl_t *pcishpc_create_controller(dev_info_t *dip);
static int	pcishpc_setup_controller(pcie_hp_ctrl_t *ctrl_p);
static int	pcishpc_destroy_controller(dev_info_t *dip);
static pcie_hp_slot_t	*pcishpc_create_slot(pcie_hp_ctrl_t *ctrl_p);
static int	pcishpc_register_slot(pcie_hp_ctrl_t *ctrl_p, int slot);
static int	pcishpc_destroy_slots(pcie_hp_ctrl_t *ctrl_p);
static int	pcishpc_slot_get_property(pcie_hp_slot_t *slot_p,
		    ddi_hp_property_t *arg, ddi_hp_property_t *rval);
static int	pcishpc_slot_set_property(pcie_hp_slot_t *slot_p,
		    ddi_hp_property_t *arg, ddi_hp_property_t *rval);
static int	pcishpc_issue_command(pcie_hp_ctrl_t *ctrl_p,
		    uint32_t cmd_code);
static int	pcishpc_wait_busy(pcie_hp_ctrl_t *ctrl_p);
static void	pcishpc_attn_btn_handler(pcie_hp_slot_t *slot_p);
static void	pcishpc_get_slot_state(pcie_hp_slot_t *slot_p);
static int	pcishpc_set_slot_state(pcie_hp_slot_t *slot_p,
		    ddi_hp_cn_state_t new_slot_state);
static void	pcishpc_set_slot_name(pcie_hp_ctrl_t *ctrl_p, int slot);
static int	pcishpc_set_bus_speed(pcie_hp_slot_t *slot_p);
static int	pcishpc_setled(pcie_hp_slot_t *slot_p, pcie_hp_led_t led,
		    pcie_hp_led_state_t state);
static int	pcishpc_led_shpc_to_hpc(int state);
static int	pcishpc_led_hpc_to_shpc(int state);
static int	pcishpc_slot_shpc_to_hpc(int shpc_state);
static int	pcishpc_slot_hpc_to_shpc(int state);
static char	*pcishpc_slot_textslotstate(ddi_hp_cn_state_t state);
static char	*pcishpc_slot_textledstate(pcie_hp_led_state_t state);

static uint32_t	pcishpc_read_reg(pcie_hp_ctrl_t *ctrl_p, int reg);
static void	pcishpc_write_reg(pcie_hp_ctrl_t *ctrl_p, int reg,
		    uint32_t data);

static int	pcishpc_upgrade_slot_state(pcie_hp_slot_t *slot_p,
		    ddi_hp_cn_state_t target_state);
static int	pcishpc_downgrade_slot_state(pcie_hp_slot_t *slot_p,
		    ddi_hp_cn_state_t target_state);
static int	pcishpc_change_slot_state(pcie_hp_slot_t *slot_p,
		    ddi_hp_cn_state_t target_state);

static int	pcishpc_slot_poweron(pcie_hp_slot_t *slot_p,
		    ddi_hp_cn_state_t *result_state);
static int	pcishpc_slot_poweroff(pcie_hp_slot_t *slot_p,
		    ddi_hp_cn_state_t *result_state);
static int	pcishpc_slot_probe(pcie_hp_slot_t *slot_p);
static int	pcishpc_slot_unprobe(pcie_hp_slot_t *slot_p);
#ifdef	DEBUG
static void	pcishpc_dump_regs(pcie_hp_ctrl_t *ctrl_p);
#endif	/* DEBUG */


/*
 * Global functions (called by other drivers/modules)
 */

/*
 * pcishpc_init()
 *
 * Install and configure an SHPC controller and register the HotPlug slots
 * with the Solaris HotPlug framework. This function is usually called by
 * a PCI bridge Nexus driver that has a built in SHPC controller.
 */
int
pcishpc_init(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	pcie_hp_ctrl_t	*ctrl_p;
	int		i;

	PCIE_DBG("pcishpc_init() called from %s#%d\n",
	    ddi_driver_name(dip), ddi_get_instance(dip));

	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) != NULL) {
		PCIE_DBG("pcishpc_init() shpc instance already "
		    "initialized!\n");
		return (DDI_SUCCESS);
	}

	/* Initialize soft state structure for the SHPC instance. */
	ctrl_p = pcishpc_create_controller(dip);

	if (ctrl_p == NULL) {
		PCIE_DBG("pcishpc_init() failed to create shpc softstate\n");
		return (DDI_FAILURE);
	}

	if (pcishpc_setup_controller(ctrl_p) != DDI_SUCCESS) {
		PCIE_DBG("pcishpc_init() failed to setup controller\n");
		goto cleanup;
	}

	/*
	 * Setup resource maps for this bus node.
	 */
	(void) pci_resource_setup(dip);

#ifdef	DEBUG
	PCIE_DBG("%s%d: P2P bridge register dump:\n",
	    ddi_driver_name(dip), ddi_get_instance(dip));

	for (i = 0; i < 0x100; i += 4) {
		PCIE_DBG("SHPC Cfg reg 0x%02x: %08x\n", i,
		    pci_config_get32(bus_p->bus_cfg_hdl, i));
	}
#endif	/* DEBUG */

	/* Setup each HotPlug slot on this SHPC controller. */
	for (i = 0; i < ctrl_p->hc_num_slots_impl; i++) {
		if (pcishpc_register_slot(ctrl_p, i) != DDI_SUCCESS) {
			PCIE_DBG("pcishpc_init() failed to register "
			    "slot %d\n", i);
			goto cleanup1;
		}
		if (pcie_create_minor_node(ctrl_p, i) != DDI_SUCCESS) {
			PCIE_DBG("pcishpc_init() failed to create "
			    "minor node for slot %d\n", i);
			goto cleanup1;
		}
	}

#ifdef	DEBUG
	/* Dump out the SHPC registers. */
	pcishpc_dump_regs(ctrl_p);
#endif	/* DEBUG */

	PCIE_DBG("pcishpc_init() success(dip=%p)\n", dip);
	return (DDI_SUCCESS);

cleanup1:
	for (i = 0; i < ctrl_p->hc_num_slots_impl; i++) {
		if (ctrl_p->hc_slots[i] == NULL)
			continue;

		pcie_remove_minor_node(ctrl_p, i);
	}
	(void) pci_resource_destroy(dip);
cleanup:
	(void) pcishpc_destroy_controller(dip);
	return (DDI_FAILURE);
}

/*
 * pcishpc_uninit()
 * Unload the HogPlug controller driver and deallocate all resources.
 */
int
pcishpc_uninit(dev_info_t *dip)
{
	pcie_hp_ctrl_t *ctrl_p;
	int i;

	PCIE_DBG("pcishpc_uninit() called(dip=%p)\n", dip);

	ctrl_p = PCIE_GET_HP_CTRL(dip);

	if (!ctrl_p) {
		PCIE_DBG("pcishpc_uninit() Unable to find softstate\n");
		return (DDI_FAILURE);
	}

	for (i = 0; i < PCIE_HP_MAX_SLOTS; i++) {
		if (ctrl_p->hc_slots[i] == NULL)
			continue;

		pcie_remove_minor_node(ctrl_p, i);
	}

	ctrl_p->hc_flags = 0;

	/*
	 * Destroy resource maps for this bus node.
	 */
	(void) pci_resource_destroy(dip);

	(void) pcishpc_destroy_controller(dip);

	PCIE_DBG("pcishpc_uninit() success(dip=%p)\n", dip);

	return (DDI_SUCCESS);
}

/*
 * pcishpc_intr()
 *
 * This is the SHPC controller interrupt handler.
 */
int
pcishpc_intr(dev_info_t *dip)
{
	pcie_hp_ctrl_t	*ctrl_p;
	uint32_t	irq_locator, irq_serr_locator, reg;
	int		slot;

	PCIE_DBG("pcishpc_intr() called\n");

	/* get the soft state structure for this dip */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL)
		return (DDI_INTR_UNCLAIMED);

	mutex_enter(&ctrl_p->hc_mutex);

	if (!(ctrl_p->hc_flags & PCIE_HP_INITIALIZED_FLAG)) {
		PCIE_DBG("pcishpc_intr() unclaimed\n");
		mutex_exit(&ctrl_p->hc_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	PCIE_DBG("pcishpc_intr() interrupt received\n");

	reg = pcishpc_read_reg(ctrl_p, PCI_HP_CTRL_SERR_INT_REG);

	if (reg & PCI_HP_SERR_INT_CMD_COMPLETE_IRQ) {
		PCIE_DBG("pcishpc_intr() "
		    "PCI_HP_SERR_INT_CMD_COMPLETE_IRQ detected\n");
		ctrl_p->hc_cmd_pending = B_FALSE;
		cv_signal(&ctrl_p->hc_cmd_comp_cv);
	}

	if (reg & PCI_HP_SERR_INT_ARBITER_IRQ) {
		PCIE_DBG("pcishpc_intr() PCI_HP_SERR_INT_ARBITER_IRQ "
		    "detected\n");
		ctrl_p->hc_arbiter_timeout = B_TRUE;
	}

	/* Write back the SERR INT register to acknowledge the IRQs. */
	pcishpc_write_reg(ctrl_p, PCI_HP_CTRL_SERR_INT_REG, reg);

	irq_locator = pcishpc_read_reg(ctrl_p, PCI_HP_IRQ_LOCATOR_REG);
	irq_serr_locator = pcishpc_read_reg(ctrl_p, PCI_HP_SERR_LOCATOR_REG);

	/* Check for slot events that might have occured. */
	for (slot = 0; slot < ctrl_p->hc_num_slots_impl; slot++) {
		if ((irq_locator & (PCI_HP_IRQ_SLOT_N_PENDING<<slot)) ||
		    (irq_serr_locator &
		    (PCI_HP_IRQ_SERR_SLOT_N_PENDING<<slot))) {
			PCIE_DBG("pcishpc_intr() slot %d and "
			    "pending IRQ\n", slot+1);

			reg = pcishpc_read_reg(ctrl_p,
			    PCI_HP_LOGICAL_SLOT_REGS+slot);

			if (reg & PCI_HP_SLOT_PRESENCE_DETECTED)
				PCIE_DBG("slot %d: "
				    "PCI_HP_SLOT_PRESENCE_DETECTED\n",
				    slot+1);

			if (reg & PCI_HP_SLOT_ISO_PWR_DETECTED)
				PCIE_DBG("slot %d: "
				    "PCI_HP_SLOT_ISO_PWR_DETECTED\n",
				    slot+1);

			if (reg & PCI_HP_SLOT_ATTN_DETECTED) {
				PCIE_DBG("slot %d: "
				    "PCI_HP_SLOT_ATTN_DETECTED\n", slot+1);

				/*
				 * if ATTN button event is still pending
				 * then cancel it
				 */
				if (ctrl_p->hc_slots[slot]->
				    hs_attn_btn_pending == B_TRUE)
					ctrl_p->hc_slots[slot]->
					    hs_attn_btn_pending = B_FALSE;

				/* wake up the ATTN event handler */
				cv_signal(&ctrl_p->hc_slots[slot]->
				    hs_attn_btn_cv);
			}

			if (reg & PCI_HP_SLOT_MRL_DETECTED)
				PCIE_DBG("slot %d: "
				    "PCI_HP_SLOT_MRL_DETECTED\n", slot+1);

			if (reg & PCI_HP_SLOT_POWER_DETECTED)
				PCIE_DBG("slot %d: "
				    "PCI_HP_SLOT_POWER_DETECTED\n", slot+1);

			/* Acknoledge any slot interrupts */
			pcishpc_write_reg(ctrl_p, PCI_HP_LOGICAL_SLOT_REGS+slot,
			    reg);
		}
	}

	mutex_exit(&ctrl_p->hc_mutex);

	PCIE_DBG("pcishpc_intr() claimed\n");

	return (DDI_INTR_CLAIMED);
}

int
pcishpc_slot_get_property(pcie_hp_slot_t *slot_p, ddi_hp_property_t *arg,
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
		n = sizeof (pcishpc_props) / sizeof (pcishpc_prop_t);

		if (strcmp(name, PCIEHPC_PROP_ALL) == 0) {
			(void) nvlist_remove_all(prop_list, PCIEHPC_PROP_ALL);

			/*
			 * Add all properties into the request list, so that we
			 * will get the values in the following for loop.
			 */
			for (i = 0; i < n; i++) {
				if (nvlist_add_string(prop_list,
				    pcishpc_props[i].prop_name, "") != 0) {
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
				    pcishpc_props[i].prop_name,
				    pcishpc_props[i].prop_value) != 0) {
					ret = DDI_FAILURE;
					goto get_prop_cleanup1;
				}
			}
		}
	}

	mutex_enter(&ctrl_p->hc_mutex);

	/* get the current slot state */
	pcishpc_get_slot_state(slot_p);

	/* for each requested property, get the value and add it to nvlist */
	prop_pair = NULL;
	while ((prop_pair = nvlist_next_nvpair(prop_list, prop_pair)) != NULL) {
		name = nvpair_name(prop_pair);
		value = NULL;

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
			ddi_acc_handle_t	handle;
			dev_info_t	*cdip;
			uint8_t		prog_class, base_class, sub_class;
			size_t		i;

			mutex_exit(&ctrl_p->hc_mutex);
			cdip = pcie_hp_devi_find(
			    ctrl_p->hc_dip, slot_p->hs_device_num, 0);
			mutex_enter(&ctrl_p->hc_mutex);

			if ((slot_p->hs_info.cn_state !=
			    DDI_HP_CN_STATE_ENABLED) || (cdip == NULL)) {
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

	// pack nvlist and copyout
	if ((ret = pcie_copyout_nvlist(prop_rlist, result.nvlist_buf,
	    &result.buf_size)) != DDI_SUCCESS) {
		goto get_prop_cleanup2;
	}
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyout(&result, rval, sizeof (ddi_hp_property_t))) {
			ret = DDI_FAILURE;
			goto get_prop_cleanup2;
		}
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
pcishpc_slot_set_property(pcie_hp_slot_t *slot_p, ddi_hp_property_t *arg,
    ddi_hp_property_t *rval)
{
	ddi_hp_property_t request, result;
#ifdef _SYSCALL32_IMPL
	ddi_hp_property32_t request32, result32;
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
	while ((prop_pair = nvlist_next_nvpair(prop_list, prop_pair)) != NULL) {
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
	pcishpc_get_slot_state(slot_p);

	// set each property
	prop_pair = NULL;
	while ((prop_pair = nvlist_next_nvpair(prop_list, prop_pair)) != NULL) {
		name = nvpair_name(prop_pair);

		if (strcmp(name, PCIEHPC_PROP_LED_ATTN) == 0) {
			if (strcmp(value, PCIEHPC_PROP_VALUE_ON) == 0)
				led_state = PCIE_HP_LED_ON;
			else if (strcmp(value, PCIEHPC_PROP_VALUE_OFF) == 0)
				led_state = PCIE_HP_LED_OFF;
			else if (strcmp(value, PCIEHPC_PROP_VALUE_BLINK) == 0)
				led_state = PCIE_HP_LED_BLINK;
			else
				continue;

			(void) pcishpc_setled(slot_p, PCIE_HP_ATTN_LED,
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
 * pcishpc_hp_ops()
 *
 * Handle hotplug commands
 *
 * Note: This function is called by DDI HP framework at kernel context only
 */
/* ARGSUSED */
int
pcishpc_hp_ops(dev_info_t *dip, char *cn_name, ddi_hp_op_t op,
    void *arg, void *result)
{
	pcie_hp_slot_t	*slot_p = NULL;
	pcie_hp_ctrl_t	*ctrl_p;
	int		ret = DDI_SUCCESS, i;

	PCIE_DBG("pcishpc_hp_ops: dip=%p cn_name=%s op=%x arg=%p\n",
	    dip, cn_name, op, arg);

	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL)
		return (DDI_FAILURE);

	for (i = 0; i < PCIE_HP_MAX_SLOTS && ctrl_p->hc_slots[i]; i++) {
		if (strcmp(ctrl_p->hc_slots[i]->hs_info.cn_name, cn_name)
		    == 0) {
			/* Match with a physical slot, found */
			slot_p = ctrl_p->hc_slots[i];
			break;
		}
	}
	if (!slot_p) {
		PCIE_DBG("pcishpc_hp_ops: Failed to find the slot under"
		    "dip %p with name: %s; op=%x arg=%p\n",
		    dip, cn_name, op, arg);
		return (DDI_EINVAL);
	}
	switch (op) {
	case DDI_HPOP_CN_GET_STATE:
	{
		mutex_enter(&ctrl_p->hc_mutex);

		/* get the current slot state */
		pcishpc_get_slot_state(slot_p);

		*((ddi_hp_cn_state_t *)result) = slot_p->hs_info.cn_state;

		mutex_exit(&ctrl_p->hc_mutex);
		break;
	}
	case DDI_HPOP_CN_CHANGE_STATE:
	{
		ddi_hp_cn_state_t target_state = *(ddi_hp_cn_state_t *)arg;

		mutex_enter(&slot_p->hs_ctrl->hc_mutex);

		ret = pcishpc_change_slot_state(slot_p, target_state);
		*((ddi_hp_cn_state_t *)result) = slot_p->hs_info.cn_state;

		mutex_exit(&slot_p->hs_ctrl->hc_mutex);
		break;
	}
	case DDI_HPOP_CN_PROBE:
		ret = pcishpc_slot_probe(slot_p);

		break;
	case DDI_HPOP_CN_UNPROBE:
		ret = pcishpc_slot_unprobe(slot_p);

		break;
	case DDI_HPOP_CN_GET_PROPERTY:
		ret = pcishpc_slot_get_property(slot_p,
		    (ddi_hp_property_t *)arg, (ddi_hp_property_t *)result);
		break;
	case DDI_HPOP_CN_SET_PROPERTY:
		ret = pcishpc_slot_set_property(slot_p,
		    (ddi_hp_property_t *)arg, (ddi_hp_property_t *)result);
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

/*
 * Local functions (called within this file)
 */

/*
 * pcishpc_create_controller()
 *
 * This function allocates and creates an SHPC controller state structure
 * and adds it to the linked list of controllers.
 */
static pcie_hp_ctrl_t *
pcishpc_create_controller(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	pcie_hp_ctrl_t	*ctrl_p;

	PCIE_DBG("pcishpc: create controller for %s#%d\n",
	    ddi_driver_name(dip), ddi_get_instance(dip));

	ctrl_p = kmem_zalloc(sizeof (pcie_hp_ctrl_t), KM_SLEEP);
	ctrl_p->hc_dip = dip;

	cv_init(&ctrl_p->hc_cmd_comp_cv, NULL, CV_DRIVER, NULL);

	/* Init the shpc controller's mutex. */
	mutex_init(&ctrl_p->hc_mutex, NULL, MUTEX_DRIVER, NULL);

	/* HPC initialization is complete now */
	ctrl_p->hc_flags = PCIE_HP_INITIALIZED_FLAG;
	bus_p->bus_hp_curr_mode = PCIE_PCI_HP_MODE;

	PCIE_SET_HP_CTRL(dip, ctrl_p);

	PCIE_DBG("pcishpc_create_controller() success\n");

	return (ctrl_p);
}


/*
 * pcishpc_setup_controller()
 *
 * Get the number of HotPlug Slots, and the PCI device information
 * for this HotPlug controller.
 */
static int
pcishpc_setup_controller(pcie_hp_ctrl_t *ctrl_p)
{
	uint32_t config;
	dev_info_t *ppdip;

	config = pcishpc_read_reg(ctrl_p, PCI_HP_SLOT_CONFIGURATION_REG);

	/* Get the number of HotPlug slots implemented */
	ctrl_p->hc_num_slots_impl = ((config)&31);

	/*
	 * Initilize the current bus speed and number of hotplug slots
	 * currently connected.
	 */
	ctrl_p->hc_curr_bus_speed = -1;
	ctrl_p->hc_num_slots_connected = 0;

	/*
	 * Get the first PCI device Number used.
	 *
	 * PCI-X I/O boat workaround.
	 * The register doesn't set up the correct value.
	 */
	ppdip = ddi_get_parent(ddi_get_parent(ctrl_p->hc_dip));
	if ((ddi_prop_get_int(DDI_DEV_T_ANY, ppdip, DDI_PROP_DONTPASS,
	    "vendor-id", -1) == 0x108e) &&
	    (ddi_prop_get_int(DDI_DEV_T_ANY, ppdip, DDI_PROP_DONTPASS,
	    "device-id", -1) == 0x9010))
		ctrl_p->hc_device_start = 4;
	else
		ctrl_p->hc_device_start = ((config>>8)&31);

	/* Get the first Physical device number. */
	ctrl_p->hc_phys_start = ((config>>16)&0x7ff);

	/* Check if the device numbers increase or decrease. */
	ctrl_p->hc_device_increases = ((config>>29)&0x1);

	ctrl_p->hc_has_attn =
	    (config & PCI_HP_SLOT_CONFIG_ATTN_BUTTON) ? B_TRUE : B_FALSE;
	ctrl_p->hc_has_mrl =
	    (config & PCI_HP_SLOT_CONFIG_MRL_SENSOR) ? B_TRUE : B_FALSE;

	ctrl_p->hc_cmd_pending = B_FALSE;
	ctrl_p->hc_arbiter_timeout = B_FALSE;

	if (ctrl_p->hc_num_slots_impl > PCIE_HP_MAX_SLOTS) {
		PCIE_DBG("pcishpc_setup_controller() too many SHPC "
		    "slots error\n");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * pcishpc_destroy_controller()
 *
 * This function deallocates all of the SHPC controller resources.
 */
static int
pcishpc_destroy_controller(dev_info_t *dip)
{
	pcie_hp_ctrl_t	*ctrl_p;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	PCIE_DBG("pcishpc_destroy_controller() called(dip=%p)\n", dip);

	/* get the soft state structure for this dip */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL) {
		PCIE_DBG("pcishpc_destroy_controller() not found\n");
		return (DDI_FAILURE);
	}

	/*
	 * Deallocate the slot state structures for this controller.
	 */
	PCIE_SET_HP_CTRL(dip, NULL);
	bus_p->bus_hp_curr_mode = PCIE_NONE_HP_MODE;

	(void) pcishpc_destroy_slots(ctrl_p);
	cv_destroy(&ctrl_p->hc_cmd_comp_cv);
	mutex_destroy(&ctrl_p->hc_mutex);
	kmem_free(ctrl_p, sizeof (pcie_hp_ctrl_t));

	PCIE_DBG("pcishpc_destroy_controller() success\n");
	return (DDI_SUCCESS);
}

/*
 * pcishpc_create_slot()
 *
 * Allocate and add a new HotPlug slot state structure to the linked list.
 */
static pcie_hp_slot_t *
pcishpc_create_slot(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t *slot_p;

	PCIE_DBG("pcishpc_create_slot() called(ctrl_p=%x)\n", ctrl_p);

	/* Allocate a new slot structure. */
	slot_p = kmem_zalloc(sizeof (pcie_hp_slot_t), KM_SLEEP);
	slot_p->hs_ctrl = ctrl_p;

	/* Assign an initial value */
	slot_p->hs_info.cn_state = DDI_HP_CN_STATE_EMPTY;

	PCIE_DBG("pcishpc_create_slot() success\n");
	return (slot_p);
}

/*
 * pcishpc_register_slot()
 *
 * Create and register a slot with the Solaris HotPlug framework.
 */
static int
pcishpc_register_slot(pcie_hp_ctrl_t *ctrl_p, int slot)
{
	dev_info_t	*dip = ctrl_p->hc_dip;
	pcie_hp_slot_t	*slot_p;

	slot_p = pcishpc_create_slot(ctrl_p);
	ctrl_p->hc_slots[slot] = slot_p;
	slot_p->hs_num = slot;

	/* Setup the PCI device # for this SHPC slot. */
	if (ctrl_p->hc_device_increases)
		slot_p->hs_device_num = ctrl_p->hc_device_start +
		    slot_p->hs_num;
	else
		slot_p->hs_device_num = ctrl_p->hc_device_start -
		    slot_p->hs_num;

	/* Setup the DDI HP framework slot information. */
	slot_p->hs_info.cn_type = DDI_HP_CN_TYPE_PCI;
	slot_p->hs_info.cn_type_str = PCIE_PCI_HP_TYPE;
	slot_p->hs_info.cn_child = NULL;

	slot_p->hs_minor = PCI_MINOR_NUM(
	    ddi_get_instance(dip), slot_p->hs_device_num);
	slot_p->hs_condition = AP_COND_UNKNOWN;

	/* setup thread for handling ATTN button events */
	if (ctrl_p->hc_has_attn) {
		PCIE_DBG("pcishpc_register_slot: "
		    "setting up ATTN button event "
		    "handler thread for slot %d\n", slot);

		cv_init(&slot_p->hs_attn_btn_cv, NULL, CV_DRIVER, NULL);
		slot_p->hs_attn_btn_pending = B_FALSE;
		slot_p->hs_attn_btn_threadp = thread_create(NULL, 0,
		    pcishpc_attn_btn_handler,
		    (void *)slot_p, 0, &p0, TS_RUN, minclsyspri);
		slot_p->hs_attn_btn_thread_exit = B_FALSE;
	}

	/* setup the slot name (used for ap-id) */
	pcishpc_set_slot_name(ctrl_p, slot);

	pcishpc_get_slot_state(slot_p);
	if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_ENABLED)
		slot_p->hs_condition = AP_COND_OK;

	/* register the slot with DDI HP framework */
	if (ndi_hp_register(dip, &slot_p->hs_info) != NDI_SUCCESS) {
		PCIE_DBG("pciehpc_register_slot() failed to register slot %d\n",
		    slot_p->hs_phy_slot_num);
		return (DDI_FAILURE);
	}

	pcie_hp_create_occupant_props(dip, makedevice(ddi_driver_major(dip),
	    slot_p->hs_minor), slot_p->hs_device_num);

	PCIE_DBG("pcishpc_register_slot() success for slot %d\n", slot);

	return (DDI_SUCCESS);
}

/*
 * pcishpc_destroy_slots()
 *
 * Free up all of the slot resources for this controller.
 */
static int
pcishpc_destroy_slots(pcie_hp_ctrl_t *ctrl_p)
{
	dev_info_t	*dip = ctrl_p->hc_dip;
	pcie_hp_slot_t	*slot_p;
	int		i;

	PCIE_DBG("pcishpc_destroy_slots() called(ctrl_p=%p)\n", ctrl_p);

	for (i = 0; i < PCIE_HP_MAX_SLOTS; i++) {
		if ((slot_p = ctrl_p->hc_slots[i]) == NULL)
			continue;

		if (slot_p->hs_attn_btn_threadp != NULL) {
			mutex_enter(&ctrl_p->hc_mutex);
			slot_p->hs_attn_btn_thread_exit = B_TRUE;
			cv_signal(&slot_p->hs_attn_btn_cv);
			PCIE_DBG("pcishpc_destroy_slots: "
			    "waiting for ATTN thread exit\n");
			cv_wait(&slot_p->hs_attn_btn_cv, &ctrl_p->hc_mutex);
			PCIE_DBG("pcishpc_destroy_slots: "
			    "ATTN thread exit\n");
			cv_destroy(&slot_p->hs_attn_btn_cv);
			slot_p->hs_attn_btn_threadp = NULL;
			mutex_exit(&ctrl_p->hc_mutex);
		}

		PCIE_DBG("pcishpc_destroy_slots() (shpc_p=%p)\n"
		    "destroyed", slot_p);

		pcie_hp_delete_occupant_props(dip,
		    makedevice(ddi_driver_major(dip),
		    slot_p->hs_minor));

		/* unregister the slot with DDI HP framework */
		if (ndi_hp_unregister(dip, slot_p->hs_info.cn_name) !=
		    NDI_SUCCESS) {
			PCIE_DBG("pcishpc_destroy_slots() "
			    "failed to unregister slot %d\n",
			    slot_p->hs_phy_slot_num);
			return (DDI_FAILURE);
		}
		kmem_free(slot_p->hs_info.cn_name,
		    strlen(slot_p->hs_info.cn_name) + 1);
		kmem_free(slot_p, sizeof (pcie_hp_slot_t));
	}

	return (DDI_SUCCESS);
}

/*
 * pcishpc_enable_irqs()
 *
 * Enable/unmask the different IRQ's we support from the SHPC controller.
 */
int
pcishpc_enable_irqs(pcie_hp_ctrl_t *ctrl_p)
{
	uint32_t reg;
	int slot;

	reg = pcishpc_read_reg(ctrl_p, PCI_HP_CTRL_SERR_INT_REG);

	/* Enable all interrupts. */
	reg &= ~PCI_HP_SERR_INT_MASK_ALL;

	pcishpc_write_reg(ctrl_p, PCI_HP_CTRL_SERR_INT_REG, reg);

	/* Unmask the interrupts for each slot. */
	for (slot = 0; slot < ctrl_p->hc_num_slots_impl; slot++) {
		reg = pcishpc_read_reg(ctrl_p, PCI_HP_LOGICAL_SLOT_REGS+slot);
		if ((reg & PCI_HP_SLOT_STATE_MASK) == PCI_HP_SLOT_ENABLED) {
			reg &= ~(PCI_HP_SLOT_MASK_ALL |
			    PCI_HP_SLOT_MRL_SERR_MASK);
			ctrl_p->hc_num_slots_connected++;
			if (ctrl_p->hc_curr_bus_speed == -1)
				ctrl_p->hc_curr_bus_speed =
				    pcishpc_read_reg(ctrl_p,
				    PCI_HP_PROF_IF_SBCR_REG) &
				    PCI_HP_SBCR_SPEED_MASK;
		} else {
			reg &= ~(PCI_HP_SLOT_MASK_ALL);
		}

		/* Enable/Unmask all slot interrupts. */
		pcishpc_write_reg(ctrl_p, PCI_HP_LOGICAL_SLOT_REGS+slot, reg);
	}

	PCIE_DBG("pcishpc_enable_irqs: ctrl_p 0x%p, "
	    "current bus speed 0x%x, slots connected 0x%x\n", ctrl_p,
	    ctrl_p->hc_curr_bus_speed, ctrl_p->hc_num_slots_connected);

	return (DDI_SUCCESS);
}


/*
 * pcishpc_disable_irqs()
 *
 * Disable/Mask the different IRQ's we support from the SHPC controller.
 */
int
pcishpc_disable_irqs(pcie_hp_ctrl_t *ctrl_p)
{
	uint32_t reg;
	int slot;

	reg = pcishpc_read_reg(ctrl_p, PCI_HP_CTRL_SERR_INT_REG);

	/* Mask all interrupts. */
	reg |= PCI_HP_SERR_INT_MASK_ALL;

	pcishpc_write_reg(ctrl_p, PCI_HP_CTRL_SERR_INT_REG, reg);

	/* Unmask the interrupts for each slot. */
	for (slot = 0; slot < ctrl_p->hc_num_slots_impl; slot++) {
		reg = pcishpc_read_reg(ctrl_p, PCI_HP_LOGICAL_SLOT_REGS+slot);

		/* Disable/Mask all slot interrupts. */
		reg |= PCI_HP_SLOT_MASK_ALL;

		pcishpc_write_reg(ctrl_p, PCI_HP_LOGICAL_SLOT_REGS+slot, reg);
	}

	PCIE_DBG("pcishpc_disable_irqs: ctrl_p 0x%p, "
	    "current bus speed 0x%x, slots connected 0x%x\n", ctrl_p,
	    ctrl_p->hc_curr_bus_speed, ctrl_p->hc_num_slots_connected);

	return (DDI_SUCCESS);
}

/*
 * pcishpc_slot_poweron()
 *
 * Poweron/Enable the slot.
 *
 * Note: This function is called by DDI HP framework at kernel context only
 */
/*ARGSUSED*/
static int
pcishpc_slot_poweron(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result_state)
{
	uint32_t	status;

	PCIE_DBG("pcishpc_slot_poweron called()\n");

	ASSERT(MUTEX_HELD(&slot_p->hs_ctrl->hc_mutex));

	/* get the current slot state */
	pcishpc_get_slot_state(slot_p);

	/* check if the slot is already in the 'enabled' state */
	if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_POWERED) {
		/* slot is already in the 'enabled' state */
		PCIE_DBG("pcishpc_slot_poweron() slot %d already enabled\n",
		    slot_p->hs_phy_slot_num);

		*result_state = slot_p->hs_info.cn_state;
		return (DDI_SUCCESS);
	}

	if (slot_p->hs_info.cn_state == DDI_HP_CN_STATE_EMPTY) {
		PCIE_DBG("pcishpc_slot_poweron() slot in empty state\n");
		goto cleanup;
	}

	/* make sure the MRL sensor is closed */
	status = pcishpc_read_reg(slot_p->hs_ctrl,
	    PCI_HP_LOGICAL_SLOT_REGS+slot_p->hs_num);

	if (status & PCI_HP_SLOT_MRL_STATE_MASK) {
		PCIE_DBG("pcishpc_slot_poweron() failed: MRL open\n");
		goto cleanup;
	}

	/* Set the Power LED to blink */
	(void) pcishpc_setled(slot_p, PCIE_HP_POWER_LED, PCIE_HP_LED_BLINK);

	/* Turn all other LEDS off */
	(void) pcishpc_setled(slot_p, PCIE_HP_FAULT_LED, PCIE_HP_LED_OFF);
	(void) pcishpc_setled(slot_p, PCIE_HP_ATTN_LED, PCIE_HP_LED_OFF);
	(void) pcishpc_setled(slot_p, PCIE_HP_ACTIVE_LED, PCIE_HP_LED_OFF);

	/* Set the bus speed only if the bus segment is not running */
	if (pcishpc_set_bus_speed(slot_p) != DDI_SUCCESS) {
		PCIE_DBG("pcishpc_slot_poweron() setting speed failed\n");
		goto cleanup;
	}

	slot_p->hs_ctrl->hc_num_slots_connected++;

	PCIE_DBG("pcishpc_slot_poweron(): slot_p 0x%p, slot state 0x%x, "
	    "current bus speed 0x%x, slots connected 0x%x\n", slot_p,
	    slot_p->hs_info.cn_state, slot_p->hs_ctrl->hc_curr_bus_speed,
	    slot_p->hs_ctrl->hc_num_slots_connected);

	/* Mask or Unmask MRL Sensor SEER bit based on new slot state */
	if (slot_p->hs_ctrl->hc_has_mrl == B_TRUE) {
		uint32_t reg;

		reg = pcishpc_read_reg(slot_p->hs_ctrl,
		    PCI_HP_LOGICAL_SLOT_REGS+slot_p->hs_num);

		pcishpc_write_reg(slot_p->hs_ctrl,
		    PCI_HP_LOGICAL_SLOT_REGS+slot_p->hs_num,
		    reg & ~PCI_HP_SLOT_MRL_SERR_MASK);
	}

	/* Update the hardware slot state. */
	if (pcishpc_set_slot_state(slot_p,
	    DDI_HP_CN_STATE_ENABLED) != DDI_SUCCESS) {
		PCIE_DBG("pcishpc_slot_poweron() failed\n");

		pcishpc_get_slot_state(slot_p);
		goto cleanup;
	}
	/* Update the current state. It will be used in pcishpc_setled() */
	slot_p->hs_info.cn_state = DDI_HP_CN_STATE_ENABLED;

	/* Turn the Power LED ON for a enabled slot. */
	(void) pcishpc_setled(slot_p, PCIE_HP_POWER_LED, PCIE_HP_LED_ON);

	/* Turn all other LEDS off. */
	(void) pcishpc_setled(slot_p, PCIE_HP_FAULT_LED, PCIE_HP_LED_OFF);
	(void) pcishpc_setled(slot_p, PCIE_HP_ATTN_LED, PCIE_HP_LED_OFF);
	(void) pcishpc_setled(slot_p, PCIE_HP_ACTIVE_LED, PCIE_HP_LED_OFF);

	/* delay after powerON to let the device initialize itself */
	delay(drv_usectohz(pcishpc_reset_delay));

	PCIE_DBG("pcishpc_slot_poweron() success!\n");

	/*
	 * Want to show up as POWERED state for now. It will be updated to
	 * ENABLED state when user explicitly enable the slot.
	 */
	slot_p->hs_info.cn_state = DDI_HP_CN_STATE_POWERED;

	/* get the current slot state */
	pcishpc_get_slot_state(slot_p);
	/*
	 * It should be poweron'ed now. Have a check here in case any
	 * hardware problems.
	 */
	if (slot_p->hs_info.cn_state < DDI_HP_CN_STATE_POWERED) {
		PCIE_DBG("pcishpc_slot_poweron() failed after hardware"
		    " registers all programmed.\n");

		goto cleanup;
	}

	*result_state = slot_p->hs_info.cn_state;

	return (DDI_SUCCESS);

cleanup:
	(void) pcishpc_setled(slot_p, PCIE_HP_POWER_LED, PCIE_HP_LED_OFF);
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
pcishpc_slot_poweroff(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result_state)
{
	PCIE_DBG("pcishpc_slot_poweroff called()\n");

	ASSERT(MUTEX_HELD(&slot_p->hs_ctrl->hc_mutex));

	/* get the current slot state */
	pcishpc_get_slot_state(slot_p);

	/* check if the slot is not in the "enabled" or "powered" state */
	if (slot_p->hs_info.cn_state < DDI_HP_CN_STATE_POWERED) {
		/* slot is in the 'disabled' state */
		PCIE_DBG("pcishpc_slot_poweroff(): "
		    "slot %d already disabled\n", slot_p->hs_phy_slot_num);

		*result_state = slot_p->hs_info.cn_state;
		return (DDI_SUCCESS);
	}

	/* Set the Power LED to blink */
	(void) pcishpc_setled(slot_p, PCIE_HP_POWER_LED, PCIE_HP_LED_BLINK);

	/* Turn all other LEDS off */
	(void) pcishpc_setled(slot_p, PCIE_HP_FAULT_LED, PCIE_HP_LED_OFF);
	(void) pcishpc_setled(slot_p, PCIE_HP_ATTN_LED, PCIE_HP_LED_OFF);
	(void) pcishpc_setled(slot_p, PCIE_HP_ACTIVE_LED, PCIE_HP_LED_OFF);

	if (--slot_p->hs_ctrl->hc_num_slots_connected == 0)
		slot_p->hs_ctrl->hc_curr_bus_speed = -1;

	PCIE_DBG("pcishpc_slot_poweroff(): slot_p 0x%p, slot state 0x%x, "
	    "current bus speed 0x%x, slots connected 0x%x\n", slot_p,
	    slot_p->hs_info.cn_state, slot_p->hs_ctrl->hc_curr_bus_speed,
	    slot_p->hs_ctrl->hc_num_slots_connected);

	/* Mask or Unmask MRL Sensor SEER bit based on new slot state */
	if (slot_p->hs_ctrl->hc_has_mrl == B_TRUE) {
		uint32_t reg;

		reg = pcishpc_read_reg(slot_p->hs_ctrl,
		    PCI_HP_LOGICAL_SLOT_REGS+slot_p->hs_num);

		pcishpc_write_reg(slot_p->hs_ctrl,
		    PCI_HP_LOGICAL_SLOT_REGS+slot_p->hs_num,
		    reg | PCI_HP_SLOT_MRL_SERR_MASK);
	}

	/* Update the hardware slot state. */
	if (pcishpc_set_slot_state(slot_p, DDI_HP_CN_STATE_PRESENT) !=
	    DDI_SUCCESS) {
		PCIE_DBG("pcishpc_slot_poweroff() failed\n");

		pcishpc_get_slot_state(slot_p);
		goto cleanup;
	}

	/* Update the current state. It will be used in pcishpc_setled() */
	slot_p->hs_info.cn_state = DDI_HP_CN_STATE_PRESENT;

	/* Turn the Power LED OFF for a disabled slot. */
	(void) pcishpc_setled(slot_p, PCIE_HP_POWER_LED, PCIE_HP_LED_OFF);

	/* Turn all other LEDS off. */
	(void) pcishpc_setled(slot_p, PCIE_HP_FAULT_LED, PCIE_HP_LED_OFF);
	(void) pcishpc_setled(slot_p, PCIE_HP_ATTN_LED, PCIE_HP_LED_OFF);
	(void) pcishpc_setled(slot_p, PCIE_HP_ACTIVE_LED, PCIE_HP_LED_OFF);

	/* delay after powerON to let the device initialize itself */
	delay(drv_usectohz(pcishpc_reset_delay));

	pcishpc_get_slot_state(slot_p);
	/*
	 * It should be poweroff'ed now. Have a check here in case any
	 * hardware problems.
	 */
	if (slot_p->hs_info.cn_state > DDI_HP_CN_STATE_PRESENT) {
		PCIE_DBG("pcishpc_slot_poweroff() failed after hardware"
		    " registers all programmed.\n");

		goto cleanup;
	}

	PCIE_DBG("pcishpc_slot_poweroff() success!\n");

	*result_state = slot_p->hs_info.cn_state;
	return (DDI_SUCCESS);

cleanup:
	(void) pcishpc_setled(slot_p, PCIE_HP_POWER_LED, PCIE_HP_LED_OFF);
	return (DDI_FAILURE);
}

/*
 * pcishpc_slot_probe()
 *
 * Probe the slot.
 *
 * Note: This function is called by DDI HP framework at kernel context only
 */
/*ARGSUSED*/
static int
pcishpc_slot_probe(pcie_hp_slot_t *slot_p)
{
	mutex_enter(&slot_p->hs_ctrl->hc_mutex);

	PCIE_DBG("pcishpc_slot_probe called()\n");

	/* get the current slot state */
	pcishpc_get_slot_state(slot_p);

	/*
	 * Probe a given PCI Hotplug Connection (CN).
	 */
	if (pcie_hp_probe(slot_p) != DDI_SUCCESS) {
		(void) pcishpc_setled(slot_p, PCIE_HP_ATTN_LED,
		    PCIE_HP_LED_BLINK);

		PCIE_DBG("pcishpc_slot_probe() failed\n");

		mutex_exit(&slot_p->hs_ctrl->hc_mutex);
		return (DDI_FAILURE);
	}

	PCIE_DBG("pcishpc_slot_probe() success!\n");

	/* get the current slot state */
	pcishpc_get_slot_state(slot_p);

	mutex_exit(&slot_p->hs_ctrl->hc_mutex);
	return (DDI_SUCCESS);
}

/*
 * pcishpc_slot_unprobe()
 *
 * Unprobe the slot.
 *
 * Note: This function is called by DDI HP framework at kernel context only
 */
/*ARGSUSED*/
static int
pcishpc_slot_unprobe(pcie_hp_slot_t *slot_p)
{
	mutex_enter(&slot_p->hs_ctrl->hc_mutex);

	PCIE_DBG("pcishpc_slot_unprobe called()\n");

	/* get the current slot state */
	pcishpc_get_slot_state(slot_p);

	/*
	 * Unprobe a given PCI Hotplug Connection (CN).
	 */
	if (pcie_hp_unprobe(slot_p) != DDI_SUCCESS) {
		(void) pcishpc_setled(slot_p, PCIE_HP_ATTN_LED,
		    PCIE_HP_LED_BLINK);

		PCIE_DBG("pcishpc_slot_unprobe() failed\n");

		mutex_exit(&slot_p->hs_ctrl->hc_mutex);
		return (DDI_FAILURE);
	}

	PCIE_DBG("pcishpc_slot_unprobe() success!\n");

	/* get the current slot state */
	pcishpc_get_slot_state(slot_p);

	mutex_exit(&slot_p->hs_ctrl->hc_mutex);
	return (DDI_SUCCESS);
}

static int
pcishpc_upgrade_slot_state(pcie_hp_slot_t *slot_p,
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
			pcishpc_get_slot_state(slot_p);
			curr_state = slot_p->hs_info.cn_state;
			if (curr_state < DDI_HP_CN_STATE_PRESENT)
				rv = DDI_FAILURE;
			break;
		case DDI_HP_CN_STATE_PRESENT:
			rv = pcishpc_slot_poweron(slot_p, &curr_state);
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
pcishpc_downgrade_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t curr_state;
	int rv = DDI_SUCCESS;


	curr_state = slot_p->hs_info.cn_state;
	while ((curr_state > target_state) && (rv == DDI_SUCCESS)) {

		switch (curr_state) {
		case DDI_HP_CN_STATE_PRESENT:
			/*
			 * From PRESENT to EMPTY, just check hardware
			 * slot state.
			 */
			pcishpc_get_slot_state(slot_p);
			curr_state = slot_p->hs_info.cn_state;
			if (curr_state >= DDI_HP_CN_STATE_PRESENT)
				rv = DDI_FAILURE;
			break;
		case DDI_HP_CN_STATE_POWERED:
			rv = pcishpc_slot_poweroff(slot_p, &curr_state);

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
pcishpc_change_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t curr_state;
	int rv;

	pcishpc_get_slot_state(slot_p);
	curr_state = slot_p->hs_info.cn_state;

	if (curr_state == target_state) {
		return (DDI_SUCCESS);
	}
	if (curr_state < target_state) {

		rv = pcishpc_upgrade_slot_state(slot_p, target_state);
	} else {
		rv = pcishpc_downgrade_slot_state(slot_p, target_state);
	}

	return (rv);
}

/*
 * pcishpc_issue_command()
 *
 * Sends a command to the SHPC controller.
 */
static int
pcishpc_issue_command(pcie_hp_ctrl_t *ctrl_p, uint32_t cmd_code)
{
	int	retCode;

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	PCIE_DBG("pcishpc_issue_command() cmd_code=%02x\n", cmd_code);

	ctrl_p->hc_cmd_pending = B_TRUE;

	/* Write the command to the SHPC controller. */
	pcishpc_write_reg(ctrl_p, PCI_HP_COMMAND_STATUS_REG, cmd_code);

	while (ctrl_p->hc_cmd_pending == B_TRUE)
		cv_wait(&ctrl_p->hc_cmd_comp_cv, &ctrl_p->hc_mutex);

	/* Wait until the SHPC controller processes the command. */
	retCode = pcishpc_wait_busy(ctrl_p);

	/* Make sure the command completed. */
	if (retCode == DDI_SUCCESS) {
		/* Did the command fail to generate the command complete IRQ? */
		if (ctrl_p->hc_cmd_pending != B_FALSE) {
			PCIE_DBG("pcishpc_issue_command() Failed on "
			    "generate cmd complete IRQ\n");
			retCode = DDI_FAILURE;
		}
	}

	if (retCode == DDI_FAILURE)
		PCIE_DBG("pcishpc_issue_command() Failed on cmd_code=%02x\n",
		    cmd_code);
	else
		PCIE_DBG("pcishpc_issue_command() Success on "
		    "cmd_code=%02x\n", cmd_code);

	return (retCode);
}

/*
 * pcishpc_wait_busy()
 *
 * Wait until the SHPC controller is not busy.
 */
static int
pcishpc_wait_busy(pcie_hp_ctrl_t *ctrl_p)
{
	uint32_t	status;

	/* Wait until SHPC controller is NOT busy */
	for (;;) {
		status = pcishpc_read_reg(ctrl_p, PCI_HP_COMMAND_STATUS_REG);

		/* Is there an MRL Sensor error? */
		if ((status & PCI_HP_COMM_STS_ERR_MASK) ==
		    PCI_HP_COMM_STS_ERR_MRL_OPEN) {
			PCIE_DBG("pcishpc_wait_busy() ERROR: "
			    "MRL Sensor error\n");
			break;
		}

		/* Is there an Invalid command error? */
		if ((status & PCI_HP_COMM_STS_ERR_MASK) ==
		    PCI_HP_COMM_STS_ERR_INVALID_COMMAND) {
			PCIE_DBG("pcishpc_wait_busy() ERROR: Invalid "
			    "command error\n");
			break;
		}

		/* Is there an Invalid Speed/Mode error? */
		if ((status & PCI_HP_COMM_STS_ERR_MASK) ==
		    PCI_HP_COMM_STS_ERR_INVALID_SPEED) {
			PCIE_DBG("pcishpc_wait_busy() ERROR: Invalid "
			    "Speed/Mode error\n");
			break;
		}

		/* Is the SHPC controller not BUSY? */
		if (!(status & PCI_HP_COMM_STS_CTRL_BUSY)) {
			/* Return Success. */
			return (DDI_SUCCESS);
		}

		PCIE_DBG("pcishpc_wait_busy() SHPC controller busy. Waiting\n");

		/* Wait before polling the status register again. */
		delay(drv_usectohz(PCIE_HP_CMD_WAIT_TIME));
	}

	return (DDI_FAILURE);
}

static void
pcishpc_attn_btn_handler(pcie_hp_slot_t *slot_p)
{
	pcie_hp_led_state_t hs_power_led_state;
	callb_cpr_t cprinfo;

	PCIE_DBG("pcishpc_attn_btn_handler: thread started\n");

	CALLB_CPR_INIT(&cprinfo, &slot_p->hs_ctrl->hc_mutex,
	    callb_generic_cpr, "pcishpc_attn_btn_handler");

	mutex_enter(&slot_p->hs_ctrl->hc_mutex);

	/* wait for ATTN button event */
	cv_wait(&slot_p->hs_attn_btn_cv, &slot_p->hs_ctrl->hc_mutex);

	while (slot_p->hs_attn_btn_thread_exit == B_FALSE) {
		if (slot_p->hs_attn_btn_pending == B_TRUE) {
			/* get the current state of power LED */
			hs_power_led_state = slot_p->hs_power_led_state;

			/* Blink the Power LED while we wait for 5 seconds */
			(void) pcishpc_setled(slot_p, PCIE_HP_POWER_LED,
			    PCIE_HP_LED_BLINK);

			/* wait for 5 seconds before taking any action */
			if (cv_reltimedwait(&slot_p->hs_attn_btn_cv,
			    &slot_p->hs_ctrl->hc_mutex,
			    SEC_TO_TICK(5), TR_CLOCK_TICK) == -1) {
				/*
				 * It is a time out;
				 * make sure the ATTN pending flag is
				 * still ON before sending the event
				 * to DDI HP framework.
				 */
				if (slot_p->hs_attn_btn_pending == B_TRUE) {
					int hint;

					/* restore the power LED state */
					(void) pcishpc_setled(slot_p,
					    PCIE_HP_POWER_LED,
					    hs_power_led_state);
					/*
					 * send the ATTN button event
					 * to DDI HP framework
					 */
					slot_p->hs_attn_btn_pending = B_FALSE;

					pcishpc_get_slot_state(slot_p);

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
					pcie_hp_gen_sysevent_req(
					    slot_p->hs_info.cn_name,
					    hint,
					    slot_p->hs_ctrl->hc_dip,
					    KM_SLEEP);

					continue;
				}
			}

			/* restore the power LED state */
			(void) pcishpc_setled(slot_p, PCIE_HP_POWER_LED,
			    hs_power_led_state);
			continue;
		}

		/* wait for another ATTN button event */
		cv_wait(&slot_p->hs_attn_btn_cv, &slot_p->hs_ctrl->hc_mutex);
	}

	PCIE_DBG("pcishpc_attn_btn_handler: thread exit\n");
	cv_signal(&slot_p->hs_attn_btn_cv);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

/*
 * pcishpc_get_slot_state()
 *
 * Get the state of the slot.
 * The slot state should have been initialized before this function gets called.
 */
static void
pcishpc_get_slot_state(pcie_hp_slot_t *slot_p)
{
	uint32_t reg;
	ddi_hp_cn_state_t curr_state = slot_p->hs_info.cn_state;

	/* Read the logical slot register for this Slot. */
	reg = pcishpc_read_reg(slot_p->hs_ctrl,
	    PCI_HP_LOGICAL_SLOT_REGS+slot_p->hs_num);

	/* Convert from the SHPC slot state to the HPC slot state. */
	slot_p->hs_info.cn_state = pcishpc_slot_shpc_to_hpc(reg);
	if (curr_state == DDI_HP_CN_STATE_POWERED &&
	    slot_p->hs_info.cn_state > DDI_HP_CN_STATE_POWERED) {
		/*
		 * Keep POWERED state if it is currently POWERED state because
		 * this driver does not really implement enable/disable
		 * slot operations. That is, when poweron, it actually enables
		 * the slot also.
		 * So, from hardware view, POWERED == ENABLED.
		 * But, when user explicitly change to POWERED state, it should
		 * be kept until user explicitly change to other states later.
		 */
		slot_p->hs_info.cn_state = DDI_HP_CN_STATE_POWERED;
	}

	/* Convert from the SHPC Power LED state to the HPC Power LED state. */
	slot_p->hs_power_led_state = pcishpc_led_shpc_to_hpc((reg>>2)&3);

	/* Convert from the SHPC Attn LED state to the HPC Attn LED state. */
	slot_p->hs_attn_led_state = pcishpc_led_shpc_to_hpc((reg>>4)&3);

	/* We don't have a fault LED so just default it to OFF. */
	slot_p->hs_fault_led_state = PCIE_HP_LED_OFF;

	/* We don't have an active LED so just default it to OFF. */
	slot_p->hs_active_led_state = PCIE_HP_LED_OFF;
}

/*
 * pcishpc_set_slot_state()
 *
 * Updates the slot's state and leds.
 */
static int
pcishpc_set_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t new_slot_state)
{
	uint32_t		reg, cmd_code;
	ddi_hp_cn_state_t	curr_state;

	ASSERT(MUTEX_HELD(&slot_p->hs_ctrl->hc_mutex));

	reg = pcishpc_read_reg(slot_p->hs_ctrl,
	    PCI_HP_LOGICAL_SLOT_REGS+slot_p->hs_num);

	/* Default all states to unchanged. */
	cmd_code = ((1 + slot_p->hs_num) << 8);

	/* Has the slot state changed? */
	curr_state = pcishpc_slot_shpc_to_hpc(reg);
	if (curr_state != new_slot_state) {
		PCIE_DBG("pcishpc_set_slot_state() Slot State changed");

		/* Set the new slot state in the Slot operation command. */
		cmd_code |= pcishpc_slot_hpc_to_shpc(new_slot_state);
	}

	/* Has the Power LED state changed? */
	if (slot_p->hs_power_led_state != pcishpc_led_shpc_to_hpc((reg>>2)&3)) {
		PCIE_DBG("pcishpc_set_slot_state() Power LED State changed\n");

		/* Set the new power led state in the Slot operation command. */
		cmd_code |=
		    (pcishpc_led_hpc_to_shpc(slot_p->hs_power_led_state) << 2);
	}

	/* Has the Attn LED state changed? */
	if (slot_p->hs_attn_led_state != pcishpc_led_shpc_to_hpc((reg>>4)&3)) {
		PCIE_DBG("pcishpc_set_slot_state() Attn LED State changed\n");

		/* Set the new attn led state in the Slot operation command. */
		cmd_code |=
		    (pcishpc_led_hpc_to_shpc(slot_p->hs_attn_led_state) << 4);
	}

	return (pcishpc_issue_command(slot_p->hs_ctrl, cmd_code));
}

/*
 * setup slot name/slot-number info.
 */
static void
pcishpc_set_slot_name(pcie_hp_ctrl_t *ctrl_p, int slot)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[slot];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uchar_t *slotname_data;
	int *slotnum;
	uint_t count;
	int len;
	uchar_t *s;
	uint32_t bit_mask;
	int pci_id_cnt, pci_id_bit;
	int slots_before, found;
	int invalid_slotnum = 0;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, ctrl_p->hc_dip,
	    DDI_PROP_DONTPASS, "physical-slot#", &slotnum, &count) ==
	    DDI_PROP_SUCCESS) {
		slot_p->hs_phy_slot_num = slotnum[0];
		ddi_prop_free(slotnum);
	} else {
		if (ctrl_p->hc_device_increases)
			slot_p->hs_phy_slot_num = ctrl_p->hc_phys_start + slot;
		else
			slot_p->hs_phy_slot_num = ctrl_p->hc_phys_start - slot;

		if ((ndi_prop_update_int(DDI_DEV_T_NONE, ctrl_p->hc_dip,
		    "physical-slot#", slot_p->hs_phy_slot_num)) != DDI_SUCCESS)
			PCIE_DBG("pcishpc_set_slot_name(): failed to "
			    "create phyical-slot#%d\n",
			    slot_p->hs_phy_slot_num);
	}

	/* Platform may not have initialized it */
	if (!slot_p->hs_phy_slot_num) {
		slot_p->hs_phy_slot_num = pci_config_get8(bus_p->bus_cfg_hdl,
		    PCI_BCNF_SECBUS);
		invalid_slotnum = 1;
	}
	slot_p->hs_info.cn_num = slot_p->hs_phy_slot_num;
	slot_p->hs_info.cn_num_dpd_on = DDI_HP_CN_NUM_NONE;

	/*
	 * construct the slot_name:
	 *	if "slot-names" property exists then use that name
	 *	else if valid slot number exists then it is "pci<slot-num>".
	 *	else it will be "pci<sec-bus-number>dev<dev-number>"
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, ctrl_p->hc_dip, DDI_PROP_DONTPASS,
	    "slot-names", (caddr_t)&slotname_data, &len) == DDI_PROP_SUCCESS) {
		bit_mask = slotname_data[3] | (slotname_data[2] << 8) |
		    (slotname_data[1] << 16) | (slotname_data[0] << 24);

		pci_id_bit = 1;
		pci_id_cnt = slots_before = found = 0;

		/*
		 * Walk the bit mask until we find the bit that corresponds
		 * to our slots device number.  We count how many bits
		 * we find before we find our slot's bit.
		 */
		while (!found && (pci_id_cnt < 32)) {
			while (slot_p->hs_device_num != pci_id_cnt) {

				/*
				 * Find the next bit set.
				 */
				while (!(bit_mask & pci_id_bit) &&
				    (pci_id_cnt < 32)) {
					pci_id_bit = pci_id_bit << 1;
					pci_id_cnt++;
				}

				if (slot_p->hs_device_num != pci_id_cnt)
					slots_before++;
				else
					found = 1;
			}
		}

		if (pci_id_cnt < 32) {

			/*
			 * Set ptr to first string.
			 */
			s = slotname_data + 4;

			/*
			 * Increment past all the strings for the slots
			 * before ours.
			 */
			while (slots_before) {
				while (*s != '\0')
					s++;
				s++;
				slots_before--;
			}

			slot_p->hs_info.cn_name = i_ddi_strdup((char *)s,
			    KM_SLEEP);
			kmem_free(slotname_data, len);
			return;
		}

		/* slot-names entry not found */
		PCIE_DBG("pcishpc_set_slot_name(): "
		    "No slot-names entry found for slot #%d\n",
		    slot_p->hs_phy_slot_num);
		kmem_free(slotname_data, len);
	}

	if (invalid_slotnum) {
		char tmp_name[256];

		(void) snprintf(tmp_name, sizeof (tmp_name), "pci%d",
		    slot_p->hs_device_num);
		slot_p->hs_info.cn_name = i_ddi_strdup(tmp_name, KM_SLEEP);
	} else {
		char tmp_name[256];

		(void) snprintf(tmp_name, sizeof (tmp_name), "pci%d",
		    slot_p->hs_phy_slot_num);
		slot_p->hs_info.cn_name = i_ddi_strdup(tmp_name, KM_SLEEP);
	}
}

/*
 * pcishpc_set_bus_speed()
 *
 * Set the bus speed and mode.
 */
static int
pcishpc_set_bus_speed(pcie_hp_slot_t *slot_p)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	int		curr_speed = ctrl_p->hc_curr_bus_speed;
	int		speed = -1;
	int		avail_slots;
	uint32_t	status, slots_avail1_reg, slots_avail2_reg;

	ASSERT(MUTEX_HELD(&slot_p->hs_ctrl->hc_mutex));

	/* Make sure that the slot is in a correct state */
	status = pcishpc_read_reg(ctrl_p,
	    PCI_HP_LOGICAL_SLOT_REGS+slot_p->hs_num);

	/* Return failure if the slot is empty */
	if ((status & PCI_HP_SLOT_CARD_EMPTY_MASK) ==
	    PCI_HP_SLOT_CARD_EMPTY_MASK) {
		PCIE_DBG("pcishpc_set_bus_speed() failed: "
		    "the slot is empty\n");
		return (DDI_FAILURE);
	}

	/* Return failure if the slot is not in disabled state */
	if ((status & PCI_HP_SLOT_STATE_MASK) != PCI_HP_SLOT_DISABLED) {
		PCIE_DBG("pcishpc_set_bus_speed() failed: "
		    "incorrect slot state\n");
		return (DDI_FAILURE);
	}

	/* Set the "power-only" mode for the slot */
	if (pcishpc_issue_command(ctrl_p, ((1+slot_p->hs_num)<<8) |
	    PCI_HP_SLOT_POWER_ONLY) != DDI_SUCCESS) {
		PCIE_DBG("pcishpc_set_bus_speed() failed to set "
		    "the slot %d in the power-only mode\n", slot_p->hs_num);
		return (DDI_FAILURE);
	}

	/* Wait for power good */
	delay(drv_usectohz(PCIE_HP_POWER_GOOD_WAIT_TIME));

	/* Make sure that the slot is in "power-only" state */
	status = pcishpc_read_reg(ctrl_p,
	    PCI_HP_LOGICAL_SLOT_REGS+slot_p->hs_num);

	if ((status & PCI_HP_SLOT_STATE_MASK) != PCI_HP_SLOT_POWER_ONLY) {
		PCIE_DBG("pcishpc_set_bus_speed() "
		    "power-only failed: incorrect slot state\n");
		return (DDI_FAILURE);
	}

	slots_avail1_reg = pcishpc_read_reg(ctrl_p,
	    PCI_HP_SLOTS_AVAIL_I_REG);
	slots_avail2_reg = pcishpc_read_reg(ctrl_p,
	    PCI_HP_SLOTS_AVAIL_II_REG);

	/*
	 * Check if SHPC has available slots and select the highest
	 * available bus speed for the slot.
	 *
	 * The bus speed codes are:
	 * 100 - 133Mhz; <--+
	 * 011 - 100Mhz; <--+   PCI-X
	 * 010 - 66Mhz;  <--+
	 *
	 * 001 - 66Mhz;  <--+
	 * 000 - 33Mhz   <--+   Conv PCI
	 */
	switch (status & PCI_HP_SLOT_PCIX_CAPABLE_MASK) {
	case PCI_HP_SLOT_133MHZ_PCIX_CAPABLE:
		avail_slots = (slots_avail1_reg >>
		    PCI_HP_AVAIL_133MHZ_PCIX_SPEED_SHIFT) &
		    PCI_HP_AVAIL_SPEED_MASK;

		if (((curr_speed == -1) && avail_slots) ||
		    (curr_speed == PCI_HP_SBCR_133MHZ_PCIX_SPEED)) {
			speed = PCI_HP_SBCR_133MHZ_PCIX_SPEED;
			break;
		}
		/* FALLTHROUGH */
	case PCI_HP_SLOT_100MHZ_PCIX_CAPABLE:
		avail_slots = (slots_avail1_reg >>
		    PCI_HP_AVAIL_100MHZ_PCIX_SPEED_SHIFT) &
		    PCI_HP_AVAIL_SPEED_MASK;

		if (((curr_speed == -1) && avail_slots) ||
		    (curr_speed == PCI_HP_SBCR_100MHZ_PCIX_SPEED)) {
			speed = PCI_HP_SBCR_100MHZ_PCIX_SPEED;
			break;
		}
		/* FALLTHROUGH */
	case PCI_HP_SLOT_66MHZ_PCIX_CAPABLE:
		avail_slots = (slots_avail1_reg >>
		    PCI_HP_AVAIL_66MHZ_PCIX_SPEED_SHIFT) &
		    PCI_HP_AVAIL_SPEED_MASK;

		if (((curr_speed == -1) && avail_slots) ||
		    (curr_speed == PCI_HP_SBCR_66MHZ_PCIX_SPEED)) {
			speed = PCI_HP_SBCR_66MHZ_PCIX_SPEED;
			break;
		}
		/* FALLTHROUGH */
	default:
		avail_slots = (slots_avail2_reg >>
		    PCI_HP_AVAIL_66MHZ_CONV_SPEED_SHIFT) &
		    PCI_HP_AVAIL_SPEED_MASK;

		if ((status & PCI_HP_SLOT_66MHZ_CONV_CAPABLE) &&
		    (((curr_speed == -1) && avail_slots) ||
		    (curr_speed == PCI_HP_SBCR_66MHZ_CONV_SPEED))) {
			speed = PCI_HP_SBCR_66MHZ_CONV_SPEED;
		} else {
			avail_slots = (slots_avail1_reg >>
			    PCI_HP_AVAIL_33MHZ_CONV_SPEED_SHIFT) &
			    PCI_HP_AVAIL_SPEED_MASK;

			if (((curr_speed == -1) && (avail_slots)) ||
			    (curr_speed == PCI_HP_SBCR_33MHZ_CONV_SPEED)) {
				speed = PCI_HP_SBCR_33MHZ_CONV_SPEED;
			} else {
				PCIE_DBG("pcishpc_set_bus_speed() "
				    " failed to set the bus speed, slot# %d\n",
				    slot_p->hs_num);
				return (DDI_FAILURE);
			}
		}
		break;
	}

	/*
	 * If the bus segment is already running, check to see the card
	 * in the slot can support the current bus speed.
	 */
	if (curr_speed == speed) {
		/*
		 * Check to see there is any slot available for the current
		 * bus speed. Otherwise, we need fail the current slot connect
		 * request.
		 */
		return ((avail_slots <= ctrl_p->hc_num_slots_connected) ?
		    DDI_FAILURE : DDI_SUCCESS);
	}

	/* Set the bus speed */
	if (pcishpc_issue_command(ctrl_p, PCI_HP_COMM_STS_SET_SPEED |
	    speed) == DDI_FAILURE) {
		PCIE_DBG("pcishpc_set_bus_speed() failed "
		    "to set bus %d speed\n", slot_p->hs_num);
		return (DDI_FAILURE);
	}

	/* Check the current bus speed */
	status = pcishpc_read_reg(ctrl_p, PCI_HP_PROF_IF_SBCR_REG) &
	    PCI_HP_SBCR_SPEED_MASK;
	if ((status & PCI_HP_SBCR_SPEED_MASK) != speed) {
		PCIE_DBG("pcishpc_set_bus_speed() an incorrect "
		    "bus speed, slot = 0x%x, speed = 0x%x\n",
		    slot_p->hs_num, status & PCI_HP_SBCR_SPEED_MASK);
		return (DDI_FAILURE);
	}


	/* Save the current bus speed */
	ctrl_p->hc_curr_bus_speed = speed;

	return (DDI_SUCCESS);
}

/*
 * pcishpc_setled()
 *
 * Change the state of a slot's LED.
 */
static int
pcishpc_setled(pcie_hp_slot_t *slot_p, pcie_hp_led_t led,
    pcie_hp_led_state_t state)
{
	ASSERT(MUTEX_HELD(&slot_p->hs_ctrl->hc_mutex));

	switch (led) {
		case PCIE_HP_FAULT_LED:
			PCIE_DBG("pcishpc_setled() - PCIE_HP_FAULT_LED "
			    "(set %s)\n", pcishpc_slot_textledstate(state));
			slot_p->hs_fault_led_state = state;
			break;

		case PCIE_HP_POWER_LED:
			PCIE_DBG("pcishpc_setled() - PCIE_HP_POWER_LED "
			    "(set %s)\n", pcishpc_slot_textledstate(state));
			slot_p->hs_power_led_state = state;
			break;

		case PCIE_HP_ATTN_LED:
			PCIE_DBG("pcishpc_setled() - PCIE_HP_ATTN_LED "
			    "(set %s)\n", pcishpc_slot_textledstate(state));
			slot_p->hs_attn_led_state = state;
			break;

		case PCIE_HP_ACTIVE_LED:
			PCIE_DBG("pcishpc_setled() - PCIE_HP_ACTIVE_LED "
			    "(set %s)\n", pcishpc_slot_textledstate(state));
			slot_p->hs_active_led_state = state;
			break;
	}

	return (pcishpc_set_slot_state(slot_p, slot_p->hs_info.cn_state));
}

/*
 * pcishpc_led_shpc_to_hpc()
 *
 * Convert from SHPC indicator status to HPC indicator status.
 */
static int
pcishpc_led_shpc_to_hpc(int state)
{
	switch (state) {
		case 1:	/* SHPC On bits b01 */
			return (PCIE_HP_LED_ON);
		case 2:	/* SHPC Blink bits b10 */
			return (PCIE_HP_LED_BLINK);
		case 3:	/* SHPC Off bits b11 */
			return (PCIE_HP_LED_OFF);
	}

	return (PCIE_HP_LED_OFF);
}


/*
 * pcishpc_led_hpc_to_shpc()
 *
 * Convert from HPC indicator status to SHPC indicator status.
 */
static int
pcishpc_led_hpc_to_shpc(int state)
{
	switch (state) {
		case PCIE_HP_LED_ON:
			return (1); /* SHPC On bits b01 */
		case PCIE_HP_LED_BLINK:
			return (2); /* SHPC Blink bits b10 */
		case PCIE_HP_LED_OFF:
			return (3); /* SHPC Off bits b11 */
	}

	return (3); /* SHPC Off bits b11 */
}

/*
 * pcishpc_slot_shpc_to_hpc()
 *
 * Convert from SHPC slot state to HPC slot state.
 * The argument shpc_state is expected to be read from the slot register.
 */
static int
pcishpc_slot_shpc_to_hpc(int shpc_state)
{
	if ((shpc_state & PCI_HP_SLOT_CARD_EMPTY_MASK) ==
	    PCI_HP_SLOT_CARD_EMPTY_MASK)
		return (DDI_HP_CN_STATE_EMPTY);

	switch (shpc_state & PCI_HP_SLOT_STATE_MASK) {
		case PCI_HP_SLOT_POWER_ONLY: /* SHPC Powered Only */
			return (DDI_HP_CN_STATE_POWERED);

		case PCI_HP_SLOT_ENABLED: /* SHPC Enabled */
			return (DDI_HP_CN_STATE_ENABLED);

		case PCI_HP_SLOT_DISABLED:	/* SHPC Disabled */
		default :			/* SHPC Reserved */
			return (DDI_HP_CN_STATE_PRESENT);
	}
}

/*
 * pcishpc_slot_hpc_to_shpc()
 *
 * Convert from HPC slot state to SHPC slot state.
 */
static int
pcishpc_slot_hpc_to_shpc(int state)
{
	switch (state) {
		case DDI_HP_CN_STATE_EMPTY:
			return (0);

		case DDI_HP_CN_STATE_POWERED:
			return (PCI_HP_SLOT_POWER_ONLY);

		case DDI_HP_CN_STATE_ENABLED:
			return (PCI_HP_SLOT_ENABLED);

		default:
			return (PCI_HP_SLOT_DISABLED);
	}
}

/*
 * pcishpc_slot_textslotstate()
 *
 * Convert the request into a text message.
 */
static char *
pcishpc_slot_textslotstate(ddi_hp_cn_state_t state)
{
	/* Convert an HPC slot state into a textual string. */
	if (state == DDI_HP_CN_STATE_EMPTY)
		return ("HPC_SLOT_EMPTY");
	else if (state == DDI_HP_CN_STATE_ENABLED)
		return ("HPC_SLOT_ENABLED");
	else if (state == DDI_HP_CN_STATE_POWERED)
		return ("HPC_SLOT_POWERED_ONLY");
	else
		return ("HPC_SLOT_DISABLED");
}


/*
 * pcishpc_slot_textledstate()
 *
 * Convert the led state into a text message.
 */
static char *
pcishpc_slot_textledstate(pcie_hp_led_state_t state)
{
	/* Convert an HPC led state into a textual string. */
	switch (state) {
		case PCIE_HP_LED_OFF:
			return ("off");

		case PCIE_HP_LED_ON:
			return ("on");

		case PCIE_HP_LED_BLINK:
			return ("blink");
	}
	return ("unknown");
}


/*
 * pcishpc_read_reg()
 *
 * Read from a SHPC controller register.
 */
static uint32_t
pcishpc_read_reg(pcie_hp_ctrl_t *ctrl_p, int reg)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

	/* Setup the SHPC dword select register. */
	pci_config_put8(bus_p->bus_cfg_hdl,
	    bus_p->bus_pci_hp_off + PCI_HP_DWORD_SELECT_OFF, (uint8_t)reg);

	/* Read back the SHPC dword select register and verify. */
	if (pci_config_get8(bus_p->bus_cfg_hdl, bus_p->bus_pci_hp_off +
	    PCI_HP_DWORD_SELECT_OFF) != (uint8_t)reg) {
		PCIE_DBG("pcishpc_read_reg() - Failed writing DWORD "
		    "select reg\n");
		return (0xFFFFFFFF);
	}

	/* Read from the SHPC dword data register. */
	return (pci_config_get32(bus_p->bus_cfg_hdl,
	    bus_p->bus_pci_hp_off + PCI_HP_DWORD_DATA_OFF));
}


/*
 * pcishpc_write_reg()
 *
 * Write to a SHPC controller register.
 */
static void
pcishpc_write_reg(pcie_hp_ctrl_t *ctrl_p, int reg, uint32_t data)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

	/* Setup the SHPC dword select register. */
	pci_config_put8(bus_p->bus_cfg_hdl,
	    bus_p->bus_pci_hp_off + PCI_HP_DWORD_SELECT_OFF, (uint8_t)reg);

	/* Read back the SHPC dword select register and verify. */
	if (pci_config_get8(bus_p->bus_cfg_hdl, bus_p->bus_pci_hp_off +
	    PCI_HP_DWORD_SELECT_OFF) != (uint8_t)reg) {
		PCIE_DBG("pcishpc_write_reg() - Failed writing "
		    "DWORD select reg\n");
		return;
	}

	/* Write to the SHPC dword data register. */
	pci_config_put32(bus_p->bus_cfg_hdl,
	    bus_p->bus_pci_hp_off + PCI_HP_DWORD_DATA_OFF, data);

	/*
	 * Issue a read of the VendorID/DeviceID just to force the previous
	 * write to complete. This is probably not necessary, but it does
	 * help enforce ordering if there is an issue.
	 */
	(void) pci_config_get16(bus_p->bus_cfg_hdl, PCI_CONF_VENID);
}


#ifdef	DEBUG
/*
 * pcishpc_dump_regs()
 *
 * Dumps all of the SHPC controller registers.
 */
static void
pcishpc_dump_regs(pcie_hp_ctrl_t *ctrl_p)
{
	int slot, numSlots;
	uint32_t reg;
	char *state;

	if (!pcie_debug_flags)
		return;

	PCIE_DBG("pcishpc_dump_regs() called:\n");
	PCIE_DBG("==========================================================");

	PCIE_DBG("SHPC Base Offset				"
	    ": 0x%08x\n", pcishpc_read_reg(ctrl_p, PCI_HP_BASE_OFFSET_REG));

	reg = pcishpc_read_reg(ctrl_p, PCI_HP_SLOTS_AVAIL_I_REG);

	PCIE_DBG("Number of PCIX slots avail (33 Mhz)		 : %d\n",
	    (reg & 31));

	PCIE_DBG("Number of PCIX slots avail (66 Mhz)		 : %d\n",
	    ((reg>>8) & 31));

	PCIE_DBG("Number of PCIX slots avail (100 Mhz)		: %d\n",
	    ((reg>>16) & 31));

	PCIE_DBG("Number of PCIX slots avail (133 Mhz)		: %d\n",
	    ((reg>>24) & 31));

	reg = pcishpc_read_reg(ctrl_p, PCI_HP_SLOTS_AVAIL_II_REG);

	PCIE_DBG("Number of conventional PCI slots (66 Mhz) : %d\n",
	    (reg & 31));

	reg = pcishpc_read_reg(ctrl_p, PCI_HP_SLOT_CONFIGURATION_REG);

	numSlots = (reg & 31);

	PCIE_DBG("Number of Slots connected to this port	 : %d\n",
	    numSlots);

	PCIE_DBG("PCI Device # for First HotPlug Slot		 : %d\n",
	    ((reg>>8) & 31));

	PCIE_DBG("Physical Slot # for First PCI Device #	 : %d\n",
	    ((reg>>16) & 0x7ff));

	PCIE_DBG("Physical Slot Number Up/Down			 : %d\n",
	    ((reg>>29) & 0x1));

	PCIE_DBG("MRL Sensor Implemented			 : %s\n",
	    (reg & PCI_HP_SLOT_CONFIG_MRL_SENSOR) ? "Yes" : "No");

	PCIE_DBG("Attention Button Implemented			 : %s\n",
	    (reg & PCI_HP_SLOT_CONFIG_ATTN_BUTTON) ? "Yes" : "No");

	reg = pcishpc_read_reg(ctrl_p, PCI_HP_PROF_IF_SBCR_REG);

	switch (reg & 7) {
		case 0:
			state = "33Mhz Conventional PCI";
			break;
		case 1:
			state = "66Mhz Conventional PCI";
			break;
		case 2:
			state = "66Mhz PCI-X";
			break;
		case 3:
			state = "100Mhz PCI-X";
			break;
		case 4:
			state = "133Mhz PCI-X";
			break;
		default:
			state = "Reserved (Error)";
			break;
	}

	PCIE_DBG("Current Port Operation Mode		: %s\n", state);

	PCIE_DBG("SHPC Interrupt Message Number		: %d\n",
	    ((reg>>16) &31));

	PCIE_DBG("SHPC Programming Interface		: %d\n",
	    ((reg>>24) & 0xff));

	reg = pcishpc_read_reg(ctrl_p, PCI_HP_COMMAND_STATUS_REG);

	PCIE_DBG("SHPC Command Code			: %d\n",
	    (reg & 0xff));

	PCIE_DBG("SHPC Target Slot			: %d\n",
	    ((reg>>8) & 31));

	PCIE_DBG("SHPC Controller Busy			: %s\n",
	    ((reg>>16) & 1) ? "Yes" : "No");

	PCIE_DBG("SHPC Controller Err: MRL Sensor	: %s\n",
	    ((reg>>17) & 1) ? "Yes" : "No");

	PCIE_DBG("SHPC Controller Err: Invalid Command	: %s\n",
	    ((reg>>18) & 1) ? "Yes" : "No");

	PCIE_DBG("SHPC Controller Err: Invalid Speed/Mode : %s\n",
	    ((reg>>19) & 1) ? "Yes" : "No");

	reg = pcishpc_read_reg(ctrl_p, PCI_HP_IRQ_LOCATOR_REG);

	PCIE_DBG("Command Completion Interrupt Pending	: %s\n",
	    (reg & PCI_HP_IRQ_CMD_COMPLETE) ? "Yes" : "No");

	for (slot = 0; slot < numSlots; slot++) {
		PCIE_DBG("Slot %d Interrupt Pending	: %s\n", slot+1,
		    (reg & (PCI_HP_IRQ_SLOT_N_PENDING<<slot)) ? "Yes" : "No");
	}

	reg = pcishpc_read_reg(ctrl_p, PCI_HP_SERR_LOCATOR_REG);

	PCIE_DBG("Arbiter SERR Pending			: %s\n",
	    (reg & PCI_HP_IRQ_SERR_ARBITER_PENDING) ? "Yes" : "No");

	for (slot = 0; slot < numSlots; slot++) {
		PCIE_DBG("Slot %d SERR Pending		: %s\n",
		    slot+1, (reg &
		    (PCI_HP_IRQ_SERR_SLOT_N_PENDING<<slot)) ? "Yes" : "No");
	}

	reg = pcishpc_read_reg(ctrl_p, PCI_HP_CTRL_SERR_INT_REG);

	PCIE_DBG("Global Interrupt Mask			: %s\n",
	    (reg & PCI_HP_SERR_INT_GLOBAL_IRQ_MASK) ? "Yes" : "No");

	PCIE_DBG("Global SERR Mask			: %s\n",
	    (reg & PCI_HP_SERR_INT_GLOBAL_SERR_MASK) ? "Yes" : "No");

	PCIE_DBG("Command Completion Interrupt Mask	: %s\n",
	    (reg & PCI_HP_SERR_INT_CMD_COMPLETE_MASK) ? "Yes" : "No");

	PCIE_DBG("Arbiter SERR Mask			: %s\n",
	    (reg & PCI_HP_SERR_INT_ARBITER_SERR_MASK) ? "Yes" : "No");

	PCIE_DBG("Command Completion Detected		: %s\n",
	    (reg & PCI_HP_SERR_INT_CMD_COMPLETE_IRQ) ? "Yes" : "No");

	PCIE_DBG("Arbiter Timeout Detected		: %s\n",
	    (reg & PCI_HP_SERR_INT_ARBITER_IRQ) ? "Yes" : "No");

	for (slot = 0; slot < numSlots; slot++) {
		PCIE_DBG("Logical Slot %d Registers:\n", slot+1);
		PCIE_DBG("------------------------------------\n");

		reg = pcishpc_read_reg(ctrl_p, PCI_HP_LOGICAL_SLOT_REGS+slot);

		PCIE_DBG("Slot %d state			: %s\n", slot+1,
		    pcishpc_slot_textslotstate(pcishpc_slot_shpc_to_hpc(reg)));

		PCIE_DBG("Slot %d Power Indicator State	: %s\n", slot+1,
		    pcishpc_slot_textledstate(pcishpc_led_shpc_to_hpc(
		    (reg>>2) &3)));

		PCIE_DBG("Slot %d Attention Indicator State : %s\n", slot+1,
		    pcishpc_slot_textledstate(pcishpc_led_shpc_to_hpc(
		    (reg>>4)&3)));

		PCIE_DBG("Slot %d Power Fault		: %s\n", slot+1,
		    ((reg>>6)&1) ? "Fault Detected" : "No Fault");
		PCIE_DBG("Slot %d Attention Button	: %s\n", slot+1,
		    ((reg>>7)&1) ? "Depressed" : "Not Depressed");
		PCIE_DBG("Slot %d MRL Sensor		: %s\n", slot+1,
		    ((reg>>8)&1) ? "Not Closed" : "Closed");
		PCIE_DBG("Slot %d 66mhz Capable		: %s\n", slot+1,
		    ((reg>>9)&1) ? "66mhz" : "33mgz");

		switch ((reg>>10)&3) {
			case 0:
				state = "Card Present 7.5W";
				break;
			case 1:
				state = "Card Present 15W";
				break;
			case 2:
				state = "Card Present 25W";
				break;
			case 3:
				state = "Slot Empty";
				break;
		}

		PCIE_DBG("Slot %d PRSNT1#/PRSNT2#	: %s\n", slot+1,
		    state);

		switch ((reg>>12)&3) {
			case 0:
				state = "Non PCI-X";
				break;
			case 1:
				state = "66mhz PCI-X";
				break;
			case 2:
				state = "Reserved";
				break;
			case 3:
				state = "133mhz PCI-X";
				break;
		}

		PCIE_DBG("Slot %d Card Presence Change Detected	  : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_PRESENCE_DETECTED) ? "Yes" :
		    "No");
		PCIE_DBG("Slot %d Isolated Power Fault Detected	  : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_ISO_PWR_DETECTED) ? "Yes" :
		    "No");
		PCIE_DBG("Slot %d Attention Button Press Detected : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_ATTN_DETECTED) ? "Yes" : "No");
		PCIE_DBG("Slot %d MRL Sensor Change Detected	  : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_MRL_DETECTED) ? "Yes" : "No");
		PCIE_DBG("Slot %d Connected Power Fault Detected  : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_POWER_DETECTED) ? "Yes" : "No");

		PCIE_DBG("Slot %d Card Presence IRQ Masked	  : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_PRESENCE_MASK) ? "Yes" : "No");
		PCIE_DBG("Slot %d Isolated Power Fault IRQ Masked : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_ISO_PWR_MASK) ? "Yes" : "No");
		PCIE_DBG("Slot %d Attention Button IRQ Masked	  : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_ATTN_MASK) ? "Yes" : "No");
		PCIE_DBG("Slot %d MRL Sensor IRQ Masked		  : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_MRL_MASK) ? "Yes" : "No");
		PCIE_DBG("Slot %d Connected Power Fault IRQ Masked : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_POWER_MASK) ? "Yes" : "No");
		PCIE_DBG("Slot %d MRL Sensor SERR Masked          : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_MRL_SERR_MASK) ? "Yes" : "No");
		PCIE_DBG("Slot %d Connected Power Fault SERR Masked : %s\n",
		    slot+1, (reg & PCI_HP_SLOT_POWER_SERR_MASK) ? "Yes" : "No");
	}
}
#endif	/* DEBUG */
