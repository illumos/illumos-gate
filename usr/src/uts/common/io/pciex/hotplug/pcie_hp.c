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
 *  Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 *  Use is subject to license terms.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This file contains the common hotplug code that is used by Standard
 * PCIe and PCI HotPlug Controller code.
 *
 * NOTE: This file is compiled and delivered through misc/pcie module.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/autoconf.h>
#include <sys/varargs.h>
#include <sys/ddi_impldefs.h>
#include <sys/time.h>
#include <sys/note.h>
#include <sys/callb.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dr.h>
#include <sys/pci_impl.h>
#include <sys/pci_cap.h>
#include <sys/hotplug/pci/pcicfg.h>
#include <sys/hotplug/pci/pcie_hp.h>
#include <sys/hotplug/pci/pciehpc.h>
#include <sys/hotplug/pci/pcishpc.h>
#include <io/pciex/pcieb.h>

/* Local functions prototype */
static int pcie_hp_list_occupants(dev_info_t *dip, void *arg);
static int pcie_hp_register_port(dev_info_t *dip, dev_info_t *pdip,
    char *cn_name);
static int pcie_hp_register_ports_for_dev(dev_info_t *dip, int device_num);
static int pcie_hp_unregister_ports_cb(ddi_hp_cn_info_t *info, void *arg);
static int pcie_hp_get_port_state(ddi_hp_cn_info_t *info, void *arg);
static int pcie_hp_match_dev_func(dev_info_t *dip, void *hdl);
static boolean_t pcie_hp_match_dev(dev_info_t *dip, int dev_num);
static int pcie_hp_get_df_from_port_name(char *cn_name, int *dev_num,
    int *func_num);
static int pcie_hp_create_port_name_num(dev_info_t *dip,
    ddi_hp_cn_info_t *cn_info);
static int pcie_hp_check_hardware_existence(dev_info_t *dip, int dev_num,
    int func_num);

/*
 * Global functions (called by other drivers/modules)
 */

/*
 * return description text for led state
 */
char *
pcie_led_state_text(pcie_hp_led_state_t state)
{
	switch (state) {
	case PCIE_HP_LED_ON:
		return (PCIEHPC_PROP_VALUE_ON);
	case PCIE_HP_LED_OFF:
		return (PCIEHPC_PROP_VALUE_OFF);
	case PCIE_HP_LED_BLINK:
	default:
		return (PCIEHPC_PROP_VALUE_BLINK);
	}
}

/*
 * return description text for slot condition
 */
char *
pcie_slot_condition_text(ap_condition_t condition)
{
	switch (condition) {
	case AP_COND_UNKNOWN:
		return (PCIEHPC_PROP_VALUE_UNKNOWN);
	case AP_COND_OK:
		return (PCIEHPC_PROP_VALUE_OK);
	case AP_COND_FAILING:
		return (PCIEHPC_PROP_VALUE_FAILING);
	case AP_COND_FAILED:
		return (PCIEHPC_PROP_VALUE_FAILED);
	case AP_COND_UNUSABLE:
		return (PCIEHPC_PROP_VALUE_UNUSABLE);
	default:
		return (PCIEHPC_PROP_VALUE_UNKNOWN);
	}
}

/*
 * routine to copy in a nvlist from userland
 */
int
pcie_copyin_nvlist(char *packed_buf, size_t packed_sz, nvlist_t **nvlp)
{
	int		ret = DDI_SUCCESS;
	char		*packed;
	nvlist_t	*dest = NULL;

	if (packed_buf == NULL || packed_sz == 0)
		return (DDI_EINVAL);

	/* copyin packed nvlist */
	if ((packed = kmem_alloc(packed_sz, KM_SLEEP)) == NULL)
		return (DDI_ENOMEM);

	if (copyin(packed_buf, packed, packed_sz) != 0) {
		cmn_err(CE_WARN, "pcie_copyin_nvlist: copyin failed.\n");
		ret = DDI_FAILURE;
		goto copyin_cleanup;
	}

	/* unpack packed nvlist */
	if ((ret = nvlist_unpack(packed, packed_sz, &dest, KM_SLEEP)) != 0) {
		cmn_err(CE_WARN, "pcie_copyin_nvlist: nvlist_unpack "
		    "failed with err %d\n", ret);
		switch (ret) {
		case EINVAL:
		case ENOTSUP:
			ret = DDI_EINVAL;
			goto copyin_cleanup;
		case ENOMEM:
			ret = DDI_ENOMEM;
			goto copyin_cleanup;
		default:
			ret = DDI_FAILURE;
			goto copyin_cleanup;
		}
	}
	*nvlp = dest;
copyin_cleanup:
	kmem_free(packed, packed_sz);
	return (ret);
}

/*
 * routine to copy out a nvlist to userland
 */
int
pcie_copyout_nvlist(nvlist_t *nvl, char *packed_buf, size_t *buf_sz)
{
	int	err = 0;
	char	*buf = NULL;
	size_t	packed_sz;

	if (nvl == NULL || packed_buf == NULL || buf_sz == NULL)
		return (DDI_EINVAL);

	/* pack nvlist, the library will allocate memory */
	if ((err = nvlist_pack(nvl, &buf, &packed_sz, NV_ENCODE_NATIVE, 0))
	    != 0) {
		cmn_err(CE_WARN, "pcie_copyout_nvlist: nvlist_pack "
		    "failed with err %d\n", err);
		switch (err) {
		case EINVAL:
		case ENOTSUP:
			return (DDI_EINVAL);
		case ENOMEM:
			return (DDI_ENOMEM);
		default:
			return (DDI_FAILURE);
		}
	}
	if (packed_sz > *buf_sz) {
		return (DDI_EINVAL);
	}

	/* copyout packed nvlist */
	if (copyout(buf, packed_buf, packed_sz) != 0) {
		cmn_err(CE_WARN, "pcie_copyout_nvlist: copyout " "failed.\n");
		kmem_free(buf, packed_sz);
		return (DDI_FAILURE);
	}

	*buf_sz = packed_sz;
	kmem_free(buf, packed_sz);
	return (DDI_SUCCESS);
}

/*
 * init bus_hp_op entry and init hotpluggable slots & virtual ports
 */
int
pcie_hp_init(dev_info_t *dip, caddr_t arg)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	int		ret = DDI_SUCCESS;
	dev_info_t	*cdip;

	if (PCIE_IS_PCIE_HOTPLUG_CAPABLE(bus_p)) {
		/* Init hotplug controller */
		ret = pciehpc_init(dip, arg);
	} else if (PCIE_IS_PCI_HOTPLUG_CAPABLE(bus_p)) {
		ret = pcishpc_init(dip);
	}

	if (ret != DDI_SUCCESS) {
		PCIE_DBG("pcie_hp_init: initialize hotplug "
		    "controller failed with %d\n", ret);
		return (ret);
	}

	ndi_devi_enter(dip);

	/* Create port for the first level children */
	cdip = ddi_get_child(dip);
	while (cdip != NULL) {
		if ((ret = pcie_hp_register_port(cdip, dip, NULL))
		    != DDI_SUCCESS) {
			/* stop and cleanup */
			break;
		}
		cdip = ddi_get_next_sibling(cdip);
	}
	ndi_devi_exit(dip);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "pcie_hp_init: initialize virtual "
		    "hotplug port failed with %d\n", ret);
		(void) pcie_hp_uninit(dip);

		return (ret);
	}

	return (DDI_SUCCESS);
}

/*
 * uninit the hotpluggable slots and virtual ports
 */
int
pcie_hp_uninit(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	pcie_hp_unreg_port_t arg;

	/*
	 * Must set arg.rv to NDI_SUCCESS so that if there's no port
	 * under this dip, we still return success thus the bridge
	 * driver can be successfully detached.
	 *
	 * Note that during the probe PCI configurator calls
	 * ndi_devi_offline() to detach driver for a new probed bridge,
	 * so that it can reprogram the resources for the bridge,
	 * ndi_devi_offline() calls into pcieb_detach() which in turn
	 * calls into this function. In this case there are no ports
	 * created under a new probe bridge dip, as ports are only
	 * created after the configurator finishing probing, thus the
	 * ndi_hp_walk_cn() will see no ports when this is called
	 * from the PCI configurtor.
	 */
	arg.nexus_dip = dip;
	arg.connector_num = DDI_HP_CN_NUM_NONE;
	arg.rv = NDI_SUCCESS;

	/* tear down all virtual hotplug handles */
	ndi_hp_walk_cn(dip, pcie_hp_unregister_ports_cb, &arg);

	if (arg.rv != NDI_SUCCESS)
		return (DDI_FAILURE);

	if (PCIE_IS_PCIE_HOTPLUG_ENABLED(bus_p))
		(void) pciehpc_uninit(dip);
	else if (PCIE_IS_PCI_HOTPLUG_ENABLED(bus_p))
		(void) pcishpc_uninit(dip);

	return (DDI_SUCCESS);
}

/*
 * interrupt handler
 */
int
pcie_hp_intr(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	int		ret = DDI_INTR_UNCLAIMED;

	if (PCIE_IS_PCIE_HOTPLUG_ENABLED(bus_p))
		ret = pciehpc_intr(dip);
	else if (PCIE_IS_PCI_HOTPLUG_ENABLED(bus_p))
		ret = pcishpc_intr(dip);

	return (ret);
}

/*
 * Probe the given PCIe/PCI Hotplug Connection (CN).
 */
/*ARGSUSED*/
int
pcie_hp_probe(pcie_hp_slot_t *slot_p)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	dev_info_t	*dip = ctrl_p->hc_dip;

	/*
	 * Call the configurator to probe a given PCI hotplug
	 * Hotplug Connection (CN).
	 */
	if (pcicfg_configure(dip, slot_p->hs_device_num, PCICFG_ALL_FUNC, 0)
	    != PCICFG_SUCCESS) {
		PCIE_DBG("pcie_hp_probe() failed\n");
		return (DDI_FAILURE);
	}
	slot_p->hs_condition = AP_COND_OK;
	pcie_hp_create_occupant_props(dip, makedevice(ddi_driver_major(dip),
	    slot_p->hs_minor), slot_p->hs_device_num);

	/*
	 * Create ports for the newly probed devices.
	 * Note, this is only for the first level children because the
	 * descendants' ports will be created during bridge driver attach.
	 */
	return (pcie_hp_register_ports_for_dev(dip, slot_p->hs_device_num));
}

/*
 * Unprobe the given PCIe/PCI Hotplug Connection (CN):
 *	1. remove all child device nodes
 *	2. unregister all dependent ports
 */
/*ARGSUSED*/
int
pcie_hp_unprobe(pcie_hp_slot_t *slot_p)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	dev_info_t	*dip = ctrl_p->hc_dip;
	pcie_hp_unreg_port_t arg;

	/*
	 * Call the configurator to unprobe a given PCI hotplug
	 * Hotplug Connection (CN).
	 */
	if (pcicfg_unconfigure(dip, slot_p->hs_device_num, PCICFG_ALL_FUNC, 0)
	    != PCICFG_SUCCESS) {
		PCIE_DBG("pcie_hp_unprobe() failed\n");
		return (DDI_FAILURE);
	}
	slot_p->hs_condition = AP_COND_UNKNOWN;
	pcie_hp_delete_occupant_props(dip, makedevice(ddi_driver_major(dip),
	    slot_p->hs_minor));

	/*
	 * Remove ports for the unprobed devices.
	 * Note, this is only for the first level children because the
	 * descendants' ports were already removed during bridge driver dettach.
	 */
	arg.nexus_dip = dip;
	arg.connector_num = slot_p->hs_info.cn_num;
	arg.rv = NDI_SUCCESS;
	ndi_hp_walk_cn(dip, pcie_hp_unregister_ports_cb, &arg);

	return (arg.rv == NDI_SUCCESS) ? (DDI_SUCCESS) : (DDI_FAILURE);
}

/* Read-only probe: no hardware register programming. */
int
pcie_read_only_probe(dev_info_t *dip, char *cn_name, dev_info_t **pcdip)
{
	long dev, func;
	int ret;
	char *sp;
	dev_info_t *cdip;

	*pcdip = NULL;
	/*
	 * Parse the string of a pci Port name and get the device number
	 * and function number.
	 */
	if (ddi_strtol(cn_name + 4, &sp, 10, &dev) != 0)
		return (DDI_EINVAL);
	if (ddi_strtol(sp + 1, NULL, 10, &func) != 0)
		return (DDI_EINVAL);

	ret = pcicfg_configure(dip, (int)dev, (int)func,
	    PCICFG_FLAG_READ_ONLY);
	if (ret == PCICFG_SUCCESS) {
		cdip = pcie_hp_devi_find(dip, (int)dev, (int)func);
		*pcdip = cdip;
	}
	return (ret);
}

/* Read-only unprobe: no hardware register programming. */
int
pcie_read_only_unprobe(dev_info_t *dip, char *cn_name)
{
	long dev, func;
	int ret;
	char *sp;

	/*
	 * Parse the string of a pci Port name and get the device number
	 * and function number.
	 */
	if (ddi_strtol(cn_name + 4, &sp, 10, &dev) != 0)
		return (DDI_EINVAL);
	if (ddi_strtol(sp + 1, NULL, 10, &func) != 0)
		return (DDI_EINVAL);

	ret = pcicfg_unconfigure(dip, (int)dev, (int)func,
	    PCICFG_FLAG_READ_ONLY);

	return (ret);
}

/* Control structure used to find a device in the devinfo tree */
struct pcie_hp_find_ctrl {
	uint_t		device;
	uint_t		function;
	dev_info_t	*dip;
};

/*
 * find a devinfo node with specified device and function number
 * in the device tree under 'dip'
 */
dev_info_t *
pcie_hp_devi_find(dev_info_t *dip, uint_t device, uint_t function)
{
	struct pcie_hp_find_ctrl	ctrl;

	ctrl.device = device;
	ctrl.function = function;
	ctrl.dip = NULL;

	ndi_devi_enter(dip);
	ddi_walk_devs(ddi_get_child(dip), pcie_hp_match_dev_func,
	    (void *)&ctrl);
	ndi_devi_exit(dip);

	return (ctrl.dip);
}

/*
 * routine to create 'pci-occupant' property for a hotplug slot
 */
void
pcie_hp_create_occupant_props(dev_info_t *dip, dev_t dev, int pci_dev)
{
	pcie_bus_t		*bus_p = PCIE_DIP2BUS(dip);
	pcie_hp_ctrl_t		*ctrl_p = (pcie_hp_ctrl_t *)bus_p->bus_hp_ctrl;
	pcie_hp_slot_t		*slotp = NULL;
	pcie_hp_cn_cfg_t	cn_cfg;
	pcie_hp_occupant_info_t	*occupant;
	int			i;

	ndi_devi_enter(dip);

	if (PCIE_IS_PCIE_HOTPLUG_ENABLED(bus_p)) {
		slotp = (ctrl_p && (pci_dev == 0)) ?
		    ctrl_p->hc_slots[pci_dev] : NULL;
	} else if (PCIE_IS_PCI_HOTPLUG_ENABLED(bus_p)) {
		if (ctrl_p) {
			int	slot_num;

			slot_num = (ctrl_p->hc_device_increases) ?
			    (pci_dev - ctrl_p->hc_device_start) :
			    (pci_dev + ctrl_p->hc_device_start);

			slotp = ctrl_p->hc_slots[slot_num];
		} else {
			slotp = NULL;
		}
	}

	if (slotp == NULL)
		return;

	occupant = kmem_alloc(sizeof (pcie_hp_occupant_info_t), KM_SLEEP);
	occupant->i = 0;

	cn_cfg.flag = B_FALSE;
	cn_cfg.rv = NDI_SUCCESS;
	cn_cfg.dip = NULL;
	cn_cfg.slotp = (void *)slotp;
	cn_cfg.cn_private = (void *)occupant;

	ddi_walk_devs(ddi_get_child(dip), pcie_hp_list_occupants,
	    (void *)&cn_cfg);

	if (occupant->i == 0) {
		/* no occupants right now, need to create stub property */
		char *c[] = { "" };
		(void) ddi_prop_update_string_array(dev, dip, "pci-occupant",
		    c, 1);
	} else {
		(void) ddi_prop_update_string_array(dev, dip, "pci-occupant",
		    occupant->id, occupant->i);
	}

	for (i = 0; i < occupant->i; i++)
		kmem_free(occupant->id[i], sizeof (char[MAXPATHLEN]));

	kmem_free(occupant, sizeof (pcie_hp_occupant_info_t));

	ndi_devi_exit(dip);
}

/*
 * routine to remove 'pci-occupant' property for a hotplug slot
 */
void
pcie_hp_delete_occupant_props(dev_info_t *dip, dev_t dev)
{
	(void) ddi_prop_remove(dev, dip, "pci-occupant");
}

/*
 * general code to create a minor node, called from hotplug controller
 * drivers.
 */
int
pcie_create_minor_node(pcie_hp_ctrl_t *ctrl_p, int slot)
{
	dev_info_t		*dip = ctrl_p->hc_dip;
	pcie_hp_slot_t		*slot_p = ctrl_p->hc_slots[slot];
	ddi_hp_cn_info_t	*info_p = &slot_p->hs_info;

	if (ddi_create_minor_node(dip, info_p->cn_name,
	    S_IFCHR, slot_p->hs_minor,
	    DDI_NT_PCI_ATTACHMENT_POINT, 0) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	(void) ddi_prop_update_int(DDI_DEV_T_NONE,
	    dip, "ap-names", 1 << slot_p->hs_device_num);

	return (DDI_SUCCESS);
}

/*
 * general code to remove a minor node, called from hotplug controller
 * drivers.
 */
void
pcie_remove_minor_node(pcie_hp_ctrl_t *ctrl_p, int slot)
{
	ddi_remove_minor_node(ctrl_p->hc_dip,
	    ctrl_p->hc_slots[slot]->hs_info.cn_name);
}

/*
 * Local functions (called within this file)
 */

/*
 * Register ports for all the children with device number device_num
 */
static int
pcie_hp_register_ports_for_dev(dev_info_t *dip, int device_num)
{
	dev_info_t	*cdip;
	int		rv;

	for (cdip = ddi_get_child(dip); cdip;
	    cdip = ddi_get_next_sibling(cdip)) {
		if (pcie_hp_match_dev(cdip, device_num)) {
			/*
			 * Found the newly probed device under the
			 * current slot. Register a port for it.
			 */
			if ((rv = pcie_hp_register_port(cdip, dip, NULL))
			    != DDI_SUCCESS)
				return (rv);
		} else {
			continue;
		}
	}

	return (DDI_SUCCESS);
}

/*
 * Unregister ports of a pci bridge dip, get called from ndi_hp_walk_cn()
 *
 * If connector_num is specified, then unregister the slot's dependent ports
 * only; Otherwise, unregister all ports of a pci bridge dip.
 */
static int
pcie_hp_unregister_ports_cb(ddi_hp_cn_info_t *info, void *arg)
{
	pcie_hp_unreg_port_t *unreg_arg = (pcie_hp_unreg_port_t *)arg;
	dev_info_t *dip = unreg_arg->nexus_dip;
	int rv = NDI_SUCCESS;

	if (info->cn_type != DDI_HP_CN_TYPE_VIRTUAL_PORT) {
		unreg_arg->rv = rv;
		return (DDI_WALK_CONTINUE);
	}

	if (unreg_arg->connector_num != DDI_HP_CN_NUM_NONE) {
		/* Unregister ports for all unprobed devices under a slot. */
		if (unreg_arg->connector_num == info->cn_num_dpd_on) {

			rv = ndi_hp_unregister(dip, info->cn_name);
		}
	} else {

		/* Unregister all ports of a pci bridge dip. */
		rv = ndi_hp_unregister(dip, info->cn_name);
	}

	unreg_arg->rv = rv;
	if (rv == NDI_SUCCESS)
		return (DDI_WALK_CONTINUE);
	else
		return (DDI_WALK_TERMINATE);
}

/*
 * Find a port according to cn_name and get the port's state.
 */
static int
pcie_hp_get_port_state(ddi_hp_cn_info_t *info, void *arg)
{
	pcie_hp_port_state_t *port = (pcie_hp_port_state_t *)arg;

	if (info->cn_type != DDI_HP_CN_TYPE_VIRTUAL_PORT)
		return (DDI_WALK_CONTINUE);

	if (strcmp(info->cn_name, port->cn_name) == 0) {
		/* Matched. */
		port->cn_state = info->cn_state;
		port->rv = DDI_SUCCESS;

		return (DDI_WALK_TERMINATE);
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * Find the physical slot with the given device number;
 * return the slot if found.
 */
static pcie_hp_slot_t *
pcie_find_physical_slot(dev_info_t *dip, int dev_num)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	pcie_hp_ctrl_t	*ctrl = PCIE_GET_HP_CTRL(dip);

	if (PCIE_IS_PCIE_HOTPLUG_CAPABLE(bus_p)) {
		/* PCIe has only one slot */
		return (dev_num == 0) ? (ctrl->hc_slots[0]) : (NULL);
	} else if (PCIE_IS_PCI_HOTPLUG_CAPABLE(bus_p)) {
		for (int slot = 0; slot < ctrl->hc_num_slots_impl; slot++) {
			if (ctrl->hc_slots[slot]->hs_device_num == dev_num) {
				/* found */
				return (ctrl->hc_slots[slot]);
			}
		}
	}

	return (NULL);
}

/*
 * setup slot name/slot-number info for the port which is being registered.
 */
static int
pcie_hp_create_port_name_num(dev_info_t *dip, ddi_hp_cn_info_t *cn_info)
{
	int		ret, dev_num, func_num, name_len;
	dev_info_t	*pdip = ddi_get_parent(dip);
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(pdip);
	pcie_hp_slot_t	*slot;
	pcie_req_id_t	bdf;
	char		tmp[PCIE_HP_DEV_FUNC_NUM_STRING_LEN];

	ret = pcie_get_bdf_from_dip(dip, &bdf);
	if (ret != DDI_SUCCESS) {
		return (ret);
	}
	if (PCIE_IS_RP(bus_p) || PCIE_IS_SWD(bus_p) ||
	    PCIE_IS_PCI2PCIE(bus_p)) {
		/*
		 * It is under a PCIe device, devcie number is always 0;
		 * function number might > 8 in ARI supported case.
		 */
		dev_num = 0;
		func_num = (bdf & ((~PCI_REG_BUS_M) >> 8));
	} else {
		dev_num = (bdf & (PCI_REG_DEV_M >> 8)) >> 3;
		func_num = bdf & (PCI_REG_FUNC_M >> 8);
	}
	/*
	 * The string length of dev_num and func_num must be no longer than 4
	 * including the string end mark. (With ARI case considered, e.g.,
	 * dev_num=0x0, func_num=0xff.)
	 */
	(void) snprintf(tmp, PCIE_HP_DEV_FUNC_NUM_STRING_LEN, "%x%x",
	    dev_num, func_num);
	/*
	 * Calculate the length of cn_name.
	 * The format of pci port name is: pci.d,f
	 * d stands for dev_num, f stands for func_num. So the length of the
	 * name string can be calculated as following.
	 */
	name_len = strlen(tmp) + PCIE_HP_PORT_NAME_STRING_LEN + 1;

	cn_info->cn_name = (char *)kmem_zalloc(name_len, KM_SLEEP);
	(void) snprintf(cn_info->cn_name, name_len, "pci.%x,%x",
	    dev_num, func_num);
	cn_info->cn_num = (dev_num << 8) | func_num;
	slot = pcie_find_physical_slot(pdip, dev_num);

	cn_info->cn_num_dpd_on = slot ?
	    slot->hs_info.cn_num : DDI_HP_CN_NUM_NONE;

	return (DDI_SUCCESS);
}

/*
 * Extract device and function number from port name, whose format is
 * something like 'pci.1,0'
 */
static int
pcie_hp_get_df_from_port_name(char *cn_name, int *dev_num, int *func_num)
{
	int name_len, ret;
	long d, f;
	char *sp;

	/* some checks for the input name */
	name_len = strlen(cn_name);
	if ((name_len <= PCIE_HP_PORT_NAME_STRING_LEN) ||
	    (name_len > (PCIE_HP_PORT_NAME_STRING_LEN +
	    PCIE_HP_DEV_FUNC_NUM_STRING_LEN - 1)) ||
	    (strncmp("pci.", cn_name, 4) != 0)) {
		return (DDI_EINVAL);
	}
	ret = ddi_strtol(cn_name + 4, &sp, 10, &d);
	if (ret != DDI_SUCCESS)
		return (ret);

	if (strncmp(",", sp, 1) != 0)
		return (DDI_EINVAL);

	ret = ddi_strtol(sp + 1, NULL, 10, &f);
	if (ret != DDI_SUCCESS)
		return (ret);
	*dev_num = (int)d;
	*func_num = (int)f;

	return (ret);
}

/*
 * Check/copy cn_name and set connection numbers.
 * If it is a valid name, then setup cn_info for the newly created port.
 */
static int
pcie_hp_setup_port_name_num(dev_info_t *pdip, char *cn_name,
    ddi_hp_cn_info_t *cn_info)
{
	int dev_num, func_num, ret;
	pcie_hp_slot_t *slot;

	if ((ret = pcie_hp_get_df_from_port_name(cn_name, &dev_num, &func_num))
	    != DDI_SUCCESS)
		return (ret);

	if (pcie_hp_check_hardware_existence(pdip, dev_num, func_num) ==
	    DDI_SUCCESS) {
		cn_info->cn_state = DDI_HP_CN_STATE_PRESENT;
	} else {
		cn_info->cn_state = DDI_HP_CN_STATE_EMPTY;
	}

	cn_info->cn_name = ddi_strdup(cn_name, KM_SLEEP);
	cn_info->cn_num = (dev_num << 8) | func_num;

	slot = pcie_find_physical_slot(pdip, dev_num);
	if (slot) {
		cn_info->cn_num_dpd_on = slot->hs_info.cn_num;
	} else {
		cn_info->cn_num_dpd_on = DDI_HP_CN_NUM_NONE;
	}
	return (DDI_SUCCESS);
}

static int
ndi2ddi(int n)
{
	int ret;

	switch (n) {
	case NDI_SUCCESS:
		ret = DDI_SUCCESS;
		break;
	case NDI_NOMEM:
		ret = DDI_ENOMEM;
		break;
	case NDI_BUSY:
		ret = DDI_EBUSY;
		break;
	case NDI_EINVAL:
		ret = DDI_EINVAL;
		break;
	case NDI_ENOTSUP:
		ret = DDI_ENOTSUP;
		break;
	case NDI_FAILURE:
	default:
		ret = DDI_FAILURE;
		break;
	}
	return (ret);
}

/*
 * Common routine to create and register a new port
 *
 * Create an empty port if dip is NULL, and cn_name needs to be specified in
 * this case. Otherwise, create a port mapping to the specified dip, and cn_name
 * is not needed in this case.
 */
static int
pcie_hp_register_port(dev_info_t *dip, dev_info_t *pdip, char *cn_name)
{
	ddi_hp_cn_info_t	*cn_info;
	int			ret;

	ASSERT((dip == NULL) != (cn_name == NULL));
	cn_info = kmem_zalloc(sizeof (ddi_hp_cn_info_t), KM_SLEEP);
	if (dip != NULL)
		ret = pcie_hp_create_port_name_num(dip, cn_info);
	else
		ret = pcie_hp_setup_port_name_num(pdip, cn_name, cn_info);

	if (ret != DDI_SUCCESS) {
		kmem_free(cn_info, sizeof (ddi_hp_cn_info_t));
		return (ret);
	}

	cn_info->cn_child = dip;
	cn_info->cn_type = DDI_HP_CN_TYPE_VIRTUAL_PORT;
	cn_info->cn_type_str = DDI_HP_CN_TYPE_STR_PORT;

	ret = ndi_hp_register(pdip, cn_info);

	kmem_free(cn_info->cn_name, strlen(cn_info->cn_name) + 1);
	kmem_free(cn_info, sizeof (ddi_hp_cn_info_t));

	return (ndi2ddi(ret));
}

/* Check if there is a piece of hardware exist corresponding to the cn_name */
static int
pcie_hp_check_hardware_existence(dev_info_t *dip, int dev_num, int func_num)
{

	/*
	 * VHPTODO:
	 * According to device and function number, check if there is a hardware
	 * device exists. Currently, this function can not be reached before
	 * we enable state transition to or from "Port-Empty" or "Port-Present"
	 * states. When the pci device type project is integrated, we are going
	 * to call the pci config space access interfaces introduced by it.
	 */
	_NOTE(ARGUNUSED(dip, dev_num, func_num));

	return (DDI_SUCCESS);
}

/*
 * Dispatch hotplug commands to different hotplug controller drivers, including
 * physical and virtual hotplug operations.
 */
/* ARGSUSED */
int
pcie_hp_common_ops(dev_info_t *dip, char *cn_name, ddi_hp_op_t op,
    void *arg, void *result)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	int		ret = DDI_SUCCESS;

	PCIE_DBG("pcie_hp_common_ops: dip=%p cn_name=%s op=%x arg=%p\n",
	    dip, cn_name, op, arg);

	switch (op) {
	case DDI_HPOP_CN_CREATE_PORT:
	{
		/* create an empty port */
		return (pcie_hp_register_port(NULL, dip, cn_name));
	}
	case DDI_HPOP_CN_CHANGE_STATE:
	{
		ddi_hp_cn_state_t curr_state;
		ddi_hp_cn_state_t target_state = *(ddi_hp_cn_state_t *)arg;
		pcie_hp_port_state_t state_arg;

		if (target_state < DDI_HP_CN_STATE_PORT_EMPTY) {
			/* this is for physical slot state change */
			break;
		}
		PCIE_DBG("pcie_hp_common_ops: change port state"
		    " dip=%p cn_name=%s"
		    " op=%x arg=%p\n", (void *)dip, cn_name, op, arg);

		state_arg.rv = DDI_FAILURE;
		state_arg.cn_name = cn_name;
		ndi_hp_walk_cn(dip, pcie_hp_get_port_state, &state_arg);
		if (state_arg.rv != DDI_SUCCESS) {
			/* can not find the port */
			return (DDI_EINVAL);
		}
		curr_state = state_arg.cn_state;
		/*
		 * Check if this is for changing port's state: change to/from
		 * PORT_EMPTY/PRESENT states.
		 */
		if (curr_state < target_state) {
			/* Upgrade state */
			switch (curr_state) {
			case DDI_HP_CN_STATE_PORT_EMPTY:
				if (target_state ==
				    DDI_HP_CN_STATE_PORT_PRESENT) {
					int dev_num, func_num;

					ret = pcie_hp_get_df_from_port_name(
					    cn_name, &dev_num, &func_num);
					if (ret != DDI_SUCCESS)
						goto port_state_done;

					ret = pcie_hp_check_hardware_existence(
					    dip, dev_num, func_num);
				} else if (target_state ==
				    DDI_HP_CN_STATE_OFFLINE) {
					ret = pcie_read_only_probe(dip,
					    cn_name, (dev_info_t **)result);
				} else
					ret = DDI_EINVAL;

				goto port_state_done;
			case DDI_HP_CN_STATE_PORT_PRESENT:
				if (target_state ==
				    DDI_HP_CN_STATE_OFFLINE)
					ret = pcie_read_only_probe(dip,
					    cn_name, (dev_info_t **)result);
				else
					ret = DDI_EINVAL;

				goto port_state_done;
			default:
				ASSERT("unexpected state");
			}
		} else {
			/* Downgrade state */
			switch (curr_state) {
			case DDI_HP_CN_STATE_PORT_PRESENT:
			{
				int dev_num, func_num;

				ret = pcie_hp_get_df_from_port_name(cn_name,
				    &dev_num, &func_num);
				if (ret != DDI_SUCCESS)
					goto port_state_done;

				ret = pcie_hp_check_hardware_existence(dip,
				    dev_num, func_num);

				goto port_state_done;
			}
			case DDI_HP_CN_STATE_OFFLINE:
				ret = pcie_read_only_unprobe(dip, cn_name);

				goto port_state_done;
			default:
				ASSERT("unexpected state");
			}
		}
port_state_done:
		*(ddi_hp_cn_state_t *)result = curr_state;
		return (ret);
	}
	default:
		break;
	}

	if (PCIE_IS_PCIE_HOTPLUG_CAPABLE(bus_p)) {
		/* PCIe hotplug */
		ret = pciehpc_hp_ops(dip, cn_name, op, arg, result);
	} else if (PCIE_IS_PCI_HOTPLUG_CAPABLE(bus_p)) {
		/* PCI SHPC hotplug */
		ret = pcishpc_hp_ops(dip, cn_name, op, arg, result);
	} else {
		cmn_err(CE_WARN, "pcie_hp_common_ops: op is not supported."
		    " dip=%p cn_name=%s"
		    " op=%x arg=%p\n", (void *)dip, cn_name, op, arg);
		ret = DDI_ENOTSUP;
	}

#if defined(__x86)
	/*
	 * like in attach, since hotplugging can change error registers,
	 * we need to ensure that the proper bits are set on this port
	 * after a configure operation
	 */
	if ((ret == DDI_SUCCESS) && (op == DDI_HPOP_CN_CHANGE_STATE) &&
	    (*(ddi_hp_cn_state_t *)arg == DDI_HP_CN_STATE_ENABLED))
		pcieb_intel_error_workaround(dip);
#endif

	return (ret);
}

/*
 * pcie_hp_match_dev_func:
 * Match dip's PCI device number and function number with input ones.
 */
static int
pcie_hp_match_dev_func(dev_info_t *dip, void *hdl)
{
	struct pcie_hp_find_ctrl	*ctrl = (struct pcie_hp_find_ctrl *)hdl;
	pci_regspec_t			*pci_rp;
	int				length;
	int				pci_dev, pci_func;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&pci_rp, (uint_t *)&length) != DDI_PROP_SUCCESS) {
		ctrl->dip = NULL;
		return (DDI_WALK_TERMINATE);
	}

	/* get the PCI device address info */
	pci_dev = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	pci_func = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(pci_rp);

	if ((pci_dev == ctrl->device) && (pci_func == ctrl->function)) {
		/* found the match for the specified device address */
		ctrl->dip = dip;
		return (DDI_WALK_TERMINATE);
	}

	/*
	 * continue the walk to the next sibling to look for a match.
	 */
	return (DDI_WALK_PRUNECHILD);
}

/*
 * pcie_hp_match_dev:
 * Match the dip's pci device number with the input dev_num
 */
static boolean_t
pcie_hp_match_dev(dev_info_t *dip, int dev_num)
{
	pci_regspec_t			*pci_rp;
	int				length;
	int				pci_dev;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&pci_rp, (uint_t *)&length) != DDI_PROP_SUCCESS) {
		return (B_FALSE);
	}

	/* get the PCI device address info */
	pci_dev = PCI_REG_DEV_G(pci_rp->pci_phys_hi);

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(pci_rp);

	if (pci_dev == dev_num) {
		/* found the match for the specified device address */
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Callback function to match with device number in order to list
 * occupants under a specific slot
 */
static int
pcie_hp_list_occupants(dev_info_t *dip, void *arg)
{
	pcie_hp_cn_cfg_t	*cn_cfg_p = (pcie_hp_cn_cfg_t *)arg;
	pcie_hp_occupant_info_t	*occupant =
	    (pcie_hp_occupant_info_t *)cn_cfg_p->cn_private;
	pcie_hp_slot_t		*slot_p =
	    (pcie_hp_slot_t *)cn_cfg_p->slotp;
	int			pci_dev;
	pci_regspec_t		*pci_rp;
	int			length;
	major_t			major;

	/*
	 * Get the PCI device number information from the devinfo
	 * node. Since the node may not have the address field
	 * setup (this is done in the DDI_INITCHILD of the parent)
	 * we look up the 'reg' property to decode that information.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp,
	    (uint_t *)&length) != DDI_PROP_SUCCESS) {
		cn_cfg_p->rv = DDI_FAILURE;
		cn_cfg_p->dip = dip;
		return (DDI_WALK_TERMINATE);
	}

	/* get the pci device id information */
	pci_dev = PCI_REG_DEV_G(pci_rp->pci_phys_hi);

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(pci_rp);

	/*
	 * Match the node for the device number of the slot.
	 */
	if (pci_dev == slot_p->hs_device_num) {

		major = ddi_driver_major(dip);

		/*
		 * If the node is not yet attached, then don't list it
		 * as an occupant. This is valid, since nothing can be
		 * consuming it until it is attached, and cfgadm will
		 * ask for the property explicitly which will cause it
		 * to be re-freshed right before checking with rcm.
		 */
		if ((major == DDI_MAJOR_T_NONE) || !i_ddi_devi_attached(dip))
			return (DDI_WALK_PRUNECHILD);

		/*
		 * If we have used all our occupants then print mesage
		 * and terminate walk.
		 */
		if (occupant->i >= PCIE_HP_MAX_OCCUPANTS) {
			cmn_err(CE_WARN,
			    "pcie (%s%d): unable to list all occupants",
			    ddi_driver_name(ddi_get_parent(dip)),
			    ddi_get_instance(ddi_get_parent(dip)));
			return (DDI_WALK_TERMINATE);
		}

		/*
		 * No need to hold the dip as ddi_walk_devs
		 * has already arranged that for us.
		 */
		occupant->id[occupant->i] =
		    kmem_alloc(sizeof (char[MAXPATHLEN]), KM_SLEEP);
		(void) ddi_pathname(dip, (char *)occupant->id[occupant->i]);
		occupant->i++;
	}

	/*
	 * continue the walk to the next sibling to look for a match
	 * or to find other nodes if this card is a multi-function card.
	 */
	return (DDI_WALK_PRUNECHILD);
}

/*
 * Generate the System Event for ESC_DR_REQ.
 * One of the consumers is pcidr, it calls to libcfgadm to perform a
 * configure or unconfigure operation to the AP.
 */
void
pcie_hp_gen_sysevent_req(char *slot_name, int hint,
    dev_info_t *self, int kmflag)
{
	sysevent_id_t	eid;
	nvlist_t	*ev_attr_list = NULL;
	char		cn_path[MAXPATHLEN];
	char		*ap_id;
	int		err, ap_id_len;

	/*
	 * Minor device name (AP) will be bus path
	 * concatenated with slot name
	 */
	(void) strcpy(cn_path, "/devices");
	(void) ddi_pathname(self, cn_path + strlen("/devices"));

	ap_id_len = strlen(cn_path) + strlen(":") +
	    strlen(slot_name) + 1;
	ap_id = kmem_zalloc(ap_id_len, kmflag);
	if (ap_id == NULL) {
		cmn_err(CE_WARN,
		    "%s%d: Failed to allocate memory for AP ID: %s:%s",
		    ddi_driver_name(self), ddi_get_instance(self),
		    cn_path, slot_name);

		return;
	}

	(void) strcpy(ap_id, cn_path);
	(void) strcat(ap_id, ":");
	(void) strcat(ap_id, slot_name);

	err = nvlist_alloc(&ev_attr_list, NV_UNIQUE_NAME_TYPE, kmflag);
	if (err != 0) {
		cmn_err(CE_WARN,
		    "%s%d: Failed to allocate memory "
		    "for event attributes%s", ddi_driver_name(self),
		    ddi_get_instance(self), ESC_DR_REQ);

		kmem_free(ap_id, ap_id_len);
		return;
	}

	switch (hint) {

	case SE_INVESTIGATE_RES:	/* fall through */
	case SE_INCOMING_RES:		/* fall through */
	case SE_OUTGOING_RES:		/* fall through */

		err = nvlist_add_string(ev_attr_list, DR_REQ_TYPE,
		    SE_REQ2STR(hint));

		if (err != 0) {
			cmn_err(CE_WARN,
			    "%s%d: Failed to add attr [%s] "
			    "for %s event", ddi_driver_name(self),
			    ddi_get_instance(self),
			    DR_REQ_TYPE, ESC_DR_REQ);

			goto done;
		}
		break;

	default:
		cmn_err(CE_WARN, "%s%d:  Unknown hint on sysevent",
		    ddi_driver_name(self), ddi_get_instance(self));

		goto done;
	}

	/*
	 * Add attachment point as attribute (common attribute)
	 */

	err = nvlist_add_string(ev_attr_list, DR_AP_ID, ap_id);

	if (err != 0) {
		cmn_err(CE_WARN, "%s%d: Failed to add attr [%s] for %s event",
		    ddi_driver_name(self), ddi_get_instance(self),
		    DR_AP_ID, EC_DR);

		goto done;
	}


	/*
	 * Log this event with sysevent framework.
	 */

	err = ddi_log_sysevent(self, DDI_VENDOR_SUNW, EC_DR,
	    ESC_DR_REQ, ev_attr_list, &eid,
	    ((kmflag == KM_SLEEP) ? DDI_SLEEP : DDI_NOSLEEP));
	if (err != 0) {
		cmn_err(CE_WARN, "%s%d: Failed to log %s event",
		    ddi_driver_name(self), ddi_get_instance(self), EC_DR);
	}

done:
	nvlist_free(ev_attr_list);
	kmem_free(ap_id, ap_id_len);
}
