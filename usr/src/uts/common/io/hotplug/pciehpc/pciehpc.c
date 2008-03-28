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
 *  Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 *  Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PCIEHPC - The Standard PCI Express HotPlug Controller driver module. This
 *           driver can be used with PCI Express HotPlug controllers that
 *           are compatible with the PCI Express ver 1.0a specification.
 */

#include <sys/types.h>
#include <sys/note.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/varargs.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/time.h>
#include <sys/callb.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pcie_impl.h>
#include <sys/hotplug/pci/pciehpc_impl.h>

/*
 * Local data/functions
 */

/* mutex to protect pciehpc_head list */
static kmutex_t pciehpc_list_mutex;

/* pointer to linked list of pciehpc structures */
static pciehpc_t *pciehpc_head = NULL;

/* mutex to protect init/uninit controllers */
static kmutex_t pciehpc_init_mutex;
static int pciehpc_init_count = 0; /* count of pciehpc instances in use */

static pciehpc_t *pciehpc_create_soft_state(dev_info_t *dip);
static pciehpc_t *pciehpc_get_soft_state(dev_info_t *dip);
static void pciehpc_destroy_soft_state(dev_info_t *dip);
static char *pciehpc_led_state_text(hpc_led_state_t state);
static void pciehpc_attn_btn_handler(pciehpc_t *ctrl_p);
static void pciehpc_dev_info(pciehpc_t *ctrl_p);

static int pciehpc_pcie_dev(dev_info_t *dip, ddi_acc_handle_t handle);
static void pciehpc_disable_errors(pciehpc_t *ctrl_p);
static void pciehpc_enable_errors(pciehpc_t *ctrl_p);

#ifdef DEBUG
int pciehpc_debug = 0;
static void pciehpc_dump_hpregs(pciehpc_t *ctrl_p);
#endif

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_miscops;
static struct modlmisc modlmisc =
{
	&mod_miscops,
	"PCIe hotplug driver v%I%",
};

static struct modlinkage modlinkage =
{
	MODREV_1,
	&modlmisc,
	NULL
};


int
_init(void)
{
	int error;

	PCIEHPC_DEBUG3((CE_NOTE, "pciehpc: _init() called\n"));
	mutex_init(&pciehpc_list_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pciehpc_init_mutex, NULL, MUTEX_DRIVER, NULL);
	if ((error = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&pciehpc_init_mutex);
		mutex_destroy(&pciehpc_list_mutex);
	}

	return (error);
}

int
_fini(void)
{
	int error;

	PCIEHPC_DEBUG3((CE_NOTE, "pciehpc: _fini() called\n"));

	mutex_enter(&pciehpc_init_mutex);
	if (pciehpc_init_count != 0) {
		mutex_exit(&pciehpc_init_mutex);
		return (EBUSY);
	}
	error = mod_remove(&modlinkage);
	if (error != 0) {
		mutex_exit(&pciehpc_init_mutex);
		return (error);
	}
	mutex_destroy(&pciehpc_list_mutex);
	mutex_destroy(&pciehpc_init_mutex);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	PCIEHPC_DEBUG3((CE_NOTE, "pciehpc: _info() called\n"));
	return (mod_info(&modlinkage, modinfop));
}

/*
 * pciehpc_init()
 *
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
pciehpc_init(dev_info_t *dip, pciehpc_regops_t *regops)
{
	pciehpc_t *ctrl_p;

	PCIEHPC_DEBUG3((CE_NOTE, "pciehpc_init() called (dip=%p)",
	    (void *)dip));

	mutex_enter(&pciehpc_init_mutex);

	/* Make sure that it is not already initialized */
	if (pciehpc_get_soft_state(dip) != NULL) {
	    PCIEHPC_DEBUG((CE_WARN,
		"%s%d: pciehpc instance already initialized!",
		ddi_driver_name(dip), ddi_get_instance(dip)));
		mutex_exit(&pciehpc_init_mutex);
		return (DDI_SUCCESS);
	}

	/* allocate a new soft state structure */
	ctrl_p = pciehpc_create_soft_state(dip);

	/* get PCI device info */
	pciehpc_dev_info(ctrl_p);

	/* setup access handle for HPC regs */
	if (regops != NULL) {
		/* HPC access is non-standard; use the supplied reg ops */
		ctrl_p->regops = *regops;
	} else {
		/* standard HPC in a PCIe bridge */
		if (pciehpc_regs_setup(dip, 0, 0, &ctrl_p->regs_base,
		    &ctrl_p->cfghdl) != DDI_SUCCESS)
		    goto cleanup;
	}

	pciehpc_disable_errors(ctrl_p);

	/*
	 * Set the platform specific hot plug mode.
	 */
	ctrl_p->hp_mode = PCIEHPC_NATIVE_HP_MODE; /* default is Native mode */
	ctrl_p->ops.init_hpc_hw = pciehpc_hpc_init;
	ctrl_p->ops.init_hpc_slotinfo = pciehpc_slotinfo_init;
	ctrl_p->ops.disable_hpc_intr = pciehpc_disable_intr;
	ctrl_p->ops.enable_hpc_intr = pciehpc_enable_intr;
	ctrl_p->ops.uninit_hpc_hw = pciehpc_hpc_uninit;
	ctrl_p->ops.uninit_hpc_slotinfo = pciehpc_slotinfo_uninit;
	ctrl_p->ops.probe_hpc = pciehpc_probe_hpc;

#if	defined(__i386) || defined(__amd64)
	pciehpc_update_ops(ctrl_p);
#endif
	if (regops == NULL) { /* it is a standard HPC in a PCIe bridge */
	    /* make sure we really have a hot plug controller */
	    if ((ctrl_p->ops.probe_hpc)(ctrl_p) != DDI_SUCCESS)
		goto cleanup1;
	}

	/* initialize hot plug controller hw */
	if ((ctrl_p->ops.init_hpc_hw)(ctrl_p) != DDI_SUCCESS)
		goto cleanup1;

	/* initialize slot information soft state structure */
	if ((ctrl_p->ops.init_hpc_slotinfo)(ctrl_p) != DDI_SUCCESS)
		goto cleanup2;

	/* register the hot plug slot with HPS framework */
	if (pciehpc_register_slot(ctrl_p) != DDI_SUCCESS)
		goto cleanup3;

	/* HPC initialization is complete now */
	ctrl_p->soft_state |= PCIEHPC_SOFT_STATE_INITIALIZED;
	ctrl_p->soft_state &= ~PCIEHPC_SOFT_STATE_UNINITIALIZED;

#ifdef DEBUG
	/* For debug, dump the HPC registers */
	if (pciehpc_debug > 2)
		pciehpc_dump_hpregs(ctrl_p);
#endif

	/* enable hot plug interrupts/event */
	(void) (ctrl_p->ops.enable_hpc_intr)(ctrl_p);

	pciehpc_init_count++;

	mutex_exit(&pciehpc_init_mutex);

	return (DDI_SUCCESS);

cleanup3:
	(void) (ctrl_p->ops.uninit_hpc_slotinfo)(ctrl_p);

cleanup2:
	(void) (ctrl_p->ops.uninit_hpc_hw)(ctrl_p);

cleanup1:
	pciehpc_enable_errors(ctrl_p);
	/* free up the HPC register mapping  if applicable */
	if (ctrl_p->cfghdl)
		pciehpc_regs_teardown(&ctrl_p->cfghdl);

cleanup:
	pciehpc_destroy_soft_state(dip);
	mutex_exit(&pciehpc_init_mutex);
	return (DDI_FAILURE);
}

/*
 * Uninitialize HPC soft state structure and free up any resources
 * used for the HPC instance.
 */
int
pciehpc_uninit(dev_info_t *dip)
{
	pciehpc_t *ctrl_p;

	PCIEHPC_DEBUG3((CE_NOTE, "pciehpc_uninit() called (dip=%p)\n",
	    (void *)dip));

	mutex_enter(&pciehpc_init_mutex);

	/* get the soft state structure for this dip */
	if ((ctrl_p = pciehpc_get_soft_state(dip)) == NULL) {
		mutex_exit(&pciehpc_init_mutex);
		return (DDI_FAILURE);
	}

	/* disable interrupts */
	(void) (ctrl_p->ops.disable_hpc_intr)(ctrl_p);

	/* unregister the slot */
	(void) pciehpc_unregister_slot(ctrl_p);

	/* uninit any slot info data structures */
	(void) (ctrl_p->ops.uninit_hpc_slotinfo)(ctrl_p);

	/* uninitialize hpc, remove interrupt handler, etc. */
	(void) (ctrl_p->ops.uninit_hpc_hw)(ctrl_p);

	pciehpc_enable_errors(ctrl_p);

	/* free up the HPC register mapping  if applicable */
	if (ctrl_p->cfghdl)
		pciehpc_regs_teardown(&ctrl_p->cfghdl);

	/* destroy the soft state structure */
	pciehpc_destroy_soft_state(dip);

	ASSERT(pciehpc_init_count != 0);

	pciehpc_init_count--;

	mutex_exit(&pciehpc_init_mutex);

	return (DDI_SUCCESS);
}

/*
 * Probe for the inband PCI-E hot plug controller. Returns DDI_SUCCESS
 * if found. This function works only for the standard PCI-E bridge
 * that has inband hot plug controller.
 *
 * NOTE: This won't work for Host-PCIE bridges.
 */
int
pciehpc_probe_hpc(pciehpc_t *ctrl_p)
{
	uint8_t cap_ptr;
	uint8_t cap_id;
	uint16_t status;

	/* Read the PCI configuration status register. */
	status = pciehpc_reg_get16(ctrl_p, PCI_CONF_STAT);

	/* check for capabilities list */
	if (!(status & PCI_STAT_CAP)) {
		/* no capabilities list */
		return (DDI_FAILURE);
	}

	/* Get a pointer to the PCI capabilities list. */
	cap_ptr = pciehpc_reg_get8(ctrl_p, PCI_BCNF_CAP_PTR);
	cap_ptr &= 0xFC; /* mask off reserved bits */

	/*
	 * Walk thru the capabilities list looking for PCI Express capability
	 * structure.
	 */
	while (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
	    cap_id = pciehpc_reg_get8(ctrl_p, (uint_t)cap_ptr);

	    PCIEHPC_DEBUG3((CE_NOTE, "pciehpc_probe_hpc() capability @"
		" pointer=%02x (id=%02x)\n", cap_ptr, cap_id));

	    if (cap_id == PCI_CAP_ID_PCI_E) {
		uint32_t slot_cap;

		/* Read the PCI Express Slot Capabilities Register */
		slot_cap = pciehpc_reg_get32(ctrl_p,
				(uint_t)cap_ptr + PCIE_SLOTCAP);

		/* Does it have PCI Express HotPlug capability? */
		if (slot_cap & PCIE_SLOTCAP_HP_CAPABLE) {
		    /* Save the offset to PCI Express Capabilities structure */
		    ctrl_p->pcie_caps_reg_offset = cap_ptr;
		    return (DDI_SUCCESS);
		}
	    }

	    /* Get the pointer to the next capability */
	    cap_ptr = pciehpc_reg_get8(ctrl_p, (uint_t)cap_ptr + 1);
	    cap_ptr &= 0xFC;
	}

	return (DDI_FAILURE);
}

/*
 * Setup slot information for use with HPS framework.
 */
int
pciehpc_slotinfo_init(pciehpc_t *ctrl_p)
{
	uint32_t slot_capabilities, link_capabilities;
	pciehpc_slot_t *p = &ctrl_p->slot;

	/*
	 * setup HPS framework slot ops structure
	 */
	p->slot_ops.hpc_version = HPC_SLOT_OPS_VERSION;
	p->slot_ops.hpc_op_connect = pciehpc_slot_connect;
	p->slot_ops.hpc_op_disconnect = pciehpc_slot_disconnect;
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

	/* set slot-name/slot-number info */
	pciehpc_set_slot_name(ctrl_p);

	/* check if Attn Button present */
	ctrl_p->has_attn = (slot_capabilities & PCIE_SLOTCAP_ATTN_BUTTON) ?
		B_TRUE : B_FALSE;

	/* check if Manual Retention Latch sensor present */
	ctrl_p->has_mrl = (slot_capabilities & PCIE_SLOTCAP_MRL_SENSOR) ?
		B_TRUE : B_FALSE;

	/*
	 * PCI-E version 1.1 defines EMI Lock Present bit
	 * in Slot Capabilities register. Check for it.
	 */
	ctrl_p->has_emi_lock = (slot_capabilities &
		PCIE_SLOTCAP_EMI_LOCK_PRESENT) ? B_TRUE : B_FALSE;

	link_capabilities = pciehpc_reg_get32(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_LINKCAP);
	ctrl_p->dll_active_rep = (link_capabilities &
		PCIE_LINKCAP_DLL_ACTIVE_REP_CAPABLE) ? B_TRUE : B_FALSE;
	if (ctrl_p->dll_active_rep)
		cv_init(&ctrl_p->slot.dll_active_cv, NULL, CV_DRIVER, NULL);

	/* initialize synchronization conditional variable */
	cv_init(&ctrl_p->slot.cmd_comp_cv, NULL, CV_DRIVER, NULL);
	ctrl_p->slot.command_pending = B_FALSE;

	/* setup thread for handling ATTN button events */
	if (ctrl_p->has_attn) {
		PCIEHPC_DEBUG3((CE_NOTE,
		    "pciehpc_slotinfo_init: setting up ATTN button event "
		    "handler thread for slot %d\n", ctrl_p->slot.slotNum));
		cv_init(&ctrl_p->slot.attn_btn_cv, NULL, CV_DRIVER, NULL);
		ctrl_p->slot.attn_btn_pending = B_FALSE;
		ctrl_p->slot.attn_btn_threadp = thread_create(NULL, 0,
			pciehpc_attn_btn_handler,
			(void *)ctrl_p, 0, &p0, TS_RUN, minclsyspri);
		ctrl_p->slot.attn_btn_thread_exit = B_FALSE;
	}

	/* get current slot state from the hw */
	pciehpc_get_slot_state(ctrl_p);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
pciehpc_slotinfo_uninit(pciehpc_t *ctrl_p)
{
	cv_destroy(&ctrl_p->slot.cmd_comp_cv);

	if (ctrl_p->slot.attn_btn_threadp != NULL) {
	    mutex_enter(&ctrl_p->pciehpc_mutex);
	    ctrl_p->slot.attn_btn_thread_exit = B_TRUE;
	    cv_signal(&ctrl_p->slot.attn_btn_cv);
	    PCIEHPC_DEBUG3((CE_NOTE,
		"pciehpc_slotinfo_uninit: waiting for ATTN thread exit\n"));
	    cv_wait(&ctrl_p->slot.attn_btn_cv, &ctrl_p->pciehpc_mutex);
	    PCIEHPC_DEBUG3((CE_NOTE,
		"pciehpc_slotinfo_uninit: ATTN thread exit\n"));
	    cv_destroy(&ctrl_p->slot.attn_btn_cv);
	    ctrl_p->slot.attn_btn_threadp = NULL;
	    mutex_exit(&ctrl_p->pciehpc_mutex);
	}

	if (ctrl_p->dll_active_rep)
		cv_destroy(&ctrl_p->slot.dll_active_cv);

	return (DDI_SUCCESS);
}

/*
 * Get the current state of the slot from the hw.
 */
void
pciehpc_get_slot_state(pciehpc_t *ctrl_p)
{
	pciehpc_slot_t *p = &ctrl_p->slot;
	uint16_t control, status;

	/* read the Slot Control Register */
	control = pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	p->fault_led_state = HPC_LED_OFF; /* no fault led */
	p->active_led_state = HPC_LED_OFF; /* no active led */

	/* read the current Slot Status Register */
	status = pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);

	/* get POWER led state */
	p->power_led_state =
	    pciehpc_led_state_to_hpc(pcie_slotctl_pwr_indicator_get(control));

	/* get ATTN led state */
	p->attn_led_state =
	    pciehpc_led_state_to_hpc(pcie_slotctl_attn_indicator_get(control));

	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED))
		/* no device present; slot is empty */
		p->slot_state = HPC_SLOT_EMPTY;

	else if (!(control & PCIE_SLOTCTL_PWR_CONTROL))
		/* device is present and powered up */
		p->slot_state = HPC_SLOT_CONNECTED;
	else
		/* device is present and powered down */
		p->slot_state = HPC_SLOT_DISCONNECTED;
}


/*
 * pciehpc_regs_setup()
 *
 * Setup PCI-E config registers for DDI access functions.
 *
 * Note: This is same as pci_config_setup() except that this may be
 * used to map specific reg set with an offset in the case of host
 * PCI-E bridges.
 */
int
pciehpc_regs_setup(dev_info_t *dip, uint_t rnum, offset_t off,
	caddr_t *addrp, ddi_acc_handle_t *handle)
{
	ddi_device_acc_attr_t attr;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Check for fault management capabilities */
	if (DDI_FM_ACC_ERR_CAP(ddi_fm_capable(dip)))
		attr.devacc_attr_access = DDI_FLAGERR_ACC;

	return (ddi_regs_map_setup(dip, rnum, addrp, off, 0, &attr, handle));
}

/*
 * pciehpc_regs_teardown()
 *
 * Unmap config register set.
 *
 * Note: This is same as pci_config_teardown() function.
 */
void
pciehpc_regs_teardown(ddi_acc_handle_t *handle)
{
	ddi_regs_map_free(handle);
}

/*
 * Find the soft state structure for the HPC associated with the dip.
 */
static pciehpc_t *
pciehpc_get_soft_state(dev_info_t *dip)
{
	pciehpc_t *ctrl_p;

	mutex_enter(&pciehpc_list_mutex);

	ctrl_p = pciehpc_head;

	while (ctrl_p) {
		if (ctrl_p->dip == dip) {
			mutex_exit(&pciehpc_list_mutex);
			return (ctrl_p);
		}
		ctrl_p = ctrl_p->nextp;
	}

	mutex_exit(&pciehpc_list_mutex);

	return (NULL);
}

/*
 * Allocate a soft state structure for the HPC associated with this dip.
 */
static pciehpc_t *
pciehpc_create_soft_state(dev_info_t *dip)
{
	pciehpc_t *ctrl_p;

	ctrl_p = kmem_zalloc(sizeof (pciehpc_t), KM_SLEEP);

	ctrl_p->dip = dip;

	mutex_enter(&pciehpc_list_mutex);
	ctrl_p->nextp = pciehpc_head;
	pciehpc_head = ctrl_p;
	ctrl_p->soft_state = PCIEHPC_SOFT_STATE_UNINITIALIZED;
	mutex_exit(&pciehpc_list_mutex);

	return (ctrl_p);
}

/*
 * Remove the HPC soft state structure from the linked list.
 */
static void
pciehpc_destroy_soft_state(dev_info_t *dip)
{
	pciehpc_t **pp;
	pciehpc_t *p;

	mutex_enter(&pciehpc_list_mutex);
	pp = &pciehpc_head;
	while ((p = *pp) != NULL) {
		if (p->dip == dip) {
			*pp = p->nextp;
			kmem_free(p, sizeof (pciehpc_t));
			break;
		}
		pp = &(p->nextp);
	}
	mutex_exit(&pciehpc_list_mutex);
}

/*
 * convert LED state from PCIE HPC definition to hpc_led_state_t
 * definition.
 */
hpc_led_state_t
pciehpc_led_state_to_hpc(uint16_t state)
{
	switch (state) {
	    case PCIE_SLOTCTL_INDICATOR_STATE_ON:
		return (HPC_LED_ON);
	    case PCIE_SLOTCTL_INDICATOR_STATE_BLINK:
		return (HPC_LED_BLINK);
	    case PCIE_SLOTCTL_INDICATOR_STATE_OFF:
	    default:
		return (HPC_LED_OFF);
	}
}

/*
 * convert LED state from hpc_led_state_t definition to PCIE HPC
 * definition.
 */
uint16_t
pciehpc_led_state_to_pciehpc(hpc_led_state_t state)
{
	switch (state) {
	    case HPC_LED_ON:
		return (PCIE_SLOTCTL_INDICATOR_STATE_ON);
	    case HPC_LED_BLINK:
		return (PCIE_SLOTCTL_INDICATOR_STATE_BLINK);
	    case HPC_LED_OFF:
	    default:
		return (PCIE_SLOTCTL_INDICATOR_STATE_OFF);
	}
}

/*
 * Initialize HPC hardware, install interrupt handler, etc. It doesn't
 * enable hot plug interrupts.
 *
 * (Note: It is called only from pciehpc_init().)
 */
int
pciehpc_hpc_init(pciehpc_t *ctrl_p)
{
	uint16_t reg;

	/* read the Slot Control Register */
	reg = pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	/* disable all interrupts */
	reg &= ~(SLOTCTL_SUPPORTED_INTRS_MASK);
	pciehpc_reg_put16(ctrl_p, ctrl_p->pcie_caps_reg_offset +
		PCIE_SLOTCTL, reg);

	/* clear any interrupt status bits */
	reg = pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);
	pciehpc_reg_put16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS, reg);

	/* initialize the interrupt mutex */
	mutex_init(&ctrl_p->pciehpc_mutex, NULL, MUTEX_DRIVER,
		(void *)PCIEHPC_INTR_PRI);

	return (DDI_SUCCESS);
}

/*
 * Uninitialize HPC hardware, uninstall interrupt handler, etc.
 *
 * (Note: It is called only from pciehpc_uninit().)
 */
int
pciehpc_hpc_uninit(pciehpc_t *ctrl_p)
{
	/* disable interrupts */
	(void) pciehpc_disable_intr(ctrl_p);

	/* destroy the mutex */
	mutex_destroy(&ctrl_p->pciehpc_mutex);

	return (DDI_SUCCESS);
}

/*
 * Disable hot plug interrupts.
 * Note: this is only for Native hot plug mode.
 */
int
pciehpc_disable_intr(pciehpc_t *ctrl_p)
{
	uint16_t reg;

	/* read the Slot Control Register */
	reg = pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	/* disable all interrupts */
	reg &= ~(SLOTCTL_SUPPORTED_INTRS_MASK);
	pciehpc_reg_put16(ctrl_p, ctrl_p->pcie_caps_reg_offset +
		PCIE_SLOTCTL, reg);

	/* clear any interrupt status bits */
	reg = pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);
	pciehpc_reg_put16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS, reg);

	return (DDI_SUCCESS);
}

/*
 * Enable hot plug interrupts.
 * Note: this is only for Native hot plug mode.
 */
int
pciehpc_enable_intr(pciehpc_t *ctrl_p)
{
	uint16_t reg;

	/* clear any interrupt status bits */
	reg = pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);
	pciehpc_reg_put16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS, reg);

	/* read the Slot Control Register */
	reg = pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	/*
	 * enable interrupts: power fault detection interrupt is enabled
	 * only when the slot is 'connected', i.e. power is ON
	 */
	if (ctrl_p->slot.slot_state == HPC_SLOT_CONNECTED)
		pciehpc_reg_put16(ctrl_p, ctrl_p->pcie_caps_reg_offset +
			PCIE_SLOTCTL, reg | SLOTCTL_SUPPORTED_INTRS_MASK);
	else
		pciehpc_reg_put16(ctrl_p, ctrl_p->pcie_caps_reg_offset +
			PCIE_SLOTCTL, reg | (SLOTCTL_SUPPORTED_INTRS_MASK &
					~PCIE_SLOTCTL_PWR_FAULT_EN));

	return (DDI_SUCCESS);
}

/*
 * Register the PCI-E hot plug slot with HPS framework.
 */
int
pciehpc_register_slot(pciehpc_t *ctrl_p)
{
	char nexus_path[MAXNAMELEN];
	pciehpc_slot_t *p = &ctrl_p->slot;

	/* get nexus path name */
	(void) ddi_pathname(ctrl_p->dip, nexus_path);

	/* register the slot with HPS framework */
	if (hpc_slot_register(ctrl_p->dip, nexus_path,
	    &p->slot_info, &p->slot_handle,
	    &p->slot_ops, (caddr_t)ctrl_p, 0) != 0) {
		PCIEHPC_DEBUG((CE_WARN,
		    "pciehpc_register_slot() failed to register slot %d\n",
		    p->slotNum));
		return (DDI_FAILURE);
	}

	PCIEHPC_DEBUG3((CE_NOTE,
	    "pciehpc_register_slot(): registered slot %d\n", p->slotNum));
	return (DDI_SUCCESS);
}

/*
 * Unregister the PCI-E hot plug slot from the HPS framework.
 */
int
pciehpc_unregister_slot(pciehpc_t *ctrl_p)
{
	pciehpc_slot_t *p = &ctrl_p->slot;

	if (hpc_slot_unregister(&p->slot_handle) != 0) {
		PCIEHPC_DEBUG((CE_WARN,
		    "pciehpc_unregister_slot() failed to unregister slot %d\n",
		    p->slotNum));
		return (DDI_FAILURE);
	}
	PCIEHPC_DEBUG3((CE_NOTE,
	    "pciehpc_unregister_slot(): unregistered slot %d\n", p->slotNum));
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
	pciehpc_t *ctrl_p;
	uint16_t status, control;

	/* get the soft state structure for this dip */
	if ((ctrl_p = pciehpc_get_soft_state(dip)) == NULL)
		return (DDI_INTR_UNCLAIMED);

	mutex_enter(&ctrl_p->pciehpc_mutex);

	/* make sure the controller soft state is initialized */
	if (ctrl_p->soft_state & PCIEHPC_SOFT_STATE_UNINITIALIZED) {
		mutex_exit(&ctrl_p->pciehpc_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	/* if it is not NATIVE hot plug mode then return */
	if (ctrl_p->hp_mode != PCIEHPC_NATIVE_HP_MODE) {
		mutex_exit(&ctrl_p->pciehpc_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	/* read the current slot status register */
	status = pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);

	/* check if there are any hot plug interrupts occurred */
	if (!(status & SLOT_STATUS_EVENTS)) {
		/* no hot plug events occurred */
		mutex_exit(&ctrl_p->pciehpc_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	/* clear the interrupt status bits */
	pciehpc_reg_put16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS, status);

	/* check for CMD COMPLETE interrupt */
	if (status & PCIE_SLOTSTS_COMMAND_COMPLETED) {
	    PCIEHPC_DEBUG3((CE_NOTE,
		"pciehpc_intr(): CMD COMPLETED interrupt received\n"));
	    /* wake up any one waiting for Command Completion event */
	    cv_signal(&ctrl_p->slot.cmd_comp_cv);
	}

	/* check for ATTN button interrupt */
	if (status & PCIE_SLOTSTS_ATTN_BTN_PRESSED) {
	    PCIEHPC_DEBUG3((CE_NOTE,
		"pciehpc_intr(): ATTN BUTTON interrupt received\n"));
	    /* if ATTN button event is still pending then cancel it */
	    if (ctrl_p->slot.attn_btn_pending == B_TRUE)
		ctrl_p->slot.attn_btn_pending = B_FALSE;
	    else
		ctrl_p->slot.attn_btn_pending = B_TRUE;
	    /* wake up the ATTN event handler */
	    cv_signal(&ctrl_p->slot.attn_btn_cv);
	}

	/* check for power fault interrupt */
	if (status & PCIE_SLOTSTS_PWR_FAULT_DETECTED) {
	    PCIEHPC_DEBUG3((CE_NOTE,
		"pciehpc_intr(): POWER FAULT interrupt received"
		" on slot %d\n", ctrl_p->slot.slotNum));
	    control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
	    if (control & PCIE_SLOTCTL_PWR_FAULT_EN) {
		/* disable power fault detction interrupt */
		pciehpc_reg_put16(ctrl_p, ctrl_p->pcie_caps_reg_offset +
		    PCIE_SLOTCTL, control & ~PCIE_SLOTCTL_PWR_FAULT_EN);

		/* send the event to HPS framework */
		(void) hpc_slot_event_notify(ctrl_p->slot.slot_handle,
		    HPC_EVENT_SLOT_POWER_FAULT, HPC_EVENT_NORMAL);
	    }
	}

	/* check for MRL SENSOR CHANGED interrupt */
	if (status & PCIE_SLOTSTS_MRL_SENSOR_CHANGED) {
	    PCIEHPC_DEBUG3((CE_NOTE,
		"pciehpc_intr(): MRL SENSOR CHANGED interrupt received"
		" on slot %d\n", ctrl_p->slot.slotNum));
	    /* For now (phase-I), no action is taken on this event */
	}

	/* check for PRESENCE CHANGED interrupt */
	if (status & PCIE_SLOTSTS_PRESENCE_CHANGED) {
	    PCIEHPC_DEBUG3((CE_NOTE,
		"pciehpc_intr(): PRESENCE CHANGED interrupt received"
		" on slot %d\n", ctrl_p->slot.slotNum));

	    if (status & PCIE_SLOTSTS_PRESENCE_DETECTED) {
		/* card is inserted into the slot */

		/* send the event to HPS framework */
		(void) hpc_slot_event_notify(ctrl_p->slot.slot_handle,
		    HPC_EVENT_SLOT_INSERTION, HPC_EVENT_NORMAL);
	    } else {
		/* card is removed from the slot */

		/* make sure to disable power fault detction interrupt */
		control =  pciehpc_reg_get16(ctrl_p,
		    ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
		if (control & PCIE_SLOTCTL_PWR_FAULT_EN)
		    pciehpc_reg_put16(ctrl_p, ctrl_p->pcie_caps_reg_offset +
			PCIE_SLOTCTL, control & ~PCIE_SLOTCTL_PWR_FAULT_EN);

		/* send the event to HPS framework */
		(void) hpc_slot_event_notify(ctrl_p->slot.slot_handle,
		    HPC_EVENT_SLOT_REMOVAL, HPC_EVENT_NORMAL);
	    }
	}

	/* check for DLL state changed interrupt */
	if (ctrl_p->dll_active_rep &&
		(status & PCIE_SLOTSTS_DLL_STATE_CHANGED)) {
	    PCIEHPC_DEBUG3((CE_NOTE,
		"pciehpc_intr(): DLL STATE CHANGED interrupt received"
		" on slot %d\n", ctrl_p->slot.slotNum));

	    cv_signal(&ctrl_p->slot.dll_active_cv);
	}

	mutex_exit(&ctrl_p->pciehpc_mutex);

	return (DDI_INTR_CLAIMED);
}

#ifdef DEBUG
/*
 * Dump PCI-E Hot Plug registers.
 */
static void
pciehpc_dump_hpregs(pciehpc_t *ctrl_p)
{
	uint16_t control;
	uint32_t capabilities;

	capabilities = pciehpc_reg_get32(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCAP);

	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	cmn_err(CE_NOTE, "pciehpc_dump_hpregs: Found PCI-E hot plug slot %d\n",
		ctrl_p->slot.slotNum);
	cmn_err(CE_NOTE, "Attention Button Present = %s",
	    capabilities & PCIE_SLOTCAP_ATTN_BUTTON ? "Yes":"No");

	cmn_err(CE_NOTE, "Power controller Present = %s",
	    capabilities & PCIE_SLOTCAP_POWER_CONTROLLER ? "Yes":"No");

	cmn_err(CE_NOTE, "MRL Sensor Present       = %s",
	    capabilities & PCIE_SLOTCAP_MRL_SENSOR ? "Yes":"No");

	cmn_err(CE_NOTE, "Attn Indicator Present   = %s",
	    capabilities & PCIE_SLOTCAP_ATTN_INDICATOR ? "Yes":"No");

	cmn_err(CE_NOTE, "Power Indicator Present  = %s",
	    capabilities & PCIE_SLOTCAP_PWR_INDICATOR ? "Yes":"No");

	cmn_err(CE_NOTE, "HotPlug Surprise         = %s",
	    capabilities & PCIE_SLOTCAP_HP_SURPRISE ? "Yes":"No");

	cmn_err(CE_NOTE, "HotPlug Capable          = %s",
	    capabilities & PCIE_SLOTCAP_HP_CAPABLE ? "Yes":"No");

	cmn_err(CE_NOTE, "Physical Slot Number     = %d",
	    PCIE_SLOTCAP_PHY_SLOT_NUM(capabilities));

	cmn_err(CE_NOTE, "Attn Button interrupt Enabled  = %s",
	    control & PCIE_SLOTCTL_ATTN_BTN_EN ? "Yes":"No");

	cmn_err(CE_NOTE, "Power Fault interrupt Enabled  = %s",
	    control & PCIE_SLOTCTL_PWR_FAULT_EN ? "Yes":"No");

	cmn_err(CE_NOTE, "MRL Sensor INTR Enabled   = %s",
	    control & PCIE_SLOTCTL_MRL_SENSOR_EN ? "Yes":"No");

	cmn_err(CE_NOTE, "Presence interrupt Enabled     = %s",
	    control & PCIE_SLOTCTL_PRESENCE_CHANGE_EN ? "Yes":"No");

	cmn_err(CE_NOTE, "Cmd Complete interrupt Enabled = %s",
	    control & PCIE_SLOTCTL_CMD_INTR_EN ? "Yes":"No");

	cmn_err(CE_NOTE, "HotPlug interrupt Enabled      = %s",
	    control & PCIE_SLOTCTL_HP_INTR_EN ? "Yes":"No");

	cmn_err(CE_NOTE, "Power Indicator LED = %s", pciehpc_led_state_text(
	    pciehpc_led_state_to_hpc(pcie_slotctl_pwr_indicator_get(control))));

	cmn_err(CE_NOTE, "Attn Indicator LED = %s",
	    pciehpc_led_state_text(pciehpc_led_state_to_hpc(
			pcie_slotctl_attn_indicator_get(control))));
}

static char *
pciehpc_led_state_text(hpc_led_state_t state)
{
	switch (state) {
		case HPC_LED_ON:
			return ("on");
		case HPC_LED_OFF:
			return ("off");
		case HPC_LED_BLINK:
		default:
			return ("blink");
	}
}
#endif /* DEBUG */

/*
 * pciehpc_slot_connect()
 *
 * Connect power to the PCI-E slot.
 *
 * Returns: HPC_SUCCESS if the slot is powered up and enabled.
 *	    HPC_ERR_FAILED if the slot can't be enabled.
 *
 * (Note: This function is called by HPS framework at kernel context only.)
 */
/*ARGSUSED*/
int
pciehpc_slot_connect(caddr_t ops_arg, hpc_slot_t slot_hdl,
	void *data, uint_t flags)
{
	uint16_t status, control;

	pciehpc_t *ctrl_p = (pciehpc_t *)ops_arg;

	ASSERT(slot_hdl == ctrl_p->slot.slot_handle);

	mutex_enter(&ctrl_p->pciehpc_mutex);

	/* get the current state of the slot */
	pciehpc_get_slot_state(ctrl_p);

	/* check if the slot is already in the 'connected' state */
	if (ctrl_p->slot.slot_state == HPC_SLOT_CONNECTED) {
		/* slot is already in the 'connected' state */
		PCIEHPC_DEBUG3((CE_NOTE,
		    "pciehpc_slot_connect() slot %d already connected\n",
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
		cmn_err(CE_WARN, "MRL switch is open on slot %d\n",
			ctrl_p->slot.slotNum);
		goto cleanup;
	}

	/* make sure the slot has a device present */
	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED)) {
		/* slot is empty */
		PCIEHPC_DEBUG((CE_NOTE,
		    "slot %d is empty\n", ctrl_p->slot.slotNum));
		goto cleanup;
	}

	/* get the current state of Slot Control Register */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	/* check if the slot's power state is ON */
	if (!(control & PCIE_SLOTCTL_PWR_CONTROL)) {
		/* slot is already powered up */
		PCIEHPC_DEBUG3((CE_NOTE,
		    "pciehpc_slot_connect() slot %d already connected\n",
		    ctrl_p->slot.slotNum));
		ctrl_p->slot.slot_state = HPC_SLOT_CONNECTED;
		mutex_exit(&ctrl_p->pciehpc_mutex);
		return (HPC_SUCCESS);
	}

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
	pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_BLINK);
	pciehpc_set_led_state(ctrl_p, HPC_ATTN_LED, HPC_LED_OFF);

	/* 2. set power control to ON */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
	control &= ~PCIE_SLOTCTL_PWR_CONTROL;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/* 3. wait for DLL State Change event, if it's supported */
	if (ctrl_p->dll_active_rep) {
		status =  pciehpc_reg_get16(ctrl_p,
		    ctrl_p->pcie_caps_reg_offset + PCIE_LINKSTS);

		if (!(status & PCIE_LINKSTS_DLL_LINK_ACTIVE)) {
			/* wait 1 sec for the DLL State Changed event */
			(void) cv_timedwait(&ctrl_p->slot.dll_active_cv,
			    &ctrl_p->pciehpc_mutex,
			    ddi_get_lbolt() +
			    SEC_TO_TICK(PCIEHPC_DLL_STATE_CHANGE_TIMEOUT));

			/* check Link status */
			status =  pciehpc_reg_get16(ctrl_p,
			    ctrl_p->pcie_caps_reg_offset +
			    PCIE_LINKSTS);
			if (!(status & PCIE_LINKSTS_DLL_LINK_ACTIVE))
				goto cleanup2;
		}

		/* wait 100ms after DLL_LINK_ACTIVE field reads 1b */
		delay(drv_usectohz(100000));
	} else {
		/* wait 1 sec for link to come up */
		delay(drv_usectohz(1000000));
	}

	/* check power is really turned ON */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
	if (control & PCIE_SLOTCTL_PWR_CONTROL) {
		PCIEHPC_DEBUG((CE_NOTE,
		    "slot %d fails to turn on power on connect\n",
		    ctrl_p->slot.slotNum));

		goto cleanup1;
	}

	/* clear power fault status */
	status =  pciehpc_reg_get16(ctrl_p,
	    ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);
	status |= PCIE_SLOTSTS_PWR_FAULT_DETECTED;
	pciehpc_reg_put16(ctrl_p, ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS,
	    status);

	/* enable power fault detection interrupt */
	control |= PCIE_SLOTCTL_PWR_FAULT_EN;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/* 4. Set power LED to be ON */
	pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_ON);

	/* if EMI is present, turn it ON */
	if (ctrl_p->has_emi_lock) {
		status =  pciehpc_reg_get16(ctrl_p,
		    ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);

		if (!(status & PCIE_SLOTSTS_EMI_LOCK_SET)) {
			control =  pciehpc_reg_get16(ctrl_p,
			    ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
			control |= PCIE_SLOTCTL_EMI_LOCK_CONTROL;
			pciehpc_issue_hpc_command(ctrl_p, control);

			/* wait 1 sec after toggling the state of EMI lock */
			delay(drv_usectohz(1000000));
		}
	}

	ctrl_p->slot.slot_state = HPC_SLOT_CONNECTED;
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_SUCCESS);

cleanup2:
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
	/* if power is ON, set power control to OFF */
	if (!(control & PCIE_SLOTCTL_PWR_CONTROL)) {
		control |= PCIE_SLOTCTL_PWR_CONTROL;
		pciehpc_issue_hpc_command(ctrl_p, control);
	}

cleanup1:
	/* set power led to OFF */
	pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_OFF);

cleanup:
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_ERR_FAILED);
}

/*
 * pciehpc_slot_disconnect()
 *
 * Disconnect power to the slot.
 *
 * Returns: HPC_SUCCESS if the slot is powered up and enabled.
 *	    HPC_ERR_FAILED if the slot can't be enabled.
 *
 * (Note: This function is called by HPS framework at kernel context only.)
 */
/*ARGSUSED*/
int
pciehpc_slot_disconnect(caddr_t ops_arg, hpc_slot_t slot_hdl,
	void *data, uint_t flags)
{
	uint16_t status;
	uint16_t control;

	pciehpc_t *ctrl_p = (pciehpc_t *)ops_arg;

	ASSERT(slot_hdl == ctrl_p->slot.slot_handle);

	mutex_enter(&ctrl_p->pciehpc_mutex);

	/* get the current state of the slot */
	pciehpc_get_slot_state(ctrl_p);

	/* check if the slot is already in the 'disconnected' state */
	if (ctrl_p->slot.slot_state == HPC_SLOT_DISCONNECTED) {
		/* slot is in the 'disconnected' state */
		PCIEHPC_DEBUG3((CE_NOTE,
		    "pciehpc_slot_disconnect(): slot %d already disconnected\n",
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
		PCIEHPC_DEBUG((CE_NOTE,
		    "pciehpc_slot_disconnect(): slot %d is empty\n",
		    ctrl_p->slot.slotNum));
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
	pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_BLINK);

	/* disable power fault detection interrupt */
	control = pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
	control &= ~PCIE_SLOTCTL_PWR_FAULT_EN;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/* 2. set power control to OFF */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
	control |= PCIE_SLOTCTL_PWR_CONTROL;
	pciehpc_issue_hpc_command(ctrl_p, control);

#ifdef DEBUG
	/* check for power control bit to be OFF */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
	ASSERT(control & PCIE_SLOTCTL_PWR_CONTROL);
#endif

	/* 3. Set power LED to be OFF */
	pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_OFF);
	pciehpc_set_led_state(ctrl_p, HPC_ATTN_LED, HPC_LED_OFF);

	/* if EMI is present, turn it OFF */
	if (ctrl_p->has_emi_lock) {
		status =  pciehpc_reg_get16(ctrl_p,
		    ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);

		if (status & PCIE_SLOTSTS_EMI_LOCK_SET) {
			control =  pciehpc_reg_get16(ctrl_p,
			    ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
			control |= PCIE_SLOTCTL_EMI_LOCK_CONTROL;
			pciehpc_issue_hpc_command(ctrl_p, control);

			/* wait 1 sec after toggling the state of EMI lock */
			delay(drv_usectohz(1000000));
		}
	}

	ctrl_p->slot.slot_state = HPC_SLOT_DISCONNECTED;
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_SUCCESS);

cleanup:
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_ERR_FAILED);
}

/*ARGSUSED*/
int
pciehpc_slot_control(caddr_t ops_arg, hpc_slot_t slot_hdl,
	int request, caddr_t arg)
{
	pciehpc_t	*ctrl_p;
	hpc_led_info_t	*led_info;
	int		ret = HPC_SUCCESS;

	ctrl_p = (pciehpc_t *)ops_arg;

	ASSERT(ctrl_p != NULL);

	mutex_enter(&ctrl_p->pciehpc_mutex);

	/* get the current slot state */
	pciehpc_get_slot_state(ctrl_p);

	switch (request) {

	    case HPC_CTRL_GET_SLOT_STATE:
		*(hpc_slot_state_t *)arg = ctrl_p->slot.slot_state;
		break;

	    case HPC_CTRL_GET_BOARD_TYPE:
		if (ctrl_p->slot.slot_state == HPC_SLOT_EMPTY)
			*(hpc_board_type_t *)arg = HPC_BOARD_UNKNOWN;
		else
			*(hpc_board_type_t *)arg = HPC_BOARD_PCI_HOTPLUG;
		break;

	    case HPC_CTRL_GET_LED_STATE:
		led_info = (hpc_led_info_t *)arg;
		switch (led_info->led) {
		    case HPC_ATTN_LED:
			led_info->state = ctrl_p->slot.attn_led_state;
			break;
		    case HPC_POWER_LED:
			led_info->state = ctrl_p->slot.power_led_state;
			break;
		    case HPC_FAULT_LED:
		    case HPC_ACTIVE_LED:
			led_info->state = HPC_LED_OFF;
			break;
		    default:
			PCIEHPC_DEBUG((CE_WARN, "pciehpc_slot_control:"
			    " unknown led state\n"));
			ret = HPC_ERR_NOTSUPPORTED;
			break;
		}
		break;
	    case HPC_CTRL_SET_LED_STATE:
		led_info = (hpc_led_info_t *)arg;
		switch (led_info->led) {
		    case HPC_ATTN_LED:
			pciehpc_set_led_state(ctrl_p, led_info->led,
				led_info->state);
			break;
		    case HPC_POWER_LED:
			PCIEHPC_DEBUG((CE_WARN, "pciehpc_slot_control: power"
			    " LED control is not allowed on slot #%d\n",
			    ctrl_p->slot.slotNum));
			ret = HPC_ERR_NOTSUPPORTED;
			break;
		    case HPC_FAULT_LED:
		    case HPC_ACTIVE_LED:
			break;
		    default:
			PCIEHPC_DEBUG((CE_WARN, "pciehpc_slot_control:"
			    " unknown led type %d\n", led_info->led));
			ret = HPC_ERR_NOTSUPPORTED;
			break;
		}
		break;
	    case HPC_CTRL_DEV_CONFIG_FAILURE:
		/* turn the ATTN led ON for configure failure */
		pciehpc_set_led_state(ctrl_p, HPC_ATTN_LED, HPC_LED_ON);
		/* if power to the slot is still on then set Power led to ON */
		if (ctrl_p->slot.slot_state == HPC_SLOT_CONNECTED)
		    pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_ON);
		break;
	    case HPC_CTRL_DEV_UNCONFIG_FAILURE:
		/* if power to the slot is still on then set Power led to ON */
		if (ctrl_p->slot.slot_state == HPC_SLOT_CONNECTED)
		    pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_ON);
		pciehpc_enable_errors(ctrl_p);
		break;
	    case HPC_CTRL_ENABLE_AUTOCFG:
	    case HPC_CTRL_DISABLE_AUTOCFG:
		/* no action is needed here */
		break;

	    case HPC_CTRL_DISABLE_SLOT:
	    case HPC_CTRL_ENABLE_SLOT:
		/* no action is needed here */
		break;

	    case HPC_CTRL_DEV_CONFIG_START:
	    case HPC_CTRL_DEV_UNCONFIG_START:
		pciehpc_disable_errors(ctrl_p);
		/* no action is needed here */
		break;
	    case HPC_CTRL_DEV_CONFIGURED:
	    case HPC_CTRL_DEV_UNCONFIGURED:
		/* no action is needed here */
		if (request == HPC_CTRL_DEV_CONFIGURED) {
			pciehpc_enable_errors(ctrl_p);
		}
		break;
	    default:
		PCIEHPC_DEBUG((CE_WARN,
		    "pciehpc_slot_control: unsupported operation\n"));
		ret = HPC_ERR_NOTSUPPORTED;
	}

	mutex_exit(&ctrl_p->pciehpc_mutex);

	return (ret);
}

/*
 * Get the state of an LED.
 */
hpc_led_state_t
pciehpc_get_led_state(pciehpc_t *ctrl_p, hpc_led_t led)
{
	uint16_t control;
	uint16_t state;

	/* get the current state of Slot Control register */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	switch (led) {
	    case HPC_POWER_LED:
		state = pcie_slotctl_pwr_indicator_get(control);
		break;
	    case HPC_ATTN_LED:
		state = pcie_slotctl_attn_indicator_get(control);
		break;
	    default:
		PCIEHPC_DEBUG((CE_WARN,
		    "pciehpc_get_led_state() invalid LED %d\n", led));
		return (HPC_LED_OFF);
	}

	switch (state) {
	    case PCIE_SLOTCTL_INDICATOR_STATE_ON:
		return (HPC_LED_ON);

	    case PCIE_SLOTCTL_INDICATOR_STATE_BLINK:
		return (HPC_LED_BLINK);

	    case PCIE_SLOTCTL_INDICATOR_STATE_OFF:
	    default:
		return (HPC_LED_OFF);
	}
}

/*
 * Set the state of an LED. It updates both hw and sw state.
 */
void
pciehpc_set_led_state(pciehpc_t *ctrl_p, hpc_led_t led, hpc_led_state_t state)
{
	uint16_t control;

	/* get the current state of Slot Control register */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	switch (led) {
	    case HPC_POWER_LED:
		/* clear led mask */
		control &= ~PCIE_SLOTCTL_PWR_INDICATOR_MASK;
		ctrl_p->slot.power_led_state = state;
		break;
	    case HPC_ATTN_LED:
		/* clear led mask */
		control &= ~PCIE_SLOTCTL_ATTN_INDICATOR_MASK;
		ctrl_p->slot.attn_led_state = state;
		break;
	    default:
		PCIEHPC_DEBUG((CE_WARN,
		    "pciehpc_set_led_state() invalid LED %d\n", led));
		return;
	}

	switch (state) {
	    case HPC_LED_ON:
		if (led == HPC_POWER_LED)
		    control = pcie_slotctl_pwr_indicator_set(control,
					PCIE_SLOTCTL_INDICATOR_STATE_ON);
		else if (led == HPC_ATTN_LED)
		    control = pcie_slotctl_attn_indicator_set(control,
					PCIE_SLOTCTL_INDICATOR_STATE_ON);
		break;
	    case HPC_LED_OFF:
		if (led == HPC_POWER_LED)
		    control = pcie_slotctl_pwr_indicator_set(control,
					PCIE_SLOTCTL_INDICATOR_STATE_OFF);
		else if (led == HPC_ATTN_LED)
		    control = pcie_slotctl_attn_indicator_set(control,
					PCIE_SLOTCTL_INDICATOR_STATE_OFF);
		break;
	    case HPC_LED_BLINK:
		if (led == HPC_POWER_LED)
		    control = pcie_slotctl_pwr_indicator_set(control,
					PCIE_SLOTCTL_INDICATOR_STATE_BLINK);
		else if (led == HPC_ATTN_LED)
		    control = pcie_slotctl_attn_indicator_set(control,
					PCIE_SLOTCTL_INDICATOR_STATE_BLINK);
		break;

	    default:
		PCIEHPC_DEBUG((CE_WARN,
		    "pciehpc_set_led_state() invalid LED state %d\n", state));
		return;
	}

	/* update the Slot Control Register */
	pciehpc_issue_hpc_command(ctrl_p, control);

#ifdef DEBUG
	/* get the current state of Slot Control register */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	PCIEHPC_DEBUG3((CE_NOTE, "pciehpc_set_led_state: "
		"slot %d power-led %s attn-led %s\n",
		ctrl_p->slot.slotNum,
		pciehpc_led_state_text(
		pciehpc_led_state_to_hpc(
		pcie_slotctl_pwr_indicator_get(control))),
		pciehpc_led_state_text(
		pciehpc_led_state_to_hpc(
		pcie_slotctl_attn_indicator_get(control)))));
#endif
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
void
pciehpc_issue_hpc_command(pciehpc_t *ctrl_p, uint16_t control)
{

	uint16_t status;
	uint32_t slot_cap;

	/*
	 * PCI-E version 1.1 spec defines No Command Completed
	 * Support bit (bit#18) in Slot Capabilities register. If this
	 * bit is set then slot doesn't support notification of command
	 * completion events.
	 */
	slot_cap =  pciehpc_reg_get32(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCAP);
	/*
	 * If no Command Completion event is supported or it is ACPI
	 * hot plug mode then just issue the command and return.
	 */
	if ((slot_cap & PCIE_SLOTCAP_NO_CMD_COMP_SUPP) ||
	    (ctrl_p->hp_mode == PCIEHPC_ACPI_HP_MODE)) {
		pciehpc_reg_put16(ctrl_p,
		    ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL, control);
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
	if (!(ctrl_p->soft_state & PCIEHPC_SOFT_STATE_INITIALIZED)) {
		int retry = PCIEHPC_CMD_WAIT_RETRY;

		/* write the command to the HPC */
		pciehpc_reg_put16(ctrl_p,
		    ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL,
		    control);

		/* poll for status completion */
		while (retry--) {
		    /* wait for 10 msec before checking the status */
		    delay(drv_usectohz(PCIEHPC_CMD_WAIT_TIME));

		    status = pciehpc_reg_get16(ctrl_p,
			ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);

		    if (status & PCIE_SLOTSTS_COMMAND_COMPLETED) {
			/* clear the status bits */
			pciehpc_reg_put16(ctrl_p,
			    ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS,
			    status);
			break;
		    }
		}
		return;
	}

	/* HPC is already initialized */

	ASSERT(MUTEX_HELD(&ctrl_p->pciehpc_mutex));

	/*
	 * If previous command is still pending then wait for its
	 * completion. i.e cv_wait()
	 */

	while (ctrl_p->slot.command_pending == B_TRUE)
		cv_wait(&ctrl_p->slot.cmd_comp_cv, &ctrl_p->pciehpc_mutex);

	/*
	 * Issue the command and wait for Command Completion or
	 * the 1 sec timeout.
	 */
	pciehpc_reg_put16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL, control);

	ctrl_p->slot.command_pending = B_TRUE;

	if (cv_timedwait(&ctrl_p->slot.cmd_comp_cv, &ctrl_p->pciehpc_mutex,
		ddi_get_lbolt() + SEC_TO_TICK(1)) == -1) {
		/* it is a timeout */
		PCIEHPC_DEBUG2((CE_NOTE,
		    "pciehpc_issue_hpc_command: Command Complete"
		    " interrupt is not received for slot %d\n",
		    ctrl_p->slot.slotNum));

		/* clear the status info in case interrupts are disabled? */
		status = pciehpc_reg_get16(ctrl_p,
			ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS);

		if (status & PCIE_SLOTSTS_COMMAND_COMPLETED) {
			/* clear the status bits */
			pciehpc_reg_put16(ctrl_p,
			    ctrl_p->pcie_caps_reg_offset + PCIE_SLOTSTS,
			    status);
		}
	}

	ctrl_p->slot.command_pending = B_FALSE;

	/* wake up any one waiting for issuing another command to HPC */
	cv_signal(&ctrl_p->slot.cmd_comp_cv);
}

/*
 * pciehcp_attn_btn_handler()
 *
 * This handles ATTN button pressed event as per the PCI-E 1.1 spec.
 */
static void
pciehpc_attn_btn_handler(pciehpc_t *ctrl_p)
{
	hpc_led_state_t power_led_state;
	callb_cpr_t cprinfo;

	PCIEHPC_DEBUG3((CE_NOTE, "pciehpc_attn_btn_handler: thread started\n"));

	CALLB_CPR_INIT(&cprinfo, &ctrl_p->pciehpc_mutex, callb_generic_cpr,
	    "pciehpc_attn_btn_handler");

	mutex_enter(&ctrl_p->pciehpc_mutex);

	/* wait for ATTN button event */
	cv_wait(&ctrl_p->slot.attn_btn_cv, &ctrl_p->pciehpc_mutex);

	while (ctrl_p->slot.attn_btn_thread_exit == B_FALSE) {

	    if (ctrl_p->slot.attn_btn_pending == B_TRUE) {

		/* get the current state of power LED */
		power_led_state = pciehpc_get_led_state(ctrl_p, HPC_POWER_LED);

		/* Blink the Power LED while we wait for 5 seconds */
		pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_BLINK);

		/* wait for 5 seconds before taking any action */
		if (cv_timedwait(&ctrl_p->slot.attn_btn_cv,
			&ctrl_p->pciehpc_mutex,
			ddi_get_lbolt() + SEC_TO_TICK(5)) == -1) {
			/*
			 * It is a time out; make sure the ATTN pending flag is
			 * still ON before sending the event to HPS framework.
			 */
			if (ctrl_p->slot.attn_btn_pending == B_TRUE) {
			    /* send the ATTN button event to HPS framework */
			    ctrl_p->slot.attn_btn_pending = B_FALSE;
			    (void) hpc_slot_event_notify(
				ctrl_p->slot.slot_handle,
				HPC_EVENT_SLOT_ATTN, HPC_EVENT_NORMAL);
			}
		}
		/* restore the power LED state */
		pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, power_led_state);
		continue;
	    }

	    /* wait for another ATTN button event */
	    cv_wait(&ctrl_p->slot.attn_btn_cv, &ctrl_p->pciehpc_mutex);
	}

	PCIEHPC_DEBUG3((CE_NOTE, "pciehpc_attn_btn_handler: thread exit\n"));
	cv_signal(&ctrl_p->slot.attn_btn_cv);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

/*
 * Read/Write access to HPC registers. If platform nexus has non-standard
 * HPC access mechanism then regops functions are used to do reads/writes.
 */
uint8_t
pciehpc_reg_get8(pciehpc_t *ctrl_p, uint_t off)
{
	PCIEHPC_DEBUG3((CE_NOTE, "read reg8 (offset %x)", off));

	if (ctrl_p->regops.get != NULL)
	    return ((uint8_t)ctrl_p->regops.get(ctrl_p->regops.cookie,
			(off_t)off));
	else
	    return (ddi_get8(ctrl_p->cfghdl,
			(uint8_t *)(ctrl_p->regs_base + off)));
}

uint16_t
pciehpc_reg_get16(pciehpc_t *ctrl_p, uint_t off)
{
	PCIEHPC_DEBUG3((CE_NOTE, "read reg16 (offset %x)", off));

	if (ctrl_p->regops.get != NULL)
	    return ((uint16_t)ctrl_p->regops.get(ctrl_p->regops.cookie,
			(off_t)off));
	else
	    return (ddi_get16(ctrl_p->cfghdl,
			(uint16_t *)(ctrl_p->regs_base + off)));
}

uint32_t
pciehpc_reg_get32(pciehpc_t *ctrl_p, uint_t off)
{
	PCIEHPC_DEBUG3((CE_NOTE, "read reg32 (offset %x)", off));

	if (ctrl_p->regops.get != NULL)
	    return ((uint32_t)ctrl_p->regops.get(ctrl_p->regops.cookie,
			(off_t)off));
	else
	    return (ddi_get32(ctrl_p->cfghdl,
			(uint32_t *)(ctrl_p->regs_base + off)));
}

void
pciehpc_reg_put8(pciehpc_t *ctrl_p, uint_t off, uint8_t val)
{
	PCIEHPC_DEBUG3((CE_NOTE, "write reg8 (offset %x, val %x)",
		off, val));

	if (ctrl_p->regops.put != NULL)
	    ctrl_p->regops.put(ctrl_p->regops.cookie, (off_t)off, (uint_t)val);
	else
	    ddi_put8(ctrl_p->cfghdl,
			(uint8_t *)(ctrl_p->regs_base + off), val);
}

void
pciehpc_reg_put16(pciehpc_t *ctrl_p, uint_t off, uint16_t val)
{
	PCIEHPC_DEBUG3((CE_NOTE, "write reg16 (offset %x, val %x)",
		off, val));

	if (ctrl_p->regops.put != NULL)
	    ctrl_p->regops.put(ctrl_p->regops.cookie, (off_t)off, (uint_t)val);
	else
	    ddi_put16(ctrl_p->cfghdl,
			(uint16_t *)(ctrl_p->regs_base + off), val);
}

void
pciehpc_reg_put32(pciehpc_t *ctrl_p, uint_t off, uint32_t val)
{
	PCIEHPC_DEBUG3((CE_NOTE, "write reg32 (offset %x, val %x)",
		off, val));

	if (ctrl_p->regops.put != NULL)
	    ctrl_p->regops.put(ctrl_p->regops.cookie, (off_t)off, (uint_t)val);
	else
	    ddi_put32(ctrl_p->cfghdl,
			(uint32_t *)(ctrl_p->regs_base + off), val);
}

static void
pciehpc_dev_info(pciehpc_t *ctrl_p)
{
	pci_regspec_t *regspec;
	int reglen;
	dev_info_t *dip = ctrl_p->dip;

	/*
	 * Check if it is a PCIe fabric hotplug nexus. This is specially
	 * not so for Rootcomplex nodes supporting PCIe hotplug.
	 * We save this information so as to implement hardening for
	 * fabric nodes only via pcie services.
	 */
	if (pciehpc_pcie_dev(dip, ctrl_p->cfghdl) == DDI_SUCCESS)
		ctrl_p->soft_state |= PCIEHPC_SOFT_STATE_PCIE_DEV;

	/* Get the device number. */
	if (ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
		"reg", (caddr_t)&regspec, &reglen) != DDI_SUCCESS) {
	    return;
	}

	ctrl_p->bus  = PCI_REG_BUS_G(regspec[0].pci_phys_hi);
	ctrl_p->dev  = PCI_REG_DEV_G(regspec[0].pci_phys_hi);
	ctrl_p->func = PCI_REG_FUNC_G(regspec[0].pci_phys_hi);

	kmem_free(regspec, reglen);

	PCIEHPC_DEBUG3((CE_NOTE, "pciehpc_dev_info: bus=%x, dev=%x, func=%x",
	    ctrl_p->bus, ctrl_p->dev, ctrl_p->func));
}

/*
 * setup slot name/slot-number info.
 */
void
pciehpc_set_slot_name(pciehpc_t *ctrl_p)
{
	pciehpc_slot_t *p = &ctrl_p->slot;
	uchar_t *slotname_data;
	int *slotnum;
	uint_t count;
	int len;
	int invalid_slotnum = 0;
	uint32_t slot_capabilities;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, ctrl_p->dip,
		DDI_PROP_DONTPASS, "physical-slot#", &slotnum, &count) ==
		DDI_PROP_SUCCESS) {
		p->slotNum = slotnum[0];
		ddi_prop_free(slotnum);
	} else {
		slot_capabilities = pciehpc_reg_get32(ctrl_p,
			ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCAP);
		p->slotNum = PCIE_SLOTCAP_PHY_SLOT_NUM(slot_capabilities);
	}

	if (!p->slotNum) { /* platform may not have initialized it */
		PCIEHPC_DEBUG((CE_WARN, "%s#%d: Invalid slot number! ",
				ddi_driver_name(ctrl_p->dip),
				ddi_get_instance(ctrl_p->dip)));
		p->slotNum = pciehpc_reg_get8(ctrl_p, PCI_BCNF_SECBUS);
		invalid_slotnum = 1;
	}

	/*
	 * construct the slot_name:
	 * 	if "slot-names" property exists then use that name
	 *	else if valid slot number exists then it is "pcie<slot-num>".
	 *	else it will be "pcie<sec-bus-number>dev0"
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, ctrl_p->dip, DDI_PROP_DONTPASS,
		"slot-names", (caddr_t)&slotname_data,
		&len) == DDI_PROP_SUCCESS) {
		/*
		 * Note: for PCI-E slots, the device number is always 0 so the
		 * first (and only) string is the slot name for this slot.
		 */
		(void) sprintf(p->slot_info.pci_slot_name,
					(char *)slotname_data + 4);
		kmem_free(slotname_data, len);
	} else {
		if (invalid_slotnum)	/* use device number ie. 0 */
		    (void) snprintf(p->slot_info.pci_slot_name,
			sizeof (p->slot_info.pci_slot_name), "pcie0");
		else
		    (void) snprintf(p->slot_info.pci_slot_name,
			sizeof (p->slot_info.pci_slot_name), "pcie%d",
			p->slotNum);
	}
}

/*ARGSUSED*/
static int
pciehpc_pcie_dev(dev_info_t *dip, ddi_acc_handle_t handle)
{
	/* get parent device's device_type property */
	char *device_type;
	int rc;
	dev_info_t *pdip = ddi_get_parent(dip);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip,
		DDI_PROP_DONTPASS, "device_type", &device_type)
			!= DDI_PROP_SUCCESS) {
		PCIEHPC_DEBUG2((CE_NOTE, "device_type property missing for "
			"%s#%d", ddi_get_name(pdip), ddi_get_instance(pdip)));
		return (DDI_FAILURE);
	}

	PCIEHPC_DEBUG((CE_NOTE, "device_type=<%s>\n", device_type));
	rc = DDI_FAILURE;
	if (strcmp(device_type, "pciex") == 0)
		rc = DDI_SUCCESS;
	ddi_prop_free(device_type);
	return (rc);
}

static void
pciehpc_disable_errors(pciehpc_t *ctrl_p)
{
	if (ctrl_p->soft_state & PCIEHPC_SOFT_STATE_PCIE_DEV) {
		PCIE_DISABLE_ERRORS(ctrl_p->dip);
		PCIEHPC_DEBUG3((CE_NOTE, "%s%d: pciehpc_disable_errors\n",
		    ddi_driver_name(ctrl_p->dip),
		    ddi_get_instance(ctrl_p->dip)));
	}
}

static void
pciehpc_enable_errors(pciehpc_t *ctrl_p)
{
	if (ctrl_p->soft_state & PCIEHPC_SOFT_STATE_PCIE_DEV) {
		(void) PCIE_ENABLE_ERRORS(ctrl_p->dip);
		PCIEHPC_DEBUG3((CE_NOTE, "%s%d: pciehpc_enable_errors\n",
		    ddi_driver_name(ctrl_p->dip),
		    ddi_get_instance(ctrl_p->dip)));
	}
}
