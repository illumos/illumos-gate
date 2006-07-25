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
 *  Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 *  Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CK8-04 specific interfaces used in PCIEHPC driver module (X86 only).
 */

#include <sys/types.h>
#include <sys/note.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/autoconf.h>
#include <sys/varargs.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/time.h>
#include <sys/callb.h>
#include "pciehpc_nvidia.h"

static int ck804_slot_connect(caddr_t, hpc_slot_t, void *, uint_t);
static int ck804_slot_disconnect(caddr_t, hpc_slot_t, void *, uint_t);
static int ck804_slotinfo_init(pciehpc_t *);
static int ck804_slotinfo_uninit(pciehpc_t *);
static void ck804_slot_refclk(pciehpc_t *, int);
static int ck804_map_regs(pciehpc_t *);
static void ck804_unmap_regs(pciehpc_t *);
static dev_info_t *ck804_find_lpc_bridge(pciehpc_t *);
static int match_lpc_dev(dev_info_t *, void *);
static uint16_t ck804_reg_get16(pciehpc_t *, uint_t);
static void ck804_reg_put16(pciehpc_t *, uint_t, uint16_t);

#ifdef DEBUG
static void ck804_dump_pci_common_config(pciehpc_t *);
static void ck804_dump_pci_device_config(pciehpc_t *);
static void ck804_dump_pci_bridge_config(pciehpc_t *);
static void ck804_dump_hpregs(pciehpc_t *);
static char *pciehpc_led_state_text(hpc_led_state_t);
#endif

/*
 * setup CK8-04 specific functions if necessary for this platform.
 */
void
pciehpc_ck804_update_ops(pciehpc_t *ctrl_p)
{
	int *vendor_id = 0;
	int *device_id = 0;
	int *revision_id = 0;
	uint_t count;
	dev_info_t *dip = ctrl_p->dip;

	/*
	 * check if this is a ck8-04 platform and revision A3 bridge
	 * controller
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "vendor-id", &vendor_id, &count) != DDI_PROP_SUCCESS) {
		return;
	}
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", &device_id, &count) != DDI_PROP_SUCCESS) {
		ddi_prop_free(vendor_id);
		return;
	}
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "revision-id", &revision_id, &count) != DDI_PROP_SUCCESS) {
		ddi_prop_free(vendor_id);
		ddi_prop_free(device_id);
		return;
	}

	if ((*vendor_id == NVIDIA_VENDOR_ID) &&
	    (*device_id == CK804_DEVICE_ID) &&
	    (*revision_id == 0xa3)) {
		/*
		 * Need special handling for CK8-04 native mode hot plug
		 * operations. Update ops vector.
		 */
		ctrl_p->ops.init_hpc_slotinfo = ck804_slotinfo_init;
		ctrl_p->ops.uninit_hpc_slotinfo = ck804_slotinfo_uninit;
	}

	ddi_prop_free(vendor_id);
	ddi_prop_free(device_id);
	ddi_prop_free(revision_id);
}

/*
 * ck804_slot_connect()
 *
 * Connect power to the PCI-E slot on CK8-04 based platform.
 * The current CK8-04 implementations require special sequence
 * which is slightly different from the standard sequence.
 * This function is equivalent to pciehpc_slot_connect() with
 * specific changes for CK8-04 native hot plug implementation.
 *
 * NOTE: This code may be applicable only on the specific
 * implementations of CK8-04. The future revisions of CK8-04
 * may be different. For now, this code is used on all CK8-04
 * based platforms.
 *
 * Returns: HPC_SUCCESS if the slot is powered up and enabled.
 *	    HPC_ERR_FAILED if the slot can't be enabled.
 *
 * (Note: This function is called by HPS framework at kernel context only.)
 */
/*ARGSUSED*/
static int
ck804_slot_connect(caddr_t ops_arg, hpc_slot_t slot_hdl,
	void *data, uint_t flags)
{
	uint16_t status;
	uint16_t control;
	uint16_t x_control;
	uint16_t x_status;
	int wait_time;
	uint32_t vend_xp;

	pciehpc_t *ctrl_p = (pciehpc_t *)ops_arg;

	ASSERT(slot_hdl == ctrl_p->slot.slot_handle);

	mutex_enter(&ctrl_p->pciehpc_mutex);

	/* get the current state of the slot */
	pciehpc_get_slot_state(ctrl_p);

	/* check if the slot is already in the 'connected' state */
	if (ctrl_p->slot.slot_state == HPC_SLOT_CONNECTED) {
		/* slot is already in the 'connected' state */
		PCIEHPC_DEBUG3((CE_NOTE,
		    "ck804_slot_connect() slot %d already connected\n",
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
		cmn_err(CE_WARN, "MRL switch is open on slot #%d\n",
			ctrl_p->slot.slotNum);
		goto cleanup;
	}

	/* make sure the slot has a device present */
	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED)) {
		/* slot is empty */
		PCIEHPC_DEBUG((CE_NOTE,
		    "slot #%d is empty\n", ctrl_p->slot.slotNum));
		goto cleanup;
	}

	/* get the current state of Slot Control Register */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	/* check if the slot's power state is ON */
	if (!(control & PCIE_SLOTCTL_PWR_CONTROL)) {
		/* slot is already powered up */
		PCIEHPC_DEBUG((CE_NOTE,
		    "ck804_slot_connect() slot %d already connected\n",
		    ctrl_p->slot.slotNum));
		ctrl_p->slot.slot_state = HPC_SLOT_CONNECTED;
		mutex_exit(&ctrl_p->pciehpc_mutex);
		return (HPC_SUCCESS);
	}

	/*
	 * Enable power to the slot involves:
	 *	1. Set power LED to blink and ATTN led to OFF.
	 *	2. Set power control ON in Slot Control Reigster.
	 *	3. Poll NV_XVR_SLOT_STS_PWROK bit in ext status reg to be up.
	 *	4. Set power LED to be ON.
	 *	5. Enable REFCLK for the slot in MCP_NVA_TGIO_CTRL register.
	 *	6. Set NV_XVR_SLOT_CTRL_SAFE bit in the extended control reg.
	 *	7. Poll link-up status bit NV_XVR_VEND_XP_DL_UP.
	 */

	x_control = pciehpc_reg_get16(ctrl_p, NV_SVR_SLOT_CONTROL_REG);
	x_status = pciehpc_reg_get16(ctrl_p, NV_SVR_SLOT_STATUS_REG);
	PCIEHPC_DEBUG3((CE_NOTE,
	    "ck804_slot_connect() x_control %x, x_status %x"
	    " for slot %d\n", x_control, x_status, ctrl_p->slot.slotNum));

	/* make sure REFCLK is off for this slot? */
	ck804_slot_refclk(ctrl_p, DISABLE_REFCLK);

	/* 1. set power LED to blink & ATTN led to OFF */
	pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_BLINK);
	pciehpc_set_led_state(ctrl_p, HPC_ATTN_LED, HPC_LED_OFF);

	/* 2. set power control to ON */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
	control &= ~PCIE_SLOTCTL_PWR_CONTROL;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/*
	 * 3. Poll NV_XVR_SLOT_STS_PWROK bit in Extended Slot Status
	 *    register to be up.
	 */
	wait_time = 200; /* 2 seconds of clock ticks OK? */
	for (;;) {

	    x_status = pciehpc_reg_get16(ctrl_p, NV_SVR_SLOT_STATUS_REG);

	    if (x_status & NV_SVR_SLOT_STS_PWROK)
		break;

	    if (wait_time <=  0) {
		cmn_err(CE_WARN, "ck804_slot_connect: time out in waiting"
			" for PWROK on slot %d\n", ctrl_p->slot.slotNum);
		/* should we turn off power? */
		goto cleanup;
	    }

	    wait_time -= 10;
	    delay(10); /* wait for 10 ticks */
	}

	/* 4. Set power LED to be ON */
	pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_ON);

	/* 5. Enable REFCLK for the slot in MCP_NVA_TGIO_CTRL register */
	ck804_slot_refclk(ctrl_p, ENABLE_REFCLK);

	/* 6. Set NV_XVR_SLOT_CTRL_SAFE bit in the extended control reg */
	pciehpc_reg_put16(ctrl_p, NV_SVR_SLOT_CONTROL_REG,
		x_control | NV_SVR_SLOT_CTRL_SAFE);

	/* 7. Poll on link-up status bit NV_XVR_VEND_XP_DL_UP */
	wait_time = 200; /* 2 seconds of clock ticks OK? */
	for (;;) {

	    vend_xp = pciehpc_reg_get32(ctrl_p, NV_XVR_VEND_XP);

	    if (vend_xp & NV_XVR_VEND_XP_DL_UP)
		break; /* link is UP */

	    if (wait_time <= 0) {
		cmn_err(CE_WARN, "ck804_slot_connect: time out in waiting"
			" for DL_UP on slot %d\n", ctrl_p->slot.slotNum);
		/* should we turn off power? */
		goto cleanup;
	    }

	    wait_time -= 10;
	    delay(10); /* wait for 10 ticks */
	}

	ctrl_p->slot.slot_state = HPC_SLOT_CONNECTED;
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_SUCCESS);

cleanup:
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_ERR_FAILED);
}

/*
 * This function is same as pciehpc_slotinfo_init() except
 * that it changes the slot_connect/slot_disconnect functions
 * to ck804 specific functions and also maps CK8-04 specific
 * control registers.
 */
static int
ck804_slotinfo_init(pciehpc_t *ctrl_p)
{
	pciehpc_slot_t *p = &ctrl_p->slot;

	(void) pciehpc_slotinfo_init(ctrl_p);
	p->slot_ops.hpc_op_connect = ck804_slot_connect;
	p->slot_ops.hpc_op_disconnect = ck804_slot_disconnect;

	/* map CK8-04 specific control registers */
	return (ck804_map_regs(ctrl_p));
}

/*
 * This function is same as pciehpc_slotinfo_uninit() except
 * that it cleans up ck8-04 specific data for the slot.
 */
static int
ck804_slotinfo_uninit(pciehpc_t *ctrl_p)
{
	(void) pciehpc_slotinfo_uninit(ctrl_p);

	ck804_unmap_regs(ctrl_p);

	return (DDI_SUCCESS);
}

/*
 * Manage REFCLK (disable/enable) for the slot. Only device
 * numbers B, C, D and E are valid. This works only for CK8-04.
 * Needs work for slots under IO-4.
 */
static void
ck804_slot_refclk(pciehpc_t *ctrl_p, int cmd)
{
	uint16_t tgio_ctrl;
	uint16_t mask;

	tgio_ctrl = ck804_reg_get16(ctrl_p, MCP_NVA_TGIO_CTRL);

	switch (ctrl_p->dev) {
	case 0xE:
		mask = DISABLE_PEx_REFCLK_DEV_E;
		break;
	case 0xD:
		mask = DISABLE_PEx_REFCLK_DEV_D;
		break;
	case 0xC:
		mask = DISABLE_PEx_REFCLK_DEV_C;
		break;
	case 0xB:
		mask = DISABLE_PEx_REFCLK_DEV_B;
		break;
	default:
		cmn_err(CE_WARN,
		    "ck804_slot_refclk: invalid device number %x\n",
		    ctrl_p->dev);
		return;
	};

	switch (cmd) {
	case DISABLE_REFCLK:
		tgio_ctrl |= mask;
		ck804_reg_put16(ctrl_p, MCP_NVA_TGIO_CTRL, tgio_ctrl);
		return;
	case ENABLE_REFCLK:
		tgio_ctrl &= ~mask;
		ck804_reg_put16(ctrl_p, MCP_NVA_TGIO_CTRL, tgio_ctrl);
		return;
	default:
		cmn_err(CE_WARN, "ck804_slot_refclk: invalid command %x\n",
			cmd);
		return;
	}
}

#ifdef DEBUG
static void
ck804_dump_pci_common_config(pciehpc_t *ctrl_p)
{
	if (pciehpc_debug <= 2)
		return;
	cmn_err(CE_CONT, " Vendor ID   = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_CONF_VENID));
	cmn_err(CE_CONT, " Device ID   = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_CONF_DEVID));
	cmn_err(CE_CONT, " Command REG = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_CONF_COMM));
	cmn_err(CE_CONT, " Status  REG = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_CONF_STAT));
	cmn_err(CE_CONT, " Revision ID = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_CONF_REVID));
	cmn_err(CE_CONT, " Prog Class  = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_CONF_PROGCLASS));
	cmn_err(CE_CONT, " Dev Class   = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_CONF_SUBCLASS));
	cmn_err(CE_CONT, " Base Class  = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_CONF_BASCLASS));
	cmn_err(CE_CONT, " Device ID   = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_CONF_CACHE_LINESZ));
	cmn_err(CE_CONT, " Header Type = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_CONF_HEADER));
	cmn_err(CE_CONT, " BIST        = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_CONF_BIST));
	cmn_err(CE_CONT, " BASE 0      = [0x%x]\n",
		pciehpc_reg_get32(ctrl_p, PCI_CONF_BASE0));
	cmn_err(CE_CONT, " BASE 1      = [0x%x]\n",
		pciehpc_reg_get32(ctrl_p, PCI_CONF_BASE1));

}

static void
ck804_dump_pci_device_config(pciehpc_t *ctrl_p)
{
	if (pciehpc_debug <= 2)
		return;
	ck804_dump_pci_common_config(ctrl_p);

	cmn_err(CE_CONT, " BASE 2      = [0x%x]\n",
		pciehpc_reg_get32(ctrl_p, PCI_CONF_BASE2));
	cmn_err(CE_CONT, " BASE 3      = [0x%x]\n",
		pciehpc_reg_get32(ctrl_p, PCI_CONF_BASE3));
	cmn_err(CE_CONT, " BASE 4      = [0x%x]\n",
		pciehpc_reg_get32(ctrl_p, PCI_CONF_BASE4));
	cmn_err(CE_CONT, " BASE 5      = [0x%x]\n",
		pciehpc_reg_get32(ctrl_p, PCI_CONF_BASE5));
	cmn_err(CE_CONT, " Cardbus CIS = [0x%x]\n",
		pciehpc_reg_get32(ctrl_p, PCI_CONF_CIS));
	cmn_err(CE_CONT, " Sub VID     = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_CONF_SUBVENID));
	cmn_err(CE_CONT, " Sub SID     = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_CONF_SUBSYSID));
	cmn_err(CE_CONT, " ROM         = [0x%x]\n",
		pciehpc_reg_get32(ctrl_p, PCI_CONF_ROM));
	cmn_err(CE_CONT, " I Line      = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_CONF_ILINE));
	cmn_err(CE_CONT, " I Pin       = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_CONF_IPIN));
	cmn_err(CE_CONT, " Max Grant   = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_CONF_MIN_G));
	cmn_err(CE_CONT, " Max Latent  = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_CONF_MAX_L));
}

static void
ck804_dump_pci_bridge_config(pciehpc_t *ctrl_p)
{
	if (pciehpc_debug <= 2)
		return;

	ck804_dump_pci_common_config(ctrl_p);

	cmn_err(CE_CONT, "........................................\n");

	cmn_err(CE_CONT, " Pri Bus     = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_BCNF_PRIBUS));
	cmn_err(CE_CONT, " Sec Bus     = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_BCNF_SECBUS));
	cmn_err(CE_CONT, " Sub Bus     = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_BCNF_SUBBUS));
	cmn_err(CE_CONT, " Latency     = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_BCNF_LATENCY_TIMER));
	cmn_err(CE_CONT, " I/O Base LO = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_BCNF_IO_BASE_LOW));
	cmn_err(CE_CONT, " I/O Lim LO  = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_BCNF_IO_LIMIT_LOW));
	cmn_err(CE_CONT, " Sec. Status = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_BCNF_SEC_STATUS));
	cmn_err(CE_CONT, " Mem Base    = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_BCNF_MEM_BASE));
	cmn_err(CE_CONT, " Mem Limit   = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_BCNF_MEM_LIMIT));
	cmn_err(CE_CONT, " PF Mem Base = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_BCNF_PF_BASE_LOW));
	cmn_err(CE_CONT, " PF Mem Lim  = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_BCNF_PF_LIMIT_LOW));
	cmn_err(CE_CONT, " PF Base HI  = [0x%x]\n",
		pciehpc_reg_get32(ctrl_p, PCI_BCNF_PF_BASE_HIGH));
	cmn_err(CE_CONT, " PF Lim  HI  = [0x%x]\n",
		pciehpc_reg_get32(ctrl_p, PCI_BCNF_PF_LIMIT_HIGH));
	cmn_err(CE_CONT, " I/O Base HI = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_BCNF_IO_BASE_HI));
	cmn_err(CE_CONT, " I/O Lim HI  = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_BCNF_IO_LIMIT_HI));
	cmn_err(CE_CONT, " ROM addr    = [0x%x]\n",
		pciehpc_reg_get32(ctrl_p, PCI_BCNF_ROM));
	cmn_err(CE_CONT, " Intr Line   = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_BCNF_ILINE));
	cmn_err(CE_CONT, " Intr Pin    = [0x%x]\n",
		pciehpc_reg_get8(ctrl_p, PCI_BCNF_IPIN));
	cmn_err(CE_CONT, " Bridge Ctrl = [0x%x]\n",
		pciehpc_reg_get16(ctrl_p, PCI_BCNF_BCNTRL));
}

/* dump hot plug registers */
static void
ck804_dump_hpregs(pciehpc_t *ctrl_p)
{
	uint16_t control;
	uint32_t capabilities;

	capabilities = pciehpc_reg_get32(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCAP);

	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);

	cmn_err(CE_NOTE, "ck804_dump_hpregs: hot plug info for slot %d\n",
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

	cmn_err(CE_NOTE, "Extended Slot Status Register: %x",
	    pciehpc_reg_get16(ctrl_p, NV_SVR_SLOT_STATUS_REG));

	cmn_err(CE_NOTE, "Extended Slot Control Register: %x",
	    pciehpc_reg_get16(ctrl_p, NV_SVR_SLOT_CONTROL_REG));

	cmn_err(CE_NOTE, "Strapping Register for Slot Capability: %x",
	    pciehpc_reg_get32(ctrl_p, NV_XVR_VEND_SLOT_STRAP));

	cmn_err(CE_NOTE, "TGIO Control Register: %x",
	    ck804_reg_get16(ctrl_p, MCP_NVA_TGIO_CTRL));
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
#endif

/*
 * ck804_slot_disconnect()
 *
 * Disconnect power to the slot. This function is equivalent of
 * pciehpc_disconnect() with necessary changes specific to CK8-04 native
 * hot plug implementation.
 *
 * Returns: HPC_SUCCESS if the slot is powered up and enabled.
 *	    HPC_ERR_FAILED if the slot can't be enabled.
 *
 * (Note: This function is called by HPS framework at kernel context only.)
 */
/*ARGSUSED*/
static int
ck804_slot_disconnect(caddr_t ops_arg, hpc_slot_t slot_hdl,
	void *data, uint_t flags)
{
	uint16_t status;
	uint16_t control;
	uint16_t x_control;
	uint16_t x_status;
	int wait_time;

	pciehpc_t *ctrl_p = (pciehpc_t *)ops_arg;

	ASSERT(slot_hdl == ctrl_p->slot.slot_handle);

	mutex_enter(&ctrl_p->pciehpc_mutex);

	/* get the current state of the slot */
	pciehpc_get_slot_state(ctrl_p);

	/* check if the slot is already in the 'disconnected' state */
	if (ctrl_p->slot.slot_state == HPC_SLOT_DISCONNECTED) {
		/* slot is in the 'disconnected' state */
		PCIEHPC_DEBUG((CE_NOTE,
		    "ck804_slot_disconnect(): slot %d already disconnected\n",
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
		PCIEHPC_DEBUG((CE_WARN,
		    "ck804_slot_disconnect(): slot %d is empty\n",
		    ctrl_p->slot.slotNum));
		goto cleanup1;
	}

	/*
	 * Disable power to the slot involves:
	 *	1. Set power LED to blink.
	 *	2. Disable REFCLK for the slot.
	 *	3. Set power control OFF in Slot Control Reigster and
	 *	   wait for Command Completed Interrupt or 1 sec timeout.
	 *	4. Clear NV_SVR_SLOT_CTRL_SAFE bit in the Ext. Control reg.
	 *	5. Poll NV_XVR_SLOT_STS_PWROK bit in ext status reg to be down.
	 *	6. Set POWER led and ATTN led to be OFF.
	 */

	/* 1. set power LED to blink */
	pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_BLINK);

	/* 2. Disable REFCLK for the slot */
	ck804_slot_refclk(ctrl_p, DISABLE_REFCLK);

	/* 3. set power control to OFF */
	control =  pciehpc_reg_get16(ctrl_p,
		ctrl_p->pcie_caps_reg_offset + PCIE_SLOTCTL);
	control |= PCIE_SLOTCTL_PWR_CONTROL;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/* 4. Clear NV_SVR_SLOT_CTRL_SAFE bit in NV_SVR_SLOT_CTRL reg */
	x_control = pciehpc_reg_get16(ctrl_p, NV_SVR_SLOT_CONTROL_REG);
	pciehpc_reg_put16(ctrl_p, NV_SVR_SLOT_CONTROL_REG,
		x_control & ~NV_SVR_SLOT_CTRL_SAFE);

	/* 5. Poll NV_SVR_SLOT_STS_PWROK bit in ext status reg to be off */
	wait_time = 200; /* 2 seconds of clock ticks OK? */
	for (;;) {

	    x_status = pciehpc_reg_get16(ctrl_p, NV_SVR_SLOT_STATUS_REG);

	    if (!(x_status & NV_SVR_SLOT_STS_PWROK))
		break; /* PWROK is cleared */

	    if (wait_time <= 0) {
		cmn_err(CE_WARN, "ck804_slot_disconnect: time out in waiting"
			" for PWROK to go off on slot %d\n",
			ctrl_p->slot.slotNum);
		goto cleanup2;
	    }

	    wait_time -= 10;
	    delay(10); /* wait for 10 ticks */
	}

	/* 6. Set power LED to be OFF */
	pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_OFF);
	pciehpc_set_led_state(ctrl_p, HPC_ATTN_LED, HPC_LED_OFF);

	ctrl_p->slot.slot_state = HPC_SLOT_DISCONNECTED;
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_SUCCESS);

cleanup2:
	pciehpc_set_led_state(ctrl_p, HPC_POWER_LED, HPC_LED_ON);
cleanup1:
	mutex_exit(&ctrl_p->pciehpc_mutex);
	return (HPC_ERR_FAILED);
}

/*
 * Background:
 *
 * CK8-04 defines two sets of system control registers (in I/O space)
 * that are mapped in and exposed from PCI config space in the ISA
 * bridge. One of the I/O BARs (offset 0x68 in PIC-ISA config space)
 * defines MCP_NVA_TGIO_CTRL register (offset 0xCC from the I/O BAR)
 * that has bits for managing reference clock for all the hot plug slots
 * (max of 4 depending on the CK8-04 configuration) during hot plug
 * operations.
 *
 * NOTE: The NVA I/O BAR is located in the PCI-ISA bridge device
 * on both CK8-04 and IO-04. Please note that these I/O BARs are
 * not regular BARs (BAR0-BAR4) in PCI config space.
 *
 * Description:
 *
 * This function finds regspec for NVA I/O BAR in the PCI-ISA
 * device node and maps it in. PCI-ISA node appears as a child
 * of parent nexus node (i.e child of npe nexus) with a name
 * pci10de,51. It assumes the regspec number as 1. So, this
 * kind of mapping registers from another device function is
 * not a common thing so it is not clean w.r.t DDI but
 * there is nothing in DDI that disallows it.
 */
static int
ck804_map_regs(pciehpc_t *ctrl_p)
{
	dev_info_t *lpcdev;
	ddi_device_acc_attr_t attr;
	ddi_acc_handle_t handle;
	pciehpc_ck804_t *ck804_p;
	caddr_t addrp;

	/* find the LPC bridge node for this pci-e hierarchy */
	if ((lpcdev = ck804_find_lpc_bridge(ctrl_p)) == NULL)
		return (DDI_FAILURE);

	/*
	 * Map in Analog Control I/O Bar.
	 *
	 * NOTE: reg set #0 corresponds to System Control I/O Bar and
	 * reg set #1 corresponds to Analog Control I/O Bar.
	 */
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	if (DDI_FM_ACC_ERR_CAP(ddi_fm_capable(lpcdev)))
		attr.devacc_attr_access = DDI_FLAGERR_ACC;
	if ((ddi_regs_map_setup(lpcdev, 1, &addrp, 0, 0,
	    &attr, &handle)) == DDI_SUCCESS) {
	    ck804_p = kmem_zalloc(sizeof (pciehpc_ck804_t), KM_SLEEP);
	    ck804_p->analog_bar_hdl = handle;
	    ck804_p->analog_bar_base = addrp;
	    ck804_p->lpcdev = lpcdev;
	    ctrl_p->misc_data = (void *)ck804_p;
	    return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/*
 * Unmap CK8-04 specific data/regs.
 */
static void
ck804_unmap_regs(pciehpc_t *ctrl_p)
{
	pciehpc_ck804_t *ck804_p = (pciehpc_ck804_t *)ctrl_p->misc_data;

	if (ck804_p == NULL)
		return;

	ddi_regs_map_free(&ck804_p->analog_bar_hdl);
	kmem_free(ck804_p, sizeof (pciehpc_ck804_t));
	ctrl_p->misc_data = NULL;
}

static dev_info_t *
ck804_find_lpc_bridge(pciehpc_t *ctrl_p)
{
	dev_info_t *pdip = ddi_get_parent(ctrl_p->dip);
	dev_info_t *lpc_dip = NULL;
	int count;

	ndi_devi_enter(pdip, &count);
	ddi_walk_devs(ddi_get_child(pdip), match_lpc_dev, &lpc_dip);
	ndi_devi_exit(pdip, count);

	return (lpc_dip);
}

/*
 * check if the dip matches LPC Bridge node
 */
static int
match_lpc_dev(dev_info_t *dip, void *hdl)
{
	dev_info_t **lpcdev = (dev_info_t **)hdl;
	int *vendor_id = 0;
	int *device_id = 0;
	uint_t count;

	*lpcdev = NULL;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "vendor-id", &vendor_id, &count) != DDI_PROP_SUCCESS) {
		return (DDI_WALK_TERMINATE);
	}
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", &device_id, &count) != DDI_PROP_SUCCESS) {
		ddi_prop_free(vendor_id);
		return (DDI_WALK_TERMINATE);
	}

	if ((*vendor_id == NVIDIA_VENDOR_ID) &&
	    (*device_id == CK804_DEVICE_ID)) {
		*lpcdev = dip;
		ddi_prop_free(vendor_id);
		ddi_prop_free(device_id);
		return (DDI_WALK_TERMINATE);
	}

	ddi_prop_free(vendor_id);
	ddi_prop_free(device_id);
	return (DDI_WALK_PRUNECHILD);
}

static uint16_t
ck804_reg_get16(pciehpc_t *ctrl_p, uint_t off)
{
	pciehpc_ck804_t *ck804_p = (pciehpc_ck804_t *)ctrl_p->misc_data;

	ASSERT(ck804_p != NULL);

	return (ddi_get16(ck804_p->analog_bar_hdl,
			(uint16_t *)(ck804_p->analog_bar_base + off)));
}

static void
ck804_reg_put16(pciehpc_t *ctrl_p, uint_t off, uint16_t val)
{
	pciehpc_ck804_t *ck804_p = (pciehpc_ck804_t *)ctrl_p->misc_data;

	ASSERT(ck804_p != NULL);

	ddi_put16(ck804_p->analog_bar_hdl,
	    (uint16_t *)(ck804_p->analog_bar_base + off), val);
}
