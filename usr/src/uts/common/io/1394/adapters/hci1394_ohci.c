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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_ohci.c
 *    Provides access routines to the OpenHCI HW.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/kmem.h>
#include <sys/pci.h>

#include <sys/1394/adapters/hci1394.h>
#include <sys/1394/adapters/hci1394_extern.h>


/*
 * Data swap macros used to swap config rom data that is going to be placed
 * in OpenHCI registers.  The config rom is treated like a byte stream.  When
 * the services layer calls into us to update the config rom, they pass us a
 * byte stream of data.  This works well except for the the fact that the
 * hardware uses its internal registers for the first 5 quadlets.  We have to
 * copy the cfgrom header and bus options into their corresponding OpenHCI
 * registers.  On an x86 machine, this means we have to byte swap them first.
 */
#ifdef _LITTLE_ENDIAN
#define	OHCI_SWAP32(DATA)	(ddi_swap32(DATA))
#else
#define	OHCI_SWAP32(DATA)	(DATA)
#endif


static int hci1394_ohci_selfid_init(hci1394_ohci_handle_t ohci_hdl);
static int hci1394_ohci_cfgrom_init(hci1394_ohci_handle_t ohci_hdl);
static int hci1394_ohci_chip_init(hci1394_ohci_handle_t ohci_hdl);
static int hci1394_ohci_phy_resume(hci1394_ohci_handle_t ohci_hdl);
static int hci1394_ohci_1394a_init(hci1394_ohci_handle_t ohci_hdl);
static int hci1394_ohci_1394a_resume(hci1394_ohci_handle_t ohci_hdl);
static int hci1394_ohci_phy_read_no_lock(hci1394_ohci_handle_t ohci_hdl,
    uint_t address, uint_t *data);
static int hci1394_ohci_phy_write_no_lock(hci1394_ohci_handle_t ohci_hdl,
    uint_t address, uint_t data);


/*
 * hci1394_ohci_init()
 *    Initialize the OpenHCI hardware.
 */
int
hci1394_ohci_init(hci1394_state_t *soft_state, hci1394_drvinfo_t *drvinfo,
    hci1394_ohci_handle_t *ohci_hdl)
{
	int status;
	uint32_t version;
	hci1394_ohci_t *ohci;
#if defined(__x86)
	uint16_t cmdreg;
#endif


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_init_enter, HCI1394_TNF_HAL_STACK, "");

	/* alloc the space for ohci */
	ohci = kmem_alloc(sizeof (hci1394_ohci_t), KM_SLEEP);
	*ohci_hdl = ohci;

	/*
	 * Start with the cycle timer rollover interrupt disabled.  When it is
	 * enabled, we will get an interrupt every 64 seconds, even if we have
	 * nothing plugged into the bus.  This interrupt is used to keep track
	 * of the bus time.  We will enable the interrupt when the bus manager
	 * writes to the bus_time CSR register (Currently there are not known
	 * implementations that write to the bus_time register)
	 */
	ohci->ohci_bustime_enabled = B_FALSE;
	ohci->ohci_bustime_count = 0;

	ohci->ohci_set_root_holdoff = B_FALSE;
	ohci->ohci_set_gap_count = B_FALSE;
	ohci->ohci_gap_count = 0;

	mutex_init(&ohci->ohci_mutex, NULL, MUTEX_DRIVER,
	    drvinfo->di_iblock_cookie);

	/* Map OpenHCI Registers */
	status = ddi_regs_map_setup(drvinfo->di_dip, OHCI_REG_SET,
	    (caddr_t *)&ohci->ohci_regs, 0, 0, &drvinfo->di_reg_attr,
	    &ohci->ohci_reg_handle);
	if (status != DDI_SUCCESS) {
		mutex_destroy(&ohci->ohci_mutex);
		kmem_free(ohci, sizeof (hci1394_ohci_t));
		*ohci_hdl = NULL;
		TNF_PROBE_0(ddi_regs_map_setup_fail, HCI1394_TNF_HAL_ERROR,
		    "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_init_exit, HCI1394_TNF_HAL_STACK,
		    "");
		return (DDI_FAILURE);
	}

	ohci->soft_state = soft_state;
	ohci->ohci_drvinfo = drvinfo;

	/*
	 * make sure PCI Master and PCI Memory Access are enabled on x86
	 * platforms. This may not be the case if plug and play OS is
	 * set in the BIOS
	 */
#if defined(__x86)
	cmdreg = pci_config_get16(soft_state->pci_config, PCI_CONF_COMM);
	if ((cmdreg & (PCI_COMM_MAE | PCI_COMM_ME)) != (PCI_COMM_MAE |
	    PCI_COMM_ME)) {
		cmdreg |= PCI_COMM_MAE | PCI_COMM_ME;
		pci_config_put16(soft_state->pci_config, PCI_CONF_COMM, cmdreg);
	}
#endif

	/*
	 * Initialize the openHCI chip.  This is broken out because we need to
	 * do this when resuming too.
	 */
	status = hci1394_ohci_chip_init(ohci);
	if (status != DDI_SUCCESS) {
		ddi_regs_map_free(&ohci->ohci_reg_handle);
		mutex_destroy(&ohci->ohci_mutex);
		kmem_free(ohci, sizeof (hci1394_ohci_t));
		*ohci_hdl = NULL;
		TNF_PROBE_0(hci1394_ohci_chip_init_fail, HCI1394_TNF_HAL_ERROR,
		    "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Init the 1394 PHY */
	status = hci1394_ohci_phy_init(ohci);
	if (status != DDI_SUCCESS) {
		(void) hci1394_ohci_soft_reset(ohci);
		ddi_regs_map_free(&ohci->ohci_reg_handle);
		mutex_destroy(&ohci->ohci_mutex);
		kmem_free(ohci, sizeof (hci1394_ohci_t));
		*ohci_hdl = NULL;
		TNF_PROBE_0(hci1394_ohci_phy_init_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Init 1394a features if present */
	if (ohci->ohci_phy == H1394_PHY_1394A) {
		status = hci1394_ohci_1394a_init(ohci);
		if (status != DDI_SUCCESS) {
			(void) hci1394_ohci_soft_reset(ohci);
			ddi_regs_map_free(&ohci->ohci_reg_handle);
			mutex_destroy(&ohci->ohci_mutex);
			kmem_free(ohci, sizeof (hci1394_ohci_t));
			*ohci_hdl = NULL;
			TNF_PROBE_0(hci1394_ohci_1394a_init_fail,
			    HCI1394_TNF_HAL_ERROR, "");
			TNF_PROBE_0_DEBUG(hci1394_ohci_init_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
	}

	/* save away guid, phy type, and vendor info */
	soft_state->halinfo.guid = hci1394_ohci_guid(ohci);
	soft_state->halinfo.phy = ohci->ohci_phy;
	soft_state->vendor_info.ohci_vendor_id =
	    ddi_get32(ohci->ohci_reg_handle, &ohci->ohci_regs->vendor_id);
	version = ddi_get32(ohci->ohci_reg_handle, &ohci->ohci_regs->version);
	soft_state->vendor_info.ohci_version = version;

	/* We do not support version < 1.0 */
	if (OHCI_VERSION(version) == 0) {
		cmn_err(CE_NOTE,
		    "hci1394(%d): OpenHCI version %x.%x is not supported",
		    drvinfo->di_instance, OHCI_VERSION(version),
		    OHCI_REVISION(version));
		(void) hci1394_ohci_soft_reset(ohci);
		ddi_regs_map_free(&ohci->ohci_reg_handle);
		mutex_destroy(&ohci->ohci_mutex);
		kmem_free(ohci, sizeof (hci1394_ohci_t));
		*ohci_hdl = NULL;
		TNF_PROBE_0(hci1394_ohci_selfid_init_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Initialize the selfid buffer */
	status = hci1394_ohci_selfid_init(ohci);
	if (status != DDI_SUCCESS) {
		(void) hci1394_ohci_soft_reset(ohci);
		ddi_regs_map_free(&ohci->ohci_reg_handle);
		mutex_destroy(&ohci->ohci_mutex);
		kmem_free(ohci, sizeof (hci1394_ohci_t));
		*ohci_hdl = NULL;
		TNF_PROBE_0(hci1394_ohci_selfid_init_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Initialize the config rom buffer */
	status = hci1394_ohci_cfgrom_init(ohci);
	if (status != DDI_SUCCESS) {
		(void) hci1394_ohci_soft_reset(ohci);
		hci1394_buf_free(&ohci->ohci_selfid_handle);
		ddi_regs_map_free(&ohci->ohci_reg_handle);
		mutex_destroy(&ohci->ohci_mutex);
		kmem_free(ohci, sizeof (hci1394_ohci_t));
		*ohci_hdl = NULL;
		TNF_PROBE_0(hci1394_ohci_cfgrom_init_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_init_exit, HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_fini()
 *    Cleanup after OpenHCI init.  This should be called during detach.
 */
void
hci1394_ohci_fini(hci1394_ohci_handle_t *ohci_hdl)
{
	hci1394_ohci_t *ohci;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_fini_enter, HCI1394_TNF_HAL_STACK, "");

	ohci = *ohci_hdl;

	/* reset chip */
	(void) hci1394_ohci_soft_reset(ohci);

	/* Free config rom space */
	hci1394_buf_free(&ohci->ohci_cfgrom_handle);

	/* Free selfid buffer space */
	hci1394_buf_free(&ohci->ohci_selfid_handle);

	/* Free up the OpenHCI registers */
	ddi_regs_map_free(&ohci->ohci_reg_handle);

	mutex_destroy(&ohci->ohci_mutex);

	/* Free the OpenHCI state space */
	kmem_free(ohci, sizeof (hci1394_ohci_t));
	*ohci_hdl = NULL;

	TNF_PROBE_0_DEBUG(hci1394_ohci_fini_exit, HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_chip_init()
 *    Initialize the OpenHCI registers.  This contains the bulk of the initial
 *    register setup.
 */
static int
hci1394_ohci_chip_init(hci1394_ohci_handle_t ohci_hdl)
{
	int status;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_chip_init_enter, HCI1394_TNF_HAL_STACK,
	    "");

	/* Reset 1394 OHCI HW */
	status = hci1394_ohci_soft_reset(ohci_hdl);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_soft_reset_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/*
	 * Setup Host Control Register. The software reset does not put all
	 * registers in a known state. The Host Control Register is one of these
	 * registers. First make sure noByteSwapData and postedWriteEnable and
	 * are cleared.
	 */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->hc_ctrl_clr, OHCI_HC_NO_BSWAP |
	    OHCI_HC_POSTWR_ENBL);

	/*
	 * the determination if we should swap data is made during the PCI
	 * initialization.
	 */
	if (ohci_hdl->soft_state->swap_data == B_FALSE) {
		/*
		 * most hba's don't swap data.  It will be swapped in the
		 * global swap for SPARC.  Enable Link Power(LPS). Enable
		 * Posted Writes
		 */
		ddi_put32(ohci_hdl->ohci_reg_handle,
		    &ohci_hdl->ohci_regs->hc_ctrl_set, OHCI_HC_NO_BSWAP |
		    OHCI_HC_LPS | OHCI_HC_POSTWR_ENBL);
	} else {
		/*
		 * Swap Data. Enable Link Power(LPS). Enable Posted Writes
		 */
		ddi_put32(ohci_hdl->ohci_reg_handle,
		    &ohci_hdl->ohci_regs->hc_ctrl_set, OHCI_HC_LPS |
		    OHCI_HC_POSTWR_ENBL);
	}

	/*
	 * Wait for PHY to come up. There does not seem to be standard time for
	 * how long wait for the PHY to come up. The problem is that the PHY
	 * provides a clock to the link layer and if that is not stable, we
	 * could get a PCI timeout error when reading/writing a phy register
	 * (and maybe an OpenHCI register?)  This used to be set to 10mS which
	 * works for just about every adapter we tested on.  We got a new TI
	 * adapter which would crash the system once in a while if nothing
	 * (1394 device) was pluged into the adapter.  Changing this delay to
	 * 50mS made that problem go away. This value is set via a patchable
	 * variable located in hci1394_extern.c
	 */
	delay(drv_usectohz(hci1394_phy_stabilization_delay_uS));

	/* Clear Isochrounous receive multi-chan mode registers */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ir_multi_maskhi_clr, 0xFFFFFFFF);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ir_multi_masklo_clr, 0xFFFFFFFF);

	/*
	 * Setup async retry on busy or ack_data_error
	 *   secondlimit = 0 <= bits 31-29
	 *   cycleLimit = 0 <= bits 28-16
	 *   maxPhysRespRetries = 0 <= bits 11-8
	 *   maxARRespRetries = 0 <= bits 7-4
	 *   maxATReqRetries = 2 <= bits 3-0
	 */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_retries, 0x00000002);

	/*
	 * Setup Link Control
	 *   Enable cycleMaster, cycleTimerEnable, and rcvPhyPkt.
	 */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->link_ctrl_clr, 0xFFFFFFFF);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->link_ctrl_set, OHCI_LC_CYC_MAST |
	    OHCI_LC_CTIME_ENBL | OHCI_LC_RCV_PHY);

	/*
	 * Set the Physical address map boundary to 0x0000FFFFFFFF. The
	 * phys_upper_bound is the upper 32-bits of the 48-bit 1394 address. The
	 * lower 16 bits are assumed to be 0xFFFF.
	 */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->phys_upper_bound, (uint32_t)0x0000FFFF);

	/*
	 * Enable all async requests.
	 * The asyncReqResourceAll bit (0x80000000) does not get cleared during
	 * a bus reset.  If this code is changed to selectively allow nodes to
	 * perform ARREQ's, the ARREQ filter bits will need to be updated after
	 * every bus reset.
	 */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ar_req_filterhi_set, (uint32_t)0x80000000);

	/*
	 * clear isochronous interrupt event and mask registers clearing the
	 * mask registers disable all isoc tx & rx ints
	 */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->it_intr_event_clr, (uint32_t)0xFFFFFFFF);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->it_intr_mask_clr, (uint32_t)0xFFFFFFFF);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ir_intr_event_clr, (uint32_t)0xFFFFFFFF);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ir_intr_mask_clr, (uint32_t)0xFFFFFFFF);

	/* Clear interrupt event/mask register */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->intr_event_clr, (uint32_t)0xFFFFFFFF);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->intr_mask_clr, (uint32_t)0xFFFFFFFF);

	TNF_PROBE_0_DEBUG(hci1394_ohci_chip_init_exit, HCI1394_TNF_HAL_STACK,
	    "");
	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_soft_reset()
 *    Reset OpenHCI HW.
 */
int
hci1394_ohci_soft_reset(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t resetStatus;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_soft_reset_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* Reset 1394 HW - Reset is bit 16 in HCControl */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->hc_ctrl_set, OHCI_HC_SOFT_RESET);

	/* Wait for reset to complete */
	drv_usecwait(OHCI_CHIP_RESET_TIME_IN_uSEC);

	/* Verify reset is complete */
	resetStatus = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->hc_ctrl_set);
	resetStatus = resetStatus & OHCI_HC_SOFT_RESET;
	if (resetStatus != 0) {
		TNF_PROBE_0(hci1394_ohci_reset_not_complete_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_soft_reset_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_soft_reset_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_reg_read()
 *    Read OpenHCI register.  This is called from the test ioctl interface
 *    through devctl.
 */
void
hci1394_ohci_reg_read(hci1394_ohci_handle_t ohci_hdl,
    uint_t offset, uint32_t *data)
{
	uint32_t *addr;


	ASSERT(ohci_hdl != NULL);
	ASSERT(data != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_reg_read_enter,
	    HCI1394_TNF_HAL_STACK, "");

	addr = (uint32_t *)((uintptr_t)ohci_hdl->ohci_regs +
	    (uintptr_t)(offset & OHCI_REG_ADDR_MASK));
	*data = ddi_get32(ohci_hdl->ohci_reg_handle, addr);

	TNF_PROBE_0_DEBUG(hci1394_ohci_reg_read_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_reg_write()
 *    Write OpenHCI register.  This is called from the test ioctl interface
 *    through devctl.
 */
void
hci1394_ohci_reg_write(hci1394_ohci_handle_t ohci_hdl,
    uint_t offset, uint32_t data)
{
	uint32_t *addr;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_reg_read_enter,
	    HCI1394_TNF_HAL_STACK, "");

	addr = (uint32_t *)((uintptr_t)ohci_hdl->ohci_regs +
	    (uintptr_t)(offset & OHCI_REG_ADDR_MASK));
	ddi_put32(ohci_hdl->ohci_reg_handle, addr, data);

	TNF_PROBE_0_DEBUG(hci1394_ohci_reg_read_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_intr_master_enable()
 *    Enable interrupts to be passed on from OpenHCI.  This is a global mask.
 *    Individual interrupts still need to be enabled for interrupts to be
 *    generated.
 */
void
hci1394_ohci_intr_master_enable(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_master_enable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->intr_mask_set, OHCI_INTR_MASTER_INTR_ENBL);

	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_master_enable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_intr_master_disable()
 *    Disable all OpenHCI interrupts from being passed on.  This does not affect
 *    the individual interrupt mask settings.  When interrupts are enabled
 *    again, the same individual interrupts will still be enabled.
 */
void
hci1394_ohci_intr_master_disable(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_master_disable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->intr_mask_clr, OHCI_INTR_MASTER_INTR_ENBL);

	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_master_disable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_intr_asserted()
 *    Return which ENABLED interrupts are asserted.  If an interrupt is disabled
 *    via its mask bit, it will not be returned from here.
 *
 * NOTE: we may want to make this a macro at some point.
 */
uint32_t
hci1394_ohci_intr_asserted(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t interrupts_asserted;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_asserted_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * Only look at interrupts which are enabled by reading the
	 * intr_event_clr register.
	 */
	interrupts_asserted = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->intr_event_clr);

	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_asserted_exit,
	    HCI1394_TNF_HAL_STACK, "");
	return (interrupts_asserted);
}


/*
 * hci1394_ohci_intr_enable()
 *    Enable an individual interrupt or set of interrupts. This does not affect
 *    the global interrupt mask.
 */
void
hci1394_ohci_intr_enable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t interrupt_mask)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_enable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->intr_mask_set, interrupt_mask);

	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_enable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_intr_disable()
 *    Disable an individual interrupt or set of interrupts. This does not affect
 *    the global interrupt mask.
 */
void
hci1394_ohci_intr_disable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t interrupt_mask)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_disable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->intr_mask_clr, interrupt_mask);

	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_disable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_intr_clear()
 *    Clear a set of interrupts so that they are not asserted anymore.
 *
 * NOTE: we may want to make this a macro at some point.
 */
void
hci1394_ohci_intr_clear(hci1394_ohci_handle_t ohci_hdl,
    uint32_t interrupt_mask)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_clear_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->intr_event_clr, interrupt_mask);
	TNF_PROBE_1_DEBUG(hci1394_ohci_intr_clear, HCI1394_TNF_HAL, "",
	    tnf_uint, intr_mask, interrupt_mask);

	TNF_PROBE_0_DEBUG(hci1394_ohci_intr_clear_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_it_intr_asserted()
 *    Return which ENABLED isoch TX interrupts are asserted.  If an interrupt is
 *    disabled via its mask bit, it will not be returned from here.
 *
 * NOTE: we may want to make this a macro at some point.
 */
uint32_t
hci1394_ohci_it_intr_asserted(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t interrupts_asserted;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_it_intr_asserted_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* Only look at interrupts which are enabled */
	interrupts_asserted = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->it_intr_event_clr);

	TNF_PROBE_0_DEBUG(hci1394_ohci_it_intr_asserted_exit,
	    HCI1394_TNF_HAL_STACK, "");
	return (interrupts_asserted);
}


/*
 * hci1394_ohci_it_intr_enable()
 *    Enable an individual isoch TX interrupt. This does not affect the general
 *    isoch interrupt mask in the OpenHCI Mask register.  That is enabled/
 *    disabled via hci1394_ohci_intr_enable/hci1394_ohci_intr_disable.
 */
void
hci1394_ohci_it_intr_enable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t interrupt_mask)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_it_intr_enable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->it_intr_mask_set, interrupt_mask);

	TNF_PROBE_0_DEBUG(hci1394_ohci_it_intr_enable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_it_intr_disable()
 *    Disable an individual isoch TX interrupt. This does not affect the general
 *    isoch interrupt mask in the OpenHCI Mask register.  That is enabled/
 *    disabled via hci1394_ohci_intr_enable/hci1394_ohci_intr_disable.
 */
void
hci1394_ohci_it_intr_disable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t interrupt_mask)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_it_intr_disable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->it_intr_mask_clr, interrupt_mask);

	TNF_PROBE_0_DEBUG(hci1394_ohci_it_intr_disable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_it_intr_clear()
 *    Clear an individual isoch TX interrupt so that it is not asserted anymore.
 *
 * NOTE: we may want to make this a macro at some point.
 */
void
hci1394_ohci_it_intr_clear(hci1394_ohci_handle_t ohci_hdl,
    uint32_t interrupt_mask)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_it_intr_clear_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->it_intr_event_clr, interrupt_mask);

	TNF_PROBE_0_DEBUG(hci1394_ohci_it_intr_clear_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_it_ctxt_count_get()
 *    Determine the number of supported isochronous transmit contexts.
 */
int
hci1394_ohci_it_ctxt_count_get(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t channel_mask;
	int count;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_it_ctxt_count_get_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * hw is required to support contexts 0 to N, where N <= 31
	 * the interrupt mask bits are wired to ground for unsupported
	 * contexts.  Write 1's to all it mask bits, then read the mask.
	 * Implemented contexts will read (sequentially) as 1
	 */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->it_intr_mask_set, 0xFFFFFFFF);
	channel_mask = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->it_intr_mask_set);
	count = 0;
	while (channel_mask != 0) {
		channel_mask = channel_mask >> 1;
		count++;
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_it_ctxt_count_get_exit,
	    HCI1394_TNF_HAL_STACK, "");
	return (count);
}


/*
 * hci1394_ohci_it_cmd_ptr_set()
 *    Set the context pointer for a given isoch TX context.  This is the IO
 *    address for the HW to fetch the first descriptor.  The context should
 *    not be running when this routine is called.
 */
void
hci1394_ohci_it_cmd_ptr_set(hci1394_ohci_handle_t ohci_hdl,
    uint_t context_number, uint32_t io_addr)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_it_cmd_ptr_set_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->it[context_number].cmd_ptrlo,
	    io_addr);

	TNF_PROBE_0_DEBUG(hci1394_ohci_it_cmd_ptr_set_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_ir_intr_asserted()
 *    Return which ENABLED isoch RX interrupts are asserted.  If an interrupt is
 *    disabled via its mask bit, it will not be returned from here.
 *
 * NOTE: we may want to make this a macro at some point.
 */
uint32_t
hci1394_ohci_ir_intr_asserted(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t interrupts_asserted;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_intr_asserted_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* Only look at interrupts which are enabled */
	interrupts_asserted = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ir_intr_event_clr);

	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_intr_asserted_exit,
	    HCI1394_TNF_HAL_STACK, "");
	return (interrupts_asserted);
}


/*
 * hci1394_ohci_ir_intr_enable()
 *    Enable an individual isoch RX interrupt. This does not affect the isoch
 *    interrupt mask in the OpenHCI Mask register.  That is enabled/disabled
 *    via hci1394_ohci_intr_enable/hci1394_ohci_intr_disable.
 */
void
hci1394_ohci_ir_intr_enable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t interrupt_mask)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_intr_enable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ir_intr_mask_set, interrupt_mask);

	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_intr_enable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_ir_intr_disable()
 *    Disable an individual isoch RX interrupt. This does not affect the isoch
 *    interrupt mask in the OpenHCI Mask register.  That is enabled/disabled
 *    via hci1394_ohci_intr_enable/hci1394_ohci_intr_disable.
 */
void
hci1394_ohci_ir_intr_disable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t interrupt_mask)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_intr_disable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ir_intr_mask_clr, interrupt_mask);

	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_intr_disable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_ir_intr_clear()
 *    Clear an individual isoch RX interrupt so that it is not asserted anymore.
 *
 * NOTE: we may want to make this a macro at some point.
 */
void
hci1394_ohci_ir_intr_clear(hci1394_ohci_handle_t ohci_hdl,
    uint32_t interrupt_mask)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_intr_clear_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ir_intr_event_clr, interrupt_mask);

	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_intr_clear_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_ir_ctxt_count_get()
 *    Determine the number of supported isochronous receive contexts.
 */
int
hci1394_ohci_ir_ctxt_count_get(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t channel_mask;
	int count;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_ctxt_count_get_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * hw is required to support contexts 0 to N, where N <= 31
	 * the interrupt mask bits are wired to ground for unsupported
	 * contexts.  Write 1's to all ir mask bits, then read the mask.
	 * Implemented contexts will read (sequentially) as 1
	 */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ir_intr_mask_set, 0xFFFFFFFF);
	channel_mask = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ir_intr_mask_set);
	count = 0;
	while (channel_mask != 0) {
		channel_mask = channel_mask >> 1;
		count++;
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_ctxt_count_get_exit,
	    HCI1394_TNF_HAL_STACK, "");
	return (count);
}


/*
 * hci1394_ohci_ir_cmd_ptr_set()
 *    Set the context pointer for a given isoch RX context.  This is the IO
 *    address for the HW to fetch the first descriptor.  The context should
 *    not be running when this routine is called.
 */
void
hci1394_ohci_ir_cmd_ptr_set(hci1394_ohci_handle_t ohci_hdl,
    uint_t context_number, uint32_t io_addr)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_cmd_ptr_set_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ir[context_number].cmd_ptrlo,
	    io_addr);

	TNF_PROBE_0_DEBUG(hci1394_ohci_ir_cmd_ptr_set_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_link_enable()
 *    Enable the 1394 link layer.  When the link is enabled, the PHY will pass
 *    up any 1394 bus transactions which would normally come up to the link.
 */
void
hci1394_ohci_link_enable(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_link_enable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->hc_ctrl_set, OHCI_HC_LINK_ENBL);

	TNF_PROBE_0_DEBUG(hci1394_ohci_link_enable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_link_disable()
 *    Disable the 1394 link layer.  When the link is disabled, the PHY will NOT
 *    pass up any 1394 bus transactions which would normally come up to the
 *    link.  This "logically" disconnects us from the 1394 bus.
 */
void
hci1394_ohci_link_disable(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_link_disable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->hc_ctrl_clr, OHCI_HC_LINK_ENBL);

	TNF_PROBE_0_DEBUG(hci1394_ohci_link_disable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_bus_reset()
 *     Reset the 1394 bus. This performs a "long" bus reset and can be called
 *     when the adapter has either a 1394-1995 or 1394A PHY.
 */
int
hci1394_ohci_bus_reset(hci1394_ohci_handle_t ohci_hdl)
{
	int status;
	uint_t reg;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_bus_reset_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * We want to reset the bus.  We also handle the root_holdoff and gap
	 * count cacheing explained at the top of this file.
	 */
	reg = OHCI_PHY_IBR;
	if (ohci_hdl->ohci_set_root_holdoff == B_TRUE) {
		reg = reg | OHCI_PHY_RHB;
	}
	if (ohci_hdl->ohci_set_gap_count == B_TRUE) {
		reg = reg | ohci_hdl->ohci_gap_count;
	} else {
		reg = reg | OHCI_PHY_MAX_GAP;
	}

	/*
	 * Reset the bus. We intentionally do NOT do a PHY read here.  A PHY
	 * read could introduce race conditions and would be more likely to fail
	 * due to a timeout.
	 */
	status = hci1394_ohci_phy_write(ohci_hdl, 0x1, reg);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_phy_write_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_bus_reset_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* clear the root holdoff and gap count state bits */
	ohci_hdl->ohci_set_root_holdoff = B_FALSE;
	ohci_hdl->ohci_set_gap_count = B_FALSE;

	TNF_PROBE_0_DEBUG(hci1394_ohci_bus_reset_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}

/*
 *
 * hci1394_ohci_bus_reset_nroot()
 *     Reset the 1394 bus. This performs a "long" bus reset with out a root.
 */
int
hci1394_ohci_bus_reset_nroot(hci1394_ohci_handle_t ohci_hdl)
{
	int status;
	uint_t reg;

	ASSERT(ohci_hdl != NULL);

	/*
	 * We want to reset the bus.  We don't care about any holdoff
	 * we are suspending need no root...
	 */
	(void) hci1394_ohci_phy_read(ohci_hdl, 0x1, &reg);
	reg = reg | OHCI_PHY_IBR;
	reg = reg & ~OHCI_PHY_RHB;

	/*
	 * Reset the bus. We intentionally do NOT do a PHY read here.  A PHY
	 * read could introduce race conditions and would be more likely to fail
	 * due to a timeout.
	 */
	status = hci1394_ohci_phy_write(ohci_hdl, 0x1, reg);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_phy_write_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_bus_reset_nroot_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * hci1394_ohci_phy_init()
 *    Setup the PHY.  This should be called during attach and performs any PHY
 *    initialization required including figuring out what kind of PHY we have.
 */
int
hci1394_ohci_phy_init(hci1394_ohci_handle_t ohci_hdl)
{
	int status;
	uint_t phy_reg;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_init_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * if the phy has extended set to 7, the phy is a not a 1394-1995 PHY.
	 * It could be a 1394a phy or beyond.  The PHY type can be found in PHY
	 * register page 1 in the compliance_level register.
	 *
	 * Since there are not any current standards beyond 1394A, we are going
	 * to consider the PHY to be a 1394A phy if the extended bit is set.
	 *
	 * phy registers are byte wide registers and are addressed as 0, 1, 2,
	 * 3, ...  Phy register 0 may not be read or written.
	 *
	 * Phy register 0x2 (bit 0 MSB, 7 LSB)
	 *   Extended    - bits 0 - 2
	 *   Total Ports - bits 4 - 7
	 */
	status = hci1394_ohci_phy_read(ohci_hdl, 2, &phy_reg);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_phy_read_failed,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	if ((phy_reg & OHCI_PHY_EXTND_MASK) != OHCI_PHY_EXTND) {
		/*
		 * if the extended bit is not set, we have to be a 1394-1995
		 * PHY
		 */
		ohci_hdl->ohci_phy = H1394_PHY_1995;
	} else {
		/* Treat all other PHY's as a 1394A PHY */
		ohci_hdl->ohci_phy = H1394_PHY_1394A;
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_init_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_phy_resume()
 *    re-initialize the PHY. This routine should be called during a resume after
 *    a successful suspend has been done.
 */
/* ARGSUSED */
static int
hci1394_ohci_phy_resume(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_resume_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* There is currently nothing to re-initialize here */

	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_resume_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_phy_set()
 *    Perform bitset operation on PHY register.
 */
int
hci1394_ohci_phy_set(hci1394_ohci_handle_t ohci_hdl, uint_t address,
    uint_t bits)
{
	int status;
	uint_t reg;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_set_enter,
	    HCI1394_TNF_HAL_STACK, "");

	mutex_enter(&ohci_hdl->ohci_mutex);

	/* read the PHY register */
	status = hci1394_ohci_phy_read_no_lock(ohci_hdl, address, &reg);
	if (status != DDI_SUCCESS) {
		mutex_exit(&ohci_hdl->ohci_mutex);
		TNF_PROBE_0(hci1394_ohci_phy_read_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_set_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Set the bits and write the result back */
	reg = reg | bits;
	status = hci1394_ohci_phy_write_no_lock(ohci_hdl, address, reg);
	if (status != DDI_SUCCESS) {
		mutex_exit(&ohci_hdl->ohci_mutex);
		TNF_PROBE_0(hci1394_ohci_phy_write_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_set_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	mutex_exit(&ohci_hdl->ohci_mutex);

	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_set_exit, HCI1394_TNF_HAL_STACK,
	    "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_phy_clr()
 *    Perform bitclr operation on PHY register.
 */
int
hci1394_ohci_phy_clr(hci1394_ohci_handle_t ohci_hdl, uint_t address,
    uint_t bits)
{
	int status;
	uint_t reg;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_clr_enter,
	    HCI1394_TNF_HAL_STACK, "");

	mutex_enter(&ohci_hdl->ohci_mutex);

	/* read the PHY register */
	status = hci1394_ohci_phy_read_no_lock(ohci_hdl, address, &reg);
	if (status != DDI_SUCCESS) {
		mutex_exit(&ohci_hdl->ohci_mutex);
		TNF_PROBE_0(hci1394_ohci_phy_read_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_clr_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Set the bits and write the result back */
	reg = reg & ~bits;
	status = hci1394_ohci_phy_write_no_lock(ohci_hdl, address, reg);
	if (status != DDI_SUCCESS) {
		mutex_exit(&ohci_hdl->ohci_mutex);
		TNF_PROBE_0(hci1394_ohci_phy_write_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_clr_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	mutex_exit(&ohci_hdl->ohci_mutex);

	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_clr_exit, HCI1394_TNF_HAL_STACK,
	    "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_phy_read()
 *    Atomic PHY register read
 */
int
hci1394_ohci_phy_read(hci1394_ohci_handle_t ohci_hdl, uint_t address,
    uint_t *data)
{
	int status;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_read_enter, HCI1394_TNF_HAL_STACK,
	    "");
	mutex_enter(&ohci_hdl->ohci_mutex);
	status = hci1394_ohci_phy_read_no_lock(ohci_hdl, address, data);
	mutex_exit(&ohci_hdl->ohci_mutex);
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_read_exit, HCI1394_TNF_HAL_STACK,
	    "");

	return (status);
}


/*
 * hci1394_ohci_phy_write()
 *    Atomic PHY register write
 */
int
hci1394_ohci_phy_write(hci1394_ohci_handle_t ohci_hdl, uint_t address,
    uint_t data)
{
	int status;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_write_enter, HCI1394_TNF_HAL_STACK,
	    "");
	mutex_enter(&ohci_hdl->ohci_mutex);
	status = hci1394_ohci_phy_write_no_lock(ohci_hdl, address, data);
	mutex_exit(&ohci_hdl->ohci_mutex);
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_write_exit, HCI1394_TNF_HAL_STACK,
	    "");

	return (status);
}


/*
 * hci1394_ohci_phy_read_no_lock()
 *    This routine actually performs the PHY register read.  It is seperated
 *    out from phy_read so set & clr lock can perform an atomic PHY register
 *    operation.  It assumes the OpenHCI mutex is held.
 */
static int
hci1394_ohci_phy_read_no_lock(hci1394_ohci_handle_t ohci_hdl, uint_t address,
    uint_t *data)
{
	uint32_t ohci_reg;
	int count;


	ASSERT(ohci_hdl != NULL);
	ASSERT(data != NULL);
	ASSERT(MUTEX_HELD(&ohci_hdl->ohci_mutex));
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_read_no_lock_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* You can't read or write PHY register #0 */
	if (address == 0) {
		TNF_PROBE_1(hci1394_ohci_phy_addr_fail, HCI1394_TNF_HAL_ERROR,
		    "", tnf_string, errmsg, "can't rd/wr PHY reg #0");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_read_no_lock_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Verify phy access not in progress */
	ohci_reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->phy_ctrl);
	if ((ohci_reg & (OHCI_PHYC_RDREG | OHCI_PHYC_WRREG)) != 0) {
		TNF_PROBE_1(hci1394_ohci_phy_xfer_fail, HCI1394_TNF_HAL_ERROR,
		    "", tnf_string, errmsg, "transfer already in progress?");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_read_no_lock_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Start the PHY register read */
	ohci_reg = OHCI_PHYC_RDREG | ((address & 0xF) <<
	    OHCI_PHYC_REGADDR_SHIFT);
	ddi_put32(ohci_hdl->ohci_reg_handle, &ohci_hdl->ohci_regs->phy_ctrl,
	    ohci_reg);

	/*
	 * The PHY read usually takes less than 1uS.  It is not worth having
	 * this be interrupt driven. Having this be interrupt driven would also
	 * make the bus reset and self id processing much more complex for
	 * 1995 PHY's.  We will wait up to hci1394_phy_delay_uS for the read
	 * to complete (this was initially set to 10).  I have yet to see
	 * count > 1.  The delay is a patchable variable.
	 */
	count = 0;
	while (count < hci1394_phy_delay_uS) {
		/* See if the read is done yet */
		ohci_reg = ddi_get32(ohci_hdl->ohci_reg_handle,
		    &ohci_hdl->ohci_regs->phy_ctrl);
		if ((ohci_reg & OHCI_PHYC_RDDONE) != 0) {
			/*
			 * The read is done. clear the phyRegRecv interrupt. We
			 * do not have this interrupt enabled but this keeps
			 * things clean in case someone in the future does.
			 * Break out of the loop, we are done.
			 */
			ddi_put32(ohci_hdl->ohci_reg_handle,
			    &ohci_hdl->ohci_regs->intr_event_clr,
			    OHCI_INTR_PHY_REG_RCVD);
			break;
		}

		/*
		 * the phy read did not yet complete, wait 1uS, increment the
		 * count and try again.
		 */
		drv_usecwait(1);
		count++;
	}

	/* Check to see if we timed out */
	if (count >= hci1394_phy_delay_uS) {
		/* we timed out, return failure */
		*data = 0;
		TNF_PROBE_0(hci1394_ohci_phy_rd_timeout_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_read_no_lock_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* setup the PHY read data to be returned */
	*data = (ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->phy_ctrl) & OHCI_PHYC_RDDATA_MASK) >>
	    OHCI_PHYC_RDDATA_SHIFT;

	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_read_no_lock_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_phy_write_no_lock()
 *    This routine actually performs the PHY register write.  It is separated
 *    out from phy_write so set & clr lock can perform an atomic PHY register
 *    operation.  It assumes the OpenHCI mutex is held.
 */
static int
hci1394_ohci_phy_write_no_lock(hci1394_ohci_handle_t ohci_hdl, uint_t address,
    uint_t data)
{
	uint32_t ohci_reg;
	int count;


	ASSERT(ohci_hdl != NULL);
	ASSERT(MUTEX_HELD(&ohci_hdl->ohci_mutex));
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_write_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* You can't read or write PHY register #0 */
	if (address == 0) {
		TNF_PROBE_1(hci1394_ohci_phy_addr_fail, HCI1394_TNF_HAL_ERROR,
		    "", tnf_string, errmsg, "can't rd/wr PHY reg #0");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_write_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Verify phy access not in progress */
	ohci_reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->phy_ctrl);
	if ((ohci_reg & (OHCI_PHYC_RDREG | OHCI_PHYC_WRREG)) != 0) {
		TNF_PROBE_1(hci1394_ohci_phy_xfer_fail, HCI1394_TNF_HAL_ERROR,
		    "", tnf_string, errmsg, "transfer already in progress?");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_write_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Start the PHY register write */
	ohci_reg = OHCI_PHYC_WRREG | ((address & 0xF) <<
	    OHCI_PHYC_REGADDR_SHIFT) | (data & OHCI_PHYC_WRDATA_MASK);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->phy_ctrl, ohci_reg);

	/*
	 * The PHY write usually takes less than 1uS.  It is not worth having
	 * this be interrupt driven. Having this be interrupt driven would also
	 * make the bus reset and self id processing much more complex. We will
	 * wait up to hci1394_phy_delay_uS for the write to complete (this was
	 * initially set to 10).  I have yet to see count > 0.  The delay is a
	 * patchable variable.
	 */
	count = 0;
	while (count < hci1394_phy_delay_uS) {
		/* See if the write is done yet */
		ohci_reg = ddi_get32(ohci_hdl->ohci_reg_handle,
		    &ohci_hdl->ohci_regs->phy_ctrl);
		if ((ohci_reg & OHCI_PHYC_WRREG) == 0) {
			/*
			 * The write completed. Break out of the loop, we are
			 * done.
			 */
			break;
		}

		/*
		 * the phy write did not yet complete, wait 1uS, increment the
		 * count and try again.
		 */
		drv_usecwait(1);
		count++;
	}

	/* Check to see if we timed out */
	if (count >= hci1394_phy_delay_uS) {
		/* we timed out, return failure */
		TNF_PROBE_0(hci1394_ohci_phy_wr_timeout_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_write_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_write_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_phy_info()
 *    Return selfid word for our PHY.  This routine should ONLY be called for
 *    adapters with a 1394-1995 PHY. These PHY's do not embed their own selfid
 *    information in the selfid buffer so we need to do it for them in the
 *    selfid complete interrupt handler.  This routine only supports building
 *    selfid info for a 3 port PHY.  Since we will probably not ever see a
 *    1394-1995 PHY in any production system, and if we do it will have 3 ports
 *    or less, this is a pretty safe assumption.
 */
int
hci1394_ohci_phy_info(hci1394_ohci_handle_t ohci_hdl, uint32_t *info)
{
	int status;
	uint32_t phy_info;
	uint32_t reg;
	int index;
	int num_ports;
	int count;
	uint32_t port_status;


	ASSERT(ohci_hdl != NULL);
	ASSERT(info != NULL);
	ASSERT(ohci_hdl->ohci_phy == H1394_PHY_1995);
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_info_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * Set Link on. We are using power class 0 since we have no idea what
	 * our real power class is.
	 */
	phy_info = 0x80400000;

	/* Add in Physical ID */
	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->node_id);
	phy_info = phy_info | ((reg << IEEE1394_SELFID_PHYID_SHIFT) &
	    IEEE1394_SELFID_PHYID_MASK);

	/* Add in Gap Count */
	status = hci1394_ohci_phy_read(ohci_hdl, 1, &reg);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_phy_read_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_info_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}
	phy_info = phy_info | ((reg << IEEE1394_SELFID_GAP_CNT_SHIFT) &
	    IEEE1394_SELFID_GAP_CNT_MASK);

	/* Add in speed & ports */
	status = hci1394_ohci_phy_read(ohci_hdl, 2, &reg);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_phy_read_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_info_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}
	phy_info = phy_info | ((reg & 0xC0) << 8);
	num_ports = reg & 0x1F;

	/* PHY reports that it has 0 ports?? */
	if (num_ports == 0) {
		TNF_PROBE_1(hci1394_ohci_phy_zero_ports_fail,
		    HCI1394_TNF_HAL_ERROR, "", tnf_string, errmsg,
		    "1995 phy has zero ports?");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_info_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Build up the port information for each port in the PHY */
	count = 0;
	for (index = 0; index < 3; index++) {
		if (num_ports > 0) {
			status = hci1394_ohci_phy_read(ohci_hdl,
			    count + 3, &reg);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(hci1394_ohci_phy_read_fail,
				    HCI1394_TNF_HAL_ERROR, "");
				TNF_PROBE_0_DEBUG(hci1394_ohci_phy_info_exit,
				    HCI1394_TNF_HAL_STACK, "");
				return (DDI_FAILURE);
			}
			/* if port is not connected */
			if ((reg & 0x04) == 0) {
				port_status =
				    IEEE1394_SELFID_PORT_NOT_CONNECTED;

			/* else if port is connected to parent */
			} else if ((reg & 0x08) == 0) {
				port_status = IEEE1394_SELFID_PORT_TO_PARENT;

			/* else port is connected to child */
			} else {
				port_status = IEEE1394_SELFID_PORT_TO_CHILD;
			}

			num_ports--;
		} else {
			port_status = IEEE1394_SELFID_PORT_NO_PORT;
		}

		/* add in the port information */
		phy_info = phy_info | (port_status << (6 - (index * 2)));
		count++;
	}

	/* Copy the PHY selfid info to the return parameter */
	*info = phy_info;

	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_info_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_current_busgen()
 *    return the current bus generation.
 */
uint_t
hci1394_ohci_current_busgen(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t reg;
	uint_t generation_count;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_current_busgen_enter,
	    HCI1394_TNF_HAL_STACK, "");

	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->self_id_count);
	generation_count = (reg & OHCI_SLFC_GEN_MASK) >> OHCI_SLFC_GEN_SHIFT;

	TNF_PROBE_0_DEBUG(hci1394_ohci_current_busgen_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (generation_count);
}


/*
 * hci1394_ohci_startup()
 *    Startup the 1394 nexus driver.  This is called after all of the HW has
 *    been initialized (in both attach and resume) and we are ready to
 *    participate on the bus.
 */
int
hci1394_ohci_startup(hci1394_ohci_handle_t ohci_hdl)
{
	int status;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_startup_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * Turn on 1394 link. This allows us to receive 1394 traffic off the
	 * bus
	 */
	hci1394_ohci_link_enable(ohci_hdl);

	/*
	 * Reset the 1394 Bus.
	 * Need to do this so that the link layer can collect all of the self-id
	 * packets.  The Interrupt routine will cause further initialization
	 * after the bus reset has completed
	 */
	status = hci1394_ohci_bus_reset(ohci_hdl);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_1_DEBUG(hci1394_ohci_startup_exit,
		    HCI1394_TNF_HAL_ERROR, "", tnf_string, errmsg,
		    "failed to reset bus");
		TNF_PROBE_0_DEBUG(hci1394_ohci_startup_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* setup out initial interrupt mask and enable interrupts */
	hci1394_isr_mask_setup(ohci_hdl->soft_state);
	hci1394_ohci_intr_master_enable(ohci_hdl);

	TNF_PROBE_0_DEBUG(hci1394_ohci_startup_exit, HCI1394_TNF_HAL_STACK,
	    "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_postwr_addr()
 *    Read the Posted Write Address registers.  This should be read when a
 *    posted write error is detected to find out what transaction had an error.
 */
void
hci1394_ohci_postwr_addr(hci1394_ohci_handle_t ohci_hdl, uint64_t *addr)
{
	uint32_t reg;


	ASSERT(ohci_hdl != NULL);
	ASSERT(addr != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_postwr_addr_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* read in the errored address */
	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->posted_write_addrhi);
	*addr = ((uint64_t)reg) << 32;
	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->posted_write_addrlo);
	*addr = *addr | (uint64_t)reg;

	/*
	 * Interrupt should be cleared after reading the posted write address.
	 * See 13.2.8.1 in OpenHCI spec v1.0.
	 */
	hci1394_ohci_intr_clear(ohci_hdl, OHCI_INTR_POST_WR_ERR);

	TNF_PROBE_0_DEBUG(hci1394_ohci_postwr_addr_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_guid()
 *    Return the adapter's GUID
 */
uint64_t
hci1394_ohci_guid(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t reg;
	uint64_t guid;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_guid_enter, HCI1394_TNF_HAL_STACK, "");

	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->guid_hi);
	guid = ((uint64_t)reg) << 32;
	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->guid_lo);
	guid = guid | (uint64_t)reg;

	TNF_PROBE_0_DEBUG(hci1394_ohci_guid_exit, HCI1394_TNF_HAL_STACK, "");

	return (guid);
}


/*
 * hci1394_ohci_csr_read()
 *    Read one of the HW implemented CSR registers.  These include
 *    bus_manager_id, bandwidth_available, channels_available_hi, and
 *    channels_available_lo. Offset should be set to
 *    OHCI_CSR_SEL_BUS_MGR_ID, OHCI_CSR_SEL_BANDWIDTH_AVAIL
 *    OHCI_CSR_SEL_CHANS_AVAIL_HI, or OHCI_CSR_SEL_CHANS_AVAIL_LO.
 */
int
hci1394_ohci_csr_read(hci1394_ohci_handle_t ohci_hdl, uint_t offset,
    uint32_t *data)
{
	uint_t generation;
	int status;


	ASSERT(ohci_hdl != NULL);
	ASSERT(data != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_csr_read_enter, HCI1394_TNF_HAL_STACK,
	    "");

	/*
	 * read the CSR register by doing a cswap with the same compare and
	 * swap value.
	 */
	generation = hci1394_ohci_current_busgen(ohci_hdl);
	status = hci1394_ohci_csr_cswap(ohci_hdl, generation, offset, 0, 0,
	    data);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_csr_read_csw_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_csr_read_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_csr_read_exit, HCI1394_TNF_HAL_STACK,
	    "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_csr_cswap()
 *    Perform a compare/swap on one of the HW implemented CSR registers. These
 *    include bus_manager_id, bandwidth_available, channels_available_hi, and
 *    channels_available_lo. Offset should be set to
 *    OHCI_CSR_SEL_BUS_MGR_ID, OHCI_CSR_SEL_BANDWIDTH_AVAIL
 *    OHCI_CSR_SEL_CHANS_AVAIL_HI, or OHCI_CSR_SEL_CHANS_AVAIL_LO.
 */
int
hci1394_ohci_csr_cswap(hci1394_ohci_handle_t ohci_hdl, uint_t generation,
    uint_t offset, uint32_t compare, uint32_t swap, uint32_t *old)
{
	int count;
	uint32_t ohci_reg;


	ASSERT(ohci_hdl != NULL);
	ASSERT(old != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_csr_cswap_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * Make sure we have not gotten a bus reset since this action was
	 * started.
	 */
	if (generation != hci1394_ohci_current_busgen(ohci_hdl)) {
		TNF_PROBE_1(hci1394_ohci_invbusgen_fail, HCI1394_TNF_HAL_ERROR,
		    "", tnf_string, errmsg, "Invalid Bus Generation");
		TNF_PROBE_0_DEBUG(hci1394_ohci_csr_cswap_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	mutex_enter(&ohci_hdl->ohci_mutex);

	/* init csrData and csrCompare */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->csr_data, swap);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->csr_compare_data, compare);

	/* start the compare swap */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->csr_ctrl, offset & OHCI_CSR_SELECT);

	/*
	 * The CSR access should be immediate.  There in nothing that officially
	 * states this so we will wait up to 2uS just in case before we timeout.
	 * We actually perform a compare swap with both compare and swap set
	 * to the same value.  This will return the old value which is in
	 * essence, a read.
	 */
	count = 0;
	while (count < 2) {
		/* See if the compare swap is done */
		ohci_reg = ddi_get32(ohci_hdl->ohci_reg_handle,
		    &ohci_hdl->ohci_regs->csr_ctrl);
		if ((ohci_reg & OHCI_CSR_DONE) != 0) {
			/* The compare swap is done, break out of the loop */
			break;
		}
		/*
		 * The compare swap has not completed yet, wait 1uS, increment
		 * the count and try again
		 */
		drv_usecwait(1);
		count++;
	}

	/* If we timed out, return an error */
	if (count >= 2) {
		*old = 0;
		mutex_exit(&ohci_hdl->ohci_mutex);
		TNF_PROBE_0(hci1394_ohci_phy_csr_timeout_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_csr_cswap_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Copy the old data into the return parameter */
	*old = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->csr_data);

	mutex_exit(&ohci_hdl->ohci_mutex);

	/*
	 * There is a race condition in the OpenHCI design here. After checking
	 * the generation and before performing the cswap, we could get a bus
	 * reset and incorrectly set something like the bus manager.  This would
	 * put us into a condition where we would not have a bus manager and
	 * we would think there was one. If it is possible that this race
	 * condition occured, we will reset the bus to clean things up. We only
	 * care about this if the compare swap was successful.
	 */
	if (generation != hci1394_ohci_current_busgen(ohci_hdl)) {
		if (*old == compare) {
			(void) hci1394_ohci_bus_reset(ohci_hdl);
			TNF_PROBE_1(hci1394_ohci_invbusgen_fail,
			    HCI1394_TNF_HAL_ERROR, "", tnf_string, errmsg,
			    "Invalid Bus Generation");
			TNF_PROBE_0_DEBUG(hci1394_ohci_csr_cswap_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_csr_cswap_exit, HCI1394_TNF_HAL_STACK,
	    "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_contender_enable()
 *    Set the contender bit in the PHY.  This routine should only be called
 *    if our PHY is 1394A compliant. (i.e. this routine should not be called
 *    for a 1394-1995 PHY).
 */
int
hci1394_ohci_contender_enable(hci1394_ohci_handle_t ohci_hdl)
{
	int status;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_contender_enable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * Make sure that phy is not a 1394-1995 phy. Those phy's do not have a
	 * contender bit to set.
	 */
	if (ohci_hdl->ohci_phy == H1394_PHY_1995) {
		TNF_PROBE_0(hci1394_ohci_phy_type_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_contender_enable_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Set the Contender Bit */
	status = hci1394_ohci_phy_set(ohci_hdl, 0x4, OHCI_PHY_CNTDR);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_phy_set_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_contender_enable_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_contender_enable_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_root_holdoff_enable()
 *    Set the root holdoff bit in the PHY. Since there are race conditions when
 *    writing to PHY register 1 (which can get updated from a PHY packet off the
 *    bus), we cache this state until a "long" bus reset is issued.
 */
int
hci1394_ohci_root_holdoff_enable(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_root_holdoff_enable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ohci_hdl->ohci_set_root_holdoff = B_TRUE;

	TNF_PROBE_0_DEBUG(hci1394_ohci_root_holdoff_enable_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_gap_count_set()
 *    Set the gap count in the PHY. Since there are race conditions when writing
 *    to PHY register 1 (which can get updated from a PHY packet off the bus),
 *    we cache this gap count until a "long" bus reset is issued.
 */
int
hci1394_ohci_gap_count_set(hci1394_ohci_handle_t ohci_hdl, uint_t gap_count)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_gap_count_set_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ohci_hdl->ohci_set_gap_count = B_TRUE;
	ohci_hdl->ohci_gap_count = gap_count & OHCI_PHY_MAX_GAP;

	TNF_PROBE_0_DEBUG(hci1394_ohci_gap_count_set_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_phy_filter_set()
 *    Enable a node (or nodes) to perform transactions to our physical
 *    memory. OpenHCI allows you to disable/enable physical requests on a node
 *    per node basis.  A physical request is basically a read/write to 1394
 *    address space 0x0 - 0xFFFFFFFF.  This address goes out to the IO MMU (in
 *    the case of a SPARC machine).  The HAL starts with all nodes unable to
 *    read/write physical memory.  The Services Layer will call down and enable
 *    nodes via setting a physical filter bit for that given node.  Since node
 *    numbers change every bus reset, the services layer has to call down after
 *    every bus reset to re-enable physical accesses. (NOTE: the hardware
 *    automatically clears these bits.
 */
int
hci1394_ohci_phy_filter_set(hci1394_ohci_handle_t ohci_hdl, uint64_t mask,
    uint_t generation)
{
	uint32_t data;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_filter_set_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * Make sure we have not gotten a bus reset since this action was
	 * started.
	 */
	if (generation != hci1394_ohci_current_busgen(ohci_hdl)) {
		TNF_PROBE_1(hci1394_ohci_invbusgen_fail, HCI1394_TNF_HAL_ERROR,
		    "", tnf_string, errmsg, "Invalid Bus Generation");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_filter_set_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	data = (uint32_t)((mask >> 32) & 0xFFFFFFFF);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->phys_req_filterhi_set, data);
	data = (uint32_t)(mask & 0xFFFFFFFF);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->phys_req_filterlo_set, data);

	/*
	 * There is a race condition in the OpenHCI design here. After checking
	 * the generation and before setting the physical filter bits, we could
	 * get a bus reset and incorrectly set the physical filter bits.  If it
	 * is possible that this race condition occured, we will reset the bus
	 * to clean things up.
	 */
	if (generation != hci1394_ohci_current_busgen(ohci_hdl)) {
		(void) hci1394_ohci_bus_reset(ohci_hdl);
		TNF_PROBE_1(hci1394_ohci_filterrace_fail, HCI1394_TNF_HAL_ERROR,
		    "", tnf_string, errmsg, "Invalid Bus Generation");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_filter_set_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_SUCCESS);
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_filter_set_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_phy_filter_clr()
 *    Disable a node (or nodes) from performing transactions to our physical
 *    memory. See hci1394_ohci_phy_filter_set() above for more info.
 */
int
hci1394_ohci_phy_filter_clr(hci1394_ohci_handle_t ohci_hdl,
    uint64_t mask, uint_t generation)
{
	uint32_t data;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_filter_clr_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * Make sure we have not gotten a bus reset since this action was
	 * started.
	 */
	if (generation != hci1394_ohci_current_busgen(ohci_hdl)) {
		TNF_PROBE_1(hci1394_ohci_invbusgen_fail, HCI1394_TNF_HAL_ERROR,
		    "", tnf_string, errmsg, "Invalid Bus Generation");
		TNF_PROBE_0_DEBUG(hci1394_ohci_phy_filter_clr_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	data = (uint32_t)((mask >> 32) & 0xFFFFFFFF);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->phys_req_filterhi_clr, data);
	data = (uint32_t)(mask & 0xFFFFFFFF);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->phys_req_filterlo_clr, data);

	TNF_PROBE_0_DEBUG(hci1394_ohci_phy_filter_clr_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_bus_reset_short()
 *    Perform a 1394A short bus reset.  This function should only be called
 *    on an adapter with a 1394A PHY (or later).
 */
int
hci1394_ohci_bus_reset_short(hci1394_ohci_handle_t ohci_hdl)
{
	int status;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_bus_reset_short_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * Make sure that phy is not a 1394-1995 phy. Those phy's do not have a
	 * contender bit to set.
	 */
	if (ohci_hdl->ohci_phy == H1394_PHY_1995) {
		TNF_PROBE_0(hci1394_ohci_brs_phy_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_bus_reset_short_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Initiate the short bus reset */
	status = hci1394_ohci_phy_set(ohci_hdl, 0x5, OHCI_PHY_ISBR);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_phy_set_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_bus_reset_short_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_bus_reset_short_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (status);
}


/*
 * hci1394_ohci_cfgrom_update()
 *    Update the config rom with the provided contents.  The config rom is
 *    provided as a byte stream which is multiple of 4 bytes large.  The
 *    size is passed as a quadlet (4 bytes) count.  The entire contents
 *    of the config rom is updated at once.  We do not provide a partial
 *    update interface.
 */
void
hci1394_ohci_cfgrom_update(hci1394_ohci_handle_t ohci_hdl, void *local_buf,
    uint_t quadlet_count)
{
	uint32_t *data;


	ASSERT(ohci_hdl != NULL);
	ASSERT(local_buf != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_cfgrom_update_enter,
	    HCI1394_TNF_HAL_STACK, "");

	data = (uint32_t *)local_buf;

	/* zero out the config ROM header to start */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->config_rom_hdr, 0);

	/* copy Services Layer buffer into config rom buffer */
	ddi_rep_put8(ohci_hdl->ohci_cfgrom.bi_handle, local_buf,
	    (uint8_t *)ohci_hdl->ohci_cfgrom.bi_kaddr, quadlet_count << 2,
	    DDI_DEV_AUTOINCR);

	(void) ddi_dma_sync(ohci_hdl->ohci_cfgrom.bi_dma_handle, 0,
	    quadlet_count << 2, DDI_DMA_SYNC_FORDEV);

	/*
	 * setup OHCI bus options and config rom hdr registers. We need to swap
	 * the config rom header and bus options on an X86 machine since the
	 * data is provided to us as a byte stream and the OHCI registers expect
	 * a big endian 32-bit number.
	 */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->bus_options, OHCI_SWAP32(data[2]));
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->config_rom_hdr, OHCI_SWAP32(data[0]));

	TNF_PROBE_0_DEBUG(hci1394_ohci_cfgrom_update_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_nodeid_get()
 *    Return our current nodeid (bus #/Node #)
 */
void
hci1394_ohci_nodeid_get(hci1394_ohci_handle_t ohci_hdl, uint_t *nodeid)
{
	uint32_t reg;

	ASSERT(ohci_hdl != NULL);
	ASSERT(nodeid != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_nodeid_get_enter, HCI1394_TNF_HAL_STACK,
	    "");
	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->node_id);
	*nodeid = (reg & 0xFFFF) << 16;
	TNF_PROBE_0_DEBUG(hci1394_ohci_nodeid_get_exit, HCI1394_TNF_HAL_STACK,
	    "");
}


/*
 * hci1394_ohci_nodeid_set()
 *    Set our current nodeid (bus #/Node #).  This actually sets our bus number.
 *    Our node number cannot be set by software.  This is usually trigered via
 *    a write to the CSR NODEIDS register.
 */
void
hci1394_ohci_nodeid_set(hci1394_ohci_handle_t ohci_hdl, uint_t nodeid)
{
	uint32_t reg;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_nodeid_set_enter,
	    HCI1394_TNF_HAL_STACK, "");

	reg = ((nodeid & 0xFFC00000) >> 16);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->node_id, reg);

	TNF_PROBE_0_DEBUG(hci1394_ohci_nodeid_set_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_nodeid_info()
 *    Return our current nodeid (bus #/Node #).  This also returns whether or
 *    not our nodeid error bit is set.  This is useful in determining if the
 *    bus reset completed without errors in the selfid complete interrupt
 *    processing.
 */
void
hci1394_ohci_nodeid_info(hci1394_ohci_handle_t ohci_hdl, uint_t *nodeid,
    boolean_t *error)
{
	uint32_t reg;

	ASSERT(ohci_hdl != NULL);
	ASSERT(nodeid != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_nodeid_info_enter,
	    HCI1394_TNF_HAL_STACK, "");

	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->node_id);
	*nodeid = reg & 0xFFFF;
	if ((reg & OHCI_NDID_IDVALID) == 0) {
		*error = B_TRUE;
	} else {
		*error = B_FALSE;
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_nodeid_info_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_cycletime_get()
 *    Return the current cycle time
 */
void
hci1394_ohci_cycletime_get(hci1394_ohci_handle_t ohci_hdl,
    uint32_t *cycle_time)
{
	ASSERT(ohci_hdl != NULL);
	ASSERT(cycle_time != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_cycletime_get_enter,
	    HCI1394_TNF_HAL_STACK, "");
	*cycle_time = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->isoch_cycle_timer);
	TNF_PROBE_0_DEBUG(hci1394_ohci_cycletime_get_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_cycletime_get()
 *    Set the cycle time
 */
void
hci1394_ohci_cycletime_set(hci1394_ohci_handle_t ohci_hdl,
    uint32_t cycle_time)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_cycletime_set_enter,
	    HCI1394_TNF_HAL_STACK, "");
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->isoch_cycle_timer, cycle_time);
	TNF_PROBE_0_DEBUG(hci1394_ohci_cycletime_set_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_bustime_get()
 *    Return the current bus time.
 */
void
hci1394_ohci_bustime_get(hci1394_ohci_handle_t ohci_hdl, uint32_t *bus_time)
{
	uint32_t bus_time1;
	uint32_t bus_time2;
	uint32_t cycle_time;


	ASSERT(ohci_hdl != NULL);
	ASSERT(bus_time != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_bustime_get_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * The bus time is composed of a portion of the cycle time and the
	 * cycle time rollover count (ohci_bustime_count). There is a race
	 * condition where we read the rollover count and then the cycle
	 * timer rolls over.  This is the reason for the double read of the
	 * rollover count.
	 */
	do {
		bus_time1 = ohci_hdl->ohci_bustime_count;
		cycle_time = ddi_get32(ohci_hdl->ohci_reg_handle,
		    &ohci_hdl->ohci_regs->isoch_cycle_timer);
		bus_time2 = ohci_hdl->ohci_bustime_count;
	} while (bus_time1 != bus_time2);

	*bus_time = (bus_time2 << 7) | (cycle_time >> 25);

	TNF_PROBE_0_DEBUG(hci1394_ohci_bustime_get_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_bustime_set()
 *    Set the cycle timer rollover portion of the bus time.
 */
void
hci1394_ohci_bustime_set(hci1394_ohci_handle_t ohci_hdl, uint32_t bus_time)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_bustime_set_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * we will start with the cycle 64 seconds interrupt disabled. If this
	 * is the first write to bus time, enable the interrupt.
	 */
	if (ohci_hdl->ohci_bustime_enabled == B_FALSE) {
		ohci_hdl->ohci_bustime_enabled = B_TRUE;
		/* Clear the cycle64Seconds interrupt then enable it */
		hci1394_ohci_intr_clear(ohci_hdl, OHCI_INTR_CYC_64_SECS);
		hci1394_ohci_intr_enable(ohci_hdl, OHCI_INTR_CYC_64_SECS);
	}
	ohci_hdl->ohci_bustime_count = (bus_time >> 7);

	TNF_PROBE_0_DEBUG(hci1394_ohci_bustime_set_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_atreq_retries_get()
 *    Get the number of atreq retries we will perform.
 */
void
hci1394_ohci_atreq_retries_get(hci1394_ohci_handle_t ohci_hdl,
    uint_t *atreq_retries)
{
	uint32_t reg;

	ASSERT(ohci_hdl != NULL);
	ASSERT(atreq_retries != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_atreq_retries_get_enter,
	    HCI1394_TNF_HAL_STACK, "");
	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_retries);
	*atreq_retries = reg & OHCI_RET_MAX_ATREQ_MASK;
	TNF_PROBE_0_DEBUG(hci1394_ohci_atreq_retries_get_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_atreq_retries_get()
 *    Set the number of atreq retries we will perform.
 */
void
hci1394_ohci_atreq_retries_set(hci1394_ohci_handle_t ohci_hdl,
    uint_t atreq_retries)
{
	uint32_t reg;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_atreq_retries_set_enter,
	    HCI1394_TNF_HAL_STACK, "");

	mutex_enter(&ohci_hdl->ohci_mutex);
	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_retries);
	reg = reg & ~OHCI_RET_MAX_ATREQ_MASK;
	reg = reg | (atreq_retries & OHCI_RET_MAX_ATREQ_MASK);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_retries, reg);
	mutex_exit(&ohci_hdl->ohci_mutex);

	TNF_PROBE_0_DEBUG(hci1394_ohci_atreq_retries_set_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_isr_cycle64seconds()
 *    Interrupt handler for the cycle64seconds interrupt.
 */
void
hci1394_ohci_isr_cycle64seconds(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t cycle_time;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_isr_cycle64seconds_enter,
	    HCI1394_TNF_HAL_STACK, "");

	hci1394_ohci_intr_clear(ohci_hdl, OHCI_INTR_CYC_64_SECS);
	cycle_time = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->isoch_cycle_timer);

	/*
	 * cycle64second interrupts when the MSBit in the cycle timer changes
	 * state.  We only care about rollover so we will increment only when
	 * the MSBit is set to 0.
	 */
	if ((cycle_time & 0x80000000) == 0) {
		ohci_hdl->ohci_bustime_count++;
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_isr_cycle64seconds_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_isr_phy()
 *    Interrupt handler for a PHY event
 */
void
hci1394_ohci_isr_phy(hci1394_ohci_handle_t ohci_hdl)
{
	uint_t phy_status;
	int status;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_isr_phy_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* clear the interrupt */
	hci1394_ohci_intr_clear(ohci_hdl, OHCI_INTR_PHY);

	/* increment the statistics count */
	ohci_hdl->ohci_drvinfo->di_stats.st_phy_isr++;

	/*
	 * If the PHY is a 1995 phy, just return since there are no status bits
	 * to read.
	 */
	if (ohci_hdl->ohci_phy == H1394_PHY_1995) {
		TNF_PROBE_0(hci1394_ohci_phy_isr_1995,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_isr_phy_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return;
	}

	/* See why we got this interrupt */
	status = hci1394_ohci_phy_read(ohci_hdl, 5, &phy_status);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_phy_read_failed,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_isr_phy_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return;
	}

	if (phy_status & OHCI_PHY_LOOP_ERR) {
		ohci_hdl->ohci_drvinfo->di_stats.st_phy_loop_err++;
		cmn_err(CE_NOTE, "hci1394(%d): ERROR - bus loop detected",
		    ohci_hdl->ohci_drvinfo->di_instance);
		TNF_PROBE_0(hci1394_ohci_phy_isr_loop, HCI1394_TNF_HAL, "");
	}
	if (phy_status & OHCI_PHY_PWRFAIL_ERR) {
		ohci_hdl->ohci_drvinfo->di_stats.st_phy_pwrfail_err++;
		TNF_PROBE_0(hci1394_ohci_phy_isr_pwr, HCI1394_TNF_HAL, "");
	}
	if (phy_status & OHCI_PHY_TIMEOUT_ERR) {
		ohci_hdl->ohci_drvinfo->di_stats.st_phy_timeout_err++;
		TNF_PROBE_0(hci1394_ohci_phy_isr_tmout, HCI1394_TNF_HAL, "");
	}
	if (phy_status & OHCI_PHY_PORTEVT_ERR) {
		ohci_hdl->ohci_drvinfo->di_stats.st_phy_portevt_err++;
		TNF_PROBE_0(hci1394_ohci_phy_isr_pevt, HCI1394_TNF_HAL, "");
	}

	/* clear any set status bits */
	status = hci1394_ohci_phy_write(ohci_hdl, 5, phy_status);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_phy_write_failed,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_isr_phy_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return;
	}

	/*
	 * Disable the PHY interrupt. We are getting stuck in this ISR in
	 * certain PHY implementations so we will disable the interrupt until
	 * we see a selfid complete.
	 */
	hci1394_ohci_intr_disable(ohci_hdl, OHCI_INTR_PHY);

	TNF_PROBE_0_DEBUG(hci1394_ohci_isr_phy_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_root_check
 *    Returns status about if we are currently the root node on the 1394 bus.
 *    returns B_TRUE if we are the root,  B_FALSE if we are not the root.
 */
boolean_t
hci1394_ohci_root_check(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t reg;
	int status;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_root_check_enter, HCI1394_TNF_HAL_STACK,
	    "");
	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->node_id);
	if ((reg & OHCI_REG_NODEID_ROOT) && (reg & OHCI_NDID_IDVALID)) {
		status = B_TRUE;
	} else {
		status = B_FALSE;
	}
	TNF_PROBE_0_DEBUG(hci1394_ohci_root_check_exit, HCI1394_TNF_HAL_STACK,
	    "");

	return (status);
}


/*
 * hci1394_ohci_cmc_check()
 *    Returns status about if we are cycle master capable. Returns
 *    B_TRUE if we are the cycle master capable, B_FALSE if we are not the cycle
 *    master capable.
 */
boolean_t
hci1394_ohci_cmc_check(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t reg;
	int status;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_cmc_check_enter, HCI1394_TNF_HAL_STACK,
	    "");
	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->bus_options);
	if (reg & OHCI_REG_BUSOPTIONS_CMC) {
		status = B_TRUE;
	} else {
		status = B_FALSE;
	}
	TNF_PROBE_0_DEBUG(hci1394_ohci_cmc_check_exit, HCI1394_TNF_HAL_STACK,
	    "");

	return (status);
}


/*
 * hci1394_ohci_cycle_master_enable()
 *    Enables us to be cycle master.  If we are root, we will start generating
 *    cycle start packets.
 */
void
hci1394_ohci_cycle_master_enable(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_cycle_master_enable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* First make sure that cycleTooLong is clear */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->intr_event_clr, OHCI_INTR_CYC_TOO_LONG);

	/* Enable Cycle Master */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->link_ctrl_set, OHCI_LC_CYC_MAST);

	TNF_PROBE_0_DEBUG(hci1394_ohci_cycle_master_enable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_cycle_master_disable()
 *    Disabled us from being cycle master. If we are root, we will stop
 *    generating cycle start packets.
 */
void
hci1394_ohci_cycle_master_disable(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_cycle_master_disable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* disable cycle master */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->link_ctrl_clr, OHCI_LC_CYC_MAST);

	TNF_PROBE_0_DEBUG(hci1394_ohci_cycle_master_disable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_resume()
 *    Re-initialize the openHCI HW during a resume. (after a power suspend)
 */
int
hci1394_ohci_resume(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t quadlet;
	int status;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_resume_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* Re-initialize the OpenHCI chip */
	status = hci1394_ohci_chip_init(ohci_hdl);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_chip_init_fail, HCI1394_TNF_HAL_ERROR,
		    "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_resume_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Re-initialize the PHY */
	status = hci1394_ohci_phy_resume(ohci_hdl);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_phy_resume_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_resume_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Re-initialize any 1394A features we are using */
	status = hci1394_ohci_1394a_resume(ohci_hdl);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_ohci_1394a_resume_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_resume_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Tell OpenHCI where the Config ROM buffer is */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->config_rom_maplo,
	    (uint32_t)ohci_hdl->ohci_cfgrom.bi_cookie.dmac_address);

	/* Tell OpenHCI where the SelfId buffer is */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->self_id_buflo,
	    (uint32_t)ohci_hdl->ohci_selfid.bi_cookie.dmac_address);

	/* Enable selfid DMA engine */
	hci1394_ohci_selfid_enable(ohci_hdl);

	/*
	 * re-setup OHCI bus options and config rom hdr registers. We need to
	 * read from the config rom using ddi_rep_get8 since it is stored as
	 * a byte stream. We need to swap the config rom header and bus options
	 * on an X86 machine since the data is a byte stream and the OHCI
	 *  registers expect a big endian 32-bit number.
	 */
	ddi_rep_get8(ohci_hdl->ohci_cfgrom.bi_handle, (uint8_t *)&quadlet,
	    &((uint8_t *)ohci_hdl->ohci_cfgrom.bi_kaddr)[8], 4,
	    DDI_DEV_AUTOINCR);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->bus_options, OHCI_SWAP32(quadlet));
	ddi_rep_get8(ohci_hdl->ohci_cfgrom.bi_handle, (uint8_t *)&quadlet,
	    &((uint8_t *)ohci_hdl->ohci_cfgrom.bi_kaddr)[0], 4,
	    DDI_DEV_AUTOINCR);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->config_rom_hdr, OHCI_SWAP32(quadlet));

	TNF_PROBE_0_DEBUG(hci1394_ohci_resume_exit,
	    HCI1394_TNF_HAL_STACK, "");
	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_selfid_init()
 *    Initialize the selfid buffer
 */
static int
hci1394_ohci_selfid_init(hci1394_ohci_handle_t ohci_hdl)
{
	hci1394_buf_parms_t parms;
	int status;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_init_selfid_enter, HCI1394_TNF_HAL_STACK, "");

	/*
	 * Setup for 2K buffer, aligned on a 2Kbyte address boundary. Make sure
	 * that the buffer is not broken up into multiple cookies.  OpenHCI can
	 * only handle one address for the selfid buffer location.
	 */
	parms.bp_length = 2048;
	parms.bp_max_cookies = 1;
	parms.bp_alignment = 2048;
	status = hci1394_buf_alloc(ohci_hdl->ohci_drvinfo, &parms,
	    &ohci_hdl->ohci_selfid, &ohci_hdl->ohci_selfid_handle);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_buf_alloc_fail, HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_init_selfid_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Tell OpenHCI where the buffer is */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->self_id_buflo,
	    (uint32_t)ohci_hdl->ohci_selfid.bi_cookie.dmac_address);

	/* Enable selfid DMA engine */
	hci1394_ohci_selfid_enable(ohci_hdl);

	TNF_PROBE_0_DEBUG(hci1394_init_selfid_exit, HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_selfid_enable()
 *    Allow selfid packets to be placed into the selfid buffer.  This should be
 *    called after the selfid buffer address has been setup in the HW.
 */
void
hci1394_ohci_selfid_enable(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_selfid_enable_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * Allow selfid packets to be received.  This should be called during
	 * driver attach after the selfid buffer address has been initialized.
	 *
	 * Link Control Register
	 *   rscSelfId = 1 <= bit 9
	 */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->link_ctrl_set, OHCI_LC_RCV_SELF);

	TNF_PROBE_0_DEBUG(hci1394_ohci_selfid_enable_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_selfid_read()
 *    Read a word out of the selfid buffer.
 */
void
hci1394_ohci_selfid_read(hci1394_ohci_handle_t ohci_hdl, uint_t offset,
    uint32_t *data)
{
	ASSERT(ohci_hdl != NULL);
	ASSERT(data != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_selfid_read_enter,
	    HCI1394_TNF_HAL_STACK, "");
	*data = ddi_get32(ohci_hdl->ohci_selfid.bi_handle,
	    &((uint32_t *)ohci_hdl->ohci_selfid.bi_kaddr)[offset]);
	TNF_PROBE_0_DEBUG(hci1394_ohci_selfid_read_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_selfid_info()
 *    Return the current bus generation, the number of bytes currently in the
 *    selfid buffer, and if we have seen any selfid errors.
 */
void
hci1394_ohci_selfid_info(hci1394_ohci_handle_t ohci_hdl, uint_t *busgen,
    uint_t *size, boolean_t *error)
{
	uint32_t reg;


	ASSERT(ohci_hdl != NULL);
	ASSERT(busgen != NULL);
	ASSERT(size != NULL);
	ASSERT(error != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_selfid_info_enter,
	    HCI1394_TNF_HAL_STACK, "");

	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->self_id_count);
	*busgen = (reg & OHCI_SLFC_GEN_MASK) >> OHCI_SLFC_GEN_SHIFT;
	*size = reg & OHCI_SLFC_NUM_QUADS_MASK;
	if ((reg & OHCI_SLFC_ERROR) == 0) {
		*error = B_FALSE;
	} else {
		*error = B_TRUE;
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_selfid_info_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_selfid_buf_current()
 *    Test if the selfid buffer is current.  Return B_TRUE if it is current and
 *    B_FALSE if it is not current.
 */
boolean_t
hci1394_ohci_selfid_buf_current(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t reg;
	int status;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_selfid_buf_current_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * if the generation stored in the selfid buffer is not equal to the
	 * generation we have previously stored, the selfid buffer is not
	 * current. (It maybe older or it maybe newer)
	 */
	reg = ddi_get32(ohci_hdl->ohci_selfid.bi_handle,
	    &((uint32_t *)ohci_hdl->ohci_selfid.bi_kaddr)[0]);
	if (ohci_hdl->ohci_drvinfo->di_gencnt != ((reg & OHCI_SLFC_GEN_MASK) >>
	    OHCI_SLFC_GEN_SHIFT)) {
		status = B_FALSE;
	} else {
		status = B_TRUE;
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_selfid_buf_current_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (status);
}


/*
 * hci1394_ohci_selfid_sync()
 *    Perform a ddi_dma_sync on the selfid buffer
 */
void
hci1394_ohci_selfid_sync(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_selfid_sync_enter,
	    HCI1394_TNF_HAL_STACK, "");
	(void) ddi_dma_sync(ohci_hdl->ohci_selfid.bi_dma_handle, 0,
	    ohci_hdl->ohci_selfid.bi_length, DDI_DMA_SYNC_FORKERNEL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_selfid_sync_exit, HCI1394_TNF_HAL_STACK,
	    "");
}


/*
 * hci1394_ohci_cfgrom_init()
 *    Initialize the configuration ROM buffer
 */
static int
hci1394_ohci_cfgrom_init(hci1394_ohci_handle_t ohci_hdl)
{
	hci1394_buf_parms_t parms;
	int status;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_cfgrom_init_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * Setup for 1K buffer, aligned at 1K address boundary, and allow no
	 * less than 4 byte data transfers. Create the Buffer.  Make sure that
	 * the buffer is not broken up into multiple cookies.  OpenHCI can only
	 * handle one address for the config ROM buffer location.
	 */
	parms.bp_length = 1024;
	parms.bp_max_cookies = 1;
	parms.bp_alignment = 1024;
	status = hci1394_buf_alloc(ohci_hdl->ohci_drvinfo, &parms,
	    &ohci_hdl->ohci_cfgrom, &ohci_hdl->ohci_cfgrom_handle);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_buf_alloc_fail, HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_cfgrom_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Tell OpenHCI where the buffer is */
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->config_rom_maplo,
	    (uint32_t)ohci_hdl->ohci_cfgrom.bi_cookie.dmac_address);

	TNF_PROBE_0_DEBUG(hci1394_ohci_cfgrom_init_exit, HCI1394_TNF_HAL_STACK,
	    "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_bus_capabilities()
 *    Return our current bus capabilities
 */
void
hci1394_ohci_bus_capabilities(hci1394_ohci_handle_t ohci_hdl,
    uint32_t *bus_capabilities)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_bus_capabilities_enter,
	    HCI1394_TNF_HAL_STACK, "");
	/*
	 * read in the bus options register.  Set bits saying that we are isoch
	 * resource manager capable, Cycle master capable, and Isoch capable
	 */
	*bus_capabilities = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->bus_options) | (OHCI_BOPT_IRMC |
	    OHCI_BOPT_CMC | OHCI_BOPT_ISC);
	TNF_PROBE_0_DEBUG(hci1394_ohci_bus_capabilities_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_at_active()
 *    Returns status one if either of the AT engines are active.  If either AT
 *    engine is active, we return B_TRUE.  If both AT engines are not active, we
 *    return B_FALSE.
 */
boolean_t
hci1394_ohci_at_active(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t reg;


	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_at_active_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/* see if atreq active bit set */
	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_req.ctxt_ctrl_set);
	if (reg & OHCI_CC_ACTIVE_MASK) {
		/* atreq engine is still active */
		TNF_PROBE_0(hci1394_ohci_atreq_active_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_at_active_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (B_TRUE);
	}

	/* see if atresp active bit set */
	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_resp.ctxt_ctrl_set);
	if (reg & OHCI_CC_ACTIVE_MASK) {
		/* atresp engine is still active */
		TNF_PROBE_0(hci1394_ohci_atresp_active_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_ohci_at_active_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (B_TRUE);
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_at_active_exit,
	    HCI1394_TNF_HAL_STACK, "");

	/* both atreq and atresp active bits are cleared */
	return (B_FALSE);
}


/*
 * hci1394_ohci_atreq_start()
 *    Start the atreq dma engine.  Set the address of the first descriptor
 *    to read in equal to cmdptr.
 */
void
hci1394_ohci_atreq_start(hci1394_ohci_handle_t ohci_hdl, uint32_t cmdptr)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_atreq_start_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_req.cmd_ptrlo, cmdptr);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_req.ctxt_ctrl_set, OHCI_CC_RUN_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_atreq_start_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_atreq_wake()
 *    Wake up the atreq dma engine.  This should be called when a new descriptor
 *    is added to the Q and the dma engine has already be started.  It it OK to
 *    call this when the DMA engine is active.
 */
void
hci1394_ohci_atreq_wake(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_atreq_wake_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_req.ctxt_ctrl_set, OHCI_CC_WAKE_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_atreq_wake_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_atreq_stop()
 *    Stop the atreq dma engine.  No further descriptors will be read until
 *    it dma engine is started again.
 */
void
hci1394_ohci_atreq_stop(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_atreq_stop_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_req.ctxt_ctrl_clr, OHCI_CC_RUN_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_atreq_stop_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_arresp_start()
 *    Start the arresp dma engine.  Set the address of the first descriptor
 *    to read in equal to cmdptr.
 */
void
hci1394_ohci_arresp_start(hci1394_ohci_handle_t ohci_hdl, uint32_t cmdptr)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_arresp_start_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ar_resp.cmd_ptrlo, cmdptr);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ar_resp.ctxt_ctrl_set, OHCI_CC_RUN_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_arresp_start_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_arresp_wake()
 *    Wake up the arresp dma engine.  This should be called when a new
 *    descriptor is added to the Q and the dma engine has already be started.
 *    It is OK to call this when the DMA engine is active.
 */
void
hci1394_ohci_arresp_wake(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_arresp_wake_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ar_resp.ctxt_ctrl_set, OHCI_CC_WAKE_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_arresp_wake_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_atreq_stop()
 *    Stop the arresp dma engine.  No further data will be received after any
 *    current packets being received have finished.
 */
void
hci1394_ohci_arresp_stop(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_arresp_stop_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ar_resp.ctxt_ctrl_clr, OHCI_CC_RUN_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_arresp_stop_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_arreq_start()
 *    Start the arreq dma engine.  Set the address of the first descriptor
 *    to read in equal to cmdptr.
 */
void
hci1394_ohci_arreq_start(hci1394_ohci_handle_t ohci_hdl, uint32_t cmdptr)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_arreq_start_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ar_req.cmd_ptrlo, cmdptr);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ar_req.ctxt_ctrl_set, OHCI_CC_RUN_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_arreq_start_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_arreq_wake()
 *    Wake up the arreq dma engine.  This should be called when a new descriptor
 *    is added to the Q and the dma engine has already be started.  It is OK to
 *    call this when the DMA engine is active.
 */
void
hci1394_ohci_arreq_wake(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_arreq_wake_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ar_req.ctxt_ctrl_set, OHCI_CC_WAKE_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_arreq_wake_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_arreq_stop()
 *    Stop the arreq dma engine.  No further data will be received after any
 *    current packets being received have finished.
 */
void
hci1394_ohci_arreq_stop(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_arreq_stop_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->ar_req.ctxt_ctrl_clr, OHCI_CC_RUN_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_arreq_stop_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_atresp_start()
 *    Start the atresp dma engine.  Set the address of the first descriptor
 *    to read in equal to cmdptr.
 */
void
hci1394_ohci_atresp_start(hci1394_ohci_handle_t ohci_hdl, uint32_t cmdptr)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_atresp_start_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_resp.cmd_ptrlo, cmdptr);
	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_resp.ctxt_ctrl_set, OHCI_CC_RUN_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_atresp_start_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_atresp_wake()
 *    Wake up the atresp dma engine.  This should be called when a new
 *    descriptor is added to the Q and the dma engine has already be started.
 *    It is OK to call this when the DMA engine is active.
 */
void
hci1394_ohci_atresp_wake(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_atresp_wake_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_resp.ctxt_ctrl_set, OHCI_CC_WAKE_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_atresp_wake_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_atresp_stop()
 *    Stop the atresp dma engine.  No further descriptors will be read until
 *    it dma engine is started again.
 */
void
hci1394_ohci_atresp_stop(hci1394_ohci_handle_t ohci_hdl)
{
	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_atresp_stop_enter,
	    HCI1394_TNF_HAL_STACK, "");

	ddi_put32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->at_resp.ctxt_ctrl_clr, OHCI_CC_RUN_MASK);

	TNF_PROBE_0_DEBUG(hci1394_ohci_atresp_stop_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_ohci_1394a_init()
 *    Initialize any 1394a features that we are using.
 */
/* ARGSUSED */
int
hci1394_ohci_1394a_init(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t reg;
	int status;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_1394a_init_enter, HCI1394_TNF_HAL_STACK,
	    "");

	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->hc_ctrl_set);
	if (reg & OHCI_HC_PROG_PHY_ENBL) {
		ddi_put32(ohci_hdl->ohci_reg_handle,
		    &ohci_hdl->ohci_regs->hc_ctrl_set, OHCI_HC_APHY_ENBL);
		status = hci1394_ohci_phy_set(ohci_hdl, 5,
		    (OHCI_PHY_ENBL_ACCEL | OHCI_PHY_ENBL_MULTI));
		if (status != DDI_SUCCESS) {
			TNF_PROBE_0(hci1394_ohci_1394a_init_phy_fail,
			    HCI1394_TNF_HAL_STACK, "");
			TNF_PROBE_0_DEBUG(hci1394_ohci_1394a_init_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_1394a_init_exit, HCI1394_TNF_HAL_STACK,
	    "");
	return (DDI_SUCCESS);
}


/*
 * hci1394_ohci_1394a_init()
 *    Re-initialize any 1394a features that we are using.
 */
/* ARGSUSED */
int
hci1394_ohci_1394a_resume(hci1394_ohci_handle_t ohci_hdl)
{
	uint32_t reg;
	int status;

	ASSERT(ohci_hdl != NULL);
	TNF_PROBE_0_DEBUG(hci1394_ohci_1394a_resume_enter,
	    HCI1394_TNF_HAL_STACK, "");

	reg = ddi_get32(ohci_hdl->ohci_reg_handle,
	    &ohci_hdl->ohci_regs->hc_ctrl_set);
	if (reg & OHCI_HC_PROG_PHY_ENBL) {
		ddi_put32(ohci_hdl->ohci_reg_handle,
		    &ohci_hdl->ohci_regs->hc_ctrl_set, OHCI_HC_APHY_ENBL);
		status = hci1394_ohci_phy_set(ohci_hdl, 5,
		    (OHCI_PHY_ENBL_ACCEL | OHCI_PHY_ENBL_MULTI));
		if (status != DDI_SUCCESS) {
			TNF_PROBE_0(hci1394_ohci_1394a_resume_phy_fail,
			    HCI1394_TNF_HAL_STACK, "");
			TNF_PROBE_0_DEBUG(hci1394_ohci_1394a_resume_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
	}

	TNF_PROBE_0_DEBUG(hci1394_ohci_1394a_resume_exit,
	    HCI1394_TNF_HAL_STACK, "");
	return (DDI_SUCCESS);
}
