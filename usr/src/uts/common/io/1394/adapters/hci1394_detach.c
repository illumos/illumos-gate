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
 * hci1394_detach.c
 *    HBA detach() routine with associated funtions.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/sunddi.h>

#include <sys/1394/h1394.h>
#include <sys/1394/adapters/hci1394.h>
#include <sys/1394/adapters/hci1394_extern.h>



int
hci1394_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	hci1394_state_t *soft_state;

	soft_state = ddi_get_soft_state(hci1394_statep, ddi_get_instance(dip));
	if (soft_state == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		/* Don't allow the HW to generate any more interrupts */
		hci1394_ohci_intr_master_disable(soft_state->ohci);
		hci1394_ohci_it_intr_disable(soft_state->ohci, 0xFFFFFFFF);
		hci1394_ohci_ir_intr_disable(soft_state->ohci, 0xFFFFFFFF);

		/* Clear any pending interrupts - no longer valid */
		hci1394_ohci_intr_clear(soft_state->ohci, 0xFFFFFFFF);
		hci1394_ohci_it_intr_clear(soft_state->ohci, 0xFFFFFFFF);
		hci1394_ohci_ir_intr_clear(soft_state->ohci, 0xFFFFFFFF);

		/* Make sure we tell others on the bus we are dropping out */
		(void) hci1394_ohci_phy_clr(soft_state->ohci, 4, 0xc0);
		ddi_put32(soft_state->ohci->ohci_reg_handle,
		    &soft_state->ohci->ohci_regs->link_ctrl_clr,
		    0xFFFFFFFF);

		/* unregister interrupt handler */
		hci1394_isr_handler_fini(soft_state);

		/* don't accept anymore commands from services layer */
		(void) hci1394_state_set(&soft_state->drvinfo,
		    HCI1394_SHUTDOWN);

		/* Do a long reset on the bus so every one knows we are gone */
		(void) hci1394_ohci_bus_reset_nroot(soft_state->ohci);

		/* Reset the OHCI HW */
		(void) hci1394_ohci_soft_reset(soft_state->ohci);

		/* Flush out async DMA Q's (cancels pendingQ timeouts too) */
		hci1394_async_flush(soft_state->async);

		(void) h1394_detach(&soft_state->drvinfo.di_sl_private,
		    DDI_DETACH);

		/* remove the minor node */
		ddi_remove_minor_node(dip, "devctl");

		/* cleanup */
		hci1394_detach_hardware(soft_state);

		/* cleanup Solaris interrupt stuff */
		hci1394_isr_fini(soft_state);

		/* cleanup soft state stuff */
		hci1394_soft_state_fini(soft_state);

		/* free soft state */
		ddi_soft_state_free(hci1394_statep,
		    soft_state->drvinfo.di_instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		/* Don't allow the HW to generate any more interrupts */
		hci1394_ohci_intr_master_disable(soft_state->ohci);
		hci1394_ohci_it_intr_disable(soft_state->ohci, 0xFFFFFFFF);
		hci1394_ohci_ir_intr_disable(soft_state->ohci, 0xFFFFFFFF);

		/* Clear any pending interrupts - no longer valid */
		hci1394_ohci_intr_clear(soft_state->ohci, 0xFFFFFFFF);
		hci1394_ohci_it_intr_clear(soft_state->ohci, 0xFFFFFFFF);
		hci1394_ohci_ir_intr_clear(soft_state->ohci, 0xFFFFFFFF);

		/* Make sure we tell others on the bus we are dropping out */
		(void) hci1394_ohci_phy_clr(soft_state->ohci, 4, 0xc0);
		ddi_put32(soft_state->ohci->ohci_reg_handle,
		    &soft_state->ohci->ohci_regs->link_ctrl_clr,
		    0xFFFFFFFF);

		/* don't accept anymore commands from services layer */
		(void) hci1394_state_set(&soft_state->drvinfo,
		    HCI1394_SHUTDOWN);

		/* Do a long reset on the bus so every one knows we are gone */
		(void) hci1394_ohci_bus_reset_nroot(soft_state->ohci);

		/* Reset the OHCI HW */
		(void) hci1394_ohci_soft_reset(soft_state->ohci);

		/* Make sure async engine is ready to suspend */
		hci1394_async_suspend(soft_state->async);

		(void) h1394_detach(&soft_state->drvinfo.di_sl_private,
		    DDI_SUSPEND);

		return (DDI_SUCCESS);

	default:
		break;
	}

	return (DDI_FAILURE);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
int
hci1394_quiesce(dev_info_t *dip)
{
	hci1394_state_t *soft_state;

	soft_state = ddi_get_soft_state(hci1394_statep, ddi_get_instance(dip));

	if (soft_state == NULL) {
		return (DDI_FAILURE);
	}

	/* Don't allow the HW to generate any more interrupts */
	hci1394_ohci_intr_master_disable(soft_state->ohci);
	hci1394_ohci_it_intr_disable(soft_state->ohci, 0xFFFFFFFF);
	hci1394_ohci_ir_intr_disable(soft_state->ohci, 0xFFFFFFFF);

	/* Clear any pending interrupts - no longer valid */
	hci1394_ohci_intr_clear(soft_state->ohci, 0xFFFFFFFF);
	hci1394_ohci_it_intr_clear(soft_state->ohci, 0xFFFFFFFF);
	hci1394_ohci_ir_intr_clear(soft_state->ohci, 0xFFFFFFFF);

	/* Make sure we tell others on the bus we are dropping out */
	(void) hci1394_ohci_phy_clr(soft_state->ohci, 4, 0xc0);
	ddi_put32(soft_state->ohci->ohci_reg_handle,
	    &soft_state->ohci->ohci_regs->link_ctrl_clr, 0xFFFFFFFF);

	/* Do a long reset on the bus so every one knows we are gone */
	(void) hci1394_ohci_bus_reset_nroot(soft_state->ohci);

	/* Reset the OHCI HW */
	(void) hci1394_ohci_soft_reset(soft_state->ohci);

	return (DDI_SUCCESS);
}

void
hci1394_detach_hardware(hci1394_state_t *soft_state)
{
	ASSERT(soft_state != NULL);

	/* free up vendor specific registers */
	hci1394_vendor_fini(&soft_state->vendor);

	/* cleanup isoch layer */
	hci1394_isoch_fini(&soft_state->isoch);

	/* cleanup async layer */
	hci1394_async_fini(&soft_state->async);

	/* Free up csr register space */
	hci1394_csr_fini(&soft_state->csr);

	/* free up OpenHCI registers */
	hci1394_ohci_fini(&soft_state->ohci);

	/* free up PCI config space */
	hci1394_pci_fini(soft_state);
}


/*
 * hci1394_pci_fini()
 *    Cleanup after a PCI init.
 */
void
hci1394_pci_fini(hci1394_state_t *soft_state)
{
	ASSERT(soft_state != NULL);
	pci_config_teardown(&soft_state->pci_config);
}


/*
 * hci1394_soft_state_fini()
 *    Cleanup any mutex's, etc. in soft_state.
 */
void
hci1394_soft_state_fini(hci1394_state_t *soft_state)
{
	ASSERT(soft_state != NULL);
	mutex_destroy(&soft_state->drvinfo.di_drvstate.ds_mutex);
}
