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
 * hci1394_isr.c
 *    Contains the core interrupt handling logic for the hci1394 driver.
 *    It also contains the routine which sets up the initial interrupt
 *    mask during HW init.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>

#include <sys/1394/h1394.h>
#include <sys/1394/adapters/hci1394.h>


static uint_t hci1394_isr(caddr_t parm);
static void hci1394_isr_bus_reset(hci1394_state_t *soft_state);
static void hci1394_isr_self_id(hci1394_state_t *soft_state);
static void hci1394_isr_isoch_ir(hci1394_state_t *soft_state);
static void hci1394_isr_isoch_it(hci1394_state_t *soft_state);
static void hci1394_isr_atreq_complete(hci1394_state_t *soft_state);
static void hci1394_isr_arresp(hci1394_state_t *soft_state);
static void hci1394_isr_arreq(hci1394_state_t *soft_state);
static void hci1394_isr_atresp_complete(hci1394_state_t *soft_state);


/*
 * hci1394_isr_init()
 *    Get the iblock_cookie, make sure we are not using a high level interrupt,
 *    register our interrupt service routine.
 */
int
hci1394_isr_init(hci1394_state_t *soft_state)
{
	int status;

	ASSERT(soft_state != NULL);

	/* This driver does not support running at a high level interrupt */
	status = ddi_intr_hilevel(soft_state->drvinfo.di_dip, 0);
	if (status != 0) {
		return (DDI_FAILURE);
	}

	/* There should only be 1 1394 interrupt for an OpenHCI adapter */
	status = ddi_get_iblock_cookie(soft_state->drvinfo.di_dip, 0,
	    &soft_state->drvinfo.di_iblock_cookie);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_isr_fini()
 *    un-register our interrupt service routine.
 */
/* ARGSUSED */
void
hci1394_isr_fini(hci1394_state_t *soft_state)
{
	ASSERT(soft_state != NULL);

	/* nothing to do right now */
}


/*
 * hci1394_isr_handler_init()
 *    register our interrupt service routine.
 */
int
hci1394_isr_handler_init(hci1394_state_t *soft_state)
{
	int status;

	ASSERT(soft_state != NULL);

	/* Initialize interrupt handler */
	status = ddi_add_intr(soft_state->drvinfo.di_dip, 0, NULL, NULL,
	    hci1394_isr, (caddr_t)soft_state);
	return (status);
}


/*
 * hci1394_isr_handler_fini()
 *    un-register our interrupt service routine.
 */
void
hci1394_isr_handler_fini(hci1394_state_t *soft_state)
{
	ASSERT(soft_state != NULL);

	/* Remove interrupt handler */
	ddi_remove_intr(soft_state->drvinfo.di_dip, 0,
	    soft_state->drvinfo.di_iblock_cookie);
}


/*
 * hci1394_isr_mask_setup()
 *    Setup the initial interrupt mask for OpenHCI.  These are the interrupts
 *    that our interrupt handler is expected to handle.
 */
void
hci1394_isr_mask_setup(hci1394_state_t *soft_state)
{
	ASSERT(soft_state != NULL);

	/* start off with all interrupts cleared/disabled */
	hci1394_ohci_ir_intr_disable(soft_state->ohci, 0xFFFFFFFF);
	hci1394_ohci_ir_intr_clear(soft_state->ohci, 0xFFFFFFFF);
	hci1394_ohci_it_intr_disable(soft_state->ohci, 0xFFFFFFFF);
	hci1394_ohci_it_intr_clear(soft_state->ohci, 0xFFFFFFFF);
	hci1394_ohci_intr_disable(soft_state->ohci, 0xFFFFFFFF);
	hci1394_ohci_intr_clear(soft_state->ohci, 0xFFFFFFFF);

	/* Setup Interrupt Mask Register */
	hci1394_ohci_intr_enable(soft_state->ohci,
	    (OHCI_INTR_UNRECOVERABLE_ERR | OHCI_INTR_CYC_TOO_LONG |
	    OHCI_INTR_BUS_RESET | OHCI_INTR_SELFID_CMPLT |
	    OHCI_INTR_REQ_TX_CMPLT | OHCI_INTR_RESP_TX_CMPLT |
	    OHCI_INTR_RQPKT | OHCI_INTR_RSPKT | OHCI_INTR_ISOCH_TX |
	    OHCI_INTR_ISOCH_RX | OHCI_INTR_POST_WR_ERR | OHCI_INTR_PHY |
	    OHCI_INTR_LOCK_RESP_ERR));
}


/*
 * hci1394_isr()
 *    Core interrupt handler.  Every interrupt enabled in
 *    hci1394_isr_mask_setup() should be covered here.  There may be other
 *    interrupts supported in here even if they are not initially enabled
 *    (like OHCI_INTR_CYC_64_SECS) since they may be enabled later (i.e. due to
 *    CSR register write)
 */
static uint_t
hci1394_isr(caddr_t parm)
{
	hci1394_state_t *soft_state;
	h1394_posted_wr_err_t posted_wr_err;
	uint32_t interrupt_event;
	uint_t status;


	status = DDI_INTR_UNCLAIMED;
	soft_state = (hci1394_state_t *)parm;

	ASSERT(soft_state != NULL);

	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN)
		return (DDI_INTR_UNCLAIMED);

	/*
	 * Get all of the enabled 1394 interrupts which are currently
	 * asserted.
	 */
	interrupt_event = hci1394_ohci_intr_asserted(soft_state->ohci);
	do {
		/* handle the asserted interrupts */
		if (interrupt_event & OHCI_INTR_BUS_RESET) {
			hci1394_isr_bus_reset(soft_state);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_SELFID_CMPLT) {
			hci1394_isr_self_id(soft_state);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_ISOCH_TX) {
			hci1394_isr_isoch_it(soft_state);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_ISOCH_RX) {
			hci1394_isr_isoch_ir(soft_state);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_REQ_TX_CMPLT) {
			hci1394_isr_atreq_complete(soft_state);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_RSPKT) {
			hci1394_isr_arresp(soft_state);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_RQPKT) {
			hci1394_isr_arreq(soft_state);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_RESP_TX_CMPLT) {
			hci1394_isr_atresp_complete(soft_state);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_CYC_64_SECS) {
			hci1394_ohci_isr_cycle64seconds(soft_state->ohci);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_UNRECOVERABLE_ERR) {
			h1394_error_detected(soft_state->drvinfo.di_sl_private,
			    H1394_SELF_INITIATED_SHUTDOWN, NULL);
			cmn_err(CE_WARN, "hci1394(%d): driver shutdown: "
			    "unrecoverable error interrupt detected",
			    soft_state->drvinfo.di_instance);
			hci1394_shutdown(soft_state->drvinfo.di_dip);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_CYC_LOST) {
			hci1394_isoch_cycle_lost(soft_state);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_CYC_INCONSISTENT) {
			hci1394_isoch_cycle_inconsistent(soft_state);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_CYC_TOO_LONG) {
			hci1394_ohci_intr_clear(soft_state->ohci,
			    OHCI_INTR_CYC_TOO_LONG);
			/* clear cycle master bit in csr state register */
			hci1394_csr_state_bclr(soft_state->csr,
			    IEEE1394_CSR_STATE_CMSTR);
			h1394_error_detected(soft_state->drvinfo.di_sl_private,
			    H1394_CYCLE_TOO_LONG, NULL);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_POST_WR_ERR) {
			hci1394_ohci_postwr_addr(soft_state->ohci,
			    &posted_wr_err.addr);
			h1394_error_detected(soft_state->drvinfo.di_sl_private,
			    H1394_POSTED_WR_ERR, &posted_wr_err);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_PHY) {
			hci1394_ohci_isr_phy(soft_state->ohci);
			status = DDI_INTR_CLAIMED;
		}
		if (interrupt_event & OHCI_INTR_LOCK_RESP_ERR) {
			hci1394_ohci_intr_clear(soft_state->ohci,
			    OHCI_INTR_LOCK_RESP_ERR);
			h1394_error_detected(soft_state->drvinfo.di_sl_private,
			    H1394_LOCK_RESP_ERR, NULL);
			status = DDI_INTR_CLAIMED;
		}

		/*
		 * Check for self-id-complete interrupt disappearing.  There is
		 * a chance in OpenHCI where it will assert the selfid
		 * interrupt and then take it away.  We will look for this case
		 * and claim it just in case.  We could possibly claim an
		 * interrupt that's not ours.  We would have to be in the
		 * middle of a bus reset and a bunch of other weird stuff
		 * would have to align.  It should not hurt anything if we do.
		 *
		 * This will very very rarely happen, if ever.  We still have
		 * to handle the case, just in case. OpenHCI 1.1 should fix
		 * this problem.
		 */
		if ((status == DDI_INTR_UNCLAIMED) &&
		    (hci1394_state(&soft_state->drvinfo) ==
		    HCI1394_BUS_RESET)) {
			if (soft_state->drvinfo.di_gencnt !=
			    hci1394_ohci_current_busgen(soft_state->ohci)) {
				status = DDI_INTR_CLAIMED;
			}
		}

		/*
		 * See if any of the enabled 1394 interrupts have been asserted
		 * since we first checked.
		 */
		interrupt_event = hci1394_ohci_intr_asserted(
		    soft_state->ohci);
	} while (interrupt_event != 0);

	return (status);
}


/*
 * hci1394_isr_bus_reset()
 *    Process a 1394 bus reset.  This signifies that a bus reset has started.
 *    A bus reset will not be complete until a selfid complete interrupt
 *    comes in.
 */
static void
hci1394_isr_bus_reset(hci1394_state_t *soft_state)
{
	int status;


	ASSERT(soft_state != NULL);

	/*
	 * Set the driver state to reset.  If we cannot, we have been shutdown.
	 * The only way we can get in this code is if we have a multi-processor
	 * machine and the HAL is shutdown by one processor running in base
	 * context while this interrupt handler runs in another processor.
	 * We will disable all interrupts and just return.  We shouldn't have
	 * to disable the interrupts, but we will just in case.
	 */
	status = hci1394_state_set(&soft_state->drvinfo, HCI1394_BUS_RESET);
	if (status != DDI_SUCCESS) {
		hci1394_ohci_intr_master_disable(soft_state->ohci);
		return;
	}

	/*
	 * Save away reset generation count so we can detect self-id-compete
	 * interrupt which disappears in event register.  This is discussed in
	 * more detail in hci1394_isr()
	 */
	soft_state->drvinfo.di_gencnt =
	    hci1394_ohci_current_busgen(soft_state->ohci);

	soft_state->drvinfo.di_stats.st_bus_reset_count++;

	/*
	 * Mask off busReset until SelfIdComplete comes in.  The bus reset
	 * interrupt will be asserted until the SelfIdComplete interrupt
	 * comes in (i.e. you cannot clear the interrupt until a SelfIdComplete
	 * interrupt).  Therefore, we disable the interrupt via its mask so we
	 * don't get stuck in the ISR indefinitely.
	 */
	hci1394_ohci_intr_disable(soft_state->ohci, OHCI_INTR_BUS_RESET);

	/* Reset the ATREQ and ATRESP Q's */
	hci1394_async_atreq_reset(soft_state->async);
	hci1394_async_atresp_reset(soft_state->async);

	/* Inform Services Layer about Bus Reset */
	h1394_bus_reset(soft_state->drvinfo.di_sl_private,
	    (void **)&soft_state->sl_selfid_buf);
}


/*
 * hci1394_isr_self_id()
 *    Process the selfid complete interrupt.  The bus reset has completed
 *    and the 1394 HW has finished it's bus enumeration.  The SW needs to
 *    see what's changed and handle any hotplug conditions.
 */
static void
hci1394_isr_self_id(hci1394_state_t *soft_state)
{
	int status;
	uint_t node_id;
	uint_t selfid_size;
	uint_t quadlet_count;
	uint_t index;
	uint32_t *selfid_buf_p;
	boolean_t selfid_error;
	boolean_t nodeid_error;
	boolean_t saw_error = B_FALSE;
	uint_t phy_status;


	ASSERT(soft_state != NULL);

	soft_state->drvinfo.di_stats.st_selfid_count++;

	/*
	 * check for the bizarre case that we got both a bus reset and self id
	 * complete after checking for a bus reset
	 */
	if (hci1394_state(&soft_state->drvinfo) != HCI1394_BUS_RESET) {
		hci1394_isr_bus_reset(soft_state);
	}

	/*
	 * Clear any set PHY error status bits set.  The PHY status bits
	 * may always be set (i.e. we removed cable power) so we do not want
	 * to clear them when we handle the interrupt. We will clear them
	 * every selfid complete interrupt so worst case we will get 1 PHY event
	 * interrupt every bus reset.
	 */
	status = hci1394_ohci_phy_read(soft_state->ohci, 5, &phy_status);
	if (status == DDI_SUCCESS) {
		phy_status |= OHCI_PHY_LOOP_ERR | OHCI_PHY_PWRFAIL_ERR |
		    OHCI_PHY_TIMEOUT_ERR | OHCI_PHY_PORTEVT_ERR;
		status = hci1394_ohci_phy_write(soft_state->ohci, 5,
		    phy_status);
		if (status == DDI_SUCCESS) {
			/*
			 * Re-enable PHY interrupt. We disable the PHY interrupt
			 *  when we get one so that we do not get stuck in the
			 * ISR.
			 */
			hci1394_ohci_intr_enable(soft_state->ohci,
			    OHCI_INTR_PHY);
		}
	}

	/* See if either AT active bit is set */
	if (hci1394_ohci_at_active(soft_state->ohci) == B_TRUE) {
		saw_error = B_TRUE;
	}

	/* Clear busReset and selfIdComplete interrupts */
	hci1394_ohci_intr_clear(soft_state->ohci, (OHCI_INTR_BUS_RESET |
	    OHCI_INTR_SELFID_CMPLT));

	/* Read node info and test for Invalid Node ID */
	hci1394_ohci_nodeid_info(soft_state->ohci, &node_id, &nodeid_error);
	if (nodeid_error == B_TRUE) {
		saw_error = B_TRUE;
	}

	/* Sync Selfid Buffer */
	hci1394_ohci_selfid_sync(soft_state->ohci);

	/* store away selfid info */
	hci1394_ohci_selfid_info(soft_state->ohci,
	    &soft_state->drvinfo.di_gencnt, &selfid_size, &selfid_error);

	/* Test for selfid error */
	if (selfid_error == B_TRUE) {
		saw_error = B_TRUE;
	}

	/*
	 * selfid size could be 0 if a bus reset has occurred. If this occurs,
	 * we should have another selfid int coming later.
	 */
	if ((saw_error == B_FALSE) && (selfid_size == 0)) {
		return;
	}

	/*
	 * make sure generation count in buffer matches generation
	 * count in register.
	 */
	if (hci1394_ohci_selfid_buf_current(soft_state->ohci) == B_FALSE) {
		return;
	}

	/*
	 * Skip over first quadlet in selfid buffer, this is OpenHCI specific
	 * data.
	 */
	selfid_size = selfid_size - IEEE1394_QUADLET;
	quadlet_count = selfid_size >> 2;

	/* Copy selfid buffer to Services Layer buffer */
	for (index = 0; index < quadlet_count; index++) {
		hci1394_ohci_selfid_read(soft_state->ohci, index + 1,
		    &soft_state->sl_selfid_buf[index]);
	}

	/*
	 * Put our selfID info into the Services Layer's selfid buffer if we
	 * have a 1394-1995 PHY.
	 */
	if (soft_state->halinfo.phy == H1394_PHY_1995) {
		selfid_buf_p = (uint32_t *)(
		    (uintptr_t)soft_state->sl_selfid_buf +
		    (uintptr_t)selfid_size);
		status = hci1394_ohci_phy_info(soft_state->ohci,
		    &selfid_buf_p[0]);
		if (status != DDI_SUCCESS) {
			/*
			 * If we fail reading from PHY, put invalid data into
			 * the selfid buffer so the SL will reset the bus again.
			 */
			selfid_buf_p[0] = 0xFFFFFFFF;
			selfid_buf_p[1] = 0xFFFFFFFF;
		} else {
			selfid_buf_p[1] = ~selfid_buf_p[0];
		}
		selfid_size = selfid_size + 8;
	}

	/* Flush out async DMA Q's */
	hci1394_async_flush(soft_state->async);

	/*
	 * Make sure generation count is still valid.  i.e. we have not gotten
	 * another bus reset since the last time we checked.  If we have gotten
	 * another bus reset, we should have another selfid interrupt coming.
	 */
	if (soft_state->drvinfo.di_gencnt !=
	    hci1394_ohci_current_busgen(soft_state->ohci)) {
		return;
	}

	/*
	 * do whatever CSR register processing that needs to be done.
	 */
	hci1394_csr_bus_reset(soft_state->csr);

	/*
	 * do whatever management may be necessary for the CYCLE_LOST and
	 * CYCLE_INCONSISTENT interrupts.
	 */
	hci1394_isoch_error_ints_enable(soft_state);

	/*
	 * See if we saw an error.  If we did, tell the services layer that we
	 * finished selfid processing and give them an illegal selfid buffer
	 * size of 0.  The Services Layer will try to reset the bus again to
	 * see if we can recover from this problem.  It will threshold after
	 * a finite number of errors.
	 */
	if (saw_error == B_TRUE) {
		h1394_self_ids(soft_state->drvinfo.di_sl_private,
		    soft_state->sl_selfid_buf, 0, node_id,
		    soft_state->drvinfo.di_gencnt);

		/*
		 * Take ourself out of Bus Reset processing mode
		 *
		 * Set the driver state to normal. If we cannot, we have been
		 * shutdown. The only way we can get in this code is if we have
		 * a multi-processor machine and the HAL is shutdown by one
		 * processor running in base context while this interrupt
		 * handler runs in another processor. We will disable all
		 * interrupts and just return.  We shouldn't have to disable
		 * the interrupts, but we will just in case.
		 */
		status = hci1394_state_set(&soft_state->drvinfo,
		    HCI1394_NORMAL);
		if (status != DDI_SUCCESS) {
			hci1394_ohci_intr_master_disable(soft_state->ohci);
			return;
		}
	} else if (IEEE1394_NODE_NUM(node_id) != 63) {
		/*
		 * Notify services layer about self-id-complete. Don't notify
		 * the services layer if there are too many devices on the bus.
		 */
		h1394_self_ids(soft_state->drvinfo.di_sl_private,
		    soft_state->sl_selfid_buf, selfid_size,
		    node_id, soft_state->drvinfo.di_gencnt);

		/*
		 * Take ourself out of Bus Reset processing mode
		 *
		 * Set the driver state to normal. If we cannot, we have been
		 * shutdown. The only way we can get in this code is if we have
		 * a multi-processor machine and the HAL is shutdown by one
		 * processor running in base context while this interrupt
		 * handler runs in another processor. We will disable all
		 * interrupts and just return.  We shouldn't have to disable
		 * the interrupts, but we will just in case.
		 */
		status = hci1394_state_set(&soft_state->drvinfo,
		    HCI1394_NORMAL);
		if (status != DDI_SUCCESS) {
			hci1394_ohci_intr_master_disable(soft_state->ohci);
			return;
		}
	} else {
		cmn_err(CE_NOTE, "hci1394(%d): Too many devices on the 1394 "
		    "bus", soft_state->drvinfo.di_instance);
	}

	/* enable bus reset interrupt */
	hci1394_ohci_intr_enable(soft_state->ohci, OHCI_INTR_BUS_RESET);
}


/*
 * hci1394_isr_isoch_ir()
 *    Process each isoch recv context which has its interrupt asserted.  The
 *    interrupt will be asserted when an isoch recv descriptor with the
 *    interrupt bits enabled have finished being processed.
 */
static void
hci1394_isr_isoch_ir(hci1394_state_t *soft_state)
{
	uint32_t i;
	uint32_t mask = 0x00000001;
	uint32_t ev;
	int num_ir_contexts;
	hci1394_iso_ctxt_t *ctxtp;


	ASSERT(soft_state != NULL);

	num_ir_contexts = hci1394_isoch_recv_count_get(soft_state->isoch);

	/*
	 * Main isochRx int is not clearable. it is automatically
	 * cleared by the hw when the ir_intr_event is cleared
	 */
	/* loop until no more IR events */
	while ((ev = hci1394_ohci_ir_intr_asserted(soft_state->ohci)) != 0) {

		/* clear the events we just learned about */
		hci1394_ohci_ir_intr_clear(soft_state->ohci, ev);

		/* for each interrupting IR context, process the interrupt */
		for (i = 0; i < num_ir_contexts; i++) {
			/*
			 * if the intr bit is on for a context,
			 * call xmit/recv common processing code
			 */
			if (ev & mask) {
				ctxtp = hci1394_isoch_recv_ctxt_get(
				    soft_state->isoch, i);
				hci1394_ixl_interrupt(soft_state, ctxtp,
				    B_FALSE);
			}
			mask <<= 1;
		}
	}
}


/*
 * hci1394_isr_isoch_it()
 *    Process each isoch transmit context which has its interrupt asserted.  The
 *    interrupt will be asserted when an isoch transmit descriptor with the
 *    interrupt bit is finished being processed.
 */
static void
hci1394_isr_isoch_it(hci1394_state_t *soft_state)
{
	uint32_t i;
	uint32_t mask = 0x00000001;
	uint32_t ev;
	int num_it_contexts;
	hci1394_iso_ctxt_t *ctxtp;


	ASSERT(soft_state != NULL);

	num_it_contexts = hci1394_isoch_xmit_count_get(soft_state->isoch);

	/*
	 * Main isochTx int is not clearable. it is automatically
	 * cleared by the hw when the it_intr_event is cleared.
	 */

	/* loop until no more IT events */
	while ((ev = hci1394_ohci_it_intr_asserted(soft_state->ohci)) != 0) {

		/* clear the events we just learned about */
		hci1394_ohci_it_intr_clear(soft_state->ohci, ev);

		/* for each interrupting IR context, process the interrupt */
		for (i = 0; i < num_it_contexts; i++) {
			/*
			 * if the intr bit is on for a context,
			 * call xmit/recv common processing code
			 */
			if (ev & mask) {
				ctxtp = hci1394_isoch_xmit_ctxt_get(
				    soft_state->isoch, i);
				hci1394_ixl_interrupt(soft_state, ctxtp,
				    B_FALSE);
			}
			mask <<= 1;
		}
	}
}


/*
 * hci1394_isr_atreq_complete()
 *    Process all completed requests that we have sent out (i.e. HW gave us
 *    an ack).
 */
static void
hci1394_isr_atreq_complete(hci1394_state_t *soft_state)
{
	boolean_t request_available;

	ASSERT(soft_state != NULL);

	hci1394_ohci_intr_clear(soft_state->ohci, OHCI_INTR_REQ_TX_CMPLT);

	/*
	 * Processes all ack'd AT requests.  If the request is pended, it is
	 * considered complete relative the the atreq engine. AR response
	 * processing will make sure we track the response.
	 */
	do {
		/*
		 * Process a single request. Do not flush Q. That is only
		 * done during bus reset processing.
		 */
		(void) hci1394_async_atreq_process(soft_state->async, B_FALSE,
		    &request_available);
	} while (request_available == B_TRUE);
}


/*
 * hci1394_isr_arresp()
 *    Process all responses that have come in off the bus and send then up to
 *    the services layer. We send out a request on the bus (atreq) and some time
 *    later a response comes in.  We send this response up to the services
 *    layer.
 */
static void
hci1394_isr_arresp(hci1394_state_t *soft_state)
{
	boolean_t response_available;

	ASSERT(soft_state != NULL);

	hci1394_ohci_intr_clear(soft_state->ohci, OHCI_INTR_RSPKT);

	/*
	 * Process all responses that have been received.  If more responses
	 * come in we will stay in interrupt handler and re-run this routine.
	 * It is possible that we will call hci1394_async_arresp_process()
	 * even though there are no more AR responses to process.  This would
	 * be because we have processed them earlier on. (i.e. we cleared
	 * interrupt, then got another response and processed it. The interrupt
	 * would still be pending.
	 */
	do {
		(void) hci1394_async_arresp_process(soft_state->async,
		    &response_available);
	} while (response_available == B_TRUE);
}


/*
 * hci1394_isr_arreq()
 *    Process all requests that have come in off the bus and send then up to
 *    the services layer.
 */
static void
hci1394_isr_arreq(hci1394_state_t *soft_state)
{
	boolean_t request_available;

	ASSERT(soft_state != NULL);

	hci1394_ohci_intr_clear(soft_state->ohci, OHCI_INTR_RQPKT);

	/*
	 * Process all requests that have been received. It is possible that we
	 * will call hci1394_async_arreq_process() even though there are no
	 * more requests to process.  This would be because we have processed
	 * them earlier on. (i.e. we cleared interrupt, got another request
	 * and processed it. The interrupt would still be pending.
	 */
	do {
		(void) hci1394_async_arreq_process(soft_state->async,
		    &request_available);
	} while (request_available == B_TRUE);
}


/*
 * hci1394_isr_atresp_complete()
 *    Process all completed responses that we have sent out (i.e. HW gave us
 *    an ack). We get in a request off the bus (arreq) and send it up to the
 *    services layer, they send down a response to that request some time
 *    later. This interrupt signifies that the HW is done with the response.
 *    (i.e. it sent it out or failed it)
 */
static void
hci1394_isr_atresp_complete(hci1394_state_t *soft_state)
{
	boolean_t response_available;

	ASSERT(soft_state != NULL);

	hci1394_ohci_intr_clear(soft_state->ohci, OHCI_INTR_RESP_TX_CMPLT);

	/*
	 * Processes all ack'd AT responses It is possible that we will call
	 * hci1394_async_atresp_process() even thought there are no more
	 * responses to process.  This would be because we have processed
	 * them earlier on. (i.e. we cleared interrupt, then got another
	 * response and processed it. The interrupt would still be pending.
	 */
	do {
		/*
		 * Process a single response. Do not flush Q. That is only
		 * done during bus reset processing.
		 */
		(void) hci1394_async_atresp_process(soft_state->async,
		    B_FALSE, &response_available);
	} while (response_available == B_TRUE);
}
