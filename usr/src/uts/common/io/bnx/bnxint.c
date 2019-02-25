/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#include "bnxint.h"
#include "bnxsnd.h"
#include "bnxrcv.h"


#define	BNX_INTR_NUMBER 0

/*
 * Name:    bnx_intr_priv
 *
 * Input:   ptr to um_device_t
 *
 * Return:  Interrupt status
 *
 * Description:
 *          This routine is called from ISR and POLL API routines to consume
 *          any pending events. This function determines if there is any
 *          pending status and calls corresponding LM functions to consume
 *          the event. L2 driver consumes three events - L2 Tx compete,
 *          L2 Rx indication and link status change.
 */
static lm_interrupt_status_t
bnx_intr_priv(um_device_t *const umdevice)
{
	u32_t idx;
	lm_device_t *lmdevice;
	lm_interrupt_status_t intrstat;

	lmdevice = &(umdevice->lm_dev);

	/*
	 * Following LM routine checks for pending interrupts and
	 * returns corresponding bits set in a 32bit integer value.
	 */
	intrstat = lm_get_interrupt_status(lmdevice);

	if (intrstat & LM_KNOCK_KNOCK_EVENT) {
		um_send_driver_pulse(umdevice);
	}

	if (intrstat & LM_RX_EVENT_MASK) {
		for (idx = RX_CHAIN_IDX0; idx < NUM_RX_CHAIN; idx++) {
			if (intrstat & (LM_RX0_EVENT_ACTIVE << idx)) {
				s_list_t *waitq;

				waitq = &(_RX_QINFO(umdevice, idx).waitq);

				mutex_enter(&umdevice->os_param.rcv_mutex);
				(void) lm_get_packets_rcvd(lmdevice, idx, 0,
				    waitq);
				mutex_exit(&umdevice->os_param.rcv_mutex);
			}
		}
	}

	if (intrstat & LM_TX_EVENT_MASK) {
		for (idx = TX_CHAIN_IDX0; idx < NUM_TX_CHAIN; idx++) {
			if (intrstat & (LM_TX0_EVENT_ACTIVE << idx)) {
				/* This call is mutex protected internally. */
				bnx_xmit_ring_intr(umdevice, idx);
			}
		}
	}

	if (intrstat & LM_PHY_EVENT_ACTIVE) {
		mutex_enter(&umdevice->os_param.phy_mutex);
		lm_service_phy_int(lmdevice, FALSE);
		mutex_exit(&umdevice->os_param.phy_mutex);
	}

	return (intrstat);
}

/*
 * Description:
 *
 * This function sends rx traffic up the stack and replenishes the hardware
 * rx buffers.  Although we share the responsibility of replenishing the
 * rx buffers with the timer, we still need to wait here indefinitely.  This
 * is the only place where we send rx traffic back up the stack.
 *
 * We go through a lot of mental gymnastics to make sure we are not holding a
 * lock while calling gld_recv().  We can deadlock in the following scenario
 * if we aren't careful :
 *
 * Thread 1:
 *          bnx_intr_disable()
 *              bnx_intr_wait()
 *                  mutex_enter(intr_*_mutex)
 *
 * Thread 2:
 *          bnx_intr_[soft|1lvl]()
 *              bnx_intr_recv()
 *                  mutex_enter(rcv_mutex)
 *
 * Thread 3:
 *          bnx_intr_[soft|1lvl]()
 *              mutex_enter(intr_*_mutex)
 *              mutex_enter(rcv_mutex)
 *
 * Return:
 */
static void
bnx_intr_recv(um_device_t * const umdevice)
{
	mutex_enter(&umdevice->os_param.rcv_mutex);

	if (umdevice->intr_enabled == B_TRUE) {
		/*
		 * Send the rx packets up.  This function will release and
		 * acquire the receive mutex across calls to gld_recv().
		 */
		bnx_rxpkts_intr(umdevice);
	}

	/*
	 * Since gld_recv() can hang while decommisioning the driver, we
	 * need to double check that interrupts are still enabled before
	 * attempting to replenish the rx buffers.
	 */
	if (umdevice->intr_enabled == B_TRUE) {
		/* This function does an implicit *_fill(). */
		bnx_rxpkts_post(umdevice);
	}

	mutex_exit(&umdevice->os_param.rcv_mutex);
}

static void
bnx_intr_xmit(um_device_t *const umdevice)
{
	mutex_enter(&umdevice->os_param.xmit_mutex);

	if (umdevice->intr_enabled == B_TRUE) {
		/*
		 * Send the tx packets in waitq & notify the GLD.
		 */
		bnx_txpkts_intr(umdevice);
	}

	mutex_exit(&umdevice->os_param.xmit_mutex);
}

static unsigned int
bnx_intr_1lvl(caddr_t arg1, caddr_t arg2)
{
	lm_device_t *lmdevice;
	um_device_t *umdevice;
	lm_interrupt_status_t intrstat = 0;
	u32_t value32;
	umdevice = (um_device_t *)arg1;

	lmdevice = &(umdevice->lm_dev);

	mutex_enter(&umdevice->intr_mutex);

	if (umdevice->intr_enabled != B_TRUE) {
		/*
		 * The interrupt cannot be ours.  Interrupts
		 * from our device have been disabled.
		 */
		mutex_exit(&umdevice->intr_mutex);
		umdevice->intr_in_disabled++;
		return (DDI_INTR_UNCLAIMED);
	}

	/* Make sure we are working with current data. */
	(void) ddi_dma_sync(*(umdevice->os_param.status_block_dma_hdl), 0,
	    STATUS_BLOCK_BUFFER_SIZE, DDI_DMA_SYNC_FORKERNEL);

	/* Make sure it is our device that is interrupting. */
	if (lmdevice->vars.status_virt->deflt.status_idx ==
	    umdevice->dev_var.processed_status_idx) {
		/*
		 * It is possible that we could have arrived at the ISR
		 * before the status block had a chance to be DMA'd into
		 * host memory.  Reading the status of the INTA line will
		 * implicitly force the DMA, and inform us of whether we
		 * are truly interrupting.  INTA is active low.
		 */
		REG_RD(lmdevice, pci_config.pcicfg_misc_status, &value32);
		if (value32 & PCICFG_MISC_STATUS_INTA_VALUE) {
			/* This isn't our interrupt. */
			umdevice->intr_no_change++;
			mutex_exit(&umdevice->intr_mutex);
			return (DDI_INTR_UNCLAIMED);
		}
	}

	umdevice->intrFired++;

	/* Disable interrupt and enqueue soft intr processing. */
	REG_WR(lmdevice, pci_config.pcicfg_int_ack_cmd,
	    (PCICFG_INT_ACK_CMD_USE_INT_HC_PARAM |
	    PCICFG_INT_ACK_CMD_MASK_INT));

	FLUSHPOSTEDWRITES(lmdevice);

	umdevice->dev_var.processed_status_idx =
	    lmdevice->vars.status_virt->deflt.status_idx;

	/* Service the interrupts. */
	intrstat = bnx_intr_priv(umdevice);

	value32 = umdevice->dev_var.processed_status_idx;
	value32 |= PCICFG_INT_ACK_CMD_INDEX_VALID;

	/*
	 * Inform the hardware of the last interrupt event we processed
	 * and reinstate the hardware's ability to assert interrupts.
	 */
	REG_WR(lmdevice, pci_config.pcicfg_int_ack_cmd, value32);

	FLUSHPOSTEDWRITES(lmdevice);

	umdevice->intr_count++;

	if (intrstat & LM_RX_EVENT_MASK) {
		bnx_intr_recv(umdevice);
	}

	if (intrstat & LM_TX_EVENT_MASK) {
		bnx_intr_xmit(umdevice);
	}

	mutex_exit(&umdevice->intr_mutex);

	return (DDI_INTR_CLAIMED);
}

void
bnx_intr_enable(um_device_t * const umdevice)
{
	int rc;

	umdevice->intr_count = 0;

	/*
	 * Allow interrupts to touch the hardware.
	 */
	umdevice->intr_enabled = B_TRUE;

	if ((rc = ddi_intr_enable(umdevice->pIntrBlock[0])) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: Failed to enable default isr block (%d)",
		    umdevice->dev_name, rc);
		return; /* XXX return error */
	}

	/* Allow the hardware to generate interrupts. */
	lm_enable_int(&(umdevice->lm_dev));

	FLUSHPOSTEDWRITES(&(umdevice->lm_dev));

	/*
	 * XXX This delay is here because of a discovered problem regarding a
	 * call to ddi_intr_disable immediately after enabling interrupts.  This
	 * can occur with the "ifconfig -a plumb up" command which brings an
	 * interface up/down/up/down/up.  There seems to be a race condition
	 * between the ddi_intr_enable/lm_enable_int and ddi_intr_disable
	 * routines that results in interrupts to no longer fire on the
	 * interface and a REBOOT IS REQUIRED to fix!
	 */
	drv_usecwait(2000000);
}

/*
 * Description:
 *
 * This function makes sure the ISR no longer touches the hardware.  It
 * accomplishes this by making sure the ISR either completes, or that it
 * acknowledges the intr_enabled status change.
 *
 * Return:
 */
static void
bnx_intr_wait(um_device_t * const umdevice)
{
	if (mutex_tryenter(&umdevice->intr_mutex)) {
		/*
		 * If we were able to get the hardware interrupt mutex, then it
		 * means that either the ISR wasn't processing at this time, or
		 * that it was at the end, processing the receive packets. If it
		 * the latter case, then all we need to do is acquire the
		 * rcv_mutex.  If we can acquire it, it means the receive
		 * processing is stalled, waiting for a GLD mutex, or that the
		 * ISR is not processing RX packets.
		 */
		mutex_enter(&umdevice->os_param.rcv_mutex);
		mutex_exit(&umdevice->os_param.rcv_mutex);
	} else {
		/*
		 * We couldn't acquire the hardware interrupt mutex. This means
		 * the ISR is running.  Wait for it to complete by
		 * (re)attempting to acquire the interrupt mutex. Whether we
		 * acquire it immediately or not, we will know the ISR has
		 * acknowledged the intr_enabled status change.
		 */
		mutex_enter(&umdevice->intr_mutex);
	}
	mutex_exit(&umdevice->intr_mutex);
}


void
bnx_intr_disable(um_device_t * const umdevice)
{
	int rc;

	/*
	 * Prevent any future interrupts to no longer touch the hardware.
	 */
	umdevice->intr_enabled = B_FALSE;

	/*
	 * Wait for any currently running interrupt to complete.
	 */
	bnx_intr_wait(umdevice);

	/* Stop the device from generating any interrupts. */
	lm_disable_int(&(umdevice->lm_dev));

	FLUSHPOSTEDWRITES(&(umdevice->lm_dev));

	if ((rc = ddi_intr_disable(umdevice->pIntrBlock[0])) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: Failed to disable default isr (%d)",
		    umdevice->dev_name, rc);
	}
}

int
bnxIntrInit(um_device_t *umdevice)
{
	dev_info_t *pDev = umdevice->os_param.dip;
	int intrActual, rc;

	if ((umdevice->pIntrBlock = kmem_zalloc(sizeof (ddi_intr_handle_t),
	    KM_SLEEP)) == NULL) {
		cmn_err(CE_WARN, "%s: Failed to allocate interrupt handle "
		    "block!", umdevice->dev_name);
		return (-1);
	}

	umdevice->intrType = (umdevice->dev_var.disableMsix) ?
	    DDI_INTR_TYPE_FIXED : DDI_INTR_TYPE_MSIX;

	while (1) {
		if ((rc = ddi_intr_alloc(pDev, umdevice->pIntrBlock,
		    umdevice->intrType, 0, 1, &intrActual,
		    DDI_INTR_ALLOC_NORMAL)) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "!%s: Failed to initialize default "
			    "%s isr handle block (%d)", umdevice->dev_name,
			    (umdevice->intrType == DDI_INTR_TYPE_MSIX) ?
			    "MSIX" : "Fixed", rc);

			if (umdevice->intrType == DDI_INTR_TYPE_MSIX) {
				cmn_err(CE_WARN, "!%s: Reverting to Fixed "
				    "level interrupts", umdevice->dev_name);

				umdevice->intrType = DDI_INTR_TYPE_FIXED;
				continue;
			} else {
				kmem_free(umdevice->pIntrBlock,
				    sizeof (ddi_intr_handle_t));
				return (-1);
			}
		}
		break;
	}

	if (intrActual != 1) {
		cmn_err(CE_WARN, "%s: Failed to alloc minimum default "
		    "isr handler!", umdevice->dev_name);
		(void) ddi_intr_free(umdevice->pIntrBlock[0]);
		kmem_free(umdevice->pIntrBlock, sizeof (ddi_intr_handle_t));
		return (-1);
	}

	if ((rc = ddi_intr_get_pri(umdevice->pIntrBlock[0],
	    &umdevice->intrPriority)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: Failed to get isr priority (%d)",
		    umdevice->dev_name, rc);
		(void) ddi_intr_free(umdevice->pIntrBlock[0]);
		kmem_free(umdevice->pIntrBlock, sizeof (ddi_intr_handle_t));
		return (-1);
	}

	if (umdevice->intrPriority >= ddi_intr_get_hilevel_pri()) {
		cmn_err(CE_WARN, "%s: Interrupt priority is too high",
		    umdevice->dev_name);
		(void) ddi_intr_free(umdevice->pIntrBlock[0]);
		kmem_free(umdevice->pIntrBlock, sizeof (ddi_intr_handle_t));
		return (-1);
	}

	if ((rc = ddi_intr_add_handler(umdevice->pIntrBlock[0], bnx_intr_1lvl,
	    (caddr_t)umdevice, NULL)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: Failed to add the default isr "
		    "handler (%d)", umdevice->dev_name, rc);
		(void) ddi_intr_free(umdevice->pIntrBlock[0]);
		kmem_free(umdevice->pIntrBlock, sizeof (ddi_intr_handle_t));
		return (-1);
	}

	/* Intialize the mutex used by the hardware interrupt handler. */
	mutex_init(&umdevice->intr_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(umdevice->intrPriority));

	umdevice->lm_dev.vars.interrupt_mode =
	    (umdevice->intrType == DDI_INTR_TYPE_FIXED) ?
	    IRQ_MODE_LINE_BASED : IRQ_MODE_MSIX_BASED;
	return (0);
}

void
bnxIntrFini(um_device_t *umdevice)
{
	int ret;

	if ((ret = ddi_intr_disable(umdevice->pIntrBlock[0])) != 0) {
		dev_err(umdevice->os_param.dip, CE_WARN,
		    "failed to disable interrupt: %d", ret);
	}
	if ((ret = ddi_intr_remove_handler(umdevice->pIntrBlock[0])) != 0) {
		dev_err(umdevice->os_param.dip, CE_WARN,
		    "failed to remove interrupt: %d", ret);
	}
	if ((ret = ddi_intr_free(umdevice->pIntrBlock[0])) != 0) {
		dev_err(umdevice->os_param.dip, CE_WARN,
		    "failed to free interrupt: %d", ret);
	}
	kmem_free(umdevice->pIntrBlock, sizeof (ddi_intr_handle_t));

	umdevice->pIntrBlock = NULL;

	mutex_destroy(&umdevice->intr_mutex);
}
