/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

/*
 * -----------------------
 * Command Ring Management
 * -----------------------
 *
 * The command ring is the primary means by which the xHCI controller is
 * managed. Events may be placed on the ring, at which point they will be
 * processed in order. When commands are finished they generate event
 * completions and we are notified via an interrupt.
 *
 * Every command is formatted in a transfer request block (TRB). These TRBs are
 * queued on the command ring. To start the command ring, a doorbell register is
 * written to. The current state of the command ring is maintained in the
 * command ring control register (XHCI_CRCR).
 *
 * Every command has a condition variable. When the driver submits a command, it
 * blocks on the command's CV waiting for a change in the commands status. This
 * CV will be signaled after the command completes or is aborted, allowing the
 * caller to treat this as a synchronous, blocking operation.
 *
 * The command ring itself consists of three primary states:
 *
 * 	XHCI_COMMAND_RING_IDLE		The command ring is not currently
 * 					processing any events. No timeout events
 * 					are active.
 *
 * 	XHCI_COMMAND_RING_RUNNING	The command ring currently has one or
 * 					more events enqueued and the hardware
 * 					has been signalled to process commands.
 *
 * 	XHCI_COMMAND_RING_ABORTING	A command has timed out and we are
 * 					attempting to abort the current command,
 * 					which will stop the ring.
 *
 * 	XHCI_COMMAND_RING_ABORT_DONE	We have successfully received a
 * 					notification that the abort worked and
 * 					that the command ring has stopped. This
 * 					allows us to clean up state and
 * 					transition back to either idle or
 * 					running, depending on if we have queued
 * 					commands.
 *
 * The state transition can be summarized as:
 *
 *    +------+                        +---------+
 *    | Idle |--------*-------------->| Running |<----------------------+
 *    +------+        . Command       +---------+                       |
 *       ^              TRB queued      |    |                          |
 *       |              on ring         |    |                          |
 *       |                              |    * . . Command not          |
 *       +-------*----------------------+    |     acknowledged         |
 *       |       . . No more                 |     within timeout       |
 *       |           commands                |     xhci_command_wait    |
 *       |           queued                  |                          |
 *       |                                   v       . abort request    |
 *       * . No commands              +----------+   . times out        |
 *       |   queued after             | Aborting |---*--+               |
 *       |   successful               +----------+      v               |
 *       |   abort                         |      +----------+          |
 *       |                       abort . . *      | HW Reset |          |
 *       |                acknowledged     |      +----------+          |
 *       |                                 v                            |
 *       |                           +------------+                     |
 *       +---------------------------| Abort Done |----*----------------+
 *                                   +------------+    . Commands queued
 *                                                       after successful
 *                                                       abort
 *
 * ---------------------------
 * Timeouts and Command Aborts
 * ---------------------------
 *
 * Commands may time out either due to issues with the host controller or with
 * the devices connected to it. For example, the ADDRESS DEVICE command may
 * issue commands to the device. As such, we need to be prepared for commands to
 * time out.
 *
 * To deal with a stalled command, we write to the XHCI_CRCR register to abort
 * the currently running command. This is discussed in xHCI 1.1 / 4.6.1.2. When
 * a command is aborted, we should eventually receive a TRB completion for that
 * command. However, this is no guarantee that an abort will be successful. The
 * specification recommends waiting about 5 seconds for that to finish. After
 * which we terminate the device.
 *
 * For an abort to be successful, we expect two different notifications. First
 * we should receive a TRB for the actual command itself indicating that it's
 * terminated. Next, we should receive a TRB indicating that the command ring
 * has stopped. Only when we receive this second one, do we consider re-enabling
 * the command ring.
 *
 * -------
 * Locking
 * -------
 *
 * The command ring's lock, xhci_command_ring_t`xcr_lock, should not be accessed
 * outside of this file. If a caller needs to take the xhci_t`xhci_lock, it must
 * be taken before the xcr_lock is taken. It is illegal for to hold
 * xhci_t`xhci_lock across any command functions. Doing so would lead to
 * deadlock.
 */

#include <sys/usb/hcd/xhci/xhci.h>
#include <sys/sysmacros.h>

/*
 * Recommended time to wait for an abort in from the Implementation Note
 * in XHCI 1.1 / 4.6.1.2. The time is kept in microseconds.
 */
clock_t xhci_command_abort_wait = 5 * MICROSEC;

/*
 * Default to waiting for one second for a command to time out. Time stored in
 * microseconds.
 */
clock_t xhci_command_wait = MICROSEC;

/*
 * Required forwards.
 */
static void xhci_command_settimeout(xhci_t *, clock_t);

void
xhci_command_ring_fini(xhci_t *xhcip)
{
	xhci_command_ring_t *xcr = &xhcip->xhci_command;

	/*
	 * If the ring is not allocated, then nothing else is here.
	 */
	if (xcr->xcr_ring.xr_trb == NULL)
		return;
	VERIFY(xcr->xcr_timeout == 0);
	xhci_ring_free(&xcr->xcr_ring);
	mutex_destroy(&xcr->xcr_lock);
	cv_destroy(&xcr->xcr_cv);
	list_destroy(&xcr->xcr_commands);
}

/*
 * Initialize or re-initialize the command ring. This will be called whenever we
 * reset the xHCI commandler, so we may actually have already allocated DMA
 * memory for the ring.
 */
int
xhci_command_ring_init(xhci_t *xhcip)
{
	int ret;
	uint64_t addr;
	xhci_command_ring_t *xcr = &xhcip->xhci_command;

	if (xcr->xcr_ring.xr_trb == NULL) {
		if ((ret = xhci_ring_alloc(xhcip, &xcr->xcr_ring)) != 0)
			return (ret);
	}

	if ((ret = xhci_ring_reset(xhcip, &xcr->xcr_ring)) != 0)
		return (ret);

#ifdef	DEBUG
	addr = xhci_get64(xhcip, XHCI_R_OPER, XHCI_CRCR);
	VERIFY0(addr & XHCI_CRCR_CRR);
#endif
	addr = LE_64(xhci_dma_pa(&xcr->xcr_ring.xr_dma) | XHCI_CRCR_RCS);
	xhci_put64(xhcip, XHCI_R_OPER, XHCI_CRCR, addr);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK)
		return (EIO);

	mutex_init(&xcr->xcr_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(xhcip->xhci_intr_pri));
	cv_init(&xcr->xcr_cv, NULL, CV_DRIVER, NULL);
	list_create(&xcr->xcr_commands, sizeof (xhci_command_t),
	    offsetof(xhci_command_t, xco_link));
	return (0);
}

static void
xhci_command_timeout(void *arg)
{
	uint64_t reg;
	clock_t delay;
	xhci_t *xhcip = arg;
	xhci_command_ring_t *xcr = &xhcip->xhci_command;
	xhci_command_t *xco;

	mutex_enter(&xcr->xcr_lock);

	xco = list_head(&xcr->xcr_commands);
	if (xco == NULL || xco->xco_state != XHCI_COMMAND_S_QUEUED) {
		xcr->xcr_timeout = 0;
		mutex_exit(&xcr->xcr_lock);
		return;
	}

	xcr->xcr_state = XHCI_COMMAND_RING_ABORTING;
	reg = xhci_get64(xhcip, XHCI_R_OPER, XHCI_CRCR);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xcr->xcr_timeout = 0;
		mutex_exit(&xcr->xcr_lock);
		xhci_error(xhcip, "encountered fatal FM error reading command "
		    "ring control register: resetting device");
		xhci_fm_runtime_reset(xhcip);
		return;
	}

	/*
	 * While all the other bits should be ignored because we're running, if
	 * for some reason we're not running, then this will make sure that we
	 * don't screw things up.
	 */
	reg |= XHCI_CRCR_CA;
	xhci_put64(xhcip, XHCI_R_OPER, XHCI_CRCR, reg);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xcr->xcr_timeout = 0;
		mutex_exit(&xcr->xcr_lock);
		xhci_error(xhcip, "encountered fatal FM error writing command "
		    "ring control register: resetting device");
		xhci_fm_runtime_reset(xhcip);
		return;
	}

	delay = drv_usectohz(xhci_command_abort_wait);
	while (xcr->xcr_state != XHCI_COMMAND_RING_ABORT_DONE) {
		int ret;

		ret = cv_reltimedwait(&xcr->xcr_cv, &xcr->xcr_lock, delay,
		    TR_CLOCK_TICK);
		if (ret == -1) {
			/* Time out waiting for the abort */
			xcr->xcr_timeout = 0;
			mutex_exit(&xcr->xcr_lock);
			xhci_error(xhcip, "abort command timed out: resetting "
			    "device");
			xhci_fm_runtime_reset(xhcip);
			return;
		}
	}

	/*
	 * Successful abort, transition the ring as needed.
	 */
	if (list_is_empty(&xcr->xcr_commands) != 0) {
		xcr->xcr_state = XHCI_COMMAND_RING_IDLE;
		xcr->xcr_timeout = 0;
	} else {
		xhci_put32(xhcip, XHCI_R_DOOR, XHCI_DOORBELL(0), 0);
		if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
			xcr->xcr_timeout = 0;
			mutex_exit(&xcr->xcr_lock);
			xhci_error(xhcip, "encountered fatal FM error writing "
			    "command ring control register: resetting device");
			xhci_fm_runtime_reset(xhcip);
			return;
		}

		/*
		 * Reset our timeout id before we create a new timeout
		 */
		xcr->xcr_timeout = 0;
		xhci_command_settimeout(xhcip, xhci_command_wait);
		xcr->xcr_state = XHCI_COMMAND_RING_RUNNING;
	}
	mutex_exit(&xcr->xcr_lock);
}

static void
xhci_command_settimeout(xhci_t *xhcip, clock_t microsecs)
{
	clock_t delay;
	xhci_command_ring_t *xcr = &xhcip->xhci_command;

	ASSERT(MUTEX_HELD(&xcr->xcr_lock));
	ASSERT(xcr->xcr_timeout == 0);

	delay = drv_usectohz(microsecs);
	xcr->xcr_timeout = timeout(xhci_command_timeout, xhcip, delay);
}

void
xhci_command_init(xhci_command_t *xcp)
{
	bzero(xcp, sizeof (xhci_command_t));
	cv_init(&xcp->xco_cv, NULL, CV_DRIVER, NULL);
}

void
xhci_command_fini(xhci_command_t *xcp)
{
	cv_destroy(&xcp->xco_cv);
}

boolean_t
xhci_command_event_callback(xhci_t *xhcip, xhci_trb_t *trb)
{
	int cstat;
	timeout_id_t to;
	xhci_command_t *xco, *rem;
	xhci_command_ring_t *xcr = &xhcip->xhci_command;
	xhci_ring_t *xrp = &xcr->xcr_ring;

	mutex_enter(&xcr->xcr_lock);

	/*
	 * If we got an event that indicates that the command ring was stopped,
	 * then we have successfully finished an abort. While a command ring
	 * stop can also be done by writing to the XHCI_CRCR register, the
	 * driver does not do so at this time; however, we guard the state
	 * transition just in case.
	 */
	cstat = XHCI_TRB_GET_CODE(LE_32(trb->trb_status));
	if (cstat == XHCI_CODE_CMD_RING_STOP) {
		if (xcr->xcr_state == XHCI_COMMAND_RING_ABORTING)
			xcr->xcr_state = XHCI_COMMAND_RING_ABORT_DONE;
		cv_broadcast(&xcr->xcr_cv);
		mutex_exit(&xcr->xcr_lock);
		return (B_TRUE);
	}

	xco = list_head(&xcr->xcr_commands);
	VERIFY(xco != NULL);

	/*
	 * The current event should be pointed to by the ring's tail pointer.
	 * We need to check if this DMA address that we've been given matches
	 * the address that we'd expect for the tail.
	 */
	if (xhci_ring_trb_tail_valid(xrp, LE_64(trb->trb_addr)) == B_FALSE) {
		mutex_exit(&xcr->xcr_lock);
		return (B_TRUE);
	}

	xco->xco_state = XHCI_COMMAND_S_RECEIVED;
	to = xcr->xcr_timeout;
	xcr->xcr_timeout = 0;
	if (xcr->xcr_state != XHCI_COMMAND_RING_ABORTING) {
		mutex_exit(&xcr->xcr_lock);
		(void) untimeout(to);
		mutex_enter(&xcr->xcr_lock);
	}
	rem = list_remove_head(&xcr->xcr_commands);

	VERIFY3P(rem, ==, xco);

	xco->xco_res.trb_addr = LE_64(trb->trb_addr);
	xco->xco_res.trb_status = LE_32(trb->trb_status);
	xco->xco_res.trb_flags = LE_32(trb->trb_flags);
	xco->xco_state = XHCI_COMMAND_S_DONE;

	/*
	 * Advance the ring and wake up anyone who was waiting for a slot.
	 */
	if (xhci_ring_trb_consumed(xrp, LE_64(trb->trb_addr)) == B_FALSE) {
		/*
		 * Indicate that we need to do a runtime reset to the interrupt
		 * handler.
		 */
		mutex_exit(&xcr->xcr_lock);
		xhci_error(xhcip, "encountered invalid TRB head while "
		    "processing command ring: TRB with addr 0x%"PRIx64 " could "
		    "not be consumed", LE_64(trb->trb_addr));
		xhci_fm_runtime_reset(xhcip);
		return (B_FALSE);
	}
	cv_broadcast(&xcr->xcr_cv);

	if (xcr->xcr_state < XHCI_COMMAND_RING_ABORTING) {
		if (list_is_empty(&xcr->xcr_commands) != 0) {
			xcr->xcr_state = XHCI_COMMAND_RING_IDLE;
		} else {
			xhci_command_settimeout(xhcip, xhci_command_wait);
		}
	}
	mutex_exit(&xcr->xcr_lock);

	/*
	 * Now, let anyone waiting for this command to finish know it's done.
	 */
	cv_signal(&xco->xco_cv);

	return (B_TRUE);
}

static int
xhci_command_submit(xhci_t *xhcip, xhci_command_t *xco)
{
	int ret;
	xhci_command_ring_t *xcr = &xhcip->xhci_command;
	xhci_ring_t *xrp = &xcr->xcr_ring;

	mutex_enter(&xcr->xcr_lock);

	while (xhci_ring_trb_space(xrp, 1U) == B_FALSE ||
	    xcr->xcr_state >= XHCI_COMMAND_RING_ABORTING) {
		cv_wait(&xcr->xcr_cv, &xcr->xcr_lock);
	}

	xhci_ring_trb_put(xrp, &xco->xco_req);
	xco->xco_state = XHCI_COMMAND_S_QUEUED;
	list_insert_tail(&xcr->xcr_commands, xco);

	/*
	 * Now, make sure the ring is synched up before we might ring the door
	 * bell and wake up the processor, if they're not currently doing so.
	 */
	XHCI_DMA_SYNC(xrp->xr_dma, DDI_DMA_SYNC_FORDEV);
	if (xhci_check_dma_handle(xhcip, &xrp->xr_dma) != DDI_FM_OK) {
		mutex_exit(&xcr->xcr_lock);
		xhci_error(xhcip, "encountered fatal FM error syncing command "
		    "ring DMA contents: resetting device");
		xhci_fm_runtime_reset(xhcip);
		return (USB_HC_HARDWARE_ERROR);
	}

	/*
	 * Always ring the door bell. You never know what state the ring will be
	 * in, but we do know that we won't be waiting for an abort as we're
	 * protecting that state currently with the xcr_lock.
	 */
	xhci_put32(xhcip, XHCI_R_DOOR, XHCI_DOORBELL(0), 0);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		mutex_exit(&xcr->xcr_lock);
		xhci_error(xhcip, "encountered fatal FM error ringing command "
		    "ring doorbell: resetting device");
		xhci_fm_runtime_reset(xhcip);
		return (USB_HC_HARDWARE_ERROR);
	}

	/*
	 * If the command ring is currently considered idle, make sure to start
	 * up the timeout.
	 */
	if (xcr->xcr_state == XHCI_COMMAND_RING_IDLE) {
		VERIFY(xcr->xcr_timeout == 0);

		xhci_command_settimeout(xhcip, xhci_command_wait);
		xcr->xcr_state = XHCI_COMMAND_RING_RUNNING;
	}

	while (xco->xco_state < XHCI_COMMAND_S_DONE)
		cv_wait(&xco->xco_cv, &xcr->xcr_lock);

	/*
	 * When we return USB_SUCCESS, the actual error is returned in the
	 * command's structure.
	 */
	if (xco->xco_state == XHCI_COMMAND_S_DONE)
		ret = USB_SUCCESS;
	else
		ret = USB_HC_HARDWARE_ERROR;
	mutex_exit(&xcr->xcr_lock);

	return (ret);
}

int
xhci_command_enable_slot(xhci_t *xhcip, uint8_t *slotp)
{
	int ret;
	uint8_t slot, code;
	xhci_command_t co;

	VERIFY(xhcip != NULL);
	VERIFY(slotp != NULL);

	xhci_command_init(&co);

	/*
	 * Note, the slot type is supposed to vary depending on the protocol
	 * type. However, XHCI 1.1/7.2.2.1.4 explicitly says that this will
	 * always be set to zero for both USB 2 and USB 3, hence why we hardcode
	 * this to zero and thus only have the command to enable the slot set
	 * below.
	 */
	co.xco_req.trb_flags = LE_32(XHCI_CMD_ENABLE_SLOT) |
	    XHCI_TRB_SET_STYPE(0);
	ret = xhci_command_submit(xhcip, &co);
	if (ret != 0)
		goto done;

	code = XHCI_TRB_GET_CODE(co.xco_res.trb_status);
	slot = XHCI_TRB_GET_SLOT(co.xco_res.trb_flags);

	if (code == XHCI_CODE_SUCCESS) {
		*slotp = slot;
		ret = USB_SUCCESS;
	} else if (code == XHCI_CODE_NO_SLOTS) {
		ret = USB_NO_RESOURCES;
	} else if (code == XHCI_CODE_CMD_ABORTED) {
		ret = USB_CR_TIMEOUT;
	} else {
		ret = USB_HC_HARDWARE_ERROR;
		xhci_log(xhcip, "!unexpected error when enabling slot: "
		    "%d", code);
	}

done:
	xhci_command_fini(&co);
	return (ret);
}

int
xhci_command_disable_slot(xhci_t *xhcip, uint8_t slot)
{
	int ret, code;
	xhci_command_t co;

	VERIFY(xhcip != NULL);

	xhci_command_init(&co);
	co.xco_req.trb_flags = LE_32(XHCI_CMD_DISABLE_SLOT |
	    XHCI_TRB_SET_SLOT(slot));
	ret = xhci_command_submit(xhcip, &co);
	if (ret != 0)
		goto done;

	code = XHCI_TRB_GET_CODE(co.xco_res.trb_status);
	if (code == XHCI_CODE_SUCCESS) {
		ret = USB_SUCCESS;
	} else if (code == XHCI_CODE_CMD_ABORTED) {
		ret = USB_CR_TIMEOUT;
	} else {
		ret = USB_HC_HARDWARE_ERROR;
		xhci_log(xhcip, "!unexpected error when disabling slot: "
		    "%d", code);
	}

done:
	xhci_command_fini(&co);
	return (ret);
}

int
xhci_command_set_address(xhci_t *xhcip, xhci_device_t *xd, boolean_t bsr)
{
	int ret, code;
	xhci_command_t co;

	VERIFY(xhcip != NULL);
	VERIFY(xd != NULL);

	xhci_command_init(&co);
	co.xco_req.trb_addr = LE_64(xhci_dma_pa(&xd->xd_ictx));
	co.xco_req.trb_status = 0;
	co.xco_req.trb_flags = LE_32(XHCI_CMD_ADDRESS_DEVICE |
	    XHCI_TRB_SET_SLOT(xd->xd_slot));
	if (bsr == B_TRUE)
		co.xco_req.trb_flags |= LE_32(XHCI_TRB_BSR);

	ret = xhci_command_submit(xhcip, &co);
	if (ret != 0)
		goto done;

	code = XHCI_TRB_GET_CODE(co.xco_res.trb_status);
	if (code == XHCI_CODE_SUCCESS) {
		ret = USB_SUCCESS;
	} else if (code == XHCI_CODE_CMD_ABORTED) {
		ret = USB_CR_TIMEOUT;
	} else {
		ret = USB_HC_HARDWARE_ERROR;
		xhci_log(xhcip, "!unexpected error when setting address: "
		    "%d", code);
	}
done:
	xhci_command_fini(&co);
	return (ret);
}

int
xhci_command_configure_endpoint(xhci_t *xhcip, xhci_device_t *xd)
{
	int ret, code;
	xhci_command_t co;

	VERIFY(xhcip != NULL);
	VERIFY(xd != NULL);

	xhci_command_init(&co);
	co.xco_req.trb_addr = LE_64(xhci_dma_pa(&xd->xd_ictx));
	co.xco_req.trb_status = LE_32(0);
	co.xco_req.trb_flags = LE_32(XHCI_CMD_CONFIG_EP |
	    XHCI_TRB_SET_SLOT(xd->xd_slot));

	ret = xhci_command_submit(xhcip, &co);
	if (ret != 0)
		goto done;
	code = XHCI_TRB_GET_CODE(co.xco_res.trb_status);
	switch (code) {
	case XHCI_CODE_SUCCESS:
		ret = USB_SUCCESS;
		break;
	case XHCI_CODE_CMD_ABORTED:
		ret = USB_CR_TIMEOUT;
		break;
	case XHCI_CODE_SLOT_NOT_ON:
		xhci_log(xhcip, "!failed to configure endpoints for slot %d, "
		    "slot not on, likely driver bug!", xd->xd_slot);
		ret = USB_FAILURE;
		break;
	case XHCI_CODE_BANDWIDTH:
		ret = USB_NO_BANDWIDTH;
		break;
	case XHCI_CODE_RESOURCE:
		ret = USB_NO_RESOURCES;
		break;
	default:
		ret = USB_HC_HARDWARE_ERROR;
		xhci_log(xhcip, "!unexpected error when configuring enpoints: "
		    "%d", code);
		break;
	}
done:
	xhci_command_fini(&co);
	return (ret);
}

int
xhci_command_evaluate_context(xhci_t *xhcip, xhci_device_t *xd)
{
	int ret, code;
	xhci_command_t co;

	VERIFY(xhcip != NULL);
	VERIFY(xd != NULL);

	xhci_command_init(&co);
	co.xco_req.trb_addr = LE_64(xhci_dma_pa(&xd->xd_ictx));
	co.xco_req.trb_status = LE_32(0);
	co.xco_req.trb_flags = LE_32(XHCI_CMD_EVAL_CTX |
	    XHCI_TRB_SET_SLOT(xd->xd_slot));

	ret = xhci_command_submit(xhcip, &co);
	if (ret != 0)
		goto done;
	code = XHCI_TRB_GET_CODE(co.xco_res.trb_status);
	switch (code) {
	case XHCI_CODE_SUCCESS:
		ret = USB_SUCCESS;
		break;
	case XHCI_CODE_CMD_ABORTED:
		ret = USB_CR_TIMEOUT;
		break;
	case XHCI_CODE_SLOT_NOT_ON:
		xhci_log(xhcip, "!failed to evaluate endpoints for slot %d, "
		    "slot not on, likely driver bug!", xd->xd_slot);
		ret = USB_FAILURE;
		break;
	default:
		ret = USB_HC_HARDWARE_ERROR;
		xhci_log(xhcip, "!unexpected error when evaluating enpoints: "
		    "%d", code);
		break;
	}
done:
	xhci_command_fini(&co);
	return (ret);

}

int
xhci_command_reset_endpoint(xhci_t *xhcip, xhci_device_t *xd,
    xhci_endpoint_t *xep)
{
	int ret, code;
	xhci_command_t co;

	VERIFY(xhcip != NULL);
	VERIFY(xd != NULL);
	VERIFY(xep != NULL);

	xhci_command_init(&co);

	co.xco_req.trb_addr = LE_64(0);
	co.xco_req.trb_status = LE_32(0);
	co.xco_req.trb_flags = LE_32(XHCI_CMD_RESET_EP |
	    XHCI_TRB_SET_SLOT(xd->xd_slot) |
	    XHCI_TRB_SET_EP(xep->xep_num + 1));

	ret = xhci_command_submit(xhcip, &co);
	if (ret != 0)
		goto done;

	code = XHCI_TRB_GET_CODE(co.xco_res.trb_status);
	switch (code) {
	case XHCI_CODE_SUCCESS:
		ret = USB_SUCCESS;
		break;
	case XHCI_CODE_CMD_ABORTED:
		ret = USB_CR_TIMEOUT;
		break;
	case XHCI_CODE_CONTEXT_STATE:
	case XHCI_CODE_SLOT_NOT_ON:
		xhci_log(xhcip, "!xhci reset endpoint command: asked to modify "
		    "endpoint (%u)/slot (%d) in wrong state: %d", xep->xep_num,
		    xd->xd_slot, code);
		if (code == XHCI_CODE_CONTEXT_STATE) {
			xhci_endpoint_context_t *epctx;

			epctx = xd->xd_endout[xep->xep_num];
			xhci_log(xhcip, "!endpoint is in state %d",
			    XHCI_EPCTX_STATE(epctx->xec_info));
		}
		ret = USB_INVALID_CONTEXT;
		break;
	default:
		ret = USB_HC_HARDWARE_ERROR;
		xhci_log(xhcip, "!unexpected error when resetting enpoint: %d",
		    code);
		break;
	}

done:
	xhci_command_fini(&co);
	return (ret);
}

int
xhci_command_set_tr_dequeue(xhci_t *xhcip, xhci_device_t *xd,
    xhci_endpoint_t *xep)
{
	uint64_t pa;
	int ret, code;
	xhci_command_t co;
	xhci_ring_t *xrp;

	VERIFY(xhcip != NULL);
	VERIFY(xd != NULL);
	VERIFY(xep != NULL);

	xhci_command_init(&co);

	xrp = &xep->xep_ring;
	pa = xhci_dma_pa(&xrp->xr_dma) + sizeof (xhci_trb_t) * xrp->xr_tail;
	pa |= xrp->xr_cycle;
	co.xco_req.trb_addr = LE_64(pa);
	co.xco_req.trb_status = LE_32(0);
	co.xco_req.trb_flags = LE_32(XHCI_CMD_SET_TR_DEQ |
	    XHCI_TRB_SET_SLOT(xd->xd_slot) |
	    XHCI_TRB_SET_EP(xep->xep_num + 1));

	ret = xhci_command_submit(xhcip, &co);
	if (ret != 0)
		goto done;

	code = XHCI_TRB_GET_CODE(co.xco_res.trb_status);
	switch (code) {
	case XHCI_CODE_SUCCESS:
		ret = USB_SUCCESS;
		break;
	case XHCI_CODE_CMD_ABORTED:
		ret = USB_CR_TIMEOUT;
		break;
	case XHCI_CODE_CONTEXT_STATE:
	case XHCI_CODE_SLOT_NOT_ON:
		xhci_log(xhcip, "!xhci set tr dequeue command: asked to modify "
		    "endpoint (%u)/slot (%d) in wrong state: %d", xep->xep_num,
		    xd->xd_slot, code);
		if (code == XHCI_CODE_CONTEXT_STATE) {
			xhci_endpoint_context_t *epctx;

			epctx = xd->xd_endout[xep->xep_num];
			xhci_log(xhcip, "!endpoint is in state %d",
			    XHCI_EPCTX_STATE(epctx->xec_info));
		}
		ret = USB_INVALID_CONTEXT;
		break;
	default:
		ret = USB_HC_HARDWARE_ERROR;
		xhci_log(xhcip, "!unexpected error when resetting enpoint: %d",
		    code);
		break;
	}

done:
	xhci_command_fini(&co);
	return (ret);

}

int
xhci_command_stop_endpoint(xhci_t *xhcip, xhci_device_t *xd,
    xhci_endpoint_t *xep)
{
	int ret, code;
	xhci_command_t co;

	VERIFY(xhcip != NULL);
	VERIFY(xd != NULL);
	VERIFY(xep != NULL);

	xhci_command_init(&co);

	co.xco_req.trb_addr = LE_64(0);
	co.xco_req.trb_status = LE_32(0);
	co.xco_req.trb_flags = LE_32(XHCI_CMD_STOP_EP |
	    XHCI_TRB_SET_SLOT(xd->xd_slot) |
	    XHCI_TRB_SET_EP(xep->xep_num + 1));

	ret = xhci_command_submit(xhcip, &co);
	if (ret != 0)
		goto done;

	code = XHCI_TRB_GET_CODE(co.xco_res.trb_status);
	switch (code) {
	case XHCI_CODE_SUCCESS:
		ret = USB_SUCCESS;
		break;
	case XHCI_CODE_CMD_ABORTED:
		ret = USB_CR_TIMEOUT;
		break;
	case XHCI_CODE_CONTEXT_STATE:
	case XHCI_CODE_SLOT_NOT_ON:
		xhci_log(xhcip, "!xhci stop endpoint command (%d)/slot "
		    "(%u) in wrong state: %d", xep->xep_num, xd->xd_slot,
		    code);
		if (code == XHCI_CODE_CONTEXT_STATE) {
			xhci_endpoint_context_t *epctx;

			epctx = xd->xd_endout[xep->xep_num];
			xhci_log(xhcip, "!endpoint is in state %d",
			    XHCI_EPCTX_STATE(epctx->xec_info));
		}
		ret = USB_INVALID_CONTEXT;
		break;
	default:
		ret = USB_HC_HARDWARE_ERROR;
		xhci_log(xhcip, "!unexpected error when resetting enpoint: %d",
		    code);
		break;
	}

done:
	xhci_command_fini(&co);
	return (ret);
}
