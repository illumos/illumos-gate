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
 * -------------------------
 * xHCI Interrupt Management
 * -------------------------
 *
 * Interrupts in the xHCI driver are quite straightforward. We only have a
 * single interrupt, which is always vector zero. Everything is configured to
 * use this interrupt.
 *
 * ------------------
 * Interrupt Claiming
 * ------------------
 *
 * One of the challenges is knowing when to claim interrupts. Generally
 * speaking, interrupts for MSI and MSI-X are directed to a specific vector for
 * a specific device. This allows us to have a bit more confidence on whether
 * the interrupt is for us. This is contrasted with traditional INTx (pin based)
 * interrupts in PCI where interrupts are shared between multiple devices.
 *
 * xHCI 1.1 / 5.5.2.1 documents the interrupt management register. One of the
 * quirks here is that when we acknowledge the PCI level MSI or MSI-X, the IP
 * bit is automatically cleared (see xHCI 1.1 / 4.17.5 for more info). However,
 * it's not for INTx based systems, thus making things a bit more confusing.
 * Because of this, we only check the IP bit when we're using INTx interrupts.
 *
 * This means that knowing whether or not we can claim something is challenging.
 * Particularly in the case where we have FM errors. In those cases we opt to
 * claim rather than not.
 */

#include <sys/usb/hcd/xhci/xhci.h>

boolean_t
xhci_ddi_intr_disable(xhci_t *xhcip)
{
	int ret;

	if (xhcip->xhci_intr_caps & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_disable(&xhcip->xhci_intr_hdl,
		    xhcip->xhci_intr_num)) != DDI_SUCCESS) {
			xhci_error(xhcip, "failed to block-disable interrupts: "
			    "%d", ret);
			return (B_FALSE);
		}
	} else {
		if ((ret = ddi_intr_disable(xhcip->xhci_intr_hdl)) !=
		    DDI_SUCCESS) {
			xhci_error(xhcip, "failed to disable interrupt: %d",
			    ret);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}


boolean_t
xhci_ddi_intr_enable(xhci_t *xhcip)
{
	int ret;

	if (xhcip->xhci_intr_caps & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_enable(&xhcip->xhci_intr_hdl,
		    xhcip->xhci_intr_num)) != DDI_SUCCESS) {
			xhci_error(xhcip, "failed to block-enable interrupts: "
			    "%d", ret);
			return (B_FALSE);
		}
	} else {
		if ((ret = ddi_intr_enable(xhcip->xhci_intr_hdl)) !=
		    DDI_SUCCESS) {
			xhci_error(xhcip, "failed to enable interrupt: %d",
			    ret);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * Configure the device for interrupts. We need to take care of three things.
 * Enabling interupt zero, setting interrupt zero's interrupt moderation, and
 * then enabling interrupts themselves globally.
 */
int
xhci_intr_conf(xhci_t *xhcip)
{
	uint32_t reg;

	reg = xhci_get32(xhcip, XHCI_R_RUN, XHCI_IMAN(0));
	reg |= XHCI_IMAN_INTR_ENA;
	xhci_put32(xhcip, XHCI_R_RUN, XHCI_IMAN(0), reg);

	xhci_put32(xhcip, XHCI_R_RUN, XHCI_IMOD(0), XHCI_IMOD_DEFAULT);

	reg = xhci_get32(xhcip, XHCI_R_OPER, XHCI_USBCMD);
	reg |= XHCI_CMD_INTE;
	xhci_put32(xhcip, XHCI_R_OPER, XHCI_USBCMD, reg);

	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	return (0);
}

uint_t
xhci_intr(caddr_t arg1, caddr_t arg2)
{
	uint32_t iman, status;

	xhci_t *xhcip = (xhci_t *)(void *)arg1;
	uintptr_t vector = (uintptr_t)arg2;

	ASSERT0(vector);

	/*
	 * First read the status register.
	 */
	status = xhci_get32(xhcip, XHCI_R_OPER, XHCI_USBSTS);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read USB status register: "
		    "encountered fatal FM error, resetting device");
		xhci_fm_runtime_reset(xhcip);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * Before we read the interrupt management register, check to see if we
	 * have a fatal bit set. At which point, it's time to reset the world
	 * anyway.
	 */
	if ((status & (XHCI_STS_HSE | XHCI_STS_SRE | XHCI_STS_HCE)) != 0) {
		xhci_error(xhcip, "found fatal error bit in status register, "
		    "value: 0x%x: resetting device", status);
		xhci_fm_runtime_reset(xhcip);
		return (DDI_INTR_CLAIMED);
	}

	iman = xhci_get32(xhcip, XHCI_R_RUN, XHCI_IMAN(0));
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read interrupt register 0: "
		    "encountered fatal FM error, resetting device");
		xhci_fm_runtime_reset(xhcip);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * When using shared interrupts, verify that this interrupt is for us.
	 * Note that when using MSI and MSI-X, writing to various PCI registers
	 * can automatically clear this for us.
	 */
	if (xhcip->xhci_intr_type == DDI_INTR_TYPE_FIXED &&
	    (iman & XHCI_IMAN_INTR_PEND) == 0) {
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * If we detect some kind of error condition here that's going to result
	 * in a device reset being dispatched, we purposefully do not clear the
	 * interrupt and enable it again.
	 */
	if (xhci_event_process(xhcip) == B_FALSE) {
		return (DDI_INTR_CLAIMED);
	}

	xhci_put32(xhcip, XHCI_R_RUN, XHCI_IMAN(0), iman);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to write USB status register: "
		    "encountered fatal FM error, resetting device");
		xhci_fm_runtime_reset(xhcip);
	}

	return (DDI_INTR_CLAIMED);
}
