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
 * Device Context Base Address Array (DCBAA) Management and Scratchpad
 * management. This is also used to manage the device slot contexts in shared
 * memory.
 *
 * Please see the big theory statement in xhci.c for more information.
 */

#include <sys/usb/hcd/xhci/xhci.h>
#include <sys/byteorder.h>

static void
xhci_scratchpad_fini(xhci_t *xhcip)
{
	xhci_scratchpad_t *xsp = &xhcip->xhci_scratchpad;

	if (xsp->xsp_scratch_dma != NULL) {
		int i, npages;
		npages = xhcip->xhci_caps.xcap_max_scratch;
		for (i = 0; i < npages; i++) {
			xhci_dma_free(&xsp->xsp_scratch_dma[i]);
		}
		kmem_free(xsp->xsp_scratch_dma,
		    sizeof (xhci_dma_buffer_t) * npages);
		xsp->xsp_scratch_dma = NULL;
	}
	xhci_dma_free(&xsp->xsp_addr_dma);
	xsp->xsp_addrs = NULL;
}

void
xhci_context_fini(xhci_t *xhcip)
{
	xhci_scratchpad_fini(xhcip);
	xhci_dma_free(&xhcip->xhci_dcbaa.xdc_dma);
	xhcip->xhci_dcbaa.xdc_base_addrs = NULL;
}

static int
xhci_scratchpad_alloc(xhci_t *xhcip)
{
	int npages, i;
	xhci_scratchpad_t *xsp;
	ddi_device_acc_attr_t acc;
	ddi_dma_attr_t attr;

	/*
	 * First allocate the scratchpad table, then the actual pages.
	 */
	ASSERT(xhcip->xhci_caps.xcap_max_scratch > 0);
	npages = xhcip->xhci_caps.xcap_max_scratch;
	xhci_dma_acc_attr(xhcip, &acc);
	xhci_dma_dma_attr(xhcip, &attr);
	xsp = &xhcip->xhci_scratchpad;
	if (xhci_dma_alloc(xhcip, &xsp->xsp_addr_dma, &attr, &acc,
	    B_TRUE, sizeof (uint64_t) * npages, B_FALSE) == B_FALSE) {
		xhci_log(xhcip, "!failed to allocate DMA memory for device "
		    "context");
		return (ENOMEM);
	}

	xsp->xsp_addrs = (void *)xsp->xsp_addr_dma.xdb_va;

	/*
	 * Note that the scratchpad memory itself can actually be relaxed, which
	 * is almost better, since we'll never actually access this memory
	 * ourselves, only use it to tear things down. As such, we also bump up
	 * the segment boundary restrictions, since we don't really have any for
	 * this memory.
	 */
	xhci_dma_scratchpad_attr(xhcip, &attr);
	xsp->xsp_scratch_dma = kmem_zalloc(sizeof (xhci_dma_buffer_t) * npages,
	    KM_SLEEP);
	for (i = 0; i < npages; i++) {
		if (xhci_dma_alloc(xhcip, &xsp->xsp_scratch_dma[i], &attr, &acc,
		    B_TRUE, xhcip->xhci_caps.xcap_pagesize, B_FALSE) ==
		    B_FALSE) {
			/*
			 * It is safe for us to call xhci_scratchpad_fini() in a
			 * partially constructed state. Because we've zeroed the
			 * structures in the above allocation, the DMA buffer
			 * teardown code can handle these zeroed or partially
			 * initialized structures correctly.
			 */
			xhci_scratchpad_fini(xhcip);
			xhci_log(xhcip, "!failed to allocate DMA memory for "
			    "device scratchpad");
			return (ENOMEM);
		}
	}

	return (0);
}

/*
 * We always allocate the DCBAA based on its maximum possible size, simplifying
 * the code and at worst wasting only a couple hundred bytes.
 */
static int
xhci_dcbaa_alloc(xhci_t *xhcip)
{
	xhci_dcbaa_t *dcb;
	ddi_device_acc_attr_t acc;
	ddi_dma_attr_t attr;

	dcb = &xhcip->xhci_dcbaa;
	xhci_dma_acc_attr(xhcip, &acc);
	xhci_dma_dma_attr(xhcip, &attr);
	if (xhci_dma_alloc(xhcip, &dcb->xdc_dma, &attr, &acc,
	    B_FALSE, sizeof (uint64_t) * XHCI_MAX_SLOTS, B_FALSE) == B_FALSE) {
		xhci_log(xhcip, "!failed to allocate DMA memory for device "
		    "context");
		return (ENOMEM);
	}

	/*
	 * This lint gag is safe, because we always have at least a 64-byte
	 * alignment from the DMA attributes.
	 */
	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	dcb->xdc_base_addrs = (uint64_t *)dcb->xdc_dma.xdb_va;
	return (0);
}

/*
 * We are called to initialize the DCBAA every time that we start the
 * controller. This happens both the first time we bring it up and after we
 * reset it from errors. Therefore to initialize the DCBAA we need to do the
 * following:
 *
 *   o Allocate DMA memory (if it doesn't already exist)
 *   o If scratchpad slots have been requested, allocate and program them if
 *     necessary
 *   o Program the DCBAAP register.
 */
int
xhci_context_init(xhci_t *xhcip)
{
	int ret;
	xhci_dcbaa_t *dcb = &xhcip->xhci_dcbaa;

	if (dcb->xdc_base_addrs == NULL) {
		if ((ret = xhci_dcbaa_alloc(xhcip)) != 0)
			return (ret);
	}

	bzero(dcb->xdc_base_addrs, sizeof (uint64_t) * XHCI_MAX_SLOTS);
	if (xhcip->xhci_caps.xcap_max_scratch != 0) {
		int i, npages;
		xhci_scratchpad_t *xsp = &xhcip->xhci_scratchpad;

		if (xsp->xsp_addrs == NULL &&
		    (ret = xhci_scratchpad_alloc(xhcip)) != 0) {
			xhci_context_fini(xhcip);
			return (ret);
		}

		dcb->xdc_base_addrs[XHCI_DCBAA_SCRATCHPAD_INDEX] =
		    LE_64(xhci_dma_pa(&xsp->xsp_addr_dma));

		npages = xhcip->xhci_caps.xcap_max_scratch;
		for (i = 0; i < npages; i++) {
			xsp->xsp_addrs[i] =
			    LE_64(xhci_dma_pa(&xsp->xsp_scratch_dma[i]));
		}

		XHCI_DMA_SYNC(xsp->xsp_addr_dma, DDI_DMA_SYNC_FORDEV);
		if (xhci_check_dma_handle(xhcip, &xsp->xsp_addr_dma) !=
		    DDI_FM_OK) {
			ddi_fm_service_impact(xhcip->xhci_dip,
			    DDI_SERVICE_LOST);
			return (EIO);
		}
	}

	XHCI_DMA_SYNC(dcb->xdc_dma, DDI_DMA_SYNC_FORDEV);
	if (xhci_check_dma_handle(xhcip, &dcb->xdc_dma) != DDI_FM_OK) {
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	xhci_put64(xhcip, XHCI_R_OPER, XHCI_DCBAAP,
	    LE_64(xhci_dma_pa(&dcb->xdc_dma)));
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		ddi_fm_service_impact(xhcip->xhci_dip,
		    DDI_SERVICE_LOST);
		return (EIO);
	}

	return (0);
}

/*
 * Initialize the default output context. It should already have been zeroed, so
 * all we need to do is insert it into the right place in the device context
 * array.
 */
boolean_t
xhci_context_slot_output_init(xhci_t *xhcip, xhci_device_t *xd)
{
	xhci_dcbaa_t *dcb = &xhcip->xhci_dcbaa;
	VERIFY(xd->xd_slot > 0 &&
	    xd->xd_slot <= xhcip->xhci_caps.xcap_max_slots);

	xhcip->xhci_dcbaa.xdc_base_addrs[xd->xd_slot] =
	    LE_64(xhci_dma_pa(&xd->xd_octx));
	XHCI_DMA_SYNC(dcb->xdc_dma, DDI_DMA_SYNC_FORDEV);
	if (xhci_check_dma_handle(xhcip, &dcb->xdc_dma) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to initialize slot output context "
		    "for device on port %d, slot %d: fatal FM error "
		    "synchronizing DCBAA slot DMA memory", xd->xd_slot,
		    xd->xd_port);
		xhci_fm_runtime_reset(xhcip);
		return (B_FALSE);
	}

	return (B_TRUE);
}

void
xhci_context_slot_output_fini(xhci_t *xhcip, xhci_device_t *xd)
{
	xhci_dcbaa_t *dcb = &xhcip->xhci_dcbaa;
	VERIFY(xd->xd_slot > 0 &&
	    xd->xd_slot <= xhcip->xhci_caps.xcap_max_slots);

	xhcip->xhci_dcbaa.xdc_base_addrs[xd->xd_slot] = 0ULL;
	XHCI_DMA_SYNC(dcb->xdc_dma, DDI_DMA_SYNC_FORDEV);
	if (xhci_check_dma_handle(xhcip, &dcb->xdc_dma) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to finalize slot output context "
		    "for device on port %d, slot %d: fatal FM error "
		    "synchronizing DCBAA slot DMA memory", xd->xd_slot,
		    xd->xd_port);
		xhci_fm_runtime_reset(xhcip);
	}
}
