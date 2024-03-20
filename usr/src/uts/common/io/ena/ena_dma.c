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
 * Copyright 2024 Oxide Computer Company
 */

#include "ena.h"

/*
 * Create DMA attributes based on the conf parameter.
 */
void
ena_dma_attr(const ena_t *ena, ddi_dma_attr_t *attrp,
    const ena_dma_conf_t *conf)
{
	bzero(attrp, sizeof (*attrp));

	/*
	 * Round up maximums to next page. This is what the Linux and
	 * FreeBSD driver do, so we follow suit.
	 */
	const size_t size_up =
	    P2ROUNDUP_TYPED(conf->edc_size, ena->ena_page_sz, size_t);

	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * The device tells us the window it supports in terms of
	 * number of bits, we convert that to the appropriate mask.
	 */
	ASSERT3U(ena->ena_dma_width, >=, 32);
	ASSERT3U(ena->ena_dma_width, <=, 48);
	attrp->dma_attr_addr_lo = 0x0;
	attrp->dma_attr_addr_hi = ENA_DMA_BIT_MASK(ena->ena_dma_width);

	/*
	 * This indicates the amount of data that can fit in one
	 * cookie/segment. We allow the entire object to live in one
	 * segment, when possible.
	 *
	 * NOTE: This value must be _one less_ than the desired max
	 * (i.e. a value of 4095 indicates a max of 4096).
	 */
	attrp->dma_attr_count_max = size_up - 1;

	/*
	 * The alignment of the starting address.
	 */
	attrp->dma_attr_align = conf->edc_align;

	/*
	 * The segment boundary dictates the address which a segment
	 * cannot cross. In this case there is no boundary.
	 */
	attrp->dma_attr_seg = UINT64_MAX;

	/*
	 * Allow a burst size of the entire object.
	 */
	attrp->dma_attr_burstsizes = size_up;

	/*
	 * Minimum and maximum amount of data we can send. This isn't
	 * strictly limited by PCI in hardware, as it'll just make the
	 * appropriate number of requests. Similarly, PCIe allows for
	 * an arbitrary granularity. We set this to one, as it's
	 * really a matter of what hardware is requesting from us.
	 */
	attrp->dma_attr_minxfer = 0x1;
	attrp->dma_attr_maxxfer = size_up;
	attrp->dma_attr_granular = 0x1;

	/*
	 * The maximum length of the Scatter Gather List, aka the
	 * maximum number of segments a device can address in a
	 * transfer.
	 */
	attrp->dma_attr_sgllen = conf->edc_sgl;
}

void
ena_dma_free(ena_dma_buf_t *edb)
{
	if (edb->edb_cookie != NULL) {
		(void) ddi_dma_unbind_handle(edb->edb_dma_hdl);
		edb->edb_cookie = NULL;
		edb->edb_real_len = 0;
	}

	if (edb->edb_acc_hdl != NULL) {
		ddi_dma_mem_free(&edb->edb_acc_hdl);
		edb->edb_acc_hdl = NULL;
		edb->edb_va = NULL;
	}

	if (edb->edb_dma_hdl != NULL) {
		ddi_dma_free_handle(&edb->edb_dma_hdl);
		edb->edb_dma_hdl = NULL;
	}

	edb->edb_va = NULL;
	edb->edb_len = 0;
}

bool
ena_dma_alloc(ena_t *ena, ena_dma_buf_t *edb, ena_dma_conf_t *conf, size_t size)
{
	int ret;
	size_t size_allocated;
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	uint_t flags =
	    conf->edc_stream ? DDI_DMA_STREAMING : DDI_DMA_CONSISTENT;

	ena_dma_attr(ena, &attr, conf);

	acc.devacc_attr_version = DDI_DEVICE_ATTR_V1;
	acc.devacc_attr_endian_flags = conf->edc_endian;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	ret = ddi_dma_alloc_handle(ena->ena_dip, &attr, DDI_DMA_DONTWAIT, NULL,
	    &edb->edb_dma_hdl);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "!failed to allocate DMA handle: %d", ret);
		return (false);
	}

	ret = ddi_dma_mem_alloc(edb->edb_dma_hdl, size, &acc, flags,
	    DDI_DMA_DONTWAIT, NULL, &edb->edb_va, &size_allocated,
	    &edb->edb_acc_hdl);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "!failed to allocate %lu bytes of DMA "
		    "memory: %d", size, ret);
		ena_dma_free(edb);
		return (false);
	}

	bzero(edb->edb_va, size_allocated);

	ret = ddi_dma_addr_bind_handle(edb->edb_dma_hdl, NULL, edb->edb_va,
	    size_allocated, DDI_DMA_RDWR | flags, DDI_DMA_DONTWAIT, NULL, NULL,
	    NULL);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "!failed to bind %lu bytes of DMA "
		    "memory: %d", size_allocated, ret);
		ena_dma_free(edb);
		return (false);
	}

	edb->edb_len = size;
	edb->edb_real_len = size_allocated;
	edb->edb_cookie = ddi_dma_cookie_one(edb->edb_dma_hdl);
	return (true);
}

void
ena_dma_bzero(ena_dma_buf_t *edb)
{
	bzero(edb->edb_va, edb->edb_real_len);
}

/*
 * Write the physical DMA address to the ENA hardware address pointer.
 * While the DMA engine should guarantee that the allocation is within
 * the specified range, we double check here to catch programmer error
 * and avoid hard-to-debug situations.
 */
void
ena_set_dma_addr(const ena_t *ena, const uint64_t phys_addr,
    enahw_addr_t *hwaddrp)
{
	ENA_DMA_VERIFY_ADDR(ena, phys_addr);
	hwaddrp->ea_low = (uint32_t)phys_addr;
	hwaddrp->ea_high = (uint16_t)(phys_addr >> 32);
}

/*
 * The same as the above function, but writes the physical address to
 * the supplied value pointers instead. Mostly used as a sanity check
 * that the address fits in the reported DMA width.
 */
void
ena_set_dma_addr_values(const ena_t *ena, const uint64_t phys_addr,
    uint32_t *dst_low, uint16_t *dst_high)
{
	ENA_DMA_VERIFY_ADDR(ena, phys_addr);
	*dst_low = (uint32_t)phys_addr;
	*dst_high = (uint16_t)(phys_addr >> 32);
}
