/*
 * Copyright (c) 2016 Microsoft Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/param.h>
#include <sys/hyperv_busdma.h>
#include <sys/hyperv_illumos.h>

/* Some dma attr defaults */
#define	HV_DMA_ALIGN		0x0000000000001000ull	/* 4KB */
#define	HV_DMA_MAX_SEGLEN	0x0000000000001000ull	/* 4KB */
#define	HV_DMA_MAX_CNT		0x0000000000001000ull	/* 4KB */

/* DMA default attributes */
static ddi_dma_attr_t hc_default_dma_attr = {
	.dma_attr_version = DMA_ATTR_V0,
	.dma_attr_addr_lo = 0,
	.dma_attr_addr_hi = 0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max = 0x7FFFFFFF,
	.dma_attr_align = HV_DMA_ALIGN,
	.dma_attr_burstsizes = 0x00001FFF,
	.dma_attr_minxfer = 1,
	.dma_attr_maxxfer = 0xFFFFFFFF,
	.dma_attr_seg = 0xFFFFFFFFULL,
	.dma_attr_sgllen = 1,
	.dma_attr_granular = 0x00000001,
	.dma_attr_flags = DDI_DMA_FLAGERR,
};


/* ARGSUSED */
caddr_t
hyperv_dmamem_alloc(dev_info_t *dip, uint64_t alignment,
    uint64_t boundary, size_t size, hv_dma_t *dma, int dma_flags)
{
	int error = DDI_FAILURE;
	size_t real_size = 0;
	ddi_dma_attr_t hc_dma_attr;
	uint_t ccnt = 0; /* cookie count */
	static ddi_device_acc_attr_t hc_acc_attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_STRUCTURE_LE_ACC,
		DDI_STRICTORDER_ACC,
		DDI_DEFAULT_ACC,
	};

	ASSERT(dip);
	ASSERT(dma);

	hc_dma_attr = hc_default_dma_attr;
	hc_dma_attr.dma_attr_align = alignment;	/* alignment in bytes */
	hc_dma_attr.dma_attr_minxfer = 1;  /* minimum transfer */

	/* maximum number of segments */
	hc_dma_attr.dma_attr_sgllen = 1;

	dma->hv_dmah = NULL;
	dma->hv_vaddr = NULL;
	dma->hv_paddr = NULL;
	dma->hv_acch = NULL;

	if ((error = ddi_dma_alloc_handle(dip, &hc_dma_attr, DDI_DMA_SLEEP,
	    NULL, &dma->hv_dmah)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN,
		    "failed to allocate DMA handle, err: 0x%x", error);
		return (NULL);
	}

	error = ddi_dma_mem_alloc(dma->hv_dmah, size, &hc_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &dma->hv_vaddr, &real_size, &dma->hv_acch);
	if (error != DDI_SUCCESS) {
		dev_err(dip, CE_WARN,
		    "failed to allocate DMA memory, size: %lu, err: 0x%x",
		    size, error);
		goto fail;
	}

	if (size != real_size) {
		dev_err(dip, CE_WARN,
		    "requested size: %lu != real size: %lu", size, real_size);
	}

	/* dma_flags => DDI_DMA_WRITE/READ etc */
	error = ddi_dma_addr_bind_handle(dma->hv_dmah, NULL, dma->hv_vaddr,
	    real_size, dma_flags, DDI_DMA_SLEEP,
	    NULL, &dma->hv_dmac, &ccnt);
	if (error != DDI_SUCCESS) {
		dev_err(dip, CE_WARN,
		    "failed to bind DMA memory, err: 0x%x", error);
		goto fail;
	}

	if (ccnt != 1) { /* since sgllen = 1 */
		dev_err(dip, CE_WARN,
		    "unusable DMA mappings (too many segments: %d)", ccnt);
		goto fail;
	}

	dma->hv_paddr = dma->hv_dmac.dmac_laddress;
	/*
	 * Host is strict about making sure that any reserved
	 * fields and padding are zero initialized.
	 */
	bzero(dma->hv_vaddr, real_size);
	return (dma->hv_vaddr);

fail:
	if (dma->hv_vaddr != NULL) {
		ddi_dma_mem_free(&dma->hv_acch);
	}
	if (dma->hv_dmah != NULL) {
		if (ddi_dma_unbind_handle(dma->hv_dmah) != DDI_SUCCESS)
			dev_err(dip, CE_WARN, "failed to unbind DMA handle");
		ddi_dma_free_handle(&dma->hv_dmah);
		dma->hv_dmah = NULL;
	}
	return (NULL);
}

void
hyperv_dmamem_free(hv_dma_t *dma)
{
	ASSERT3P(dma, !=, NULL);

	if (dma->hv_acch != NULL)
		ddi_dma_mem_free(&dma->hv_acch);

	if (dma->hv_dmah != NULL) {
		(void) ddi_dma_unbind_handle(dma->hv_dmah);
		ddi_dma_free_handle(&dma->hv_dmah);
	}
}
