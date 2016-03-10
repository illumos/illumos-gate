/*
 * Copyright (c) 2008-2016 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#include <sys/ddi.h>

#include "sfxge.h"
#include "efx.h"

static int
sfxge_dma_buffer_unbind_handle(efsys_mem_t *esmp)
{
	int rc;

	esmp->esm_addr = 0;
	rc = ddi_dma_unbind_handle(esmp->esm_dma_handle);
	if (rc != DDI_SUCCESS)
		goto fail1;

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_dma_buffer_mem_free(efsys_mem_t *esmp)
{
	esmp->esm_base = NULL;
	ddi_dma_mem_free(&(esmp->esm_acc_handle));
	esmp->esm_acc_handle = NULL;
}

static void
sfxge_dma_buffer_handle_free(ddi_dma_handle_t *dhandlep)
{
	ddi_dma_free_handle(dhandlep);
	*dhandlep = NULL;
}

int
sfxge_dma_buffer_create(efsys_mem_t *esmp, const sfxge_dma_buffer_attr_t *sdbap)
{
	int err;
	int rc;
	size_t unit;
	ddi_dma_cookie_t dmac;
	unsigned int ncookies;

	/* Allocate a DMA handle */
	err = ddi_dma_alloc_handle(sdbap->sdba_dip, sdbap->sdba_dattrp,
	    sdbap->sdba_callback, NULL, &(esmp->esm_dma_handle));
	switch (err) {
	case DDI_SUCCESS:
		break;

	case DDI_DMA_BADATTR:
		rc = EINVAL;
		goto fail1;

	case DDI_DMA_NORESOURCES:
		rc = ENOMEM;
		goto fail1;

	default:
		rc = EFAULT;
		goto fail1;
	}

	/* Allocate some DMA memory */
	err = ddi_dma_mem_alloc(esmp->esm_dma_handle, sdbap->sdba_length,
	    sdbap->sdba_devaccp, sdbap->sdba_memflags,
	    sdbap->sdba_callback, NULL,
	    &(esmp->esm_base), &unit, &(esmp->esm_acc_handle));
	switch (err) {
	case DDI_SUCCESS:
		break;

	case DDI_FAILURE:
		/*FALLTHRU*/
	default:
		rc = EFAULT;
		goto fail2;
	}

	if (sdbap->sdba_zeroinit)
		bzero(esmp->esm_base, sdbap->sdba_length);

	/* Bind the DMA memory to the DMA handle */
	/* We aren't handling partial mappings */
	ASSERT3U(sdbap->sdba_bindflags & DDI_DMA_PARTIAL, !=, DDI_DMA_PARTIAL);
	err = ddi_dma_addr_bind_handle(esmp->esm_dma_handle, NULL,
	    esmp->esm_base, sdbap->sdba_length, sdbap->sdba_bindflags,
	    sdbap->sdba_callback, NULL, &dmac, &ncookies);
	switch (err) {
	case DDI_DMA_MAPPED:
		break;

	case DDI_DMA_INUSE:
		rc = EEXIST;
		goto fail3;

	case DDI_DMA_NORESOURCES:
		rc = ENOMEM;
		goto fail3;

	case DDI_DMA_NOMAPPING:
		rc = ENOTSUP;
		goto fail3;

	case DDI_DMA_TOOBIG:
		rc = EFBIG;
		goto fail3;

	default:
		rc = EFAULT;
		goto fail3;
	}
	ASSERT3U(ncookies, >=, 1);
	ASSERT3U(ncookies, <=, sdbap->sdba_maxcookies);

	esmp->esm_addr = dmac.dmac_laddress;
	esmp->esm_size = dmac.dmac_size;
	DTRACE_PROBE1(addr, efsys_dma_addr_t, esmp->esm_addr);

	return (0);

fail3:
	DTRACE_PROBE(fail3);

	sfxge_dma_buffer_mem_free(esmp);

fail2:
	DTRACE_PROBE(fail2);

	sfxge_dma_buffer_handle_free(&(esmp->esm_dma_handle));
	esmp->esm_dma_handle = NULL;

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (-1);
}

void
sfxge_dma_buffer_destroy(efsys_mem_t *esmp)
{
	int rc;

	rc = sfxge_dma_buffer_unbind_handle(esmp);
	if (rc != 0) {
		cmn_err(CE_WARN, SFXGE_CMN_ERR "DMA Unbind failed rc=%d", rc);
	}
	sfxge_dma_buffer_mem_free(esmp);
	sfxge_dma_buffer_handle_free(&(esmp->esm_dma_handle));
}
