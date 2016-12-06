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

#include <sys/scsi/adapters/smrt/smrt.h>


static ddi_dma_attr_t smrt_command_dma_attr = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x00000000,
	.dma_attr_addr_hi =		0xFFFFFFFF,
	.dma_attr_count_max =		0x00FFFFFF,
	.dma_attr_align =		0x20,
	.dma_attr_burstsizes =		0x20,
	.dma_attr_minxfer =		DMA_UNIT_8,
	.dma_attr_maxxfer =		0xFFFFFFFF,
	.dma_attr_seg =			0x0000FFFF,
	.dma_attr_sgllen =		1,
	.dma_attr_granular =		512,
	.dma_attr_flags =		0
};

/*
 * These device access attributes are for command block allocation, where we do
 * not use any of the structured byte swapping facilities.
 */
static ddi_device_acc_attr_t smrt_command_dev_attr = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags =	DDI_NEVERSWAP_ACC,
	.devacc_attr_dataorder =	DDI_STRICTORDER_ACC,
	.devacc_attr_access =		0
};


static void smrt_contig_free(smrt_dma_t *);


static int
smrt_check_command_type(smrt_command_type_t type)
{
	/*
	 * Note that we leave out the default case in order to utilise
	 * compiler warnings about missed enum values.
	 */
	switch (type) {
	case SMRT_CMDTYPE_ABORTQ:
	case SMRT_CMDTYPE_SCSA:
	case SMRT_CMDTYPE_INTERNAL:
	case SMRT_CMDTYPE_PREINIT:
		return (type);
	}

	panic("unexpected command type");
	/* LINTED: E_FUNC_NO_RET_VAL */
}

static int
smrt_contig_alloc(smrt_t *smrt, smrt_dma_t *smdma, size_t sz, int kmflags,
    void **vap, uint32_t *pap)
{
	caddr_t va;
	int rv;
	dev_info_t *dip = smrt->smrt_dip;
	int (*dma_wait)(caddr_t) = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP :
	    DDI_DMA_DONTWAIT;

	VERIFY(kmflags == KM_SLEEP || kmflags == KM_NOSLEEP);

	/*
	 * Ensure we don't try to allocate a second time using the same
	 * tracking object.
	 */
	VERIFY0(smdma->smdma_level);

	if ((rv = ddi_dma_alloc_handle(dip, &smrt_command_dma_attr,
	    dma_wait, NULL, &smdma->smdma_dma_handle)) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "DMA handle allocation failed (%x)",
		    rv);
		goto fail;
	}
	smdma->smdma_level |= SMRT_DMALEVEL_HANDLE_ALLOC;

	if ((rv = ddi_dma_mem_alloc(smdma->smdma_dma_handle, sz,
	    &smrt_command_dev_attr, DDI_DMA_CONSISTENT, dma_wait, NULL,
	    &va, &smdma->smdma_real_size, &smdma->smdma_acc_handle)) !=
	    DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "DMA memory allocation failed (%x)", rv);
		goto fail;
	}
	smdma->smdma_level |= SMRT_DMALEVEL_MEMORY_ALLOC;

	if ((rv = ddi_dma_addr_bind_handle(smdma->smdma_dma_handle,
	    NULL, va, smdma->smdma_real_size,
	    DDI_DMA_CONSISTENT | DDI_DMA_RDWR, dma_wait, NULL,
	    smdma->smdma_dma_cookies, &smdma->smdma_dma_ncookies)) !=
	    DDI_DMA_MAPPED) {
		dev_err(dip, CE_WARN, "DMA handle bind failed (%x)", rv);
		goto fail;
	}
	smdma->smdma_level |= SMRT_DMALEVEL_HANDLE_BOUND;

	VERIFY3U(smdma->smdma_dma_ncookies, ==, 1);
	*pap = smdma->smdma_dma_cookies[0].dmac_address;
	*vap = (void *)va;
	return (DDI_SUCCESS);

fail:
	*vap = NULL;
	*pap = 0;
	smrt_contig_free(smdma);
	return (DDI_FAILURE);
}

static void
smrt_contig_free(smrt_dma_t *smdma)
{
	if (smdma->smdma_level & SMRT_DMALEVEL_HANDLE_BOUND) {
		VERIFY3U(ddi_dma_unbind_handle(smdma->smdma_dma_handle), ==,
		    DDI_SUCCESS);

		smdma->smdma_level &= ~SMRT_DMALEVEL_HANDLE_BOUND;
	}

	if (smdma->smdma_level & SMRT_DMALEVEL_MEMORY_ALLOC) {
		ddi_dma_mem_free(&smdma->smdma_acc_handle);

		smdma->smdma_level &= ~SMRT_DMALEVEL_MEMORY_ALLOC;
	}

	if (smdma->smdma_level & SMRT_DMALEVEL_HANDLE_ALLOC) {
		ddi_dma_free_handle(&smdma->smdma_dma_handle);

		smdma->smdma_level &= ~SMRT_DMALEVEL_HANDLE_ALLOC;
	}

	VERIFY(smdma->smdma_level == 0);
	bzero(smdma, sizeof (*smdma));
}

static smrt_command_t *
smrt_command_alloc_impl(smrt_t *smrt, smrt_command_type_t type, int kmflags)
{
	smrt_command_t *smcm;

	VERIFY(kmflags == KM_SLEEP || kmflags == KM_NOSLEEP);

	if ((smcm = kmem_zalloc(sizeof (*smcm), kmflags)) == NULL) {
		return (NULL);
	}

	smcm->smcm_ctlr = smrt;
	smcm->smcm_type = smrt_check_command_type(type);

	/*
	 * Allocate a single contiguous chunk of memory for the command block
	 * (smcm_va_cmd) and the error information block (smcm_va_err).  The
	 * physical address of each block should be 32-byte aligned.
	 */
	size_t contig_size = 0;
	contig_size += P2ROUNDUP_TYPED(sizeof (CommandList_t), 32, size_t);

	size_t errorinfo_offset = contig_size;
	contig_size += P2ROUNDUP_TYPED(sizeof (ErrorInfo_t), 32, size_t);

	if (smrt_contig_alloc(smrt, &smcm->smcm_contig, contig_size,
	    kmflags, (void **)&smcm->smcm_va_cmd, &smcm->smcm_pa_cmd) !=
	    DDI_SUCCESS) {
		kmem_free(smcm, sizeof (*smcm));
		return (NULL);
	}

	smcm->smcm_va_err = (void *)((caddr_t)smcm->smcm_va_cmd +
	    errorinfo_offset);
	smcm->smcm_pa_err = smcm->smcm_pa_cmd + errorinfo_offset;

	/*
	 * Ensure we asked for, and received, the correct physical alignment:
	 */
	VERIFY0(smcm->smcm_pa_cmd & 0x1f);
	VERIFY0(smcm->smcm_pa_err & 0x1f);

	/*
	 * Populate Fields.
	 */
	bzero(smcm->smcm_va_cmd, contig_size);
	smcm->smcm_va_cmd->ErrDesc.Addr = smcm->smcm_pa_err;
	smcm->smcm_va_cmd->ErrDesc.Len = sizeof (ErrorInfo_t);

	return (smcm);
}

smrt_command_t *
smrt_command_alloc_preinit(smrt_t *smrt, size_t datasize, int kmflags)
{
	smrt_command_t *smcm;

	if ((smcm = smrt_command_alloc_impl(smrt, SMRT_CMDTYPE_PREINIT,
	    kmflags)) == NULL) {
		return (NULL);
	}

	/*
	 * Note that most driver infrastructure has not been initialised at
	 * this time.  All commands are submitted to the controller serially,
	 * using a pre-specified tag, and are not attached to the command
	 * tracking list.
	 */
	smcm->smcm_tag = SMRT_PRE_TAG_NUMBER;
	smcm->smcm_va_cmd->Header.Tag.tag_value = SMRT_PRE_TAG_NUMBER;

	if (smrt_command_attach_internal(smrt, smcm, datasize, kmflags) != 0) {
		smrt_command_free(smcm);
		return (NULL);
	}

	return (smcm);
}

smrt_command_t *
smrt_command_alloc(smrt_t *smrt, smrt_command_type_t type, int kmflags)
{
	smrt_command_t *smcm;

	VERIFY(type != SMRT_CMDTYPE_PREINIT);

	if ((smcm = smrt_command_alloc_impl(smrt, type, kmflags)) == NULL) {
		return (NULL);
	}

	/*
	 * Insert into the per-controller command list.
	 */
	mutex_enter(&smrt->smrt_mutex);
	list_insert_tail(&smrt->smrt_commands, smcm);
	mutex_exit(&smrt->smrt_mutex);

	return (smcm);
}

int
smrt_command_attach_internal(smrt_t *smrt, smrt_command_t *smcm, size_t len,
    int kmflags)
{
	smrt_command_internal_t *smcmi;

	VERIFY(kmflags == KM_SLEEP || kmflags == KM_NOSLEEP);
	VERIFY3U(len, <=, UINT32_MAX);

	if ((smcmi = kmem_zalloc(sizeof (*smcmi), kmflags)) == NULL) {
		return (ENOMEM);
	}

	if (smrt_contig_alloc(smrt, &smcmi->smcmi_contig, len, kmflags,
	    &smcmi->smcmi_va, &smcmi->smcmi_pa) != DDI_SUCCESS) {
		kmem_free(smcmi, sizeof (*smcmi));
		return (ENOMEM);
	}

	bzero(smcmi->smcmi_va, smcmi->smcmi_len);

	smcm->smcm_internal = smcmi;

	smcm->smcm_va_cmd->SG[0].Addr = smcmi->smcmi_pa;
	smcm->smcm_va_cmd->SG[0].Len = (uint32_t)len;
	smcm->smcm_va_cmd->Header.SGList = 1;
	smcm->smcm_va_cmd->Header.SGTotal = 1;

	return (0);
}

void
smrt_command_reuse(smrt_command_t *smcm)
{
	smrt_t *smrt = smcm->smcm_ctlr;

	mutex_enter(&smrt->smrt_mutex);

	/*
	 * Make sure the command is not currently inflight, then
	 * reset the command status.
	 */
	VERIFY(!(smcm->smcm_status & SMRT_CMD_STATUS_INFLIGHT));
	smcm->smcm_status = SMRT_CMD_STATUS_REUSED;

	/*
	 * Ensure we are not trying to reuse a command that is in the finish or
	 * abort queue.
	 */
	VERIFY(!list_link_active(&smcm->smcm_link_abort));
	VERIFY(!list_link_active(&smcm->smcm_link_finish));

	/*
	 * Clear the previous tag value.
	 */
	smcm->smcm_tag = 0;
	smcm->smcm_va_cmd->Header.Tag.tag_value = 0;

	mutex_exit(&smrt->smrt_mutex);
}

void
smrt_command_free(smrt_command_t *smcm)
{
	smrt_t *smrt = smcm->smcm_ctlr;

	/*
	 * Ensure the object we are about to free is not currently in the
	 * inflight AVL.
	 */
	VERIFY(!(smcm->smcm_status & SMRT_CMD_STATUS_INFLIGHT));

	if (smcm->smcm_internal != NULL) {
		smrt_command_internal_t *smcmi = smcm->smcm_internal;

		smrt_contig_free(&smcmi->smcmi_contig);
		kmem_free(smcmi, sizeof (*smcmi));
	}

	smrt_contig_free(&smcm->smcm_contig);

	if (smcm->smcm_type != SMRT_CMDTYPE_PREINIT) {
		mutex_enter(&smrt->smrt_mutex);

		/*
		 * Ensure we are not trying to free a command that is in the
		 * finish or abort queue.
		 */
		VERIFY(!list_link_active(&smcm->smcm_link_abort));
		VERIFY(!list_link_active(&smcm->smcm_link_finish));

		list_remove(&smrt->smrt_commands, smcm);

		mutex_exit(&smrt->smrt_mutex);
	}

	kmem_free(smcm, sizeof (*smcm));
}

smrt_command_t *
smrt_lookup_inflight(smrt_t *smrt, uint32_t tag)
{
	smrt_command_t srch;

	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	bzero(&srch, sizeof (srch));
	srch.smcm_tag = tag;

	return (avl_find(&smrt->smrt_inflight, &srch, NULL));
}
