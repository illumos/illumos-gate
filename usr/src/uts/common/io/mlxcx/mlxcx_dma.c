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
 * Copyright 2020, The University of Queensland
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * DMA allocation and tear down routines.
 */

#include <mlxcx.h>

void
mlxcx_dma_acc_attr(mlxcx_t *mlxp, ddi_device_acc_attr_t *accp)
{
	bzero(accp, sizeof (*accp));
	accp->devacc_attr_version = DDI_DEVICE_ATTR_V0;
	accp->devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	accp->devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (DDI_FM_DMA_ERR_CAP(mlxp->mlx_fm_caps)) {
		accp->devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		accp->devacc_attr_access = DDI_DEFAULT_ACC;
	}
}

void
mlxcx_dma_page_attr(mlxcx_t *mlxp, ddi_dma_attr_t *attrp)
{
	bzero(attrp, sizeof (*attrp));
	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * This is a 64-bit PCIe device. We can use the entire address space.
	 */
	attrp->dma_attr_addr_lo = 0x0;
	attrp->dma_attr_addr_hi = UINT64_MAX;

	/*
	 * The count max indicates the total amount that can fit into one
	 * cookie. Because we're creating a single page for tracking purposes,
	 * this can be a page in size. The alignment and segment are related to
	 * this same requirement. The alignment needs to be page aligned and the
	 * segment is the boundary that this can't cross, aka a 4k page.
	 */
	attrp->dma_attr_count_max = MLXCX_CMD_DMA_PAGE_SIZE - 1;
	attrp->dma_attr_align = MLXCX_CMD_DMA_PAGE_SIZE;
	attrp->dma_attr_seg = MLXCX_CMD_DMA_PAGE_SIZE - 1;

	attrp->dma_attr_burstsizes = 0xfff;

	/*
	 * The minimum and and maximum sizes that we can send. We cap this based
	 * on the use of this, which is a page size.
	 */
	attrp->dma_attr_minxfer = 0x1;
	attrp->dma_attr_maxxfer = MLXCX_CMD_DMA_PAGE_SIZE;

	/*
	 * This is supposed to be used for static data structures, therefore we
	 * keep this just to a page.
	 */
	attrp->dma_attr_sgllen = 1;

	/*
	 * The granularity describe the addressing graularity. That is, the
	 * hardware can ask for chunks in this units of bytes.
	 */
	attrp->dma_attr_granular = MLXCX_CMD_DMA_PAGE_SIZE;

	if (DDI_FM_DMA_ERR_CAP(mlxp->mlx_fm_caps)) {
		attrp->dma_attr_flags = DDI_DMA_FLAGERR;
	} else {
		attrp->dma_attr_flags = 0;
	}
}

/*
 * DMA attributes for queue memory (EQ, CQ, WQ etc)
 *
 * These have to allocate in units of whole pages, but can be multiple
 * pages and don't have to be physically contiguous.
 */
void
mlxcx_dma_queue_attr(mlxcx_t *mlxp, ddi_dma_attr_t *attrp)
{
	bzero(attrp, sizeof (*attrp));
	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * This is a 64-bit PCIe device. We can use the entire address space.
	 */
	attrp->dma_attr_addr_lo = 0x0;
	attrp->dma_attr_addr_hi = UINT64_MAX;

	attrp->dma_attr_count_max = MLXCX_QUEUE_DMA_PAGE_SIZE - 1;

	attrp->dma_attr_align = MLXCX_QUEUE_DMA_PAGE_SIZE;

	attrp->dma_attr_burstsizes = 0xfff;

	/*
	 * The minimum and and maximum sizes that we can send. We cap this based
	 * on the use of this, which is a page size.
	 */
	attrp->dma_attr_minxfer = MLXCX_QUEUE_DMA_PAGE_SIZE;
	attrp->dma_attr_maxxfer = UINT32_MAX;

	attrp->dma_attr_seg = UINT64_MAX;

	attrp->dma_attr_granular = MLXCX_QUEUE_DMA_PAGE_SIZE;

	/* But we can have more than one. */
	attrp->dma_attr_sgllen = MLXCX_CREATE_QUEUE_MAX_PAGES;

	if (DDI_FM_DMA_ERR_CAP(mlxp->mlx_fm_caps)) {
		attrp->dma_attr_flags = DDI_DMA_FLAGERR;
	} else {
		attrp->dma_attr_flags = 0;
	}
}

/*
 * DMA attributes for packet buffers
 */
void
mlxcx_dma_buf_attr(mlxcx_t *mlxp, ddi_dma_attr_t *attrp)
{
	bzero(attrp, sizeof (*attrp));
	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * This is a 64-bit PCIe device. We can use the entire address space.
	 */
	attrp->dma_attr_addr_lo = 0x0;
	attrp->dma_attr_addr_hi = UINT64_MAX;

	/*
	 * Each scatter pointer has a 32-bit length field.
	 */
	attrp->dma_attr_count_max = UINT32_MAX;

	/*
	 * The PRM gives us no alignment requirements for scatter pointers,
	 * but it implies that units < 16bytes are a bad idea.
	 */
	attrp->dma_attr_align = 16;
	attrp->dma_attr_granular = 1;

	attrp->dma_attr_burstsizes = 0xfff;

	attrp->dma_attr_minxfer = 1;
	attrp->dma_attr_maxxfer = UINT64_MAX;

	attrp->dma_attr_seg = UINT64_MAX;

	/*
	 * We choose how many scatter pointers we're allowed per packet when
	 * we set the recv queue stride. This macro is from mlxcx_reg.h where
	 * we fix that for all of our receive queues.
	 */
	attrp->dma_attr_sgllen = MLXCX_RECVQ_MAX_PTRS;

	if (DDI_FM_DMA_ERR_CAP(mlxp->mlx_fm_caps)) {
		attrp->dma_attr_flags = DDI_DMA_FLAGERR;
	} else {
		attrp->dma_attr_flags = 0;
	}
}

/*
 * DMA attributes for queue doorbells
 */
void
mlxcx_dma_qdbell_attr(mlxcx_t *mlxp, ddi_dma_attr_t *attrp)
{
	bzero(attrp, sizeof (*attrp));
	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * This is a 64-bit PCIe device. We can use the entire address space.
	 */
	attrp->dma_attr_addr_lo = 0x0;
	attrp->dma_attr_addr_hi = UINT64_MAX;

	/*
	 * Queue doorbells are always exactly 16 bytes in length, but
	 * the ddi_dma functions don't like such small values of count_max.
	 *
	 * We tell some lies here.
	 */
	attrp->dma_attr_count_max = MLXCX_QUEUE_DMA_PAGE_SIZE - 1;
	attrp->dma_attr_align = 8;
	attrp->dma_attr_burstsizes = 0x8;
	attrp->dma_attr_minxfer = 1;
	attrp->dma_attr_maxxfer = UINT16_MAX;
	attrp->dma_attr_seg = MLXCX_QUEUE_DMA_PAGE_SIZE - 1;
	attrp->dma_attr_granular = 1;
	attrp->dma_attr_sgllen = 1;

	if (DDI_FM_DMA_ERR_CAP(mlxp->mlx_fm_caps)) {
		attrp->dma_attr_flags = DDI_DMA_FLAGERR;
	} else {
		attrp->dma_attr_flags = 0;
	}
}

void
mlxcx_dma_free(mlxcx_dma_buffer_t *mxdb)
{
	int ret;

	if (mxdb->mxdb_flags & MLXCX_DMABUF_BOUND) {
		VERIFY(mxdb->mxdb_dma_handle != NULL);
		ret = ddi_dma_unbind_handle(mxdb->mxdb_dma_handle);
		VERIFY3S(ret, ==, DDI_SUCCESS);
		mxdb->mxdb_flags &= ~MLXCX_DMABUF_BOUND;
		mxdb->mxdb_ncookies = 0;
	}

	if (mxdb->mxdb_flags & MLXCX_DMABUF_MEM_ALLOC) {
		ddi_dma_mem_free(&mxdb->mxdb_acc_handle);
		mxdb->mxdb_acc_handle = NULL;
		mxdb->mxdb_va = NULL;
		mxdb->mxdb_len = 0;
		mxdb->mxdb_flags &= ~MLXCX_DMABUF_MEM_ALLOC;
	}

	if (mxdb->mxdb_flags & MLXCX_DMABUF_FOREIGN) {
		/* The mblk will be freed separately */
		mxdb->mxdb_va = NULL;
		mxdb->mxdb_len = 0;
		mxdb->mxdb_flags &= ~MLXCX_DMABUF_FOREIGN;
	}

	if (mxdb->mxdb_flags & MLXCX_DMABUF_HDL_ALLOC) {
		ddi_dma_free_handle(&mxdb->mxdb_dma_handle);
		mxdb->mxdb_dma_handle = NULL;
		mxdb->mxdb_flags &= ~MLXCX_DMABUF_HDL_ALLOC;
	}

	ASSERT3U(mxdb->mxdb_flags, ==, 0);
	ASSERT3P(mxdb->mxdb_dma_handle, ==, NULL);
	ASSERT3P(mxdb->mxdb_va, ==, NULL);
	ASSERT3U(mxdb->mxdb_len, ==, 0);
	ASSERT3U(mxdb->mxdb_ncookies, ==, 0);
}

void
mlxcx_dma_unbind(mlxcx_t *mlxp, mlxcx_dma_buffer_t *mxdb)
{
	int ret;

	ASSERT(mxdb->mxdb_flags & MLXCX_DMABUF_HDL_ALLOC);
	ASSERT(mxdb->mxdb_flags & MLXCX_DMABUF_BOUND);

	if (mxdb->mxdb_flags & MLXCX_DMABUF_FOREIGN) {
		/* The mblk will be freed separately */
		mxdb->mxdb_va = NULL;
		mxdb->mxdb_len = 0;
		mxdb->mxdb_flags &= ~MLXCX_DMABUF_FOREIGN;
	}

	ret = ddi_dma_unbind_handle(mxdb->mxdb_dma_handle);
	VERIFY3S(ret, ==, DDI_SUCCESS);
	mxdb->mxdb_flags &= ~MLXCX_DMABUF_BOUND;
	mxdb->mxdb_ncookies = 0;
}

boolean_t
mlxcx_dma_init(mlxcx_t *mlxp, mlxcx_dma_buffer_t *mxdb,
    ddi_dma_attr_t *attrp, boolean_t wait)
{
	int ret;
	int (*memcb)(caddr_t);

	if (wait == B_TRUE) {
		memcb = DDI_DMA_SLEEP;
	} else {
		memcb = DDI_DMA_DONTWAIT;
	}

	ASSERT3S(mxdb->mxdb_flags, ==, 0);

	ret = ddi_dma_alloc_handle(mlxp->mlx_dip, attrp, memcb, NULL,
	    &mxdb->mxdb_dma_handle);
	if (ret != 0) {
		mlxcx_warn(mlxp, "!failed to allocate DMA handle: %d", ret);
		mxdb->mxdb_dma_handle = NULL;
		return (B_FALSE);
	}
	mxdb->mxdb_flags |= MLXCX_DMABUF_HDL_ALLOC;

	return (B_TRUE);
}

boolean_t
mlxcx_dma_bind_mblk(mlxcx_t *mlxp, mlxcx_dma_buffer_t *mxdb,
    const mblk_t *mp, size_t off, boolean_t wait)
{
	int ret;
	uint_t flags = DDI_DMA_STREAMING;
	int (*memcb)(caddr_t);

	if (wait == B_TRUE) {
		memcb = DDI_DMA_SLEEP;
	} else {
		memcb = DDI_DMA_DONTWAIT;
	}

	ASSERT(mxdb->mxdb_flags & MLXCX_DMABUF_HDL_ALLOC);
	ASSERT0(mxdb->mxdb_flags &
	    (MLXCX_DMABUF_FOREIGN | MLXCX_DMABUF_MEM_ALLOC));
	ASSERT0(mxdb->mxdb_flags & MLXCX_DMABUF_BOUND);

	ASSERT3U(off, <=, MBLKL(mp));
	mxdb->mxdb_va = (caddr_t)(mp->b_rptr + off);
	mxdb->mxdb_len = MBLKL(mp) - off;
	mxdb->mxdb_flags |= MLXCX_DMABUF_FOREIGN;

	ret = ddi_dma_addr_bind_handle(mxdb->mxdb_dma_handle, NULL,
	    mxdb->mxdb_va, mxdb->mxdb_len, DDI_DMA_WRITE | flags, memcb, NULL,
	    NULL, NULL);
	if (ret != DDI_DMA_MAPPED) {
		mxdb->mxdb_va = NULL;
		mxdb->mxdb_len = 0;
		mxdb->mxdb_flags &= ~MLXCX_DMABUF_FOREIGN;
		return (B_FALSE);
	}
	mxdb->mxdb_flags |= MLXCX_DMABUF_BOUND;
	mxdb->mxdb_ncookies = ddi_dma_ncookies(mxdb->mxdb_dma_handle);

	return (B_TRUE);
}

boolean_t
mlxcx_dma_alloc(mlxcx_t *mlxp, mlxcx_dma_buffer_t *mxdb,
    ddi_dma_attr_t *attrp, ddi_device_acc_attr_t *accp, boolean_t zero,
    size_t size, boolean_t wait)
{
	int ret;
	uint_t flags = DDI_DMA_CONSISTENT;
	size_t len;
	int (*memcb)(caddr_t);

	if (wait == B_TRUE) {
		memcb = DDI_DMA_SLEEP;
	} else {
		memcb = DDI_DMA_DONTWAIT;
	}

	ASSERT3U(mxdb->mxdb_flags, ==, 0);

	ret = ddi_dma_alloc_handle(mlxp->mlx_dip, attrp, memcb, NULL,
	    &mxdb->mxdb_dma_handle);
	if (ret != 0) {
		mlxcx_warn(mlxp, "!failed to allocate DMA handle: %d", ret);
		mxdb->mxdb_dma_handle = NULL;
		return (B_FALSE);
	}
	mxdb->mxdb_flags |= MLXCX_DMABUF_HDL_ALLOC;

	ret = ddi_dma_mem_alloc(mxdb->mxdb_dma_handle, size, accp, flags, memcb,
	    NULL, &mxdb->mxdb_va, &len, &mxdb->mxdb_acc_handle);
	if (ret != DDI_SUCCESS) {
		mlxcx_warn(mlxp, "!failed to allocate DMA memory: %d", ret);
		mxdb->mxdb_va = NULL;
		mxdb->mxdb_acc_handle = NULL;
		mlxcx_dma_free(mxdb);
		return (B_FALSE);
	}
	mxdb->mxdb_len = size;
	mxdb->mxdb_flags |= MLXCX_DMABUF_MEM_ALLOC;

	if (zero == B_TRUE)
		bzero(mxdb->mxdb_va, len);

	ret = ddi_dma_addr_bind_handle(mxdb->mxdb_dma_handle, NULL,
	    mxdb->mxdb_va, len, DDI_DMA_RDWR | flags, memcb, NULL, NULL,
	    NULL);
	if (ret != 0) {
		mlxcx_warn(mlxp, "!failed to bind DMA memory: %d", ret);
		mlxcx_dma_free(mxdb);
		return (B_FALSE);
	}
	mxdb->mxdb_flags |= MLXCX_DMABUF_BOUND;
	mxdb->mxdb_ncookies = ddi_dma_ncookies(mxdb->mxdb_dma_handle);

	return (B_TRUE);
}

boolean_t
mlxcx_dma_alloc_offset(mlxcx_t *mlxp, mlxcx_dma_buffer_t *mxdb,
    ddi_dma_attr_t *attrp, ddi_device_acc_attr_t *accp, boolean_t zero,
    size_t size, size_t offset, boolean_t wait)
{
	int ret;
	uint_t flags = DDI_DMA_STREAMING;
	size_t len;
	int (*memcb)(caddr_t);

	if (wait == B_TRUE) {
		memcb = DDI_DMA_SLEEP;
	} else {
		memcb = DDI_DMA_DONTWAIT;
	}

	ASSERT3U(mxdb->mxdb_flags, ==, 0);

	ret = ddi_dma_alloc_handle(mlxp->mlx_dip, attrp, memcb, NULL,
	    &mxdb->mxdb_dma_handle);
	if (ret != 0) {
		mlxcx_warn(mlxp, "!failed to allocate DMA handle: %d", ret);
		mxdb->mxdb_dma_handle = NULL;
		return (B_FALSE);
	}
	mxdb->mxdb_flags |= MLXCX_DMABUF_HDL_ALLOC;

	ret = ddi_dma_mem_alloc(mxdb->mxdb_dma_handle, size + offset, accp,
	    flags, memcb, NULL, &mxdb->mxdb_va, &len, &mxdb->mxdb_acc_handle);
	if (ret != DDI_SUCCESS) {
		mlxcx_warn(mlxp, "!failed to allocate DMA memory: %d", ret);
		mxdb->mxdb_va = NULL;
		mxdb->mxdb_acc_handle = NULL;
		mlxcx_dma_free(mxdb);
		return (B_FALSE);
	}

	if (zero == B_TRUE)
		bzero(mxdb->mxdb_va, len);

	mxdb->mxdb_va += offset;
	len -= offset;
	mxdb->mxdb_len = len;
	mxdb->mxdb_flags |= MLXCX_DMABUF_MEM_ALLOC;

	ret = ddi_dma_addr_bind_handle(mxdb->mxdb_dma_handle, NULL,
	    mxdb->mxdb_va, len, DDI_DMA_RDWR | flags, memcb, NULL, NULL,
	    NULL);
	if (ret != 0) {
		mlxcx_warn(mlxp, "!failed to bind DMA memory: %d", ret);
		mlxcx_dma_free(mxdb);
		return (B_FALSE);
	}
	mxdb->mxdb_flags |= MLXCX_DMABUF_BOUND;
	mxdb->mxdb_ncookies = ddi_dma_ncookies(mxdb->mxdb_dma_handle);

	return (B_TRUE);
}
