/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2005-06 Adaptec, Inc.
 * Copyright (c) 2005-06 Adaptec Inc., Achim Leubner
 * Copyright (c) 2000 Michael Smith
 * Copyright (c) 2001 Scott Long
 * Copyright (c) 2000 BSDi
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/pci.h>
#include <sys/types.h>
#include <sys/ddidmareq.h>
#include <sys/scsi/scsi.h>
#include <sys/ksynch.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/kmem.h>
#include "aac_regs.h"
#include "aac.h"
#include "aac_ioctl.h"

/*
 * External functions
 */
extern int aac_sync_mbcommand(struct aac_softstate *, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t *);
extern int aac_do_io(struct aac_softstate *, struct aac_cmd *);
extern void aac_free_dmamap(struct aac_cmd *);
extern void aac_ioctl_complete(struct aac_softstate *, struct aac_cmd *);

extern ddi_device_acc_attr_t aac_acc_attr;
extern int aac_check_dma_handle(ddi_dma_handle_t);

/*
 * IOCTL command handling functions
 */
static int aac_check_revision(struct aac_softstate *, intptr_t, int);
static int aac_ioctl_send_fib(struct aac_softstate *, intptr_t, int);
static int aac_open_getadapter_fib(struct aac_softstate *, intptr_t, int);
static int aac_next_getadapter_fib(struct aac_softstate *, intptr_t, int);
static int aac_close_getadapter_fib(struct aac_softstate *, intptr_t);
static int aac_send_raw_srb(struct aac_softstate *, intptr_t, int);
static int aac_get_pci_info(struct aac_softstate *, intptr_t, int);
static int aac_query_disk(struct aac_softstate *, intptr_t, int);
static int aac_delete_disk(struct aac_softstate *, intptr_t, int);
static int aac_supported_features(struct aac_softstate *, intptr_t, int);

/*
 * Warlock directives
 */
_NOTE(SCHEME_PROTECTS_DATA("unique to each handling function", aac_features
    aac_pci_info aac_query_disk aac_revision))

int
aac_do_ioctl(struct aac_softstate *softs, int cmd, intptr_t arg, int mode)
{
	int status;

	switch (cmd) {
	case FSACTL_MINIPORT_REV_CHECK:
		AACDB_PRINT_IOCTL(softs, "FSACTL_MINIPORT_REV_CHECK");
		status = aac_check_revision(softs, arg, mode);
		break;
	case FSACTL_SENDFIB:
		AACDB_PRINT_IOCTL(softs, "FSACTL_SEND_LARGE_FIB");
		goto send_fib;
	case FSACTL_SEND_LARGE_FIB:
		AACDB_PRINT_IOCTL(softs, "FSACTL_SEND_LARGE_FIB");
send_fib:
		status = aac_ioctl_send_fib(softs, arg, mode);
		break;
	case FSACTL_OPEN_GET_ADAPTER_FIB:
		AACDB_PRINT_IOCTL(softs, "FSACTL_OPEN_GET_ADAPTER_FIB");
		status = aac_open_getadapter_fib(softs, arg, mode);
		break;
	case FSACTL_GET_NEXT_ADAPTER_FIB:
		AACDB_PRINT_IOCTL(softs, "FSACTL_GET_NEXT_ADAPTER_FIB");
		status = aac_next_getadapter_fib(softs, arg, mode);
		break;
	case FSACTL_CLOSE_GET_ADAPTER_FIB:
		AACDB_PRINT_IOCTL(softs, "FSACTL_CLOSE_GET_ADAPTER_FIB");
		status = aac_close_getadapter_fib(softs, arg);
		break;
	case FSACTL_SEND_RAW_SRB:
		AACDB_PRINT_IOCTL(softs, "FSACTL_SEND_RAW_SRB");
		status = aac_send_raw_srb(softs, arg, mode);
		break;
	case FSACTL_GET_PCI_INFO:
		AACDB_PRINT_IOCTL(softs, "FSACTL_GET_PCI_INFO");
		status = aac_get_pci_info(softs, arg, mode);
		break;
	case FSACTL_QUERY_DISK:
		AACDB_PRINT_IOCTL(softs, "FSACTL_QUERY_DISK");
		status = aac_query_disk(softs, arg, mode);
		break;
	case FSACTL_DELETE_DISK:
		AACDB_PRINT_IOCTL(softs, "FSACTL_DELETE_DISK");
		status = aac_delete_disk(softs, arg, mode);
		break;
	case FSACTL_GET_FEATURES:
		AACDB_PRINT_IOCTL(softs, "FSACTL_GET_FEATURES");
		status = aac_supported_features(softs, arg, mode);
		break;
	default:
		status = ENOTTY;
		AACDB_PRINT(softs, CE_WARN,
		    "!IOCTL cmd 0x%x not supported", cmd);
		break;
	}

	return (status);
}

/*ARGSUSED*/
static int
aac_check_revision(struct aac_softstate *softs, intptr_t arg, int mode)
{
	struct aac_revision aac_rev;

	DBCALLED(softs, 2);

	/* Copyin the revision struct from userspace */
	if (ddi_copyin((void *)arg, &aac_rev,
	    sizeof (struct aac_revision), mode) != 0)
		return (EFAULT);

	/* Doctor up the response struct */
	aac_rev.compat = 1;
	if (ddi_copyout(&aac_rev, (void *)arg,
	    sizeof (struct aac_revision), mode) != 0)
		return (EFAULT);

	return (0);
}

static int
aac_send_fib(struct aac_softstate *softs, struct aac_cmd *acp)
{
	int rval;

	acp->flags |= AAC_CMD_NO_CB | AAC_CMD_SYNC;
	acp->ac_comp = aac_ioctl_complete;
	acp->timeout = AAC_IOCTL_TIMEOUT;

	mutex_enter(&softs->io_lock);
	if (softs->state & AAC_STATE_DEAD) {
		mutex_exit(&softs->io_lock);
		return (ENXIO);
	}

	rval = aac_do_io(softs, acp);
	if (rval == TRAN_ACCEPT) {
		rval = 0;
	} else if (rval == TRAN_BADPKT) {
		AACDB_PRINT(softs, CE_CONT, "User SendFib failed ENXIO");
		rval = ENXIO;
	} else if (rval == TRAN_BUSY) {
		AACDB_PRINT(softs, CE_CONT, "User SendFib failed EBUSY");
		rval = EBUSY;
	}
	mutex_exit(&softs->io_lock);

	return (rval);
}

static int
aac_ioctl_send_fib(struct aac_softstate *softs, intptr_t arg, int mode)
{
	int hbalen;
	struct aac_cmd *acp;
	struct aac_fib *fibp;
	uint16_t fib_size;
	int rval = 0;

	DBCALLED(softs, 2);

	/* Copy in FIB header */
	hbalen = sizeof (struct aac_cmd) + softs->aac_max_fib_size;
	if ((acp = kmem_zalloc(hbalen, KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	fibp = (struct aac_fib *)(acp + 1);
	acp->fibp = fibp;
	if (ddi_copyin((void *)arg, fibp,
	    sizeof (struct aac_fib_header), mode) != 0) {
		rval = EFAULT;
		goto finish;
	}

	fib_size = fibp->Header.Size + sizeof (struct aac_fib_header);
	if (fib_size < fibp->Header.SenderSize)
		fib_size = fibp->Header.SenderSize;
	if (fib_size > softs->aac_max_fib_size) {
		rval = EFAULT;
		goto finish;
	}

	/* Copy in FIB data */
	if (ddi_copyin(((struct aac_fib *)arg)->data, fibp->data,
	    fibp->Header.Size, mode) != 0) {
		rval = EFAULT;
		goto finish;
	}
	acp->fib_size = fib_size;
	fibp->Header.Size = fib_size;

	AACDB_PRINT_FIB(softs, fibp);

	/* Process FIB */
	if (fibp->Header.Command == TakeABreakPt) {
		(void) aac_sync_mbcommand(softs, AAC_BREAKPOINT_REQ,
		    0, 0, 0, 0, NULL);
		fibp->Header.XferState = 0;
	} else {
		ASSERT(!(fibp->Header.XferState & AAC_FIBSTATE_ASYNC));
		fibp->Header.XferState |=
		    (AAC_FIBSTATE_FROMHOST | AAC_FIBSTATE_REXPECTED);

		if ((rval = aac_send_fib(softs, acp)) != 0)
			goto finish;
	}

	if (acp->flags & AAC_CMD_ERR) {
		AACDB_PRINT(softs, CE_CONT, "FIB data corrupt");
		rval = EIO;
		goto finish;
	}

	if (ddi_copyout(fibp, (void *)arg, acp->fib_size, mode) != 0) {
		AACDB_PRINT(softs, CE_CONT, "FIB copyout failed");
		rval = EFAULT;
		goto finish;
	}

	rval = 0;
finish:
	kmem_free(acp, hbalen);
	return (rval);
}

static int
aac_open_getadapter_fib(struct aac_softstate *softs, intptr_t arg, int mode)
{
	struct aac_fib_context *fibctx, *ctx;

	DBCALLED(softs, 2);

	fibctx = kmem_zalloc(sizeof (struct aac_fib_context), KM_NOSLEEP);
	if (fibctx == NULL)
		return (ENOMEM);

	mutex_enter(&softs->aifq_mutex);
	/* All elements are already 0, add to queue */
	if (softs->fibctx == NULL) {
		softs->fibctx = fibctx;
	} else {
		for (ctx = softs->fibctx; ctx->next; ctx = ctx->next)
			;
		ctx->next = fibctx;
		fibctx->prev = ctx;
	}

	/* Evaluate unique value */
	fibctx->unique = (unsigned long)fibctx & 0xfffffffful;
	ctx = softs->fibctx;
	while (ctx != fibctx) {
		if (ctx->unique == fibctx->unique) {
			fibctx->unique++;
			ctx = softs->fibctx;
		} else {
			ctx = ctx->next;
		}
	}

	/* Set ctx_idx to the oldest AIF */
	if (softs->aifq_wrap) {
		fibctx->ctx_idx = softs->aifq_idx;
		fibctx->ctx_filled = 1;
	}
	mutex_exit(&softs->aifq_mutex);

	if (ddi_copyout(&fibctx->unique, (void *)arg,
	    sizeof (uint32_t), mode) != 0)
		return (EFAULT);

	return (0);
}

static int
aac_return_aif(struct aac_softstate *softs,
    struct aac_fib_context *ctx, caddr_t uptr, int mode)
{
	int current;

	current = ctx->ctx_idx;
	if (current == softs->aifq_idx && !ctx->ctx_filled)
		return (EAGAIN); /* Empty */
	if (ddi_copyout(&softs->aifq[current], (void *)uptr,
	    sizeof (struct aac_fib), mode) != 0)
		return (EFAULT);

	ctx->ctx_filled = 0;
	ctx->ctx_idx = (current + 1) % AAC_AIFQ_LENGTH;

	return (0);
}

static int
aac_next_getadapter_fib(struct aac_softstate *softs, intptr_t arg, int mode)
{
	struct aac_get_adapter_fib af;
	struct aac_fib_context *ctx;
	int rval;

	DBCALLED(softs, 2);

	if (ddi_copyin((void *)arg, &af, sizeof (af), mode) != 0)
		return (EFAULT);

	mutex_enter(&softs->aifq_mutex);
	for (ctx = softs->fibctx; ctx; ctx = ctx->next) {
		if (af.context == ctx->unique)
			break;
	}
	if (ctx) {
#ifdef	_LP64
		rval = aac_return_aif(softs, ctx,
		    (caddr_t)(uint64_t)af.aif_fib, mode);
#else
		rval = aac_return_aif(softs, ctx, (caddr_t)af.aif_fib, mode);
#endif
		if (rval == EAGAIN && af.wait) {
			AACDB_PRINT(softs, CE_NOTE,
			    "aac_next_getadapter_fib(): waiting for AIF");
			rval = cv_wait_sig(&softs->aifv, &softs->aifq_mutex);
			if (rval > 0) {
#ifdef	_LP64
				rval = aac_return_aif(softs, ctx,
				    (caddr_t)(uint64_t)af.aif_fib, mode);
#else
				rval = aac_return_aif(softs, ctx,
				    (caddr_t)af.aif_fib, mode);
#endif
			} else {
				rval = EINTR;
			}
		}
	} else {
		rval = EFAULT;
	}
	mutex_exit(&softs->aifq_mutex);

	return (rval);
}

static int
aac_close_getadapter_fib(struct aac_softstate *softs, intptr_t arg)
{
	struct aac_fib_context *ctx;

	DBCALLED(softs, 2);

	mutex_enter(&softs->aifq_mutex);
	for (ctx = softs->fibctx; ctx; ctx = ctx->next) {
		if (ctx->unique != (uint32_t)arg)
			continue;

		if (ctx == softs->fibctx)
			softs->fibctx = ctx->next;
		else
			ctx->prev->next = ctx->next;
		if (ctx->next)
			ctx->next->prev = ctx->prev;
		break;
	}
	mutex_exit(&softs->aifq_mutex);
	if (ctx)
		kmem_free(ctx, sizeof (struct aac_fib_context));

	return (0);
}

/*
 * The following function comes from Adaptec:
 *
 * SRB is required for the new management tools
 */
static int
aac_send_raw_srb(struct aac_softstate *softs, intptr_t arg, int mode)
{
	int hbalen;
	struct aac_cmd *acp;
	struct aac_fib *fibp;
	struct aac_srb *srb;
	uint32_t usr_fib_size;
	uint_t dma_flags = DDI_DMA_CONSISTENT;
	struct aac_sg_entry *sgp;
	struct aac_sg_entry64 *sg64p;
	uint16_t fib_size;
	uint32_t srb_sg_bytecount;
	uint64_t srb_sg_address;
	int rval;

	DBCALLED(softs, 2);

	hbalen = sizeof (struct aac_cmd) + softs->aac_max_fib_size;
	if ((acp = kmem_zalloc(hbalen, KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	fibp = (struct aac_fib *)(acp + 1);
	acp->fibp = fibp;
	srb = (struct aac_srb *)fibp->data;

	/* Read srb size */
	if (ddi_copyin(&((struct aac_srb *)arg)->count, &usr_fib_size,
	    sizeof (uint32_t), mode) != 0) {
		rval = EFAULT;
		goto finish;
	}
	if (usr_fib_size > (softs->aac_max_fib_size - \
	    sizeof (struct aac_fib_header))) {
		rval = EINVAL;
		goto finish;
	}

	/* Copy in srb */
	if (ddi_copyin((void *)arg, srb, usr_fib_size, mode) != 0) {
		rval = EFAULT;
		goto finish;
	}

	srb->function = 0;	/* SRBF_ExecuteScsi */
	srb->retry_limit = 0;	/* obsolete */

	/* Only one sg element from userspace supported */
	if (srb->sg.SgCount > 1) {
		rval = EINVAL;
		AACDB_PRINT(softs, CE_NOTE, "srb->sg.SgCount %d >1",
		    srb->sg.SgCount);
		goto finish;
	}

	/* Check FIB size */
	sgp = srb->sg.SgEntry;
	sg64p = (struct aac_sg_entry64 *)sgp;
	if (usr_fib_size != (sizeof (struct aac_srb) + \
	    (srb->sg.SgCount - 1) * sizeof (struct aac_sg_entry))) {
		rval = EINVAL;
		goto finish;
	}
	srb_sg_bytecount = sgp->SgByteCount;
	srb_sg_address = (uint64_t)sgp->SgAddress;

	/* Allocate and bind DMA memory space */
	acp->buf_dma_handle = NULL;
	acp->abh = NULL;
	acp->left_cookien = 0;

	rval = ddi_dma_alloc_handle(softs->devinfo_p, &softs->buf_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &acp->buf_dma_handle);
	if (rval != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "Can't allocate DMA handle, errno=%d", rval);
		rval = EFAULT;
		goto finish;
	}

	/* TODO: remove duplicate code with aac_tran_init_pkt() */
	if (srb->sg.SgCount == 1 && srb_sg_bytecount != 0) {
		size_t bufsz;

		/* Allocate DMA buffer */
		rval = ddi_dma_mem_alloc(acp->buf_dma_handle,
		    AAC_ROUNDUP(srb_sg_bytecount, AAC_DMA_ALIGN),
		    &aac_acc_attr, DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
		    NULL, &acp->abp, &bufsz, &acp->abh);
		if (rval != DDI_SUCCESS) {
			AACDB_PRINT(softs, CE_NOTE,
			    "Cannot alloc DMA to non-aligned buf");
			rval = ENOMEM;
			goto finish;
		}

		if ((srb->flags & (SRB_DataIn | SRB_DataOut)) ==
		    (SRB_DataIn | SRB_DataOut))
			dma_flags |= DDI_DMA_RDWR;
		else if ((srb->flags & (SRB_DataIn | SRB_DataOut)) ==
		    SRB_DataIn)
			dma_flags |= DDI_DMA_READ;
		else if ((srb->flags & (SRB_DataIn | SRB_DataOut)) ==
		    SRB_DataOut)
			dma_flags |= DDI_DMA_WRITE;

		rval = ddi_dma_addr_bind_handle(acp->buf_dma_handle, NULL,
		    acp->abp, bufsz, dma_flags, DDI_DMA_DONTWAIT, 0,
		    &acp->cookie, &acp->left_cookien);
		if (rval != DDI_DMA_MAPPED) {
			AACDB_PRINT(softs, CE_NOTE, "Cannot bind buf for DMA");
			rval = EFAULT;
			goto finish;
		}
		acp->flags |= AAC_CMD_DMA_VALID;

		/* Copy in user srb buf content */
		if (srb->flags & SRB_DataOut) {
			if (ddi_copyin(
#ifdef _LP64
			    (void *)srb_sg_address,
#else
			    (void *)(uint32_t)srb_sg_address,
#endif
			    acp->abp, srb_sg_bytecount, mode) != 0) {
				rval = EFAULT;
				goto finish;
			}
			(void) ddi_dma_sync(acp->buf_dma_handle, 0, 0,
			    DDI_DMA_SYNC_FORDEV);
		}
	}

	if (acp->left_cookien > softs->aac_sg_tablesize) {
		AACDB_PRINT(softs, CE_NOTE, "large cookiec received %d\n",
		    acp->left_cookien);
		rval = EFAULT;
		goto finish;
	}

	/* Init FIB header */
	fibp->Header.XferState =
	    AAC_FIBSTATE_HOSTOWNED |
	    AAC_FIBSTATE_INITIALISED |
	    AAC_FIBSTATE_EMPTY |
	    AAC_FIBSTATE_FROMHOST |
	    AAC_FIBSTATE_REXPECTED |
	    AAC_FIBSTATE_NORM;
	fibp->Header.StructType = AAC_FIBTYPE_TFIB;
	fibp->Header.SenderSize = softs->aac_max_fib_size;

	fib_size = sizeof (struct aac_fib_header) + \
	    sizeof (struct aac_srb) - sizeof (struct aac_sg_entry);

	/* Calculate FIB data size */
	if (softs->flags & AAC_FLAGS_SG_64BIT) {
		fibp->Header.Command = ScsiPortCommandU64;
		fib_size += acp->left_cookien * sizeof (struct aac_sg_entry64);
	} else {
		fibp->Header.Command = ScsiPortCommand;
		fib_size += acp->left_cookien * sizeof (struct aac_sg_entry);
	}
	fibp->Header.Size = fib_size;

	/* Fill in sg elements */
	srb->sg.SgCount = acp->left_cookien;
	acp->bcount = 0;
	do {
		if (softs->flags & AAC_FLAGS_SG_64BIT) {
			sg64p->SgAddress = acp->cookie.dmac_laddress;
			sg64p->SgByteCount = acp->cookie.dmac_size;
			sg64p++;
		} else {
			sgp->SgAddress = acp->cookie.dmac_laddress;
			sgp->SgByteCount = acp->cookie.dmac_size;
			sgp++;
		}

		acp->bcount += acp->cookie.dmac_size;
		acp->left_cookien--;
		if (acp->left_cookien > 0)
			ddi_dma_nextcookie(acp->buf_dma_handle,
			    &acp->cookie);
		else
			break;
	/*CONSTCOND*/
	} while (1);

	/* Send FIB command */
	AACDB_PRINT_FIB(softs, fibp);
	acp->fib_size = fib_size;
	if ((rval = aac_send_fib(softs, acp)) != 0)
		goto finish;

	if ((srb->sg.SgCount == 1) && (srb->flags & SRB_DataIn)) {
		(void) ddi_dma_sync(acp->buf_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		if (aac_check_dma_handle(acp->buf_dma_handle) != DDI_SUCCESS) {
			ddi_fm_service_impact(softs->devinfo_p,
			    DDI_SERVICE_UNAFFECTED);
			rval = ENXIO;
			goto finish;
		}
		if (ddi_copyout(acp->abp,
#ifdef _LP64
		    (void *)srb_sg_address,
#else
		    (void *)(uint32_t)srb_sg_address,
#endif
		    srb_sg_bytecount, mode) != 0) {
			rval = EFAULT;
			goto finish;
		}
	}

	/* Status struct */
	if (ddi_copyout((struct aac_srb_reply *)fibp->data,
	    ((uint8_t *)arg + usr_fib_size),
	    sizeof (struct aac_srb_reply), mode) != 0) {
		rval = EFAULT;
		goto finish;
	}

	rval = 0;
finish:
	aac_free_dmamap(acp);
	kmem_free(acp, hbalen);
	return (rval);
}

/*ARGSUSED*/
static int
aac_get_pci_info(struct aac_softstate *softs, intptr_t arg, int mode)
{
	struct aac_pci_info resp;

	DBCALLED(softs, 2);

	resp.bus = 0;
	resp.slot = 0;

	if (ddi_copyout(&resp, (void *)arg,
	    sizeof (struct aac_pci_info), mode) != 0)
		return (EFAULT);
	return (0);
}

static int
aac_query_disk(struct aac_softstate *softs, intptr_t arg, int mode)
{
	struct aac_query_disk qdisk;
	struct aac_container *dvp;

	DBCALLED(softs, 2);

	if (ddi_copyin((void *)arg, &qdisk, sizeof (qdisk), mode) != 0)
		return (EFAULT);

	if (qdisk.container_no == -1) {
		qdisk.container_no = qdisk.target * 16 + qdisk.lun;
	} else if (qdisk.bus == -1 && qdisk.target == -1 && qdisk.lun == -1) {
		if (qdisk.container_no > AAC_MAX_CONTAINERS)
			return (EINVAL);
		qdisk.bus = 0;
		qdisk.target = (qdisk.container_no & 0xf);
		qdisk.lun = (qdisk.container_no >> 4);
	} else {
		return (EINVAL);
	}

	mutex_enter(&softs->io_lock);
	dvp = &softs->container[qdisk.container_no];
	qdisk.valid = dvp->valid;
	qdisk.locked = dvp->locked;
	qdisk.deleted = dvp->deleted;
	mutex_exit(&softs->io_lock);

	if (ddi_copyout(&qdisk, (void *)arg, sizeof (qdisk), mode) != 0)
		return (EFAULT);
	return (0);
}

static int
aac_delete_disk(struct aac_softstate *softs, intptr_t arg, int mode)
{
	struct aac_delete_disk ddisk;
	struct aac_container *dvp;
	int rval = 0;

	DBCALLED(softs, 2);

	if (ddi_copyin((void *)arg, &ddisk, sizeof (ddisk), mode) != 0)
		return (EFAULT);

	if (ddisk.container_no >= AAC_MAX_CONTAINERS)
		return (EINVAL);

	mutex_enter(&softs->io_lock);
	dvp = &softs->container[ddisk.container_no];
	/*
	 * We don't trust the userland to tell us when to delete
	 * a container, rather we rely on an AIF coming from the
	 * controller.
	 */
	if (dvp->valid) {
		if (dvp->locked)
			rval = EBUSY;
	}
	mutex_exit(&softs->io_lock);

	return (rval);
}

/*
 * The following function comes from Adaptec to support creation of arrays
 * bigger than 2TB.
 */
static int
aac_supported_features(struct aac_softstate *softs, intptr_t arg, int mode)
{
	struct aac_features f;

	DBCALLED(softs, 2);

	if (ddi_copyin((void *)arg, &f, sizeof (f), mode) != 0)
		return (EFAULT);

	/*
	 * When the management driver receives FSACTL_GET_FEATURES ioctl with
	 * ALL zero in the featuresState, the driver will return the current
	 * state of all the supported features, the data field will not be
	 * valid.
	 * When the management driver receives FSACTL_GET_FEATURES ioctl with
	 * a specific bit set in the featuresState, the driver will return the
	 * current state of this specific feature and whatever data that are
	 * associated with the feature in the data field or perform whatever
	 * action needed indicates in the data field.
	 */
	if (f.feat.fValue == 0) {
		f.feat.fBits.largeLBA =
		    (softs->flags & AAC_FLAGS_LBA_64BIT) ? 1 : 0;
		/* TODO: In the future, add other features state here as well */
	} else {
		if (f.feat.fBits.largeLBA)
			f.feat.fBits.largeLBA =
			    (softs->flags & AAC_FLAGS_LBA_64BIT) ? 1 : 0;
		/* TODO: Add other features state and data in the future */
	}

	if (ddi_copyout(&f, (void *)arg, sizeof (f), mode) != 0)
		return (EFAULT);
	return (0);
}
