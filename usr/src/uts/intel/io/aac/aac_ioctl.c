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
extern int aac_do_async_io(struct aac_softstate *, struct aac_cmd *);

extern ddi_device_acc_attr_t aac_acc_attr;

/*
 * IOCTL command handling functions
 */
int aac_do_ioctl(struct aac_softstate *, int, intptr_t, int);
static int aac_check_revision(intptr_t, int);
static int aac_ioctl_send_fib(struct aac_softstate *, intptr_t, int);
static int aac_open_getadapter_fib(struct aac_softstate *, intptr_t, int);
static int aac_next_getadapter_fib(struct aac_softstate *, intptr_t, int);
static int aac_close_getadapter_fib(struct aac_softstate *, intptr_t);
static int aac_send_raw_srb(struct aac_softstate *, intptr_t, int);
static int aac_get_pci_info(intptr_t, int);
static int aac_query_disk(struct aac_softstate *, intptr_t, int);
static int aac_delete_disk(struct aac_softstate *, intptr_t, int);
static int aac_supported_features(struct aac_softstate *, intptr_t, int);
static int aac_return_aif(struct aac_softstate *, struct aac_fib_context *,
    caddr_t, int);

int
aac_do_ioctl(struct aac_softstate *softs, int cmd, intptr_t arg, int mode)
{
	int status;

	switch (cmd) {
	case FSACTL_MINIPORT_REV_CHECK:
		status = aac_check_revision(arg, mode);
		break;
	case FSACTL_SENDFIB:
	case FSACTL_SEND_LARGE_FIB:
		status = aac_ioctl_send_fib(softs, arg, mode);
		break;
	case FSACTL_OPEN_GET_ADAPTER_FIB:
		status = aac_open_getadapter_fib(softs, arg, mode);
		break;
	case FSACTL_GET_NEXT_ADAPTER_FIB:
		status = aac_next_getadapter_fib(softs, arg, mode);
		break;
	case FSACTL_CLOSE_GET_ADAPTER_FIB:
		status = aac_close_getadapter_fib(softs, arg);
		break;
	case FSACTL_SEND_RAW_SRB:
		status = aac_send_raw_srb(softs, arg, mode);
		break;
	case FSACTL_GET_PCI_INFO:
		status = aac_get_pci_info(arg, mode);
		break;
	case FSACTL_QUERY_DISK:
		status = aac_query_disk(softs, arg, mode);
		break;
	case FSACTL_DELETE_DISK:
		status = aac_delete_disk(softs, arg, mode);
		break;
	case FSACTL_GET_FEATURES:
		status = aac_supported_features(softs, arg, mode);
		break;
	default:
		status = ENOTTY;
		AACDB_PRINT((CE_WARN, "!IOCTL cmd 0x%x not supported", cmd));
		break;
	}

	return (status);
}

static int
aac_check_revision(intptr_t arg, int mode)
{
	struct aac_revision aac_rev;

	DBCALLED(1);

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
aac_ioctl_send_fib(struct aac_softstate *softs, intptr_t arg, int mode)
{
	int hbalen;
	struct aac_cmd *acp;
	struct aac_fib *fibp;
	unsigned size;
	int rval = 0;

	DBCALLED(1);

	if (softs->state == AAC_STATE_DEAD)
		return (ENXIO);

	/* Copy in FIB header */
	hbalen = sizeof (struct aac_cmd) - sizeof (struct aac_fib) +
	    softs->aac_max_fib_size;
	if ((acp = kmem_zalloc(hbalen, KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	fibp = &acp->fib;
	if (ddi_copyin((void *)arg, fibp,
	    sizeof (struct aac_fib_header), mode) != 0) {
		rval = EFAULT;
		goto finish;
	}
	size = fibp->Header.Size + sizeof (struct aac_fib_header);
	if (size < fibp->Header.SenderSize)
		size = fibp->Header.SenderSize;
	if (size > softs->aac_max_fib_size) {
		rval = EFAULT;
		goto finish;
	}

	/* Copy in FIB data */
	if (ddi_copyin((void *)arg, fibp, size, mode) != 0) {
		rval = EFAULT;
		goto finish;
	}

	AACDB_PRINT_FIB(fibp);

	/* Process FIB */
	if (fibp->Header.Command == TakeABreakPt) {
		(void) aac_sync_mbcommand(softs, AAC_BREAKPOINT_REQ,
		    0, 0, 0, 0, NULL);
		fibp->Header.XferState = 0;
	} else {
		ASSERT(!(fibp->Header.XferState & AAC_FIBSTATE_ASYNC));
		fibp->Header.XferState |=
		    (AAC_FIBSTATE_FROMHOST | AAC_FIBSTATE_REXPECTED);
		fibp->Header.Size = size;

		acp->flags = AAC_CMD_HARD_INTR;
		acp->state = AAC_CMD_INCMPLT;

		/* Send FIB */
		rw_enter(&softs->errlock, RW_READER);
		if (aac_do_async_io(softs, acp) != AACOK) {
			AACDB_PRINT((CE_CONT, "User SendFib failed"));
			rval = ENXIO;
		}
		rw_exit(&softs->errlock);
		if (rval != 0)
			goto finish;

		/* Wait FIB to complete */
		mutex_enter(&softs->event_mutex);
		while (acp->state == AAC_CMD_INCMPLT)
			cv_wait(&softs->event, &softs->event_mutex);
		if (acp->state == AAC_CMD_ABORT)
			rval = EBUSY;
		mutex_exit(&softs->event_mutex);
	}

	if (rval == 0) {
		if (ddi_copyout(fibp, (void *)arg,
		    fibp->Header.Size, mode) != 0) {
			rval = EFAULT;
			goto finish;
		}
	}

finish:
	kmem_free(acp, hbalen);
	return (rval);
}

static int
aac_open_getadapter_fib(struct aac_softstate *softs, intptr_t arg, int mode)
{
	struct aac_fib_context *fibctx, *ctx;

	DBCALLED(1);

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
	mutex_exit(&softs->aifq_mutex);

	if (ddi_copyout(&fibctx->unique, (void *)arg,
	    sizeof (uint32_t), mode) != 0)
		return (EFAULT);

	return (0);
}

static int
aac_next_getadapter_fib(struct aac_softstate *softs, intptr_t arg, int mode)
{
	struct aac_get_adapter_fib af;
	struct aac_fib_context *ctx;
	int rval;

	DBCALLED(1);

	if (ddi_copyin((void *)arg, &af, sizeof (af), mode) != 0)
		return (EFAULT);

	for (ctx = softs->fibctx; ctx; ctx = ctx->next) {
		if (af.context == ctx->unique)
			break;
	}
	if (!ctx)
		return (EFAULT);

#ifdef	_LP64
	rval = aac_return_aif(softs, ctx, (caddr_t)(uint64_t)af.aif_fib, mode);
#else
	rval = aac_return_aif(softs, ctx, (caddr_t)af.aif_fib, mode);
#endif
	if (rval == EAGAIN && af.wait) {
		AACDB_PRINT((CE_NOTE,
		    "aac_next_getadapter_fib(): waiting for AIF"));
		mutex_enter(&softs->aifq_mutex);
		rval = cv_wait_sig(&softs->aifv, &softs->aifq_mutex);
		mutex_exit(&softs->aifq_mutex);
		if (rval == 0)
			rval = EINTR;
		else
#ifdef	_LP64
			rval = aac_return_aif(softs, ctx,
			    (caddr_t)(uint64_t)af.aif_fib, mode);
#else
			rval = aac_return_aif(softs, ctx,
			    (caddr_t)af.aif_fib, mode);
#endif
	}

	return (rval);
}

static int
aac_close_getadapter_fib(struct aac_softstate *softs, intptr_t arg)
{
	struct aac_fib_context *ctx;

	DBCALLED(1);

	mutex_enter(&softs->aifq_mutex);
	for (ctx = softs->fibctx; ctx; ctx = ctx->next) {
		if (ctx->unique != (uint32_t)arg)
			continue;

		if (ctx == softs->fibctx) {
			softs->fibctx = NULL;
		} else {
			ctx->prev->next = ctx->next;
			if (ctx->next)
				ctx->next->prev = ctx->prev;
		}
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
	struct aac_srb *srbcmd;
	struct aac_srb *user_srb = (struct aac_srb *)arg;
	struct aac_srb_reply *srbreply;
	void *user_reply;
	uint32_t byte_count = 0, fibsize = 0;
	uint_t i, dma_flags = DDI_DMA_CONSISTENT;
	ddi_dma_cookie_t *cookiep = NULL;
	int err, rval = 0;

	DBCALLED(1);

	if (softs->state == AAC_STATE_DEAD)
		return (ENXIO);

	hbalen = sizeof (struct aac_cmd) - sizeof (struct aac_fib) +
	    softs->aac_max_fib_size;
	if ((acp = kmem_zalloc(hbalen, KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	fibp = &acp->fib;
	srbcmd = (struct aac_srb *)fibp->data;

	/* Read srb size */
	if (ddi_copyin((void *)&user_srb->count, &fibsize,
	    sizeof (uint32_t), mode) != 0) {
		rval = EFAULT;
		goto finish;
	}
	if (fibsize > (softs->aac_max_fib_size - \
	    sizeof (struct aac_fib_header))) {
		rval = EINVAL;
		goto finish;
	}

	/* Copy in srb */
	if (ddi_copyin((void *)user_srb, srbcmd, fibsize, mode) != 0) {
		rval = EFAULT;
		goto finish;
	}
	srbcmd->function = 0;		/* SRBF_ExecuteScsi */
	srbcmd->retry_limit = 0;	/* obsolete */

	/* Only one sg element from userspace supported */
	if (srbcmd->sg.SgCount > 1) {
		rval = EINVAL;
		goto finish;
	}
	/* Check FIB size */
	if (fibsize != (sizeof (struct aac_srb) + \
	    (srbcmd->sg.SgCount - 1) * sizeof (struct aac_sg_entry))) {
		rval = EINVAL;
		goto finish;
	}
	user_reply = (char *)arg + fibsize;

	/* Allocate and bind DMA memory space */
	acp->buf_dma_handle = NULL;
	acp->abh = NULL;
	acp->left_cookien = 0;

	err = ddi_dma_alloc_handle(softs->devinfo_p, &softs->buf_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &acp->buf_dma_handle);
	if (err != DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN,
		    "Can't allocate DMA handle, errno=%d", rval));
		rval = EFAULT;
		goto finish;
	}

	/* TODO: remove duplicate code with aac_tran_init_pkt() */
	if (srbcmd->sg.SgCount == 1) {
		size_t bufsz;

		err = ddi_dma_mem_alloc(acp->buf_dma_handle,
		    AAC_ROUNDUP(srbcmd->sg.SgEntry[0].SgByteCount,
		    AAC_DMA_ALIGN),
		    &aac_acc_attr, DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
		    NULL, &acp->abp, &bufsz, &acp->abh);
		if (err != DDI_SUCCESS) {
			AACDB_PRINT((CE_NOTE,
			    "Cannot alloc DMA to non-aligned buf"));
			rval = ENOMEM;
			goto finish;
		}

		if ((srbcmd->flags & (SRB_DataIn | SRB_DataOut)) ==
		    (SRB_DataIn | SRB_DataOut))
			dma_flags |= DDI_DMA_RDWR;
		else if ((srbcmd->flags & (SRB_DataIn | SRB_DataOut)) ==
		    SRB_DataIn)
			dma_flags |= DDI_DMA_READ;
		else if ((srbcmd->flags & (SRB_DataIn | SRB_DataOut)) ==
		    SRB_DataOut)
			dma_flags |= DDI_DMA_WRITE;
		err = ddi_dma_addr_bind_handle(acp->buf_dma_handle, NULL,
		    acp->abp, bufsz, dma_flags, DDI_DMA_DONTWAIT, 0,
		    &acp->cookie, &acp->left_cookien);
		if (err != DDI_DMA_MAPPED) {
			AACDB_PRINT((CE_NOTE, "Cannot bind buf for DMA"));
			rval = EFAULT;
			goto finish;
		}
		cookiep = &acp->cookie;

		if (srbcmd->flags & SRB_DataOut) {
			if (ddi_copyin(
#ifdef _LP64
			    (void *)(uint64_t)user_srb-> \
			    sg.SgEntry[0].SgAddress,
#else
			    (void *)user_srb->sg.SgEntry[0].SgAddress,
#endif
			    acp->abp, user_srb->sg.SgEntry[0].SgByteCount,
			    mode) != 0) {
				rval = EFAULT;
				goto finish;
			}
		}
	}

	/* Fill in command, sg elements */
	if (softs->flags & AAC_FLAGS_SG_64BIT) {
		struct aac_sg_entry64 *sgp = (struct aac_sg_entry64 *)
		    srbcmd->sg.SgEntry;

		fibp->Header.Command = ScsiPortCommandU64;
		for (i = 0; i < acp->left_cookien &&
		    i < softs->aac_sg_tablesize; i++) {
			sgp[i].SgAddress = cookiep->dmac_laddress;
			sgp[i].SgByteCount = cookiep->dmac_size;
			if ((i + 1) < acp->left_cookien)
				ddi_dma_nextcookie(acp->buf_dma_handle,
				    cookiep);
			byte_count += sgp[i].SgByteCount;
		}
		fibsize = sizeof (struct aac_srb) - \
		    sizeof (struct aac_sg_entry) + \
		    i * sizeof (struct aac_sg_entry64);
	} else {
		struct aac_sg_entry *sgp = srbcmd->sg.SgEntry;

		fibp->Header.Command = ScsiPortCommand;
		for (i = 0; i < acp->left_cookien &&
		    i < softs->aac_sg_tablesize; i++) {
			sgp[i].SgAddress = cookiep->dmac_laddress;
			sgp[i].SgByteCount = cookiep->dmac_size;
			if ((i + 1) < acp->left_cookien)
				ddi_dma_nextcookie(acp->buf_dma_handle,
				    cookiep);
			byte_count += sgp[i].SgByteCount;
		}
		fibsize = sizeof (struct aac_srb) + \
		    (i - 1) * sizeof (struct aac_sg_entry);
	}
	srbcmd->count = byte_count;
	srbcmd->sg.SgCount = i;

	/* Fill fib header */
	fibp->Header.XferState =
	    AAC_FIBSTATE_HOSTOWNED |
	    AAC_FIBSTATE_INITIALISED |
	    AAC_FIBSTATE_EMPTY |
	    AAC_FIBSTATE_FROMHOST |
	    AAC_FIBSTATE_REXPECTED |
	    AAC_FIBSTATE_NORM;
	fibp->Header.Size = sizeof (struct aac_fib_header) + fibsize;
	fibp->Header.StructType = AAC_FIBTYPE_TFIB;
	fibp->Header.SenderSize = softs->aac_max_fib_size;

	/* TODO: remove duplicate code with aac_ioctl_send_fib() */
	AACDB_PRINT_FIB(fibp);

	/* Send command */
	acp->flags = AAC_CMD_HARD_INTR;
	acp->state = AAC_CMD_INCMPLT;

	rw_enter(&softs->errlock, RW_READER);
	if (aac_do_async_io(softs, acp) != AACOK) {
		AACDB_PRINT((CE_CONT, "User SendFib failed"));
		rval = ENXIO;
	}
	rw_exit(&softs->errlock);
	if (rval != 0)
		goto finish;

	mutex_enter(&softs->event_mutex);
	while (acp->state == AAC_CMD_INCMPLT)
		cv_wait(&softs->event, &softs->event_mutex);
	if (acp->state == AAC_CMD_ABORT)
		rval = EBUSY;
	mutex_exit(&softs->event_mutex);

	if (rval != 0)
		goto finish;

	if ((srbcmd->sg.SgCount == 1) && (srbcmd->flags & SRB_DataIn)) {
		if (ddi_copyout(acp->abp,
#ifdef _LP64
		    (void *)(uint64_t)user_srb->sg.SgEntry[0].SgAddress,
#else
		    (void *)user_srb->sg.SgEntry[0].SgAddress,
#endif
		    user_srb->sg.SgEntry[0].SgByteCount, mode) != 0) {
			rval = EFAULT;
			goto finish;
		}
	}

	/* Status struct */
	srbreply = (struct aac_srb_reply *)fibp->data;
	if (ddi_copyout(srbreply, user_reply,
	    sizeof (struct aac_srb_reply), mode) != 0) {
		rval = EFAULT;
		goto finish;
	}

finish:
	if (cookiep)
		(void) ddi_dma_unbind_handle(acp->buf_dma_handle);
	if (acp->abh)
		ddi_dma_mem_free(&acp->abh);
	if (acp->buf_dma_handle)
		ddi_dma_free_handle(&acp->buf_dma_handle);
	kmem_free(acp, hbalen);
	return (rval);
}

static int
aac_get_pci_info(intptr_t arg, int mode)
{
	struct aac_pci_info resp;

	DBCALLED(1);

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

	DBCALLED(1);

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

	qdisk.valid = softs->container[qdisk.container_no].valid;
	qdisk.locked = softs->container[qdisk.container_no].locked;
	qdisk.deleted = softs->container[qdisk.container_no].deleted;

	if (ddi_copyout(&qdisk, (void *)arg, sizeof (qdisk), mode) != 0)
		return (EFAULT);
	return (0);
}

static int
aac_delete_disk(struct aac_softstate *softs, intptr_t arg, int mode)
{
	struct aac_delete_disk ddisk;

	DBCALLED(1);

	if (ddi_copyin((void *)arg, &ddisk, sizeof (ddisk), mode) != 0)
		return (EFAULT);

	if (ddisk.container_no > AAC_MAX_CONTAINERS)
		return (EINVAL);
	if (softs->container[ddisk.container_no].locked)
		return (EBUSY);

	/*
	 * We don't trust the userland to tell us when to delete
	 * a container, rather we rely on an AIF coming from the
	 * controller.
	 */
	return (0);
}

/*
 * The following function comes from Adaptec to support creation of arrays
 * bigger than 2TB.
 */
static int
aac_supported_features(struct aac_softstate *softs, intptr_t arg, int mode)
{
	struct aac_features f;

	DBCALLED(1);

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

static int
aac_return_aif(struct aac_softstate *softs,
    struct aac_fib_context *ctx, caddr_t uptr, int mode)
{
	int current;

	mutex_enter(&softs->aifq_mutex);
	current = ctx->ctx_idx;
	if (current == softs->aifq_idx && !ctx->ctx_wrap) {
		/* Empty */
		mutex_exit(&softs->aifq_mutex);
		return (EAGAIN);
	}
	if (ddi_copyout(&softs->aifq[current], (void *)uptr,
	    sizeof (struct aac_fib), mode) != 0) {
		mutex_exit(&softs->aifq_mutex);
		return (EFAULT);
	}

	ctx->ctx_wrap = 0;
	ctx->ctx_idx = (current + 1) % AAC_AIFQ_LENGTH;
	mutex_exit(&softs->aifq_mutex);

	return (0);
}
