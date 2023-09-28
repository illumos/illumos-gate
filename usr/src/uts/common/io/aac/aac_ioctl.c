/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
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

struct aac_umem_sge {
	uint32_t bcount;
	caddr_t addr;
	struct aac_cmd acp;
};

/*
 * External functions
 */
extern int aac_sync_mbcommand(struct aac_softstate *, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t *);
extern int aac_cmd_dma_alloc(struct aac_softstate *, struct aac_cmd *,
    struct buf *, int, int (*)(), caddr_t);
extern void aac_free_dmamap(struct aac_cmd *);
extern int aac_do_io(struct aac_softstate *, struct aac_cmd *);
extern void aac_cmd_fib_copy(struct aac_softstate *, struct aac_cmd *);
extern void aac_ioctl_complete(struct aac_softstate *, struct aac_cmd *);
extern int aac_return_aif_wait(struct aac_softstate *, struct aac_fib_context *,
    struct aac_fib **);
extern int aac_return_aif(struct aac_softstate *, struct aac_fib_context *,
    struct aac_fib **);

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
static int aac_send_raw_srb(struct aac_softstate *, dev_t, intptr_t, int);
static int aac_get_pci_info(struct aac_softstate *, intptr_t, int);
static int aac_query_disk(struct aac_softstate *, intptr_t, int);
static int aac_delete_disk(struct aac_softstate *, intptr_t, int);
static int aac_supported_features(struct aac_softstate *, intptr_t, int);

/*
 * Warlock directives
 */
_NOTE(SCHEME_PROTECTS_DATA("unique to each handling function", aac_features
    aac_pci_info aac_query_disk aac_revision aac_umem_sge))

int
aac_do_ioctl(struct aac_softstate *softs, dev_t dev, int cmd, intptr_t arg,
    int mode)
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
		status = aac_send_raw_srb(softs, dev, arg, mode);
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
	union aac_revision_align un;
	struct aac_revision *aac_rev = &un.d;

	DBCALLED(softs, 2);

	/* Copyin the revision struct from userspace */
	if (ddi_copyin((void *)arg, aac_rev,
	    sizeof (struct aac_revision), mode) != 0)
		return (EFAULT);

	/* Doctor up the response struct */
	aac_rev->compat = 1;
	aac_rev->version =
	    ((uint32_t)AAC_DRIVER_MAJOR_VERSION << 24) |
	    ((uint32_t)AAC_DRIVER_MINOR_VERSION << 16) |
	    ((uint32_t)AAC_DRIVER_TYPE << 8) |
	    ((uint32_t)AAC_DRIVER_BUGFIX_LEVEL);
	aac_rev->build = (uint32_t)AAC_DRIVER_BUILD;

	if (ddi_copyout(aac_rev, (void *)arg,
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
	uint16_t fib_command;
	uint32_t fib_xfer_state;
	uint16_t fib_data_size, fib_size;
	uint16_t fib_sender_size;
	int rval;

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

	fib_xfer_state = LE_32(fibp->Header.XferState);
	fib_command = LE_16(fibp->Header.Command);
	fib_data_size = LE_16(fibp->Header.Size);
	fib_sender_size = LE_16(fibp->Header.SenderSize);

	fib_size = fib_data_size + sizeof (struct aac_fib_header);
	if (fib_size < fib_sender_size)
		fib_size = fib_sender_size;
	if (fib_size > softs->aac_max_fib_size) {
		rval = EFAULT;
		goto finish;
	}

	/* Copy in FIB data */
	if (ddi_copyin(((struct aac_fib *)arg)->data, fibp->data,
	    fib_data_size, mode) != 0) {
		rval = EFAULT;
		goto finish;
	}
	acp->fib_size = fib_size;
	fibp->Header.Size = LE_16(fib_size);

	/* Process FIB */
	if (fib_command == TakeABreakPt) {
#ifdef DEBUG
		if (aac_dbflag_on(softs, AACDB_FLAGS_FIB) &&
		    (softs->debug_fib_flags & AACDB_FLAGS_FIB_IOCTL))
			aac_printf(softs, CE_NOTE, "FIB> TakeABreakPt, sz=%d",
			    fib_size);
#endif
		(void) aac_sync_mbcommand(softs, AAC_BREAKPOINT_REQ,
		    0, 0, 0, 0, NULL);
		fibp->Header.XferState = LE_32(0);
	} else {
		ASSERT(!(fib_xfer_state & AAC_FIBSTATE_ASYNC));
		fibp->Header.XferState = LE_32(fib_xfer_state | \
		    (AAC_FIBSTATE_FROMHOST | AAC_FIBSTATE_REXPECTED));

		acp->timeout = AAC_IOCTL_TIMEOUT;
		acp->aac_cmd_fib = aac_cmd_fib_copy;
#ifdef DEBUG
		acp->fib_flags = AACDB_FLAGS_FIB_IOCTL;
#endif
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
	struct aac_fib_context *fibctx_p, *ctx_p;

	DBCALLED(softs, 2);

	fibctx_p = kmem_zalloc(sizeof (struct aac_fib_context), KM_NOSLEEP);
	if (fibctx_p == NULL)
		return (ENOMEM);

	mutex_enter(&softs->aifq_mutex);
	/* All elements are already 0, add to queue */
	if (softs->fibctx_p == NULL) {
		softs->fibctx_p = fibctx_p;
	} else {
		for (ctx_p = softs->fibctx_p; ctx_p->next; ctx_p = ctx_p->next)
			;
		ctx_p->next = fibctx_p;
		fibctx_p->prev = ctx_p;
	}

	/* Evaluate unique value */
	fibctx_p->unique = (unsigned long)fibctx_p & 0xfffffffful;
	ctx_p = softs->fibctx_p;
	while (ctx_p != fibctx_p) {
		if (ctx_p->unique == fibctx_p->unique) {
			fibctx_p->unique++;
			ctx_p = softs->fibctx_p;
		} else {
			ctx_p = ctx_p->next;
		}
	}

	/* Set ctx_idx to the oldest AIF */
	if (softs->aifq_wrap) {
		fibctx_p->ctx_idx = softs->aifq_idx;
		fibctx_p->ctx_filled = 1;
	}
	mutex_exit(&softs->aifq_mutex);

	if (ddi_copyout(&fibctx_p->unique, (void *)arg,
	    sizeof (uint32_t), mode) != 0)
		return (EFAULT);

	return (0);
}

static int
aac_next_getadapter_fib(struct aac_softstate *softs, intptr_t arg, int mode)
{
	union aac_get_adapter_fib_align un;
	struct aac_get_adapter_fib *af = &un.d;
	struct aac_fib_context *ctx_p;
	struct aac_fib *fibp;
	int rval;

	DBCALLED(softs, 2);

	if (ddi_copyin((void *)arg, af, sizeof (*af), mode) != 0)
		return (EFAULT);

	mutex_enter(&softs->aifq_mutex);
	for (ctx_p = softs->fibctx_p; ctx_p; ctx_p = ctx_p->next) {
		if (af->context == ctx_p->unique)
			break;
	}
	mutex_exit(&softs->aifq_mutex);

	if (ctx_p) {
		if (af->wait)
			rval = aac_return_aif_wait(softs, ctx_p, &fibp);
		else
			rval = aac_return_aif(softs, ctx_p, &fibp);
	}
	else
		rval = EFAULT;

	if (rval == 0) {
		if (ddi_copyout(fibp,
#ifdef _LP64
		    (void *)(uint64_t)af->aif_fib,
#else
		    (void *)af->aif_fib,
#endif
		    sizeof (struct aac_fib), mode) != 0)
			rval = EFAULT;
	}
	return (rval);
}

static int
aac_close_getadapter_fib(struct aac_softstate *softs, intptr_t arg)
{
	struct aac_fib_context *ctx_p;

	DBCALLED(softs, 2);

	mutex_enter(&softs->aifq_mutex);
	for (ctx_p = softs->fibctx_p; ctx_p; ctx_p = ctx_p->next) {
		if (ctx_p->unique != (uint32_t)arg)
			continue;

		if (ctx_p == softs->fibctx_p)
			softs->fibctx_p = ctx_p->next;
		else
			ctx_p->prev->next = ctx_p->next;
		if (ctx_p->next)
			ctx_p->next->prev = ctx_p->prev;
		break;
	}
	mutex_exit(&softs->aifq_mutex);
	if (ctx_p)
		kmem_free(ctx_p, sizeof (struct aac_fib_context));

	return (0);
}

/*
 * The following function comes from Adaptec:
 *
 * SRB is required for the new management tools
 * Note: SRB passed down from IOCTL is always in CPU endianness.
 */
static int
aac_send_raw_srb(struct aac_softstate *softs, dev_t dev, intptr_t arg, int mode)
{
	struct aac_cmd *acp;
	struct aac_fib *fibp;
	struct aac_srb *srb;
	uint32_t usr_fib_size;
	uint32_t srb_sgcount;
	struct aac_umem_sge *usgt = NULL;
	struct aac_umem_sge *usge;
	ddi_umem_cookie_t cookie;
	int umem_flags = 0;
	int direct = 0;
	int locked = 0;
	caddr_t addrlo = (caddr_t)-1;
	caddr_t addrhi = 0;
	struct aac_sge *sge, *sge0;
	int sg64;
	int rval;

	DBCALLED(softs, 2);

	/* Read srb size */
	if (ddi_copyin(&((struct aac_srb *)arg)->count, &usr_fib_size,
	    sizeof (uint32_t), mode) != 0)
		return (EFAULT);
	if (usr_fib_size > (softs->aac_max_fib_size - \
	    sizeof (struct aac_fib_header)))
		return (EINVAL);

	if ((acp = kmem_zalloc(sizeof (struct aac_cmd) + usr_fib_size + \
	    sizeof (struct aac_fib_header), KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	acp->fibp = (struct aac_fib *)(acp + 1);
	fibp = acp->fibp;
	srb = (struct aac_srb *)fibp->data;

	/* Copy in srb */
	if (ddi_copyin((void *)arg, srb, usr_fib_size, mode) != 0) {
		rval = EFAULT;
		goto finish;
	}

	srb_sgcount = srb->sg.SgCount; /* No endianness conversion needed */
	if (srb_sgcount == 0)
		goto send_fib;

	/* Check FIB size */
	if (usr_fib_size == (sizeof (struct aac_srb) + \
	    srb_sgcount * sizeof (struct aac_sg_entry64) - \
	    sizeof (struct aac_sg_entry))) {
		sg64 = 1;
	} else if (usr_fib_size == (sizeof (struct aac_srb) + \
	    (srb_sgcount - 1) * sizeof (struct aac_sg_entry))) {
		sg64 = 0;
	} else {
		rval = EINVAL;
		goto finish;
	}

	/* Read user SG table */
	if ((usgt = kmem_zalloc(sizeof (struct aac_umem_sge) * srb_sgcount,
	    KM_NOSLEEP)) == NULL) {
		rval = ENOMEM;
		goto finish;
	}
	for (usge = usgt; usge < &usgt[srb_sgcount]; usge++) {
		if (sg64) {
			struct aac_sg_entry64 *sg64p =
			    (struct aac_sg_entry64 *)srb->sg.SgEntry;

			usge->bcount = sg64p->SgByteCount;
			usge->addr = (caddr_t)
#ifndef _LP64
			    (uint32_t)
#endif
			    sg64p->SgAddress;
		} else {
			struct aac_sg_entry *sgp = srb->sg.SgEntry;

			usge->bcount = sgp->SgByteCount;
			usge->addr = (caddr_t)
#ifdef _LP64
			    (uint64_t)
#endif
			    sgp->SgAddress;
		}
		acp->bcount += usge->bcount;
		if (usge->addr < addrlo)
			addrlo = usge->addr;
		if ((usge->addr + usge->bcount) > addrhi)
			addrhi = usge->addr + usge->bcount;
	}
	if (acp->bcount > softs->buf_dma_attr.dma_attr_maxxfer) {
		AACDB_PRINT(softs, CE_NOTE,
		    "large srb xfer size received %d\n", acp->bcount);
		rval = EINVAL;
		goto finish;
	}

	/* Lock user buffers */
	if (srb->flags & SRB_DataIn) {
		umem_flags |= DDI_UMEMLOCK_READ;
		direct |= B_READ;
	}
	if (srb->flags & SRB_DataOut) {
		umem_flags |= DDI_UMEMLOCK_WRITE;
		direct |= B_WRITE;
	}
	addrlo = (caddr_t)((uintptr_t)addrlo & (uintptr_t)PAGEMASK);
	rval = ddi_umem_lock(addrlo, (((size_t)addrhi + PAGEOFFSET) & \
	    PAGEMASK) - (size_t)addrlo, umem_flags, &cookie);
	if (rval != 0) {
		AACDB_PRINT(softs, CE_NOTE, "ddi_umem_lock failed: %d",
		    rval);
		goto finish;
	}
	locked = 1;

	/* Allocate DMA for user buffers */
	for (usge = usgt; usge < &usgt[srb_sgcount]; usge++) {
		struct buf *bp;

		bp = ddi_umem_iosetup(cookie, (uintptr_t)usge->addr - \
		    (uintptr_t)addrlo, usge->bcount, direct, dev, 0, NULL,
		    DDI_UMEM_NOSLEEP);
		if (bp == NULL) {
			AACDB_PRINT(softs, CE_NOTE, "ddi_umem_iosetup failed");
			rval = ENOMEM;
			goto finish;
		}
		if (aac_cmd_dma_alloc(softs, &usge->acp, bp, 0, NULL_FUNC,
		    0) != AACOK) {
			rval = EFAULT;
			goto finish;
		}
		acp->left_cookien += usge->acp.left_cookien;
		if (acp->left_cookien > softs->aac_sg_tablesize) {
			AACDB_PRINT(softs, CE_NOTE, "large cookiec received %d",
			    acp->left_cookien);
			rval = EINVAL;
			goto finish;
		}
	}

	/* Construct aac cmd SG table */
	if ((sge = kmem_zalloc(sizeof (struct aac_sge) * acp->left_cookien,
	    KM_NOSLEEP)) == NULL) {
		rval = ENOMEM;
		goto finish;
	}
	acp->sgt = sge;
	for (usge = usgt; usge < &usgt[srb_sgcount]; usge++) {
		for (sge0 = usge->acp.sgt;
		    sge0 < &usge->acp.sgt[usge->acp.left_cookien];
		    sge0++, sge++)
			*sge = *sge0;
	}

send_fib:
	acp->cmdlen = srb->cdb_size;
	acp->timeout = srb->timeout;

	/* Send FIB command */
	acp->aac_cmd_fib = softs->aac_cmd_fib_scsi;
#ifdef DEBUG
	acp->fib_flags = AACDB_FLAGS_FIB_SRB;
#endif
	if ((rval = aac_send_fib(softs, acp)) != 0)
		goto finish;

	/* Status struct */
	if (ddi_copyout((struct aac_srb_reply *)fibp->data,
	    ((uint8_t *)arg + usr_fib_size),
	    sizeof (struct aac_srb_reply), mode) != 0) {
		rval = EFAULT;
		goto finish;
	}

	rval = 0;
finish:
	if (acp->sgt)
		kmem_free(acp->sgt, sizeof (struct aac_sge) * \
		    acp->left_cookien);
	if (usgt) {
		for (usge = usgt; usge < &usgt[srb_sgcount]; usge++) {
			if (usge->acp.sgt)
				kmem_free(usge->acp.sgt,
				    sizeof (struct aac_sge) * \
				    usge->acp.left_cookien);
			aac_free_dmamap(&usge->acp);
			if (usge->acp.bp)
				freerbuf(usge->acp.bp);
		}
		kmem_free(usgt, sizeof (struct aac_umem_sge) * srb_sgcount);
	}
	if (locked)
		ddi_umem_unlock(cookie);
	kmem_free(acp, sizeof (struct aac_cmd) + usr_fib_size + \
	    sizeof (struct aac_fib_header));
	return (rval);
}

/*ARGSUSED*/
static int
aac_get_pci_info(struct aac_softstate *softs, intptr_t arg, int mode)
{
	union aac_pci_info_align un;
	struct aac_pci_info *resp = &un.d;
	pci_regspec_t *pci_rp;
	uint_t num;

	DBCALLED(softs, 2);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, softs->devinfo_p,
	    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp, &num) !=
	    DDI_PROP_SUCCESS)
		return (EINVAL);
	if (num < (sizeof (pci_regspec_t) / sizeof (int))) {
		ddi_prop_free(pci_rp);
		return (EINVAL);
	}

	resp->bus = PCI_REG_BUS_G(pci_rp->pci_phys_hi);
	resp->slot = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	ddi_prop_free(pci_rp);

	if (ddi_copyout(resp, (void *)arg,
	    sizeof (struct aac_pci_info), mode) != 0)
		return (EFAULT);
	return (0);
}

static int
aac_query_disk(struct aac_softstate *softs, intptr_t arg, int mode)
{
	union aac_query_disk_align un;
	struct aac_query_disk *qdisk = &un.d;
	struct aac_container *dvp;

	DBCALLED(softs, 2);

	if (ddi_copyin((void *)arg, qdisk, sizeof (*qdisk), mode) != 0)
		return (EFAULT);

	if (qdisk->container_no == -1) {
		qdisk->container_no = qdisk->target * 16 + qdisk->lun;
	} else if (qdisk->bus == -1 && qdisk->target == -1 &&
	    qdisk->lun == -1) {
		if (qdisk->container_no >= AAC_MAX_CONTAINERS)
			return (EINVAL);
		qdisk->bus = 0;
		qdisk->target = (qdisk->container_no & 0xf);
		qdisk->lun = (qdisk->container_no >> 4);
	} else {
		return (EINVAL);
	}

	mutex_enter(&softs->io_lock);
	dvp = &softs->containers[qdisk->container_no];
	qdisk->valid = AAC_DEV_IS_VALID(&dvp->dev);
	qdisk->locked = dvp->locked;
	qdisk->deleted = dvp->deleted;
	mutex_exit(&softs->io_lock);

	if (ddi_copyout(qdisk, (void *)arg, sizeof (*qdisk), mode) != 0)
		return (EFAULT);
	return (0);
}

static int
aac_delete_disk(struct aac_softstate *softs, intptr_t arg, int mode)
{
	union aac_delete_disk_align un;
	struct aac_delete_disk *ddisk = &un.d;
	struct aac_container *dvp;
	int rval = 0;

	DBCALLED(softs, 2);

	if (ddi_copyin((void *)arg, ddisk, sizeof (*ddisk), mode) != 0)
		return (EFAULT);

	if (ddisk->container_no >= AAC_MAX_CONTAINERS)
		return (EINVAL);

	mutex_enter(&softs->io_lock);
	dvp = &softs->containers[ddisk->container_no];
	/*
	 * We don't trust the userland to tell us when to delete
	 * a container, rather we rely on an AIF coming from the
	 * controller.
	 */
	if (AAC_DEV_IS_VALID(&dvp->dev)) {
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
	union aac_features_align un;
	struct aac_features *f = &un.d;

	DBCALLED(softs, 2);

	if (ddi_copyin((void *)arg, f, sizeof (*f), mode) != 0)
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
	if (f->feat.fValue == 0) {
		f->feat.fBits.largeLBA =
		    (softs->flags & AAC_FLAGS_LBA_64BIT) ? 1 : 0;
		f->feat.fBits.JBODSupport =
		    (softs->flags & AAC_FLAGS_JBOD) ? 1 : 0;
		/* TODO: In the future, add other features state here as well */
	} else {
		if (f->feat.fBits.largeLBA)
			f->feat.fBits.largeLBA =
			    (softs->flags & AAC_FLAGS_LBA_64BIT) ? 1 : 0;
		if (f->feat.fBits.JBODSupport)
			f->feat.fBits.JBODSupport =
			    (softs->flags & AAC_FLAGS_JBOD) ? 1 : 0;
		/* TODO: Add other features state and data in the future */
	}

	if (ddi_copyout(f, (void *)arg, sizeof (*f), mode) != 0)
		return (EFAULT);
	return (0);
}
