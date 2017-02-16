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
 * Copyright 2016 Nexenta Systems, Inc.
 */

#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/ddi.h>
#include <sys/errno.h>
#include <sys/fs/dv_node.h>
#include <sys/kmem.h>
#include <sys/kmem_impl.h>
#include <sys/list.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/scsi/scsi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>

#include "pvscsi.h"
#include "pvscsi_var.h"

int pvscsi_enable_msi = 1;
int pvscsi_ring_pages = PVSCSI_DEFAULT_NUM_PAGES_PER_RING;
int pvscsi_msg_ring_pages = PVSCSI_DEFAULT_NUM_PAGES_MSG_RING;

static int pvscsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt);

static void *pvscsi_sstate;

/* HBA DMA attributes */
static ddi_dma_attr_t pvscsi_hba_dma_attr = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0000000000000000ull,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max =	0x000000007FFFFFFFull,
	.dma_attr_align =	0x0000000000000001ull,
	.dma_attr_burstsizes =	0x7ff,
	.dma_attr_minxfer =	0x00000001u,
	.dma_attr_maxxfer =	0x00000000FFFFFFFFull,
	.dma_attr_seg =		0x00000000FFFFFFFFull,
	.dma_attr_sgllen =	1,
	.dma_attr_granular =	0x00000200u,
	.dma_attr_flags =	0
};

/* DMA attributes for req/comp rings */
static ddi_dma_attr_t pvscsi_ring_dma_attr = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0000000000000000ull,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max =	0x000000007FFFFFFFull,
	.dma_attr_align =	0x0000000000000001ull,
	.dma_attr_burstsizes =	0x7ff,
	.dma_attr_minxfer =	0x00000001u,
	.dma_attr_maxxfer =	0x00000000FFFFFFFFull,
	.dma_attr_seg =		0x00000000FFFFFFFFull,
	.dma_attr_sgllen =	1,
	.dma_attr_granular =	0x00000001u,
	.dma_attr_flags =	0
};

/* DMA attributes for buffer I/O */
static ddi_dma_attr_t pvscsi_io_dma_attr = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0000000000000000ull,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max =	0x000000007FFFFFFFull,
	.dma_attr_align =	0x0000000000000001ull,
	.dma_attr_burstsizes =	0x7ff,
	.dma_attr_minxfer =	0x00000001u,
	.dma_attr_maxxfer =	0x00000000FFFFFFFFull,
	.dma_attr_seg =		0x00000000FFFFFFFFull,
	.dma_attr_sgllen =	PVSCSI_MAX_SG_SIZE,
	.dma_attr_granular =	0x00000200u,
	.dma_attr_flags =	0
};

static ddi_device_acc_attr_t pvscsi_mmio_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

static ddi_device_acc_attr_t pvscsi_dma_attrs = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC,
};

static void
pvscsi_add_to_queue(pvscsi_cmd_t *cmd)
{
	pvscsi_softc_t	*pvs = cmd->cmd_pvs;

	ASSERT(pvs != NULL);
	ASSERT(mutex_owned(&pvs->mutex));
	ASSERT(!list_link_active(&(cmd)->cmd_queue_node));

	list_insert_tail(&pvs->cmd_queue, cmd);
	pvs->cmd_queue_len++;
}

static void
pvscsi_remove_from_queue(pvscsi_cmd_t *cmd)
{
	pvscsi_softc_t	*pvs = cmd->cmd_pvs;

	ASSERT(pvs != NULL);
	ASSERT(mutex_owned(&pvs->mutex));
	ASSERT(list_link_active(&cmd->cmd_queue_node));
	ASSERT(pvs->cmd_queue_len > 0);

	if (list_link_active(&cmd->cmd_queue_node)) {
		list_remove(&pvs->cmd_queue, cmd);
		pvs->cmd_queue_len--;
	}
}

static uint64_t
pvscsi_map_ctx(pvscsi_softc_t *pvs, pvscsi_cmd_ctx_t *io_ctx)
{
	return (io_ctx - pvs->cmd_ctx + 1);
}

static pvscsi_cmd_ctx_t *
pvscsi_lookup_ctx(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd)
{
	pvscsi_cmd_ctx_t *ctx, *end;

	end = &pvs->cmd_ctx[pvs->req_depth];
	for (ctx = pvs->cmd_ctx; ctx < end; ctx++) {
		if (ctx->cmd == cmd)
			return (ctx);
	}

	return (NULL);
}

static pvscsi_cmd_ctx_t *
pvscsi_resolve_ctx(pvscsi_softc_t *pvs, uint64_t ctx)
{
	if (ctx > 0 && ctx <= pvs->req_depth)
		return (&pvs->cmd_ctx[ctx - 1]);
	else
		return (NULL);
}

static boolean_t
pvscsi_acquire_ctx(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd)
{
	pvscsi_cmd_ctx_t *ctx;

	if (list_is_empty(&pvs->cmd_ctx_pool))
		return (B_FALSE);

	ctx = (pvscsi_cmd_ctx_t *)list_remove_head(&pvs->cmd_ctx_pool);
	ASSERT(ctx != NULL);

	ctx->cmd = cmd;
	cmd->ctx = ctx;

	return (B_TRUE);
}

static void
pvscsi_release_ctx(pvscsi_cmd_t *cmd)
{
	pvscsi_softc_t	*pvs = cmd->cmd_pvs;

	ASSERT(mutex_owned(&pvs->mutex));

	cmd->ctx->cmd = NULL;
	list_insert_tail(&pvs->cmd_ctx_pool, cmd->ctx);
	cmd->ctx = NULL;
}

static uint32_t
pvscsi_reg_read(pvscsi_softc_t *pvs, uint32_t offset)
{
	uint32_t	ret;

	ASSERT((offset & (sizeof (uint32_t) - 1)) == 0);

	ret = ddi_get32(pvs->mmio_handle,
	    (uint32_t *)(pvs->mmio_base + offset));

	return (ret);
}

static void
pvscsi_reg_write(pvscsi_softc_t *pvs, uint32_t offset, uint32_t value)
{
	ASSERT((offset & (sizeof (uint32_t) - 1)) == 0);

	ddi_put32(pvs->mmio_handle, (uint32_t *)(pvs->mmio_base + offset),
	    value);
}

static void
pvscsi_write_cmd_desc(pvscsi_softc_t *pvs, uint32_t cmd, void *desc, size_t len)
{
	len /= sizeof (uint32_t);
	pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_COMMAND, cmd);
	ddi_rep_put32(pvs->mmio_handle, (uint32_t *)desc,
	    (uint32_t *)(pvs->mmio_base + PVSCSI_REG_OFFSET_COMMAND_DATA),
	    len, DDI_DEV_NO_AUTOINCR);
}

static uint32_t
pvscsi_read_intr_status(pvscsi_softc_t *pvs)
{
	return (pvscsi_reg_read(pvs, PVSCSI_REG_OFFSET_INTR_STATUS));
}

static void
pvscsi_write_intr_status(pvscsi_softc_t *pvs, uint32_t val)
{
	pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_INTR_STATUS, val);
}

static void
pvscsi_mask_intr(pvscsi_softc_t *pvs)
{
	mutex_enter(&pvs->intr_mutex);

	VERIFY(pvs->intr_lock_counter >= 0);

	if (++pvs->intr_lock_counter == 1)
		pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_INTR_MASK, 0);

	mutex_exit(&pvs->intr_mutex);
}

static void
pvscsi_unmask_intr(pvscsi_softc_t *pvs)
{
	mutex_enter(&pvs->intr_mutex);

	VERIFY(pvs->intr_lock_counter > 0);

	if (--pvs->intr_lock_counter == 0) {
		pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_INTR_MASK,
		    PVSCSI_INTR_CMPL_MASK | PVSCSI_INTR_MSG_MASK);
	}

	mutex_exit(&pvs->intr_mutex);
}

static void
pvscsi_reset_hba(pvscsi_softc_t *pvs)
{
	pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_ADAPTER_RESET, NULL, 0);
}

static void
pvscsi_reset_bus(pvscsi_softc_t *pvs)
{
	pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_RESET_BUS, NULL, 0);
}

static void
pvscsi_submit_nonrw_io(pvscsi_softc_t *pvs)
{
	pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_KICK_NON_RW_IO, 0);
}

static void
pvscsi_submit_rw_io(pvscsi_softc_t *pvs)
{
	pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_KICK_RW_IO, 0);
}


static int
pvscsi_inquiry_target(pvscsi_softc_t *pvs, int target, struct scsi_inquiry *inq)
{
	int		len = sizeof (struct scsi_inquiry);
	int		ret = -1;
	struct buf	*b;
	struct scsi_address ap;
	struct scsi_pkt	*pkt;
	uint8_t		cdb[CDB_GROUP0];

	ap.a_hba_tran = pvs->tran;
	ap.a_target = (ushort_t)target;
	ap.a_lun = (uchar_t)0;

	if ((b = scsi_alloc_consistent_buf(&ap, (struct buf *)NULL, len,
	    B_READ, NULL_FUNC, NULL)) == NULL)
		return (-1);

	if ((pkt = scsi_init_pkt(&ap, (struct scsi_pkt *)NULL, b,
	    CDB_GROUP0, sizeof (struct scsi_arq_status), 0, 0,
	    NULL_FUNC, NULL)) == NULL)
		goto free_buf;

	cdb[0] = SCMD_INQUIRY;
	cdb[1] = 0;
	cdb[2] = 0;
	cdb[3] = (len & 0xff00) >> 8;
	cdb[4] = (len & 0x00ff);
	cdb[5] = 0;

	if (inq != NULL)
		bzero(inq, sizeof (*inq));
	bcopy(cdb, pkt->pkt_cdbp, CDB_GROUP0);
	bzero((struct scsi_inquiry *)b->b_un.b_addr, sizeof (*inq));

	if ((ret = scsi_poll(pkt)) == 0 && inq != NULL)
		bcopy(b->b_un.b_addr, inq, sizeof (*inq));

	scsi_destroy_pkt(pkt);

free_buf:
	scsi_free_consistent_buf(b);

	return (ret);
}

static int
pvscsi_config_one(dev_info_t *pdip, pvscsi_softc_t *pvs, int target,
    dev_info_t **childp)
{
	char		**compatible = NULL;
	char		*nodename = NULL;
	dev_info_t	*dip;
	int		inqrc;
	int		ncompatible = 0;
	pvscsi_device_t	*devnode;
	struct scsi_inquiry inq;

	ASSERT(DEVI_BUSY_OWNED(pdip));

	/* Inquiry target */
	inqrc = pvscsi_inquiry_target(pvs, target, &inq);

	/* Find devnode */
	for (devnode = list_head(&pvs->devnodes); devnode != NULL;
	    devnode = list_next(&pvs->devnodes, devnode)) {
		if (devnode->target == target)
			break;
	}

	if (devnode != NULL) {
		if (inqrc != 0) {
			/* Target disappeared, drop devnode */
			if (i_ddi_devi_attached(devnode->pdip)) {
				char    *devname;
				/* Get full devname */
				devname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
				(void) ddi_deviname(devnode->pdip, devname);
				/* Clean cache and name */
				(void) devfs_clean(devnode->parent, devname + 1,
				    DV_CLEAN_FORCE);
				kmem_free(devname, MAXPATHLEN);
			}

			(void) ndi_devi_offline(devnode->pdip, NDI_DEVI_REMOVE);

			list_remove(&pvs->devnodes, devnode);
			kmem_free(devnode, sizeof (*devnode));
		} else if (childp != NULL) {
			/* Target exists */
			*childp = devnode->pdip;
		}
		return (NDI_SUCCESS);
	} else if (inqrc != 0) {
		/* Target doesn't exist */
		return (NDI_FAILURE);
	}

	scsi_hba_nodename_compatible_get(&inq, NULL, inq.inq_dtype, NULL,
	    &nodename, &compatible, &ncompatible);
	if (nodename == NULL)
		goto free_nodename;

	if (ndi_devi_alloc(pdip, nodename, DEVI_SID_NODEID,
	    &dip) != NDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to alloc device instance");
		goto free_nodename;
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "device-type", "scsi") != DDI_PROP_SUCCESS ||
	    ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "target", target) != DDI_PROP_SUCCESS ||
	    ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "lun", 0) != DDI_PROP_SUCCESS ||
	    ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "pm-capable", 1) != DDI_PROP_SUCCESS ||
	    ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "compatible", compatible, ncompatible) != DDI_PROP_SUCCESS) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to update props for target %d", target);
		goto free_devi;
	}

	if ((devnode = kmem_zalloc(sizeof (*devnode), KM_NOSLEEP)) == NULL)
		goto free_devi;

	if (ndi_devi_online(dip, NDI_ONLINE_ATTACH) != NDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to online target %d",
		    target);
		kmem_free(devnode, sizeof (*devnode));
		goto free_devi;
	}

	devnode->target = target;
	devnode->pdip = dip;
	devnode->parent = pdip;
	list_insert_tail(&pvs->devnodes, devnode);

	if (childp != NULL)
		*childp = dip;

	scsi_hba_nodename_compatible_free(nodename, compatible);

	return (NDI_SUCCESS);

free_devi:
	ndi_prop_remove_all(dip);
	(void) ndi_devi_free(dip);
free_nodename:
	scsi_hba_nodename_compatible_free(nodename, compatible);

	return (NDI_FAILURE);
}

static int
pvscsi_config_all(dev_info_t *pdip, pvscsi_softc_t *pvs)
{
	int		target;

	for (target = 0; target < PVSCSI_MAXTGTS; target++) {
		/* ndi_devi_enter is done in pvscsi_bus_config */
		(void) pvscsi_config_one(pdip, pvs, target, NULL);
	}

	return (NDI_SUCCESS);
}

static pvscsi_cmd_t *
pvscsi_process_comp_ring(pvscsi_softc_t *pvs)
{
	pvscsi_cmd_t	**pnext_cmd = NULL;
	pvscsi_cmd_t	*cmd;
	pvscsi_cmd_t	*head = NULL;
	struct PVSCSIRingsState *sdesc = RINGS_STATE(pvs);
	uint32_t	cmp_ne = sdesc->cmpNumEntriesLog2;

	ASSERT(mutex_owned(&pvs->rx_mutex));

	while (sdesc->cmpConsIdx != sdesc->cmpProdIdx) {
		pvscsi_cmd_ctx_t *ctx;
		struct PVSCSIRingCmpDesc *cdesc;

		cdesc = CMP_RING(pvs) + (sdesc->cmpConsIdx & MASK(cmp_ne));
		membar_consumer();

		ctx = pvscsi_resolve_ctx(pvs, cdesc->context);
		ASSERT(ctx != NULL);

		if ((cmd = ctx->cmd) != NULL) {
			cmd->next_cmd = NULL;

			/* Save command status for further processing */
			cmd->cmp_stat.host_status = cdesc->hostStatus;
			cmd->cmp_stat.scsi_status = cdesc->scsiStatus;
			cmd->cmp_stat.data_len = cdesc->dataLen;

			/* Mark this command as arrived from hardware */
			cmd->flags |= PVSCSI_FLAG_HW_STATUS;

			if (head == NULL) {
				head = cmd;
				head->tail_cmd = cmd;
			} else {
				head->tail_cmd = cmd;
			}

			if (pnext_cmd == NULL) {
				pnext_cmd = &cmd->next_cmd;
			} else {
				*pnext_cmd = cmd;
				pnext_cmd = &cmd->next_cmd;
			}
		}

		membar_consumer();
		sdesc->cmpConsIdx++;
	}

	return (head);
}

static pvscsi_msg_t *
pvscsi_process_msg_ring(pvscsi_softc_t *pvs)
{
	pvscsi_msg_t	*msg;
	struct PVSCSIRingsState *sdesc = RINGS_STATE(pvs);
	struct PVSCSIRingMsgDesc *mdesc;
	struct PVSCSIMsgDescDevStatusChanged *desc;
	uint32_t	msg_ne = sdesc->msgNumEntriesLog2;

	ASSERT(mutex_owned(&pvs->rx_mutex));

	if (sdesc->msgProdIdx == sdesc->msgConsIdx)
		return (NULL);

	mdesc = MSG_RING(pvs) + (sdesc->msgConsIdx & MASK(msg_ne));
	membar_consumer();

	switch (mdesc->type) {
	case PVSCSI_MSG_DEV_ADDED:
	case PVSCSI_MSG_DEV_REMOVED:
		desc = (struct PVSCSIMsgDescDevStatusChanged *)mdesc;
		msg = kmem_alloc(sizeof (pvscsi_msg_t), KM_NOSLEEP);
		if (msg == NULL)
			return (NULL);
		msg->msg_pvs = pvs;
		msg->type = mdesc->type;
		msg->target = desc->target;
		break;
	default:
		dev_err(pvs->dip, CE_WARN, "!unknown msg type: %d",
		    mdesc->type);
		return (NULL);
	}

	membar_consumer();
	sdesc->msgConsIdx++;

	return (msg);
}

static void
pvscsi_handle_msg(void *arg)
{
	pvscsi_msg_t	*msg = (pvscsi_msg_t *)arg;
	dev_info_t	*dip = msg->msg_pvs->dip;
	int		circ;

	ndi_devi_enter(dip, &circ);
	(void) pvscsi_config_one(dip, msg->msg_pvs, msg->target, NULL);
	ndi_devi_exit(dip, circ);

	kmem_free(msg, sizeof (pvscsi_msg_t));
}

static int
pvscsi_abort_cmd(pvscsi_cmd_t *cmd, pvscsi_cmd_t **pending)
{
	pvscsi_softc_t	*pvs = cmd->cmd_pvs;
	pvscsi_cmd_t	*c;
	pvscsi_cmd_t	*done;
	struct PVSCSICmdDescAbortCmd acmd;

	dev_err(pvs->dip, CE_WARN, "!aborting command %p", (void *)cmd);

	ASSERT(mutex_owned(&pvs->rx_mutex));
	ASSERT(mutex_owned(&pvs->tx_mutex));

	/* Check if the cmd was already completed by the HBA */
	*pending = done = pvscsi_process_comp_ring(pvs);
	for (c = done; c != NULL; c = c->next_cmd) {
		if (c == cmd)
			return (CMD_CMPLT);
	}

	/* Check if cmd was really scheduled by the HBA */
	if (pvscsi_lookup_ctx(pvs, cmd) == NULL)
		return (CMD_CMPLT);

	/* Abort cmd in the HBA */
	bzero(&acmd, sizeof (acmd));
	acmd.target = cmd->cmd_target;
	acmd.context = pvscsi_map_ctx(pvs, cmd->ctx);
	pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_ABORT_CMD, &acmd, sizeof (acmd));

	/* Check if cmd was completed by the HBA before it could be aborted */
	if ((done = pvscsi_process_comp_ring(pvs)) != NULL) {
		done->tail_cmd->next_cmd = *pending;
		*pending = done;
		for (c = done; c != NULL; c = c->next_cmd) {
			if (c == cmd)
				return (CMD_CMPLT);
		}
	}

	/* Release I/O ctx */
	mutex_enter(&pvs->mutex);
	if (cmd->ctx != NULL)
		pvscsi_release_ctx(cmd);
	/* Remove cmd from the queue */
	pvscsi_remove_from_queue(cmd);
	mutex_exit(&pvs->mutex);

	/* Insert cmd at the beginning of the list */
	cmd->next_cmd = *pending;
	*pending = cmd;

	dev_err(pvs->dip, CE_WARN, "!command %p aborted", (void *)cmd);

	return (CMD_ABORTED);
}

static void
pvscsi_map_buffers(pvscsi_cmd_t *cmd, struct PVSCSIRingReqDesc *rdesc)
{
	int	i;

	ASSERT(cmd->ctx);
	ASSERT(cmd->cmd_dmaccount > 0 && cmd->cmd_dmaccount <=
	    PVSCSI_MAX_SG_SIZE);

	rdesc->dataLen = cmd->cmd_dma_count;
	rdesc->dataAddr = 0;

	if (cmd->cmd_dma_count == 0)
		return;

	if (cmd->cmd_dmaccount > 1) {
		struct PVSCSISGElement *sgl = CMD_CTX_SGLIST_VA(cmd->ctx);

		for (i = 0; i < cmd->cmd_dmaccount; i++) {
			sgl[i].addr = cmd->cached_cookies[i].dmac_laddress;
			sgl[i].length = cmd->cached_cookies[i].dmac_size;
			sgl[i].flags = 0;
		}
		rdesc->flags |= PVSCSI_FLAG_CMD_WITH_SG_LIST;
		rdesc->dataAddr = (uint64_t)CMD_CTX_SGLIST_PA(cmd->ctx);
	} else {
		rdesc->dataAddr = cmd->cached_cookies[0].dmac_laddress;
	}
}

static void
pvscsi_comp_cmd(pvscsi_cmd_t *cmd, uint8_t status)
{
	struct scsi_pkt	*pkt = CMD2PKT(cmd);

	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
	    STATE_GOT_STATUS);
	if ((cmd->flags & PVSCSI_FLAG_DMA_VALID) != 0)
		pkt->pkt_state |= STATE_XFERRED_DATA;
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_resid = 0;
	*(pkt->pkt_scbp) = status;
}

static void
pvscsi_set_status(pvscsi_cmd_t *cmd)
{
	pvscsi_softc_t	*pvs = cmd->cmd_pvs;
	struct scsi_pkt	*pkt = CMD2PKT(cmd);
	uchar_t		scsi_status = cmd->cmp_stat.scsi_status;
	uint32_t	host_status = cmd->cmp_stat.host_status;

	if (scsi_status != STATUS_GOOD &&
	    (host_status == BTSTAT_SUCCESS ||
	    (host_status == BTSTAT_LINKED_COMMAND_COMPLETED) ||
	    (host_status == BTSTAT_LINKED_COMMAND_COMPLETED_WITH_FLAG))) {
		if (scsi_status == STATUS_CHECK) {
			struct scsi_arq_status *astat = (void*)(pkt->pkt_scbp);
			uint8_t		*sensedata;
			int		arq_size;

			*pkt->pkt_scbp = scsi_status;
			pkt->pkt_state |= STATE_ARQ_DONE;

			if ((cmd->flags & PVSCSI_FLAG_XARQ) != 0) {
				arq_size = (cmd->cmd_rqslen >=
				    SENSE_BUFFER_SIZE) ? SENSE_BUFFER_SIZE :
				    cmd->cmd_rqslen;

				astat->sts_rqpkt_resid = SENSE_BUFFER_SIZE -
				    arq_size;
				sensedata = (uint8_t *)&astat->sts_sensedata;
				bcopy(cmd->arqbuf->b_un.b_addr, sensedata,
				    arq_size);

				pkt->pkt_state |= STATE_XARQ_DONE;
			} else {
				astat->sts_rqpkt_resid = 0;
			}

			astat->sts_rqpkt_statistics = 0;
			astat->sts_rqpkt_reason = CMD_CMPLT;
			(*(uint8_t *)&astat->sts_rqpkt_status) = STATUS_GOOD;
			astat->sts_rqpkt_state = STATE_GOT_BUS |
			    STATE_GOT_TARGET | STATE_SENT_CMD |
			    STATE_XFERRED_DATA | STATE_GOT_STATUS;
		}
		pvscsi_comp_cmd(cmd, scsi_status);

		return;
	}

	switch (host_status) {
	case BTSTAT_SUCCESS:
	case BTSTAT_LINKED_COMMAND_COMPLETED:
	case BTSTAT_LINKED_COMMAND_COMPLETED_WITH_FLAG:
		pvscsi_comp_cmd(cmd, STATUS_GOOD);
		break;
	case BTSTAT_DATARUN:
		pkt->pkt_reason = CMD_DATA_OVR;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS |
		    STATE_XFERRED_DATA);
		pkt->pkt_resid = 0;
		break;
	case BTSTAT_DATA_UNDERRUN:
		pkt->pkt_reason = pkt->pkt_state |= (STATE_GOT_BUS |
		    STATE_GOT_TARGET | STATE_SENT_CMD | STATE_GOT_STATUS);
		pkt->pkt_resid = cmd->dma_count - cmd->cmp_stat.data_len;
		if (pkt->pkt_resid != cmd->dma_count)
			pkt->pkt_state |= STATE_XFERRED_DATA;
		break;
	case BTSTAT_SELTIMEO:
		pkt->pkt_reason = CMD_DEV_GONE;
		pkt->pkt_state |= STATE_GOT_BUS;
		break;
	case BTSTAT_TAGREJECT:
		pkt->pkt_reason = CMD_TAG_REJECT;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		break;
	case BTSTAT_BADMSG:
		pkt->pkt_reason = CMD_BADMSG;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		break;
	case BTSTAT_SENTRST:
	case BTSTAT_RECVRST:
	case BTSTAT_BUSRESET:
		pkt->pkt_reason = CMD_RESET;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		break;
	case BTSTAT_ABORTQUEUE:
		pkt->pkt_reason = CMD_ABORTED;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		break;
	case BTSTAT_HAHARDWARE:
	case BTSTAT_INVPHASE:
	case BTSTAT_HATIMEOUT:
	case BTSTAT_NORESPONSE:
	case BTSTAT_DISCONNECT:
	case BTSTAT_HASOFTWARE:
	case BTSTAT_BUSFREE:
	case BTSTAT_SENSFAILED:
		pkt->pkt_reason = CMD_TRAN_ERR;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		break;
	default:
		dev_err(pvs->dip, CE_WARN,
		    "!unknown host status code: %d", host_status);
		pkt->pkt_reason = CMD_TRAN_ERR;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		break;
	}
}

static void
pvscsi_complete_chained(void *arg)
{
	pvscsi_cmd_t	*cmd = (pvscsi_cmd_t *)arg;
	pvscsi_cmd_t	*c;
	struct scsi_pkt	*pkt;

	while (cmd != NULL) {
		pvscsi_softc_t	*pvs = cmd->cmd_pvs;

		c = cmd->next_cmd;
		cmd->next_cmd = NULL;

		pkt = CMD2PKT(cmd);
		if (pkt == NULL)
			return;

		if ((cmd->flags & PVSCSI_FLAG_IO_IOPB) != 0 &&
		    (cmd->flags & PVSCSI_FLAG_IO_READ) != 0) {
			(void) ddi_dma_sync(cmd->cmd_dmahdl, 0, 0,
			    DDI_DMA_SYNC_FORCPU);
		}

		mutex_enter(&pvs->mutex);
		/* Release I/O ctx */
		if (cmd->ctx != NULL)
			pvscsi_release_ctx(cmd);
		/* Remove command from queue */
		pvscsi_remove_from_queue(cmd);
		mutex_exit(&pvs->mutex);

		if ((cmd->flags & PVSCSI_FLAG_HW_STATUS) != 0) {
			pvscsi_set_status(cmd);
		} else {
			ASSERT((cmd->flags & PVSCSI_FLAGS_NON_HW_COMPLETION) !=
			    0);

			if ((cmd->flags & PVSCSI_FLAG_TIMED_OUT) != 0) {
				cmd->pkt->pkt_reason = CMD_TIMEOUT;
				cmd->pkt->pkt_statistics |=
				    (STAT_TIMEOUT | STAT_ABORTED);
			} else if ((cmd->flags & PVSCSI_FLAG_ABORTED) != 0) {
				cmd->pkt->pkt_reason = CMD_ABORTED;
				cmd->pkt->pkt_statistics |=
				    (STAT_TIMEOUT | STAT_ABORTED);
			} else if ((cmd->flags & PVSCSI_FLAGS_RESET) != 0) {
				cmd->pkt->pkt_reason = CMD_RESET;
				if ((cmd->flags & PVSCSI_FLAG_RESET_BUS) != 0) {
					cmd->pkt->pkt_statistics |=
					    STAT_BUS_RESET;
				} else {
					cmd->pkt->pkt_statistics |=
					    STAT_DEV_RESET;
				}
			}
		}

		cmd->flags |= PVSCSI_FLAG_DONE;
		cmd->flags &= ~PVSCSI_FLAG_TRANSPORT;

		if ((pkt->pkt_flags & FLAG_NOINTR) == 0 &&
		    pkt->pkt_comp != NULL)
			(*pkt->pkt_comp)(pkt);

		cmd = c;
	}
}

static void
pvscsi_dev_reset(pvscsi_softc_t *pvs, int target)
{
	struct PVSCSICmdDescResetDevice cmd = { 0 };

	cmd.target = target;
	pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_RESET_DEVICE, &cmd, sizeof (cmd));
}

static int
pvscsi_poll_cmd(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd)
{
	boolean_t	seen_intr;
	int		cycles = (cmd->pkt->pkt_time * 1000000) / USECS_TO_WAIT;
	int		i;
	pvscsi_cmd_t	*dcmd;
	struct scsi_pkt *pkt = CMD2PKT(cmd);

	/*
	 * Make sure we're not missing any commands completed
	 * concurrently before we have actually disabled interrupts.
	 */
	mutex_enter(&pvs->rx_mutex);
	dcmd = pvscsi_process_comp_ring(pvs);
	mutex_exit(&pvs->rx_mutex);

	pvscsi_complete_chained(dcmd);

	while ((cmd->flags & PVSCSI_FLAG_DONE) == 0) {
		seen_intr = B_FALSE;

		/* Disable interrupts from H/W */
		pvscsi_mask_intr(pvs);

		/* Wait for interrupt to arrive */
		for (i = 0; i < cycles; i++) {
			uint32_t status;

			mutex_enter(&pvs->rx_mutex);
			mutex_enter(&pvs->intr_mutex);
			status = pvscsi_read_intr_status(pvs);
			if ((status & PVSCSI_INTR_ALL_SUPPORTED) != 0) {
				/* Check completion ring */
				mutex_exit(&pvs->intr_mutex);
				dcmd = pvscsi_process_comp_ring(pvs);
				mutex_exit(&pvs->rx_mutex);
				seen_intr = B_TRUE;
				break;
			} else {
				mutex_exit(&pvs->intr_mutex);
				mutex_exit(&pvs->rx_mutex);
				drv_usecwait(USECS_TO_WAIT);
			}
		}

		/* Enable interrupts from H/W */
		pvscsi_unmask_intr(pvs);

		if (!seen_intr) {
			/* No interrupts seen from device during the timeout */
			mutex_enter(&pvs->tx_mutex);
			mutex_enter(&pvs->rx_mutex);
			if ((cmd->flags & PVSCSI_FLAGS_COMPLETION) != 0) {
				/* Command was cancelled asynchronously */
				dcmd = NULL;
			} else if ((pvscsi_abort_cmd(cmd,
			    &dcmd)) == CMD_ABORTED) {
				/* Command was cancelled in hardware */
				pkt->pkt_state |= (STAT_TIMEOUT | STAT_ABORTED);
				pkt->pkt_statistics |= (STAT_TIMEOUT |
				    STAT_ABORTED);
				pkt->pkt_reason = CMD_TIMEOUT;
			}
			mutex_exit(&pvs->rx_mutex);
			mutex_exit(&pvs->tx_mutex);

			/*
			 * Complete commands that might be on completion list.
			 * Target command can also be on the list in case it was
			 * completed before it could be actually cancelled.
			 */
			break;
		}

		pvscsi_complete_chained(dcmd);

		if (!seen_intr)
			break;
	}

	return (TRAN_ACCEPT);
}

static void
pvscsi_abort_all(struct scsi_address *ap, pvscsi_softc_t *pvs,
    pvscsi_cmd_t **pending, int marker_flag)
{
	int		qlen = pvs->cmd_queue_len;
	pvscsi_cmd_t	*cmd, *pcmd, *phead = NULL;

	ASSERT(mutex_owned(&pvs->rx_mutex));
	ASSERT(mutex_owned(&pvs->tx_mutex));

	/*
	 * Try to abort all queued commands, merging commands waiting
	 * for completion into a single list to complete them at one
	 * time when mutex is released.
	 */
	while (qlen > 0) {
		mutex_enter(&pvs->mutex);
		cmd = list_remove_head(&pvs->cmd_queue);
		ASSERT(cmd != NULL);

		qlen--;

		if (ap == NULL || ap->a_target == cmd->cmd_target) {
			int c = --pvs->cmd_queue_len;

			mutex_exit(&pvs->mutex);

			if (pvscsi_abort_cmd(cmd, &pcmd) == CMD_ABORTED) {
				/*
				 * Assume command is completely cancelled now,
				 * so mark it as requested.
				 */
				cmd->flags |= marker_flag;
			}

			qlen -= (c - pvs->cmd_queue_len);

			/*
			 * Now merge current pending commands with
			 * previous ones.
			 */
			if (phead == NULL) {
				phead = pcmd;
			} else if (pcmd != NULL) {
				phead->tail_cmd->next_cmd = pcmd;
				phead->tail_cmd = pcmd->tail_cmd;
			}
		} else {
			list_insert_tail(&pvs->cmd_queue, cmd);
			mutex_exit(&pvs->mutex);
		}
	}

	*pending = phead;
}

static void
pvscsi_quiesce_notify(pvscsi_softc_t *pvs)
{
	mutex_enter(&pvs->mutex);
	if (pvs->cmd_queue_len == 0 &&
	    (pvs->flags & PVSCSI_HBA_QUIESCE_PENDING) != 0) {
		pvs->flags &= ~PVSCSI_HBA_QUIESCE_PENDING;
		cv_broadcast(&pvs->quiescevar);
	}
	mutex_exit(&pvs->mutex);
}

static int
pvscsi_transport_command(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd)
{
	struct PVSCSIRingReqDesc *rdesc;
	struct PVSCSIRingsState *sdesc = RINGS_STATE(pvs);
	struct scsi_pkt *pkt = CMD2PKT(cmd);
	uint32_t	req_ne = sdesc->reqNumEntriesLog2;

	mutex_enter(&pvs->tx_mutex);
	mutex_enter(&pvs->mutex);
	if (!pvscsi_acquire_ctx(pvs, cmd)) {
		mutex_exit(&pvs->mutex);
		mutex_exit(&pvs->tx_mutex);
		dev_err(pvs->dip, CE_WARN, "!no free ctx available");
		return (TRAN_BUSY);
	}

	if ((sdesc->reqProdIdx - sdesc->cmpConsIdx) >= (1 << req_ne)) {
		pvscsi_release_ctx(cmd);
		mutex_exit(&pvs->mutex);
		mutex_exit(&pvs->tx_mutex);
		dev_err(pvs->dip, CE_WARN, "!no free I/O slots available");
		return (TRAN_BUSY);
	}
	mutex_exit(&pvs->mutex);

	cmd->flags |= PVSCSI_FLAG_TRANSPORT;

	rdesc = REQ_RING(pvs) + (sdesc->reqProdIdx & MASK(req_ne));

	bzero(&rdesc->lun, sizeof (rdesc->lun));

	rdesc->bus = 0;
	rdesc->target = cmd->cmd_target;

	if ((cmd->flags & PVSCSI_FLAG_XARQ) != 0) {
		bzero((void*)cmd->arqbuf->b_un.b_addr, SENSE_BUFFER_SIZE);
		rdesc->senseLen = SENSE_BUFFER_SIZE;
		rdesc->senseAddr = cmd->arqc.dmac_laddress;
	} else {
		rdesc->senseLen = 0;
		rdesc->senseAddr = 0;
	}

	rdesc->vcpuHint = CPU->cpu_id;
	rdesc->cdbLen = cmd->cmdlen;
	bcopy(cmd->cmd_cdb, rdesc->cdb, cmd->cmdlen);

	/* Setup tag info */
	if ((cmd->flags & PVSCSI_FLAG_TAG) != 0)
		rdesc->tag = cmd->tag;
	else
		rdesc->tag = MSG_SIMPLE_QTAG;

	/* Setup I/O direction and map data buffers */
	if ((cmd->flags & PVSCSI_FLAG_DMA_VALID) != 0) {
		if ((cmd->flags & PVSCSI_FLAG_IO_READ) != 0)
			rdesc->flags = PVSCSI_FLAG_CMD_DIR_TOHOST;
		else
			rdesc->flags = PVSCSI_FLAG_CMD_DIR_TODEVICE;
		pvscsi_map_buffers(cmd, rdesc);
	} else {
		rdesc->flags = 0;
	}

	rdesc->context = pvscsi_map_ctx(pvs, cmd->ctx);
	membar_producer();

	sdesc->reqProdIdx++;
	membar_producer();

	mutex_enter(&pvs->mutex);
	cmd->timeout_lbolt = ddi_get_lbolt() + SEC_TO_TICK(pkt->pkt_time);
	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD);
	pvscsi_add_to_queue(cmd);

	switch (cmd->pkt->pkt_cdbp[0]) {
	case SCMD_READ:
	case SCMD_WRITE:
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
	case SCMD_READ_G4:
	case SCMD_WRITE_G4:
	case SCMD_READ_G5:
	case SCMD_WRITE_G5:
		ASSERT((cmd->flags & PVSCSI_FLAG_DMA_VALID) != 0);
		pvscsi_submit_rw_io(pvs);
		break;
	default:
		pvscsi_submit_nonrw_io(pvs);
		break;
	}
	mutex_exit(&pvs->mutex);
	mutex_exit(&pvs->tx_mutex);

	return (TRAN_ACCEPT);
}

static int
pvscsi_reset_generic(pvscsi_softc_t *pvs, struct scsi_address *ap)
{
	boolean_t	bus_reset = (ap == NULL);
	int		flags;
	pvscsi_cmd_t	*done, *aborted;

	flags = bus_reset ? PVSCSI_FLAG_RESET_BUS : PVSCSI_FLAG_RESET_DEV;

	mutex_enter(&pvs->tx_mutex);
	mutex_enter(&pvs->rx_mutex);
	/* Try to process pending requests */
	done = pvscsi_process_comp_ring(pvs);

	/* Abort all pending requests */
	pvscsi_abort_all(ap, pvs, &aborted, flags);

	/* Reset at hardware level */
	if (bus_reset) {
		pvscsi_reset_bus(pvs);
		/* Should never happen after bus reset */
		ASSERT(pvscsi_process_comp_ring(pvs) == NULL);
	} else {
		pvscsi_dev_reset(pvs, ap->a_target);
	}
	mutex_exit(&pvs->rx_mutex);
	mutex_exit(&pvs->tx_mutex);

	pvscsi_complete_chained(done);
	pvscsi_complete_chained(aborted);

	return (1);
}

static void
pvscsi_cmd_ext_free(pvscsi_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = CMD2PKT(cmd);

	if ((cmd->flags & PVSCSI_FLAG_CDB_EXT) != 0) {
		kmem_free(pkt->pkt_cdbp, cmd->cmdlen);
		cmd->flags &= ~PVSCSI_FLAG_CDB_EXT;
	}
	if ((cmd->flags & PVSCSI_FLAG_SCB_EXT) != 0) {
		kmem_free(pkt->pkt_scbp, cmd->statuslen);
		cmd->flags &= ~PVSCSI_FLAG_SCB_EXT;
	}
	if ((cmd->flags & PVSCSI_FLAG_PRIV_EXT) != 0) {
		kmem_free(pkt->pkt_private, cmd->tgtlen);
		cmd->flags &= ~PVSCSI_FLAG_PRIV_EXT;
	}
}

/* ARGSUSED pvs */
static int
pvscsi_cmd_ext_alloc(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd, int kf)
{
	struct scsi_pkt *pkt = CMD2PKT(cmd);
	void		*buf;

	if (cmd->cmdlen > sizeof (cmd->cmd_cdb)) {
		if ((buf = kmem_zalloc(cmd->cmdlen, kf)) == NULL)
			return (DDI_FAILURE);
		pkt->pkt_cdbp = buf;
		cmd->flags |= PVSCSI_FLAG_CDB_EXT;
	}

	if (cmd->statuslen > sizeof (cmd->cmd_scb)) {
		if ((buf = kmem_zalloc(cmd->statuslen, kf)) == NULL)
			goto out;
		pkt->pkt_scbp = buf;
		cmd->flags |= PVSCSI_FLAG_SCB_EXT;
		cmd->cmd_rqslen = (cmd->statuslen - sizeof (cmd->cmd_scb));
	}

	if (cmd->tgtlen > sizeof (cmd->tgt_priv)) {
		if ((buf = kmem_zalloc(cmd->tgtlen, kf)) == NULL)
			goto out;
		pkt->pkt_private = buf;
		cmd->flags |= PVSCSI_FLAG_PRIV_EXT;
	}

	return (DDI_SUCCESS);

out:
	pvscsi_cmd_ext_free(cmd);

	return (DDI_FAILURE);
}

static int
pvscsi_setup_dma_buffer(pvscsi_softc_t *pvs, size_t length,
    pvscsi_dma_buf_t *buf)
{
	ddi_dma_cookie_t cookie;
	uint_t		ccount;

	if ((ddi_dma_alloc_handle(pvs->dip, &pvscsi_ring_dma_attr,
	    DDI_DMA_SLEEP, NULL, &buf->dma_handle)) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to allocate DMA handle");
		return (DDI_FAILURE);
	}

	if ((ddi_dma_mem_alloc(buf->dma_handle, length, &pvscsi_dma_attrs,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &buf->addr,
	    &buf->real_length, &buf->acc_handle)) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to allocate %ld bytes for DMA buffer", length);
		ddi_dma_free_handle(&buf->dma_handle);
		return (DDI_FAILURE);
	}

	if ((ddi_dma_addr_bind_handle(buf->dma_handle, NULL, buf->addr,
	    buf->real_length, DDI_DMA_CONSISTENT | DDI_DMA_RDWR, DDI_DMA_SLEEP,
	    NULL, &cookie, &ccount)) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to bind DMA buffer");
		ddi_dma_free_handle(&buf->dma_handle);
		ddi_dma_mem_free(&buf->acc_handle);
		return (DDI_FAILURE);
	}

	/* TODO Support multipart SG regions */
	ASSERT(ccount == 1);

	buf->pa = cookie.dmac_laddress;

	return (DDI_SUCCESS);
}

static void
pvscsi_free_dma_buffer(pvscsi_dma_buf_t *buf)
{
	ddi_dma_free_handle(&buf->dma_handle);
	ddi_dma_mem_free(&buf->acc_handle);
}

static int
pvscsi_setup_sg(pvscsi_softc_t *pvs)
{
	int		i;
	pvscsi_cmd_ctx_t *ctx;
	size_t		size = pvs->req_depth * sizeof (pvscsi_cmd_ctx_t);

	ctx = pvs->cmd_ctx = kmem_zalloc(size, KM_SLEEP);

	for (i = 0; i < pvs->req_depth; ++i, ++ctx) {
		list_insert_tail(&pvs->cmd_ctx_pool, ctx);
		if (pvscsi_setup_dma_buffer(pvs, PAGE_SIZE,
		    &ctx->dma_buf) != DDI_SUCCESS)
			goto cleanup;
	}

	return (DDI_SUCCESS);

cleanup:
	for (; i >= 0; --i, --ctx) {
		list_remove(&pvs->cmd_ctx_pool, ctx);
		pvscsi_free_dma_buffer(&ctx->dma_buf);
	}
	kmem_free(pvs->cmd_ctx, size);

	return (DDI_FAILURE);
}

static void
pvscsi_free_sg(pvscsi_softc_t *pvs)
{
	int		i;
	pvscsi_cmd_ctx_t *ctx = pvs->cmd_ctx;

	for (i = 0; i < pvs->req_depth; ++i, ++ctx) {
		list_remove(&pvs->cmd_ctx_pool, ctx);
		pvscsi_free_dma_buffer(&ctx->dma_buf);
	}

	kmem_free(pvs->cmd_ctx, pvs->req_pages << PAGE_SHIFT);
}

static int
pvscsi_allocate_rings(pvscsi_softc_t *pvs)
{
	/* Allocate DMA buffer for rings state */
	if (pvscsi_setup_dma_buffer(pvs, PAGE_SIZE,
	    &pvs->rings_state_buf) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* Allocate DMA buffer for request ring */
	pvs->req_pages = MIN(pvscsi_ring_pages, PVSCSI_MAX_NUM_PAGES_REQ_RING);
	pvs->req_depth = pvs->req_pages * PVSCSI_MAX_NUM_REQ_ENTRIES_PER_PAGE;
	if (pvscsi_setup_dma_buffer(pvs, pvs->req_pages * PAGE_SIZE,
	    &pvs->req_ring_buf) != DDI_SUCCESS)
		goto free_rings_state;

	/* Allocate completion ring */
	pvs->cmp_pages = MIN(pvscsi_ring_pages, PVSCSI_MAX_NUM_PAGES_CMP_RING);
	if (pvscsi_setup_dma_buffer(pvs, pvs->cmp_pages * PAGE_SIZE,
	    &pvs->cmp_ring_buf) != DDI_SUCCESS)
		goto free_req_buf;

	/* Allocate message ring */
	pvs->msg_pages = MIN(pvscsi_msg_ring_pages,
	    PVSCSI_MAX_NUM_PAGES_MSG_RING);
	if (pvscsi_setup_dma_buffer(pvs, pvs->msg_pages * PAGE_SIZE,
	    &pvs->msg_ring_buf) != DDI_SUCCESS)
		goto free_cmp_buf;

	return (DDI_SUCCESS);

free_cmp_buf:
	pvscsi_free_dma_buffer(&pvs->cmp_ring_buf);
free_req_buf:
	pvscsi_free_dma_buffer(&pvs->req_ring_buf);
free_rings_state:
	pvscsi_free_dma_buffer(&pvs->rings_state_buf);

	return (DDI_FAILURE);
}

static void
pvscsi_free_rings(pvscsi_softc_t *pvs)
{
	pvscsi_free_dma_buffer(&pvs->msg_ring_buf);
	pvscsi_free_dma_buffer(&pvs->cmp_ring_buf);
	pvscsi_free_dma_buffer(&pvs->req_ring_buf);
	pvscsi_free_dma_buffer(&pvs->rings_state_buf);
}

static void
pvscsi_setup_rings(pvscsi_softc_t *pvs)
{
	int		i;
	struct PVSCSICmdDescSetupMsgRing cmd_msg = { 0 };
	struct PVSCSICmdDescSetupRings cmd = { 0 };
	uint64_t	base;

	cmd.ringsStatePPN = pvs->rings_state_buf.pa >> PAGE_SHIFT;
	cmd.reqRingNumPages = pvs->req_pages;
	cmd.cmpRingNumPages = pvs->cmp_pages;

	/* Setup request ring */
	base = pvs->req_ring_buf.pa;
	for (i = 0; i < pvs->req_pages; i++) {
		cmd.reqRingPPNs[i] = base >> PAGE_SHIFT;
		base += PAGE_SIZE;
	}

	/* Setup completion ring */
	base = pvs->cmp_ring_buf.pa;
	for (i = 0; i < pvs->cmp_pages; i++) {
		cmd.cmpRingPPNs[i] = base >> PAGE_SHIFT;
		base += PAGE_SIZE;
	}

	bzero(RINGS_STATE(pvs), PAGE_SIZE);
	bzero(REQ_RING(pvs), pvs->req_pages * PAGE_SIZE);
	bzero(CMP_RING(pvs), pvs->cmp_pages * PAGE_SIZE);

	/* Issue SETUP command */
	pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_SETUP_RINGS, &cmd, sizeof (cmd));

	/* Setup message ring */
	cmd_msg.numPages = pvs->msg_pages;
	base = pvs->msg_ring_buf.pa;

	for (i = 0; i < pvs->msg_pages; i++) {
		cmd_msg.ringPPNs[i] = base >> PAGE_SHIFT;
		base += PAGE_SIZE;
	}
	bzero(MSG_RING(pvs), pvs->msg_pages * PAGE_SIZE);

	pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_SETUP_MSG_RING, &cmd_msg,
	    sizeof (cmd_msg));
}

static int
pvscsi_setup_io(pvscsi_softc_t *pvs)
{
	int		offset, rcount, rn, type;
	int		ret = DDI_FAILURE;
	off_t		regsize;
	pci_regspec_t	*regs;
	uint_t		regs_length;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, pvs->dip,
	    DDI_PROP_DONTPASS, "reg", (int **)&regs,
	    &regs_length) != DDI_PROP_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to lookup 'reg' property");
		return (DDI_FAILURE);
	}

	rcount = regs_length * sizeof (int) / sizeof (pci_regspec_t);

	for (offset = PCI_CONF_BASE0; offset <= PCI_CONF_BASE5; offset += 4) {
		for (rn = 0; rn < rcount; ++rn) {
			if (PCI_REG_REG_G(regs[rn].pci_phys_hi) == offset) {
				type = regs[rn].pci_phys_hi & PCI_ADDR_MASK;
				break;
			}
		}

		if (rn >= rcount)
			continue;

		if (type != PCI_ADDR_IO) {
			if (ddi_dev_regsize(pvs->dip, rn,
			    &regsize) != DDI_SUCCESS) {
				dev_err(pvs->dip, CE_WARN,
				    "!failed to get size of reg %d", rn);
				goto out;
			}
			if (regsize == PVSCSI_MEM_SPACE_SIZE) {
				if (ddi_regs_map_setup(pvs->dip, rn,
				    &pvs->mmio_base, 0, 0,
				    &pvscsi_mmio_attr,
				    &pvs->mmio_handle) != DDI_SUCCESS) {
					dev_err(pvs->dip, CE_WARN,
					    "!failed to map MMIO BAR");
					goto out;
				}
				ret = DDI_SUCCESS;
				break;
			}
		}
	}

out:
	ddi_prop_free(regs);

	return (ret);
}

static void
pvscsi_free_io(pvscsi_softc_t *pvs)
{
	ddi_regs_map_free(&pvs->mmio_handle);
}

static int
pvscsi_enable_intrs(pvscsi_softc_t *pvs)
{
	int	i, rc, intr_caps;

	if ((rc = ddi_intr_get_cap(pvs->intr_htable[0], &intr_caps)) !=
	    DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to get interrupt caps");
		return (DDI_FAILURE);
	}

	if ((intr_caps & DDI_INTR_FLAG_BLOCK) != 0) {
		if ((rc = ddi_intr_block_enable(pvs->intr_htable,
		    pvs->intr_cnt)) != DDI_SUCCESS) {
			dev_err(pvs->dip, CE_WARN,
			    "!failed to enable interrupt block");
		}
	} else {
		for (i = 0; i < pvs->intr_cnt; i++) {
			if ((rc = ddi_intr_enable(pvs->intr_htable[i])) ==
			    DDI_SUCCESS)
				continue;
			dev_err(pvs->dip, CE_WARN,
			    "!failed to enable interrupt");
			while (--i >= 0)
				(void) ddi_intr_disable(pvs->intr_htable[i]);
			break;
		}
	}

	/* Unmask interrupts */
	if (rc == DDI_SUCCESS) {
		pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_INTR_MASK,
		    PVSCSI_INTR_CMPL_MASK | PVSCSI_INTR_MSG_MASK);
	}

	return (rc);
}

/* ARGSUSED arg2 */
static uint32_t
pvscsi_intr_handler(caddr_t arg1, caddr_t arg2)
{
	boolean_t	handled;
	pvscsi_softc_t	*pvs = (pvscsi_softc_t *)arg1;
	uint32_t	status;

	mutex_enter(&pvs->intr_mutex);
	if (pvs->num_pollers > 0) {
		mutex_exit(&pvs->intr_mutex);
		return (DDI_INTR_CLAIMED);
	}

	if (pvscsi_enable_msi) {
		handled = B_TRUE;
	} else {
		status = pvscsi_read_intr_status(pvs);
		handled = (status & PVSCSI_INTR_ALL_SUPPORTED) != 0;
		if (handled)
			pvscsi_write_intr_status(pvs, status);
	}
	mutex_exit(&pvs->intr_mutex);

	if (handled) {
		boolean_t	qnotify;
		pvscsi_cmd_t	*pending;
		pvscsi_msg_t	*msg;

		mutex_enter(&pvs->rx_mutex);
		pending = pvscsi_process_comp_ring(pvs);
		msg = pvscsi_process_msg_ring(pvs);
		mutex_exit(&pvs->rx_mutex);

		mutex_enter(&pvs->mutex);
		qnotify = HBA_QUIESCE_PENDING(pvs);
		mutex_exit(&pvs->mutex);

		if (pending != NULL && ddi_taskq_dispatch(pvs->comp_tq,
		    pvscsi_complete_chained, pending,
		    DDI_NOSLEEP) == DDI_FAILURE)
			pvscsi_complete_chained(pending);

		if (msg != NULL && ddi_taskq_dispatch(pvs->msg_tq,
		    pvscsi_handle_msg, msg, DDI_NOSLEEP) == DDI_FAILURE) {
			dev_err(pvs->dip, CE_WARN,
			    "!failed to process msg type %d for target %d",
			    msg->type, msg->target);
			kmem_free(msg, sizeof (pvscsi_msg_t));
		}

		if (qnotify)
			pvscsi_quiesce_notify(pvs);
	}

	return (handled ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

static int
pvscsi_register_isr(pvscsi_softc_t *pvs, int type)
{
	int	navail, nactual;
	int	i;

	if (ddi_intr_get_navail(pvs->dip, type, &navail) != DDI_SUCCESS ||
	    navail == 0) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to get number of available interrupts of type %d",
		    type);
		return (DDI_FAILURE);
	}
	navail = MIN(navail, PVSCSI_MAX_INTRS);

	pvs->intr_size = navail * sizeof (ddi_intr_handle_t);
	if ((pvs->intr_htable = kmem_alloc(pvs->intr_size, KM_SLEEP)) == NULL) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to allocate %d bytes for interrupt hashtable",
		    pvs->intr_size);
		return (DDI_FAILURE);
	}

	if (ddi_intr_alloc(pvs->dip, pvs->intr_htable, type, 0, navail,
	    &nactual, DDI_INTR_ALLOC_NORMAL) != DDI_SUCCESS || nactual == 0) {
		dev_err(pvs->dip, CE_WARN, "!failed to allocate %d interrupts",
		    navail);
		goto free_htable;
	}

	pvs->intr_cnt = nactual;

	if (ddi_intr_get_pri(pvs->intr_htable[0],
	    (uint_t *)&pvs->intr_pri) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to get interrupt priority");
		goto free_intrs;
	}

	for (i = 0; i < nactual; i++) {
		if (ddi_intr_add_handler(pvs->intr_htable[i],
		    pvscsi_intr_handler, (caddr_t)pvs, NULL) != DDI_SUCCESS) {
			dev_err(pvs->dip, CE_WARN,
			    "!failed to add interrupt handler");
			goto free_intrs;
		}
	}

	return (DDI_SUCCESS);

free_intrs:
	for (i = 0; i < nactual; i++)
		(void) ddi_intr_free(pvs->intr_htable[i]);
free_htable:
	kmem_free(pvs->intr_htable, pvs->intr_size);

	return (DDI_FAILURE);
}

static void
pvscsi_free_intr_resources(pvscsi_softc_t *pvs)
{
	int	i;

	for (i = 0; i < pvs->intr_cnt; i++) {
		(void) ddi_intr_disable(pvs->intr_htable[i]);
		(void) ddi_intr_remove_handler(pvs->intr_htable[i]);
		(void) ddi_intr_free(pvs->intr_htable[i]);
	}
	kmem_free(pvs->intr_htable, pvs->intr_size);
}

static int
pvscsi_setup_isr(pvscsi_softc_t *pvs)
{
	int	intr_types;

	if (ddi_intr_get_supported_types(pvs->dip,
	    &intr_types) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to get supported interrupt types");
		return (DDI_FAILURE);
	}

	if ((intr_types & DDI_INTR_TYPE_MSIX) != 0 && pvscsi_enable_msi) {
		if (pvscsi_register_isr(pvs,
		    DDI_INTR_TYPE_MSIX) == DDI_SUCCESS) {
			pvs->intr_type = DDI_INTR_TYPE_MSIX;
		} else {
			dev_err(pvs->dip, CE_WARN,
			    "!failed to install MSI-X interrupt handler");
		}
	} else if ((intr_types & DDI_INTR_TYPE_MSI) != 0 && pvscsi_enable_msi) {
		if (pvscsi_register_isr(pvs,
		    DDI_INTR_TYPE_MSI) == DDI_SUCCESS) {
			pvs->intr_type = DDI_INTR_TYPE_MSI;
		} else {
			dev_err(pvs->dip, CE_WARN,
			    "!failed to install MSI interrupt handler");
		}
	} else if ((intr_types & DDI_INTR_TYPE_FIXED) != 0) {
		if (pvscsi_register_isr(pvs,
		    DDI_INTR_TYPE_FIXED) == DDI_SUCCESS) {
			pvs->intr_type = DDI_INTR_TYPE_FIXED;
		} else {
			dev_err(pvs->dip, CE_WARN,
			    "!failed to install FIXED interrupt handler");
		}
	}

	return (pvs->intr_type == 0 ? DDI_FAILURE : DDI_SUCCESS);
}

static void
pvscsi_wd_thread(pvscsi_softc_t *pvs)
{
	clock_t		now;
	pvscsi_cmd_t	*expired, *c, *cn, **pnext;

	mutex_enter(&pvs->mutex);
	for (;;) {
		expired = NULL;
		pnext = NULL;
		now = ddi_get_lbolt();

		for (c = list_head(&pvs->cmd_queue); c != NULL; ) {
			cn = list_next(&pvs->cmd_queue, c);

			/*
			 * Commands with 'FLAG_NOINTR' are watched using their
			 * own timeouts, so we should not touch them.
			 */
			if ((c->pkt->pkt_flags & FLAG_NOINTR) == 0 &&
			    now > c->timeout_lbolt) {
				dev_err(pvs->dip, CE_WARN,
				    "!expired command: %p (%ld > %ld)",
				    (void *)c, now, c->timeout_lbolt);
				pvscsi_remove_from_queue(c);
				if (expired == NULL)
					expired = c;
				if (pnext == NULL) {
					pnext = &c->next_cmd;
				} else {
					*pnext = c;
					pnext = &c->next_cmd;
				}
			}
			c = cn;
		}
		mutex_exit(&pvs->mutex);

		/* Now cancel all expired commands */
		if (expired != NULL) {
			struct scsi_address sa = {0};
			/* Build a fake SCSI address */
			sa.a_hba_tran = pvs->tran;
			while (expired != NULL) {
				c = expired->next_cmd;
				sa.a_target = expired->cmd_target;
				sa.a_lun = 0;
				(void) pvscsi_abort(&sa, CMD2PKT(expired));
				expired = c;
			}
		}

		mutex_enter(&pvs->mutex);
		if ((pvs->flags & PVSCSI_DRIVER_SHUTDOWN) != 0) {
			/* Finish job */
			break;
		}
		if (cv_reltimedwait(&pvs->wd_condvar, &pvs->mutex,
		    SEC_TO_TICK(1), TR_CLOCK_TICK) > 0) {
			/* Explicitly woken up, finish job */
			break;
		}
	}

	/* Confirm thread termination */
	cv_signal(&pvs->syncvar);
	mutex_exit(&pvs->mutex);
}

static int
pvscsi_ccache_constructor(void *buf, void *cdrarg, int kmflags)
{
	int		(*callback)(caddr_t);
	uint_t		cookiec;
	pvscsi_cmd_t	*cmd = (pvscsi_cmd_t *)buf;
	pvscsi_softc_t	*pvs = cdrarg;
	struct scsi_address ap;

	callback = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;
	ap.a_hba_tran = pvs->tran;
	ap.a_target = 0;
	ap.a_lun = 0;

	/* Allocate a DMA handle for data transfers */
	if ((ddi_dma_alloc_handle(pvs->dip, &pvs->io_dma_attr, callback,
	    NULL, &cmd->cmd_dmahdl)) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to allocate DMA handle");
		return (-1);
	}

	/* Setup ARQ buffer */
	if ((cmd->arqbuf = scsi_alloc_consistent_buf(&ap, (struct buf *)NULL,
	    SENSE_BUFFER_SIZE, B_READ, callback, NULL)) == NULL) {
		dev_err(pvs->dip, CE_WARN, "!failed to allocate ARQ buffer");
		goto free_handle;
	}

	if (ddi_dma_alloc_handle(pvs->dip, &pvs->hba_dma_attr,
	    callback, NULL, &cmd->arqhdl) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to allocate DMA handle for ARQ buffer");
		goto free_arqbuf;
	}

	if (ddi_dma_buf_bind_handle(cmd->arqhdl, cmd->arqbuf,
	    (DDI_DMA_READ | DDI_DMA_CONSISTENT), callback, NULL,
	    &cmd->arqc, &cookiec) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to bind ARQ buffer");
		goto free_arqhdl;
	}

	return (0);

free_arqhdl:
	ddi_dma_free_handle(&cmd->arqhdl);
free_arqbuf:
	scsi_free_consistent_buf(cmd->arqbuf);
free_handle:
	ddi_dma_free_handle(&cmd->cmd_dmahdl);

	return (-1);
}

/* ARGSUSED cdrarg */
static void
pvscsi_ccache_destructor(void *buf, void *cdrarg)
{
	pvscsi_cmd_t	*cmd = (pvscsi_cmd_t *)buf;

	if (cmd->cmd_dmahdl != NULL) {
		(void) ddi_dma_unbind_handle(cmd->cmd_dmahdl);
		ddi_dma_free_handle(&cmd->cmd_dmahdl);
		cmd->cmd_dmahdl = NULL;
	}

	if (cmd->arqhdl != NULL) {
		(void) ddi_dma_unbind_handle(cmd->arqhdl);
		ddi_dma_free_handle(&cmd->arqhdl);
		cmd->arqhdl = NULL;
	}

	if (cmd->arqbuf != NULL) {
		scsi_free_consistent_buf(cmd->arqbuf);
		cmd->arqbuf = NULL;
	}
}

/* tran_* entry points and setup */
/* ARGSUSED hba_dip tgt_dip hba_tran */
static int
pvscsi_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	pvscsi_softc_t	*pvs = SDEV2PRIV(sd);

	ASSERT(pvs != NULL);

	if (sd->sd_address.a_target >= PVSCSI_MAXTGTS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static int
pvscsi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	boolean_t	poll = ((pkt->pkt_flags & FLAG_NOINTR) != 0);
	int		rc;
	pvscsi_cmd_t	*cmd = PKT2CMD(pkt);
	pvscsi_softc_t	*pvs = ap->a_hba_tran->tran_hba_private;

	ASSERT(cmd->pkt == pkt);
	ASSERT(cmd->cmd_pvs == pvs);

	/*
	 * Reinitialize some fields because the packet may
	 * have been resubmitted.
	 */
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state = 0;
	pkt->pkt_statistics = 0;

	/* Zero status byte */
	*(pkt->pkt_scbp) = 0;

	if ((cmd->flags & PVSCSI_FLAG_DMA_VALID) != 0) {
		ASSERT(cmd->cmd_dma_count != 0);
		pkt->pkt_resid = cmd->cmd_dma_count;

		/*
		 * Consistent packets need to be synced first
		 * (only for data going out).
		 */
		if ((cmd->flags & PVSCSI_FLAG_IO_IOPB) != 0) {
			(void) ddi_dma_sync(cmd->cmd_dmahdl, 0, 0,
			    DDI_DMA_SYNC_FORDEV);
		}
	}

	cmd->cmd_target = ap->a_target;

	mutex_enter(&pvs->mutex);
	if (HBA_IS_QUIESCED(pvs) && !poll) {
		mutex_exit(&pvs->mutex);
		return (TRAN_BUSY);
	}
	mutex_exit(&pvs->mutex);

	rc = pvscsi_transport_command(pvs, cmd);

	if (poll) {
		pvscsi_cmd_t *dcmd;
		boolean_t qnotify;

		if (rc == TRAN_ACCEPT)
			rc = pvscsi_poll_cmd(pvs, cmd);

		mutex_enter(&pvs->rx_mutex);
		dcmd = pvscsi_process_comp_ring(pvs);
		mutex_exit(&pvs->rx_mutex);

		mutex_enter(&pvs->mutex);
		qnotify = HBA_QUIESCE_PENDING(pvs);
		mutex_exit(&pvs->mutex);

		pvscsi_complete_chained(dcmd);

		if (qnotify)
			pvscsi_quiesce_notify(pvs);
	}

	return (rc);
}

static int
pvscsi_reset(struct scsi_address *ap, int level)
{
	pvscsi_softc_t	*pvs = AP2PRIV(ap);

	switch (level) {
	case RESET_ALL:
		return (pvscsi_reset_generic(pvs, NULL));
	case RESET_TARGET:
		ASSERT(ap != NULL);
		return (pvscsi_reset_generic(pvs, ap));
	default:
		return (0);
	}
}

static int
pvscsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	boolean_t	qnotify = B_FALSE;
	pvscsi_cmd_t	*pending;
	pvscsi_softc_t	*pvs = ap->a_hba_tran->tran_hba_private;

	mutex_enter(&pvs->tx_mutex);
	mutex_enter(&pvs->rx_mutex);
	if (pkt != NULL) {
		/* Abort single command */
		pvscsi_cmd_t *cmd = PKT2CMD(pkt);

		if (pvscsi_abort_cmd(cmd, &pending) == CMD_ABORTED) {
			/* Assume command is completely cancelled now */
			cmd->flags |= PVSCSI_FLAG_ABORTED;
		}
	} else {
		/* Abort all commands on the bus */
		pvscsi_abort_all(ap, pvs, &pending, PVSCSI_FLAG_ABORTED);
	}
	qnotify = HBA_QUIESCE_PENDING(pvs);
	mutex_exit(&pvs->rx_mutex);
	mutex_exit(&pvs->tx_mutex);

	pvscsi_complete_chained(pending);

	if (qnotify)
		pvscsi_quiesce_notify(pvs);

	return (1);
}

/* ARGSUSED tgtonly */
static int
pvscsi_getcap(struct scsi_address *ap, char *cap, int tgtonly)
{
	pvscsi_softc_t	*pvs = ap->a_hba_tran->tran_hba_private;

	if (cap == NULL)
		return (-1);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		return ((pvs->flags & PVSCSI_HBA_AUTO_REQUEST_SENSE) != 0);
	case SCSI_CAP_UNTAGGED_QING:
		return (1);
	default:
		return (-1);
	}
}

/* ARGSUSED tgtonly */
static int
pvscsi_setcap(struct scsi_address *ap, char *cap, int value, int tgtonly)
{
	pvscsi_softc_t	*pvs = ap->a_hba_tran->tran_hba_private;

	if (cap == NULL)
		return (-1);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		mutex_enter(&pvs->mutex);
		if (value == 0)
			pvs->flags &= ~PVSCSI_HBA_AUTO_REQUEST_SENSE;
		else
			pvs->flags |= PVSCSI_HBA_AUTO_REQUEST_SENSE;
		mutex_exit(&pvs->mutex);
		return (1);
	default:
		return (0);
	}
}

static void
pvscsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	pvscsi_cmd_t	*cmd = PKT2CMD(pkt);
	pvscsi_softc_t	*pvs = ap->a_hba_tran->tran_hba_private;

	ASSERT(cmd->cmd_pvs == pvs);

	if ((cmd->flags & PVSCSI_FLAG_DMA_VALID) != 0) {
		cmd->flags &= ~PVSCSI_FLAG_DMA_VALID;
		(void) ddi_dma_unbind_handle(cmd->cmd_dmahdl);
	}

	if (cmd->ctx != NULL) {
		mutex_enter(&pvs->mutex);
		pvscsi_release_ctx(cmd);
		mutex_exit(&pvs->mutex);
	}

	if ((cmd->flags & PVSCSI_FLAGS_EXT) != 0)
		pvscsi_cmd_ext_free(cmd);

	kmem_cache_free(pvs->cmd_cache, cmd);
}

static struct scsi_pkt *
pvscsi_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt, struct buf *bp,
    int cmdlen, int statuslen, int tgtlen, int flags, int (*callback)(),
    caddr_t arg)
{
	boolean_t	is_new;
	int		kf = (callback == SLEEP_FUNC) ? KM_SLEEP: KM_NOSLEEP;
	int		rc, i;
	pvscsi_cmd_t	*cmd;
	pvscsi_softc_t	*pvs;

	pvs = ap->a_hba_tran->tran_hba_private;
	ASSERT(pvs != NULL);

	/* Allocate a new SCSI packet */
	if (pkt == NULL) {
		ddi_dma_handle_t saved_dmahdl, saved_arqhdl;
		struct buf	*saved_arqbuf;
		ddi_dma_cookie_t saved_arqc;

		is_new = B_TRUE;

		if ((cmd = kmem_cache_alloc(pvs->cmd_cache, kf)) == NULL)
			return (NULL);

		saved_dmahdl = cmd->cmd_dmahdl;
		saved_arqhdl = cmd->arqhdl;
		saved_arqbuf = cmd->arqbuf;
		saved_arqc = cmd->arqc;

		bzero(cmd, sizeof (pvscsi_cmd_t) -
		    sizeof (cmd->cached_cookies));

		cmd->cmd_pvs = pvs;
		cmd->cmd_dmahdl = saved_dmahdl;
		cmd->arqhdl = saved_arqhdl;
		cmd->arqbuf = saved_arqbuf;
		cmd->arqc = saved_arqc;

		pkt = &cmd->cached_pkt;
		pkt->pkt_ha_private = (opaque_t)cmd;
		pkt->pkt_address = *ap;
		pkt->pkt_scbp = (uint8_t *)&cmd->cmd_scb;
		pkt->pkt_cdbp = (uint8_t *)&cmd->cmd_cdb;
		pkt->pkt_private = (opaque_t)&cmd->tgt_priv;

		cmd->tgtlen = tgtlen;
		cmd->statuslen = statuslen;
		cmd->cmdlen = cmdlen;
		cmd->pkt = pkt;
		cmd->ctx = NULL;

		/* Allocate extended buffers */
		if ((cmdlen > sizeof (cmd->cmd_cdb)) ||
		    (statuslen > sizeof (cmd->cmd_scb)) ||
		    (tgtlen > sizeof (cmd->tgt_priv))) {
			if (pvscsi_cmd_ext_alloc(pvs, cmd, kf) != DDI_SUCCESS) {
				dev_err(pvs->dip, CE_WARN,
				    "!extent allocation failed");
				goto out;
			}
		}
	} else {
		is_new = B_FALSE;

		cmd = PKT2CMD(pkt);
		cmd->flags &= PVSCSI_FLAGS_PERSISTENT;
	}

	ASSERT((cmd->flags & PVSCSI_FLAG_TRANSPORT) == 0);

	if ((flags & PKT_XARQ) != 0)
		cmd->flags |= PVSCSI_FLAG_XARQ;

	/* Handle partial DMA transfers */
	if (cmd->cmd_nwin > 0) {
		if (++cmd->cmd_winindex >= cmd->cmd_nwin)
			return (NULL);
		if (ddi_dma_getwin(cmd->cmd_dmahdl, cmd->cmd_winindex,
		    &cmd->cmd_dma_offset, &cmd->cmd_dma_len,
		    &cmd->cmd_dmac, &cmd->cmd_dmaccount) == DDI_FAILURE)
			return (NULL);
		goto handle_dma_cookies;
	}

	/* Setup data buffer */
	if (bp != NULL && bp->b_bcount > 0 &&
	    (cmd->flags & PVSCSI_FLAG_DMA_VALID) == 0) {
		int dma_flags;

		ASSERT(cmd->cmd_dmahdl != NULL);

		if ((bp->b_flags & B_READ) != 0) {
			cmd->flags |= PVSCSI_FLAG_IO_READ;
			dma_flags = DDI_DMA_READ;
		} else {
			cmd->flags &= ~PVSCSI_FLAG_IO_READ;
			dma_flags = DDI_DMA_WRITE;
		}
		if ((flags & PKT_CONSISTENT) != 0) {
			cmd->flags |= PVSCSI_FLAG_IO_IOPB;
			dma_flags |= DDI_DMA_CONSISTENT;
		}
		if ((flags & PKT_DMA_PARTIAL) != 0)
			dma_flags |= DDI_DMA_PARTIAL;

		rc = ddi_dma_buf_bind_handle(cmd->cmd_dmahdl, bp,
		    dma_flags, callback, arg, &cmd->cmd_dmac,
		    &cmd->cmd_dmaccount);
		if (rc == DDI_DMA_PARTIAL_MAP) {
			(void) ddi_dma_numwin(cmd->cmd_dmahdl,
			    &cmd->cmd_nwin);
			cmd->cmd_winindex = 0;
			(void) ddi_dma_getwin(cmd->cmd_dmahdl,
			    cmd->cmd_winindex, &cmd->cmd_dma_offset,
			    &cmd->cmd_dma_len, &cmd->cmd_dmac,
			    &cmd->cmd_dmaccount);
		} else if (rc != 0 && rc != DDI_DMA_MAPPED) {
			switch (rc) {
			case DDI_DMA_NORESOURCES:
				bioerror(bp, 0);
				break;
			case DDI_DMA_BADATTR:
			case DDI_DMA_NOMAPPING:
				bioerror(bp, EFAULT);
				break;
			case DDI_DMA_TOOBIG:
			default:
				bioerror(bp, EINVAL);
				break;
			}
			cmd->flags &= ~PVSCSI_FLAG_DMA_VALID;
			goto out;
		}

handle_dma_cookies:
		ASSERT(cmd->cmd_dmaccount > 0);
		if (cmd->cmd_dmaccount > PVSCSI_MAX_SG_SIZE) {
			dev_err(pvs->dip, CE_WARN,
			    "!invalid cookie count: %d (max %d)",
			    cmd->cmd_dmaccount, PVSCSI_MAX_SG_SIZE);
			bioerror(bp, EINVAL);
			goto out;
		}

		cmd->flags |= PVSCSI_FLAG_DMA_VALID;
		cmd->cmd_dma_count = cmd->cmd_dmac.dmac_size;
		cmd->cmd_total_dma_count += cmd->cmd_dmac.dmac_size;

		cmd->cached_cookies[0] = cmd->cmd_dmac;

		/*
		 * Calculate total amount of bytes for this I/O and
		 * store cookies for further processing.
		 */
		for (i = 1; i < cmd->cmd_dmaccount; i++) {
			ddi_dma_nextcookie(cmd->cmd_dmahdl, &cmd->cmd_dmac);
			cmd->cached_cookies[i] = cmd->cmd_dmac;
			cmd->cmd_dma_count += cmd->cmd_dmac.dmac_size;
			cmd->cmd_total_dma_count += cmd->cmd_dmac.dmac_size;
		}

		pkt->pkt_resid = (bp->b_bcount - cmd->cmd_total_dma_count);
	}

	return (pkt);

out:
	if (is_new)
		pvscsi_destroy_pkt(ap, pkt);

	return (NULL);
}

/* ARGSUSED ap */
static void
pvscsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	pvscsi_cmd_t	*cmd = PKT2CMD(pkt);

	if ((cmd->flags & PVSCSI_FLAG_DMA_VALID) != 0) {
		(void) ddi_dma_unbind_handle(cmd->cmd_dmahdl);
		cmd->flags &= ~PVSCSI_FLAG_DMA_VALID;
	}
}

/* ARGSUSED ap */
static void
pvscsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	pvscsi_cmd_t	*cmd = PKT2CMD(pkt);

	if (cmd->cmd_dmahdl != NULL) {
		(void) ddi_dma_sync(cmd->cmd_dmahdl, 0, 0,
		    (cmd->flags & PVSCSI_FLAG_IO_READ) ?
		    DDI_DMA_SYNC_FORCPU : DDI_DMA_SYNC_FORDEV);
	}

}

/* ARGSUSED ap flag callback arg */
static int
pvscsi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg)
{
	return (DDI_FAILURE);
}

static int
pvscsi_quiesce_hba(dev_info_t *dip)
{
	pvscsi_softc_t	*pvs;
	scsi_hba_tran_t *tran;

	if ((tran = ddi_get_driver_private(dip)) == NULL ||
	    (pvs = TRAN2PRIV(tran)) == NULL)
		return (-1);

	mutex_enter(&pvs->mutex);
	if (!HBA_IS_QUIESCED(pvs))
		pvs->flags |= PVSCSI_HBA_QUIESCED;

	if (pvs->cmd_queue_len != 0) {
		/* Outstanding commands present, wait */
		pvs->flags |= PVSCSI_HBA_QUIESCE_PENDING;
		cv_wait(&pvs->quiescevar, &pvs->mutex);
		ASSERT(pvs->cmd_queue_len == 0);
	}
	mutex_exit(&pvs->mutex);

	/* Suspend taskq delivery and complete all scheduled tasks */
	ddi_taskq_suspend(pvs->msg_tq);
	ddi_taskq_wait(pvs->msg_tq);
	ddi_taskq_suspend(pvs->comp_tq);
	ddi_taskq_wait(pvs->comp_tq);

	return (0);
}

static int
pvscsi_unquiesce_hba(dev_info_t *dip)
{
	pvscsi_softc_t	*pvs;
	scsi_hba_tran_t	*tran;

	if ((tran = ddi_get_driver_private(dip)) == NULL ||
	    (pvs = TRAN2PRIV(tran)) == NULL)
		return (-1);

	mutex_enter(&pvs->mutex);
	if (!HBA_IS_QUIESCED(pvs)) {
		mutex_exit(&pvs->mutex);
		return (0);
	}
	ASSERT(pvs->cmd_queue_len == 0);
	pvs->flags &= ~PVSCSI_HBA_QUIESCED;
	mutex_exit(&pvs->mutex);

	/* Resume taskq delivery */
	ddi_taskq_resume(pvs->msg_tq);
	ddi_taskq_resume(pvs->comp_tq);

	return (0);
}

static int
pvscsi_bus_config(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **childp)
{
	char		*p;
	int		circ;
	int		ret = NDI_FAILURE;
	long		target = 0;
	pvscsi_softc_t	*pvs;
	scsi_hba_tran_t	*tran;

	tran = ddi_get_driver_private(pdip);
	pvs = tran->tran_hba_private;

	ndi_devi_enter(pdip, &circ);
	switch (op) {
	case BUS_CONFIG_ONE:
		if ((p = strrchr((char *)arg, '@')) != NULL &&
		    ddi_strtol(p + 1, NULL, 16, &target) == 0)
			ret = pvscsi_config_one(pdip, pvs, (int)target, childp);
		break;
	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL:
		ret = pvscsi_config_all(pdip, pvs);
		break;
	default:
		break;
	}

	if (ret == NDI_SUCCESS)
		ret = ndi_busop_bus_config(pdip, flags, op, arg, childp, 0);
	ndi_devi_exit(pdip, circ);

	return (ret);
}

static int
pvscsi_hba_setup(pvscsi_softc_t *pvs)
{
	scsi_hba_tran_t	*hba_tran;

	hba_tran = pvs->tran = scsi_hba_tran_alloc(pvs->dip,
	    SCSI_HBA_CANSLEEP);
	ASSERT(pvs->tran != NULL);

	hba_tran->tran_hba_private = pvs;
	hba_tran->tran_tgt_private = NULL;

	hba_tran->tran_tgt_init	= pvscsi_tgt_init;
	hba_tran->tran_tgt_free	= NULL;
	hba_tran->tran_tgt_probe = scsi_hba_probe;

	hba_tran->tran_start = pvscsi_start;
	hba_tran->tran_reset = pvscsi_reset;
	hba_tran->tran_abort = pvscsi_abort;
	hba_tran->tran_getcap = pvscsi_getcap;
	hba_tran->tran_setcap = pvscsi_setcap;
	hba_tran->tran_init_pkt = pvscsi_init_pkt;
	hba_tran->tran_destroy_pkt = pvscsi_destroy_pkt;

	hba_tran->tran_dmafree = pvscsi_dmafree;
	hba_tran->tran_sync_pkt = pvscsi_sync_pkt;
	hba_tran->tran_reset_notify = pvscsi_reset_notify;

	hba_tran->tran_quiesce = pvscsi_quiesce_hba;
	hba_tran->tran_unquiesce = pvscsi_unquiesce_hba;
	hba_tran->tran_bus_reset = NULL;

	hba_tran->tran_add_eventcall = NULL;
	hba_tran->tran_get_eventcookie = NULL;
	hba_tran->tran_post_event = NULL;
	hba_tran->tran_remove_eventcall = NULL;

	hba_tran->tran_bus_config = pvscsi_bus_config;

	hba_tran->tran_interconnect_type = INTERCONNECT_SAS;

	if (scsi_hba_attach_setup(pvs->dip, &pvs->hba_dma_attr, hba_tran,
	    SCSI_HBA_TRAN_CDB | SCSI_HBA_TRAN_SCB | SCSI_HBA_TRAN_CLONE) !=
	    DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to attach HBA");
		scsi_hba_tran_free(hba_tran);
		pvs->tran = NULL;
		return (-1);
	}

	return (0);
}

static int
pvscsi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;
	pvscsi_softc_t	*pvs;
	char		buf[32];

	ASSERT(scsi_hba_iport_unit_address(dip) == NULL);

	switch (cmd) {
	case DDI_ATTACH:
	case DDI_RESUME:
		break;
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	/* Allocate softstate information */
	if (ddi_soft_state_zalloc(pvscsi_sstate, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "!ddi_soft_state_zalloc() failed for instance %d",
		    instance);
		return (DDI_FAILURE);
	}

	if ((pvs = ddi_get_soft_state(pvscsi_sstate, instance)) == NULL) {
		cmn_err(CE_WARN, "!failed to get soft state for instance %d",
		    instance);
		goto fail;
	}

	/*
	 * Indicate that we are 'sizeof (scsi_*(9S))' clean, we use
	 * scsi_pkt_size() instead.
	 */
	scsi_size_clean(dip);

	/* Setup HBA instance */
	pvs->instance = instance;
	pvs->dip = dip;
	pvs->hba_dma_attr = pvscsi_hba_dma_attr;
	pvs->ring_dma_attr = pvscsi_ring_dma_attr;
	pvs->io_dma_attr = pvscsi_io_dma_attr;
	mutex_init(&pvs->mutex, "pvscsi instance mutex", MUTEX_DRIVER, NULL);
	mutex_init(&pvs->intr_mutex, "pvscsi instance interrupt mutex",
	    MUTEX_DRIVER, NULL);
	mutex_init(&pvs->rx_mutex, "pvscsi rx ring mutex", MUTEX_DRIVER, NULL);
	mutex_init(&pvs->tx_mutex, "pvscsi tx ring mutex", MUTEX_DRIVER, NULL);
	list_create(&pvs->cmd_ctx_pool, sizeof (pvscsi_cmd_ctx_t),
	    offsetof(pvscsi_cmd_ctx_t, list));
	list_create(&pvs->devnodes, sizeof (pvscsi_device_t),
	    offsetof(pvscsi_device_t, list));
	list_create(&pvs->cmd_queue, sizeof (pvscsi_cmd_t),
	    offsetof(pvscsi_cmd_t, cmd_queue_node));
	cv_init(&pvs->syncvar, "pvscsi synchronization cv", CV_DRIVER, NULL);
	cv_init(&pvs->wd_condvar, "pvscsi watchdog cv", CV_DRIVER, NULL);
	cv_init(&pvs->quiescevar, "pvscsi quiesce cv", CV_DRIVER, NULL);

	(void) sprintf(buf, "pvscsi%d_cache", instance);
	pvs->cmd_cache = kmem_cache_create(buf, sizeof (pvscsi_cmd_t), 0,
	    pvscsi_ccache_constructor, pvscsi_ccache_destructor, NULL,
	    (void *)pvs, NULL, 0);
	if (pvs->cmd_cache == NULL) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to create a cache for SCSI commands");
		goto fail;
	}

	if ((pvscsi_setup_io(pvs)) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to setup I/O region");
		goto free_cache;
	}

	pvscsi_reset_hba(pvs);

	if ((pvscsi_allocate_rings(pvs)) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to allocate DMA rings");
		goto free_io;
	}

	pvscsi_setup_rings(pvs);

	if (pvscsi_setup_isr(pvs) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to setup ISR");
		goto free_rings;
	}

	if (pvscsi_setup_sg(pvs) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to setup S/G");
		goto free_intr;
	}

	if (pvscsi_hba_setup(pvs) != 0) {
		dev_err(pvs->dip, CE_WARN, "!failed to setup HBA");
		goto free_sg;
	}

	if ((pvs->comp_tq = ddi_taskq_create(pvs->dip, "comp_tq",
	    MIN(UINT16_MAX, ncpus), TASKQ_DEFAULTPRI, 0)) == NULL) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to create completion taskq");
		goto free_sg;
	}

	if ((pvs->msg_tq = ddi_taskq_create(pvs->dip, "msg_tq",
	    1, TASKQ_DEFAULTPRI, 0)) == NULL) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to create message taskq");
		goto free_comp_tq;
	}

	if (pvscsi_enable_intrs(pvs) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to enable interrupts");
		goto free_msg_tq;
	}

	/* Launch watchdog thread */
	pvs->wd_thread = thread_create(NULL, 0, pvscsi_wd_thread, pvs, 0, &p0,
	    TS_RUN, minclsyspri);

	return (DDI_SUCCESS);

free_msg_tq:
	ddi_taskq_destroy(pvs->msg_tq);
free_comp_tq:
	ddi_taskq_destroy(pvs->comp_tq);
free_sg:
	pvscsi_free_sg(pvs);
free_intr:
	pvscsi_free_intr_resources(pvs);
free_rings:
	pvscsi_reset_hba(pvs);
	pvscsi_free_rings(pvs);
free_io:
	pvscsi_free_io(pvs);
free_cache:
	kmem_cache_destroy(pvs->cmd_cache);
fail:
	ddi_soft_state_free(pvscsi_sstate, instance);

	return (DDI_FAILURE);
}

static int
pvscsi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	pvscsi_softc_t	*pvs;

	switch (cmd) {
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	if ((pvs = ddi_get_soft_state(pvscsi_sstate, instance)) == NULL) {
		cmn_err(CE_WARN, "!failed to get soft state for instance %d",
		    instance);
		return (DDI_FAILURE);
	}

	pvscsi_reset_hba(pvs);
	pvscsi_free_intr_resources(pvs);

	/* Shutdown message taskq */
	ddi_taskq_wait(pvs->msg_tq);
	ddi_taskq_destroy(pvs->msg_tq);

	/* Shutdown completion taskq */
	ddi_taskq_wait(pvs->comp_tq);
	ddi_taskq_destroy(pvs->comp_tq);

	/* Shutdown watchdog thread */
	mutex_enter(&pvs->mutex);
	pvs->flags |= PVSCSI_DRIVER_SHUTDOWN;
	cv_signal(&pvs->wd_condvar);
	cv_wait(&pvs->syncvar, &pvs->mutex);
	mutex_exit(&pvs->mutex);

	pvscsi_free_sg(pvs);
	pvscsi_free_rings(pvs);
	pvscsi_free_io(pvs);

	kmem_cache_destroy(pvs->cmd_cache);

	mutex_destroy(&pvs->mutex);
	mutex_destroy(&pvs->intr_mutex);
	mutex_destroy(&pvs->rx_mutex);

	cv_destroy(&pvs->syncvar);
	cv_destroy(&pvs->wd_condvar);
	cv_destroy(&pvs->quiescevar);

	ddi_soft_state_free(pvscsi_sstate, instance);
	ddi_prop_remove_all(dip);

	return (DDI_SUCCESS);
}

static int
pvscsi_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp,
    int *rval)
{
	int	ret;

	if (ddi_get_soft_state(pvscsi_sstate, getminor(dev)) == NULL) {
		cmn_err(CE_WARN, "!invalid device instance: %d", getminor(dev));
		return (ENXIO);
	}

	/* Try to handle command in a common way */
	if ((ret = scsi_hba_ioctl(dev, cmd, data, mode, credp, rval)) != ENOTTY)
		return (ret);

	cmn_err(CE_WARN, "!unsupported IOCTL command: 0x%X", cmd);

	return (ENXIO);
}

static int
pvscsi_quiesce(dev_info_t *devi)
{
	scsi_hba_tran_t	*tran;
	pvscsi_softc_t	*pvs;

	if ((tran = ddi_get_driver_private(devi)) == NULL)
		return (DDI_SUCCESS);

	if ((pvs = tran->tran_hba_private) == NULL)
		return (DDI_SUCCESS);

	/* Mask all interrupts from device */
	pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_INTR_MASK, 0);

	/* Reset the HBA */
	pvscsi_reset_hba(pvs);

	return (DDI_SUCCESS);
}

/* module */

static struct cb_ops pvscsi_cb_ops = {
	.cb_open =	scsi_hba_open,
	.cb_close =	scsi_hba_close,
	.cb_strategy =	nodev,
	.cb_print =	nodev,
	.cb_dump =	nodev,
	.cb_read =	nodev,
	.cb_write =	nodev,
	.cb_ioctl =	pvscsi_ioctl,
	.cb_devmap =	nodev,
	.cb_mmap =	nodev,
	.cb_segmap =	nodev,
	.cb_chpoll =	nochpoll,
	.cb_prop_op =	ddi_prop_op,
	.cb_str =	NULL,
	.cb_flag =	D_MP,
	.cb_rev =	CB_REV,
	.cb_aread =	nodev,
	.cb_awrite =	nodev
};

static struct dev_ops pvscsi_ops = {
	.devo_rev =	DEVO_REV,
	.devo_refcnt =	0,
	.devo_getinfo =	ddi_no_info,
	.devo_identify = nulldev,
	.devo_probe =	nulldev,
	.devo_attach =	pvscsi_attach,
	.devo_detach =	pvscsi_detach,
	.devo_reset =	nodev,
	.devo_cb_ops =	&pvscsi_cb_ops,
	.devo_bus_ops =	NULL,
	.devo_power =	NULL,
	.devo_quiesce =	pvscsi_quiesce
};

#define	PVSCSI_IDENT "VMware PVSCSI"

static struct modldrv modldrv = {
	&mod_driverops,
	PVSCSI_IDENT,
	&pvscsi_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int	ret;

	if ((ret = ddi_soft_state_init(&pvscsi_sstate,
	    sizeof (struct pvscsi_softc), PVSCSI_INITIAL_SSTATE_ITEMS)) != 0) {
		cmn_err(CE_WARN, "!ddi_soft_state_init() failed");
		return (ret);
	}

	if ((ret = scsi_hba_init(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "!scsi_hba_init() failed");
		ddi_soft_state_fini(&pvscsi_sstate);
		return (ret);
	}

	if ((ret = mod_install(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "!mod_install() failed");
		ddi_soft_state_fini(&pvscsi_sstate);
		scsi_hba_fini(&modlinkage);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	ret;

	if ((ret = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&pvscsi_sstate);
		scsi_hba_fini(&modlinkage);
	}

	return (ret);
}
