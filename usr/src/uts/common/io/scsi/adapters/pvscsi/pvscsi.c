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
 * Copyright 2022 RackTop Systems, Inc.
 */

#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/ddi.h>
#include <sys/id32.h>
#include <sys/kmem.h>
#include <sys/list.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/scsi/scsi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/note.h>

#include "pvscsi.h"
#include "pvscsi_var.h"

/* we can support any of the interrupt types */
int pvscsi_intr_types = \
	DDI_INTR_TYPE_MSIX|DDI_INTR_TYPE_MSI|DDI_INTR_TYPE_FIXED;
int pvscsi_ring_pages = PVSCSI_DEFAULT_NUM_PAGES_PER_RING;
int pvscsi_msg_ring_pages = PVSCSI_DEFAULT_NUM_PAGES_MSG_RING;
static int pvscsi_hz;

static int pvscsi_abort(struct scsi_address *, struct scsi_pkt *);
static void pvscsi_timeout(void *);
static void pvscsi_setup_rings(pvscsi_softc_t *);
static void pvscsi_complete_cmds(pvscsi_softc_t *, pvscsi_cmd_t *);
static boolean_t pvscsi_cmd_init(pvscsi_softc_t *, pvscsi_cmd_t *, int);
static void pvscsi_cmd_fini(pvscsi_cmd_t *);

/* HBA DMA attributes */
static ddi_dma_attr_t pvscsi_dma_attr = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_align =	PAGE_SIZE,
	.dma_attr_burstsizes =	1,
	.dma_attr_minxfer =	1,
	.dma_attr_maxxfer =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_seg =		0xFFFFFFFFFFFFFFFFull,
	.dma_attr_sgllen =	1,
	.dma_attr_granular =	1,
	.dma_attr_flags =	0
};

/* DMA attributes for buffer I/O */
static ddi_dma_attr_t pvscsi_io_dma_attr = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max =	0x7FFFFFFFll,
	.dma_attr_align =	1,
	.dma_attr_burstsizes =	1,
	.dma_attr_minxfer =	1,
	.dma_attr_maxxfer =	PAGE_SIZE * PVSCSI_MAX_SG_SIZE,
	.dma_attr_seg =		0xFFFFFFFFFFFFFFFFull,
	.dma_attr_sgllen =	PVSCSI_MAX_SG_SIZE,
	.dma_attr_granular =	1,
	.dma_attr_flags =	0
};

/*
 * The structures are always little endian (VMware only runs
 * on little endian CPUs), but we only run on LE processors,
 * and NEVERSWAP avoids needing to use DDI accessor functions.
 * (It would be incredibly bizarre to have a VMware guest running
 * with a different endianness than the hypervisor.)
 */
static ddi_device_acc_attr_t pvscsi_mmio_attr = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V1,
	.devacc_attr_endian_flags =	DDI_NEVERSWAP_ACC,
	.devacc_attr_dataorder =	DDI_STRICTORDER_ACC,
	.devacc_attr_access =		DDI_DEFAULT_ACC
};

static ddi_device_acc_attr_t pvscsi_dma_attrs = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V1,
	.devacc_attr_endian_flags =	DDI_NEVERSWAP_ACC,
	.devacc_attr_dataorder =	DDI_STRICTORDER_ACC,
	.devacc_attr_access =		DDI_DEFAULT_ACC,
};

static void
pvscsi_add_to_queue(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd)
{
	pvscsi_cmd_t	*r;
	list_t		*l;

	/*
	 * We insert in order of expiration, with the earliest
	 * expirations at the front.  This logic assumes that most
	 * commands will have the same timeout, and is optimized
	 * to minimize walking the list.  It allows timeouts to
	 * run without looking at more than one node that has not
	 * yet expired.
	 */
	ASSERT(mutex_owned(&pvs->lock));

	l = &pvs->cmd_queue;
	for (r = list_tail(l); r != NULL; r = list_prev(l, r)) {
		/* this subtraction is safe if lbolt wraps */
		if (((cmd->start + cmd->timeout) -
		    (r->start + r->timeout)) >= 0) {
			list_insert_after(l, r, cmd);
			return;
		}
	}

	list_insert_head(l, cmd);
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

static pvscsi_cmd_t *
pvscsi_reclaim_cmds(pvscsi_softc_t *pvs)
{
	pvscsi_cmd_t	*head = NULL;
	pvscsi_cmd_t	**tail = &head;
	pvscsi_cmd_t	*cmd;

	ASSERT(mutex_owned(&pvs->lock));
	while ((cmd = list_remove_head(&pvs->cmd_queue)) != NULL) {
		list_remove(&pvs->cmd_queue, cmd);
		*tail = cmd;
		tail = &cmd->next_cmd;
		*tail = NULL;
		cmd->host_status = BTSTAT_BUSRESET;
	}
	return (head);
}

static void
pvscsi_stop_hba(pvscsi_softc_t *pvs)
{
	pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_ADAPTER_RESET, NULL, 0);
	pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_INTR_MASK, 0);
	/* read interrupt status to flush PCI write buffers */
	(void) pvscsi_read_intr_status(pvs);
}

static void
pvscsi_start_hba(pvscsi_softc_t *pvs)
{
	pvscsi_setup_rings(pvs);
	pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_INTR_MASK,
	    PVSCSI_INTR_CMPL_MASK | PVSCSI_INTR_MSG_MASK);
}

static void
pvscsi_reset_bus(pvscsi_softc_t *pvs)
{
	pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_RESET_BUS, NULL, 0);
}

/*
 * pvscsi_restart_hba resets the HBA, and reconfigures it.  It also
 * completes all commands that have not been already completed with
 * a reset.
 */
static void
pvscsi_restart_hba(pvscsi_softc_t *pvs)
{
	pvscsi_cmd_t	*cmd;

	mutex_enter(&pvs->lock);
	pvscsi_stop_hba(pvs);
	cmd = pvscsi_reclaim_cmds(pvs);
	pvscsi_start_hba(pvs);
	mutex_exit(&pvs->lock);

	/* run the completions from the reclaimed commands */
	pvscsi_complete_cmds(pvs, cmd);
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

static pvscsi_cmd_t *
pvscsi_process_comp_ring(pvscsi_softc_t *pvs)
{
	pvscsi_cmd_t	**pnext_cmd;
	pvscsi_cmd_t	*cmd;
	pvscsi_cmd_t	*head = NULL;
	struct PVSCSIRingsState *sdesc = RINGS_STATE(pvs);
	uint32_t	cmp_ne = sdesc->cmpNumEntriesLog2;

	ASSERT(mutex_owned(&pvs->lock));

	pnext_cmd = &head;

	(void) ddi_dma_sync(pvs->state_buf.dmah, 0, 0, DDI_DMA_SYNC_FORKERNEL);

	while (sdesc->cmpConsIdx != sdesc->cmpProdIdx) {
		struct PVSCSIRingCmpDesc *cdesc;

		(void) ddi_dma_sync(pvs->cmp_ring_buf.dmah, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);

		cdesc = CMP_RING(pvs) + (sdesc->cmpConsIdx & MASK(cmp_ne));

		if ((cmd = id32_lookup((uint32_t)cdesc->context)) != NULL) {
			cmd->next_cmd = NULL;

			/* Save command status for further processing */
			cmd->host_status = cdesc->hostStatus;
			cmd->scsi_status = cdesc->scsiStatus;
			cmd->transferred = cdesc->dataLen;

			*pnext_cmd = cmd;
			pnext_cmd = &cmd->next_cmd;

			list_remove(&pvs->cmd_queue, cmd);
		}

		sdesc->cmpConsIdx++;
	}
	(void) ddi_dma_sync(pvs->state_buf.dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

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

	(void) ddi_dma_sync(pvs->state_buf.dmah, 0, 0, DDI_DMA_SYNC_FORKERNEL);

	if (sdesc->msgProdIdx == sdesc->msgConsIdx) {
		return (NULL);
	}

	(void) ddi_dma_sync(pvs->msg_ring_buf.dmah, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);

	mdesc = MSG_RING(pvs) + (sdesc->msgConsIdx & MASK(msg_ne));

	switch (mdesc->type) {
	case PVSCSI_MSG_DEV_ADDED:
	case PVSCSI_MSG_DEV_REMOVED:
		desc = (struct PVSCSIMsgDescDevStatusChanged *)mdesc;
		msg = kmem_alloc(sizeof (pvscsi_msg_t), KM_NOSLEEP);
		if (msg == NULL)
			return (NULL);
		msg->pvs = pvs;
		msg->type = mdesc->type;
		msg->target = desc->target;
		msg->lun = desc->lun[1]; /* T10 format */
		break;
	default:
		dev_err(pvs->dip, CE_WARN, "!unknown msg type: %d",
		    mdesc->type);
		return (NULL);
	}

	sdesc->msgConsIdx++;
	(void) ddi_dma_sync(pvs->state_buf.dmah, 0, 0, DDI_DMA_SYNC_FORDEV);
	return (msg);
}

static void
pvscsi_handle_msg(void *arg)
{
	pvscsi_msg_t	*msg = arg;
	pvscsi_softc_t	*pvs = msg->pvs;
	char		addr[8];

	(void) snprintf(addr, sizeof (addr), "%x", msg->target);

	if (msg->lun == 0) {
		switch (msg->type) {
		case PVSCSI_MSG_DEV_ADDED:
			(void) scsi_hba_tgtmap_tgt_add(pvs->tgtmap,
			    SCSI_TGT_SCSI_DEVICE, addr, NULL);
			break;
		case PVSCSI_MSG_DEV_REMOVED:
			(void) scsi_hba_tgtmap_tgt_remove(pvs->tgtmap,
			    SCSI_TGT_SCSI_DEVICE, addr);
			break;
		}
	} else {
		scsi_hba_tgtmap_scan_luns(pvs->tgtmap, addr);
	}
	kmem_free(msg, sizeof (pvscsi_msg_t));
}

static void
pvscsi_abort_cmd(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd)
{
	struct PVSCSICmdDescAbortCmd	acmd;

	bzero(&acmd, sizeof (acmd));
	acmd.target = cmd->target;
	acmd.context = cmd->ctx;
	pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_ABORT_CMD, &acmd, sizeof (acmd));
}

static void
pvscsi_map_buffers(pvscsi_cmd_t *cmd, struct PVSCSIRingReqDesc *rdesc)
{
	struct scsi_pkt *pkt = cmd->pkt;

	rdesc->dataLen = 0;
	rdesc->dataAddr = 0;
	if (pkt == NULL || pkt->pkt_numcookies == 0) {
		return;
	}

	pkt->pkt_resid = 0;

	if (pkt->pkt_numcookies > 1) {
		size_t	len = 0;
		struct PVSCSISGElement *sgl = cmd->sgl;

		for (uint_t i = 0; i < pkt->pkt_numcookies; i++) {
			sgl[i].addr = pkt->pkt_cookies[i].dmac_laddress;
			sgl[i].length = pkt->pkt_cookies[i].dmac_size;
			sgl[i].flags = 0;
			len += pkt->pkt_cookies[i].dmac_size;
		}
		rdesc->flags |= PVSCSI_FLAG_CMD_WITH_SG_LIST;
		rdesc->dataAddr = cmd->sgl_pa;
		rdesc->dataLen = len;
		(void) ddi_dma_sync(cmd->sgl_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);
	} else {
		rdesc->flags = 0;
		rdesc->dataAddr = pkt->pkt_cookies[0].dmac_laddress;
		rdesc->dataLen = pkt->pkt_cookies[0].dmac_size;
	}
	pkt->pkt_resid = rdesc->dataLen;
}

static void
pvscsi_comp_cmd(pvscsi_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = cmd->pkt;
	uint8_t		status = cmd->scsi_status;

	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
	    STATE_GOT_STATUS);
	if (pkt->pkt_numcookies > 0) {
		pkt->pkt_state |= STATE_XFERRED_DATA;
	}
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_resid -= cmd->transferred;
	*(pkt->pkt_scbp) = status;

	if (status == STATUS_CHECK) {
		/*
		 * Our virtual HBA *always* does ARQ, and it never
		 * is more than 20 bytes, so no need to try to handle
		 * extended versions of it.
		 */
		struct scsi_arq_status *ars = (void *)(pkt->pkt_scbp);
		int		len = min(pkt->pkt_scblen, SENSE_LENGTH);

		pkt->pkt_state |= STATE_ARQ_DONE;
		ars->sts_rqpkt_resid = 0;
		bcopy(cmd->arq_sense, &ars->sts_sensedata, len);
		ars->sts_rqpkt_reason = CMD_CMPLT;
		*(uint8_t *)&ars->sts_rqpkt_status = STATUS_GOOD;
		ars->sts_rqpkt_state = STATE_GOT_BUS |
		    STATE_GOT_TARGET | STATE_SENT_CMD |
		    STATE_XFERRED_DATA | STATE_GOT_STATUS;
	}
}

static void
pvscsi_set_status(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = cmd->pkt;
	uint32_t	host_status = cmd->host_status;

	switch (host_status) {
	case BTSTAT_SUCCESS:
	case BTSTAT_LINKED_COMMAND_COMPLETED:
	case BTSTAT_LINKED_COMMAND_COMPLETED_WITH_FLAG:
		pvscsi_comp_cmd(cmd);
		break;
	case BTSTAT_DATARUN:
		pkt->pkt_reason = CMD_DATA_OVR;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS |
		    STATE_XFERRED_DATA);
		pkt->pkt_resid -= cmd->transferred;
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
		pkt->pkt_reason = CMD_RESET;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		pkt->pkt_statistics |= STAT_DEV_RESET;
		pkt->pkt_resid -= cmd->transferred;
		break;
	case BTSTAT_BUSRESET:
		pkt->pkt_reason = CMD_RESET;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		pkt->pkt_statistics |= STAT_BUS_RESET;
		pkt->pkt_resid -= cmd->transferred;
		break;
	case BTSTAT_ABORTQUEUE:
		if (cmd->expired) {
			pkt->pkt_reason = CMD_TIMEOUT;
			pkt->pkt_statistics |= STAT_TIMEOUT;
		} else {
			pkt->pkt_reason = CMD_ABORTED;
			pkt->pkt_statistics |= STAT_ABORTED;
		}
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		pkt->pkt_resid -= cmd->transferred;
		break;
	case BTSTAT_HAHARDWARE:
	case BTSTAT_INVPHASE:
	case BTSTAT_HATIMEOUT:
	case BTSTAT_NORESPONSE:
	case BTSTAT_DISCONNECT:
	case BTSTAT_HASOFTWARE:
	case BTSTAT_BUSFREE:
	case BTSTAT_SENSFAILED:
	case BTSTAT_DATA_UNDERRUN:
		pkt->pkt_reason = CMD_TRAN_ERR;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		pkt->pkt_resid -= cmd->transferred;
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

/*
 * pvscsi_complete_cmds processes a linked list of
 * commands that have been completed.  This is done
 * without acquiring any locks.
 */
static void
pvscsi_complete_cmds(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd)
{
	struct scsi_pkt	*pkt;

	while (cmd != NULL) {
		pvscsi_cmd_t	*next = cmd->next_cmd;

		cmd->next_cmd = NULL;

		if (((pkt = cmd->pkt) == NULL) || (cmd->poll)) {
			atomic_or_8(&cmd->done, 1);
		} else {
			pvscsi_set_status(pvs, cmd);
			scsi_hba_pkt_comp(pkt);
		}

		cmd = next;
	}
}

static void
pvscsi_dev_reset(pvscsi_softc_t *pvs, int target, int lun)
{
	struct PVSCSICmdDescResetDevice cmd = { 0 };

	cmd.target = target;
	cmd.lun[1] = lun & 0xff;
	pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_RESET_DEVICE, &cmd, sizeof (cmd));
}

static boolean_t
pvscsi_poll_cmd_until(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd, clock_t usec)
{
	while (usec > 0) {
		pvscsi_cmd_t	*done;
		if (cmd->done) {
			return (B_TRUE);
		}
		mutex_enter(&pvs->lock);
		done = pvscsi_process_comp_ring(pvs);
		mutex_exit(&pvs->lock);

		pvscsi_complete_cmds(pvs, done);
		drv_usecwait(10);
		usec -= 10;
	}

	return (B_FALSE);
}

static void
pvscsi_poll_cmd(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd)
{
	if (pvscsi_poll_cmd_until(pvs, cmd, drv_hztousec(cmd->timeout))) {
		return;
	}

	/* now we try an abort first */
	pvscsi_abort_cmd(pvs, cmd);
	if (pvscsi_poll_cmd_until(pvs, cmd, 2)) {
		return;
	}
	/* well that failed... try reset */
	pvscsi_dev_reset(pvs, cmd->target, cmd->lun);
	if (pvscsi_poll_cmd_until(pvs, cmd, 2)) {
		return;
	}
	/* still trying... reset the bus */
	pvscsi_reset_bus(pvs);
	if (pvscsi_poll_cmd_until(pvs, cmd, 2)) {
		return;
	}
	/* full up adapter reset -- be brutal */
	pvscsi_restart_hba(pvs);
}

static void
pvscsi_abort_all(pvscsi_softc_t *pvs, pvscsi_device_t *pd)
{
	pvscsi_cmd_t	*cmd;

	mutex_enter(&pvs->lock);
	list_t *l = &pvs->cmd_queue;
	for (cmd = list_head(l); cmd != NULL; cmd = list_next(l, cmd)) {
		if ((pd->target == cmd->target) && (pd->lun == cmd->lun)) {
			pvscsi_abort_cmd(pvs, cmd);
		}
	}
	mutex_exit(&pvs->lock);
}

static int
pvscsi_transport_command(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd)
{
	struct PVSCSIRingReqDesc	*rdesc;
	struct PVSCSIRingsState		*sdesc = RINGS_STATE(pvs);
	uint32_t			req_ne = sdesc->reqNumEntriesLog2;

	cmd->done = 0;
	cmd->expired = 0;

	mutex_enter(&pvs->lock);

	if ((sdesc->reqProdIdx - sdesc->cmpConsIdx) >= (1 << req_ne)) {
		mutex_exit(&pvs->lock);
		return (TRAN_BUSY);
	}

	rdesc = REQ_RING(pvs) + (sdesc->reqProdIdx & MASK(req_ne));

	rdesc->bus = 0;
	rdesc->target = cmd->target;
	bzero(rdesc->lun, sizeof (rdesc->lun));
	/* Matches other implementations; can pvscsi support luns > 255? */
	rdesc->lun[1] = cmd->lun & 0xff;

	bzero(cmd->arq_sense, sizeof (cmd->arq_sense));
	rdesc->context = cmd->ctx;
	rdesc->senseLen = sizeof (cmd->arq_sense);
	rdesc->senseAddr = cmd->arq_pa;
	rdesc->tag = cmd->tag;
	rdesc->vcpuHint = CPU->cpu_id;
	rdesc->cdbLen = cmd->cdblen;
	rdesc->flags = cmd->dma_dir;
	bcopy(cmd->cdb, rdesc->cdb, cmd->cdblen);
	pvscsi_map_buffers(cmd, rdesc);

	(void) ddi_dma_sync(pvs->req_ring_buf.dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	sdesc->reqProdIdx++;
	(void) ddi_dma_sync(pvs->state_buf.dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	pvscsi_add_to_queue(pvs, cmd);

	switch (cmd->cdb[0]) {
	case SCMD_READ:
	case SCMD_WRITE:
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
	case SCMD_READ_G4:
	case SCMD_WRITE_G4:
	case SCMD_READ_G5:
	case SCMD_WRITE_G5:
		pvscsi_submit_rw_io(pvs);
		break;
	default:
		pvscsi_submit_nonrw_io(pvs);
		break;
	}

	if (pvs->timeout == 0) {
		/* drivers above should supply, but give a default */
		pvs->timeout = timeout(pvscsi_timeout, pvs, pvscsi_hz * 8);
	}
	mutex_exit(&pvs->lock);

	return (TRAN_ACCEPT);
}

static int
pvscsi_setup_dma_buffer(pvscsi_softc_t *pvs, size_t length,
    pvscsi_dma_buf_t *buf)
{
	if ((ddi_dma_alloc_handle(pvs->dip, &pvscsi_dma_attr,
	    DDI_DMA_SLEEP, NULL, &buf->dmah)) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to alloc DMA handle");
		return (DDI_FAILURE);
	}

	if ((ddi_dma_mem_alloc(buf->dmah, length, &pvscsi_dma_attrs,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &buf->addr,
	    &length, &buf->acch)) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to alloc DMA memory");
		return (DDI_FAILURE);
	}

	if ((ddi_dma_addr_bind_handle(buf->dmah, NULL, buf->addr,
	    length, DDI_DMA_CONSISTENT | DDI_DMA_RDWR, DDI_DMA_SLEEP,
	    NULL, NULL, NULL)) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to bind DMA buffer");
		return (DDI_FAILURE);
	}

	buf->pa = ddi_dma_cookie_one(buf->dmah)->dmac_laddress;

	return (DDI_SUCCESS);
}

static void
pvscsi_free_dma_buffer(pvscsi_dma_buf_t *buf)
{
	if (buf->pa != 0) {
		(void) ddi_dma_unbind_handle(buf->dmah);
	}
	if (buf->acch != NULL) {
		ddi_dma_mem_free(&buf->acch);
	}
	if (buf->dmah != NULL) {
		ddi_dma_free_handle(&buf->dmah);
	}
}

static int
pvscsi_allocate_rings(pvscsi_softc_t *pvs)
{
	/* allocate DMA buffer for rings state */
	if (pvscsi_setup_dma_buffer(pvs, PAGE_SIZE, &pvs->state_buf) !=
	    DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* allocate DMA buffer for request ring */
	pvs->req_pages = MIN(pvscsi_ring_pages, PVSCSI_MAX_NUM_PAGES_REQ_RING);
	pvs->req_depth = pvs->req_pages * PVSCSI_MAX_NUM_REQ_ENTRIES_PER_PAGE;
	if (pvscsi_setup_dma_buffer(pvs, pvs->req_pages * PAGE_SIZE,
	    &pvs->req_ring_buf) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* allocate completion ring */
	pvs->cmp_pages = MIN(pvscsi_ring_pages, PVSCSI_MAX_NUM_PAGES_CMP_RING);
	if (pvscsi_setup_dma_buffer(pvs, pvs->cmp_pages * PAGE_SIZE,
	    &pvs->cmp_ring_buf) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* allocate message ring */
	pvs->msg_pages = MIN(pvscsi_msg_ring_pages,
	    PVSCSI_MAX_NUM_PAGES_MSG_RING);
	if (pvscsi_setup_dma_buffer(pvs, pvs->msg_pages * PAGE_SIZE,
	    &pvs->msg_ring_buf) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
pvscsi_free_rings(pvscsi_softc_t *pvs)
{
	pvscsi_free_dma_buffer(&pvs->msg_ring_buf);
	pvscsi_free_dma_buffer(&pvs->cmp_ring_buf);
	pvscsi_free_dma_buffer(&pvs->req_ring_buf);
	pvscsi_free_dma_buffer(&pvs->state_buf);
}

static void
pvscsi_setup_rings(pvscsi_softc_t *pvs)
{
	int		i;
	struct PVSCSICmdDescSetupMsgRing cmd_msg = { 0 };
	struct PVSCSICmdDescSetupRings cmd = { 0 };
	uint64_t	base;

	cmd.ringsStatePPN = pvs->state_buf.pa >> PAGE_SHIFT;
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

static int
pvscsi_enable_intrs(pvscsi_softc_t *pvs)
{
	int	i, rc, intr_caps;

	if ((rc = ddi_intr_get_cap(pvs->intr_handles[0], &intr_caps)) !=
	    DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to get interrupt caps");
		return (DDI_FAILURE);
	}

	if ((intr_caps & DDI_INTR_FLAG_BLOCK) != 0) {
		if ((rc = ddi_intr_block_enable(pvs->intr_handles,
		    pvs->intr_cnt)) != DDI_SUCCESS) {
			dev_err(pvs->dip, CE_WARN,
			    "!failed to enable interrupt block");
		}
	} else {
		for (i = 0; i < pvs->intr_cnt; i++) {
			if ((rc = ddi_intr_enable(pvs->intr_handles[i])) ==
			    DDI_SUCCESS)
				continue;
			dev_err(pvs->dip, CE_WARN,
			    "!failed to enable interrupt");
			while (--i >= 0)
				(void) ddi_intr_disable(pvs->intr_handles[i]);
			break;
		}
	}

	return (rc);
}

static uint32_t
pvscsi_intr(caddr_t arg1, caddr_t arg2)
{
	pvscsi_softc_t	*pvs = (pvscsi_softc_t *)arg1;
	uint32_t	status;
	pvscsi_cmd_t	*cmd;
	pvscsi_msg_t	*msg;
	uint32_t	rv = DDI_INTR_CLAIMED;
	_NOTE(ARGUNUSED(arg2));

	mutex_enter(&pvs->lock);
	status = pvscsi_read_intr_status(pvs);
	if ((status & PVSCSI_INTR_ALL_SUPPORTED) != 0) {
		pvscsi_write_intr_status(pvs, status);
	} else if (pvs->intr_type == DDI_INTR_TYPE_FIXED) {
		rv = DDI_INTR_UNCLAIMED;
	}
	if (pvs->detach) {
		mutex_exit(&pvs->lock);
		return (rv);
	}
	cmd = pvscsi_process_comp_ring(pvs);
	msg = pvscsi_process_msg_ring(pvs);

	/*
	 * Do this under the lock, so that we won't dispatch
	 * if we are detaching
	 */
	if (msg != NULL) {
		if (ddi_taskq_dispatch(pvs->tq, pvscsi_handle_msg, msg,
		    DDI_NOSLEEP) != DDI_SUCCESS) {
			dev_err(pvs->dip, CE_WARN,
			    "!failed to dispatch discovery");
		}
	}
	mutex_exit(&pvs->lock);

	pvscsi_complete_cmds(pvs, cmd);

	return (rv);
}

static void
pvscsi_free_intrs(pvscsi_softc_t *pvs)
{
	for (int i = 0; i < pvs->intr_cnt; i++) {
		(void) ddi_intr_disable(pvs->intr_handles[i]);
		(void) ddi_intr_remove_handler(pvs->intr_handles[i]);
		(void) ddi_intr_free(pvs->intr_handles[i]);
	}
	pvs->intr_cnt = 0;
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

	if (ddi_intr_alloc(pvs->dip, pvs->intr_handles, type, 0, navail,
	    &nactual, DDI_INTR_ALLOC_NORMAL) != DDI_SUCCESS || nactual == 0) {
		dev_err(pvs->dip, CE_WARN, "!failed to allocate %d interrupts",
		    navail);
		return (DDI_FAILURE);
	}

	pvs->intr_cnt = nactual;

	if (ddi_intr_get_pri(pvs->intr_handles[0], (uint_t *)&pvs->intr_pri) !=
	    DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to get interrupt priority");
		pvscsi_free_intrs(pvs);
		return (DDI_FAILURE);
	}

	for (i = 0; i < nactual; i++) {
		if (ddi_intr_add_handler(pvs->intr_handles[i], pvscsi_intr,
		    (caddr_t)pvs, NULL) != DDI_SUCCESS) {
			dev_err(pvs->dip, CE_WARN,
			    "!failed to add intr handler");
			pvscsi_free_intrs(pvs);
			return (DDI_FAILURE);
		}
	}

	pvs->intr_type = type;
	return (DDI_SUCCESS);
}

static int
pvscsi_setup_isr(pvscsi_softc_t *pvs)
{
	int	types;

	if (ddi_intr_get_supported_types(pvs->dip, &types) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to get interrupt types");
		return (DDI_FAILURE);
	}

	types &= pvscsi_intr_types;
	if (types == 0) {
		dev_err(pvs->dip, CE_WARN, "!no supported interrupt types");
		return (DDI_FAILURE);
	}


	if (((types & DDI_INTR_TYPE_MSIX) != 0) &&
	    (pvscsi_register_isr(pvs, DDI_INTR_TYPE_MSIX) == DDI_SUCCESS)) {
		return (DDI_SUCCESS);
	}
	if (((types & DDI_INTR_TYPE_MSI) != 0) &&
	    (pvscsi_register_isr(pvs, DDI_INTR_TYPE_MSI) == DDI_SUCCESS)) {
		return (DDI_SUCCESS);
	}
	if (((types & DDI_INTR_TYPE_FIXED) != 0) &&
	    (pvscsi_register_isr(pvs, DDI_INTR_TYPE_FIXED) == DDI_SUCCESS)) {
		return (DDI_SUCCESS);
	}

	dev_err(pvs->dip, CE_WARN, "!failed installing any interrupt handler");
	return (DDI_FAILURE);
}


static void
pvscsi_timeout(void *arg)
{
	pvscsi_softc_t	*pvs;
	pvscsi_cmd_t	*cmd;
	pvscsi_cmd_t	*reclaimed = NULL;
	list_t		*l;
	clock_t		now;

	pvs = arg;
	l = &pvs->cmd_queue;
	now = ddi_get_lbolt();

	mutex_enter(&pvs->lock);
	if (pvs->timeout == 0) {
		mutex_exit(&pvs->lock);
		return;
	}

	for (cmd = list_head(l); cmd != NULL; cmd = list_next(l, cmd)) {
		clock_t	overdue;

		/* polling takes care of it's own timeouts */
		if (cmd->poll) {
			continue;
		}

		overdue = now - (cmd->start + cmd->timeout);

		/*
		 * We keep the list of requests sorted by expiration
		 * time, so we hopefully won't need to walk through
		 * many of these.  This check is safe if lbolt wraps.
		 */
		if (overdue <= 0) {
			break;
		}

		/* first we try aborting */
		if (!cmd->expired) {
			atomic_or_8(&cmd->expired, 1);
			dev_err(pvs->dip, CE_WARN, "!cmd timed out (%lds)",
			    drv_hztousec(cmd->timeout)/1000000);
			continue;
		}

		/* if we're less than 2 seconds overdue, wait for abort */
		if (overdue <= pvscsi_hz * 2) {
			continue;
		}

		/* next it's a reset of the device */
		if (overdue <= pvscsi_hz * 8) {
			pvscsi_dev_reset(pvs, cmd->target, cmd->lun);
			break;
		}

		/* next it's a reset of the bus */
		if (overdue <= pvscsi_hz * 16) {
			pvscsi_reset_bus(pvs);
			break;
		}

		/* finally it's a reset of the entire adapter */
		dev_err(pvs->dip, CE_WARN, "!adapter hung? restarting...");
		mutex_enter(&pvs->lock);
		pvscsi_stop_hba(pvs);
		reclaimed = pvscsi_reclaim_cmds(pvs);
		pvscsi_start_hba(pvs);
		mutex_exit(&pvs->lock);
		break;
	}

	/* see if reset or abort completed anything */
	cmd = pvscsi_process_comp_ring(pvs);

	/* reschedule us if we still have requests pending */
	if (!list_is_empty(l)) {
		pvs->timeout = timeout(pvscsi_timeout, pvs, pvscsi_hz);
	}

	mutex_exit(&pvs->lock);

	/* if we had things that got completed, then do the callbacks */
	pvscsi_complete_cmds(pvs, reclaimed);
	pvscsi_complete_cmds(pvs, cmd);
}

static int
pvscsi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	pvscsi_cmd_t		*cmd = pkt->pkt_ha_private;
	struct scsi_device	*sd;
	pvscsi_device_t		*pd;
	pvscsi_softc_t		*pvs;
	int			rc;

	/* make sure the packet is sane */
	if ((pkt->pkt_numcookies > PVSCSI_MAX_SG_SIZE) ||
	    ((pkt->pkt_dma_flags & DDI_DMA_RDWR) == DDI_DMA_RDWR) ||
	    (pkt->pkt_cdblen > sizeof (cmd->cdb)) ||
	    ((sd = scsi_address_device(ap)) == NULL) ||
	    ((pd = scsi_device_hba_private_get(sd)) == NULL) ||
	    ((pvs = pd->pvs) == NULL))  {
		return (TRAN_BADPKT);
	}

	ASSERT(cmd->pkt == pkt);

	cmd->poll = ((pkt->pkt_flags & FLAG_NOINTR) != 0);

	if (pkt->pkt_flags & (FLAG_HTAG|FLAG_HEAD)) {
		cmd->tag = MSG_HEAD_QTAG;
	} else if (pkt->pkt_flags & FLAG_OTAG) {
		cmd->tag = MSG_ORDERED_QTAG;
	} else { /* also FLAG_STAG */
		cmd->tag = MSG_SIMPLE_QTAG;
	}

	bcopy(pkt->pkt_cdbp, cmd->cdb, pkt->pkt_cdblen);
	cmd->cdblen = pkt->pkt_cdblen;
	bzero(&cmd->cmd_scb, sizeof (cmd->cmd_scb));

	/*
	 * Reinitialize some fields because the packet may
	 * have been resubmitted.
	 */
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state = 0;
	pkt->pkt_statistics = 0;

	/* Zero status byte - but only if present */
	if (pkt->pkt_scblen > 0) {
		*(pkt->pkt_scbp) = 0;
	}

	if (pkt->pkt_numcookies > 0) {
		if (pkt->pkt_dma_flags & DDI_DMA_READ) {
			cmd->dma_dir = PVSCSI_FLAG_CMD_DIR_TOHOST;
		} else if (pkt->pkt_dma_flags & DDI_DMA_WRITE) {
			cmd->dma_dir = PVSCSI_FLAG_CMD_DIR_TODEVICE;
		} else {
			cmd->dma_dir = 0;
		}
	}

	cmd->target = pd->target;
	cmd->lun = pd->lun;
	cmd->start = ddi_get_lbolt();
	cmd->timeout = pkt->pkt_time * pvscsi_hz;

	rc = pvscsi_transport_command(pvs, cmd);

	if (cmd->poll && rc == TRAN_ACCEPT) {
		pvscsi_poll_cmd(pvs, cmd);
		pvscsi_set_status(pvs, cmd);
	}

	return (rc);
}


static int
pvscsi_parse_ua(const char *ua, int *target, int *lun)
{
	char *end;
	long num;
	if (((ddi_strtol(ua, &end, 16, &num)) != 0) ||
	    ((*end != ',') && (*end != 0))) {
		return (DDI_FAILURE);
	}
	*target = (int)num;
	if (*end == 0) {
		*lun = 0;
		return (DDI_SUCCESS);
	}
	end++;
	if ((ddi_strtol(end, &end, 16, &num) != 0) || (*end != 0)) {
		return (DDI_FAILURE);
	}
	*lun = (int)num;
	return (DDI_SUCCESS);
}

static uint32_t
pvscsi_max_targets(pvscsi_softc_t *pvs)
{
	pvscsi_dma_buf_t			db;
	struct PVSCSIConfigPageController	cpc;
	struct PVSCSICmdDescConfigCmd		cmd;

	bzero(&db, sizeof (db));

	/* NB: config pages fit in a single page */
	if (pvscsi_setup_dma_buffer(pvs, PAGE_SIZE, &db) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to setup config page DMA");
		return (PVSCSI_MAXTGTS);
	}

	bzero(&cmd, sizeof (cmd));
	cmd.configPageAddress = PVSCSI_CONFIG_CONTROLLER_ADDRESS;
	cmd.configPageAddress <<= 32;
	cmd.configPageNum = PVSCSI_CONFIG_PAGE_CONTROLLER;
	cmd.cmpAddr = db.pa;

	pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_CONFIG, &cmd, sizeof (cmd));
	(void) ddi_dma_sync(db.dmah, 0, 0, DDI_DMA_SYNC_FORKERNEL);
	bcopy(db.addr, &cpc, sizeof (cpc));
	pvscsi_free_dma_buffer(&db);


	if ((cpc.header.scsiStatus == STATUS_GOOD) &&
	    (cpc.header.hostStatus == BTSTAT_SUCCESS) &&
	    (cpc.numPhys > 0)) {
		return (cpc.numPhys);
	}

	dev_err(pvs->dip, CE_WARN, "!failed to determine max targets");
	return (PVSCSI_MAXTGTS);
}

static boolean_t
pvscsi_probe_target(pvscsi_softc_t *pvs, int target)
{
	pvscsi_cmd_t		cmd;

	if (!pvscsi_cmd_init(pvs, &cmd, KM_SLEEP)) {
		pvscsi_cmd_fini(&cmd);
		return (B_FALSE);
	}
	/* NB: CDB 0 is a TUR which is perfect for our needs */
	bzero(cmd.cdb, sizeof (cmd.cdb));
	cmd.poll = B_TRUE;
	cmd.dma_dir = 0;
	cmd.target = target;
	cmd.lun = 0;
	cmd.start = ddi_get_lbolt();
	cmd.timeout = pvscsi_hz;

	if (pvscsi_transport_command(pvs, &cmd) != TRAN_ACCEPT) {
		pvscsi_cmd_fini(&cmd);
		return (B_FALSE);
	}
	pvscsi_poll_cmd(pvs, &cmd);

	switch (cmd.host_status) {
	case BTSTAT_SUCCESS:
	case BTSTAT_LINKED_COMMAND_COMPLETED:
	case BTSTAT_LINKED_COMMAND_COMPLETED_WITH_FLAG:
		/* We don't care about the actual SCSI status */
		pvscsi_cmd_fini(&cmd);
		return (B_TRUE);
	}

	pvscsi_cmd_fini(&cmd);
	return (B_FALSE);
}

static int
pvscsi_tgt_init(dev_info_t *dip, dev_info_t *child, scsi_hba_tran_t *tran,
    struct scsi_device *sd)
{
	/*
	 * Assumption: the HBA framework only asks us to have a single
	 * target initialized per address at any given time.
	 */
	pvscsi_device_t	*pd;
	pvscsi_softc_t	*pvs;
	const char	*ua;

	if (((scsi_hba_iport_unit_address(dip)) == NULL) ||
	    ((pvs = tran->tran_hba_private) == NULL) ||
	    ((ua = scsi_device_unit_address(sd)) == NULL)) {
		return (DDI_FAILURE);
	}

	/* parse the unit address */
	pd = kmem_zalloc(sizeof (*pd), KM_SLEEP);
	if (pvscsi_parse_ua(ua, &pd->target, &pd->lun) != DDI_SUCCESS) {
		kmem_free(pd, sizeof (*pd));
		return (DDI_FAILURE);
	}
	pd->pvs = pvs;
	scsi_device_hba_private_set(sd, pd);

	mutex_enter(&pvs->lock);
	list_insert_tail(&pvs->devices, pd);
	mutex_exit(&pvs->lock);
	return (DDI_SUCCESS);
}

static void
pvscsi_tgt_free(dev_info_t *dip, dev_info_t *child, scsi_hba_tran_t *tran,
    struct scsi_device *sd)
{
	pvscsi_device_t	*pd;
	pvscsi_softc_t	*pvs;

	if (((scsi_hba_iport_unit_address(dip)) == NULL) ||
	    ((pvs = tran->tran_hba_private) == NULL) ||
	    ((pd = scsi_device_hba_private_get(sd)) == NULL)) {
		return;
	}
	scsi_device_hba_private_set(sd, NULL);
	mutex_enter(&pvs->lock);
	list_remove(&pvs->devices, pd);
	mutex_exit(&pvs->lock);

	kmem_free(pd, sizeof (*pd));
}

static int
pvscsi_reset(struct scsi_address *ap, int level)
{
	struct scsi_device	*sd;
	pvscsi_device_t		*pd;
	pvscsi_softc_t		*pvs;
	pvscsi_cmd_t		*cmd;

	if (((sd = scsi_address_device(ap)) == NULL) ||
	    ((pd = scsi_device_hba_private_get(sd)) == NULL) ||
	    ((pvs = pd->pvs) == NULL))  {
		return (0);
	}
	switch (level) {
	case RESET_ALL:
	case RESET_BUS:
		pvscsi_reset_bus(pvs);
		break;
	case RESET_TARGET:
		/* reset both the lun and lun 0 */
		pvscsi_dev_reset(pvs, pd->target, pd->lun);
		pvscsi_dev_reset(pvs, pd->target, 0);
		break;
	case RESET_LUN:
		pvscsi_dev_reset(pvs, pd->target, pd->lun);
		break;
	default:
		return (0);
	}

	/* reset may have caused some completions */
	mutex_enter(&pvs->lock);
	cmd = pvscsi_process_comp_ring(pvs);
	mutex_exit(&pvs->lock);

	pvscsi_complete_cmds(pvs, cmd);
	return (1);
}

static int
pvscsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct scsi_device	*sd;
	pvscsi_device_t		*pd;
	pvscsi_softc_t		*pvs;
	pvscsi_cmd_t		*cmd;

	if (pkt != NULL) {
		/* abort single command */
		cmd = pkt->pkt_ha_private;
		pvs = cmd->pvs;
		pvscsi_abort_cmd(pvs, cmd);
	} else if ((ap != NULL) &&
	    ((sd = scsi_address_device(ap)) != NULL) &&
	    ((pd = scsi_device_hba_private_get(sd)) != NULL) &&
	    ((pvs = pd->pvs) != NULL)) {
		/* abort all commands on the bus */
		pvscsi_abort_all(pvs, pd);
	} else {
		return (0);
	}

	/* abort may have caused some completions */
	mutex_enter(&pvs->lock);
	cmd = pvscsi_process_comp_ring(pvs);
	mutex_exit(&pvs->lock);

	pvscsi_complete_cmds(pvs, cmd);

	return (1);
}

static int
pvscsi_getcap(struct scsi_address *ap, char *cap, int whom)
{
	_NOTE(ARGUNUSED(ap));
	_NOTE(ARGUNUSED(whom));

	if (cap == NULL) {
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
		return (1);
	default:
		return (-1);
	}
}

static int
pvscsi_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	_NOTE(ARGUNUSED(ap));
	_NOTE(ARGUNUSED(value));
	_NOTE(ARGUNUSED(whom));

	if (cap == NULL) {
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
		return (0); /* not changeable */
	default:
		return (-1);
	}
}

static void
pvscsi_cmd_fini(pvscsi_cmd_t *cmd)
{
	if (cmd->arq_pa != 0) {
		(void) ddi_dma_unbind_handle(cmd->arq_dmah);
		cmd->arq_dmah = NULL;
	}
	if (cmd->arq_dmah != NULL) {
		ddi_dma_free_handle(&cmd->arq_dmah);
		cmd->arq_dmah = NULL;
	}
	if (cmd->sgl_pa != 0) {
		(void) ddi_dma_unbind_handle(cmd->sgl_dmah);
		cmd->sgl_pa = 0;
	}
	if (cmd->sgl_acch != NULL) {
		ddi_dma_mem_free(&cmd->sgl_acch);
		cmd->sgl_acch = NULL;
		cmd->sgl = NULL;
	}
	if (cmd->sgl_dmah != NULL) {
		ddi_dma_free_handle(&cmd->sgl_dmah);
		cmd->sgl_dmah = NULL;
	}
	if (cmd->ctx != 0) {
		id32_free(cmd->ctx);
		cmd->ctx = 0;
	}
}

static void
pvscsi_pkt_dtor(struct scsi_pkt *pkt, scsi_hba_tran_t *tran)
{
	pvscsi_cmd_t	*cmd = pkt->pkt_ha_private;
	pvscsi_cmd_fini(cmd);
}

static boolean_t
pvscsi_cmd_init(pvscsi_softc_t *pvs, pvscsi_cmd_t *cmd, int sleep)
{
	int		(*cb)(caddr_t);
	size_t		len;
	caddr_t		kaddr;

	cb = sleep == KM_SLEEP ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;

	bzero(cmd, sizeof (*cmd));
	cmd->ctx = id32_alloc(cmd, sleep);
	if (cmd->ctx == 0) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to allocate 32-bit context id");
		return (B_FALSE);
	}

	/* allocate DMA resources for scatter/gather list */
	if (ddi_dma_alloc_handle(pvs->dip, &pvscsi_dma_attr, cb, NULL,
	    &cmd->sgl_dmah) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to allocate DMA handle for SG list");
		return (B_FALSE);
	}
	if (ddi_dma_mem_alloc(cmd->sgl_dmah, PAGE_SIZE, &pvscsi_dma_attrs,
	    DDI_DMA_CONSISTENT, cb, NULL, &kaddr, &len, &cmd->sgl_acch) !=
	    DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to allocate DMA memory for SG list");
		return (B_FALSE);
	}
	cmd->sgl = (void *)kaddr;
	if (ddi_dma_addr_bind_handle(cmd->sgl_dmah, NULL, kaddr,
	    PAGE_SIZE, DDI_DMA_WRITE | DDI_DMA_CONSISTENT, cb, NULL,
	    NULL, NULL) != DDI_DMA_MAPPED) {
		dev_err(pvs->dip, CE_WARN, "!failed to bind SGL list");
		return (B_FALSE);
	}
	cmd->sgl_pa = ddi_dma_cookie_one(cmd->sgl_dmah)->dmac_laddress;

	/* allocate DMA resource for auto-sense-request */
	if (ddi_dma_alloc_handle(pvs->dip, &pvscsi_dma_attr,
	    cb, NULL, &cmd->arq_dmah) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN,
		    "!failed to allocate DMA handle for ARQ buffer");
		return (B_FALSE);
	}

	if (ddi_dma_addr_bind_handle(cmd->arq_dmah, NULL,
	    (void *)cmd->arq_sense, SENSE_LENGTH,
	    DDI_DMA_READ | DDI_DMA_CONSISTENT, cb, NULL,
	    NULL, NULL) != DDI_DMA_MAPPED) {
		dev_err(pvs->dip, CE_WARN, "!failed to bind ARQ buffer");
		return (B_FALSE);
	}
	cmd->arq_pa = ddi_dma_cookie_one(cmd->arq_dmah)->dmac_laddress;
	return (B_TRUE);
}

static int
pvscsi_pkt_ctor(struct scsi_pkt *pkt, scsi_hba_tran_t *tran, int sleep)
{
	pvscsi_cmd_t	*cmd = pkt->pkt_ha_private;
	pvscsi_softc_t	*pvs = tran->tran_hba_private;

	if (!pvscsi_cmd_init(pvs, cmd, sleep)) {
		pvscsi_pkt_dtor(pkt, tran);
		return (-1);
	}
	cmd->pkt = pkt;
	return (0);
}

static void
pvscsi_teardown_pkt(struct scsi_pkt *pkt)
{
	_NOTE(ARGUNUSED(pkt));
	/* nothing to do */
}

static int
pvscsi_setup_pkt(struct scsi_pkt *pkt, int (*cb)(caddr_t), caddr_t arg)
{
	/* all work is done in start */
	return (0);
}

static int
pvscsi_hba_setup(pvscsi_softc_t *pvs)
{
	scsi_hba_tran_t	*tran;

	tran = scsi_hba_tran_alloc(pvs->dip, SCSI_HBA_CANSLEEP);
	ASSERT(tran != NULL);

	tran->tran_hba_private = pvs;
	tran->tran_start = pvscsi_start;
	tran->tran_reset = pvscsi_reset;
	tran->tran_abort = pvscsi_abort;
	tran->tran_getcap = pvscsi_getcap;
	tran->tran_setcap = pvscsi_setcap;
	tran->tran_pkt_constructor = pvscsi_pkt_ctor;
	tran->tran_pkt_destructor = pvscsi_pkt_dtor;
	tran->tran_setup_pkt = pvscsi_setup_pkt;
	tran->tran_teardown_pkt = pvscsi_teardown_pkt;
	tran->tran_tgt_init = pvscsi_tgt_init;
	tran->tran_tgt_free = pvscsi_tgt_free;
	tran->tran_hba_len = sizeof (pvscsi_cmd_t);

	tran->tran_interconnect_type = INTERCONNECT_PARALLEL;

	if (scsi_hba_attach_setup(pvs->dip, &pvscsi_io_dma_attr, tran,
	    SCSI_HBA_HBA | SCSI_HBA_TRAN_CDB | SCSI_HBA_TRAN_SCB |
	    SCSI_HBA_ADDR_COMPLEX) !=
	    DDI_SUCCESS) {
		scsi_hba_tran_free(tran);
		dev_err(pvs->dip, CE_WARN, "!failed to attach HBA");
		return (DDI_FAILURE);
	}

	pvs->tran = tran;
	return (DDI_SUCCESS);
}

static void
pvscsi_teardown(pvscsi_softc_t *pvs)
{
	timeout_id_t	tid;

	pvscsi_stop_hba(pvs);

	if (pvs->tq != NULL) {
		ddi_taskq_destroy(pvs->tq);
	}
	mutex_enter(&pvs->lock);
	tid = pvs->timeout;
	pvs->timeout = 0;
	mutex_exit(&pvs->lock);

	if (tid != 0) {
		(void) untimeout(tid);
	}

	pvscsi_free_intrs(pvs);
	pvscsi_free_rings(pvs);

	if (pvs->mmio_handle != NULL) {
		ddi_regs_map_free(&pvs->mmio_handle);
	}

	if (pvs->tran != NULL) {
		scsi_hba_tran_free(pvs->tran);
	}
	mutex_destroy(&pvs->lock);
	list_destroy(&pvs->cmd_queue);
	list_destroy(&pvs->devices);

	kmem_free(pvs, sizeof (*pvs));
}

static int
pvscsi_iport_attach(dev_info_t *dip)
{
	scsi_hba_tran_t	*tran;
	dev_info_t	*parent;
	pvscsi_softc_t	*pvs;
	char		*ua;
	uint32_t	max_targets;

	if (((parent = ddi_get_parent(dip)) == NULL) ||
	    ((tran = ddi_get_driver_private(parent)) == NULL) ||
	    ((pvs = tran->tran_hba_private) == NULL) ||
	    ((ua = scsi_hba_iport_unit_address(dip)) == NULL) ||
	    (strcmp(ua, "iport0") != 0)) {
		return (DDI_FAILURE);
	}

	/* store our softc on the iport private tran */
	tran = ddi_get_driver_private(dip);
	tran->tran_hba_private = pvs;

	/* setup the target map - allow 100ms for settle / sync times */
	if (scsi_hba_tgtmap_create(dip, SCSI_TM_PERADDR, 100000,
	    100000, pvs, NULL, NULL, &pvs->tgtmap) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to create target map");
		return (DDI_FAILURE);
	}

	/* reset hardware and setup the rings */
	mutex_enter(&pvs->lock);
	pvs->detach = B_FALSE; /* in case of reattach */
	pvscsi_start_hba(pvs);

	max_targets = pvs->max_targets = pvscsi_max_targets(pvs);
	mutex_exit(&pvs->lock);

	for (uint32_t i = 0; i < max_targets; i++) {
		char addr[8];
		if (pvscsi_probe_target(pvs, i)) {
			(void) snprintf(addr, sizeof (addr), "%x", i);
			(void) scsi_hba_tgtmap_tgt_add(pvs->tgtmap,
			    SCSI_TGT_SCSI_DEVICE, addr, NULL);
		}
	}

	return (DDI_SUCCESS);
}

static int
pvscsi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	pvscsi_softc_t	*pvs;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (pvscsi_iport_attach(dip));
	}

	pvs = kmem_zalloc(sizeof (*pvs), KM_SLEEP);

	/* Setup HBA instance */
	pvs->dip = dip;

	/*
	 * mutex initialization - note that we always run below
	 * lock level, so we can get by without interrupt priorities
	 */
	mutex_init(&pvs->lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&pvs->cmd_queue, sizeof (pvscsi_cmd_t),
	    offsetof(pvscsi_cmd_t, queue_node));
	list_create(&pvs->devices, sizeof (pvscsi_device_t),
	    offsetof(pvscsi_device_t, node));

	if ((pvscsi_setup_io(pvs)) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to setup I/O region");
		pvscsi_teardown(pvs);
		return (DDI_FAILURE);
	}

	pvscsi_stop_hba(pvs);

	if ((pvscsi_allocate_rings(pvs)) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to allocate DMA rings");
		pvscsi_teardown(pvs);
		return (DDI_FAILURE);
	}

	if (pvscsi_setup_isr(pvs) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to setup ISR");
		pvscsi_teardown(pvs);
		return (DDI_FAILURE);
	}

	/* enable interrupts */
	if (pvscsi_enable_intrs(pvs) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to enable interrupts");
		pvscsi_teardown(pvs);
		return (DDI_FAILURE);
	}

	pvs->tq = ddi_taskq_create(dip, "iport", 1, TASKQ_DEFAULTPRI, 0);
	if (pvs->tq == NULL) {
		dev_err(pvs->dip, CE_WARN, "!failed creating tq");
		pvscsi_teardown(pvs);
		return (DDI_FAILURE);
	}
	if (pvscsi_hba_setup(pvs) != DDI_SUCCESS) {
		dev_err(pvs->dip, CE_WARN, "!failed to setup HBA");
		pvscsi_teardown(pvs);
		return (DDI_FAILURE);
	}

	if (scsi_hba_iport_register(dip, "iport0") != 0) {
		dev_err(pvs->dip, CE_WARN, "failed to register iport");
		/* detach cannot fail since we didn't setup the iport */
		(void) scsi_hba_detach(dip);
		pvscsi_teardown(pvs);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
pvscsi_iport_detach(dev_info_t *dip)
{
	pvscsi_softc_t	*pvs;
	scsi_hba_tran_t	*tran;
	const char	*ua;
	pvscsi_cmd_t	*reclaimed;

	if (((ua = scsi_hba_iport_unit_address(dip)) == NULL) ||
	    (strcmp(ua, "iport0") != 0) ||
	    ((tran = ddi_get_driver_private(dip)) == NULL) ||
	    ((pvs = tran->tran_hba_private) == NULL)) {
		return (DDI_FAILURE);
	}

	/* stop the HBA */
	mutex_enter(&pvs->lock);
	pvs->detach = B_TRUE;
	pvscsi_stop_hba(pvs);
	mutex_exit(&pvs->lock);

	/* drain the taskq - nothing else will post to it */
	ddi_taskq_wait(pvs->tq);

	/* reset the HBA */
	mutex_enter(&pvs->lock);
	reclaimed = pvscsi_reclaim_cmds(pvs);
	mutex_exit(&pvs->lock);

	/*
	 * If we had any commands, complete them so we can
	 * reclaim the resources.  There really should not be any.
	 */
	pvscsi_complete_cmds(pvs, reclaimed);

	scsi_hba_tgtmap_destroy(pvs->tgtmap);
	pvs->tgtmap = NULL;

	return (DDI_SUCCESS);
}

static int
pvscsi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	pvscsi_softc_t	*pvs;
	scsi_hba_tran_t	*tran;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (pvscsi_iport_detach(dip));
	}

	if (((tran = ddi_get_driver_private(dip)) == NULL) ||
	    ((pvs = tran->tran_hba_private) == NULL)) {
		/* this can only mean we aren't attached yet */
		return (DDI_SUCCESS);
	}
	if (scsi_hba_detach(dip) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	pvscsi_teardown(pvs);

	return (DDI_SUCCESS);
}

static int
pvscsi_quiesce(dev_info_t *dip)
{
	scsi_hba_tran_t	*tran;
	pvscsi_softc_t	*pvs;

	if (((tran = ddi_get_driver_private(dip)) == NULL) ||
	    ((pvs = tran->tran_hba_private) == NULL)) {
		return (DDI_SUCCESS);
	}

	pvscsi_stop_hba(pvs);

	return (DDI_SUCCESS);
}

static struct dev_ops pvscsi_ops = {
	.devo_rev =	DEVO_REV,
	.devo_refcnt =	0,
	.devo_getinfo =	nodev,
	.devo_identify = nulldev,
	.devo_probe =	nulldev,
	.devo_attach =	pvscsi_attach,
	.devo_detach =	pvscsi_detach,
	.devo_reset =	nodev,
	.devo_cb_ops =	NULL,
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

	/* get HZ - DDI compliant */
	pvscsi_hz = drv_usectohz(1000000);

	if ((ret = scsi_hba_init(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "!scsi_hba_init() failed");
		return (ret);
	}

	if ((ret = mod_install(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "!mod_install() failed");
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
		scsi_hba_fini(&modlinkage);
	}

	return (ret);
}
