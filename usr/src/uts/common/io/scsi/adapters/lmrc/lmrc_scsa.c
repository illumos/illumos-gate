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
 * Copyright 2024 Racktop Systems, Inc.
 */

/*
 * This file implements the basic HBA interface to SCSAv3.
 *
 * For target initialization, we'll look up the driver target state by the
 * device address and set it as HBA private in the struct scsi_device.
 *
 * The tran_reset(9e) and tran_abort(9e) entry points are implemented by a
 * common function that sends the appropriate task management request to the
 * target, iff the target supports task management requests. There is no support
 * for bus resets. The case of RESET_ALL is special: sd(4d) issues a RESET_ALL
 * in sddump() and errors out if that fails, so even if task management is
 * unsupported by a target or the reset fails for any other reason, we return
 * success. Any I/O errors due to an unsuccessful reset will be caught later.
 *
 * The tran_start(9e) code paths are almost identical for physical and logical
 * devices, the major difference being that PDs will have the DevHandle in the
 * MPT I/O frame set to the invalid DevHandle (0xffff), while LDs will use the
 * target ID. Also, special settings are applied for LDs and PDs in the RAID
 * context (VendorRegion of the MPT I/O frame). There is no support for fastpath
 * I/O.
 *
 * In tran_setup_pkt(9e), a MPT command is allocated for the scsi_pkt, and its
 * members are initialized as follows:
 * - pkt_cdbp will point to the CDB structure embedded in the MPT I/O frame
 * - pkt_scbp will point to the struct scsi_arq_status in the sense DMA memory
 *   allocated for the MPT command
 * - pkt_scblen will be set to the size of the sense DMA memory, minus alignment
 * - SenseBufferLowAddress and SenseBufferLength in the MPT I/O frame will be
 *   set to the sense DMA address and length, respectively, adjusted to account
 *   for the space needed for the ARQ pkt and alignment.
 * - There is no SenseBufferHighAddress.
 * - rc_timeout is set to pkt_time, but it is unknown if that has any effect
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>

#include "lmrc.h"
#include "lmrc_reg.h"

static int lmrc_getcap(struct scsi_address *, char *, int);
static int lmrc_setcap(struct scsi_address *, char *, int, int);

static int lmrc_tran_tgt_init(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);
static void lmrc_tran_tgt_free(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);

static int lmrc_tran_abort(struct scsi_address *, struct scsi_pkt *);
static int lmrc_tran_reset(struct scsi_address *, int);

static int lmrc_tran_setup_pkt(struct scsi_pkt *, int (*)(caddr_t), caddr_t);
static void lmrc_tran_teardown_pkt(struct scsi_pkt *);

boolean_t lmrc_relaxed_ordering = B_TRUE;

static int
lmrc_getcap(struct scsi_address *sa, char *cap, int whom)
{
	struct scsi_device *sd = scsi_address_device(sa);
	lmrc_tgt_t *tgt = scsi_device_hba_private_get(sd);
	lmrc_t *lmrc = tgt->tgt_lmrc;
	int index;

	VERIFY(lmrc != NULL);

	if ((index = scsi_hba_lookup_capstr(cap)) == DDI_FAILURE)
		return (-1);

	switch (index) {
	case SCSI_CAP_CDB_LEN:
		return (sizeof (((Mpi25SCSIIORequest_t *)NULL)->CDB.CDB32));

	case SCSI_CAP_DMA_MAX:
		if (lmrc->l_dma_attr.dma_attr_maxxfer > INT_MAX)
			return (INT_MAX);
		return (lmrc->l_dma_attr.dma_attr_maxxfer);

	case SCSI_CAP_SECTOR_SIZE:
		if (lmrc->l_dma_attr.dma_attr_granular > INT_MAX)
			return (INT_MAX);
		return (lmrc->l_dma_attr.dma_attr_granular);

	case SCSI_CAP_INTERCONNECT_TYPE: {
		uint8_t interconnect_type;

		rw_enter(&tgt->tgt_lock, RW_READER);
		interconnect_type = tgt->tgt_interconnect_type;
		rw_exit(&tgt->tgt_lock);
		return (interconnect_type);
	}
	case SCSI_CAP_MSG_OUT:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_PARITY:
	case SCSI_CAP_ARQ:
		return (1);

	case SCSI_CAP_RESET_NOTIFICATION:
	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_LINKED_CMDS:
	case SCSI_CAP_INITIATOR_ID:
		return (0);

	default:
		return (-1);
	}
}

static int
lmrc_setcap(struct scsi_address *sa, char *cap, int value, int whom)
{
	struct scsi_device *sd = scsi_address_device(sa);
	lmrc_tgt_t *tgt = scsi_device_hba_private_get(sd);
	lmrc_t *lmrc = tgt->tgt_lmrc;
	int index;

	VERIFY(lmrc != NULL);

	if ((index = scsi_hba_lookup_capstr(cap)) == DDI_FAILURE)
		return (-1);

	if (whom == 0)
		return (-1);

	switch (index) {
	case SCSI_CAP_DMA_MAX:
		if (value <= lmrc->l_dma_attr.dma_attr_maxxfer)
			return (1);
		else
			return (0);

	case SCSI_CAP_MSG_OUT:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_PARITY:
	case SCSI_CAP_ARQ:
		if (value == 1)
			return (1);
		else
			return (0);

	case SCSI_CAP_RESET_NOTIFICATION:
	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_LINKED_CMDS:
	case SCSI_CAP_INITIATOR_ID:
		if (value == 0)
			return (1);
		else
			return (0);

	case SCSI_CAP_SECTOR_SIZE:
	case SCSI_CAP_TOTAL_SECTORS:
		return (0);

	default:
		return (-1);
	}
}

/*
 * lmrc_tran_tgt_init
 *
 * Find the driver target state and link it with the scsi_device.
 */
static int
lmrc_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	lmrc_t *lmrc = hba_tran->tran_hba_private;
	lmrc_tgt_t *tgt;

	VERIFY(lmrc != NULL);

	tgt = lmrc_tgt_find(lmrc, sd);
	if (tgt == NULL)
		return (DDI_FAILURE);

	/* lmrc_tgt_find() returns the target read-locked. */
	scsi_device_hba_private_set(sd, tgt);
	rw_exit(&tgt->tgt_lock);


	return (DDI_SUCCESS);
}

static void
lmrc_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	scsi_device_hba_private_set(sd, NULL);
}

/*
 * lmrc_tran_start
 *
 * Start I/O of a scsi_pkt. Set up the MPT frame, the RAID context and if
 * necessary the SGL for the transfer. Wait for a reply if this is polled I/O.
 *
 * There are subtle differences in the way I/O is done for LDs and PDs.
 *
 * There is no support for fastpath I/O.
 */
static int
lmrc_tran_start(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	Mpi25SCSIIORequest_t *io_req;
	lmrc_atomic_req_desc_t req_desc;
	lmrc_raidctx_g35_t *rc;
	struct scsi_device *sd;
	lmrc_scsa_cmd_t *cmd;
	lmrc_mpt_cmd_t *mpt;
	lmrc_tgt_t *tgt;
	lmrc_t *lmrc;
	uint8_t req_flags = MPI2_REQ_DESCRIPT_FLAGS_SCSI_IO;
	boolean_t intr = (pkt->pkt_flags & FLAG_NOINTR) == 0;
	int ret = TRAN_BADPKT;

	/*
	 * FLAG_NOINTR was set but we're not panicked. This may theoretically
	 * happen if scsi_transport() is called from an interrupt thread, and
	 * we don't support this.
	 */
	if (!intr && !ddi_in_panic())
		return (ret);

	sd = scsi_address_device(sa);
	VERIFY(sd != NULL);

	tgt = scsi_device_hba_private_get(sd);
	VERIFY(tgt != NULL);

	cmd = pkt->pkt_ha_private;
	VERIFY(cmd != NULL);

	VERIFY(cmd->sc_tgt == tgt);

	lmrc = tgt->tgt_lmrc;
	VERIFY(lmrc != NULL);

	if (lmrc->l_fw_fault)
		return (TRAN_FATAL_ERROR);

	if (atomic_inc_uint_nv(&lmrc->l_fw_outstanding_cmds) >
	    lmrc->l_max_scsi_cmds) {
		atomic_dec_uint(&lmrc->l_fw_outstanding_cmds);
		return (TRAN_BUSY);
	}

	rw_enter(&tgt->tgt_lock, RW_READER);

	mpt = cmd->sc_mpt;
	VERIFY(mpt != NULL);
	mutex_enter(&mpt->mpt_lock);

	io_req = mpt->mpt_io_frame;

	io_req->Function = LMRC_MPI2_FUNCTION_LD_IO_REQUEST;

	rc = &io_req->VendorRegion;
	rc->rc_ld_tgtid = tgt->tgt_dev_id;

	if (tgt->tgt_pd_info == NULL) {
		/* This is LD I/O */
		io_req->DevHandle = tgt->tgt_dev_id;

		if (lmrc_cmd_is_rw(pkt->pkt_cdbp[0])) {
			rc->rc_type = MPI2_TYPE_CUDA;
			rc->rc_nseg = 1;
			rc->rc_routing_flags.rf_sqn = 1;
		}
	} else {
		/* This is PD I/O */
		io_req->DevHandle = LMRC_DEVHDL_INVALID;
		rc->rc_raid_flags.rf_io_subtype = LMRC_RF_IO_SUBTYPE_SYSTEM_PD;

		if (tgt->tgt_type == DTYPE_DIRECT &&
		    lmrc->l_use_seqnum_jbod_fp) {
			lmrc_pd_cfg_t *pdcfg;

			rw_enter(&lmrc->l_pdmap_lock, RW_READER);
			pdcfg = &lmrc->l_pdmap->pm_pdcfg[tgt->tgt_dev_id];

			if (lmrc->l_pdmap_tgtid_support)
				rc->rc_ld_tgtid = pdcfg->pd_tgtid;

			rc->rc_cfg_seqnum = pdcfg->pd_seqnum;
			io_req->DevHandle = pdcfg->pd_devhdl;
			rw_exit(&lmrc->l_pdmap_lock);

			if (lmrc_cmd_is_rw(pkt->pkt_cdbp[0])) {
				/*
				 * MPI2_TYPE_CUDA is valid only if FW supports
				 * JBOD Sequence number
				 */
				rc->rc_type = MPI2_TYPE_CUDA;
				rc->rc_nseg = 1;
				rc->rc_routing_flags.rf_sqn = 1;

				io_req->Function =
				    MPI2_FUNCTION_SCSI_IO_REQUEST;
				io_req->IoFlags |=
				    MPI25_SAS_DEVICE0_FLAGS_ENABLED_FAST_PATH;
				req_flags =
				    MPI25_REQ_DESCRIPT_FLAGS_FAST_PATH_SCSI_IO;
			}
		}

	}

	if (pkt->pkt_numcookies > 0) {
		if ((pkt->pkt_dma_flags & DDI_DMA_READ) != 0)
			io_req->Control |= MPI2_SCSIIO_CONTROL_READ;

		if ((pkt->pkt_dma_flags & DDI_DMA_WRITE) != 0)
			io_req->Control |= MPI2_SCSIIO_CONTROL_WRITE;

		lmrc_dma_build_sgl(lmrc, mpt, pkt->pkt_cookies,
		    pkt->pkt_numcookies);

		io_req->DataLength = pkt->pkt_dma_len;

		rc->rc_num_sge = pkt->pkt_numcookies;
	}

	VERIFY3S(ddi_dma_sync(lmrc->l_ioreq_dma.ld_hdl,
	    (void *)io_req - lmrc->l_ioreq_dma.ld_buf,
	    LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE, DDI_DMA_SYNC_FORDEV),
	    ==, DDI_SUCCESS);

	req_desc = lmrc_build_atomic_request(lmrc, mpt, req_flags);

	mpt->mpt_timeout = gethrtime() + pkt->pkt_time * NANOSEC;
	lmrc_send_atomic_request(lmrc, req_desc);

	if (intr) {
		/* normal interrupt driven I/O processing */
		lmrc_tgt_add_active_mpt(tgt, mpt);
		ret = TRAN_ACCEPT;
	} else {
		/* FLAG_NOINTR was set and we're panicked */
		VERIFY(ddi_in_panic());

		ret = lmrc_poll_for_reply(lmrc, mpt);
		atomic_dec_uint(&lmrc->l_fw_outstanding_cmds);
	}

	mutex_exit(&mpt->mpt_lock);
	rw_exit(&tgt->tgt_lock);

	return (ret);
}

/*
 * lmrc_task_mgmt
 *
 * Send a TASK MGMT command to a target, provied it is TM capable.
 */
static int
lmrc_task_mgmt(lmrc_t *lmrc, lmrc_tgt_t *tgt, uint8_t type, uint16_t smid)
{
	Mpi2SCSITaskManagementRequest_t *tm_req;
	Mpi2SCSITaskManagementReply_t *tm_reply;
	uint64_t *pd_ld_flags;
	lmrc_atomic_req_desc_t req_desc;
	lmrc_mpt_cmd_t *mpt;
	clock_t ret;
	boolean_t tm_capable;

	rw_enter(&tgt->tgt_lock, RW_READER);

	/* Make sure the target can handle task mgmt commands. */
	if (tgt->tgt_pd_info == NULL) {
		tm_capable = lmrc_ld_tm_capable(lmrc, tgt->tgt_dev_id);
	} else {
		tm_capable = lmrc_pd_tm_capable(lmrc, tgt->tgt_dev_id);
	}

	if (!tm_capable) {
		rw_exit(&tgt->tgt_lock);
		return (0);
	}

	if (atomic_inc_uint_nv(&lmrc->l_fw_outstanding_cmds) >
	    lmrc->l_max_scsi_cmds) {
		rw_exit(&tgt->tgt_lock);
		atomic_dec_uint(&lmrc->l_fw_outstanding_cmds);
		return (0);
	}

	mpt = lmrc_get_mpt(lmrc);
	if (mpt == NULL) {
		rw_exit(&tgt->tgt_lock);
		atomic_dec_uint(&lmrc->l_fw_outstanding_cmds);
		return (0);
	}
	ASSERT(mutex_owned(&mpt->mpt_lock));


	bzero(mpt->mpt_io_frame, LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE);
	tm_req = mpt->mpt_io_frame;
	tm_reply = mpt->mpt_io_frame + 128;
	pd_ld_flags = (uint64_t *)tm_reply;


	tm_req->Function = MPI2_FUNCTION_SCSI_TASK_MGMT;
	tm_req->TaskType = type;
	tm_req->TaskMID = smid;
	tm_req->DevHandle = tgt->tgt_dev_id;

	/*
	 * The uint32_t immediately following the MPI2 task management request
	 * contains two flags indicating whether the target is a LD or PD.
	 */
	if (tgt->tgt_pd_info == NULL)
		*pd_ld_flags = 1<<0;
	else
		*pd_ld_flags = 1<<1;

	VERIFY3S(ddi_dma_sync(lmrc->l_ioreq_dma.ld_hdl,
	    (void *)tm_req - lmrc->l_ioreq_dma.ld_buf,
	    LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE, DDI_DMA_SYNC_FORDEV),
	    ==, DDI_SUCCESS);

	req_desc = lmrc_build_atomic_request(lmrc, mpt,
	    MPI2_REQ_DESCRIPT_FLAGS_HIGH_PRIORITY);

	lmrc_send_atomic_request(lmrc, req_desc);

	/* Poll for completion if we're called while the system is panicked. */
	if (ddi_in_panic()) {
		ret = lmrc_poll_for_reply(lmrc, mpt);
	} else {
		clock_t timeout = drv_usectohz(LMRC_RESET_WAIT_TIME * MICROSEC);

		timeout += ddi_get_lbolt();
		do {
			ret = cv_timedwait(&mpt->mpt_cv, &mpt->mpt_lock,
			    timeout);
		} while (mpt->mpt_complete == B_FALSE && ret != -1);
	}

	atomic_dec_uint(&lmrc->l_fw_outstanding_cmds);
	lmrc_put_mpt(mpt);
	rw_exit(&tgt->tgt_lock);

	if (ret >= 0)
		return (1);
	else
		return (-1);
}

/*
 * lmrc_abort_mpt
 *
 * Abort a MPT command by sending a TASK MGMT ABORT TASK command.
 */
int
lmrc_abort_mpt(lmrc_t *lmrc, lmrc_tgt_t *tgt, lmrc_mpt_cmd_t *mpt)
{
	ASSERT(mutex_owned(&tgt->tgt_mpt_active_lock));
	ASSERT(mutex_owned(&mpt->mpt_lock));

	return (lmrc_task_mgmt(lmrc, tgt, MPI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK,
	    mpt->mpt_smid));
}

/*
 * lmrc_tran_abort
 *
 * Send a SCSI TASK MGMT request to abort a packet.
 */
static int
lmrc_tran_abort(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	struct scsi_device *sd = scsi_address_device(sa);
	lmrc_tgt_t *tgt = scsi_device_hba_private_get(sd);
	lmrc_t *lmrc = tgt->tgt_lmrc;
	lmrc_scsa_cmd_t *cmd;
	lmrc_mpt_cmd_t *mpt;
	int ret = 0;

	VERIFY(lmrc != NULL);

	if (lmrc->l_fw_fault)
		return (0);

	/*
	 * If no pkt was given, abort all outstanding pkts for this target.
	 */
	if (pkt == NULL) {
		mutex_enter(&tgt->tgt_mpt_active_lock);
		for (mpt = lmrc_tgt_first_active_mpt(tgt);
		    mpt != NULL;
		    mpt = lmrc_tgt_next_active_mpt(tgt, mpt)) {
			ASSERT(mutex_owned(&mpt->mpt_lock));
			if (mpt->mpt_complete)
				continue;
			if (mpt->mpt_pkt == NULL)
				continue;

			if (lmrc_abort_mpt(lmrc, tgt, mpt) > 0)
				ret = 1;
		}
		mutex_exit(&tgt->tgt_mpt_active_lock);

		return (ret);
	}

	cmd = pkt->pkt_ha_private;

	VERIFY(cmd != NULL);
	VERIFY(cmd->sc_tgt == tgt);

	mpt = cmd->sc_mpt;
	VERIFY(mpt != NULL);

	mutex_enter(&mpt->mpt_lock);
	ret = lmrc_abort_mpt(lmrc, tgt, mpt);
	mutex_exit(&mpt->mpt_lock);

	if (ret == -1) {
		dev_err(lmrc->l_dip, CE_WARN, "!target reset timed out, "
		    "tgt %d", tgt->tgt_dev_id);
		return (0);
	}

	return (ret);
}

/*
 * lmrc_tran_reset
 *
 * Reset a target. There's no support for RESET_LUN or RESET_ALL.
 */
static int
lmrc_tran_reset(struct scsi_address *sa, int level)
{
	struct scsi_device *sd = scsi_address_device(sa);
	lmrc_tgt_t *tgt = scsi_device_hba_private_get(sd);
	lmrc_t *lmrc = tgt->tgt_lmrc;
	int ret = 0;

	VERIFY(lmrc != NULL);

	if (lmrc->l_fw_fault)
		return (0);

	switch (level) {
	case RESET_ALL:
	case RESET_LUN:
	case RESET_TARGET:
		rw_enter(&tgt->tgt_lock, RW_READER);
		ret = lmrc_task_mgmt(lmrc, tgt,
		    MPI2_SCSITASKMGMT_TASKTYPE_TARGET_RESET, 0);
		rw_exit(&tgt->tgt_lock);

		if (ret == -1) {
			dev_err(lmrc->l_dip, CE_WARN,
			    "!target reset timed out, tgt %d",
			    tgt->tgt_dev_id);
			return (0);
		}

		break;
	}

	/*
	 * Fake a successful return in the case of RESET_ALL for the benefit of
	 * being able to save kernel core dumps. sddump() wants to reset the
	 * device and errors out if that fails, even if that happens not because
	 * of an error but because of a reset not being supported.
	 */
	if (ret == 0 && level == RESET_ALL)
		ret = 1;

	return (ret);
}

/*
 * lmrc_tran_setup_pkt
 *
 * Set up a MPT command for a scsi_pkt, and initialize scsi_pkt members as
 * needed:
 * - pkt_cdbp will point to the CDB structure embedded in the MPT I/O frame
 * - pkt_scbp will point to the struct scsi_arq_status in the sense DMA memory
 *   allocated for the MPT command
 * - pkt_scblen will be set to the size of the sense DMA memory, minus alignment
 * - SenseBufferLowAddress and SenseBufferLength in the MPT I/O frame will be
 *   set to the sense DMA address and length, respectively, adjusted to account
 *   for the space needed for the ARQ pkt and alignment.
 * - There is no SenseBufferHighAddress.
 * - rc_timeout is set to pkt_time, but it is unknown if that has any effect
 *
 * The procedure is the same irrespective of whether the command is sent to a
 * physical device or RAID volume.
 */
static int
lmrc_tran_setup_pkt(struct scsi_pkt *pkt, int (*callback)(caddr_t),
    caddr_t arg)
{
	struct scsi_address *sa;
	struct scsi_device *sd;
	lmrc_tgt_t *tgt;
	lmrc_t *lmrc;
	lmrc_scsa_cmd_t *cmd;
	lmrc_mpt_cmd_t *mpt;
	Mpi25SCSIIORequest_t *io_req;
	lmrc_raidctx_g35_t *rc;

	if (pkt->pkt_cdblen > sizeof (io_req->CDB.CDB32))
		return (-1);

	sa = &pkt->pkt_address;
	VERIFY(sa != NULL);

	sd = scsi_address_device(sa);
	VERIFY(sd != NULL);

	tgt = scsi_device_hba_private_get(sd);
	VERIFY(tgt != NULL);

	rw_enter(&tgt->tgt_lock, RW_READER);

	lmrc = tgt->tgt_lmrc;
	VERIFY(lmrc != NULL);

	cmd = pkt->pkt_ha_private;
	ASSERT(cmd != NULL);

	mpt = lmrc_get_mpt(lmrc);
	if (mpt == NULL) {
		rw_exit(&tgt->tgt_lock);
		return (-1);
	}
	ASSERT(mutex_owned(&mpt->mpt_lock));


	io_req = mpt->mpt_io_frame;

	pkt->pkt_cdbp = io_req->CDB.CDB32;

	/* Just the CDB length now, but other flags may be set later. */
	io_req->IoFlags = pkt->pkt_cdblen;

	/*
	 * Set up sense buffer. The DMA memory was setup to holds the whole ARQ
	 * structure aligned so that its sts_sensedata is aligned to 64 bytes.
	 * Point SenseBufferLowAddress to sts_sensedata and reduce the length
	 * accordingly.
	 */
	pkt->pkt_scbp = mpt->mpt_sense;
	pkt->pkt_scblen = lmrc_dma_get_size(&mpt->mpt_sense_dma) - 64 +
	    offsetof(struct scsi_arq_status, sts_sensedata);

	lmrc_dma_set_addr32(&mpt->mpt_sense_dma,
	    &io_req->SenseBufferLowAddress);
	io_req->SenseBufferLowAddress +=
	    P2ROUNDUP(offsetof(struct scsi_arq_status, sts_sensedata), 64);
	io_req->SenseBufferLength = pkt->pkt_scblen -
	    offsetof(struct scsi_arq_status, sts_sensedata);

	rc = &io_req->VendorRegion;
	rc->rc_timeout = pkt->pkt_time;

	cmd->sc_mpt = mpt;
	cmd->sc_tgt = tgt;
	mpt->mpt_pkt = pkt;
	mutex_exit(&mpt->mpt_lock);
	rw_exit(&tgt->tgt_lock);

	return (0);
}

/*
 * lmrc_tran_teardown_pkt
 *
 * Return the MPT command to the free list. It'll be cleared later before
 * it is reused.
 */
static void
lmrc_tran_teardown_pkt(struct scsi_pkt *pkt)
{
	lmrc_scsa_cmd_t *cmd;
	lmrc_mpt_cmd_t *mpt;

	cmd = pkt->pkt_ha_private;
	ASSERT(cmd != NULL);

	mpt = cmd->sc_mpt;
	ASSERT(mpt != NULL);

	mutex_enter(&mpt->mpt_lock);
	lmrc_put_mpt(mpt);
}

/*
 * lmrc_hba_attach
 *
 * Set up the HBA functions of lmrc. This is a SAS controller and uses complex
 * addressing for targets, presenting physical devices (PDs) and RAID volumes
 * (LD) as separate iports.
 */
int
lmrc_hba_attach(lmrc_t *lmrc)
{
	scsi_hba_tran_t	*tran;
	ddi_dma_attr_t tran_attr = lmrc->l_dma_attr_32;

	tran = scsi_hba_tran_alloc(lmrc->l_dip, SCSI_HBA_CANSLEEP);
	if (tran == NULL) {
		dev_err(lmrc->l_dip, CE_WARN, "!scsi_hba_tran_alloc failed");
		return (DDI_FAILURE);
	}

	tran->tran_hba_private = lmrc;

	tran->tran_tgt_init = lmrc_tran_tgt_init;
	tran->tran_tgt_free = lmrc_tran_tgt_free;

	tran->tran_tgt_probe = scsi_hba_probe;

	tran->tran_start = lmrc_tran_start;
	tran->tran_abort = lmrc_tran_abort;
	tran->tran_reset = lmrc_tran_reset;

	tran->tran_getcap = lmrc_getcap;
	tran->tran_setcap = lmrc_setcap;

	tran->tran_setup_pkt = lmrc_tran_setup_pkt;
	tran->tran_teardown_pkt = lmrc_tran_teardown_pkt;
	tran->tran_hba_len = sizeof (lmrc_scsa_cmd_t);
	tran->tran_interconnect_type = INTERCONNECT_SAS;

	if (lmrc_relaxed_ordering)
		tran_attr.dma_attr_flags |= DDI_DMA_RELAXED_ORDERING;
	tran_attr.dma_attr_sgllen = lmrc->l_max_num_sge;

	if (scsi_hba_attach_setup(lmrc->l_dip, &tran_attr, tran,
	    SCSI_HBA_HBA | SCSI_HBA_ADDR_COMPLEX) != DDI_SUCCESS)
		goto fail;

	lmrc->l_hba_tran = tran;

	if (scsi_hba_iport_register(lmrc->l_dip, LMRC_IPORT_RAID) !=
	    DDI_SUCCESS)
		goto fail;

	if (scsi_hba_iport_register(lmrc->l_dip, LMRC_IPORT_PHYS) !=
	    DDI_SUCCESS)
		goto fail;

	return (DDI_SUCCESS);

fail:
	dev_err(lmrc->l_dip, CE_WARN,
	    "!could not attach to SCSA framework");
	lmrc_hba_detach(lmrc);

	return (DDI_FAILURE);
}

void
lmrc_hba_detach(lmrc_t *lmrc)
{
	if (lmrc->l_hba_tran == NULL)
		return;

	(void) scsi_hba_detach(lmrc->l_dip);
	scsi_hba_tran_free(lmrc->l_hba_tran);
	lmrc->l_hba_tran = NULL;
}
