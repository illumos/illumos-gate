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
 * Copyright 2023 Racktop Systems, Inc.
 */

/*
 * This file implements the interfaces for communicating with the MegaRAID HBA.
 * There are three basic interfaces:
 * - the device registers, which provide basic information about the controller
 *   hardware and the features it supports, as well as control registers used
 *   during sending and reception of I/O frames
 * - Fusion-MPT v2.5, perhaps later, which defines the format of the I/O frames
 *   used for communicating with the HBA and virtual and physical devices that
 *   are attached to it
 * - MFI, the MegaRAID Firmware Interface, which are sent and received as MPT
 *   payloads to control and communicate with the RAID controller.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>

#include <sys/cpuvar.h>

#include "lmrc.h"
#include "lmrc_reg.h"
#include "lmrc_raid.h"
#include "lmrc_phys.h"

static uint32_t lmrc_read_reg(lmrc_t *, uint32_t);
static void lmrc_write_reg(lmrc_t *, uint32_t, uint32_t);
static int lmrc_transition_to_ready(lmrc_t *);
static void lmrc_process_mptmfi_passthru(lmrc_t *, lmrc_mpt_cmd_t *);
static int lmrc_poll_mfi(lmrc_t *, lmrc_mfi_cmd_t *, uint8_t);
static boolean_t lmrc_check_fw_fault(lmrc_t *);
static int lmrc_get_event_log_info(lmrc_t *, lmrc_evt_log_info_t *);
static void lmrc_aen_handler(void *);
static void lmrc_complete_aen(lmrc_t *, lmrc_mfi_cmd_t *);
static int lmrc_register_aen(lmrc_t *, uint32_t);

/*
 * Device register access functions.
 *
 * Due to the way ddi_get* and ddi_put* work, we'll need to calculate the
 * absolute virtual address of the registers ourselves.
 *
 * For read accesses, employ a erratum workaround for Aero controllers. In some
 * cases, reads of certain registers will intermittently return all zeros. As a
 * workaround, retry the read up to three times until a non-zero value is read.
 * Supposedly this is enough, every other driver I looked at does this.
 */
static uint32_t
lmrc_read_reg_1(lmrc_t *lmrc, uint32_t reg)
{
	uint32_t *addr = (uint32_t *)((uintptr_t)lmrc->l_regmap + reg);
	return (ddi_get32(lmrc->l_reghandle, addr));
}

static uint32_t
lmrc_read_reg(lmrc_t *lmrc, uint32_t reg)
{
	if (lmrc->l_class != LMRC_ACLASS_AERO)
		return (lmrc_read_reg_1(lmrc, reg));

	/* Workaround for the hardware erratum in Aero controllers */
	for (uint_t i = 0; i < 3; i++) {
		uint32_t val = lmrc_read_reg_1(lmrc, reg);

		if (val != 0)
			return (val);
	}

	return (0);
}

static void
lmrc_write_reg(lmrc_t *lmrc, uint32_t reg, uint32_t val)
{
	uint32_t *addr = (uint32_t *)((uintptr_t)lmrc->l_regmap + reg);
	ddi_put32(lmrc->l_reghandle, addr, val);
}

static void
lmrc_write_reg64(lmrc_t *lmrc, uint32_t reg, uint64_t val)
{
	uint64_t *addr = (uint64_t *)((uintptr_t)lmrc->l_regmap + reg);
	ddi_put64(lmrc->l_reghandle, addr, val);
}

/*
 * Interrupt control
 *
 * There are two interrupt registers for host driver use, HostInterruptStatus
 * and HostInterruptMask. Most of the bits in each register are reserved and
 * must masked and/or preserved when used.
 */
void
lmrc_disable_intr(lmrc_t *lmrc)
{
	uint32_t mask = lmrc_read_reg(lmrc, MPI2_HOST_INTERRUPT_MASK_OFFSET);

	/* Disable all known interrupt: reset, reply, and doorbell. */
	mask |= MPI2_HIM_RESET_IRQ_MASK;
	mask |= MPI2_HIM_REPLY_INT_MASK;
	mask |= MPI2_HIM_IOC2SYS_DB_MASK;

	lmrc_write_reg(lmrc, MPI2_HOST_INTERRUPT_MASK_OFFSET, mask);

	/* Dummy read to force pci flush. Probably bogus but harmless. */
	(void) lmrc_read_reg(lmrc, MPI2_HOST_INTERRUPT_MASK_OFFSET);
}

void
lmrc_enable_intr(lmrc_t *lmrc)
{
	uint32_t mask = lmrc_read_reg(lmrc, MPI2_HOST_INTERRUPT_MASK_OFFSET);

	/* Enable the reply interrupts and the doorbell interrupts. */
	mask &= ~MPI2_HIM_REPLY_INT_MASK;
	mask &= ~MPI2_HIM_IOC2SYS_DB_MASK;

	/* Clear outstanding interrupts before enabling any. */
	lmrc_write_reg(lmrc, MPI2_HOST_INTERRUPT_STATUS_OFFSET, 0);
	/* Dummy read to force pci flush. Probably bogus but harmless. */
	(void) lmrc_read_reg(lmrc, MPI2_HOST_INTERRUPT_STATUS_OFFSET);

	lmrc_write_reg(lmrc, MPI2_HOST_INTERRUPT_MASK_OFFSET, mask);
	/* Dummy read to force pci flush. Probably bogus but harmless. */
	(void) lmrc_read_reg(lmrc, MPI2_HOST_INTERRUPT_MASK_OFFSET);
}

uint_t
lmrc_intr_ack(lmrc_t *lmrc)
{
	uint32_t mask =
	    MPI2_HIS_REPLY_DESCRIPTOR_INTERRUPT | MPI2_HIS_IOC2SYS_DB_STATUS;
	uint32_t status;

	status = lmrc_read_reg(lmrc, MPI2_HOST_INTERRUPT_STATUS_OFFSET);

	if ((status & mask) == 0)
		return (DDI_INTR_UNCLAIMED);

	if (lmrc_check_acc_handle(lmrc->l_reghandle) != DDI_SUCCESS) {
		ddi_fm_service_impact(lmrc->l_dip, DDI_SERVICE_LOST);
		return (DDI_INTR_UNCLAIMED);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * Fusion-MPT requests
 *
 * The controller expects to have access to a large chunk of DMA memory, into
 * which the driver writes fixed-size I/O requests for the controller to
 * process. To notify the hardware about a new request, a request descriptor is
 * written to the queue port registers which includes the SMID of the request.
 * This memory isn't really a queue, though, as it seems there are no
 * constraints about ordering of the requests. All that matters is that there
 * is a valid request at the address that corresponds with the SMID in the
 * descriptor.
 *
 * If the hardware supports MPI 2.6 atomic request descriptors, which are a
 * 32bit subset of the 64bit MPI 2.0/2.5 request descriptors, the descriptor is
 * sent to the controller in a single 32bit write into a device register.
 *
 * For all other descriptor types, we'll employ a 64bit write to the queue
 * registers, assuming that provides the required atomicity.
 */
void
lmrc_send_atomic_request(lmrc_t *lmrc, lmrc_atomic_req_desc_t req_desc)
{
	if (lmrc->l_atomic_desc_support) {
		lmrc_write_reg(lmrc,
		    MPI26_ATOMIC_REQUEST_DESCRIPTOR_POST_OFFSET,
		    req_desc.rd_reg);
	} else {
		lmrc_req_desc_t rd;

		bzero(&rd, sizeof (rd));
		rd.rd_atomic = req_desc;

		lmrc_send_request(lmrc, rd);
	}
}

void
lmrc_send_request(lmrc_t *lmrc, lmrc_req_desc_t req_desc)
{
	lmrc_write_reg64(lmrc, MPI2_REQUEST_DESCRIPTOR_POST_LOW_OFFSET,
	    req_desc.rd_reg);
}

lmrc_atomic_req_desc_t
lmrc_build_atomic_request(lmrc_t *lmrc, lmrc_mpt_cmd_t *mpt, uint8_t flags)
{
	lmrc_atomic_req_desc_t req_desc;

	VERIFY3U(mpt->mpt_smid, !=, 0);

	/*
	 * Select the reply queue based on the CPU id to distribute reply load
	 * among queues.
	 */
	mpt->mpt_queue = CPU->cpu_id % lmrc->l_max_reply_queues;

	bzero(&req_desc, sizeof (req_desc));

	req_desc.rd_atomic.RequestFlags = flags;
	req_desc.rd_atomic.MSIxIndex = mpt->mpt_queue;
	req_desc.rd_atomic.SMID = mpt->mpt_smid;

	return (req_desc);
}

/*
 * Reply Processing
 *
 * The controller will post replies to completed requests in the DMA memory
 * provided for that purpose. This memory is divided in equally-sized chunks,
 * each being a separate reply queue that is also associated with an interrupt
 * vector. The replies are fixed size structures and will be written by the
 * hardware in order of completion into the queue. For each queue, there is a
 * register to tell the hardware which replies have been consumed by the driver.
 *
 * In response to an interrupt, the driver will walk the reply queue associated
 * with the interrupt vector at the last known position and processess all
 * completed replies. After a number of replies has been processed, or if no
 * more replies are ready to be processed, the controller will be notified about
 * the last reply index to be processed by writing the appropriate register.
 */

/*
 * lmrc_get_next_reply_desc
 *
 * Get the next unprocessed reply descriptor for a queue, or NULL if there is
 * none.
 */
static Mpi2ReplyDescriptorsUnion_t *
lmrc_get_next_reply_desc(lmrc_t *lmrc, int queue)
{
	Mpi2ReplyDescriptorsUnion_t *desc;

	desc = lmrc->l_reply_dma.ld_buf;

	desc += (queue * lmrc->l_reply_alloc_sz) / sizeof (*desc);
	desc += lmrc->l_last_reply_idx[queue];

	VERIFY3S(ddi_dma_sync(lmrc->l_reply_dma.ld_hdl,
	    (void *)desc - lmrc->l_reply_dma.ld_buf, sizeof (*desc),
	    DDI_DMA_SYNC_FORKERNEL), ==, DDI_SUCCESS);

	/*
	 * Check if this is an unused reply descriptor, indicating that
	 * we've reached the end of replies in this queue.
	 *
	 * Even if the descriptor is only "half unused" we can't use it.
	 */
	if (desc->Words.Low == MPI2_RPY_DESCRIPT_UNUSED_WORD0_MARK ||
	    desc->Words.High == MPI2_RPY_DESCRIPT_UNUSED_WORD1_MARK)
		return (NULL);

	/* advance last reply index, wrap around if necessary */
	lmrc->l_last_reply_idx[queue]++;
	if (lmrc->l_last_reply_idx[queue] >= lmrc->l_reply_q_depth)
		lmrc->l_last_reply_idx[queue] = 0;

	return (desc);
}

/*
 * lmrc_write_rphi
 *
 * Write the Reply Post Host Index register for queue.
 */
static void
lmrc_write_rphi(lmrc_t *lmrc, uint32_t queue)
{
	int reg = 0;
	uint32_t val = (queue << 24) | lmrc->l_last_reply_idx[queue];

	if (lmrc->l_intr_type != DDI_INTR_TYPE_MSIX)
		VERIFY3U(queue, ==, 0);

	if (lmrc->l_msix_combined) {
		reg = queue / 8;
		val &= 0x07ffffff;
	}

	lmrc_write_reg(lmrc, lmrc->l_rphi[reg], val);
}

/*
 * lmrc_process_mpt_pkt
 *
 * Process a reply to a MPT IO request. Update the scsi_pkt according to status,
 * ex_status, and data_len, setting up the ARQ pkt if necessary.
 */
static void
lmrc_process_mpt_pkt(lmrc_t *lmrc, struct scsi_pkt *pkt, uint8_t status,
    uint8_t ex_status, uint32_t data_len)
{
	pkt->pkt_statistics = 0;
	pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
	    STATE_XFERRED_DATA | STATE_GOT_STATUS;

	pkt->pkt_resid = pkt->pkt_dma_len - data_len;

	switch (status) {
	case MFI_STAT_OK:
	case MFI_STAT_LD_CC_IN_PROGRESS:
	case MFI_STAT_LD_RECON_IN_PROGRESS:
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_scbp[0] = STATUS_GOOD;
		break;

	case MFI_STAT_SCSI_DONE_WITH_ERROR:
	case MFI_STAT_LD_LBA_OUT_OF_RANGE: {
		struct scsi_arq_status *arq =
		    (struct scsi_arq_status *)pkt->pkt_scbp;

		pkt->pkt_reason = CMD_CMPLT;
		arq->sts_status.sts_chk = 1;

		pkt->pkt_state |= STATE_ARQ_DONE;
		arq->sts_rqpkt_reason = CMD_CMPLT;
		arq->sts_rqpkt_resid = 0;
		arq->sts_rqpkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA;
		*(uint8_t *)&arq->sts_rqpkt_status = STATUS_GOOD;
		break;
	}
	case MFI_STAT_LD_OFFLINE:
	case MFI_STAT_DEVICE_NOT_FOUND:
		pkt->pkt_reason = CMD_DEV_GONE;
		pkt->pkt_statistics = STAT_DISCON;
		break;

	default:
		dev_err(lmrc->l_dip, CE_PANIC, "!command failed, status = %x, "
		    "ex_status = %x, cdb[0] = %x", status, ex_status,
		    pkt->pkt_cdbp[0]);
		pkt->pkt_reason = CMD_TRAN_ERR;
		break;
	}
}

/*
 * lmrc_poll_for_reply
 *
 * During a panic we'll have to resort to polled I/O to write core dumps.
 * Repeatedly check the reply queue for a new reply associated with the
 * given request descriptor and complete it, or return an error if we get
 * no reply within a reasonable time.
 */
int
lmrc_poll_for_reply(lmrc_t *lmrc, lmrc_mpt_cmd_t *mpt)
{
	clock_t max_wait = LMRC_IO_TIMEOUT * MILLISEC * 10;
	Mpi25SCSIIORequest_t *io_req = mpt->mpt_io_frame;
	Mpi2ReplyDescriptorsUnion_t *desc;
	uint16_t desc_smid;

	VERIFY(ddi_in_panic());

	/*
	 * Walk the reply queue. Discard entries which we aren't
	 * looking for.
	 */
	do {
		desc = lmrc_get_next_reply_desc(lmrc, mpt->mpt_queue);
		if (desc == NULL) {
			if (max_wait == 0)
				return (TRAN_FATAL_ERROR);

			drv_usecwait(100);
			max_wait--;
			continue;
		}

		desc_smid = desc->SCSIIOSuccess.SMID;

		/* reset descriptor */
		desc->Words.Low = MPI2_RPY_DESCRIPT_UNUSED_WORD0_MARK;
		desc->Words.High = MPI2_RPY_DESCRIPT_UNUSED_WORD1_MARK;

		lmrc_write_rphi(lmrc, mpt->mpt_queue);
	} while (desc == NULL || desc_smid != mpt->mpt_smid);

	VERIFY3S(ddi_dma_sync(lmrc->l_ioreq_dma.ld_hdl,
	    (void *)io_req - lmrc->l_ioreq_dma.ld_buf,
	    LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE, DDI_DMA_SYNC_FORKERNEL),
	    ==, DDI_SUCCESS);

	/* If this is I/O, process it. */
	if (io_req->Function == LMRC_MPI2_FUNCTION_LD_IO_REQUEST ||
	    io_req->Function == MPI2_FUNCTION_SCSI_IO_REQUEST) {
		lmrc_process_mpt_pkt(lmrc, mpt->mpt_pkt,
		    io_req->VendorRegion.rc_status,
		    io_req->VendorRegion.rc_exstatus, io_req->DataLength);
	}

	return (TRAN_ACCEPT);
}

/*
 * lmrc_process_replies
 *
 * Process all new reply entries in a queue in response to an interrupt.
 */
int
lmrc_process_replies(lmrc_t *lmrc, uint8_t queue)
{
	int nprocessed = 0;
	Mpi2ReplyDescriptorsUnion_t *desc;

	for (desc = lmrc_get_next_reply_desc(lmrc, queue);
	    desc != NULL;
	    desc = lmrc_get_next_reply_desc(lmrc, queue)) {
		Mpi2SCSIIOSuccessReplyDescriptor_t *reply =
		    &desc->SCSIIOSuccess;
		uint16_t smid = reply->SMID;
		lmrc_mpt_cmd_t *mpt = lmrc->l_mpt_cmds[smid - 1];
		lmrc_tgt_t *tgt = NULL;
		Mpi25SCSIIORequest_t *io_req;
		struct scsi_pkt *pkt;
		struct scsi_device *sd;

		VERIFY3U(reply->SMID, <=, lmrc->l_max_fw_cmds);

		mutex_enter(&mpt->mpt_lock);
		mpt->mpt_complete = B_TRUE;
		pkt = mpt->mpt_pkt;
		io_req = mpt->mpt_io_frame;

		VERIFY3S(ddi_dma_sync(lmrc->l_ioreq_dma.ld_hdl,
		    (void *)io_req - lmrc->l_ioreq_dma.ld_buf,
		    LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE,
		    DDI_DMA_SYNC_FORKERNEL), ==, DDI_SUCCESS);


		switch (io_req->Function) {
		case MPI2_FUNCTION_SCSI_TASK_MGMT:
			VERIFY0(pkt);
			VERIFY0(list_link_active(&mpt->mpt_node));
			cv_signal(&mpt->mpt_cv);
			break;

		case MPI2_FUNCTION_SCSI_IO_REQUEST:
		case LMRC_MPI2_FUNCTION_LD_IO_REQUEST:
			VERIFY(pkt != NULL);

			sd = scsi_address_device(&pkt->pkt_address);
			VERIFY(sd != NULL);

			tgt = scsi_device_hba_private_get(sd);
			VERIFY(tgt != NULL);

			lmrc_process_mpt_pkt(lmrc, pkt,
			    io_req->VendorRegion.rc_status,
			    io_req->VendorRegion.rc_exstatus,
			    io_req->DataLength);

			break;

		case LMRC_MPI2_FUNCTION_PASSTHRU_IO_REQUEST:
			VERIFY0(pkt);
			VERIFY0(list_link_active(&mpt->mpt_node));
			lmrc_process_mptmfi_passthru(lmrc, mpt);
			break;

		default:
			mutex_exit(&mpt->mpt_lock);
			dev_err(lmrc->l_dip, CE_PANIC,
			    "!reply received for unknown Function %x",
			    io_req->Function);
		}

		mutex_exit(&mpt->mpt_lock);

		if (pkt != NULL) {
			lmrc_tgt_rem_active_mpt(tgt, mpt);
			atomic_dec_uint(&lmrc->l_fw_outstanding_cmds);
			scsi_hba_pkt_comp(pkt);
		}

		/* reset descriptor */
		desc->Words.Low = MPI2_RPY_DESCRIPT_UNUSED_WORD0_MARK;
		desc->Words.High = MPI2_RPY_DESCRIPT_UNUSED_WORD1_MARK;

		nprocessed++;

		if (nprocessed % LMRC_THRESHOLD_REPLY_COUNT == 0)
			lmrc_write_rphi(lmrc, queue);
	}

	if (nprocessed != 0 && nprocessed % LMRC_THRESHOLD_REPLY_COUNT != 0)
		lmrc_write_rphi(lmrc, queue);

	return (DDI_INTR_CLAIMED);
}


/*
 * MFI - MegaRAID Firmware Interface
 */

/*
 * lmrc_build_mptmfi_passthru
 *
 * MFI commands are send as MPT MFI passthrough I/O requests. To be able to send
 * a MFI frame to the RAID controller, we need to have a MPT command set up as
 * MPT I/O request and a one-entry SGL pointing to the MFI command.
 *
 * As there's only a small number of MFI commands compared to the amound of MPT
 * commands, the MPT command for each MFI is pre-allocated at attach time and
 * initialized here.
 */
int
lmrc_build_mptmfi_passthru(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi)
{
	Mpi25SCSIIORequest_t *io_req;
	const ddi_dma_cookie_t *cookie;
	lmrc_mpt_cmd_t *mpt;

	mpt = lmrc_get_mpt(lmrc);
	if (mpt == NULL)
		return (DDI_FAILURE);

	/* lmrc_get_mpt() should return the mpt locked */
	ASSERT(mutex_owned(&mpt->mpt_lock));

	mfi->mfi_mpt = mpt;
	mpt->mpt_mfi = mfi;

	io_req = mpt->mpt_io_frame;
	io_req->Function = LMRC_MPI2_FUNCTION_PASSTHRU_IO_REQUEST;
	io_req->ChainOffset = lmrc->l_chain_offset_mfi_pthru;

	cookie = ddi_dma_cookie_one(mfi->mfi_frame_dma.ld_hdl);
	lmrc_dma_build_sgl(lmrc, mpt, cookie, 1);

	VERIFY3S(ddi_dma_sync(lmrc->l_ioreq_dma.ld_hdl,
	    (void *)io_req - lmrc->l_ioreq_dma.ld_buf,
	    LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE, DDI_DMA_SYNC_FORDEV),
	    ==, DDI_SUCCESS);

	/*
	 * As we're not sending this command to the hardware any time soon,
	 * drop the mutex before we return.
	 */
	mutex_exit(&mpt->mpt_lock);

	return (DDI_SUCCESS);
}

/*
 * lmrc_process_mptmfi_passthru
 *
 * When a MPT MFI passthrough command completes, invoke the callback if there
 * is one. Panic if an invalid command completed as that should never happen.
 */
static void
lmrc_process_mptmfi_passthru(lmrc_t *lmrc, lmrc_mpt_cmd_t *mpt)
{
	lmrc_mfi_cmd_t *mfi;
	lmrc_mfi_header_t *hdr;

	VERIFY3P(mpt->mpt_mfi, !=, NULL);
	mfi = mpt->mpt_mfi;
	VERIFY0(list_link_active(&mfi->mfi_node));

	hdr = &mfi->mfi_frame->mf_hdr;

	if ((hdr->mh_flags & MFI_FRAME_DIR_READ) != 0)
		(void) ddi_dma_sync(mfi->mfi_data_dma.ld_hdl, 0,
		    mfi->mfi_data_dma.ld_len, DDI_DMA_SYNC_FORKERNEL);

	switch (hdr->mh_cmd) {
	case MFI_CMD_DCMD:
	case MFI_CMD_LD_SCSI_IO:
	case MFI_CMD_PD_SCSI_IO:
	case MFI_CMD_ABORT:
		mutex_enter(&mfi->mfi_lock);
		if (mfi->mfi_callback != NULL)
			mfi->mfi_callback(lmrc, mfi);
		mutex_exit(&mfi->mfi_lock);
		break;

	case MFI_CMD_INVALID:
	default:
		dev_err(lmrc->l_dip, CE_PANIC,
		    "!invalid MFI cmd completion received, cmd = %x",
		    hdr->mh_cmd);
		break;
	}
}

/*
 * lmrc_issue_mfi
 *
 * Post a MFI command to the firmware. Reset the cmd_status to invalid. Build
 * a MPT MFI passthru command if necessary and a MPT atomic request descriptor
 * before posting the request. The MFI command's mutex must be held.
 */
void
lmrc_issue_mfi(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi, lmrc_mfi_cmd_cb_t *cb)
{
	lmrc_mfi_header_t *hdr = &mfi->mfi_frame->mf_hdr;
	lmrc_atomic_req_desc_t req_desc;

	ASSERT(mutex_owned(&mfi->mfi_lock));

	if ((hdr->mh_flags & MFI_FRAME_DONT_POST_IN_REPLY_QUEUE) == 0) {
		VERIFY3U(cb, !=, NULL);
		mfi->mfi_callback = cb;
	} else {
		VERIFY3U(cb, ==, NULL);
	}

	hdr->mh_cmd_status = MFI_STAT_INVALID_STATUS;

	req_desc = lmrc_build_atomic_request(lmrc, mfi->mfi_mpt,
	    MPI2_REQ_DESCRIPT_FLAGS_SCSI_IO);

	(void) ddi_dma_sync(mfi->mfi_frame_dma.ld_hdl, 0,
	    mfi->mfi_frame_dma.ld_len, DDI_DMA_SYNC_FORDEV);

	if ((hdr->mh_flags & MFI_FRAME_DIR_WRITE) != 0)
		(void) ddi_dma_sync(mfi->mfi_data_dma.ld_hdl, 0,
		    mfi->mfi_data_dma.ld_len, DDI_DMA_SYNC_FORDEV);

	lmrc_send_atomic_request(lmrc, req_desc);
}

/*
 * lmrc_poll_mfi
 *
 * Poll a MFI command for completion, waiting up to max_wait secs. Repeatedly
 * check the command status until it changes to something that is not invalid.
 *
 * Trigger an online controller reset on timeout.
 */
static int
lmrc_poll_mfi(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi, uint8_t max_wait)
{
	lmrc_mfi_header_t *hdr = &mfi->mfi_frame->mf_hdr;
	lmrc_dma_t *dma = &mfi->mfi_frame_dma;
	clock_t timeout = ddi_get_lbolt() + drv_usectohz(max_wait * MICROSEC);
	clock_t now;

	ASSERT(mutex_owned(&mfi->mfi_lock));

	do {
		(void) ddi_dma_sync(dma->ld_hdl, 0, dma->ld_len,
		    DDI_DMA_SYNC_FORKERNEL);
		if (hdr->mh_cmd_status != MFI_STAT_INVALID_STATUS)
			break;

		(void) cv_reltimedwait(&mfi->mfi_cv, &mfi->mfi_lock,
		    drv_usectohz(MILLISEC), TR_MILLISEC);
		now = ddi_get_lbolt();
	} while (!lmrc->l_fw_fault && now <= timeout);

	if (hdr->mh_cmd_status != MFI_STAT_INVALID_STATUS)
		return (DDI_SUCCESS);

	if (now > timeout) {
		dev_err(lmrc->l_dip, CE_WARN,
		    "!%s: command timeout after %ds", __func__, max_wait);

		/*
		 * Signal the housekeeping thread to check for FW/HW faults,
		 * performing a reset if necessary.
		 */
		cv_signal(&lmrc->l_thread_cv);
	}

	return (DDI_FAILURE);
}

/*
 * lmrc_wait_mfi
 *
 * Wait for up to max_wait secs for a MFI command to complete. The cmd mutex
 * must be held.
 *
 * Trigger an online controller reset on timeout.
 */
int
lmrc_wait_mfi(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi, uint8_t max_wait)
{
	lmrc_mfi_header_t *hdr = &mfi->mfi_frame->mf_hdr;
	lmrc_dma_t *dma = &mfi->mfi_frame_dma;
	clock_t timeout = ddi_get_lbolt() + drv_usectohz(max_wait * MICROSEC);
	int ret;

	ASSERT(mutex_owned(&mfi->mfi_lock));

	do {
		ret = cv_timedwait(&mfi->mfi_cv, &mfi->mfi_lock, timeout);

		(void) ddi_dma_sync(dma->ld_hdl, 0, dma->ld_len,
		    DDI_DMA_SYNC_FORKERNEL);

	} while (!lmrc->l_fw_fault &&
	    hdr->mh_cmd_status == MFI_STAT_INVALID_STATUS && ret != -1);

	if (!lmrc->l_fw_fault && ret != -1)
		return (DDI_SUCCESS);

	if (ret == -1) {
		dev_err(lmrc->l_dip, CE_WARN, "!%s: blocked command timeout "
		    "after %ds, cmd = %d, status = %d", __func__, max_wait,
		    hdr->mh_cmd, hdr->mh_cmd_status);

		/*
		 * Signal the housekeeping thread to check for FW/HW faults,
		 * performing a reset if necessary.
		 */
		cv_signal(&lmrc->l_thread_cv);
	}

	return (DDI_FAILURE);
}

/*
 * lmrc_wakeup_mfi
 *
 * Signal the CV associated with a MFI command to wake up the thread waiting
 * for its completion.
 */
void
lmrc_wakeup_mfi(lmrc_t *lmrc, lmrc_mfi_cmd_t *cmd)
{
	ASSERT(mutex_owned(&cmd->mfi_lock));
	cv_signal(&cmd->mfi_cv);
}

/*
 * lmrc_issue_blocked_mfi
 *
 * Post a MFI command to the firmware and wait for the command to complete.
 */
int
lmrc_issue_blocked_mfi(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi)
{
	lmrc_mfi_header_t *hdr = &mfi->mfi_frame->mf_hdr;
	int ret;

	mutex_enter(&mfi->mfi_lock);
	lmrc_issue_mfi(lmrc, mfi, lmrc_wakeup_mfi);
	ret = lmrc_wait_mfi(lmrc, mfi, LMRC_INTERNAL_CMD_WAIT_TIME);
	mutex_exit(&mfi->mfi_lock);

	if (ret == DDI_SUCCESS && hdr->mh_cmd_status == MFI_STAT_OK)
		return (DDI_SUCCESS);

	dev_err(lmrc->l_dip, CE_WARN,
	    "!%s: blocked command failure, cmd = %d, status = %d",
	    __func__, hdr->mh_cmd, hdr->mh_cmd_status);

	return (ret);
}

/*
 * lmrc_abort_cb
 *
 * Callback for any command that is to be aborted.
 *
 * If the command completed normally before it could be aborted, set the status
 * to indicate the intended abortion.
 */
static void
lmrc_abort_cb(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi)
{
	lmrc_mfi_header_t *hdr = &mfi->mfi_frame->mf_hdr;

	if (hdr->mh_cmd_status == MFI_STAT_OK)
		hdr->mh_cmd_status = MFI_STAT_NOT_FOUND;
}

/*
 * lmrc_abort_mfi
 *
 * Abort a MFI command. This is a bit tricky as the hardware may still complete
 * it at any time.
 *
 * The mutex of the command to be aborted must be held to prevent it from
 * completing behind our back. We'll replace its callback with our own, issue an
 * ABORT command, and drop the mutex before we wait for the ABORT command to
 * complete.
 */
static int
lmrc_abort_cmd(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi_to_abort)
{
	lmrc_mfi_cmd_t *mfi = lmrc_get_mfi(lmrc);
	lmrc_mfi_header_t *hdr = &mfi->mfi_frame->mf_hdr;
	lmrc_mfi_abort_payload_t *abort = &mfi->mfi_frame->mf_abort;
	lmrc_mfi_cmd_cb_t *orig_cb = mfi_to_abort->mfi_callback;
	int ret;

	ASSERT(mutex_owned(&mfi_to_abort->mfi_lock));

	/* Replace the commands callback with our own. */
	mfi_to_abort->mfi_callback = lmrc_abort_cb;

	hdr->mh_cmd = MFI_CMD_ABORT;
	abort->ma_abort_context = mfi_to_abort->mfi_idx;
	lmrc_dma_set_addr64(&mfi_to_abort->mfi_frame_dma,
	    &abort->ma_abort_mfi_phys_addr);

	/* Send the ABORT. */
	mutex_enter(&mfi->mfi_lock);
	lmrc_issue_mfi(lmrc, mfi, lmrc_wakeup_mfi);

	/*
	 * Drop the mutex of the command to be aborted, allowing it to proceed
	 * while we wait for the ABORT command to complete.
	 */
	mutex_exit(&mfi_to_abort->mfi_lock);
	ret = lmrc_wait_mfi(lmrc, mfi, LMRC_INTERNAL_CMD_WAIT_TIME);
	mutex_exit(&mfi->mfi_lock);

	/*
	 * The ABORT command may fail if cmd_to_abort has completed already.
	 * Treat any other failure as fatal, restore the callback and fail.
	 */
	if (ret != DDI_SUCCESS && hdr->mh_cmd_status != MFI_STAT_NOT_FOUND) {
		mutex_enter(&mfi_to_abort->mfi_lock);
		mfi_to_abort->mfi_callback = orig_cb;
		goto out;
	}

	/*
	 * Wait for the aborted command to complete. If we time out on this
	 * there's little we can do here, so we restore the callback and fail.
	 */
	mutex_enter(&mfi_to_abort->mfi_lock);
	ret = lmrc_poll_mfi(lmrc, mfi_to_abort, LMRC_INTERNAL_CMD_WAIT_TIME);
	mfi_to_abort->mfi_callback = orig_cb;

	if (ret != DDI_SUCCESS)
		goto out;

	/* Wake up anyone waiting on the aborted command. */
	if (mfi_to_abort->mfi_callback != NULL)
		mfi_to_abort->mfi_callback(lmrc, mfi_to_abort);

out:
	lmrc_put_mfi(mfi);
	ASSERT(mutex_owned(&mfi_to_abort->mfi_lock));
	return (ret);
}


/*
 * Controller Initialization and Housekeeping
 */

/*
 * lmrc_check_fw_fault
 *
 * Check the firmware state. If faulted, return B_TRUE.
 * Return B_FALSE otherwise.
 */
static boolean_t
lmrc_check_fw_fault(lmrc_t *lmrc)
{
	uint32_t status = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD0_OFFSET);
	uint32_t fw_state = LMRC_FW_STATE(status);

	if (fw_state == LMRC_FW_STATE_FAULT)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * lmrc_wait_for_reg
 *
 * Repeatedly read the register and check that 'bits' match 'exp'.
 */
static boolean_t
lmrc_wait_for_reg(lmrc_t *lmrc, uint32_t reg, uint32_t bits, uint32_t exp,
    uint64_t max_wait)
{
	uint32_t val;
	uint64_t i;

	max_wait *= MILLISEC / 100;

	for (i = 0; i < max_wait; i++) {
		delay(drv_usectohz(100 * MILLISEC));
		val = lmrc_read_reg(lmrc, reg);

		if ((val & bits) == exp)
			return (B_TRUE);
	}

	return (B_FALSE);
}

static int
lmrc_hard_reset(lmrc_t *lmrc)
{
	int ret = DDI_SUCCESS;

	/* Write the reset key sequence. */
	lmrc_write_reg(lmrc, MPI2_WRITE_SEQUENCE_OFFSET,
	    MPI2_WRSEQ_FLUSH_KEY_VALUE);
	lmrc_write_reg(lmrc, MPI2_WRITE_SEQUENCE_OFFSET,
	    MPI2_WRSEQ_1ST_KEY_VALUE);
	lmrc_write_reg(lmrc, MPI2_WRITE_SEQUENCE_OFFSET,
	    MPI2_WRSEQ_2ND_KEY_VALUE);
	lmrc_write_reg(lmrc, MPI2_WRITE_SEQUENCE_OFFSET,
	    MPI2_WRSEQ_3RD_KEY_VALUE);
	lmrc_write_reg(lmrc, MPI2_WRITE_SEQUENCE_OFFSET,
	    MPI2_WRSEQ_4TH_KEY_VALUE);
	lmrc_write_reg(lmrc, MPI2_WRITE_SEQUENCE_OFFSET,
	    MPI2_WRSEQ_5TH_KEY_VALUE);
	lmrc_write_reg(lmrc, MPI2_WRITE_SEQUENCE_OFFSET,
	    MPI2_WRSEQ_6TH_KEY_VALUE);

	/* Check diag write enable. */
	if (!lmrc_wait_for_reg(lmrc, MPI2_HOST_DIAGNOSTIC_OFFSET,
	    MPI2_DIAG_DIAG_WRITE_ENABLE, MPI2_DIAG_DIAG_WRITE_ENABLE,
	    LMRC_RESET_TIMEOUT)) {
		dev_err(lmrc->l_dip, CE_WARN, "diag unlock failed");
		return (DDI_FAILURE);
	}

	/* Reset IOC. */
	lmrc_write_reg(lmrc, MPI2_HOST_DIAGNOSTIC_OFFSET,
	    lmrc_read_reg(lmrc, MPI2_HOST_DIAGNOSTIC_OFFSET) |
	    MPI2_DIAG_RESET_ADAPTER);
	delay(drv_usectohz(MPI2_HARD_RESET_PCIE_FIRST_READ_DELAY_MICRO_SEC));

	/* Check the reset adapter bit. */
	if ((lmrc_read_reg(lmrc, MPI2_HOST_DIAGNOSTIC_OFFSET) &
	    MPI2_DIAG_RESET_ADAPTER) == 0)
		goto out;

	delay(drv_usectohz(MPI2_HARD_RESET_PCIE_SECOND_READ_DELAY_MICRO_SEC));

	/* Check the reset adapter bit again. */
	if ((lmrc_read_reg(lmrc, MPI2_HOST_DIAGNOSTIC_OFFSET) &
	    MPI2_DIAG_RESET_ADAPTER) == 0)
		goto out;

	ret = DDI_FAILURE;
out:
	lmrc_write_reg(lmrc, MPI2_WRITE_SEQUENCE_OFFSET,
	    MPI2_WRSEQ_FLUSH_KEY_VALUE);
	return (ret);
}

/*
 * lmrc_reset_ctrl
 *
 * Attempt to reset the controller, if the hardware supports it.
 * If reset is unsupported or the reset fails repeatedly, we shut the
 * controller down.
 */
static int
lmrc_reset_ctrl(lmrc_t *lmrc)
{
	uint32_t status, fw_state, reset_adapter;
	int max_wait, i;

	if (lmrc->l_disable_online_ctrl_reset)
		return (DDI_FAILURE);

	status = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD0_OFFSET);
	fw_state = LMRC_FW_STATE(status);
	reset_adapter = LMRC_FW_RESET_ADAPTER(status);

	if (fw_state == LMRC_FW_STATE_FAULT && reset_adapter == 0) {
		dev_err(lmrc->l_dip, CE_WARN,
		    "FW in fault state, but reset not supported");
		goto out;
	}

	for (i = 0; i < LMRC_MAX_RESET_TRIES; i++) {
		dev_err(lmrc->l_dip, CE_WARN, "resetting...");

		if (lmrc_hard_reset(lmrc) != DDI_SUCCESS)
			continue;

		/* Wait for the FW state to move beyond INIT. */
		max_wait = LMRC_IO_TIMEOUT * MILLISEC / 100;
		do {
			status = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD0_OFFSET);
			fw_state = LMRC_FW_STATE(status);

			if (fw_state <= LMRC_FW_STATE_FW_INIT)
				delay(drv_usectohz(100 * MILLISEC));
		} while (fw_state <= LMRC_FW_STATE_FW_INIT && max_wait > 0);

		if (fw_state <= LMRC_FW_STATE_FW_INIT) {
			dev_err(lmrc->l_dip, CE_WARN,
			    "fw state <= LMRC_FW_STATE_FW_INIT, state = %x",
			    fw_state);
			continue;
		}

		return (DDI_SUCCESS);
	}

	dev_err(lmrc->l_dip, CE_WARN, "reset failed");
out:
	/* Stop the controller. */
	lmrc_write_reg(lmrc, MPI2_DOORBELL_OFFSET, MFI_STOP_ADP);
	(void) lmrc_read_reg(lmrc, MPI2_DOORBELL_OFFSET);

	return (DDI_FAILURE);
}

/*
 * lmrc_tgt_complete_cmd
 *
 * In case of a controller reset, complete the cmd and clean up. This is done
 * in a taskq to avoid locking and list manipulation headaches.
 */
static void
lmrc_tgt_complete_cmd(void *arg)
{
	lmrc_scsa_cmd_t *cmd = arg;
	struct scsi_pkt *pkt;
	lmrc_t *lmrc;

	mutex_enter(&cmd->sc_mpt->mpt_lock);

	/* Just in case the command completed before the taskq was run... */
	if (cmd->sc_mpt->mpt_complete) {
		mutex_exit(&cmd->sc_mpt->mpt_lock);
		return;
	}

	lmrc = cmd->sc_mpt->mpt_lmrc;
	pkt = cmd->sc_mpt->mpt_pkt;

	pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD;
	pkt->pkt_reason = CMD_RESET;
	pkt->pkt_statistics = STAT_BUS_RESET;
	mutex_exit(&cmd->sc_mpt->mpt_lock);

	lmrc_tgt_rem_active_mpt(cmd->sc_tgt, cmd->sc_mpt);
	atomic_dec_uint(&lmrc->l_fw_outstanding_cmds);

	scsi_hba_pkt_comp(pkt);
}

/*
 * lmrc_tgt_complete_cmds
 *
 * Walk the list of active commands of a target. Schedule a taskq to handle the
 * timeout processing and clean up.
 */
static void
lmrc_tgt_complete_cmds(lmrc_t *lmrc, lmrc_tgt_t *tgt)
{
	lmrc_mpt_cmd_t *mpt;

	mutex_enter(&tgt->tgt_mpt_active_lock);
	if (list_is_empty(&tgt->tgt_mpt_active)) {
		mutex_exit(&tgt->tgt_mpt_active_lock);
		return;
	}

	for (mpt = lmrc_tgt_first_active_mpt(tgt);
	    mpt != NULL;
	    mpt = lmrc_tgt_next_active_mpt(tgt, mpt)) {
		lmrc_scsa_cmd_t *cmd = mpt->mpt_pkt->pkt_ha_private;

		ASSERT(mutex_owned(&mpt->mpt_lock));
		VERIFY(mpt->mpt_pkt != NULL);
		VERIFY(cmd != NULL);

		if (mpt->mpt_complete)
			continue;

		taskq_dispatch_ent(lmrc->l_taskq, lmrc_tgt_complete_cmd, cmd,
		    TQ_NOSLEEP, &mpt->mpt_tqent);
	}
	mutex_exit(&tgt->tgt_mpt_active_lock);
}

/*
 * lmrc_tgt_timeout_cmds
 *
 * Walk the list of active commands of a target. Try to abort commands which are
 * overdue.
 */
static int
lmrc_tgt_timeout_cmds(lmrc_t *lmrc, lmrc_tgt_t *tgt)
{
	lmrc_mpt_cmd_t *mpt;
	int ret = DDI_SUCCESS;

	mutex_enter(&tgt->tgt_mpt_active_lock);
	if (list_is_empty(&tgt->tgt_mpt_active))
		goto out;

	for (mpt = lmrc_tgt_first_active_mpt(tgt);
	    mpt != NULL;
	    mpt = lmrc_tgt_next_active_mpt(tgt, mpt)) {
		hrtime_t now;

		ASSERT(mutex_owned(&mpt->mpt_lock));
		VERIFY(mpt->mpt_pkt != NULL);

		/* Just in case the command completed by now... */
		if (mpt->mpt_complete)
			continue;

		now = gethrtime();

		if (now > mpt->mpt_timeout) {
			/*
			 * Give the packet a bit more time for the abort to
			 * complete.
			 */
			mpt->mpt_timeout = now + LMRC_IO_TIMEOUT * NANOSEC;

			/*
			 * If the abort failed for whatever reason,
			 * we can stop here as only a controller reset
			 * can get us back into a sane state.
			 */
			if (lmrc_abort_mpt(lmrc, tgt, mpt) != 1) {
				mutex_exit(&mpt->mpt_lock);
				ret = DDI_FAILURE;
				goto out;
			}
		}
	}

out:
	mutex_exit(&tgt->tgt_mpt_active_lock);
	return (ret);
}

/*
 * lmrc_thread
 *
 * Check whether the controller is FW fault state. Check all targets for
 * commands which have timed out.
 */
void
lmrc_thread(void *arg)
{
	lmrc_t *lmrc = arg;

	do {
		int i;

		/* Wake up at least once a minute. */
		mutex_enter(&lmrc->l_thread_lock);
		(void) cv_reltimedwait(&lmrc->l_thread_cv, &lmrc->l_thread_lock,
		    drv_usectohz(60 * MICROSEC), TR_SEC);
		mutex_exit(&lmrc->l_thread_lock);

		if (lmrc->l_thread_stop)
			continue;

		lmrc->l_fw_fault = lmrc_check_fw_fault(lmrc);

		/*
		 * Check all targets for timed-out commands. If we find any
		 * and fail to abort them, we pretend the FW has faulted to
		 * trigger a reset.
		 */
		if (!lmrc->l_fw_fault) {
			for (i = 0; i < ARRAY_SIZE(lmrc->l_targets); i++) {
				if (lmrc_tgt_timeout_cmds(lmrc,
				    &lmrc->l_targets[i]) != DDI_SUCCESS) {
					lmrc->l_fw_fault = B_TRUE;
					break;
				}
			}
		}

		/*
		 * If the FW is faulted, try to recover by performing a reset.
		 */
		if (lmrc->l_fw_fault) {
			int ret;

			lmrc_disable_intr(lmrc);

			/*
			 * Even if the reset failed, it will have stopped the
			 * controller and we can complete all outstanding
			 * commands.
			 */
			ret = lmrc_reset_ctrl(lmrc);

			(void) lmrc_abort_outstanding_mfi(lmrc,
			    LMRC_MAX_MFI_CMDS);

			for (i = 0; i < ARRAY_SIZE(lmrc->l_targets); i++)
				lmrc_tgt_complete_cmds(lmrc,
				    &lmrc->l_targets[i]);

			if (ret != DDI_SUCCESS) {
				dev_err(lmrc->l_dip, CE_WARN, "reset failed");
				continue;
			}

			if (lmrc_transition_to_ready(lmrc) != DDI_SUCCESS)
				continue;

			if (lmrc_ioc_init(lmrc) != DDI_SUCCESS)
				continue;

			lmrc_enable_intr(lmrc);

			if (lmrc_start_aen(lmrc) != DDI_SUCCESS) {
				dev_err(lmrc->l_dip, CE_WARN,
				    "failed to re-initiate AEN");
				continue;
			}

			lmrc->l_fw_fault = lmrc_check_fw_fault(lmrc);
		}
	} while (!lmrc->l_thread_stop);

	thread_exit();
}

/*
 * lmrc_transition_to_ready
 *
 * Move firmware to ready state. At attach time, the FW can potentially be in
 * any one of several possible states. If the FW is in operational, waiting-for-
 * handshake states, take steps to bring it to ready state. Otherwise, wait for
 * the FW to reach ready state.
 */
static int
lmrc_transition_to_ready(lmrc_t *lmrc)
{
	uint32_t status, new_status;
	uint32_t fw_state;
	uint8_t max_wait;
	uint_t i;

	status = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD0_OFFSET);
	fw_state = LMRC_FW_STATE(status);
	max_wait = LMRC_RESET_TIMEOUT;

	while (fw_state != LMRC_FW_STATE_READY) {
		switch (fw_state) {
		case LMRC_FW_STATE_FAULT:
			dev_err(lmrc->l_dip, CE_NOTE, "FW is in fault state!");
			if (lmrc_reset_ctrl(lmrc) != DDI_SUCCESS)
				return (DDI_FAILURE);
			break;

		case LMRC_FW_STATE_WAIT_HANDSHAKE:
			/* Set the CLR bit in inbound doorbell */
			lmrc_write_reg(lmrc, MPI2_DOORBELL_OFFSET,
			    MFI_INIT_CLEAR_HANDSHAKE | MFI_INIT_HOTPLUG);
			break;

		case LMRC_FW_STATE_BOOT_MSG_PENDING:
			lmrc_write_reg(lmrc, MPI2_DOORBELL_OFFSET,
			    MFI_INIT_HOTPLUG);
			break;

		case LMRC_FW_STATE_OPERATIONAL:
			/* Bring it to READY state, wait up to 10s */
			lmrc_disable_intr(lmrc);
			lmrc_write_reg(lmrc, MPI2_DOORBELL_OFFSET,
			    MFI_RESET_FLAGS);
			(void) lmrc_wait_for_reg(lmrc, MPI2_DOORBELL_OFFSET, 1,
			    0, 10);
			break;

		case LMRC_FW_STATE_UNDEFINED:
			/* This state should not last for more than 2 sec */
		case LMRC_FW_STATE_BB_INIT:
		case LMRC_FW_STATE_FW_INIT:
		case LMRC_FW_STATE_FW_INIT_2:
		case LMRC_FW_STATE_DEVICE_SCAN:
		case LMRC_FW_STATE_FLUSH_CACHE:
			break;
		default:
			dev_err(lmrc->l_dip, CE_WARN, "Unknown FW state %x",
			    fw_state);
			return (DDI_FAILURE);
		}

		/*
		 * The current state should not last for more than max_wait
		 * seconds.
		 */
		for (i = 0; i < max_wait * 1000; i++) {
			new_status = lmrc_read_reg(lmrc,
			    MPI26_SCRATCHPAD0_OFFSET);

			if (status != new_status)
				break;

			delay(drv_usectohz(MILLISEC));
		}

		if (new_status == status) {
			dev_err(lmrc->l_dip, CE_WARN,
			    "FW state (%x) hasn't changed in %d seconds",
			    fw_state, max_wait);
			return (DDI_FAILURE);
		}

		status = new_status;
		fw_state = LMRC_FW_STATE(status);
	}

	if (lmrc_check_acc_handle(lmrc->l_reghandle) != DDI_FM_OK)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

/*
 * lmrc_adapter_init
 *
 * Get the hardware and firmware into a usable state, and fetch some basic
 * information from the registers to calculate sizes of basic data structures.
 */
int
lmrc_adapter_init(lmrc_t *lmrc)
{
	uint32_t reg;
	int ret;
	int i;

	ret = lmrc_transition_to_ready(lmrc);
	if (ret != DDI_SUCCESS)
		return (ret);

	/*
	 * Get maximum RAID map size.
	 */
	reg = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD2_OFFSET);
	lmrc->l_max_raid_map_sz = LMRC_MAX_RAID_MAP_SZ(reg);

	lmrc->l_max_reply_queues = 1;
	lmrc->l_rphi[0] = MPI2_REPLY_POST_HOST_INDEX_OFFSET;

	/*
	 * Apparently, bit 27 of the scratch pad register indicates whether
	 * MSI-X is supported by the firmware.
	 */
	reg = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD0_OFFSET);

	if (LMRC_FW_MSIX_ENABLED(reg)) {
		lmrc->l_fw_msix_enabled = B_TRUE;

		reg = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD1_OFFSET);
		lmrc->l_max_reply_queues = LMRC_MAX_REPLY_QUEUES_EXT(reg);

		if (lmrc->l_max_reply_queues > LMRC_MAX_REPLY_POST_HOST_INDEX) {
			lmrc->l_msix_combined = B_TRUE;
			lmrc->l_rphi[0] =
			    MPI25_SUP_REPLY_POST_HOST_INDEX_OFFSET;
		}

		/*
		 * Compute reply post index register addresses 1-15.
		 */
		for (i = 1; i < LMRC_MAX_REPLY_POST_HOST_INDEX; i++) {
			lmrc->l_rphi[i] = i * 0x10 +
			    MPI25_SUP_REPLY_POST_HOST_INDEX_OFFSET;
		}
	}

	/*
	 * Get the number of commands the firmware supports. Use one less,
	 * because reply_q_depth is based on one more than this. XXX: Why?
	 */
	reg = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD0_OFFSET);
	lmrc->l_max_fw_cmds = LMRC_FW_MAX_CMD(reg) - 1;

	if (lmrc->l_max_fw_cmds < LMRC_MAX_MFI_CMDS) {
		dev_err(lmrc->l_dip, CE_WARN, "!max_fw_cmds too low: %d",
		    lmrc->l_max_fw_cmds);
		return (DDI_FAILURE);
	}

	/*
	 * Reserve some commands for MFI, the remainder is for SCSI commands.
	 */
	lmrc->l_max_scsi_cmds = lmrc->l_max_fw_cmds - LMRC_MAX_MFI_CMDS;

	/*
	 * XXX: This magic calculation isn't explained anywhere. Let's see...
	 * lmrc_max_fw_cmds + 1 gives us what was reported in the register,
	 * That + 15 is for rounding it up the next multiple of 16, which
	 * / 16 * 16 does.
	 * And apparently we want twice that much for queue depth. Why?
	 *
	 * So in reality, the queue depth is based on at least one more than
	 * lmrc_max_fw_cmds, but it could be even more. That makes the above
	 * statement about lmrc_max_fw_cmds questionable.
	 */
	lmrc->l_reply_q_depth = (lmrc->l_max_fw_cmds + 1 + 15) / 16 * 16 * 2;

	/* Allocation size of one reply queue, based on depth. */
	lmrc->l_reply_alloc_sz =
	    sizeof (Mpi2ReplyDescriptorsUnion_t) * lmrc->l_reply_q_depth;

	/* Allocation size of the DMA memory used for all MPI I/O frames. */
	lmrc->l_io_frames_alloc_sz = LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE *
	    (lmrc->l_max_fw_cmds + 2);

	/*
	 * If LMRC_EXT_CHAIN_SIZE_SUPPORT is set in scratch pad 1, firmware
	 * supports an extended IO chain frame which is 4 times the size of a
	 * legacy firmware frame.
	 * Legacy Firmware frame size is (8 * 128) = 1K
	 * 1M IO Firmware frame size is (8 * 128 * 4) = 4K
	 */
	reg = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD1_OFFSET);
	lmrc->l_max_chain_frame_sz = LMRC_MAX_CHAIN_SIZE(reg) *
	    (LMRC_EXT_CHAIN_SIZE_SUPPORT(reg) ? LMRC_1MB_IO : LMRC_256K_IO);

	/*
	 * Check whether the controller supports DMA to the full 64bit address
	 * space.
	 */
	lmrc->l_64bit_dma_support = LMRC_64BIT_DMA_SUPPORT(reg);

	/*
	 * We use a I/O frame size of 256 bytes, that is what
	 * LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE is set to.
	 *
	 * The offset of the SGL in the I/O frame is 128, so
	 * there are 128 bytes left for 8 SGEs of 16 bytes each.
	 */
	lmrc->l_max_sge_in_main_msg =
	    (LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE -
	    offsetof(Mpi25SCSIIORequest_t, SGL)) / sizeof (Mpi25SGEIOUnion_t);

	/*
	 * Similarly, number of SGE in a SGE chain frame.
	 */
	lmrc->l_max_sge_in_chain =
	    lmrc->l_max_chain_frame_sz / sizeof (Mpi25SGEIOUnion_t);

	/*
	 * The total number of SGE we support in a transfer is sum of
	 * the above two, minus one for the link (last SGE in main msg).
	 *
	 * XXX: So why -2?
	 */
	lmrc->l_max_num_sge =
	    lmrc->l_max_sge_in_main_msg + lmrc->l_max_sge_in_chain - 2;

	/*
	 * The offset of the last SGE in the I/O request, used for linking
	 * the SGE chain frame if necessary.
	 */
	lmrc->l_chain_offset_io_request =
	    (LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE -
	    sizeof (Mpi25SGEIOUnion_t)) / sizeof (Mpi25SGEIOUnion_t);

	/*
	 * For MFI passthru, the link to the SGE chain frame is always
	 * the first SGE in the I/O frame, the other SGEs in the I/O frame
	 * will not be used.
	 */
	lmrc->l_chain_offset_mfi_pthru =
	    offsetof(Mpi25SCSIIORequest_t, SGL) / sizeof (Mpi25SGEIOUnion_t);


	reg = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD3_OFFSET);
	if (LMRC_NVME_PAGE_SHIFT(reg) > LMRC_DEFAULT_NVME_PAGE_SHIFT) {
		lmrc->l_nvme_page_sz = 1 << LMRC_NVME_PAGE_SHIFT(reg);
		dev_err(lmrc->l_dip, CE_NOTE, "!NVME page size: %ld",
		    lmrc->l_nvme_page_sz);
	}

	reg = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD1_OFFSET);
	lmrc->l_fw_sync_cache_support = LMRC_SYNC_CACHE_SUPPORT(reg);

	if (lmrc->l_class == LMRC_ACLASS_AERO) {
		reg = lmrc_read_reg(lmrc, MPI26_SCRATCHPAD1_OFFSET);
		lmrc->l_atomic_desc_support =
		    LMRC_ATOMIC_DESCRIPTOR_SUPPORT(reg);
	}

	return (DDI_SUCCESS);
}

/*
 * lmrc_ioc_init
 *
 * Manually build a MFI IOC INIT command to setup basic operating parameters
 * such as the DMA parameters for the I/O request frames and the reply post
 * queues. Send the IOC INIT command using a special request descriptor which
 * directly includes the physical address of the MFI command frame.
 *
 * After this command completes, the controller is ready to accept MPT commands
 * using the normal method of placing it in the I/O request DMA memory and
 * writing a MPT request descripter to the appropriate registers.
 */
int
lmrc_ioc_init(lmrc_t *lmrc)
{
	lmrc_mfi_cmd_t *mfi = lmrc_get_mfi(lmrc);
	lmrc_mfi_header_t *hdr = &mfi->mfi_frame->mf_hdr;
	lmrc_mfi_init_payload_t *init = &mfi->mfi_frame->mf_init;
	lmrc_req_desc_t req_desc;
	Mpi2IOCInitRequest_t *IOCInitMsg;
	lmrc_dma_t dma;
	int ret = DDI_SUCCESS;

	ret = lmrc_dma_alloc(lmrc, lmrc->l_dma_attr, &dma,
	    sizeof (Mpi2IOCInitRequest_t), 256, DDI_DMA_CONSISTENT);
	if (ret != DDI_SUCCESS) {
		lmrc_put_mfi(mfi);
		dev_err(lmrc->l_dip, CE_WARN,
		    "!%s: failed to allocate IOC command", __func__);
		return (DDI_FAILURE);
	}

	IOCInitMsg = dma.ld_buf;
	IOCInitMsg->Function = MPI2_FUNCTION_IOC_INIT;
	IOCInitMsg->WhoInit = MPI2_WHOINIT_HOST_DRIVER;
	IOCInitMsg->MsgVersion = MPI2_VERSION;
	IOCInitMsg->HeaderVersion = MPI2_HEADER_VERSION;
	IOCInitMsg->SystemRequestFrameSize =
	    LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE / 4;
	IOCInitMsg->ReplyDescriptorPostQueueDepth = lmrc->l_reply_q_depth;
	lmrc_dma_set_addr64(&lmrc->l_reply_dma,
	    (uint64_t *)&IOCInitMsg->ReplyDescriptorPostQueueAddress);
	lmrc_dma_set_addr64(&lmrc->l_ioreq_dma,
	    (uint64_t *)&IOCInitMsg->SystemRequestFrameBaseAddress);
	IOCInitMsg->HostMSIxVectors = lmrc->l_max_reply_queues;
	/* XXX: Why NVMe? */
	IOCInitMsg->HostPageSize = LMRC_DEFAULT_NVME_PAGE_SHIFT;

	hdr->mh_cmd = MFI_CMD_INIT;
	hdr->mh_cmd_status = MFI_STAT_INVALID_STATUS;
	hdr->mh_flags = MFI_FRAME_DONT_POST_IN_REPLY_QUEUE;

	hdr->mh_drv_opts.mc_support_additional_msix = 1;
	hdr->mh_drv_opts.mc_support_max_255lds = 1;
	hdr->mh_drv_opts.mc_support_ndrive_r1_lb = 1;
	hdr->mh_drv_opts.mc_support_security_protocol_cmds_fw = 1;
	hdr->mh_drv_opts.mc_support_ext_io_size = 1;

	hdr->mh_data_xfer_len = lmrc_dma_get_size(&dma);

	lmrc_dma_set_addr64(&dma, &init->mi_queue_info_new_phys_addr);

	lmrc_dma_set_addr64(&mfi->mfi_frame_dma, &req_desc.rd_reg);
	VERIFY0(req_desc.rd_mfa_io.RequestFlags);
	req_desc.rd_mfa_io.RequestFlags = LMRC_REQ_DESCRIPT_FLAGS_MFA;

	lmrc_disable_intr(lmrc);
	if (!lmrc_wait_for_reg(lmrc, MPI2_DOORBELL_OFFSET, 1, 0, 10))
		return (DDI_FAILURE);

	(void) ddi_dma_sync(dma.ld_hdl, 0, dma.ld_len, DDI_DMA_SYNC_FORDEV);
	(void) ddi_dma_sync(mfi->mfi_frame_dma.ld_hdl, 0,
	    mfi->mfi_frame_dma.ld_len, DDI_DMA_SYNC_FORDEV);

	lmrc_send_request(lmrc, req_desc);

	mutex_enter(&mfi->mfi_lock);
	ret = lmrc_poll_mfi(lmrc, mfi, LMRC_INTERNAL_CMD_WAIT_TIME);
	mutex_exit(&mfi->mfi_lock);

	if (ret != DDI_SUCCESS) {
		if (hdr->mh_cmd_status != MFI_STAT_INVALID_STATUS)
			dev_err(lmrc->l_dip, CE_WARN,
			    "!IOC Init failed, status = 0x%x",
			    hdr->mh_cmd_status);
	}

	lmrc_dma_free(&dma);
	lmrc_put_mfi(mfi);

	return (ret);
}

/*
 * lmrc_get_ctrl_info
 *
 * Build a MFI DCMD to get controller information from FW. Update the copy in
 * the soft state.
 */
static int
lmrc_get_ctrl_info(lmrc_t *lmrc)
{
	lmrc_ctrl_info_t *ci = lmrc->l_ctrl_info;
	lmrc_mfi_cmd_t *mfi;
	int ret;

	mfi = lmrc_get_dcmd(lmrc, MFI_FRAME_DIR_READ, LMRC_DCMD_CTRL_GET_INFO,
	    sizeof (lmrc_ctrl_info_t), 1);

	if (mfi == NULL)
		return (DDI_FAILURE);

	ret = lmrc_issue_blocked_mfi(lmrc, mfi);

	if (ret != DDI_SUCCESS)
		goto out;

	(void) ddi_dma_sync(mfi->mfi_data_dma.ld_hdl, 0,
	    mfi->mfi_data_dma.ld_len, DDI_DMA_SYNC_FORKERNEL);
	bcopy(mfi->mfi_data_dma.ld_buf, ci, sizeof (lmrc_ctrl_info_t));

out:
	lmrc_put_dcmd(lmrc, mfi);
	return (ret);
}

/*
 * lmrc_fw_init
 *
 * Complete firmware initialization. At this point, we can already send MFI
 * commands. so we can start by getting the controller information from the
 * firmware and set up things in our soft state. Next we issue the commands
 * to get the PD map and RAID map, which will complete asynchronously when
 * new information is available and then re-send themselves.
 */
int
lmrc_fw_init(lmrc_t *lmrc)
{
	int drv_max_lds = LMRC_MAX_LOGICAL_DRIVES;
	lmrc_ctrl_info_t *ci = lmrc->l_ctrl_info;
	int ret;

	ret = lmrc_get_ctrl_info(lmrc);
	if (ret != DDI_SUCCESS) {
		dev_err(lmrc->l_dip, CE_WARN, "!Unable to get FW ctrl info.");
		return (DDI_FAILURE);
	}

	lmrc->l_disable_online_ctrl_reset =
	    ci->ci_prop.cp_disable_online_ctrl_reset == 1;

	lmrc->l_max_256_vd_support =
	    ci->ci_adapter_opts3.ao3_support_max_ext_lds == 1;

	if (ci->ci_max_lds > 64) {
		lmrc->l_max_256_vd_support = B_TRUE;
		drv_max_lds = LMRC_MAX_LOGICAL_DRIVES_EXT;
	}

	lmrc->l_fw_supported_vd_count = min(ci->ci_max_lds, drv_max_lds);

	lmrc->l_fw_supported_pd_count = min(ci->ci_max_pds, LMRC_MAX_PHYS_DEV);

	lmrc->l_max_map_sz = lmrc->l_current_map_sz =
	    lmrc->l_max_raid_map_sz * LMRC_MIN_MAP_SIZE;

	lmrc->l_use_seqnum_jbod_fp =
	    ci->ci_adapter_opts3.ao3_use_seq_num_jbod_FP != 0;

	lmrc->l_pdmap_tgtid_support =
	    ci->ci_adapter_opts4.ao4_support_pd_map_target_id != 0;

	return (DDI_SUCCESS);
}


/*
 * lmrc_ctrl_shutdown
 *
 * Called by lmrc_quiesce() to send a shutdown command to the controller.
 * Cannot use locks, therefore cannot use lmrc_get_dcmd() or lmrc_get_mfi().
 */
int
lmrc_ctrl_shutdown(lmrc_t *lmrc)
{
	lmrc_mfi_cmd_t *mfi = list_remove_head(&lmrc->l_mfi_cmd_list);
	lmrc_mfi_header_t *hdr;
	lmrc_mfi_dcmd_payload_t *dcmd;

	if (mfi == NULL)
		return (DDI_FAILURE);

	hdr = &mfi->mfi_frame->mf_hdr;
	dcmd = &mfi->mfi_frame->mf_dcmd;

	hdr->mh_cmd = MFI_CMD_DCMD;
	hdr->mh_flags = MFI_FRAME_DONT_POST_IN_REPLY_QUEUE;
	dcmd->md_opcode = LMRC_DCMD_CTRL_SHUTDOWN;

	lmrc_disable_intr(lmrc);
	lmrc_issue_mfi(lmrc, mfi, NULL);

	return (DDI_SUCCESS);
}

/*
 * driver target state management
 *
 * The soft state of the controller instance keeps a pre-allocated array of
 * target structures for all possible targets, even though only a small number
 * of them are likely to be used. Each target structure contains back link to
 * the soft state and a mutex, which are never cleared or changed when a target
 * is added or removed.
 */

/*
 * lmrc_tgt_init
 *
 * Initialize the tgt structure for a newly discovered tgt. The same tgt
 * structure is used for PDs and LDs, the distinction can be made by the
 * presence or absence of tgt_pd_info. LDs are always of type disk, the type
 * of PDs is taken from their pd_info. If a device has no SAS WWN, we'll fake
 * the interconnect type to be PARALLEL to make sure device address isn't
 * misunderstood as a WWN by devfsadm.
 */
void
lmrc_tgt_init(lmrc_tgt_t *tgt, uint16_t dev_id, char *addr,
    lmrc_pd_info_t *pd_info)
{
	rw_enter(&tgt->tgt_lock, RW_WRITER);

	bzero(&tgt->tgt_dev_id,
	    sizeof (lmrc_tgt_t) - offsetof(lmrc_tgt_t, tgt_dev_id));

	tgt->tgt_dev_id = dev_id;
	tgt->tgt_pd_info = pd_info;
	tgt->tgt_interconnect_type = INTERCONNECT_SAS;

	if (pd_info == NULL) {
		tgt->tgt_type = DTYPE_DIRECT;
	} else {
		tgt->tgt_type = pd_info->pd_scsi_dev_type;
	}

	(void) strlcpy(tgt->tgt_wwnstr, addr, sizeof (tgt->tgt_wwnstr));
	if (scsi_wwnstr_to_wwn(tgt->tgt_wwnstr, &tgt->tgt_wwn) != DDI_SUCCESS) {
		tgt->tgt_interconnect_type = INTERCONNECT_PARALLEL;
		tgt->tgt_wwn = dev_id;
	}

	rw_exit(&tgt->tgt_lock);
}

/*
 * lmrc_tgt_clear
 *
 * Reset the tgt structure of a target which is no longer present.
 */
void
lmrc_tgt_clear(lmrc_tgt_t *tgt)
{
	rw_enter(&tgt->tgt_lock, RW_WRITER);

	if (tgt->tgt_pd_info != NULL)
		kmem_free(tgt->tgt_pd_info, sizeof (lmrc_pd_info_t));

	bzero(&tgt->tgt_dev_id,
	    sizeof (lmrc_tgt_t) - offsetof(lmrc_tgt_t, tgt_dev_id));
	tgt->tgt_dev_id = LMRC_DEVHDL_INVALID;
	rw_exit(&tgt->tgt_lock);
}

/*
 * lmrc_tgt_find
 *
 * Walk the target list and find a tgt matching the given scsi_device.
 * Return the tgt read-locked. The targets_lock mutex must be held the
 * whole time.
 */
lmrc_tgt_t *
lmrc_tgt_find(lmrc_t *lmrc, struct scsi_device *sd)
{
	const char *ua = scsi_device_unit_address(sd);
	char *comma, wwnstr[SCSI_WWN_BUFLEN];
	uint64_t wwn;
	unsigned long tgtid;
	lmrc_tgt_t *tgt;
	size_t i;

	VERIFY(ua != NULL);

	(void) strlcpy(wwnstr, ua, sizeof (wwnstr));

	/*
	 * If the unit address is a valid target ID and within range for
	 * VD IDs, use that.
	 */
	if (ddi_strtoul(wwnstr, &comma, 10, &tgtid) == 0 &&
	    *comma == ',' &&
	    tgtid <= lmrc->l_fw_supported_vd_count) {
		tgt = &lmrc->l_targets[tgtid];

		rw_enter(&tgt->tgt_lock, RW_READER);
		if (tgt->tgt_dev_id == tgtid &&
		    tgt->tgt_wwn == tgtid) {
			return (tgt);
		}
		rw_exit(&tgt->tgt_lock);
	}

	/* Chop off ",lun" as scsi_wwnstr_to_wwn() can't handle it. */
	comma = strchr(wwnstr, ',');
	if (comma != NULL)
		*comma = '\0';

	/* Else, if unit address is a valid WWN, look for that. */
	if (scsi_wwnstr_to_wwn(wwnstr, &wwn) == DDI_SUCCESS) {
		for (i = 0; i < ARRAY_SIZE(lmrc->l_targets); i++) {
			tgt = &lmrc->l_targets[i];

			rw_enter(&tgt->tgt_lock, RW_READER);
			if (tgt->tgt_wwn == wwn) {
				return (tgt);
			}
			rw_exit(&tgt->tgt_lock);
		}
	} else {
		/* Do it the hard way and compare wwnstr. */
		for (i = 0; i < ARRAY_SIZE(lmrc->l_targets); i++) {
			tgt = &lmrc->l_targets[i];

			rw_enter(&tgt->tgt_lock, RW_READER);
			if (strcmp(tgt->tgt_wwnstr, wwnstr) == 0) {
				return (tgt);
			}
			rw_exit(&tgt->tgt_lock);
		}
	}

	return (NULL);
}

/*
 * MPT/MFI command management
 *
 * For each kind of command, MFI and MPT, the driver keeps an array of pre-
 * allocated and pre-initialized commands. Additionally, it keeps two lists of
 * currently unused commands. A set of functions is provided for each list to
 * get and put commands from/to the list. Commands are initialized during get(),
 * because having completed commands on the list can help in certain cases
 * during debugging.
 *
 * MPT commands in use for I/O are kept on a active command list of the target
 * they are addressing. All other types of commands are not kept on any list
 * while they are being processed by the hardware. When walking the command
 * arrays, busy commands not associated with a target can be distinguished by
 * not being linked on any list.
 */

/*
 * lmrc_get_mpt
 *
 * Get a MPT command from the list and initialize it. Return the command locked.
 * Return NULL if the MPT command list is empty.
 */
lmrc_mpt_cmd_t *
lmrc_get_mpt(lmrc_t *lmrc)
{
	lmrc_mpt_cmd_t *mpt;
	Mpi25SCSIIORequest_t *io_req;

	mutex_enter(&lmrc->l_mpt_cmd_lock);
	mpt = list_remove_head(&lmrc->l_mpt_cmd_list);
	mutex_exit(&lmrc->l_mpt_cmd_lock);
	if (mpt == NULL)
		return (NULL);

	mutex_enter(&mpt->mpt_lock);
	bzero(mpt->mpt_io_frame, LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE);
	bzero(mpt->mpt_chain_dma.ld_buf, mpt->mpt_chain_dma.ld_len);
	bzero(mpt->mpt_sense_dma.ld_buf, mpt->mpt_sense_dma.ld_len);

	mpt->mpt_mfi = NULL;
	mpt->mpt_pkt = NULL;

	/* Set the offset of the SGL entries inside the MPT command. */
	io_req = mpt->mpt_io_frame;
	io_req->SGLOffset0 = offsetof(Mpi25SCSIIORequest_t, SGL) / 4;

	mpt->mpt_complete = B_FALSE;
	cv_init(&mpt->mpt_cv, NULL, CV_DRIVER, NULL);

	return (mpt);
}

/*
 * lmrc_put_mpt
 *
 * Put a MPT command back on the list. The command lock must be held when this
 * function is called, being unlocked only after the command has been put on
 * the free list. The command CV is destroyed, thereby asserting that no one is
 * still waiting on it.
 */
void
lmrc_put_mpt(lmrc_mpt_cmd_t *mpt)
{
	lmrc_t *lmrc = mpt->mpt_lmrc;

	VERIFY(lmrc != NULL);

	ASSERT0(list_link_active(&mpt->mpt_node));
	ASSERT(mutex_owned(&mpt->mpt_lock));
	cv_destroy(&mpt->mpt_cv);

	mutex_enter(&lmrc->l_mpt_cmd_lock);
	list_insert_tail(&lmrc->l_mpt_cmd_list, mpt);
	mutex_exit(&lmrc->l_mpt_cmd_lock);
	mutex_exit(&mpt->mpt_lock);
}

/*
 * lmrc_get_mfi
 *
 * Get a MFI command from the list and initialize it.
 */
lmrc_mfi_cmd_t *
lmrc_get_mfi(lmrc_t *lmrc)
{
	lmrc_mfi_cmd_t *mfi;

	mutex_enter(&lmrc->l_mfi_cmd_lock);
	mfi = list_remove_head(&lmrc->l_mfi_cmd_list);
	mutex_exit(&lmrc->l_mfi_cmd_lock);
	VERIFY(mfi != NULL);

	mutex_enter(&mfi->mfi_lock);
	bzero(mfi->mfi_frame, sizeof (lmrc_mfi_frame_t));
	mfi->mfi_frame->mf_hdr.mh_context = mfi->mfi_idx;
	mfi->mfi_callback = NULL;

	cv_init(&mfi->mfi_cv, NULL, CV_DRIVER, NULL);
	mutex_exit(&mfi->mfi_lock);

	return (mfi);
}

/*
 * lmrc_put_mfi
 *
 * Put a MFI command back on the list. Destroy the CV, thereby
 * asserting that no one is waiting on it.
 */
void
lmrc_put_mfi(lmrc_mfi_cmd_t *mfi)
{
	lmrc_t *lmrc = mfi->mfi_lmrc;

	VERIFY(lmrc != NULL);

	ASSERT0(list_link_active(&mfi->mfi_node));

	mutex_enter(&mfi->mfi_lock);

	cv_destroy(&mfi->mfi_cv);

	mutex_enter(&lmrc->l_mfi_cmd_lock);
	list_insert_tail(&lmrc->l_mfi_cmd_list, mfi);
	mutex_exit(&lmrc->l_mfi_cmd_lock);
	mutex_exit(&mfi->mfi_lock);
}

/*
 * lmrc_abort_outstanding_mfi
 *
 * Walk the MFI cmd array and abort each command which is still outstanding,
 * which is indicated by not being linked on l_mfi_cmd_list.
 *
 * As a special case, if the FW is in fault state, just call each commands
 * completion callback.
 */
int
lmrc_abort_outstanding_mfi(lmrc_t *lmrc, const size_t ncmd)
{
	int ret;
	int i;

	for (i = 0; i < ncmd; i++) {
		lmrc_mfi_cmd_t *mfi = lmrc->l_mfi_cmds[i];

		mutex_enter(&mfi->mfi_lock);
		if (list_link_active(&mfi->mfi_node)) {
			mutex_exit(&mfi->mfi_lock);
			continue;
		}

		/*
		 * If the FW is faulted, wake up anyone waiting on the command
		 * to clean it up.
		 */
		if (lmrc->l_fw_fault) {
			if (mfi->mfi_callback != NULL)
				mfi->mfi_callback(lmrc, mfi);
			mutex_exit(&mfi->mfi_lock);
			continue;
		}

		ret = lmrc_abort_cmd(lmrc, mfi);
		mutex_exit(&mfi->mfi_lock);
		if (ret != DDI_SUCCESS)
			return (ret);

		lmrc_dma_free(&mfi->mfi_data_dma);
		lmrc_put_mfi(mfi);
	}

	return (DDI_SUCCESS);
}

/*
 * lmrc_get_dcmd
 *
 * Build a MFI DCMD with DMA memory for data transfers.
 */
lmrc_mfi_cmd_t *
lmrc_get_dcmd(lmrc_t *lmrc, uint16_t flags, uint32_t opcode, uint32_t xferlen,
    uint_t align)
{
	lmrc_mfi_cmd_t *mfi = lmrc_get_mfi(lmrc);
	lmrc_mfi_header_t *hdr = &mfi->mfi_frame->mf_hdr;
	lmrc_mfi_dcmd_payload_t *dcmd = &mfi->mfi_frame->mf_dcmd;
	lmrc_dma_t *dma = &mfi->mfi_data_dma;
	int ret;

	hdr->mh_cmd = MFI_CMD_DCMD;
	hdr->mh_flags = flags;

	dcmd->md_opcode = opcode;

	if ((flags & MFI_FRAME_DIR_READ) != 0 ||
	    (flags & MFI_FRAME_DIR_WRITE) != 0) {
		ret = lmrc_dma_alloc(lmrc, lmrc->l_dma_attr, dma, xferlen,
		    align, DDI_DMA_CONSISTENT);
		if (ret != DDI_SUCCESS) {
			lmrc_put_mfi(mfi);
			return (NULL);
		}

		hdr->mh_flags |= MFI_FRAME_SGL64;
		hdr->mh_sge_count = 1;
		hdr->mh_data_xfer_len = lmrc_dma_get_size(dma);

		dcmd->md_sgl.ms64_length = lmrc_dma_get_size(dma);
		lmrc_dma_set_addr64(dma, &dcmd->md_sgl.ms64_phys_addr);
	}

	return (mfi);
}

/*
 * lmrc_put_dcmd
 *
 * Free the DMA memory of a MFI DCMD and return the command back on the list.
 */
void
lmrc_put_dcmd(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi)
{
	lmrc_dma_free(&mfi->mfi_data_dma);
	lmrc_put_mfi(mfi);
}


/*
 * Asynchronous Event Notifications
 */
/*
 * lmrc_get_event_log_info
 *
 * Get the Event Log Info from the firmware.
 */
static int
lmrc_get_event_log_info(lmrc_t *lmrc, lmrc_evt_log_info_t *eli)
{
	lmrc_mfi_cmd_t *mfi;
	int ret;

	mfi = lmrc_get_dcmd(lmrc, MFI_FRAME_DIR_READ,
	    LMRC_DCMD_CTRL_EVENT_GET_INFO, sizeof (lmrc_evt_log_info_t), 1);

	if (mfi == NULL)
		return (DDI_FAILURE);

	ret = lmrc_issue_blocked_mfi(lmrc, mfi);

	if (ret != DDI_SUCCESS)
		goto out;

	bcopy(mfi->mfi_data_dma.ld_buf, eli, sizeof (lmrc_evt_log_info_t));

out:
	lmrc_put_dcmd(lmrc, mfi);
	return (ret);
}

/*
 * lmrc_aen_handler
 *
 * Check the event code and handle it as needed. In the case of PD or LD related
 * events, invoke their special handlers.
 */
static void
lmrc_aen_handler(void *arg)
{
	lmrc_mfi_cmd_t *mfi = arg;
	lmrc_t *lmrc = mfi->mfi_lmrc;
	lmrc_evt_t *evt = mfi->mfi_data_dma.ld_buf;
	lmrc_mfi_dcmd_payload_t *dcmd = &mfi->mfi_frame->mf_dcmd;
	int ret = DDI_FAILURE;

	/* Controller & Configuration specific events */
	switch (evt->evt_code) {
	case LMRC_EVT_CFG_CLEARED:
	case LMRC_EVT_CTRL_HOST_BUS_SCAN_REQD:
	case LMRC_EVT_FOREIGN_CFG_IMPORTED:
		ret = lmrc_get_pd_list(lmrc);
		if (ret != DDI_SUCCESS)
			break;

		ret = lmrc_get_ld_list(lmrc);
		break;

	case LMRC_EVT_CTRL_PROP_CHANGED:
		ret = lmrc_get_ctrl_info(lmrc);
		break;

	case LMRC_EVT_CTRL_PATROL_READ_START:
	case LMRC_EVT_CTRL_PATROL_READ_RESUMED:
	case LMRC_EVT_CTRL_PATROL_READ_COMPLETE:
	case LMRC_EVT_CTRL_PATROL_READ_CANT_START:
	case LMRC_EVT_CTRL_PERF_COLLECTION:
	case LMRC_EVT_CTRL_BOOTDEV_SET:
	case LMRC_EVT_CTRL_BOOTDEV_RESET:
	case LMRC_EVT_CTRL_PERSONALITY_CHANGE:
	case LMRC_EVT_CTRL_PERSONALITY_CHANGE_PEND:
	case LMRC_EVT_CTRL_NR_OF_VALID_SNAPDUMP:
		break;

	default:
		/* LD-specific events */
		if ((evt->evt_locale & LMRC_EVT_LOCALE_LD) != 0)
			ret = lmrc_raid_aen_handler(lmrc, evt);

		/* PD-specific events */
		else if ((evt->evt_locale & LMRC_EVT_LOCALE_PD) != 0)
			ret = lmrc_phys_aen_handler(lmrc, evt);

		if (ret != DDI_SUCCESS) {
			dev_err(lmrc->l_dip, CE_NOTE, "!unknown AEN received, "
			    "seqnum = %d, timestamp = %d, code = %x, "
			    "locale = %x, class = %d, argtype = %d",
			    evt->evt_seqnum, evt->evt_timestamp, evt->evt_code,
			    evt->evt_locale, evt->evt_class, evt->evt_argtype);
		}
	}

	dev_err(lmrc->l_dip, CE_NOTE, "!%s", evt->evt_descr);

	/*
	 * Just reuse the command in its entirety. Increase the sequence
	 * number.
	 */
	dcmd->md_mbox_32[0] = evt->evt_seqnum + 1;
	mutex_enter(&mfi->mfi_lock);
	lmrc_issue_mfi(lmrc, mfi, lmrc_complete_aen);
	mutex_exit(&mfi->mfi_lock);
}

/*
 * lmrc_complete_aen
 *
 * An AEN was received, so schedule a taskq to process it.
 */
static void
lmrc_complete_aen(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi)
{
	lmrc_mfi_header_t *hdr = &mfi->mfi_frame->mf_hdr;

	ASSERT(mutex_owned(&mfi->mfi_lock));

	if (hdr->mh_cmd_status != MFI_STAT_OK) {
		/* Was the command aborted? */
		if (hdr->mh_cmd_status == MFI_STAT_NOT_FOUND)
			return;

		dev_err(lmrc->l_dip, CE_WARN,
		    "!AEN failed, status = %d",
		    hdr->mh_cmd_status);
		taskq_dispatch_ent(lmrc->l_taskq, (task_func_t *)lmrc_put_mfi,
		    mfi, TQ_NOSLEEP, &mfi->mfi_tqent);
		return;
	}

	taskq_dispatch_ent(lmrc->l_taskq, lmrc_aen_handler, mfi, TQ_NOSLEEP,
	    &mfi->mfi_tqent);
}

/*
 * lmrc_register_aen
 *
 * In FreeBSD, this function checks for an existing AEN. If its class and locale
 * already include what is requested here they just return. In the other case,
 * the existing AEN is aborted and a new one is created, which includes
 * the previous locale and class and new ones.
 *
 * Given that the driver (same as in FreeBSD) calls this function during attach
 * to create an AEN with LOCALE_ALL and CLASS_DEBUG, all of this would be dead
 * code anyway.
 */
static int
lmrc_register_aen(lmrc_t *lmrc, uint32_t seqnum)
{
	lmrc_evt_class_locale_t ecl = {
		.ecl_class = LMRC_EVT_CLASS_DEBUG,
		.ecl_locale = LMRC_EVT_LOCALE_ALL
	};

	lmrc_mfi_cmd_t *mfi;
	lmrc_mfi_dcmd_payload_t *dcmd;

	mfi = lmrc_get_dcmd(lmrc, MFI_FRAME_DIR_READ, LMRC_DCMD_CTRL_EVENT_WAIT,
	    sizeof (lmrc_evt_t), 1);

	if (mfi == NULL)
		return (DDI_FAILURE);

	dcmd = &mfi->mfi_frame->mf_dcmd;
	dcmd->md_mbox_32[0] = seqnum;
	dcmd->md_mbox_32[1] = ecl.ecl_word;

	mutex_enter(&mfi->mfi_lock);
	lmrc_issue_mfi(lmrc, mfi, lmrc_complete_aen);
	mutex_exit(&mfi->mfi_lock);

	return (DDI_SUCCESS);
}

/*
 * lmrc_start_aen
 *
 * Set up and enable AEN processing.
 */
int
lmrc_start_aen(lmrc_t *lmrc)
{
	lmrc_evt_log_info_t eli;
	int ret;

	bzero(&eli, sizeof (eli));

	/* Get the latest sequence number from the Event Log Info. */
	ret = lmrc_get_event_log_info(lmrc, &eli);
	if (ret != DDI_SUCCESS)
		return (ret);

	/* Register AEN with FW for latest sequence number + 1. */
	ret = lmrc_register_aen(lmrc, eli.eli_newest_seqnum + 1);
	return (ret);
}
