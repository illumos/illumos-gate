/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Finite State Machines for ATA controller and ATAPI devices
 */

#include <sys/types.h>

#include "ata_common.h"
#include "atapi.h"

/*
 * Local functions
 */
static	int	atapi_start_cmd(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
				ata_pkt_t *ata_pktp);
static	void	atapi_send_cdb(ata_ctl_t *ata_ctlp, ata_pkt_t *ata_pktp);
static	void	atapi_start_dma(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
				ata_pkt_t *ata_pktp);
static	void	atapi_pio_data_in(ata_ctl_t *ata_ctlp, ata_pkt_t *ata_pktp);
static	void	atapi_pio_data_out(ata_ctl_t *ata_ctlp, ata_pkt_t *ata_pktp);
static	void	atapi_status(ata_ctl_t *ata_ctlp, ata_pkt_t *ata_pktp,
				uchar_t status, int dma_complete);
static	void	atapi_fsm_error(ata_ctl_t *ata_ctlp, uchar_t state,
				uchar_t event);




static void
atapi_fsm_error(
	ata_ctl_t *ata_ctlp,
	uchar_t	   state,
	uchar_t	   event)
{
	ADBG_ERROR(("atapi protocol error: 0x%p 0x%x 0x%x\n",
	    (void *)ata_ctlp->ac_data, state, event));
}


/*
 *
 *  IO  CoD  DRQ
 *  --  ---  ---
 *   0    0    0  == 0 invalid
 *   0    0    1  == 1 Data to device
 *   0    1    0  == 2 Idle
 *   0    1    1  == 3 Send ATAPI CDB to device
 *   1    0    0  == 4 invalid
 *   1    0    1  == 5 Data from device
 *   1    1    0  == 6 Status ready
 *   1    1    1  == 7 Future use
 *
 */

/*
 * Given the current state and the current event this
 * table determines what action to take. Note, in the actual
 * table I've left room for the invalid event codes: 0, 2, and 7.
 *
 *		+-----------------------------------------------------
 *		|		Current Event
 *		|
 *	State	|	dataout	idle	cdb	datain	status
 *		|	1	2	3	5	6
 *		|-----------------------------------------------------
 *	idle	|	sendcmd	sendcmd	sendcmd	sendcmd	sendcmd
 *	cmd	|	*	 *	sendcdb	*	read-err-code
 *	cdb	|	xfer-out nada	nada	xfer-in read-err-code
 *	datain	|	*	 *	*	xfer-in	read-err-code
 *	dataout	|	xfer-out *	*	*	read-err-code
 *	DMA	|	*	 *	*	*	read-err-code
 *
 */

uchar_t	atapi_PioAction[ATAPI_NSTATES][ATAPI_NEVENTS] = {
/* invalid dataout idle	  cdb	  invalid datain  status  future */
{ A_NADA, A_NADA, A_NADA, A_NADA, A_NADA, A_NADA, A_NADA, A_NADA }, /* Idle */
{ A_NADA, A_NADA, A_NADA, A_CDB,  A_NADA, A_NADA, A_RE,   A_NADA }, /* Cmd */
{ A_REX,  A_OUT,  A_NADA, A_NADA, A_IDLE, A_IN,   A_RE,   A_UNK  }, /* Cdb */
{ A_REX,  A_UNK,  A_IDLE, A_UNK,  A_IDLE, A_IN,   A_RE,   A_UNK  }, /* DtaIn */
{ A_REX,  A_OUT,  A_IDLE, A_UNK,  A_IDLE, A_UNK,  A_RE,   A_UNK  }, /* DtaOut */
{ A_REX,  A_UNK,  A_UNK,  A_UNK,  A_UNK,  A_UNK,  A_RE,   A_UNK  }  /* DmaAct */
};

/*
 *
 * Give the current state and the current event this table
 * determines the new state of the device.
 *
 *		+----------------------------------------------
 *		|		Current Event
 *		|
 *	State	|	dataout	idle	cdb	datain	status
 *		|----------------------------------------------
 *	idle	|	cmd	cmd	cmd	cmd	cmd
 *	cmd	|	*	*	cdb	*	*
 *	cdb	|	dataout	cdb	cdb	datain	(idle)
 *	datain	|	*	*	*	datain	(idle)
 *	dataout	|	dataout	*	*	*	(idle)
 *	DMA	|	DMA	DMA	DMA	DMA	(idle)
 *
 *
 * Note: the states enclosed in parens "(state)", are the accept states
 * for this FSM. A separate table is used to encode the done
 * states rather than extra state codes.
 *
 */

uchar_t	atapi_PioNextState[ATAPI_NSTATES][ATAPI_NEVENTS] = {
/* invalid dataout idle	  cdb	  invalid datain  status  future */
{ S_IDLE, S_IDLE, S_IDLE, S_IDLE, S_IDLE, S_IDLE, S_IDLE, S_IDLE}, /* idle */
{ S_CDB,  S_CDB,  S_CDB,  S_CDB,  S_CDB,  S_CDB,  S_IDLE, S_X   }, /* cmd */
{ S_IDLE, S_OUT,  S_CDB,  S_CDB,  S_CDB,  S_IN,   S_IDLE, S_X   }, /* cdb */
{ S_IDLE, S_X,    S_IN,   S_X,    S_IN,   S_IN,   S_IDLE, S_X   }, /* datain */
{ S_IDLE, S_OUT,  S_OUT,  S_X,    S_OUT,  S_X,    S_IDLE, S_X   }, /* dataout */
{ S_IDLE, S_DMA,  S_DMA,  S_DMA,  S_DMA,  S_DMA,  S_IDLE, S_DMA }  /* dmaActv */
};


static int
atapi_start_cmd(
	ata_ctl_t	*ata_ctlp,
	ata_drv_t	*ata_drvp,
	ata_pkt_t	*ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;

	/*
	 * Bug 1256489:
	 *
	 * If AC_BSY_WAIT is set, wait for controller to be not busy,
	 * before issuing a command.  If AC_BSY_WAIT is not set,
	 * skip the wait.  This is important for laptops that do
	 * suspend/resume but do not correctly wait for the busy bit to
	 * drop after a resume.
	 */

	if (ata_ctlp->ac_timing_flags & AC_BSY_WAIT) {
		if (!ata_wait(io_hdl2, ata_ctlp->ac_ioaddr2,
			0, ATS_BSY, 5000000)) {
			ADBG_WARN(("atapi_start: BSY too long!\n"));
			ata_pktp->ap_flags |= AP_ERROR;
			return (ATA_FSM_RC_BUSY);
		}
	}

	/*
	 * Select the drive
	 */
	ddi_put8(io_hdl1, ata_ctlp->ac_drvhd, ata_pktp->ap_hd);
	ata_nsecwait(400);

	/*
	 * make certain the drive selected
	 */
	if (!ata_wait(io_hdl2,  ata_ctlp->ac_ioaddr2, 0, ATS_BSY, 5000000)) {
		ADBG_ERROR(("atapi_start_cmd: drive select failed\n"));
		return (ATA_FSM_RC_BUSY);
	}

	/*
	 * Always make certain interrupts are enabled. It's been reported
	 * (but not confirmed) that some notebook computers don't
	 * clear the interrupt disable bit after being resumed. The
	 * easiest way to fix this is to always clear the disable bit
	 * before every command.
	 */
	ddi_put8(io_hdl2, ata_ctlp->ac_devctl, ATDC_D3);

	ddi_put8(io_hdl1, ata_ctlp->ac_lcyl, ata_pktp->ap_lwcyl);
	ddi_put8(io_hdl1, ata_ctlp->ac_hcyl, ata_pktp->ap_hicyl);
	ddi_put8(io_hdl1, ata_ctlp->ac_sect, ata_pktp->ap_sec);
	ddi_put8(io_hdl1, ata_ctlp->ac_count, ata_pktp->ap_count);

	if (ata_pktp->ap_pciide_dma) {

		ASSERT((ata_pktp->ap_flags & (AP_READ | AP_WRITE)) != 0);

		/*
		 * DMA but no Overlap
		 */
		ddi_put8(io_hdl1, ata_ctlp->ac_feature, ATF_ATAPI_DMA);

		/*
		 * copy the Scatter/Gather list to the controller's
		 * Physical Region Descriptor Table
		 */
		ata_pciide_dma_setup(ata_ctlp, ata_pktp->ap_sg_list,
			ata_pktp->ap_sg_cnt);
	} else {
		/*
		 * no DMA and no Overlap
		 */
		ddi_put8(io_hdl1, ata_ctlp->ac_feature, 0);
	}

	/*
	 * This next one sets the device in motion
	 */
	ddi_put8(io_hdl1, ata_ctlp->ac_cmd, ata_pktp->ap_cmd);

	/* wait for the busy bit to settle */
	ata_nsecwait(400);

	if (!(ata_drvp->ad_flags & AD_NO_CDB_INTR)) {
		/*
		 * the device will send me an interrupt when it's
		 * ready for the packet
		 */
		return (ATA_FSM_RC_OKAY);
	}

	/* else */

	/*
	 * If we don't receive an interrupt requesting the scsi CDB,
	 * we must poll for DRQ, and then send out the CDB.
	 */

	/*
	 * Wait for DRQ before sending the CDB. Bailout early
	 * if an error occurs.
	 *
	 * I'm not certain what the correct timeout should be.
	 */
	if (ata_wait3(io_hdl2, ata_ctlp->ac_ioaddr2,
		ATS_DRQ, ATS_BSY, /* okay */
		ATS_ERR, ATS_BSY, /* cmd failed */
		ATS_DF,  ATS_BSY, /* cmd failed */
		4000000)) {
		/* got good status */
		return (ATA_FSM_RC_INTR);
	}

	ADBG_WARN(("atapi_start_cmd: 0x%x status 0x%x error 0x%x\n",
		ata_pktp->ap_cmd,
		ddi_get8(io_hdl2,  ata_ctlp->ac_altstatus),
		ddi_get8(io_hdl1, ata_ctlp->ac_error)));

	return (ATA_FSM_RC_INTR);
}


/*
 *
 * Send the SCSI CDB to the ATAPI device
 *
 */

static void
atapi_send_cdb(
	ata_ctl_t	*ata_ctlp,
	ata_pkt_t	*ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	int		 padding;

	ADBG_TRACE(("atapi_send_cdb entered\n"));

	/*
	 * send the CDB to the drive
	 */
	ddi_rep_put16(io_hdl1, (ushort_t *)ata_pktp->ap_cdbp, ata_ctlp->ac_data,
		ata_pktp->ap_cdb_len >> 1, DDI_DEV_NO_AUTOINCR);

	/*
	 * pad to ad_cdb_len bytes
	 */

	padding = ata_pktp->ap_cdb_pad;

	while (padding) {
		ddi_put16(io_hdl1, ata_ctlp->ac_data, 0);
		padding--;
	}

	/* wait for the busy bit to settle */
	ata_nsecwait(400);

#ifdef ATA_DEBUG_XXX
	{
		uchar_t	*cp = ata_pktp->ap_cdbp;

		ADBG_TRANSPORT(("\tatapi scsi cmd (%d bytes):\n ",
				ata_pktp->ap_cdb_len));
		ADBG_TRANSPORT(("\t\t 0x%x 0x%x 0x%x 0x%x\n",
			cp[0], cp[1], cp[2], cp[3]));
		ADBG_TRANSPORT(("\t\t 0x%x 0x%x 0x%x 0x%x\n",
			cp[4], cp[5], cp[6], cp[7]));
		ADBG_TRANSPORT(("\t\t 0x%x 0x%x 0x%x 0x%x\n",
			cp[8], cp[9], cp[10], cp[11]));
	}
#endif

	ata_pktp->ap_flags |= AP_SENT_CMD;
}



/*
 * Start the DMA engine
 */

/* ARGSUSED */
static void
atapi_start_dma(
	ata_ctl_t	*ata_ctlp,
	ata_drv_t	*ata_drvp,
	ata_pkt_t	*ata_pktp)
{
	uchar_t		 rd_wr;

	/*
	 * Determine the direction. This may look backwards
	 * but the command bit programmed into the DMA engine
	 * specifies the type of operation the engine performs
	 * on the PCI bus (not the ATA bus). Therefore when
	 * transferring data from the device to system memory, the
	 * DMA engine performs PCI Write operations.
	 */
	if (ata_pktp->ap_flags & AP_READ)
		rd_wr = PCIIDE_BMICX_RWCON_WRITE_TO_MEMORY;
	else
		rd_wr = PCIIDE_BMICX_RWCON_READ_FROM_MEMORY;

	/*
	 * Start the DMA engine
	 */
	ata_pciide_dma_start(ata_ctlp, rd_wr);
}



/*
 * Transfer the data from the device
 *
 * Note: the atapi_pio_data_in() and atapi_pio_data_out() functions
 * are complicated a lot by the requirement to handle an odd byte count.
 * The only device we've seen which does this is the Hitachi CDR-7730.
 * See bug ID 1214595. It's my understanding that Dell stopped shipping
 * that drive after discovering all the problems it caused, so it may
 * be impossible to find one for any sort of regression test.
 *
 * In the future, ATAPI tape drives will also probably support odd byte
 * counts so this code will be excersized more often.
 *
 */

static void
atapi_pio_data_in(
	ata_ctl_t	*ata_ctlp,
	ata_pkt_t	*ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	int		 drive_bytes;
	int		 xfer_bytes;
	int		 xfer_words;

	ata_pktp->ap_flags |= AP_XFERRED_DATA;

	/*
	 * Get the device's byte count for this transfer
	 */
	drive_bytes = ((int)ddi_get8(io_hdl1, ata_ctlp->ac_hcyl) << 8)
			+ ddi_get8(io_hdl1, ata_ctlp->ac_lcyl);

	/*
	 * Determine actual number I'm going to transfer. My
	 * buffer might have fewer bytes than what the device
	 * expects or handles on each interrupt.
	 */
	xfer_bytes = min(ata_pktp->ap_resid, drive_bytes);

	ASSERT(xfer_bytes >= 0);

	/*
	 * Round down my transfer count to whole words so that
	 * if the transfer count is odd it's still handled correctly.
	 */
	xfer_words = xfer_bytes / 2;

	if (xfer_words) {
		int	byte_count = xfer_words * 2;

		ddi_rep_get16(io_hdl1, (ushort_t *)ata_pktp->ap_v_addr,
			ata_ctlp->ac_data, xfer_words, DDI_DEV_NO_AUTOINCR);

		ata_pktp->ap_v_addr += byte_count;
		drive_bytes -= byte_count;
	}

	/*
	 * Handle possible odd byte at end. Read a 16-bit
	 * word but discard the high-order byte.
	 */
	if (xfer_bytes & 1) {
		ushort_t tmp_word;

		tmp_word = ddi_get16(io_hdl1, ata_ctlp->ac_data);
		*ata_pktp->ap_v_addr++ = tmp_word & 0xff;
		drive_bytes -= 2;
	}

	ata_pktp->ap_resid -= xfer_bytes;

	ADBG_TRANSPORT(("atapi_pio_data_in: read 0x%x bytes\n", xfer_bytes));

	/*
	 * Discard any unwanted data.
	 */
	if (drive_bytes > 0) {
		ADBG_TRANSPORT(("atapi_pio_data_in: dump 0x%x bytes\n",
				drive_bytes));

		/* rounded up if the drive_bytes count is odd */
		for (; drive_bytes > 0; drive_bytes -= 2)
			(void) ddi_get16(io_hdl1, ata_ctlp->ac_data);
	}

	/* wait for the busy bit to settle */
	ata_nsecwait(400);
}


/*
 * Transfer the data to the device
 */

static void
atapi_pio_data_out(
	ata_ctl_t	*ata_ctlp,
	ata_pkt_t	*ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	int		 drive_bytes;
	int		 xfer_bytes;
	int		 xfer_words;

	ata_pktp->ap_flags |= AP_XFERRED_DATA;

	/*
	 * Get the device's byte count for this transfer
	 */
	drive_bytes = ((int)ddi_get8(io_hdl1, ata_ctlp->ac_hcyl) << 8)
			+ ddi_get8(io_hdl1, ata_ctlp->ac_lcyl);

	/*
	 * Determine actual number I'm going to transfer. My
	 * buffer might have fewer bytes than what the device
	 * expects or handles on each interrupt.
	 */
	xfer_bytes = min(ata_pktp->ap_resid, drive_bytes);

	/*
	 * Round down my transfer count to whole words so that
	 * if the transfer count is odd it's handled correctly.
	 */
	xfer_words = xfer_bytes / 2;

	if (xfer_words) {
		int	byte_count = xfer_words * 2;

		ddi_rep_put16(io_hdl1, (ushort_t *)ata_pktp->ap_v_addr,
			ata_ctlp->ac_data, xfer_words, DDI_DEV_NO_AUTOINCR);
		ata_pktp->ap_v_addr += byte_count;
	}

	/*
	 * If odd byte count, transfer the last
	 * byte. Use a tmp so that I don't run off
	 * the end off the buffer and possibly page
	 * fault.
	 */
	if (xfer_bytes & 1) {
		ushort_t tmp_word;

		/* grab the last unsigned byte and widen it to 16-bits */
		tmp_word = *ata_pktp->ap_v_addr++;
		ddi_put16(io_hdl1, ata_ctlp->ac_data, tmp_word);
	}

	ata_pktp->ap_resid -= xfer_bytes;

	ADBG_TRANSPORT(("atapi_pio_data_out: wrote 0x%x bytes\n", xfer_bytes));

	/* wait for the busy bit to settle */
	ata_nsecwait(400);
}


/*
 *
 * check status of completed command
 *
 */
static void
atapi_status(
	ata_ctl_t	*ata_ctlp,
	ata_pkt_t	*ata_pktp,
	uchar_t		 status,
	int		 dma_completion)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;

	ata_pktp->ap_flags |= AP_GOT_STATUS;

	if (status & (ATS_DF | ATS_ERR)) {
		ata_pktp->ap_flags |= AP_ERROR;
	}

	if (ata_pktp->ap_flags & AP_ERROR) {
		ata_pktp->ap_status = status;
		ata_pktp->ap_error = ddi_get8(io_hdl1, ata_ctlp->ac_error);
	}


	/*
	 * If the DMA transfer failed leave the resid set to
	 * the original byte count. The target driver has
	 * to do a REQUEST SENSE to get the true residual
	 * byte count. Otherwise, it all transferred so update
	 * the flags and residual byte count.
	 */
	if (dma_completion && !(ata_pktp->ap_flags & AP_TRAN_ERROR)) {
		ata_pktp->ap_flags |= AP_XFERRED_DATA;
		ata_pktp->ap_resid = 0;
	}
}


static void
atapi_device_reset(
	ata_ctl_t	*ata_ctlp,
	ata_drv_t	*ata_drvp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;

	/* select the drive */
	ddi_put8(io_hdl1, ata_ctlp->ac_drvhd, ata_drvp->ad_drive_bits);
	ata_nsecwait(400);

	/* issue atapi DEVICE RESET */
	ddi_put8(io_hdl1, ata_ctlp->ac_cmd, ATC_DEVICE_RESET);

	/* wait for the busy bit to settle */
	ata_nsecwait(400);

	/*
	 * Re-select the drive (this is probably only necessary
	 * when resetting drive 1).
	 */
	ddi_put8(io_hdl1, ata_ctlp->ac_drvhd, ata_drvp->ad_drive_bits);
	ata_nsecwait(400);

	/* allow the drive the full 6 seconds to respond */
	/* LINTED */
	if (!ata_wait(io_hdl2, ata_ctlp->ac_ioaddr2, 0, ATS_BSY, 6 * 1000000)) {
		ADBG_WARN(("atapi_device_reset: still busy\n"));
		/*
		 * It's not clear to me what to do at this point,
		 * the drive might be dead or might eventually
		 * recover. For now just ignore it and continue
		 * to attempt to use the drive.
		 */
	}
}



void
atapi_fsm_reset(ata_ctl_t *ata_ctlp)
{
	ata_drv_t *ata_drvp;
	int	   drive;

	/*
	 * reset drive drive 0 and the drive 1
	 */
	for (drive = 0; drive <= 1; drive++) {
		ata_drvp = CTL2DRV(ata_ctlp, drive, 0);
		if (ata_drvp && ATAPIDRV(ata_drvp)) {
			ata_drvp->ad_state = S_IDLE;
			atapi_device_reset(ata_ctlp, ata_drvp);
		}
	}
}


int
atapi_fsm_start(
	ata_ctl_t	*ata_ctlp,
	ata_drv_t	*ata_drvp,
	ata_pkt_t	*ata_pktp)
{
	int		 rc;

	ADBG_TRACE(("atapi_start entered\n"));
	ADBG_TRANSPORT(("atapi_start: pkt = 0x%p\n", ata_pktp));

	/*
	 * check for valid state
	 */
	if (ata_drvp->ad_state != S_IDLE) {
		ADBG_ERROR(("atapi_fsm_start not idle 0x%x\n",
			    ata_drvp->ad_state));
		return (ATA_FSM_RC_BUSY);
	} else {
		ata_drvp->ad_state = S_CMD;
	}

	rc = atapi_start_cmd(ata_ctlp, ata_drvp, ata_pktp);

	switch (rc) {
	case ATA_FSM_RC_OKAY:
		/*
		 * The command started okay. Just return.
		 */
		break;
	case ATA_FSM_RC_INTR:
		/*
		 * Got Command Phase. The upper layer will send
		 * the cdb by faking an interrupt.
		 */
		break;
	case ATA_FSM_RC_FINI:
		/*
		 * command completed immediately, stick on done q
		 */
		break;
	case ATA_FSM_RC_BUSY:
		/*
		 * The command wouldn't start, tell the upper layer to
		 * stick this request on the done queue.
		 */
		ata_drvp->ad_state = S_IDLE;
		return (ATA_FSM_RC_BUSY);
	}
	return (rc);
}

/*
 *
 * All interrupts on an ATAPI device come through here.
 * This function determines what to do next, based on
 * the current state of the request and the drive's current
 * status bits.  See the FSM tables at the top of this file.
 *
 */

int
atapi_fsm_intr(
	ata_ctl_t	*ata_ctlp,
	ata_drv_t	*ata_drvp,
	ata_pkt_t	*ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	uchar_t		 status;
	uchar_t		 intr_reason;
	uchar_t		 state;
	uchar_t		 event;
	uchar_t		 action;


	/*
	 * get the prior state
	 */
	state = ata_drvp->ad_state;

	/*
	 * If doing DMA, then:
	 *
	 *	1. halt the DMA engine
	 *	2. reset the interrupt and error latches
	 *	3. reset the drive's IRQ.
	 *
	 * I think the order of these operations must be
	 * exactly as listed. Otherwise we the PCI-IDE
	 * controller can hang or we can miss the next interrupt
	 * edge.
	 *
	 */
	switch (state) {
	case S_DMA:
		ASSERT(ata_pktp->ap_pciide_dma == TRUE);
		/*
		 * Halt the DMA engine. When we reach this point
		 * we already know for certain that the device has
		 * an interrupt pending since the ata_get_status()
		 * function already checked the PCI-IDE interrupt
		 * status bit.
		 */
		ata_pciide_dma_stop(ata_ctlp);
		/*FALLTHRU*/
	case S_IDLE:
	case S_CMD:
	case S_CDB:
	case S_IN:
	case S_OUT:
		break;
	}


	/*
	 * Clear the PCI-IDE latches and the drive's IRQ
	 */
	status = ata_get_status_clear_intr(ata_ctlp, ata_pktp);

	/*
	 * some non-compliant (i.e., NEC) drives don't
	 * set ATS_BSY within 400 nsec. and/or don't keep
	 * it asserted until they're actually non-busy.
	 * There's a small window between reading the alt_status
	 * and status registers where the drive might "bounce"
	 * the ATS_BSY bit.
	 */
	if (status & ATS_BSY)
		return (ATA_FSM_RC_BUSY);

	/*
	 * get the interrupt reason code
	 */
	intr_reason = ddi_get8(io_hdl1, ata_ctlp->ac_count);

	/*
	 * encode the status and interrupt reason bits
	 * into an event code which is used to index the
	 * FSM tables
	 */
	event = ATAPI_EVENT(status, intr_reason);

	/*
	 * determine the action for this event
	 */
	action = atapi_PioAction[state][event];

	/*
	 * determine the new state
	 */
	ata_drvp->ad_state = atapi_PioNextState[state][event];

	switch (action) {
	default:
	case A_UNK:
		/*
		 * invalid state
		 */
/*
 * ??? this shouldn't happen. ???
 *	if there's an active command on
 *	this device, the pkt timer should eventually clear the
 *	device. I might try sending a DEVICE-RESET here to speed
 *	up the error recovery except that DEVICE-RESET is kind of
 *	complicated to implement correctly because if I send a
 *	DEVICE-RESET to drive 1 it deselects itself.
 */
		ADBG_WARN(("atapi_fsm_intr: Unsupported intr\n"));
		break;

	case A_NADA:
		drv_usecwait(100);
		break;

	case A_CDB:
		/*
		 * send out atapi pkt
		 */
		atapi_send_cdb(ata_ctlp, ata_pktp);

		/*
		 * start the DMA engine if necessary and change
		 * the state variable to reflect not doing PIO
		 */
		if (ata_pktp->ap_pciide_dma) {
			atapi_start_dma(ata_ctlp, ata_drvp, ata_pktp);
			ata_drvp->ad_state = S_DMA;
		}
		break;

	case A_IN:
		if (!(ata_pktp->ap_flags & AP_READ)) {
			/*
			 * maybe this was a spurious interrupt, just
			 * spin for a bit and see if the drive
			 * recovers
			 */
			atapi_fsm_error(ata_ctlp, state, event);
			drv_usecwait(100);
			break;
		}
		/*
		 * read in the data
		 */
		if (!ata_pktp->ap_pciide_dma) {
			atapi_pio_data_in(ata_ctlp, ata_pktp);
		}
		break;

	case A_OUT:
		if (!(ata_pktp->ap_flags & AP_WRITE)) {
			/* spin for a bit and see if the drive recovers */
			atapi_fsm_error(ata_ctlp, state, event);
			drv_usecwait(100);
			break;
		}
		/*
		 * send out data
		 */
		if (!ata_pktp->ap_pciide_dma) {
			atapi_pio_data_out(ata_ctlp, ata_pktp);
		}
		break;

	case A_IDLE:
		/*
		 * The DRQ bit deasserted before or between the data
		 * transfer phases.
		 */
		if (!ata_drvp->ad_bogus_drq) {
			ata_drvp->ad_bogus_drq = TRUE;
			atapi_fsm_error(ata_ctlp, state, event);
		}
		drv_usecwait(100);
		break;

	case A_RE:
		/*
		 * If we get here, a command has completed!
		 *
		 * check status of completed command
		 */
		atapi_status(ata_ctlp, ata_pktp, status,
			(state == S_DMA) ? TRUE : FALSE);

		return (ATA_FSM_RC_FINI);

	case A_REX:
		/*
		 * some NEC drives don't report the right interrupt
		 * reason code for the status phase
		 */
		if (!ata_drvp->ad_nec_bad_status) {
			ata_drvp->ad_nec_bad_status = TRUE;
			atapi_fsm_error(ata_ctlp, state, event);
			drv_usecwait(100);
		}
		atapi_status(ata_ctlp, ata_pktp, status,
			(state == S_DMA) ? TRUE : FALSE);
		return (ATA_FSM_RC_FINI);

	}
	return (ATA_FSM_RC_OKAY);
}
