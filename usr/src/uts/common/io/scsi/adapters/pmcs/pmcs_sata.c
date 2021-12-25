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
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * SATA midlayer interface for PMC driver.
 */

#include <sys/scsi/adapters/pmcs/pmcs.h>

static void
SATAcopy(pmcs_cmd_t *sp, void *kbuf, uint32_t amt)
{
	struct buf *bp = scsi_pkt2bp(CMD2PKT(sp));

	bp_mapin(scsi_pkt2bp(CMD2PKT(sp)));
	/* There is only one direction currently */
	(void) memcpy(bp->b_un.b_addr, kbuf, amt);
	CMD2PKT(sp)->pkt_resid -= amt;
	CMD2PKT(sp)->pkt_state |= STATE_XFERRED_DATA;
	bp_mapout(scsi_pkt2bp(CMD2PKT(sp)));
}

/*
 * Run a non block-io command. Some commands are interpreted
 * out of extant data. Some imply actually running a SATA command.
 *
 * Returns zero if we were able to run.
 *
 * Returns -1 only if other commands are active, either another
 * command here or regular I/O active.
 *
 * Called with PHY lock and xp statlock held.
 */
#define	SRESPSZ	132
CTASSERT(SRESPSZ == sizeof (struct scsi_inquiry));

static int
pmcs_sata_special_work(pmcs_hw_t *pwp, pmcs_xscsi_t *xp)
{
	int i;
	int saq;
	pmcs_cmd_t *sp;
	struct scsi_pkt *pkt;
	pmcs_phy_t *pptr;
	uint8_t rp[SRESPSZ];
	ata_identify_t *id;
	uint32_t amt = 0;
	uint8_t key = 0x05;	/* illegal command */
	uint8_t asc = 0;
	uint8_t ascq = 0;
	uint8_t status = STATUS_GOOD;

	if (xp->actv_cnt) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG1, NULL, xp,
		    "%s: target %p actv count %u",
		    __func__, (void *)xp, xp->actv_cnt);
		return (-1);
	}
	if (xp->special_running) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp,
		    "%s: target %p special running already",
		    __func__, (void *)xp);
		return (-1);
	}
	xp->special_needed = 0;

	/*
	 * We're now running special.
	 */
	xp->special_running = 1;
	pptr = xp->phy;

	sp = STAILQ_FIRST(&xp->sq);
	if (sp == NULL) {
		xp->special_running = 0;
		return (0);
	}

	pkt = CMD2PKT(sp);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, xp,
	    "%s: target %p cmd %p cdb0 %x with actv_cnt %u",
	    __func__, (void *)xp, (void *)sp, pkt->pkt_cdbp[0], xp->actv_cnt);

	if (pkt->pkt_cdbp[0] == SCMD_INQUIRY ||
	    pkt->pkt_cdbp[0] == SCMD_READ_CAPACITY) {
		int retval;

		if (pmcs_acquire_scratch(pwp, B_FALSE)) {
			xp->special_running = 0;
			return (-1);
		}
		saq = 1;

		mutex_exit(&xp->statlock);
		retval = pmcs_sata_identify(pwp, pptr);
		mutex_enter(&xp->statlock);

		if (retval) {
			pmcs_release_scratch(pwp);
			xp->special_running = 0;

			pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, xp,
			    "%s: target %p identify failed %x",
			    __func__, (void *)xp, retval);
			/*
			 * If the failure is due to not being
			 * able to get resources, return such
			 * that we'll try later. Otherwise,
			 * fail current command.
			 */
			if (retval == ENOMEM) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
				    "%s: sata identify failed (ENOMEM) for "
				    "cmd %p", __func__, (void *)sp);
				return (-1);
			}
			pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_SENT_CMD;
			if (retval == ETIMEDOUT) {
				pkt->pkt_reason = CMD_TIMEOUT;
				pkt->pkt_statistics |= STAT_TIMEOUT;
			} else {
				pkt->pkt_reason = CMD_TRAN_ERR;
			}
			goto out;
		}

		id = pwp->scratch;

		/*
		 * Check to see if this device is an NCQ capable device.
		 * Yes, we'll end up doing this check for every INQUIRY
		 * if indeed we *are* only a pio device, but this is so
		 * infrequent that it's not really worth an extra bitfield.
		 *
		 * Note that PIO mode here means that the PMCS firmware
		 * performs PIO- not us.
		 */
		if (xp->ncq == 0) {
			/*
			 * Reset existing stuff.
			 */
			xp->pio = 0;
			xp->qdepth = 1;
			xp->tagmap = 0;

			if (id->word76 != 0 && id->word76 != 0xffff &&
			    (LE_16(id->word76) & (1 << 8))) {
				xp->ncq = 1;
				xp->qdepth = (LE_16(id->word75) & 0x1f) + 1;
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, xp,
				    "%s: device %s supports NCQ %u deep",
				    __func__, xp->phy->path, xp->qdepth);
			} else {
				/*
				 * Default back to PIO.
				 *
				 * Note that non-FPDMA would still be possible,
				 * but for this specific configuration, if it's
				 * not NCQ it's safest to assume PIO.
				 */
				xp->pio = 1;
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, xp,
				    "%s: device %s assumed PIO",
				    __func__, xp->phy->path);
			}
		}
	} else {
		saq = 0;
		id = NULL;
	}

	bzero(rp, SRESPSZ);

	switch (pkt->pkt_cdbp[0]) {
	case SCMD_INQUIRY:
	{
		struct scsi_inquiry *inqp;
		uint16_t *a, *b;

		/* Check for illegal bits */
		if ((pkt->pkt_cdbp[1] & 0xfc) || pkt->pkt_cdbp[5]) {
			status = STATUS_CHECK;
			asc = 0x24;	/* invalid field in cdb */
			break;
		}
		if (pkt->pkt_cdbp[1] & 0x1) {
			switch (pkt->pkt_cdbp[2]) {
			case 0x0:
				rp[3] = 3;
				rp[5] = 0x80;
				rp[6] = 0x83;
				amt = 7;
				break;
			case 0x80:
				rp[1] = 0x80;
				rp[3] = 0x14;
				a = (void *) &rp[4];
				b = id->model_number;
				for (i = 0; i < 5; i++) {
					*a = ddi_swap16(*b);
					a++;
					b++;
				}
				amt = 24;
				break;
			case 0x83:
				rp[1] = 0x83;
				if ((LE_16(id->word87) & 0x100) &&
				    (LE_16(id->word108) >> 12) == 5)  {
					rp[3] = 12;
					rp[4] = 1;
					rp[5] = 3;
					rp[7] = 8;
					rp[8] = LE_16(id->word108) >> 8;
					rp[9] = LE_16(id->word108);
					rp[10] = LE_16(id->word109) >> 8;
					rp[11] = LE_16(id->word109);
					rp[12] = LE_16(id->word110) >> 8;
					rp[13] = LE_16(id->word110);
					rp[14] = LE_16(id->word111) >> 8;
					rp[15] = LE_16(id->word111);
					amt = 16;
				} else {
					rp[3] = 64;
					rp[4] = 2;
					rp[5] = 1;
					rp[7] = 60;
					rp[8] = 'A';
					rp[9] = 'T';
					rp[10] = 'A';
					rp[11] = ' ';
					rp[12] = ' ';
					rp[13] = ' ';
					rp[14] = ' ';
					rp[15] = ' ';
					a = (void *) &rp[16];
					b = id->model_number;
					for (i = 0; i < 20; i++) {
						*a = ddi_swap16(*b);
						a++;
						b++;
					}
					a = (void *) &rp[40];
					b = id->serial_number;
					for (i = 0; i < 10; i++) {
						*a = ddi_swap16(*b);
						a++;
						b++;
					}
					amt = 68;
				}
				break;
			default:
				status = STATUS_CHECK;
				asc = 0x24;	/* invalid field in cdb */
				break;
			}
		} else {
			inqp = (struct scsi_inquiry *)rp;
			inqp->inq_qual = 0;
			inqp->inq_ansi = 5;	/* spc3 */
			inqp->inq_rdf = 2;	/* response format 2 */
			inqp->inq_len = 32;

			if (xp->ncq && (xp->qdepth > 1)) {
				inqp->inq_cmdque = 1;
			}

			(void) memcpy(inqp->inq_vid, "ATA     ", 8);

			a = (void *)inqp->inq_pid;
			b = id->model_number;
			for (i = 0; i < 8; i++) {
				*a = ddi_swap16(*b);
				a++;
				b++;
			}
			if (id->firmware_revision[2] == 0x2020 &&
			    id->firmware_revision[3] == 0x2020) {
				inqp->inq_revision[0] =
				    ddi_swap16(id->firmware_revision[0]) >> 8;
				inqp->inq_revision[1] =
				    ddi_swap16(id->firmware_revision[0]);
				inqp->inq_revision[2] =
				    ddi_swap16(id->firmware_revision[1]) >> 8;
				inqp->inq_revision[3] =
				    ddi_swap16(id->firmware_revision[1]);
			} else {
				inqp->inq_revision[0] =
				    ddi_swap16(id->firmware_revision[2]) >> 8;
				inqp->inq_revision[1] =
				    ddi_swap16(id->firmware_revision[2]);
				inqp->inq_revision[2] =
				    ddi_swap16(id->firmware_revision[3]) >> 8;
				inqp->inq_revision[3] =
				    ddi_swap16(id->firmware_revision[3]);
			}
			amt = 36;
		}
		amt = pmcs_set_resid(pkt, amt, pkt->pkt_cdbp[4]);
		if (amt) {
			if (xp->actv_cnt) {
				xp->special_needed = 1;
				xp->special_running = 0;
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
				    "%s: @ line %d", __func__, __LINE__);
				if (saq) {
					pmcs_release_scratch(pwp);
				}
				return (-1);
			}
			SATAcopy(sp, rp, amt);
		}
		break;
	}
	case SCMD_READ_CAPACITY:
	{
		uint64_t last_block;
		uint32_t block_size = 512;	/* XXXX */

		xp->capacity = LBA_CAPACITY(id);
		last_block = xp->capacity - 1;
		/* Check for illegal bits */
		if ((pkt->pkt_cdbp[1] & 0xfe) || pkt->pkt_cdbp[6] ||
		    (pkt->pkt_cdbp[8] & 0xfe) || pkt->pkt_cdbp[7] ||
		    pkt->pkt_cdbp[9]) {
			status = STATUS_CHECK;
			asc = 0x24;	/* invalid field in cdb */
			break;
		}
		for (i = 1; i < 10; i++) {
			if (pkt->pkt_cdbp[i]) {
				status = STATUS_CHECK;
				asc = 0x24;	/* invalid field in cdb */
				break;
			}
		}
		if (status != STATUS_GOOD) {
			break;
		}
		if (last_block > 0xffffffffULL) {
			last_block = 0xffffffffULL;
		}
		rp[0] = (last_block >> 24) & 0xff;
		rp[1] = (last_block >> 16) & 0xff;
		rp[2] = (last_block >>  8) & 0xff;
		rp[3] = (last_block) & 0xff;
		rp[4] = (block_size >> 24) & 0xff;
		rp[5] = (block_size >> 16) & 0xff;
		rp[6] = (block_size >>  8) & 0xff;
		rp[7] = (block_size) & 0xff;
		amt = 8;
		amt = pmcs_set_resid(pkt, amt, 8);
		if (amt) {
			if (xp->actv_cnt) {
				xp->special_needed = 1;
				xp->special_running = 0;
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
				    "%s: @ line %d", __func__, __LINE__);
				if (saq) {
					pmcs_release_scratch(pwp);
				}
				return (-1);
			}
			SATAcopy(sp, rp, amt);
		}
		break;
	}
	case SCMD_REPORT_LUNS: {
		int rl_len;

		/* Check for illegal bits */
		if (pkt->pkt_cdbp[1] || pkt->pkt_cdbp[3] || pkt->pkt_cdbp[4] ||
		    pkt->pkt_cdbp[5] || pkt->pkt_cdbp[10] ||
		    pkt->pkt_cdbp[11]) {
			status = STATUS_CHECK;
			asc = 0x24;	/* invalid field in cdb */
			break;
		}

		rp[3] = 8;
		rl_len = 16;	/* list length (4) + reserved (4) + 1 LUN (8) */
		amt = rl_len;
		amt = pmcs_set_resid(pkt, amt, rl_len);

		if (amt) {
			if (xp->actv_cnt) {
				xp->special_needed = 1;
				xp->special_running = 0;
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
				    "%s: @ line %d", __func__, __LINE__);
				if (saq) {
					pmcs_release_scratch(pwp);
				}
				return (-1);
			}
			SATAcopy(sp, rp, rl_len);
		}
		break;
	}

	case SCMD_REQUEST_SENSE:
		/* Check for illegal bits */
		if ((pkt->pkt_cdbp[1] & 0xfe) || pkt->pkt_cdbp[2] ||
		    pkt->pkt_cdbp[3] || pkt->pkt_cdbp[5]) {
			status = STATUS_CHECK;
			asc = 0x24;	/* invalid field in cdb */
			break;
		}
		rp[0] = 0xf0;
		amt = 18;
		amt = pmcs_set_resid(pkt, amt, pkt->pkt_cdbp[4]);
		if (amt) {
			if (xp->actv_cnt) {
				xp->special_needed = 1;
				xp->special_running = 0;
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
				    "%s: @ line %d", __func__, __LINE__);
				if (saq) {
					pmcs_release_scratch(pwp);
				}
				return (-1);
			}
			SATAcopy(sp, rp, 18);
		}
		break;
	case SCMD_START_STOP:
		/* Check for illegal bits */
		if ((pkt->pkt_cdbp[1] & 0xfe) || pkt->pkt_cdbp[2] ||
		    (pkt->pkt_cdbp[3] & 0xf0) || (pkt->pkt_cdbp[4] & 0x08) ||
		    pkt->pkt_cdbp[5]) {
			status = STATUS_CHECK;
			asc = 0x24;	/* invalid field in cdb */
			break;
		}
		break;
	case SCMD_SYNCHRONIZE_CACHE:
		/* Check for illegal bits */
		if ((pkt->pkt_cdbp[1] & 0xf8) || (pkt->pkt_cdbp[6] & 0xe0) ||
		    pkt->pkt_cdbp[9]) {
			status = STATUS_CHECK;
			asc = 0x24;	/* invalid field in cdb */
			break;
		}
		break;
	case SCMD_TEST_UNIT_READY:
		/* Check for illegal bits */
		if (pkt->pkt_cdbp[1] || pkt->pkt_cdbp[2] || pkt->pkt_cdbp[3] ||
		    pkt->pkt_cdbp[4] || pkt->pkt_cdbp[5]) {
			status = STATUS_CHECK;
			asc = 0x24;	/* invalid field in cdb */
			break;
		}
		if (xp->ca) {
			status = STATUS_CHECK;
			key = 0x6;
			asc = 0x28;
			xp->ca = 0;
		}
		break;
	default:
		asc = 0x20;	/* invalid operation command code */
		status = STATUS_CHECK;
		break;
	}
	if (status != STATUS_GOOD) {
		bzero(rp, 18);
		rp[0] = 0xf0;
		rp[2] = key;
		rp[12] = asc;
		rp[13] = ascq;
		pmcs_latch_status(pwp, sp, status, rp, 18, pptr->path);
	} else {
		pmcs_latch_status(pwp, sp, status, NULL, 0, pptr->path);
	}

out:
	STAILQ_REMOVE_HEAD(&xp->sq, cmd_next);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, xp,
	    "%s: pkt %p tgt %u done reason=%x state=%x resid=%ld status=%x",
	    __func__, (void *)pkt, xp->target_num, pkt->pkt_reason,
	    pkt->pkt_state, pkt->pkt_resid, status);

	if (saq) {
		pmcs_release_scratch(pwp);
	}

	if (xp->draining) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: waking up drain waiters", __func__);
		cv_signal(&pwp->drain_cv);
	}

	mutex_exit(&xp->statlock);
	mutex_enter(&pwp->cq_lock);
	STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
	PMCS_CQ_RUN_LOCKED(pwp);
	mutex_exit(&pwp->cq_lock);
	mutex_enter(&xp->statlock);
	xp->special_running = 0;
	return (0);
}

/*
 * Run all special commands queued up for a SATA device.
 * We're only called if the caller knows we have work to do.
 *
 * We can't run them if things are still active for the device,
 * return saying we didn't run anything.
 *
 * When we finish, wake up anyone waiting for active commands
 * to go to zero.
 *
 * Called with PHY lock and xp statlock held.
 */
int
pmcs_run_sata_special(pmcs_hw_t *pwp, pmcs_xscsi_t *xp)
{
	while (!STAILQ_EMPTY(&xp->sq)) {
		if (pmcs_sata_special_work(pwp, xp)) {
			return (-1);
		}
	}
	return (0);
}

/*
 * Search for SATA special commands to run and run them.
 * If we succeed in running the special command(s), kick
 * the normal commands into operation again. Call completion
 * for any commands that were completed while we were here.
 *
 * Called unlocked.
 */
void
pmcs_sata_work(pmcs_hw_t *pwp)
{
	pmcs_xscsi_t *xp;
	int spinagain = 0;
	uint16_t target;

	for (target = 0; target < pwp->max_dev; target++) {
		xp = pwp->targets[target];
		if ((xp == NULL) || (xp->phy == NULL)) {
			continue;
		}
		pmcs_lock_phy(xp->phy);
		mutex_enter(&xp->statlock);
		if (STAILQ_EMPTY(&xp->sq)) {
			mutex_exit(&xp->statlock);
			pmcs_unlock_phy(xp->phy);
			continue;
		}
		if (xp->actv_cnt) {
			xp->special_needed = 1;
			pmcs_prt(pwp, PMCS_PRT_DEBUG1, NULL, xp,
			    "%s: deferring until drained", __func__);
			spinagain++;
		} else {
			if (pmcs_run_sata_special(pwp, xp)) {
				spinagain++;
			}
		}
		mutex_exit(&xp->statlock);
		pmcs_unlock_phy(xp->phy);
	}

	if (spinagain) {
		SCHEDULE_WORK(pwp, PMCS_WORK_SATA_RUN);
	} else {
		SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
	}

	/*
	 * Run completion on any commands ready for it.
	 */
	PMCS_CQ_RUN(pwp);
}

/*
 * Called with PHY lock held and scratch acquired
 */
int
pmcs_sata_identify(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	fis_t fis;
	fis[0] = (IDENTIFY_DEVICE << 16) | (1 << 15) | FIS_REG_H2DEV;
	fis[1] = 0;
	fis[2] = 0;
	fis[3] = 0;
	fis[4] = 0;
	return (pmcs_run_sata_cmd(pwp, pptr, fis, SATA_PROTOCOL_PIO,
	    PMCIN_DATADIR_2_INI, sizeof (ata_identify_t)));
}

/*
 * Called with PHY lock held and scratch held
 */
int
pmcs_run_sata_cmd(pmcs_hw_t *pwp, pmcs_phy_t *pptr, fis_t fis, uint32_t mode,
    uint32_t ddir, uint32_t dlen)
{
	struct pmcwork *pwrk;
	uint32_t *ptr, msg[PMCS_MSG_SIZE];
	uint32_t iq, htag, status;
	int i, result = 0;

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, pptr);
	if (pwrk == NULL) {
		return (ENOMEM);
	}

	msg[0] = LE_32(PMCS_IOMB_IN_SAS(PMCS_OQ_IODONE,
	    PMCIN_SATA_HOST_IO_START));
	htag = pwrk->htag;
	pwrk->arg = msg;
	pwrk->dtype = SATA;
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(pptr->device_id);
	msg[3] = LE_32(dlen);
	msg[4] = LE_32(mode | ddir);
	if (dlen) {
		if (ddir == PMCIN_DATADIR_2_DEV) {
			if (ddi_dma_sync(pwp->cip_handles, 0, 0,
			    DDI_DMA_SYNC_FORDEV) != DDI_SUCCESS) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
				    "Condition check failed at %s():%d",
				    __func__, __LINE__);
			}
		}
		msg[12] = LE_32(DWORD0(pwp->scratch_dma));
		msg[13] = LE_32(DWORD1(pwp->scratch_dma));
		msg[14] = LE_32(dlen);
		msg[15] = 0;
	} else {
		msg[12] = 0;
		msg[13] = 0;
		msg[14] = 0;
		msg[15] = 0;
	}
	for (i = 0; i < 5; i++) {
		msg[5+i] = LE_32(fis[i]);
	}
	msg[10] = 0;
	msg[11] = 0;
	GET_IO_IQ_ENTRY(pwp, ptr, pptr->device_id, iq);
	if (ptr == NULL) {
		pmcs_pwork(pwp, pwrk);
		return (ENOMEM);
	}
	COPY_MESSAGE(ptr, msg, PMCS_MSG_SIZE);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, iq);

	pmcs_unlock_phy(pptr);
	WAIT_FOR(pwrk, 1000, result);
	pmcs_pwork(pwp, pwrk);
	pmcs_lock_phy(pptr);

	if (result) {
		pmcs_timed_out(pwp, htag, __func__);
		if (pmcs_abort(pwp, pptr, htag, 0, 1)) {
			pptr->abort_pending = 1;
			SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
		}
		return (ETIMEDOUT);
	}

	status = LE_32(msg[2]);

	if (status != PMCOUT_STATUS_OK) {
		if (status == PMCOUT_STATUS_OPEN_CNX_ERROR_STP_RESOURCES_BUSY) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, pptr->target,
			    "%s: Potential affiliation active on 0x%" PRIx64,
			    __func__, pmcs_barray2wwn(pptr->sas_address));
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, pptr->target,
			    "%s: SATA I/O returned with IOMB status 0x%x",
			    __func__, status);
		}
		return (EIO);
	}

	if (LE_32(ptr[3]) != 0) {
		size_t j, amt = LE_32(ptr[3]);
		if (amt > sizeof (fis_t)) {
			amt = sizeof (fis_t);
		}
		amt >>= 2;
		for (j = 0; j < amt; j++) {
			fis[j] = LE_32(msg[4 + j]);
		}
	}
	if (dlen && ddir == PMCIN_DATADIR_2_INI) {
		if (ddi_dma_sync(pwp->cip_handles, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "Condition check failed at %s():%d",
			    __func__, __LINE__);
		}
	}
	return (0);
}
