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


#include <sys/types.h>

#include "ata_common.h"
#include "atapi.h"

/* SCSA entry points */

static int atapi_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static int atapi_tran_tgt_probe(struct scsi_device *sd, int (*callback)(void));
static void atapi_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static int atapi_tran_abort(struct scsi_address *ap, struct scsi_pkt *spktp);
static int atapi_tran_reset(struct scsi_address *ap, int level);
static int atapi_tran_getcap(struct scsi_address *ap, char *capstr, int whom);
static int atapi_tran_setcap(struct scsi_address *ap, char *capstr,
    int value, int whom);
static struct scsi_pkt	*atapi_tran_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *spktp, struct buf *bp, int cmdlen, int statuslen,
    int tgtlen, int flags, int (*callback)(caddr_t), caddr_t arg);
static void atapi_tran_destroy_pkt(struct scsi_address *ap,
    struct scsi_pkt *spktp);
static void atapi_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *spktp);
static void atapi_tran_sync_pkt(struct scsi_address *ap,
    struct scsi_pkt *spktp);
static int atapi_tran_start(struct scsi_address *ap, struct scsi_pkt *spktp);

/*
 * packet callbacks
 */
static void atapi_complete(ata_drv_t *ata_drvp, ata_pkt_t *ata_pktp,
    int do_callback);
static int atapi_id_update(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);


/* external dependencies */

char _depends_on[] = "misc/scsi";

/*
 * Local static data
 */

#if 0
static ddi_dma_lim_t atapi_dma_limits = {
	0,		/* address low				*/
	0xffffffffU,	/* address high				*/
	0,		/* counter max				*/
	1,		/* burstsize				*/
	DMA_UNIT_8,	/* minimum xfer				*/
	0,		/* dma speed				*/
	(uint_t)DMALIM_VER0,	/* version			*/
	0xffffffffU,	/* address register			*/
	0xffffffffU,	/* counter register			*/
	1,		/* granular				*/
	1,		/* scatter/gather list length		*/
	0xffffffffU	/* request size				*/
};
#endif

static	int	atapi_use_static_geometry = TRUE;
static	int	atapi_arq_enable = TRUE;


/*
 *
 * Call SCSA init to initialize the ATAPI half of the driver
 *
 */

int
atapi_attach(ata_ctl_t *ata_ctlp)
{
	dev_info_t	*dip = ata_ctlp->ac_dip;
	scsi_hba_tran_t *tran;

	ADBG_TRACE(("atapi_init entered\n"));

	/* allocate transport structure */

	tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);

	if (tran == NULL) {
		ADBG_WARN(("atapi_init: scsi_hba_tran_alloc failed\n"));
		goto errout;
	}

	ata_ctlp->ac_atapi_tran = tran;
	ata_ctlp->ac_flags |= AC_SCSI_HBA_TRAN_ALLOC;

	/* initialize transport structure */

	tran->tran_hba_private = ata_ctlp;
	tran->tran_tgt_private = NULL;

	tran->tran_tgt_init = atapi_tran_tgt_init;
	tran->tran_tgt_probe = atapi_tran_tgt_probe;
	tran->tran_tgt_free = atapi_tran_tgt_free;
	tran->tran_start = atapi_tran_start;
	tran->tran_reset = atapi_tran_reset;
	tran->tran_abort = atapi_tran_abort;
	tran->tran_getcap = atapi_tran_getcap;
	tran->tran_setcap = atapi_tran_setcap;
	tran->tran_init_pkt = atapi_tran_init_pkt;
	tran->tran_destroy_pkt = atapi_tran_destroy_pkt;
	tran->tran_dmafree = atapi_tran_dmafree;
	tran->tran_sync_pkt = atapi_tran_sync_pkt;

	if (scsi_hba_attach_setup(ata_ctlp->ac_dip, &ata_pciide_dma_attr, tran,
	    SCSI_HBA_TRAN_CLONE) != DDI_SUCCESS) {
		ADBG_WARN(("atapi_init: scsi_hba_attach_setup failed\n"));
		goto errout;
	}

	ata_ctlp->ac_flags |= AC_SCSI_HBA_ATTACH;

	return (TRUE);

errout:
	atapi_detach(ata_ctlp);
	return (FALSE);
}


/*
 *
 * destroy the atapi sub-system
 *
 */

void
atapi_detach(
	ata_ctl_t *ata_ctlp)
{
	ADBG_TRACE(("atapi_detach entered\n"));

	if (ata_ctlp->ac_flags & AC_SCSI_HBA_ATTACH)
		(void) scsi_hba_detach(ata_ctlp->ac_dip);

	if (ata_ctlp->ac_flags & AC_SCSI_HBA_TRAN_ALLOC)
		scsi_hba_tran_free(ata_ctlp->ac_atapi_tran);
}



/*
 *
 * initialize the ATAPI drive's soft-state based on the
 * response to IDENTIFY PACKET DEVICE command
 *
 */

int
atapi_init_drive(
	ata_drv_t *ata_drvp)
{
	ata_ctl_t *ata_ctlp = ata_drvp->ad_ctlp;

	ADBG_TRACE(("atapi_init_drive entered\n"));

	/* Determine ATAPI CDB size */
	(void) atapi_id_update(ata_ctlp, ata_drvp, NULL);

	switch (ata_drvp->ad_id.ai_config & ATAPI_ID_CFG_PKT_SZ) {

	case ATAPI_ID_CFG_PKT_12B:
		ata_drvp->ad_cdb_len = 12;
		break;
	case ATAPI_ID_CFG_PKT_16B:
		ata_drvp->ad_cdb_len = 16;
		break;
	default:
		ADBG_WARN(("atapi_init_drive: bad pkt size support\n"));
		return (FALSE);
	}

	/* determine if drive gives an intr when it wants the CDB */

	if ((ata_drvp->ad_id.ai_config & ATAPI_ID_CFG_DRQ_TYPE) !=
	    ATAPI_ID_CFG_DRQ_INTR)
		ata_drvp->ad_flags |= AD_NO_CDB_INTR;

	/*
	 * Some devices may have no DMA mode enabled (UDMA or MWDMA)
	 * by default, so here we need check and enable DMA if none
	 * mode is selected.
	 */
	if (ata_set_dma_mode(ata_ctlp, ata_drvp) == TRUE) {
		/* Update the IDENTIFY PACKET DEVICE data */
		(void) atapi_id_update(ata_ctlp, ata_drvp, NULL);
	}

	return (TRUE);
}


/*
 *
 * destroy an atapi drive
 *
 */

/* ARGSUSED */
void
atapi_uninit_drive(
	ata_drv_t *ata_drvp)
{
	ADBG_TRACE(("atapi_uninit_drive entered\n"));
}

/*
 *
 * Issue an IDENTIFY PACKET (ATAPI) DEVICE command
 *
 */

int
atapi_id(
	ddi_acc_handle_t io_hdl1,
	caddr_t		 ioaddr1,
	ddi_acc_handle_t io_hdl2,
	caddr_t		 ioaddr2,
	struct ata_id	*ata_idp)
{
	int	rc;

	ADBG_TRACE(("atapi_id entered\n"));

	rc = ata_id_common(ATC_ID_PACKET_DEVICE, FALSE, io_hdl1, ioaddr1,
	    io_hdl2, ioaddr2, ata_idp);

	if (!rc)
		return (FALSE);

	if ((ata_idp->ai_config & ATAC_ATAPI_TYPE_MASK) != ATAC_ATAPI_TYPE)
		return (FALSE);

	return (TRUE);
}


/*
 *
 * Check the device's register block for the ATAPI signature.
 *
 * Although the spec says the sector count, sector number and device/head
 * registers are also part of the signature, for some unknown reason, this
 * routine only checks the cyl hi and cyl low registers. I'm just
 * guessing, but it might be because ATA and ATAPI devices return
 * identical values in those registers and we actually rely on the
 * IDENTIFY DEVICE and IDENTIFY PACKET DEVICE commands to recognize the
 * device type.
 *
 */

int
atapi_signature(
	ddi_acc_handle_t io_hdl,
	caddr_t ioaddr)
{
	int	rc = FALSE;
	ADBG_TRACE(("atapi_signature entered\n"));

	if (ddi_get8(io_hdl, (uchar_t *)ioaddr + AT_HCYL) == ATAPI_SIG_HI &&
	    ddi_get8(io_hdl, (uchar_t *)ioaddr + AT_LCYL) != ATAPI_SIG_LO)
		rc = TRUE;

	/*
	 * The following is a little bit of bullet proofing.
	 *
	 * When some drives are configured on a master-only bus they
	 * "shadow" their registers for the not-present slave drive.
	 * This is bogus and if you're not careful it may cause a
	 * master-only drive to be mistakenly recognized as both
	 * master and slave. By clearing the signature registers here
	 * I can make certain that when ata_drive_type() switches from
	 * the master to slave drive that I'll read back non-signature
	 * values regardless of whether the master-only drive does
	 * the "shadow" register trick. This prevents a bogus
	 * IDENTIFY PACKET DEVICE command from being issued which
	 * a really bogus master-only drive will return "shadow"
	 * data for.
	 */
	ddi_put8(io_hdl, (uchar_t *)ioaddr + AT_HCYL, 0);
	ddi_put8(io_hdl, (uchar_t *)ioaddr + AT_LCYL, 0);

	return (rc);
}


/*
 *
 * SCSA tran_tgt_init entry point
 *
 */

/* ARGSUSED */
static int
atapi_tran_tgt_init(
	dev_info_t	*hba_dip,
	dev_info_t	*tgt_dip,
	scsi_hba_tran_t *hba_tran,
	struct scsi_device *sd)
{
	gtgt_t	  *gtgtp;	/* GHD's per-target-instance structure */
	ata_ctl_t *ata_ctlp;
	ata_tgt_t *ata_tgtp;
	ata_drv_t *ata_drvp;
	struct scsi_address *ap;
	int	rc = DDI_SUCCESS;

	ADBG_TRACE(("atapi_tran_tgt_init entered\n"));

	/*
	 * Qualification of targ, lun, and ATAPI device presence
	 *  have already been taken care of by ata_bus_ctl
	 */

	/* store pointer to drive struct in cloned tran struct */

	ata_ctlp = TRAN2CTL(hba_tran);
	ap = &sd->sd_address;

	ata_drvp = CTL2DRV(ata_ctlp, ap->a_target, ap->a_lun);

	/*
	 * Create the "atapi" property so the target driver knows
	 * to use the correct set of SCSI commands
	 */
	if (!ata_prop_create(tgt_dip, ata_drvp, "atapi")) {
		return (DDI_FAILURE);
	}

	gtgtp = ghd_target_init(hba_dip, tgt_dip, &ata_ctlp->ac_ccc,
	    sizeof (ata_tgt_t), ata_ctlp,
	    ap->a_target, ap->a_lun);

	/* tran_tgt_private points to gtgt_t */
	hba_tran->tran_tgt_private = gtgtp;

	/* gt_tgt_private points to ata_tgt_t */
	ata_tgtp = GTGTP2ATATGTP(gtgtp);

	/* initialize the per-target-instance data */
	ata_tgtp->at_drvp = ata_drvp;
	ata_tgtp->at_dma_attr = ata_pciide_dma_attr;
	ata_tgtp->at_dma_attr.dma_attr_maxxfer =
	    ata_ctlp->ac_max_transfer << SCTRSHFT;

	return (rc);
}


/*
 *
 * SCSA tran_tgt_probe entry point
 *
 */

static int
atapi_tran_tgt_probe(struct scsi_device *sd, int (*callback)(void))
{
	ADBG_TRACE(("atapi_tran_tgt_probe entered\n"));

	return (scsi_hba_probe(sd, callback));
}


/*
 *
 * SCSA tran_tgt_free entry point
 *
 */

/* ARGSUSED */
static void
atapi_tran_tgt_free(
	dev_info_t	*hba_dip,
	dev_info_t	*tgt_dip,
	scsi_hba_tran_t	*hba_tran,
	struct scsi_device *sd)
{
	ADBG_TRACE(("atapi_tran_tgt_free entered\n"));

	ghd_target_free(hba_dip, tgt_dip, &TRAN2ATAP(hba_tran)->ac_ccc,
	    TRAN2GTGTP(hba_tran));
	hba_tran->tran_tgt_private = NULL;
}



/*
 *
 * SCSA tran_abort entry point
 *
 */

/* ARGSUSED */
static int
atapi_tran_abort(
	struct scsi_address *ap,
	struct scsi_pkt *spktp)
{
	ADBG_TRACE(("atapi_tran_abort entered\n"));

	if (spktp) {
		return (ghd_tran_abort(&ADDR2CTL(ap)->ac_ccc, PKTP2GCMDP(spktp),
		    ADDR2GTGTP(ap), NULL));
	}

	return (ghd_tran_abort_lun(&ADDR2CTL(ap)->ac_ccc, ADDR2GTGTP(ap),
	    NULL));
}


/*
 *
 * SCSA tran_reset entry point
 *
 */

/* ARGSUSED */
static int
atapi_tran_reset(
	struct scsi_address *ap,
	int level)
{
	ADBG_TRACE(("atapi_tran_reset entered\n"));

	if (level == RESET_TARGET)
		return (ghd_tran_reset_target(&ADDR2CTL(ap)->ac_ccc,
		    ADDR2GTGTP(ap), NULL));
	if (level == RESET_ALL)
		return (ghd_tran_reset_bus(&ADDR2CTL(ap)->ac_ccc,
		    ADDR2GTGTP(ap), NULL));
	return (FALSE);

}


/*
 *
 * SCSA tran_setcap entry point
 *
 */

static int
atapi_tran_setcap(
	struct scsi_address *ap,
	char *capstr,
	int value,
	int whom)
{
	gtgt_t	  *gtgtp = ADDR2GTGTP(ap);
	ata_tgt_t *tgtp = GTGTP2ATATGTP(gtgtp);

	ADBG_TRACE(("atapi_tran_setcap entered\n"));

	switch (scsi_hba_lookup_capstr(capstr)) {
		case SCSI_CAP_SECTOR_SIZE:
			tgtp->at_dma_attr.dma_attr_granular = (uint_t)value;
			return (TRUE);

		case SCSI_CAP_ARQ:
			if (whom) {
				tgtp->at_arq = value;
				return (TRUE);
			}
			break;

		case SCSI_CAP_TOTAL_SECTORS:
			tgtp->at_total_sectors = value;
			return (TRUE);
	}
	return (FALSE);
}


/*
 *
 * SCSA tran_getcap entry point
 *
 */

static int
atapi_tran_getcap(
	struct scsi_address *ap,
	char *capstr,
	int whom)
{
	struct ata_id	 ata_id;
	struct ata_id	*ata_idp;
	ata_ctl_t	*ata_ctlp;
	ata_drv_t	*ata_drvp;
	gtgt_t		*gtgtp;
	int		 rval = -1;

	ADBG_TRACE(("atapi_tran_getcap entered\n"));

	if (capstr == NULL || whom == 0)
		return (-1);

	ata_ctlp = ADDR2CTL(ap);

	switch (scsi_hba_lookup_capstr(capstr)) {
	case SCSI_CAP_ARQ:
		rval = TRUE;
		break;

	case SCSI_CAP_INITIATOR_ID:
		rval = 7;
		break;

	case SCSI_CAP_DMA_MAX:
		/* XXX - what should the real limit be?? */
		/* limit to 64K ??? */
		rval = 4096 * (ATA_DMA_NSEGS - 1);
		break;

	case SCSI_CAP_GEOMETRY:
		/* Default geometry */
		if (atapi_use_static_geometry) {
			rval = ATAPI_HEADS << 16 | ATAPI_SECTORS_PER_TRK;
			break;
		}

		/* this code is currently not used */

		ata_drvp = CTL2DRV(ata_ctlp, ap->a_target, ap->a_lun);
		gtgtp = ADDR2GTGTP(ap);

		/*
		 * retrieve the current IDENTIFY PACKET DEVICE info
		 */
		if (!ata_queue_cmd(atapi_id_update, &ata_id, ata_ctlp,
		    ata_drvp, gtgtp)) {
			ADBG_TRACE(("atapi_tran_getcap geometry failed"));
			return (0);
		}

		/*
		 * save the new response data
		 */
		ata_idp = &ata_drvp->ad_id;
		*ata_idp = ata_id;

		switch ((ata_idp->ai_config >> 8) & 0xf) {
		case DTYPE_RODIRECT:
			rval = ATAPI_HEADS << 16 | ATAPI_SECTORS_PER_TRK;
			break;
		case DTYPE_DIRECT:
		case DTYPE_OPTICAL:
			rval = (ata_idp->ai_curheads << 16) |
			    ata_idp->ai_cursectrk;
			break;
		default:
			rval = 0;
		}
		break;
	}

	return (rval);
}



/*
 *
 * SCSA tran_init_pkt entry point
 *
 */

static struct scsi_pkt *
atapi_tran_init_pkt(
	struct scsi_address *ap,
	struct scsi_pkt	*spktp,
	struct buf	*bp,
	int		 cmdlen,
	int		 statuslen,
	int		 tgtlen,
	int		 flags,
	int		(*callback)(caddr_t),
	caddr_t		 arg)
{
	gtgt_t		*gtgtp = ADDR2GTGTP(ap);
	ata_tgt_t	*ata_tgtp = GTGTP2ATATGTP(gtgtp);
	ata_ctl_t	*ata_ctlp = ADDR2CTL(ap);
	ata_pkt_t	*ata_pktp;
	struct scsi_pkt	*new_spktp;
	ddi_dma_attr_t	*sg_attrp;
	int		 bytes;

	ADBG_TRACE(("atapi_tran_init_pkt entered\n"));


	/*
	 * Determine whether to do PCI-IDE DMA setup, start out by
	 * assuming we're not.
	 */
	sg_attrp = NULL;

	if (bp == NULL) {
		/* no data to transfer */
		goto skip_dma_setup;
	}

	if (bp->b_bcount == 0) {
		/* no data to transfer */
		goto skip_dma_setup;
	}

	if ((GTGTP2ATADRVP(ADDR2GTGTP(ap))->ad_pciide_dma == ATA_DMA_OFF)) {
		goto skip_dma_setup;
	}

	if (ata_dma_disabled)
		goto skip_dma_setup;


	/*
	 * The PCI-IDE DMA engine is brain-damaged and can't
	 * DMA non-aligned buffers.
	 */
	if (((bp->b_flags & B_PAGEIO) == 0) &&
	    ((uintptr_t)bp->b_un.b_addr) & PCIIDE_PRDE_ADDR_MASK) {
		/*
		 * if the virtual address isn't aligned, then the
		 * physical address also isn't aligned.
		 */
		goto skip_dma_setup;
	}

	/*
	 * It also insists that the byte count must be even.
	 */
	if (bp->b_bcount & 1) {
		/* something odd here */
		goto skip_dma_setup;
	}

	/*
	 * Huzza! We're really going to do it
	 */
	sg_attrp = &ata_tgtp->at_dma_attr;


skip_dma_setup:

	/*
	 * Call GHD packet init function
	 */

	new_spktp = ghd_tran_init_pkt_attr(&ata_ctlp->ac_ccc, ap, spktp, bp,
	    cmdlen, statuslen, tgtlen, flags,
	    callback, arg, sizeof (ata_pkt_t), sg_attrp);

	if (new_spktp == NULL)
		return (NULL);

	ata_pktp = SPKT2APKT(new_spktp);
	ata_pktp->ap_cdbp = new_spktp->pkt_cdbp;
	if (statuslen > 255) {
		statuslen = sizeof (struct scsi_arq_status);
	}
	ata_pktp->ap_statuslen = (uchar_t)statuslen;

	/* reset data direction flags */
	if (spktp)
		ata_pktp->ap_flags &= ~(AP_READ | AP_WRITE);

	/*
	 * check for ARQ mode
	 */
	if (atapi_arq_enable == TRUE &&
	    ata_tgtp->at_arq == TRUE &&
	    ata_pktp->ap_statuslen >= sizeof (struct scsi_arq_status)) {
		ADBG_TRACE(("atapi_tran_init_pkt ARQ\n"));
		ata_pktp->ap_scbp =
		    (struct scsi_arq_status *)new_spktp->pkt_scbp;
		ata_pktp->ap_flags |= AP_ARQ_ON_ERROR;
	}

	/*
	 * fill these with zeros for ATA/ATAPI-4 compatibility
	 */
	ata_pktp->ap_sec = 0;
	ata_pktp->ap_count = 0;

	if (ata_pktp->ap_sg_cnt) {
		ASSERT(bp != NULL);
		/* determine direction to program the DMA engine later */
		if (bp->b_flags & B_READ) {
			ata_pktp->ap_flags |= AP_READ;
		} else {
			ata_pktp->ap_flags |= AP_WRITE;
		}
		ata_pktp->ap_pciide_dma = TRUE;
		ata_pktp->ap_hicyl = 0;
		ata_pktp->ap_lwcyl = 0;
		return (new_spktp);
	}

	/*
	 * Since we're not using DMA, we need to map the buffer into
	 * kernel address space
	 */

	ata_pktp->ap_pciide_dma = FALSE;
	if (bp && bp->b_bcount) {
		/*
		 * If this is a fresh request map the buffer and
		 * reset the ap_baddr pointer and the current offset
		 * and byte count.
		 *
		 * The ap_boffset is used to set the ap_v_addr ptr at
		 * the start of each I/O request.
		 *
		 * The ap_bcount is used to update ap_boffset when the
		 * target driver requests the next segment.
		 *
		 */
		if (cmdlen) {
			bp_mapin(bp);
			ata_pktp->ap_baddr = bp->b_un.b_addr;
			ata_pktp->ap_bcount = 0;
			ata_pktp->ap_boffset = 0;
		}
		ASSERT(ata_pktp->ap_baddr != NULL);

		/* determine direction for the PIO FSM */
		if (bp->b_flags & B_READ) {
			ata_pktp->ap_flags |= AP_READ;
		} else {
			ata_pktp->ap_flags |= AP_WRITE;
		}

		/*
		 * If the drive has the Single Sector bug, limit
		 * the transfer to a single sector. This assumes
		 * ATAPI CD drives always use 2k sectors.
		 */
		if (GTGTP2ATADRVP(ADDR2GTGTP(ap))->ad_flags & AD_1SECTOR) {
			size_t resid;
			size_t tmp;

			/* adjust offset based on prior request */
			ata_pktp->ap_boffset += ata_pktp->ap_bcount;

			/* compute number of bytes left to transfer */
			resid = bp->b_bcount - ata_pktp->ap_boffset;

			/* limit the transfer to 2k */
			tmp = MIN(2048, resid);
			ata_pktp->ap_bcount = tmp;

			/* tell target driver how much is left for next time */
			new_spktp->pkt_resid = resid - tmp;
		} else {
			/* do the whole request in one swell foop */
			ata_pktp->ap_bcount = bp->b_bcount;
			new_spktp->pkt_resid = 0;
		}

	} else {
		ata_pktp->ap_baddr = NULL;
		ata_pktp->ap_bcount = 0;
		ata_pktp->ap_boffset = 0;
	}

	/*
	 * determine the size of each partial data transfer
	 * to/from the drive
	 */
	bytes = min(ata_pktp->ap_bcount, ATAPI_MAX_BYTES_PER_DRQ);
	ata_pktp->ap_hicyl = (uchar_t)(bytes >> 8);
	ata_pktp->ap_lwcyl = (uchar_t)bytes;
	return (new_spktp);
}


/*
 * GHD ccballoc callback
 *
 *	Initializing the ata_pkt, and return the ptr to the gcmd_t to GHD.
 *
 */

/* ARGSUSED */
int
atapi_ccballoc(
	gtgt_t	*gtgtp,
	gcmd_t	*gcmdp,
	int	 cmdlen,
	int	 statuslen,
	int	 tgtlen,
	int	 ccblen)

{
	ata_drv_t *ata_drvp = GTGTP2ATADRVP(gtgtp);
	ata_pkt_t *ata_pktp = GCMD2APKT(gcmdp);

	ADBG_TRACE(("atapi_ccballoc entered\n"));

	/* set the back ptr from the ata_pkt to the gcmd_t */
	ata_pktp->ap_gcmdp = gcmdp;

	/* check length of SCSI CDB is not larger than drive expects */

	if (cmdlen > ata_drvp->ad_cdb_len) {
		ADBG_WARN(("atapi_ccballoc: SCSI CDB too large!\n"));
		return (FALSE);
	}

	/*
	 * save length of the SCSI CDB, and calculate CDB padding
	 * note that for convenience, padding is expressed in shorts.
	 */

	ata_pktp->ap_cdb_len = (uchar_t)cmdlen;
	ata_pktp->ap_cdb_pad =
		((unsigned)(ata_drvp->ad_cdb_len - cmdlen)) >> 1;

	/* set up callback functions */

	ata_pktp->ap_start = atapi_fsm_start;
	ata_pktp->ap_intr = atapi_fsm_intr;
	ata_pktp->ap_complete = atapi_complete;

	/* set-up for start */

	ata_pktp->ap_flags = AP_ATAPI;
	ata_pktp->ap_hd = ata_drvp->ad_drive_bits;
	ata_pktp->ap_cmd = ATC_PACKET;

	return (TRUE);
}



/*
 *
 * SCSA tran_destroy_pkt entry point
 *
 */

static void
atapi_tran_destroy_pkt(
	struct scsi_address *ap,
	struct scsi_pkt *spktp)
{
	gcmd_t	  *gcmdp = PKTP2GCMDP(spktp);

	ADBG_TRACE(("atapi_tran_destroy_pkt entered\n"));

	if (gcmdp->cmd_dma_handle != NULL) {
		ghd_dmafree_attr(gcmdp);
	}

	ghd_pktfree(&ADDR2CTL(ap)->ac_ccc, ap, spktp);
}



/*
 *
 * GHD ccbfree callback function
 *
 */

/* ARGSUSED */
void
atapi_ccbfree(
	gcmd_t *gcmdp)
{
	ADBG_TRACE(("atapi_ccbfree entered\n"));

	/* nothing to do */
}


/*
 *
 * SCSA tran_dmafree entry point
 *
 */

/*ARGSUSED*/
static void
atapi_tran_dmafree(
	struct scsi_address *ap,
	struct scsi_pkt *spktp)
{
	gcmd_t	  *gcmdp = PKTP2GCMDP(spktp);

	ADBG_TRACE(("atapi_tran_dmafree entered\n"));

	if (gcmdp->cmd_dma_handle != NULL) {
		ghd_dmafree_attr(gcmdp);
	}
}



/*
 *
 * SCSA tran_sync_pkt entry point
 *
 */

/*ARGSUSED*/
static void
atapi_tran_sync_pkt(
	struct scsi_address *ap,
	struct scsi_pkt *spktp)
{

	ADBG_TRACE(("atapi_tran_sync_pkt entered\n"));

	if (PKTP2GCMDP(spktp)->cmd_dma_handle != NULL) {
		ghd_tran_sync_pkt(ap, spktp);
	}
}



/*
 *
 * SCSA tran_start entry point
 *
 */

/* ARGSUSED */
static int
atapi_tran_start(
	struct scsi_address *ap,
	struct scsi_pkt *spktp)
{
	ata_pkt_t *ata_pktp = SPKT2APKT(spktp);
	ata_drv_t *ata_drvp = APKT2DRV(ata_pktp);
	ata_ctl_t *ata_ctlp = ata_drvp->ad_ctlp;
	gcmd_t	  *gcmdp = APKT2GCMD(ata_pktp);
	int	   polled = FALSE;
	int	   rc;

	ADBG_TRACE(("atapi_tran_start entered\n"));

	/*
	 * Basic initialization performed each and every time a
	 * scsi_pkt is submitted. A single scsi_pkt may be submitted
	 * multiple times so this routine has to be idempotent. One
	 * time initializations don't belong here.
	 */

	/*
	 * The ap_v_addr pointer is incremented by the PIO data
	 * transfer routine as each word is transferred. Therefore, need
	 * to reset ap_v_addr here (rather than atapi_tran_init_pkt())
	 * in case the target resubmits the same pkt multiple times
	 * (which is permitted by SCSA).
	 */
	ata_pktp->ap_v_addr = ata_pktp->ap_baddr + ata_pktp->ap_boffset;

	/* ap_resid is decremented as the data transfer progresses */
	ata_pktp->ap_resid = ata_pktp->ap_bcount;

	/* clear error flags */
	ata_pktp->ap_flags &= (AP_ATAPI | AP_READ | AP_WRITE | AP_ARQ_ON_ERROR);
	spktp->pkt_reason = 0;
	spktp->pkt_state = 0;
	spktp->pkt_statistics = 0;

	/*
	 * check for polling pkt
	 */
	if (spktp->pkt_flags & FLAG_NOINTR) {
		polled = TRUE;
	}

#ifdef ___just_ignore_unsupported_flags___
	/* driver cannot accept tagged commands */

	if (spktp->pkt_flags & (FLAG_HTAG|FLAG_OTAG|FLAG_STAG)) {
		spktp->pkt_reason = CMD_TRAN_ERR;
		return (TRAN_BADPKT);
	}
#endif

	/* call common transport routine */

	rc = ghd_transport(&ata_ctlp->ac_ccc, gcmdp, gcmdp->cmd_gtgtp,
	    spktp->pkt_time, polled, NULL);

	/* see if pkt was not accepted */

	if (rc != TRAN_ACCEPT)
		return (rc);

	return (rc);
}


/*
 *
 * GHD packet complete callback
 *
 */
/* ARGSUSED */
static void
atapi_complete(
	ata_drv_t *ata_drvp,
	ata_pkt_t *ata_pktp,
	int do_callback)
{
	struct scsi_pkt *spktp = APKT2SPKT(ata_pktp);
	struct scsi_status *scsi_stat = (struct scsi_status *)spktp->pkt_scbp;

	ADBG_TRACE(("atapi_complete entered\n"));
	ADBG_TRANSPORT(("atapi_complete: pkt = 0x%p\n", ata_pktp));

	/* update resid */

	spktp->pkt_resid = ata_pktp->ap_resid;

	if (ata_pktp->ap_flags & AP_SENT_CMD) {
		spktp->pkt_state |=
		    STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD;
	}
	if (ata_pktp->ap_flags & AP_XFERRED_DATA) {
		spktp->pkt_state |= STATE_XFERRED_DATA;
	}

	if (ata_pktp->ap_flags & AP_GOT_STATUS) {
		spktp->pkt_state |= STATE_GOT_STATUS;
	}

	/* check for fatal errors */

	if (ata_pktp->ap_flags & AP_TRAN_ERROR) {
		spktp->pkt_reason = CMD_TRAN_ERR;
	} else if (ata_pktp->ap_flags & AP_BUS_RESET) {
		spktp->pkt_reason = CMD_RESET;
		spktp->pkt_statistics |= STAT_BUS_RESET;
	} else if (ata_pktp->ap_flags & AP_DEV_RESET) {
		spktp->pkt_reason = CMD_RESET;
		spktp->pkt_statistics |= STAT_DEV_RESET;
	} else if (ata_pktp->ap_flags & AP_ABORT) {
		spktp->pkt_reason = CMD_ABORTED;
		spktp->pkt_statistics |= STAT_ABORTED;
	} else if (ata_pktp->ap_flags & AP_TIMEOUT) {
		spktp->pkt_reason = CMD_TIMEOUT;
		spktp->pkt_statistics |= STAT_TIMEOUT;
	} else {
		spktp->pkt_reason = CMD_CMPLT;
	}

	/* non-fatal errors */

	if (ata_pktp->ap_flags & AP_ERROR)
		scsi_stat->sts_chk = 1;
	else
		scsi_stat->sts_chk = 0;

	if (ata_pktp->ap_flags & AP_ARQ_ERROR) {
		ADBG_ARQ(("atapi_complete ARQ error 0x%p\n", ata_pktp));
		spktp->pkt_reason = CMD_TRAN_ERR;

	} else if (ata_pktp->ap_flags & AP_ARQ_OKAY) {
		static struct scsi_status zero_scsi_status = { 0 };
		struct scsi_arq_status *arqp;

		ADBG_ARQ(("atapi_complete ARQ okay 0x%p\n", ata_pktp));
		spktp->pkt_state |= STATE_ARQ_DONE;
		arqp = ata_pktp->ap_scbp;
		arqp->sts_rqpkt_reason = CMD_CMPLT;
		arqp->sts_rqpkt_state = STATE_XFERRED_DATA;
		arqp->sts_rqpkt_status = zero_scsi_status;
		arqp->sts_rqpkt_resid = 0;
		arqp->sts_rqpkt_statistics = 0;

	}

	ADBG_TRANSPORT(("atapi_complete: reason = 0x%x stats = 0x%x "
	    "sts_chk = %d\n", spktp->pkt_reason, spktp->pkt_statistics,
	    scsi_stat->sts_chk));

	if (do_callback && (spktp->pkt_comp))
		(*spktp->pkt_comp)(spktp);
}



/*
 * Update the IDENTIFY PACKET DEVICE info
 */

static int
atapi_id_update(
	ata_ctl_t	*ata_ctlp,
	ata_drv_t	*ata_drvp,
	ata_pkt_t	*ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	caddr_t		 ioaddr1 = ata_ctlp->ac_ioaddr1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;
	caddr_t		 ioaddr2 = ata_ctlp->ac_ioaddr2;
	struct ata_id	*aidp;
	int	rc;

	/*
	 * select the appropriate drive and LUN
	 */
	ddi_put8(io_hdl1, (uchar_t *)ioaddr1 + AT_DRVHD,
	    ata_drvp->ad_drive_bits);
	ata_nsecwait(400);

	/*
	 * make certain the drive is selected, and wait for not busy
	 */
	if (!ata_wait(io_hdl2, ioaddr2, ATS_DRDY, ATS_BSY, 5 * 1000000)) {
		ADBG_ERROR(("atapi_id_update: select failed\n"));
		if (ata_pktp != NULL)
			ata_pktp->ap_flags |= AP_ERROR;
		return (ATA_FSM_RC_FINI);
	}

	if (ata_pktp != NULL)
		aidp = (struct ata_id *)ata_pktp->ap_v_addr;
	else
		aidp = &ata_drvp->ad_id;

	rc = atapi_id(ata_ctlp->ac_iohandle1, ata_ctlp->ac_ioaddr1,
	    ata_ctlp->ac_iohandle2, ata_ctlp->ac_ioaddr2, aidp);
	if (rc) {
		swab(aidp->ai_drvser, aidp->ai_drvser,
		    sizeof (aidp->ai_drvser));
		swab(aidp->ai_fw, aidp->ai_fw,
		    sizeof (aidp->ai_fw));
		swab(aidp->ai_model, aidp->ai_model,
		    sizeof (aidp->ai_model));
	}

	if (ata_pktp == NULL)
		return (ATA_FSM_RC_FINI);

	if (!rc) {
		ata_pktp->ap_flags |= AP_ERROR;
	} else {
		ata_pktp->ap_flags |= AP_XFERRED_DATA;
	}
	return (ATA_FSM_RC_FINI);
}



/*
 * Both drives on the controller share a common pkt to do
 * ARQ processing. Therefore the pkt is only partially
 * initialized here. The rest of initialization occurs
 * just before starting the ARQ pkt when an error is
 * detected.
 */

void
atapi_init_arq(
	ata_ctl_t *ata_ctlp)
{
	ata_pkt_t *arq_pktp = ata_ctlp->ac_arq_pktp;

	arq_pktp->ap_cdbp = ata_ctlp->ac_arq_cdb;
	arq_pktp->ap_cdb_len = sizeof (ata_ctlp->ac_arq_cdb);
	arq_pktp->ap_start = atapi_fsm_start;
	arq_pktp->ap_intr = atapi_fsm_intr;
	arq_pktp->ap_complete = atapi_complete;
	arq_pktp->ap_flags = AP_ATAPI;
	arq_pktp->ap_cmd = ATC_PACKET;

	ata_ctlp->ac_arq_cdb[0] = SCMD_REQUEST_SENSE;
}
