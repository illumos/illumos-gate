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
 * Copyright (C) 2013 Hewlett-Packard Development Company, L.P.
 */

#include <sys/sdt.h>
#include "cpqary3.h"

/*
 * Local Functions Definitions
 */

static int cpqary3_tgt_init(dev_info_t *, dev_info_t *, scsi_hba_tran_t *,
    struct scsi_device *);
static int cpqary3_tgt_probe(struct scsi_device *, int (*)());
static int cpqary3_transport(struct scsi_address *, struct scsi_pkt *);
static int cpqary3_reset(struct scsi_address *, int);
static int cpqary3_abort(struct scsi_address *, struct scsi_pkt *);
static int cpqary3_getcap(struct scsi_address *, char *, int);
static int cpqary3_setcap(struct scsi_address *, char *, int, int);
static int cpqary3_dma_alloc(cpqary3_t *, struct scsi_pkt *,
    struct buf *, int, int (*)());
static int cpqary3_dma_move(struct scsi_pkt *, struct buf *, cpqary3_t *);
static int cpqary3_handle_flag_nointr(cpqary3_cmdpvt_t *, struct scsi_pkt *);
static int cpqary3_poll(cpqary3_t *, uint32_t);
static void cpqary3_dmafree(struct scsi_address *, struct scsi_pkt *);
static void cpqary3_dma_sync(struct scsi_address *, struct scsi_pkt *);
static void cpqary3_destroy_pkt(struct scsi_address *, struct scsi_pkt *);
static struct scsi_pkt *cpqary3_init_pkt(struct scsi_address *,
    struct scsi_pkt *, struct buf *, int, int, int, int, int (*callback)(),
    caddr_t);
static int cpqary3_additional_cmd(struct scsi_pkt *scsi_pktp, cpqary3_t *);
void cpqary3_oscmd_complete(cpqary3_cmdpvt_t *);
static uint8_t cpqary3_is_scsi_read_write(struct scsi_pkt *scsi_pktp);

/*
 * External Variable Declarations
 */

extern ddi_dma_attr_t cpqary3_dma_attr;

/*
 * Function	: 	cpqary3_init_hbatran
 * Description	: 	This routine initializes the transport vector in the
 *			SCSA architecture for entry ponts in this driver.
 * Called By	: 	cpqary3_attach()
 * Parameters	: 	per_controller
 * Calls	: 	None
 * Return Values: 	None
 */
void
cpqary3_init_hbatran(cpqary3_t *ctlr)
{
	scsi_hba_tran_t	*hba_tran;

	ASSERT(ctlr != NULL);

	hba_tran = ctlr->hba_tran;

	/*
	 * Memory for the transport vector has been allocated by now.
	 * initialize all the entry points in this vector
	 */

	hba_tran->tran_hba_private = (void *)ctlr;

	/* Target Driver Instance Initialization */
	hba_tran->tran_tgt_init = cpqary3_tgt_init;
	hba_tran->tran_tgt_probe = cpqary3_tgt_probe;

	/* Resource Allocation */
	hba_tran->tran_init_pkt = cpqary3_init_pkt;
	hba_tran->tran_destroy_pkt = cpqary3_destroy_pkt;
	hba_tran->tran_sync_pkt = cpqary3_dma_sync;
	hba_tran->tran_dmafree = cpqary3_dmafree;

	/* Command Transport */
	hba_tran->tran_start = cpqary3_transport;

	/* Capability Management */
	hba_tran->tran_getcap = cpqary3_getcap;
	hba_tran->tran_setcap = cpqary3_setcap;

	/* Abort and Reset */
	hba_tran->tran_reset = cpqary3_reset;
	hba_tran->tran_abort = cpqary3_abort;
}

/*
 * Function	:	cpqary3_tgt_init ()
 * Description	: 	This routine validates the target ID.
 * Called By	:  	cpqary3_init_hbatran()
 * Parameters	: 	HBA-instance, target instance, transport vector,
 *			scsi-device structure
 * Calls	:  	cpqary3_detect_target_geometry(),
 *			cpqary3_probe4targets()
 * Return Values: 	DDI_SUCCESS : A Target exists at this ID.
 *			DDI_FAILURE : No such target exists.
 */
/* ARGSUSED */
static int
cpqary3_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	uint32_t	tid = SD2TGT(sd);
	uint32_t	lun = SD2LUN(sd);
	cpqary3_t	*ctlr;

	ctlr = (cpqary3_t *)hba_tran->tran_hba_private;

	/* HPQacucli Changes */

	extern int8_t	cpqary3_detect_target_geometry(cpqary3_t *);
	if ((CPQARY3_SUCCESS == cpqary3_probe4targets(ctlr)) &&
	    (ctlr->num_of_targets > 0)) {
		(void) cpqary3_detect_target_geometry(ctlr);
	}

	/* HPQacucli Changes */
	/*
	 * Validate the Target ID
	 * Validate Lun --Ver1.10--
	 * If not a valid target id, return FAILURE.
	 * Derieve the per-controller
	 */

	if ((tid >= CPQARY3_MAX_TGT) || (lun != 0)) {
		DTRACE_PROBE2(tgt_init_notsup,
		    cpqary3_t *, ctlr, uint32_t, tid);
		return (DDI_FAILURE);
	}

	/*
	 * Check to see if a target structure corrresponding to this
	 * target Id exists.(support only for Logical Drives and Controller)
	 * if target exists, update target flags, return SUCCESS
	 * is target does not exist, return FAILURE
	 */

	mutex_enter(&ctlr->sw_mutex);

	if (!(ctlr->cpqary3_tgtp[tid])) {
		mutex_exit(&ctlr->sw_mutex);
		return (DDI_FAILURE);
	}

	ctlr->cpqary3_tgtp[tid]->tgt_dip = tgt_dip;
	ctlr->cpqary3_tgtp[tid]->ctlr_flags = CPQARY3_CAP_DISCON_ENABLED |
	    CPQARY3_CAP_SYNC_ENABLED | CPQARY3_CAP_WIDE_XFER_ENABLED |
	    CPQARY3_CAP_ARQ_ENABLED;

	mutex_exit(&ctlr->sw_mutex);

	DTRACE_PROBE1(tgt_init_done, uint32_t, tid);

	return (DDI_SUCCESS);
}

/*
 * Function	:	cpqary3_tgt_probe()
 * Description	: 	This routine probes into the Target Details.
 * Called By	:  	cpqary3_init_hbatran()
 * Parameters	: 	scsi-device structure, calling function if any
 * Calls	: 	None
 * Return Values: 	value returned by scsi_hba_probe()
 */
static int
cpqary3_tgt_probe(struct scsi_device *sd, int (*waitfunc)())
{
#ifdef CPQARY3_DEBUG
	int	status;
#endif

	/*
	 * Probe for the presence of the target, using the scsi_hba_probe().
	 * It inturn issues the SCSI inquiry command that is serviced by our
	 * driver
	 */

	/* HPQacucli Changes */
	extern int8_t		cpqary3_detect_target_geometry(cpqary3_t *);
	struct scsi_hba_tran	*hba_tran = sd->sd_address.a_hba_tran;
	cpqary3_t		*ctlr = hba_tran->tran_hba_private;

	if ((CPQARY3_SUCCESS == cpqary3_probe4targets(ctlr)) &&
	    (ctlr->num_of_targets > 0)) {
		(void) cpqary3_detect_target_geometry(ctlr);
	}
	/* HPQacucli Changes */

	return (scsi_hba_probe(sd, waitfunc));

#ifdef CPQARY3_DEBUG

	/* Comment the previous line of code */
	status = scsi_hba_probe(sd, waitfunc);
	cmn_err(CE_CONT, "CPQary3 : _tgt_probe : target = %d \n", SD2TGT(sd));
	cmn_err(CE_CONT, "CPQary3 : _tgt_probe : scsi_hba_probe returned %d \n",
	    status);
	cmn_err(CE_CONT, "CPQary3 : _tgt_probe : Leaving \n");
	return (status);

#endif
}

/*
 * Function	:	cpqary3_init_pkt
 * Description	: 	This routine allocates resources for a SCSI packet.
 * Called By	:  	cpqary3_init_pkt()
 * Parameters	: 	SCSI address, SCSI packet, buffer, CDB length,
 *			SCB length, driver private length, flags modifier,
 *			callback function, arguement for the callback function
 * Calls	: 	cpqary3_dma_alloc(), cpqary3_dma_move()
 * Return Values: 	allocated SCSI packet / NULL
 */
/* ARGSUSED */
static struct scsi_pkt *
cpqary3_init_pkt(struct scsi_address *sa, struct scsi_pkt *scsi_pktp,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen,
    int flags, int (*callback)(), caddr_t arg)
{
	cpqary3_t	*cpqary3p;
	dev_info_t	*dip;
	cpqary3_pkt_t	*cpqary3_pktp;
	struct scsi_pkt	*new_scsi_pktp;

	ASSERT(callback == NULL_FUNC || callback == SLEEP_FUNC);

	cpqary3p = SA2CTLR(sa);
	dip = cpqary3p->dip;

	/*
	 * If the SCSI packet is NULL, allocate frresh resources to it.
	 * Else, get the next available resources for the same
	 */

	if (!scsi_pktp) {
		scsi_pktp = scsi_hba_pkt_alloc(dip, sa, cmdlen, statuslen,
		    tgtlen, sizeof (cpqary3_pkt_t), callback, NULL);
		if (!scsi_pktp)
			return (NULL);

		cpqary3_pktp = (cpqary3_pkt_t *)scsi_pktp->pkt_ha_private;
		bzero(cpqary3_pktp, sizeof (cpqary3_pkt_t));

		cpqary3_pktp->scsi_cmd_pkt = scsi_pktp;

		/*
		 * Store the CDB length and sense data length in the
		 * pkt private
		 */
		cpqary3_pktp->cdb_len = cmdlen;
		cpqary3_pktp->scb_len = statuslen;
		cpqary3_pktp->cmd_dmahandle = NULL;
		cpqary3_pktp->memp = (cpqary3_cmdpvt_t *)NULL;

		/*
		 * Initialize to NULL all the fields of scsi_pktp, except
		 * pkt_scbp, pkt_cdbp, pkt_ha_private and pkt_private members.
		 */
		scsi_pktp->pkt_address = *sa;
		scsi_pktp->pkt_comp = (void (*) ())NULL;
		scsi_pktp->pkt_flags = 0;
		scsi_pktp->pkt_time = 0;
		scsi_pktp->pkt_resid = 0;
		scsi_pktp->pkt_statistics = 0;
		scsi_pktp->pkt_state = 0;
		scsi_pktp->pkt_reason = 0;

		if (flags & PKT_CONSISTENT)
			cpqary3_pktp->cmd_flags |=  DDI_DMA_CONSISTENT;

		if (flags & PKT_DMA_PARTIAL)
			cpqary3_pktp->cmd_flags |= DDI_DMA_PARTIAL;

		new_scsi_pktp = scsi_pktp;
	} else {
		new_scsi_pktp = NULL;
		cpqary3_pktp = (cpqary3_pkt_t *)scsi_pktp->pkt_ha_private;
	}

	cpqary3_pktp->bf = bp;

	/*
	 * If any I/O is desired, Allocate/Move DMA resources for the SCSI
	 * packet
	 * If first time allocation for this SCSI packet, allocate fresh DMA
	 * Else, move the already allocated DMA resources
	 */
	if (bp && bp->b_bcount != 0) { /* I/O is desired */
		if (!cpqary3_pktp->cmd_dmahandle) { /* First time allocation */
			if (cpqary3_dma_alloc(cpqary3p, scsi_pktp,
			    bp, flags, callback) == CPQARY3_FAILURE) {
				if (new_scsi_pktp)
					scsi_hba_pkt_free(sa, new_scsi_pktp);
				return ((struct scsi_pkt *)NULL);
			}
		} else {
			ASSERT(new_scsi_pktp == NULL);
			if (CPQARY3_FAILURE ==
			    cpqary3_dma_move(scsi_pktp, bp, cpqary3p)) {
				return ((struct scsi_pkt *)NULL);
			}
		}
	}

	return (scsi_pktp);
}

/*
 * Function	:	cpqary3_dma_alloc()
 * Description	: 	This routine services requests for memory (dynamic)
 *			as and when required by the OS.
 * Called By	: 	cpqary3_init_pkt()
 * Parameters	: 	per-controller, SCSI packet, buffer, flag modifier,
 *			callback function
 * Calls	: 	None
 * Return Values: 	SUCCESS / FAILURE
 */
static int
cpqary3_dma_alloc(cpqary3_t *cpqary3p, struct scsi_pkt *scsi_pktp,
    struct buf *bp, int flags, int (*callback)())
{
	int32_t		(*cb)(caddr_t);
	int32_t		retvalue;
	uint32_t	i = 0;
	uint32_t	dma_flags;
	cpqary3_pkt_t	*cpqary3_pktp;
	ddi_dma_attr_t	tmp_dma_attr;

	cpqary3_pktp = (cpqary3_pkt_t *)scsi_pktp->pkt_ha_private;

	ASSERT(callback == NULL_FUNC || callback == SLEEP_FUNC);
	/*
	 * Record the direction of the data transfer, so that it
	 * can be used in appropriate synchronization during cpqary3_sync_pkt()
	 */
	if (bp->b_flags & B_READ) {
		cpqary3_pktp->cmd_flags &= ~CFLAG_DMASEND;
		dma_flags = DDI_DMA_READ;
	} else {
		cpqary3_pktp->cmd_flags |= CFLAG_DMASEND;
		dma_flags = DDI_DMA_WRITE;
	}

	if (flags & PKT_CONSISTENT) {
		cpqary3_pktp->cmd_flags |= CFLAG_CMDIOPB;
		dma_flags |= DDI_DMA_CONSISTENT;
	}

	if (flags & PKT_DMA_PARTIAL) {
		dma_flags |= DDI_DMA_PARTIAL;
	}

	tmp_dma_attr = cpqary3_dma_attr;

	/* SG */
	tmp_dma_attr.dma_attr_sgllen = cpqary3p->sg_cnt;
	/* SG */

	cb = (callback == NULL_FUNC) ? DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	/*
	 * DMA resources are allocated thru a 2 step protocol :
	 * - allocate a DMA handle
	 * - bind the buffer to the handle
	 * If both the steps succeed, we have succeeded in allocating resources
	 */

	if (DDI_SUCCESS != (retvalue = ddi_dma_alloc_handle(cpqary3p->dip,
	    &tmp_dma_attr, cb, CPQARY3_DMA_NO_CALLBACK,
	    &cpqary3_pktp->cmd_dmahandle))) {
		switch (retvalue) {
		case DDI_DMA_NORESOURCES:
			/*
			 * No Resources are available to be allocated
			 */
			bioerror(bp, CPQARY3_BUFFER_ERROR_CLEAR);
			break;

		case DDI_DMA_BADATTR:
			/*
			 * The attributes stated in our DMA attribute
			 * structure is such that potential DMA resources can
			 * not be allocated.
			 */
			cmn_err(CE_CONT, "CPQary3: DmaAlloc: "
			    "AllocHandle Failed BadAttr\n");
			bioerror(bp, EFAULT);
			break;

		default:
			/*
			 * There is no other possible return value
			 */
			cmn_err(CE_WARN,
			    "CPQary3: dma_alloc: Unexpected Return Value %x "
			    "From call to Allocate DMA Handle \n", retvalue);
			break;
		}
		return (CPQARY3_FAILURE);
	}

	retvalue = ddi_dma_buf_bind_handle(cpqary3_pktp->cmd_dmahandle, bp,
	    dma_flags, cb, CPQARY3_DMA_NO_CALLBACK,
	    &cpqary3_pktp->cmd_dmacookies[0], &cpqary3_pktp->cmd_ncookies);

	switch (retvalue) {
	case DDI_DMA_PARTIAL_MAP :
	case DDI_DMA_MAPPED :
		if (DDI_DMA_PARTIAL_MAP == retvalue) {
			if (ddi_dma_numwin(cpqary3_pktp->cmd_dmahandle,
			    &cpqary3_pktp->cmd_nwin) == DDI_FAILURE) {
				cmn_err(CE_PANIC, "CPQary3: Retrieval of DMA "
				    "windows number failed");
			}

			if (ddi_dma_getwin(cpqary3_pktp->cmd_dmahandle,
			    cpqary3_pktp->cmd_curwin,
			    &cpqary3_pktp->cmd_dma_offset,
			    &cpqary3_pktp->cmd_dma_len,
			    &cpqary3_pktp->cmd_dmacookies[0],
			    &cpqary3_pktp->cmd_ncookies) == DDI_FAILURE) {
				cmn_err(CE_PANIC, "CPQary3: Activation of New "
				    "DMA Window Failed");
			}
		} else {
			cpqary3_pktp->cmd_nwin = 1;
			cpqary3_pktp->cmd_dma_len = 0;
			cpqary3_pktp->cmd_dma_offset = 0;
		}

		cpqary3_pktp->cmd_dmacount = 0;
		i = 0;
		for (;;) {
			cpqary3_pktp->cmd_dmacount +=
			    cpqary3_pktp->cmd_dmacookies[i++].dmac_size;
			/* SG */
			/* Check Out for Limits */
			if (i == cpqary3p->sg_cnt ||
			    i == cpqary3_pktp->cmd_ncookies)
				break;
			/* SG */

			ddi_dma_nextcookie(cpqary3_pktp->cmd_dmahandle,
			    &cpqary3_pktp->cmd_dmacookies[i]);
		}

		cpqary3_pktp->cmd_cookie = i;
		cpqary3_pktp->cmd_cookiecnt = i;
		cpqary3_pktp->cmd_flags |= CFLAG_DMAVALID;

		scsi_pktp->pkt_resid =
		    bp->b_bcount - cpqary3_pktp->cmd_dmacount;

		return (CPQARY3_SUCCESS);

	case DDI_DMA_NORESOURCES:
		bioerror(bp, CPQARY3_BUFFER_ERROR_CLEAR);
		break;

	case DDI_DMA_NOMAPPING:
		bioerror(bp, EFAULT);
		break;

	case DDI_DMA_TOOBIG:
		bioerror(bp, EINVAL);
		break;

	case DDI_DMA_INUSE:
		cmn_err(CE_PANIC, "CPQary3: Another I/O transaction "
		    "is using the DMA handle");

	default:
		cmn_err(CE_PANIC, "CPQary3: Unexpected ERROR "
		    "returned from Call to Bind Buffer "
		    "to Handle : 0x%X", i);
	}

	ddi_dma_free_handle(&cpqary3_pktp->cmd_dmahandle);
	cpqary3_pktp->cmd_dmahandle = NULL;
	cpqary3_pktp->cmd_flags &= ~CFLAG_DMAVALID;

	return (CPQARY3_FAILURE);

}

/*
 * Function	:	cpqary3_dma_move()
 * Description	: 	This routine gets the next DMA window.
 * Called By	: 	cpqary3_init_pkt()
 * Parameters	: 	per-controller, SCSI packet, buffer
 * Calls	: 	None
 * Return Values: 	SUCCESS / FAILURE
 */
static int
cpqary3_dma_move(struct scsi_pkt *scsi_pktp, struct buf *bp,
    cpqary3_t *cpqary3p)
{
	uint32_t		i = 0;
	cpqary3_pkt_t	*cpqary3_pktp;

	cpqary3_pktp = PKT2PVTPKT(scsi_pktp);

	/*
	 * If there are no more cookies remaining in this window,
	 * must move to the next window first.
	 */
	if (cpqary3_pktp->cmd_cookie == cpqary3_pktp->cmd_ncookies) {
		/* For small pkts, leave things where they are */
		if ((cpqary3_pktp->cmd_curwin == cpqary3_pktp->cmd_nwin) &&
		    (cpqary3_pktp->cmd_nwin == 1))
			return (CPQARY3_SUCCESS);

		/* Shall not be able to move if last window */
		if (++cpqary3_pktp->cmd_curwin >= cpqary3_pktp->cmd_nwin)
			return (CPQARY3_FAILURE);

		if (ddi_dma_getwin(cpqary3_pktp->cmd_dmahandle,
		    cpqary3_pktp->cmd_curwin, &cpqary3_pktp->cmd_dma_offset,
		    &cpqary3_pktp->cmd_dma_len,
		    &cpqary3_pktp->cmd_dmacookies[0],
		    &cpqary3_pktp->cmd_ncookies) == DDI_FAILURE)
			return (CPQARY3_FAILURE);

		cpqary3_pktp->cmd_cookie = 0;
	} else {
		/* Still more cookies in this window - get the next one */
		ddi_dma_nextcookie(cpqary3_pktp->cmd_dmahandle,
		    &cpqary3_pktp->cmd_dmacookies[0]);
	}

	/* Get remaining cookies in this window, up to our maximum */
	for (;;) {
		cpqary3_pktp->cmd_dmacount +=
		    cpqary3_pktp->cmd_dmacookies[i++].dmac_size;
		cpqary3_pktp->cmd_cookie++;
		/* SG */
		/* no. of DATA SEGMENTS */
		if (i == cpqary3p->sg_cnt ||
		    cpqary3_pktp->cmd_cookie == cpqary3_pktp->cmd_ncookies)
			break;
		/* SG */

		ddi_dma_nextcookie(cpqary3_pktp->cmd_dmahandle,
		    &cpqary3_pktp->cmd_dmacookies[i]);
	}

	cpqary3_pktp->cmd_cookiecnt = i;
	scsi_pktp->pkt_resid = bp->b_bcount - cpqary3_pktp->cmd_dmacount;

	return (CPQARY3_SUCCESS);

}

/*
 * Function	:	cpqary3_transport()
 * Description	: 	This routine services requests from the OS that are
 *			directed towards the targets.(any SCSI command)
 * Called By	: 	kernel
 * Parameters	: 	SCSI address, SCSI packet, buffer
 * Calls	: 	cpqary3_build_iop, cpqary3_add2submitted
 * Return Values: 	TRAN_ACCEPT	: The driver accepts the command.
 *			TRAN_BUSY	: Required resources not available
 *					at the moment.
 *			TRAN_FATAL_ERROR: A target no longer exists.
 */
static int
cpqary3_transport(struct scsi_address *sa, struct scsi_pkt *scsi_pktp)
{
	cpqary3_t		*ctlr;
	cpqary3_pkt_t		*cpqary3_pktp;
	cpqary3_tgt_t		*tgtp;
	cpqary3_cmdpvt_t	*memp;

	ASSERT(sa != NULL);
	ctlr = SA2CTLR(sa);
	cpqary3_pktp = PKT2PVTPKT(scsi_pktp);
	tgtp = ctlr->cpqary3_tgtp[SA2TGT(sa)];

	if (!tgtp)
		return (TRAN_FATAL_ERROR);

	if (tgtp->type == CPQARY3_TARGET_NONE)
		return (TRAN_FATAL_ERROR);

	if (cpqary3_additional_cmd(scsi_pktp, ctlr))
		return (TRAN_ACCEPT);

	/*
	 * Attempt to occupy a free command memory block
	 * If not successful, return TRAN_BUSY
	 * Else, build the Command
	 * Submit it to the controller
	 * If NO_INTR flag is set, wait for the completion of the command and
	 * when the command completes, update packet values appropriately and
	 * return TRAN_ACCEPT.
	 * Make an entry in the submitted Q
	 * return TRAN_ACCEPT
	 */

	if (NULL == (memp = cpqary3_cmdlist_occupy(ctlr)))
		return (TRAN_BUSY);

	cpqary3_pktp->memp = memp;
	memp->pvt_pkt = cpqary3_pktp;

	if ((cpqary3_pktp->cmd_flags & DDI_DMA_CONSISTENT) &&
	    cpqary3_pktp->cmd_dmahandle) {
		(void) ddi_dma_sync(cpqary3_pktp->cmd_dmahandle, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
	}
	/* SG */
	ASSERT(cpqary3_pktp->cmd_cookiecnt <= ctlr->sg_cnt);
	/* SG */

	/* PERF */
	memp->complete = cpqary3_oscmd_complete;
	/* PERF */

	switch (cpqary3_build_cmdlist(memp, SA2TGT(sa))) {
	case CPQARY3_SUCCESS :
		if (scsi_pktp->pkt_flags & FLAG_NOINTR) {
			return (cpqary3_handle_flag_nointr(memp, scsi_pktp));
		}
		cpqary3_pktp->cmd_start_time = ddi_get_lbolt();
		mutex_enter(&ctlr->hw_mutex);
		/* CONTROLLER_LOCKUP */
		if (EIO == cpqary3_submit(ctlr, memp->cmdlist_phyaddr)) {
			mutex_exit(&ctlr->hw_mutex);
			cpqary3_cmdlist_release(memp, CPQARY3_HOLD_SW_MUTEX);
			return (TRAN_FATAL_ERROR);
		}
		/* CONTROLLER_LOCKUP */
		mutex_exit(&ctlr->hw_mutex);
		break;
	case CPQARY3_FAILURE :
		cpqary3_cmdlist_release(memp, CPQARY3_HOLD_SW_MUTEX);
		return (TRAN_FATAL_ERROR);
	default: /* Never occurs */
		cmn_err(CE_NOTE, "CPQary3 : Transport : Unexpected Error");
		return (TRAN_FATAL_ERROR);
	}

	return (TRAN_ACCEPT);
}

/*
 * Function	:	cpqary3_dmafree
 * Description	: 	This routine de-allocates previously allocated
 *			DMA resources.
 * Called By	: 	kernel
 * Parameters	: 	SCSI address, SCSI packet
 * Calls	: 	None
 * Return Values: 	None
 */
/* ARGSUSED */
static void
cpqary3_dmafree(struct scsi_address *sa, struct scsi_pkt *scsi_pktp)
{
	cpqary3_pkt_t	*cpqary3_pktp;

	cpqary3_pktp = PKT2PVTPKT(scsi_pktp);

	/*
	 * If any DMA was succesfully attempted earlier, free all allocated
	 * resources
	 */

	if (cpqary3_pktp->cmd_flags & CFLAG_DMAVALID) {
		if (!cpqary3_pktp->cmd_dmahandle) {
			DTRACE_PROBE(dmafree_null);
			return;
		}
		cpqary3_pktp->cmd_flags &= ~CFLAG_DMAVALID;
		(void) ddi_dma_unbind_handle(cpqary3_pktp->cmd_dmahandle);
		ddi_dma_free_handle(&cpqary3_pktp->cmd_dmahandle);
		cpqary3_pktp->cmd_dmahandle = NULL;
	}
}

/*
 * Function	:	cpqary3_dma_sync
 * Description	: 	This routine synchronizes the CPU's / HBA's view of
 *			the data associated with the pkt, typically by calling
 *			ddi_dma_sync().
 * Called By	: 	kernel
 * Parameters	: 	SCSI address, SCSI packet
 * Calls	: 	None
 * Return Values: 	None
 */
/* ARGSUSED */
static void
cpqary3_dma_sync(struct scsi_address *sa, struct scsi_pkt *scsi_pktp)
{
	cpqary3_pkt_t	*cpqary3_pktp = PKT2PVTPKT(scsi_pktp);

	/*
	 * Check whether DMA was attempted successfully earlier
	 * If yes and
	 * if the command flags is write, then synchronise the device else
	 * synchronise the CPU
	 */

	if (cpqary3_pktp->cmd_flags & CFLAG_DMAVALID) {
		(void) ddi_dma_sync(cpqary3_pktp->cmd_dmahandle,
		    cpqary3_pktp->cmd_dma_offset, cpqary3_pktp->cmd_dma_len,
		    (cpqary3_pktp->cmd_flags & CFLAG_DMASEND) ?
		    DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU);
	}
}

/*
 * Function	:	cpqary3_destroy_pkt
 * Description	: 	This routine de-allocates previously allocated
 *			resources for the SCSI packet.
 * Called By	: 	kernel
 * Parameters	: 	SCSI address, SCSI packet
 * Calls	: 	None
 * Return Values: 	None
 */
static void
cpqary3_destroy_pkt(struct scsi_address *sa, struct scsi_pkt *scsi_pktp)
{
	cpqary3_pkt_t	*cpqary3_pktp;

	cpqary3_pktp = PKT2PVTPKT(scsi_pktp);

	/*
	 * Deallocate DMA Resources, if allocated.
	 * Free the SCSI Packet.
	 */

	if (cpqary3_pktp->cmd_flags & CFLAG_DMAVALID) {
		if (!cpqary3_pktp->cmd_dmahandle) {
			DTRACE_PROBE(dmafree_null);
		} else {
			cpqary3_pktp->cmd_flags &= ~CFLAG_DMAVALID;

			(void) ddi_dma_unbind_handle(
			    cpqary3_pktp->cmd_dmahandle);
			ddi_dma_free_handle(&cpqary3_pktp->cmd_dmahandle);

			cpqary3_pktp->cmd_dmahandle = NULL;
		}
	}

	scsi_hba_pkt_free(sa, scsi_pktp);
}

/*
 * Function	:	cpqary3_reset
 * Description	: 	This routine resets a SCSI bus/target.
 * Called By	: 	kernel
 * Parameters	: 	SCSI address, reset level required
 * Calls	: 	None
 * Return Values: 	SUCCESS
 */
/* ARGSUSED */
static int
cpqary3_reset(struct scsi_address *sa, int level)
{
	/*
	 * Fix for Crash seen during RAID 0 Drive removal -
	 * just return CPQARY3_SUCCESS on reset request
	 */
	return (CPQARY3_SUCCESS);
}

/*
 * Function	:	cpqary3_abort()
 * Description	: 	This routine aborts a particular command or all commands
 *			directed towards a target.
 * Called By	: 	kernel
 * Parameters	: 	SCSI address, SCSI packet
 * Calls	: 	None
 * Return Values: 	SUCCESS / FAILURE
 *			[ abort of concernd command(s) was a success or
 *			a failure. ]
 */
static int
cpqary3_abort(struct scsi_address *sa, struct scsi_pkt *scsi_pktp)
{
	uint32_t	tid;
	cpqary3_t	*ctlr;

	ASSERT(sa != NULL);
	tid  = SA2TGT(sa);
	ctlr = SA2CTLR(sa);

	/*
	 * If SCSI packet exists, abort that particular command.
	 * Else, abort all existing commands to the target
	 * In either of the cases, we shall have to wait after the abort
	 * functions are called to return the status.
	 */

	if (!scsi_pktp) {
		return (cpqary3_send_abortcmd(ctlr, tid,
		    (CommandList_t *)NULL));
	} else {
		return (cpqary3_send_abortcmd(ctlr, tid, SP2CMD(scsi_pktp)));
	}
}

/*
 * Function	:	cpqary3_getcap
 * Description	: 	This routine is called to get the current value of a
 *			capability.(SCSI transport capability)
 * Called By	: 	kernel
 * Parameters	: 	SCSI address, capability identifier, target(s) affected
 * Calls	: 	None
 * Return Values: 	current value of capability / -1 (if unsupported)
 */
static int
cpqary3_getcap(struct scsi_address *sa, char *capstr, int tgtonly)
{
	int		index;
	cpqary3_t	*ctlr = SA2CTLR(sa);
	cpqary3_tgt_t	*tgtp = ctlr->cpqary3_tgtp[SA2TGT(sa)];

	/*
	 * If requested Capability is not supported, return -1.
	 */
	if (DDI_FAILURE == (index = scsi_hba_lookup_capstr(capstr)))
		return (CAP_NOT_DEFINED);

	/*
	 * Getting capability for a particulat target is supported
	 * the generic form of tran_getcap() is unsupported(for all targets)
	 * If directed towards a particular target, return current capability.
	 */
	if (tgtonly == 0) {	/* all targets */
		DTRACE_PROBE1(getcap_alltgt, int, index);
		return (CAP_NOT_DEFINED);
	}

	DTRACE_PROBE1(getcap_index, int, index);

	switch (index) {
	case SCSI_CAP_DMA_MAX:
		return ((int)cpqary3_dma_attr.dma_attr_maxxfer);
	case SCSI_CAP_DISCONNECT:
		return (tgtp->ctlr_flags & CPQARY3_CAP_DISCON_ENABLED);
	case SCSI_CAP_SYNCHRONOUS:
		return (tgtp->ctlr_flags & CPQARY3_CAP_SYNC_ENABLED);
	case SCSI_CAP_WIDE_XFER:
		return (tgtp->ctlr_flags & CPQARY3_CAP_WIDE_XFER_ENABLED);
	case SCSI_CAP_ARQ:
		return ((tgtp->ctlr_flags & CPQARY3_CAP_ARQ_ENABLED) ? 1 : 0);
	case SCSI_CAP_INITIATOR_ID:
		return (CTLR_SCSI_ID);
	case SCSI_CAP_UNTAGGED_QING:
		return (1);
	case SCSI_CAP_TAGGED_QING:
		return (1);
	case SCSI_CAP_SECTOR_SIZE:
		return (cpqary3_dma_attr.dma_attr_granular);
	case SCSI_CAP_TOTAL_SECTORS:
		return (CAP_NOT_DEFINED);
	case SCSI_CAP_GEOMETRY:
		return (cpqary3_target_geometry(sa));
	case SCSI_CAP_RESET_NOTIFICATION:
		return (0);
	default:
		return (CAP_NOT_DEFINED);
	}
}

/*
 * Function	:	cpqary3_setcap
 * Description	: 	This routine is called to set the current value of a
 *			capability.(SCSI transport capability)
 * Called By	: 	kernel
 * Parameters	: 	SCSI address, capability identifier,
 *			new capability value, target(s) affected
 * Calls	: 	None
 * Return Values: 	SUCCESS / FAILURE / -1 (if capability is unsupported)
 */
/* ARGSUSED */
static int
cpqary3_setcap(struct scsi_address *sa, char *capstr, int value, int tgtonly)
{
	int	index;
	int	retstatus = CAP_NOT_DEFINED;

	/*
	 * If requested Capability is not supported, return -1.
	 */
	if ((index = scsi_hba_lookup_capstr(capstr)) == DDI_FAILURE)
		return (retstatus);

	/*
	 * Setting capability for a particulat target is supported
	 * the generic form of tran_setcap() is unsupported(for all targets)
	 * If directed towards a particular target, set & return current
	 * capability.
	 */
	if (!tgtonly) {
		DTRACE_PROBE1(setcap_alltgt, int, index);
		return (retstatus);
	}

	DTRACE_PROBE1(setcap_index, int, index);

	switch (index) {
	case SCSI_CAP_DMA_MAX:
		return (CAP_CHG_NOT_ALLOWED);
	case SCSI_CAP_DISCONNECT:
		return (CAP_CHG_NOT_ALLOWED);
	case SCSI_CAP_SYNCHRONOUS:
		return (CAP_CHG_NOT_ALLOWED);
	case SCSI_CAP_WIDE_XFER:
		return (CAP_CHG_NOT_ALLOWED);
	case SCSI_CAP_ARQ:
		return (1);
	case SCSI_CAP_INITIATOR_ID:
		return (CAP_CHG_NOT_ALLOWED);
	case SCSI_CAP_UNTAGGED_QING:
		return (1);
	case SCSI_CAP_TAGGED_QING:
		return (1);
	case SCSI_CAP_SECTOR_SIZE:
		return (CAP_CHG_NOT_ALLOWED);
	case SCSI_CAP_TOTAL_SECTORS:
		return (CAP_CHG_NOT_ALLOWED);
	case SCSI_CAP_GEOMETRY:
		return (CAP_CHG_NOT_ALLOWED);
	case SCSI_CAP_RESET_NOTIFICATION:
		return (CAP_CHG_NOT_ALLOWED);
	default:
		return (CAP_NOT_DEFINED);
	}
}

/*
 * Function	:	cpqary3_handle_flag_nointr
 * Description	: 	This routine is called to handle submission and
 *			subsequently poll for the completion of a command,
 *			when its FLAG_NOINTR bit is set.
 * Called By	: 	cpqary3_transport()
 * Parameters	: 	command private structure, SCSI packet
 * Calls	: 	cpqary3_intr_onoff, cpqary3_retrieve,
 *			cpqary3_submit, cpqary3_poll
 * Return Values: 	TRAN_ACCEPT
 */
static int
cpqary3_handle_flag_nointr(cpqary3_cmdpvt_t *memp, struct scsi_pkt *scsi_pktp)
{
	uint32_t		tag;
	uint32_t		simple_tag;
	uint32_t		i;
	cpqary3_t		*ctlr;
	cpqary3_cmdpvt_t	*cpqary3_cmdpvtp;
	uint32_t		CmdsOutMax;
	uint32_t		no_cmds;

	RETURN_FAILURE_IF_NULL(memp);
	tag = memp->tag.tag_value;
	ctlr = memp->ctlr;
	ctlr->poll_flag = CPQARY3_FALSE;

	/*
	 * Before sumitting this command, ensure all commands pending
	 * with the controller are completed.
	 */

	cpqary3_intr_onoff(ctlr, CPQARY3_INTR_DISABLE);
	if (ctlr->host_support & 0x4)
		cpqary3_lockup_intr_onoff(ctlr, CPQARY3_LOCKUP_INTR_DISABLE);

	no_cmds = (uint32_t)((ctlr->ctlr_maxcmds / 3) * NO_OF_CMDLIST_IN_A_BLK);
	mutex_enter(&ctlr->sw_mutex);

	for (;;) {
		ctlr->poll_flag = CPQARY3_FALSE;
		for (i = 0; i < no_cmds; i++) {
			cpqary3_cmdpvtp = &ctlr->cmdmemlistp->pool[i];
			ASSERT(cpqary3_cmdpvtp != NULL);

			if ((tag != cpqary3_cmdpvtp->tag.tag_value) &&
			    (cpqary3_cmdpvtp->occupied == CPQARY3_OCCUPIED)) {
				if (ctlr->noe_support == 1) {
					if ((cpqary3_cmdpvtp->cmdlist_memaddr->
					    Header.Tag.drvinfo_n_err ==
					    CPQARY3_NOECMD_SUCCESS) ||
					    (cpqary3_cmdpvtp->cmdpvt_flag ==
					    CPQARY3_TIMEOUT))  {
						continue;
					}
				} else {
					if (cpqary3_cmdpvtp->cmdpvt_flag ==
					    CPQARY3_TIMEOUT)  {
						continue;
					}
				}
				ctlr->poll_flag = CPQARY3_TRUE;
			}
			/* NOE */

			if (ctlr->poll_flag == CPQARY3_TRUE) {
				break;
			}
		}

		if (ctlr->poll_flag == CPQARY3_TRUE) {
			if (!(ctlr->bddef->bd_flags & SA_BD_SAS)) {
				while ((simple_tag =
				    ddi_get32(ctlr->opq_handle,
				    (uint32_t *)ctlr->opq)) != 0xFFFFFFFF) {
					CmdsOutMax = ctlr->ctlr_maxcmds;
					if ((simple_tag >>
					    CPQARY3_GET_MEM_TAG) >=
					    ((CmdsOutMax / 3) * 3)) {
						cmn_err(CE_WARN,
						    "CPQary3 : HBA returned "
						    "Spurious Tag");
						return (CPQARY3_FAILURE);
					}

					cpqary3_cmdpvtp =
					    &ctlr->cmdmemlistp->pool[
					    simple_tag >> CPQARY3_GET_MEM_TAG];
					cpqary3_cmdpvtp->cmdlist_memaddr->
					    Header.Tag.drvinfo_n_err =
					    (simple_tag & 0xF) >> 1;
					cpqary3_cmdpvtp->complete(
					    cpqary3_cmdpvtp);
				}
			} else {
				mutex_exit(&ctlr->sw_mutex);
				if (CPQARY3_SUCCESS != cpqary3_retrieve(ctlr)) {
					drv_usecwait(1000);
				}
				mutex_enter(&ctlr->sw_mutex); /* Changes */
			}
		} else {
			break;
		}
	}

	mutex_enter(&ctlr->hw_mutex);
	if (EIO == cpqary3_submit(ctlr, memp->cmdlist_phyaddr)) {
		mutex_exit(&ctlr->hw_mutex);
		mutex_exit(&ctlr->sw_mutex);
		cpqary3_cmdlist_release(memp, CPQARY3_HOLD_SW_MUTEX);
		return (TRAN_FATAL_ERROR);
	}

	if (CPQARY3_FAILURE == cpqary3_poll(ctlr, tag)) {
		scsi_pktp->pkt_reason = CMD_TIMEOUT;
		scsi_pktp->pkt_statistics = STAT_TIMEOUT;
		scsi_pktp->pkt_state = 0;
		mutex_exit(&ctlr->hw_mutex);
		mutex_exit(&ctlr->sw_mutex);
		cpqary3_cmdlist_release(memp, CPQARY3_HOLD_SW_MUTEX);
		cpqary3_intr_onoff(ctlr, CPQARY3_INTR_ENABLE);
		if (ctlr->host_support & 0x4)
			cpqary3_lockup_intr_onoff(ctlr,
			    CPQARY3_LOCKUP_INTR_ENABLE);
		return (TRAN_ACCEPT);
	} else {
		mutex_exit(&ctlr->hw_mutex);
		mutex_exit(&ctlr->sw_mutex);
		cpqary3_intr_onoff(ctlr, CPQARY3_INTR_ENABLE);
		if (ctlr->host_support & 0x4) {
			cpqary3_lockup_intr_onoff(ctlr,
			    CPQARY3_LOCKUP_INTR_ENABLE);
		}
		return (TRAN_ACCEPT);
	}
}

/*
 * Function	:	cpqary3_poll
 * Description	: 	This routine polls for the completion of a command.
 * Called By	: 	cpqary3_handle_flag_nointr
 * Parameters	: 	per controller, tag of the command to be polled
 * Calls	: 	cpqary3_poll_retrieve
 * Return Values: 	TRAN_ACCEPT
 */
static int
cpqary3_poll(cpqary3_t *ctlr, uint32_t tag)
{
	uint32_t		ii = 0;

	RETURN_FAILURE_IF_NULL(ctlr);

	/*
	 * POLL for the completion of the said command
	 * Since, we had ensured that controller is empty, we need not
	 * check for the complete Retrieved Q.
	 * However, we just check the Retrieved Q and complete all
	 * commands in it, inclusive of the polled command.
	 * if the polled command is completed, send back a success.
	 */

	for (;;) {	/* this function is called with both the locks held */
		if (CPQARY3_SUCCESS != cpqary3_poll_retrieve(ctlr, tag)) {
			ii++;
			if (ii > 120000)
				return (CPQARY3_FAILURE);
			drv_usecwait(500);
			continue;
		}
		break;
	}

	return (CPQARY3_SUCCESS);
}

static int
cpqary3_additional_cmd(struct scsi_pkt *scsi_pktp, cpqary3_t *ctlr)
{
	struct scsi_arq_status *arqstat;
	/* LINTED: alignment */
	arqstat = (struct scsi_arq_status *)(scsi_pktp->pkt_scbp);

	switch (scsi_pktp->pkt_cdbp[0]) {
	case 0x35: /* Synchronize Cache */

		cpqary3_flush_cache(ctlr);

		scsi_pktp->pkt_reason = CMD_CMPLT;
		scsi_pktp->pkt_statistics = 0;
		scsi_pktp->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;

		if (scsi_pktp->pkt_comp) {
			(*scsi_pktp->pkt_comp)(scsi_pktp);
		}

		return (1);

	case 0x04: /* Format Unit */
		cmn_err(CE_NOTE, "The FORMAT UNIT is not supported by this "
		    "device If this option is selected from the format utility "
		    "do not continue further.  Please refer to cpqary3 driver "
		    "man pages for details.");

		return (0);
	case SCSI_LOG_SENSE:
	case SCSI_MODE_SELECT:
	case SCSI_PERSISTENT_RESERVE_IN:
		arqstat->sts_status.sts_chk = 1; /* CHECK CONDITION */
		arqstat->sts_rqpkt_reason = CMD_CMPLT;
		arqstat->sts_rqpkt_resid = 0;
		arqstat->sts_rqpkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA;
		arqstat->sts_rqpkt_statistics = 0;
		arqstat->sts_sensedata.es_valid = 1;
		arqstat->sts_sensedata.es_class = CLASS_EXTENDED_SENSE;
		arqstat->sts_sensedata.es_key = KEY_ILLEGAL_REQUEST;
		scsi_pktp->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA;

		if (scsi_pktp->pkt_comp) {
			(*scsi_pktp->pkt_comp)(scsi_pktp);
		}
		return (1);
	}

	return (0);
}

/* PERF */
/*
 * Function	:      	cpqary3_oscmd_complete
 * Description	:      	This routine processes the
 *			completed OS commands and
 *			initiates any callback that is needed.
 * Called By	:      	cpqary3_transport
 * Parameters	:      	per-command
 * Calls	:      	cpqary3_ioctl_send_bmiccmd,
 *			cpqary3_ioctl_send_scsicmd,
 *			cpqary3_send_abortcmd, cpqary3_flush_cache,
 *			cpqary3_probe4LVs,
 *			cpqary3_probe4Tapes, cpqary3_synccmd_complete,
 *			cpqary3_detect_target_geometry,
 *			cpqary3_detect_target_geometry
 * Return Values:      	None
 */
void
cpqary3_oscmd_complete(cpqary3_cmdpvt_t *cpqary3_cmdpvtp)
{
	cpqary3_t	*cpqary3p;
	ErrorInfo_t	*errorinfop;
	CommandList_t	*cmdlistp;
	struct scsi_pkt	*scsi_pktp;

	ASSERT(cpqary3_cmdpvtp != NULL);

	if (CPQARY3_TIMEOUT == cpqary3_cmdpvtp->cmdpvt_flag) {
		cpqary3_cmdlist_release(cpqary3_cmdpvtp,
		    CPQARY3_NO_MUTEX);
		return;
	}

	cpqary3p = cpqary3_cmdpvtp->ctlr;
	cmdlistp = cpqary3_cmdpvtp->cmdlist_memaddr;
	errorinfop = cpqary3_cmdpvtp->errorinfop;

	if (cmdlistp->Header.Tag.drvinfo_n_err == CPQARY3_OSCMD_SUCCESS) {
		scsi_pktp = cpqary3_cmdpvtp->pvt_pkt->scsi_cmd_pkt;
		scsi_pktp->pkt_reason = CMD_CMPLT;
		scsi_pktp->pkt_statistics = 0;
		scsi_pktp->pkt_state = STATE_GOT_BUS |
		    STATE_GOT_TARGET | STATE_SENT_CMD |
		    STATE_XFERRED_DATA | STATE_GOT_STATUS;

		if (cpqary3_cmdpvtp->pvt_pkt->scsi_cmd_pkt->pkt_flags &
		    FLAG_NOINTR) {
			cpqary3_cmdlist_release(cpqary3_cmdpvtp,
			    CPQARY3_NO_MUTEX);
		} else {
			cpqary3_cmdlist_release(cpqary3_cmdpvtp,
			    CPQARY3_NO_MUTEX);

			if (scsi_pktp->pkt_comp) {
				mutex_exit(&cpqary3p->sw_mutex);
				(*scsi_pktp->pkt_comp)(scsi_pktp);
				mutex_enter(&cpqary3p->sw_mutex);
			}
		}
		return;
	} else {
		scsi_pktp = cpqary3_cmdpvtp->pvt_pkt->scsi_cmd_pkt;
	}

	switch (errorinfop->CommandStatus) {
	case CISS_CMD_DATA_OVERRUN :
		scsi_pktp->pkt_reason = CMD_DATA_OVR;
		scsi_pktp->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;
		break;

	case CISS_CMD_INVALID :
		DTRACE_PROBE1(invalid_cmd, struct scsi_pkt *, scsi_pktp);
		scsi_pktp->pkt_reason = CMD_BADMSG;
		scsi_pktp->pkt_state = STATE_GOT_BUS |STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS;
		break;

	case CISS_CMD_PROTOCOL_ERR :
		scsi_pktp->pkt_reason = CMD_BADMSG;
		scsi_pktp->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS;
		break;

	case CISS_CMD_HARDWARE_ERR:
	case CISS_CMD_CONNECTION_LOST:
		scsi_pktp->pkt_reason = CMD_INCOMPLETE;
		scsi_pktp->pkt_state = 0;
		break;

	case CISS_CMD_ABORTED:
	case CISS_CMD_UNSOLICITED_ABORT:
		scsi_pktp->pkt_reason = CMD_ABORTED;
		scsi_pktp->pkt_statistics = STAT_ABORTED;
		scsi_pktp->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;
		break;

	case CISS_CMD_ABORT_FAILED:
		break;

	case CISS_CMD_TIMEOUT:
		scsi_pktp->pkt_reason = CMD_TIMEOUT;
		scsi_pktp->pkt_statistics = STAT_TIMEOUT;
		scsi_pktp->pkt_state = 0;
		break;

	case CISS_CMD_DATA_UNDERRUN:	/* Significant ONLY for Read & Write */
		if (cpqary3_is_scsi_read_write(scsi_pktp)) {
			scsi_pktp->pkt_reason = CMD_CMPLT;
			scsi_pktp->pkt_statistics = 0;
			scsi_pktp->pkt_state =
			    STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
			    STATE_XFERRED_DATA | STATE_GOT_STATUS;
			break;
		}
		/* FALLTHROUGH */
	case CISS_CMD_SUCCESS:
	case CISS_CMD_TARGET_STATUS:
		scsi_pktp->pkt_reason = CMD_CMPLT;
		scsi_pktp->pkt_statistics = 0;
		scsi_pktp->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;
		break;

	default:	/* Should never Occur !!! */
		scsi_pktp->pkt_reason = CMD_TRAN_ERR;
		break;
	}


	/*
	 * if ever a command completes with a CHECK CONDITION or a
	 * COMMAND_TERMINATED SCSI status, Update the sense data.
	 * NOTE : The CISS_CMD_INVALID command status would always result in a
	 * CHECK CONDITION and hence reach this part of the code.
	 */

	if ((errorinfop->ScsiStatus == SCSI_CHECK_CONDITION) ||
	    (errorinfop->ScsiStatus == SCSI_COMMAND_TERMINATED)) {
		if (errorinfop->SenseLen) {
			struct scsi_arq_status	*arq_statusp;
			arq_statusp =
			    /* LINTED: alignment */
			    (struct scsi_arq_status *)scsi_pktp->pkt_scbp;

			if ((errorinfop->ScsiStatus == SCSI_CHECK_CONDITION)) {
				arq_statusp->sts_status.sts_chk = (uint8_t)1;
			} else {
				arq_statusp->sts_status.sts_chk = (uint8_t)1;
				arq_statusp->sts_status.sts_scsi2 = (uint8_t)1;
			}
			bzero((void *)&(arq_statusp->sts_rqpkt_status),
			    sizeof (struct scsi_status));
			arq_statusp->sts_rqpkt_reason = CMD_CMPLT;
			arq_statusp->sts_rqpkt_resid = 0;
			arq_statusp->sts_rqpkt_state = scsi_pktp->pkt_state;
			arq_statusp->sts_rqpkt_statistics =
			    scsi_pktp->pkt_statistics;
			bcopy((caddr_t)&errorinfop->SenseInfo[0],
			    (caddr_t)(&arq_statusp->sts_sensedata),
			    CPQARY3_MIN(errorinfop->SenseLen,
			    cpqary3_cmdpvtp->pvt_pkt->scb_len));
			scsi_pktp->pkt_state |= STATE_ARQ_DONE;
		}
	}

	if (cpqary3_cmdpvtp->pvt_pkt->scsi_cmd_pkt->pkt_flags & FLAG_NOINTR) {
		cpqary3_cmdlist_release(cpqary3_cmdpvtp, CPQARY3_NO_MUTEX);
	} else {
		cpqary3_cmdlist_release(cpqary3_cmdpvtp, CPQARY3_NO_MUTEX);

		if (scsi_pktp->pkt_comp) {
			mutex_exit(&cpqary3p->sw_mutex);
			(*scsi_pktp->pkt_comp)(scsi_pktp);
			mutex_enter(&cpqary3p->sw_mutex);
		}
	}
}

static uint8_t
cpqary3_is_scsi_read_write(struct scsi_pkt *scsi_pktp)
{
	/*
	 * In the scsi packet structure, the first byte is the SCSI Command
	 * OpCode.  We check to see if it is any one of the SCSI Read or Write
	 * opcodes.
	 */

	switch (scsi_pktp->pkt_cdbp[0]) {
	case SCSI_READ_6:
	case SCSI_READ_10:
	case SCSI_READ_12:
	case SCSI_WRITE_6:
	case SCSI_WRITE_10:
	case SCSI_WRITE_12:
		return (1);

	default:
		return (0);
	}
}
