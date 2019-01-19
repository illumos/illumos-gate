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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * SCSI (SCSA) midlayer interface for PMC drier.
 */

#include <sys/scsi/adapters/pmcs/pmcs.h>

extern scsi_lun_t scsi_lun64_to_lun(scsi_lun64_t lun64);

static int pmcs_scsa_tran_tgt_init(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);
static void pmcs_scsa_tran_tgt_free(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);
static int pmcs_scsa_start(struct scsi_address *, struct scsi_pkt *);
static int pmcs_scsa_abort(struct scsi_address *, struct scsi_pkt *);
static int pmcs_scsa_reset(struct scsi_address *, int);
static int pmcs_scsi_reset_notify(struct scsi_address *, int,
    void (*)(caddr_t), caddr_t);
static int pmcs_scsa_getcap(struct scsi_address *, char *, int);
static int pmcs_scsa_setcap(struct scsi_address *, char *, int, int);
static int pmcs_scsa_setup_pkt(struct scsi_pkt *, int (*)(caddr_t), caddr_t);
static void pmcs_scsa_teardown_pkt(struct scsi_pkt *);

static int pmcs_smp_init(dev_info_t *, dev_info_t *, smp_hba_tran_t *,
    smp_device_t *);
static void pmcs_smp_free(dev_info_t *, dev_info_t *, smp_hba_tran_t *,
    smp_device_t *);
static int pmcs_smp_start(struct smp_pkt *);

static int pmcs_scsi_quiesce(dev_info_t *);
static int pmcs_scsi_unquiesce(dev_info_t *);

static int pmcs_cap(struct scsi_address *, char *, int, int, int);
static pmcs_xscsi_t *
    pmcs_addr2xp(struct scsi_address *, uint64_t *, pmcs_cmd_t *);
static int pmcs_SAS_run(pmcs_cmd_t *, pmcwork_t *);
static void pmcs_SAS_done(pmcs_hw_t *, pmcwork_t *, uint32_t *);

static int pmcs_SATA_run(pmcs_cmd_t *, pmcwork_t *);
static void pmcs_SATA_done(pmcs_hw_t *, pmcwork_t *, uint32_t *);
static uint8_t pmcs_SATA_rwparm(uint8_t *, uint32_t *, uint64_t *, uint64_t);

static void pmcs_ioerror(pmcs_hw_t *, pmcs_dtype_t pmcs_dtype,
    pmcwork_t *, uint32_t *, uint32_t);


int
pmcs_scsa_init(pmcs_hw_t *pwp, const ddi_dma_attr_t *ap)
{
	scsi_hba_tran_t *tran;
	ddi_dma_attr_t pmcs_scsa_dattr;
	int flags;

	(void) memcpy(&pmcs_scsa_dattr, ap, sizeof (ddi_dma_attr_t));
	pmcs_scsa_dattr.dma_attr_sgllen =
	    ((PMCS_SGL_NCHUNKS - 1) * (PMCS_MAX_CHUNKS - 1)) + PMCS_SGL_NCHUNKS;
	pmcs_scsa_dattr.dma_attr_flags = DDI_DMA_RELAXED_ORDERING;
	pmcs_scsa_dattr.dma_attr_flags |= DDI_DMA_FLAGERR;

	/*
	 * Allocate a transport structure
	 */
	tran = scsi_hba_tran_alloc(pwp->dip, SCSI_HBA_CANSLEEP);
	if (tran == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "scsi_hba_tran_alloc failed");
		return (DDI_FAILURE);
	}

	tran->tran_hba_private		= pwp;
	tran->tran_tgt_init		= pmcs_scsa_tran_tgt_init;
	tran->tran_tgt_free		= pmcs_scsa_tran_tgt_free;
	tran->tran_start		= pmcs_scsa_start;
	tran->tran_abort		= pmcs_scsa_abort;
	tran->tran_reset		= pmcs_scsa_reset;
	tran->tran_reset_notify		= pmcs_scsi_reset_notify;
	tran->tran_getcap		= pmcs_scsa_getcap;
	tran->tran_setcap		= pmcs_scsa_setcap;
	tran->tran_setup_pkt		= pmcs_scsa_setup_pkt;
	tran->tran_teardown_pkt		= pmcs_scsa_teardown_pkt;
	tran->tran_quiesce		= pmcs_scsi_quiesce;
	tran->tran_unquiesce		= pmcs_scsi_unquiesce;
	tran->tran_interconnect_type	= INTERCONNECT_SAS;
	tran->tran_hba_len		= sizeof (pmcs_cmd_t);

	/*
	 * Attach this instance of the hba
	 */

	flags = SCSI_HBA_TRAN_SCB | SCSI_HBA_TRAN_CDB | SCSI_HBA_ADDR_COMPLEX |
	    SCSI_HBA_TRAN_PHCI | SCSI_HBA_HBA;

	if (scsi_hba_attach_setup(pwp->dip, &pmcs_scsa_dattr, tran, flags)) {
		scsi_hba_tran_free(tran);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "scsi_hba_attach failed");
		return (DDI_FAILURE);
	}
	pwp->tran = tran;

	/*
	 * Attach the SMP part of this hba
	 */
	pwp->smp_tran = smp_hba_tran_alloc(pwp->dip);
	ASSERT(pwp->smp_tran != NULL);
	pwp->smp_tran->smp_tran_hba_private = pwp;
	pwp->smp_tran->smp_tran_init = pmcs_smp_init;
	pwp->smp_tran->smp_tran_free = pmcs_smp_free;
	pwp->smp_tran->smp_tran_start = pmcs_smp_start;

	if (smp_hba_attach_setup(pwp->dip, pwp->smp_tran) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "smp_hba_attach failed");
		smp_hba_tran_free(pwp->smp_tran);
		pwp->smp_tran = NULL;
		scsi_hba_tran_free(tran);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * SCSA entry points
 */

static int
pmcs_scsa_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	pmcs_hw_t	*pwp = NULL;
	int		rval;
	char		*variant_prop = "sata";
	char		*tgt_port = NULL, *ua = NULL;
	pmcs_xscsi_t	*tgt = NULL;
	pmcs_iport_t	*iport;
	pmcs_lun_t	*lun = NULL;
	pmcs_phy_t	*phyp = NULL;
	uint64_t	lun_num;
	boolean_t	got_scratch = B_FALSE;

	/*
	 * First, make sure we're an iport and get the pointer to the HBA
	 * node's softstate
	 */
	if (scsi_hba_iport_unit_address(hba_dip) == NULL) {
		pmcs_prt(TRAN2PMC(tran), PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: We don't enumerate devices on the HBA node", __func__);
		goto tgt_init_fail;
	}

	pwp = ITRAN2PMC(tran);
	iport = ITRAN2IPORT(tran);

	/*
	 * Get the unit-address
	 */
	ua = scsi_device_unit_address(sd);
	if (ua == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: Couldn't get UA", __func__);
		pwp = NULL;
		goto tgt_init_fail;
	}
	pmcs_prt(pwp, PMCS_PRT_DEBUG3, NULL, NULL,
	    "got ua '%s'", ua);

	/*
	 * Get the target address
	 */
	rval = scsi_device_prop_lookup_string(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_TARGET_PORT, &tgt_port);
	if (rval != DDI_PROP_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "Couldn't get target UA");
		pwp = NULL;
		goto tgt_init_fail;
	}
	pmcs_prt(pwp, PMCS_PRT_DEBUG3, NULL, NULL,
	    "got tgt_port '%s'", tgt_port);

	/*
	 * Validate that this tran_tgt_init is for an active iport.
	 */
	if (iport->ua_state == UA_INACTIVE) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: Got tran_tgt_init on inactive iport for '%s'",
		    __func__, tgt_port);
		pwp = NULL;
		goto tgt_init_fail;
	}

	/*
	 * Since we're going to wait for scratch, be sure to acquire it while
	 * we're not holding any other locks
	 */
	(void) pmcs_acquire_scratch(pwp, B_TRUE);
	got_scratch = B_TRUE;

	mutex_enter(&pwp->lock);

	/*
	 * See if there's already a target softstate.  If not, allocate one.
	 */
	tgt = pmcs_get_target(iport, tgt_port, B_TRUE);

	if (tgt == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "%s: "
		    "No tgt for tgt_port (%s)", __func__, tgt_port);
		goto tgt_init_fail;
	}

	phyp = tgt->phy;
	if (!IS_ROOT_PHY(phyp)) {
		pmcs_inc_phy_ref_count(phyp);
	}
	ASSERT(mutex_owned(&phyp->phy_lock));

	pmcs_prt(pwp, PMCS_PRT_DEBUG2, phyp, tgt, "@%s tgt = 0x%p, dip = 0x%p",
	    ua, (void *)tgt, (void *)tgt_dip);

	/* Now get the lun */
	lun_num = scsi_device_prop_get_int64(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_LUN64, SCSI_LUN64_ILLEGAL);
	if (lun_num == SCSI_LUN64_ILLEGAL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, tgt,
		    "No LUN for tgt %p", (void *)tgt);
		goto tgt_init_fail;
	}

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, tgt, "%s: @%s tgt 0x%p phy "
	    "0x%p (%s)", __func__, ua, (void *)tgt, (void *)phyp, phyp->path);

	mutex_enter(&tgt->statlock);
	tgt->dtype = phyp->dtype;
	if (tgt->dtype != SAS && tgt->dtype != SATA) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, tgt,
		    "PHY 0x%p went away?", (void *)phyp);
		goto tgt_init_fail;
	}

	/* We don't support SATA devices at LUN > 0. */
	if ((tgt->dtype == SATA) && (lun_num > 0)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, tgt,
		    "%s: No support for SATA devices at LUN > 0 "
		    "(target = 0x%p)", __func__, (void *)tgt);
		goto tgt_init_fail;
	}

	/*
	 * Allocate LU soft state. We use ddi_soft_state_bystr_zalloc instead
	 * of kmem_alloc because ddi_soft_state_bystr_zalloc allows us to
	 * verify that the framework never tries to initialize two scsi_device
	 * structures with the same unit-address at the same time.
	 */
	if (ddi_soft_state_bystr_zalloc(tgt->lun_sstate, ua) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG2, phyp, tgt,
		    "Couldn't allocate LU soft state");
		goto tgt_init_fail;
	}

	lun = ddi_soft_state_bystr_get(tgt->lun_sstate, ua);
	if (lun == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG2, phyp, tgt,
		    "Couldn't get LU soft state");
		goto tgt_init_fail;
	}
	scsi_device_hba_private_set(sd, lun);
	lun->lun_num = lun_num;

	/* convert the scsi_lun64_t value to SCSI standard form */
	lun->scsi_lun = scsi_lun64_to_lun(lun_num);

	ASSERT(strlen(ua) < (PMCS_MAX_UA_SIZE - 1));
	bcopy(ua, lun->unit_address, strnlen(ua, PMCS_MAX_UA_SIZE - 1));

	lun->target = tgt;

	/*
	 * If this is the first tran_tgt_init, add this target to our list
	 */
	if (tgt->target_num == PMCS_INVALID_TARGET_NUM) {
		int target;
		for (target = 0; target < pwp->max_dev; target++) {
			if (pwp->targets[target] != NULL) {
				continue;
			}

			pwp->targets[target] = tgt;
			tgt->target_num = (uint16_t)target;
			break;
		}

		if (target == pwp->max_dev) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, tgt,
			    "Target list full.");
			goto tgt_init_fail;
		}
	}

	tgt->dip = sd->sd_dev;
	lun->sd = sd;
	list_insert_tail(&tgt->lun_list, lun);

	if (!pmcs_assign_device(pwp, tgt)) {
		pmcs_release_scratch(pwp);
		pwp->targets[tgt->target_num] = NULL;
		tgt->target_num = PMCS_INVALID_TARGET_NUM;
		tgt->phy = NULL;
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, tgt,
		    "%s: pmcs_assign_device failed for target 0x%p",
		    __func__, (void *)tgt);
		goto tgt_init_fail;
	}

	pmcs_release_scratch(pwp);
	tgt->ref_count++;

	(void) scsi_device_prop_update_int(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_TARGET, (uint32_t)(tgt->target_num));

	/* SM-HBA */
	if (tgt->dtype == SATA) {
		/* TCR in PSARC/1997/281 opinion */
		(void) scsi_device_prop_update_string(sd,
		    SCSI_DEVICE_PROP_PATH, "variant", variant_prop);
	}

	tgt->phy_addressable = PMCS_PHY_ADDRESSABLE(phyp);

	if (tgt->phy_addressable) {
		(void) scsi_device_prop_update_int(sd, SCSI_DEVICE_PROP_PATH,
		    SCSI_ADDR_PROP_SATA_PHY, phyp->phynum);
	}

	/* SM-HBA */
	(void) pmcs_smhba_set_scsi_device_props(pwp, phyp, sd);
	/*
	 * Make sure attached port and target port pm props are updated
	 * By passing in 0s, we're not actually updating any values, but
	 * the properties should now get updated on the node.
	 */

	mutex_exit(&tgt->statlock);
	pmcs_update_phy_pm_props(phyp, 0, 0, B_TRUE);
	pmcs_unlock_phy(phyp);
	mutex_exit(&pwp->lock);
	scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, tgt_port);
	return (DDI_SUCCESS);

tgt_init_fail:
	scsi_device_hba_private_set(sd, NULL);
	if (got_scratch) {
		pmcs_release_scratch(pwp);
	}
	if (lun) {
		list_remove(&tgt->lun_list, lun);
		ddi_soft_state_bystr_free(tgt->lun_sstate, ua);
	}
	if (phyp) {
		mutex_exit(&tgt->statlock);
		pmcs_unlock_phy(phyp);
		/*
		 * phyp's ref count was incremented in pmcs_new_tport.
		 * We're failing configuration, we now need to decrement it.
		 */
		if (!IS_ROOT_PHY(phyp)) {
			pmcs_dec_phy_ref_count(phyp);
		}
		phyp->target = NULL;
	}
	if (tgt && tgt->ref_count == 0) {
		ddi_soft_state_bystr_free(iport->tgt_sstate, tgt_port);
	}
	if (pwp) {
		mutex_exit(&pwp->lock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, tgt,
		    "%s: failed for @%s tgt 0x%p phy 0x%p", __func__, ua,
		    (void *)tgt, (void *)phyp);
	}
	if (tgt_port) {
		scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, tgt_port);
	}
	return (DDI_FAILURE);
}

static void
pmcs_scsa_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	_NOTE(ARGUNUSED(hba_dip, tgt_dip));
	pmcs_hw_t	*pwp;
	pmcs_lun_t	*lun;
	pmcs_xscsi_t	*target;
	char		*unit_address;
	pmcs_phy_t	*phyp;

	if (scsi_hba_iport_unit_address(hba_dip) == NULL) {
		pwp = TRAN2PMC(tran);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: We don't enumerate devices on the HBA node", __func__);
		return;
	}

	lun = (pmcs_lun_t *)scsi_device_hba_private_get(sd);

	ASSERT((lun != NULL) && (lun->target != NULL));
	ASSERT(lun->target->ref_count > 0);

	target = lun->target;
	unit_address = lun->unit_address;
	list_remove(&target->lun_list, lun);

	pwp = ITRAN2PMC(tran);
	mutex_enter(&pwp->lock);
	phyp = target->phy;
	if (phyp) {
		mutex_enter(&phyp->phy_lock);
	}
	mutex_enter(&target->statlock);

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, target,
	    "%s: for @%s tgt 0x%p phy 0x%p", __func__, unit_address,
	    (void *)target, (void *)phyp);
	ddi_soft_state_bystr_free(lun->target->lun_sstate, unit_address);

	if (target->recover_wait) {
		mutex_exit(&target->statlock);
		if (phyp) {
			mutex_exit(&phyp->phy_lock);
		}
		mutex_exit(&pwp->lock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, target, "%s: "
		    "Target 0x%p in device state recovery, fail tran_tgt_free",
		    __func__, (void *)target);
		return;
	}

	/*
	 * If this target still has a PHY pointer and that PHY's target pointer
	 * has been cleared, then that PHY has been reaped. In that case, there
	 * would be no need to decrement the reference count
	 */
	if (phyp && !IS_ROOT_PHY(phyp) && phyp->target) {
		pmcs_dec_phy_ref_count(phyp);
	}

	if (--target->ref_count == 0) {
		/*
		 * Remove this target from our list.  The target soft
		 * state will remain, and the device will remain registered
		 * with the hardware unless/until we're told the device
		 * physically went away.
		 */
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, target,
		    "%s: Free target 0x%p (vtgt %d)", __func__, (void *)target,
		    target->target_num);
		pwp->targets[target->target_num] = NULL;
		target->target_num = PMCS_INVALID_TARGET_NUM;
		/* If the PHY has a pointer to this target, clear it */
		if (phyp && (phyp->target == target)) {
			phyp->target = NULL;
		}
		target->phy = NULL;
		if (phyp) {
			mutex_exit(&phyp->phy_lock);
		}
		pmcs_destroy_target(target);
	} else {
		mutex_exit(&target->statlock);
		if (phyp) {
			mutex_exit(&phyp->phy_lock);
		}
	}

	mutex_exit(&pwp->lock);
}

static int
pmcs_scsa_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	pmcs_cmd_t *sp = PKT2CMD(pkt);
	pmcs_hw_t *pwp = ADDR2PMC(ap);
	pmcs_xscsi_t *xp;
	boolean_t blocked;
	uint32_t hba_state;

	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL,
	    "%s: pkt %p sd %p cdb0=0x%02x dl=%lu", __func__, (void *)pkt,
	    (void *)scsi_address_device(&pkt->pkt_address),
	    pkt->pkt_cdbp[0] & 0xff, pkt->pkt_dma_len);

	if (pkt->pkt_flags & FLAG_NOINTR) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG3, NULL, NULL,
		    "%s: nointr pkt", __func__);
		return (TRAN_BADPKT);
	}

	sp->cmd_tag = 0;
	pkt->pkt_state = pkt->pkt_statistics = 0;
	pkt->pkt_reason = CMD_INCOMPLETE;

	mutex_enter(&pwp->lock);
	hba_state = pwp->state;
	blocked = pwp->blocked;
	mutex_exit(&pwp->lock);

	if (hba_state != STATE_RUNNING) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: hba dead", __func__);
		return (TRAN_FATAL_ERROR);
	}

	xp = pmcs_addr2xp(ap, NULL, sp);
	if (xp == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL,
		    "%s: dropping due to null target", __func__);
		goto dead_target;
	}
	ASSERT(mutex_owned(&xp->statlock));

	/*
	 * First, check to see if the device is gone.
	 */
	if (xp->dev_gone) {
		xp->actv_pkts++;
		mutex_exit(&xp->statlock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG3, NULL, xp,
		    "%s: dropping due to dead target 0x%p",
		    __func__, (void *)xp);
		goto dead_target;
	}

	/*
	 * If we're blocked (quiesced) just return.
	 */
	if (blocked) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: hba blocked", __func__);
		xp->actv_pkts++;
		mutex_exit(&xp->statlock);
		mutex_enter(&xp->wqlock);
		STAILQ_INSERT_TAIL(&xp->wq, sp, cmd_next);
		mutex_exit(&xp->wqlock);
		return (TRAN_ACCEPT);
	}

	/*
	 * If we're draining or resetting, queue and return.
	 */
	if (xp->draining || xp->resetting || xp->recover_wait) {
		xp->actv_pkts++;
		mutex_exit(&xp->statlock);
		mutex_enter(&xp->wqlock);
		STAILQ_INSERT_TAIL(&xp->wq, sp, cmd_next);
		mutex_exit(&xp->wqlock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG1, NULL, xp,
		    "%s: draining/resetting/recovering (cnt %u)",
		    __func__, xp->actv_cnt);
		/*
		 * By the time we get here, draining or
		 * resetting may have come and gone, not
		 * yet noticing that we had put something
		 * on the wait queue, so schedule a worker
		 * to look at this later.
		 */
		SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
		return (TRAN_ACCEPT);
	}

	xp->actv_pkts++;
	mutex_exit(&xp->statlock);

	/*
	 * Queue this command to the tail of the wait queue.
	 * This keeps us getting commands out of order.
	 */
	mutex_enter(&xp->wqlock);
	STAILQ_INSERT_TAIL(&xp->wq, sp, cmd_next);
	mutex_exit(&xp->wqlock);

	/*
	 * Now run the queue for this device.
	 */
	(void) pmcs_scsa_wq_run_one(pwp, xp);

	return (TRAN_ACCEPT);

dead_target:
	pkt->pkt_state = STATE_GOT_BUS;
	pkt->pkt_reason = CMD_DEV_GONE;
	mutex_enter(&pwp->cq_lock);
	STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
	PMCS_CQ_RUN_LOCKED(pwp);
	mutex_exit(&pwp->cq_lock);
	return (TRAN_ACCEPT);
}

/* Return code 1 = Success */
static int
pmcs_scsa_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	pmcs_hw_t *pwp = ADDR2PMC(ap);
	pmcs_cmd_t *sp = NULL;
	pmcs_xscsi_t *xp = NULL;
	pmcs_phy_t *pptr = NULL;
	pmcs_lun_t *pmcs_lun = (pmcs_lun_t *)
	    scsi_device_hba_private_get(scsi_address_device(ap));
	uint32_t tag;
	uint64_t lun;
	pmcwork_t *pwrk;

	mutex_enter(&pwp->lock);
	if (pwp->state != STATE_RUNNING) {
		mutex_exit(&pwp->lock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: hba dead", __func__);
		return (0);
	}
	mutex_exit(&pwp->lock);

	if (pkt == NULL) {
		if (pmcs_lun == NULL) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "%s: "
			    "No pmcs_lun_t struct to do ABORT_ALL", __func__);
			return (0);
		}
		xp = pmcs_lun->target;
		if (xp != NULL) {
			pptr = xp->phy;
		}
		if (pptr == NULL) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp, "%s: pkt is "
			    "NULL. No tgt/phy to do ABORT_ALL", __func__);
			return (0);
		}
		pmcs_lock_phy(pptr);
		if (pmcs_abort(pwp, pptr, 0, 1, 0)) {
			pptr->abort_pending = 1;
			SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
		}
		pmcs_unlock_phy(pptr);
		return (1);
	}

	sp = PKT2CMD(pkt);
	xp = sp->cmd_target;

	if (sp->cmd_lun) {
		lun = sp->cmd_lun->lun_num;
	} else {
		lun = 0;
	}
	if (xp == NULL) {
		return (0);
	}

	/*
	 * See if we have a real work structure associated with this cmd.
	 */
	pwrk = pmcs_tag2wp(pwp, sp->cmd_tag, B_FALSE);
	if (pwrk && pwrk->arg == sp) {
		tag = pwrk->htag;
		pptr = pwrk->phy;
		pwrk->timer = 0;	/* we don't time this here */
		ASSERT(pwrk->state == PMCS_WORK_STATE_ONCHIP);
		mutex_exit(&pwrk->lock);
		pmcs_lock_phy(pptr);
		if (pptr->dtype == SAS) {
			if (pmcs_ssp_tmf(pwp, pptr, SAS_ABORT_TASK, tag, lun,
			    NULL)) {
				pptr->abort_pending = 1;
				pmcs_unlock_phy(pptr);
				SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
				return (0);
			}
		} else {
			/*
			 * XXX: Was the command that was active an
			 * NCQ I/O command?
			 */
			pptr->need_rl_ext = 1;
			if (pmcs_sata_abort_ncq(pwp, pptr)) {
				pptr->abort_pending = 1;
				pmcs_unlock_phy(pptr);
				SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
				return (0);
			}
		}
		pptr->abort_pending = 1;
		pmcs_unlock_phy(pptr);
		SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
		return (1);
	}
	if (pwrk) {
		mutex_exit(&pwrk->lock);
	}
	/*
	 * Okay, those weren't the droids we were looking for.
	 * See if the command is on any of the wait queues.
	 */
	mutex_enter(&xp->wqlock);
	sp = NULL;
	STAILQ_FOREACH(sp, &xp->wq, cmd_next) {
		if (sp == PKT2CMD(pkt)) {
			STAILQ_REMOVE(&xp->wq, sp, pmcs_cmd, cmd_next);
			break;
		}
	}
	mutex_exit(&xp->wqlock);
	if (sp) {
		pkt->pkt_reason = CMD_ABORTED;
		pkt->pkt_statistics |= STAT_ABORTED;
		mutex_enter(&pwp->cq_lock);
		STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
		PMCS_CQ_RUN_LOCKED(pwp);
		mutex_exit(&pwp->cq_lock);
		return (1);
	}
	return (0);
}

/*
 * SCSA reset functions
 */
static int
pmcs_scsa_reset(struct scsi_address *ap, int level)
{
	pmcs_hw_t *pwp = ADDR2PMC(ap);
	pmcs_phy_t *pptr;
	pmcs_xscsi_t *xp;
	uint64_t lun = (uint64_t)-1, *lp = NULL;
	int rval;

	mutex_enter(&pwp->lock);
	if (pwp->state != STATE_RUNNING) {
		mutex_exit(&pwp->lock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: hba dead", __func__);
		return (0);
	}
	mutex_exit(&pwp->lock);

	switch (level)  {
	case RESET_ALL:
		rval = 0;
		break;
	case RESET_LUN:
		/*
		 * Point lp at lun so that pmcs_addr2xp
		 * will fill out the 64 bit lun number.
		 */
		lp = &lun;
		/* FALLTHROUGH */
	case RESET_TARGET:
		xp = pmcs_addr2xp(ap, lp, NULL);
		if (xp == NULL) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: no xp found for this scsi address", __func__);
			return (0);
		}

		if (xp->dev_gone) {
			mutex_exit(&xp->statlock);
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp,
			    "%s: Target 0x%p has gone away", __func__,
			    (void *)xp);
			return (0);
		}

		/*
		 * If we're already performing this action, or if device
		 * state recovery is already running, just return failure.
		 */
		if (xp->resetting || xp->recover_wait) {
			mutex_exit(&xp->statlock);
			return (0);
		}
		xp->reset_wait = 0;
		xp->reset_success = 0;
		xp->resetting = 1;
		pptr = xp->phy;
		mutex_exit(&xp->statlock);

		if (pmcs_reset_dev(pwp, pptr, lun)) {
			rval = 0;
		} else {
			rval = 1;
		}

		mutex_enter(&xp->statlock);
		if (rval == 1) {
			xp->reset_success = 1;
		}
		if (xp->reset_wait) {
			xp->reset_wait = 0;
			cv_signal(&xp->reset_cv);
		}
		xp->resetting = 0;
		mutex_exit(&xp->statlock);
		SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
		break;
	default:
		rval = 0;
		break;
	}

	return (rval);
}

static int
pmcs_scsi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg)
{
	pmcs_hw_t *pwp = ADDR2PMC(ap);
	return (scsi_hba_reset_notify_setup(ap, flag, callback, arg,
	    &pwp->lock, &pwp->reset_notify_listf));
}


static int
pmcs_cap(struct scsi_address *ap, char *cap, int val, int tonly, int set)
{
	_NOTE(ARGUNUSED(val, tonly));
	int cidx, rval = 0;
	pmcs_xscsi_t *xp;

	cidx = scsi_hba_lookup_capstr(cap);
	if (cidx == -1) {
		return (-1);
	}

	xp = pmcs_addr2xp(ap, NULL, NULL);
	if (xp == NULL) {
		return (-1);
	}

	switch (cidx) {
	case SCSI_CAP_DMA_MAX:
	case SCSI_CAP_INITIATOR_ID:
		if (set == 0) {
			rval = INT_MAX;	/* argh */
		}
		break;
	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_PARITY:
	case SCSI_CAP_ARQ:
	case SCSI_CAP_UNTAGGED_QING:
		if (set == 0) {
			rval = 1;
		}
		break;

	case SCSI_CAP_TAGGED_QING:
		rval = 1;
		break;

	case SCSI_CAP_MSG_OUT:
	case SCSI_CAP_RESET_NOTIFICATION:
	case SCSI_CAP_QFULL_RETRIES:
	case SCSI_CAP_QFULL_RETRY_INTERVAL:
		break;
	case SCSI_CAP_SCSI_VERSION:
		if (set == 0) {
			rval = SCSI_VERSION_3;
		}
		break;
	case SCSI_CAP_INTERCONNECT_TYPE:
		if (set) {
			break;
		}
		if (xp->phy_addressable) {
			rval = INTERCONNECT_SATA;
		} else {
			rval = INTERCONNECT_SAS;
		}
		break;
	case SCSI_CAP_CDB_LEN:
		if (set == 0) {
			rval = 16;
		}
		break;
	case SCSI_CAP_LUN_RESET:
		if (set) {
			break;
		}
		if (xp->dtype == SATA) {
			rval = 0;
		} else {
			rval = 1;
		}
		break;
	default:
		rval = -1;
		break;
	}
	mutex_exit(&xp->statlock);
	pmcs_prt(ADDR2PMC(ap), PMCS_PRT_DEBUG3, NULL, NULL,
	    "%s: cap %s val %d set %d rval %d",
	    __func__, cap, val, set, rval);
	return (rval);
}

/*
 * Returns with statlock held if the xp is found.
 * Fills in pmcs_cmd_t with values if pmcs_cmd_t pointer non-NULL.
 */
static pmcs_xscsi_t *
pmcs_addr2xp(struct scsi_address *ap, uint64_t *lp, pmcs_cmd_t *sp)
{
	pmcs_xscsi_t *xp;
	pmcs_lun_t *lun = (pmcs_lun_t *)
	    scsi_device_hba_private_get(scsi_address_device(ap));

	if ((lun == NULL) || (lun->target == NULL)) {
		return (NULL);
	}
	xp = lun->target;
	mutex_enter(&xp->statlock);

	if (xp->dev_gone || (xp->phy == NULL)) {
		/*
		 * This may be a retried packet, so it's possible cmd_target
		 * and cmd_lun may still be populated.  Clear them.
		 */
		if (sp != NULL) {
			sp->cmd_target = NULL;
			sp->cmd_lun = NULL;
		}
		mutex_exit(&xp->statlock);
		return (NULL);
	}

	if (sp != NULL) {
		sp->cmd_target = xp;
		sp->cmd_lun = lun;
	}
	if (lp) {
		*lp = lun->lun_num;
	}
	return (xp);
}

static int
pmcs_scsa_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int r;
	if (cap == NULL) {
		return (-1);
	}
	r = pmcs_cap(ap, cap, 0, whom, 0);
	return (r);
}

static int
pmcs_scsa_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	int r;
	if (cap == NULL) {
		return (-1);
	}
	r = pmcs_cap(ap, cap, value, whom, 1);
	return (r);
}

static int
pmcs_scsa_setup_pkt(struct scsi_pkt *pkt, int (*callback)(caddr_t),
    caddr_t cbarg)
{
	_NOTE(ARGUNUSED(callback, cbarg));
	pmcs_cmd_t *sp = pkt->pkt_ha_private;

	bzero(sp, sizeof (pmcs_cmd_t));
	sp->cmd_pkt = pkt;
	return (0);
}

static void
pmcs_scsa_teardown_pkt(struct scsi_pkt *pkt)
{
	pmcs_cmd_t *sp = pkt->pkt_ha_private;
	sp->cmd_target = NULL;
	sp->cmd_lun = NULL;
}

static int
pmcs_smp_start(struct smp_pkt *smp_pkt)
{
	struct pmcwork *pwrk;
	pmcs_iport_t *iport;
	const uint_t rdoff = SAS_SMP_MAX_PAYLOAD;
	uint32_t msg[PMCS_MSG_SIZE], *ptr, htag, status;
	uint64_t wwn;
	pmcs_hw_t *pwp;
	pmcs_phy_t *pptr;
	pmcs_xscsi_t *xp;
	uint_t reqsz, rspsz, will_retry;
	int result;

	pwp = smp_pkt->smp_pkt_address->smp_a_hba_tran->smp_tran_hba_private;
	bcopy(smp_pkt->smp_pkt_address->smp_a_wwn, &wwn, SAS_WWN_BYTE_SIZE);

	pmcs_prt(pwp, PMCS_PRT_DEBUG1, NULL, NULL,
	    "%s: starting for wwn 0x%" PRIx64, __func__, wwn);

	will_retry = smp_pkt->smp_pkt_will_retry;

	(void) pmcs_acquire_scratch(pwp, B_TRUE);
	reqsz = smp_pkt->smp_pkt_reqsize;
	if (reqsz > SAS_SMP_MAX_PAYLOAD) {
		reqsz = SAS_SMP_MAX_PAYLOAD;
	}
	(void) memcpy(pwp->scratch, smp_pkt->smp_pkt_req, reqsz);

	rspsz = smp_pkt->smp_pkt_rspsize;
	if (rspsz > SAS_SMP_MAX_PAYLOAD) {
		rspsz = SAS_SMP_MAX_PAYLOAD;
	}

	/*
	 * The request size from the SMP driver always includes 4 bytes
	 * for the CRC. The PMCS chip, however, doesn't want to see those
	 * counts as part of the transfer size.
	 */
	reqsz -= 4;

	pptr = pmcs_find_phy_by_wwn(pwp, wwn);
	/* PHY is now locked */
	if (pptr == NULL || pptr->dtype != EXPANDER) {
		if (pptr) {
			pmcs_unlock_phy(pptr);
		}
		pmcs_release_scratch(pwp);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: could not find phy", __func__);
		smp_pkt->smp_pkt_reason = ENXIO;
		return (DDI_FAILURE);
	}

	if ((pptr->iport == NULL) || !pptr->valid_device_id) {
		pmcs_unlock_phy(pptr);
		pmcs_release_scratch(pwp);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, pptr->target,
		    "%s: Can't reach PHY %s", __func__, pptr->path);
		smp_pkt->smp_pkt_reason = ENXIO;
		return (DDI_FAILURE);
	}

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, pptr);
	if (pwrk == NULL) {
		pmcs_unlock_phy(pptr);
		pmcs_release_scratch(pwp);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: could not get work structure", __func__);
		smp_pkt->smp_pkt_reason = will_retry ? EAGAIN : EBUSY;
		return (DDI_FAILURE);
	}

	pwrk->arg = msg;
	pwrk->dtype = EXPANDER;
	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		pmcs_pwork(pwp, pwrk);
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_unlock_phy(pptr);
		pmcs_release_scratch(pwp);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: could not get IQ entry", __func__);
		smp_pkt->smp_pkt_reason = will_retry ? EAGAIN :EBUSY;
		return (DDI_FAILURE);
	}
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL, PMCIN_SMP_REQUEST));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(pptr->device_id);
	msg[3] = LE_32(SMP_INDIRECT_RESPONSE | SMP_INDIRECT_REQUEST);
	msg[8] = LE_32(DWORD0(pwp->scratch_dma));
	msg[9] = LE_32(DWORD1(pwp->scratch_dma));
	msg[10] = LE_32(reqsz);
	msg[11] = 0;
	msg[12] = LE_32(DWORD0(pwp->scratch_dma+rdoff));
	msg[13] = LE_32(DWORD1(pwp->scratch_dma+rdoff));
	msg[14] = LE_32(rspsz);
	msg[15] = 0;

	COPY_MESSAGE(ptr, msg, PMCS_MSG_SIZE);

	pmcs_hold_iport(pptr->iport);
	iport = pptr->iport;
	pmcs_smp_acquire(iport);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	htag = pwrk->htag;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	pmcs_unlock_phy(pptr);
	WAIT_FOR(pwrk, smp_pkt->smp_pkt_timeout * 1000, result);
	pmcs_pwork(pwp, pwrk);
	pmcs_smp_release(iport);
	pmcs_rele_iport(iport);
	pmcs_lock_phy(pptr);
	if (result) {
		pmcs_timed_out(pwp, htag, __func__);
		if (pmcs_abort(pwp, pptr, htag, 0, 0)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, pptr->target,
			    "%s: Unable to issue SMP ABORT for htag 0x%08x",
			    __func__, htag);
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, pptr->target,
			    "%s: Issuing SMP ABORT for htag 0x%08x",
			    __func__, htag);
		}
		pmcs_unlock_phy(pptr);
		pmcs_release_scratch(pwp);
		smp_pkt->smp_pkt_reason = ETIMEDOUT;
		return (DDI_FAILURE);
	}
	status = LE_32(msg[2]);
	if (status == PMCOUT_STATUS_OVERFLOW) {
		status = PMCOUT_STATUS_OK;
		smp_pkt->smp_pkt_reason = EOVERFLOW;
	}
	if (status != PMCOUT_STATUS_OK) {
		const char *emsg = pmcs_status_str(status);
		if (emsg == NULL) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, pptr->target,
			    "SMP operation failed (0x%x)", status);
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, pptr->target,
			    "SMP operation failed (%s)", emsg);
		}

		if ((status == PMCOUT_STATUS_ERROR_HW_TIMEOUT) ||
		    (status == PMCOUT_STATUS_IO_XFER_OPEN_RETRY_TIMEOUT)) {
			smp_pkt->smp_pkt_reason =
			    will_retry ? EAGAIN : ETIMEDOUT;
			result = DDI_FAILURE;
		} else if (status ==
		    PMCOUT_STATUS_OPEN_CNX_ERROR_IT_NEXUS_LOSS) {
			xp = pptr->target;
			if (xp == NULL) {
				smp_pkt->smp_pkt_reason = EIO;
				result = DDI_FAILURE;
				goto out;
			}
			if (xp->dev_state !=
			    PMCS_DEVICE_STATE_NON_OPERATIONAL) {
				xp->dev_state =
				    PMCS_DEVICE_STATE_NON_OPERATIONAL;
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, xp->phy,
				    xp, "%s: Got _IT_NEXUS_LOSS SMP status. "
				    "Tgt(0x%p) dev_state set to "
				    "_NON_OPERATIONAL", __func__,
				    (void *)xp);
			}
			/* ABORT any pending commands related to this device */
			if (pmcs_abort(pwp, pptr, pptr->device_id, 1, 1) != 0) {
				pptr->abort_pending = 1;
				smp_pkt->smp_pkt_reason = EIO;
				result = DDI_FAILURE;
			}
		} else {
			smp_pkt->smp_pkt_reason = will_retry ? EAGAIN : EIO;
			result = DDI_FAILURE;
		}
	} else {
		(void) memcpy(smp_pkt->smp_pkt_rsp,
		    &((uint8_t *)pwp->scratch)[rdoff], rspsz);
		if (smp_pkt->smp_pkt_reason == EOVERFLOW) {
			result = DDI_FAILURE;
		} else {
			result = DDI_SUCCESS;
		}
	}
out:
	pmcs_prt(pwp, PMCS_PRT_DEBUG1, pptr, pptr->target,
	    "%s: done for wwn 0x%" PRIx64, __func__, wwn);

	pmcs_unlock_phy(pptr);
	pmcs_release_scratch(pwp);
	return (result);
}

static int
pmcs_smp_init(dev_info_t *self, dev_info_t *child,
    smp_hba_tran_t *tran, smp_device_t *smp_sd)
{
	_NOTE(ARGUNUSED(tran, smp_sd));
	pmcs_iport_t *iport;
	pmcs_hw_t *pwp;
	pmcs_xscsi_t *tgt;
	pmcs_phy_t *phy, *pphy;
	uint64_t wwn;
	char *addr, *tgt_port;
	int ua_form = 1;

	iport = ddi_get_soft_state(pmcs_iport_softstate,
	    ddi_get_instance(self));
	ASSERT(iport);
	if (iport == NULL)
		return (DDI_FAILURE);
	pwp = iport->pwp;
	ASSERT(pwp);
	if (pwp == NULL)
		return (DDI_FAILURE);

	/* Get "target-port" prop from devinfo node */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SCSI_ADDR_PROP_TARGET_PORT, &tgt_port) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "%s: Failed to "
		    "lookup prop ("SCSI_ADDR_PROP_TARGET_PORT")", __func__);
		/* Dont fail _smp_init() because we couldnt get/set a prop */
		return (DDI_SUCCESS);
	}

	/*
	 * Validate that this tran_tgt_init is for an active iport.
	 */
	if (iport->ua_state == UA_INACTIVE) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: Init on inactive iport for '%s'", __func__, tgt_port);
		ddi_prop_free(tgt_port);
		return (DDI_FAILURE);
	}

	mutex_enter(&pwp->lock);

	/* Retrieve softstate using unit-address */
	tgt = pmcs_get_target(iport, tgt_port, B_TRUE);
	if (tgt == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: tgt softstate not found", __func__);
		ddi_prop_free(tgt_port);
		mutex_exit(&pwp->lock);
		return (DDI_FAILURE);
	}

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, tgt, "%s: %s (%s)",
	    __func__, ddi_get_name(child), tgt_port);

	mutex_enter(&tgt->statlock);
	phy = tgt->phy;
	ASSERT(mutex_owned(&phy->phy_lock));

	if (IS_ROOT_PHY(phy)) {
		/* Expander attached to HBA - don't ref_count it */
		wwn = pwp->sas_wwns[0];
	} else {
		pmcs_inc_phy_ref_count(phy);

		/*
		 * Parent (in topology) is also an expander
		 * Now that we've increased the ref count on phy, it's OK
		 * to drop the lock so we can acquire the parent's lock.
		 */
		pphy = phy->parent;
		mutex_exit(&tgt->statlock);
		pmcs_unlock_phy(phy);
		pmcs_lock_phy(pphy);
		wwn = pmcs_barray2wwn(pphy->sas_address);
		pmcs_unlock_phy(pphy);
		pmcs_lock_phy(phy);
		mutex_enter(&tgt->statlock);
	}

	/*
	 * If this is the 1st smp_init, add this to our list.
	 */
	if (tgt->target_num == PMCS_INVALID_TARGET_NUM) {
		int target;
		for (target = 0; target < pwp->max_dev; target++) {
			if (pwp->targets[target] != NULL) {
				continue;
			}

			pwp->targets[target] = tgt;
			tgt->target_num = (uint16_t)target;
			tgt->assigned = 1;
			tgt->dev_state = PMCS_DEVICE_STATE_OPERATIONAL;
			break;
		}

		if (target == pwp->max_dev) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
			    "Target list full.");
			goto smp_init_fail;
		}
	}

	if (!pmcs_assign_device(pwp, tgt)) {
		pwp->targets[tgt->target_num] = NULL;
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, tgt,
		    "%s: pmcs_assign_device failed for target 0x%p",
		    __func__, (void *)tgt);
		goto smp_init_fail;
	}

	/*
	 * Update the attached port and target port pm properties
	 */
	tgt->smpd = smp_sd;

	pmcs_unlock_phy(phy);
	mutex_exit(&pwp->lock);

	tgt->ref_count++;
	tgt->dtype = phy->dtype;
	mutex_exit(&tgt->statlock);

	pmcs_update_phy_pm_props(phy, 0, 0, B_TRUE);

	addr = scsi_wwn_to_wwnstr(wwn, ua_form, NULL);
	if (smp_device_prop_update_string(smp_sd, SCSI_ADDR_PROP_ATTACHED_PORT,
	    addr) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "%s: Failed to set "
		    "prop ("SCSI_ADDR_PROP_ATTACHED_PORT")", __func__);
	}
	(void) scsi_free_wwnstr(addr);
	ddi_prop_free(tgt_port);
	return (DDI_SUCCESS);

smp_init_fail:
	tgt->phy = NULL;
	tgt->target_num = PMCS_INVALID_TARGET_NUM;
	phy->target = NULL;
	if (!IS_ROOT_PHY(phy)) {
		pmcs_dec_phy_ref_count(phy);
	}
	mutex_exit(&tgt->statlock);
	pmcs_unlock_phy(phy);
	mutex_exit(&pwp->lock);
	ddi_soft_state_bystr_free(iport->tgt_sstate, tgt->unit_address);
	ddi_prop_free(tgt_port);
	return (DDI_FAILURE);
}

static void
pmcs_smp_free(dev_info_t *self, dev_info_t *child,
    smp_hba_tran_t *tran, smp_device_t *smp)
{
	_NOTE(ARGUNUSED(tran, smp));
	pmcs_iport_t *iport;
	pmcs_hw_t *pwp;
	pmcs_xscsi_t *tgt;
	pmcs_phy_t *phyp;
	char *tgt_port;

	iport = ddi_get_soft_state(pmcs_iport_softstate,
	    ddi_get_instance(self));
	ASSERT(iport);
	if (iport == NULL)
		return;

	pwp = iport->pwp;
	if (pwp == NULL)
		return;
	ASSERT(pwp);

	/* Get "target-port" prop from devinfo node */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SCSI_ADDR_PROP_TARGET_PORT, &tgt_port) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "%s: Failed to "
		    "lookup prop ("SCSI_ADDR_PROP_TARGET_PORT")", __func__);
		return;
	}

	/* Retrieve softstate using unit-address */
	mutex_enter(&pwp->lock);
	tgt = ddi_soft_state_bystr_get(iport->tgt_sstate, tgt_port);
	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, tgt, "%s: %s (%s)", __func__,
	    ddi_get_name(child), tgt_port);
	ddi_prop_free(tgt_port);

	if (tgt == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: tgt softstate not found", __func__);
		mutex_exit(&pwp->lock);
		return;
	}

	phyp = tgt->phy;
	if (phyp) {
		mutex_enter(&phyp->phy_lock);
		if (!IS_ROOT_PHY(phyp)) {
			pmcs_dec_phy_ref_count(phyp);
		}
	}
	mutex_enter(&tgt->statlock);

	if (--tgt->ref_count == 0) {
		/*
		 * Remove this target from our list. The softstate
		 * will remain, and the device will remain registered
		 * with the hardware unless/until we're told that the
		 * device physically went away.
		 */
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, tgt,
		    "Removing target 0x%p (vtgt %d) from target list",
		    (void *)tgt, tgt->target_num);
		pwp->targets[tgt->target_num] = NULL;
		tgt->target_num = PMCS_INVALID_TARGET_NUM;
		/* If the PHY has a pointer to this target, clear it */
		if (phyp && (phyp->target == tgt)) {
			phyp->target = NULL;
		}
		tgt->phy = NULL;
		pmcs_destroy_target(tgt);
	} else {
		mutex_exit(&tgt->statlock);
	}

	if (phyp) {
		mutex_exit(&phyp->phy_lock);
	}
	mutex_exit(&pwp->lock);
}

static int
pmcs_scsi_quiesce(dev_info_t *dip)
{
	pmcs_hw_t *pwp;
	int totactive = -1;
	pmcs_xscsi_t *xp;
	uint16_t target;

	if (ddi_get_soft_state(pmcs_iport_softstate, ddi_get_instance(dip)))
		return (0);		/* iport */

	pwp  = ddi_get_soft_state(pmcs_softc_state, ddi_get_instance(dip));
	if (pwp == NULL) {
		return (-1);
	}
	mutex_enter(&pwp->lock);
	if (pwp->state != STATE_RUNNING) {
		mutex_exit(&pwp->lock);
		return (-1);
	}

	pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "%s called", __func__);
	pwp->quiesced = pwp->blocked = 1;
	while (totactive) {
		totactive = 0;
		for (target = 0; target < pwp->max_dev; target++) {
			xp = pwp->targets[target];
			if (xp == NULL) {
				continue;
			}
			mutex_enter(&xp->statlock);
			if (xp->actv_cnt) {
				totactive += xp->actv_cnt;
				xp->draining = 1;
			}
			mutex_exit(&xp->statlock);
		}
		if (totactive) {
			cv_wait(&pwp->drain_cv, &pwp->lock);
		}
		/*
		 * The pwp->blocked may have been reset. e.g a SCSI bus reset
		 */
		pwp->blocked = 1;
	}

	for (target = 0; target < pwp->max_dev; target++) {
		xp = pwp->targets[target];
		if (xp == NULL) {
			continue;
		}
		mutex_enter(&xp->statlock);
		xp->draining = 0;
		mutex_exit(&xp->statlock);
	}

	mutex_exit(&pwp->lock);
	if (totactive == 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp,
		    "%s drain complete", __func__);
	}
	return (0);
}

static int
pmcs_scsi_unquiesce(dev_info_t *dip)
{
	pmcs_hw_t *pwp;

	if (ddi_get_soft_state(pmcs_iport_softstate, ddi_get_instance(dip)))
		return (0);		/* iport */

	pwp  = ddi_get_soft_state(pmcs_softc_state, ddi_get_instance(dip));
	if (pwp == NULL) {
		return (-1);
	}
	mutex_enter(&pwp->lock);
	if (pwp->state != STATE_RUNNING) {
		mutex_exit(&pwp->lock);
		return (-1);
	}
	pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL, "%s called", __func__);
	pwp->blocked = pwp->quiesced = 0;
	mutex_exit(&pwp->lock);

	/*
	 * Run all pending commands.
	 */
	pmcs_scsa_wq_run(pwp);

	/*
	 * Complete all completed commands.
	 * This also unlocks us.
	 */
	PMCS_CQ_RUN(pwp);
	return (0);
}

/*
 * Start commands for a particular device
 * If the actual start of a command fails, return B_FALSE.  Any other result
 * is a B_TRUE return.
 */
boolean_t
pmcs_scsa_wq_run_one(pmcs_hw_t *pwp, pmcs_xscsi_t *xp)
{
	pmcs_cmd_t *sp;
	pmcs_phy_t *phyp;
	pmcwork_t *pwrk;
	boolean_t run_one, blocked;
	int rval;

	/*
	 * First, check to see if we're blocked or resource limited
	 */
	mutex_enter(&pwp->lock);
	blocked = pwp->blocked;
	/*
	 * If resource_limited is set, we're resource constrained and
	 * we will run only one work request for this target.
	 */
	run_one = pwp->resource_limited;
	mutex_exit(&pwp->lock);

	if (blocked) {
		/* Queues will get restarted when we get unblocked */
		return (B_TRUE);
	}

	/*
	 * Might as well verify the queue is not empty before moving on
	 */
	mutex_enter(&xp->wqlock);
	if (STAILQ_EMPTY(&xp->wq)) {
		mutex_exit(&xp->wqlock);
		return (B_TRUE);
	}
	mutex_exit(&xp->wqlock);

	/*
	 * If we're draining or resetting, just reschedule work queue and bail.
	 */
	mutex_enter(&xp->statlock);
	if (xp->draining || xp->resetting || xp->special_running ||
	    xp->special_needed) {
		mutex_exit(&xp->statlock);
		SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
		return (B_TRUE);
	}

	/*
	 * Next, check to see if the target is gone.
	 */
	if (xp->dev_gone) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp,
		    "%s: Flushing wait queue for dead tgt 0x%p", __func__,
		    (void *)xp);
		pmcs_flush_target_queues(pwp, xp, PMCS_TGT_WAIT_QUEUE);
		mutex_exit(&xp->statlock);
		return (B_TRUE);
	}

	/*
	 * Increment the PHY's ref_count now so we know it won't go away
	 * after we drop the target lock.  Drop it before returning.  If the
	 * PHY dies, the commands we attempt to send will fail, but at least
	 * we know we have a real PHY pointer.
	 */
	phyp = xp->phy;
	pmcs_inc_phy_ref_count(phyp);
	mutex_exit(&xp->statlock);

	mutex_enter(&xp->wqlock);
	while ((sp = STAILQ_FIRST(&xp->wq)) != NULL) {
		pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_CBACK, phyp);
		if (pwrk == NULL) {
			mutex_exit(&xp->wqlock);
			mutex_enter(&pwp->lock);
			if (pwp->resource_limited == 0) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
				    "%s: out of work structures", __func__);
			}
			pwp->resource_limited = 1;
			SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
			mutex_exit(&pwp->lock);
			return (B_FALSE);
		}
		STAILQ_REMOVE_HEAD(&xp->wq, cmd_next);
		mutex_exit(&xp->wqlock);

		pwrk->xp = xp;
		pwrk->arg = sp;
		pwrk->timer = 0;
		sp->cmd_tag = pwrk->htag;

		pwrk->dtype = xp->dtype;

		if (xp->dtype == SAS) {
			pwrk->ptr = (void *) pmcs_SAS_done;
			if ((rval = pmcs_SAS_run(sp, pwrk)) != 0) {
				if (rval != PMCS_WQ_RUN_FAIL_RES_CMP) {
					sp->cmd_tag = 0;
				}
				pmcs_dec_phy_ref_count(phyp);
				pmcs_pwork(pwp, pwrk);
				SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
				if (rval == PMCS_WQ_RUN_FAIL_RES) {
					return (B_FALSE);
				} else {
					return (B_TRUE);
				}
			}
		} else {
			ASSERT(xp->dtype == SATA);
			pwrk->ptr = (void *) pmcs_SATA_done;
			if ((rval = pmcs_SATA_run(sp, pwrk)) != 0) {
				sp->cmd_tag = 0;
				pmcs_dec_phy_ref_count(phyp);
				pmcs_pwork(pwp, pwrk);
				SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
				if (rval == PMCS_WQ_RUN_FAIL_RES) {
					return (B_FALSE);
				} else {
					return (B_TRUE);
				}
			}
		}

		if (run_one) {
			goto wq_out;
		}
		mutex_enter(&xp->wqlock);
	}

	mutex_exit(&xp->wqlock);

wq_out:
	pmcs_dec_phy_ref_count(phyp);
	return (B_TRUE);
}

/*
 * Start commands for all devices.
 */
void
pmcs_scsa_wq_run(pmcs_hw_t *pwp)
{
	pmcs_xscsi_t *xp;
	uint16_t target_start, target;
	boolean_t	rval = B_TRUE;

	mutex_enter(&pwp->lock);
	target_start = pwp->last_wq_dev;
	target = target_start;

	do {
		xp = pwp->targets[target];
		if ((xp == NULL) || (STAILQ_EMPTY(&xp->wq))) {
			if (++target == pwp->max_dev) {
				target = 0;
			}
			continue;
		}

		mutex_exit(&pwp->lock);
		rval = pmcs_scsa_wq_run_one(pwp, xp);
		mutex_enter(&pwp->lock);

		if (rval == B_FALSE) {
			break;
		}

		if (++target == pwp->max_dev) {
			target = 0;
		}
	} while (target != target_start);

	if (rval) {
		/*
		 * If we were resource limited, but apparently are not now,
		 * reschedule the work queues anyway.
		 */
		if (pwp->resource_limited) {
			SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
		}
		pwp->resource_limited = 0; /* Not resource-constrained */
	} else {
		/*
		 * Give everybody a chance, and reschedule to run the queues
		 * again as long as we're limited.
		 */
		pwp->resource_limited = 1;
		SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
	}

	pwp->last_wq_dev = target;
	mutex_exit(&pwp->lock);
}

/*
 * Pull the completion queue, drop the lock and complete all elements.
 */

void
pmcs_scsa_cq_run(void *arg)
{
	pmcs_cq_thr_info_t *cqti = (pmcs_cq_thr_info_t *)arg;
	pmcs_hw_t *pwp = cqti->cq_pwp;
	pmcs_cmd_t *sp, *nxt;
	struct scsi_pkt *pkt;
	pmcs_xscsi_t *tgt;
	pmcs_iocomp_cb_t *ioccb, *ioccb_next;
	pmcs_cb_t callback;

	DTRACE_PROBE1(pmcs__scsa__cq__run__start, pmcs_cq_thr_info_t *, cqti);

	mutex_enter(&pwp->cq_lock);

	while (!pwp->cq_info.cq_stop) {
		/*
		 * First, check the I/O completion callback queue.
		 */
		ioccb = pwp->iocomp_cb_head;
		pwp->iocomp_cb_head = NULL;
		pwp->iocomp_cb_tail = NULL;
		mutex_exit(&pwp->cq_lock);

		while (ioccb) {
			/*
			 * Grab the lock on the work structure. The callback
			 * routine is responsible for clearing it.
			 */
			mutex_enter(&ioccb->pwrk->lock);
			ioccb_next = ioccb->next;
			callback = (pmcs_cb_t)ioccb->pwrk->ptr;
			(*callback)(pwp, ioccb->pwrk,
			    (uint32_t *)((void *)ioccb->iomb));
			kmem_cache_free(pwp->iocomp_cb_cache, ioccb);
			ioccb = ioccb_next;
		}

		/*
		 * Next, run the completion queue
		 */
		mutex_enter(&pwp->cq_lock);
		sp = STAILQ_FIRST(&pwp->cq);
		STAILQ_INIT(&pwp->cq);
		mutex_exit(&pwp->cq_lock);

		DTRACE_PROBE1(pmcs__scsa__cq__run__start__loop,
		    pmcs_cq_thr_info_t *, cqti);

		if (sp && pmcs_check_acc_dma_handle(pwp)) {
			ddi_fm_service_impact(pwp->dip, DDI_SERVICE_UNAFFECTED);
		}

		while (sp) {
			nxt = STAILQ_NEXT(sp, cmd_next);
			pkt = CMD2PKT(sp);
			tgt = sp->cmd_target;
			pmcs_prt(pwp, PMCS_PRT_DEBUG3, NULL, tgt,
			    "%s: calling completion on %p for tgt %p", __func__,
			    (void *)sp, (void *)tgt);
			if (tgt) {
				mutex_enter(&tgt->statlock);
				ASSERT(tgt->actv_pkts != 0);
				tgt->actv_pkts--;
				mutex_exit(&tgt->statlock);
			}
			scsi_hba_pkt_comp(pkt);
			sp = nxt;
		}

		DTRACE_PROBE1(pmcs__scsa__cq__run__end__loop,
		    pmcs_cq_thr_info_t *, cqti);

		/*
		 * Check if there are more completions to do.  If so, and we've
		 * not been told to stop, skip the wait and cycle through again.
		 */
		mutex_enter(&pwp->cq_lock);
		if ((pwp->iocomp_cb_head == NULL) && STAILQ_EMPTY(&pwp->cq) &&
		    !pwp->cq_info.cq_stop) {
			mutex_exit(&pwp->cq_lock);
			mutex_enter(&cqti->cq_thr_lock);
			cv_wait(&cqti->cq_cv, &cqti->cq_thr_lock);
			mutex_exit(&cqti->cq_thr_lock);
			mutex_enter(&pwp->cq_lock);
		}
	}

	mutex_exit(&pwp->cq_lock);
	DTRACE_PROBE1(pmcs__scsa__cq__run__stop, pmcs_cq_thr_info_t *, cqti);
	thread_exit();
}

/*
 * Run a SAS command.  Called with pwrk->lock held, returns unlocked.
 */
static int
pmcs_SAS_run(pmcs_cmd_t *sp, pmcwork_t *pwrk)
{
	pmcs_hw_t *pwp = CMD2PMC(sp);
	struct scsi_pkt *pkt = CMD2PKT(sp);
	pmcs_xscsi_t *xp = pwrk->xp;
	uint32_t iq, lhtag, *ptr;
	sas_ssp_cmd_iu_t sc;
	int sp_pkt_time = 0;

	ASSERT(xp != NULL);
	mutex_enter(&xp->statlock);
	if (!xp->assigned) {
		mutex_exit(&xp->statlock);
		return (PMCS_WQ_RUN_FAIL_OTHER);
	}
	if ((xp->actv_cnt >= xp->qdepth) || xp->recover_wait) {
		mutex_exit(&xp->statlock);
		mutex_enter(&xp->wqlock);
		STAILQ_INSERT_HEAD(&xp->wq, sp, cmd_next);
		mutex_exit(&xp->wqlock);
		return (PMCS_WQ_RUN_FAIL_OTHER);
	}
	GET_IO_IQ_ENTRY(pwp, ptr, pwrk->phy->device_id, iq);
	if (ptr == NULL) {
		mutex_exit(&xp->statlock);
		/*
		 * This is a temporary failure not likely to unblocked by
		 * commands completing as the test for scheduling the
		 * restart of work is a per-device test.
		 */
		mutex_enter(&xp->wqlock);
		STAILQ_INSERT_HEAD(&xp->wq, sp, cmd_next);
		mutex_exit(&xp->wqlock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp,
		    "%s: Failed to get IO IQ entry for tgt %d",
		    __func__, xp->target_num);
		return (PMCS_WQ_RUN_FAIL_RES);

	}

	ptr[0] =
	    LE_32(PMCS_IOMB_IN_SAS(PMCS_OQ_IODONE, PMCIN_SSP_INI_IO_START));
	ptr[1] = LE_32(pwrk->htag);
	ptr[2] = LE_32(pwrk->phy->device_id);
	ptr[3] = LE_32(pkt->pkt_dma_len);
	if (ptr[3]) {
		ASSERT(pkt->pkt_numcookies);
		if (pkt->pkt_dma_flags & DDI_DMA_READ) {
			ptr[4] = LE_32(PMCIN_DATADIR_2_INI);
		} else {
			ptr[4] = LE_32(PMCIN_DATADIR_2_DEV);
		}
		if (pmcs_dma_load(pwp, sp, ptr)) {
			mutex_exit(&pwp->iqp_lock[iq]);
			mutex_exit(&xp->statlock);
			mutex_enter(&xp->wqlock);
			if (STAILQ_EMPTY(&xp->wq)) {
				STAILQ_INSERT_HEAD(&xp->wq, sp, cmd_next);
				mutex_exit(&xp->wqlock);
				return (PMCS_WQ_RUN_FAIL_RES);
			} else {
				mutex_exit(&xp->wqlock);
				CMD2PKT(sp)->pkt_scbp[0] = STATUS_QFULL;
				CMD2PKT(sp)->pkt_reason = CMD_CMPLT;
				CMD2PKT(sp)->pkt_state |= STATE_GOT_BUS |
				    STATE_GOT_TARGET | STATE_SENT_CMD |
				    STATE_GOT_STATUS;
				sp->cmd_tag = 0;
				mutex_enter(&pwp->cq_lock);
				STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
				PMCS_CQ_RUN_LOCKED(pwp);
				mutex_exit(&pwp->cq_lock);
				pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp,
				    "%s: Failed to dma_load for tgt %d (QF)",
				    __func__, xp->target_num);
				return (PMCS_WQ_RUN_FAIL_RES_CMP);
			}
		}
	} else {
		ptr[4] = LE_32(PMCIN_DATADIR_NONE);
		CLEAN_MESSAGE(ptr, 12);
	}
	xp->actv_cnt++;
	if (xp->actv_cnt > xp->maxdepth) {
		xp->maxdepth = xp->actv_cnt;
		pmcs_prt(pwp, PMCS_PRT_DEBUG2, pwrk->phy, xp, "%s: max depth "
		    "now %u", pwrk->phy->path, xp->maxdepth);
	}
	mutex_exit(&xp->statlock);


#ifdef	DEBUG
	/*
	 * Generate a PMCOUT_STATUS_XFER_CMD_FRAME_ISSUED
	 * event when this goes out on the wire.
	 */
	ptr[4] |= PMCIN_MESSAGE_REPORT;
#endif
	/*
	 * Fill in the SSP IU
	 */

	bzero(&sc, sizeof (sas_ssp_cmd_iu_t));
	bcopy((uint8_t *)&sp->cmd_lun->scsi_lun, sc.lun, sizeof (scsi_lun_t));

	switch (pkt->pkt_flags & FLAG_TAGMASK) {
	case FLAG_HTAG:
		sc.task_attribute = SAS_CMD_TASK_ATTR_HEAD;
		break;
	case FLAG_OTAG:
		sc.task_attribute = SAS_CMD_TASK_ATTR_ORDERED;
		break;
	case FLAG_STAG:
	default:
		sc.task_attribute = SAS_CMD_TASK_ATTR_SIMPLE;
		break;
	}
	(void) memcpy(sc.cdb, pkt->pkt_cdbp,
	    min(SCSA_CDBLEN(sp), sizeof (sc.cdb)));
	(void) memcpy(&ptr[5], &sc, sizeof (sas_ssp_cmd_iu_t));
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	lhtag = pwrk->htag;
	mutex_exit(&pwrk->lock);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL,
	    "%s: giving pkt %p (tag %x) to the hardware", __func__,
	    (void *)pkt, pwrk->htag);
#ifdef DEBUG
	pmcs_print_entry(pwp, PMCS_PRT_DEBUG3, "SAS INI Message", ptr);
#endif
	mutex_enter(&xp->aqlock);
	STAILQ_INSERT_TAIL(&xp->aq, sp, cmd_next);
	mutex_exit(&xp->aqlock);
	sp_pkt_time = CMD2PKT(sp)->pkt_time;
	INC_IQ_ENTRY(pwp, iq);
	mutex_enter(&pwrk->lock);
	if (lhtag == pwrk->htag) {
		pwrk->timer = US2WT(sp_pkt_time * 1000000);
		if (pwrk->timer == 0) {
			pwrk->timer = US2WT(1000000);
		}
	}
	mutex_exit(&pwrk->lock);

	/*
	 * If we just submitted the last command queued from device state
	 * recovery, clear the wq_recovery_tail pointer.
	 */
	mutex_enter(&xp->wqlock);
	if (xp->wq_recovery_tail == sp) {
		xp->wq_recovery_tail = NULL;
	}
	mutex_exit(&xp->wqlock);

	return (PMCS_WQ_RUN_SUCCESS);
}

/*
 * Complete a SAS command
 *
 * Called with pwrk lock held.
 * The free of pwrk releases the lock.
 */

static void
pmcs_SAS_done(pmcs_hw_t *pwp, pmcwork_t *pwrk, uint32_t *msg)
{
	pmcs_cmd_t *sp = pwrk->arg;
	pmcs_phy_t *pptr = pwrk->phy;
	pmcs_xscsi_t *xp = pwrk->xp;
	struct scsi_pkt *pkt = CMD2PKT(sp);
	int dead;
	uint32_t sts;
	boolean_t aborted = B_FALSE;
	boolean_t do_ds_recovery = B_FALSE;

	ASSERT(xp != NULL);
	ASSERT(sp != NULL);
	ASSERT(pptr != NULL);

	DTRACE_PROBE4(pmcs__io__done, uint64_t, pkt->pkt_dma_len, int,
	    (pkt->pkt_dma_flags & DDI_DMA_READ) != 0, hrtime_t, pwrk->start,
	    hrtime_t, gethrtime());

	dead = pwrk->dead;

	if (msg) {
		sts = LE_32(msg[2]);
	} else {
		sts = 0;
	}

	if (dead != 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp, "%s: dead cmd tag "
		    "0x%x for %s", __func__, pwrk->htag, pptr->path);
		goto out;
	}

	if (sts == PMCOUT_STATUS_ABORTED) {
		aborted = B_TRUE;
	}

	if (pwrk->state == PMCS_WORK_STATE_TIMED_OUT) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: cmd 0x%p (tag 0x%x) timed out for %s",
		    __func__, (void *)sp, pwrk->htag, pptr->path);
		CMD2PKT(sp)->pkt_scbp[0] = STATUS_GOOD;
		CMD2PKT(sp)->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD;
		CMD2PKT(sp)->pkt_statistics |= STAT_TIMEOUT;
		goto out;
	}

	/*
	 * If the status isn't okay but not underflow,
	 * step to the side and parse the (possible) error.
	 */
#ifdef DEBUG
	if (msg) {
		pmcs_print_entry(pwp, PMCS_PRT_DEBUG3, "Outbound Message", msg);
	}
#endif
	if (!msg) {
		goto out;
	}

	switch (sts) {
	case PMCOUT_STATUS_OPEN_CNX_ERROR_IT_NEXUS_LOSS:
	case PMCOUT_STATUS_IO_DS_NON_OPERATIONAL:
	case PMCOUT_STATUS_IO_DS_IN_RECOVERY:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: PHY %s requires DS recovery (status=%d)",
		    __func__, pptr->path, sts);
		do_ds_recovery = B_TRUE;
		break;
	case PMCOUT_STATUS_UNDERFLOW:
		(void) pmcs_set_resid(pkt, pkt->pkt_dma_len, LE_32(msg[3]));
		pmcs_prt(pwp, PMCS_PRT_DEBUG_UNDERFLOW, NULL, NULL,
		    "%s: underflow %u for cdb 0x%x",
		    __func__, LE_32(msg[3]), pkt->pkt_cdbp[0] & 0xff);
		sts = PMCOUT_STATUS_OK;
		msg[3] = 0;
		break;
	case PMCOUT_STATUS_OK:
		pkt->pkt_resid = 0;
		break;
	}

	if (sts != PMCOUT_STATUS_OK) {
		pmcs_ioerror(pwp, SAS, pwrk, msg, sts);
	} else {
		if (msg[3]) {
			uint8_t local[PMCS_QENTRY_SIZE << 1], *xd;
			sas_ssp_rsp_iu_t *rptr = (void *)local;
			const int lim =
			    (PMCS_QENTRY_SIZE << 1) - SAS_RSP_HDR_SIZE;
			static const uint8_t ssp_rsp_evec[] = {
				0x58, 0x61, 0x56, 0x72, 0x00
			};

			/*
			 * Transform the the first part of the response
			 * to host canonical form. This gives us enough
			 * information to figure out what to do with the
			 * rest (which remains unchanged in the incoming
			 * message which can be up to two queue entries
			 * in length).
			 */
			pmcs_endian_transform(pwp, local, &msg[5],
			    ssp_rsp_evec);
			xd = (uint8_t *)(&msg[5]);
			xd += SAS_RSP_HDR_SIZE;

			if (rptr->datapres == SAS_RSP_DATAPRES_RESPONSE_DATA) {
				if (rptr->response_data_length != 4) {
					pmcs_print_entry(pwp, PMCS_PRT_DEBUG,
					    "Bad SAS RESPONSE DATA LENGTH",
					    msg);
					pkt->pkt_reason = CMD_TRAN_ERR;
					goto out;
				}
				(void) memcpy(&sts, xd, sizeof (uint32_t));
				sts = BE_32(sts);
				/*
				 * The only response code we should legally get
				 * here is an INVALID FRAME response code.
				 */
				if (sts == SAS_RSP_INVALID_FRAME) {
					pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
					    "%s: pkt %p tgt %u path %s "
					    "completed: INVALID FRAME response",
					    __func__, (void *)pkt,
					    xp->target_num, pptr->path);
				} else {
					pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
					    "%s: pkt %p tgt %u path %s "
					    "completed: illegal response 0x%x",
					    __func__, (void *)pkt,
					    xp->target_num, pptr->path, sts);
				}
				pkt->pkt_reason = CMD_TRAN_ERR;
				goto out;
			}
			if (rptr->datapres == SAS_RSP_DATAPRES_SENSE_DATA) {
				uint32_t slen;
				slen = rptr->sense_data_length;
				if (slen > lim) {
					slen = lim;
				}
				pmcs_latch_status(pwp, sp, rptr->status, xd,
				    slen, pptr->path);
			} else if (rptr->datapres == SAS_RSP_DATAPRES_NO_DATA) {
				pmcout_ssp_comp_t *sspcp;
				sspcp = (pmcout_ssp_comp_t *)msg;
				uint32_t *residp;
				/*
				 * This is the case for a plain SCSI status.
				 * Note: If RESC_V is set and we're here, there
				 * is a residual.  We need to find it and update
				 * the packet accordingly.
				 */
				pmcs_latch_status(pwp, sp, rptr->status, NULL,
				    0, pptr->path);

				if (sspcp->resc_v) {
					/*
					 * Point residual to the SSP_RESP_IU
					 */
					residp = (uint32_t *)(sspcp + 1);
					/*
					 * param contains the number of bytes
					 * between where the SSP_RESP_IU may
					 * or may not be and the residual.
					 * Increment residp by the appropriate
					 * number of words: (param+resc_pad)/4).
					 */
					residp += (LE_32(sspcp->param) +
					    sspcp->resc_pad) /
					    sizeof (uint32_t);
					pmcs_prt(pwp, PMCS_PRT_DEBUG_UNDERFLOW,
					    pptr, xp, "%s: tgt 0x%p "
					    "residual %d for pkt 0x%p",
					    __func__, (void *) xp, *residp,
					    (void *) pkt);
					ASSERT(LE_32(*residp) <=
					    pkt->pkt_dma_len);
					(void) pmcs_set_resid(pkt,
					    pkt->pkt_dma_len, LE_32(*residp));
				}
			} else {
				pmcs_print_entry(pwp, PMCS_PRT_DEBUG,
				    "illegal SAS response", msg);
				pkt->pkt_reason = CMD_TRAN_ERR;
				goto out;
			}
		} else {
			pmcs_latch_status(pwp, sp, STATUS_GOOD, NULL, 0,
			    pptr->path);
		}
		if (pkt->pkt_dma_len) {
			pkt->pkt_state |= STATE_XFERRED_DATA;
		}
	}
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, xp,
	    "%s: pkt %p tgt %u done reason=%x state=%x resid=%ld status=%x",
	    __func__, (void *)pkt, xp->target_num, pkt->pkt_reason,
	    pkt->pkt_state, pkt->pkt_resid, pkt->pkt_scbp[0]);

	if (pwrk->state == PMCS_WORK_STATE_ABORTED) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: scsi_pkt 0x%p aborted for PHY %s; work = 0x%p",
		    __func__, (void *)pkt, pptr->path, (void *)pwrk);
		aborted = B_TRUE;
	}

out:
	pmcs_dma_unload(pwp, sp);
	mutex_enter(&xp->statlock);

	/*
	 * If the device no longer has a PHY pointer, clear the PHY pointer
	 * from the work structure before we free it.  Otherwise, pmcs_pwork
	 * may decrement the ref_count on a PHY that's been freed.
	 */
	if (xp->phy == NULL) {
		pwrk->phy = NULL;
	}

	/*
	 * We may arrive here due to a command timing out, which in turn
	 * could be addressed in a different context.  So, free the work
	 * back, but only after confirming it's not already been freed
	 * elsewhere.
	 */
	if (pwrk->htag != PMCS_TAG_FREE) {
		pmcs_pwork(pwp, pwrk);
	}

	/*
	 * If the device is gone, we only put this command on the completion
	 * queue if the work structure is not marked dead.  If it's marked
	 * dead, it will already have been put there.
	 */
	if (xp->dev_gone) {
		mutex_exit(&xp->statlock);
		if (!dead) {
			mutex_enter(&xp->aqlock);
			STAILQ_REMOVE(&xp->aq, sp, pmcs_cmd, cmd_next);
			mutex_exit(&xp->aqlock);
			pmcs_prt(pwp, PMCS_PRT_DEBUG3, pptr, xp,
			    "%s: Removing cmd 0x%p (htag 0x%x) from aq",
			    __func__, (void *)sp, sp->cmd_tag);
			mutex_enter(&pwp->cq_lock);
			STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
			PMCS_CQ_RUN_LOCKED(pwp);
			mutex_exit(&pwp->cq_lock);
			pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, xp,
			    "%s: Completing command for dead target 0x%p",
			    __func__, (void *)xp);
		}
		return;
	}

	ASSERT(xp->actv_cnt > 0);
	if (--(xp->actv_cnt) == 0) {
		if (xp->draining) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG1, pptr, xp,
			    "%s: waking up drain waiters", __func__);
			cv_signal(&pwp->drain_cv);
		}
	}
	mutex_exit(&xp->statlock);

	/*
	 * If the status is other than OK, determine if it's something that
	 * is worth re-attempting enumeration.  If so, mark the PHY.
	 */
	if (sts != PMCOUT_STATUS_OK) {
		pmcs_status_disposition(pptr, sts);
	}

	if (dead == 0) {
#ifdef	DEBUG
		pmcs_cmd_t *wp;
		mutex_enter(&xp->aqlock);
		STAILQ_FOREACH(wp, &xp->aq, cmd_next) {
			if (wp == sp) {
				break;
			}
		}
		ASSERT(wp != NULL);
#else
		mutex_enter(&xp->aqlock);
#endif
		pmcs_prt(pwp, PMCS_PRT_DEBUG3, pptr, xp,
		    "%s: Removing cmd 0x%p (htag 0x%x) from aq", __func__,
		    (void *)sp, sp->cmd_tag);
		STAILQ_REMOVE(&xp->aq, sp, pmcs_cmd, cmd_next);
		if (aborted) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
			    "%s: Aborted cmd for tgt 0x%p, signaling waiters",
			    __func__, (void *)xp);
			cv_signal(&xp->abort_cv);
		}
		mutex_exit(&xp->aqlock);
	}

	/*
	 * If do_ds_recovery is set, we need to initiate device state
	 * recovery.  In this case, we put this I/O back on the head of
	 * the wait queue to run again after recovery is complete
	 */
	if (do_ds_recovery) {
		mutex_enter(&xp->statlock);
		pmcs_start_dev_state_recovery(xp, pptr);
		mutex_exit(&xp->statlock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG1, pptr, xp, "%s: Putting cmd 0x%p "
		    "back on wq during recovery for tgt 0x%p", __func__,
		    (void *)sp, (void *)xp);
		mutex_enter(&xp->wqlock);
		if (xp->wq_recovery_tail == NULL) {
			STAILQ_INSERT_HEAD(&xp->wq, sp, cmd_next);
		} else {
			/*
			 * If there are other I/Os waiting at the head due to
			 * device state recovery, add this one in the right spot
			 * to maintain proper order.
			 */
			STAILQ_INSERT_AFTER(&xp->wq, xp->wq_recovery_tail, sp,
			    cmd_next);
		}
		xp->wq_recovery_tail = sp;
		mutex_exit(&xp->wqlock);
	} else {
		/*
		 * If we're not initiating device state recovery and this
		 * command was not "dead", put it on the completion queue
		 */
		if (!dead) {
			mutex_enter(&pwp->cq_lock);
			STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
			PMCS_CQ_RUN_LOCKED(pwp);
			mutex_exit(&pwp->cq_lock);
		}
	}
}

/*
 * Run a SATA command (normal reads and writes),
 * or block and schedule a SATL interpretation
 * of the command.
 *
 * Called with pwrk lock held, returns unlocked.
 */

static int
pmcs_SATA_run(pmcs_cmd_t *sp, pmcwork_t *pwrk)
{
	pmcs_hw_t *pwp = CMD2PMC(sp);
	struct scsi_pkt *pkt = CMD2PKT(sp);
	pmcs_xscsi_t *xp;
	uint8_t cdb_base, asc, tag;
	uint32_t *ptr, lhtag, iq, nblk, i, mtype;
	fis_t fis;
	size_t amt;
	uint64_t lba;
	int sp_pkt_time = 0;

	xp = pwrk->xp;
	ASSERT(xp != NULL);

	/*
	 * First, see if this is just a plain read/write command.
	 * If not, we have to queue it up for processing, block
	 * any additional commands from coming in, and wake up
	 * the thread that will process this command.
	 */
	cdb_base = pkt->pkt_cdbp[0] & 0x1f;
	if (cdb_base != SCMD_READ && cdb_base != SCMD_WRITE) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG1, NULL, NULL,
		    "%s: special SATA cmd %p", __func__, (void *)sp);

		ASSERT(xp->phy != NULL);
		pmcs_pwork(pwp, pwrk);
		pmcs_lock_phy(xp->phy);
		mutex_enter(&xp->statlock);
		xp->special_needed = 1; /* Set the special_needed flag */
		STAILQ_INSERT_TAIL(&xp->sq, sp, cmd_next);
		if (pmcs_run_sata_special(pwp, xp)) {
			SCHEDULE_WORK(pwp, PMCS_WORK_SATA_RUN);
		}
		mutex_exit(&xp->statlock);
		pmcs_unlock_phy(xp->phy);

		return (PMCS_WQ_RUN_SUCCESS);
	}

	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL, "%s: regular cmd", __func__);

	mutex_enter(&xp->statlock);
	if (!xp->assigned) {
		mutex_exit(&xp->statlock);
		return (PMCS_WQ_RUN_FAIL_OTHER);
	}
	if (xp->special_running || xp->special_needed || xp->recover_wait) {
		mutex_exit(&xp->statlock);
		mutex_enter(&xp->wqlock);
		STAILQ_INSERT_HEAD(&xp->wq, sp, cmd_next);
		mutex_exit(&xp->wqlock);
		/*
		 * By the time we get here the special
		 * commands running or waiting to be run
		 * may have come and gone, so kick our
		 * worker to run the waiting queues
		 * just in case.
		 */
		SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
		return (PMCS_WQ_RUN_FAIL_OTHER);
	}
	lba = xp->capacity;
	mutex_exit(&xp->statlock);

	/*
	 * Extract data length and lba parameters out of the command. The
	 * function pmcs_SATA_rwparm returns a non-zero ASC value if the CDB
	 * values are considered illegal.
	 */
	asc = pmcs_SATA_rwparm(pkt->pkt_cdbp, &nblk, &lba, lba);
	if (asc) {
		uint8_t sns[18];
		bzero(sns, sizeof (sns));
		sns[0] = 0xf0;
		sns[2] = 0x5;
		sns[12] = asc;
		pmcs_latch_status(pwp, sp, STATUS_CHECK, sns, sizeof (sns),
		    pwrk->phy->path);
		pmcs_pwork(pwp, pwrk);
		mutex_enter(&pwp->cq_lock);
		STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
		PMCS_CQ_RUN_LOCKED(pwp);
		mutex_exit(&pwp->cq_lock);
		return (PMCS_WQ_RUN_SUCCESS);
	}

	/*
	 * If the command decodes as not moving any data, complete it here.
	 */
	amt = nblk;
	amt <<= 9;
	amt = pmcs_set_resid(pkt, amt, nblk << 9);
	if (amt == 0) {
		pmcs_latch_status(pwp, sp, STATUS_GOOD, NULL, 0,
		    pwrk->phy->path);
		pmcs_pwork(pwp, pwrk);
		mutex_enter(&pwp->cq_lock);
		STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
		PMCS_CQ_RUN_LOCKED(pwp);
		mutex_exit(&pwp->cq_lock);
		return (PMCS_WQ_RUN_SUCCESS);
	}

	/*
	 * Get an inbound queue entry for this I/O
	 */
	GET_IO_IQ_ENTRY(pwp, ptr, xp->phy->device_id, iq);
	if (ptr == NULL) {
		/*
		 * This is a temporary failure not likely to unblocked by
		 * commands completing as the test for scheduling the
		 * restart of work is a per-device test.
		 */
		mutex_enter(&xp->wqlock);
		STAILQ_INSERT_HEAD(&xp->wq, sp, cmd_next);
		mutex_exit(&xp->wqlock);
		pmcs_dma_unload(pwp, sp);
		SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp,
		    "%s: Failed to get IO IQ entry for tgt %d",
		    __func__, xp->target_num);
		return (PMCS_WQ_RUN_FAIL_RES);
	}

	/*
	 * Get a tag.  At this point, hold statlock until the tagmap is
	 * updated (just prior to sending the cmd to the hardware).
	 */
	mutex_enter(&xp->statlock);
	for (tag = 0; tag < xp->qdepth; tag++) {
		if ((xp->tagmap & (1 << tag)) == 0) {
			break;
		}
	}

	if (tag == xp->qdepth) {
		mutex_exit(&xp->statlock);
		mutex_exit(&pwp->iqp_lock[iq]);
		mutex_enter(&xp->wqlock);
		STAILQ_INSERT_HEAD(&xp->wq, sp, cmd_next);
		mutex_exit(&xp->wqlock);
		return (PMCS_WQ_RUN_FAIL_OTHER);
	}

	sp->cmd_satltag = (uint8_t)tag;

	/*
	 * Set up the command
	 */
	bzero(fis, sizeof (fis));
	ptr[0] =
	    LE_32(PMCS_IOMB_IN_SAS(PMCS_OQ_IODONE, PMCIN_SATA_HOST_IO_START));
	ptr[1] = LE_32(pwrk->htag);
	ptr[2] = LE_32(pwrk->phy->device_id);
	ptr[3] = LE_32(amt);

	if (xp->ncq) {
		mtype = SATA_PROTOCOL_FPDMA | (tag << 16);
		fis[0] = ((nblk & 0xff) << 24) | (C_BIT << 8) | FIS_REG_H2DEV;
		if (cdb_base == SCMD_READ) {
			fis[0] |= (READ_FPDMA_QUEUED << 16);
		} else {
			fis[0] |= (WRITE_FPDMA_QUEUED << 16);
		}
		fis[1] = (FEATURE_LBA << 24) | (lba & 0xffffff);
		fis[2] = ((nblk & 0xff00) << 16) | ((lba >> 24) & 0xffffff);
		fis[3] = tag << 3;
	} else {
		int op;
		fis[0] = (C_BIT << 8) | FIS_REG_H2DEV;
		if (xp->pio) {
			mtype = SATA_PROTOCOL_PIO;
			if (cdb_base == SCMD_READ) {
				op = READ_SECTORS_EXT;
			} else {
				op = WRITE_SECTORS_EXT;
			}
		} else {
			mtype = SATA_PROTOCOL_DMA;
			if (cdb_base == SCMD_READ) {
				op = READ_DMA_EXT;
			} else {
				op = WRITE_DMA_EXT;
			}
		}
		fis[0] |= (op << 16);
		fis[1] = (FEATURE_LBA << 24) | (lba & 0xffffff);
		fis[2] = (lba >> 24) & 0xffffff;
		fis[3] = nblk;
	}

	if (cdb_base == SCMD_READ) {
		ptr[4] = LE_32(mtype | PMCIN_DATADIR_2_INI);
	} else {
		ptr[4] = LE_32(mtype | PMCIN_DATADIR_2_DEV);
	}
#ifdef	DEBUG
	/*
	 * Generate a PMCOUT_STATUS_XFER_CMD_FRAME_ISSUED
	 * event when this goes out on the wire.
	 */
	ptr[4] |= PMCIN_MESSAGE_REPORT;
#endif
	for (i = 0; i < (sizeof (fis_t))/(sizeof (uint32_t)); i++) {
		ptr[i+5] = LE_32(fis[i]);
	}
	if (pmcs_dma_load(pwp, sp, ptr)) {
		mutex_exit(&xp->statlock);
		mutex_exit(&pwp->iqp_lock[iq]);
		mutex_enter(&xp->wqlock);
		STAILQ_INSERT_HEAD(&xp->wq, sp, cmd_next);
		mutex_exit(&xp->wqlock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, xp,
		    "%s: Failed to dma_load for tgt %d",
		    __func__, xp->target_num);
		return (PMCS_WQ_RUN_FAIL_RES);

	}

	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	lhtag = pwrk->htag;
	mutex_exit(&pwrk->lock);
	xp->tagmap |= (1 << tag);
	xp->actv_cnt++;
	if (xp->actv_cnt > xp->maxdepth) {
		xp->maxdepth = xp->actv_cnt;
		pmcs_prt(pwp, PMCS_PRT_DEBUG2, pwrk->phy, xp,
		    "%s: max depth now %u", pwrk->phy->path, xp->maxdepth);
	}
	mutex_exit(&xp->statlock);
	mutex_enter(&xp->aqlock);
	STAILQ_INSERT_TAIL(&xp->aq, sp, cmd_next);
	mutex_exit(&xp->aqlock);
	pmcs_prt(pwp, PMCS_PRT_DEBUG2, NULL, NULL,
	    "%s: giving pkt %p to hardware", __func__, (void *)pkt);
#ifdef DEBUG
	pmcs_print_entry(pwp, PMCS_PRT_DEBUG3, "SATA INI Message", ptr);
#endif
	sp_pkt_time = CMD2PKT(sp)->pkt_time;
	INC_IQ_ENTRY(pwp, iq);
	mutex_enter(&pwrk->lock);
	if (lhtag == pwrk->htag) {
		pwrk->timer = US2WT(sp_pkt_time * 1000000);
		if (pwrk->timer == 0) {
			pwrk->timer = US2WT(1000000);
		}
	}
	mutex_exit(&pwrk->lock);

	return (PMCS_WQ_RUN_SUCCESS);
}

/*
 * Complete a SATA command.  Called with pwrk lock held.
 */
void
pmcs_SATA_done(pmcs_hw_t *pwp, pmcwork_t *pwrk, uint32_t *msg)
{
	pmcs_cmd_t *sp = pwrk->arg;
	struct scsi_pkt *pkt = CMD2PKT(sp);
	pmcs_phy_t *pptr = pwrk->phy;
	int dead;
	uint32_t sts;
	pmcs_xscsi_t *xp;
	boolean_t aborted = B_FALSE;

	xp = pwrk->xp;
	ASSERT(xp != NULL);

	DTRACE_PROBE4(pmcs__io__done, uint64_t, pkt->pkt_dma_len, int,
	    (pkt->pkt_dma_flags & DDI_DMA_READ) != 0, hrtime_t, pwrk->start,
	    hrtime_t, gethrtime());

	dead = pwrk->dead;

	if (msg) {
		sts = LE_32(msg[2]);
	} else {
		sts = 0;
	}

	if (dead != 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp, "%s: dead cmd tag "
		    "0x%x for %s", __func__, pwrk->htag, pptr->path);
		goto out;
	}
	if ((pwrk->state == PMCS_WORK_STATE_TIMED_OUT) &&
	    (sts != PMCOUT_STATUS_ABORTED)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: cmd 0x%p (tag 0x%x) timed out for %s",
		    __func__, (void *)sp, pwrk->htag, pptr->path);
		CMD2PKT(sp)->pkt_scbp[0] = STATUS_GOOD;
		/* pkt_reason already set to CMD_TIMEOUT */
		ASSERT(CMD2PKT(sp)->pkt_reason == CMD_TIMEOUT);
		CMD2PKT(sp)->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD;
		CMD2PKT(sp)->pkt_statistics |= STAT_TIMEOUT;
		goto out;
	}

	pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, xp, "%s: pkt %p tgt %u done",
	    __func__, (void *)pkt, xp->target_num);

	/*
	 * If the status isn't okay but not underflow,
	 * step to the side and parse the (possible) error.
	 */
#ifdef DEBUG
	if (msg) {
		pmcs_print_entry(pwp, PMCS_PRT_DEBUG3, "Outbound Message", msg);
	}
#endif
	if (!msg) {
		goto out;
	}

	/*
	 * If the status isn't okay or we got a FIS response of some kind,
	 * step to the side and parse the (possible) error.
	 */
	if ((sts != PMCOUT_STATUS_OK) || (LE_32(msg[3]) != 0)) {
		if (sts == PMCOUT_STATUS_IO_DS_NON_OPERATIONAL) {
			mutex_exit(&pwrk->lock);
			pmcs_lock_phy(pptr);
			mutex_enter(&xp->statlock);
			if ((xp->resetting == 0) && (xp->reset_success != 0) &&
			    (xp->reset_wait == 0)) {
				mutex_exit(&xp->statlock);
				if (pmcs_reset_phy(pwp, pptr,
				    PMCS_PHYOP_LINK_RESET) != 0) {
					pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
					    "%s: PHY (%s) Local Control/Link "
					    "Reset FAILED as part of error "
					    "recovery", __func__, pptr->path);
				}
				mutex_enter(&xp->statlock);
			}
			mutex_exit(&xp->statlock);
			pmcs_unlock_phy(pptr);
			mutex_enter(&pwrk->lock);
		}
		pmcs_ioerror(pwp, SATA, pwrk, msg, sts);
	} else {
		pmcs_latch_status(pwp, sp, STATUS_GOOD, NULL, 0,
		    pwrk->phy->path);
		pkt->pkt_state |= STATE_XFERRED_DATA;
		pkt->pkt_resid = 0;
	}

	pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, xp,
	    "%s: pkt %p tgt %u done reason=%x state=%x resid=%ld status=%x",
	    __func__, (void *)pkt, xp->target_num, pkt->pkt_reason,
	    pkt->pkt_state, pkt->pkt_resid, pkt->pkt_scbp[0]);

	if (pwrk->state == PMCS_WORK_STATE_ABORTED) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
		    "%s: scsi_pkt 0x%p aborted for PHY %s; work = 0x%p",
		    __func__, (void *)pkt, pptr->path, (void *)pwrk);
		aborted = B_TRUE;
	}

out:
	pmcs_dma_unload(pwp, sp);
	mutex_enter(&xp->statlock);
	xp->tagmap &= ~(1 << sp->cmd_satltag);

	/*
	 * If the device no longer has a PHY pointer, clear the PHY pointer
	 * from the work structure before we free it.  Otherwise, pmcs_pwork
	 * may decrement the ref_count on a PHY that's been freed.
	 */
	if (xp->phy == NULL) {
		pwrk->phy = NULL;
	}

	/*
	 * We may arrive here due to a command timing out, which in turn
	 * could be addressed in a different context.  So, free the work
	 * back, but only after confirming it's not already been freed
	 * elsewhere.
	 */
	if (pwrk->htag != PMCS_TAG_FREE) {
		pmcs_pwork(pwp, pwrk);
	}

	if (xp->dev_gone) {
		mutex_exit(&xp->statlock);
		if (!dead) {
			mutex_enter(&xp->aqlock);
			STAILQ_REMOVE(&xp->aq, sp, pmcs_cmd, cmd_next);
			mutex_exit(&xp->aqlock);
			pmcs_prt(pwp, PMCS_PRT_DEBUG3, pptr, xp,
			    "%s: Removing cmd 0x%p (htag 0x%x) from aq",
			    __func__, (void *)sp, sp->cmd_tag);
			mutex_enter(&pwp->cq_lock);
			STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
			PMCS_CQ_RUN_LOCKED(pwp);
			mutex_exit(&pwp->cq_lock);
			pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, xp,
			    "%s: Completing command for dead target 0x%p",
			    __func__, (void *)xp);
		}
		return;
	}

	ASSERT(xp->actv_cnt > 0);
	if (--(xp->actv_cnt) == 0) {
		if (xp->draining) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG1, pptr, xp,
			    "%s: waking up drain waiters", __func__);
			cv_signal(&pwp->drain_cv);
		} else if (xp->special_needed) {
			SCHEDULE_WORK(pwp, PMCS_WORK_SATA_RUN);
		}
	}
	mutex_exit(&xp->statlock);

	/*
	 * If the status is other than OK, determine if it's something that
	 * is worth re-attempting enumeration.  If so, mark the PHY.
	 */
	if (sts != PMCOUT_STATUS_OK) {
		pmcs_status_disposition(pptr, sts);
	}

	if (dead == 0) {
#ifdef	DEBUG
		pmcs_cmd_t *wp;
		mutex_enter(&xp->aqlock);
		STAILQ_FOREACH(wp, &xp->aq, cmd_next) {
			if (wp == sp) {
				break;
			}
		}
		ASSERT(wp != NULL);
#else
		mutex_enter(&xp->aqlock);
#endif
		STAILQ_REMOVE(&xp->aq, sp, pmcs_cmd, cmd_next);
		if (aborted) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
			    "%s: Aborted cmd for tgt 0x%p, signaling waiters",
			    __func__, (void *)xp);
			cv_signal(&xp->abort_cv);
		}
		mutex_exit(&xp->aqlock);
		mutex_enter(&pwp->cq_lock);
		STAILQ_INSERT_TAIL(&pwp->cq, sp, cmd_next);
		PMCS_CQ_RUN_LOCKED(pwp);
		mutex_exit(&pwp->cq_lock);
	}
}

static uint8_t
pmcs_SATA_rwparm(uint8_t *cdb, uint32_t *xfr, uint64_t *lba, uint64_t lbamax)
{
	uint8_t asc = 0;
	switch (cdb[0]) {
	case SCMD_READ_G5:
	case SCMD_WRITE_G5:
		*xfr =
		    (((uint32_t)cdb[10]) <<  24) |
		    (((uint32_t)cdb[11]) <<  16) |
		    (((uint32_t)cdb[12]) <<   8) |
		    ((uint32_t)cdb[13]);
		*lba =
		    (((uint64_t)cdb[2]) << 56) |
		    (((uint64_t)cdb[3]) << 48) |
		    (((uint64_t)cdb[4]) << 40) |
		    (((uint64_t)cdb[5]) << 32) |
		    (((uint64_t)cdb[6]) << 24) |
		    (((uint64_t)cdb[7]) << 16) |
		    (((uint64_t)cdb[8]) <<  8) |
		    ((uint64_t)cdb[9]);
		/* Check for illegal bits */
		if (cdb[15]) {
			asc = 0x24;	/* invalid field in cdb */
		}
		break;
	case SCMD_READ_G4:
	case SCMD_WRITE_G4:
		*xfr =
		    (((uint32_t)cdb[6]) <<  16) |
		    (((uint32_t)cdb[7]) <<   8) |
		    ((uint32_t)cdb[8]);
		*lba =
		    (((uint32_t)cdb[2]) << 24) |
		    (((uint32_t)cdb[3]) << 16) |
		    (((uint32_t)cdb[4]) <<  8) |
		    ((uint32_t)cdb[5]);
		/* Check for illegal bits */
		if (cdb[11]) {
			asc = 0x24;	/* invalid field in cdb */
		}
		break;
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
		*xfr = (((uint32_t)cdb[7]) <<  8) | ((uint32_t)cdb[8]);
		*lba =
		    (((uint32_t)cdb[2]) << 24) |
		    (((uint32_t)cdb[3]) << 16) |
		    (((uint32_t)cdb[4]) <<  8) |
		    ((uint32_t)cdb[5]);
		/* Check for illegal bits */
		if (cdb[9]) {
			asc = 0x24;	/* invalid field in cdb */
		}
		break;
	case SCMD_READ:
	case SCMD_WRITE:
		*xfr = cdb[4];
		if (*xfr == 0) {
			*xfr = 256;
		}
		*lba =
		    (((uint32_t)cdb[1] & 0x1f) << 16) |
		    (((uint32_t)cdb[2]) << 8) |
		    ((uint32_t)cdb[3]);
		/* Check for illegal bits */
		if (cdb[5]) {
			asc = 0x24;	/* invalid field in cdb */
		}
		break;
	}

	if (asc == 0) {
		if ((*lba + *xfr) > lbamax) {
			asc = 0x21;	/* logical block out of range */
		}
	}
	return (asc);
}

/*
 * Called with pwrk lock held.
 */
static void
pmcs_ioerror(pmcs_hw_t *pwp, pmcs_dtype_t t, pmcwork_t *pwrk, uint32_t *w,
    uint32_t status)
{
	static uint8_t por[] = {
	    0xf0, 0x0, 0x6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x28
	};
	static uint8_t parity[] = {
	    0xf0, 0x0, 0xb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x47, 5
	};
	const char *msg;
	char buf[20];
	pmcs_cmd_t *sp = pwrk->arg;
	pmcs_phy_t *phyp = pwrk->phy;
	struct scsi_pkt *pkt = CMD2PKT(sp);
	uint32_t resid;

	ASSERT(w != NULL);
	resid = LE_32(w[3]);

	msg = pmcs_status_str(status);
	if (msg == NULL) {
		(void) snprintf(buf, sizeof (buf), "Error 0x%x", status);
		msg = buf;
	}

	if (status != PMCOUT_STATUS_OK) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG1, phyp, NULL,
		    "%s: device %s tag 0x%x status %s @ %llu", __func__,
		    phyp->path, pwrk->htag, msg,
		    (unsigned long long)gethrtime());
	}

	pkt->pkt_reason = CMD_CMPLT;		/* default reason */

	switch (status) {
	case PMCOUT_STATUS_OK:
		if (t == SATA) {
			int i;
			fis_t fis;
			for (i = 0; i < sizeof (fis) / sizeof (fis[0]); i++) {
				fis[i] = LE_32(w[4+i]);
			}
			if ((fis[0] & 0xff) != FIS_REG_D2H) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, NULL,
				    "unexpected fis code 0x%x", fis[0] & 0xff);
			} else {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, NULL,
				    "FIS ERROR");
				pmcs_fis_dump(pwp, fis);
			}
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;
		}
		pmcs_latch_status(pwp, sp, STATUS_GOOD, NULL, 0, phyp->path);
		break;

	case PMCOUT_STATUS_ABORTED:
		/*
		 * Command successfully aborted.
		 */
		if (phyp->dead) {
			pkt->pkt_reason = CMD_DEV_GONE;
			pkt->pkt_state = STATE_GOT_BUS;
		} else if (pwrk->ssp_event != 0) {
			pkt->pkt_reason = CMD_TRAN_ERR;
			pkt->pkt_state = STATE_GOT_BUS;
		} else if (pwrk->state == PMCS_WORK_STATE_TIMED_OUT) {
			pkt->pkt_reason = CMD_TIMEOUT;
			pkt->pkt_statistics |= STAT_TIMEOUT;
			pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_SENT_CMD;
		} else {
			pkt->pkt_reason = CMD_ABORTED;
			pkt->pkt_statistics |= STAT_ABORTED;
			pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_SENT_CMD;
		}

		/*
		 * PMCS_WORK_STATE_TIMED_OUT doesn't need to be preserved past
		 * this point, so go ahead and mark it as aborted.
		 */
		pwrk->state = PMCS_WORK_STATE_ABORTED;
		break;

	case PMCOUT_STATUS_UNDERFLOW:
		/*
		 * This will only get called for SATA
		 */
		pkt->pkt_resid = resid;
		if (pkt->pkt_dma_len < pkt->pkt_resid) {
			(void) pmcs_set_resid(pkt, pkt->pkt_dma_len, resid);
		}
		pmcs_latch_status(pwp, sp, STATUS_GOOD, NULL, 0, phyp->path);
		break;

	case PMCOUT_STATUS_NO_DEVICE:
	case PMCOUT_STATUS_XFER_ERROR_SATA_LINK_TIMEOUT:
		pkt->pkt_reason = CMD_DEV_GONE;
		break;

	case PMCOUT_STATUS_OPEN_CNX_ERROR_WRONG_DESTINATION:
		/*
		 * Need to do rediscovery. We probably have
		 * the wrong device (disk swap), so kill
		 * this one.
		 */
	case PMCOUT_STATUS_OPEN_CNX_PROTOCOL_NOT_SUPPORTED:
	case PMCOUT_STATUS_OPEN_CNX_ERROR_ZONE_VIOLATION:
	case PMCOUT_STATUS_OPEN_CNX_ERROR_CONNECTION_RATE_NOT_SUPPORTED:
	case PMCOUT_STATUS_OPEN_CNX_ERROR_UNKNOWN_ERROR:
		/*
		 * Need to do rediscovery.
		 */
		if (!phyp->dead) {
			mutex_exit(&pwrk->lock);
			pmcs_lock_phy(pwrk->phy);
			pmcs_kill_changed(pwp, pwrk->phy, 0);
			pmcs_unlock_phy(pwrk->phy);
			mutex_enter(&pwrk->lock);
			pkt->pkt_reason = CMD_INCOMPLETE;
			pkt->pkt_state = STATE_GOT_BUS;
		} else {
			pkt->pkt_reason = CMD_DEV_GONE;
		}
		break;

	case PMCOUT_STATUS_OPEN_CNX_ERROR_BREAK:
	case PMCOUT_STATUS_OPEN_CNX_ERROR_IT_NEXUS_LOSS:
	case PMCOUT_STATUS_OPENCNX_ERROR_BAD_DESTINATION:
	case PMCOUT_STATUS_IO_XFER_ERROR_NAK_RECEIVED:
		/* cmd is pending on the target */
	case PMCOUT_STATUS_XFER_ERROR_OFFSET_MISMATCH:
	case PMCOUT_STATUS_XFER_ERROR_REJECTED_NCQ_MODE:
		/* transitory - commands sent while in NCQ failure mode */
	case PMCOUT_STATUS_XFER_ERROR_ABORTED_NCQ_MODE:
		/* NCQ failure */
	case PMCOUT_STATUS_IO_PORT_IN_RESET:
	case PMCOUT_STATUS_XFER_ERR_BREAK:
	case PMCOUT_STATUS_XFER_ERR_PHY_NOT_READY:
		pkt->pkt_reason = CMD_INCOMPLETE;
		pkt->pkt_state = STATE_GOT_BUS;
		break;

	case PMCOUT_STATUS_IO_XFER_OPEN_RETRY_TIMEOUT:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, phyp->target,
		    "STATUS_BUSY for htag 0x%08x", sp->cmd_tag);
		pmcs_latch_status(pwp, sp, STATUS_BUSY, NULL, 0, phyp->path);
		break;

	case PMCOUT_STATUS_OPEN_CNX_ERROR_STP_RESOURCES_BUSY:
		/* synthesize a RESERVATION CONFLICT */
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, phyp->target,
		    "%s: Potential affiliation active on 0x%" PRIx64, __func__,
		    pmcs_barray2wwn(phyp->sas_address));
		pmcs_latch_status(pwp, sp, STATUS_RESERVATION_CONFLICT, NULL,
		    0, phyp->path);
		break;

	case PMCOUT_STATUS_XFER_ERROR_ABORTED_DUE_TO_SRST:
		/* synthesize a power-on/reset */
		pmcs_latch_status(pwp, sp, STATUS_CHECK, por, sizeof (por),
		    phyp->path);
		break;

	case PMCOUT_STATUS_XFER_ERROR_UNEXPECTED_PHASE:
	case PMCOUT_STATUS_XFER_ERROR_RDY_OVERRUN:
	case PMCOUT_STATUS_XFER_ERROR_RDY_NOT_EXPECTED:
	case PMCOUT_STATUS_XFER_ERROR_CMD_ISSUE_ACK_NAK_TIMEOUT:
	case PMCOUT_STATUS_XFER_ERROR_CMD_ISSUE_BREAK_BEFORE_ACK_NACK:
	case PMCOUT_STATUS_XFER_ERROR_CMD_ISSUE_PHY_DOWN_BEFORE_ACK_NAK:
		/* synthesize a PARITY ERROR */
		pmcs_latch_status(pwp, sp, STATUS_CHECK, parity,
		    sizeof (parity), phyp->path);
		break;

	case PMCOUT_STATUS_IO_XFER_ERROR_DMA:
	case PMCOUT_STATUS_IO_NOT_VALID:
	case PMCOUT_STATUS_PROG_ERROR:
	case PMCOUT_STATUS_XFER_ERROR_PEER_ABORTED:
	case PMCOUT_STATUS_XFER_ERROR_SATA: /* non-NCQ failure */
	default:
		pkt->pkt_reason = CMD_TRAN_ERR;
		break;
	}
}

/*
 * Latch up SCSI status
 */

void
pmcs_latch_status(pmcs_hw_t *pwp, pmcs_cmd_t *sp, uint8_t status,
    uint8_t *snsp, size_t snslen, char *path)
{
	static const char c1[] =
	    "%s: Status Byte 0x%02x for CDB0=0x%02x (%02x %02x %02x) "
	    "HTAG 0x%x @ %llu";
	static const char c2[] =
	    "%s: Status Byte 0x%02x for CDB0=0x%02x HTAG 0x%x @ %llu";

	CMD2PKT(sp)->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS;
	CMD2PKT(sp)->pkt_scbp[0] = status;

	if (status == STATUS_CHECK && snsp &&
	    (size_t)SCSA_STSLEN(sp) >= sizeof (struct scsi_arq_status)) {
		struct scsi_arq_status *aqp =
		    (void *) CMD2PKT(sp)->pkt_scbp;
		size_t amt = sizeof (struct scsi_extended_sense);
		uint8_t key = scsi_sense_key(snsp);
		uint8_t asc = scsi_sense_asc(snsp);
		uint8_t ascq = scsi_sense_ascq(snsp);
		if (amt > snslen) {
			amt = snslen;
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG_SCSI_STATUS, NULL, NULL, c1, path,
		    status, CMD2PKT(sp)->pkt_cdbp[0] & 0xff, key, asc, ascq,
		    sp->cmd_tag, (unsigned long long)gethrtime());
		CMD2PKT(sp)->pkt_state |= STATE_ARQ_DONE;
		(*(uint8_t *)&aqp->sts_rqpkt_status) = STATUS_GOOD;
		aqp->sts_rqpkt_statistics = 0;
		aqp->sts_rqpkt_reason = CMD_CMPLT;
		aqp->sts_rqpkt_state = STATE_GOT_BUS |
		    STATE_GOT_TARGET | STATE_SENT_CMD |
		    STATE_XFERRED_DATA | STATE_GOT_STATUS;
		(void) memcpy(&aqp->sts_sensedata, snsp, amt);
		if (aqp->sts_sensedata.es_class != CLASS_EXTENDED_SENSE) {
			aqp->sts_rqpkt_reason = CMD_TRAN_ERR;
			aqp->sts_rqpkt_state = 0;
			aqp->sts_rqpkt_resid =
			    sizeof (struct scsi_extended_sense);
		} else {
			aqp->sts_rqpkt_resid =
			    sizeof (struct scsi_extended_sense) - amt;
		}
	} else if (status) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_SCSI_STATUS, NULL, NULL, c2,
		    path, status, CMD2PKT(sp)->pkt_cdbp[0] & 0xff,
		    sp->cmd_tag, (unsigned long long)gethrtime());
	}

	CMD2PKT(sp)->pkt_reason = CMD_CMPLT;
}

/*
 * Calculate and set packet residual and return the amount
 * left over after applying various filters.
 */
size_t
pmcs_set_resid(struct scsi_pkt *pkt, size_t amt, uint32_t cdbamt)
{
	pkt->pkt_resid = cdbamt;
	if (amt > pkt->pkt_resid) {
		amt = pkt->pkt_resid;
	}
	if (amt > pkt->pkt_dma_len) {
		amt = pkt->pkt_dma_len;
	}
	return (amt);
}

/*
 * Return the existing target softstate (unlocked) if there is one.  If so,
 * the PHY is locked and that lock must be freed by the caller after the
 * target/PHY linkage is established.  If there isn't one, and alloc_tgt is
 * TRUE, then allocate one.
 */
pmcs_xscsi_t *
pmcs_get_target(pmcs_iport_t *iport, char *tgt_port, boolean_t alloc_tgt)
{
	pmcs_hw_t *pwp = iport->pwp;
	pmcs_phy_t *phyp;
	pmcs_xscsi_t *tgt;
	uint64_t wwn;
	char unit_address[PMCS_MAX_UA_SIZE];
	int ua_form = 1;

	/*
	 * Find the PHY for this target
	 */
	phyp = pmcs_find_phy_by_sas_address(pwp, iport, NULL, tgt_port);
	if (phyp == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG3, NULL, NULL,
		    "%s: No PHY for target @ %s", __func__, tgt_port);
		return (NULL);
	}

	tgt = ddi_soft_state_bystr_get(iport->tgt_sstate, tgt_port);

	if (tgt) {
		mutex_enter(&tgt->statlock);
		/*
		 * There's already a target.  Check its PHY pointer to see
		 * if we need to clear the old linkages
		 */
		if (tgt->phy && (tgt->phy != phyp)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, tgt,
			    "%s: Target PHY updated from %p to %p", __func__,
			    (void *)tgt->phy, (void *)phyp);
			if (!IS_ROOT_PHY(tgt->phy)) {
				pmcs_dec_phy_ref_count(tgt->phy);
				pmcs_inc_phy_ref_count(phyp);
			}
			tgt->phy->target = NULL;
		}

		/*
		 * If this target has no PHY pointer and alloc_tgt is FALSE,
		 * that implies we expect the target to already exist.  This
		 * implies that there has already been a tran_tgt_init on at
		 * least one LU.
		 */
		if ((tgt->phy == NULL) && !alloc_tgt) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, tgt,
			    "%s: Establish linkage from new PHY to old target @"
			    "%s", __func__, tgt->unit_address);
			for (int idx = 0; idx < tgt->ref_count; idx++) {
				pmcs_inc_phy_ref_count(phyp);
			}
		}

		/*
		 * Set this target pointer back up, since it's been
		 * through pmcs_clear_xp().
		 */
		tgt->dev_gone = 0;
		tgt->assigned = 1;
		tgt->dtype = phyp->dtype;
		tgt->dev_state = PMCS_DEVICE_STATE_OPERATIONAL;
		tgt->phy = phyp;
		phyp->target = tgt;

		mutex_exit(&tgt->statlock);
		return (tgt);
	}

	/*
	 * Make sure the PHY we found is on the correct iport
	 */
	if (phyp->iport != iport) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, NULL,
		    "%s: No target at %s on this iport", __func__, tgt_port);
		pmcs_unlock_phy(phyp);
		return (NULL);
	}

	/*
	 * If this was just a lookup (i.e. alloc_tgt is false), return now.
	 */
	if (alloc_tgt == B_FALSE) {
		pmcs_unlock_phy(phyp);
		return (NULL);
	}

	/*
	 * Allocate the new softstate
	 */
	wwn = pmcs_barray2wwn(phyp->sas_address);
	(void) scsi_wwn_to_wwnstr(wwn, ua_form, unit_address);

	if (ddi_soft_state_bystr_zalloc(iport->tgt_sstate, unit_address) !=
	    DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, tgt,
		    "%s: Couldn't alloc softstate for device at %s",
		    __func__, unit_address);
		pmcs_unlock_phy(phyp);
		return (NULL);
	}

	tgt = ddi_soft_state_bystr_get(iport->tgt_sstate, unit_address);
	ASSERT(tgt != NULL);
	STAILQ_INIT(&tgt->wq);
	STAILQ_INIT(&tgt->aq);
	STAILQ_INIT(&tgt->sq);
	mutex_init(&tgt->statlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pwp->intr_pri));
	mutex_init(&tgt->wqlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pwp->intr_pri));
	mutex_init(&tgt->aqlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pwp->intr_pri));
	cv_init(&tgt->reset_cv, NULL, CV_DRIVER, NULL);
	cv_init(&tgt->abort_cv, NULL, CV_DRIVER, NULL);
	list_create(&tgt->lun_list, sizeof (pmcs_lun_t),
	    offsetof(pmcs_lun_t, lun_list_next));
	tgt->qdepth = 1;
	tgt->target_num = PMCS_INVALID_TARGET_NUM;
	bcopy(unit_address, tgt->unit_address, PMCS_MAX_UA_SIZE);
	tgt->pwp = pwp;
	tgt->ua = strdup(iport->ua);
	tgt->phy = phyp;
	ASSERT((phyp->target == NULL) || (phyp->target == tgt));
	if (phyp->target == NULL) {
		phyp->target = tgt;
	}

	/*
	 * Don't allocate LUN softstate for SMP targets
	 */
	if (phyp->dtype == EXPANDER) {
		return (tgt);
	}

	if (ddi_soft_state_bystr_init(&tgt->lun_sstate,
	    sizeof (pmcs_lun_t), PMCS_LUN_SSTATE_SZ) != 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, phyp, tgt,
		    "%s: LUN soft_state_bystr_init failed", __func__);
		ddi_soft_state_bystr_free(iport->tgt_sstate, tgt_port);
		pmcs_unlock_phy(phyp);
		return (NULL);
	}

	return (tgt);
}
