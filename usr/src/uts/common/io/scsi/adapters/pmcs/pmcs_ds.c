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
 * PM8001 device state recovery routines
 */

#include <sys/scsi/adapters/pmcs/pmcs.h>

/*
 * SAS Topology Configuration
 */
static void pmcs_ds_operational(pmcs_phy_t *pptr, pmcs_xscsi_t *tgt);
static void pmcs_handle_ds_recovery_error(pmcs_phy_t *phyp,
    pmcs_xscsi_t *tgt, pmcs_hw_t *pwp, const char *func_name,
    char *reason_string);

/*
 * Get device state.  Called with statlock and PHY lock held.
 */
static int
pmcs_get_dev_state(pmcs_hw_t *pwp, pmcs_phy_t *phyp, pmcs_xscsi_t *xp,
    uint8_t *ds)
{
	uint32_t htag, *ptr, msg[PMCS_MSG_SIZE];
	int result;
	struct pmcwork *pwrk;

	pmcs_prt(pwp, PMCS_PRT_DEBUG3, phyp, xp, "%s: tgt(0x%p)", __func__,
	    (void *)xp);

	if (xp != NULL) {
		ASSERT(mutex_owned(&xp->statlock));
	}

	if (phyp == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, NULL, xp,
		    "%s: PHY is NULL", __func__);
		return (-1);
	}
	ASSERT(mutex_owned(&phyp->phy_lock));

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, phyp);
	if (pwrk == NULL) {
		pmcs_prt(pwp, PMCS_PRT_ERR, phyp, xp, pmcs_nowrk, __func__);
		return (-1);
	}
	pwrk->arg = msg;
	pwrk->dtype = phyp->dtype;

	if (phyp->valid_device_id == 0) {
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, xp,
		    "%s: Invalid DeviceID", __func__);
		return (-1);
	}
	htag = pwrk->htag;
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
	    PMCIN_GET_DEVICE_STATE));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(phyp->device_id);
	CLEAN_MESSAGE(msg, 3);

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_ERR, phyp, xp, pmcs_nomsg, __func__);
		return (-1);
	}
	COPY_MESSAGE(ptr, msg, PMCS_MSG_SIZE);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	if (xp != NULL) {
		mutex_exit(&xp->statlock);
	}
	pmcs_unlock_phy(phyp);
	WAIT_FOR(pwrk, 1000, result);
	pmcs_lock_phy(phyp);
	pmcs_pwork(pwp, pwrk);

	if (xp != NULL) {
		mutex_enter(&xp->statlock);
	}

	if (result) {
		pmcs_timed_out(pwp, htag, __func__);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, xp,
		    "%s: cmd timed out, returning", __func__);
		return (-1);
	}
	if (LE_32(msg[2]) == 0) {
		*ds = (uint8_t)(LE_32(msg[4]));
		if (xp == NULL) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
			    "%s: retrieved_ds=0x%x", __func__, *ds);
		} else if (*ds !=  xp->dev_state) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
			    "%s: retrieved_ds=0x%x, target_ds=0x%x", __func__,
			    *ds, xp->dev_state);
		}
		return (0);
	} else {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: cmd failed Status(0x%x), returning ", __func__,
		    LE_32(msg[2]));
		return (-1);
	}
}

/*
 * Set device state.  Called with target's statlock and PHY lock held.
 */
static int
pmcs_set_dev_state(pmcs_hw_t *pwp, pmcs_phy_t *phyp, pmcs_xscsi_t *xp,
    uint8_t ds)
{
	uint32_t htag, *ptr, msg[PMCS_MSG_SIZE];
	int result;
	uint8_t pds, nds;
	struct pmcwork *pwrk;

	pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
	    "%s: ds: 0x%x tgt: 0x%p phy: 0x%p", __func__, ds, (void *)xp,
	    (void *)phyp);

	if (phyp == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, NULL, xp,
		    "%s: PHY is NULL", __func__);
		return (-1);
	}

	pwrk = pmcs_gwork(pwp, PMCS_TAG_TYPE_WAIT, phyp);
	if (pwrk == NULL) {
		pmcs_prt(pwp, PMCS_PRT_ERR, phyp, xp, pmcs_nowrk, __func__);
		return (-1);
	}
	if (phyp->valid_device_id == 0) {
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: Invalid DeviceID", __func__);
		return (-1);
	}
	pwrk->arg = msg;
	pwrk->dtype = phyp->dtype;
	htag = pwrk->htag;
	msg[0] = LE_32(PMCS_HIPRI(pwp, PMCS_OQ_GENERAL,
	    PMCIN_SET_DEVICE_STATE));
	msg[1] = LE_32(pwrk->htag);
	msg[2] = LE_32(phyp->device_id);
	msg[3] = LE_32(ds);
	CLEAN_MESSAGE(msg, 4);

	mutex_enter(&pwp->iqp_lock[PMCS_IQ_OTHER]);
	ptr = GET_IQ_ENTRY(pwp, PMCS_IQ_OTHER);
	if (ptr == NULL) {
		mutex_exit(&pwp->iqp_lock[PMCS_IQ_OTHER]);
		pmcs_pwork(pwp, pwrk);
		pmcs_prt(pwp, PMCS_PRT_ERR, phyp, xp, pmcs_nomsg, __func__);
		return (-1);
	}
	COPY_MESSAGE(ptr, msg, PMCS_MSG_SIZE);
	pwrk->state = PMCS_WORK_STATE_ONCHIP;
	INC_IQ_ENTRY(pwp, PMCS_IQ_OTHER);

	if (xp != NULL) {
		mutex_exit(&xp->statlock);
	}
	pmcs_unlock_phy(phyp);
	WAIT_FOR(pwrk, 1000, result);
	pmcs_lock_phy(phyp);
	pmcs_pwork(pwp, pwrk);
	if (xp != NULL) {
		mutex_enter(&xp->statlock);
	}

	if (result) {
		pmcs_timed_out(pwp, htag, __func__);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: cmd timed out, returning", __func__);
		return (-1);
	}
	if (LE_32(msg[2]) == 0) {
		pds = (uint8_t)(LE_32(msg[4]) >> 4);
		nds = (uint8_t)(LE_32(msg[4]) & 0x0000000f);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: previous_ds=0x%x, new_ds=0x%x", __func__, pds, nds);
		if (xp != NULL) {
			xp->dev_state = nds;
		}
		return (0);
	} else {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: cmd failed Status(0x%x), returning ", __func__,
		    LE_32(msg[2]));
		return (-1);
	}
}

static void
pmcs_ds_operational(pmcs_phy_t *pptr, pmcs_xscsi_t *tgt)
{
	pmcs_hw_t	*pwp;

	ASSERT(pptr);
	pwp = pptr->pwp;

	if (tgt != NULL) {
		tgt->recover_wait = 0;
	}
	pptr->ds_recovery_retries = 0;

	if ((pptr->ds_prev_good_recoveries == 0) ||
	    (ddi_get_lbolt() - pptr->last_good_recovery >
	    drv_usectohz(PMCS_MAX_DS_RECOVERY_TIME))) {
		pptr->last_good_recovery = ddi_get_lbolt();
		pptr->ds_prev_good_recoveries = 1;
	} else if (ddi_get_lbolt() < pptr->last_good_recovery +
	    drv_usectohz(PMCS_MAX_DS_RECOVERY_TIME)) {
		pptr->ds_prev_good_recoveries++;
	} else {
		pmcs_handle_ds_recovery_error(pptr, tgt, pwp, __func__,
		    "Max recovery attempts reached. Declaring PHY dead");
	}

	/* Don't bother to run the work queues if the PHY is dead */
	if (!pptr->dead) {
		SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
		(void) ddi_taskq_dispatch(pwp->tq, pmcs_worker,
		    pwp, DDI_NOSLEEP);
	}
}

void
pmcs_dev_state_recovery(pmcs_hw_t *pwp, pmcs_phy_t *phyp)
{
	boolean_t reschedule = B_FALSE;
	uint8_t	ds, tgt_dev_state;
	int rc;
	pmcs_xscsi_t *tgt;
	pmcs_phy_t *pptr, *pnext, *pchild;

	/*
	 * First time, check to see if we're already performing recovery
	 */
	if (phyp == NULL) {
		mutex_enter(&pwp->lock);
		if (pwp->ds_err_recovering) {
			mutex_exit(&pwp->lock);
			SCHEDULE_WORK(pwp, PMCS_WORK_DS_ERR_RECOVERY);
			return;
		}

		pwp->ds_err_recovering = 1;
		pptr = pwp->root_phys;
		mutex_exit(&pwp->lock);
	} else {
		pptr = phyp;
	}

	while (pptr) {
		/*
		 * Since ds_err_recovering is set, we can be assured these
		 * PHYs won't disappear on us while we do this.
		 */
		pmcs_lock_phy(pptr);
		pchild = pptr->children;
		pnext = pptr->sibling;
		pmcs_unlock_phy(pptr);

		if (pchild) {
			pmcs_dev_state_recovery(pwp, pchild);
		}

		tgt = NULL;
		pmcs_lock_phy(pptr);

		if (pptr->dead || !pptr->valid_device_id) {
			goto next_phy;
		}

		if (pptr->iport && (pptr->iport->ua_state != UA_ACTIVE)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, pptr->target,
			    "%s: No DS recovery on PHY %s, iport not active",
			    __func__, pptr->path);
			goto next_phy;
		}

		tgt = pptr->target;

		if (tgt != NULL) {
			mutex_enter(&tgt->statlock);
			if (tgt->recover_wait == 0) {
				goto next_phy;
			}
			tgt_dev_state = tgt->dev_state;
		} else {
			tgt_dev_state = PMCS_DEVICE_STATE_NOT_AVAILABLE;
		}

		if (pptr->prev_recovery) {
			if (ddi_get_lbolt() - pptr->prev_recovery <
			    drv_usectohz(PMCS_DS_RECOVERY_INTERVAL)) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, tgt,
				    "%s: DS recovery on PHY %s "
				    "re-invoked too soon. Skipping...",
				    __func__, pptr->path);
				if ((tgt) && (tgt->recover_wait)) {
					reschedule = B_TRUE;
				}
				goto next_phy;
			}
		}
		pptr->prev_recovery = ddi_get_lbolt();

		/*
		 * Step 1: Put the device into the IN_RECOVERY state
		 */
		rc = pmcs_get_dev_state(pwp, pptr, tgt, &ds);
		if (rc != 0) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
			    "%s: pmcs_get_dev_state on PHY %s "
			    "failed (rc=%d)",
			    __func__, pptr->path, rc);

			pmcs_handle_ds_recovery_error(pptr, tgt, pwp,
			    __func__, "pmcs_get_dev_state");

			goto next_phy;
		}

		/* If the chip says it's operational, we're done */
		if (ds == PMCS_DEVICE_STATE_OPERATIONAL) {
			pmcs_ds_operational(pptr, tgt);
			goto next_phy;
		}

		if ((tgt_dev_state == ds) &&
		    (ds == PMCS_DEVICE_STATE_IN_RECOVERY)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
			    "%s: Target 0x%p already IN_RECOVERY", __func__,
			    (void *)tgt);
		} else {
			if (tgt != NULL) {
				tgt->dev_state = ds;
			}
			tgt_dev_state = ds;
			ds = PMCS_DEVICE_STATE_IN_RECOVERY;
			rc = pmcs_send_err_recovery_cmd(pwp, ds, pptr, tgt);
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
			    "%s: pmcs_send_err_recovery_cmd "
			    "result(%d) tgt(0x%p) ds(0x%x) tgt->ds(0x%x)",
			    __func__, rc, (void *)tgt, ds, tgt_dev_state);

			if (rc) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
				    "%s: pmcs_send_err_recovery_cmd to PHY %s "
				    "failed (rc=%d)",
				    __func__, pptr->path, rc);

				pmcs_handle_ds_recovery_error(pptr, tgt, pwp,
				    __func__, "pmcs_send_err_recovery_cmd");

				goto next_phy;
			}
		}

		/*
		 * Step 2: Perform a hard reset on the PHY.
		 */
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
		    "%s: Issue HARD_RESET to PHY %s", __func__,
		    pptr->path);
		/*
		 * Must release statlock here because pmcs_reset_phy
		 * will drop and reacquire the PHY lock.
		 */
		if (tgt != NULL) {
			mutex_exit(&tgt->statlock);
		}
		rc = pmcs_reset_phy(pwp, pptr, PMCS_PHYOP_HARD_RESET);
		if (tgt != NULL) {
			mutex_enter(&tgt->statlock);
		}
		if (rc) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
			    "%s: HARD_RESET to PHY %s failed (rc=%d)",
			    __func__, pptr->path, rc);

			pmcs_handle_ds_recovery_error(pptr, tgt, pwp,
			    __func__, "HARD_RESET");

			goto next_phy;
		}

		/*
		 * Step 3: Abort all I/Os to the device
		 */
		if (pptr->abort_all_start) {
			while (pptr->abort_all_start) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
				    "%s: Waiting for outstanding ABORT_ALL on "
				    "PHY 0x%p", __func__, (void *)pptr);
				cv_wait(&pptr->abort_all_cv, &pptr->phy_lock);
			}
		} else {
			if (tgt != NULL) {
				mutex_exit(&tgt->statlock);
			}
			rc = pmcs_abort(pwp, pptr, pptr->device_id, 1, 1);
			if (tgt != NULL) {
				mutex_enter(&tgt->statlock);
			}
			if (rc != 0) {
				pptr->abort_pending = 1;
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
				    "%s: pmcs_abort to PHY %s failed (rc=%d)",
				    __func__, pptr->path, rc);

				pmcs_handle_ds_recovery_error(pptr, tgt,
				    pwp, __func__, "pmcs_abort");

				goto next_phy;
			}
		}

		/*
		 * Step 4: Set the device back to OPERATIONAL state
		 */
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
		    "%s: Set PHY/tgt 0x%p/0x%p to OPERATIONAL state",
		    __func__, (void *)pptr, (void *)tgt);
		rc = pmcs_set_dev_state(pwp, pptr, tgt,
		    PMCS_DEVICE_STATE_OPERATIONAL);
		if (rc == 0) {
			pmcs_ds_operational(pptr, tgt);
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, pptr, tgt,
			    "%s: Failed to SET tgt 0x%p to OPERATIONAL state",
			    __func__, (void *)tgt);

			pmcs_handle_ds_recovery_error(pptr, tgt, pwp,
			    __func__, "SET tgt to OPERATIONAL state");

			goto next_phy;
		}

next_phy:
		if (tgt) {
			mutex_exit(&tgt->statlock);
		}
		pmcs_unlock_phy(pptr);
		pptr = pnext;
	}

	/*
	 * Only clear ds_err_recovering if we're exiting for good and not
	 * just unwinding from recursion
	 */
	if (phyp == NULL) {
		mutex_enter(&pwp->lock);
		pwp->ds_err_recovering = 0;
		mutex_exit(&pwp->lock);
	}

	if (reschedule) {
		SCHEDULE_WORK(pwp, PMCS_WORK_DS_ERR_RECOVERY);
	}
}

/*
 * Called with target's statlock held (if target is non-NULL) and PHY lock held.
 */
int
pmcs_send_err_recovery_cmd(pmcs_hw_t *pwp, uint8_t dev_state, pmcs_phy_t *phyp,
    pmcs_xscsi_t *tgt)
{
	int rc = -1;
	uint8_t tgt_dev_state = PMCS_DEVICE_STATE_NOT_AVAILABLE;

	if (tgt != NULL) {
		ASSERT(mutex_owned(&tgt->statlock));
		if (tgt->recovering) {
			return (0);
		}

		tgt->recovering = 1;
		tgt_dev_state = tgt->dev_state;
	}

	if (phyp == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, NULL, tgt,
		    "%s: PHY is NULL", __func__);
		return (-1);
	}

	ASSERT(mutex_owned(&phyp->phy_lock));

	pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, tgt,
	    "%s: ds: 0x%x, tgt ds(0x%x)", __func__, dev_state, tgt_dev_state);

	switch (dev_state) {
	case PMCS_DEVICE_STATE_IN_RECOVERY:
		if (tgt_dev_state == PMCS_DEVICE_STATE_IN_RECOVERY) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, tgt,
			    "%s: Target 0x%p already IN_RECOVERY", __func__,
			    (void *)tgt);
			rc = 0;	/* This is not an error */
			goto no_action;
		}

		rc = pmcs_set_dev_state(pwp, phyp, tgt,
		    PMCS_DEVICE_STATE_IN_RECOVERY);
		if (rc != 0) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, tgt,
			    "%s(1): Failed to set tgt(0x%p) to IN_RECOVERY",
			    __func__, (void *)tgt);
		}

		break;

	case PMCS_DEVICE_STATE_OPERATIONAL:
		if (tgt_dev_state != PMCS_DEVICE_STATE_IN_RECOVERY) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, tgt,
			    "%s: Target 0x%p not ready to go OPERATIONAL",
			    __func__, (void *)tgt);
			goto no_action;
		}

		rc = pmcs_set_dev_state(pwp, phyp, tgt,
		    PMCS_DEVICE_STATE_OPERATIONAL);
		if (tgt != NULL) {
			tgt->reset_success = 1;
		}
		if (rc != 0) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, tgt,
			    "%s(2): Failed to SET tgt(0x%p) to OPERATIONAL",
			    __func__, (void *)tgt);
			if (tgt != NULL) {
				tgt->reset_success = 0;
			}
		}

		break;

	case PMCS_DEVICE_STATE_NON_OPERATIONAL:
		PHY_CHANGED(pwp, phyp);
		RESTART_DISCOVERY(pwp);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, tgt,
		    "%s: Device at %s is non-operational",
		    __func__, phyp->path);
		if (tgt != NULL) {
			tgt->dev_state = PMCS_DEVICE_STATE_NON_OPERATIONAL;
		}
		rc = 0;

		break;

	default:
		pmcs_prt(pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, tgt,
		    "%s: Invalid state requested (%d)", __func__,
		    dev_state);
		break;

	}

no_action:
	if (tgt != NULL) {
		tgt->recovering = 0;
	}
	return (rc);
}

/*
 * Start ssp event recovery. We have to schedule recovery operation because
 * it involves sending multiple commands to device and we should not do it
 * in the interrupt context.
 * If it is failure of a recovery command, let the recovery thread deal with it.
 * Called with pmcwork lock held.
 */
void
pmcs_start_ssp_event_recovery(pmcs_hw_t *pwp, pmcwork_t *pwrk, uint32_t *iomb,
    size_t amt)
{
	pmcs_xscsi_t *tgt = pwrk->xp;
	uint32_t event = LE_32(iomb[2]);
	pmcs_phy_t *pptr = pwrk->phy;
	pmcs_cb_t callback;
	uint32_t tag;

	if (tgt != NULL) {
		mutex_enter(&tgt->statlock);
		if (!tgt->assigned) {
			if (pptr) {
				pmcs_dec_phy_ref_count(pptr);
			}
			pptr = NULL;
			pwrk->phy = NULL;
		}
		mutex_exit(&tgt->statlock);
	}

	if (pptr == NULL) {
		/*
		 * No target, need to run RE-DISCOVERY here.
		 */
		if (pwrk->state != PMCS_WORK_STATE_TIMED_OUT) {
			pwrk->state = PMCS_WORK_STATE_INTR;
		}
		/*
		 * Although we cannot mark phy to force abort nor mark phy
		 * as changed, killing of a target would take care of aborting
		 * commands for the device.
		 */
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
		    "%s: No valid target for event processing. Reconfigure.",
		    __func__);
		pmcs_pwork(pwp, pwrk);
		RESTART_DISCOVERY(pwp);
		return;
	} else {
		pmcs_lock_phy(pptr);
		if (tgt) {
			mutex_enter(&tgt->statlock);
		}
		if (event == PMCOUT_STATUS_OPEN_CNX_ERROR_IT_NEXUS_LOSS) {
			if (tgt && tgt->dev_state !=
			    PMCS_DEVICE_STATE_NON_OPERATIONAL) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
				    "%s: Device at %s is non-operational",
				    __func__, pptr->path);
				tgt->dev_state =
				    PMCS_DEVICE_STATE_NON_OPERATIONAL;
			}
			pptr->abort_pending = 1;
			if (tgt) {
				mutex_exit(&tgt->statlock);
			}
			pmcs_unlock_phy(pptr);
			mutex_exit(&pwrk->lock);
			SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
			RESTART_DISCOVERY(pwp);
			return;
		}

		/*
		 * If this command is run in WAIT mode, it is a failing recovery
		 * command. If so, just wake up recovery thread waiting for
		 * command completion.
		 */
		tag = PMCS_TAG_TYPE(pwrk->htag);
		if (tag == PMCS_TAG_TYPE_WAIT) {
			pwrk->htag |= PMCS_TAG_DONE;
			if (pwrk->arg && amt) {
				(void) memcpy(pwrk->arg, iomb, amt);
			}
			cv_signal(&pwrk->sleep_cv);
			if (tgt) {
				mutex_exit(&tgt->statlock);
			}
			pmcs_unlock_phy(pptr);
			mutex_exit(&pwrk->lock); /* XXX: Is this right??? */
			return;
		}

		if (!tgt) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG1, pptr, NULL,
			    "%s: Not scheduling SSP event recovery for NULL tgt"
			    " pwrk(%p) tag(0x%x)", __func__, (void *)pwrk,
			    pwrk->htag);
			return;
		}

		/*
		 * If the SSP event was an OPEN_RETRY_TIMEOUT, we don't want
		 * to go through the recovery (abort/LU reset) process.
		 * Simply complete the command and return it as STATUS_BUSY.
		 * This will cause the target driver to simply retry.
		 */
		if (event == PMCOUT_STATUS_IO_XFER_OPEN_RETRY_TIMEOUT) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
			    "%s: Got OPEN_RETRY_TIMEOUT event (htag 0x%08x)",
			    __func__, pwrk->htag);

			mutex_exit(&tgt->statlock);
			pmcs_unlock_phy(pptr);
			pwrk->ssp_event = event;
			callback = (pmcs_cb_t)pwrk->ptr;
			(*callback)(pwp, pwrk, iomb);
			return;
		}

		/*
		 * To recover from primary failures,
		 * we need to schedule handling events recovery.
		 */
		tgt->event_recovery = 1;
		mutex_exit(&tgt->statlock);
		pmcs_unlock_phy(pptr);
		pwrk->ssp_event = event;
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
		    "%s: Scheduling SSP event recovery for tgt(0x%p) "
		    "pwrk(%p) tag(0x%x)", __func__, (void *)tgt, (void *)pwrk,
		    pwrk->htag);
		mutex_exit(&pwrk->lock);
		SCHEDULE_WORK(pwp, PMCS_WORK_SSP_EVT_RECOVERY);
	}

	/* Work cannot be completed until event recovery is completed. */
}

/*
 * SSP target event recovery
 * Entered with a phy lock held
 * Pwrk lock is not needed - pwrk is on the target aq and no other thread
 * will do anything with it until this thread starts the chain of recovery.
 * Statlock may be acquired and released.
 */
void
pmcs_tgt_event_recovery(pmcs_hw_t *pwp, pmcwork_t *pwrk)
{
	pmcs_phy_t *pptr = pwrk->phy;
	pmcs_cmd_t *sp = pwrk->arg;
	pmcs_lun_t *lun = sp->cmd_lun;
	pmcs_xscsi_t *tgt = pwrk->xp;
	uint32_t event;
	uint32_t htag;
	uint32_t status;
	uint8_t dstate;
	int rv;

	ASSERT(pwrk->arg != NULL);
	ASSERT(pwrk->xp != NULL);
	pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
	    "%s: event recovery for target 0x%p", __func__, (void *)pwrk->xp);
	htag = pwrk->htag;
	event = pwrk->ssp_event;
	pwrk->ssp_event = 0xffffffff;

	if (event == PMCOUT_STATUS_XFER_ERR_BREAK ||
	    event == PMCOUT_STATUS_XFER_ERR_PHY_NOT_READY ||
	    event == PMCOUT_STATUS_XFER_ERROR_CMD_ISSUE_ACK_NAK_TIMEOUT) {
		/* Command may be still pending on device */
		rv = pmcs_ssp_tmf(pwp, pptr, SAS_QUERY_TASK, htag,
		    lun->lun_num, &status);
		if (rv != 0) {
			goto out;
		}
		if (status == SAS_RSP_TMF_COMPLETE) {
			/* Command NOT pending on a device */
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
			    "%s: No pending command for tgt 0x%p",
			    __func__, (void *)tgt);
			/* Nothing more to do, just abort it on chip */
			htag = 0;
		}
	}
	/*
	 * All other events left the command pending in the host
	 * Send abort task and abort it on the chip
	 */
	if (htag != 0) {
		if (pmcs_ssp_tmf(pwp, pptr, SAS_ABORT_TASK, htag,
		    lun->lun_num, &status))
			goto out;
	}
	(void) pmcs_abort(pwp, pptr, pwrk->htag, 0, 1);
	/*
	 * Abort either took care of work completion, or put device in
	 * a recovery state
	 */
	return;
out:
	/* Abort failed, do full device recovery */
	mutex_enter(&tgt->statlock);
	if (!pmcs_get_dev_state(pwp, pptr, tgt, &dstate))
		tgt->dev_state = dstate;

	if ((tgt->dev_state != PMCS_DEVICE_STATE_IN_RECOVERY) &&
	    (tgt->dev_state != PMCS_DEVICE_STATE_NON_OPERATIONAL)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, tgt,
		    "%s: Setting IN_RECOVERY for tgt 0x%p",
		    __func__, (void *)tgt);
		(void) pmcs_send_err_recovery_cmd(pwp,
		    PMCS_DEVICE_STATE_IN_RECOVERY, pptr, tgt);
	}
	mutex_exit(&tgt->statlock);
}

/*
 * SSP event recovery task.
 */
void
pmcs_ssp_event_recovery(pmcs_hw_t *pwp)
{
	int idx;
	pmcs_xscsi_t *tgt;
	pmcs_cmd_t *cp;
	pmcwork_t *pwrk;
	pmcs_phy_t *pphy;
	int er_flag;
	uint32_t idxpwrk;

restart:
	for (idx = 0; idx < pwp->max_dev; idx++) {
		mutex_enter(&pwp->lock);
		tgt = pwp->targets[idx];
		mutex_exit(&pwp->lock);
		if (tgt == NULL) {
			continue;
		}

		mutex_enter(&tgt->statlock);
		if (!tgt->assigned) {
			mutex_exit(&tgt->statlock);
			continue;
		}
		pphy = tgt->phy;
		er_flag = tgt->event_recovery;
		mutex_exit(&tgt->statlock);

		if ((pphy == NULL) || (er_flag == 0)) {
			continue;
		}

		pmcs_lock_phy(pphy);
		mutex_enter(&tgt->statlock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pphy, tgt,
		    "%s: found target(0x%p)", __func__, (void *) tgt);

		/* Check what cmd expects recovery */
		mutex_enter(&tgt->aqlock);
		STAILQ_FOREACH(cp, &tgt->aq, cmd_next) {
			/*
			 * Since work structure is on this target aq, and only
			 * this thread is accessing it now, we do not need
			 * to lock it
			 */
			idxpwrk = PMCS_TAG_INDEX(cp->cmd_tag);
			pwrk = &pwp->work[idxpwrk];
			if (pwrk->htag != cp->cmd_tag) {
				/*
				 * aq may contain TMF commands, so we
				 * may not find work structure with htag
				 */
				break;
			}
			if ((pwrk->ssp_event != 0) &&
			    (pwrk->ssp_event != PMCS_REC_EVENT)) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pphy, tgt,
				    "%s: pwrk(%p) htag(0x%x)",
				    __func__, (void *) pwrk, cp->cmd_tag);
				mutex_exit(&tgt->aqlock);
				mutex_exit(&tgt->statlock);
				pmcs_tgt_event_recovery(pwp, pwrk);
				/*
				 * We dropped statlock, so restart the scan
				 */
				pmcs_unlock_phy(pphy);
				goto restart;
			}
		}
		mutex_exit(&tgt->aqlock);
		tgt->event_recovery = 0;
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pphy, tgt,
		    "%s: end of SSP event recovery for target(0x%p)",
		    __func__, (void *) tgt);
		mutex_exit(&tgt->statlock);
		pmcs_unlock_phy(pphy);
	}
	pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
	    "%s: end of SSP event recovery for pwp(0x%p)", __func__,
	    (void *) pwp);
}

void
pmcs_start_dev_state_recovery(pmcs_xscsi_t *xp, pmcs_phy_t *phyp)
{
	ASSERT(mutex_owned(&xp->statlock));
	ASSERT(xp->pwp != NULL);

	if (xp->recover_wait == 0) {
		pmcs_prt(xp->pwp, PMCS_PRT_DEBUG_DEV_STATE, phyp, xp,
		    "%s: Start ds_recovery for tgt 0x%p/PHY 0x%p (%s)",
		    __func__, (void *)xp, (void *)phyp, phyp->path);
		xp->recover_wait = 1;

		/*
		 * Rather than waiting for the watchdog timer, we'll
		 * kick it right now.
		 */
		SCHEDULE_WORK(xp->pwp, PMCS_WORK_DS_ERR_RECOVERY);
		(void) ddi_taskq_dispatch(xp->pwp->tq, pmcs_worker, xp->pwp,
		    DDI_NOSLEEP);
	}
}

/*
 * Increment the phy ds error retry count.
 * If too many retries, mark phy dead and restart discovery;
 * otherwise schedule ds recovery.
 */
static void
pmcs_handle_ds_recovery_error(pmcs_phy_t *phyp, pmcs_xscsi_t *tgt,
    pmcs_hw_t *pwp, const char *func_name, char *reason_string)
{
	ASSERT(mutex_owned(&phyp->phy_lock));
	ASSERT((tgt == NULL) || mutex_owned(&tgt->statlock));

	phyp->ds_recovery_retries++;

	if (phyp->ds_recovery_retries > PMCS_MAX_DS_RECOVERY_RETRIES) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, tgt,
		    "%s: retry limit reached after %s to PHY %s failed",
		    func_name, reason_string, phyp->path);
		if (tgt != NULL) {
			tgt->recover_wait = 0;
		}
		/*
		 * Mark the PHY as dead and it and its parent as changed,
		 * then restart discovery
		 */
		phyp->dead = 1;
		PHY_CHANGED(pwp, phyp);
		if (phyp->parent)
			PHY_CHANGED(pwp, phyp->parent);
		RESTART_DISCOVERY(pwp);
	} else if ((phyp->ds_prev_good_recoveries >
	    PMCS_MAX_DS_RECOVERY_RETRIES) &&
	    (phyp->last_good_recovery + drv_usectohz(PMCS_MAX_DS_RECOVERY_TIME)
	    < ddi_get_lbolt())) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, tgt, "%s: max number of "
		    "successful recoveries reached, declaring PHY %s dead",
		    __func__, phyp->path);
		if (tgt != NULL) {
			tgt->recover_wait = 0;
		}
		/*
		 * Mark the PHY as dead and its parent as changed,
		 * then restart discovery
		 */
		phyp->dead = 1;
		PHY_CHANGED(pwp, phyp);
		if (phyp->parent)
			PHY_CHANGED(pwp, phyp->parent);
		RESTART_DISCOVERY(pwp);
	} else {
		SCHEDULE_WORK(pwp, PMCS_WORK_DS_ERR_RECOVERY);
	}
}
