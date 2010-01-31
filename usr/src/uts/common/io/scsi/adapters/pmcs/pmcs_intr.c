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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains functions that are called via interrupts.
 */

#include <sys/scsi/adapters/pmcs/pmcs.h>

#ifdef	DEBUG
#define	VALID_IOMB_CHECK(p, w, m, b, c)					\
	if (!(w & PMCS_IOMB_VALID)) {					\
		char l[64];						\
		(void) snprintf(l, sizeof (l),				\
		    "%s: INVALID IOMB (oq_ci=%u oq_pi=%u)", __func__, b, c); \
		pmcs_print_entry(pwp, PMCS_PRT_DEBUG, l, m);		\
		STEP_OQ_ENTRY(pwp, PMCS_OQ_EVENTS, b, 1);		\
		continue;						\
	}
#define	WRONG_OBID_CHECK(pwp, w, q)	\
	if (((w & PMCS_IOMB_OBID_MASK) >> PMCS_IOMB_OBID_SHIFT) != q) {	\
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,		\
		    "%s: COMPLETION WITH WRONG OBID (0x%x)", __func__,	\
		    (w & PMCS_IOMB_OBID_MASK) >> PMCS_IOMB_OBID_SHIFT);	\
	}
#else
#define	VALID_IOMB_CHECK(a, b, c, d, e)
#define	WRONG_OBID_CHECK(a, b, c)
#endif

#define	OQLIM_CHECK(p, l)				\
	if (++l == (p)->ioq_depth) {			\
		pmcs_prt(p, PMCS_PRT_DEBUG, NULL, NULL,	\
		    "%s: possible ob queue overflow",	\
		    __func__);				\
		break;					\
	}

#define	COPY_OUTBOUND(p, w, l, n, a, x, q, c)				\
	n = ((w & PMCS_IOMB_BC_MASK) >> PMCS_IOMB_BC_SHIFT);		\
	a = PMCS_QENTRY_SIZE;						\
	(void) memcpy(l, x, PMCS_QENTRY_SIZE);				\
	if (n > 1) {							\
		a <<= 1;						\
		(void) memcpy(&l[PMCS_QENTRY_SIZE],			\
		    GET_OQ_ENTRY(p, q, c, 1), PMCS_QENTRY_SIZE);	\
	}								\
	pmcs_prt(p, PMCS_PRT_DEBUG3, NULL, NULL,			\
	    "%s: ptr %p ci %d w0 %x nbuf %d",				\
	    __func__, (void *)x, ci, w0, n)

#define	EVT_PRT(hwp, msg, phy)	\
	pmcs_prt(hwp, PMCS_PRT_DEBUG, NULL, NULL, "Phy 0x%x: %s", phy, # msg)


/*
 * Map the link rate reported in the event to the SAS link rate value
 */
static uint8_t
pmcs_link_rate(uint32_t event_link_rate)
{
	uint8_t sas_link_rate = 0;

	switch (event_link_rate) {
	case 1:
		sas_link_rate = SAS_LINK_RATE_1_5GBIT;
		break;
	case 2:
		sas_link_rate = SAS_LINK_RATE_3GBIT;
		break;
	case 4:
		sas_link_rate = SAS_LINK_RATE_6GBIT;
		break;
	}

	return (sas_link_rate);
}

/*
 * Called with pwrk lock
 */
static void
pmcs_complete_work(pmcs_hw_t *pwp, pmcwork_t *pwrk, uint32_t *iomb, size_t amt)
{
#ifdef	DEBUG
	pwp->ltime[pwp->lti] = gethrtime();
	pwp->ltags[pwp->lti++] = pwrk->htag;
#endif
	pwrk->htag |= PMCS_TAG_DONE;

	/*
	 * If the command has timed out, leave it in that state.
	 */
	if (pwrk->state != PMCS_WORK_STATE_TIMED_OUT) {
		pwrk->state = PMCS_WORK_STATE_INTR;
	}

	pmcs_complete_work_impl(pwp, pwrk, iomb, amt);
}

static void
pmcs_work_not_found(pmcs_hw_t *pwp, uint32_t htag, uint32_t *iomb)
{
#ifdef	DEBUG
	int i;
	hrtime_t now;
	char buf[64];

	(void) snprintf(buf, sizeof (buf),
	    "unable to find work structure for tag 0x%x", htag);

	pmcs_print_entry(pwp, PMCS_PRT_DEBUG, buf, iomb);
	if (htag == 0) {
		return;
	}
	now = gethrtime();
	for (i = 0; i < 256; i++) {
		mutex_enter(&pwp->dbglock);
		if (pwp->ltags[i] == htag) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "same tag already completed (%llu us ago)",
			    (unsigned long long) (now - pwp->ltime[i]));
		}
		if (pwp->ftags[i] == htag) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "same tag started (line %d) (%llu ns ago)",
			    pwp->ftag_lines[i], (unsigned long long)
			    (now - pwp->ftime[i]));
		}
		mutex_exit(&pwp->dbglock);
	}
#else
	char buf[64];
	(void) snprintf(buf, sizeof (buf),
	    "unable to find work structure for tag 0x%x", htag);
	pmcs_print_entry(pwp, PMCS_PRT_DEBUG, buf, iomb);
#endif
}


static void
pmcs_process_io_completion(pmcs_hw_t *pwp, pmcs_iocomp_cb_t *ioccb, size_t amt)
{
	pmcwork_t *pwrk;
	uint32_t tag_type;
	uint32_t htag = LE_32(((uint32_t *)((void *)ioccb->iomb))[1]);

	pwrk = pmcs_tag2wp(pwp, htag);
	if (pwrk == NULL) {
		pmcs_work_not_found(pwp, htag, (void *)&ioccb->iomb);
		kmem_cache_free(pwp->iocomp_cb_cache, ioccb);
		return;
	}

	pwrk->htag |= PMCS_TAG_DONE;

	/*
	 * If the command has timed out, leave it in that state.
	 */
	if (pwrk->state != PMCS_WORK_STATE_TIMED_OUT) {
		pwrk->state = PMCS_WORK_STATE_INTR;
	}

	/*
	 * Some SATA and SAS commands are run in "WAIT" mode.
	 * We can tell this from the tag type. In this case,
	 * we just do a wakeup (not a callback).
	 */
	tag_type = PMCS_TAG_TYPE(pwrk->htag);
	if (tag_type == PMCS_TAG_TYPE_WAIT) {
		ASSERT(PMCS_TAG_TYPE(pwrk->htag) == PMCS_TAG_TYPE_WAIT);
		if (pwrk->arg && amt) {
			(void) memcpy(pwrk->arg, ioccb->iomb, amt);
		}
		cv_signal(&pwrk->sleep_cv);
		mutex_exit(&pwrk->lock);
		kmem_cache_free(pwp->iocomp_cb_cache, ioccb);
		return;
	}
	ASSERT(tag_type == PMCS_TAG_TYPE_CBACK);

#ifdef	DEBUG
	pwp->ltime[pwp->lti] = gethrtime();
	pwp->ltags[pwp->lti++] = pwrk->htag;
#endif

	ioccb->pwrk = pwrk;

	/*
	 * Only update state to IOCOMPQ if we were in the INTR state.
	 * Any other state (e.g. TIMED_OUT, ABORTED) needs to remain.
	 */
	if (pwrk->state == PMCS_WORK_STATE_INTR) {
		pwrk->state = PMCS_WORK_STATE_IOCOMPQ;
	}

	mutex_enter(&pwp->cq_lock);
	if (pwp->iocomp_cb_tail) {
		pwp->iocomp_cb_tail->next = ioccb;
		pwp->iocomp_cb_tail = ioccb;
	} else {
		pwp->iocomp_cb_head = ioccb;
		pwp->iocomp_cb_tail = ioccb;
	}
	ioccb->next = NULL;
	mutex_exit(&pwp->cq_lock);

	mutex_exit(&pwrk->lock);
	/* Completion queue will be run at end of pmcs_iodone_intr */
}


static void
pmcs_process_completion(pmcs_hw_t *pwp, void *iomb, size_t amt)
{
	pmcwork_t *pwrk;
	uint32_t htag = LE_32(((uint32_t *)iomb)[1]);

	pwrk = pmcs_tag2wp(pwp, htag);
	if (pwrk == NULL) {
		pmcs_work_not_found(pwp, htag, iomb);
		return;
	}

	pmcs_complete_work(pwp, pwrk, iomb, amt);
	/*
	 * The pwrk lock is now released
	 */
}

static void
pmcs_kill_port(pmcs_hw_t *pwp, int portid)
{
	pmcs_phy_t *pptr = pwp->ports[portid];

	if (pptr == NULL) {
		return;
	}

	/*
	 * Clear any subsidiary phys
	 */
	mutex_enter(&pwp->lock);

	for (pptr = pwp->root_phys; pptr; pptr = pptr->sibling) {
		pmcs_lock_phy(pptr);
		if (pptr->link_rate && pptr->portid == portid &&
		    pptr->subsidiary) {
			pmcs_clear_phy(pwp, pptr);
		}
		pmcs_unlock_phy(pptr);
	}

	pptr = pwp->ports[portid];
	pwp->ports[portid] = NULL;
	mutex_exit(&pwp->lock);

	pmcs_lock_phy(pptr);
	pmcs_kill_changed(pwp, pptr, 0);
	pmcs_unlock_phy(pptr);

	RESTART_DISCOVERY(pwp);
	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "PortID 0x%x Cleared", portid);
}

void
pmcs_process_sas_hw_event(pmcs_hw_t *pwp, void *iomb, size_t amt)
{
	uint32_t w1 = LE_32(((uint32_t *)iomb)[1]);
	uint32_t w3 = LE_32(((uint32_t *)iomb)[3]);
	char buf[32];
	uint8_t phynum = IOP_EVENT_PHYNUM(w1);
	uint8_t portid = IOP_EVENT_PORTID(w1);
	pmcs_iport_t *iport;
	pmcs_phy_t *pptr, *subphy, *tphyp;
	int need_ack = 0;
	int primary;

	switch (IOP_EVENT_EVENT(w1)) {
	case IOP_EVENT_PHY_STOP_STATUS:
		if (IOP_EVENT_STATUS(w1)) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "PORT %d failed to stop (0x%x)",
			    phynum, IOP_EVENT_STATUS(w1));
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
			    "PHY 0x%x Stopped", phynum);
			mutex_enter(&pwp->lock);
			pptr = pwp->root_phys + phynum;
			pmcs_lock_phy(pptr);
			mutex_exit(&pwp->lock);
			if (pptr->configured) {
				pmcs_kill_changed(pwp, pptr, 0);
			} else {
				pmcs_set_changed(pwp, pptr, B_TRUE, 0);
			}
			pmcs_unlock_phy(pptr);
			RESTART_DISCOVERY(pwp);
		}
		/* Reposition htag to the 'expected' position. */
		((uint32_t *)iomb)[1] = ((uint32_t *)iomb)[2];
		pmcs_process_completion(pwp, iomb, amt);
		break;
	case IOP_EVENT_SAS_PHY_UP:
	{
		static const uint8_t sas_identify_af_endian_xfvec[] = {
			0x5c, 0x5a, 0x56, 0x00
		};
		pmcs_phy_t *rp;
		sas_identify_af_t af;
		uint64_t phy_id, wwn;

		/*
		 * If we're not at running state, don't do anything
		 */
		mutex_enter(&pwp->lock);
		if (pwp->state != STATE_RUNNING) {
			mutex_exit(&pwp->lock);
			break;
		}
		pptr = pwp->root_phys + phynum;
		pmcs_lock_phy(pptr);

		/*
		 * No need to lock the primary root PHY.  It can never go
		 * away, and we're only concerned with the port width and
		 * the portid, both of which only ever change in this function.
		 */
		rp = pwp->ports[portid];

		mutex_exit(&pwp->lock);

		pmcs_endian_transform(pwp, &af, &((uint32_t *)iomb)[4],
		    sas_identify_af_endian_xfvec);

		/* Copy the remote address into our phy handle */
		(void) memcpy(pptr->sas_address, af.sas_address, 8);
		wwn = pmcs_barray2wwn(pptr->sas_address);
		phy_id = (uint64_t)af.phy_identifier;

		/*
		 * Check to see if there is a PortID already active.
		 */
		if (rp) {
			if (rp->portid != portid) {
				pmcs_unlock_phy(pptr);
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
				    "PortID 0x%x: PHY 0x%x SAS LINK UP IS FOR "
				    "A DIFFERENT PORTID 0x%x", rp->portid,
				    phynum, portid);
				break;
			}

			/*
			 * If the dtype isn't NOTHING, then this is actually
			 * the primary PHY for this port.  It probably went
			 * down and came back up, so be sure not to mark it
			 * as a subsidiary.
			 */
			if (pptr->dtype == NOTHING) {
				pptr->subsidiary = 1;
			}
			pptr->link_rate =
			    pmcs_link_rate(IOP_EVENT_LINK_RATE(w1));
			pptr->portid = portid;
			pptr->dead = 0;
			pmcs_unlock_phy(pptr);

			rp->width = IOP_EVENT_NPIP(w3);

			/* Add this PHY to the phymap */
			if (sas_phymap_phy_add(pwp->hss_phymap, phynum,
			    pwp->sas_wwns[0], wwn) != DDI_SUCCESS) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
				    "Unable to add phy %u for 0x%" PRIx64 ".0x%"
				    PRIx64, phynum, pwp->sas_wwns[rp->phynum],
				    wwn);
			}

			/*
			 * Get our iport, if attached, and set it up.  Update
			 * the PHY's phymask props while we're locked.
			 */
			pmcs_lock_phy(pptr);
			pmcs_update_phy_pm_props(pptr, (1ULL << phynum),
			    (1ULL << phy_id), B_TRUE);
			pmcs_unlock_phy(pptr);
			iport = pmcs_get_iport_by_wwn(pwp, wwn);
			if (iport) {
				primary = !pptr->subsidiary;

				mutex_enter(&iport->lock);
				if (primary) {
					iport->pptr = pptr;
				}
				if (iport->ua_state == UA_ACTIVE) {
					pmcs_add_phy_to_iport(iport, pptr);
					pptr->iport = iport;
				}
				mutex_exit(&iport->lock);
				pmcs_rele_iport(iport);
			}

			pmcs_update_phy_pm_props(rp, (1ULL << phynum),
			    (1ULL << phy_id), B_TRUE);
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
			    "PortID 0x%x: PHY 0x%x SAS LINK UP WIDENS PORT "
			    "TO %d PHYS", portid, phynum, rp->width);

			break;
		}

		/*
		 * Check to see if anything is here already
		 */
		if (pptr->dtype != NOTHING && pptr->configured) {
			pmcs_unlock_phy(pptr);
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "PortID 0x%x: SAS PHY 0x%x UP HITS EXISTING "
			    "CONFIGURED TREE", portid, phynum);
			break;
		}

		if (af.address_frame_type != SAS_AF_IDENTIFY) {
			pmcs_unlock_phy(pptr);
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "SAS link up on phy 0x%x, "
			    "but unexpected frame type 0x%x found", phynum,
			    af.address_frame_type);
			break;
		}
		pptr->width = IOP_EVENT_NPIP(w3);
		pptr->portid = portid;
		pptr->dead = 0;
		pptr->link_rate = pmcs_link_rate(IOP_EVENT_LINK_RATE(w1));

		/*
		 * Check to see whether this is an expander or an endpoint
		 */
		switch (af.device_type) {
		case SAS_IF_DTYPE_ENDPOINT:
			pptr->pend_dtype = SAS;
			pptr->dtype = SAS;
			break;
		case SAS_IF_DTYPE_EDGE:
		case SAS_IF_DTYPE_FANOUT:
			pptr->pend_dtype = EXPANDER;
			pptr->dtype = EXPANDER;
			break;
		default:
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "unknown device type 0x%x", af.device_type);
			pptr->pend_dtype = NOTHING;
			pptr->dtype = NOTHING;
			break;
		}

		/*
		 * If this is a direct-attached SAS drive, do the spinup
		 * release now.
		 */
		if (pptr->dtype == SAS) {
			pptr->spinup_hold = 1;
			pmcs_spinup_release(pwp, pptr);
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, NULL,
			    "Release spinup hold on PHY 0x%x", phynum);
		}

		pmcs_set_changed(pwp, pptr, B_TRUE, 0);
		if (pptr->width > 1) {
			pmcs_prt(pwp, PMCS_PRT_INFO, pptr, NULL,
			    "PortID 0x%x: PHY 0x%x SAS"
			    " LINK UP @ %s Gb with %d phys/s", portid, phynum,
			    pmcs_get_rate(pptr->link_rate), pptr->width);
		} else {
			pmcs_prt(pwp, PMCS_PRT_INFO, pptr, NULL,
			    "PortID 0x%x: PHY 0x%x SAS"
			    " LINK UP @ %s Gb/s", portid, phynum,
			    pmcs_get_rate(pptr->link_rate));
		}
		pmcs_unlock_phy(pptr);

		/* Add this PHY to the phymap */
		if (sas_phymap_phy_add(pwp->hss_phymap, phynum,
		    pwp->sas_wwns[0], wwn) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "Unable to add phy %u for 0x%" PRIx64 ".0x%"
			    PRIx64, phynum, pwp->sas_wwns[pptr->phynum], wwn);
		}

		/* Get a pointer to our iport and set it up if attached */
		iport = pmcs_get_iport_by_wwn(pwp, wwn);
		if (iport) {
			primary = !pptr->subsidiary;

			mutex_enter(&iport->lock);
			if (primary) {
				iport->pptr = pptr;
			}
			if (iport->ua_state == UA_ACTIVE) {
				pmcs_add_phy_to_iport(iport, pptr);
				pptr->iport = iport;
			}
			mutex_exit(&iport->lock);
			pmcs_rele_iport(iport);
		}

		pmcs_lock_phy(pptr);
		pmcs_update_phy_pm_props(pptr, (1ULL << phynum),
		    (1ULL << phy_id), B_TRUE);
		pmcs_smhba_log_sysevent(pwp, ESC_SAS_PHY_EVENT,
		    SAS_PHY_ONLINE, pptr);
		pmcs_unlock_phy(pptr);

		mutex_enter(&pwp->lock);
		pwp->ports[portid] = pptr;
		mutex_exit(&pwp->lock);
		RESTART_DISCOVERY(pwp);

		break;
	}
	case IOP_EVENT_SATA_PHY_UP: {
		uint64_t wwn;
		/*
		 * If we're not at running state, don't do anything
		 */
		mutex_enter(&pwp->lock);
		if (pwp->state != STATE_RUNNING) {
			mutex_exit(&pwp->lock);
			break;
		}

		/*
		 * Check to see if anything is here already
		 */
		pmcs_lock_phy(pwp->root_phys + phynum);
		pptr = pwp->root_phys + phynum;
		mutex_exit(&pwp->lock);

		if (pptr->dtype != NOTHING && pptr->configured) {
			pmcs_unlock_phy(pptr);
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "PortID 0x%x: SATA PHY 0x%x"
			    " UP HITS EXISTING CONFIGURED TREE",
			    portid, phynum);
			break;
		}

		pptr->width = 1;
		pptr->dead = 0;

		/*
		 * Install the PHY number in the least significant byte
		 * with a NAA=3 (locally assigned address) in the most
		 * significant nubble.
		 *
		 * Later, we'll either use that or dig a
		 * WWN out of words 108..111.
		 */
		pptr->sas_address[0] = 0x30;
		pptr->sas_address[1] = 0;
		pptr->sas_address[2] = 0;
		pptr->sas_address[3] = 0;
		pptr->sas_address[4] = 0;
		pptr->sas_address[5] = 0;
		pptr->sas_address[6] = 0;
		pptr->sas_address[7] = phynum;
		pptr->portid = portid;
		pptr->link_rate = pmcs_link_rate(IOP_EVENT_LINK_RATE(w1));
		pptr->dtype = SATA;
		pmcs_set_changed(pwp, pptr, B_TRUE, 0);
		pmcs_prt(pwp, PMCS_PRT_INFO, pptr, NULL,
		    "PortID 0x%x: PHY 0x%x SATA LINK UP @ %s Gb/s",
		    pptr->portid, phynum, pmcs_get_rate(pptr->link_rate));
		wwn = pmcs_barray2wwn(pptr->sas_address);
		pmcs_unlock_phy(pptr);

		/* Add this PHY to the phymap */
		if (sas_phymap_phy_add(pwp->hss_phymap, phynum,
		    pwp->sas_wwns[0], wwn) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "Unable to add phy %u for 0x%" PRIx64 ".0x%"
			    PRIx64, phynum, pwp->sas_wwns[pptr->phynum],
			    wwn);
		}

		/* Get our iport, if attached, and set it up */
		iport = pmcs_get_iport_by_wwn(pwp, wwn);
		if (iport) {
			mutex_enter(&iport->lock);
			iport->pptr = pptr;
			if (iport->ua_state == UA_ACTIVE) {
				pmcs_add_phy_to_iport(iport, pptr);
				pptr->iport = iport;
				ASSERT(iport->nphy == 1);
				iport->nphy = 1;
			}
			mutex_exit(&iport->lock);
			pmcs_rele_iport(iport);
		}

		pmcs_lock_phy(pptr);
		pmcs_update_phy_pm_props(pptr, (1ULL << phynum), 1ULL, B_TRUE);
		pmcs_smhba_log_sysevent(pwp, ESC_SAS_PHY_EVENT,
		    SAS_PHY_ONLINE, pptr);
		pmcs_unlock_phy(pptr);

		mutex_enter(&pwp->lock);
		pwp->ports[pptr->portid] = pptr;
		mutex_exit(&pwp->lock);
		RESTART_DISCOVERY(pwp);
		break;
	}

	case IOP_EVENT_SATA_SPINUP_HOLD:
		tphyp = (pmcs_phy_t *)(pwp->root_phys + phynum);
		/*
		 * No need to lock the entire tree for this
		 */
		mutex_enter(&tphyp->phy_lock);
		tphyp->spinup_hold = 1;
		pmcs_spinup_release(pwp, tphyp);
		mutex_exit(&tphyp->phy_lock);
		break;
	case IOP_EVENT_PHY_DOWN: {
		uint64_t wwn;

		/*
		 * If we're not at running state, don't do anything
		 */
		mutex_enter(&pwp->lock);
		if (pwp->state != STATE_RUNNING) {
			mutex_exit(&pwp->lock);
			break;
		}
		pptr = pwp->ports[portid];

		subphy = pwp->root_phys + phynum;
		/*
		 * subphy is a pointer to the PHY corresponding to the incoming
		 * event. pptr points to the primary PHY for the corresponding
		 * port.  So, subphy and pptr may or may not be the same PHY,
		 * but that doesn't change what we need to do with each.
		 */
		ASSERT(subphy);
		mutex_exit(&pwp->lock);

		if (pptr == NULL) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "PortID 0x%x: PHY 0x%x LINK DOWN- no portid ptr",
			    portid, phynum);
			break;
		}
		if (IOP_EVENT_PORT_STATE(w3) == IOP_EVENT_PS_NIL) {
			pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
			    "PortID 0x%x: PHY 0x%x NOT VALID YET",
			    portid, phynum);
			need_ack = 1;
			break;
		}
		if (IOP_EVENT_PORT_STATE(w3) == IOP_EVENT_PS_IN_RESET) {
			pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
			    "PortID 0x%x: PHY 0x%x IN RESET",
			    portid, phynum);
			/* Entire port is down due to a host-initiated reset */
			mutex_enter(&pptr->phy_lock);
			/* Clear the phymask props in pptr */
			pmcs_update_phy_pm_props(pptr, pptr->att_port_pm_tmp,
			    pptr->tgt_port_pm_tmp, B_FALSE);
			iport = pptr->iport;
			mutex_exit(&pptr->phy_lock);
			if (iport) {
				mutex_enter(&iport->lock);
				pmcs_iport_teardown_phys(iport);
				mutex_exit(&iport->lock);
			}

			/* Clear down all PHYs in the port */
			for (pptr = pwp->root_phys; pptr;
			    pptr = pptr->sibling) {
				pmcs_lock_phy(pptr);
				if (pptr->portid == portid) {
					pptr->dtype = NOTHING;
					pptr->portid =
					    PMCS_IPORT_INVALID_PORT_ID;
					if (pptr->valid_device_id) {
						pptr->deregister_wait = 1;
					}
				}
				pmcs_unlock_phy(pptr);
				SCHEDULE_WORK(pwp, PMCS_WORK_DEREGISTER_DEV);
				(void) ddi_taskq_dispatch(pwp->tq, pmcs_worker,
				    pwp, DDI_NOSLEEP);
			}

			break;
		}

		if (IOP_EVENT_PORT_STATE(w3) == IOP_EVENT_PS_LOSTCOMM) {
			pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
			    "PortID 0x%x: PHY 0x%x TEMPORARILY DOWN",
			    portid, phynum);
			need_ack = 1;
			break;
		}

		if (IOP_EVENT_PORT_STATE(w3) == IOP_EVENT_PS_VALID) {

			/*
			 * This is not the last phy in the port, so if this
			 * is the primary PHY, promote another PHY to primary.
			 */
			if (pptr == subphy) {
				primary = !subphy->subsidiary;
				ASSERT(primary);

				tphyp = pptr;
				pptr = pmcs_promote_next_phy(tphyp);

				if (pptr) {
					/* Update primary pptr in ports */
					pwp->ports[portid] = pptr;
					pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr,
					    NULL, "PortID 0x%x: PHY 0x%x "
					    "promoted to primary", portid,
					    pptr->phynum);
				} else {
					pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr,
					    NULL, "PortID 0x%x: PHY 0x%x: "
					    "unable to promote phy", portid,
					    phynum);
				}
			}

			/*
			 * Drop port width on the primary phy handle
			 * No need to lock the entire tree for this
			 */
			mutex_enter(&pptr->phy_lock);
			pmcs_update_phy_pm_props(pptr, subphy->att_port_pm_tmp,
			    subphy->tgt_port_pm_tmp, B_FALSE);
			pptr->width = IOP_EVENT_NPIP(w3);
			mutex_exit(&pptr->phy_lock);

			/* Clear the iport reference and portid on the subphy */
			mutex_enter(&subphy->phy_lock);
			iport = subphy->iport;
			subphy->iport = NULL;
			subphy->portid = PMCS_PHY_INVALID_PORT_ID;
			subphy->dtype = NOTHING;
			mutex_exit(&subphy->phy_lock);

			/*
			 * If the iport was set on this phy, decrement its
			 * nphy count and remove this phy from the phys list.
			 */
			if (iport) {
				mutex_enter(&iport->lock);
				if (iport->ua_state == UA_ACTIVE) {
					pmcs_remove_phy_from_iport(iport,
					    subphy);
				}
				mutex_exit(&iport->lock);
			}

			pmcs_lock_phy(subphy);
			wwn = pmcs_barray2wwn(pptr->sas_address);
			if (subphy->subsidiary)
				pmcs_clear_phy(pwp, subphy);
			pmcs_unlock_phy(subphy);

			/* Remove this PHY from the phymap */
			if (sas_phymap_phy_rem(pwp->hss_phymap, phynum) !=
			    DDI_SUCCESS) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
				    "Unable to remove phy %u for 0x%" PRIx64
				    ".0x%" PRIx64, phynum,
				    pwp->sas_wwns[pptr->phynum], wwn);
			}

			pmcs_prt(pwp, PMCS_PRT_INFO, pptr, NULL,
			    "PortID 0x%x: PHY 0x%x LINK DOWN NARROWS PORT "
			    "TO %d PHYS", portid, phynum, pptr->width);
			break;
		}
		if (IOP_EVENT_PORT_STATE(w3) != IOP_EVENT_PS_INVALID) {
			pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
			    "PortID 0x%x: PHY 0x%x LINK DOWN NOT HANDLED "
			    "(state 0x%x)", portid, phynum,
			    IOP_EVENT_PORT_STATE(w3));
			need_ack = 1;
			break;
		}
		/* Remove this PHY from the phymap */
		if (sas_phymap_phy_rem(pwp->hss_phymap, phynum) !=
		    DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "Unable to remove phy %u for 0x%" PRIx64
			    ".0x%" PRIx64, phynum,
			    pwp->sas_wwns[pptr->phynum], wwn);
		}

		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "PortID 0x%x: PHY 0x%x LINK DOWN (port invalid)",
		    portid, phynum);

		/*
		 * Last PHY on the port.
		 * Assumption: pptr and subphy are both "valid".  In fact,
		 * they should be one and the same.
		 *
		 * Drop port width on the primary phy handle
		 * Report the event and clear its PHY pm props while we've
		 * got the lock
		 */
		ASSERT(pptr == subphy);
		mutex_enter(&pptr->phy_lock);
		pptr->width = 0;
		pmcs_update_phy_pm_props(pptr, pptr->att_port_pm_tmp,
		    pptr->tgt_port_pm_tmp, B_FALSE);
		pmcs_smhba_log_sysevent(pwp, ESC_SAS_PHY_EVENT,
		    SAS_PHY_OFFLINE, pptr);
		mutex_exit(&pptr->phy_lock);

		/* Clear the iport reference and portid on the subphy */
		pmcs_lock_phy(subphy);
		iport = subphy->iport;
		subphy->deregister_wait = 1;
		subphy->iport = NULL;
		subphy->portid = PMCS_PHY_INVALID_PORT_ID;
		subphy->dtype = NOTHING;
		pmcs_unlock_phy(subphy);
		SCHEDULE_WORK(pwp, PMCS_WORK_DEREGISTER_DEV);
		(void) ddi_taskq_dispatch(pwp->tq, pmcs_worker,
		    pwp, DDI_NOSLEEP);

		/*
		 * If the iport was set on this phy, decrement its
		 * nphy count and remove this phy from the phys list.
		 * Also, clear the iport's pptr as this port is now
		 * down.
		 */
		if (iport) {
			mutex_enter(&iport->lock);
			if (iport->ua_state == UA_ACTIVE) {
				pmcs_remove_phy_from_iport(iport, subphy);
				iport->pptr = NULL;
				iport->ua_state = UA_PEND_DEACTIVATE;
			}
			mutex_exit(&iport->lock);
		}

		pmcs_lock_phy(subphy);
		if (subphy->subsidiary)
			pmcs_clear_phy(pwp, subphy);
		pmcs_unlock_phy(subphy);

		/*
		 * Since we're now really dead, it's time to clean up.
		 */
		pmcs_kill_port(pwp, portid);
		need_ack = 1;

		break;
	}
	case IOP_EVENT_BROADCAST_CHANGE:
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "PortID 0x%x: PHY 0x%x Broadcast Change", portid, phynum);
		need_ack = 1;
		mutex_enter(&pwp->lock);
		pptr = pwp->ports[portid];
		if (pptr) {
			pmcs_lock_phy(pptr);
			if (pptr->phynum == phynum) {
				pmcs_set_changed(pwp, pptr, B_TRUE, 0);
			}
			pmcs_smhba_log_sysevent(pwp, ESC_SAS_HBA_PORT_BROADCAST,
			    SAS_PORT_BROADCAST_CHANGE, pptr);
			pmcs_unlock_phy(pptr);
		}
		mutex_exit(&pwp->lock);
		RESTART_DISCOVERY(pwp);
		break;
	case IOP_EVENT_BROADCAST_SES:
		EVT_PRT(pwp, IOP_EVENT_BROADCAST_SES, phynum);
		mutex_enter(&pwp->lock);
		pptr = pwp->ports[portid];
		mutex_exit(&pwp->lock);
		if (pptr) {
			pmcs_lock_phy(pptr);
			pmcs_smhba_log_sysevent(pwp, ESC_SAS_HBA_PORT_BROADCAST,
			    SAS_PORT_BROADCAST_SES, pptr);
			pmcs_unlock_phy(pptr);
		}
		break;
	case IOP_EVENT_PHY_ERR_INBOUND_CRC:
	{
		char buf[32];
		(void) snprintf(buf, sizeof (buf), "Inbound PHY CRC error");
		need_ack = 1;
		break;
	}
	case IOP_EVENT_HARD_RESET_RECEIVED:
		EVT_PRT(pwp, IOP_EVENT_HARD_RESET_RECEIVED, phynum);
		break;
	case IOP_EVENT_EVENT_ID_FRAME_TIMO:
		EVT_PRT(pwp, IOP_EVENT_EVENT_ID_FRAME_TIMO, phynum);
		break;
	case IOP_EVENT_BROADCAST_EXP:
		pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
		    "PortID 0x%x: PHY 0x%x Broadcast Exp Change",
		    portid, phynum);
		/*
		 * Comparing Section 6.8.1.4 of SMHBA (rev 7) spec and Section
		 * 7.2.3 of SAS2 (Rev 15) spec,
		 * _BROADCAST_EXPANDER event corresponds to _D01_4 primitive
		 */
		mutex_enter(&pwp->lock);
		pptr = pwp->ports[portid];
		mutex_exit(&pwp->lock);
		if (pptr) {
			pmcs_lock_phy(pptr);
			pmcs_smhba_log_sysevent(pwp, ESC_SAS_HBA_PORT_BROADCAST,
			    SAS_PORT_BROADCAST_D01_4, pptr);
			pmcs_unlock_phy(pptr);
		}
		break;
	case IOP_EVENT_PHY_START_STATUS:
		switch (IOP_EVENT_STATUS(w1)) {
		case IOP_PHY_START_OK:
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
			    "PHY 0x%x Started", phynum);
			break;
		case IOP_PHY_START_ALREADY:
			pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
			    "PHY 0x%x Started (Already)", phynum);
			break;
		case IOP_PHY_START_INVALID:
			pmcs_prt(pwp, PMCS_PRT_WARN, NULL, NULL,
			    "PHY 0x%x failed to start (invalid phy)", phynum);
			break;
		case IOP_PHY_START_ERROR:
			pmcs_prt(pwp, PMCS_PRT_WARN, NULL, NULL,
			    "PHY 0x%x Start Error", phynum);
			break;
		default:
			pmcs_prt(pwp, PMCS_PRT_WARN, NULL, NULL,
			    "PHY 0x%x failed to start (0x%x)", phynum,
			    IOP_EVENT_STATUS(w1));
			break;
		}
		/* Reposition htag to the 'expected' position. */
		((uint32_t *)iomb)[1] = ((uint32_t *)iomb)[2];
		pmcs_process_completion(pwp, iomb, amt);
		break;
	case IOP_EVENT_PHY_ERR_INVALID_DWORD:
		need_ack = 1;
		EVT_PRT(pwp, IOP_EVENT_PHY_ERR_INVALID_DWORD, phynum);
		break;
	case IOP_EVENT_PHY_ERR_DISPARITY_ERROR:
		need_ack = 1;
		EVT_PRT(pwp, IOP_EVENT_PHY_ERR_DISPARITY_ERROR, phynum);
		break;
	case IOP_EVENT_PHY_ERR_CODE_VIOLATION:
		need_ack = 1;
		EVT_PRT(pwp, IOP_EVENT_PHY_ERR_CODE_VIOLATION, phynum);
		break;
	case IOP_EVENT_PHY_ERR_LOSS_OF_DWORD_SYN:
		need_ack = 1;
		EVT_PRT(pwp, IOP_EVENT_PHY_ERR_LOSS_OF_DWORD_SYN, phynum);
		break;
	case IOP_EVENT_PHY_ERR_PHY_RESET_FAILD:
		need_ack = 1;
		EVT_PRT(pwp, IOP_EVENT_PHY_ERR_PHY_RESET_FAILD, phynum);
		break;
	case IOP_EVENT_PORT_RECOVERY_TIMER_TMO:
		EVT_PRT(pwp, IOP_EVENT_PORT_RECOVERY_TIMER_TMO, phynum);
		break;
	case IOP_EVENT_PORT_RECOVER:
		EVT_PRT(pwp, IOP_EVENT_PORT_RECOVER, phynum);
		break;
	case IOP_EVENT_PORT_INVALID:
		mutex_enter(&pwp->lock);
		if (pwp->state != STATE_RUNNING) {
			mutex_exit(&pwp->lock);
			break;
		}
		mutex_exit(&pwp->lock);
		pmcs_kill_port(pwp, portid);
		pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
		    "PortID 0x%x: PORT Now Invalid", portid);
		break;
	case IOP_EVENT_PORT_RESET_TIMER_TMO:
		EVT_PRT(pwp, IOP_EVENT_PORT_RESET_TIMER_TMO, phynum);
		break;
	case IOP_EVENT_PORT_RESET_COMPLETE:
		EVT_PRT(pwp, IOP_EVENT_PORT_RESET_COMPLETE, phynum);
		break;
	case IOP_EVENT_BROADCAST_ASYNC_EVENT:
		EVT_PRT(pwp, IOP_EVENT_BROADCAST_ASYNC_EVENT, phynum);
		/*
		 * Comparing Section 6.8.1.4 of SMHBA (rev 7) spec and Section
		 * 7.2.3 of SAS2 (Rev 15) spec,
		 * _BROADCAST_ASYNC event corresponds to _D04_7 primitive
		 */
		mutex_enter(&pwp->lock);
		pptr = pwp->ports[portid];
		mutex_exit(&pwp->lock);
		if (pptr) {
			pmcs_lock_phy(pptr);
			pmcs_smhba_log_sysevent(pwp, ESC_SAS_HBA_PORT_BROADCAST,
			    SAS_PORT_BROADCAST_D04_7, pptr);
			pmcs_unlock_phy(pptr);
		}
		break;
	default:
		(void) snprintf(buf, sizeof (buf),
		    "unknown SAS H/W Event PHY 0x%x", phynum);
		pmcs_print_entry(pwp, PMCS_PRT_DEBUG, buf, iomb);
		break;
	}
	if (need_ack) {
		mutex_enter(&pwp->lock);
		/*
		 * Don't lock the entire tree for this.  Just grab the mutex
		 * on the root PHY.
		 */
		tphyp = pwp->root_phys + phynum;
		mutex_enter(&tphyp->phy_lock);
		tphyp->hw_event_ack = w1;
		mutex_exit(&tphyp->phy_lock);
		mutex_exit(&pwp->lock);
		pmcs_ack_events(pwp);
	}
}

static void
pmcs_process_echo_completion(pmcs_hw_t *pwp, void *iomb, size_t amt)
{
	echo_test_t fred;
	pmcwork_t *pwrk;
	uint32_t *msg = iomb, htag = LE_32(msg[1]);
	pwrk = pmcs_tag2wp(pwp, htag);
	if (pwrk) {
		(void) memcpy(&fred, &((uint32_t *)iomb)[2], sizeof (fred));
		fred.ptr[0]++;
		msg[2] = LE_32(PMCOUT_STATUS_OK);
		pmcs_complete_work(pwp, pwrk, msg, amt);
	} else {
		pmcs_print_entry(pwp, PMCS_PRT_DEBUG,
		    "ECHO completion with no work structure", iomb);
	}
}

static void
pmcs_process_ssp_event(pmcs_hw_t *pwp, void *iomb, size_t amt)
{
	_NOTE(ARGUNUSED(amt));
	uint32_t status, htag, *w;
	pmcwork_t *pwrk;
	pmcs_phy_t *phyp = NULL;
	char *path;

	w = iomb;
	htag = LE_32(w[1]);
	status = LE_32(w[2]);


	pwrk = pmcs_tag2wp(pwp, htag);
	if (pwrk == NULL) {
		path = "????";
	} else {
		phyp = pwrk->phy;
		path = pwrk->phy->path;
	}

	if (status != PMCOUT_STATUS_XFER_CMD_FRAME_ISSUED) {
		char buf[20];
		const char *emsg = pmcs_status_str(status);

		if (emsg == NULL) {
			(void) snprintf(buf, sizeof (buf), "Status 0x%x",
			    status);
			emsg = buf;
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, NULL, "%s: Bad SAS Status "
		    "(tag 0x%x) %s on %s", __func__, htag, emsg, path);
		if (pwrk != NULL) {
			/*
			 * There may be pending command on a target device.
			 * Or, it may be a double fault.
			 */
			pmcs_start_ssp_event_recovery(pwp, pwrk, iomb, amt);
		}
	} else {
		pmcs_prt(pwp, PMCS_PRT_DEBUG2, phyp, NULL,
		    "%s: tag %x put onto the wire for %s",
		    __func__, htag, path);
		if (pwrk) {
			pwrk->onwire = 1;
			mutex_exit(&pwrk->lock);
		}
	}
}

static void
pmcs_process_sata_event(pmcs_hw_t *pwp, void *iomb, size_t amt)
{
	_NOTE(ARGUNUSED(amt));
	pmcwork_t *pwrk = NULL;
	pmcs_phy_t *pptr;
	uint32_t status, htag, *w;
	char *path;

	w = iomb;
	htag = LE_32(w[1]);
	status = LE_32(w[2]);

	/*
	 * If the status is PMCOUT_STATUS_XFER_ERROR_ABORTED_NCQ_MODE,
	 * we have to issue a READ LOG EXT ATA (page 0x10) command
	 * to the device. In this case, htag is not valid.
	 *
	 * If the status is PMCOUT_STATUS_XFER_CMD_FRAME_ISSUED, we're
	 * just noting that an I/O got put onto the wire.
	 *
	 * Othewise, other errors are indicative that things need to
	 * be aborted.
	 */
	path = NULL;
	if (htag) {
		pwrk = pmcs_tag2wp(pwp, htag);
		if (pwrk) {
			pmcs_lock_phy(pwrk->phy);
			pptr = pwrk->phy;
			path = pptr->path;
		}
	}
	if (path == NULL) {
		mutex_enter(&pwp->lock);
		pptr = pmcs_find_phy_by_devid(pwp, LE_32(w[4]));
		/* This PHY is now locked */
		mutex_exit(&pwp->lock);
		if (pptr) {
			path = pptr->path;
		} else {
			path = "????";
		}
	}

	if (status != PMCOUT_STATUS_XFER_CMD_FRAME_ISSUED) {
		char buf[20];
		const char *emsg = pmcs_status_str(status);

		ASSERT(pptr != NULL);
		if (emsg == NULL) {
			(void) snprintf(buf, sizeof (buf), "Status 0x%x",
			    status);
			emsg = buf;
		}
		if (status == PMCOUT_STATUS_XFER_ERROR_ABORTED_NCQ_MODE) {
			ASSERT(pptr != NULL);
			pptr->need_rl_ext = 1;
			htag = 0;
		} else {
			pptr->abort_pending = 1;
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
		    "%s: Bad SATA Status (tag 0x%x) %s on %s",
		    __func__, htag, emsg, path);
		SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
		/*
		 * Unlike SSP devices, we let the abort we
		 * schedule above force the completion of
		 * problem commands.
		 */
		if (pwrk) {
			mutex_exit(&pwrk->lock);
		}
	} else if (status == PMCOUT_STATUS_XFER_CMD_FRAME_ISSUED) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG2, pptr, NULL,
		    "%s: tag %x put onto the wire for %s",
		    __func__, htag, path);
		if (pwrk) {
			pwrk->onwire = 1;
			mutex_exit(&pwrk->lock);
		}
	}

	if (pptr) {
		pmcs_unlock_phy(pptr);
	}
}

static void
pmcs_process_abort_completion(pmcs_hw_t *pwp, void *iomb, size_t amt)
{
	pmcs_phy_t *pptr;
	struct pmcwork *pwrk;
	uint32_t htag = LE_32(((uint32_t *)iomb)[1]);
	uint32_t status = LE_32(((uint32_t *)iomb)[2]);
	uint32_t scp = LE_32(((uint32_t *)iomb)[3]) & 0x1;
	char *path;

	pwrk = pmcs_tag2wp(pwp, htag);
	if (pwrk == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: cannot find work structure for ABORT", __func__);
		return;
	}

	pptr = pwrk->phy;
	if (pptr) {
		pmcs_lock_phy(pptr);
		pptr->abort_pending = 0;
		pptr->abort_sent = 0;

		/*
		 * Don't do this if the status was ABORT_IN_PROGRESS and
		 * the scope bit was set
		 */
		if ((status != PMCOUT_STATUS_IO_ABORT_IN_PROGRESS) || !scp) {
			pptr->abort_all_start = 0;
			cv_signal(&pptr->abort_all_cv);
		}
		path = pptr->path;
		pmcs_unlock_phy(pptr);
	} else {
		path = "(no phy)";
	}

	switch (status) {
	case PMCOUT_STATUS_OK:
		if (scp) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "%s: abort all succeeded for %s. (htag=0x%x)",
			    __func__, path, htag);
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "%s: abort tag 0x%x succeeded for %s. (htag=0x%x)",
			    __func__, pwrk->abt_htag, path, htag);
		}
		break;

	case PMCOUT_STATUS_IO_NOT_VALID:
		if (scp) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "%s: ABORT %s failed (DEV NOT VALID) for %s. "
			    "(htag=0x%x)", __func__, scp ? "all" : "tag",
			    path, htag);
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL,
			    "%s: ABORT %s failed (I/O NOT VALID) for %s. "
			    "(htag=0x%x)", __func__, scp ? "all" : "tag",
			    path, htag);
		}
		break;

	case PMCOUT_STATUS_IO_ABORT_IN_PROGRESS:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL, "%s: ABORT %s failed "
		    "for %s, htag 0x%x (ABORT IN PROGRESS)", __func__,
		    scp ? "all" : "tag", path, htag);
		break;

	default:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, NULL, "%s: Unknown status "
		    "%d for ABORT %s, htag 0x%x, PHY %s", __func__, status,
		    scp ? "all" : "tag", htag, path);
		break;
	}

	pmcs_complete_work(pwp, pwrk, iomb, amt);
}

static void
pmcs_process_general_event(pmcs_hw_t *pwp, uint32_t *iomb)
{
	uint32_t htag;
	char local[60];
	struct pmcwork *pwrk;
	int i;

	if (LE_32(iomb[1]) == INBOUND_IOMB_V_BIT_NOT_SET) {
		(void) snprintf(local, sizeof (local),
		    "VALID bit not set on INBOUND IOMB");
	} else if (LE_32(iomb[1]) ==
	    INBOUND_IOMB_OPC_NOT_SUPPORTED) {
		(void) snprintf(local, sizeof (local),
		    "opcode not set on inbound IOMB");
	} else {
		(void) snprintf(local, sizeof (local),
		    "unknown GENERAL EVENT status (0x%x)",
		    LE_32(iomb[1]));
	}
	/* Pull up bad IOMB into usual position */
	for (i = 0; i < PMCS_MSG_SIZE - 2; i++) {
		iomb[i] = iomb[i+2];
	}
	/* overwrite status with an error */
	iomb[2] = LE_32(PMCOUT_STATUS_PROG_ERROR);
	iomb[PMCS_MSG_SIZE - 2] = 0;
	iomb[PMCS_MSG_SIZE - 1] = 0;
	htag = LE_32(iomb[1]);
	pmcs_print_entry(pwp, PMCS_PRT_DEBUG, local, iomb);
	pwrk = pmcs_tag2wp(pwp, htag);
	if (pwrk) {
		pmcs_complete_work(pwp, pwrk, iomb, PMCS_QENTRY_SIZE);
	}
}

void
pmcs_general_intr(pmcs_hw_t *pwp)
{
	char local[PMCS_QENTRY_SIZE << 1];
	uint32_t w0, pi, ci;
	uint32_t *ptr, nbuf, lim = 0;
	size_t amt;

	ci = pmcs_rd_oqci(pwp, PMCS_OQ_GENERAL);
	pi = pmcs_rd_oqpi(pwp, PMCS_OQ_GENERAL);

	while (ci != pi) {
		OQLIM_CHECK(pwp, lim);
		ptr = GET_OQ_ENTRY(pwp, PMCS_OQ_GENERAL, ci, 0);
		w0 = LE_32(ptr[0]);
		VALID_IOMB_CHECK(pwp, w0, ptr, ci, pi);
		WRONG_OBID_CHECK(pwp, w0, PMCS_OQ_GENERAL);
		COPY_OUTBOUND(pwp, w0, local, nbuf, amt, ptr,
		    PMCS_OQ_GENERAL, ci);

		switch (w0 & PMCS_IOMB_OPCODE_MASK) {
		case PMCOUT_SSP_COMPLETION:
			/*
			 * We only get SSP completion here for Task Management
			 * completions.
			 */
		case PMCOUT_SMP_COMPLETION:
		case PMCOUT_LOCAL_PHY_CONTROL:
		case PMCOUT_DEVICE_REGISTRATION:
		case PMCOUT_DEREGISTER_DEVICE_HANDLE:
		case PMCOUT_GET_NVMD_DATA:
		case PMCOUT_SET_NVMD_DATA:
		case PMCOUT_GET_DEVICE_STATE:
		case PMCOUT_SET_DEVICE_STATE:
			pmcs_process_completion(pwp, local, amt);
			break;
		case PMCOUT_SSP_ABORT:
		case PMCOUT_SATA_ABORT:
		case PMCOUT_SMP_ABORT:
			pmcs_process_abort_completion(pwp, local, amt);
			break;
		case PMCOUT_SSP_EVENT:
			pmcs_process_ssp_event(pwp, local, amt);
			break;
		case PMCOUT_ECHO:
			pmcs_process_echo_completion(pwp, local, amt);
			break;
		case PMCOUT_SAS_HW_EVENT_ACK_ACK:
			if (LE_32(ptr[2]) != SAS_HW_EVENT_ACK_OK) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
				    "SAS H/W EVENT ACK/ACK Status=0x%b",
				    LE_32(ptr[2]), "\020\4InvParm\3"
				    "InvPort\2InvPhy\1InvSEA");
			}
			pmcs_process_completion(pwp, local, amt);
			break;
		case PMCOUT_SKIP_ENTRIES:
			pmcs_prt(pwp, PMCS_PRT_DEBUG3, NULL, NULL,
			    "%s: skip %d entries", __func__, nbuf);
			break;
		default:
			(void) snprintf(local, sizeof (local),
			    "%s: unhandled message", __func__);
			pmcs_print_entry(pwp, PMCS_PRT_DEBUG, local, ptr);
			break;
		}
		STEP_OQ_ENTRY(pwp, PMCS_OQ_GENERAL, ci, nbuf);
	}
	if (lim) {
		SYNC_OQ_ENTRY(pwp, PMCS_OQ_GENERAL, ci, pi);
	}
}

/*
 * pmcs_check_intr_coal
 *
 * This function makes a determination on the dynamic value of the
 * interrupt coalescing timer register.  We only use this for I/O
 * completions.
 *
 * The basic algorithm is as follows:
 *
 * PMCS_MAX_IO_COMPS_PER_INTR: The maximum number of I/O completions per
 * I/O completion interrupt.  We won't increase the interrupt coalescing
 * timer if we're already processing this many completions per interrupt
 * beyond the threshold.
 *
 * Values in io_intr_coal structure:
 *
 * intr_latency: The average number of nsecs between interrupts during
 * the echo test.  Used to help determine whether to increase the coalescing
 * timer.
 *
 * intr_threshold: Calculated number of interrupts beyond which we may
 * increase the timer.  This value is calculated based on the calculated
 * interrupt latency during the ECHO test and the current value of the
 * coalescing timer.
 *
 * nsecs_between_intrs: Total number of nsecs between all the interrupts
 * in the current timeslice.
 *
 * last_io_comp: Time of the last I/O interrupt.
 *
 * num_io_completions: Number of I/O completions during the slice
 *
 * num_intrs: Number of I/O completion interrupts during the slice
 *
 * max_io_completions: Number of times we hit >= PMCS_MAX_IO_COMPS_PER_INTR
 * during interrupt processing.
 *
 * PMCS_MAX_IO_COMPS_LOWAT_SHIFT/HIWAT_SHIFT
 * Low and high marks used to determine whether we processed enough interrupts
 * that contained the maximum number of I/O completions to warrant increasing
 * the timer
 *
 * intr_coal_timer: The current value of the register (in usecs)
 *
 * timer_on: B_TRUE means we are using the timer
 *
 * The timer is increased if we processed more than intr_threshold interrupts
 * during the quantum and the number of interrupts containing the maximum
 * number of I/O completions is between PMCS_MAX_IO_COMPS_LOWAT_SHIFT and
 * _HIWAT_SHIFT
 *
 * If the average time between completions is greater than twice
 * the current timer value, the timer value is decreased.
 *
 * If we did not take any interrupts during a quantum, we turn the timer off.
 */
void
pmcs_check_intr_coal(void *arg)
{
	pmcs_hw_t	*pwp = (pmcs_hw_t *)arg;
	uint32_t	avg_nsecs;
	pmcs_io_intr_coal_t *ici;

	ici = &pwp->io_intr_coal;
	mutex_enter(&pwp->ict_lock);

	while (ici->stop_thread == B_FALSE) {
		/*
		 * Wait for next time quantum... collect stats
		 */
		(void) cv_timedwait(&pwp->ict_cv, &pwp->ict_lock,
		    ddi_get_lbolt() + ici->quantum);

		if (ici->stop_thread == B_TRUE) {
			continue;
		}

		DTRACE_PROBE1(pmcs__check__intr__coal, pmcs_io_intr_coal_t *,
		    &pwp->io_intr_coal);

		/*
		 * Determine whether to adjust timer
		 */
		if (ici->num_intrs == 0) {
			/*
			 * If timer is off, nothing more to do.
			 */
			if (!pwp->io_intr_coal.timer_on) {
				continue;
			}

			/*
			 * No interrupts.  Turn off the timer.
			 */
			pmcs_wr_topunit(pwp, PMCS_INT_COALESCING_CONTROL, 0);

			if (pwp->odb_auto_clear & (1 << PMCS_MSIX_IODONE)) {
				pmcs_wr_topunit(pwp, PMCS_OBDB_AUTO_CLR,
				    pwp->odb_auto_clear);
			}

			ici->timer_on = B_FALSE;
			ici->max_io_completions = 0;
			ici->num_intrs = 0;
			ici->int_cleared = B_FALSE;
			ici->num_io_completions = 0;
			DTRACE_PROBE1(pmcs__intr__coalesce__timer__off,
			    pmcs_io_intr_coal_t *, ici);
			continue;
		}

		avg_nsecs = ici->nsecs_between_intrs / ici->num_intrs;

		if ((ici->num_intrs > ici->intr_threshold) &&
		    (ici->max_io_completions > (ici->num_intrs >>
		    PMCS_MAX_IO_COMPS_LOWAT_SHIFT)) &&
		    (ici->max_io_completions < (ici->num_intrs >>
		    PMCS_MAX_IO_COMPS_HIWAT_SHIFT))) {
			pmcs_set_intr_coal_timer(pwp, INCREASE_TIMER);
		} else if (avg_nsecs >
		    (ici->intr_coal_timer * 1000 * 2)) {
			pmcs_set_intr_coal_timer(pwp, DECREASE_TIMER);
		}

		/*
		 * Reset values for new sampling period.
		 */
		ici->max_io_completions = 0;
		ici->nsecs_between_intrs = 0;
		ici->num_intrs = 0;
		ici->num_io_completions = 0;
	}

	mutex_exit(&pwp->ict_lock);
	thread_exit();
}

void
pmcs_iodone_intr(pmcs_hw_t *pwp)
{
	char local[PMCS_QENTRY_SIZE << 1];
	pmcs_iocomp_cb_t *ioccb;
	uint32_t w0, ci, pi, nbuf, lim = 0, niodone = 0, iomb_opcode;
	size_t amt;
	uint32_t *ptr;
	hrtime_t curtime = gethrtime();

	ci = pmcs_rd_oqci(pwp, PMCS_OQ_IODONE);
	pi = pmcs_rd_oqpi(pwp, PMCS_OQ_IODONE);

	while (ci != pi) {
		OQLIM_CHECK(pwp, lim);
		ptr = GET_OQ_ENTRY(pwp, PMCS_OQ_IODONE, ci, 0);
		w0 = LE_32(ptr[0]);
		VALID_IOMB_CHECK(pwp, w0, ptr, ci, pi);
		WRONG_OBID_CHECK(pwp, w0, PMCS_OQ_IODONE);
		iomb_opcode = (w0 & PMCS_IOMB_OPCODE_MASK);

		if ((iomb_opcode == PMCOUT_SSP_COMPLETION) ||
		    (iomb_opcode == PMCOUT_SATA_COMPLETION)) {
			ioccb =
			    kmem_cache_alloc(pwp->iocomp_cb_cache, KM_NOSLEEP);
			if (ioccb == NULL) {
				pmcs_prt(pwp, PMCS_PRT_WARN, NULL, NULL,
				    "%s: kmem_cache_alloc failed", __func__);
				break;
			}

			COPY_OUTBOUND(pwp, w0, ioccb->iomb, nbuf, amt, ptr,
			    PMCS_OQ_IODONE, ci);

			niodone++;
			pmcs_process_io_completion(pwp, ioccb, amt);
		} else {
			COPY_OUTBOUND(pwp, w0, local, nbuf, amt, ptr,
			    PMCS_OQ_IODONE, ci);

			switch (iomb_opcode) {
			case PMCOUT_ECHO:
				pmcs_process_echo_completion(pwp, local, amt);
				break;
			case PMCOUT_SATA_EVENT:
				pmcs_process_sata_event(pwp, local, amt);
				break;
			case PMCOUT_SSP_EVENT:
				pmcs_process_ssp_event(pwp, local, amt);
				break;
			case PMCOUT_SKIP_ENTRIES:
				pmcs_prt(pwp, PMCS_PRT_DEBUG3, NULL, NULL,
				    "%s: skip %d entries", __func__, nbuf);
				break;
			default:
				(void) snprintf(local, sizeof (local),
				    "%s: unhandled message", __func__);
				pmcs_print_entry(pwp, PMCS_PRT_DEBUG, local,
				    ptr);
				break;
			}
		}

		STEP_OQ_ENTRY(pwp, PMCS_OQ_IODONE, ci, nbuf);
	}

	if (lim != 0) {
		SYNC_OQ_ENTRY(pwp, PMCS_OQ_IODONE, ci, pi);
	}

	/*
	 * Update the interrupt coalescing timer check stats and run
	 * completions for queued up commands.
	 */

	if (niodone > 0) {
		/*
		 * If we can't get the lock, then completions are either
		 * already running or will be scheduled to do so shortly.
		 */
		if (mutex_tryenter(&pwp->cq_lock) != 0) {
			PMCS_CQ_RUN_LOCKED(pwp);
			mutex_exit(&pwp->cq_lock);
		}

		mutex_enter(&pwp->ict_lock);
		pwp->io_intr_coal.nsecs_between_intrs +=
		    curtime - pwp->io_intr_coal.last_io_comp;
		pwp->io_intr_coal.num_intrs++;
		pwp->io_intr_coal.num_io_completions += niodone;
		if (niodone >= PMCS_MAX_IO_COMPS_PER_INTR) {
			pwp->io_intr_coal.max_io_completions++;
		}
		pwp->io_intr_coal.last_io_comp = gethrtime();
		mutex_exit(&pwp->ict_lock);
	}
}

void
pmcs_event_intr(pmcs_hw_t *pwp)
{
	char local[PMCS_QENTRY_SIZE << 1];
	uint32_t w0, ci, pi, nbuf, lim =  0;
	size_t amt;
	uint32_t *ptr;

	ci = pmcs_rd_oqci(pwp, PMCS_OQ_EVENTS);
	pi = pmcs_rd_oqpi(pwp, PMCS_OQ_EVENTS);

	while (ci != pi) {
		OQLIM_CHECK(pwp, lim);
		ptr = GET_OQ_ENTRY(pwp, PMCS_OQ_EVENTS, ci, 0);
		w0 = LE_32(ptr[0]);
		VALID_IOMB_CHECK(pwp, w0, ptr, ci, pi);
		WRONG_OBID_CHECK(pwp, w0, PMCS_OQ_EVENTS);
		COPY_OUTBOUND(pwp, w0, local, nbuf, amt, ptr,
		    PMCS_OQ_EVENTS, ci);

		switch (w0 & PMCS_IOMB_OPCODE_MASK) {
		case PMCOUT_ECHO:
			pmcs_process_echo_completion(pwp, local, amt);
			break;
		case PMCOUT_SATA_EVENT:
			pmcs_process_sata_event(pwp, local, amt);
			break;
		case PMCOUT_SSP_EVENT:
			pmcs_process_ssp_event(pwp, local, amt);
			break;
		case PMCOUT_GENERAL_EVENT:
			pmcs_process_general_event(pwp, ptr);
			break;
		case PMCOUT_DEVICE_HANDLE_REMOVED:
		{
			uint32_t port = IOP_EVENT_PORTID(LE_32(ptr[1]));
			uint32_t did = LE_32(ptr[2]);
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "PortID 0x%x device_id 0x%x removed", port, did);
			break;
		}
		case PMCOUT_SAS_HW_EVENT:
			if (nbuf > 1) {
				pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL,
				    "multiple SAS HW_EVENT (%d) responses "
				    "in EVENT OQ", nbuf);
			}
			pmcs_process_sas_hw_event(pwp, local, PMCS_QENTRY_SIZE);
			break;
		case PMCOUT_FW_FLASH_UPDATE:
		case PMCOUT_GET_TIME_STAMP:
		case PMCOUT_GET_DEVICE_STATE:
		case PMCOUT_SET_DEVICE_STATE:
		case PMCOUT_SAS_DIAG_EXECUTE:
			pmcs_process_completion(pwp, local, amt);
			break;
		case PMCOUT_SKIP_ENTRIES:
			pmcs_prt(pwp, PMCS_PRT_DEBUG3, NULL, NULL,
			    "%s: skip %d entries", __func__, nbuf);
			break;
		default:
			(void) snprintf(local, sizeof (local),
			    "%s: unhandled message", __func__);
			pmcs_print_entry(pwp, PMCS_PRT_DEBUG, local, ptr);
			break;
		}
		STEP_OQ_ENTRY(pwp, PMCS_OQ_EVENTS, ci, nbuf);
	}
	if (lim) {
		SYNC_OQ_ENTRY(pwp, PMCS_OQ_EVENTS, ci, pi);
	}
}

void
pmcs_timed_out(pmcs_hw_t *pwp, uint32_t htag, const char *func)
{
#ifdef	DEBUG
	hrtime_t now = gethrtime();
	int i;

	for (i = 0; i < 256; i++) {
		if (pwp->ftags[i] == htag) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "Inbound msg (tag 0x%8x) timed out - "
			    "was started %llu ns ago in %s:%d",
			    htag, (unsigned long long) (now - pwp->ftime[i]),
			    func, pwp->ftag_lines[i]);
			return;
		}
	}
#endif
	pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
	    "Inbound Message (tag 0x%08x) timed out- was started in %s",
	    htag, func);
}
