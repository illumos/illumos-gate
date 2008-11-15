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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#include "emlxs.h"

/* Timer period in seconds */
#define	EMLXS_TIMER_PERIOD		1	/* secs */
#define	EMLXS_PKT_PERIOD		5	/* secs */
#define	EMLXS_UB_PERIOD			60	/* secs */

EMLXS_MSG_DEF(EMLXS_CLOCK_C);


#ifdef DFC_SUPPORT
static void emlxs_timer_check_loopback(emlxs_hba_t *hba);
#endif	/* DFC_SUPPORT */

#ifdef DHCHAP_SUPPORT
static void emlxs_timer_check_dhchap(emlxs_port_t *port);
#endif	/* DHCHAP_SUPPORT */

static void emlxs_timer(void *arg);
static void emlxs_timer_check_heartbeat(emlxs_hba_t *hba);
static uint32_t emlxs_timer_check_pkts(emlxs_hba_t *hba, uint8_t *flag);
static void emlxs_timer_check_nodes(emlxs_port_t *port, uint8_t *flag);
static void emlxs_timer_check_linkup(emlxs_hba_t *hba);
static void emlxs_timer_check_mbox(emlxs_hba_t *hba);
static void emlxs_timer_check_discovery(emlxs_port_t *port);
static void emlxs_timer_check_ub(emlxs_port_t *port);
static void emlxs_timer_check_rings(emlxs_hba_t *hba, uint8_t *flag);
static uint32_t emlxs_pkt_chip_timeout(emlxs_port_t *port,
	emlxs_buf_t *sbp, Q *abortq, uint8_t *flag);

#ifdef TX_WATCHDOG
static void emlxs_tx_watchdog(emlxs_hba_t *hba);
#endif	/* TX_WATCHDOG */

extern clock_t
emlxs_timeout(emlxs_hba_t *hba, uint32_t timeout)
{
	emlxs_config_t *cfg = &CFG;
	clock_t time;

	/* Set thread timeout */
	if (cfg[CFG_TIMEOUT_ENABLE].current) {
		(void) drv_getparm(LBOLT, &time);
		time += (timeout * drv_usectohz(1000000));
	} else {
		time = -1;
	}

	return (time);

} /* emlxs_timeout() */


static void
emlxs_timer(void *arg)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg;
	emlxs_port_t *port = &PPORT;
	uint8_t flag[MAX_RINGS];
	uint32_t i;
	uint32_t rc;

	if (!hba->timer_id) {
		return;
	}
	mutex_enter(&EMLXS_TIMER_LOCK);

	/* Only one timer thread is allowed */
	if (hba->timer_flags & EMLXS_TIMER_BUSY) {
		mutex_exit(&EMLXS_TIMER_LOCK);
		return;
	}
	/* Check if a kill request has been made */
	if (hba->timer_flags & EMLXS_TIMER_KILL) {
		hba->timer_id = 0;
		hba->timer_flags |= EMLXS_TIMER_ENDED;

		mutex_exit(&EMLXS_TIMER_LOCK);
		return;
	}
	hba->timer_flags |= (EMLXS_TIMER_BUSY | EMLXS_TIMER_STARTED);
	hba->timer_tics = DRV_TIME;

	mutex_exit(&EMLXS_TIMER_LOCK);

	/* Exit if we are still initializing */
	if (hba->state < FC_LINK_DOWN) {
		goto done;
	}
	bzero((void *) flag, sizeof (flag));

	/* Check for mailbox timeout */
	emlxs_timer_check_mbox(hba);

	/* Check heartbeat timer */
	emlxs_timer_check_heartbeat(hba);

#ifdef IDLE_TIMER
	emlxs_pm_idle_timer(hba);
#endif	/* IDLE_TIMER */

#ifdef DFC_SUPPORT
	/* Check for loopback timeouts */
	emlxs_timer_check_loopback(hba);
#endif	/* DFC_SUPPORT */

	/* Check for packet timeouts */
	rc = emlxs_timer_check_pkts(hba, flag);

	if (rc) {
		/* Link or adapter is being reset */
		goto done;
	}
	/* Check for linkup timeout */
	emlxs_timer_check_linkup(hba);

	/* Check the ports */
	for (i = 0; i < MAX_VPORTS; i++) {
		port = &VPORT(i);

		if (!(port->flag & EMLXS_PORT_BOUND)) {
			continue;
		}
		/* Check for node gate timeouts */
		emlxs_timer_check_nodes(port, flag);

		/* Check for tape discovery timeout */
		emlxs_timer_check_discovery(port);

		/* Check for UB timeouts */
		emlxs_timer_check_ub(port);

#ifdef DHCHAP_SUPPORT
		/* Check for DHCHAP authentication timeouts */
		emlxs_timer_check_dhchap(port);
#endif	/* DHCHAP_SUPPORT */

	}

	/* Check for ring service timeouts */
	/* Always do this last */
	emlxs_timer_check_rings(hba, flag);

done:

	/* Restart the timer */
	mutex_enter(&EMLXS_TIMER_LOCK);

	hba->timer_flags &= ~EMLXS_TIMER_BUSY;

	/* If timer is still enabled, restart it */
	if (!(hba->timer_flags & EMLXS_TIMER_KILL)) {
		hba->timer_id = timeout(emlxs_timer, (void *) hba,
		    (EMLXS_TIMER_PERIOD * drv_usectohz(1000000)));
	} else {
		hba->timer_id = 0;
		hba->timer_flags |= EMLXS_TIMER_ENDED;
	}

	mutex_exit(&EMLXS_TIMER_LOCK);

	return;

} /* emlxs_timer() */


extern void
emlxs_timer_start(emlxs_hba_t *hba)
{
	if (hba->timer_id) {
		return;
	}
	/* Restart the timer */
	mutex_enter(&EMLXS_TIMER_LOCK);
	if (!hba->timer_id) {
		hba->timer_flags = 0;
		hba->timer_id = timeout(emlxs_timer, (void *)hba,
		    drv_usectohz(1000000));
	}
	mutex_exit(&EMLXS_TIMER_LOCK);

} /* emlxs_timer_start() */


extern void
emlxs_timer_stop(emlxs_hba_t *hba)
{
	if (!hba->timer_id) {
		return;
	}
	mutex_enter(&EMLXS_TIMER_LOCK);
	hba->timer_flags |= EMLXS_TIMER_KILL;

	while (hba->timer_id) {
		mutex_exit(&EMLXS_TIMER_LOCK);
		delay(drv_usectohz(500000));
		mutex_enter(&EMLXS_TIMER_LOCK);
	}
	mutex_exit(&EMLXS_TIMER_LOCK);

	return;

} /* emlxs_timer_stop() */


static uint32_t
emlxs_timer_check_pkts(emlxs_hba_t *hba, uint8_t *flag)
{
	emlxs_port_t *port = &PPORT;
	/* emlxs_port_t *vport; */
	emlxs_config_t *cfg = &CFG;
	Q tmo;
	int32_t ringno;
	RING *rp;
	NODELIST *nlp;
	IOCBQ *prev;
	IOCBQ *next;
	IOCB *iocb;
	IOCBQ *iocbq;
	emlxs_buf_t *sbp;
	fc_packet_t *pkt;
	Q abort;
	uint32_t iotag;
	uint32_t rc;

	if (!cfg[CFG_TIMEOUT_ENABLE].current) {
		return (0);
	}
	if (hba->pkt_timer > hba->timer_tics) {
		return (0);
	}
	hba->pkt_timer = hba->timer_tics + EMLXS_PKT_PERIOD;


	bzero((void *) &tmo, sizeof (Q));

	/*
	 * We must hold the locks here because we never know when an iocb
	 * will be removed out from under us
	 */

	mutex_enter(&EMLXS_RINGTX_LOCK);

	for (ringno = 0; ringno < hba->ring_count; ringno++) {
		rp = &hba->ring[ringno];

		/* Scan the tx queues for each active node on the ring */

		/* Get the first node */
		nlp = (NODELIST *)rp->nodeq.q_first;

		while (nlp) {
			/* Scan the node's priority tx queue */
			prev = NULL;
			iocbq = (IOCBQ *)nlp->nlp_ptx[ringno].q_first;

			while (iocbq) {
				next = (IOCBQ *)iocbq->next;
				iocb = &iocbq->iocb;
				sbp = (emlxs_buf_t *)iocbq->sbp;

				/* Check if iocb has timed out */
				if (sbp && hba->timer_tics >= sbp->ticks) {
					/* iocb timed out, now deque it */
					if (next == NULL) {
						nlp->nlp_ptx[ringno].q_last =
						    (uint8_t *)prev;
					}
					if (prev == NULL) {
						nlp->nlp_ptx[ringno].q_first =
						    (uint8_t *)next;
					} else {
						prev->next = next;
					}

					iocbq->next = NULL;
					nlp->nlp_ptx[ringno].q_cnt--;

					/*
					 * Add this iocb to our local timout
					 * Q
					 */

					/*
					 * This way we don't hold the RINGTX
					 * lock too long
					 */

					if (tmo.q_first) {
						((IOCBQ *)tmo.q_last)->next =
						    iocbq;
						tmo.q_last = (uint8_t *)iocbq;
						tmo.q_cnt++;
					} else {
						tmo.q_first = (uint8_t *)iocbq;
						tmo.q_last = (uint8_t *)iocbq;
						tmo.q_cnt = 1;
					}
					iocbq->next = NULL;

				} else {
					prev = iocbq;
				}

				iocbq = next;

			}	/* while (iocbq) */


			/* Scan the node's tx queue */
			prev = NULL;
			iocbq = (IOCBQ *)nlp->nlp_tx[ringno].q_first;

			while (iocbq) {
				next = (IOCBQ *)iocbq->next;
				iocb = &iocbq->iocb;
				sbp = (emlxs_buf_t *)iocbq->sbp;

				/* Check if iocb has timed out */
				if (sbp && hba->timer_tics >= sbp->ticks) {
					/* iocb timed out, now deque it */
					if (next == NULL) {
						nlp->nlp_tx[ringno].q_last =
						    (uint8_t *)prev;
					}
					if (prev == NULL) {
						nlp->nlp_tx[ringno].q_first =
						    (uint8_t *)next;
					} else {
						prev->next = next;
					}

					iocbq->next = NULL;
					nlp->nlp_tx[ringno].q_cnt--;

					/*
					 * Add this iocb to our local timout
					 * Q
					 */

					/*
					 * This way we don't hold the RINGTX
					 * lock too long
					 */

					/*
					 * EMLXS_MSGF(EMLXS_CONTEXT,
					 * &emlxs_pkt_timeout_msg, "TXQ
					 * abort: Removing iotag=%x qcnt=%d
					 * pqcnt=%d", sbp->iotag,
					 * nlp->nlp_tx[ringno].q_cnt,
					 * nlp->nlp_ptx[ringno].q_cnt);
					 */

					if (tmo.q_first) {
						((IOCBQ *)tmo.q_last)->next =
						    iocbq;
						tmo.q_last = (uint8_t *)iocbq;
						tmo.q_cnt++;
					} else {
						tmo.q_first = (uint8_t *)iocbq;
						tmo.q_last = (uint8_t *)iocbq;
						tmo.q_cnt = 1;
					}
					iocbq->next = NULL;

				} else {
					prev = iocbq;
				}

				iocbq = next;

			}	/* while (iocbq) */

			if (nlp == (NODELIST *) rp->nodeq.q_last) {
				nlp = NULL;
			} else {
				nlp = nlp->nlp_next[ringno];
			}

		}	/* while(nlp) */

	}	/* end of for */

	/* Now cleanup the iocb's */
	iocbq = (IOCBQ *)tmo.q_first;
	while (iocbq) {
		/* Free the IoTag and the bmp */
		iocb = &iocbq->iocb;
		sbp = emlxs_unregister_pkt(iocbq->ring, iocb->ulpIoTag, 0);
		ringno = ((RING *)iocbq->ring)->ringno;

		if (sbp && (sbp != STALE_PACKET)) {
			mutex_enter(&sbp->mtx);
			if (sbp->pkt_flags & PACKET_IN_TXQ) {
				sbp->pkt_flags &= ~PACKET_IN_TXQ;
				hba->ring_tx_count[ringno]--;
			}
			sbp->pkt_flags |= PACKET_IN_TIMEOUT;
			mutex_exit(&sbp->mtx);
		}
		iocbq = (IOCBQ *)iocbq->next;

	}	/* end of while */

	mutex_exit(&EMLXS_RINGTX_LOCK);

	/* Now complete the transmit timeouts outside the locks */
	iocbq = (IOCBQ *)tmo.q_first;
	while (iocbq) {
		/* Save the next iocbq for now */
		next = (IOCBQ *)iocbq->next;

		/* Unlink this iocbq */
		iocbq->next = NULL;

		/* Get the pkt */
		sbp = (emlxs_buf_t *)iocbq->sbp;

		if (sbp) {
			/*
			 * Warning: Some FCT sbp's don't have fc_packet
			 * objects
			 */
			pkt = PRIV2PKT(sbp);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_timeout_msg,
			    "TXQ abort: sbp=%p iotag=%x tmo=%d", sbp,
			    sbp->iotag, (pkt) ? pkt->pkt_timeout : 0);

			if (hba->state >= FC_LINK_UP) {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    IOERR_ABORT_TIMEOUT, 1);
			} else {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    IOERR_LINK_DOWN, 1);
			}
		}
		iocbq = next;

	}	/* end of while */



	/* Now check the chip */
	bzero((void *) &abort, sizeof (Q));

	/* Check the rings */
	rc = 0;
	for (ringno = 0; ringno < hba->ring_count; ringno++) {
		rp = &hba->ring[ringno];

		mutex_enter(&EMLXS_FCTAB_LOCK(ringno));
		for (iotag = 1; iotag < rp->max_iotag; iotag++) {
			sbp = rp->fc_table[iotag];
			if (sbp && (sbp != STALE_PACKET) &&
			    (sbp->pkt_flags & PACKET_IN_CHIPQ) &&
			    (hba->timer_tics >= sbp->ticks)) {
				rc = emlxs_pkt_chip_timeout(sbp->iocbq.port,
				    sbp, &abort, flag);

				if (rc) {
					break;
				}
			}
		}
		mutex_exit(&EMLXS_FCTAB_LOCK(ringno));

		if (rc) {
			break;
		}
	}

	/* Now put the iocb's on the tx queue */
	iocbq = (IOCBQ *)abort.q_first;
	while (iocbq) {
		/* Save the next iocbq for now */
		next = (IOCBQ *)iocbq->next;

		/* Unlink this iocbq */
		iocbq->next = NULL;

		/* Send this iocbq */
		emlxs_tx_put(iocbq, 1);

		iocbq = next;
	}

	if (rc == 1) {
		/* Spawn a thread to reset the link */
		(void) thread_create(NULL, 0, emlxs_reset_link_thread,
		    (char *)hba, 0, &p0, TS_RUN, v.v_maxsyspri - 2);
	} else if (rc == 2) {
		/* Spawn a thread to reset the adapter */
		(void) thread_create(NULL, 0, emlxs_restart_thread,
		    (char *)hba, 0, &p0, TS_RUN, v.v_maxsyspri - 2);
	}
	return (rc);

} /* emlxs_timer_check_pkts() */



static void
emlxs_timer_check_rings(emlxs_hba_t *hba, uint8_t *flag)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	int32_t ringno;
	RING *rp;
	uint32_t logit = 0;

	if (!cfg[CFG_TIMEOUT_ENABLE].current) {
		return;
	}
	for (ringno = 0; ringno < hba->ring_count; ringno++) {
		rp = &hba->ring[ringno];

		/* Check for ring timeout now */
		mutex_enter(&EMLXS_RINGTX_LOCK);
		if (rp->timeout && (hba->timer_tics >= rp->timeout)) {
			/* Check if there is still work to do on the ring and */
			/* the link is still up */
			if (rp->nodeq.q_first) {
				flag[ringno] = 1;
				rp->timeout = hba->timer_tics + 10;

				if (hba->state >= FC_LINK_UP) {
					logit = 1;
				}
			} else {
				rp->timeout = 0;
			}
		}
		mutex_exit(&EMLXS_RINGTX_LOCK);

		if (logit) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_ring_watchdog_msg,
			    "%s host=%d port=%d cnt=%d,%d",
			    emlxs_ring_xlate(ringno),
			    rp->fc_cmdidx, rp->fc_port_cmdidx,
			    hba->ring_tx_count[ringno],
			    hba->io_count[ringno]);
		}

		/*
		 * If ring flag is set, request iocb servicing here to send
		 * any iocb's that may still be queued
		 */
		if (flag[ringno]) {
			emlxs_issue_iocb_cmd(hba, rp, 0);
		}
	}

	return;

} /* emlxs_timer_check_rings() */


static void
emlxs_timer_check_nodes(emlxs_port_t *port, uint8_t *flag)
{
	emlxs_hba_t *hba = HBA;
	uint32_t found;
	uint32_t i;
	NODELIST *nlp;
	int32_t ringno;

	for (;;) {
		/* Check node gate flag for expiration */
		found = 0;

		/*
		 * We need to lock, scan, and unlock because we can't hold
		 * the lock while we call node_open
		 */
		rw_enter(&port->node_rwlock, RW_READER);
		for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
			nlp = port->node_table[i];
			while (nlp != NULL) {
				for (ringno = 0;
				    ringno < hba->ring_count;
				    ringno++) {
					/*
					 * Check if the node timer is active
					 * and if timer has expired
					 */
					if ((nlp->nlp_flag[ringno] &
					    NLP_TIMER) &&
					    nlp->nlp_tics[ringno] &&
					    (hba->timer_tics >=
					    nlp->nlp_tics[ringno])) {
						/*
						 * If so, set the flag and
						 * break out
						 */
						found = 1;
						flag[ringno] = 1;
						break;
					}
				}

				if (found) {
					break;
				}
				nlp = nlp->nlp_list_next;
			}

			if (found) {
				break;
			}
		}
		rw_exit(&port->node_rwlock);

		if (!found) {
			break;
		}
		emlxs_node_open(port, nlp, ringno);
	}

} /* emlxs_timer_check_nodes() */


#ifdef DFC_SUPPORT
static void
emlxs_timer_check_loopback(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	int32_t reset = 0;

	if (!cfg[CFG_TIMEOUT_ENABLE].current) {
		return;
	}
	/* Check the loopback timer for expiration */
	mutex_enter(&EMLXS_PORT_LOCK);

	if (!hba->loopback_tics ||
	    (hba->timer_tics < hba->loopback_tics)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}
	hba->loopback_tics = 0;

	if (hba->flag & FC_LOOPBACK_MODE) {
		reset = 1;
	}
	mutex_exit(&EMLXS_PORT_LOCK);

	if (reset) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_debug_msg,
		    "LOOPBACK_MODE: Expired. Resetting...");
		(void) emlxs_reset(port, FC_FCA_LINK_RESET);
	}
	return;

} /* emlxs_timer_check_loopback() */
#endif	/* DFC_SUPPORT  */


static void
emlxs_timer_check_linkup(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t linkup;

	/* Check the linkup timer for expiration */
	mutex_enter(&EMLXS_PORT_LOCK);
	linkup = 0;
	if (hba->linkup_timer && (hba->timer_tics >= hba->linkup_timer)) {
		hba->linkup_timer = 0;

		/* Make sure link is still ready */
		if (hba->state >= FC_LINK_UP) {
			linkup = 1;
		}
	}
	mutex_exit(&EMLXS_PORT_LOCK);

	/* Make the linkup callback */
	if (linkup) {
		emlxs_port_online(port);
	}
	return;

} /* emlxs_timer_check_linkup() */


static void
emlxs_timer_check_heartbeat(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *mb;
	emlxs_config_t *cfg = &CFG;

	if (!cfg[CFG_HEARTBEAT_ENABLE].current) {
		return;
	}
	if (hba->timer_tics < hba->heartbeat_timer) {
		return;
	}
	hba->heartbeat_timer = hba->timer_tics + 5;

	/* Return if adapter interrupts have occurred */
	if (hba->heartbeat_flag) {
		hba->heartbeat_flag = 0;
		return;
	}
	/* No adapter interrupts have occured for 5 seconds now */

	/* Return if mailbox is busy */
	/* This means the mailbox timer routine is watching for problems */
	if (hba->mbox_timer) {
		return;
	}
	/* Return if heartbeat is still outstanding */
	if (hba->heartbeat_active) {
		return;
	}
	if ((mb = (MAILBOX *) emlxs_mem_get(hba, MEM_MBOX | MEM_PRI)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to allocate heartbeat mailbox.");
		return;
	}
	emlxs_mb_heartbeat(hba, mb);
	hba->heartbeat_active = 1;

	if (emlxs_mb_issue_cmd(hba, mb, MBX_NOWAIT, 0) != MBX_BUSY) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
	}
	return;

} /* emlxs_timer_check_heartbeat() */



static void
emlxs_timer_check_mbox(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	MAILBOX *mb;
	uint32_t word0;
	uint32_t offset;
	uint32_t ha_copy = 0;

	if (!cfg[CFG_TIMEOUT_ENABLE].current) {
		return;
	}
	mutex_enter(&EMLXS_PORT_LOCK);

	/* Return if timer hasn't expired */
	if (!hba->mbox_timer || (hba->timer_tics < hba->mbox_timer)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}
	hba->mbox_timer = 0;

	/* Mailbox timed out, first check for error attention */
	ha_copy = READ_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr));

	if (ha_copy & HA_ERATT) {
		mutex_exit(&EMLXS_PORT_LOCK);
		emlxs_handle_ff_error(hba);
		return;
	}
	if (hba->mbox_queue_flag) {
		/* Get first word of mailbox */
		if (hba->flag & FC_SLIM2_MODE) {
			mb = FC_SLIM2_MAILBOX(hba);
			offset = (off_t)((uint64_t)(unsigned long)mb -
			    (uint64_t)(unsigned long)hba->slim2.virt);

			emlxs_mpdata_sync(hba->slim2.dma_handle,
			    offset, sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
			word0 = *((volatile uint32_t *) mb);
			word0 = PCIMEM_LONG(word0);
		} else {
			mb = FC_SLIM1_MAILBOX(hba);
			word0 = READ_SLIM_ADDR(hba, ((volatile uint32_t *)mb));
		}

		mb = (MAILBOX *) & word0;

		/* Check if mailbox has actually completed */
		if (mb->mbxOwner == OWN_HOST) {
			/*
			 * Read host attention register to determine
			 * interrupt source
			 */
			uint32_t ha_copy = READ_CSR_REG(hba,
			    FC_HA_REG(hba, hba->csr_addr));

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Mailbox attention missed: %s."
			    "Forcing event. hc = %x ha = %x",
			    emlxs_mb_cmd_xlate(mb->mbxCommand),
			    hba->hc_copy, ha_copy);

			mutex_exit(&EMLXS_PORT_LOCK);

			(void) emlxs_handle_mb_event(hba);

			return;
		}
		if (hba->mbox_mbq) {
			mb = (MAILBOX *)hba->mbox_mbq;
		}
	}
	switch (hba->mbox_queue_flag) {
	case MBX_NOWAIT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "Mailbox Timeout: %s: Nowait.",
		    emlxs_mb_cmd_xlate(mb->mbxCommand));
		break;

	case MBX_SLEEP:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "Mailbox Timeout: %s: mb=%p Sleep.",
		    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);
		break;

	case MBX_POLL:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "Mailbox Timeout: %s: mb=%p Polled.",
		    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "Mailbox Timeout.");
		break;
	}

	hba->flag |= FC_MBOX_TIMEOUT;
	emlxs_ffstate_change_locked(hba, FC_ERROR);

	mutex_exit(&EMLXS_PORT_LOCK);

	/* Perform mailbox cleanup */
	/* This will wake any sleeping or polling threads */
	emlxs_mb_fini(hba, NULL, MBX_TIMEOUT);

	/* Trigger adapter shutdown */
	(void) thread_create(NULL, 0, emlxs_shutdown_thread, (char *)hba, 0,
	    &p0, TS_RUN, v.v_maxsyspri - 2);

	return;

} /* emlxs_timer_check_mbox() */



static void
emlxs_timer_check_discovery(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	int32_t send_clear_la;
	uint32_t found;
	uint32_t i;
	NODELIST *nlp;
	MAILBOXQ *mbox;

	if (!cfg[CFG_TIMEOUT_ENABLE].current) {
		return;
	}
	/* Check the discovery timer for expiration */
	send_clear_la = 0;
	mutex_enter(&EMLXS_PORT_LOCK);
	while (hba->discovery_timer &&
	    (hba->timer_tics >= hba->discovery_timer) &&
	    (hba->state == FC_LINK_UP)) {
		send_clear_la = 1;

		/* Perform a flush on fcp2 nodes that are still closed */
		found = 0;
		rw_enter(&port->node_rwlock, RW_READER);
		for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
			nlp = port->node_table[i];
			while (nlp != NULL) {
				if ((nlp->nlp_fcp_info & NLP_FCP_2_DEVICE) &&
				    (nlp->nlp_flag[FC_FCP_RING] &
				    NLP_CLOSED)) {
					found = 1;
					break;

				}
				nlp = nlp->nlp_list_next;
			}

			if (found) {
				break;
			}
		}
		rw_exit(&port->node_rwlock);

		if (!found) {
			break;
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_missing_msg,
		    "FCP2 device (did=%06x) missing. Flushing...",
		    nlp->nlp_DID);

		mutex_exit(&EMLXS_PORT_LOCK);

		(void) emlxs_mb_unreg_did(port, nlp->nlp_DID, NULL, NULL, NULL);

		mutex_enter(&EMLXS_PORT_LOCK);

	}
	mutex_exit(&EMLXS_PORT_LOCK);

	/* Try to send clear link attention, if needed */
	if ((send_clear_la == 1) &&
	    (mbox = (MAILBOXQ *) emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		mutex_enter(&EMLXS_PORT_LOCK);

		/*
		 * If state is not FC_LINK_UP, then either the link has gone
		 * down or a FC_CLEAR_LA has already been issued
		 */
		if (hba->state != FC_LINK_UP) {
			mutex_exit(&EMLXS_PORT_LOCK);
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbox);
		} else {
			/* Change state and clear discovery timer */
			emlxs_ffstate_change_locked(hba, FC_CLEAR_LA);

			hba->discovery_timer = 0;

			mutex_exit(&EMLXS_PORT_LOCK);

			/* Prepare and send the CLEAR_LA command */
			emlxs_mb_clear_la(hba, (MAILBOX *)mbox);

			if (emlxs_mb_issue_cmd(hba, (MAILBOX *)mbox,
			    MBX_NOWAIT, 0) != MBX_BUSY) {
				(void) emlxs_mem_put(hba, MEM_MBOX,
				    (uint8_t *)mbox);
			}
		}
	}
	return;

} /* emlxs_timer_check_discovery()  */


static void
emlxs_timer_check_ub(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	emlxs_unsol_buf_t *ulistp;
	fc_unsol_buf_t *ubp;
	emlxs_ub_priv_t *ub_priv;
	uint32_t i;

	if (port->ub_timer > hba->timer_tics) {
		return;
	}
	port->ub_timer = hba->timer_tics + EMLXS_UB_PERIOD;

	/* Check the unsolicited buffers */
	mutex_enter(&EMLXS_UB_LOCK);

	ulistp = port->ub_pool;
	while (ulistp) {
		/* Check buffers in this pool */
		for (i = 0; i < ulistp->pool_nentries; i++) {
			ubp = (fc_unsol_buf_t *)&ulistp->fc_ubufs[i];
			ub_priv = ubp->ub_fca_private;

			if (!(ub_priv->flags & EMLXS_UB_IN_USE)) {
				continue;
			}
			/*
			 * If buffer has timed out, print message and
			 * increase timeout
			 */
			if ((ub_priv->time + ub_priv->timeout) <=
			    hba->timer_tics) {
				ub_priv->flags |= EMLXS_UB_TIMEOUT;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
				    "Stale UB buffer detected (%d mins): "
				    "buffer = %p (%x,%x,%x,%x)",
				    (ub_priv->timeout / 60),
				    ubp, ubp->ub_frame.type,
				    ubp->ub_frame.s_id,
				    ubp->ub_frame.ox_id,
				    ubp->ub_frame.rx_id);

				/* Increase timeout period */

				/*
				 * If timeout was 5 mins or less, increase it
				 * to 10 mins
				 */
				if (ub_priv->timeout <= (5 * 60)) {
					ub_priv->timeout = (10 * 60);
				}
				/*
				 * If timeout was 10 mins or less, increase
				 * it to 30 mins
				 */
				else if (ub_priv->timeout <= (10 * 60)) {
					ub_priv->timeout = (30 * 60);
				}
				/* Otherwise double it. */
				else {
					ub_priv->timeout *= 2;
				}
			}
		}

		ulistp = ulistp->pool_next;
	}

	mutex_exit(&EMLXS_UB_LOCK);

	return;

} /* emlxs_timer_check_ub()  */


/* EMLXS_FCTAB_LOCK must be held to call this */
static uint32_t
emlxs_pkt_chip_timeout(emlxs_port_t *port, emlxs_buf_t *sbp,
	Q *abortq, uint8_t *flag)
{
	emlxs_hba_t *hba = HBA;
	RING *rp = (RING *) sbp->ring;
	IOCBQ *iocbq = NULL;
	fc_packet_t *pkt;
	uint32_t rc = 0;

	mutex_enter(&sbp->mtx);

	/* Warning: Some FCT sbp's don't have fc_packet objects */
	pkt = PRIV2PKT(sbp);

	switch (sbp->abort_attempts) {
	case 0:

		/* Create the abort IOCB */
		if (hba->state >= FC_LINK_UP) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_timeout_msg,
			    "chipQ: 1:Aborting. sbp=%p iotag=%x tmo=%d",
			    sbp, sbp->iotag, (pkt) ? pkt->pkt_timeout : 0);

			iocbq = emlxs_create_abort_xri_cn(port, sbp->node,
			    sbp->iotag, rp, sbp->class, ABORT_TYPE_ABTS);

			/*
			 * The adapter will make 2 attempts to send ABTS with
			 * 2*ratov timeout each time
			 */
			sbp->ticks = hba->timer_tics + (4 * hba->fc_ratov) + 10;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_timeout_msg,
			    "chipQ: 1:Closing. sbp=%p iotag=%x tmo=%d",
			    sbp, sbp->iotag, (pkt) ? pkt->pkt_timeout : 0);

			iocbq = emlxs_create_close_xri_cn(port, sbp->node,
			    sbp->iotag, rp);

			sbp->ticks = hba->timer_tics + 30;
		}

		/* set the flags */
		sbp->pkt_flags |= (PACKET_IN_TIMEOUT | PACKET_XRI_CLOSED);

		flag[rp->ringno] = 1;
		rc = 0;

		break;

	case 1:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_timeout_msg,
		    "chipQ: 2:Closing. sbp=%p iotag=%x",
		    sbp, sbp->iotag);

		iocbq = emlxs_create_close_xri_cn(port, sbp->node,
		    sbp->iotag, rp);

		sbp->ticks = hba->timer_tics + 30;

		flag[rp->ringno] = 1;
		rc = 0;

		break;

	case 2:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_timeout_msg,
		    "chipQ: 3:Resetting link. sbp=%p iotag=%x",
		    sbp, sbp->iotag);

		sbp->ticks = hba->timer_tics + 60;
		rc = 1;

		break;

	default:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_timeout_msg,
		    "chipQ: %d:Resetting adapter. sbp=%p iotag=%x",
		    sbp->abort_attempts, sbp, sbp->iotag);

		sbp->ticks = hba->timer_tics + 60;
		rc = 2;

		break;
	}

	sbp->abort_attempts++;
	mutex_exit(&sbp->mtx);

	if (iocbq) {
		if (abortq->q_first) {
			((IOCBQ *) abortq->q_last)->next = iocbq;
			abortq->q_last = (uint8_t *)iocbq;
			abortq->q_cnt++;
		} else {
			abortq->q_first = (uint8_t *)iocbq;
			abortq->q_last = (uint8_t *)iocbq;
			abortq->q_cnt = 1;
		}
		iocbq->next = NULL;
	}
	return (rc);

} /* emlxs_pkt_chip_timeout() */


#ifdef TX_WATCHDOG

static void
emlxs_tx_watchdog(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	NODELIST *nlp;
	uint32_t ringno;
	RING *rp;
	IOCBQ *next;
	IOCBQ *iocbq;
	IOCB *iocb;
	uint32_t found;
	MATCHMAP *bmp;
	Q abort;
	uint32_t iotag;
	emlxs_buf_t *sbp;
	fc_packet_t *pkt = NULL;
	uint32_t cmd;
	uint32_t did;

	bzero((void *) &abort, sizeof (Q));

	mutex_enter(&EMLXS_RINGTX_LOCK);

	for (ringno = 0; ringno < hba->ring_count; ringno++) {
		rp = &hba->ring[ringno];

		mutex_enter(&EMLXS_FCTAB_LOCK(ringno));
		for (iotag = 1; iotag < rp->max_iotag; iotag++) {
			sbp = rp->fc_table[iotag];
			if (sbp && (sbp != STALE_PACKET) &&
			    (sbp->pkt_flags & PACKET_IN_TXQ)) {
				nlp = sbp->node;
				iocbq = &sbp->iocbq;

				if (iocbq->flag & IOCB_PRIORITY) {
					iocbq = (IOCBQ *)
					    nlp->nlp_ptx[ringno].q_first;
				} else {
					iocbq = (IOCBQ *)
					    nlp->nlp_tx[ringno].q_first;
				}

				/* Find a matching entry */
				found = 0;
				while (iocbq) {
					if (iocbq == &sbp->iocbq) {
						found = 1;
						break;
					}
					iocbq = (IOCBQ *) iocbq->next;
				}

				if (!found) {
					if (!(sbp->pkt_flags & PACKET_STALE)) {
						mutex_enter(&sbp->mtx);
						sbp->pkt_flags |= PACKET_STALE;
						mutex_exit(&sbp->mtx);
					} else {
						if (abort.q_first == 0) {
							abort.q_first =
							    &sbp->iocbq;
							abort.q_last =
							    &sbp->iocbq;
						} else {
							((IOCBQ *)
							    abort.q_last)->next=
							    &sbp->iocbq;
						}

						abort.q_cnt++;
					}

				} else {
					if ((sbp->pkt_flags & PACKET_STALE)) {
						mutex_enter(&sbp->mtx);
						sbp->pkt_flags &= ~PACKET_STALE;
						mutex_exit(&sbp->mtx);
					}
				}
			}
		}
		mutex_exit(&EMLXS_FCTAB_LOCK(ringno));
	}

	iocbq = (IOCBQ *) abort.q_first;
	while (iocbq) {
		next = (IOCBQ *) iocbq->next;
		iocbq->next = NULL;
		sbp = (emlxs_buf_t *)iocbq->sbp;

		pkt = PRIV2PKT(sbp);
		if (pkt) {
			did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);
			cmd = *((uint32_t *)pkt->pkt_cmd);
			cmd = SWAP_DATA32(cmd);
		}


		emlxs_tx_put(iocbq, 0);

		iocbq = next;

	}	/* end of while */

	mutex_exit(&EMLXS_RINGTX_LOCK);

	return;

} /* emlxs_tx_watchdog() */

#endif	/* TX_WATCHDOG */


#ifdef DHCHAP_SUPPORT

static void
emlxs_timer_check_dhchap(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	uint32_t i;
	NODELIST *ndlp = NULL;

	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		ndlp = port->node_table[i];

		if (!ndlp) {
			continue;
		}
		/* Check authentication response timeout */
		if (ndlp->node_dhc.nlp_authrsp_tmo &&
		    (hba->timer_tics >= ndlp->node_dhc.nlp_authrsp_tmo)) {
			/* Trigger authresp timeout handler */
			(void) emlxs_dhc_authrsp_timeout(port, ndlp, NULL);
		}
		/* Check reauthentication timeout */
		if (ndlp->node_dhc.nlp_reauth_tmo &&
		    (hba->timer_tics >= ndlp->node_dhc.nlp_reauth_tmo)) {
			/* Trigger reauth timeout handler */
			emlxs_dhc_reauth_timeout(port, NULL, ndlp);
		}
	}
	return;

} /* emlxs_timer_check_dhchap */

#endif	/* DHCHAP_SUPPORT */
