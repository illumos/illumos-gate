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


/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_NODE_C);


extern void
emlxs_node_close(emlxs_port_t *port, NODELIST *ndlp, uint32_t ringno,
    uint32_t tics)
{
	emlxs_hba_t *hba = HBA;
	RING *rp;
	NODELIST *prev;

	/* If node is on a ring service queue, then remove it */
	mutex_enter(&EMLXS_RINGTX_LOCK);

	/* Return if node destroyed */
	if (!ndlp || !ndlp->nlp_active) {
		mutex_exit(&EMLXS_RINGTX_LOCK);

		return;
	}
	if (ringno == FC_IP_RING) {
		/* Clear IP XRI */
		ndlp->nlp_Xri = 0;
	}
	/* Check if node is already closed */
	if (ndlp->nlp_flag[ringno] & NLP_CLOSED) {
		/* If so, check to see if the timer needs to be updated */
		if (tics) {
			if ((ndlp->nlp_tics[ringno] &&
			    (ndlp->nlp_tics[ringno] <
			    (tics + hba->timer_tics))) ||
			    !(ndlp->nlp_flag[ringno] & NLP_TIMER)) {

				ndlp->nlp_tics[ringno] = hba->timer_tics + tics;
				ndlp->nlp_flag[ringno] |= NLP_TIMER;

				mutex_exit(&EMLXS_RINGTX_LOCK);

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_node_closed_msg,
				    "node=%p did=%06x %s. timeout=%d updated.",
				    ndlp, ndlp->nlp_DID,
				    emlxs_ring_xlate(ringno), tics);
				return;
			}
		}
		mutex_exit(&EMLXS_RINGTX_LOCK);

		return;
	}
	/* Set the node closed */
	ndlp->nlp_flag[ringno] |= NLP_CLOSED;

	if (tics) {
		ndlp->nlp_tics[ringno] = hba->timer_tics + tics;
		ndlp->nlp_flag[ringno] |= NLP_TIMER;
	}

	if (ndlp->nlp_next[ringno]) {
		/* Remove node from ring queue */
		rp = &hba->ring[ringno];

		/* If this is the only node on list */
		if (rp->nodeq.q_first == (void *) ndlp && rp->nodeq.q_last ==
		    (void *) ndlp) {
			rp->nodeq.q_last = NULL;
			rp->nodeq.q_first = NULL;
			rp->nodeq.q_cnt = 0;
		} else if (rp->nodeq.q_first == (void *) ndlp) {
			rp->nodeq.q_first = ndlp->nlp_next[ringno];
			((NODELIST *) rp->nodeq.q_last)->nlp_next[ringno] =
			    rp->nodeq.q_first;
			rp->nodeq.q_cnt--;
		} else {	/* This is a little more difficult */
			/* Find the previous node in the circular ring queue */
			prev = ndlp;
			while (prev->nlp_next[ringno] != ndlp) {
				prev = prev->nlp_next[ringno];
			}

			prev->nlp_next[ringno] = ndlp->nlp_next[ringno];

			if (rp->nodeq.q_last == (void *) ndlp) {
				rp->nodeq.q_last = (void *) prev;
			}
			rp->nodeq.q_cnt--;

		}

		/* Clear node */
		ndlp->nlp_next[ringno] = NULL;
	}
	mutex_exit(&EMLXS_RINGTX_LOCK);
	if (tics) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_closed_msg,
		    "node=%p did=%06x %s. timeout=%d set.",
		    ndlp, ndlp->nlp_DID, emlxs_ring_xlate(ringno), tics);

	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_closed_msg,
		    "node=%p did=%06x %s.", ndlp, ndlp->nlp_DID,
		    emlxs_ring_xlate(ringno));
	}

	return;

} /* emlxs_node_close() */


extern void
emlxs_node_open(emlxs_port_t *port, NODELIST * ndlp, uint32_t ringno)
{
	emlxs_hba_t *hba = HBA;
	RING *rp;
	uint32_t found;
	NODELIST *nlp;
	MAILBOXQ *mbox;
	uint32_t i;
	uint32_t logit = 0;

	/* If node needs servicing, then add it to the ring queues */
	mutex_enter(&EMLXS_RINGTX_LOCK);

	/* Return if node destroyed */
	if (!ndlp || !ndlp->nlp_active) {
		mutex_exit(&EMLXS_RINGTX_LOCK);

		return;
	}
	/* Return if node already open */
	if (!(ndlp->nlp_flag[ringno] & NLP_CLOSED)) {
		mutex_exit(&EMLXS_RINGTX_LOCK);

		return;
	}
	/* Set the node open (not closed) */
	ndlp->nlp_flag[ringno] &= ~NLP_CLOSED;

	if ((ndlp->nlp_flag[ringno] & NLP_TIMER) && ndlp->nlp_tics[ringno] &&
	    (ndlp->nlp_tics[ringno] <= hba->timer_tics)) {
		logit = 1;
	}

	/* Clear the timer */
	ndlp->nlp_flag[ringno] &= ~NLP_TIMER;
	ndlp->nlp_tics[ringno] = 0;

	/*
	 * If the ptx or the tx queue needs servicing and the node is not
	 * already on the ring queue
	 */
	if ((ndlp->nlp_ptx[ringno].q_first || ndlp->nlp_tx[ringno].q_first) &&
	    !ndlp->nlp_next[ringno]) {
		rp = &hba->ring[ringno];

		/* If so, then add it to the ring queue */
		if (rp->nodeq.q_first) {
			((NODELIST *)rp->nodeq.q_last)->nlp_next[ringno] =
			    (uint8_t *)ndlp;
			ndlp->nlp_next[ringno] = rp->nodeq.q_first;

			/*
			 * If this is not the base node then add it to the
			 * tail
			 */
			if (!ndlp->nlp_base) {
				rp->nodeq.q_last = (uint8_t *)ndlp;
			} else {	/* Otherwise, add it to the head */
				/* The command node always gets priority */
				rp->nodeq.q_first = (uint8_t *)ndlp;
			}

			rp->nodeq.q_cnt++;
		} else {
			rp->nodeq.q_first = (uint8_t *)ndlp;
			rp->nodeq.q_last = (uint8_t *)ndlp;
			ndlp->nlp_next[ringno] = ndlp;
			rp->nodeq.q_cnt = 1;
		}
	}
	mutex_exit(&EMLXS_RINGTX_LOCK);

	if (logit) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_opened_msg,
		    "node=%p did=%06x %s. Timeout.", ndlp, ndlp->nlp_DID,
		    emlxs_ring_xlate(ringno));
	}

	/* If link attention needs to be cleared */
	if ((hba->state == FC_LINK_UP) &&
	    (ringno == FC_FCP_RING)) {

		/* Scan to see if any FCP2 devices are still closed */
		found = 0;
		rw_enter(&port->node_rwlock, RW_READER);
		for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
			nlp = port->node_table[i];
			while (nlp != NULL) {
				if ((nlp->nlp_fcp_info & NLP_FCP_2_DEVICE) &&
				    (nlp->nlp_flag[FC_FCP_RING] & NLP_CLOSED)) {
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
			/* Clear link attention */
			if ((mbox = (MAILBOXQ *)
			    emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
				mutex_enter(&EMLXS_PORT_LOCK);

				/*
				 * If state is not FC_LINK_UP, then either
				 * the link has gone down or a FC_CLEAR_LA
				 * has already been issued
				 */
				if (hba->state != FC_LINK_UP) {
					mutex_exit(&EMLXS_PORT_LOCK);
					(void) emlxs_mem_put(hba, MEM_MBOX,
					    (uint8_t *)mbox);
					goto done;
				}
				emlxs_ffstate_change_locked(hba, FC_CLEAR_LA);
				hba->discovery_timer = 0;
				mutex_exit(&EMLXS_PORT_LOCK);

				emlxs_mb_clear_la(hba, (MAILBOX *) mbox);

				if (emlxs_mb_issue_cmd(hba, (MAILBOX *) mbox,
				    MBX_NOWAIT, 0) != MBX_BUSY) {
					(void) emlxs_mem_put(hba, MEM_MBOX,
					    (uint8_t *)mbox);
				}
			} else {
				/*
				 * Close the node and try again in a few
				 * seconds
				 */
				emlxs_node_close(port, ndlp, ringno, 5);
				return;
			}
		}
	}
done:

	/* Wake any sleeping threads */
	mutex_enter(&EMLXS_PKT_LOCK);
	cv_broadcast(&EMLXS_PKT_CV);
	mutex_exit(&EMLXS_PKT_LOCK);

	return;

} /* emlxs_node_open() */


static int
emlxs_node_match_did(emlxs_port_t *port, NODELIST *ndlp, uint32_t did)
{
	D_ID mydid;
	D_ID odid;
	D_ID ndid;

	if (ndlp->nlp_DID == did) {
		return (1);
	}

	/*
	 * Next check for area/domain == 0 match
	 */
	mydid.un.word = port->did;
	if ((mydid.un.b.domain == 0) && (mydid.un.b.area == 0)) {
		goto out;
	}
	ndid.un.word = did;
	odid.un.word = ndlp->nlp_DID;
	if (ndid.un.b.id == odid.un.b.id) {
		if ((mydid.un.b.domain == ndid.un.b.domain) &&
		    (mydid.un.b.area == ndid.un.b.area)) {
			ndid.un.word = ndlp->nlp_DID;
			odid.un.word = did;
			if ((ndid.un.b.domain == 0) &&
			    (ndid.un.b.area == 0)) {
				return (1);
			}
			goto out;
		}
		ndid.un.word = ndlp->nlp_DID;
		if ((mydid.un.b.domain == ndid.un.b.domain) &&
		    (mydid.un.b.area == ndid.un.b.area)) {
			odid.un.word = ndlp->nlp_DID;
			ndid.un.word = did;
			if ((ndid.un.b.domain == 0) &&
			    (ndid.un.b.area == 0)) {
				return (1);
			}
		}
	}
out:

	return (0);

} /* End emlxs_node_match_did */



extern NODELIST *
emlxs_node_find_mac(emlxs_port_t *port, uint8_t *mac)
{
	NODELIST *nlp;
	uint32_t i;

	rw_enter(&port->node_rwlock, RW_READER);
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = port->node_table[i];
		while (nlp != NULL) {
			/*
			 * If portname matches mac address, return NODELIST
			 * entry
			 */
			if ((nlp->nlp_portname.IEEE[0] == mac[0])) {
				if ((nlp->nlp_DID != Bcast_DID) &&
				    ((nlp->nlp_DID & Fabric_DID_MASK) ==
				    Fabric_DID_MASK)) {
					nlp = (NODELIST *) nlp->nlp_list_next;
					continue;
				}
				if ((nlp->nlp_portname.IEEE[1] == mac[1]) &&
				    (nlp->nlp_portname.IEEE[2] == mac[2]) &&
				    (nlp->nlp_portname.IEEE[3] == mac[3]) &&
				    (nlp->nlp_portname.IEEE[4] == mac[4]) &&
				    (nlp->nlp_portname.IEEE[5] == mac[5])) {
					rw_exit(&port->node_rwlock);
					return (nlp);
				}
			}
			nlp = (NODELIST *) nlp->nlp_list_next;
		}
	}
	rw_exit(&port->node_rwlock);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_not_found_msg,
	    "find: MAC=%02x%02x%02x%02x%02x%02x",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return (NULL);

} /* emlxs_node_find_mac() */


extern NODELIST *
emlxs_node_find_did(emlxs_port_t *port, uint32_t did)
{
	emlxs_hba_t *hba = HBA;
	NODELIST *nlp;
	uint32_t hash;

	/* Check for invalid node ids  */
	if (did == 0 || (did & 0xff000000)) {
		return ((NODELIST *) 0);
	}
	/* Check for bcast node */
	if (did == Bcast_DID) {
		/* Use the base node here */
		return (&port->node_base);
	}
#ifdef MENLO_SUPPORT
	/* Check for menlo node */
	if (did == EMLXS_MENLO_DID) {
		/* Use the base node here */
		return (&port->node_base);
	}
#endif	/* MENLO_SUPPORT */

	/* Check for host node */
	if (did == port->did && !(hba->flag & FC_LOOPBACK_MODE)) {
		/* Use the base node here */
		return (&port->node_base);
	}
	/*
	 * Convert well known fabric addresses to the Fabric_DID, since we
	 * don't login to some of them
	 */
	if ((did == SCR_DID)) {
		did = Fabric_DID;
	}
	rw_enter(&port->node_rwlock, RW_READER);
	hash = EMLXS_DID_HASH(did);
	nlp = port->node_table[hash];
	while (nlp != NULL) {
		/* Check for obvious match */
		if (nlp->nlp_DID == did) {
			rw_exit(&port->node_rwlock);
			return (nlp);
		}
		/* Check for detailed match */
		else if (emlxs_node_match_did(port, nlp, did)) {
			rw_exit(&port->node_rwlock);
			return (nlp);
		}
		nlp = (NODELIST *) nlp->nlp_list_next;
	}
	rw_exit(&port->node_rwlock);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_not_found_msg,
	    "find: did=%x", did);

	/* no match found */
	return ((NODELIST *) 0);

} /* emlxs_node_find_did() */


extern NODELIST *
emlxs_node_find_rpi(emlxs_port_t *port, uint32_t rpi)
{
	NODELIST *nlp;
	uint32_t i;

	rw_enter(&port->node_rwlock, RW_READER);
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = port->node_table[i];
		while (nlp != NULL) {
			if (nlp->nlp_Rpi == rpi) {
				rw_exit(&port->node_rwlock);
				return (nlp);
			}
			nlp = (NODELIST *) nlp->nlp_list_next;
		}
	}
	rw_exit(&port->node_rwlock);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_not_found_msg,
	    "find: rpi=%x", rpi);

	/* no match found */
	return ((NODELIST *) 0);

} /* emlxs_node_find_rpi() */


extern NODELIST *
emlxs_node_find_wwpn(emlxs_port_t *port, uint8_t *wwpn)
{
	NODELIST *nlp;
	uint32_t i;
	uint32_t j;
	uint8_t *bptr1;
	uint8_t *bptr2;

	rw_enter(&port->node_rwlock, RW_READER);
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = port->node_table[i];
		while (nlp != NULL) {
			bptr1 = (uint8_t *)&nlp->nlp_portname;
			bptr1 += 7;
			bptr2 = (uint8_t *)wwpn;
			bptr2 += 7;

			for (j = 0; j < 8; j++) {
				if (*bptr1-- != *bptr2--) {
					break;
				}
			}

			if (j == 8) {
				rw_exit(&port->node_rwlock);
				return (nlp);
			}
			nlp = (NODELIST *) nlp->nlp_list_next;
		}
	}
	rw_exit(&port->node_rwlock);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_not_found_msg,
	    "find: wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
	    wwpn[0], wwpn[1], wwpn[2], wwpn[3],
	    wwpn[4], wwpn[5], wwpn[6], wwpn[7]);

	/* no match found */
	return ((NODELIST *) 0);

} /* emlxs_node_find_wwpn() */


extern NODELIST *
emlxs_node_find_index(emlxs_port_t *port, uint32_t index, uint32_t nports_only)
{
	NODELIST *nlp;
	uint32_t i;
	uint32_t count;

	rw_enter(&port->node_rwlock, RW_READER);

	if (index > port->node_count - 1) {
		rw_exit(&port->node_rwlock);
		return (NULL);
	}
	count = 0;
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = port->node_table[i];
		while (nlp != NULL) {
			/* Skip fabric ports if requested */
			if (nports_only && (nlp->nlp_DID & 0xFFF000) ==
			    0xFFF000) {
				nlp = (NODELIST *) nlp->nlp_list_next;
				continue;
			}
			if (count == index) {
				rw_exit(&port->node_rwlock);
				return (nlp);
			}
			nlp = (NODELIST *) nlp->nlp_list_next;
			count++;
		}
	}
	rw_exit(&port->node_rwlock);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_not_found_msg,
	    "find: index=%d", index);

	/* no match found */
	return ((NODELIST *) 0);

} /* emlxs_node_find_wwpn() */


extern uint32_t
emlxs_nport_count(emlxs_port_t *port)
{
	NODELIST *nlp;
	uint32_t i;
	uint32_t nport_count = 0;

	rw_enter(&port->node_rwlock, RW_READER);
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = port->node_table[i];
		while (nlp != NULL) {
			if ((nlp->nlp_DID & 0xFFF000) != 0xFFF000) {
				nport_count++;
			}
			nlp = (NODELIST *) nlp->nlp_list_next;
		}
	}
	rw_exit(&port->node_rwlock);

	return (nport_count);

} /* emlxs_nport_count() */



extern void
emlxs_node_destroy_all(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	NODELIST *next;
	NODELIST *ndlp;
	uint8_t *wwn;
	uint32_t i;

	/* Flush and free the nodes */
	rw_enter(&port->node_rwlock, RW_WRITER);
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		ndlp = port->node_table[i];
		port->node_table[i] = 0;
		while (ndlp != NULL) {
			next = ndlp->nlp_list_next;
			ndlp->nlp_list_next = NULL;
			ndlp->nlp_list_prev = NULL;
			ndlp->nlp_active = 0;

			if (port->node_count) {
				port->node_count--;
			}
			wwn = (uint8_t *)&ndlp->nlp_portname;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_destroy_msg,
			    "did=%06x rpi=%x "
			    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x count=%d",
			    ndlp->nlp_DID, ndlp->nlp_Rpi,
			    wwn[0], wwn[1], wwn[2], wwn[3],
			    wwn[4], wwn[5], wwn[6], wwn[7], port->node_count);

			(void) emlxs_tx_node_flush(port, ndlp, 0, 0, 0);

			(void) emlxs_mem_put(hba, MEM_NLP, (uint8_t *)ndlp);

			ndlp = next;
		}
	}
	port->node_count = 0;
	rw_exit(&port->node_rwlock);

	/* Clean the base node */
	mutex_enter(&EMLXS_PORT_LOCK);
	port->node_base.nlp_list_next = NULL;
	port->node_base.nlp_list_prev = NULL;
	port->node_base.nlp_active = 1;
	mutex_exit(&EMLXS_PORT_LOCK);

	/* Flush the base node */
	(void) emlxs_tx_node_flush(port, &port->node_base, 0, 1, 0);
	(void) emlxs_chipq_node_flush(port, 0, &port->node_base, 0);

	return;

} /* emlxs_node_destroy_all() */


extern void
emlxs_node_add(emlxs_port_t *port, NODELIST *ndlp)
{
	NODELIST *np;
	uint8_t *wwn;
	uint32_t hash;

	rw_enter(&port->node_rwlock, RW_WRITER);
	hash = EMLXS_DID_HASH(ndlp->nlp_DID);
	np = port->node_table[hash];

	/*
	 * Insert node pointer to the head
	 */
	port->node_table[hash] = ndlp;
	if (!np) {
		ndlp->nlp_list_next = NULL;
	} else {
		ndlp->nlp_list_next = np;
	}
	port->node_count++;

	wwn = (uint8_t *)&ndlp->nlp_portname;
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_msg,
	    "node=%p did=%06x rpi=%x "
	    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x count=%d",
	    ndlp, ndlp->nlp_DID, ndlp->nlp_Rpi,
	    wwn[0], wwn[1], wwn[2], wwn[3],
	    wwn[4], wwn[5], wwn[6], wwn[7], port->node_count);

	rw_exit(&port->node_rwlock);

	return;

} /* emlxs_node_add() */


extern void
emlxs_node_rm(emlxs_port_t *port, NODELIST *ndlp)
{
	emlxs_hba_t *hba = HBA;
	NODELIST *np;
	NODELIST *prevp;
	uint8_t *wwn;
	uint32_t hash;

	rw_enter(&port->node_rwlock, RW_WRITER);
	hash = EMLXS_DID_HASH(ndlp->nlp_DID);
	np = port->node_table[hash];
	prevp = NULL;
	while (np != NULL) {
		if (np->nlp_DID == ndlp->nlp_DID) {
			if (prevp == NULL) {
				port->node_table[hash] = np->nlp_list_next;
			} else {
				prevp->nlp_list_next = np->nlp_list_next;
			}

			if (port->node_count) {
				port->node_count--;
			}
			wwn = (uint8_t *)&ndlp->nlp_portname;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_destroy_msg,
			    "did=%06x rpi=%x "
			    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x count=%d",
			    ndlp->nlp_DID, ndlp->nlp_Rpi,
			    wwn[0], wwn[1], wwn[2], wwn[3],
			    wwn[4], wwn[5], wwn[6], wwn[7], port->node_count);

			(void) emlxs_tx_node_flush(port, ndlp, 0, 1, 0);

			ndlp->nlp_active = 0;
			(void) emlxs_mem_put(hba, MEM_NLP, (uint8_t *)ndlp);

			break;
		}
		prevp = np;
		np = np->nlp_list_next;
	}
	rw_exit(&port->node_rwlock);

	return;

} /* emlxs_node_rm() */
