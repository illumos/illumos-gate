/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#include <emlxs.h>


/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_NODE_C);

static void	emlxs_node_add(emlxs_port_t *, NODELIST *);
static int	emlxs_node_match_did(emlxs_port_t *, NODELIST *, uint32_t);

/* Timeout == -1 will enable the offline timer */
/* Timeout not -1 will apply the timeout */
extern void
emlxs_node_close(emlxs_port_t *port, NODELIST *ndlp, uint32_t channelno,
    int32_t timeout)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	CHANNEL *cp;
	NODELIST *prev;
	uint32_t offline = 0;


	/* If node is on a channel service queue, then remove it */
	mutex_enter(&EMLXS_TX_CHANNEL_LOCK);

	/* Return if node destroyed */
	if (!ndlp || !ndlp->nlp_active) {
		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

		return;
	}

	/* Check offline support */
	if (timeout == -1) {
		if (cfg[CFG_OFFLINE_TIMEOUT].current) {
			timeout = cfg[CFG_OFFLINE_TIMEOUT].current;
			offline = 1;
		} else {
			timeout = 0;
		}
	}

	if (channelno == hba->channel_ip) {
		/* Clear IP XRI */
		ndlp->nlp_Xri = 0;
	}

	/* Check if node is already closed */
	if (ndlp->nlp_flag[channelno] & NLP_CLOSED) {
		if (ndlp->nlp_flag[channelno] & NLP_OFFLINE) {
			mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
			return;
		}

		if (offline) {
			ndlp->nlp_tics[channelno] = hba->timer_tics + timeout;
			ndlp->nlp_flag[channelno] |= NLP_OFFLINE;
			mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_closed_msg,
			    "node=%p did=%06x channel=%d. offline=%d update.",
			    ndlp, ndlp->nlp_DID, channelno, timeout);

		} else if (timeout) {
			ndlp->nlp_tics[channelno] = hba->timer_tics + timeout;
			mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_closed_msg,
			    "node=%p did=%06x channel=%d. timeout=%d update.",
			    ndlp, ndlp->nlp_DID, channelno, timeout);
		} else {
			mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
		}

		return;
	}

	/* Set the node closed */
	ndlp->nlp_flag[channelno] |= NLP_CLOSED;

	if (offline) {
		ndlp->nlp_tics[channelno] = hba->timer_tics + timeout;
		ndlp->nlp_flag[channelno] |= NLP_OFFLINE;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_closed_msg,
		    "node=%p did=%06x channel=%d. offline=%d set.",
		    ndlp, ndlp->nlp_DID, channelno, timeout);

	} else if (timeout) {
		ndlp->nlp_tics[channelno] = hba->timer_tics + timeout;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_closed_msg,
		    "node=%p did=%06x channel=%d. timeout=%d set.",
		    ndlp, ndlp->nlp_DID, channelno, timeout);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_closed_msg,
		    "node=%p did=%06x channel=%d.",
		    ndlp, ndlp->nlp_DID, channelno);
	}


	/*
	 * ndlp->nlp_next[] and cp->nodeq list have to be updated
	 * simulaneously
	 */
	if (ndlp->nlp_next[channelno]) {
		/* Remove node from channel queue */
		cp = &hba->chan[channelno];

		/* If this is the only node on list */
		if (cp->nodeq.q_first == (void *)ndlp &&
		    cp->nodeq.q_last == (void *)ndlp) {
			cp->nodeq.q_last = NULL;
			cp->nodeq.q_first = NULL;
			cp->nodeq.q_cnt = 0;
		} else if (cp->nodeq.q_first == (void *)ndlp) {
			cp->nodeq.q_first = ndlp->nlp_next[channelno];
			((NODELIST *)cp->nodeq.q_last)->nlp_next[channelno] =
			    cp->nodeq.q_first;
			cp->nodeq.q_cnt--;
		} else {	/* This is a little more difficult */

			/* Find the previous node in circular channel queue */
			prev = ndlp;
			while (prev->nlp_next[channelno] != ndlp) {
				prev = prev->nlp_next[channelno];
			}

			prev->nlp_next[channelno] = ndlp->nlp_next[channelno];

			if (cp->nodeq.q_last == (void *)ndlp) {
				cp->nodeq.q_last = (void *)prev;
			}
			cp->nodeq.q_cnt--;

		}

		/* Clear node */
		ndlp->nlp_next[channelno] = NULL;
	}

	mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

	return;

} /* emlxs_node_close() */


/* Called by emlxs_timer_check_nodes() */
extern void
emlxs_node_timeout(emlxs_port_t *port, NODELIST *ndlp, uint32_t channelno)
{
	emlxs_hba_t *hba = HBA;

	/* If node needs servicing, then add it to the channel queues */
	mutex_enter(&EMLXS_TX_CHANNEL_LOCK);

	/* Return if node destroyed */
	if (!ndlp || !ndlp->nlp_active) {
		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
		return;
	}

	/* Open the node if not offline */
	if (!(ndlp->nlp_flag[channelno] & NLP_OFFLINE)) {
		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_timeout_msg,
		    "node=%p did=%06x channel=%d Opening.", ndlp, ndlp->nlp_DID,
		    channelno);

		emlxs_node_open(port, ndlp, channelno);
		return;
	}

	/* OFFLINE TIMEOUT OCCURRED! */

	/* Clear the timer */
	ndlp->nlp_tics[channelno] = 0;

	mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_timeout_msg,
	    "node=%p did=%06x channel=%d. Flushing.", ndlp, ndlp->nlp_DID,
	    channelno);

	/* Flush tx queue for this channel */
	(void) emlxs_tx_node_flush(port, ndlp, &hba->chan[channelno], 0, 0);

	/* Flush chip queue for this channel */
	(void) emlxs_chipq_node_flush(port, &hba->chan[channelno], ndlp, 0);

	return;

} /* emlxs_node_timeout() */


extern void
emlxs_node_open(emlxs_port_t *port, NODELIST *ndlp, uint32_t channelno)
{
	emlxs_hba_t *hba = HBA;
	CHANNEL *cp;
	uint32_t found;
	NODELIST *nlp;
	MAILBOXQ *mbox;
	uint32_t i;
	int rc;

	/* If node needs servicing, then add it to the channel queues */
	mutex_enter(&EMLXS_TX_CHANNEL_LOCK);

	/* Return if node destroyed */
	if (!ndlp || !ndlp->nlp_active) {
		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

		return;
	}

	/* Return if node already open */
	if (!(ndlp->nlp_flag[channelno] & NLP_CLOSED)) {
		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

		return;
	}

	/* Set the node open (not closed) */
	ndlp->nlp_flag[channelno] &= ~(NLP_CLOSED|NLP_OFFLINE);

	/* Clear the timer */
	ndlp->nlp_tics[channelno] = 0;

	/*
	 * If the ptx or the tx queue needs servicing and
	 * the node is not already on the channel queue
	 */
	if ((ndlp->nlp_ptx[channelno].q_first ||
	    ndlp->nlp_tx[channelno].q_first) && !ndlp->nlp_next[channelno]) {
		cp = &hba->chan[channelno];

		/* If so, then add it to the channel queue */
		if (cp->nodeq.q_first) {
			((NODELIST *)cp->nodeq.q_last)->nlp_next[channelno] =
			    (uint8_t *)ndlp;
			ndlp->nlp_next[channelno] = cp->nodeq.q_first;

			/* If this is not the base node then */
			/* add it to the tail */
			if (!ndlp->nlp_base) {
				cp->nodeq.q_last = (uint8_t *)ndlp;
			} else {	/* Otherwise, add it to the head */

				/* The command node always gets priority */
				cp->nodeq.q_first = (uint8_t *)ndlp;
			}

			cp->nodeq.q_cnt++;
		} else {
			cp->nodeq.q_first = (uint8_t *)ndlp;
			cp->nodeq.q_last = (uint8_t *)ndlp;
			ndlp->nlp_next[channelno] = ndlp;
			cp->nodeq.q_cnt = 1;
		}
	}

	mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_opened_msg,
	    "node=%p did=%06x rpi=%d channel=%d", ndlp, ndlp->nlp_DID,
	    ndlp->nlp_Rpi, channelno);

	/* If link attention needs to be cleared */
	if ((hba->state == FC_LINK_UP) && (channelno == hba->channel_fcp)) {
		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			goto done;
		}

		/* Scan to see if any FCP2 devices are still closed */
		found = 0;
		rw_enter(&port->node_rwlock, RW_READER);
		for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
			nlp = port->node_table[i];
			while (nlp != NULL) {
				if ((nlp->nlp_fcp_info & NLP_FCP_2_DEVICE) &&
				    (nlp->nlp_flag[hba->channel_fcp] &
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
			/* Clear link attention */
			if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
			    MEM_MBOX))) {
				mutex_enter(&EMLXS_PORT_LOCK);

				/*
				 * If state is not FC_LINK_UP, then either the
				 * link has gone down or a FC_CLEAR_LA has
				 * already been issued
				 */
				if (hba->state != FC_LINK_UP) {
					mutex_exit(&EMLXS_PORT_LOCK);
					emlxs_mem_put(hba, MEM_MBOX,
					    (void *)mbox);
					goto done;
				}

				EMLXS_STATE_CHANGE_LOCKED(hba, FC_CLEAR_LA);
				hba->discovery_timer = 0;
				mutex_exit(&EMLXS_PORT_LOCK);

				emlxs_mb_clear_la(hba, mbox);

				rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba,
				    mbox, MBX_NOWAIT, 0);
				if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
					emlxs_mem_put(hba, MEM_MBOX,
					    (void *)mbox);
				}
			} else {
				/* Close the node and try again */
				/* in a few seconds */
				emlxs_node_close(port, ndlp, channelno, 5);
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

	if (ndlp->nlp_DID == did)
		return (1);

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
			if ((ndid.un.b.domain == 0) && (ndid.un.b.area == 0)) {
				return (1);
			}
			goto out;
		}

		ndid.un.word = ndlp->nlp_DID;
		if ((mydid.un.b.domain == ndid.un.b.domain) &&
		    (mydid.un.b.area == ndid.un.b.area)) {
			odid.un.word = ndlp->nlp_DID;
			ndid.un.word = did;
			if ((ndid.un.b.domain == 0) && (ndid.un.b.area == 0)) {
				return (1);
			}
		}
	}

out:

	return (0);

} /* emlxs_node_match_did() */



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
			 * If portname matches mac address,
			 * return NODELIST entry
			 */
			if ((nlp->nlp_portname.IEEE[0] == mac[0])) {
				if ((nlp->nlp_DID != BCAST_DID) &&
				    ((nlp->nlp_DID & FABRIC_DID_MASK) ==
				    FABRIC_DID_MASK)) {
					nlp = (NODELIST *)nlp->nlp_list_next;
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

			nlp = (NODELIST *)nlp->nlp_list_next;
		}
	}
	rw_exit(&port->node_rwlock);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_not_found_msg,
	    "find: MAC=%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2],
	    mac[3], mac[4], mac[5]);

	return (NULL);

} /* emlxs_node_find_mac() */


extern NODELIST *
emlxs_node_find_did(emlxs_port_t *port, uint32_t did, uint32_t lock)
{
	emlxs_hba_t *hba = HBA;
	NODELIST *nlp;
	uint32_t hash;

	/* Check for invalid node ids  */
	if ((did == 0) && (!(hba->flag & FC_LOOPBACK_MODE))) {
		return ((NODELIST *)0);
	}

	if (did & 0xff000000) {
		return ((NODELIST *)0);
	}

	/* Check for bcast node */
	if (did == BCAST_DID) {
		/* Use the base node here */
		return (&port->node_base);
	}
#ifdef MENLO_SUPPORT
	/* Check for menlo node */
	if (did == EMLXS_MENLO_DID) {
		/* Use the base node here */
		return (&port->node_base);
	}
#endif /* MENLO_SUPPORT */

	/* Check for host node */
	if (did == port->did && !(hba->flag & FC_LOOPBACK_MODE)) {
		/* Use the base node here */
		return (&port->node_base);
	}

	/*
	 * Convert well known fabric addresses to the FABRIC_DID,
	 * since we don't login to some of them
	 */
	if ((did == SCR_DID)) {
		did = FABRIC_DID;
	}

	if (lock) {
		rw_enter(&port->node_rwlock, RW_READER);
	}
	hash = EMLXS_DID_HASH(did);
	nlp = port->node_table[hash];
	while (nlp != NULL) {
		/* Check for obvious match */
		if (nlp->nlp_DID == did) {
			if (lock) {
				rw_exit(&port->node_rwlock);
			}
			return (nlp);
		}

		/* Check for detailed match */
		else if (emlxs_node_match_did(port, nlp, did)) {
			if (lock) {
				rw_exit(&port->node_rwlock);
			}
			return (nlp);
		}

		nlp = (NODELIST *)nlp->nlp_list_next;
	}

	if (lock) {
		rw_exit(&port->node_rwlock);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_not_found_msg, "find: did=%x",
	    did);

	/* no match found */
	return ((NODELIST *)0);

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

			nlp = (NODELIST *)nlp->nlp_list_next;
		}
	}
	rw_exit(&port->node_rwlock);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_not_found_msg, "find: rpi=%d",
	    rpi);

	/* no match found */
	return ((NODELIST *)0);

} /* emlxs_node_find_rpi() */


extern NODELIST *
emlxs_node_find_wwpn(emlxs_port_t *port, uint8_t *wwpn, uint32_t lock)
{
	NODELIST *nlp;
	uint32_t i;
	uint32_t j;
	uint8_t *bptr1;
	uint8_t *bptr2;

	if (lock) {
		rw_enter(&port->node_rwlock, RW_READER);
	}

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
				if (lock) {
					rw_exit(&port->node_rwlock);
				}
				return (nlp);
			}

			nlp = (NODELIST *)nlp->nlp_list_next;
		}
	}

	if (lock) {
		rw_exit(&port->node_rwlock);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_not_found_msg,
	    "find: wwpn=%02x%02x%02x%02x%02x%02x%02x%02x", wwpn[0], wwpn[1],
	    wwpn[2], wwpn[3], wwpn[4], wwpn[5], wwpn[6], wwpn[7]);

	/* no match found */
	return ((NODELIST *)0);

} /* emlxs_node_find_wwpn() */


extern NODELIST *
emlxs_node_find_index(emlxs_port_t *port, uint32_t index,
    uint32_t nports_only)
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
			if (nports_only &&
			    (nlp->nlp_DID & 0xFFF000) == 0xFFF000) {
				nlp = (NODELIST *)nlp->nlp_list_next;
				continue;
			}

			if (count == index) {
				rw_exit(&port->node_rwlock);
				return (nlp);
			}

			nlp = (NODELIST *)nlp->nlp_list_next;
			count++;
		}
	}
	rw_exit(&port->node_rwlock);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_not_found_msg, "find: index=%d",
	    index);

	/* no match found */
	return ((NODELIST *)0);

} /* emlxs_node_find_index() */


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

			nlp = (NODELIST *)nlp->nlp_list_next;
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
	RPIobj_t *rpip;
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
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_node_destroy_msg, "did=%06x "
			    "rpi=%d wwpn=%02x%02x%02x%02x%02x%02x%02x%02x "
			    "count=%d", ndlp->nlp_DID, ndlp->nlp_Rpi, wwn[0],
			    wwn[1], wwn[2], wwn[3], wwn[4], wwn[5], wwn[6],
			    wwn[7], port->node_count);

			(void) emlxs_tx_node_flush(port, ndlp, 0, 0, 0);

			/* Break Node/RPI binding */
			if (ndlp->rpip) {
				rpip = ndlp->rpip;

				ndlp->rpip = NULL;
				rpip->node = NULL;

				(void) emlxs_rpi_free_notify(port, rpip);
			}

			emlxs_mem_put(hba, MEM_NLP, (void *)ndlp);

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


extern NODELIST *
emlxs_node_create(emlxs_port_t *port, uint32_t did, uint32_t rpi, SERV_PARM *sp)
{
	emlxs_hba_t *hba = HBA;
	NODELIST *ndlp, *ndlp_wwn;
	uint8_t *wwn;
	emlxs_vvl_fmt_t vvl;
	RPIobj_t *rpip;

	rw_enter(&port->node_rwlock, RW_WRITER);

	ndlp = emlxs_node_find_did(port, did, 0);
	ndlp_wwn = emlxs_node_find_wwpn(port, (uint8_t *)&sp->portName, 0);

	/* Zero out the stale node worldwide names */
	if (ndlp_wwn && (ndlp != ndlp_wwn)) {
		bzero((uint8_t *)&ndlp_wwn->nlp_nodename, sizeof (NAME_TYPE));
		bzero((uint8_t *)&ndlp_wwn->nlp_portname, sizeof (NAME_TYPE));
	}

	/* Update the node */
	if (ndlp) {
		ndlp->nlp_Rpi = (uint16_t)rpi;
		ndlp->nlp_DID = did;

		bcopy((uint8_t *)sp, (uint8_t *)&ndlp->sparm,
		    sizeof (SERV_PARM));

		bcopy((uint8_t *)&sp->nodeName,
		    (uint8_t *)&ndlp->nlp_nodename,
		    sizeof (NAME_TYPE));

		bcopy((uint8_t *)&sp->portName,
		    (uint8_t *)&ndlp->nlp_portname,
		    sizeof (NAME_TYPE));

		/* Add Node/RPI binding */
		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			rpip = emlxs_rpi_find(port, rpi);

			if (rpip) {
				rpip->node = ndlp;
				ndlp->rpip = rpip;
			} else {
				ndlp->rpip = NULL;

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_node_create_msg,
				    "Unable to find RPI. did=%x rpi=%d",
				    did, rpi);
			}
		} else {
			ndlp->rpip = NULL;
		}

		wwn = (uint8_t *)&ndlp->nlp_portname;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_update_msg,
		    "node=%p did=%06x rpi=%d "
		    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
		    ndlp, ndlp->nlp_DID, ndlp->nlp_Rpi, wwn[0],
		    wwn[1], wwn[2], wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

		goto done;
	}

	/* Allocate a new node */
	ndlp = (NODELIST *)emlxs_mem_get(hba, MEM_NLP);

	if (ndlp) {
		ndlp->nlp_Rpi = (uint16_t)rpi;
		ndlp->nlp_DID = did;

		bcopy((uint8_t *)sp, (uint8_t *)&ndlp->sparm,
		    sizeof (SERV_PARM));

		bcopy((uint8_t *)&sp->nodeName,
		    (uint8_t *)&ndlp->nlp_nodename,
		    sizeof (NAME_TYPE));

		bcopy((uint8_t *)&sp->portName,
		    (uint8_t *)&ndlp->nlp_portname,
		    sizeof (NAME_TYPE));

		ndlp->nlp_active = 1;
		ndlp->nlp_flag[hba->channel_ct]  |= NLP_CLOSED;
		ndlp->nlp_flag[hba->channel_els] |= NLP_CLOSED;
		ndlp->nlp_flag[hba->channel_fcp] |= NLP_CLOSED;
		ndlp->nlp_flag[hba->channel_ip]  |= NLP_CLOSED;

		/* Add Node/RPI binding */
		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			rpip = emlxs_rpi_find(port, rpi);

			if (rpip) {
				rpip->node = ndlp;
				ndlp->rpip = rpip;
			} else {
				ndlp->rpip = NULL;

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_node_create_msg,
				    "Unable to find RPI. did=%x rpi=%d",
				    did, rpi);
			}
		} else {
			ndlp->rpip = NULL;
		}

#ifdef NODE_THROTTLE_SUPPORT
		emlxs_node_throttle_set(port, ndlp);
#endif /* NODE_THROTTLE_SUPPORT */

		/* Add the node */
		emlxs_node_add(port, ndlp);

		goto done;
	}

	rw_exit(&port->node_rwlock);
	wwn = (uint8_t *)&sp->portName;
	EMLXS_MSGF(EMLXS_CONTEXT,
	    &emlxs_node_create_failed_msg,
	    "Unable to allocate node. did=%06x "
	    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
	    did, wwn[0], wwn[1], wwn[2],
	    wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

	return (NULL);

done:
	rw_exit(&port->node_rwlock);
	if (sp->VALID_VENDOR_VERSION) {
		bcopy((caddr_t *)&sp->vendorVersion[0],
		    (caddr_t *)&vvl, sizeof (emlxs_vvl_fmt_t));

		vvl.un0.word0 = LE_SWAP32(vvl.un0.word0);
		vvl.un1.word1 = LE_SWAP32(vvl.un1.word1);

		if ((vvl.un0.w0.oui == 0x0000C9) &&
		    (vvl.un1.w1.vport)) {
			ndlp->nlp_fcp_info |= NLP_EMLX_VPORT;
		}
	}

	/* Open the node */
	emlxs_node_open(port, ndlp, hba->channel_ct);
	emlxs_node_open(port, ndlp, hba->channel_els);
	emlxs_node_open(port, ndlp, hba->channel_ip);
	emlxs_node_open(port, ndlp, hba->channel_fcp);

	EMLXS_SET_DFC_STATE(ndlp, NODE_LOGIN);

	return (ndlp);

} /* emlxs_node_create() */


/* node_rwlock must be held when calling this routine */
static void
emlxs_node_add(emlxs_port_t *port, NODELIST *ndlp)
{
	NODELIST *np;
	uint8_t *wwn;
	uint32_t hash;

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
	    "node=%p did=%06x rpi=%d wwpn=%02x%02x%02x%02x%02x%02x%02x%02x "
	    "count=%d", ndlp, ndlp->nlp_DID, ndlp->nlp_Rpi, wwn[0], wwn[1],
	    wwn[2], wwn[3], wwn[4], wwn[5], wwn[6], wwn[7], port->node_count);

	return;

} /* emlxs_node_add() */


extern void
emlxs_node_rm(emlxs_port_t *port, NODELIST *ndlp)
{
	emlxs_hba_t *hba = HBA;
	NODELIST *np;
	NODELIST *prevp;
	RPIobj_t *rpip;
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
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_node_destroy_msg, "did=%06x "
			    "rpi=%d wwpn=%02x%02x%02x%02x%02x%02x%02x%02x "
			    "count=%d", ndlp->nlp_DID, ndlp->nlp_Rpi, wwn[0],
			    wwn[1], wwn[2], wwn[3], wwn[4], wwn[5], wwn[6],
			    wwn[7], port->node_count);

			(void) emlxs_tx_node_flush(port, ndlp, 0, 1, 0);

			ndlp->nlp_active = 0;

			/* Break Node/RPI binding */
			if (ndlp->rpip) {
				rpip = ndlp->rpip;

				ndlp->rpip = NULL;
				rpip->node = NULL;

				(void) emlxs_rpi_free_notify(port, rpip);
			}

			emlxs_mem_put(hba, MEM_NLP, (void *)ndlp);

			break;
		}
		prevp = np;
		np = np->nlp_list_next;
	}
	rw_exit(&port->node_rwlock);

	return;

} /* emlxs_node_rm() */


extern void
emlxs_node_throttle_set(emlxs_port_t *port, NODELIST *ndlp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	char prop[64];
	char buf1[32];
	uint32_t throttle;

	/* Set global default */
	throttle = (ndlp->nlp_fcp_info & NLP_FCP_TGT_DEVICE)?
	    cfg[CFG_TGT_DEPTH].current:0;

	/* Check per wwpn default */
	(void) snprintf(prop, sizeof (prop), "w%s-depth",
	    emlxs_wwn_xlate(buf1, sizeof (buf1),
	    (uint8_t *)&ndlp->nlp_portname));

	throttle = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY,
	    (void *)hba->dip, DDI_PROP_DONTPASS, prop, throttle);

	/* Check per driver/wwpn default */
	(void) snprintf(prop, sizeof (prop), "%s%d-w%s-depth", DRIVER_NAME,
	    hba->ddiinst, emlxs_wwn_xlate(buf1, sizeof (buf1),
	    (uint8_t *)&ndlp->nlp_portname));

	throttle = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY,
	    (void *)hba->dip, DDI_PROP_DONTPASS, prop, throttle);

	/* Check limit */
	throttle = MIN(throttle, MAX_NODE_THROTTLE);

	ndlp->io_throttle = throttle;

	return;

} /* emlxs_node_throttle_set() */
