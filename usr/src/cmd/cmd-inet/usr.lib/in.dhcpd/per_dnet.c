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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/dhcp.h>
#include "dhcpd.h"
#include "interfaces.h"
#include <locale.h>

/*
 * This file contains the access routines for the dhcp databases.
 */

static dsvc_dnet_t *get_dnet(struct in_addr *);
static boolean_t unhash_dnet(dsvc_dnet_t *, boolean_t);
static int dnet_cmp(dsvc_dnet_t *, dsvc_dnet_t *);
static dsvc_clnt_t *get_client(hash_tbl *, uchar_t *, uchar_t);
static int clnt_cmp(dsvc_clnt_t *, dsvc_clnt_t *);
static boolean_t unhash_clnt(dsvc_clnt_t *, boolean_t);
static boolean_t unhash_offer(dsvc_clnt_t *, boolean_t);

static hash_tbl	*ntable;		/* global per net datastore table */

/*
 * Initialize global per network hash table.
 *
 * Per-bucket rwlocks reduce lock contention between interface and
 * client threads.
 *
 * Performance: dynamically calculate hash table size.
 */
int
initntab(void)
{
	char **listppp;
	uint_t cnt = 0;
	uint_t ind;

	if (list_dd(&datastore, DSVC_DHCPNETWORK, &listppp, &cnt) ==
	    DSVC_SUCCESS) {
		if (listppp) {
			for (ind = 0; listppp[ind] != NULL && ind < cnt;
			    ind++)
				free(listppp[ind]);
			free(listppp);
		}
	}
	ntable = hash_Init(cnt, unhash_dnet, MAX(net_thresh, clnt_thresh),
	    B_TRUE);
	return (ntable == NULL ? -1 : 0);
}

/*
 * open_dnet: Open the appropriate dhcp database given a network address and
 * a subnet mask. These in_addr's are expected in network order.
 *
 * Returns: DSVC_SUCCESS for success or dsvc error.
 */
int
open_dnet(dsvc_dnet_t **pndp, struct in_addr *net, struct in_addr *mask)
{
	int		err;
	dsvc_dnet_t	*pnd;
	struct in_addr	datum;
	int		hsize = 0;
	uint32_t	query;
	dn_rec_t	dn;
	uint_t		count;
	struct in_addr	*oip;

	datum.s_addr = net->s_addr;
	datum.s_addr &= mask->s_addr;

	*pndp = NULL;
	/* Locate existing dnet. */
	if ((pnd = get_dnet(&datum)) != NULL) {
		(void) mutex_lock(&pnd->pnd_mtx);
		if ((pnd->flags & DHCP_PND_ERROR) != 0) {
			(void) mutex_unlock(&pnd->pnd_mtx);
			close_dnet(pnd, B_TRUE);
			return (DSVC_INTERNAL);
		} else if ((pnd->flags & DHCP_PND_CLOSING) != 0) {
			(void) mutex_unlock(&pnd->pnd_mtx);
			close_dnet(pnd, B_FALSE);
			return (DSVC_BUSY);
		} else {
			(void) mutex_unlock(&pnd->pnd_mtx);
			*pndp = pnd;
			return (DSVC_SUCCESS);
		}
	}

	/* Allocate new dnet. */

	pnd = (dsvc_dnet_t *)smalloc(sizeof (dsvc_dnet_t));
	pnd->net.s_addr = datum.s_addr;
	pnd->subnet.s_addr = mask != 0 ? mask->s_addr : htonl(INADDR_ANY);
	(void) inet_ntop(AF_INET, &datum, pnd->network, sizeof (pnd->network));

	/* Allocate hash tables. */
	if (max_clients != -1)
		hsize = max_clients;
	if ((pnd->ctable =
	    hash_Init(hsize, unhash_clnt, MAX(off_secs, clnt_thresh),
	    B_TRUE)) == NULL) {
		free(pnd);
		return (DSVC_INTERNAL);
	}
	if ((pnd->itable =
	    hash_Init(hsize, unhash_offer, off_secs, B_TRUE)) == NULL) {
		free(pnd->ctable);
		free(pnd);
		return (DSVC_INTERNAL);
	}

	err = dhcp_open_dd(&pnd->dh, &datastore, DSVC_DHCPNETWORK, pnd->network,
	    DSVC_READ|DSVC_WRITE);

	if (err != DSVC_SUCCESS) {
		free(pnd->ctable);
		free(pnd->itable);
		free(pnd);
		return (err);
	}

	/* Find out how many addresses the server owns in this datastore */

	pnd->naddrs = 0;
	for (oip = owner_ip; oip->s_addr != INADDR_ANY; oip++) {

		DSVC_QINIT(query);
		DSVC_QEQ(query, DN_QSIP);
		dn.dn_sip.s_addr = ntohl(oip->s_addr);

		err = lookup_dd(pnd->dh, B_FALSE, query, -1, &dn, NULL, &count);

		if (err != DSVC_SUCCESS) {
			free(pnd->ctable);
			free(pnd->itable);
			free(pnd);
			return (err);
		}

		pnd->naddrs += count;
	}

	if ((pnd->hand = hash_Insert(ntable, &pnd->net, sizeof (struct in_addr),
	    dnet_cmp, pnd, pnd)) == NULL) {
		/* Another thread has begun work on this net. */
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "Duplicate network: %s\n", pnd->network);
#endif	/* DEBUG */
		free(pnd->ctable);
		free(pnd->itable);
		free(pnd);
		return (DSVC_BUSY);
	}

	(void) mutex_init(&pnd->pnd_mtx, USYNC_THREAD, NULL);
	(void) mutex_init(&pnd->thr_mtx, USYNC_THREAD, NULL);
	(void) mutex_init(&pnd->free_mtx, USYNC_THREAD, NULL);
	(void) mutex_init(&pnd->lru_mtx, USYNC_THREAD, NULL);
	(void) mutex_init(&pnd->lrupage_mtx, USYNC_THREAD, NULL);

	*pndp = pnd;
	return (DSVC_SUCCESS);
}

/*
 * close_dnet: Closes specified dhcp-network database.
 *
 * delete - immediately delete.
 */
void
close_dnet(dsvc_dnet_t *pnd, boolean_t delete)
{
	hash_Rele(pnd->hand, delete);
}

/*
 * get_dnet: Given a network name, look it up in the hash table.
 * Returns ptr to dsvc_dnet_t structure, NULL if error occurs.
 */
static dsvc_dnet_t *
get_dnet(struct in_addr *netp)
{
	dsvc_dnet_t tpnd;
	dsvc_dnet_t *pnd;

	tpnd.net.s_addr = netp->s_addr;
	pnd = (dsvc_dnet_t *)hash_Lookup(ntable, netp,
	    sizeof (struct in_addr), dnet_cmp, &tpnd, B_TRUE);

	/* refresh pnd hash entry timer */
	if (pnd != NULL)
		hash_Dtime(pnd->hand, time(NULL) + ntable->dfree_time);
	return (pnd);
}

/*
 * unhash_dnet: Free a datastore reference.
 *
 * Aging in hash routines will trigger freeing of unused references.
 */
/*ARGSUSED*/
static boolean_t
unhash_dnet(dsvc_dnet_t *pnd, boolean_t force)
{
	int		err = 0;
	dsvc_pendclnt_t	*workp;
	dsvc_thr_t	*thrp;
	timestruc_t	tm;
	int		nthreads;
	int		refcnt;

	if (pnd == NULL)
		return (B_FALSE);

	/* Mark as closing. */
	(void) mutex_lock(&pnd->pnd_mtx);
	pnd->flags |= DHCP_PND_CLOSING;
	(void) mutex_unlock(&pnd->pnd_mtx);

	/*
	 * Wait for any remaining thread(s) to exit.
	 */
	refcnt = hash_Refcount(pnd->hand);

	(void) mutex_lock(&pnd->thr_mtx);
	nthreads = pnd->nthreads;
	while (nthreads > 0 || refcnt > 0) {
		/*
		 * Wait for 1ms to avoid stalling monitor threads.
		 * cond_wait() not used to avoid thread synchronization
		 * overhead.
		 */
		tm.tv_sec = 0;
		tm.tv_nsec = 1000 * 10;
		(void) cond_reltimedwait(&pnd->thr_cv, &pnd->thr_mtx, &tm);
		nthreads = pnd->nthreads;
		(void) mutex_unlock(&pnd->thr_mtx);
		/* Threads will exit. */
		for (thrp = pnd->thrhead; thrp; thrp = thrp->thr_next) {
			(void) mutex_lock(&thrp->thr_mtx);
			thrp->thr_flags |= DHCP_THR_EXITING;
			(void) mutex_unlock(&thrp->thr_mtx);
			(void) cond_signal(&thrp->thr_cv);
		}
		refcnt = hash_Refcount(pnd->hand);
		(void) mutex_lock(&pnd->thr_mtx);
	}

	/* Free threads. */
	while ((thrp = pnd->thrhead) != NULL) {
		pnd->thrhead = pnd->thrhead->thr_next;
		(void) mutex_destroy(&thrp->thr_mtx);
		free(thrp);
	}
	pnd->thrtail = NULL;

	/* Free deferred thread work. */
	while ((workp = pnd->workhead) != NULL) {
		pnd->workhead = pnd->workhead->pnd_next;
		free(workp);
	}
	pnd->worktail = NULL;
	(void) mutex_unlock(&pnd->thr_mtx);

	/* Free clients. */
	if (pnd->ctable) {
		hash_Reset(pnd->ctable, unhash_clnt);
		free(pnd->ctable);
	}

	/* Free cached datastore records. */
	(void) mutex_lock(&pnd->free_mtx);
	if (pnd->freerec != NULL)
		dhcp_free_dd_list(pnd->dh, pnd->freerec);
	(void) mutex_unlock(&pnd->free_mtx);

	(void) mutex_lock(&pnd->lru_mtx);
	if (pnd->lrurec != NULL)
		dhcp_free_dd_list(pnd->dh, pnd->lrurec);
	(void) mutex_unlock(&pnd->lru_mtx);

	if (pnd->itable) {
		hash_Reset(pnd->itable, unhash_offer);
		free(pnd->itable);
	}

	(void) mutex_lock(&pnd->lrupage_mtx);
	if (pnd->lrupage) {
		free(pnd->lrupage);
		pnd->lrupage = NULL;
	}
	(void) mutex_unlock(&pnd->lrupage_mtx);

	if (pnd->dh != NULL) {
		if (dhcp_close_dd(&pnd->dh) != DSVC_SUCCESS) {
			dhcpmsg(LOG_ERR,
			    "Error %d while closing for network %s\n",
			    err, pnd->network);
		}
		pnd->dh = NULL;
	}

	(void) mutex_destroy(&pnd->pnd_mtx);
	(void) mutex_destroy(&pnd->thr_mtx);
	(void) mutex_destroy(&pnd->free_mtx);
	(void) mutex_destroy(&pnd->lru_mtx);
	(void) mutex_destroy(&pnd->lrupage_mtx);
	free(pnd);

	return (B_TRUE);
}

/*
 * dnet_cmp: Compare datastore references by network address.
 */
static int
dnet_cmp(dsvc_dnet_t *m1, dsvc_dnet_t *m2)
{
	return (m1->net.s_addr == m2->net.s_addr);
}

/*
 * open_clnt: Open the appropriate dhcp client given a network
 * database and client id.
 *
 * Returns: DSVC_SUCCESS for success or errno if an error occurs.
 *
 * pnd - per net struct
 * pcdp - client struct returned here
 * cid - clientid
 * cid_len - cid length
 * nocreate - if set, client struct must previously exist
 */
int
open_clnt(dsvc_dnet_t *pnd, dsvc_clnt_t **pcdp, uchar_t *cid,
	uchar_t cid_len, boolean_t nocreate)
{
	dsvc_clnt_t	*pcd;
	time_t		now;
	uint_t		blen;

	*pcdp = NULL;

	/* Network is closing. */
	if ((pnd->flags & DHCP_PND_CLOSING) != 0)
		return (DSVC_BUSY);

	/* Locate existing client. */
	if ((pcd = get_client(pnd->ctable, cid, cid_len)) != NULL) {
		(void) mutex_lock(&pcd->pcd_mtx);
		/* Client is closing - temporarily busy. */
		if ((pcd->flags & DHCP_PCD_CLOSING) != 0) {
			(void) mutex_unlock(&pcd->pcd_mtx);
			close_clnt(pcd, B_FALSE);
			return (DSVC_BUSY);
		}
		(void) mutex_unlock(&pcd->pcd_mtx);
		*pcdp = pcd;
		return (DSVC_SUCCESS);
	}
	if (nocreate == B_TRUE)
		return (DSVC_NOENT);

	/* Allocate new client. */
	(void) mutex_lock(&pnd->thr_mtx);
	if (max_clients != -1) {
		now = time(NULL);
		/*
		 * Performance/DOS: dsvc_clnt_t structs are normally
		 * freed when the protocol conversation completes,
		 * or when garbage collected (see hash.c). In
		 * certain error scenarios (e.g. DOS attacks, or
		 * network failures where large numbers of clients
		 * begin protocol conversations that never complete)
		 * the server will become unresponsive. To detect
		 * these scenarios, free slot time is observed, and
		 * after a grace period (2 * the offer time the currently
		 * allocated clients are allowed), clients are randomly
		 * deleted.
		 */
		if (pnd->nclients < max_clients) {
			/* Keep track of last time there were free slots. */
			pnd->clnt_stamp = now;
			(void) mutex_unlock(&pnd->thr_mtx);
		} else if (pnd->clnt_stamp + off_secs > now) {
			/* Wait for other clients to complete. */
			(void) mutex_unlock(&pnd->thr_mtx);
			return (DSVC_INTERNAL);
		} else {
			/* Forcibly delete a client to free a slot. */
			pnd->clnt_stamp = now;
			(void) mutex_unlock(&pnd->thr_mtx);
			hash_Reap(pnd->ctable, unhash_clnt);
		}
	} else
		(void) mutex_unlock(&pnd->thr_mtx);

	pcd = (dsvc_clnt_t *)smalloc(sizeof (dsvc_clnt_t));
	(void) mutex_init(&pcd->pcd_mtx, USYNC_THREAD, NULL);
	(void) mutex_init(&pcd->pkt_mtx, USYNC_THREAD, NULL);
	(void) mutex_lock(&pcd->pcd_mtx);
	pcd->pkthead = pcd->pkttail = NULL;
	pcd->pnd = pnd;
	(void) memcpy(pcd->cid, cid, cid_len);
	pcd->cid_len = cid_len;
	blen = sizeof (pcd->cidbuf);
	(void) octet_to_hexascii(cid, cid_len, pcd->cidbuf, &blen);

	if ((pcd->chand = hash_Insert(pnd->ctable, cid, cid_len, clnt_cmp,
	    pcd, pcd)) == NULL) {
		/* Another thread has begun work on this client */
#ifdef	DEBUG
		dhcpmsg(LOG_DEBUG, "Duplicate client\n");
#endif	/* DEBUG */
		(void) mutex_unlock(&pcd->pcd_mtx);
		(void) mutex_destroy(&pcd->pcd_mtx);
		(void) mutex_destroy(&pcd->pkt_mtx);
		free(pcd);
		return (DSVC_BUSY);
	}
	(void) mutex_unlock(&pcd->pcd_mtx);
	(void) mutex_lock(&pnd->thr_mtx);
	pnd->nclients++;
	(void) mutex_unlock(&pnd->thr_mtx);
	*pcdp = pcd;
	return (DSVC_SUCCESS);
}

/*
 * close_clnt: Closes specified client.
 *
 * delete - immediately delete.
 */
void
close_clnt(dsvc_clnt_t *pcd, boolean_t delete)
{
	hash_Rele(pcd->chand, delete);
}

/*
 * get_client: Given a client name, look it up in the per client hash table.
 * Returns ptr to dsvc_clnt_t structure, NULL if error occurs.
 */
static dsvc_clnt_t *
get_client(hash_tbl *table, uchar_t *cid, uchar_t cid_len)
{
	dsvc_clnt_t tpcd;
	dsvc_clnt_t *pcd;

	(void) memcpy(tpcd.cid, cid, cid_len);
	tpcd.cid_len = cid_len;

	pcd = (dsvc_clnt_t *)hash_Lookup(table, cid, cid_len, clnt_cmp,
	    &tpcd, B_TRUE);

	/* refresh client hash entry's timer */
	if (pcd != NULL) {
		(void) mutex_lock(&pcd->pcd_mtx);
		hash_Dtime(pcd->chand, time(NULL) + table->dfree_time);
		(void) mutex_unlock(&pcd->pcd_mtx);
	}
	return (pcd);
}

/*
 * unhash_clnt: Free a client structure.
 *
 * Aging in hash routines will trigger freeing of unused references.
 */
/*ARGSUSED*/
static boolean_t
unhash_clnt(dsvc_clnt_t *pcd, boolean_t force)
{
	dsvc_dnet_t	*pnd = pcd->pnd;
	timestruc_t	tm;
	int		refcnt;
	struct in_addr	off_ip;


	refcnt = hash_Refcount(pcd->chand);

	/*
	 * Wait for thread(s) accessing pcd to drop references.
	 */
	(void) mutex_lock(&pcd->pcd_mtx);
	pcd->flags |= DHCP_PCD_CLOSING;	/* client no longer usable... */
	while (pcd->clnt_thread != NULL || refcnt > 0) {
		/*
		 * Wait for 1ms to avoid stalling monitor threads.
		 * cond_wait() not used to avoid thread synchronization
		 * overhead.
		 */
		tm.tv_sec = 0;
		tm.tv_nsec = 1000 * 10;
		(void) cond_reltimedwait(&pcd->pcd_cv, &pcd->pcd_mtx, &tm);
		(void) mutex_unlock(&pcd->pcd_mtx);
		refcnt = hash_Refcount(pcd->chand);
		(void) mutex_lock(&pcd->pcd_mtx);
	}

	if (pcd->pkthead != NULL)
		free_pktlist(pcd);

	off_ip.s_addr = pcd->off_ip.s_addr;
	(void) mutex_unlock(&pcd->pcd_mtx);

	if (off_ip.s_addr != htonl(INADDR_ANY))
		purge_offer(pcd, B_TRUE, B_FALSE);

	if (pcd->dnlp != NULL)
		dhcp_free_dd_list(pnd->dh, pcd->dnlp);

	(void) mutex_destroy(&pcd->pcd_mtx);
	(void) mutex_destroy(&pcd->pkt_mtx);
	free(pcd);

	(void) mutex_lock(&pnd->thr_mtx);
	pnd->nclients--;
	(void) mutex_unlock(&pnd->thr_mtx);

	return (B_TRUE);
}

/*
 * unhash_offer: Free offer associated with a client structure.
 *
 * Aging in hash routines will trigger freeing of expired offers.
 */
static boolean_t
unhash_offer(dsvc_clnt_t *pcd, boolean_t force)
{
	IF		*ifp = pcd->ifp;
	boolean_t	ret = B_TRUE;
	char		ntoab[INET_ADDRSTRLEN];

	(void) mutex_lock(&pcd->pcd_mtx);
	if (pcd->off_ip.s_addr != htonl(INADDR_ANY) &&
	    PCD_OFFER_TIMEOUT(pcd, time(NULL))) {
		if (pcd->clnt_thread == NULL) {
			if (debug)
				dhcpmsg(LOG_INFO, "Freeing offer: %s\n",
				    inet_ntop(AF_INET, &pcd->off_ip,
				    ntoab, sizeof (ntoab)));
			pcd->off_ip.s_addr = htonl(INADDR_ANY);
			(void) mutex_unlock(&pcd->pcd_mtx);
			(void) mutex_lock(&ifp->ifp_mtx);
			if (ifp->offers > 0)
				ifp->offers--;
			ifp->expired++;
			(void) mutex_unlock(&ifp->ifp_mtx);
		} else if (force == B_FALSE) {
			/*
			 * Worker thread is currently active. To avoid
			 * unnecessary thread synchronization, defer
			 * freeing the offer until the worker thread has
			 * completed.
			 */
			(void) mutex_unlock(&pcd->pcd_mtx);
			hash_Age(pcd->ihand);
			ret = B_FALSE;
		} else
			(void) mutex_unlock(&pcd->pcd_mtx);
	} else
		(void) mutex_unlock(&pcd->pcd_mtx);
	return (ret);
}

/*
 * clnt_cmp: Compare client structures by cid.
 */
static int
clnt_cmp(dsvc_clnt_t *m1, dsvc_clnt_t *m2)
{
	return (m1->cid_len == m2->cid_len &&
	    memcmp((char *)m1->cid, (char *)m2->cid, m1->cid_len) == 0);
}

/*
 * clnt_netcmp Compare clients by network address. This is used to maintain
 * the itable hash table of client addresses.
 */
int
clnt_netcmp(dsvc_clnt_t *d1, dsvc_clnt_t *d2)
{
	return (d1->off_ip.s_addr == d2->off_ip.s_addr);
}

/*
 * close_clnts: Free the ntable hash table and associated client structs.
 * Table walk frees each per network and client struct.
 */
void
close_clnts(void)
{
	hash_Reset(ntable, unhash_dnet);
}
