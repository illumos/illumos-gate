/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PER_DSTORE_H
#define	_PER_DSTORE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * per_dnet.h -- DHCP-datastore database definitions.
 */

/*
 * DHCP thread deferred work structure. One per deferred client thread.
 *
 * Track clients who cannot be immediately serviced due
 * to a lack of available client threads. Locked by thr_mtx.
 */
typedef struct dsvc_pending {
	uchar_t			pnd_cid[DN_MAX_CID_LEN];	/* cid */
	uchar_t			pnd_cid_len;			/* cid length */
	struct dsvc_pending	*pnd_next;			/* next */
} dsvc_pendclnt_t;

/*
 * DHCP thread structure. One per client thread.
 *
 * Performance: create and track each client thread, using
 * thr_suspend/thr_resume, rather than slower thread creation
 * and deletion. Locked by thr_mtx.
 */
struct clnt;
typedef struct dsvc_free {
	thread_t		thr_tid;	/* thread id */
	cond_t			thr_cv;		/* suspend/resume cv */
	mutex_t			thr_mtx;	/* suspend/resume mutex */
	uint_t			thr_flags;	/* suspend/resume flags */
	struct clnt		*thr_pcd;	/* per client data struct */
	struct dsvc_free	*thr_next;	/* next */
} dsvc_thr_t;

/*
 * DHCP thread structure flags
 */
#define	DHCP_THR_LIST		0x1		/* Thread is on freelist */
#define	DHCP_THR_EXITING	0x2		/* Thread is exiting */

/*
 * DHCP datastore table. One per active network or dhcptab datastore.
 *
 * Timestamps are used to age the datastore structure, and any cached
 * datastore free or lru records managed in select_offer().
 * The number of threads and clients can be controlled via MAX_THREADS
 * and MAX_CLIENTS server parameters.
 *
 * Client and offer hashes provide fast lookup/reservation.
 * Per-bucket rwlocks implemented in the hash routines reduce
 * lock contention between clients.
 *
 * To minimize expensive datastore activity, threads synchronize to
 * manage cached free and lru datastore records, which have the
 * same lifetime as cached offers, which can be controlled via
 * the OFFER_CACHE_TIMEOUT server parameter.
 */
typedef	struct dnet {
	hash_handle	hand;		/* hash insertion handle */
	time_t		free_mtime;	/* macro table purge time */
	time_t		free_stamp;	/* D_OFFER freerec purge time */
	time_t		lru_mtime;	/* macro table purge time */
	time_t		lru_stamp;	/* D_OFFER lrurec purge time */
	time_t		clnt_stamp;	/* D_OFFER client purge time */
	uint_t		flags;		/* dnet flags */
	struct in_addr	net;		/* network */
	struct in_addr	subnet;		/* subnet mask */
	int		naddrs;		/* # addrs owned by server */
	int		nthreads;	/* number of active threads */
	int		nclients;	/* number of active clients */
	hash_tbl	*ctable;	/* per client hash table */
	hash_tbl	*itable;	/* per ipaddr hash table */
	dsvc_thr_t	*thrhead;	/* free thread list */
	dsvc_thr_t	*thrtail;	/* free thread list tail */
	dsvc_pendclnt_t	*workhead;	/* head of thread work list */
	dsvc_pendclnt_t	*worktail;	/* tail of thread work list */
	dn_rec_list_t	*freerec;	/* free records head */
	dn_rec_list_t	*lrurec;	/* lru records head */
	dn_rec_list_t	**lrupage;	/* lru records sort area */
	size_t		lrusize;

	dsvc_handle_t	dh;		/* datastore handle */
	mutex_t		pnd_mtx;	/* open/close mutex */
	mutex_t		free_mtx;	/* lock for free records */
	mutex_t		lru_mtx;	/* lock for lru records */
	mutex_t		lrupage_mtx;	/* lock for lru page */
	mutex_t		thr_mtx;	/* lock for thread work list */
	cond_t		thr_cv;		/* cond var (nthreads == 0) */
	char		network[INET_ADDRSTRLEN];	/* display buffer */
} dsvc_dnet_t;

/*
 * DHCP datastore table flags
 */
#define	DHCP_PND_CLOSING	0x1		/* Dstore is closing */
#define	DHCP_PND_ERROR		0x2		/* Dstore experienced error */

/*
 * DHCP datastore table macros
 */
#define	PND_FREE_TIMEOUT(pnd, now)	((pnd)->free_stamp < (now) || \
					    (pnd)->free_mtime != reinit_time)
#define	PND_LRU_TIMEOUT(pnd, now)	((pnd)->lru_stamp < (now) || \
					    (pnd)->lru_mtime != reinit_time)

struct interfaces;

/*
 * DHCP client. One per active client, per network.
 *
 * Timestamps are used to age the client structure, and any cached
 * offer, which can be controlled via the OFFER_CACHE_TIMEOUT server
 * parameter, and the -t option, and SIGHUP signal.
 *
 * The original datastore record is cached, along with offer information,
 * for use if the datastore record is modified.
 *
 * The clnt struct may appear on the client hash table, and offer hash table,
 * depending on the validity of the current offer. A different dsvc_clnt_t
 * is used for each link, to allow independent aging of client and offer.
 */
typedef struct clnt {
	hash_handle	chand;		/* hash insertion handle: client hash */
	hash_handle	ihand;		/* hash insertion handle: inet hash */
	time_t		mtime;		/* macro table offer purge time */
	uint_t		flags;		/* Client flags */
	uint_t		state;		/* Client DHCP state */
	struct in_addr	off_ip;		/* Offered address */
	struct interfaces *ifp;		/* the ifp the packet arrived on */
	dsvc_dnet_t	*pnd;		/* the per network datastore */
	PKT_LIST	*pkthead;	/* head of client packet list */
	PKT_LIST	*pkttail;	/* tail of client packet list */
	uint_t		pending;	/* # of pkts on client packet list */
	lease_t		lease;		/* Offered lease time */
	dsvc_thr_t	*clnt_thread;	/* client thread */

	dn_rec_list_t	*dnlp;		/* Original datastore record */
	mutex_t		pcd_mtx;	/* overall struct lock */
	mutex_t		pkt_mtx;	/* lock for PKT_LIST */
	cond_t		pcd_cv;		/* cond var (clnt_thread == 0) */
	char 		cidbuf[DHCP_MAX_OPT_SIZE]; /* display buffer */
	uchar_t		cid[DN_MAX_CID_LEN]; /* Offered cid */
	uchar_t		cid_len;	/* Offered cid length */
} dsvc_clnt_t;

/*
 * Per Client flags and indices
 */
#define	DHCP_HDR_CLIENT		0x0	/* clnt dsvc_clnt_t */
#define	DHCP_HDR_OFFER		0x1	/* offer dsvc_clnt_t */

#define	DHCP_PCD_OFFER		0x1	/* Offered ip addr is valid */
#define	DHCP_PCD_WORK		0x2	/* Client is on deferred work list */
#define	DHCP_PCD_CLOSING	0x4	/* Client thread should exit */

/*
 * Per Client macros
 */
#define	PCD_OFFER_TIMEOUT(pcd, now)	(hash_Htime(pcd->ihand) < (now) || \
						(pcd)->mtime != reinit_time)

/*
 * Datastore hash table dynamic data free timeout values
 */
#define	DHCP_CLIENT_THRESHOLD	90	/* Time to free inactive clients */
#define	DHCP_NET_THRESHOLD	900	/* Time to free inactive nets */

/*
 * Datastore database access routines.
 */
extern int	open_dnet(dsvc_dnet_t **, struct in_addr *, struct in_addr *);
extern void	close_dnet(dsvc_dnet_t *, boolean_t);

/*
 * Per Client hash and utility routines.
 */
extern int open_clnt(dsvc_dnet_t *, dsvc_clnt_t **, uchar_t *, uchar_t,
	boolean_t);
extern void close_clnt(dsvc_clnt_t *, boolean_t);
extern int clnt_netcmp(dsvc_clnt_t *, dsvc_clnt_t *);
extern void close_clnts(void);
extern void purge_offer(dsvc_clnt_t *, boolean_t, boolean_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _PER_DSTORE_H */
