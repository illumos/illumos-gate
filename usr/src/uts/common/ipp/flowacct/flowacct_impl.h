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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPP_FLOWACCT_FLOWACCT_IMPL_H
#define	_IPP_FLOWACCT_FLOWACCT_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <ipp/ipp.h>
#include <inet/ipp_common.h>
#include <ipp/flowacct/flowacct.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Header file for implementation of flowacct */

#ifdef	_KERNEL

#define	_FLOWACCT_DEBUG

#ifdef _FLOWACCT_DEBUG
#include <sys/debug.h>
#define	flowacct0dbg(a)		printf a
#define	flowacct1dbg(a)		if (flowacct_debug > 2) printf a
#define	flowacct2dbg(a)		if (flowacct_debug > 3) printf a
#else
#define	flowacct0dbg(a)		/*  */
#define	flowacct1dbg(a)		/*  */
#define	flowacct2dbg(a)		/*  */
#endif /* _FLOWACCT_DEBUG */

#define	FLOWACCT_PURGE_FLOW	0x01
#define	FLOWACCT_FLOW_TIMER	0x02
#define	FLOWACCT_JUST_ONE	0x03

/* Flow Table Size */
#define	FLOW_TBL_COUNT	((uint_t)256)

/* To identify objects in the list - could be a flow or an item */
#define	FLOWACCT_FLOW		0x01
#define	FLOWACCT_ITEM		0x02

/* Whether an object has to be physically removed from the table */
#define	FLOWACCT_DEL_OBJ		0x01

/* Utility macros to convert from msec to usec/nsec */
#define	FLOWACCT_MSEC_TO_USEC		(1000)
#define	FLOWACCT_MSEC_TO_NSEC		(1000000)

/*
 * Default values for timer and timeout - taken from SBM
 * timer 15 secs (15000 msec) and timeout 60 secs (60000 msec).
 */
#define	FLOWACCT_DEF_TIMER		(15000)
#define	FLOWACCT_DEF_TIMEOUT		(60000)

/* List holding an obj - flow or item */
typedef struct	list_hdr_s {
	struct	list_hdr_s	*next;
	struct	list_hdr_s	*prev;
	struct	list_hdr_s	*timeout_next;
	struct	list_hdr_s	*timeout_prev;
	timespec_t		last_seen;
	void			*objp;
} list_hdr_t;

/* List of list of flows */
typedef struct list_head_s {
	list_hdr_t	*head;
	list_hdr_t	*tail;
	uint_t		nbr_items;
	uint_t		max_items;
	kmutex_t	lock;
} list_head_t;

/* Global stats for flowacct */
typedef struct flowacct_stat_s {
	ipp_named_t npackets;		/* no. of pkts seen by this instance */
	ipp_named_t nbytes;		/* no. of bytes seen by this instance */
	ipp_named_t nflows;		/* no. of flow items in the table */
	ipp_named_t tbytes;		/* no. of bytes in the flow table */
	ipp_named_t usedmem;		/* memory used by the flow table */
	ipp_named_t epackets;		/* no. of pkts. in error */
} flowacct_stat_t;

#define	FLOWACCT_STATS_COUNT	6
#define	FLOWACCT_STATS_STRING	"Flowacct statistics"

/* Item common to a flow (identified by 5-tuple) */
typedef struct flow_item_s {
	uint_t		type;
	list_hdr_t	*hdr;
	timespec_t	creation_time;
	uint64_t	npackets;
	uint64_t	nbytes;
	uint8_t		dsfield;
	projid_t	projid;
	uid_t		uid;
} flow_item_t;

/* Flow attributes */
typedef struct flow_s {
	uint_t		type;
	list_hdr_t	*hdr;
	in6_addr_t	saddr;
	in6_addr_t	daddr;
	uint8_t		proto;
	uint16_t	sport;
	uint16_t	dport;
	list_head_t	items;
	list_head_t	*back_ptr;
	boolean_t	isv4;
	/*
	 * to indicate to the flow timer not to delete this flow
	 */
	boolean_t	inuse;
} flow_t;

/* From the IP header */
typedef struct header {
	uint_t		dir;
	uint_t		len;
	in6_addr_t	saddr;
	in6_addr_t	daddr;
	uint16_t	sport;
	uint16_t	dport;
	uint16_t	ident;
	uint8_t		proto;
	uint8_t		dsfield;
	projid_t	projid;
	uid_t		uid;
	boolean_t	isv4;
	uint32_t	pktlen;
} header_t;


typedef struct flowacct_data_s {
	ipp_action_id_t next_action; 		/* action id of next action */
	char		*act_name;		/* action name of next action */
	uint64_t 	timer;			/* flow timer */
	uint64_t 	timeout;		/* flow timeout */
	uint32_t	max_limit;		/* max flow entries */
	uint32_t 	nflows;			/* no. of flows */
	kmutex_t	lock;			/* for nflows */

	/* TRhe flow table. We'll use the last bucket for timeout purposes */
	list_head_t flows_tbl[FLOW_TBL_COUNT+1];
	boolean_t 	global_stats;		/* global stats */

	uint64_t 	tbytes;			/* no. of bytes in flow tbl. */
	uint64_t 	nbytes;			/* no. of bytes seen */
	uint64_t 	npackets;		/* no. of pkts seen */
	uint64_t 	usedmem;		/* mem used by flow table */
	uint64_t 	epackets;		/* packets in error */
	ipp_stat_t 	*stats;
	timeout_id_t	flow_tid;

} flowacct_data_t;

#define	FLOWACCT_DATA_SZ	sizeof (flowacct_data_t)
#define	FLOWACCT_HDR_SZ		sizeof (list_hdr_t)
#define	FLOWACCT_HEAD_SZ	sizeof (list_head_t)
#define	FLOWACCT_FLOW_SZ	sizeof (flow_t)
#define	FLOWACCT_ITEM_SZ	sizeof (flow_item_t)
#define	FLOWACCT_HEADER_SZ	sizeof (header_t)
#define	FLOWACCT_FLOW_RECORD_SZ (FLOWACCT_HDR_SZ + FLOWACCT_FLOW_SZ)
#define	FLOWACCT_ITEM_RECORD_SZ (FLOWACCT_HDR_SZ + FLOWACCT_ITEM_SZ)

extern int flowacct_process(mblk_t **, flowacct_data_t *);
extern void flowacct_timer(int, flowacct_data_t *);
extern void flowacct_timeout_flows(void *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _IPP_FLOWACCT_FLOWACCT_IMPL_H */
