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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TRILL_IMPL_H
#define	_TRILL_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/list.h>
#include <net/trill.h>
#include <sys/mac.h>
#include <sys/kstat.h>
#include <sys/rwlock.h>
#include <net/bridge_impl.h>
#include <net/if_dl.h>

#define	TRILL_KSSOCK_NAMES "recv", "sent", "drops", "encap", "decap", "forward"

/* kstats per TRILL socket */
typedef struct trill_kssock_s {
	kstat_named_t	tks_recv;	/* packets received */
	kstat_named_t	tks_sent;	/* packets sent through */
	kstat_named_t	tks_drops;	/* packets dropped */
	kstat_named_t   tks_encap;	/* packets encapsulated */
	kstat_named_t   tks_decap;	/* packets decapsulated */
	kstat_named_t	tks_forward;	/* packets forwarded */
} trill_kssock_t;

#define	KSPINCR(stat) ++(tsock->ts_kstats.stat.value.ui64)

#define	TRILL_NO_TCI	0	/* No VLAN tag */
#define	TRILL_VLANS_ARRSIZE ((1<<12)/NBBY)
#define	TRILL_VLANBIT(v) ((v) % NBBY)
#define	TRILL_VLANBYTE(v) ((v)/NBBY)
#define	TRILL_VLANISSET(l, v) ((l)[TRILL_VLANBYTE(v)] & (1<<TRILL_VLANBIT(v)))

struct trill_node_s;

/*
 * TRILL instance structure, one for each TRILL instance running in
 * support of a bridge instance. Members ti_bridgename and ti_binst
 * refer to the specific bridge instance. The bridge instance in
 * question must be online before we can support and rely on it.
 * We rely on the bridge instance for TRILL sockets to transmit and
 * receive TRILL packets. Each TRILL instance holds the TRILL
 * forwarding and nick database in ti_nodes. trill_inst_rwlock
 * protects changes to the TRILL instances list. Within each TRILL
 * instance the ti_rwlock protects changes to the structure. A refcount
 * (ti_refs) helps in destroying the TRILL instance when all TRILL
 * sockets part of the instance are shutdown.
 */
typedef struct trill_s {
	list_node_t		ti_instnode;
	uint16_t		ti_nick; /* our nickname */
	uint16_t		ti_treeroot; /* tree root nickname */
	struct trill_node_s	*ti_nodes[RBRIDGE_NICKNAME_MAX];
	uint_t			ti_nodecount;
	list_t			ti_socklist;
	char			ti_bridgename[MAXLINKNAMELEN];
	krwlock_t		ti_rwlock;
	uint_t			ti_refs;
	bridge_inst_t		*ti_binst;
} trill_inst_t;

/*
 * TRILL socket structure. IS-IS daemon opens a TRILL socket for
 * each broadcast link the TRILL IS-IS protocol instance is
 * running on. TRILL specific link properties, state and stats
 * are stored as well. ts_vlanfwder indicates whether the RBridges
 * is the designated forwarder on the link for a particular VLAN.
 * A refcount (ts_refs) ensures the last consumer (TRILL module
 * or the IS-IS daemon) destroys the socket.
 */
typedef struct trillsocket_s {
	list_node_t		ts_socklistnode;
	uint8_t			ts_state;
	bridge_link_t		*ts_link;
	struct sockaddr_dl	ts_lladdr;
	uint16_t		ts_desigvlan;
	kstat_t			*ts_ksp;
	trill_kssock_t		ts_kstats;
	trill_inst_t		*ts_tip;
	uint_t			ts_refs;
	uint_t			ts_flags;
	sock_upcalls_t		*ts_conn_upcalls;	/* Upcalls to sockfs */
	sock_upper_handle_t	ts_conn_upper_handle;	/* sonode */
	boolean_t		ts_flow_ctrld;
	kmutex_t		ts_socklock;
	uint_t			ts_sockthreadcount;
	kcondvar_t		ts_sockthreadwait;
	kcondvar_t		ts_sockclosewait;
} trill_sock_t;

/*
 * TRILL socket flags (ts_flags). TSF_SHUTDOWN indicates the TRILL socket
 * owner (IS-IS daemon process) had done a close on the socket and other
 * consumers (TRILL threads) should not pass any packets downstream.
 * TSF_CLOSEWAIT indicates socket close is in progress.
 */
#define	TSF_SHUTDOWN	0x0001
#define	TSF_CLOSEWAIT	0x0002

/*
 * TRILL node information structure. Holds information to reach the
 * TRILL node and other RBridge information specified in trill_nick_info_t
 */
typedef struct trill_node_s {
	trill_sock_t		*tn_tsp;
	trill_nickinfo_t	*tn_ni;
	uint_t			tn_refs;
} trill_node_t;

/* Limit to alloc max 1MB per trill_nickinfo_t received from user daemon */
#define	TNI_MAXSIZE	(1<<30)

#ifdef __cplusplus
}
#endif

#endif /* _TRILL_IMPL_H */
