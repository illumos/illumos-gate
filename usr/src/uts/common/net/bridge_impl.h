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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _BRIDGE_IMPL_H
#define	_BRIDGE_IMPL_H

/*
 * These are the internal data structures used by the layer-two (Ethernet)
 * bridging module.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/avl.h>
#include <sys/queue.h>
#include <sys/kstat.h>
#include <sys/ksynch.h>
#include <sys/ethernet.h>
#include <sys/dld.h>
#include <sys/mac.h>
#include <sys/mac_client.h>
#include <sys/vlan.h>
#include <net/bridge.h>

#define	BRIDGE_DEV_NAME	"bridge"

#define	KSINST_NAMES	"recv", "sent", "drops", \
	"forward_direct", "forward_unknown", "forward_mbcast",	\
	"learn_source", "learn_moved", "learn_expire", "learn_size"
typedef struct bridge_ksinst_s {
	kstat_named_t	bki_recv;	/* packets received */
	kstat_named_t	bki_sent;	/* packets sent through */
	kstat_named_t	bki_drops;	/* packets dropped (untowardly) */
	kstat_named_t	bki_forwards;	/* packets forwarded */
	kstat_named_t	bki_unknown;	/* packets forwarded (unknown dest) */
	kstat_named_t	bki_mbcast;	/* packets forwarded (multi/bcast) */
	kstat_named_t	bki_source;	/* source addresses learned */
	kstat_named_t	bki_moved;	/* source addresses moved */
	kstat_named_t	bki_expire;	/* source addresses expired */
	kstat_named_t	bki_count;	/* source addresses known */
} bridge_ksinst_t;

#define	KSLINK_NAMES	"recv", "xmit", "drops"
typedef struct bridge_kslink_s {
	kstat_named_t	bkl_recv;	/* packets received */
	kstat_named_t	bkl_xmit;	/* packets transmitted */
	kstat_named_t	bkl_drops;	/* packets dropped */
} bridge_kslink_t;

/*
 * There's one instance structure and one observability mac node for each
 * bridge.  Each open non-DLPI stream gets a 'stream' structure; these are used
 * for bridge instance allocation and control.  Each link on the bridge has a
 * link structure.  Finally, the bridge has a table of learned forwarding
 * entries, each with a list of outputs, which are either links or TRILL
 * nicknames.
 *
 * The mac structure lives as long as the dls and mac layers are busy.  It can
 * outlive the bridge instance and be picked up again (by name) if the instance
 * is restarted.
 */

struct bridge_mac_s;
struct bridge_stream_s;

typedef struct bridge_inst_s {
	list_node_t	bi_node;
	dev_t		bi_dev;
	uint_t		bi_flags;
	uint_t		bi_refs;
	uint32_t	bi_tablemax;
	uint_t		bi_tshift;
	krwlock_t	bi_rwlock;
	list_t		bi_links;
	kcondvar_t	bi_linkwait;
	avl_tree_t	bi_fwd;
	kstat_t		*bi_ksp;
	struct bridge_stream_s *bi_control;
	struct bridge_mac_s *bi_mac;
	void		*bi_trilldata;
	char		bi_name[MAXLINKNAMELEN];
	bridge_ksinst_t	bi_kstats;
} bridge_inst_t;

#define	BIF_SHUTDOWN	0x0001		/* control stream has closed */

/*
 * The bridge MAC structure has the same lifetime as an observability node.
 * It's created when a bridge instance is allocated, but is not freed when the
 * instance is removed because there's no way for a MAC client to guarantee
 * that all users have disappeared.
 */
typedef struct bridge_mac_s {
	list_node_t	bm_node;
	mac_handle_t	bm_mh;
	bridge_inst_t	*bm_inst;
	uint_t		bm_flags;	/* BMF_* below */
	uint_t		bm_maxsdu;
	link_state_t	bm_linkstate;
	char		bm_name[MAXLINKNAMELEN];
} bridge_mac_t;

#define	BMF_DLS		0x0001		/* dls monitor node created */
#define	BMF_STARTED	0x0002		/* snoop-like client is present */

/*
 * Bridge streams are used only for instance allocation and control.
 */
typedef struct bridge_stream_s {
	bridge_inst_t	*bs_inst;
	queue_t		*bs_wq;		/* write-side queue for stream */
	minor_t		bs_minor;
	uint_t		bs_taskq_cnt;	/* taskq references */
} bridge_stream_t;

/*
 * These macros are used to set and test link membership in particular VLANs.
 * This membership is used to determine how to forward packets between
 * interfaces.
 */

#define	BRIDGE_VLAN_ARR_SIZE	\
	(P2ROUNDUP(VLAN_ID_MAX, NBBY) / NBBY)

#define	BRIDGE_VLAN_ISSET(l, v)	((l)->bl_vlans[(v) / NBBY] & \
	(1 << ((v) % NBBY)))

#define	BRIDGE_VLAN_SET(l, v)	((l)->bl_vlans[(v) / NBBY] |= \
	(1 << ((v) % NBBY)))

#define	BRIDGE_VLAN_CLR(l, v)	((l)->bl_vlans[(v) / NBBY] &= \
	~(1 << ((v) % NBBY)))

#define	BRIDGE_AF_ISSET(l, v)	((l)->bl_afs[(v) / NBBY] & \
	(1 << ((v) % NBBY)))

/*
 * This structure represents a link attached to a bridge.  VLAN membership
 * information is kept here; when forwarding, we must look at the membership of
 * the input link and the output to determine when to update the packet
 * contents and when to discard.
 */
typedef struct bridge_link_s {
	list_node_t	bl_node;
	uint_t		bl_refs;
	datalink_id_t	bl_linkid;	/* allocated link ID for bridge */
	bridge_state_t	bl_state;	/* blocking/learning/forwarding */
	uint_t		bl_pvid;	/* VLAN ID for untagged traffic */
	uint_t		bl_flags;	/* BLF_* below */
	uint_t		bl_learns;	/* learning limit */
	mac_handle_t	bl_mh;
	mac_client_handle_t	bl_mch;
	uint32_t	bl_margin;
	uint_t		bl_maxsdu;
	mac_unicast_handle_t	bl_mah;
	mac_notify_handle_t	bl_mnh;
	mac_promisc_handle_t	bl_mphp;
	bridge_inst_t	*bl_inst;	/* backpointer to bridge instance */
	kstat_t		*bl_ksp;
	void		*bl_trilldata;
	mblk_t		*bl_lfailmp;	/* preallocated */
	link_state_t	bl_linkstate;
	uint_t		bl_trillthreads;
	kcondvar_t	bl_trillwait;
	kmutex_t	bl_trilllock;
	uint8_t		bl_local_mac[ETHERADDRL];
	uint8_t		bl_vlans[BRIDGE_VLAN_ARR_SIZE];
	uint8_t		bl_afs[BRIDGE_VLAN_ARR_SIZE];
	bridge_kslink_t	bl_kstats;
} bridge_link_t;

#define	BLF_DELETED		0x0001	/* waiting for last reference to go */
#define	BLF_CLIENT_OPEN		0x0002	/* MAC client opened */
#define	BLF_MARGIN_ADDED	0x0004	/* MAC margin added */
#define	BLF_SET_BRIDGE		0x0008	/* MAC in bridging mode */
#define	BLF_PROM_ADDED		0x0010	/* MAC promiscuous added */
#define	BLF_FREED		0x0020	/* free has begun; debug assertion */
#define	BLF_TRILLACTIVE		0x0040	/* in active forwarding use */
#define	BLF_SDUFAIL		0x0080	/* has mismatched SDU */
#define	BLF_LINK_ADDED		0x0100	/* link added in bridge instance */

/*
 * This represents a learned forwarding entry.  These are generally created and
 * refreshed on demand as we learn about nodes through source MAC addresses we
 * see.  They're destroyed when they age away.  For forwarding, we look up the
 * destination address in an AVL tree, and the entry found tells us where the
 * that source must live.
 */
typedef struct bridge_fwd_s {
	avl_node_t	bf_node;
	uchar_t		bf_dest[ETHERADDRL];
	uint16_t	bf_trill_nick;	/* destination nickname */
	clock_t		bf_lastheard;	/* time we last heard from this node */
	uint_t		bf_flags;	/* BFF_* below */
	uint_t		bf_refs;
	uint16_t	bf_vlanid;	/* VLAN ID for IVL */
	uint16_t	bf_vcnt;	/* number of duplicates */
	uint_t		bf_nlinks;	/* number of links in bf_links */
	uint_t		bf_maxlinks;	/* allocated size of link array */
	bridge_link_t	**bf_links;
} bridge_fwd_t;

#define	BFF_INTREE	0x0001
#define	BFF_LOCALADDR	0x0002		/* address is known to mac layer */
#define	BFF_VLANLOCAL	0x0004		/* set if duplicate for IVL */

/* TRILL linkage */
typedef void (*trill_recv_pkt_t)(void *, bridge_link_t *, mac_resource_handle_t,
    mblk_t *, mac_header_info_t *);
typedef void (*trill_encap_pkt_t)(void *, bridge_link_t *, mac_header_info_t *,
    mblk_t *, uint16_t);
typedef void (*trill_br_dstr_t)(void *, bridge_inst_t *);
typedef void (*trill_ln_dstr_t)(void *, bridge_link_t *);

extern void bridge_trill_register_cb(trill_recv_pkt_t, trill_encap_pkt_t,
    trill_br_dstr_t, trill_ln_dstr_t);
extern bridge_inst_t *bridge_trill_brref(const char *, void *);
extern void bridge_trill_brunref(bridge_inst_t *);
extern bridge_link_t *bridge_trill_lnref(bridge_inst_t *, datalink_id_t,
    void *);
extern void bridge_trill_lnunref(bridge_link_t *);
extern void bridge_trill_decaps(bridge_link_t *, mblk_t *, uint16_t);
extern mblk_t *bridge_trill_output(bridge_link_t *, mblk_t *);
extern void bridge_trill_setvlans(bridge_link_t *, const uint8_t *);
extern void bridge_trill_flush(bridge_link_t *, uint16_t, boolean_t);

/* Ethernet multicast address; constant stored in bridge module */
extern const uint8_t all_isis_rbridges[];
extern const uint8_t bridge_group_address[];

#ifdef __cplusplus
}
#endif

#endif /* _BRIDGE_IMPL_H */
