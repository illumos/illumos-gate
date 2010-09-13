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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_IB_CLIENTS_IBD_H
#define	_SYS_IB_CLIENTS_IBD_H

#ifdef __cplusplus
extern "C" {
#endif

/* The following macros are used in both ibd.c and ibd_cm.c */

/*
 * Completion queue polling control
 */
#define	IBD_CQ_POLLING			0x1
#define	IBD_REDO_CQ_POLLING		0x2

/*
 * Maximum length for returning chained mps back to crossbow.
 * Also used as the maximum number of rx wc's polled at a time.
 */
#define	IBD_MAX_RX_MP_LEN		16

/*
 * When doing multiple-send-wr, this value determines how many to do at
 * a time (in a single ibt_post_send).
 */
#define	IBD_MAX_TX_POST_MULTIPLE	4

/*
 * Flag bits for resources to reap
 */
#define	IBD_RSRC_SWQE			0x1
#define	IBD_RSRC_LSOBUF			0x2
#define	IBD_RSRC_RC_SWQE		0x4
#define	IBD_RSRC_RC_TX_LARGEBUF		0x8

/*
 * Async operation types
 */
#define	IBD_ASYNC_GETAH			1
#define	IBD_ASYNC_JOIN			2
#define	IBD_ASYNC_LEAVE			3
#define	IBD_ASYNC_PROMON		4
#define	IBD_ASYNC_PROMOFF		5
#define	IBD_ASYNC_REAP			6
#define	IBD_ASYNC_TRAP			7
#define	IBD_ASYNC_SCHED			8
#define	IBD_ASYNC_LINK			9
#define	IBD_ASYNC_EXIT			10
#define	IBD_ASYNC_RC_TOO_BIG		11
#define	IBD_ASYNC_RC_CLOSE_ACT_CHAN	12
#define	IBD_ASYNC_RC_RECYCLE_ACE	13
#define	IBD_ASYNC_RC_CLOSE_PAS_CHAN	14

/*
 * State of IBD driver initialization during attach/m_start
 */
#define	IBD_DRV_STATE_INITIALIZED	0x000001
#define	IBD_DRV_RXINTR_ADDED		0x000002
#define	IBD_DRV_TXINTR_ADDED		0x000004
#define	IBD_DRV_IBTL_ATTACH_DONE	0x000008
#define	IBD_DRV_HCA_OPENED		0x000010
#define	IBD_DRV_PD_ALLOCD		0x000020
#define	IBD_DRV_MAC_REGISTERED		0x000040
#define	IBD_DRV_PORT_DETAILS_OBTAINED	0x000080
#define	IBD_DRV_BCAST_GROUP_FOUND	0x000100
#define	IBD_DRV_ACACHE_INITIALIZED	0x000200
#define	IBD_DRV_CQS_ALLOCD		0x000400
#define	IBD_DRV_UD_CHANNEL_SETUP	0x000800
#define	IBD_DRV_TXLIST_ALLOCD		0x001000
#define	IBD_DRV_SCQ_NOTIFY_ENABLED	0x002000
#define	IBD_DRV_RXLIST_ALLOCD		0x004000
#define	IBD_DRV_BCAST_GROUP_JOINED	0x008000
#define	IBD_DRV_ASYNC_THR_CREATED	0x010000
#define	IBD_DRV_RCQ_NOTIFY_ENABLED	0x020000
#define	IBD_DRV_SM_NOTICES_REGISTERED	0x040000
#define	IBD_DRV_STARTED			0x080000
#define	IBD_DRV_RC_SRQ_ALLOCD		0x100000
#define	IBD_DRV_RC_LARGEBUF_ALLOCD	0x200000
#define	IBD_DRV_RC_LISTEN		0x400000
#ifdef DEBUG
#define	IBD_DRV_RC_PRIVATE_STATE	0x800000
#endif
#define	IBD_DRV_IN_DELETION		0x1000000
#define	IBD_DRV_IN_LATE_HCA_INIT 	0x2000000
#define	IBD_DRV_REQ_LIST_INITED 	0x4000000
#define	IBD_DRV_RC_TIMEOUT		0x8000000

/*
 * Miscellaneous constants
 */
#define	IBD_SEND			0
#define	IBD_RECV			1

/* Tunables defaults and limits */
#define	IBD_LINK_MODE_UD		0
#define	IBD_LINK_MODE_RC		1

#define	IBD_DEF_LINK_MODE		IBD_LINK_MODE_RC
#define	IBD_DEF_LSO_POLICY		B_TRUE
#define	IBD_DEF_NUM_LSO_BUFS		1024
#define	IBD_DEF_CREATE_BCAST_GROUP	B_TRUE
#define	IBD_DEF_COALESCE_COMPLETIONS	B_TRUE
#define	IBD_DEF_UD_RX_COMP_COUNT	4
#define	IBD_DEF_UD_RX_COMP_USEC		10
#define	IBD_DEF_UD_TX_COMP_COUNT	16
#define	IBD_DEF_UD_TX_COMP_USEC		300
#define	IBD_DEF_RC_RX_COMP_COUNT	4
#define	IBD_DEF_RC_RX_COMP_USEC		10
#define	IBD_DEF_RC_TX_COMP_COUNT	10
#define	IBD_DEF_RC_TX_COMP_USEC		300
#define	IBD_DEF_UD_TX_COPY_THRESH	4096
#define	IBD_DEF_RC_RX_COPY_THRESH	4096
#define	IBD_DEF_RC_TX_COPY_THRESH	4096
#define	IBD_DEF_UD_NUM_RWQE		4000
#define	IBD_DEF_UD_NUM_SWQE		4000
#define	IBD_DEF_RC_ENABLE_SRQ		B_TRUE
#if defined(__i386)
#define	IBD_DEF_RC_NUM_RWQE		511
#define	IBD_DEF_RC_NUM_SWQE		255
#else
#define	IBD_DEF_RC_NUM_RWQE		2047
#define	IBD_DEF_RC_NUM_SWQE		511
#endif
#define	IBD_DEF_NUM_AH			256
#define	IBD_DEF_HASH_SIZE		32
#define	IBD_DEF_RC_NUM_SRQ		(IBD_DEF_RC_NUM_RWQE - 1)
#define	IBD_DEF_RC_RX_RWQE_THRESH	(IBD_DEF_RC_NUM_RWQE >> 2)

/* Tunable limits */
#define	IBD_MIN_NUM_LSO_BUFS		512
#define	IBD_MAX_NUM_LSO_BUFS		4096
#define	IBD_MIN_UD_TX_COPY_THRESH	2048
#define	IBD_MAX_UD_TX_COPY_THRESH	65536
#define	IBD_MIN_UD_NUM_SWQE		512
#define	IBD_MAX_UD_NUM_SWQE		8000
#define	IBD_MIN_UD_NUM_RWQE		512
#define	IBD_MAX_UD_NUM_RWQE		8000
#define	IBD_MIN_NUM_AH			32
#define	IBD_MAX_NUM_AH			8192
#define	IBD_MIN_HASH_SIZE		32
#define	IBD_MAX_HASH_SIZE		1024

#if defined(__i386)
#define	IBD_MIN_RC_NUM_SWQE		255
#else
#define	IBD_MIN_RC_NUM_SWQE		511
#endif
#define	IBD_MAX_RC_NUM_SWQE		8000
#define	IBD_MIN_RC_NUM_RWQE		511
#define	IBD_MAX_RC_NUM_RWQE		8000
#define	IBD_MIN_RC_RX_COPY_THRESH	1500
#define	IBD_MAX_RC_RX_COPY_THRESH	65520
#define	IBD_MIN_RC_TX_COPY_THRESH	1500
#define	IBD_MAX_RC_TX_COPY_THRESH	65520
#define	IBD_MIN_RC_NUM_SRQ		(IBD_MIN_RC_NUM_RWQE - 1)
#define	IBD_MIN_RC_RX_RWQE_THRESH	(IBD_MIN_RC_NUM_RWQE >> 2)

/*
 * Thresholds
 *
 * When waiting for resources (swqes or lso buffers) to become available,
 * the first two thresholds below determine how long to wait before informing
 * the network layer to start sending packets again. The IBD_TX_POLL_THRESH
 * determines how low the available swqes should go before we start polling
 * the completion queue.
 */
#define	IBD_FREE_LSOS_THRESH		8
#define	IBD_FREE_SWQES_THRESH		20
#define	IBD_TX_POLL_THRESH		80

#ifdef DEBUG
void debug_print(int l, char *fmt, ...);
#define	DPRINT		debug_print
#else
#define	DPRINT		0 &&
#endif

/*
 * AH and MCE active list manipulation:
 *
 * Multicast disable requests and MCG delete traps are two cases
 * where the active AH entry for the mcg (if any unreferenced one exists)
 * will be moved to the free list (to force the next Tx to the mcg to
 * join the MCG in SendOnly mode). Port up handling will also move AHs
 * from active to free list.
 *
 * In the case when some transmits are still pending on an entry
 * for an mcg, but a multicast disable has already been issued on the
 * mcg, there are some options to consider to preserve the join state
 * to ensure the emitted packet is properly routed on the IBA fabric.
 * For the AH, we can
 * 1. take out of active list at multicast disable time.
 * 2. take out of active list only when last pending Tx completes.
 * For the MCE, we can
 * 3. take out of active list at multicast disable time.
 * 4. take out of active list only when last pending Tx completes.
 * 5. move from active list to stale list at multicast disable time.
 * We choose to use 2,4. We use option 4 so that if a multicast enable
 * is tried before the pending Tx completes, the enable code finds the
 * mce in the active list and just has to make sure it will not be reaped
 * (ie the mcg leave done) when the pending Tx does complete. Alternatively,
 * a stale list (#5) that would be checked in the enable code would need
 * to be implemented. Option 2 is used, because otherwise, a Tx attempt
 * after the multicast disable would try to put an AH in the active list,
 * and associate the mce it finds in the active list to this new AH,
 * whereas the mce is already associated with the previous AH (taken off
 * the active list), and will be removed once the pending Tx's complete
 * (unless a reference count on mce's is implemented). One implication of
 * using 2,4 is that new Tx's posted before the pending Tx's complete will
 * grab new references on the AH, further delaying the leave.
 *
 * In the case of mcg delete (or create) trap when the port is sendonly
 * joined, the AH and MCE handling is different: the AH and MCE has to be
 * immediately taken off the active lists (forcing a join and path lookup
 * at the next Tx is the only guaranteed means of ensuring a proper Tx
 * to an mcg as it is repeatedly created and deleted and goes thru
 * reincarnations).
 *
 * When a port is already sendonly joined, and a multicast enable is
 * attempted, the same mce structure is promoted; this ensures only a
 * single mce on the active list tracks the most powerful join state.
 *
 * In the case of port up event handling, the MCE for sendonly membership
 * is freed up, and the ACE is put into the free list as soon as possible
 * (depending on whether posted Tx's have completed). For fullmembership
 * MCE's though, the ACE is similarly handled; but the MCE is kept around
 * (a re-JOIN is attempted) only if the DLPI leave has not already been
 * done; else the mce is deconstructed (mc_fullreap case).
 *
 * MCG creation and deletion trap handling:
 *
 * These traps are unreliable (meaning sometimes the trap might never
 * be delivered to the subscribed nodes) and may arrive out-of-order
 * since they use UD transport. An alternative to relying on these
 * unreliable traps is to poll for mcg presence every so often, but
 * instead of doing that, we try to be as conservative as possible
 * while handling the traps, and hope that the traps do arrive at
 * the subscribed nodes soon. Note that if a node is fullmember
 * joined to an mcg, it can not possibly receive a mcg create/delete
 * trap for that mcg (by fullmember definition); if it does, it is
 * an old trap from a previous incarnation of the mcg.
 *
 * Whenever a trap is received, the driver cleans up its sendonly
 * membership to the group; we choose to do a sendonly leave even
 * on a creation trap to handle the case of a prior deletion of the mcg
 * having gone unnoticed. Consider an example scenario:
 * T1: MCG M is deleted, and fires off deletion trap D1.
 * T2: MCG M is recreated, fires off creation trap C1, which is lost.
 * T3: Node N tries to transmit to M, joining in sendonly mode.
 * T4: MCG M is deleted, and fires off deletion trap D2.
 * T5: N receives a deletion trap, but can not distinguish D1 from D2.
 *     If the trap is D2, then a LEAVE is not required, since the mcg
 *     is already deleted; but if it is D1, a LEAVE is required. A safe
 *     approach is to always LEAVE, but the SM may be confused if it
 *     receives a LEAVE without a prior JOIN.
 *
 * Management of the non-membership to an mcg is similar to the above,
 * except that if the interface is in promiscuous mode, it is required
 * to attempt to re-join the mcg after receiving a trap. Unfortunately,
 * if the re-join attempt fails (in which case a warning message needs
 * to be printed), it is not clear whether it failed due to the mcg not
 * existing, or some fabric/hca issues, due to the delayed nature of
 * trap delivery. Querying the SA to establish presence/absence of the
 * mcg is also racy at best. Thus, the driver just prints a warning
 * message when it can not rejoin after receiving a create trap, although
 * this might be (on rare occasions) a mis-warning if the create trap is
 * received after the mcg was deleted.
 */

/*
 * Implementation of atomic "recycle" bits and reference count
 * on address handles. This utilizes the fact that max reference
 * count on any handle is limited by number of send wqes, thus
 * high bits in the ac_ref field can be used as the recycle bits,
 * and only the low bits hold the number of pending Tx requests.
 * This atomic AH reference counting allows the Tx completion
 * handler not to acquire the id_ac_mutex to process every completion,
 * thus reducing lock contention problems between completion and
 * the Tx path.
 */
#define	CYCLEVAL		0x80000
#define	CLEAR_REFCYCLE(ace)	(ace)->ac_ref = 0
#define	CYCLE_SET(ace)		(((ace)->ac_ref & CYCLEVAL) == CYCLEVAL)
#define	GET_REF(ace)		((ace)->ac_ref)
#define	GET_REF_CYCLE(ace) (				\
	/*						\
	 * Make sure "cycle" bit is set.		\
	 */						\
	ASSERT(CYCLE_SET(ace)),				\
	((ace)->ac_ref & ~(CYCLEVAL))			\
)
#define	INC_REF(ace, num) {				\
	atomic_add_32(&(ace)->ac_ref, num);		\
}
#define	SET_CYCLE_IF_REF(ace) (				\
	CYCLE_SET(ace) ? B_TRUE :			\
	    atomic_add_32_nv(&ace->ac_ref, CYCLEVAL) ==	\
		CYCLEVAL ?				\
		/*					\
		 * Clear the "cycle" bit we just set;	\
		 * ref count known to be 0 from above.	\
		 */					\
		CLEAR_REFCYCLE(ace), B_FALSE :		\
		/*					\
		 * We set "cycle" bit; let caller know.	\
		 */					\
		B_TRUE					\
)
#define	DEC_REF_DO_CYCLE(ace) (				\
	atomic_dec_32_nv(&ace->ac_ref) == CYCLEVAL ?	\
		/*					\
		 * Ref count known to be 0 from above.	\
		 */					\
		B_TRUE :				\
		B_FALSE					\
)

/*
 * Address handle entries maintained by the driver are kept in the
 * free and active lists. Each entry starts out in the free list;
 * it migrates to the active list when primed using ibt_get_paths()
 * and ibt_modify_ud_dest() for transmission to a specific destination.
 * In the active list, the entry has a reference count indicating the
 * number of ongoing/uncompleted transmits that reference it. The
 * entry is left in the active list even after the reference count
 * goes to 0, since successive transmits can find it there and do
 * not need to set up another entry (ie the path information is
 * cached using the active list). Entries on the active list are
 * also hashed using the destination link address as a key for faster
 * lookups during transmits.
 *
 * For any destination address (unicast or multicast, whatever the
 * join states), there will be at most one entry in the active list.
 * Entries with a 0 reference count on the active list can be reused
 * for a transmit to a new destination, if the free list is empty.
 *
 * The AH free list insertion/deletion is protected with the id_ac_mutex,
 * since the async thread and Tx callback handlers insert/delete. The
 * active list does not need a lock (all operations are done by the
 * async thread) but updates to the reference count are atomically
 * done (increments done by Tx path, decrements by the Tx callback handler).
 */
#define	IBD_ACACHE_INSERT_FREE(state, ce) \
	list_insert_head(&state->id_ah_free, ce)
#define	IBD_ACACHE_GET_FREE(state) \
	list_get_head(&state->id_ah_free)
#define	IBD_ACACHE_INSERT_ACTIVE(state, ce) {			\
	int _ret_;						\
	list_insert_head(&state->id_ah_active, ce);		\
	_ret_ = mod_hash_insert(state->id_ah_active_hash,	\
	    (mod_hash_key_t)&ce->ac_mac, (mod_hash_val_t)ce);	\
	ASSERT(_ret_ == 0);					\
	state->id_ac_hot_ace = ce;				\
}
#define	IBD_ACACHE_PULLOUT_ACTIVE(state, ce) {			\
	list_remove(&state->id_ah_active, ce);			\
	if (state->id_ac_hot_ace == ce)				\
		state->id_ac_hot_ace = NULL;			\
	(void) mod_hash_remove(state->id_ah_active_hash,	\
	    (mod_hash_key_t)&ce->ac_mac, (mod_hash_val_t)ce);	\
}
#define	IBD_ACACHE_GET_ACTIVE(state) \
	list_get_head(&state->id_ah_active)

/*
 * Padding for nd6 Neighbor Solicitation and Advertisement needs to be at
 * front of optional src/tgt link layer address. Right now Solaris inserts
 * padding by default at the end. The routine which is doing is nce_xmit()
 * in ip_ndp.c. It copies the nd_lla_addr after the nd_opt_hdr_t. So when
 * the packet comes down from IP layer to the IBD driver, it is in the
 * following format: [IPoIB_PTXHDR_T][INET6 packet][ICMP6][OPT_ND_HDR_T]
 * This size is 2 bytes followed by [22 bytes of ipoib_machdr]. As a result
 * machdr is not 4 byte aligned and had 2 bytes of padding at the end.
 *
 * The send routine at IBD driver changes this packet as follows:
 * [IPoIB_HDR_T][INET6 packet][ICMP6][OPT_ND_HDR_T + 2 bytes of padding]
 * followed by [22 bytes of ipoib_machdr] resulting in machdr 4 byte
 * aligned.
 *
 * At the receiving side again ibd_process_rx takes the above packet and
 * removes the two bytes of front padding and inserts it at the end. This
 * is since the IP layer does not understand padding at the front.
 */
#define	IBD_PAD_NSNA(ip6h, len, type) {					\
	uchar_t 	*nd_lla_ptr;					\
	icmp6_t 	*icmp6;						\
	nd_opt_hdr_t	*opt;						\
	int 		i;						\
									\
	icmp6 = (icmp6_t *)&ip6h[1];					\
	len -= sizeof (nd_neighbor_advert_t);				\
	if (((icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT) ||		\
	    (icmp6->icmp6_type == ND_NEIGHBOR_ADVERT)) &&		\
	    (len != 0)) {						\
		opt = (nd_opt_hdr_t *)((uint8_t *)ip6h			\
		    + IPV6_HDR_LEN + sizeof (nd_neighbor_advert_t));	\
		ASSERT(opt != NULL);					\
		nd_lla_ptr = (uchar_t *)&opt[1];			\
		if (type == IBD_SEND) {					\
			for (i = IPOIB_ADDRL; i > 0; i--)		\
				*(nd_lla_ptr + i + 1) =			\
				    *(nd_lla_ptr + i - 1);		\
		} else {						\
			for (i = 0; i < IPOIB_ADDRL; i++)		\
				*(nd_lla_ptr + i) =			\
				    *(nd_lla_ptr + i + 2);		\
		}							\
		*(nd_lla_ptr + i) = 0;					\
		*(nd_lla_ptr + i + 1) = 0;				\
	}								\
}


/*
 * IETF defined IPoIB encapsulation header, with 2b of ethertype
 * followed by 2 reserved bytes. This is at the start of the
 * datagram sent to and received over the wire by the driver.
 */
typedef struct ipoib_header {
	ushort_t	ipoib_type;
	ushort_t	ipoib_mbz;
} ipoib_hdr_t;

#define	IPOIB_HDRSIZE	sizeof (struct ipoib_header)

/*
 * IETF defined IPoIB link address; IBA QPN, followed by GID,
 * which has a prefix and suffix, as reported via ARP.
 */
typedef struct ipoib_mac {
	uint32_t	ipoib_qpn;
	uint32_t	ipoib_gidpref[2];
	uint32_t	ipoib_gidsuff[2];
} ipoib_mac_t;

#define	IPOIB_ADDRL	sizeof (struct ipoib_mac)

/*
 * Pseudo header prepended to datagram in DLIOCRAW transmit path
 * and when GLD hands the datagram to the gldm_send entry point.
 */
typedef struct ipoib_ptxhdr {
	ipoib_mac_t	ipoib_dest;
	ipoib_hdr_t	ipoib_rhdr;
} ipoib_ptxhdr_t;

#define	IPOIBDLSAP(p, offset)	((ipoib_ptxhdr_t *)((caddr_t)(p)+offset))

/*
 * The pseudo-GRH structure that sits before the data in the
 * receive buffer, and is overlaid on top of the real GRH.
 * The driver sets the ipoib_vertcflow to 0 if the pseudo-GRH
 * does not hold valid information. If it is indicated valid,
 * the driver must additionally provide the sender's qpn in
 * network byte order in ipoib_sqpn, and not touch the
 * remaining parts which were DMA'ed in by the IBA hardware.
 */
typedef struct ipoib_pgrh {
	uint32_t	ipoib_vertcflow;
	uint32_t	ipoib_sqpn;
	uint32_t	ipoib_sgid_pref[2];
	uint32_t	ipoib_sgid_suff[2];
	uint32_t	ipoib_dgid_pref[2];
	uint32_t	ipoib_dgid_suff[2];
} ipoib_pgrh_t;

/*
 * The GRH is also dma'ed into recv buffers, thus space needs
 * to be allocated for them.
 */
#define	IPOIB_GRH_SIZE	sizeof (ipoib_pgrh_t)

/* support  the RC (reliable connected) mode */
#define	IBD_MAC_ADDR_RC		0x80000000
/* support the UC (unreliable connected) mode */
#define	IBD_MAC_ADDR_UC		0x40000000

#define	IBD_RC_SERVICE_ID 0x100000000000000ULL

/*
 * Legacy OFED had used a wrong service ID (one additional zero digit) for
 * many years. To interop with legacy OFED, we support this wrong service ID
 * here.
 */
#define	IBD_RC_SERVICE_ID_OFED_INTEROP 0x1000000000000000ULL

#define	IBD_RC_MIN_CQ_SIZE	0x7f

/* Number of ibt_wc_t provided for each RC channel */
#define	IBD_RC_MAX_CQ_WC	0x3f

#if defined(_KERNEL) && !defined(_BOOT)

#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ib_pkt_hdrs.h>
#include <sys/list.h>
#include <sys/mac_provider.h>
#include <sys/mac_ib.h>
#include <sys/modhash.h>

/* State of a reliable connected channel (ibd_rc_chan_t->chan_state) */
typedef enum {
	IBD_RC_STATE_INIT = 0,

	/* Active side */
	IBD_RC_STATE_ACT_REP_RECV,	/* reply received */
	IBD_RC_STATE_ACT_ESTAB,		/* established, ready to send */
	IBD_RC_STATE_ACT_REJECT,	/* rejected */
	/* Someone else is closing this channel, please don't re-close it */
	IBD_RC_STATE_ACT_CLOSING,
	IBD_RC_STATE_ACT_CLOSED,
	IBD_RC_STATE_ACT_ERROR,

	/* Passive side */
	IBD_RC_STATE_PAS_REQ_RECV,	/* request received */
	IBD_RC_STATE_PAS_ESTAB,		/* established, ready to receive */
	IBD_RC_STATE_PAS_REJECT,	/* rejected */

	IBD_RC_STATE_PAS_CLOSED
} ibd_rc_chan_state_t;

/*
 * Structure to encapsulate various types of async requests.
 */
typedef struct ibd_acache_rq {
	struct list_node 	rq_list; 	/* list of pending work */
	int			rq_op;		/* what operation */
	ipoib_mac_t		rq_mac;
	ib_gid_t		rq_gid;
	void			*rq_ptr;
	void			*rq_ptr2;
} ibd_req_t;

typedef struct ibd_mcache {
	struct list_node	mc_list;	/* full/non list */
	uint8_t			mc_jstate;
	boolean_t		mc_fullreap;
	ibt_mcg_info_t		mc_info;
	ibd_req_t		mc_req;		/* to queue LEAVE req */
} ibd_mce_t;

typedef struct ibd_acache_s {
	struct list_node	ac_list;	/* free/active list */
	ibt_ud_dest_hdl_t	ac_dest;
	ipoib_mac_t		ac_mac;
	uint32_t		ac_ref;
	ibd_mce_t		*ac_mce;	/* for MCG AHs */

	/* For Reliable Connected mode */
	struct ibd_rc_chan_s	*ac_chan;
	/* protect tx_too_big_ongoing */
	kmutex_t		tx_too_big_mutex;
	/* Deal with too big packet */
	boolean_t		tx_too_big_ongoing;
} ibd_ace_t;

#define	IBD_MAX_SQSEG	59
#define	IBD_MAX_RQSEG	1

typedef enum {
	IBD_WQE_SEND,
	IBD_WQE_RECV
} ibd_wqe_type_t;

typedef enum {
	IBD_WQE_TXBUF = 1,
	IBD_WQE_LSOBUF = 2,
	IBD_WQE_MAPPED = 3,
	IBD_WQE_RC_COPYBUF = 4
} ibd_wqe_buftype_t;

#ifdef DEBUG
typedef struct ibd_rc_stat_s {
	kstat_named_t		rc_rcv_trans_byte;
	kstat_named_t		rc_rcv_trans_pkt;
	kstat_named_t		rc_rcv_copy_byte;
	kstat_named_t		rc_rcv_copy_pkt;
	kstat_named_t		rc_rcv_alloc_fail;

	kstat_named_t		rc_rcq_err;	/* fail in rcq handler */

	kstat_named_t		rc_rwqe_short;	/* short rwqe */

	kstat_named_t		rc_xmt_bytes;
	/* pkt size <= state->id_rc_tx_copy_thresh */
	kstat_named_t		rc_xmt_small_pkt;
	kstat_named_t		rc_xmt_fragmented_pkt;
	/* fail in ibt_map_mem_iov() */
	kstat_named_t		rc_xmt_map_fail_pkt;
	/* succ in ibt_map_mem_iov() */
	kstat_named_t		rc_xmt_map_succ_pkt;

	kstat_named_t		rc_ace_not_found;	/* ace not found */
	/* no swqe even after recycle */
	kstat_named_t		rc_scq_no_swqe;
	/* no tx large buf even after recycle */
	kstat_named_t		rc_scq_no_largebuf;

	/* short swqe in ibd_send() */
	kstat_named_t		rc_swqe_short;
	/* call mac_tx_update() when there is enough swqe */
	kstat_named_t		rc_swqe_mac_update;
	/* short large buf in ibd_send() */
	kstat_named_t		rc_xmt_buf_short;
	/* call mac_tx_update() when there is enough Tx large buffers */
	kstat_named_t rc_xmt_buf_mac_update;

	kstat_named_t		rc_conn_succ;	/* # of success connect */
	kstat_named_t		rc_conn_fail;	/* # of fail connect */
	/* ace->ac_chan == NULL for unicast packet */
	kstat_named_t		rc_null_conn;
	/* not in active established state */
	kstat_named_t		rc_no_estab_conn;

	kstat_named_t		rc_act_close;	/* call ibd_rc_act_close() */
	kstat_named_t		rc_pas_close;	/* call ibd_rc_pas_close() */
	kstat_named_t		rc_delay_ace_recycle;
	kstat_named_t		rc_act_close_simultaneous;

	kstat_named_t		rc_reset_cnt;	/* # of Reset RC channel */
	kstat_named_t		rc_timeout_act;
	kstat_named_t		rc_timeout_pas;
} ibd_rc_stat_t;
#endif

typedef struct ibd_rc_chan_list_s {
	/* This mutex protects chan_list and ibd_rc_chan_t.next */
	kmutex_t		chan_list_mutex;
	struct ibd_rc_chan_s	*chan_list;
} ibd_rc_chan_list_t;

typedef struct ibd_rc_tx_largebuf_s {
	struct ibd_rc_tx_largebuf_s	*lb_next;
	uint8_t				*lb_buf;
} ibd_rc_tx_largebuf_t;

/*
 * Pre-registered copybuf used for send and receive
 */
typedef struct ibd_copybuf_s {
	ibt_wr_ds_t		ic_sgl;
	uint8_t			*ic_bufaddr;
} ibd_copybuf_t;

typedef struct ibd_wqe_s {
	struct ibd_wqe_s	*w_next;
	ibd_copybuf_t		w_copybuf;
	mblk_t			*im_mblk;
} ibd_wqe_t;

/*
 * Send WQE
 */
typedef struct ibd_swqe_s {
	ibd_wqe_t		w_ibd_swqe;
	ibd_wqe_buftype_t	w_buftype;
	ibt_send_wr_t		w_swr;
	ibd_ace_t		*w_ahandle;
	ibt_mi_hdl_t		w_mi_hdl;
	ibt_wr_ds_t		w_sgl[IBD_MAX_SQSEG];
	ibd_rc_tx_largebuf_t	*w_rc_tx_largebuf;
} ibd_swqe_t;

#define	swqe_next		w_ibd_swqe.w_next
#define	swqe_copybuf		w_ibd_swqe.w_copybuf
#define	swqe_im_mblk		w_ibd_swqe.im_mblk
#define	SWQE_TO_WQE(swqe)	(ibd_wqe_t *)&((swqe)->w_ibd_swqe)
#define	WQE_TO_SWQE(wqe)	(ibd_swqe_t *)wqe

/*
 * Receive WQE
 */
typedef struct ibd_rwqe_s {
	ibd_wqe_t		w_ibd_rwqe;
	struct ibd_state_s	*w_state;
	ibt_recv_wr_t		w_rwr;
	frtn_t			w_freemsg_cb;
	boolean_t		w_freeing_wqe;
	struct ibd_rc_chan_s	*w_chan;
} ibd_rwqe_t;

#define	rwqe_next		w_ibd_rwqe.w_next
#define	rwqe_copybuf		w_ibd_rwqe.w_copybuf
#define	rwqe_im_mblk		w_ibd_rwqe.im_mblk
#define	RWQE_TO_WQE(rwqe)	(ibd_wqe_t *)&((rwqe)->w_ibd_rwqe)
#define	WQE_TO_RWQE(wqe)	(ibd_rwqe_t *)wqe

typedef struct ibd_list_s {
	kmutex_t		dl_mutex;
	ibd_wqe_t		*dl_head;
	union {
		boolean_t	pending_sends;
		uint32_t	bufs_outstanding;
	} ustat;
	uint32_t		dl_cnt;
} ibd_list_t;

#define	dl_pending_sends	ustat.pending_sends
#define	dl_bufs_outstanding	ustat.bufs_outstanding

/*
 * LSO buffers
 *
 * Under normal circumstances we should never need to use any buffer
 * that's larger than MTU.  Unfortunately, IB HCA has limitations
 * on the length of SGL that are much smaller than those for regular
 * ethernet NICs.  Since the network layer doesn't care to limit the
 * number of mblk fragments in any send mp chain, we end up having to
 * use these larger-than-MTU sized (larger than id_tx_buf_sz actually)
 * buffers occasionally.
 */
typedef struct ibd_lsobuf_s {
	struct ibd_lsobuf_s *lb_next;
	uint8_t		*lb_buf;
	int		lb_isfree;
} ibd_lsobuf_t;

typedef struct ibd_lsobkt_s {
	uint8_t		*bkt_mem;
	ibd_lsobuf_t	*bkt_bufl;
	ibd_lsobuf_t	*bkt_free_head;
	ibt_mr_hdl_t	bkt_mr_hdl;
	ibt_mr_desc_t	bkt_mr_desc;
	uint_t		bkt_nelem;
	uint_t		bkt_nfree;
} ibd_lsobkt_t;

#define	IBD_PORT_DRIVER		0x1
#define	IBD_PARTITION_OBJ	0x2

/*
 * Posting to a single software rx post queue is contentious,
 * so break it out to (multiple) an array of queues.
 *
 * Try to ensure rx_queue structs fall in different cache lines using a filler.
 * Note: the RX_QUEUE_CACHE_LINE needs to change if the struct changes.
 */
#define	RX_QUEUE_CACHE_LINE \
	(64 - (sizeof (kmutex_t) + sizeof (ibd_wqe_t *) + sizeof (uint_t)))
typedef struct ibd_rx_queue_s {
	kmutex_t		rx_post_lock;
	ibd_wqe_t		*rx_head;
	uint_t			rx_cnt;
	uint8_t			rx_pad[RX_QUEUE_CACHE_LINE];
} ibd_rx_queue_t;

/*
 * This structure maintains information per port per HCA
 * (per network interface).
 */
typedef struct ibd_state_s {
	uint_t			id_type;
	dev_info_t		*id_dip;
	ibt_clnt_hdl_t		id_ibt_hdl;
	ibt_hca_hdl_t		id_hca_hdl;
	ibt_pd_hdl_t		id_pd_hdl;
	kmem_cache_t		*id_req_kmc;

	ibd_list_t		id_tx_rel_list;

	uint32_t		id_running;

	uint32_t		id_max_sqseg;
	uint32_t		id_max_sqseg_hiwm;
	ibd_list_t		id_tx_list;
	ddi_softintr_t		id_tx;
	uint32_t		id_tx_sends;

	kmutex_t		id_txpost_lock;
	ibd_swqe_t		*id_tx_head;
	ibd_swqe_t		*id_tx_tail;
	int			id_tx_busy;

	uint_t			id_tx_buf_sz;
	uint8_t			*id_tx_bufs;
	ibd_swqe_t		*id_tx_wqes;
	ibt_mr_hdl_t		id_tx_mr_hdl;
	ibt_mr_desc_t		id_tx_mr_desc;

	kmutex_t		id_lso_lock;
	ibd_lsobkt_t		*id_lso;

	kmutex_t		id_scq_poll_lock;
	int			id_scq_poll_busy;

	ibt_cq_hdl_t		id_scq_hdl;
	ibt_wc_t		*id_txwcs;
	uint32_t		id_txwcs_size;

	int			id_rx_nqueues;
	ibd_rx_queue_t		*id_rx_queues;
	int			id_rx_post_queue_index;
	uint32_t		id_rx_post_active;

	ibd_rwqe_t		*id_rx_wqes;
	uint8_t			*id_rx_bufs;
	ibt_mr_hdl_t		id_rx_mr_hdl;
	ibt_mr_desc_t		id_rx_mr_desc;
	uint_t			id_rx_buf_sz;
	/*
	 * id_ud_num_rwqe
	 * Number of "receive WQE" elements that will be allocated and used
	 * by ibd. This parameter is limited by the maximum channel size of
	 * the HCA. Each buffer in the receive wqe will be of MTU size.
	 */
	uint32_t		id_ud_num_rwqe;
	ibd_list_t		id_rx_list;
	ddi_softintr_t		id_rx;
	uint32_t		id_rx_bufs_outstanding_limit;
	uint32_t		id_rx_allocb;
	uint32_t		id_rx_allocb_failed;
	ibd_list_t		id_rx_free_list;

	kmutex_t		id_rcq_poll_lock;
	int			id_rcq_poll_busy;
	uint32_t		id_rxwcs_size;
	ibt_wc_t		*id_rxwcs;
	ibt_cq_hdl_t		id_rcq_hdl;

	ibt_channel_hdl_t	id_chnl_hdl;
	ib_pkey_t		id_pkey;
	uint16_t		id_pkix;
	uint8_t			id_port;
	ibt_mcg_info_t		*id_mcinfo;

	mac_handle_t		id_mh;
	mac_resource_handle_t	id_rh;
	ib_gid_t		id_sgid;
	ib_qpn_t		id_qpnum;
	ipoib_mac_t		id_macaddr;
	ib_gid_t		id_mgid;
	ipoib_mac_t		id_bcaddr;

	int			id_mtu;
	uchar_t			id_scope;

	kmutex_t		id_acache_req_lock;
	kcondvar_t		id_acache_req_cv;
	struct list		id_req_list;
	kt_did_t		id_async_thrid;

	kmutex_t		id_ac_mutex;
	ibd_ace_t		*id_ac_hot_ace;
	struct list		id_ah_active;
	struct list		id_ah_free;
	ipoib_mac_t		id_ah_addr;
	ibd_req_t		id_ah_req;
	char			id_ah_op;
	uint64_t		id_ah_error;
	ibd_ace_t		*id_ac_list;
	mod_hash_t		*id_ah_active_hash;

	kmutex_t		id_mc_mutex;
	struct list		id_mc_full;
	struct list		id_mc_non;

	kmutex_t		id_trap_lock;
	kcondvar_t		id_trap_cv;
	boolean_t		id_trap_stop;
	uint32_t		id_trap_inprog;

	char			id_prom_op;

	kmutex_t		id_sched_lock;
	int			id_sched_needed;
	int			id_sched_cnt;
	int			id_sched_lso_cnt;

	kmutex_t		id_link_mutex;
	link_state_t		id_link_state;
	uint64_t		id_link_speed;

	uint64_t		id_num_intrs;
	uint64_t		id_tx_short;
	/*
	 * id_ud_num_swqe
	 * Number of "send WQE" elements that will be allocated and used by
	 * ibd. When tuning this parameter, the size of pre-allocated, pre-
	 * mapped copy buffer in each of these send wqes must be taken into
	 * account. This copy buffer size is determined by the value of
	 * IBD_TX_BUF_SZ (this is currently set to the same value of
	 * ibd_tx_copy_thresh, but may be changed independently if needed).
	 */
	uint32_t		id_ud_num_swqe;

	uint64_t		id_xmt_bytes;
	uint64_t		id_rcv_bytes;
	uint64_t		id_multi_xmt;
	uint64_t		id_brd_xmt;
	uint64_t		id_multi_rcv;
	uint64_t		id_brd_rcv;
	uint64_t		id_xmt_pkt;
	uint64_t		id_rcv_pkt;

	uint32_t		id_hwcksum_capab;
	boolean_t		id_lso_policy;
	boolean_t		id_lso_capable;
	uint_t			id_lso_maxlen;
	int			id_hca_res_lkey_capab;
	ibt_lkey_t		id_res_lkey;

	boolean_t		id_bgroup_created;
	kmutex_t		id_macst_lock;
	kcondvar_t		id_macst_cv;
	uint32_t		id_mac_state;

	/* For Reliable Connected Mode */
	boolean_t		id_enable_rc;
	boolean_t		rc_enable_srq;

	int			rc_mtu;
	uint32_t		rc_tx_max_sqseg;
	/*
	 * In IPoIB over Reliable Connected mode, its mac address is added
	 * an "IBD_MAC_ADDR_RC" prefix. But for loopback filter in function
	 * ibd_process_rx(), the input mac address should not include the
	 * "IBD_MAC_ADDR_RC" prefix.
	 *
	 * So, we introduce the rc_macaddr_loopback for the loopback filter in
	 * IPoIB over Reliable Connected mode.
	 *
	 * rc_macaddr_loopback = id_macaddr excludes "IBD_MAC_ADDR_RC" prefix.
	 */
	ipoib_mac_t		rc_macaddr_loopback;

	ibt_srv_hdl_t		rc_listen_hdl;
	ibt_sbind_hdl_t		rc_listen_bind;
	ibt_srv_hdl_t		rc_listen_hdl_OFED_interop;
	ibt_sbind_hdl_t		rc_listen_bind_OFED_interop;

	ibd_rc_chan_list_t	rc_pass_chan_list;
	/* obsolete active channel list */
	ibd_rc_chan_list_t	rc_obs_act_chan_list;

	kmutex_t		rc_ace_recycle_lock;
	ibd_ace_t		*rc_ace_recycle;

	/* Send */
	/*
	 * This mutex protects rc_tx_largebuf_free_head, rc_tx_largebuf_nfree
	 * and ibd_rc_tx_largebuf_t->lb_next
	 */
	kmutex_t		rc_tx_large_bufs_lock;
	ibd_rc_tx_largebuf_t	*rc_tx_largebuf_free_head;
	uint_t			rc_tx_largebuf_nfree;
	/* The chunk of whole Tx large buffers */
	uint8_t			*rc_tx_mr_bufs;
	ibt_mr_hdl_t		rc_tx_mr_hdl;
	ibt_mr_desc_t		rc_tx_mr_desc;
	ibd_rc_tx_largebuf_t	*rc_tx_largebuf_desc_base;	/* base addr */

	boolean_t		rc_enable_iov_map;
	uint_t			rc_max_sqseg_hiwm;

	/* For SRQ */
	uint32_t 		rc_srq_size;
	ibt_srq_hdl_t		rc_srq_hdl;
	ibd_list_t		rc_srq_rwqe_list;
	ibd_list_t		rc_srq_free_list;
	ibd_rwqe_t		*rc_srq_rwqes;
	uint8_t			*rc_srq_rx_bufs;
	ibt_mr_hdl_t		rc_srq_rx_mr_hdl;
	ibt_mr_desc_t		rc_srq_rx_mr_desc;

	/* For chained receive */
	kmutex_t		rc_rx_lock;
	mblk_t			*rc_rx_mp;
	mblk_t			*rc_rx_mp_tail;
	uint32_t		rc_rx_mp_len;

	uint32_t		rc_num_tx_chan;
	uint32_t		rc_num_rx_chan;

	/* Protect rc_timeout_start and rc_timeout */
	kmutex_t		rc_timeout_lock;
	boolean_t		rc_timeout_start;
	timeout_id_t		rc_timeout;

	/* Counters for RC mode */
	/* RX */
	/*
	 * # of Received packets. These packets are directly transferred to GLD
	 * without copy it
	 */
	uint64_t		rc_rcv_trans_byte;
	uint64_t		rc_rcv_trans_pkt;
	/*
	 * # of Received packets. We will allocate new buffers for these packet,
	 * copy their content into new buffers, then transfer to GLD
	 */
	uint64_t		rc_rcv_copy_byte;
	uint64_t		rc_rcv_copy_pkt;
	uint64_t		rc_rcv_alloc_fail;

#ifdef DEBUG
	uint64_t		rc_rwqe_short;	/* short rwqe */
#endif

	/* wc->wc_status != IBT_WC_SUCCESS */
	uint64_t		rc_rcq_err;

	/* Tx */
	uint64_t		rc_xmt_bytes;

	/* pkt size <= ibd_rc_tx_copy_thresh */
	uint64_t		rc_xmt_small_pkt;
	uint64_t		rc_xmt_fragmented_pkt;
	/* fail in ibt_map_mem_iov() */
	uint64_t		rc_xmt_map_fail_pkt;
	/* succ in ibt_map_mem_iov() */
	uint64_t		rc_xmt_map_succ_pkt;

	uint64_t		rc_ace_not_found;

	uint64_t		rc_xmt_drop_too_long_pkt;
	uint64_t		rc_xmt_icmp_too_long_pkt;
	uint64_t		rc_xmt_reenter_too_long_pkt;

	/* short swqe in ibd_send() */
	uint64_t		rc_swqe_short;
	/* call mac_tx_update when there is enough swqe */
	uint64_t		rc_swqe_mac_update;
	/* short tx large copy buf in ibd_send() */
	uint64_t		rc_xmt_buf_short;
	/* call mac_tx_update when there is enough Tx copy buf */
	uint64_t		rc_xmt_buf_mac_update;

	/* No swqe even after call swqe recycle function */
	uint64_t		rc_scq_no_swqe;
	/* No large Tx buf even after call swqe recycle function */
	uint64_t		rc_scq_no_largebuf;

	/* Connection setup and close */
	uint64_t		rc_conn_succ;	/* time of succ connect */
	uint64_t		rc_conn_fail;	/* time of fail connect */
	/* ace->ac_chan == NULL for unicast packet */
	uint64_t		rc_null_conn;
	/* not in active established state */
	uint64_t		rc_no_estab_conn;

	uint64_t		rc_act_close;	/* call ibd_rc_act_close() */
	uint64_t		rc_pas_close;	/* call ibd_rc_pas_close() */
	uint64_t		rc_delay_ace_recycle;
	uint64_t		rc_act_close_simultaneous;
	/* Fail to close a channel because someone else is still using it */
	uint64_t		rc_act_close_not_clean;
	/* RCQ is being invoked when closing RC channel */
	uint64_t		rc_pas_close_rcq_invoking;

	/* the counter of reset RC channel */
	uint64_t		rc_reset_cnt;

	uint64_t		rc_timeout_act;
	uint64_t		rc_timeout_pas;

	/*
	 * Fail to stop this port because this port is connecting to a remote
	 * port
	 */
	uint64_t		rc_stop_connect;

#ifdef DEBUG
	kstat_t 		*rc_ksp;
#endif
	ib_guid_t		id_hca_guid;
	ib_guid_t		id_port_guid;
	datalink_id_t		id_dlinkid;
	datalink_id_t		id_plinkid;
	int			id_port_inst;
	struct ibd_state_s	*id_next;
	boolean_t		id_force_create;
	boolean_t		id_bgroup_present;
	uint_t			id_hca_max_chan_sz;

	/*
	 * UD Mode Tunables
	 *
	 * id_ud_tx_copy_thresh
	 * This sets the threshold at which ibd will attempt to do a bcopy
	 * of the outgoing data into a pre-mapped buffer. IPoIB driver's
	 * send behavior is restricted by various parameters, so setting of
	 * this value must be made after careful considerations only. For
	 * instance, IB HCAs currently impose a relatively small limit
	 * (when compared to ethernet NICs) on the length of the SGL for
	 * transmit. On the other hand, the ip stack could send down mp
	 * chains that are quite long when LSO is enabled.
	 *
	 * id_num_lso_bufs
	 * Number of "larger-than-MTU" copy buffers to use for cases when the
	 * outgoing mblk chain is too fragmented to be used with
	 * ibt_map_mem_iov() and too large to be used with regular MTU-sized
	 * copy buffers. It is not recommended to tune this variable without
	 * understanding the application environment and/or memory resources.
	 * The size of each of these lso buffers is determined by the value of
	 * IBD_LSO_BUFSZ.
	 *
	 * id_num_ah
	 * Number of AH cache entries to allocate
	 *
	 * id_hash_size
	 * Hash table size for the active AH list
	 *
	 */
	uint_t id_ud_tx_copy_thresh;
	uint_t id_num_lso_bufs;
	uint_t id_num_ah;
	uint_t id_hash_size;

	boolean_t id_create_broadcast_group;

	boolean_t id_allow_coalesce_comp_tuning;
	uint_t id_ud_rx_comp_count;
	uint_t id_ud_rx_comp_usec;
	uint_t id_ud_tx_comp_count;
	uint_t id_ud_tx_comp_usec;

	/* RC Mode Tunables */

	uint_t id_rc_rx_comp_count;
	uint_t id_rc_rx_comp_usec;
	uint_t id_rc_tx_comp_count;
	uint_t id_rc_tx_comp_usec;
	/*
	 * id_rc_tx_copy_thresh
	 * This sets the threshold at which ibd will attempt to do a bcopy
	 * of the outgoing data into a pre-mapped buffer.
	 *
	 * id_rc_rx_copy_thresh
	 * If (the size of incoming buffer <= id_rc_rx_copy_thresh), ibd
	 * will attempt to allocate a buffer and do a bcopy of the incoming
	 * data into the allocated buffer.
	 *
	 * id_rc_rx_rwqe_thresh
	 * If (the number of available rwqe < ibd_rc_rx_rwqe_thresh), ibd
	 * will attempt to allocate a buffer and do a bcopy of the incoming
	 * data into the allocated buffer.
	 *
	 * id_rc_num_swqe
	 * 1) Send CQ size = ibd_rc_num_swqe
	 * 2) The send queue size = ibd_rc_num_swqe -1
	 * 3) Number of pre-allocated Tx buffers for ibt_post_send() =
	 * ibd_rc_num_swqe - 1.
	 *
	 * id_rc_num_rwqe
	 * 1) For non-SRQ, we pre-post id_rc_num_rwqe number of WRs
	 * via ibt_post_receive() for receive queue of each RC channel.
	 * 2) For SRQ and non-SRQ, receive CQ size = id_rc_num_rwqe
	 *
	 * For SRQ
	 * If using SRQ, we allocate id_rc_num_srq number of buffers (the
	 * size of each buffer is equal to RC mtu). And post them by
	 * ibt_post_srq().
	 *
	 * id_rc_num_srq
	 * id_rc_num_srq should not be larger than id_rc_num_rwqe,
	 * otherwise it will cause a bug with the following warnings:
	 * NOTICE: hermon0: Device Error: EQE cq overrun or protection error
	 * NOTICE: hermon0: Device Error: EQE local work queue catastrophic
	 * error
	 * NOTICE: ibd0: HCA GUID 0003ba0001008984 port 1 PKEY ffff
	 * catastrophic channel error
	 * NOTICE: ibd0: HCA GUID 0003ba0001008984 port 1 PKEY ffff
	 * completion queue error
	 */
	uint_t id_rc_tx_copy_thresh;
	uint_t id_rc_rx_copy_thresh;
	uint_t id_rc_rx_rwqe_thresh;
	uint_t id_rc_num_swqe;
	uint_t id_rc_num_rwqe;
	uint_t id_rc_num_srq;
} ibd_state_t;

/*
 * Structures to track global IBTF data, data that is shared
 * among the IBD device instances.  This includes the one ibt_hdl
 * and the list of service registrations.
 */
typedef struct ibd_service_s {
	struct ibd_service_s	*is_link;
	ibt_srv_hdl_t		is_srv_hdl;
	ib_svc_id_t		is_sid;
	uint_t			is_ref_cnt;
} ibd_service_t;

typedef struct ibd_global_state_s {
	kmutex_t	ig_mutex;
	ibt_clnt_hdl_t	ig_ibt_hdl;
	uint_t		ig_ibt_hdl_ref_cnt;
	ibd_service_t	*ig_service_list;
} ibd_global_state_t;

typedef struct ibd_rc_msg_hello_s {
	uint32_t reserved_qpn;
	uint32_t rx_mtu;
} ibd_rc_msg_hello_t;

typedef struct ibd_rc_chan_s {
	struct ibd_rc_chan_s	*next;
	/* channel hdl that we'll be using for Reliable Connected Mode */
	ibt_channel_hdl_t	chan_hdl;
	struct ibd_state_s	*state;
	ibd_ace_t		*ace;
	ibd_rc_chan_state_t	chan_state;

	ibd_list_t		tx_wqe_list;	/* free wqe list */
	ibd_list_t		tx_rel_list;	/* for swqe recycle */

	ibd_swqe_t		*tx_wqes;

	/* start address of Tx Buffers */
	uint8_t			*tx_mr_bufs;
	ibt_mr_hdl_t		tx_mr_hdl;
	ibt_mr_desc_t		tx_mr_desc;

	ibt_cq_hdl_t		scq_hdl;	/* Tx completion queue */
	ibt_wc_t		tx_wc[IBD_RC_MAX_CQ_WC];
	ddi_softintr_t		scq_softintr;

	/* For chained send */
	kmutex_t		tx_post_lock;
	ibd_swqe_t		*tx_head;
	ibd_swqe_t		*tx_tail;
	int			tx_busy;

	/* For tx buffer recycle */
	kmutex_t		tx_poll_lock;
	int			tx_poll_busy;

	/* Rx */
	ibd_list_t		rx_wqe_list;	/* used by ibt_post_recv */
	ibd_list_t		rx_free_list;	/* free rwqe list */

	ibt_cq_hdl_t		rcq_hdl;	/* Rx completion queue */
	ibt_wc_t		rx_wc[IBD_RC_MAX_CQ_WC];

	ibd_rwqe_t		*rx_rwqes;	/* the chuck of whole rwqes */
	uint8_t			*rx_bufs;	/* the chuck of whole Rx bufs */
	ibt_mr_hdl_t		rx_mr_hdl;	/* ibt_mr_hdl_t for rx_bufs */
	ibt_mr_desc_t		rx_mr_desc;	/* ibt_mr_desc_t for rx_bufs */

	/* For chained receive */
	kmutex_t		rx_lock;
	mblk_t			*rx_mp;
	mblk_t			*rx_mp_tail;
	uint32_t		rx_mp_len;

	uint32_t 		rcq_size;
	uint32_t 		scq_size;
	/*
	 * We need two channels for each connection.
	 * One channel for Tx; another channel for Rx.
	 * If "is_tx_chan == B_TRUE", this is a Tx channel.
	 */
	boolean_t		is_tx_chan;

	/*
	 * For the connection reaper routine ibd_rc_conn_timeout_call().
	 * "is_used == B_FALSE" indicates this RC channel has not been used for
	 * a long (=ibd_rc_conn_timeout) time.
	 */
	boolean_t		is_used;
	/*
	 * When closing this channel, we need to make sure
	 * "chan->rcq_invoking == 0".
	 */
	uint32_t		rcq_invoking;
} ibd_rc_chan_t;

/*
 * The following functions are defined in "ibd.c".
 * They are also used by "ibd_cm.c"
 */
void ibd_print_warn(ibd_state_t *, char *, ...);
void ibd_unmap_mem(ibd_state_t *, ibd_swqe_t *);
void ibd_queue_work_slot(ibd_state_t *, ibd_req_t *, int);
boolean_t ibd_acache_recycle(ibd_state_t *, ipoib_mac_t *, boolean_t);
void ibd_dec_ref_ace(ibd_state_t *, ibd_ace_t *);
ibd_ace_t *ibd_acache_find(ibd_state_t *, ipoib_mac_t *, boolean_t, int);

/*
 * The following functions are defined in "ibd_cm.c".
 * They are also used in "ibd.c".
 */
void ibd_async_rc_process_too_big(ibd_state_t *, ibd_req_t *);
void ibd_async_rc_close_act_chan(ibd_state_t *, ibd_req_t *);
void ibd_async_rc_recycle_ace(ibd_state_t *, ibd_req_t *);

/* Connection Setup/Close Functions */
ibt_status_t ibd_rc_listen(ibd_state_t *);
void ibd_rc_stop_listen(ibd_state_t *);
ibt_status_t ibd_rc_connect(ibd_state_t *, ibd_ace_t *, ibt_path_info_t *,
    uint64_t);
void ibd_rc_try_connect(ibd_state_t *, ibd_ace_t *,  ibt_path_info_t *);
void ibd_rc_signal_act_close(ibd_state_t *, ibd_ace_t *);
void ibd_rc_signal_ace_recycle(ibd_state_t *, ibd_ace_t *);
int ibd_rc_pas_close(ibd_rc_chan_t *, boolean_t, boolean_t);
void ibd_rc_close_all_chan(ibd_state_t *);
void ibd_rc_conn_timeout_call(void *carg);

/* Receive Functions */
int ibd_rc_init_srq_list(ibd_state_t *);
void ibd_rc_fini_srq_list(ibd_state_t *);
int ibd_rc_repost_srq_free_list(ibd_state_t *);

/* Send Functions */
int ibd_rc_init_tx_largebuf_list(ibd_state_t *);
void ibd_rc_fini_tx_largebuf_list(ibd_state_t *);
ibd_swqe_t *ibd_rc_acquire_swqes(ibd_rc_chan_t *);
void ibd_rc_post_send(ibd_rc_chan_t *, ibd_swqe_t *);
void ibd_rc_drain_scq(ibd_rc_chan_t *, ibt_cq_hdl_t);
void ibd_rc_tx_cleanup(ibd_swqe_t *);

/* Others */
void ibd_rc_get_conf(ibd_state_t *);
int ibd_rc_init_stats(ibd_state_t *);

#endif /* _KERNEL && !_BOOT */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_CLIENTS_IBD_H */
