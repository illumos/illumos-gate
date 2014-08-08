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

#ifndef	_SYS_AGGR_IMPL_H
#define	_SYS_AGGR_IMPL_H

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/mac_ether.h>
#include <sys/mac_provider.h>
#include <sys/mac_client.h>
#include <sys/mac_client_priv.h>
#include <sys/aggr_lacp.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	AGGR_MINOR_CTL	1		/* control interface minor */

/* flags for aggr_grp_modify() */
#define	AGGR_MODIFY_POLICY		0x01
#define	AGGR_MODIFY_MAC			0x02
#define	AGGR_MODIFY_LACP_MODE		0x04
#define	AGGR_MODIFY_LACP_TIMER		0x08

/*
 * Possible value of aggr_rseudo_rx_ring_t.arr_flags. Set when the ring entry
 * in the pseudo RX group is used.
 */
#define	MAC_PSEUDO_RING_INUSE	0x01

typedef struct aggr_unicst_addr_s {
	uint8_t				aua_addr[ETHERADDRL];
	struct aggr_unicst_addr_s	*aua_next;
} aggr_unicst_addr_t;

typedef struct aggr_pseudo_rx_ring_s {
	mac_ring_handle_t	arr_rh;	/* filled in by aggr_fill_ring() */
	struct aggr_port_s	*arr_port;
	mac_ring_handle_t	arr_hw_rh;
	uint_t			arr_flags;
	uint64_t		arr_gen;
} aggr_pseudo_rx_ring_t;

typedef struct aggr_pseudo_rx_group_s {
	struct aggr_grp_s	*arg_grp; /* filled in by aggr_fill_group() */
	mac_group_handle_t	arg_gh;   /* filled in by aggr_fill_group() */
	aggr_unicst_addr_t	*arg_macaddr;
	aggr_pseudo_rx_ring_t	arg_rings[MAX_RINGS_PER_GROUP];
	uint_t			arg_ring_cnt;
} aggr_pseudo_rx_group_t;

typedef struct aggr_pseudo_tx_ring_s {
	mac_ring_handle_t	atr_rh;	/* filled in by aggr_fill_ring() */
	struct aggr_port_s	*atr_port;
	mac_ring_handle_t	atr_hw_rh;
	uint_t			atr_flags;
} aggr_pseudo_tx_ring_t;

typedef struct aggr_pseudo_tx_group_s {
	mac_group_handle_t	atg_gh;	/* filled in by aggr_fill_group() */
	uint_t			atg_ring_cnt;
	aggr_pseudo_tx_ring_t	atg_rings[MAX_RINGS_PER_GROUP];
} aggr_pseudo_tx_group_t;

/*
 * A link aggregation MAC port.
 * Note that lp_next is protected by the lg_lock of the group the
 * port is part of.
 */
typedef struct aggr_port_s {
	struct aggr_port_s *lp_next;
	struct aggr_grp_s *lp_grp;		/* back ptr to group */
	datalink_id_t	lp_linkid;
	uint16_t	lp_portid;
	uint8_t		lp_addr[ETHERADDRL];	/* port MAC address */
	uint32_t	lp_refs;		/* refcount */
	aggr_port_state_t lp_state;
	uint32_t	lp_started : 1,
			lp_tx_enabled : 1,
			lp_collector_enabled : 1,
			lp_promisc_on : 1,
			lp_no_link_update : 1,
			lp_rx_grp_added : 1,
			lp_tx_grp_added : 1,
			lp_closing : 1,
			lp_pad_bits : 24;
	mac_handle_t	lp_mh;
	mac_client_handle_t lp_mch;
	const mac_info_t *lp_mip;
	mac_notify_handle_t lp_mnh;
	uint_t		lp_tx_idx;		/* idx in group's tx array */
	uint64_t	lp_ifspeed;
	link_state_t	lp_link_state;
	link_duplex_t	lp_link_duplex;
	uint64_t	lp_stat[MAC_NSTAT];
	uint64_t	lp_ether_stat[ETHER_NSTAT];
	aggr_lacp_port_t lp_lacp;		/* LACP state */
	lacp_stats_t	lp_lacp_stats;
	uint32_t	lp_margin;
	mac_promisc_handle_t lp_mphp;
	mac_unicast_handle_t lp_mah;

	/* List of non-primary addresses that requires promiscous mode set */
	aggr_unicst_addr_t	*lp_prom_addr;
	/* handle of the underlying HW RX group */
	mac_group_handle_t	lp_hwgh;
	int			lp_tx_ring_cnt;
	/* handles of the underlying HW TX rings */
	mac_ring_handle_t	*lp_tx_rings;
	/*
	 * Handles of the pseudo TX rings. Each of them maps to
	 * corresponding hardware TX ring in lp_tx_rings[]. A
	 * pseudo TX ring is presented to aggr primary mac
	 * client even when underlying NIC has no TX ring.
	 */
	mac_ring_handle_t	*lp_pseudo_tx_rings;
	void			*lp_tx_notify_mh;
} aggr_port_t;

/*
 * A link aggregation group.
 *
 * The following per-group flags are defined:
 *
 * - lg_addr_fixed: set when the MAC address has been explicitely set
 *   when the group was created, or by a m_unicst_set() request.
 *   If this flag is not set, the MAC address of the group will be
 *   set to the first port that is added to the group.
 *
 * - lg_add_set: used only when lg_addr_fixed is not set. Captures whether
 *   the MAC address was initialized according to the members of the group.
 *   When set, the lg_port field points to the port from which the
 *   MAC address was initialized.
 *
 */
typedef struct aggr_grp_s {
	datalink_id_t	lg_linkid;
	uint16_t	lg_key;			/* key (group port number) */
	uint32_t	lg_refs;		/* refcount */
	uint16_t	lg_nports;		/* number of MAC ports */
	uint8_t		lg_addr[ETHERADDRL];	/* group MAC address */
	uint16_t
			lg_closing : 1,
			lg_addr_fixed : 1,	/* fixed MAC address? */
			lg_started : 1,		/* group started? */
			lg_promisc : 1,		/* in promiscuous mode? */
			lg_zcopy : 1,
			lg_vlan : 1,
			lg_force : 1,
			lg_lso : 1,
			lg_pad_bits : 8;
	aggr_port_t	*lg_ports;		/* list of configured ports */
	aggr_port_t	*lg_mac_addr_port;
	mac_handle_t	lg_mh;
	zoneid_t	lg_zoneid;
	uint_t		lg_nattached_ports;
	krwlock_t	lg_tx_lock;
	uint_t		lg_ntx_ports;
	aggr_port_t	**lg_tx_ports;		/* array of tx ports */
	uint_t		lg_tx_ports_size;	/* size of lg_tx_ports */
	uint32_t	lg_tx_policy;		/* outbound policy */
	uint8_t		lg_mac_tx_policy;
	uint64_t	lg_ifspeed;
	link_state_t	lg_link_state;
	link_duplex_t	lg_link_duplex;
	uint64_t	lg_stat[MAC_NSTAT];
	uint64_t	lg_ether_stat[ETHER_NSTAT];
	aggr_lacp_mode_t lg_lacp_mode;		/* off, active, or passive */
	Agg_t		aggr;			/* 802.3ad data */
	uint32_t	lg_hcksum_txflags;
	uint_t		lg_max_sdu;
	uint32_t	lg_margin;
	mac_capab_lso_t lg_cap_lso;

	/*
	 * The following fields are used by the LACP packets processing.
	 * Specifically, as the LACP packets processing is not performance
	 * critical, all LACP packets will be handled by a dedicated thread
	 * instead of in the mac_rx() call. This is to avoid the dead lock
	 * with mac_unicast_remove(), which holding the mac perimeter of the
	 * aggr, and wait for the mr_refcnt of the RX ring to drop to zero.
	 */
	kmutex_t	lg_lacp_lock;
	kcondvar_t	lg_lacp_cv;
	mblk_t		*lg_lacp_head;
	mblk_t		*lg_lacp_tail;
	kthread_t	*lg_lacp_rx_thread;
	boolean_t	lg_lacp_done;

	aggr_pseudo_rx_group_t	lg_rx_group;
	aggr_pseudo_tx_group_t	lg_tx_group;

	kmutex_t	lg_tx_flowctl_lock;
	kcondvar_t	lg_tx_flowctl_cv;
	uint_t		lg_tx_blocked_cnt;
	mac_ring_handle_t	*lg_tx_blocked_rings;
	kthread_t	*lg_tx_notify_thread;
	boolean_t	lg_tx_notify_done;

	/*
	 * The following fields are used by aggr to wait for all the
	 * aggr_port_notify_cb() and aggr_port_timer_thread() to finish
	 * before it calls mac_unregister() when the aggr is deleted.
	 */
	kmutex_t	lg_port_lock;
	kcondvar_t	lg_port_cv;
	int		lg_port_ref;
} aggr_grp_t;

#define	AGGR_GRP_REFHOLD(grp) {			\
	atomic_inc_32(&(grp)->lg_refs);	\
	ASSERT((grp)->lg_refs != 0);		\
}

#define	AGGR_GRP_REFRELE(grp) {					\
	ASSERT((grp)->lg_refs != 0);				\
	membar_exit();						\
	if (atomic_dec_32_nv(&(grp)->lg_refs) == 0)		\
		aggr_grp_free(grp);				\
}

#define	AGGR_PORT_REFHOLD(port) {		\
	atomic_inc_32(&(port)->lp_refs);	\
	ASSERT((port)->lp_refs != 0);		\
}

#define	AGGR_PORT_REFRELE(port) {				\
	ASSERT((port)->lp_refs != 0);				\
	membar_exit();						\
	if (atomic_dec_32_nv(&(port)->lp_refs) == 0)	\
		aggr_port_free(port);				\
}

extern dev_info_t *aggr_dip;
extern int aggr_ioc_init(void);
extern void aggr_ioc_fini(void);

typedef int (*aggr_grp_info_new_grp_fn_t)(void *, datalink_id_t, uint32_t,
    uchar_t *, boolean_t, boolean_t, uint32_t, uint32_t, aggr_lacp_mode_t,
    aggr_lacp_timer_t);
typedef int (*aggr_grp_info_new_port_fn_t)(void *, datalink_id_t, uchar_t *,
    aggr_port_state_t, aggr_lacp_state_t *);

extern void aggr_grp_init(void);
extern void aggr_grp_fini(void);
extern int aggr_grp_create(datalink_id_t, uint32_t, uint_t, laioc_port_t *,
    uint32_t, boolean_t, boolean_t, uchar_t *, aggr_lacp_mode_t,
    aggr_lacp_timer_t, cred_t *);
extern int aggr_grp_delete(datalink_id_t, cred_t *);
extern void aggr_grp_free(aggr_grp_t *);

extern int aggr_grp_info(datalink_id_t, void *, aggr_grp_info_new_grp_fn_t,
    aggr_grp_info_new_port_fn_t, cred_t *);
extern void aggr_grp_notify(aggr_grp_t *, uint32_t);
extern boolean_t aggr_grp_attach_port(aggr_grp_t *, aggr_port_t *);
extern boolean_t aggr_grp_detach_port(aggr_grp_t *, aggr_port_t *);
extern void aggr_grp_port_mac_changed(aggr_grp_t *, aggr_port_t *,
    boolean_t *, boolean_t *);
extern int aggr_grp_add_ports(datalink_id_t, uint_t, boolean_t,
    laioc_port_t *);
extern int aggr_grp_rem_ports(datalink_id_t, uint_t, laioc_port_t *);
extern boolean_t aggr_grp_update_ports_mac(aggr_grp_t *);
extern int aggr_grp_modify(datalink_id_t, uint8_t, uint32_t, boolean_t,
    const uchar_t *, aggr_lacp_mode_t, aggr_lacp_timer_t);
extern void aggr_grp_multicst_port(aggr_port_t *, boolean_t);
extern uint_t aggr_grp_count(void);

extern void aggr_port_init(void);
extern void aggr_port_fini(void);
extern int aggr_port_create(aggr_grp_t *, const datalink_id_t, boolean_t,
    aggr_port_t **);
extern void aggr_port_delete(aggr_port_t *);
extern void aggr_port_free(aggr_port_t *);
extern int aggr_port_start(aggr_port_t *);
extern void aggr_port_stop(aggr_port_t *);
extern int aggr_port_promisc(aggr_port_t *, boolean_t);
extern int aggr_port_unicst(aggr_port_t *);
extern int aggr_port_multicst(void *, boolean_t, const uint8_t *);
extern uint64_t aggr_port_stat(aggr_port_t *, uint_t);
extern boolean_t aggr_port_notify_link(aggr_grp_t *, aggr_port_t *);
extern void aggr_port_init_callbacks(aggr_port_t *);

extern void aggr_recv_cb(void *, mac_resource_handle_t, mblk_t *, boolean_t);

extern void aggr_tx_ring_update(void *, uintptr_t);
extern void aggr_tx_notify_thread(void *);
extern void aggr_send_port_enable(aggr_port_t *);
extern void aggr_send_port_disable(aggr_port_t *);
extern void aggr_send_update_policy(aggr_grp_t *, uint32_t);

extern void aggr_lacp_init(void);
extern void aggr_lacp_fini(void);
extern void aggr_lacp_init_port(aggr_port_t *);
extern void aggr_lacp_init_grp(aggr_grp_t *);
extern void aggr_lacp_set_mode(aggr_grp_t *, aggr_lacp_mode_t,
    aggr_lacp_timer_t);
extern void aggr_lacp_update_mode(aggr_grp_t *, aggr_lacp_mode_t);
extern void aggr_lacp_update_timer(aggr_grp_t *, aggr_lacp_timer_t);
extern void aggr_lacp_rx_enqueue(aggr_port_t *, mblk_t *);
extern void aggr_lacp_port_attached(aggr_port_t *);
extern void aggr_lacp_port_detached(aggr_port_t *);
extern void aggr_port_lacp_set_mode(aggr_grp_t *, aggr_port_t *);

extern void aggr_lacp_rx_thread(void *);
extern void aggr_recv_lacp(aggr_port_t *, mac_resource_handle_t, mblk_t *);

extern void aggr_grp_port_hold(aggr_port_t *);
extern void aggr_grp_port_rele(aggr_port_t *);
extern void aggr_grp_port_wait(aggr_grp_t *);

extern int aggr_port_addmac(aggr_port_t *, const uint8_t *);
extern void aggr_port_remmac(aggr_port_t *, const uint8_t *);

extern mblk_t *aggr_ring_tx(void *, mblk_t *);
extern mblk_t *aggr_find_tx_ring(void *, mblk_t *,
    uintptr_t, mac_ring_handle_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AGGR_IMPL_H */
