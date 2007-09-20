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

#ifndef	_SYS_AGGR_IMPL_H
#define	_SYS_AGGR_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
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
 * A link aggregation MAC port.
 * Note that lp_next is protected by the lg_lock of the group the
 * port is part of.
 */
typedef struct aggr_port_s {
	struct aggr_port_s *lp_next;
	struct aggr_grp_s *lp_grp;		/* back ptr to group */
	char		lp_devname[MAXNAMELEN + 1];
	uint16_t	lp_portid;
	uint8_t		lp_addr[ETHERADDRL];	/* port MAC address */
	uint32_t	lp_refs;		/* refcount */
	aggr_port_state_t lp_state;
	uint32_t	lp_started : 1,
			lp_tx_enabled : 1,
			lp_collector_enabled : 1,
			lp_promisc_on : 1,
			lp_pad_bits : 28;
	uint32_t	lp_closing;
	mac_handle_t	lp_mh;
	const mac_info_t *lp_mip;
	mac_notify_handle_t lp_mnh;
	mac_rx_handle_t	lp_mrh;
	krwlock_t	lp_lock;
	uint_t		lp_tx_idx;		/* idx in group's tx array */
	uint64_t	lp_ifspeed;
	link_state_t	lp_link_state;
	link_duplex_t	lp_link_duplex;
	uint64_t	lp_stat[MAC_NSTAT];
	uint64_t	lp_ether_stat[ETHER_NSTAT];
	aggr_lacp_port_t lp_lacp;		/* LACP state */
	lacp_stats_t	lp_lacp_stats;
	const mac_txinfo_t *lp_txinfo;
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
	krwlock_t	lg_lock;
	uint16_t	lg_key;			/* key (group port number) */
	uint32_t	lg_refs;		/* refcount */
	uint16_t	lg_nports;		/* number of MAC ports */
	uint8_t		lg_addr[ETHERADDRL];	/* group MAC address */
	uint16_t
			lg_closing : 1,
			lg_addr_fixed : 1,	/* fixed MAC address? */
			lg_started : 1,		/* group started? */
			lg_promisc : 1,		/* in promiscuous mode? */
			lg_gldv3_polling : 1,
			lg_pad_bits : 11;
	aggr_port_t	*lg_ports;		/* list of configured ports */
	aggr_port_t	*lg_mac_addr_port;
	mac_handle_t	lg_mh;
	uint_t		lg_rx_resources;
	uint_t		lg_nattached_ports;
	uint_t		lg_ntx_ports;
	aggr_port_t	**lg_tx_ports;		/* array of tx ports */
	uint_t		lg_tx_ports_size;	/* size of lg_tx_ports */
	uint32_t	lg_tx_policy;		/* outbound policy */
	uint64_t	lg_ifspeed;
	link_state_t	lg_link_state;
	link_duplex_t	lg_link_duplex;
	uint64_t	lg_stat[MAC_NSTAT];
	uint64_t	lg_ether_stat[ETHER_NSTAT];
	aggr_lacp_mode_t lg_lacp_mode;		/* off, active, or passive */
	Agg_t		aggr;			/* 802.3ad data */
	uint32_t	lg_hcksum_txflags;
	uint_t		lg_max_sdu;
} aggr_grp_t;

#define	AGGR_LACP_LOCK(grp)	mutex_enter(&(grp)->aggr.gl_lock);
#define	AGGR_LACP_UNLOCK(grp)	mutex_exit(&(grp)->aggr.gl_lock);
#define	AGGR_LACP_LOCK_HELD(grp) MUTEX_HELD(&(grp)->aggr.gl_lock)

#define	AGGR_GRP_REFHOLD(grp) {			\
	atomic_add_32(&(grp)->lg_refs, 1);	\
	ASSERT((grp)->lg_refs != 0);		\
}

#define	AGGR_GRP_REFRELE(grp) {					\
	ASSERT((grp)->lg_refs != 0);				\
	membar_exit();						\
	if (atomic_add_32_nv(&(grp)->lg_refs, -1) == 0)		\
		aggr_grp_free(grp);				\
}

#define	AGGR_PORT_REFHOLD(port) {		\
	atomic_add_32(&(port)->lp_refs, 1);	\
	ASSERT((port)->lp_refs != 0);		\
}

#define	AGGR_PORT_REFRELE(port) {				\
	ASSERT((port)->lp_refs != 0);				\
	membar_exit();						\
	if (atomic_add_32_nv(&(port)->lp_refs, -1) == 0)	\
		aggr_port_free(port);				\
}

extern dev_info_t *aggr_dip;
extern void aggr_ioctl(queue_t *, mblk_t *);

typedef int (*aggr_grp_info_new_grp_fn_t)(void *, uint32_t, uchar_t *,
    boolean_t, uint32_t, uint32_t, aggr_lacp_mode_t, aggr_lacp_timer_t);
typedef int (*aggr_grp_info_new_port_fn_t)(void *, char *, uchar_t *,
    aggr_port_state_t, aggr_lacp_state_t *);

extern void aggr_grp_init(void);
extern void aggr_grp_fini(void);
extern int aggr_grp_create(uint32_t, uint_t, laioc_port_t *, uint32_t,
    boolean_t, uchar_t *, aggr_lacp_mode_t, aggr_lacp_timer_t);
extern int aggr_grp_delete(uint32_t);
extern void aggr_grp_free(aggr_grp_t *);

extern int aggr_grp_info(uint_t *, uint32_t, void *,
    aggr_grp_info_new_grp_fn_t, aggr_grp_info_new_port_fn_t);
extern void aggr_grp_notify(aggr_grp_t *, uint32_t);
extern boolean_t aggr_grp_attach_port(aggr_grp_t *, aggr_port_t *);
extern boolean_t aggr_grp_detach_port(aggr_grp_t *, aggr_port_t *);
extern void aggr_grp_port_mac_changed(aggr_grp_t *, aggr_port_t *,
    boolean_t *, boolean_t *);
extern int aggr_grp_add_ports(uint32_t, uint_t, laioc_port_t *);
extern int aggr_grp_rem_ports(uint32_t, uint_t, laioc_port_t *);
extern boolean_t aggr_grp_update_ports_mac(aggr_grp_t *);
extern int aggr_grp_modify(uint32_t, aggr_grp_t *, uint8_t, uint32_t,
    boolean_t, const uchar_t *, aggr_lacp_mode_t, aggr_lacp_timer_t);
extern void aggr_grp_multicst_port(aggr_port_t *, boolean_t);
extern uint_t aggr_grp_count(void);

extern void aggr_port_init(void);
extern void aggr_port_fini(void);
extern int aggr_port_create(const char *, aggr_port_t **);
extern void aggr_port_delete(aggr_port_t *);
extern void aggr_port_free(aggr_port_t *);
extern int aggr_port_start(aggr_port_t *);
extern void aggr_port_stop(aggr_port_t *);
extern int aggr_port_promisc(aggr_port_t *, boolean_t);
extern int aggr_port_unicst(aggr_port_t *, uint8_t *);
extern int aggr_port_multicst(void *, boolean_t, const uint8_t *);
extern uint64_t aggr_port_stat(aggr_port_t *, uint_t);
extern boolean_t aggr_port_notify_link(aggr_grp_t *, aggr_port_t *, boolean_t);
extern void aggr_port_init_callbacks(aggr_port_t *);

extern void aggr_recv_cb(void *, mac_resource_handle_t, mblk_t *);

extern mblk_t *aggr_m_tx(void *, mblk_t *);
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
extern void aggr_lacp_rx(aggr_port_t *, mblk_t *);
extern void aggr_lacp_port_attached(aggr_port_t *);
extern void aggr_lacp_port_detached(aggr_port_t *);
extern void aggr_lacp_policy_changed(aggr_grp_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AGGR_IMPL_H */
