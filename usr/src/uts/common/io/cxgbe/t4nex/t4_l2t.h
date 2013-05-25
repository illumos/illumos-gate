/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2010-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGBE_T4L2T_H
#define	__CXGBE_T4L2T_H

#include <inet/ip.h>
#include <inet/ip2mac.h>

enum { L2T_SIZE = 4096 };	/* # of L2T entries */

#define	MBUF_EQ(mp)	(*((void **)(&(mp)->b_datap->db_cksumstuff)))

/*
 * Each L2T entry plays multiple roles.  First of all, it keeps state for the
 * corresponding entry of the HW L2 table and maintains a queue of offload
 * packets awaiting address resolution.  Second, it is a node of a hash table
 * chain, where the nodes of the chain are linked together through their next
 * pointer.  Finally, each node is a bucket of a hash table, pointing to the
 * first element in its chain through its first pointer.
 */
struct l2t_entry {
	uint16_t state;			/* entry state */
	uint16_t idx;			/* entry index */
	uint32_t addr[4];		/* next hop IP or IPv6 address */
	in_addr_t in_addr;
	struct adapter *sc;		/* associated adapter */
	uint16_t smt_idx;		/* SMT index */
	uint16_t vlan;			/* VLAN TCI (id: 0-11, prio: 13-15) */
	int ifindex;			/* interface index */
	struct l2t_entry *first;	/* start of hash chain */
	struct l2t_entry *next;		/* next l2t_entry on chain */
	mblk_t *arpq_head;	/* list of mblks awaiting resolution */
	mblk_t *arpq_tail;
	kmutex_t lock;
	volatile uint_t refcnt;		/* entry reference count */
	uint16_t hash;			/* hash bucket the entry is on */
	uint8_t v6;			/* whether entry is for IPv6 */
	uint8_t lport;			/* associated offload logical port */
	uint8_t dmac[ETHERADDRL];	/* next hop's MAC address */
};

int t4_free_l2t(struct l2t_data *d);
void t4_l2t_release(struct l2t_entry *e);
int  do_l2t_write_rpl(struct sge_iq *iq, const struct rss_header *rss,
    mblk_t *m);

#ifndef TCP_OFFLOAD_DISABLE
struct l2t_entry *t4_l2t_get(struct port_info *pi, conn_t *connp);
int t4_l2t_send(struct adapter *sc, mblk_t *m, struct l2t_entry *e);
void t4_l2t_update(ip2mac_t *ip2macp, void* arg);
#endif

#endif /* __CXGBE_T4L2T_H */
