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

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/atomic.h>
#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <sys/strsubr.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <inet/ip.h>
#include <inet/ipclassifier.h>
#include <inet/tcp.h>

#include "common/common.h"
#include "common/t4_msg.h"
#include "common/t4_regs.h"
#include "common/t4_regs_values.h"
#include "t4_l2t.h"

/* identifies sync vs async L2T_WRITE_REQs */
#define	S_SYNC_WR	12
#define	V_SYNC_WR(x)	((x) << S_SYNC_WR)
#define	F_SYNC_WR	V_SYNC_WR(1)
#define	VLAN_NONE	0xfff

/*
 * jhash.h: Jenkins hash support.
 *
 * Copyright (C) 1996 Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup2.c, by Bob Jenkins, December 1996, Public Domain.
 * hash(), hash2(), hash3, and mix() are externally useful functions.
 * Routines to test the hash are included if SELF_TEST is defined.
 * You can use this free for any purpose.  It has no warranty.
 */

/* NOTE: Arguments are modified. */
#define	__jhash_mix(a, b, c) \
{ \
	a -= b; a -= c; a ^= (c>>13); \
	b -= c; b -= a; b ^= (a<<8); \
	c -= a; c -= b; c ^= (b>>13); \
	a -= b; a -= c; a ^= (c>>12);  \
	b -= c; b -= a; b ^= (a<<16); \
	c -= a; c -= b; c ^= (b>>5); \
	a -= b; a -= c; a ^= (c>>3);  \
	b -= c; b -= a; b ^= (a<<10); \
	c -= a; c -= b; c ^= (b>>15); \
}

/* The golden ration: an arbitrary value */
#define	JHASH_GOLDEN_RATIO	0x9e3779b9

/*
 * A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 *
 * NOTE: In partilar the "c += length; __jhash_mix(a,b,c);" normally
 *	 done at the end is not done here.
 */
static inline u32
jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
	a += JHASH_GOLDEN_RATIO;
	b += JHASH_GOLDEN_RATIO;
	c += initval;

	__jhash_mix(a, b, c);

	return (c);
}

static inline u32
jhash_2words(u32 a, u32 b, u32 initval)
{
	return (jhash_3words(a, b, 0, initval));
}

#ifndef container_of
#define	container_of(p, s, f) ((s *)(((uint8_t *)(p)) - offsetof(s, f)))
#endif

#if defined(__GNUC__)
#define	likely(x)	__builtin_expect((x), 1)
#define	unlikely(x)	__builtin_expect((x), 0)
#else
#define	likely(x)	(x)
#define	unlikely(x)	(x)
#endif /* defined(__GNUC__) */

enum {
	L2T_STATE_VALID,	/* entry is up to date */
	L2T_STATE_STALE,	/* entry may be used but needs revalidation */
	L2T_STATE_RESOLVING,	/* entry needs address resolution */
	L2T_STATE_SYNC_WRITE,	/* synchronous write of entry underway */

	/* when state is one of the below the entry is not hashed */
	L2T_STATE_SWITCHING,	/* entry is being used by a switching filter */
	L2T_STATE_UNUSED	/* entry not in use */
};

struct l2t_data {
	krwlock_t lock;
	volatile uint_t nfree;	 /* number of free entries */
	struct l2t_entry *rover; /* starting point for next allocation */
	struct l2t_entry l2tab[L2T_SIZE];
};

#define	VLAN_NONE	0xfff
#define	SA(x)		((struct sockaddr *)(x))
#define	SIN(x)		((struct sockaddr_in *)(x))
#define	SINADDR(x)	(SIN(x)->sin_addr.s_addr)
#define	atomic_read(x) atomic_add_int_nv(x, 0)
/*
 * Allocate a free L2T entry.
 * Must be called with l2t_data.lockatomic_load_acq_int held.
 */
static struct l2t_entry *
alloc_l2e(struct l2t_data *d)
{
	struct l2t_entry *end, *e, **p;

	ASSERT(rw_write_held(&d->lock));

	if (!atomic_read(&d->nfree))
		return (NULL);

	/* there's definitely a free entry */
	for (e = d->rover, end = &d->l2tab[L2T_SIZE]; e != end; ++e)
		if (atomic_read(&e->refcnt) == 0)
			goto found;

	for (e = d->l2tab; atomic_read(&e->refcnt); ++e)
		/* */;
found:
	d->rover = e + 1;
	atomic_dec_uint(&d->nfree);

	/*
	 * The entry we found may be an inactive entry that is
	 * presently in the hash table.  We need to remove it.
	 */
	if (e->state < L2T_STATE_SWITCHING) {
		for (p = &d->l2tab[e->hash].first; *p; p = &(*p)->next) {
			if (*p == e) {
				*p = e->next;
				e->next = NULL;
				break;
			}
		}
	}

	e->state = L2T_STATE_UNUSED;
	return (e);
}

/*
 * Write an L2T entry.  Must be called with the entry locked.
 * The write may be synchronous or asynchronous.
 */
static int
write_l2e(adapter_t *sc, struct l2t_entry *e, int sync)
{
	mblk_t *m;
	struct cpl_l2t_write_req *req;

	ASSERT(MUTEX_HELD(&e->lock));

	if ((m = allocb(sizeof (*req), BPRI_HI)) == NULL)
		return (ENOMEM);

	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	req = (struct cpl_l2t_write_req *)m->b_wptr;

	/* LINTED: E_CONSTANT_CONDITION */
	INIT_TP_WR(req, 0);
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_L2T_WRITE_REQ, e->idx |
	    V_SYNC_WR(sync) | V_TID_QID(sc->sge.fwq.abs_id)));
	req->params = htons(V_L2T_W_PORT(e->lport) | V_L2T_W_NOREPLY(!sync));
	req->l2t_idx = htons(e->idx);
	req->vlan = htons(e->vlan);
	(void) memcpy(req->dst_mac, e->dmac, sizeof (req->dst_mac));

	m->b_wptr += sizeof (*req);

	(void) t4_mgmt_tx(sc, m);

	if (sync && e->state != L2T_STATE_SWITCHING)
		e->state = L2T_STATE_SYNC_WRITE;

	return (0);
}

struct l2t_data *
t4_init_l2t(struct adapter *sc)
{
	int i;
	struct l2t_data *d;

	d = kmem_zalloc(sizeof (*d), KM_SLEEP);

	d->rover = d->l2tab;
	(void) atomic_swap_uint(&d->nfree, L2T_SIZE);
	rw_init(&d->lock, NULL, RW_DRIVER, NULL);

	for (i = 0; i < L2T_SIZE; i++) {
		/* LINTED: E_ASSIGN_NARROW_CONV */
		d->l2tab[i].idx = i;
		d->l2tab[i].state = L2T_STATE_UNUSED;
		mutex_init(&d->l2tab[i].lock, NULL, MUTEX_DRIVER, NULL);
		(void) atomic_swap_uint(&d->l2tab[i].refcnt, 0);
	}

	(void) t4_register_cpl_handler(sc, CPL_L2T_WRITE_RPL, do_l2t_write_rpl);

	return (d);
}

int
t4_free_l2t(struct l2t_data *d)
{
	int i;

	for (i = 0; i < L2T_SIZE; i++)
		mutex_destroy(&d->l2tab[i].lock);
	rw_destroy(&d->lock);
	kmem_free(d, sizeof (*d));

	return (0);
}

#ifndef TCP_OFFLOAD_DISABLE
static inline void
l2t_hold(struct l2t_data *d, struct l2t_entry *e)
{
	if (atomic_inc_uint_nv(&e->refcnt) == 1)  /* 0 -> 1 transition */
		atomic_dec_uint(&d->nfree);
}

/*
 * To avoid having to check address families we do not allow v4 and v6
 * neighbors to be on the same hash chain.  We keep v4 entries in the first
 * half of available hash buckets and v6 in the second.
 */
enum {
	L2T_SZ_HALF = L2T_SIZE / 2,
	L2T_HASH_MASK = L2T_SZ_HALF - 1
};

static inline unsigned int
arp_hash(const uint32_t *key, int ifindex)
{
	return (jhash_2words(*key, ifindex, 0) & L2T_HASH_MASK);
}

static inline unsigned int
ipv6_hash(const uint32_t *key, int ifindex)
{
	uint32_t xor = key[0] ^ key[1] ^ key[2] ^ key[3];

	return (L2T_SZ_HALF + (jhash_2words(xor, ifindex, 0) & L2T_HASH_MASK));
}

static inline unsigned int
addr_hash(const uint32_t *addr, int addr_len, int ifindex)
{
	return (addr_len == 4 ? arp_hash(addr, ifindex) :
	    ipv6_hash(addr, ifindex));
}

/*
 * Checks if an L2T entry is for the given IP/IPv6 address.  It does not check
 * whether the L2T entry and the address are of the same address family.
 * Callers ensure an address is only checked against L2T entries of the same
 * family, something made trivial by the separation of IP and IPv6 hash chains
 * mentioned above.  Returns 0 if there's a match,
 */
static inline int
addreq(const struct l2t_entry *e, const uint32_t *addr)
{
	if (e->v6 != 0)
		return ((e->addr[0] ^ addr[0]) | (e->addr[1] ^ addr[1]) |
		    (e->addr[2] ^ addr[2]) | (e->addr[3] ^ addr[3]));
	return (e->addr[0] ^ addr[0]);
}

/*
 * Add a packet to an L2T entry's queue of packets awaiting resolution.
 * Must be called with the entry's lock held.
 */
static inline void
arpq_enqueue(struct l2t_entry *e, mblk_t *m)
{
	ASSERT(MUTEX_HELD(&e->lock));

	ASSERT(m->b_next == NULL);
	if (e->arpq_head != NULL)
		e->arpq_tail->b_next = m;
	else
		e->arpq_head = m;
	e->arpq_tail = m;
}

static inline void
send_pending(struct adapter *sc, struct l2t_entry *e)
{
	mblk_t *m, *next;

	ASSERT(MUTEX_HELD(&e->lock));

	for (m = e->arpq_head; m; m = next) {
		next = m->b_next;
		m->b_next = NULL;
		(void) t4_wrq_tx(sc, MBUF_EQ(m), m);
	}
	e->arpq_head = e->arpq_tail = NULL;
}

int
t4_l2t_send(struct adapter *sc, mblk_t *m, struct l2t_entry *e)
{
	sin_t *sin;
	ip2mac_t ip2m;

	if (e->v6 != 0)
		ASSERT(0);
again:
	switch (e->state) {
	case L2T_STATE_STALE:	/* entry is stale, kick off revalidation */

	/* Fall through */
	case L2T_STATE_VALID:	/* fast-path, send the packet on */
		(void) t4_wrq_tx(sc, MBUF_EQ(m), m);
		return (0);

	case L2T_STATE_RESOLVING:
	case L2T_STATE_SYNC_WRITE:
		mutex_enter(&e->lock);
		if (e->state != L2T_STATE_SYNC_WRITE &&
		    e->state != L2T_STATE_RESOLVING) {
			/* state changed by the time we got here */
			mutex_exit(&e->lock);
			goto again;
		}
		arpq_enqueue(e, m);
		mutex_exit(&e->lock);

		bzero(&ip2m, sizeof (ip2m));
		sin = (sin_t *)&ip2m.ip2mac_pa;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = e->in_addr;
		ip2m.ip2mac_ifindex = e->ifindex;

		if (e->state == L2T_STATE_RESOLVING) {
			(void) ip2mac(IP2MAC_RESOLVE, &ip2m, t4_l2t_update, e,
			    0);
			if (ip2m.ip2mac_err == EINPROGRESS)
				ASSERT(0);
			else if (ip2m.ip2mac_err == 0)
				t4_l2t_update(&ip2m, e);
			else
				ASSERT(0);
		}
	}

	return (0);
}

/*
 * Called when an L2T entry has no more users.  The entry is left in the hash
 * table since it is likely to be reused but we also bump nfree to indicate
 * that the entry can be reallocated for a different neighbor.  We also drop
 * the existing neighbor reference in case the neighbor is going away and is
 * waiting on our reference.
 *
 * Because entries can be reallocated to other neighbors once their ref count
 * drops to 0 we need to take the entry's lock to avoid races with a new
 * incarnation.
 */
static void
t4_l2e_free(struct l2t_entry *e)
{
	struct l2t_data *d;

	mutex_enter(&e->lock);
	/* LINTED: E_NOP_IF_STMT */
	if (atomic_read(&e->refcnt) == 0) {  /* hasn't been recycled */
		/*
		 * Don't need to worry about the arpq, an L2T entry can't be
		 * released if any packets are waiting for resolution as we
		 * need to be able to communicate with the device to close a
		 * connection.
		 */
	}
	mutex_exit(&e->lock);

	d = container_of(e, struct l2t_data, l2tab[e->idx]);
	atomic_inc_uint(&d->nfree);

}

void
t4_l2t_release(struct l2t_entry *e)
{
	if (atomic_dec_uint_nv(&e->refcnt) == 0)
		t4_l2e_free(e);
}

/* ARGSUSED */
int
do_l2t_write_rpl(struct sge_iq *iq, const struct rss_header *rss, mblk_t *m)
{
	struct adapter *sc = iq->adapter;
	const struct cpl_l2t_write_rpl *rpl = (const void *)(rss + 1);
	unsigned int tid = GET_TID(rpl);
	unsigned int idx = tid & (L2T_SIZE - 1);

	if (likely(rpl->status != CPL_ERR_NONE)) {
		cxgb_printf(sc->dip, CE_WARN,
		    "Unexpected L2T_WRITE_RPL status %u for entry %u",
		    rpl->status, idx);
		return (-EINVAL);
	}

	if (tid & F_SYNC_WR) {
		struct l2t_entry *e = &sc->l2t->l2tab[idx];

		mutex_enter(&e->lock);
		if (e->state != L2T_STATE_SWITCHING) {
			send_pending(sc, e);
			e->state = L2T_STATE_VALID;
		}
		mutex_exit(&e->lock);
	}

	return (0);
}

/*
 * The TOE wants an L2 table entry that it can use to reach the next hop over
 * the specified port.  Produce such an entry - create one if needed.
 *
 * Note that the ifnet could be a pseudo-device like if_vlan, if_lagg, etc. on
 * top of the real cxgbe interface.
 */
struct l2t_entry *
t4_l2t_get(struct port_info *pi, conn_t *connp)
{
	struct l2t_entry *e;
	struct l2t_data *d = pi->adapter->l2t;
	int addr_len;
	uint32_t *addr;
	int hash;
	int index = \
	    connp->conn_ixa->ixa_ire->ire_ill->ill_phyint->phyint_ifindex;
	unsigned int smt_idx = pi->port_id;
	addr = (uint32_t *)&connp->conn_faddr_v4;
	addr_len  = sizeof (connp->conn_faddr_v4);

	hash = addr_hash(addr, addr_len, index);

	rw_enter(&d->lock, RW_WRITER);
	for (e = d->l2tab[hash].first; e; e = e->next) {
		if (!addreq(e, addr) && e->smt_idx == smt_idx) {
			l2t_hold(d, e);
			goto done;
		}
	}

	/* Need to allocate a new entry */
	e = alloc_l2e(d);
	if (e != NULL) {
		mutex_enter(&e->lock);	/* avoid race with t4_l2t_free */
		e->state = L2T_STATE_RESOLVING;
		(void) memcpy(e->addr, addr, addr_len);
		e->in_addr = connp->conn_faddr_v4;
		e->ifindex = index;
		/* LINTED: E_ASSIGN_NARROW_CONV */
		e->smt_idx = smt_idx;
		/* LINTED: E_ASSIGN_NARROW_CONV */
		e->hash = hash;
		e->lport = pi->lport;
		e->arpq_head = e->arpq_tail = NULL;
		e->v6 = (addr_len == 16);
		e->sc = pi->adapter;
		(void) atomic_swap_uint(&e->refcnt, 1);
		e->vlan = VLAN_NONE;
		e->next = d->l2tab[hash].first;
		d->l2tab[hash].first = e;
		mutex_exit(&e->lock);
	} else {
		ASSERT(0);
	}

done:
	rw_exit(&d->lock);
	return (e);
}

/*
 * Called when the host's neighbor layer makes a change to some entry that is
 * loaded into the HW L2 table.
 */
void
t4_l2t_update(ip2mac_t *ip2macp, void *arg)
{
	struct l2t_entry *e = (struct l2t_entry *)arg;
	struct adapter *sc = e->sc;
	uchar_t *cp;

	if (ip2macp->ip2mac_err != 0) {
		ASSERT(0); /* Don't know what to do. Needs to be investigated */
	}

	mutex_enter(&e->lock);
	if (atomic_read(&e->refcnt) != 0)
		goto found;
	e->state = L2T_STATE_STALE;
	mutex_exit(&e->lock);

	/* The TOE has no interest in this LLE */
	return;

found:
	if (atomic_read(&e->refcnt) != 0) {

		/* Entry is referenced by at least 1 offloaded connection. */

		cp = (uchar_t *)LLADDR(&ip2macp->ip2mac_ha);
		bcopy(cp, e->dmac, 6);
		(void) write_l2e(sc, e, 1);
		e->state = L2T_STATE_VALID;

	}
	mutex_exit(&e->lock);
}
#endif
