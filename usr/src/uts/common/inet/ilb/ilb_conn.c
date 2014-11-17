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

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/time.h>
#include <sys/taskq.h>
#include <sys/cmn_err.h>
#include <sys/sdt.h>
#include <sys/atomic.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>
#include <inet/udp_impl.h>
#include <inet/ilb.h>

#include "ilb_stack.h"
#include "ilb_impl.h"
#include "ilb_conn.h"
#include "ilb_nat.h"

/*
 * Timer struct for ilb_conn_t and ilb_sticky_t garbage collection
 *
 * start: starting index into the hash table to do gc
 * end: ending index into the hash table to do gc
 * ilbs: pointer to the ilb_stack_t of the IP stack
 * tid_lock: mutex to protect the timer id.
 * tid: timer id of the timer
 */
typedef struct ilb_timer_s {
	uint32_t	start;
	uint32_t	end;
	ilb_stack_t	*ilbs;
	kmutex_t	tid_lock;
	timeout_id_t	tid;
} ilb_timer_t;

/* Hash macro for finding the index to the conn hash table */
#define	ILB_CONN_HASH(saddr, sport, daddr, dport, hash_size)	\
	(((*((saddr) + 3) ^ *((daddr) + 3)) * 50653 +		\
	(*((saddr) + 2) ^ *((daddr) + 2)) * 1369 +		\
	(*((saddr) + 1) ^ *((daddr) + 1)) * 37 +		\
	(*(saddr) ^ *(daddr)) + (sport) * 37 + (dport)) &	\
	((hash_size) - 1))

/* Kmem cache for the conn hash entry */
static struct kmem_cache *ilb_conn_cache = NULL;

/*
 * There are 60 timers running to do conn cache garbage collection.  Each
 * gc thread is responsible for 1/60 of the conn hash table.
 */
static int ilb_conn_timer_size = 60;

/* Each of the above gc timers wake up every 15s to do the gc. */
static int ilb_conn_cache_timeout = 15;

#define	ILB_STICKY_HASH(saddr, rule, hash_size)			\
	(((*((saddr) + 3) ^ ((rule) >> 24)) * 29791 +		\
	(*((saddr) + 2) ^ ((rule) >> 16)) * 961 +		\
	(*((saddr) + 1) ^ ((rule) >> 8)) * 31 +			\
	(*(saddr) ^ (rule))) & ((hash_size) - 1))

static struct kmem_cache *ilb_sticky_cache = NULL;

/*
 * There are 60 timers running to do sticky cache garbage collection.  Each
 * gc thread is responsible for 1/60 of the sticky hash table.
 */
static int ilb_sticky_timer_size = 60;

/* Each of the above gc timers wake up every 15s to do the gc. */
static int ilb_sticky_timeout = 15;

#define	ILB_STICKY_REFRELE(s)			\
{						\
	mutex_enter(&(s)->hash->sticky_lock);	\
	(s)->refcnt--;				\
	(s)->atime = ddi_get_lbolt64();		\
	mutex_exit(&s->hash->sticky_lock);	\
}


static void
ilb_conn_cache_init(void)
{
	ilb_conn_cache = kmem_cache_create("ilb_conn_cache",
	    sizeof (ilb_conn_t), 0, NULL, NULL, NULL, NULL, NULL,
	    ilb_kmem_flags);
}

void
ilb_conn_cache_fini(void)
{
	if (ilb_conn_cache != NULL) {
		kmem_cache_destroy(ilb_conn_cache);
		ilb_conn_cache = NULL;
	}
}

static void
ilb_conn_remove_common(ilb_conn_t *connp, boolean_t c2s)
{
	ilb_conn_hash_t *hash;
	ilb_conn_t **next, **prev;
	ilb_conn_t **next_prev, **prev_next;

	if (c2s) {
		hash = connp->conn_c2s_hash;
		ASSERT(MUTEX_HELD(&hash->ilb_conn_hash_lock));
		next = &connp->conn_c2s_next;
		prev = &connp->conn_c2s_prev;
		if (*next != NULL)
			next_prev = &(*next)->conn_c2s_prev;
		if (*prev != NULL)
			prev_next = &(*prev)->conn_c2s_next;
	} else {
		hash = connp->conn_s2c_hash;
		ASSERT(MUTEX_HELD(&hash->ilb_conn_hash_lock));
		next = &connp->conn_s2c_next;
		prev = &connp->conn_s2c_prev;
		if (*next != NULL)
			next_prev = &(*next)->conn_s2c_prev;
		if (*prev != NULL)
			prev_next = &(*prev)->conn_s2c_next;
	}

	if (hash->ilb_connp == connp) {
		hash->ilb_connp = *next;
		if (*next != NULL)
			*next_prev = NULL;
	} else {
		if (*prev != NULL)
			*prev_next = *next;
		if (*next != NULL)
			*next_prev = *prev;
	}
	ASSERT(hash->ilb_conn_cnt > 0);
	hash->ilb_conn_cnt--;

	*next = NULL;
	*prev = NULL;
}

static void
ilb_conn_remove(ilb_conn_t *connp)
{
	ASSERT(MUTEX_HELD(&connp->conn_c2s_hash->ilb_conn_hash_lock));
	ilb_conn_remove_common(connp, B_TRUE);
	ASSERT(MUTEX_HELD(&connp->conn_s2c_hash->ilb_conn_hash_lock));
	ilb_conn_remove_common(connp, B_FALSE);

	if (connp->conn_rule_cache.topo == ILB_TOPO_IMPL_NAT) {
		in_port_t port;

		port = ntohs(connp->conn_rule_cache.info.nat_sport);
		vmem_free(connp->conn_rule_cache.info.src_ent->nse_port_arena,
		    (void *)(uintptr_t)port, 1);
	}

	if (connp->conn_sticky != NULL)
		ILB_STICKY_REFRELE(connp->conn_sticky);
	ILB_SERVER_REFRELE(connp->conn_server);
	kmem_cache_free(ilb_conn_cache, connp);
}

/*
 * Routine to do periodic garbage collection of conn hash entries.  When
 * a conn hash timer fires, it dispatches a taskq to call this function
 * to do the gc.  Note that each taskq is responisble for a portion of
 * the table.  The portion is stored in timer->start, timer->end.
 */
static void
ilb_conn_cleanup(void *arg)
{
	ilb_timer_t *timer = (ilb_timer_t *)arg;
	uint32_t i;
	ilb_stack_t *ilbs;
	ilb_conn_hash_t *c2s_hash, *s2c_hash;
	ilb_conn_t *connp, *nxt_connp;
	int64_t now;
	int64_t expiry;
	boolean_t die_now;

	ilbs = timer->ilbs;
	c2s_hash = ilbs->ilbs_c2s_conn_hash;
	ASSERT(c2s_hash != NULL);

	now = ddi_get_lbolt64();
	for (i = timer->start; i < timer->end; i++) {
		mutex_enter(&c2s_hash[i].ilb_conn_hash_lock);
		if ((connp = c2s_hash[i].ilb_connp) == NULL) {
			ASSERT(c2s_hash[i].ilb_conn_cnt == 0);
			mutex_exit(&c2s_hash[i].ilb_conn_hash_lock);
			continue;
		}
		do {
			ASSERT(c2s_hash[i].ilb_conn_cnt > 0);
			ASSERT(connp->conn_c2s_hash == &c2s_hash[i]);
			nxt_connp = connp->conn_c2s_next;
			expiry = now - SEC_TO_TICK(connp->conn_expiry);
			if (connp->conn_server->iser_die_time != 0 &&
			    connp->conn_server->iser_die_time < now)
				die_now = B_TRUE;
			else
				die_now = B_FALSE;
			s2c_hash = connp->conn_s2c_hash;
			mutex_enter(&s2c_hash->ilb_conn_hash_lock);

			if (connp->conn_gc || die_now ||
			    (connp->conn_c2s_atime < expiry &&
			    connp->conn_s2c_atime < expiry)) {
				/* Need to update the nat list cur_connp */
				if (connp == ilbs->ilbs_conn_list_connp) {
					ilbs->ilbs_conn_list_connp =
					    connp->conn_c2s_next;
				}
				ilb_conn_remove(connp);
				goto nxt_connp;
			}

			if (connp->conn_l4 != IPPROTO_TCP)
				goto nxt_connp;

			/* Update and check TCP related conn info */
			if (connp->conn_c2s_tcp_fin_sent &&
			    SEQ_GT(connp->conn_s2c_tcp_ack,
			    connp->conn_c2s_tcp_fss)) {
				connp->conn_c2s_tcp_fin_acked = B_TRUE;
			}
			if (connp->conn_s2c_tcp_fin_sent &&
			    SEQ_GT(connp->conn_c2s_tcp_ack,
			    connp->conn_s2c_tcp_fss)) {
				connp->conn_s2c_tcp_fin_acked = B_TRUE;
			}
			if (connp->conn_c2s_tcp_fin_acked &&
			    connp->conn_s2c_tcp_fin_acked) {
				ilb_conn_remove(connp);
			}
nxt_connp:
			mutex_exit(&s2c_hash->ilb_conn_hash_lock);
			connp = nxt_connp;
		} while (connp != NULL);
		mutex_exit(&c2s_hash[i].ilb_conn_hash_lock);
	}
}

/* Conn hash timer routine.  It dispatches a taskq and restart the timer */
static void
ilb_conn_timer(void *arg)
{
	ilb_timer_t *timer = (ilb_timer_t *)arg;

	(void) taskq_dispatch(timer->ilbs->ilbs_conn_taskq, ilb_conn_cleanup,
	    arg, TQ_SLEEP);
	mutex_enter(&timer->tid_lock);
	if (timer->tid == 0) {
		mutex_exit(&timer->tid_lock);
	} else {
		timer->tid = timeout(ilb_conn_timer, arg,
		    SEC_TO_TICK(ilb_conn_cache_timeout));
		mutex_exit(&timer->tid_lock);
	}
}

void
ilb_conn_hash_init(ilb_stack_t *ilbs)
{
	extern pri_t minclsyspri;
	int i, part;
	ilb_timer_t *tm;
	char tq_name[TASKQ_NAMELEN];

	/*
	 * If ilbs->ilbs_conn_hash_size is not a power of 2, bump it up to
	 * the next power of 2.
	 */
	if (!ISP2(ilbs->ilbs_conn_hash_size)) {
		for (i = 0; i < 31; i++) {
			if (ilbs->ilbs_conn_hash_size < (1 << i))
				break;
		}
		ilbs->ilbs_conn_hash_size = 1 << i;
	}

	/*
	 * Can sleep since this should be called when a rule is being added,
	 * hence we are not in interrupt context.
	 */
	ilbs->ilbs_c2s_conn_hash = kmem_zalloc(sizeof (ilb_conn_hash_t) *
	    ilbs->ilbs_conn_hash_size, KM_SLEEP);
	ilbs->ilbs_s2c_conn_hash = kmem_zalloc(sizeof (ilb_conn_hash_t) *
	    ilbs->ilbs_conn_hash_size, KM_SLEEP);

	for (i = 0; i < ilbs->ilbs_conn_hash_size; i++) {
		mutex_init(&ilbs->ilbs_c2s_conn_hash[i].ilb_conn_hash_lock,
		    NULL, MUTEX_DEFAULT, NULL);
	}
	for (i = 0; i < ilbs->ilbs_conn_hash_size; i++) {
		mutex_init(&ilbs->ilbs_s2c_conn_hash[i].ilb_conn_hash_lock,
		    NULL, MUTEX_DEFAULT, NULL);
	}

	if (ilb_conn_cache == NULL)
		ilb_conn_cache_init();

	(void) snprintf(tq_name, sizeof (tq_name), "ilb_conn_taskq_%p",
	    (void *)ilbs->ilbs_netstack);
	ASSERT(ilbs->ilbs_conn_taskq == NULL);
	ilbs->ilbs_conn_taskq = taskq_create(tq_name,
	    ilb_conn_timer_size * 2, minclsyspri, ilb_conn_timer_size,
	    ilb_conn_timer_size * 2, TASKQ_PREPOPULATE|TASKQ_DYNAMIC);

	ASSERT(ilbs->ilbs_conn_timer_list == NULL);
	ilbs->ilbs_conn_timer_list = kmem_zalloc(sizeof (ilb_timer_t) *
	    ilb_conn_timer_size, KM_SLEEP);

	/*
	 * The hash table is divided in equal partition for those timers
	 * to do garbage collection.
	 */
	part = ilbs->ilbs_conn_hash_size / ilb_conn_timer_size + 1;
	for (i = 0; i < ilb_conn_timer_size; i++) {
		tm = ilbs->ilbs_conn_timer_list + i;
		tm->start = i * part;
		tm->end = i * part + part;
		if (tm->end > ilbs->ilbs_conn_hash_size)
			tm->end = ilbs->ilbs_conn_hash_size;
		tm->ilbs = ilbs;
		mutex_init(&tm->tid_lock, NULL, MUTEX_DEFAULT, NULL);
		/* Spread out the starting execution time of all the timers. */
		tm->tid = timeout(ilb_conn_timer, tm,
		    SEC_TO_TICK(ilb_conn_cache_timeout + i));
	}
}

void
ilb_conn_hash_fini(ilb_stack_t *ilbs)
{
	uint32_t i;
	ilb_conn_t *connp;

	if (ilbs->ilbs_c2s_conn_hash == NULL) {
		ASSERT(ilbs->ilbs_s2c_conn_hash == NULL);
		return;
	}

	/* Stop all the timers first. */
	for (i = 0; i < ilb_conn_timer_size; i++) {
		timeout_id_t tid;

		/* Setting tid to 0 tells the timer handler not to restart. */
		mutex_enter(&ilbs->ilbs_conn_timer_list[i].tid_lock);
		tid = ilbs->ilbs_conn_timer_list[i].tid;
		ilbs->ilbs_conn_timer_list[i].tid = 0;
		mutex_exit(&ilbs->ilbs_conn_timer_list[i].tid_lock);
		(void) untimeout(tid);
	}
	kmem_free(ilbs->ilbs_conn_timer_list, sizeof (ilb_timer_t) *
	    ilb_conn_timer_size);
	taskq_destroy(ilbs->ilbs_conn_taskq);
	ilbs->ilbs_conn_taskq = NULL;

	/* Then remove all the conns. */
	for (i = 0; i < ilbs->ilbs_conn_hash_size; i++) {
		while ((connp = ilbs->ilbs_s2c_conn_hash->ilb_connp) != NULL) {
			ilbs->ilbs_s2c_conn_hash->ilb_connp =
			    connp->conn_s2c_next;
			ILB_SERVER_REFRELE(connp->conn_server);
			if (connp->conn_rule_cache.topo == ILB_TOPO_IMPL_NAT) {
				ilb_nat_src_entry_t *ent;
				in_port_t port;

				/*
				 * src_ent will be freed in ilb_nat_src_fini().
				 */
				port = ntohs(
				    connp->conn_rule_cache.info.nat_sport);
				ent = connp->conn_rule_cache.info.src_ent;
				vmem_free(ent->nse_port_arena,
				    (void *)(uintptr_t)port, 1);
			}
			kmem_cache_free(ilb_conn_cache, connp);
		}
	}
	kmem_free(ilbs->ilbs_c2s_conn_hash, sizeof (ilb_conn_hash_t) *
	    ilbs->ilbs_conn_hash_size);
	kmem_free(ilbs->ilbs_s2c_conn_hash, sizeof (ilb_conn_hash_t) *
	    ilbs->ilbs_conn_hash_size);
}

/*
 * Internet checksum adjustment calculation routines.  We pre-calculate
 * checksum adjustment so that we don't need to compute the checksum on
 * the whole packet when we change address/port in the packet.
 */

static void
hnat_cksum_v4(uint16_t *oaddr, uint16_t *naddr, in_port_t old_port,
    in_port_t new_port, uint32_t *adj_sum)
{
	uint32_t sum;

	sum = *oaddr + *(oaddr + 1) + old_port;
	while ((sum >> 16) != 0)
		sum = (sum & 0xffff) + (sum >> 16);
	*adj_sum = (uint16_t)~sum + *naddr + *(naddr + 1) + new_port;
}

static void
hnat_cksum_v6(uint16_t *oaddr, uint16_t *naddr, in_port_t old_port,
    in_port_t new_port, uint32_t *adj_sum)
{
	uint32_t sum = 0;

	sum = *oaddr + *(oaddr + 1) + *(oaddr + 2) + *(oaddr + 3) +
	    *(oaddr + 4) + *(oaddr + 5) + *(oaddr + 6) + *(oaddr + 7) +
	    old_port;
	while ((sum >> 16) != 0)
		sum = (sum & 0xffff) + (sum >> 16);
	*adj_sum = (uint16_t)~sum + *naddr + *(naddr + 1) +
	    *(naddr + 2) + *(naddr + 3) + *(naddr + 4) + *(naddr + 5) +
	    *(naddr + 6) + *(naddr + 7) + new_port;
}

static void
fnat_cksum_v4(uint16_t *oaddr1, uint16_t *oaddr2, uint16_t *naddr1,
    uint16_t *naddr2, in_port_t old_port1, in_port_t old_port2,
    in_port_t new_port1, in_port_t new_port2, uint32_t *adj_sum)
{
	uint32_t sum;

	sum = *oaddr1 + *(oaddr1 + 1) + old_port1 + *oaddr2 + *(oaddr2 + 1) +
	    old_port2;
	while ((sum >> 16) != 0)
		sum = (sum & 0xffff) + (sum >> 16);
	*adj_sum = (uint16_t)~sum + *naddr1 + *(naddr1 + 1) + new_port1 +
	    *naddr2 + *(naddr2 + 1) + new_port2;
}

static void
fnat_cksum_v6(uint16_t *oaddr1, uint16_t *oaddr2, uint16_t *naddr1,
    uint16_t *naddr2, in_port_t old_port1, in_port_t old_port2,
    in_port_t new_port1, in_port_t new_port2, uint32_t *adj_sum)
{
	uint32_t sum = 0;

	sum = *oaddr1 + *(oaddr1 + 1) + *(oaddr1 + 2) + *(oaddr1 + 3) +
	    *(oaddr1 + 4) + *(oaddr1 + 5) + *(oaddr1 + 6) + *(oaddr1 + 7) +
	    old_port1;
	sum += *oaddr2 + *(oaddr2 + 1) + *(oaddr2 + 2) + *(oaddr2 + 3) +
	    *(oaddr2 + 4) + *(oaddr2 + 5) + *(oaddr2 + 6) + *(oaddr2 + 7) +
	    old_port2;
	while ((sum >> 16) != 0)
		sum = (sum & 0xffff) + (sum >> 16);
	sum = (uint16_t)~sum + *naddr1 + *(naddr1 + 1) + *(naddr1 + 2) +
	    *(naddr1 + 3) + *(naddr1 + 4) + *(naddr1 + 5) + *(naddr1 + 6) +
	    *(naddr1 + 7) + new_port1;
	*adj_sum = sum + *naddr2 + *(naddr2 + 1) + *(naddr2 + 2) +
	    *(naddr2 + 3) + *(naddr2 + 4) + *(naddr2 + 5) + *(naddr2 + 6) +
	    *(naddr2 + 7) + new_port2;
}

/*
 * Add a conn hash entry to the tables.  Note that a conn hash entry
 * (ilb_conn_t) contains info on both directions.  And there are two hash
 * tables, one for client to server and the other for server to client.
 * So the same entry is added to both tables and can be ccessed by two
 * thread simultaneously.  But each thread will only access data on one
 * direction, so there is no conflict.
 */
int
ilb_conn_add(ilb_stack_t *ilbs, ilb_rule_t *rule, ilb_server_t *server,
    in6_addr_t *src, in_port_t sport, in6_addr_t *dst, in_port_t dport,
    ilb_nat_info_t *info, uint32_t *ip_sum, uint32_t *tp_sum, ilb_sticky_t *s)
{
	ilb_conn_t *connp;
	ilb_conn_hash_t *hash;
	int i;

	connp = kmem_cache_alloc(ilb_conn_cache, KM_NOSLEEP);
	if (connp == NULL) {
		if (s != NULL) {
			if (rule->ir_topo == ILB_TOPO_IMPL_NAT) {
				ilb_nat_src_entry_t **entry;

				entry = s->server->iser_nat_src->src_list;
				vmem_free(entry[s->nat_src_idx]->nse_port_arena,
				    (void *)(uintptr_t)ntohs(info->nat_sport),
				    1);
			}
			ILB_STICKY_REFRELE(s);
		}
		return (ENOMEM);
	}

	connp->conn_l4 = rule->ir_proto;

	connp->conn_server = server;
	ILB_SERVER_REFHOLD(server);
	connp->conn_sticky = s;

	connp->conn_rule_cache.topo = rule->ir_topo;
	connp->conn_rule_cache.info = *info;

	connp->conn_gc = B_FALSE;

	connp->conn_expiry = rule->ir_nat_expiry;
	connp->conn_cr_time = ddi_get_lbolt64();

	/* Client to server info. */
	connp->conn_c2s_saddr = *src;
	connp->conn_c2s_sport = sport;
	connp->conn_c2s_daddr = *dst;
	connp->conn_c2s_dport = dport;

	connp->conn_c2s_atime = ddi_get_lbolt64();
	/* The packet ths triggers this creation should be counted */
	connp->conn_c2s_pkt_cnt = 1;
	connp->conn_c2s_tcp_fin_sent = B_FALSE;
	connp->conn_c2s_tcp_fin_acked = B_FALSE;

	/* Server to client info, before NAT */
	switch (rule->ir_topo) {
	case ILB_TOPO_IMPL_HALF_NAT:
		connp->conn_s2c_saddr = info->nat_dst;
		connp->conn_s2c_sport = info->nat_dport;
		connp->conn_s2c_daddr = *src;
		connp->conn_s2c_dport = sport;

		/* Pre-calculate checksum changes for both directions */
		if (rule->ir_ipver == IPPROTO_IP) {
			hnat_cksum_v4((uint16_t *)&dst->s6_addr32[3],
			    (uint16_t *)&info->nat_dst.s6_addr32[3], 0, 0,
			    &connp->conn_c2s_ip_sum);
			hnat_cksum_v4((uint16_t *)&dst->s6_addr32[3],
			    (uint16_t *)&info->nat_dst.s6_addr32[3], dport,
			    info->nat_dport, &connp->conn_c2s_tp_sum);
			*ip_sum = connp->conn_c2s_ip_sum;
			*tp_sum = connp->conn_c2s_tp_sum;

			hnat_cksum_v4(
			    (uint16_t *)&info->nat_dst.s6_addr32[3],
			    (uint16_t *)&dst->s6_addr32[3], 0, 0,
			    &connp->conn_s2c_ip_sum);
			hnat_cksum_v4(
			    (uint16_t *)&info->nat_dst.s6_addr32[3],
			    (uint16_t *)&dst->s6_addr32[3],
			    info->nat_dport, dport,
			    &connp->conn_s2c_tp_sum);
		} else {
			connp->conn_c2s_ip_sum = 0;
			hnat_cksum_v6((uint16_t *)dst,
			    (uint16_t *)&info->nat_dst, dport,
			    info->nat_dport, &connp->conn_c2s_tp_sum);
			*ip_sum = 0;
			*tp_sum = connp->conn_c2s_tp_sum;

			connp->conn_s2c_ip_sum = 0;
			hnat_cksum_v6((uint16_t *)&info->nat_dst,
			    (uint16_t *)dst, info->nat_dport, dport,
			    &connp->conn_s2c_tp_sum);
		}
		break;
	case ILB_TOPO_IMPL_NAT:
		connp->conn_s2c_saddr = info->nat_dst;
		connp->conn_s2c_sport = info->nat_dport;
		connp->conn_s2c_daddr = info->nat_src;
		connp->conn_s2c_dport = info->nat_sport;

		if (rule->ir_ipver == IPPROTO_IP) {
			fnat_cksum_v4((uint16_t *)&src->s6_addr32[3],
			    (uint16_t *)&dst->s6_addr32[3],
			    (uint16_t *)&info->nat_src.s6_addr32[3],
			    (uint16_t *)&info->nat_dst.s6_addr32[3],
			    0, 0, 0, 0, &connp->conn_c2s_ip_sum);
			fnat_cksum_v4((uint16_t *)&src->s6_addr32[3],
			    (uint16_t *)&dst->s6_addr32[3],
			    (uint16_t *)&info->nat_src.s6_addr32[3],
			    (uint16_t *)&info->nat_dst.s6_addr32[3],
			    sport, dport, info->nat_sport,
			    info->nat_dport, &connp->conn_c2s_tp_sum);
			*ip_sum = connp->conn_c2s_ip_sum;
			*tp_sum = connp->conn_c2s_tp_sum;

			fnat_cksum_v4(
			    (uint16_t *)&info->nat_src.s6_addr32[3],
			    (uint16_t *)&info->nat_dst.s6_addr32[3],
			    (uint16_t *)&src->s6_addr32[3],
			    (uint16_t *)&dst->s6_addr32[3],
			    0, 0, 0, 0, &connp->conn_s2c_ip_sum);
			fnat_cksum_v4(
			    (uint16_t *)&info->nat_src.s6_addr32[3],
			    (uint16_t *)&info->nat_dst.s6_addr32[3],
			    (uint16_t *)&src->s6_addr32[3],
			    (uint16_t *)&dst->s6_addr32[3],
			    info->nat_sport, info->nat_dport,
			    sport, dport, &connp->conn_s2c_tp_sum);
		} else {
			fnat_cksum_v6((uint16_t *)src, (uint16_t *)dst,
			    (uint16_t *)&info->nat_src,
			    (uint16_t *)&info->nat_dst,
			    sport, dport, info->nat_sport,
			    info->nat_dport, &connp->conn_c2s_tp_sum);
			connp->conn_c2s_ip_sum = 0;
			*ip_sum = 0;
			*tp_sum = connp->conn_c2s_tp_sum;

			fnat_cksum_v6((uint16_t *)&info->nat_src,
			    (uint16_t *)&info->nat_dst, (uint16_t *)src,
			    (uint16_t *)dst, info->nat_sport,
			    info->nat_dport, sport, dport,
			    &connp->conn_s2c_tp_sum);
			connp->conn_s2c_ip_sum = 0;
		}
		break;
	}

	connp->conn_s2c_atime = ddi_get_lbolt64();
	connp->conn_s2c_pkt_cnt = 1;
	connp->conn_s2c_tcp_fin_sent = B_FALSE;
	connp->conn_s2c_tcp_fin_acked = B_FALSE;

	/* Add it to the s2c hash table. */
	hash = ilbs->ilbs_s2c_conn_hash;
	i = ILB_CONN_HASH((uint8_t *)&connp->conn_s2c_saddr.s6_addr32[3],
	    ntohs(connp->conn_s2c_sport),
	    (uint8_t *)&connp->conn_s2c_daddr.s6_addr32[3],
	    ntohs(connp->conn_s2c_dport), ilbs->ilbs_conn_hash_size);
	connp->conn_s2c_hash = &hash[i];
	DTRACE_PROBE2(ilb__conn__hash__add__s2c, ilb_conn_t *, connp, int, i);

	mutex_enter(&hash[i].ilb_conn_hash_lock);
	hash[i].ilb_conn_cnt++;
	connp->conn_s2c_next = hash[i].ilb_connp;
	if (hash[i].ilb_connp != NULL)
		hash[i].ilb_connp->conn_s2c_prev = connp;
	connp->conn_s2c_prev = NULL;
	hash[i].ilb_connp = connp;
	mutex_exit(&hash[i].ilb_conn_hash_lock);

	/* Add it to the c2s hash table. */
	hash = ilbs->ilbs_c2s_conn_hash;
	i = ILB_CONN_HASH((uint8_t *)&src->s6_addr32[3], ntohs(sport),
	    (uint8_t *)&dst->s6_addr32[3], ntohs(dport),
	    ilbs->ilbs_conn_hash_size);
	connp->conn_c2s_hash = &hash[i];
	DTRACE_PROBE2(ilb__conn__hash__add__c2s, ilb_conn_t *, connp, int, i);

	mutex_enter(&hash[i].ilb_conn_hash_lock);
	hash[i].ilb_conn_cnt++;
	connp->conn_c2s_next = hash[i].ilb_connp;
	if (hash[i].ilb_connp != NULL)
		hash[i].ilb_connp->conn_c2s_prev = connp;
	connp->conn_c2s_prev = NULL;
	hash[i].ilb_connp = connp;
	mutex_exit(&hash[i].ilb_conn_hash_lock);

	return (0);
}

/*
 * If a connection is using TCP, we keep track of simple TCP state transition
 * so that we know when to clean up an entry.
 */
static boolean_t
update_conn_tcp(ilb_conn_t *connp, void *iph, tcpha_t *tcpha, int32_t pkt_len,
    boolean_t c2s)
{
	uint32_t ack, seq;
	int32_t seg_len;

	if (tcpha->tha_flags & TH_RST)
		return (B_FALSE);

	seg_len = pkt_len - ((uint8_t *)tcpha - (uint8_t *)iph) -
	    TCP_HDR_LENGTH((tcph_t *)tcpha);

	if (tcpha->tha_flags & TH_ACK)
		ack = ntohl(tcpha->tha_ack);
	seq = ntohl(tcpha->tha_seq);
	if (c2s) {
		ASSERT(MUTEX_HELD(&connp->conn_c2s_hash->ilb_conn_hash_lock));
		if (tcpha->tha_flags & TH_FIN) {
			connp->conn_c2s_tcp_fss = seq + seg_len;
			connp->conn_c2s_tcp_fin_sent = B_TRUE;
		}
		connp->conn_c2s_tcp_ack = ack;

		/* Port reuse by the client, restart the conn. */
		if (connp->conn_c2s_tcp_fin_sent &&
		    SEQ_GT(seq, connp->conn_c2s_tcp_fss + 1)) {
			connp->conn_c2s_tcp_fin_sent = B_FALSE;
			connp->conn_c2s_tcp_fin_acked = B_FALSE;
		}
	} else {
		ASSERT(MUTEX_HELD(&connp->conn_s2c_hash->ilb_conn_hash_lock));
		if (tcpha->tha_flags & TH_FIN) {
			connp->conn_s2c_tcp_fss = seq + seg_len;
			connp->conn_s2c_tcp_fin_sent = B_TRUE;
		}
		connp->conn_s2c_tcp_ack = ack;

		/* Port reuse by the client, restart the conn. */
		if (connp->conn_s2c_tcp_fin_sent &&
		    SEQ_GT(seq, connp->conn_s2c_tcp_fss + 1)) {
			connp->conn_s2c_tcp_fin_sent = B_FALSE;
			connp->conn_s2c_tcp_fin_acked = B_FALSE;
		}
	}

	return (B_TRUE);
}

/*
 * Helper routint to find conn hash entry given some packet information and
 * the traffic direction (c2s, client to server?)
 */
static boolean_t
ilb_find_conn(ilb_stack_t *ilbs, void *iph, void *tph, int l4, in6_addr_t *src,
    in_port_t sport, in6_addr_t *dst, in_port_t dport,
    ilb_rule_info_t *rule_cache, uint32_t *ip_sum, uint32_t *tp_sum,
    int32_t pkt_len, boolean_t c2s)
{
	ilb_conn_hash_t *hash;
	uint_t i;
	ilb_conn_t *connp;
	boolean_t tcp_alive;
	boolean_t ret = B_FALSE;

	i = ILB_CONN_HASH((uint8_t *)&src->s6_addr32[3], ntohs(sport),
	    (uint8_t *)&dst->s6_addr32[3], ntohs(dport),
	    ilbs->ilbs_conn_hash_size);
	if (c2s) {
		hash = ilbs->ilbs_c2s_conn_hash;
		mutex_enter(&hash[i].ilb_conn_hash_lock);
		for (connp = hash[i].ilb_connp; connp != NULL;
		    connp = connp->conn_c2s_next) {
			if (connp->conn_l4 == l4 &&
			    connp->conn_c2s_dport == dport &&
			    connp->conn_c2s_sport == sport &&
			    IN6_ARE_ADDR_EQUAL(src, &connp->conn_c2s_saddr) &&
			    IN6_ARE_ADDR_EQUAL(dst, &connp->conn_c2s_daddr)) {
				connp->conn_c2s_atime = ddi_get_lbolt64();
				connp->conn_c2s_pkt_cnt++;
				*rule_cache = connp->conn_rule_cache;
				*ip_sum = connp->conn_c2s_ip_sum;
				*tp_sum = connp->conn_c2s_tp_sum;
				ret = B_TRUE;
				break;
			}
		}
	} else {
		hash = ilbs->ilbs_s2c_conn_hash;
		mutex_enter(&hash[i].ilb_conn_hash_lock);
		for (connp = hash[i].ilb_connp; connp != NULL;
		    connp = connp->conn_s2c_next) {
			if (connp->conn_l4 == l4 &&
			    connp->conn_s2c_dport == dport &&
			    connp->conn_s2c_sport == sport &&
			    IN6_ARE_ADDR_EQUAL(src, &connp->conn_s2c_saddr) &&
			    IN6_ARE_ADDR_EQUAL(dst, &connp->conn_s2c_daddr)) {
				connp->conn_s2c_atime = ddi_get_lbolt64();
				connp->conn_s2c_pkt_cnt++;
				*rule_cache = connp->conn_rule_cache;
				*ip_sum = connp->conn_s2c_ip_sum;
				*tp_sum = connp->conn_s2c_tp_sum;
				ret = B_TRUE;
				break;
			}
		}
	}
	if (ret) {
		ILB_S_KSTAT(connp->conn_server, pkt_processed);
		ILB_S_KSTAT_UPDATE(connp->conn_server, bytes_processed,
		    pkt_len);

		switch (l4) {
		case (IPPROTO_TCP):
			tcp_alive = update_conn_tcp(connp, iph, tph, pkt_len,
			    c2s);
			if (!tcp_alive) {
				connp->conn_gc = B_TRUE;
			}
			break;
		default:
			break;
		}
	}
	mutex_exit(&hash[i].ilb_conn_hash_lock);

	return (ret);
}

/*
 * To check if a give packet matches an existing conn hash entry.  If it
 * does, return the information about this entry so that the caller can
 * do the proper NAT.
 */
boolean_t
ilb_check_conn(ilb_stack_t *ilbs, int l3, void *iph, int l4, void *tph,
    in6_addr_t *src, in6_addr_t *dst, in_port_t sport, in_port_t dport,
    uint32_t pkt_len, in6_addr_t *lb_dst)
{
	ilb_rule_info_t rule_cache;
	uint32_t adj_ip_sum, adj_tp_sum;
	boolean_t ret;

	/* Check the incoming hash table. */
	if (ilb_find_conn(ilbs, iph, tph, l4, src, sport, dst, dport,
	    &rule_cache, &adj_ip_sum, &adj_tp_sum, pkt_len, B_TRUE)) {
		switch (rule_cache.topo) {
		case ILB_TOPO_IMPL_NAT:
			*lb_dst = rule_cache.info.nat_dst;
			ilb_full_nat(l3, iph, l4, tph, &rule_cache.info,
			    adj_ip_sum, adj_tp_sum, B_TRUE);
			ret = B_TRUE;
			break;
		case ILB_TOPO_IMPL_HALF_NAT:
			*lb_dst = rule_cache.info.nat_dst;
			ilb_half_nat(l3, iph, l4, tph, &rule_cache.info,
			    adj_ip_sum, adj_tp_sum, B_TRUE);
			ret = B_TRUE;
			break;
		default:
			ret = B_FALSE;
			break;
		}
		return (ret);
	}
	if (ilb_find_conn(ilbs, iph, tph, l4, src, sport, dst, dport,
	    &rule_cache, &adj_ip_sum, &adj_tp_sum, pkt_len, B_FALSE)) {
		switch (rule_cache.topo) {
		case ILB_TOPO_IMPL_NAT:
			*lb_dst = rule_cache.info.src;
			ilb_full_nat(l3, iph, l4, tph, &rule_cache.info,
			    adj_ip_sum, adj_tp_sum, B_FALSE);
			ret = B_TRUE;
			break;
		case ILB_TOPO_IMPL_HALF_NAT:
			*lb_dst = *dst;
			ilb_half_nat(l3, iph, l4, tph, &rule_cache.info,
			    adj_ip_sum, adj_tp_sum, B_FALSE);
			ret = B_TRUE;
			break;
		default:
			ret = B_FALSE;
			break;
		}
		return (ret);
	}

	return (B_FALSE);
}

/*
 * To check if an ICMP packet belongs to a connection in one of the conn
 * hash entries.
 */
boolean_t
ilb_check_icmp_conn(ilb_stack_t *ilbs, mblk_t *mp, int l3, void *out_iph,
    void *icmph, in6_addr_t *lb_dst)
{
	ilb_conn_hash_t *hash;
	ipha_t *in_iph4;
	ip6_t *in_iph6;
	icmph_t *icmph4;
	icmp6_t *icmph6;
	in6_addr_t *in_src_p, *in_dst_p;
	in_port_t *sport, *dport;
	int l4;
	uint_t i;
	ilb_conn_t *connp;
	ilb_rule_info_t rule_cache;
	uint32_t adj_ip_sum;
	boolean_t full_nat;

	if (l3 == IPPROTO_IP) {
		in6_addr_t in_src, in_dst;

		icmph4 = (icmph_t *)icmph;
		in_iph4 = (ipha_t *)&icmph4[1];

		if ((uint8_t *)in_iph4 + IPH_HDR_LENGTH(in_iph4) +
		    ICMP_MIN_TP_HDR_LEN > mp->b_wptr) {
			return (B_FALSE);
		}

		IN6_IPADDR_TO_V4MAPPED(in_iph4->ipha_src, &in_src);
		in_src_p = &in_src;
		IN6_IPADDR_TO_V4MAPPED(in_iph4->ipha_dst, &in_dst);
		in_dst_p = &in_dst;

		l4 = in_iph4->ipha_protocol;
		if (l4 != IPPROTO_TCP && l4 != IPPROTO_UDP)
			return (B_FALSE);

		sport = (in_port_t *)((char *)in_iph4 +
		    IPH_HDR_LENGTH(in_iph4));
		dport = sport + 1;

		DTRACE_PROBE4(ilb__chk__icmp__conn__v4, uint32_t,
		    in_iph4->ipha_src, uint32_t, in_iph4->ipha_dst, uint16_t,
		    ntohs(*sport), uint16_t, ntohs(*dport));
	} else {
		ASSERT(l3 == IPPROTO_IPV6);

		icmph6 = (icmp6_t *)icmph;
		in_iph6 = (ip6_t *)&icmph6[1];
		in_src_p = &in_iph6->ip6_src;
		in_dst_p = &in_iph6->ip6_dst;

		if ((uint8_t *)in_iph6 + sizeof (ip6_t) +
		    ICMP_MIN_TP_HDR_LEN > mp->b_wptr) {
			return (B_FALSE);
		}

		l4 = in_iph6->ip6_nxt;
		/* We don't go deep inside an IPv6 packet yet. */
		if (l4 != IPPROTO_TCP && l4 != IPPROTO_UDP)
			return (B_FALSE);

		sport = (in_port_t *)&in_iph6[1];
		dport = sport + 1;

		DTRACE_PROBE4(ilb__chk__icmp__conn__v6, in6_addr_t *,
		    &in_iph6->ip6_src, in6_addr_t *, &in_iph6->ip6_dst,
		    uint16_t, ntohs(*sport), uint16_t, ntohs(*dport));
	}

	i = ILB_CONN_HASH((uint8_t *)&in_dst_p->s6_addr32[3], ntohs(*dport),
	    (uint8_t *)&in_src_p->s6_addr32[3], ntohs(*sport),
	    ilbs->ilbs_conn_hash_size);
	hash = ilbs->ilbs_c2s_conn_hash;

	mutex_enter(&hash[i].ilb_conn_hash_lock);
	for (connp = hash[i].ilb_connp; connp != NULL;
	    connp = connp->conn_c2s_next) {
		if (connp->conn_l4 == l4 &&
		    connp->conn_c2s_dport == *sport &&
		    connp->conn_c2s_sport == *dport &&
		    IN6_ARE_ADDR_EQUAL(in_dst_p, &connp->conn_c2s_saddr) &&
		    IN6_ARE_ADDR_EQUAL(in_src_p, &connp->conn_c2s_daddr)) {
			connp->conn_c2s_atime = ddi_get_lbolt64();
			connp->conn_c2s_pkt_cnt++;
			rule_cache = connp->conn_rule_cache;
			adj_ip_sum = connp->conn_c2s_ip_sum;
			break;
		}
	}
	mutex_exit(&hash[i].ilb_conn_hash_lock);

	if (connp == NULL) {
		DTRACE_PROBE(ilb__chk__icmp__conn__failed);
		return (B_FALSE);
	}

	switch (rule_cache.topo) {
	case ILB_TOPO_IMPL_NAT:
		full_nat = B_TRUE;
		break;
	case ILB_TOPO_IMPL_HALF_NAT:
		full_nat = B_FALSE;
		break;
	default:
		return (B_FALSE);
	}

	*lb_dst = rule_cache.info.nat_dst;
	if (l3 == IPPROTO_IP) {
		ilb_nat_icmpv4(mp, out_iph, icmph4, in_iph4, sport, dport,
		    &rule_cache.info, adj_ip_sum, full_nat);
	} else {
		ilb_nat_icmpv6(mp, out_iph, icmph6, in_iph6, sport, dport,
		    &rule_cache.info, full_nat);
	}
	return (B_TRUE);
}

/*
 * This routine sends up the conn hash table to user land.  Note that the
 * request is an ioctl, hence we cannot really differentiate requests
 * from different clients.  There is no context shared between different
 * ioctls.  Here we make the assumption that the user land ilbd will
 * only allow one client to show the conn hash table at any time.
 * Otherwise, the results will be "very" inconsistent.
 *
 * In each ioctl, a flag (ILB_LIST_BEGIN) indicates whether the client wants
 * to read from the beginning of the able.  After a certain entries
 * are reported, the kernel remembers the position of the last returned
 * entry.  When the next ioctl comes in with the ILB_LIST_BEGIN flag,
 * it will return entries starting from where it was left off.  When
 * the end of table is reached, a flag (ILB_LIST_END) is set to tell
 * the client that there is no more entry.
 *
 * It is assumed that the caller has checked the size of nat so that it
 * can hold num entries.
 */
/* ARGSUSED */
int
ilb_list_nat(ilb_stack_t *ilbs, zoneid_t zoneid, ilb_nat_entry_t *nat,
    uint32_t *num, uint32_t *flags)
{
	ilb_conn_hash_t *hash;
	ilb_conn_t *cur_connp;
	uint32_t i, j;
	int ret = 0;

	mutex_enter(&ilbs->ilbs_conn_list_lock);
	while (ilbs->ilbs_conn_list_busy) {
		if (cv_wait_sig(&ilbs->ilbs_conn_list_cv,
		    &ilbs->ilbs_conn_list_lock) == 0) {
			mutex_exit(&ilbs->ilbs_conn_list_lock);
			return (EINTR);
		}
	}
	if ((hash = ilbs->ilbs_c2s_conn_hash) == NULL) {
		ASSERT(ilbs->ilbs_s2c_conn_hash == NULL);
		mutex_exit(&ilbs->ilbs_conn_list_lock);
		*num = 0;
		*flags |= ILB_LIST_END;
		return (0);
	}
	ilbs->ilbs_conn_list_busy = B_TRUE;
	mutex_exit(&ilbs->ilbs_conn_list_lock);

	if (*flags & ILB_LIST_BEGIN) {
		i = 0;
		mutex_enter(&hash[0].ilb_conn_hash_lock);
		cur_connp = hash[0].ilb_connp;
	} else if (*flags & ILB_LIST_CONT) {
		if (ilbs->ilbs_conn_list_cur == ilbs->ilbs_conn_hash_size) {
			*num = 0;
			*flags |= ILB_LIST_END;
			goto done;
		}
		i = ilbs->ilbs_conn_list_cur;
		mutex_enter(&hash[i].ilb_conn_hash_lock);
		cur_connp = ilbs->ilbs_conn_list_connp;
	} else {
		ret = EINVAL;
		goto done;
	}

	j = 0;
	while (j < *num) {
		if (cur_connp == NULL) {
			mutex_exit(&hash[i].ilb_conn_hash_lock);
			if (++i == ilbs->ilbs_conn_hash_size) {
				*flags |= ILB_LIST_END;
				break;
			}
			mutex_enter(&hash[i].ilb_conn_hash_lock);
			cur_connp = hash[i].ilb_connp;
			continue;
		}
		nat[j].proto = cur_connp->conn_l4;

		nat[j].in_global = cur_connp->conn_c2s_daddr;
		nat[j].in_global_port = cur_connp->conn_c2s_dport;
		nat[j].out_global = cur_connp->conn_c2s_saddr;
		nat[j].out_global_port = cur_connp->conn_c2s_sport;

		nat[j].in_local = cur_connp->conn_s2c_saddr;
		nat[j].in_local_port = cur_connp->conn_s2c_sport;
		nat[j].out_local = cur_connp->conn_s2c_daddr;
		nat[j].out_local_port = cur_connp->conn_s2c_dport;

		nat[j].create_time = TICK_TO_MSEC(cur_connp->conn_cr_time);
		nat[j].last_access_time =
		    TICK_TO_MSEC(cur_connp->conn_c2s_atime);

		/*
		 * The conn_s2c_pkt_cnt may not be accurate since we are not
		 * holding the s2c hash lock.
		 */
		nat[j].pkt_cnt = cur_connp->conn_c2s_pkt_cnt +
		    cur_connp->conn_s2c_pkt_cnt;
		j++;

		cur_connp = cur_connp->conn_c2s_next;
	}
	ilbs->ilbs_conn_list_connp = cur_connp;
	if (j == *num)
		mutex_exit(&hash[i].ilb_conn_hash_lock);

	ilbs->ilbs_conn_list_cur = i;

	*num = j;
done:
	mutex_enter(&ilbs->ilbs_conn_list_lock);
	ilbs->ilbs_conn_list_busy = B_FALSE;
	cv_signal(&ilbs->ilbs_conn_list_cv);
	mutex_exit(&ilbs->ilbs_conn_list_lock);

	return (ret);
}


/*
 * Stickiness (persistence) handling routines.
 */


static void
ilb_sticky_cache_init(void)
{
	ilb_sticky_cache = kmem_cache_create("ilb_sticky_cache",
	    sizeof (ilb_sticky_t), 0, NULL, NULL, NULL, NULL, NULL,
	    ilb_kmem_flags);
}

void
ilb_sticky_cache_fini(void)
{
	if (ilb_sticky_cache != NULL) {
		kmem_cache_destroy(ilb_sticky_cache);
		ilb_sticky_cache = NULL;
	}
}

void
ilb_sticky_refrele(ilb_sticky_t *s)
{
	ILB_STICKY_REFRELE(s);
}

static ilb_sticky_t *
ilb_sticky_lookup(ilb_sticky_hash_t *hash, ilb_rule_t *rule, in6_addr_t *src)
{
	ilb_sticky_t *s;

	ASSERT(mutex_owned(&hash->sticky_lock));

	for (s = list_head(&hash->sticky_head); s != NULL;
	    s = list_next(&hash->sticky_head, s)) {
		if (s->rule_instance == rule->ir_ks_instance) {
			if (IN6_ARE_ADDR_EQUAL(src, &s->src))
				return (s);
		}
	}
	return (NULL);
}

static ilb_sticky_t *
ilb_sticky_add(ilb_sticky_hash_t *hash, ilb_rule_t *rule, ilb_server_t *server,
    in6_addr_t *src)
{
	ilb_sticky_t *s;

	ASSERT(mutex_owned(&hash->sticky_lock));

	if ((s = kmem_cache_alloc(ilb_sticky_cache, KM_NOSLEEP)) == NULL)
		return (NULL);

	/*
	 * The rule instance is for handling the scenario when the same
	 * client talks to different rules at the same time.  Stickiness
	 * is per rule so we can use the rule instance to differentiate
	 * the client's request.
	 */
	s->rule_instance = rule->ir_ks_instance;
	/*
	 * Copy the rule name for listing all sticky cache entry.  ir_name
	 * is guaranteed to be NULL terminated.
	 */
	(void) strcpy(s->rule_name, rule->ir_name);
	s->server = server;

	/*
	 * Grab a ref cnt on the server so that it won't go away while
	 * it is still in the sticky table.
	 */
	ILB_SERVER_REFHOLD(server);
	s->src = *src;
	s->expiry = rule->ir_sticky_expiry;
	s->refcnt = 1;
	s->hash = hash;

	/*
	 * There is no need to set atime here since the refcnt is not
	 * zero.  A sticky entry is removed only when the refcnt is
	 * zero.  But just set it here for debugging purpose.  The
	 * atime is set when a refrele is done on a sticky entry.
	 */
	s->atime = ddi_get_lbolt64();

	list_insert_head(&hash->sticky_head, s);
	hash->sticky_cnt++;
	return (s);
}

/*
 * This routine checks if there is an existing sticky entry which matches
 * a given packet.  If there is one, return it.  If there is not, create
 * a sticky entry using the packet's info.
 */
ilb_server_t *
ilb_sticky_find_add(ilb_stack_t *ilbs, ilb_rule_t *rule, in6_addr_t *src,
    ilb_server_t *server, ilb_sticky_t **res, uint16_t *src_ent_idx)
{
	int i;
	ilb_sticky_hash_t *hash;
	ilb_sticky_t *s;

	ASSERT(server != NULL);

	*res = NULL;

	i = ILB_STICKY_HASH((uint8_t *)&src->s6_addr32[3],
	    (uint32_t)(uintptr_t)rule, ilbs->ilbs_sticky_hash_size);
	hash = &ilbs->ilbs_sticky_hash[i];

	/* First check if there is already an entry. */
	mutex_enter(&hash->sticky_lock);
	s = ilb_sticky_lookup(hash, rule, src);

	/* No sticky entry, add one. */
	if (s == NULL) {
add_new_entry:
		s = ilb_sticky_add(hash, rule, server, src);
		if (s == NULL) {
			mutex_exit(&hash->sticky_lock);
			return (NULL);
		}
		/*
		 * Find a source for this server.  All subseqent requests from
		 * the same client matching this sticky entry will use this
		 * source address in doing NAT.  The current algorithm is
		 * simple, rotate the source address.  Note that the
		 * source address array does not change after it's created, so
		 * it is OK to just increment the cur index.
		 */
		if (server->iser_nat_src != NULL) {
			/* It is a hint, does not need to be atomic. */
			*src_ent_idx = (server->iser_nat_src->cur++ %
			    server->iser_nat_src->num_src);
			s->nat_src_idx = *src_ent_idx;
		}
		mutex_exit(&hash->sticky_lock);
		*res = s;
		return (server);
	}

	/*
	 * We don't hold any lock accessing iser_enabled.  Refer to the
	 * comment in ilb_server_add() about iser_lock.
	 */
	if (!s->server->iser_enabled) {
		/*
		 * s->server == server can only happen if there is a race in
		 * toggling the iser_enabled flag (we don't hold a lock doing
		 * that) so that the load balance algorithm still returns a
		 * disabled server.  In this case, just drop the packet...
		 */
		if (s->server == server) {
			mutex_exit(&hash->sticky_lock);
			return (NULL);
		}

		/*
		 * The old server is disabled and there is a new server, use
		 * the new one to create a sticky entry.  Since we will
		 * add the entry at the beginning, subsequent lookup will
		 * find this new entry instead of the old one.
		 */
		goto add_new_entry;
	}

	s->refcnt++;
	*res = s;
	mutex_exit(&hash->sticky_lock);
	if (server->iser_nat_src != NULL)
		*src_ent_idx = s->nat_src_idx;
	return (s->server);
}

static void
ilb_sticky_cleanup(void *arg)
{
	ilb_timer_t *timer = (ilb_timer_t *)arg;
	uint32_t i;
	ilb_stack_t *ilbs;
	ilb_sticky_hash_t *hash;
	ilb_sticky_t *s, *nxt_s;
	int64_t now, expiry;

	ilbs = timer->ilbs;
	hash = ilbs->ilbs_sticky_hash;
	ASSERT(hash != NULL);

	now = ddi_get_lbolt64();
	for (i = timer->start; i < timer->end; i++) {
		mutex_enter(&hash[i].sticky_lock);
		for (s = list_head(&hash[i].sticky_head); s != NULL;
		    s = nxt_s) {
			nxt_s = list_next(&hash[i].sticky_head, s);
			if (s->refcnt != 0)
				continue;
			expiry = now - SEC_TO_TICK(s->expiry);
			if (s->atime < expiry) {
				ILB_SERVER_REFRELE(s->server);
				list_remove(&hash[i].sticky_head, s);
				kmem_cache_free(ilb_sticky_cache, s);
				hash[i].sticky_cnt--;
			}
		}
		mutex_exit(&hash[i].sticky_lock);
	}
}

static void
ilb_sticky_timer(void *arg)
{
	ilb_timer_t *timer = (ilb_timer_t *)arg;

	(void) taskq_dispatch(timer->ilbs->ilbs_sticky_taskq,
	    ilb_sticky_cleanup, arg, TQ_SLEEP);
	mutex_enter(&timer->tid_lock);
	if (timer->tid == 0) {
		mutex_exit(&timer->tid_lock);
	} else {
		timer->tid = timeout(ilb_sticky_timer, arg,
		    SEC_TO_TICK(ilb_sticky_timeout));
		mutex_exit(&timer->tid_lock);
	}
}

void
ilb_sticky_hash_init(ilb_stack_t *ilbs)
{
	extern pri_t minclsyspri;
	int i, part;
	char tq_name[TASKQ_NAMELEN];
	ilb_timer_t *tm;

	if (!ISP2(ilbs->ilbs_sticky_hash_size)) {
		for (i = 0; i < 31; i++) {
			if (ilbs->ilbs_sticky_hash_size < (1 << i))
				break;
		}
		ilbs->ilbs_sticky_hash_size = 1 << i;
	}

	ilbs->ilbs_sticky_hash = kmem_zalloc(sizeof (ilb_sticky_hash_t) *
	    ilbs->ilbs_sticky_hash_size, KM_SLEEP);
	for (i = 0; i < ilbs->ilbs_sticky_hash_size; i++) {
		mutex_init(&ilbs->ilbs_sticky_hash[i].sticky_lock, NULL,
		    MUTEX_DEFAULT, NULL);
		list_create(&ilbs->ilbs_sticky_hash[i].sticky_head,
		    sizeof (ilb_sticky_t),
		    offsetof(ilb_sticky_t, list));
	}

	if (ilb_sticky_cache == NULL)
		ilb_sticky_cache_init();

	(void) snprintf(tq_name, sizeof (tq_name), "ilb_sticky_taskq_%p",
	    (void *)ilbs->ilbs_netstack);
	ASSERT(ilbs->ilbs_sticky_taskq == NULL);
	ilbs->ilbs_sticky_taskq = taskq_create(tq_name,
	    ilb_sticky_timer_size * 2, minclsyspri, ilb_sticky_timer_size,
	    ilb_sticky_timer_size * 2, TASKQ_PREPOPULATE|TASKQ_DYNAMIC);

	ASSERT(ilbs->ilbs_sticky_timer_list == NULL);
	ilbs->ilbs_sticky_timer_list = kmem_zalloc(sizeof (ilb_timer_t) *
	    ilb_sticky_timer_size, KM_SLEEP);
	part = ilbs->ilbs_sticky_hash_size / ilb_sticky_timer_size + 1;
	for (i = 0; i < ilb_sticky_timer_size; i++) {
		tm = ilbs->ilbs_sticky_timer_list + i;
		tm->start = i * part;
		tm->end = i * part + part;
		if (tm->end > ilbs->ilbs_sticky_hash_size)
			tm->end = ilbs->ilbs_sticky_hash_size;
		tm->ilbs = ilbs;
		mutex_init(&tm->tid_lock, NULL, MUTEX_DEFAULT, NULL);
		/* Spread out the starting execution time of all the timers. */
		tm->tid = timeout(ilb_sticky_timer, tm,
		    SEC_TO_TICK(ilb_sticky_timeout + i));
	}
}

void
ilb_sticky_hash_fini(ilb_stack_t *ilbs)
{
	int i;
	ilb_sticky_t *s;

	if (ilbs->ilbs_sticky_hash == NULL)
		return;

	/* Stop all the timers first. */
	for (i = 0; i < ilb_sticky_timer_size; i++) {
		timeout_id_t tid;

		/* Setting tid to 0 tells the timer handler not to restart. */
		mutex_enter(&ilbs->ilbs_sticky_timer_list[i].tid_lock);
		tid = ilbs->ilbs_sticky_timer_list[i].tid;
		ilbs->ilbs_sticky_timer_list[i].tid = 0;
		mutex_exit(&ilbs->ilbs_sticky_timer_list[i].tid_lock);
		(void) untimeout(tid);
	}
	kmem_free(ilbs->ilbs_sticky_timer_list, sizeof (ilb_timer_t) *
	    ilb_sticky_timer_size);
	taskq_destroy(ilbs->ilbs_sticky_taskq);
	ilbs->ilbs_sticky_taskq = NULL;

	for (i = 0; i < ilbs->ilbs_sticky_hash_size; i++) {
		while ((s = list_head(&ilbs->ilbs_sticky_hash[i].sticky_head))
		    != NULL) {
			list_remove(&ilbs->ilbs_sticky_hash[i].sticky_head, s);
			ILB_SERVER_REFRELE(s->server);
			kmem_free(s, sizeof (ilb_sticky_t));
		}
	}
	kmem_free(ilbs->ilbs_sticky_hash, ilbs->ilbs_sticky_hash_size *
	    sizeof (ilb_sticky_hash_t));
}

/*
 * This routine sends up the sticky hash table to user land.  Refer to
 * the comments before ilb_list_nat().  Both routines assume similar
 * conditions.
 *
 * It is assumed that the caller has checked the size of st so that it
 * can hold num entries.
 */
/* ARGSUSED */
int
ilb_list_sticky(ilb_stack_t *ilbs, zoneid_t zoneid, ilb_sticky_entry_t *st,
    uint32_t *num, uint32_t *flags)
{
	ilb_sticky_hash_t *hash;
	ilb_sticky_t *curp;
	uint32_t i, j;
	int ret = 0;

	mutex_enter(&ilbs->ilbs_sticky_list_lock);
	while (ilbs->ilbs_sticky_list_busy) {
		if (cv_wait_sig(&ilbs->ilbs_sticky_list_cv,
		    &ilbs->ilbs_sticky_list_lock) == 0) {
			mutex_exit(&ilbs->ilbs_sticky_list_lock);
			return (EINTR);
		}
	}
	if ((hash = ilbs->ilbs_sticky_hash) == NULL) {
		mutex_exit(&ilbs->ilbs_sticky_list_lock);
		*num = 0;
		*flags |= ILB_LIST_END;
		return (0);
	}
	ilbs->ilbs_sticky_list_busy = B_TRUE;
	mutex_exit(&ilbs->ilbs_sticky_list_lock);

	if (*flags & ILB_LIST_BEGIN) {
		i = 0;
		mutex_enter(&hash[0].sticky_lock);
		curp = list_head(&hash[0].sticky_head);
	} else if (*flags & ILB_LIST_CONT) {
		if (ilbs->ilbs_sticky_list_cur == ilbs->ilbs_sticky_hash_size) {
			*num = 0;
			*flags |= ILB_LIST_END;
			goto done;
		}
		i = ilbs->ilbs_sticky_list_cur;
		mutex_enter(&hash[i].sticky_lock);
		curp = ilbs->ilbs_sticky_list_curp;
	} else {
		ret = EINVAL;
		goto done;
	}

	j = 0;
	while (j < *num) {
		if (curp == NULL) {
			mutex_exit(&hash[i].sticky_lock);
			if (++i == ilbs->ilbs_sticky_hash_size) {
				*flags |= ILB_LIST_END;
				break;
			}
			mutex_enter(&hash[i].sticky_lock);
			curp = list_head(&hash[i].sticky_head);
			continue;
		}
		(void) strcpy(st[j].rule_name, curp->rule_name);
		st[j].req_addr = curp->src;
		st[j].srv_addr = curp->server->iser_addr_v6;
		st[j].expiry_time = TICK_TO_MSEC(curp->expiry);
		j++;
		curp = list_next(&hash[i].sticky_head, curp);
	}
	ilbs->ilbs_sticky_list_curp = curp;
	if (j == *num)
		mutex_exit(&hash[i].sticky_lock);

	ilbs->ilbs_sticky_list_cur = i;

	*num = j;
done:
	mutex_enter(&ilbs->ilbs_sticky_list_lock);
	ilbs->ilbs_sticky_list_busy = B_FALSE;
	cv_signal(&ilbs->ilbs_sticky_list_cv);
	mutex_exit(&ilbs->ilbs_sticky_list_lock);

	return (ret);
}
