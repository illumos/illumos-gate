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

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/crc32.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>
#include <inet/udp_impl.h>
#include <inet/ilb.h>

#include "ilb_impl.h"
#include "ilb_stack.h"
#include "ilb_nat.h"

/*
 * NAT source entry garbarge collection timeout.  The actual timeout value
 * includes a random jitter bounded by the ILB_NAT_SRC_TIMEOUT_JITTER.
 */
#define	ILB_NAT_SRC_TIMEOUT		30
#define	ILB_NAT_SRC_TIMEOUT_JITTER	5

/* key1/2 are assumed to be uint32_t. */
#define	ILB_NAT_SRC_HASH(hash, key1, key2, hash_size)			\
{									\
	CRC32((hash), (key1), sizeof (uint32_t), -1U, crc32_table);	\
	CRC32((hash), (key2), sizeof (uint32_t), (hash), crc32_table);	\
	(hash) %= (hash_size);						\
}

/* NAT source port space instance number.  */
static uint32_t ilb_nat_src_instance = 0;

static void
incr_addr(in6_addr_t *a)
{
	uint32_t i;

	i = ntohl(a->s6_addr32[3]);
	if (IN6_IS_ADDR_V4MAPPED(a)) {
		a->s6_addr32[3] = htonl(++i);
		ASSERT(i != 0);
		return;
	}

	if (++i != 0) {
		a->s6_addr32[3] = htonl(i);
		return;
	}
	a->s6_addr32[3] = 0;
	i = ntohl(a->s6_addr[2]);
	if (++i != 0) {
		a->s6_addr32[2] = htonl(i);
		return;
	}
	a->s6_addr32[2] = 0;
	i = ntohl(a->s6_addr[1]);
	if (++i != 0) {
		a->s6_addr32[1] = htonl(i);
		return;
	}
	a->s6_addr32[1] = 0;
	i = ntohl(a->s6_addr[0]);
	a->s6_addr[0] = htonl(++i);
	ASSERT(i != 0);
}

/*
 * When ILB does full NAT, it first picks one source address from the rule's
 * specified NAT source address list (currently done in round robin fashion).
 * Then it needs to allocate a port.  This source port must make the tuple
 * (source address:source port:destination address:destination port)
 * unique.  The destination part of the tuple is determined by the back
 * end server, and could not be changed.
 *
 * To handle the above source port number allocation, ILB sets up a table
 * of entries identified by source address:back end server address:server port
 * tuple.  This table is used by all rules for NAT source port allocation.
 * Each tuple has an associated vmem arena used for managing the NAT source
 * port space between the source address and back end server address/port.
 * Each back end server (ilb_server_t) has an array of pointers (iser_nat_src)
 * to the different entries in this table for NAT source port allocation.
 * When ILB needs to allocate a NAT source address and port to talk to a back
 * end server, it picks a source address  and uses the array pointer to get
 * to an entry.  Then it calls vmem_alloc() on the associated vmem arena to
 * find an unused port.
 *
 * When a back end server is added, ILB sets up the aforementioned array.
 * For each source address specified in the rule, ILB checks if there is any
 * existing entry which matches this source address:back end server address:
 * port tuple.  The server port is either a specific port or 0 (meaning wild
 * card port).  Normally, a back end server uses the same port as in the rule.
 * If a back end server is used to serve two different rules, there will be
 * two different ports.  Source port allocation for these two rules do not
 * conflict, hence we can use two vmem arenas (two different entries in the
 * table).  But if a server uses port range in one rule, we will treat it as
 * a wild card port.  Wild card poart matches with any port.  If this server
 * is used to serve more than one rules and those rules use the same set of
 * NAT source addresses, this means that they must share the same set of vmem
 * arenas (source port spaces).  We do this for simplicity reason.  If not,
 * we need to partition the port range so that we can identify different forms
 * of source port number collision.
 */

/*
 * NAT source address initialization routine.
 */
void
ilb_nat_src_init(ilb_stack_t *ilbs)
{
	int i;

	ilbs->ilbs_nat_src = kmem_zalloc(sizeof (ilb_nat_src_hash_t) *
	    ilbs->ilbs_nat_src_hash_size, KM_SLEEP);
	for (i = 0; i < ilbs->ilbs_nat_src_hash_size; i++) {
		list_create(&ilbs->ilbs_nat_src[i].nsh_head,
		    sizeof (ilb_nat_src_entry_t),
		    offsetof(ilb_nat_src_entry_t, nse_link));
		mutex_init(&ilbs->ilbs_nat_src[i].nsh_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}
	ilbs->ilbs_nat_src_tid = timeout(ilb_nat_src_timer, ilbs,
	    SEC_TO_TICK(ILB_NAT_SRC_TIMEOUT +
	    gethrtime() % ILB_NAT_SRC_TIMEOUT_JITTER));
}

/*
 * NAT source address clean up routine.
 */
void
ilb_nat_src_fini(ilb_stack_t *ilbs)
{
	ilb_nat_src_entry_t *cur;
	timeout_id_t tid;
	int i;

	/*
	 * By setting ilbs_nat_src_tid to 0, the timer handler will not
	 * restart the timer.
	 */
	mutex_enter(&ilbs->ilbs_nat_src_lock);
	tid = ilbs->ilbs_nat_src_tid;
	ilbs->ilbs_nat_src_tid = 0;
	mutex_exit(&ilbs->ilbs_nat_src_lock);
	if (tid != 0)
		(void) untimeout(tid);

	mutex_destroy(&ilbs->ilbs_nat_src_lock);

	for (i = 0; i < ilbs->ilbs_nat_src_hash_size; i++) {
		while ((cur = list_remove_head(&ilbs->ilbs_nat_src[i].nsh_head))
		    != NULL) {
			vmem_destroy(cur->nse_port_arena);
			kmem_free(cur, sizeof (ilb_nat_src_entry_t));
		}
		mutex_destroy(&ilbs->ilbs_nat_src[i].nsh_lock);
	}

	kmem_free(ilbs->ilbs_nat_src, sizeof (ilb_nat_src_hash_t) *
	    ilbs->ilbs_nat_src_hash_size);
	ilbs->ilbs_nat_src = NULL;
}

/* An arena name is "ilb_ns" + "_xxxxxxxxxx"  */
#define	ARENA_NAMESZ	18
#define	NAT_PORT_START	4096
#define	NAT_PORT_SIZE	65535 - NAT_PORT_START

/*
 * Check if the NAT source and back end server pair ilb_nat_src_entry_t
 * exists.  If it does, increment the refcnt and return it.  If not, create
 * one and return it.
 */
static ilb_nat_src_entry_t *
ilb_find_nat_src(ilb_stack_t *ilbs, const in6_addr_t *nat_src,
    const in6_addr_t *serv_addr, in_port_t port)
{
	ilb_nat_src_entry_t *tmp;
	uint32_t idx;
	char arena_name[ARENA_NAMESZ];
	list_t *head;

	ILB_NAT_SRC_HASH(idx, &nat_src->s6_addr32[3], &serv_addr->s6_addr32[3],
	    ilbs->ilbs_nat_src_hash_size);
	mutex_enter(&ilbs->ilbs_nat_src[idx].nsh_lock);
	head = &ilbs->ilbs_nat_src[idx].nsh_head;
	for (tmp = list_head(head); tmp != NULL; tmp = list_next(head, tmp)) {
		if (IN6_ARE_ADDR_EQUAL(&tmp->nse_src_addr, nat_src) &&
		    IN6_ARE_ADDR_EQUAL(&tmp->nse_serv_addr, serv_addr) &&
		    (port == tmp->nse_port || port == 0 ||
		    tmp->nse_port == 0)) {
			break;
		}
	}
	/* Found one, return it. */
	if (tmp != NULL) {
		tmp->nse_refcnt++;
		mutex_exit(&ilbs->ilbs_nat_src[idx].nsh_lock);
		return (tmp);
	}

	tmp = kmem_alloc(sizeof (ilb_nat_src_entry_t), KM_NOSLEEP);
	if (tmp == NULL) {
		mutex_exit(&ilbs->ilbs_nat_src[idx].nsh_lock);
		return (NULL);
	}
	tmp->nse_src_addr = *nat_src;
	tmp->nse_serv_addr = *serv_addr;
	tmp->nse_port = port;
	tmp->nse_nsh_lock = &ilbs->ilbs_nat_src[idx].nsh_lock;
	tmp->nse_refcnt = 1;

	(void) snprintf(arena_name, ARENA_NAMESZ, "ilb_ns_%u",
	    atomic_inc_32_nv(&ilb_nat_src_instance));
	if ((tmp->nse_port_arena = vmem_create(arena_name,
	    (void *)NAT_PORT_START, NAT_PORT_SIZE, 1, NULL, NULL, NULL, 1,
	    VM_SLEEP | VMC_IDENTIFIER)) == NULL) {
		kmem_free(tmp, sizeof (*tmp));
		return (NULL);
	}

	list_insert_tail(head, tmp);
	mutex_exit(&ilbs->ilbs_nat_src[idx].nsh_lock);

	return (tmp);
}

/*
 * Create ilb_nat_src_t struct for a ilb_server_t struct.
 */
int
ilb_create_nat_src(ilb_stack_t *ilbs, ilb_nat_src_t **nat_src,
    const in6_addr_t *srv_addr, in_port_t port, const in6_addr_t *start,
    int num)
{
	ilb_nat_src_t *src;
	in6_addr_t cur_addr;
	int i;

	if ((src = kmem_zalloc(sizeof (ilb_nat_src_t), KM_NOSLEEP)) == NULL) {
		*nat_src = NULL;
		return (ENOMEM);
	}
	cur_addr = *start;
	for (i = 0; i < num && i < ILB_MAX_NAT_SRC; i++) {
		src->src_list[i] = ilb_find_nat_src(ilbs, &cur_addr, srv_addr,
		    port);
		if (src->src_list[i] == NULL) {
			ilb_destroy_nat_src(&src);
			*nat_src = NULL;
			return (ENOMEM);
		}
		incr_addr(&cur_addr);
		/*
		 * Increment num_src here so that we can call
		 * ilb_destroy_nat_src() when we need to do cleanup.
		 */
		src->num_src++;
	}
	*nat_src = src;
	return (0);
}

/*
 * Timer routine for garbage collecting unneeded NAT source entry.  We
 * don't use a taskq for this since the table should be relatively small
 * and should be OK for a timer to handle.
 */
void
ilb_nat_src_timer(void *arg)
{
	ilb_stack_t *ilbs = (ilb_stack_t *)arg;
	ilb_nat_src_entry_t *cur, *tmp;
	list_t *head;
	int i;

	for (i = 0; i < ilbs->ilbs_nat_src_hash_size; i++) {
		mutex_enter(&ilbs->ilbs_nat_src[i].nsh_lock);
		head = &ilbs->ilbs_nat_src[i].nsh_head;
		cur = list_head(head);
		while (cur != NULL) {
			/*
			 * When a server is removed, it will release its
			 * reference on an entry.  But there may still be
			 * conn using some ports.  So check the size also.
			 */
			if (cur->nse_refcnt != 0 ||
			    vmem_size(cur->nse_port_arena, VMEM_ALLOC) != 0) {
				cur = list_next(head, cur);
				continue;
			}
			tmp = cur;
			cur = list_next(head, cur);
			list_remove(head, tmp);
			vmem_destroy(tmp->nse_port_arena);
			kmem_free(tmp, sizeof (ilb_nat_src_entry_t));
		}
		mutex_exit(&ilbs->ilbs_nat_src[i].nsh_lock);
	}

	mutex_enter(&ilbs->ilbs_nat_src_lock);
	if (ilbs->ilbs_nat_src_tid == 0) {
		mutex_exit(&ilbs->ilbs_nat_src_lock);
	} else {
		ilbs->ilbs_nat_src_tid = timeout(ilb_nat_src_timer, ilbs,
		    SEC_TO_TICK(ILB_NAT_SRC_TIMEOUT +
		    gethrtime() % ILB_NAT_SRC_TIMEOUT_JITTER));
		mutex_exit(&ilbs->ilbs_nat_src_lock);
	}
}

/*
 * Destroy a given ilb_nat_src_t struct.  It will also release the reference
 * hold on all its ilb_nat_src_entry_t.
 */
void
ilb_destroy_nat_src(ilb_nat_src_t **nat_src)
{
	int i, size;
	ilb_nat_src_t *src;
	ilb_nat_src_entry_t *entry;

	src = *nat_src;
	if (src == NULL)
		return;
	size = src->num_src;
	/*
	 * Set each entry to be condemned and the garbarge collector will
	 * clean them up.
	 */
	for (i = 0; i < size; i++) {
		entry = src->src_list[i];
		mutex_enter(entry->nse_nsh_lock);
		entry->nse_refcnt--;
		mutex_exit(entry->nse_nsh_lock);
	}
	kmem_free(src, sizeof (ilb_nat_src_t));
	*nat_src = NULL;
}

/*
 * Given a backend server address and its ilb_nat_src_t, allocate a source
 * address and port for NAT usage.
 */
ilb_nat_src_entry_t *
ilb_alloc_nat_addr(ilb_nat_src_t *src, in6_addr_t *addr, in_port_t *port,
    uint16_t *nat_src_idx)
{
	int i, try, size;
	in_port_t p;

	size = src->num_src;
	/* Increment of cur does not need to be atomic.  It is just a hint. */
	if (nat_src_idx == NULL)
		i = (++src->cur) % size;
	else
		i = *nat_src_idx;

	for (try = 0; try < size; try++) {
		p = (in_port_t)(uintptr_t)vmem_alloc(
		    src->src_list[i]->nse_port_arena, 1, VM_NOSLEEP);
		if (p != 0)
			break;
		/*
		 * If an index is given and we cannot allocate a port using
		 * that entry, return NULL.
		 */
		if (nat_src_idx != NULL)
			return (NULL);
		i = (i + 1) % size;
	}
	if (try == size)
		return (NULL);
	*addr = src->src_list[i]->nse_src_addr;
	*port = htons(p);
	return (src->src_list[i]);
}

/*
 * Use the pre-calculated checksum to adjust the checksum of a packet after
 * NAT.
 */
static void
adj_cksum(uint16_t *chksum, uint32_t adj_sum)
{
	adj_sum += (uint16_t)~(*chksum);
	while ((adj_sum >> 16) != 0)
		adj_sum = (adj_sum & 0xffff) + (adj_sum >> 16);
	*chksum = (uint16_t)~adj_sum;
}

/* Do full NAT (replace both source and desination info) on a packet. */
void
ilb_full_nat(int l3, void *iph, int l4, void *tph, ilb_nat_info_t *info,
    uint32_t adj_ip_sum, uint32_t adj_tp_sum, boolean_t c2s)
{
	in_port_t *orig_sport, *orig_dport;
	uint16_t *tp_cksum;

	switch (l4) {
	case IPPROTO_TCP:
		orig_sport = &((tcpha_t *)tph)->tha_lport;
		orig_dport = &((tcpha_t *)tph)->tha_fport;
		tp_cksum = &((tcpha_t *)tph)->tha_sum;
		break;
	case IPPROTO_UDP:
		orig_sport = &((udpha_t *)tph)->uha_src_port;
		orig_dport = &((udpha_t *)tph)->uha_dst_port;
		tp_cksum = &((udpha_t *)tph)->uha_checksum;
		break;
	default:
		ASSERT(0);
		return;
	}

	switch (l3) {
	case IPPROTO_IP: {
		ipha_t *ipha;

		ipha = iph;
		if (c2s) {
			IN6_V4MAPPED_TO_IPADDR(&info->nat_src,
			    ipha->ipha_src);
			IN6_V4MAPPED_TO_IPADDR(&info->nat_dst,
			    ipha->ipha_dst);
			*orig_sport = info->nat_sport;
			*orig_dport = info->nat_dport;
		} else {
			IN6_V4MAPPED_TO_IPADDR(&info->vip, ipha->ipha_src);
			IN6_V4MAPPED_TO_IPADDR(&info->src, ipha->ipha_dst);
			*orig_sport = info->dport;
			*orig_dport = info->sport;
		}
		adj_cksum(&ipha->ipha_hdr_checksum, adj_ip_sum);
		adj_cksum(tp_cksum, adj_tp_sum);
		break;
	}
	case IPPROTO_IPV6: {
		ip6_t *ip6h;

		ip6h = iph;
		if (c2s) {
			ip6h->ip6_src = info->nat_src;
			ip6h->ip6_dst = info->nat_dst;
			*orig_sport = info->nat_sport;
			*orig_dport = info->nat_dport;
		} else {
			ip6h->ip6_src = info->vip;
			ip6h->ip6_dst = info->src;
			*orig_sport = info->dport;
			*orig_dport = info->sport;
		}
		/* No checksum for IPv6 header */
		adj_cksum(tp_cksum, adj_tp_sum);
		break;
	}
	default:
		ASSERT(0);
		break;
	}
}

/* Do half NAT (only replace the destination info) on a packet. */
void
ilb_half_nat(int l3, void *iph, int l4, void *tph, ilb_nat_info_t *info,
    uint32_t adj_ip_sum, uint32_t adj_tp_sum, boolean_t c2s)
{
	in_port_t *orig_port;
	uint16_t *tp_cksum;

	switch (l4) {
	case IPPROTO_TCP:
		if (c2s)
			orig_port = &((tcpha_t *)tph)->tha_fport;
		else
			orig_port = &((tcpha_t *)tph)->tha_lport;
		tp_cksum = &((tcpha_t *)tph)->tha_sum;
		break;
	case IPPROTO_UDP:
		if (c2s)
			orig_port = &((udpha_t *)tph)->uha_dst_port;
		else
			orig_port = &((udpha_t *)tph)->uha_src_port;
		tp_cksum = &((udpha_t *)tph)->uha_checksum;
		break;
	default:
		ASSERT(0);
		return;
	}

	switch (l3) {
	case IPPROTO_IP: {
		ipha_t *ipha;

		ipha = iph;
		if (c2s) {
			IN6_V4MAPPED_TO_IPADDR(&info->nat_dst,
			    ipha->ipha_dst);
			*orig_port = info->nat_dport;
		} else {
			IN6_V4MAPPED_TO_IPADDR(&info->vip, ipha->ipha_src);
			*orig_port = info->dport;
		}
		adj_cksum(&ipha->ipha_hdr_checksum, adj_ip_sum);
		adj_cksum(tp_cksum, adj_tp_sum);
		break;
	}
	case IPPROTO_IPV6: {
		ip6_t *ip6h;

		ip6h = iph;
		if (c2s) {
			ip6h->ip6_dst = info->nat_dst;
			*orig_port = info->nat_dport;
		} else {
			ip6h->ip6_src = info->vip;
			*orig_port = info->dport;
		}
		/* No checksum for IPv6 header */
		adj_cksum(tp_cksum, adj_tp_sum);
		break;
	}
	default:
		ASSERT(0);
		break;
	}
}

/* Calculate the IPv6 pseudo checksum, used for ICMPv6 NAT. */
uint32_t
ilb_pseudo_sum_v6(ip6_t *ip6h, uint8_t nxt_hdr)
{
	uint32_t sum;
	uint16_t *cur;

	cur = (uint16_t *)&ip6h->ip6_src;
	sum = cur[0] + cur[1] + cur[2] + cur[3] + cur[4] + cur[5] + cur[6] +
	    cur[7] + cur[8] + cur[9] + cur[10] + cur[11] + cur[12] + cur[13] +
	    cur[14] + cur[15] + htons(nxt_hdr);
	return ((sum & 0xffff) + (sum >> 16));
}

/* Do NAT on an ICMPv4 packet. */
void
ilb_nat_icmpv4(mblk_t *mp, ipha_t *out_iph, icmph_t *icmph, ipha_t *in_iph,
    in_port_t *sport, in_port_t *dport, ilb_nat_info_t *info, uint32_t sum,
    boolean_t full_nat)
{
	if (full_nat) {
		IN6_V4MAPPED_TO_IPADDR(&info->nat_src, out_iph->ipha_src);
		IN6_V4MAPPED_TO_IPADDR(&info->nat_src, in_iph->ipha_dst);
		*dport = info->nat_sport;
	}
	IN6_V4MAPPED_TO_IPADDR(&info->nat_dst, out_iph->ipha_dst);
	adj_cksum(&out_iph->ipha_hdr_checksum, sum);
	IN6_V4MAPPED_TO_IPADDR(&info->nat_dst, in_iph->ipha_src);
	*sport = info->nat_dport;

	icmph->icmph_checksum = 0;
	icmph->icmph_checksum = IP_CSUM(mp, IPH_HDR_LENGTH(out_iph), 0);
}

/* Do NAT on an ICMPv6 packet. */
void
ilb_nat_icmpv6(mblk_t *mp, ip6_t *out_ip6h, icmp6_t *icmp6h, ip6_t *in_ip6h,
    in_port_t *sport, in_port_t *dport, ilb_nat_info_t *info,
    boolean_t full_nat)
{
	int hdr_len;

	if (full_nat) {
		out_ip6h->ip6_src = info->nat_src;
		in_ip6h->ip6_dst = info->nat_src;
		*dport = info->nat_sport;
	}
	out_ip6h->ip6_dst = info->nat_dst;
	in_ip6h->ip6_src = info->nat_dst;
	*sport = info->nat_dport;

	icmp6h->icmp6_cksum = out_ip6h->ip6_plen;
	hdr_len = (char *)icmp6h - (char *)out_ip6h;
	icmp6h->icmp6_cksum = IP_CSUM(mp, hdr_len,
	    ilb_pseudo_sum_v6(out_ip6h, IPPROTO_ICMPV6));
}
