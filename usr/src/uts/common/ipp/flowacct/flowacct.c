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

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/atomic.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <sys/acct.h>
#include <sys/exacct.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/ddi.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <ipp/flowacct/flowacct_impl.h>

/*
 * flowacct - IPQoS accounting module. The module maintains an array
 * of 256 hash buckets. When the action routine is invoked for a flow,
 * if the flow (identified by the 5-tuple: saddr, daddr, sport, dport, proto)
 * is already present in the flow table (indexed by the hash function FLOW_HASH)
 * then a check is made to see if an item for this flow with the same
 * dsfield, projid & user id is present. If it is, then the number of packets
 * and the bytes are incremented for that item. If the item does
 * not exist a new item is added for the flow. If the flow is not present
 * an entry is made for the flow.
 *
 * A timer runs thru the table and writes all the flow items that have
 * timed out to the accounting file (via exacct PSARC/1999/119), if present
 * Configuration commands to change the timing interval is provided. The
 * flow timeout value can also be configured. While the timeout is in nsec,
 * the flow timer interval is in usec.
 * Information for an active flow can be obtained by using kstats.
 */

/* Used in computing the hash index */
#define	FLOWACCT_ADDR_HASH(addr) 			\
	((addr).s6_addr8[8] ^ (addr).s6_addr8[9] ^ 	\
	(addr).s6_addr8[10] ^ (addr).s6_addr8[13] ^ 	\
	(addr).s6_addr8[14] ^ (addr).s6_addr8[15])

#define	FLOWACCT_FLOW_HASH(f)				\
	(((FLOWACCT_ADDR_HASH(f->saddr)) + 		\
	(FLOWACCT_ADDR_HASH(f->daddr)) + 		\
	(f->proto) + (f->sport) + (f->dport)) 		\
	% FLOW_TBL_COUNT)

/*
 * Compute difference between a and b in nsec and store in delta.
 * delta should be a hrtime_t. Taken from ip_mroute.c.
 */
#define	FLOWACCT_DELTA(a, b, delta) { \
	int xxs; \
 \
	delta = (a).tv_nsec - (b).tv_nsec; \
	if ((xxs = (a).tv_sec - (b).tv_sec) != 0) { \
		switch (xxs) { \
		case 2: \
		    delta += NANOSEC; \
		    /*FALLTHRU*/ \
		case 1: \
		    delta += NANOSEC; \
		    break; \
		default: \
		    delta += ((hrtime_t)NANOSEC * xxs); \
		} \
	} \
}

/* Debug level */
int flowacct_debug = 0;

/* Collect timed out flows to be written to the accounting file */
typedef struct flow_records_s {
	flow_usage_t *fl_use;
	struct flow_records_s *next;
}flow_records_t;

/* Get port information from the packet. Ignore fragments. */
static void
flowacct_port_info(header_t *header, void *iph, int af, mblk_t *mp)
{
	uint16_t *up;

	if (af == AF_INET) {
		ipha_t *ipha = (ipha_t *)iph;
		uint32_t u2, u1;
		uint_t iplen;

		u2 = ntohs(ipha->ipha_fragment_offset_and_flags);
		u1 = u2 & (IPH_MF | IPH_OFFSET);
		if (u1 != 0) {
			return;
		}
		iplen = (ipha->ipha_version_and_hdr_length & 0xF) << 2;
		up = (uint16_t *)(mp->b_rptr + iplen);
		header->sport = (uint16_t)*up++;
		header->dport = (uint16_t)*up;
	} else {
		ip6_t *ip6h = (ip6_t *)iph;
		uint_t  length = IPV6_HDR_LEN;
		uint_t  ehdrlen;
		uint8_t *nexthdrp, *whereptr, *endptr;
		ip6_dest_t *desthdr;
		ip6_rthdr_t *rthdr;
		ip6_hbh_t *hbhhdr;

		whereptr = ((uint8_t *)&ip6h[1]);
		endptr = mp->b_wptr;
		nexthdrp = &ip6h->ip6_nxt;
		while (whereptr < endptr) {
			switch (*nexthdrp) {
			case IPPROTO_HOPOPTS:
				hbhhdr = (ip6_hbh_t *)whereptr;
				ehdrlen = 8 * (hbhhdr->ip6h_len + 1);
				if ((uchar_t *)hbhhdr +  ehdrlen > endptr)
					return;
				nexthdrp = &hbhhdr->ip6h_nxt;
				break;
			case IPPROTO_DSTOPTS:
				desthdr = (ip6_dest_t *)whereptr;
				ehdrlen = 8 * (desthdr->ip6d_len + 1);
				if ((uchar_t *)desthdr +  ehdrlen > endptr)
					return;
				nexthdrp = &desthdr->ip6d_nxt;
				break;
			case IPPROTO_ROUTING:
				rthdr = (ip6_rthdr_t *)whereptr;
				ehdrlen =  8 * (rthdr->ip6r_len + 1);
				if ((uchar_t *)rthdr +  ehdrlen > endptr)
					return;
				nexthdrp = &rthdr->ip6r_nxt;
				break;
			case IPPROTO_FRAGMENT:
				return;
			case IPPROTO_TCP:
			case IPPROTO_UDP:
			case IPPROTO_SCTP:
				/*
				 * Verify we have at least ICMP_MIN_TP_HDR_LEN
				 * bytes of the ULP's header to get the port
				 * info.
				 */
				if (((uchar_t *)ip6h + length +
				    ICMP_MIN_TP_HDR_LEN)  > endptr) {
					return;
				}
				/* Get the protocol & ports */
				header->proto = *nexthdrp;
				up = (uint16_t *)((uchar_t *)ip6h + length);
				header->sport = (uint16_t)*up++;
				header->dport = (uint16_t)*up;
				return;
			case IPPROTO_ICMPV6:
			case IPPROTO_ENCAP:
			case IPPROTO_IPV6:
			case IPPROTO_ESP:
			case IPPROTO_AH:
				header->proto = *nexthdrp;
				return;
			case IPPROTO_NONE:
			default:
				return;
			}
			length += ehdrlen;
			whereptr += ehdrlen;
		}
	}
}

/*
 * flowacct_find_ids(mp, header)
 *
 * attempt to discern the uid and projid of the originator of a packet by
 * looking at the dblks making up the packet - yeuch!
 *
 * We do it by skipping any fragments with a credp of NULL (originated in
 * kernel), taking the first value that isn't NULL to be the cred_t for the
 * whole packet.
 */
static void
flowacct_find_ids(mblk_t *mp, header_t *header)
{
	cred_t *cr;

	cr = msg_getcred(mp, NULL);
	if (cr != NULL) {
		header->uid = crgetuid(cr);
		header->projid = crgetprojid(cr);
	} else {
		header->uid = (uid_t)-1;
		header->projid = -1;
	}
}

/*
 * Extract header information in a header_t structure so that we don't have
 * have to parse the packet everytime.
 */
static int
flowacct_extract_header(mblk_t *mp, header_t *header)
{
	ipha_t *ipha;
	ip6_t *ip6h;
#define	rptr	((uchar_t *)ipha)

	/* 0 means no port extracted. */
	header->sport = 0;
	header->dport = 0;
	flowacct_find_ids(mp, header);

	V6_SET_ZERO(header->saddr);
	V6_SET_ZERO(header->daddr);

	ipha = (ipha_t *)mp->b_rptr;
	header->isv4 = IPH_HDR_VERSION(ipha) == IPV4_VERSION;
	if (header->isv4) {
		ipha = (ipha_t *)mp->b_rptr;
		V4_PART_OF_V6(header->saddr) = (int32_t)ipha->ipha_src;
		V4_PART_OF_V6(header->daddr) = (int32_t)ipha->ipha_dst;
		header->dsfield = ipha->ipha_type_of_service;
		header->proto = ipha->ipha_protocol;
		header->pktlen = ntohs(ipha->ipha_length);
		if ((header->proto == IPPROTO_TCP) ||
		    (header->proto == IPPROTO_UDP) ||
		    (header->proto == IPPROTO_SCTP)) {
			flowacct_port_info(header, ipha, AF_INET, mp);
		}
	} else {
		/*
		 * Need to pullup everything.
		 */
		if (mp->b_cont != NULL) {
			if (!pullupmsg(mp, -1)) {
				flowacct0dbg(("flowacct_extract_header: "\
				    "pullup error"));
				return (-1);
			}
		}
		ip6h = (ip6_t *)mp->b_rptr;
		bcopy(ip6h->ip6_src.s6_addr32, header->saddr.s6_addr32,
		    sizeof (ip6h->ip6_src.s6_addr32));
		bcopy(ip6h->ip6_dst.s6_addr32, header->daddr.s6_addr32,
		    sizeof (ip6h->ip6_dst.s6_addr32));
		header->dsfield = __IPV6_TCLASS_FROM_FLOW(ip6h->ip6_vcf);
		header->proto = ip6h->ip6_nxt;
		header->pktlen = ntohs(ip6h->ip6_plen) +
		    ip_hdr_length_v6(mp, ip6h);
		flowacct_port_info(header, ip6h, AF_INET6, mp);

	}
#undef	rptr
	return (0);
}

/* Check if the flow (identified by the 5-tuple) exists in the hash table */
static flow_t *
flowacct_flow_present(header_t *header, int index,
    flowacct_data_t *flowacct_data)
{
	list_hdr_t *hdr = flowacct_data->flows_tbl[index].head;
	flow_t *flow;

	while (hdr != NULL) {
		flow = (flow_t *)hdr->objp;
		if ((flow != NULL) &&
		    (IN6_ARE_ADDR_EQUAL(&flow->saddr, &header->saddr)) &&
		    (IN6_ARE_ADDR_EQUAL(&flow->daddr, &header->daddr)) &&
		    (flow->proto == header->proto) &&
		    (flow->sport == header->sport) &&
		    (flow->dport == header->dport)) {
			return (flow);
		}
		hdr = hdr->next;
	}
	return ((flow_t *)NULL);
}

/*
 * Add an object to the list at insert_point. This could be a flow item or
 * a flow itself.
 */
static list_hdr_t *
flowacct_add_obj(list_head_t *tophdr, list_hdr_t *insert_point, void *obj)
{
	list_hdr_t *new_hdr;

	if (tophdr == NULL) {
		return ((list_hdr_t *)NULL);
	}

	new_hdr = (list_hdr_t *)kmem_zalloc(FLOWACCT_HDR_SZ, KM_NOSLEEP);
	if (new_hdr == NULL) {
		flowacct0dbg(("flowacct_add_obj: error allocating mem"));
		return ((list_hdr_t *)NULL);
	}
	gethrestime(&new_hdr->last_seen);
	new_hdr->objp = obj;
	tophdr->nbr_items++;

	if (insert_point == NULL) {
		if (tophdr->head == NULL) {
			tophdr->head = new_hdr;
			tophdr->tail = new_hdr;
			return (new_hdr);
		}

		new_hdr->next = tophdr->head;
		tophdr->head->prev = new_hdr;
		tophdr->head = new_hdr;
		return (new_hdr);
	}

	if (insert_point == tophdr->tail) {
		tophdr->tail->next = new_hdr;
		new_hdr->prev = tophdr->tail;
		tophdr->tail = new_hdr;
		return (new_hdr);
	}

	new_hdr->next = insert_point->next;
	new_hdr->prev = insert_point;
	insert_point->next->prev = new_hdr;
	insert_point->next = new_hdr;
	return (new_hdr);
}

/* Delete an obj from the list. This could be a flow item or the flow itself */
static void
flowacct_del_obj(list_head_t *tophdr, list_hdr_t *hdr, uint_t mode)
{
	size_t	length;
	uint_t	type;

	if ((tophdr == NULL) || (hdr == NULL)) {
		return;
	}

	type = ((flow_t *)hdr->objp)->type;

	tophdr->nbr_items--;

	if (hdr->next != NULL) {
		hdr->next->prev = hdr->prev;
	}
	if (hdr->prev != NULL) {
		hdr->prev->next = hdr->next;
	}
	if (tophdr->head == hdr) {
		tophdr->head = hdr->next;
	}
	if (tophdr->tail == hdr) {
		tophdr->tail = hdr->prev;
	}

	if (mode == FLOWACCT_DEL_OBJ) {
		switch (type) {
		case FLOWACCT_FLOW:
			length = FLOWACCT_FLOW_SZ;
			break;
		case FLOWACCT_ITEM:
			length = FLOWACCT_ITEM_SZ;
			break;
		}
		kmem_free(hdr->objp, length);
		hdr->objp = NULL;
	}

	kmem_free((void *)hdr, FLOWACCT_HDR_SZ);
}

/*
 * Checks if the given item (identified by dsfield, project id and uid)
 * is already present for the flow.
 */
static flow_item_t *
flowacct_item_present(flow_t *flow, uint8_t dsfield, pid_t proj_id, uint_t uid)
{
	list_hdr_t	*itemhdr;
	flow_item_t	*item;

	itemhdr = flow->items.head;

	while (itemhdr != NULL) {
		item = (flow_item_t *)itemhdr->objp;

		if ((item->dsfield != dsfield) || (item->projid != proj_id) ||
		    (item->uid != uid)) {
			itemhdr = itemhdr->next;
			continue;
		}
		return (item);
	}

	return ((flow_item_t *)NULL);
}

/*
 * Add the flow to the table, if not already present. If the flow is
 * present in the table, add the item. Also, update the flow stats.
 * Additionally, re-adjust the timout list as well.
 */
static int
flowacct_update_flows_tbl(header_t *header, flowacct_data_t *flowacct_data)
{
	int index;
	list_head_t *fhead;
	list_head_t *thead;
	list_head_t *ihead;
	boolean_t added_flow = B_FALSE;
	timespec_t  now;
	flow_item_t *item;
	flow_t *flow;

	index = FLOWACCT_FLOW_HASH(header);
	fhead = &flowacct_data->flows_tbl[index];

	/* The timeout list */
	thead = &flowacct_data->flows_tbl[FLOW_TBL_COUNT];

	mutex_enter(&fhead->lock);
	flow = flowacct_flow_present(header, index, flowacct_data);
	if (flow == NULL) {
		flow = (flow_t *)kmem_zalloc(FLOWACCT_FLOW_SZ, KM_NOSLEEP);
		if (flow == NULL) {
			mutex_exit(&fhead->lock);
			flowacct0dbg(("flowacct_update_flows_tbl: mem alloc "\
			    "error"));
			return (-1);
		}
		flow->hdr = flowacct_add_obj(fhead, fhead->tail, (void *)flow);
		if (flow->hdr == NULL) {
			mutex_exit(&fhead->lock);
			kmem_free(flow, FLOWACCT_FLOW_SZ);
			flowacct0dbg(("flowacct_update_flows_tbl: mem alloc "\
			    "error"));
			return (-1);
		}

		flow->type = FLOWACCT_FLOW;
		flow->isv4 = header->isv4;
		bcopy(header->saddr.s6_addr32, flow->saddr.s6_addr32,
		    sizeof (header->saddr.s6_addr32));
		bcopy(header->daddr.s6_addr32, flow->daddr.s6_addr32,
		    sizeof (header->daddr.s6_addr32));
		flow->proto = header->proto;
		flow->sport = header->sport;
		flow->dport = header->dport;
		flow->back_ptr = fhead;
		added_flow = B_TRUE;
	} else {
		/*
		 * We need to make sure that this 'flow' is not deleted
		 * either by a scheduled timeout or an explict call
		 * to flowacct_timer() below.
		 */
		flow->inuse = B_TRUE;
	}

	ihead = &flow->items;
	item = flowacct_item_present(flow, header->dsfield, header->projid,
	    header->uid);
	if (item == NULL) {
		boolean_t just_once = B_TRUE;
		/*
		 * For all practical purposes, we limit the no. of entries in
		 * the flow table - i.e. the max_limt that a user specifies is
		 * the maximum no. of flow items in the table.
		 */
	try_again:
		atomic_inc_32(&flowacct_data->nflows);
		if (flowacct_data->nflows > flowacct_data->max_limit) {
			atomic_dec_32(&flowacct_data->nflows);

			/* Try timing out once */
			if (just_once) {
				/*
				 * Need to release the lock, as this entry
				 * could contain a flow that can be timed
				 * out.
				 */
				mutex_exit(&fhead->lock);
				flowacct_timer(FLOWACCT_JUST_ONE,
				    flowacct_data);
				mutex_enter(&fhead->lock);
				/* Lets check again */
				just_once = B_FALSE;
				goto try_again;
			} else {
				flow->inuse = B_FALSE;
				/* Need to remove the flow, if one was added */
				if (added_flow) {
					flowacct_del_obj(fhead, flow->hdr,
					    FLOWACCT_DEL_OBJ);
				}
				mutex_exit(&fhead->lock);
				flowacct1dbg(("flowacct_update_flows_tbl: "\
				    "maximum active flows exceeded\n"));
				return (-1);
			}
		}
		item = (flow_item_t *)kmem_zalloc(FLOWACCT_ITEM_SZ, KM_NOSLEEP);
		if (item == NULL) {
			flow->inuse = B_FALSE;
			/* Need to remove the flow, if one was added */
			if (added_flow) {
				flowacct_del_obj(fhead, flow->hdr,
				    FLOWACCT_DEL_OBJ);
			}
			mutex_exit(&fhead->lock);
			atomic_dec_32(&flowacct_data->nflows);
			flowacct0dbg(("flowacct_update_flows_tbl: mem alloc "\
			    "error"));
			return (-1);
		}
		item->hdr = flowacct_add_obj(ihead, ihead->tail, (void *)item);
		if (item->hdr == NULL) {
			flow->inuse = B_FALSE;
			/* Need to remove the flow, if one was added */
			if (added_flow) {
				flowacct_del_obj(fhead, flow->hdr,
				    FLOWACCT_DEL_OBJ);
			}
			mutex_exit(&fhead->lock);
			atomic_dec_32(&flowacct_data->nflows);
			kmem_free(item, FLOWACCT_ITEM_SZ);
			flowacct0dbg(("flowacct_update_flows_tbl: mem alloc "\
			    "error\n"));
			return (-1);
		}
		/* If a flow was added, add it too */
		if (added_flow) {
			atomic_add_64(&flowacct_data->usedmem,
			    FLOWACCT_FLOW_RECORD_SZ);
		}
		atomic_add_64(&flowacct_data->usedmem, FLOWACCT_ITEM_RECORD_SZ);

		item->type = FLOWACCT_ITEM;
		item->dsfield = header->dsfield;
		item->projid = header->projid;
		item->uid = header->uid;
		item->npackets = 1;
		item->nbytes = header->pktlen;
		item->creation_time = item->hdr->last_seen;
	} else {
		item->npackets++;
		item->nbytes += header->pktlen;
	}
	gethrestime(&now);
	flow->hdr->last_seen = item->hdr->last_seen = now;
	mutex_exit(&fhead->lock);

	/*
	 * Re-adjust the timeout list. The timer takes the thead lock
	 * follwed by fhead lock(s), so we release fhead, take thead
	 * and re-take fhead.
	 */
	mutex_enter(&thead->lock);
	mutex_enter(&fhead->lock);
	/* If the flow was added, append it to the tail of the timeout list */
	if (added_flow) {
		if (thead->head == NULL) {
			thead->head = flow->hdr;
			thead->tail = flow->hdr;
		} else {
			thead->tail->timeout_next = flow->hdr;
			flow->hdr->timeout_prev = thead->tail;
			thead->tail = flow->hdr;
		}
	/*
	 * Else, move this flow to the tail of the timeout list, if it is not
	 * already.
	 * flow->hdr in the timeout list :-
	 * timeout_next = NULL, timeout_prev != NULL, at the tail end.
	 * timeout_next != NULL, timeout_prev = NULL, at the head.
	 * timeout_next != NULL, timeout_prev != NULL, in the middle.
	 * timeout_next = NULL, timeout_prev = NULL, not in the timeout list,
	 * ignore such flow.
	 */
	} else if ((flow->hdr->timeout_next != NULL) ||
	    (flow->hdr->timeout_prev != NULL)) {
		if (flow->hdr != thead->tail) {
			if (flow->hdr == thead->head) {
				thead->head->timeout_next->timeout_prev = NULL;
				thead->head = thead->head->timeout_next;
				flow->hdr->timeout_next = NULL;
				thead->tail->timeout_next = flow->hdr;
				flow->hdr->timeout_prev = thead->tail;
				thead->tail = flow->hdr;
			} else {
				flow->hdr->timeout_prev->timeout_next =
				    flow->hdr->timeout_next;
				flow->hdr->timeout_next->timeout_prev =
				    flow->hdr->timeout_prev;
				flow->hdr->timeout_next = NULL;
				thead->tail->timeout_next = flow->hdr;
				flow->hdr->timeout_prev = thead->tail;
				thead->tail = flow->hdr;
			}
		}
	}
	/*
	 * Unset this variable, now it is fine even if this
	 * flow gets deleted (i.e. after timing out its
	 * flow items) since we are done using it.
	 */
	flow->inuse = B_FALSE;
	mutex_exit(&fhead->lock);
	mutex_exit(&thead->lock);
	atomic_add_64(&flowacct_data->tbytes, header->pktlen);
	return (0);
}

/* Timer for timing out flows/items from the flow table */
void
flowacct_timeout_flows(void *args)
{
	flowacct_data_t *flowacct_data = (flowacct_data_t *)args;
	flowacct_timer(FLOWACCT_FLOW_TIMER, flowacct_data);
	flowacct_data->flow_tid = timeout(flowacct_timeout_flows, flowacct_data,
	    drv_usectohz(flowacct_data->timer));
}


/* Delete the item from the flow in the flow table */
static void
flowacct_timeout_item(flow_t **flow, list_hdr_t **item_hdr)
{
	list_hdr_t *next_it_hdr;

	next_it_hdr = (*item_hdr)->next;
	flowacct_del_obj(&(*flow)->items, *item_hdr, FLOWACCT_DEL_OBJ);
	*item_hdr = next_it_hdr;
}

/* Create a flow record for this timed out item */
static flow_records_t *
flowacct_create_record(flow_t *flow, list_hdr_t *ithdr)
{
	int count;
	flow_item_t *item = (flow_item_t *)ithdr->objp;
	flow_records_t *tmp_frec = NULL;

	/* Record to be written into the accounting file */
	tmp_frec = kmem_zalloc(sizeof (flow_records_t), KM_NOSLEEP);
	if (tmp_frec == NULL) {
		flowacct0dbg(("flowacct_create_record: mem alloc error.\n"));
		return (NULL);
	}
	tmp_frec->fl_use = kmem_zalloc(sizeof (flow_usage_t), KM_NOSLEEP);
	if (tmp_frec->fl_use == NULL) {
		flowacct0dbg(("flowacct_create_record: mem alloc error\n"));
		kmem_free(tmp_frec, sizeof (flow_records_t));
		return (NULL);
	}

	/* Copy the IP address */
	for (count = 0; count < 4; count++) {
		tmp_frec->fl_use->fu_saddr[count] =
		    htonl(flow->saddr.s6_addr32[count]);
		tmp_frec->fl_use->fu_daddr[count] =
		    htonl(flow->daddr.s6_addr32[count]);
	}

	/*
	 * Ports, protocol, version, dsfield, project id, uid, nbytes, npackets
	 * creation time and last seen.
	 */
	tmp_frec->fl_use->fu_sport = htons(flow->sport);
	tmp_frec->fl_use->fu_dport = htons(flow->dport);
	tmp_frec->fl_use->fu_protocol = flow->proto;
	tmp_frec->fl_use->fu_isv4 = flow->isv4;
	tmp_frec->fl_use->fu_dsfield = item->dsfield;
	tmp_frec->fl_use->fu_projid = item->projid;
	tmp_frec->fl_use->fu_userid = item->uid;
	tmp_frec->fl_use->fu_nbytes = item->nbytes;
	tmp_frec->fl_use->fu_npackets = item->npackets;
	tmp_frec->fl_use->fu_lseen =
	    (uint64_t)(ulong_t)ithdr->last_seen.tv_sec;
	tmp_frec->fl_use->fu_ctime =
	    (uint64_t)(ulong_t)item->creation_time.tv_sec;

	return (tmp_frec);
}

/*
 * Scan thru the timeout list and write the records to the accounting file, if
 * possible. Basically step thru the timeout list maintained in the last
 * hash bucket, FLOW_COUNT_TBL + 1, and timeout flows. This could be called
 * from the timer, FLOWACCT_TIMER - delete only timed out flows or when this
 * instance is deleted, FLOWACCT_PURGE_FLOW - delete all the flows from the
 * table or as FLOWACCT_JUST_ONE - delete the first timed out flow. Since the
 * flows are cronologically arranged in the timeout list,  when called as
 * FLOWACCT_TIMER and FLOWACCT_JUST_ONE, we can stop when we come across
 * the first flow that has not timed out (which means none of the following
 * flows would have timed out).
 */
void
flowacct_timer(int type, flowacct_data_t *flowacct_data)
{
	hrtime_t diff;
	timespec_t now;
	list_head_t *head, *thead;
	flow_t *flow;
	flow_item_t *item;
	list_hdr_t *fl_hdr, *next_fl_hdr;
	list_hdr_t *ithdr = (list_hdr_t *)NULL;
	flow_records_t *frec = NULL, *tmp_frec, *tail;
	uint64_t flow_size;
	uint64_t item_size;

	ASSERT(flowacct_data != NULL);

	/* 2s-complement for subtraction */
	flow_size = ~FLOWACCT_FLOW_RECORD_SZ + 1;
	item_size = ~FLOWACCT_ITEM_RECORD_SZ + 1;

	/* Get the current time */
	gethrestime(&now);

	/*
	 * For each flow in the table, scan thru all the items and delete
	 * those that have exceeded the timeout. If all the items in a
	 * flow have timed out, delete the flow entry as well. Finally,
	 * write all the delted items to the accounting file.
	 */
	thead = &flowacct_data->flows_tbl[FLOW_TBL_COUNT];

	mutex_enter(&thead->lock);
	fl_hdr = thead->head;
	while (fl_hdr != NULL) {
		uint32_t	items_deleted = 0;

		next_fl_hdr = fl_hdr->timeout_next;
		flow = (flow_t *)fl_hdr->objp;
		head = flow->back_ptr;
		mutex_enter(&head->lock);

		/*LINTED*/
		FLOWACCT_DELTA(now, fl_hdr->last_seen, diff);

		/*
		 * If type is FLOW_TIMER, then check if the item has timed out.
		 * If type is FLOW_PURGE delete the entry anyways.
		 */
		if ((type != FLOWACCT_PURGE_FLOW) &&
		    (diff < flowacct_data->timeout)) {
			mutex_exit(&head->lock);
			mutex_exit(&thead->lock);
			goto write_records;
		}

		ithdr = flow->items.head;
		while (ithdr != NULL) {
			item = (flow_item_t *)ithdr->objp;
			/*
			 * Fill in the flow record to be
			 * written to the accounting file.
			 */
			tmp_frec = flowacct_create_record(flow, ithdr);
			/*
			 * If we don't have memory for records,
			 * we will come back in case this is
			 * called as FLOW_TIMER, else we will
			 * go ahead and delete the item from
			 * the table (when asked to PURGE the
			 * table), so there could be some
			 * entries not written to the file
			 * when this action instance is
			 * deleted.
			 */
			if (tmp_frec != NULL) {
				tmp_frec->fl_use->fu_aname =
				    flowacct_data->act_name;
				if (frec == NULL) {
					frec = tmp_frec;
					tail = frec;
				} else {
					tail->next = tmp_frec;
					tail = tmp_frec;
				}
			} else if (type != FLOWACCT_PURGE_FLOW) {
				mutex_exit(&head->lock);
				mutex_exit(&thead->lock);
				atomic_add_32(&flowacct_data->nflows,
				    (~items_deleted + 1));
				goto write_records;
			}

			/* Update stats */
			atomic_add_64(&flowacct_data->tbytes, (~item->nbytes +
			    1));

			/* Delete the item */
			flowacct_timeout_item(&flow, &ithdr);
			items_deleted++;
			atomic_add_64(&flowacct_data->usedmem, item_size);
		}
		ASSERT(flow->items.nbr_items == 0);
		atomic_add_32(&flowacct_data->nflows, (~items_deleted + 1));

		/*
		 * Don't delete this flow if we are making place for
		 * a new item for this flow.
		 */
		if (!flow->inuse) {
			if (fl_hdr->timeout_prev != NULL) {
				fl_hdr->timeout_prev->timeout_next =
				    fl_hdr->timeout_next;
			} else {
				thead->head = fl_hdr->timeout_next;
			}
			if (fl_hdr->timeout_next != NULL) {
				fl_hdr->timeout_next->timeout_prev =
				    fl_hdr->timeout_prev;
			} else {
				thead->tail = fl_hdr->timeout_prev;
			}
			fl_hdr->timeout_prev = NULL;
			fl_hdr->timeout_next = NULL;
			flowacct_del_obj(head, fl_hdr, FLOWACCT_DEL_OBJ);
			atomic_add_64(&flowacct_data->usedmem, flow_size);
		}
		mutex_exit(&head->lock);
		if (type == FLOWACCT_JUST_ONE) {
			mutex_exit(&thead->lock);
			goto write_records;
		}
		fl_hdr = next_fl_hdr;
	}
	mutex_exit(&thead->lock);
write_records:
	/* Write all the timed out flows to the accounting file */
	while (frec != NULL) {
		tmp_frec = frec->next;
		exacct_commit_flow(frec->fl_use);
		kmem_free(frec->fl_use, sizeof (flow_usage_t));
		kmem_free(frec, sizeof (flow_records_t));
		frec = tmp_frec;
	}
}

/*
 * Get the IP header contents from the packet, update the flow table with
 * this item and return.
 */
int
flowacct_process(mblk_t **mpp, flowacct_data_t *flowacct_data)
{
	header_t *header;
	mblk_t *mp = *mpp;

	ASSERT(mp != NULL);

	/* If we don't find an M_DATA, return error */
	if (mp->b_datap->db_type != M_DATA) {
		if ((mp->b_cont != NULL) &&
		    (mp->b_cont->b_datap->db_type == M_DATA)) {
			mp = mp->b_cont;
		} else {
			flowacct0dbg(("flowacct_process: no data\n"));
			atomic_inc_64(&flowacct_data->epackets);
			return (EINVAL);
		}
	}

	header = kmem_zalloc(FLOWACCT_HEADER_SZ, KM_NOSLEEP);
	if (header == NULL) {
		flowacct0dbg(("flowacct_process: error allocing mem"));
		atomic_inc_64(&flowacct_data->epackets);
		return (ENOMEM);
	}

	/* Get all the required information into header. */
	if (flowacct_extract_header(mp, header) != 0) {
		kmem_free(header, FLOWACCT_HEADER_SZ);
		atomic_inc_64(&flowacct_data->epackets);
		return (EINVAL);
	}

	/* Updated the flow table with this entry */
	if (flowacct_update_flows_tbl(header, flowacct_data) != 0) {
		kmem_free(header, FLOWACCT_HEADER_SZ);
		atomic_inc_64(&flowacct_data->epackets);
		return (ENOMEM);
	}

	/* Update global stats */
	atomic_inc_64(&flowacct_data->npackets);
	atomic_add_64(&flowacct_data->nbytes, header->pktlen);

	kmem_free(header, FLOWACCT_HEADER_SZ);
	if (flowacct_data->flow_tid == 0) {
		flowacct_data->flow_tid = timeout(flowacct_timeout_flows,
		    flowacct_data, drv_usectohz(flowacct_data->timer));
	}
	return (0);
}
