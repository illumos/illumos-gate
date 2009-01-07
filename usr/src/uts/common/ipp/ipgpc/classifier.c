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

#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/strsun.h>
#include <netinet/in.h>
#include <ipp/ipgpc/classifier.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <net/if.h>
#include <inet/ipp_common.h>

/* Implementation file for classifier used in ipgpc module */

/*
 * CHECK_MATCH_STATUS(match_status, slctrs_srchd, selector_mask)
 *
 * determines what the result of the selector search and what action needs to
 * be taken next.
 * if a NORMAL_MATCH occurs, business as usual NORMAL_MATCH
 * if the selector was not searched because only DONTCARE keys are loaded,
 * the selector is marked as not being searched
 * otherwise, memory error occurred or no matches were found, classify()
 * should return the error match status immediately
 */
#define	CHECK_MATCH_STATUS(match_status, slctrs_srchd, selector_mask)	\
	(((match_status) == NORMAL_MATCH) ?			\
	(NORMAL_MATCH) :					\
	(((match_status) == DONTCARE_ONLY_MATCH) ?		\
	(*(slctrs_srchd) ^= (selector_mask), NORMAL_MATCH) :	\
	(match_status)))

/* used to determine if an action instance already exists */
boolean_t ipgpc_action_exist = B_FALSE;
int ipgpc_debug = 0;		/* IPGPC debugging level */

/* Statics */
static int common_classify(ipgpc_packet_t *, ht_match_t *, uint16_t *);
static void update_stats(int, uint_t);
static int bestmatch(ht_match_t *, uint16_t);
static void get_port_info(ipgpc_packet_t *, void *, int, mblk_t *);

/*
 * common_classify(packet, fid_table, slctrs_srchd)
 *
 * searches each of the common selectors
 * - will return NORMAL_MATCH on success.  NO_MATCHES on error
 */
static int
common_classify(ipgpc_packet_t *packet, ht_match_t *fid_table,
    uint16_t *slctrs_srchd)
{
	int match_status;

	/* Find on packet direction */
	match_status =
	    ipgpc_findfilters(IPGPC_TABLE_DIR, packet->direction, fid_table);
	if (CHECK_MATCH_STATUS(match_status, slctrs_srchd,
	    ipgpc_table_list[DIR_IDX].info.mask) != NORMAL_MATCH) {
		return (match_status);
	}

	/* Find on IF_INDEX of packet */
	match_status =
	    ipgpc_findfilters(IPGPC_TABLE_IF, packet->if_index, fid_table);
	if (CHECK_MATCH_STATUS(match_status, slctrs_srchd,
	    ipgpc_table_list[IF_IDX].info.mask) != NORMAL_MATCH) {
		return (match_status);
	}

	/* Find on DS field */
	match_status =
	    ipgpc_findfilters(IPGPC_BA_DSID, packet->dsfield, fid_table);
	if (CHECK_MATCH_STATUS(match_status, slctrs_srchd,
	    ipgpc_ds_table_id.info.mask) != NORMAL_MATCH) {
		return (match_status);
	}

	/* Find on UID of packet */
	match_status =
	    ipgpc_findfilters(IPGPC_TABLE_UID, packet->uid, fid_table);
	if (CHECK_MATCH_STATUS(match_status, slctrs_srchd,
	    ipgpc_table_list[UID_IDX].info.mask) != NORMAL_MATCH) {
		return (match_status);
	}

	/* Find on PROJID of packet */
	match_status =
	    ipgpc_findfilters(IPGPC_TABLE_PROJID, packet->projid, fid_table);
	if (CHECK_MATCH_STATUS(match_status, slctrs_srchd,
	    ipgpc_table_list[PROJID_IDX].info.mask) != NORMAL_MATCH) {
		return (match_status);
	}

	/* Find on IP Protocol field */
	if (packet->proto > 0) {
		match_status = ipgpc_findfilters(IPGPC_TABLE_PROTOID,
		    packet->proto, fid_table);
		if (CHECK_MATCH_STATUS(match_status, slctrs_srchd,
		    ipgpc_table_list[PROTOID_IDX].info.mask)
		    != NORMAL_MATCH) {
			return (match_status);
		}
	} else {
		/* skip search */
		*slctrs_srchd ^= ipgpc_table_list[PROTOID_IDX].info.mask;
	}

	/* Find on IP Source Port field */
	if (packet->sport > 0) {
		match_status = ipgpc_findfilters(IPGPC_TRIE_SPORTID,
		    packet->sport, fid_table);
		if (CHECK_MATCH_STATUS(match_status, slctrs_srchd,
		    ipgpc_trie_list[IPGPC_TRIE_SPORTID].info.mask)
		    != NORMAL_MATCH) {
			return (match_status);
		}
	} else {
		/* skip search */
		*slctrs_srchd ^= ipgpc_trie_list[IPGPC_TRIE_SPORTID].info.mask;
	}

	/* Find on IP Destination Port field */
	if (packet->dport > 0) {
		match_status = ipgpc_findfilters(IPGPC_TRIE_DPORTID,
		    packet->dport, fid_table);
		if (CHECK_MATCH_STATUS(match_status, slctrs_srchd,
		    ipgpc_trie_list[IPGPC_TRIE_DPORTID].info.mask)
		    != NORMAL_MATCH) {
			return (match_status);
		}
	} else {
		/* skip search */
		*slctrs_srchd ^= ipgpc_trie_list[IPGPC_TRIE_DPORTID].info.mask;
	}
	return (NORMAL_MATCH);
}

/*
 * update_stats(class_id, nbytes)
 *
 * if ipgpc_gather_stats == TRUE
 * updates the statistics for class pointed to be the input classid
 * and the global ipgpc kstats
 * updates the last time the class was matched with the current hrtime value,
 * number of packets and number of bytes with nbytes
 */
static void
update_stats(int class_id, uint_t nbytes)
{
	if (ipgpc_gather_stats) {
		/* update global stats */
		BUMP_STATS(ipgpc_npackets);
		UPDATE_STATS(ipgpc_nbytes, nbytes);
		if (ipgpc_cid_list[class_id].aclass.gather_stats) {
			/* update per class stats */
			SET_STATS(ipgpc_cid_list[class_id].stats.last_match,
			    gethrtime());
			BUMP_STATS(ipgpc_cid_list[class_id].stats.npackets);
			UPDATE_STATS(ipgpc_cid_list[class_id].stats.nbytes,
			    nbytes);
		}
	}
}

/*
 * FREE_FID_TABLE(fid_table, p, q, i)
 *
 * searches fid_table for dynamically allocated memory and frees it
 * p, q, i are temps
 */
#define	FREE_FID_TABLE(fid_table, p, q, i)				\
	/* free all allocated memory in fid_table */			\
	for (i = 0; i < HASH_SIZE; ++i) {				\
		if (fid_table[i].next != NULL) {			\
			p = fid_table[i].next;				\
			while (p != NULL) {				\
				q = p;					\
				p = p->next;				\
				kmem_cache_free(ht_match_cache, q);	\
			}						\
		}							\
	}


/*
 * ipgpc_classify(af, packet)
 *
 * The function that drives the packet classification algorithm.  Given a
 * address family (either AF_INET or AF_INET6) the input packet structure
 * is matched against all the selector structures.  For each search of
 * a selector structure, all matched filters are collected.  Once all
 * selectors are searched, the best match of all matched filters is
 * determined.  Finally, the class associated with the best matching filter
 * is returned.  If no filters were matched, the default class is returned.
 * If a memory error occurred, NULL is returned.
 */
ipgpc_class_t *
ipgpc_classify(int af, ipgpc_packet_t *packet)
{
	int match_status;
	uint16_t slctrs_srchd;
	int class_id;
	ht_match_t fid_table[HASH_SIZE];
	ht_match_t *p, *q;
	int i;
	int rc;

	if (ipgpc_num_fltrs == 0) {
		/* zero filters are loaded, return default class */
		update_stats(ipgpc_def_class_id, packet->len);
		/*
		 * no need to free fid_table. Since zero selectors were
		 * searched and dynamic memory wasn't allocated.
		 */
		return (&ipgpc_cid_list[ipgpc_def_class_id].aclass);
	}

	match_status = 0;
	slctrs_srchd = ALL_MATCH_MASK;
	bzero(fid_table, sizeof (ht_match_t) * HASH_SIZE);

	/* first search all address family independent selectors */
	rc = common_classify(packet, fid_table, &slctrs_srchd);
	if (rc != NORMAL_MATCH) {
		/* free all dynamic allocated memory */
		FREE_FID_TABLE(fid_table, p, q, i);
		if (rc == NO_MATCHES) {
			update_stats(ipgpc_def_class_id, packet->len);
			return (&ipgpc_cid_list[ipgpc_def_class_id].aclass);
		} else {	/* memory error */
			return (NULL);
		}
	}

	switch (af) {		/* switch off of address family */
	case AF_INET:
		/* Find on IPv4 Source Address field */
		match_status = ipgpc_findfilters(IPGPC_TRIE_SADDRID,
		    V4_PART_OF_V6(packet->saddr), fid_table);
		if (CHECK_MATCH_STATUS(match_status, &slctrs_srchd,
		    ipgpc_trie_list[IPGPC_TRIE_SADDRID].info.mask)
		    != NORMAL_MATCH) {
			/* free all dynamic allocated memory */
			FREE_FID_TABLE(fid_table, p, q, i);
			if (match_status == NO_MATCHES) {
				update_stats(ipgpc_def_class_id, packet->len);
				return (&ipgpc_cid_list[ipgpc_def_class_id].
				    aclass);
			} else { /* memory error */
				return (NULL);
			}
		}
		/* Find on IPv4 Destination Address field */
		match_status = ipgpc_findfilters(IPGPC_TRIE_DADDRID,
		    V4_PART_OF_V6(packet->daddr), fid_table);
		if (CHECK_MATCH_STATUS(match_status, &slctrs_srchd,
		    ipgpc_trie_list[IPGPC_TRIE_DADDRID].info.mask)
		    != NORMAL_MATCH) {
			/* free all dynamic allocated memory */
			FREE_FID_TABLE(fid_table, p, q, i);
			if (match_status == NO_MATCHES) {
				update_stats(ipgpc_def_class_id, packet->len);
				return (&ipgpc_cid_list[ipgpc_def_class_id].
				    aclass);
			} else { /* memory error */
				return (NULL);
			}
		}
		break;
	case AF_INET6:
		/* Find on IPv6 Source Address field */
		match_status = ipgpc_findfilters6(IPGPC_TRIE_SADDRID6,
		    packet->saddr, fid_table);
		if (CHECK_MATCH_STATUS(match_status, &slctrs_srchd,
		    ipgpc_trie_list[IPGPC_TRIE_SADDRID6].info.mask)
		    != NORMAL_MATCH) {
			/* free all dynamic allocated memory */
			FREE_FID_TABLE(fid_table, p, q, i);
			if (match_status == NO_MATCHES) {
				update_stats(ipgpc_def_class_id, packet->len);
				return (&ipgpc_cid_list[ipgpc_def_class_id].
				    aclass);
			} else { /* memory error */
				return (NULL);
			}
		}
		/* Find on IPv6 Destination Address field */
		match_status = ipgpc_findfilters6(IPGPC_TRIE_DADDRID6,
		    packet->daddr, fid_table);
		if (CHECK_MATCH_STATUS(match_status, &slctrs_srchd,
		    ipgpc_trie_list[IPGPC_TRIE_DADDRID6].info.mask)
		    != NORMAL_MATCH) {
			/* free all dynamic allocated memory */
			FREE_FID_TABLE(fid_table, p, q, i);
			if (match_status == NO_MATCHES) {
				update_stats(ipgpc_def_class_id, packet->len);
				return (&ipgpc_cid_list[ipgpc_def_class_id].
				    aclass);
			} else {
				return (NULL);
			}
		}
		break;
	default:
		ipgpc0dbg(("ipgpc_classify(): Unknown Address Family"));
		/* free all dynamic allocated memory */
		FREE_FID_TABLE(fid_table, p, q, i);
		return (NULL);
	}

	/* zero selectors were searched, return default */
	if (slctrs_srchd == 0) {
		/*
		 * no need to free fid_table.  Since zero selectors were
		 * searched and dynamic memory wasn't allocated
		 */
		update_stats(ipgpc_def_class_id, packet->len);
		return (&ipgpc_cid_list[ipgpc_def_class_id].aclass);
	}

	/* Perform best match search */
	class_id = bestmatch(fid_table, slctrs_srchd);
	/* free all dynamic allocated memory */
	FREE_FID_TABLE(fid_table, p, q, i);

	update_stats(class_id, packet->len);
	return (&ipgpc_cid_list[class_id].aclass);
}

/*
 * bestmatch(fid_table, bestmask)
 *
 * determines the bestmatching filter in fid_table which matches the criteria
 * described below and returns the class id
 */
static int
bestmatch(ht_match_t *fid_table, uint16_t bestmask)
{
	int i, key;
	int bestmatch = -1;
	int oldbm = -1;
	uint32_t temp_prec;
	uint32_t temp_prio;
	uint64_t best_prio;
	uint64_t real_prio;
	ht_match_t *item;

	for (i = 0; i < HASH_SIZE; ++i) {
		if (fid_table[i].key == 0) {
			continue;
		}
		for (item = &fid_table[i]; item != NULL; item = item->next) {
			/*
			 * BESTMATCH is:
			 * 1. Matches in all selectors searched
			 * 2. highest priority of filters that meet 1.
			 * 3. best precedence of filters that meet 2
			 *    with the same priority
			 */
			if ((key = item->key) == 0) {
				continue;
			}
			if (ipgpc_fid_list[key].info <= 0) {
				continue;
			}

			/*
			 * check to see if fid has been inserted into a
			 * selector structure we did not search
			 * if so, then this filter is not a valid match
			 * and bestmatch() should continue
			 * this statement will == 0
			 * - a selector has been searched and this filter
			 *   either describes don't care or has inserted a
			 *   value into this selector structure
			 * - a selector has not been searched and this filter
			 *   has described don't care for this selector
			 */
			if (((~bestmask) & ipgpc_fid_list[key].insert_map)
			    != 0) {
				continue;
			}

			/*
			 * tests to see if the map of selectors that
			 * were matched, equals the map of selectors
			 * structures this filter inserts into
			 */
			if (item->match_map != ipgpc_fid_list[key].insert_map) {
				continue;
			}

			if (bestmatch == -1) { /* first matching filter */
				/* this filter becomes the bestmatch */
				temp_prio =
				    ipgpc_fid_list[key].filter.priority;
				temp_prec =
				    ipgpc_fid_list[key].filter.precedence;
				best_prio = ((uint64_t)temp_prio << 32) |
				    (uint64_t)~temp_prec;
				bestmatch = key;
				continue;
			}

			/*
			 * calculate the real priority by combining priority
			 * and precedence
			 */
			real_prio =
			    ((uint64_t)ipgpc_fid_list[key].filter.priority
			    << 32) |
			    (uint64_t)~ipgpc_fid_list[key].filter.precedence;

			/* check to see if this is the new bestmatch */
			if (real_prio > best_prio) {
				oldbm = bestmatch;
				ipgpc3dbg(("bestmatch: filter %s " \
				    "REJECTED because of better priority %d" \
				    " and/or precedence %d",
				    ipgpc_fid_list[oldbm].filter.filter_name,
				    ipgpc_fid_list[oldbm].filter.priority,
				    ipgpc_fid_list[oldbm].filter.precedence));
				best_prio = real_prio;
				bestmatch = key;
			} else {
				ipgpc3dbg(("bestmatch: filter %s " \
				    "REJECTED because of beter priority %d" \
				    " and/or precedence %d",
				    ipgpc_fid_list[key].filter.filter_name,
				    ipgpc_fid_list[key].filter.priority,
				    ipgpc_fid_list[key].filter.precedence));
			}
		}
	}
	if (bestmatch == -1) {	/* no best matches were found */
		ipgpc3dbg(("bestmatch: No filters ACCEPTED"));
		return (ipgpc_def_class_id);
	} else {
		ipgpc3dbg(("bestmatch: filter %s ACCEPTED with priority %d " \
		    "and precedence %d",
		    ipgpc_fid_list[bestmatch].filter.filter_name,
		    ipgpc_fid_list[bestmatch].filter.priority,
		    ipgpc_fid_list[bestmatch].filter.precedence));
		return (ipgpc_fid_list[bestmatch].class_id);
	}
}

/*
 * get_port_info(packet, iph, af, mp)
 *
 * Gets the source and destination ports from the ULP header, if present.
 * If this is a fragment, don't try to get the port information even if this
 * is the first fragment. The reason being we won't have this information
 * in subsequent fragments and may end up classifying the first fragment
 * differently than others. This is not desired.
 * For IPv6 packets, step through the extension headers, if present, in
 * order to get to the ULP header.
 */
static void
get_port_info(ipgpc_packet_t *packet, void *iph, int af, mblk_t *mp)
{
	uint16_t *up;

	if (af == AF_INET) {
		uint32_t u2, u1;
		uint_t iplen;
		ipha_t *ipha = (ipha_t *)iph;

		u2 = ntohs(ipha->ipha_fragment_offset_and_flags);
		u1 = u2 & (IPH_MF | IPH_OFFSET);
		if (u1) {
			return;
		}
		iplen = (ipha->ipha_version_and_hdr_length & 0xF) << 2;
		up = (uint16_t *)(mp->b_rptr + iplen);
		packet->sport = (uint16_t)*up++;
		packet->dport = (uint16_t)*up;
	} else {	/* AF_INET6 */
		uint_t  length = IPV6_HDR_LEN;
		ip6_t *ip6h = (ip6_t *)iph;
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
				/* Get the protocol and the ports */
				packet->proto = *nexthdrp;
				up = (uint16_t *)((uchar_t *)ip6h + length);
				packet->sport = (uint16_t)*up++;
				packet->dport = (uint16_t)*up;
				return;
			case IPPROTO_ICMPV6:
			case IPPROTO_ENCAP:
			case IPPROTO_IPV6:
			case IPPROTO_ESP:
			case IPPROTO_AH:
				packet->proto = *nexthdrp;
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
 * find_ids(packet, mp)
 *
 * attempt to discern the uid and projid of the originator of a packet by
 * looking at the dblks making up the packet - yeuch!
 *
 * We do it by skipping any fragments with a credp of NULL (originated in
 * kernel), taking the first value that isn't NULL to be the credp for the
 * whole packet. We also suck the projid from the same fragment.
 */
static void
find_ids(ipgpc_packet_t *packet, mblk_t *mp)
{
	cred_t *cr;

	while (DB_CRED(mp) == NULL && mp->b_cont != NULL)
		mp = mp->b_cont;

	if ((cr = DB_CRED(mp)) != NULL) {
		packet->uid = crgetuid(cr);
		packet->projid = crgetprojid(cr);
	} else {
		packet->uid = (uid_t)-1;
		packet->projid = -1;
	}
}

/*
 * parse_packet(packet, mp)
 *
 * parses the given message block into a ipgpc_packet_t structure
 */
void
parse_packet(ipgpc_packet_t *packet, mblk_t *mp)
{
	ipha_t	*ipha;

	/* parse message block for IP header and ports */
	ipha = (ipha_t *)mp->b_rptr; /* get ip header */
	V4_PART_OF_V6(packet->saddr) = (int32_t)ipha->ipha_src;
	V4_PART_OF_V6(packet->daddr) = (int32_t)ipha->ipha_dst;
	packet->dsfield = ipha->ipha_type_of_service;
	packet->proto = ipha->ipha_protocol;
	packet->sport = 0;
	packet->dport = 0;
	find_ids(packet, mp);
	packet->len = msgdsize(mp);
	/* parse out TCP/UDP ports, if appropriate */
	if ((packet->proto == IPPROTO_TCP) || (packet->proto == IPPROTO_UDP) ||
	    (packet->proto == IPPROTO_SCTP)) {
		get_port_info(packet, ipha, AF_INET, mp);
	}
}

/*
 * parse_packet6(packet, mp)
 *
 * parses the message block into a ipgpc_packet_t structure for IPv6 traffic
 */
void
parse_packet6(ipgpc_packet_t *packet, mblk_t *mp)
{
	ip6_t *ip6h = (ip6_t *)mp->b_rptr;

	/* parse message block for IP header and ports */
	bcopy(ip6h->ip6_src.s6_addr32, packet->saddr.s6_addr32,
	    sizeof (ip6h->ip6_src.s6_addr32));
	bcopy(ip6h->ip6_dst.s6_addr32, packet->daddr.s6_addr32,
	    sizeof (ip6h->ip6_dst.s6_addr32));
	/* Will be (re-)assigned in get_port_info */
	packet->proto = ip6h->ip6_nxt;
	packet->dsfield = __IPV6_TCLASS_FROM_FLOW(ip6h->ip6_vcf);
	find_ids(packet, mp);
	packet->len = msgdsize(mp);
	packet->sport = 0;
	packet->dport = 0;
	/* Need to pullup everything. */
	if (mp->b_cont != NULL) {
		if (!pullupmsg(mp, -1)) {
			ipgpc0dbg(("parse_packet6(): pullup error, can't " \
			    "find ports"));
			return;
		}
		ip6h = (ip6_t *)mp->b_rptr;
	}
	get_port_info(packet, ip6h, AF_INET6, mp);
}

#ifdef	IPGPC_DEBUG
/*
 * print_packet(af, packet)
 *
 * prints the contents of the packet structure for specified address family
 */
void
print_packet(int af, ipgpc_packet_t *pkt)
{
	char saddrbuf[INET6_ADDRSTRLEN];
	char daddrbuf[INET6_ADDRSTRLEN];

	if (af == AF_INET) {
		(void) inet_ntop(af, &V4_PART_OF_V6(pkt->saddr), saddrbuf,
		    sizeof (saddrbuf));
		(void) inet_ntop(af, &V4_PART_OF_V6(pkt->daddr), daddrbuf,
		    sizeof (daddrbuf));

		ipgpc4dbg(("print_packet: saddr = %s, daddr = %s, sport = %u" \
		    ", dport = %u, proto = %u, dsfield = %x, uid = %d," \
		    " if_index = %d, projid = %d, direction = %d", saddrbuf,
		    daddrbuf, ntohs(pkt->sport), ntohs(pkt->dport), pkt->proto,
		    pkt->dsfield, pkt->uid, pkt->if_index,
		    pkt->projid, pkt->direction));
	} else if (af == AF_INET6) {
		(void) inet_ntop(af, pkt->saddr.s6_addr32, saddrbuf,
		    sizeof (saddrbuf));
		(void) inet_ntop(af, pkt->daddr.s6_addr32, daddrbuf,
		    sizeof (daddrbuf));

		ipgpc4dbg(("print_packet: saddr = %s, daddr = %s, sport = %u" \
		    ", dport = %u, proto = %u, dsfield = %x, uid = %d," \
		    " if_index = %d, projid = %d, direction = %d", saddrbuf,
		    daddrbuf, ntohs(pkt->sport), ntohs(pkt->dport), pkt->proto,
		    pkt->dsfield, pkt->uid, pkt->if_index,
		    pkt->projid, pkt->direction));
	}
}
#endif /* IPGPC_DEBUG */
