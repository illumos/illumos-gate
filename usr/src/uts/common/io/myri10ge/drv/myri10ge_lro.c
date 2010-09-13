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
 * Copyright 2007-2009 Myricom, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef lint
static const char __idstring[] =
	"@(#)$Id: myri10ge_lro.c,v 1.7 2009-06-29 13:47:22 gallatin Exp $";
#endif

#include "myri10ge_var.h"

#define	IP_OFFMASK 0x1fff
#define	TCPOPT_TIMESTAMP 8
#define	TCPOLEN_TIMESTAMP 10
#define	TCPOLEN_TSTAMP_APPA 12


/*
 * Assume len is a multiple of 4. Note that "raw" must be
 * suitably aligned. In practice, it will always enter algned on
 * at least a 4 bytes bounday, due to the alignment of our rx buffers.
 */
uint16_t
myri10ge_csum_generic(uint16_t *raw, int len)
{
	uint32_t csum;
	csum = 0;
	while (len > 0) {
		csum += *raw;
		raw++;
		csum += *raw;
		raw++;
		len -= 4;
	}
	csum = (csum >> 16) + (csum & 0xffff);
	csum = (csum >> 16) + (csum & 0xffff);
	return ((uint16_t)csum);
}

static uint16_t
myri10ge_in_pseudo(unsigned int a, unsigned int b,
    unsigned int c)
{
	uint64_t csum;

	csum = (uint64_t)a + b + c;
	csum = (csum >> 16) + (csum & 0xffff);
	csum = (csum >> 16) + (csum & 0xffff);
	return ((uint16_t)csum);
}

void
myri10ge_lro_flush(struct myri10ge_slice_state *ss, struct lro_entry *lro,
	struct myri10ge_mblk_list *mbl)
{
	struct ip *ip;
	struct tcphdr *tcp;
	uint32_t *ts_ptr;
	uint32_t tcplen, tcp_csum;

	if (lro->append_cnt) {
		/*
		 * incorporate the new len into the ip header and
		 * re-calculate the checksum
		 */
		ip = lro->ip;
		ip->ip_len = htons(lro->len - ETHERNET_HEADER_SIZE);
		ip->ip_sum = 0;
		ip->ip_sum = 0xffff ^
		    myri10ge_csum_generic((uint16_t *)ip, sizeof (*ip));
		/* incorporate the latest ack into the tcp header */
		tcp = (struct tcphdr *)(ip + 1);
		tcp->th_ack = lro->ack_seq;
		tcp->th_win = lro->window;
		tcp->th_flags = lro->flags;
		/* incorporate latest timestamp into the tcp header */
		if (lro->timestamp) {
			ts_ptr = (uint32_t *)(tcp + 1);
			ts_ptr[1] = htonl(lro->tsval);
			ts_ptr[2] = lro->tsecr;
		}
		/*
		 * update checksum in tcp header by re-calculating the
		 * tcp pseudoheader checksum, and adding it to the checksum
		 * of the tcp payload data
		 */
		tcp->th_sum = 0;
		tcplen = lro->len - sizeof (*ip) - ETHERNET_HEADER_SIZE;
		tcp_csum = lro->data_csum;
		tcp_csum += myri10ge_in_pseudo(ip->ip_src.s_addr,
		    ip->ip_dst.s_addr, htons(tcplen + IPPROTO_TCP));
		tcp_csum += myri10ge_csum_generic((uint16_t *)tcp,
		    tcp->th_off << 2);
		tcp_csum = (tcp_csum & 0xffff) + (tcp_csum >> 16);
		tcp_csum = (tcp_csum & 0xffff) + (tcp_csum >> 16);
		tcp->th_sum = 0xffff ^ tcp_csum;
	}

	mac_hcksum_set(lro->m_head, 0, 0, 0,
	    0, HCK_IPV4_HDRCKSUM_OK | HCK_FULLCKSUM_OK);

	mbl->cnt += lro->append_cnt;
	myri10ge_mbl_append(ss, mbl, lro->m_head);
	MYRI10GE_SLICE_STAT_INC(lro_flushed);
	MYRI10GE_SLICE_STAT_ADD(lro_queued, lro->append_cnt + 1);
	lro->m_head = NULL;
	lro->timestamp = 0;
	lro->append_cnt = 0;
	lro->next = ss->lro_free;
	ss->lro_free = lro;
}

int
myri10ge_lro_rx(struct myri10ge_slice_state *ss, mblk_t *m_head,
		uint32_t csum, struct myri10ge_mblk_list *mbl)
{
	struct ether_header *eh;
	struct ip *ip;
	struct tcphdr *tcp;
	uint32_t *ts_ptr;
	struct lro_entry *lro, *curr;
	int hlen, ip_len, tcp_hdr_len, tcp_data_len;
	int opt_bytes, trim;
	int tot_len = MBLKL(m_head);
	uint32_t seq, tmp_csum;

	eh = (struct ether_header *)(void *)m_head->b_rptr;
	if (eh->ether_type != htons(ETHERTYPE_IP))
		return (EINVAL);
	ip = (struct ip *)(void *)(eh + 1);
	if (ip->ip_p != IPPROTO_TCP)
		return (EINVAL);

	/* ensure there are no options */
	if ((ip->ip_hl << 2) != sizeof (*ip))
		return (EINVAL);

	/* .. and the packet is not fragmented */
	if (ip->ip_off & htons(IP_MF|IP_OFFMASK))
		return (EINVAL);

	/* verify that the IP header checksum is correct */
	tmp_csum = myri10ge_csum_generic((uint16_t *)ip, sizeof (*ip));
	if (unlikely((tmp_csum ^ 0xffff) != 0)) {
		MYRI10GE_SLICE_STAT_INC(lro_bad_csum);
		return (EINVAL);
	}

	/* find the TCP header */
	tcp = (struct tcphdr *)(ip + 1);

	/* ensure no bits set besides ack or psh */
	if ((tcp->th_flags & ~(TH_ACK | TH_PUSH)) != 0)
		return (EINVAL);

	/*
	 * check for timestamps. Since the only option we handle are
	 * timestamps, we only have to handle the simple case of
	 * aligned timestamps
	 */

	opt_bytes = (tcp->th_off << 2) - sizeof (*tcp);
	tcp_hdr_len =  sizeof (*tcp) + opt_bytes;
	ts_ptr = (uint32_t *)(tcp + 1);
	if (opt_bytes != 0) {
		if (unlikely(opt_bytes != TCPOLEN_TSTAMP_APPA) ||
		    (*ts_ptr !=  ntohl(TCPOPT_NOP<<24|TCPOPT_NOP<<16|
		    TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)))
			return (EINVAL);
	}

	ip_len = ntohs(ip->ip_len);
	tcp_data_len = ip_len - (tcp->th_off << 2) - sizeof (*ip);

	/*
	 * If frame is padded beyond the end of the IP packet,
	 * then we must trim the extra bytes off the end.
	 */
	trim = tot_len - (ip_len + ETHERNET_HEADER_SIZE);
	if (trim != 0) {
		if (trim < 0) {
			/* truncated packet */
			return (EINVAL);
		}
		m_head->b_wptr -= trim;
		tot_len -= trim;
	}

	/* Verify TCP checksum */
	csum = ntohs((uint16_t)csum);
	tmp_csum = csum + myri10ge_in_pseudo(ip->ip_src.s_addr,
	    ip->ip_dst.s_addr, htons(tcp_hdr_len + tcp_data_len + IPPROTO_TCP));
	tmp_csum = (tmp_csum & 0xffff) + (tmp_csum >> 16);
	tmp_csum = (tmp_csum & 0xffff) + (tmp_csum >> 16);
	if (tmp_csum != 0xffff) {
		MYRI10GE_SLICE_STAT_INC(lro_bad_csum);
		return (EINVAL);
	}

	hlen = ip_len + ETHERNET_HEADER_SIZE - tcp_data_len;
	seq = ntohl(tcp->th_seq);

	for (lro = ss->lro_active; lro != NULL; lro = lro->next) {
		if (lro->source_port == tcp->th_sport &&
		    lro->dest_port == tcp->th_dport &&
		    lro->source_ip == ip->ip_src.s_addr &&
		    lro->dest_ip == ip->ip_dst.s_addr) {
			/* Try to append it */

			if (unlikely(seq != lro->next_seq)) {
				/* out of order packet */
				if (ss->lro_active == lro) {
					ss->lro_active = lro->next;
				} else {
					curr = ss->lro_active;
					while (curr->next != lro)
						curr = curr->next;
					curr->next = lro->next;
				}
				myri10ge_lro_flush(ss, lro, mbl);
				return (EINVAL);
			}

			if (opt_bytes) {
				uint32_t tsval = ntohl(*(ts_ptr + 1));
				/* make sure timestamp values are increasing */
				if (unlikely(lro->tsval > tsval ||
				    *(ts_ptr + 2) == 0)) {
					return (-8);
				}
				lro->tsval = tsval;
				lro->tsecr = *(ts_ptr + 2);
			}

			lro->next_seq += tcp_data_len;
			lro->ack_seq = tcp->th_ack;
			lro->window = tcp->th_win;
			lro->flags |= tcp->th_flags;
			lro->append_cnt++;
			if (tcp_data_len == 0) {
				freeb(m_head);
				return (0);
			}
			/*
			 * subtract off the checksum of the tcp header
			 * from the hardware checksum, and add it to
			 * the stored tcp data checksum.  Byteswap
			 * the checksum if the total length so far is
			 * odd
			 */
			tmp_csum = myri10ge_csum_generic((uint16_t *)tcp,
			    tcp_hdr_len);
			csum = csum + (tmp_csum ^ 0xffff);
			csum = (csum & 0xffff) + (csum >> 16);
			csum = (csum & 0xffff) + (csum >> 16);
			if (lro->len & 0x1) {
				/* Odd number of bytes so far, flip bytes */
				csum = ((csum << 8) | (csum >> 8)) & 0xffff;
			}
			csum = csum + lro->data_csum;
			csum = (csum & 0xffff) + (csum >> 16);
			csum = (csum & 0xffff) + (csum >> 16);
			lro->data_csum = csum;

			lro->len += tcp_data_len;

			/*
			 * adjust mblk so that rptr points to
			 * the first byte of the payload
			 */
			m_head->b_rptr += hlen;
			/* append mbuf chain */
			lro->m_tail->b_cont = m_head;
			/* advance the last pointer */
			lro->m_tail = m_head;
			/* flush packet if required */
			if (lro->len > (65535 - myri10ge_mtu) ||
			    (lro->append_cnt + 1) == myri10ge_lro_max_aggr) {
				if (ss->lro_active == lro) {
					ss->lro_active = lro->next;
				} else {
					curr = ss->lro_active;
					while (curr->next != lro)
						curr = curr->next;
					curr->next = lro->next;
				}
				myri10ge_lro_flush(ss, lro, mbl);
			}
			return (0);
		}
	}

	if (ss->lro_free == NULL)
		return (ENOMEM);

	/* start a new chain */
	lro = ss->lro_free;
	ss->lro_free = lro->next;
	lro->next = ss->lro_active;
	ss->lro_active = lro;
	lro->source_port = tcp->th_sport;
	lro->dest_port = tcp->th_dport;
	lro->source_ip = ip->ip_src.s_addr;
	lro->dest_ip = ip->ip_dst.s_addr;
	lro->next_seq = seq + tcp_data_len;
	lro->mss = (uint16_t)tcp_data_len;
	lro->ack_seq = tcp->th_ack;
	lro->window = tcp->th_win;
	lro->flags = tcp->th_flags;

	/*
	 * save the checksum of just the TCP payload by
	 * subtracting off the checksum of the TCP header from
	 * the entire hardware checksum
	 * Since IP header checksum is correct, checksum over
	 * the IP header is -0.  Substracting -0 is unnecessary.
	 */
	tmp_csum = myri10ge_csum_generic((uint16_t *)tcp, tcp_hdr_len);
	csum = csum + (tmp_csum ^ 0xffff);
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	lro->data_csum = csum;
	lro->ip = ip;

	/* record timestamp if it is present */
	if (opt_bytes) {
		lro->timestamp = 1;
		lro->tsval = ntohl(*(ts_ptr + 1));
		lro->tsecr = *(ts_ptr + 2);
	}
	lro->len = tot_len;
	lro->m_head = m_head;
	lro->m_tail = m_head;
	return (0);
}

/*
 *  This file uses MyriGE driver indentation.
 *
 * Local Variables:
 * c-file-style:"sun"
 * tab-width:8
 * End:
 */
