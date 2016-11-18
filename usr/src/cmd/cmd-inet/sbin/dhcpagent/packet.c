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
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <dhcpmsg.h>
#include <stddef.h>
#include <assert.h>
#include <search.h>
#include <alloca.h>
#include <limits.h>
#include <stropts.h>
#include <netinet/dhcp6.h>
#include <arpa/inet.h>
#include <sys/sysmacros.h>
#include <sys/sockio.h>
#include <inet/ip6_asp.h>

#include "states.h"
#include "interface.h"
#include "agent.h"
#include "packet.h"
#include "util.h"

int v6_sock_fd = -1;
int v4_sock_fd = -1;

const in6_addr_t ipv6_all_dhcp_relay_and_servers = {
	0xff, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x02
};

/*
 * We have our own version of this constant because dhcpagent is compiled with
 * -lxnet.
 */
const in6_addr_t my_in6addr_any = IN6ADDR_ANY_INIT;

static void 	retransmit(iu_tq_t *, void *);
static void	next_retransmission(dhcp_smach_t *, boolean_t, boolean_t);
static boolean_t send_pkt_internal(dhcp_smach_t *);

/*
 * pkt_send_type(): returns an integer representing the packet's type; only
 *		    for use with outbound packets.
 *
 *   input: dhcp_pkt_t *: the packet to examine
 *  output: uchar_t: the packet type (0 if unknown)
 */

static uchar_t
pkt_send_type(const dhcp_pkt_t *dpkt)
{
	const uchar_t *option;

	if (dpkt->pkt_isv6)
		return (((const dhcpv6_message_t *)dpkt->pkt)->d6m_msg_type);

	/*
	 * this is a little dirty but it should get the job done.
	 * assumes that the type is in the statically allocated part
	 * of the options field.
	 */

	option = dpkt->pkt->options;
	for (;;) {
		if (*option == CD_PAD) {
			option++;
			continue;
		}
		if (*option == CD_END ||
		    option + 2 - dpkt->pkt->options >=
		    sizeof (dpkt->pkt->options))
			return (0);
		if (*option == CD_DHCP_TYPE)
			break;
		option++;
		option += *option + 1;
	}

	return (option[2]);
}

/*
 * pkt_recv_type(): returns an integer representing the packet's type; only
 *		    for use with inbound packets.
 *
 *   input: dhcp_pkt_t *: the packet to examine
 *  output: uchar_t: the packet type (0 if unknown)
 */

uchar_t
pkt_recv_type(const PKT_LIST *plp)
{
	if (plp->isv6)
		return (((const dhcpv6_message_t *)plp->pkt)->d6m_msg_type);
	else if (plp->opts[CD_DHCP_TYPE] != NULL)
		return (plp->opts[CD_DHCP_TYPE]->value[0]);
	else
		return (0);
}

/*
 * pkt_get_xid(): returns transaction ID from a DHCP packet.
 *
 *   input: const PKT *: the packet to examine
 *  output: uint_t: the transaction ID (0 if unknown)
 */

uint_t
pkt_get_xid(const PKT *pkt, boolean_t isv6)
{
	if (pkt == NULL)
		return (0);
	if (isv6)
		return (DHCPV6_GET_TRANSID((const dhcpv6_message_t *)pkt));
	else
		return (pkt->xid);
}

/*
 * init_pkt(): initializes and returns a packet of a given type
 *
 *   input: dhcp_smach_t *: the state machine that will send the packet
 *	    uchar_t: the packet type (DHCP message type)
 *  output: dhcp_pkt_t *: a pointer to the initialized packet; may be NULL
 */

dhcp_pkt_t *
init_pkt(dhcp_smach_t *dsmp, uchar_t type)
{
	dhcp_pkt_t	*dpkt = &dsmp->dsm_send_pkt;
	dhcp_lif_t	*lif = dsmp->dsm_lif;
	dhcp_pif_t	*pif = lif->lif_pif;
	uint_t		mtu = lif->lif_max;
	uint32_t	xid;
	boolean_t	isv6;

	dpkt->pkt_isv6 = isv6 = pif->pif_isv6;

	/*
	 * Since multiple dhcp leases may be maintained over the same pif
	 * (e.g. "hme0" and "hme0:1"), make sure the xid is unique.
	 *
	 * Note that transaction ID zero is intentionally never assigned.
	 * That's used to represent "no ID."  Also note that transaction IDs
	 * are only 24 bits long in DHCPv6.
	 */

	do {
		xid = mrand48();
		if (isv6)
			xid &= 0xFFFFFF;
	} while (xid == 0 ||
	    lookup_smach_by_xid(xid, NULL, dpkt->pkt_isv6) != NULL);

	if (isv6) {
		dhcpv6_message_t *v6;

		if (mtu != dpkt->pkt_max_len &&
		    (v6 = realloc(dpkt->pkt, mtu)) != NULL) {
			/* LINTED: alignment known to be correct */
			dpkt->pkt = (PKT *)v6;
			dpkt->pkt_max_len = mtu;
		}

		if (sizeof (*v6) > dpkt->pkt_max_len) {
			dhcpmsg(MSG_ERR, "init_pkt: cannot allocate v6 pkt: %u",
			    mtu);
			return (NULL);
		}

		v6 = (dhcpv6_message_t *)dpkt->pkt;
		dpkt->pkt_cur_len = sizeof (*v6);

		(void) memset(v6, 0, dpkt->pkt_max_len);

		v6->d6m_msg_type = type;
		DHCPV6_SET_TRANSID(v6, xid);

		if (dsmp->dsm_cidlen > 0 &&
		    add_pkt_opt(dpkt, DHCPV6_OPT_CLIENTID, dsmp->dsm_cid,
		    dsmp->dsm_cidlen) == NULL) {
			dhcpmsg(MSG_WARNING,
			    "init_pkt: cannot insert client ID");
			return (NULL);
		}

		/* For v6, time starts with the creation of a transaction */
		dsmp->dsm_neg_hrtime = gethrtime();
		dsmp->dsm_newstart_monosec = monosec();
	} else {
		static uint8_t bootmagic[] = BOOTMAGIC;
		PKT *v4;

		if (mtu != dpkt->pkt_max_len &&
		    (v4 = realloc(dpkt->pkt, mtu)) != NULL) {
			dpkt->pkt = v4;
			dpkt->pkt_max_len = mtu;
		}

		if (offsetof(PKT, options) > dpkt->pkt_max_len) {
			dhcpmsg(MSG_ERR, "init_pkt: cannot allocate v4 pkt: %u",
			    mtu);
			return (NULL);
		}

		v4 = dpkt->pkt;
		dpkt->pkt_cur_len = offsetof(PKT, options);

		(void) memset(v4, 0, dpkt->pkt_max_len);
		(void) memcpy(v4->cookie, bootmagic, sizeof (bootmagic));
		if (pif->pif_hwlen <= sizeof (v4->chaddr)) {
			v4->hlen  = pif->pif_hwlen;
			(void) memcpy(v4->chaddr, pif->pif_hwaddr,
			    pif->pif_hwlen);
		} else {
			/*
			 * The mac address does not fit in the chaddr
			 * field, thus it can not be sent to the server,
			 * thus server can not unicast the reply. Per
			 * RFC 2131 4.4.1, client can set this bit in
			 * DISCOVER/REQUEST. If the client is already
			 * in a bound state, do not set this bit, as it
			 * can respond to unicast responses from server
			 * using the 'ciaddr' address.
			 */
			if (type == DISCOVER || (type == REQUEST &&
			    !is_bound_state(dsmp->dsm_state)))
				v4->flags = htons(BCAST_MASK);
		}

		v4->xid   = xid;
		v4->op    = BOOTREQUEST;
		v4->htype = pif->pif_hwtype;

		if (add_pkt_opt(dpkt, CD_DHCP_TYPE, &type, 1) == NULL) {
			dhcpmsg(MSG_WARNING,
			    "init_pkt: cannot set DHCP packet type");
			return (NULL);
		}

		if (dsmp->dsm_cidlen > 0 &&
		    add_pkt_opt(dpkt, CD_CLIENT_ID, dsmp->dsm_cid,
		    dsmp->dsm_cidlen) == NULL) {
			dhcpmsg(MSG_WARNING,
			    "init_pkt: cannot insert client ID");
			return (NULL);
		}
	}

	return (dpkt);
}

/*
 * remove_pkt_opt(): removes the first instance of an option from a dhcp_pkt_t
 *
 *   input: dhcp_pkt_t *: the packet to remove the option from
 *	    uint_t: the type of option being added
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 *    note: currently does not work with DHCPv6 suboptions, or to remove
 *	    arbitrary option instances.
 */

boolean_t
remove_pkt_opt(dhcp_pkt_t *dpkt, uint_t opt_type)
{
	uchar_t		*raw_pkt, *raw_end, *next;
	uint_t		len;

	raw_pkt = (uchar_t *)dpkt->pkt;
	raw_end = raw_pkt + dpkt->pkt_cur_len;
	if (dpkt->pkt_isv6) {
		dhcpv6_option_t d6o;

		raw_pkt += sizeof (dhcpv6_message_t);

		opt_type = htons(opt_type);
		while (raw_pkt + sizeof (d6o) <= raw_end) {
			(void) memcpy(&d6o, raw_pkt, sizeof (d6o));
			len = ntohs(d6o.d6o_len) + sizeof (d6o);
			if (len > raw_end - raw_pkt)
				break;
			next = raw_pkt + len;
			if (d6o.d6o_code == opt_type) {
				if (next < raw_end) {
					(void) memmove(raw_pkt, next,
					    raw_end - next);
				}
				dpkt->pkt_cur_len -= len;
				return (B_TRUE);
			}
			raw_pkt = next;
		}
	} else {
		uchar_t *pstart, *padrun;

		raw_pkt += offsetof(PKT, options);
		pstart = raw_pkt;

		if (opt_type == CD_END || opt_type == CD_PAD)
			return (B_FALSE);

		padrun = NULL;
		while (raw_pkt + 1 <= raw_end) {
			if (*raw_pkt == CD_END)
				break;
			if (*raw_pkt == CD_PAD) {
				if (padrun == NULL)
					padrun = raw_pkt;
				raw_pkt++;
				continue;
			}
			if (raw_pkt + 2 > raw_end)
				break;
			len = raw_pkt[1];
			if (len > raw_end - raw_pkt || len < 2)
				break;
			next = raw_pkt + len;
			if (*raw_pkt == opt_type) {
				if (next < raw_end) {
					int toadd = (4 + ((next-pstart)&3) -
					    ((raw_pkt-pstart)&3)) & 3;
					int torem = 4 - toadd;

					if (torem != 4 && padrun != NULL &&
					    (raw_pkt - padrun) >= torem) {
						raw_pkt -= torem;
						dpkt->pkt_cur_len -= torem;
					} else if (toadd > 0) {
						(void) memset(raw_pkt, CD_PAD,
						    toadd);
						raw_pkt += toadd;
						/* max is not an issue here */
						dpkt->pkt_cur_len += toadd;
					}
					if (raw_pkt != next) {
						(void) memmove(raw_pkt, next,
						    raw_end - next);
					}
				}
				dpkt->pkt_cur_len -= len;
				return (B_TRUE);
			}
			padrun = NULL;
			raw_pkt = next;
		}
	}
	return (B_FALSE);
}

/*
 * update_v6opt_len(): updates the length field of a DHCPv6 option.
 *
 *   input: dhcpv6_option_t *: option to be updated
 *	    int: number of octets to add or subtract
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */

boolean_t
update_v6opt_len(dhcpv6_option_t *opt, int adjust)
{
	dhcpv6_option_t optval;

	(void) memcpy(&optval, opt, sizeof (optval));
	adjust += ntohs(optval.d6o_len);
	if (adjust < 0 || adjust > UINT16_MAX) {
		return (B_FALSE);
	} else {
		optval.d6o_len = htons(adjust);
		(void) memcpy(opt, &optval, sizeof (optval));
		return (B_TRUE);
	}
}

/*
 * add_pkt_opt(): adds an option to a dhcp_pkt_t
 *
 *   input: dhcp_pkt_t *: the packet to add the option to
 *	    uint_t: the type of option being added
 *	    const void *: the value of that option
 *	    uint_t: the length of the value of the option
 *  output: void *: pointer to the option that was added, or NULL on failure.
 */

void *
add_pkt_opt(dhcp_pkt_t *dpkt, uint_t opt_type, const void *opt_val,
    uint_t opt_len)
{
	uchar_t		*raw_pkt;
	size_t		req_len;
	void		*optr;

	raw_pkt = (uchar_t *)dpkt->pkt;
	optr = raw_pkt + dpkt->pkt_cur_len;
	if (dpkt->pkt_isv6) {
		req_len = opt_len + sizeof (dhcpv6_option_t);

		if (dpkt->pkt_cur_len + req_len > dpkt->pkt_max_len) {
			dhcpmsg(MSG_WARNING,
			    "add_pkt_opt: not enough room for v6 option %u in "
			    "packet (%u + %u > %u)", opt_type,
			    dpkt->pkt_cur_len, req_len, dpkt->pkt_max_len);
			return (NULL);
		}
	} else {
		req_len = opt_len + DHCP_OPT_META_LEN;

		/* CD_END and CD_PAD options don't have a length field */
		if (opt_type == CD_END || opt_type == CD_PAD) {
			req_len = 1;
		} else if (opt_val == NULL) {
			dhcpmsg(MSG_ERROR, "add_pkt_opt: option type %d is "
			    "missing required value", opt_type);
			return (NULL);
		}

		if ((dpkt->pkt_cur_len + req_len) > dpkt->pkt_max_len) {
			dhcpmsg(MSG_WARNING,
			    "add_pkt_opt: not enough room for v4 option %u in "
			    "packet", opt_type);
			return (NULL);
		}
	}

	req_len = encode_dhcp_opt(&raw_pkt[dpkt->pkt_cur_len], dpkt->pkt_isv6,
	    opt_type, opt_val, opt_len);
	dpkt->pkt_cur_len += req_len;

	return (optr);
}

/*
 * encode_dhcp_opt(): sets the fields of an allocated DHCP option buffer
 *
 *   input: void *: the buffer allocated for enough space for
 *		    (DHCPv6) dhcpv6_option_t and value, or for
 *		    (DHCPv4) opt_type + length + value (length/value are
 *		    skipped for CD_END or CD_PAD);
 *	    boolean_t: a value indicating whether DHCPv6 or not;
 *	    uint_t: the type of option being added;
 *	    const void *: the value of that option;
 *	    uint_t: the length of the value of the option
 *  output: size_t: the number of bytes written starting at opt.
 */

size_t
encode_dhcp_opt(void *dopt, boolean_t isv6, uint_t opt_type,
    const void *opt_val, uint_t opt_len)
{
	boolean_t do_copy_value = B_FALSE;
	size_t res_len = 0;
	uint8_t *pval;

	if (isv6) {
		dhcpv6_option_t d6o;
		d6o.d6o_code = htons(opt_type);
		d6o.d6o_len = htons(opt_len);
		(void) memcpy(dopt, &d6o, sizeof (d6o));
		res_len += sizeof (d6o);

		do_copy_value = B_TRUE;
	} else {
		pval = (uint8_t *)dopt;
		pval[res_len++] = opt_type;

		if (opt_type != CD_END && opt_type != CD_PAD) {
			pval[res_len++] = opt_len;
			do_copy_value = B_TRUE;
		}
	}

	pval = (uint8_t *)dopt + res_len;
	if (do_copy_value && opt_len > 0) {
		(void) memcpy(pval, opt_val, opt_len);
		res_len += opt_len;
	}

	return (res_len);
}

/*
 * add_pkt_subopt(): adds an option to a dhcp_pkt_t option.  DHCPv6-specific,
 *		     but could be extended to IPv4 DHCP if necessary.  Assumes
 *		     that if the parent isn't a top-level option, the caller
 *		     will adjust any upper-level options recursively using
 *		     update_v6opt_len.
 *
 *   input: dhcp_pkt_t *: the packet to add the suboption to
 *	    dhcpv6_option_t *: the start of the option to that should contain
 *			       it (parent)
 *	    uint_t: the type of suboption being added
 *	    const void *: the value of that option
 *	    uint_t: the length of the value of the option
 *  output: void *: pointer to the suboption that was added, or NULL on
 *		    failure.
 */

void *
add_pkt_subopt(dhcp_pkt_t *dpkt, dhcpv6_option_t *parentopt, uint_t opt_type,
    const void *opt_val, uint_t opt_len)
{
	uchar_t		*raw_pkt;
	int		req_len;
	void		*optr;
	dhcpv6_option_t d6o;
	uchar_t		*optend;
	int		olen;

	if (!dpkt->pkt_isv6)
		return (NULL);

	raw_pkt = (uchar_t *)dpkt->pkt;
	req_len = opt_len + sizeof (d6o);

	if (dpkt->pkt_cur_len + req_len > dpkt->pkt_max_len) {
		dhcpmsg(MSG_WARNING,
		    "add_pkt_subopt: not enough room for v6 suboption %u in "
		    "packet (%u + %u > %u)", opt_type,
		    dpkt->pkt_cur_len, req_len, dpkt->pkt_max_len);
		return (NULL);
	}

	/*
	 * Update the parent option to include room for this option,
	 * and compute the insertion point.
	 */
	(void) memcpy(&d6o, parentopt, sizeof (d6o));
	olen = ntohs(d6o.d6o_len);
	optend = (uchar_t *)(parentopt + 1) + olen;
	olen += req_len;
	d6o.d6o_len = htons(olen);
	(void) memcpy(parentopt, &d6o, sizeof (d6o));

	/*
	 * If there's anything at the end to move, then move it.  Also bump up
	 * the packet size.
	 */
	if (optend < raw_pkt + dpkt->pkt_cur_len) {
		(void) memmove(optend + req_len, optend,
		    (raw_pkt + dpkt->pkt_cur_len) - optend);
	}
	dpkt->pkt_cur_len += req_len;

	/*
	 * Now format the suboption and add it in.
	 */
	optr = optend;
	d6o.d6o_code = htons(opt_type);
	d6o.d6o_len = htons(opt_len);
	(void) memcpy(optend, &d6o, sizeof (d6o));
	if (opt_len > 0)
		(void) memcpy(optend + sizeof (d6o), opt_val, opt_len);
	return (optr);
}

/*
 * add_pkt_opt16(): adds an option with a 16-bit value to a dhcp_pkt_t
 *
 *   input: dhcp_pkt_t *: the packet to add the option to
 *	    uint_t: the type of option being added
 *	    uint16_t: the value of that option
 *  output: void *: pointer to the option that was added, or NULL on failure.
 */

void *
add_pkt_opt16(dhcp_pkt_t *dpkt, uint_t opt_type, uint16_t opt_value)
{
	return (add_pkt_opt(dpkt, opt_type, &opt_value, 2));
}

/*
 * add_pkt_opt32(): adds an option with a 32-bit value to a dhcp_pkt_t
 *
 *   input: dhcp_pkt_t *: the packet to add the option to
 *	    uint_t: the type of option being added
 *	    uint32_t: the value of that option
 *  output: void *: pointer to the option that was added, or NULL on failure.
 */

void *
add_pkt_opt32(dhcp_pkt_t *dpkt, uint_t opt_type, uint32_t opt_value)
{
	return (add_pkt_opt(dpkt, opt_type, &opt_value, 4));
}

/*
 * add_pkt_prl(): adds the parameter request option to the packet
 *
 *   input: dhcp_pkt_t *: the packet to add the option to
 *	    dhcp_smach_t *: state machine with request option
 *  output: void *: pointer to the option that was added, or NULL on failure.
 */

void *
add_pkt_prl(dhcp_pkt_t *dpkt, dhcp_smach_t *dsmp)
{
	uint_t len;

	if (dsmp->dsm_prllen == 0)
		return (0);

	if (dpkt->pkt_isv6) {
		uint16_t *prl;

		/*
		 * RFC 3315 requires that we include the option, even if we
		 * have nothing to request.
		 */
		if (dsmp->dsm_prllen == 0)
			prl = NULL;
		else
			prl = alloca(dsmp->dsm_prllen * sizeof (uint16_t));

		for (len = 0; len < dsmp->dsm_prllen; len++)
			prl[len] = htons(dsmp->dsm_prl[len]);
		return (add_pkt_opt(dpkt, DHCPV6_OPT_ORO, prl,
		    len * sizeof (uint16_t)));
	} else {
		uint8_t *prl = alloca(dsmp->dsm_prllen);

		for (len = 0; len < dsmp->dsm_prllen; len++)
			prl[len] = dsmp->dsm_prl[len];
		return (add_pkt_opt(dpkt, CD_REQUEST_LIST, prl, len));
	}
}

/*
 * add_pkt_lif(): Adds CD_REQUESTED_IP_ADDR (IPv4 DHCP) or IA_NA and IAADDR
 *		  (DHCPv6) options to the packet to represent the given LIF.
 *
 *   input: dhcp_pkt_t *: the packet to add the options to
 *	    dhcp_lif_t *: the logical interface to represent
 *	    int: status code (unused for IPv4 DHCP)
 *	    const char *: message to include with status option, or NULL
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */

boolean_t
add_pkt_lif(dhcp_pkt_t *dpkt, dhcp_lif_t *lif, int status, const char *msg)
{
	if (lif->lif_pif->pif_isv6) {
		dhcp_smach_t *dsmp;
		dhcpv6_message_t *d6m;
		dhcpv6_ia_na_t d6in;
		dhcpv6_iaaddr_t d6ia;
		uint32_t iaid;
		uint16_t *statusopt;
		dhcpv6_option_t *d6o, *d6so;
		uint_t olen;

		/*
		 * Currently, we support just one IAID related to the primary
		 * LIF on the state machine.
		 */
		dsmp = lif->lif_lease->dl_smach;
		iaid = dsmp->dsm_lif->lif_iaid;
		iaid = htonl(iaid);

		d6m = (dhcpv6_message_t *)dpkt->pkt;

		/*
		 * Find or create the IA_NA needed for this LIF.  If we
		 * supported IA_TA, we'd check the IFF_TEMPORARY bit here.
		 */
		d6o = NULL;
		while ((d6o = dhcpv6_find_option(d6m + 1,
		    dpkt->pkt_cur_len - sizeof (*d6m), d6o, DHCPV6_OPT_IA_NA,
		    &olen)) != NULL) {
			if (olen < sizeof (d6in))
				continue;
			(void) memcpy(&d6in, d6o, sizeof (d6in));
			if (d6in.d6in_iaid == iaid)
				break;
		}
		if (d6o == NULL) {
			d6in.d6in_iaid = iaid;
			d6in.d6in_t1 = 0;
			d6in.d6in_t2 = 0;
			d6o = add_pkt_opt(dpkt, DHCPV6_OPT_IA_NA,
			    (dhcpv6_option_t *)&d6in + 1,
			    sizeof (d6in) - sizeof (*d6o));
			if (d6o == NULL)
				return (B_FALSE);
		}

		/*
		 * Now add the IAADDR suboption for this LIF.  No need to
		 * search here, as we know that this is unique.
		 */
		d6ia.d6ia_addr = lif->lif_v6addr;

		/*
		 * For Release and Decline, we zero out the lifetime.  For
		 * Renew and Rebind, we report the original time as the
		 * preferred and valid lifetimes.
		 */
		if (d6m->d6m_msg_type == DHCPV6_MSG_RELEASE ||
		    d6m->d6m_msg_type == DHCPV6_MSG_DECLINE) {
			d6ia.d6ia_preflife = 0;
			d6ia.d6ia_vallife = 0;
		} else {
			d6ia.d6ia_preflife = htonl(lif->lif_preferred.dt_start);
			d6ia.d6ia_vallife = htonl(lif->lif_expire.dt_start);
		}
		d6so = add_pkt_subopt(dpkt, d6o, DHCPV6_OPT_IAADDR,
		    (dhcpv6_option_t *)&d6ia + 1,
		    sizeof (d6ia) - sizeof (*d6o));
		if (d6so == NULL)
			return (B_FALSE);

		/*
		 * Add a status code suboption to the IAADDR to tell the server
		 * why we're declining the address.  Note that we must manually
		 * update the enclosing IA_NA, as add_pkt_subopt doesn't know
		 * how to do that.
		 */
		if (status != DHCPV6_STAT_SUCCESS || msg != NULL) {
			olen = sizeof (*statusopt) +
			    (msg == NULL ? 0 : strlen(msg));
			statusopt = alloca(olen);
			*statusopt = htons(status);
			if (msg != NULL) {
				(void) memcpy((char *)(statusopt + 1), msg,
				    olen - sizeof (*statusopt));
			}
			d6so = add_pkt_subopt(dpkt, d6so,
			    DHCPV6_OPT_STATUS_CODE, statusopt, olen);
			if (d6so != NULL) {
				/*
				 * Update for length of suboption header and
				 * suboption contents.
				 */
				(void) update_v6opt_len(d6o, sizeof (*d6so) +
				    olen);
			}
		}
	} else {
		/*
		 * For DECLINE, we need to add the CD_REQUESTED_IP_ADDR option.
		 * In all other cases (RELEASE and REQUEST), we need to set
		 * ciadr.
		 */
		if (pkt_send_type(dpkt) == DECLINE) {
			if (!add_pkt_opt32(dpkt, CD_REQUESTED_IP_ADDR,
			    lif->lif_addr))
				return (B_FALSE);
		} else {
			dpkt->pkt->ciaddr.s_addr = lif->lif_addr;
		}

		/*
		 * It's not too worrisome if the message fails to fit in the
		 * packet.  The result will still be valid.
		 */
		if (msg != NULL)
			(void) add_pkt_opt(dpkt, CD_MESSAGE, msg,
			    strlen(msg) + 1);
	}
	return (B_TRUE);
}

/*
 * free_pkt_entry(): frees a packet list list entry
 *
 *   input: PKT_LIST *: the packet list entry to free
 *  output: void
 */
void
free_pkt_entry(PKT_LIST *plp)
{
	if (plp != NULL) {
		free(plp->pkt);
		free(plp);
	}
}

/*
 * free_pkt_list(): frees an entire packet list
 *
 *   input: PKT_LIST **: the packet list to free
 *  output: void
 */

void
free_pkt_list(PKT_LIST **head)
{
	PKT_LIST *plp;

	while ((plp = *head) != NULL) {
		remque(plp);
		free_pkt_entry(plp);
	}
}

/*
 * send_pkt_internal(): sends a packet out on an interface
 *
 *   input: dhcp_smach_t *: the state machine with a packet to send
 *  output: boolean_t: B_TRUE if the packet is sent, B_FALSE otherwise
 */

static boolean_t
send_pkt_internal(dhcp_smach_t *dsmp)
{
	ssize_t		n_bytes;
	dhcp_lif_t	*lif = dsmp->dsm_lif;
	dhcp_pkt_t	*dpkt = &dsmp->dsm_send_pkt;
	uchar_t		ptype = pkt_send_type(dpkt);
	const char	*pkt_name;
	struct iovec	iov;
	struct msghdr	msg;
	struct cmsghdr	*cmsg;
	struct in6_pktinfo *ipi6;
	boolean_t	ismcast;
	int		msgtype;

	/*
	 * Timer should not be running at the point we go to send a packet.
	 */
	if (dsmp->dsm_retrans_timer != -1) {
		dhcpmsg(MSG_CRIT, "send_pkt_internal: unexpected retransmit "
		    "timer on %s", dsmp->dsm_name);
		stop_pkt_retransmission(dsmp);
	}

	pkt_name = pkt_type_to_string(ptype, dpkt->pkt_isv6);

	/*
	 * if needed, schedule a retransmission timer, then attempt to
	 * send the packet.  if we fail, then log the error.  our
	 * return value should indicate whether or not we were
	 * successful in sending the request, independent of whether
	 * we could schedule a timer.
	 */

	if (dsmp->dsm_send_timeout != 0) {
		if ((dsmp->dsm_retrans_timer = iu_schedule_timer_ms(tq,
		    dsmp->dsm_send_timeout, retransmit, dsmp)) == -1)
			dhcpmsg(MSG_WARNING, "send_pkt_internal: cannot "
			    "schedule retransmit timer for %s packet",
			    pkt_name);
		else
			hold_smach(dsmp);
	}

	if (dpkt->pkt_isv6) {
		hrtime_t delta;

		/*
		 * Convert current time into centiseconds since transaction
		 * started.  This is what DHCPv6 expects to see in the Elapsed
		 * Time option.
		 */
		delta = (gethrtime() - dsmp->dsm_neg_hrtime) /
		    (NANOSEC / 100);
		if (delta > DHCPV6_FOREVER)
			delta = DHCPV6_FOREVER;
		(void) remove_pkt_opt(dpkt, DHCPV6_OPT_ELAPSED_TIME);
		(void) add_pkt_opt16(dpkt, DHCPV6_OPT_ELAPSED_TIME,
		    htons(delta));
	} else {
		/*
		 * set the `pkt->secs' field depending on the type of packet.
		 * it should be zero, except in the following cases:
		 *
		 * DISCOVER:	set to the number of seconds since we started
		 *		trying to obtain a lease.
		 *
		 * INFORM:	set to the number of seconds since we started
		 *		trying to get configuration parameters.
		 *
		 * REQUEST:	if in the REQUESTING state, then same value as
		 *		DISCOVER, otherwise the number of seconds
		 *		since we started trying to obtain a lease.
		 *
		 * we also set `dsm_newstart_monosec', to the time we sent a
		 * REQUEST or DISCOVER packet, so we know the lease start
		 * time (the DISCOVER case is for handling BOOTP servers).
		 */

		switch (ptype) {

		case DISCOVER:
			dsmp->dsm_newstart_monosec = monosec();
			dsmp->dsm_disc_secs = dsmp->dsm_newstart_monosec -
			    hrtime_to_monosec(dsmp->dsm_neg_hrtime);
			dpkt->pkt->secs = htons(dsmp->dsm_disc_secs);
			break;

		case INFORM:
			dpkt->pkt->secs = htons(monosec() -
			    hrtime_to_monosec(dsmp->dsm_neg_hrtime));
			break;

		case REQUEST:
			dsmp->dsm_newstart_monosec = monosec();

			if (dsmp->dsm_state == REQUESTING) {
				dpkt->pkt->secs = htons(dsmp->dsm_disc_secs);
				break;
			}

			dpkt->pkt->secs = htons(monosec() -
			    hrtime_to_monosec(dsmp->dsm_neg_hrtime));
			break;

		default:
			dpkt->pkt->secs = htons(0);
			break;
		}
	}

	if (dpkt->pkt_isv6) {
		struct sockaddr_in6 sin6;

		(void) memset(&iov, 0, sizeof (iov));
		iov.iov_base = dpkt->pkt;
		iov.iov_len = dpkt->pkt_cur_len;

		(void) memset(&msg, 0, sizeof (msg));
		msg.msg_name = &dsmp->dsm_send_dest.v6;
		msg.msg_namelen = sizeof (struct sockaddr_in6);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		/*
		 * If the address that's requested cannot be reached, then fall
		 * back to the multcast address.
		 */
		if (IN6_IS_ADDR_MULTICAST(&dsmp->dsm_send_dest.v6.sin6_addr)) {
			ismcast = B_TRUE;
		} else {
			struct dstinforeq dinfo;
			struct strioctl str;

			ismcast = B_FALSE;
			(void) memset(&dinfo, 0, sizeof (dinfo));
			dinfo.dir_daddr = dsmp->dsm_send_dest.v6.sin6_addr;
			str.ic_cmd = SIOCGDSTINFO;
			str.ic_timout = 0;
			str.ic_len = sizeof (dinfo);
			str.ic_dp = (char *)&dinfo;
			if (ioctl(v6_sock_fd, I_STR, &str) == -1) {
				dhcpmsg(MSG_ERR,
				    "send_pkt_internal: ioctl SIOCGDSTINFO");
			} else if (!dinfo.dir_dreachable) {
				char abuf[INET6_ADDRSTRLEN];

				dhcpmsg(MSG_DEBUG, "send_pkt_internal: %s is "
				    "not reachable; using multicast instead",
				    inet_ntop(AF_INET6, &dinfo.dir_daddr, abuf,
				    sizeof (abuf)));
				sin6 = dsmp->dsm_send_dest.v6;
				sin6.sin6_addr =
				    ipv6_all_dhcp_relay_and_servers;
				msg.msg_name = &sin6;
				ismcast = B_TRUE;
			}
		}

		/*
		 * Make room for our ancillary data option as well as a dummy
		 * option used by CMSG_NXTHDR.
		 */
		msg.msg_controllen = sizeof (*cmsg) + _MAX_ALIGNMENT +
		    sizeof (*ipi6) + _MAX_ALIGNMENT + sizeof (*cmsg);
		msg.msg_control = alloca(msg.msg_controllen);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		/* LINTED: alignment */
		ipi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		if (ismcast)
			ipi6->ipi6_addr = lif->lif_v6addr;
		else
			ipi6->ipi6_addr = my_in6addr_any;
		if (lif->lif_pif->pif_under_ipmp)
			ipi6->ipi6_ifindex = lif->lif_pif->pif_grindex;
		else
			ipi6->ipi6_ifindex = lif->lif_pif->pif_index;
		cmsg->cmsg_len = (char *)(ipi6 + 1) - (char *)cmsg;

		/*
		 * Now correct the control message length.
		 */
		cmsg = CMSG_NXTHDR(&msg, cmsg);
		msg.msg_controllen = (char *)cmsg - (char *)msg.msg_control;

		n_bytes = sendmsg(v6_sock_fd, &msg, 0);
	} else {
		n_bytes = sendto(lif->lif_sock_ip_fd, dpkt->pkt,
		    dpkt->pkt_cur_len, 0,
		    (struct sockaddr *)&dsmp->dsm_send_dest.v4,
		    sizeof (struct sockaddr_in));
	}

	if (n_bytes != dpkt->pkt_cur_len) {
		msgtype = (n_bytes == -1) ? MSG_ERR : MSG_WARNING;
		if (dsmp->dsm_retrans_timer == -1)
			dhcpmsg(msgtype, "send_pkt_internal: cannot send "
			    "%s packet to server", pkt_name);
		else
			dhcpmsg(msgtype, "send_pkt_internal: cannot send "
			    "%s packet to server (will retry in %u seconds)",
			    pkt_name, dsmp->dsm_send_timeout / MILLISEC);
		return (B_FALSE);
	}

	dhcpmsg(MSG_VERBOSE, "sent %s xid %x packet out %s", pkt_name,
	    pkt_get_xid(dpkt->pkt, dpkt->pkt_isv6), dsmp->dsm_name);

	dsmp->dsm_packet_sent++;
	dsmp->dsm_sent++;
	return (B_TRUE);
}

/*
 * send_pkt(): sends a packet out
 *
 *   input: dhcp_smach_t *: the state machine sending the packet
 *	    dhcp_pkt_t *: the packet to send out
 *	    in_addr_t: the destination IP address for the packet
 *	    stop_func_t *: a pointer to function to indicate when to stop
 *			   retransmitting the packet (if NULL, packet is
 *			   not retransmitted)
 *  output: boolean_t: B_TRUE if the packet was sent, B_FALSE otherwise
 */

boolean_t
send_pkt(dhcp_smach_t *dsmp, dhcp_pkt_t *dpkt, in_addr_t dest,
    stop_func_t *stop)
{
	/*
	 * packets must be at least sizeof (PKT) or they may be dropped
	 * by routers.  pad out the packet in this case.
	 */

	dpkt->pkt_cur_len = MAX(dpkt->pkt_cur_len, sizeof (PKT));

	dsmp->dsm_packet_sent = 0;

	(void) memset(&dsmp->dsm_send_dest.v4, 0,
	    sizeof (dsmp->dsm_send_dest.v4));
	dsmp->dsm_send_dest.v4.sin_addr.s_addr	= dest;
	dsmp->dsm_send_dest.v4.sin_family	= AF_INET;
	dsmp->dsm_send_dest.v4.sin_port		= htons(IPPORT_BOOTPS);
	dsmp->dsm_send_stop_func		= stop;

	/*
	 * TODO: dispose of this gruesome assumption (there's no real
	 * technical gain from doing so, but it would be cleaner)
	 */

	assert(dpkt == &dsmp->dsm_send_pkt);

	/*
	 * clear out any packets which had been previously received
	 * but not pulled off of the recv_packet queue.
	 */

	free_pkt_list(&dsmp->dsm_recv_pkt_list);

	if (stop == NULL)
		dsmp->dsm_send_timeout = 0;	/* prevents retransmissions */
	else
		next_retransmission(dsmp, B_TRUE, B_FALSE);

	return (send_pkt_internal(dsmp));
}

/*
 * send_pkt_v6(): sends a DHCPv6 packet out
 *
 *   input: dhcp_smach_t *: the state machine sending the packet
 *	    dhcp_pkt_t *: the packet to send out
 *	    in6_addr_t: the destination IPv6 address for the packet
 *	    stop_func_t *: a pointer to function to indicate when to stop
 *			   retransmitting the packet (if NULL, packet is
 *			   not retransmitted)
 *	    uint_t: Initial Retransmit Timer value
 *	    uint_t: Maximum Retransmit Timer value, zero if none
 *  output: boolean_t: B_TRUE if the packet was sent, B_FALSE otherwise
 */

boolean_t
send_pkt_v6(dhcp_smach_t *dsmp, dhcp_pkt_t *dpkt, in6_addr_t dest,
    stop_func_t *stop, uint_t irt, uint_t mrt)
{
	dsmp->dsm_packet_sent = 0;

	(void) memset(&dsmp->dsm_send_dest.v6, 0,
	    sizeof (dsmp->dsm_send_dest.v6));
	dsmp->dsm_send_dest.v6.sin6_addr	= dest;
	dsmp->dsm_send_dest.v6.sin6_family	= AF_INET6;
	dsmp->dsm_send_dest.v6.sin6_port	= htons(IPPORT_DHCPV6S);
	dsmp->dsm_send_stop_func		= stop;

	/*
	 * TODO: dispose of this gruesome assumption (there's no real
	 * technical gain from doing so, but it would be cleaner)
	 */

	assert(dpkt == &dsmp->dsm_send_pkt);

	/*
	 * clear out any packets which had been previously received
	 * but not pulled off of the recv_packet queue.
	 */

	free_pkt_list(&dsmp->dsm_recv_pkt_list);

	if (stop == NULL) {
		dsmp->dsm_send_timeout = 0;	/* prevents retransmissions */
	} else {
		dsmp->dsm_send_timeout = irt;
		dsmp->dsm_send_tcenter = mrt;
		/*
		 * This is quite ugly, but RFC 3315 section 17.1.2 requires
		 * that the RAND value for the very first retransmission of a
		 * Solicit message is strictly greater than zero.
		 */
		next_retransmission(dsmp, B_TRUE,
		    pkt_send_type(dpkt) == DHCPV6_MSG_SOLICIT);
	}

	return (send_pkt_internal(dsmp));
}

/*
 * retransmit(): retransmits the current packet on an interface
 *
 *   input: iu_tq_t *: unused
 *	    void *: the dhcp_smach_t * (state machine) sending a packet
 *  output: void
 */

/* ARGSUSED */
static void
retransmit(iu_tq_t *tqp, void *arg)
{
	dhcp_smach_t	*dsmp = arg;

	dsmp->dsm_retrans_timer = -1;

	if (!verify_smach(dsmp))
		return;

	/*
	 * Check the callback to see if we should keep sending retransmissions.
	 * Compute the next retransmission time first, so that the callback can
	 * cap the value if need be.  (Required for DHCPv6 Confirm messages.)
	 *
	 * Hold the state machine across the callback so that the called
	 * function can remove the state machine from the system without
	 * disturbing the string used subsequently for verbose logging.  The
	 * Release function destroys the state machine when the retry count
	 * expires.
	 */

	next_retransmission(dsmp, B_FALSE, B_FALSE);
	hold_smach(dsmp);
	if (dsmp->dsm_send_stop_func(dsmp, dsmp->dsm_packet_sent)) {
		dhcpmsg(MSG_VERBOSE, "retransmit: time to stop on %s",
		    dsmp->dsm_name);
	} else {
		dhcpmsg(MSG_VERBOSE, "retransmit: sending another on %s",
		    dsmp->dsm_name);
		(void) send_pkt_internal(dsmp);
	}
	release_smach(dsmp);
}

/*
 * stop_pkt_retransmission(): stops retransmission of last sent packet
 *
 *   input: dhcp_smach_t *: the state machine to stop retransmission on
 *  output: void
 */

void
stop_pkt_retransmission(dhcp_smach_t *dsmp)
{
	if (dsmp->dsm_retrans_timer != -1 &&
	    iu_cancel_timer(tq, dsmp->dsm_retrans_timer, NULL) == 1) {
		dhcpmsg(MSG_VERBOSE, "stop_pkt_retransmission: stopped on %s",
		    dsmp->dsm_name);
		dsmp->dsm_retrans_timer = -1;
		release_smach(dsmp);
	}
}

/*
 * retransmit_now(): force a packet retransmission right now.  Used only with
 *		     the DHCPv6 UseMulticast status code.  Use with caution;
 *		     triggered retransmissions can cause packet storms.
 *
 *   input: dhcp_smach_t *: the state machine to force retransmission on
 *  output: void
 */

void
retransmit_now(dhcp_smach_t *dsmp)
{
	stop_pkt_retransmission(dsmp);
	(void) send_pkt_internal(dsmp);
}

/*
 * alloc_pkt_entry(): Allocates a packet list entry with a given data area
 *		      size.
 *
 *   input: size_t: size of data area for packet
 *	    boolean_t: B_TRUE for IPv6
 *  output: PKT_LIST *: allocated packet list entry
 */

PKT_LIST *
alloc_pkt_entry(size_t psize, boolean_t isv6)
{
	PKT_LIST	*plp;

	if ((plp = calloc(1, sizeof (*plp))) == NULL ||
	    (plp->pkt = malloc(psize)) == NULL) {
		free(plp);
		plp = NULL;
	} else {
		plp->len = psize;
		plp->isv6 = isv6;
	}

	return (plp);
}

/*
 * sock_recvpkt(): read from the given socket into an allocated buffer and
 *		   handles any ancillary data options.
 *
 *   input: int: file descriptor to read
 *	    PKT_LIST *: allocated buffer
 *  output: ssize_t: number of bytes read, or -1 on error
 */

static ssize_t
sock_recvpkt(int fd, PKT_LIST *plp)
{
	struct iovec iov;
	struct msghdr msg;
	int64_t ctrl[8192 / sizeof (int64_t)];
	ssize_t msglen;

	(void) memset(&iov, 0, sizeof (iov));
	iov.iov_base = (caddr_t)plp->pkt;
	iov.iov_len = plp->len;

	(void) memset(&msg, 0, sizeof (msg));
	msg.msg_name = &plp->pktfrom;
	msg.msg_namelen = sizeof (plp->pktfrom);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctrl;
	msg.msg_controllen = sizeof (ctrl);

	if ((msglen = recvmsg(fd, &msg, 0)) != -1) {
		struct cmsghdr *cmsg;

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
		    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			struct sockaddr_in *sinp;
			struct sockaddr_in6 *sin6;
			struct in6_pktinfo *ipi6;

			switch (cmsg->cmsg_level) {
			case IPPROTO_IP:
				switch (cmsg->cmsg_type) {
				case IP_RECVDSTADDR:
					sinp = (struct sockaddr_in *)
					    &plp->pktto;
					sinp->sin_family = AF_INET;
					(void) memcpy(&sinp->sin_addr.s_addr,
					    CMSG_DATA(cmsg),
					    sizeof (ipaddr_t));
					break;

				case IP_RECVIF:
					(void) memcpy(&plp->ifindex,
					    CMSG_DATA(cmsg), sizeof (uint_t));
					break;
				}
				break;

			case IPPROTO_IPV6:
				switch (cmsg->cmsg_type) {
				case IPV6_PKTINFO:
					/* LINTED: alignment */
					ipi6 = (struct in6_pktinfo *)
					    CMSG_DATA(cmsg);
					sin6 = (struct sockaddr_in6 *)
					    &plp->pktto;
					sin6->sin6_family = AF_INET6;
					(void) memcpy(&sin6->sin6_addr,
					    &ipi6->ipi6_addr,
					    sizeof (ipi6->ipi6_addr));
					(void) memcpy(&plp->ifindex,
					    &ipi6->ipi6_ifindex,
					    sizeof (uint_t));
					break;
				}
			}
		}
	}
	return (msglen);
}

/*
 * recv_pkt(): receives a single DHCP packet on a given file descriptor.
 *
 *   input: int: the file descriptor to receive the packet from
 *	    int: the maximum packet size to allow
 *	    boolean_t: B_TRUE for IPv6
 *  output: PKT_LIST *: the received packet
 */

PKT_LIST *
recv_pkt(int fd, int mtu, boolean_t isv6)
{
	PKT_LIST	*plp;
	ssize_t		retval;

	if ((plp = alloc_pkt_entry(mtu, isv6)) == NULL) {
		dhcpmsg(MSG_ERROR,
		    "recv_pkt: allocation failure; dropped packet");
		return (NULL);
	}

	retval = sock_recvpkt(fd, plp);
	if (retval == -1) {
		dhcpmsg(MSG_ERR, "recv_pkt: recvfrom v%d failed, dropped",
		    isv6 ? 6 : 4);
		goto failure;
	}

	plp->len = retval;

	if (isv6) {
		if (retval < sizeof (dhcpv6_message_t)) {
			dhcpmsg(MSG_WARNING, "recv_pkt: runt message");
			goto failure;
		}
	} else {
		switch (dhcp_options_scan(plp, B_TRUE)) {

		case DHCP_WRONG_MSG_TYPE:
			dhcpmsg(MSG_WARNING,
			    "recv_pkt: unexpected DHCP message");
			goto failure;

		case DHCP_GARBLED_MSG_TYPE:
			dhcpmsg(MSG_WARNING,
			    "recv_pkt: garbled DHCP message type");
			goto failure;

		case DHCP_BAD_OPT_OVLD:
			dhcpmsg(MSG_WARNING, "recv_pkt: bad option overload");
			goto failure;

		case 0:
			break;

		default:
			dhcpmsg(MSG_WARNING,
			    "recv_pkt: packet corrupted, dropped");
			goto failure;
		}
	}
	return (plp);

failure:
	free_pkt_entry(plp);
	return (NULL);
}

/*
 * pkt_v4_match(): check if a given DHCPv4 message type is in a given set
 *
 *   input: uchar_t: packet type
 *	    dhcp_message_type_t: bit-wise OR of DHCP_P* values.
 *  output: boolean_t: B_TRUE if packet type is in the set
 */

boolean_t
pkt_v4_match(uchar_t type, dhcp_message_type_t match_type)
{
	/*
	 * note: the ordering here allows direct indexing of the table
	 *	 based on the RFC2131 packet type value passed in.
	 */

	static dhcp_message_type_t type_map[] = {
		DHCP_PUNTYPED, DHCP_PDISCOVER, DHCP_POFFER, DHCP_PREQUEST,
		DHCP_PDECLINE, DHCP_PACK, DHCP_PNAK, DHCP_PRELEASE,
		DHCP_PINFORM
	};

	if (type < (sizeof (type_map) / sizeof (*type_map)))
		return ((type_map[type] & match_type) ? B_TRUE : B_FALSE);
	else
		return (B_FALSE);
}

/*
 * pkt_smach_enqueue(): enqueue a packet on a given state machine
 *
 *   input: dhcp_smach_t: state machine
 *	    PKT_LIST *: packet to enqueue
 *  output: none
 */

void
pkt_smach_enqueue(dhcp_smach_t *dsmp, PKT_LIST *plp)
{
	dhcpmsg(MSG_VERBOSE, "pkt_smach_enqueue: received %s %s packet on %s",
	    pkt_type_to_string(pkt_recv_type(plp), dsmp->dsm_isv6),
	    dsmp->dsm_isv6 ? "v6" : "v4", dsmp->dsm_name);

	/* add to front of list */
	insque(plp, &dsmp->dsm_recv_pkt_list);
}

/*
 * next_retransmission(): computes the number of seconds until the next
 *			  retransmission, based on the algorithms in RFCs 2131
 *			  3315.
 *
 *   input: dhcp_smach_t *: state machine that needs a new timer
 *	    boolean_t: B_TRUE if this is the first time sending the message
 *	    boolean_t: B_TRUE for positive RAND values only (RFC 3315 17.1.2)
 *  output: none
 */

static void
next_retransmission(dhcp_smach_t *dsmp, boolean_t first_send,
    boolean_t positive_only)
{
	uint32_t timeout_ms;

	if (dsmp->dsm_isv6) {
		double randval;

		/*
		 * The RFC specifies 0 to 10% jitter for the initial
		 * solicitation, and plus or minus 10% jitter for all others.
		 * This works out to 100 milliseconds on the shortest timer we
		 * use.
		 */
		if (positive_only)
			randval = drand48() / 10.0;
		else
			randval = (drand48() - 0.5) / 5.0;

		/* The RFC specifies doubling *after* the first transmission */
		timeout_ms = dsmp->dsm_send_timeout;
		if (!first_send)
			timeout_ms *= 2;
		timeout_ms += (int)(randval * dsmp->dsm_send_timeout);

		/* This checks the MRT (maximum retransmission time) */
		if (dsmp->dsm_send_tcenter != 0 &&
		    timeout_ms > dsmp->dsm_send_tcenter) {
			timeout_ms = dsmp->dsm_send_tcenter +
			    (uint_t)(randval * dsmp->dsm_send_tcenter);
		}

		dsmp->dsm_send_timeout = timeout_ms;
	} else {
		if (dsmp->dsm_state == RENEWING ||
		    dsmp->dsm_state == REBINDING) {
			monosec_t mono;

			timeout_ms = dsmp->dsm_state == RENEWING ?
			    dsmp->dsm_leases->dl_t2.dt_start :
			    dsmp->dsm_leases->dl_lifs->lif_expire.dt_start;
			timeout_ms += dsmp->dsm_curstart_monosec;
			mono = monosec();
			if (mono > timeout_ms)
				timeout_ms = 0;
			else
				timeout_ms -= mono;
			timeout_ms *= MILLISEC / 2;
		} else {
			/*
			 * Start at 4, and increase by a factor of 2 up to 64.
			 */
			if (first_send) {
				timeout_ms = 4 * MILLISEC;
			} else {
				timeout_ms = MIN(dsmp->dsm_send_tcenter << 1,
				    64 * MILLISEC);
			}
		}

		dsmp->dsm_send_tcenter = timeout_ms;

		/*
		 * At each iteration, jitter the timeout by some fraction of a
		 * second.
		 */
		dsmp->dsm_send_timeout = timeout_ms +
		    ((lrand48() % (2 * MILLISEC)) - MILLISEC);
	}
}

/*
 * dhcp_ip_default(): open and bind the default IP sockets used for I/O and
 *		      interface control.
 *
 *   input: none
 *  output: B_TRUE on success
 */

boolean_t
dhcp_ip_default(void)
{
	int on = 1;

	if ((v4_sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		dhcpmsg(MSG_ERR,
		    "dhcp_ip_default: unable to create IPv4 socket");
		return (B_FALSE);
	}

	if (setsockopt(v4_sock_fd, IPPROTO_IP, IP_RECVDSTADDR, &on,
	    sizeof (on)) == -1) {
		dhcpmsg(MSG_ERR,
		    "dhcp_ip_default: unable to enable IP_RECVDSTADDR");
		return (B_FALSE);
	}

	if (setsockopt(v4_sock_fd, IPPROTO_IP, IP_RECVIF, &on, sizeof (on)) ==
	    -1) {
		dhcpmsg(MSG_ERR,
		    "dhcp_ip_default: unable to enable IP_RECVIF");
		return (B_FALSE);
	}

	if (!bind_sock(v4_sock_fd, IPPORT_BOOTPC, INADDR_ANY)) {
		dhcpmsg(MSG_ERROR,
		    "dhcp_ip_default: unable to bind IPv4 socket to port %d",
		    IPPORT_BOOTPC);
		return (B_FALSE);
	}

	if (iu_register_event(eh, v4_sock_fd, POLLIN, dhcp_acknak_global,
	    NULL) == -1) {
		dhcpmsg(MSG_WARNING, "dhcp_ip_default: cannot register to "
		    "receive IPv4 broadcasts");
		return (B_FALSE);
	}

	if ((v6_sock_fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
		dhcpmsg(MSG_ERR,
		    "dhcp_ip_default: unable to create IPv6 socket");
		return (B_FALSE);
	}

	if (setsockopt(v6_sock_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
	    sizeof (on)) == -1) {
		dhcpmsg(MSG_ERR,
		    "dhcp_ip_default: unable to enable IPV6_RECVPKTINFO");
		return (B_FALSE);
	}

	if (!bind_sock_v6(v6_sock_fd, IPPORT_DHCPV6C, NULL)) {
		dhcpmsg(MSG_ERROR,
		    "dhcp_ip_default: unable to bind IPv6 socket to port %d",
		    IPPORT_DHCPV6C);
		return (B_FALSE);
	}

	if (iu_register_event(eh, v6_sock_fd, POLLIN, dhcp_acknak_global,
	    NULL) == -1) {
		dhcpmsg(MSG_WARNING, "dhcp_ip_default: cannot register to "
		    "receive IPv6 packets");
		return (B_FALSE);
	}

	return (B_TRUE);
}
