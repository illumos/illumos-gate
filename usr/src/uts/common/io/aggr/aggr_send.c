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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IEEE 802.3ad Link Aggregation - Send code.
 *
 * Implements the Distributor function.
 */

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/vlan.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>

#include <inet/common.h>
#include <inet/led.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>
#include <netinet/udp.h>
#include <inet/ipsec_impl.h>
#include <inet/sadb.h>
#include <inet/ipsecesp.h>
#include <inet/ipsecah.h>

#include <sys/aggr.h>
#include <sys/aggr_impl.h>

#define	HASH_4BYTES(x) ((x)[0] ^ (x)[1] ^ (x)[2] ^ (x)[3])
#define	HASH_MAC(x) ((x)[0] ^ (x)[1] ^ (x)[2] ^ (x)[3] ^ (x)[4] ^ (x)[5])

static uint16_t aggr_send_ip6_hdr_len(mblk_t *, ip6_t *);

static uint_t
aggr_send_port(aggr_grp_t *grp, mblk_t *mp)
{
	struct ether_header *ehp;
	uint16_t sap;
	uint_t skip_len;
	uint8_t proto;
	uint32_t policy = grp->lg_tx_policy;
	uint32_t hash = 0;

	ASSERT(IS_P2ALIGNED(mp->b_rptr, sizeof (uint16_t)));
	ASSERT(MBLKL(mp) >= sizeof (struct ether_header));

	/* compute MAC hash */

	ehp = (struct ether_header *)mp->b_rptr;

	if (policy & AGGR_POLICY_L2) {
		uchar_t *mac_src = ehp->ether_shost.ether_addr_octet;
		uchar_t *mac_dst = ehp->ether_dhost.ether_addr_octet;
		hash = HASH_MAC(mac_src) ^ HASH_MAC(mac_dst);
		policy &= ~AGGR_POLICY_L2;
	}

	if (policy == 0)
		goto done;

	/* skip ethernet header */

	if (ntohs(ehp->ether_type) == ETHERTYPE_VLAN) {
		struct ether_vlan_header *evhp;

		ASSERT(MBLKL(mp) >= sizeof (struct ether_vlan_header));
		evhp = (struct ether_vlan_header *)mp->b_rptr;
		sap = ntohs(evhp->ether_type);
		skip_len = sizeof (struct ether_vlan_header);
	} else {
		sap = ntohs(ehp->ether_type);
		skip_len = sizeof (struct ether_header);
	}

	/* if ethernet header is in its own mblk, skip it */
	if (MBLKL(mp) <= skip_len) {
		skip_len -= MBLKL(mp);
		mp = mp->b_cont;
	}

	sap = (sap < ETHERTYPE_802_MIN) ? 0 : sap;

	/* compute IP src/dst addresses hash and skip IPv{4,6} header */

	switch (sap) {
	case ETHERTYPE_IP: {
		ipha_t *iphp;

		ASSERT(MBLKL(mp) >= skip_len + sizeof (ipha_t));
		iphp = (ipha_t *)(mp->b_rptr + skip_len);
		proto = iphp->ipha_protocol;
		skip_len += IPH_HDR_LENGTH(iphp);

		if (policy & AGGR_POLICY_L3) {
			uint8_t *ip_src = (uint8_t *)&(iphp->ipha_src);
			uint8_t *ip_dst = (uint8_t *)&(iphp->ipha_dst);

			hash ^= (HASH_4BYTES(ip_src) ^ HASH_4BYTES(ip_dst));
			policy &= ~AGGR_POLICY_L3;
		}
		break;
	}
	case ETHERTYPE_IPV6: {
		ip6_t *ip6hp;

		/*
		 * if ipv6 packet has options, the proto will not be one of the
		 * ones handled by the ULP processor below, and will return 0
		 * as the index
		 */
		ASSERT(MBLKL(mp) >= skip_len + sizeof (ip6_t));
		ip6hp = (ip6_t *)(mp->b_rptr + skip_len);
		proto = ip6hp->ip6_nxt;
		skip_len += aggr_send_ip6_hdr_len(mp, ip6hp);

		if (policy & AGGR_POLICY_L3) {
			uint8_t *ip_src = &(ip6hp->ip6_src.s6_addr8[12]);
			uint8_t *ip_dst = &(ip6hp->ip6_dst.s6_addr8[12]);

			hash ^= (HASH_4BYTES(ip_src) ^ HASH_4BYTES(ip_dst));
			policy &= ~AGGR_POLICY_L3;
		}
		break;
	}
	default:
		goto done;
	}

	if (!(policy & AGGR_POLICY_L4))
		goto done;

	/* if ip header is in its own mblk, skip it */
	if (MBLKL(mp) <= skip_len) {
		skip_len -= MBLKL(mp);
		mp = mp->b_cont;
	}

	/* parse ULP header */
again:
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ESP:
	case IPPROTO_SCTP:
		/*
		 * These Internet Protocols are intentionally designed
		 * for hashing from the git-go.  Port numbers are in the first
		 * word for transports, SPI is first for ESP.
		 */
		hash ^= HASH_4BYTES((mp->b_rptr + skip_len));
		break;

	case IPPROTO_AH: {
		ah_t *ah = (ah_t *)(mp->b_rptr + skip_len);

		uint_t ah_length = AH_TOTAL_LEN(ah);
		proto = ah->ah_nexthdr;
		skip_len += ah_length;

		/* if ip header is in its own mblk, skip it */
		if (MBLKL(mp) <= skip_len) {
			skip_len -= MBLKL(mp);
			mp = mp->b_cont;
		}

		goto again;
	}
	}

done:
	return (hash % grp->lg_ntx_ports);
}

/*
 * Update the TX load balancing policy of the specified group.
 */
void
aggr_send_update_policy(aggr_grp_t *grp, uint32_t policy)
{
	ASSERT(AGGR_LACP_LOCK_HELD(grp));
	ASSERT(RW_WRITE_HELD(&grp->lg_lock));

	grp->lg_tx_policy = policy;
}

/*
 * Send function invoked by the MAC service module.
 */
mblk_t *
aggr_m_tx(void *arg, mblk_t *mp)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port;
	mblk_t *nextp;
	const mac_txinfo_t *mtp;

	for (;;) {
		rw_enter(&grp->lg_lock, RW_READER);
		if (grp->lg_ntx_ports == 0) {
			/*
			 * We could have returned from aggr_m_start() before
			 * the ports were actually attached. Drop the chain.
			 */
			rw_exit(&grp->lg_lock);
			freemsgchain(mp);
			return (NULL);
		}
		nextp = mp->b_next;
		mp->b_next = NULL;

		port = grp->lg_tx_ports[aggr_send_port(grp, mp)];
		ASSERT(port->lp_state == AGGR_PORT_STATE_ATTACHED);

		rw_exit(&grp->lg_lock);

		/*
		 * We store the transmit info pointer locally in case it
		 * changes between loading mt_fn and mt_arg.
		 */
		mtp = port->lp_txinfo;
		if ((mp = mtp->mt_fn(mtp->mt_arg, mp)) != NULL) {
			mp->b_next = nextp;
			break;
		}

		if ((mp = nextp) == NULL)
			break;
	}
	return (mp);
}

/*
 * Enable sending on the specified port.
 */
void
aggr_send_port_enable(aggr_port_t *port)
{
	aggr_grp_t *grp = port->lp_grp;

	if (port->lp_tx_enabled || (port->lp_state !=
	    AGGR_PORT_STATE_ATTACHED)) {
		/* already enabled or port not yet attached */
		return;
	}

	/*
	 * Add to group's array of tx ports.
	 */
	if (grp->lg_tx_ports_size < grp->lg_ntx_ports+1) {
		/* current array too small */
		aggr_port_t **new_ports;
		uint_t new_size;

		new_size = grp->lg_ntx_ports+1;
		new_ports = kmem_zalloc(new_size * sizeof (aggr_port_t *),
		    KM_SLEEP);

		if (grp->lg_tx_ports_size > 0) {
			ASSERT(grp->lg_tx_ports != NULL);
			bcopy(grp->lg_tx_ports, new_ports,
			    grp->lg_ntx_ports * sizeof (aggr_port_t *));
			kmem_free(grp->lg_tx_ports,
			    grp->lg_tx_ports_size * sizeof (aggr_port_t *));
		}

		grp->lg_tx_ports = new_ports;
		grp->lg_tx_ports_size = new_size;
	}

	grp->lg_tx_ports[grp->lg_ntx_ports++] = port;
	port->lp_tx_idx = grp->lg_ntx_ports-1;

	port->lp_tx_enabled = B_TRUE;
}

/*
 * Disable sending from the specified port.
 */
void
aggr_send_port_disable(aggr_port_t *port)
{
	uint_t idx, ntx;
	aggr_grp_t *grp = port->lp_grp;

	ASSERT(RW_WRITE_HELD(&port->lp_lock));

	if (!port->lp_tx_enabled) {
		/* not yet enabled */
		return;
	}

	idx = port->lp_tx_idx;
	ntx = grp->lg_ntx_ports;
	ASSERT(idx < ntx);

	/* remove from array of attached ports */
	if (idx == (ntx - 1)) {
		grp->lg_tx_ports[idx] = NULL;
	} else {
		/* not the last entry, replace with last one */
		aggr_port_t *victim;

		victim = grp->lg_tx_ports[ntx - 1];
		grp->lg_tx_ports[ntx - 1] = NULL;
		victim->lp_tx_idx = idx;
		grp->lg_tx_ports[idx] = victim;
	}

	port->lp_tx_idx = 0;
	grp->lg_ntx_ports--;

	port->lp_tx_enabled = B_FALSE;
}

static uint16_t
aggr_send_ip6_hdr_len(mblk_t *mp, ip6_t *ip6h)
{
	uint16_t length;
	uint_t	ehdrlen;
	uint8_t	*nexthdrp;
	uint8_t *whereptr;
	uint8_t *endptr;
	ip6_dest_t *desthdr;
	ip6_rthdr_t *rthdr;
	ip6_frag_t *fraghdr;

	length = IPV6_HDR_LEN;
	whereptr = ((uint8_t *)&ip6h[1]); /* point to next hdr */
	endptr = mp->b_wptr;

	nexthdrp = &ip6h->ip6_nxt;
	while (whereptr < endptr) {
		switch (*nexthdrp) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
			/* Assumes the headers are identical for hbh and dst */
			desthdr = (ip6_dest_t *)whereptr;
			ehdrlen = 8 * (desthdr->ip6d_len + 1);
			nexthdrp = &desthdr->ip6d_nxt;
			break;
		case IPPROTO_ROUTING:
			rthdr = (ip6_rthdr_t *)whereptr;
			ehdrlen =  8 * (rthdr->ip6r_len + 1);
			nexthdrp = &rthdr->ip6r_nxt;
			break;
		case IPPROTO_FRAGMENT:
			fraghdr = (ip6_frag_t *)whereptr;
			ehdrlen = sizeof (ip6_frag_t);
			nexthdrp = &fraghdr->ip6f_nxt;
			break;
		case IPPROTO_NONE:
			/* No next header means we're finished */
		default:
			return (length);
		}
		length += ehdrlen;
		whereptr += ehdrlen;
	}

	return (length);
}
