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

/*
 * DL_IPV6 MAC Type plugin for the Nemo mac module
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/dlpi.h>
#include <sys/mac.h>
#include <sys/mac_ipv6.h>
#include <sys/mac_ipv4_impl.h>
#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <netinet/ip6.h>
#include <inet/common.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/iptun.h>

static struct modlmisc mac_ipv6_modlmisc = {
	&mod_miscops,
	"IPv6 tunneling MAC plugin"
};

static struct modlinkage mac_ipv6_modlinkage = {
	MODREV_1,
	&mac_ipv6_modlmisc,
	NULL
};

static mactype_ops_t mac_ipv6_type_ops;

int
_init(void)
{
	mactype_register_t *mtrp;
	int	err;

	if ((mtrp = mactype_alloc(MACTYPE_VERSION)) == NULL)
		return (EINVAL);
	mtrp->mtr_ident = MAC_PLUGIN_IDENT_IPV6;
	mtrp->mtr_ops = &mac_ipv6_type_ops;
	mtrp->mtr_mactype = DL_IPV6;
	mtrp->mtr_nativetype = DL_IPV6;
	mtrp->mtr_addrlen = sizeof (in6_addr_t);
	if ((err = mactype_register(mtrp)) == 0) {
		if ((err = mod_install(&mac_ipv6_modlinkage)) != 0)
			(void) mactype_unregister(MAC_PLUGIN_IDENT_IPV6);
	}
	mactype_free(mtrp);
	return (err);
}

int
_fini(void)
{
	int	err;
	if ((err = mactype_unregister(MAC_PLUGIN_IDENT_IPV6)) != 0)
		return (err);
	return (mod_remove(&mac_ipv6_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&mac_ipv6_modlinkage, modinfop));
}


/*
 * MAC Type plugin operations
 */

/* ARGSUSED */
int
mac_ipv6_unicst_verify(const void *addr, void *pdata)
{
	const in6_addr_t *in6addr = addr;
	if (IN6_IS_ADDR_UNSPECIFIED(in6addr) ||
	    IN6_IS_ADDR_LOOPBACK(in6addr) ||
	    IN6_IS_ADDR_MULTICAST(in6addr) ||
	    IN6_IS_ADDR_V4MAPPED(in6addr) ||
	    IN6_IS_ADDR_V4COMPAT(in6addr)) {
		return (EINVAL);
	}
	return (0);
}

/*
 * Build an IPv6 link-layer header for tunneling.  If provided, the
 * template header provided by the driver supplies the traffic class, flow
 * label, hop limit, and potential options.  The template's payload length
 * must either be 0 if there are no extension headers, or reflect the size
 * of the extension headers if present.  The template's next header value
 * must either be IPPROTO_NONE if no extension headers are present, or
 * reflect the type of extension header that follows (the same is true for
 * the field values of the extension headers themselves.)
 */
/* ARGSUSED */
mblk_t *
mac_ipv6_header(const void *saddr, const void *daddr, uint32_t sap, void *pdata,
    mblk_t *payload, size_t extra_len)
{
	ip6_t	*ip6hp;
	ip6_t	*tmpl_ip6hp = pdata;
	mblk_t	*mp;
	size_t	hdr_len = sizeof (ip6_t);
	uint8_t	*nxt_proto;

	if (!mac_ipv4_sap_verify(sap, NULL, NULL))
		return (NULL);

	if (tmpl_ip6hp != NULL)
		hdr_len = sizeof (ip6_t) + tmpl_ip6hp->ip6_plen;

	if ((mp = allocb(hdr_len + extra_len, BPRI_HI)) == NULL)
		return (NULL);

	ip6hp = (ip6_t *)mp->b_rptr;

	bzero(ip6hp, hdr_len + extra_len);
	if (tmpl_ip6hp != NULL) {
		bcopy(tmpl_ip6hp, ip6hp, hdr_len);
	} else {
		ip6hp->ip6_nxt = IPPROTO_NONE;
		ip6hp->ip6_hlim = IPTUN_DEFAULT_HOPLIMIT;
	}

	ip6hp->ip6_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
	ip6hp->ip6_plen = 0;

	nxt_proto = &ip6hp->ip6_nxt;
	if (*nxt_proto != IPPROTO_NONE) {
		ip6_dest_t *hdrptr = (ip6_dest_t *)(ip6hp + 1);
		nxt_proto = &hdrptr->ip6d_nxt;
		while (*nxt_proto != IPPROTO_NONE) {
			hdrptr = (ip6_dest_t *)((uint8_t *)hdrptr +
			    (8 * (hdrptr->ip6d_len + 1)));
			nxt_proto = &hdrptr->ip6d_nxt;
		}
	}
	*nxt_proto = (uint8_t)sap;
	bcopy(saddr, &(ip6hp->ip6_src), sizeof (in6_addr_t));
	bcopy(daddr, &(ip6hp->ip6_dst), sizeof (in6_addr_t));

	mp->b_wptr += hdr_len;
	return (mp);
}

/* ARGSUSED */
int
mac_ipv6_header_info(mblk_t *mp, void *pdata, mac_header_info_t *hdr_info)
{
	ip6_t	*ip6hp;
	uint8_t	*whereptr, *endptr;
	uint8_t	nexthdr;

	if (MBLKL(mp) < sizeof (ip6_t))
		return (EINVAL);

	ip6hp = (ip6_t *)mp->b_rptr;

	/*
	 * IPv6 tunnels don't have a concept of link-layer multicast since
	 * they have fixed unicast endpoints.
	 */
	if (mac_ipv6_unicst_verify(&ip6hp->ip6_dst, NULL) != 0)
		return (EINVAL);

	nexthdr = ip6hp->ip6_nxt;
	whereptr = (uint8_t *)(ip6hp + 1);
	endptr = mp->b_wptr;
	while (nexthdr != IPPROTO_ENCAP && nexthdr != IPPROTO_IPV6) {
		ip6_dest_t	*exthdrptr = (ip6_dest_t *)whereptr;

		if (whereptr + sizeof (ip6_dest_t) >= endptr)
			return (EINVAL);

		nexthdr = exthdrptr->ip6d_nxt;
		whereptr += 8 * (exthdrptr->ip6d_len + 1);

		if (whereptr > endptr)
			return (EINVAL);
	}

	hdr_info->mhi_hdrsize = whereptr - mp->b_rptr;
	hdr_info->mhi_pktsize = 0;
	hdr_info->mhi_daddr = (const uint8_t *)&(ip6hp->ip6_dst);
	hdr_info->mhi_saddr = (const uint8_t *)&(ip6hp->ip6_src);
	hdr_info->mhi_bindsap = hdr_info->mhi_origsap = nexthdr;
	hdr_info->mhi_dsttype = MAC_ADDRTYPE_UNICAST;
	return (0);
}

/*
 * This plugin's MAC plugin data is a template IPv6 header followed by
 * optional extension headers.  The chain of headers must be terminated by
 * a header with a next header value of IPPROTO_NONE.  The payload length
 * of the IPv6 header must be 0 if there are no extension headers, or must
 * reflect the total size of extension headers present.
 */
boolean_t
mac_ipv6_pdata_verify(void *pdata, size_t pdata_size)
{
	ip6_t	*ip6hp = pdata;
	uint8_t	*whereptr, *endptr;
	uint8_t	nexthdr;

	/*
	 * Since the plugin does not require plugin data, it is acceptable
	 * for drivers to pass in NULL plugin data as long as the plugin
	 * data size is consistent.
	 */
	if (pdata == NULL)
		return (pdata_size == 0);

	/* First verify that we have enough data to hold an IPv6 header. */
	if (pdata_size < sizeof (ip6_t))
		return (B_FALSE);
	/* Make sure that pdata_size is consistent with the payload length. */
	if (pdata_size != sizeof (ip6_t) + ip6hp->ip6_plen)
		return (B_FALSE);

	/*
	 * Make sure that the header chain is terminated by a header with a
	 * next header value of IPPROTO_NONE.
	 */
	nexthdr = ip6hp->ip6_nxt;
	if (nexthdr == IPPROTO_NONE)
		return (ip6hp->ip6_plen == 0);
	whereptr = (uint8_t *)(ip6hp + 1);
	endptr = (uint8_t *)pdata + pdata_size;

	while (nexthdr != IPPROTO_NONE && whereptr < endptr) {
		ip6_dest_t *hdrptr = (ip6_dest_t *)whereptr;

		/* make sure we're pointing at a complete header */
		if (whereptr + sizeof (ip6_dest_t) > endptr)
			break;
		nexthdr = hdrptr->ip6d_nxt;
		whereptr += 8 * (hdrptr->ip6d_len + 1);
	}

	return (nexthdr == IPPROTO_NONE && whereptr == endptr);
}

static mactype_ops_t mac_ipv6_type_ops = {
	MTOPS_PDATA_VERIFY,
	mac_ipv6_unicst_verify,
	mac_ipv4_multicst_verify, /* neither plugin supports multicast */
	mac_ipv4_sap_verify,	/* same set of legal SAP values */
	mac_ipv6_header,
	mac_ipv6_header_info,
	mac_ipv6_pdata_verify,
	NULL,
	NULL,
	NULL
};
