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
 * DL_IPV4 MAC Type plugin for the Nemo mac module
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/dlpi.h>
#include <sys/mac.h>
#include <sys/mac_ipv4.h>
#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/iptun.h>

static struct modlmisc mac_ipv4_modlmisc = {
	&mod_miscops,
	"IPv4 tunneling MAC plugin"
};

static struct modlinkage mac_ipv4_modlinkage = {
	MODREV_1,
	&mac_ipv4_modlmisc,
	NULL
};

static mactype_ops_t mac_ipv4_type_ops;

int
_init(void)
{
	mactype_register_t *mtrp;
	int	err;

	if ((mtrp = mactype_alloc(MACTYPE_VERSION)) == NULL)
		return (ENOTSUP);
	mtrp->mtr_ident = MAC_PLUGIN_IDENT_IPV4;
	mtrp->mtr_ops = &mac_ipv4_type_ops;
	mtrp->mtr_mactype = DL_IPV4;
	mtrp->mtr_nativetype = DL_IPV4;
	mtrp->mtr_addrlen = sizeof (ipaddr_t);
	if ((err = mactype_register(mtrp)) == 0) {
		if ((err = mod_install(&mac_ipv4_modlinkage)) != 0)
			(void) mactype_unregister(MAC_PLUGIN_IDENT_IPV4);
	}
	mactype_free(mtrp);
	return (err);
}

int
_fini(void)
{
	int	err;
	if ((err = mactype_unregister(MAC_PLUGIN_IDENT_IPV4)) != 0)
		return (err);
	return (mod_remove(&mac_ipv4_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&mac_ipv4_modlinkage, modinfop));
}

/*
 * MAC Type plugin operations
 */

/* ARGSUSED */
int
mac_ipv4_unicst_verify(const void *addr, void *pdata)
{
	const ipaddr_t *ipaddr = addr;
	return ((CLASSD(*ipaddr) || (*ipaddr == INADDR_BROADCAST)) ?
	    EINVAL : 0);
}

/* ARGSUSED */
int
mac_ipv4_multicst_verify(const void *addr, void *pdata)
{
	/*
	 * IPv4 configured tunnels do not have the concept of link-layer
	 * multicast.
	 */
	return (ENOTSUP);
}

/*
 * Check the legality of an IPv4 tunnel SAP value.  The only two acceptable
 * values are IPPROTO_ENCAP (IPv4 in IPv4) and IPPROTO_IPV6 (IPv6 in IPv4).
 */
/* ARGSUSED */
boolean_t
mac_ipv4_sap_verify(uint32_t sap, uint32_t *bind_sap, void *pdata)
{
	if (sap == IPPROTO_ENCAP || sap == IPPROTO_IPV6 || sap == 0) {
		if (bind_sap != NULL)
			*bind_sap = sap;
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Build an IPv4 link-layer header for tunneling.  If provided, the
 * template header provided by the driver supplies the header length, type
 * of service, don't fragment flag, ttl, and potential options (depending
 * on the header length).
 */
/* ARGSUSED */
mblk_t *
mac_ipv4_header(const void *saddr, const void *daddr, uint32_t sap, void *pdata,
    mblk_t *payload, size_t extra_len)
{
	struct ip	*iphp;
	struct ip	*tmpl_iphp = pdata;
	mblk_t		*mp;
	size_t		hdr_len = sizeof (struct ip);

	if (!mac_ipv4_sap_verify(sap, NULL, NULL))
		return (NULL);

	if (tmpl_iphp != NULL)
		hdr_len = tmpl_iphp->ip_hl * sizeof (uint32_t);

	if ((mp = allocb(hdr_len + extra_len, BPRI_HI)) == NULL)
		return (NULL);

	iphp = (struct ip *)mp->b_rptr;

	bzero(iphp, hdr_len + extra_len);
	if (tmpl_iphp != NULL) {
		bcopy(tmpl_iphp, iphp, hdr_len);
	} else {
		iphp->ip_hl = IP_SIMPLE_HDR_LENGTH_IN_WORDS;
		iphp->ip_off = htons(IP_DF);
		iphp->ip_ttl = IPTUN_DEFAULT_HOPLIMIT;
	}

	iphp->ip_v = IPVERSION;
	iphp->ip_len = 0;
	iphp->ip_p = (uint8_t)sap;
	bcopy(saddr, &(iphp->ip_src), sizeof (struct in_addr));
	bcopy(daddr, &(iphp->ip_dst), sizeof (struct in_addr));

	mp->b_wptr += hdr_len;
	return (mp);
}

/* ARGSUSED */
int
mac_ipv4_header_info(mblk_t *mp, void *pdata, mac_header_info_t *hdr_info)
{
	struct ip	*iphp;

	if (MBLKL(mp) < sizeof (struct ip))
		return (EINVAL);

	iphp = (struct ip *)mp->b_rptr;

	/*
	 * IPv4 tunnels don't have a concept of link-layer multicast since
	 * they have fixed unicast endpoints.
	 */
	if (mac_ipv4_unicst_verify(&iphp->ip_dst, NULL) != 0)
		return (EINVAL);

	hdr_info->mhi_hdrsize = iphp->ip_hl * sizeof (uint32_t);
	hdr_info->mhi_pktsize = 0;
	hdr_info->mhi_daddr = (const uint8_t *)&(iphp->ip_dst);
	hdr_info->mhi_saddr = (const uint8_t *)&(iphp->ip_src);
	hdr_info->mhi_origsap = hdr_info->mhi_bindsap = iphp->ip_p;
	hdr_info->mhi_dsttype = MAC_ADDRTYPE_UNICAST;
	return (0);
}

/*
 * Plugin data is either NULL or a pointer to an IPv4 header.
 */
boolean_t
mac_ipv4_pdata_verify(void *pdata, size_t pdata_size)
{
	const struct ip	*iphp = pdata;

	if (pdata == NULL)
		return (pdata_size == 0);
	if (pdata_size < sizeof (struct ip))
		return (B_FALSE);
	/* Make sure that the header length field matches pdata_size */
	return (pdata_size == iphp->ip_hl * sizeof (uint32_t));
}

static mactype_ops_t	mac_ipv4_type_ops = {
	MTOPS_PDATA_VERIFY,
	mac_ipv4_unicst_verify,
	mac_ipv4_multicst_verify,
	mac_ipv4_sap_verify,
	mac_ipv4_header,
	mac_ipv4_header_info,
	mac_ipv4_pdata_verify,
	NULL,
	NULL,
	NULL
};
