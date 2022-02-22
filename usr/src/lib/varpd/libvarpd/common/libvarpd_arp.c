/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Common routines for implementing proxy arp
 */

#include <sys/types.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/dhcp.h>
#include <libvarpd_impl.h>
#include <sys/vlan.h>
#include <strings.h>
#include <assert.h>

#define	IPV6_VERSION	6

typedef struct varpd_arp_query {
	int				vaq_type;
	char				vaq_buf[ETHERMAX + VLAN_TAGSZ];
	size_t				vaq_bsize;
	uint8_t				vaq_lookup[ETHERADDRL];
	struct sockaddr_storage		vaq_sock;
	varpd_instance_t		*vaq_inst;
	struct ether_arp		*vaq_ea;
	varpd_query_handle_t		*vaq_query;
	const overlay_targ_lookup_t	*vaq_otl;
	ip6_t				*vaq_ip6;
	nd_neighbor_solicit_t		*vaq_ns;
} varpd_arp_query_t;

typedef struct varpd_dhcp_query {
	char				vdq_buf[ETHERMAX + VLAN_TAGSZ];
	size_t				vdq_bsize;
	uint8_t				vdq_lookup[ETHERADDRL];
	const overlay_targ_lookup_t	*vdq_otl;
	varpd_instance_t		*vdq_inst;
	varpd_query_handle_t		*vdq_query;
	struct ether_header		*vdq_ether;
} varpd_dhcp_query_t;

static const uint8_t libvarpd_arp_bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff,
	    0xff };

void
libvarpd_plugin_proxy_arp(varpd_provider_handle_t *hdl,
    varpd_query_handle_t *vqh, const overlay_targ_lookup_t *otl)
{
	varpd_arp_query_t *vaq;
	varpd_instance_t *inst = (varpd_instance_t *)hdl;
	struct ether_arp *ea;
	struct sockaddr_in *ip;

	vaq = umem_alloc(sizeof (varpd_arp_query_t), UMEM_DEFAULT);
	if (vaq == NULL) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		return;
	}
	vaq->vaq_bsize = sizeof (vaq->vaq_buf);

	if (otl->otl_sap != ETHERTYPE_ARP) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	/*
	 * An ARP packet should not be very large because it's definited to only
	 * be allowed to have a single entry at a given time. But our data must
	 * be at least as large as an ether_arp and our header must be at least
	 * as large as a standard ethernet header.
	 */
	if (otl->otl_hdrsize + otl->otl_pktsize > vaq->vaq_bsize ||
	    otl->otl_pktsize < sizeof (struct ether_arp) ||
	    otl->otl_hdrsize < sizeof (struct ether_header)) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	if (libvarpd_overlay_packet(inst->vri_impl, otl, vaq->vaq_buf,
	    &vaq->vaq_bsize) != 0) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	if (otl->otl_hdrsize + otl->otl_pktsize < vaq->vaq_bsize) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	ea = (void *)((uintptr_t)vaq->vaq_buf + (uintptr_t)otl->otl_hdrsize);

	/*
	 * Make sure it matches something that we know about.
	 */
	if (ntohs(ea->ea_hdr.ar_hrd) != ARPHRD_ETHER ||
	    ntohs(ea->ea_hdr.ar_pro) != ETHERTYPE_IP ||
	    ea->ea_hdr.ar_hln != ETHERADDRL ||
	    ea->ea_hdr.ar_pln != sizeof (ea->arp_spa) ||
	    ntohs(ea->ea_hdr.ar_op) != ARPOP_REQUEST) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	/*
	 * Now that we've verified that our data is sane, see if we're doing a
	 * gratuitous arp and if so, drop it. Otherwise, we may end up
	 * triggering duplicate address detection.
	 */
	if (bcmp(ea->arp_spa, ea->arp_tpa, sizeof (ea->arp_spa)) == 0) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	bzero(&vaq->vaq_sock, sizeof (struct sockaddr_storage));
	ip = (struct sockaddr_in *)&vaq->vaq_sock;
	ip->sin_family = AF_INET;
	bcopy(ea->arp_tpa, &ip->sin_addr, sizeof (ea->arp_tpa));

	vaq->vaq_type = AF_INET;
	vaq->vaq_inst = inst;
	vaq->vaq_ea = ea;
	vaq->vaq_query = vqh;
	vaq->vaq_otl = otl;

	if (inst->vri_plugin->vpp_ops->vpo_arp == NULL)
		libvarpd_panic("%s plugin asked to do arp, but has no method",
		    inst->vri_plugin->vpp_name);

	inst->vri_plugin->vpp_ops->vpo_arp(inst->vri_private,
	    (varpd_arp_handle_t *)vaq, VARPD_QTYPE_ETHERNET,
	    (struct sockaddr *)ip, vaq->vaq_lookup);
}

static void
libvarpd_proxy_arp_fini(varpd_arp_query_t *vaq)
{
	struct ether_header *ether;
	struct sockaddr_in *ip;

	ip = (struct sockaddr_in *)&vaq->vaq_sock;
	/*
	 * Modify our packet in place for a reply. We need to swap around the
	 * sender and target addresses.
	 */
	vaq->vaq_ea->ea_hdr.ar_op = htons(ARPOP_REPLY);
	bcopy(vaq->vaq_ea->arp_sha, vaq->vaq_ea->arp_tha, ETHERADDRL);
	bcopy(vaq->vaq_lookup, vaq->vaq_ea->arp_sha, ETHERADDRL);
	bcopy(vaq->vaq_ea->arp_spa, &ip->sin_addr,
	    sizeof (vaq->vaq_ea->arp_spa));
	bcopy(vaq->vaq_ea->arp_tpa, vaq->vaq_ea->arp_spa,
	    sizeof (vaq->vaq_ea->arp_spa));
	bcopy(&ip->sin_addr, vaq->vaq_ea->arp_tpa,
	    sizeof (vaq->vaq_ea->arp_spa));

	/*
	 * Finally go ahead and fix up the mac header and reply to the sender
	 * explicitly.
	 */
	ether = (struct ether_header *)vaq->vaq_buf;
	bcopy(&ether->ether_shost, &ether->ether_dhost, ETHERADDRL);
	bcopy(vaq->vaq_lookup, &ether->ether_shost, ETHERADDRL);

	(void) libvarpd_overlay_inject(vaq->vaq_inst->vri_impl, vaq->vaq_otl,
	    vaq->vaq_buf, vaq->vaq_bsize);

	libvarpd_plugin_query_reply(vaq->vaq_query, VARPD_LOOKUP_DROP);
	umem_free(vaq, sizeof (varpd_arp_query_t));
}

static uint16_t
libvarpd_icmpv6_checksum(const ip6_t *v6hdr, const uint16_t *buf, uint16_t mlen)
{
	int i;
	uint16_t *v;
	uint32_t sum = 0;

	assert(mlen % 2 == 0);
	v = (uint16_t *)&v6hdr->ip6_src;
	for (i = 0; i < sizeof (struct in6_addr); i += 2, v++)
		sum += *v;
	v = (uint16_t *)&v6hdr->ip6_dst;
	for (i = 0; i < sizeof (struct in6_addr); i += 2, v++)
		sum += *v;
	sum += htons(mlen);
#ifdef _BIG_ENDIAN
	sum += IPPROTO_ICMPV6;
#else
	sum += IPPROTO_ICMPV6 << 8;
#endif	/* _BIG_ENDIAN */

	for (i = 0; i < mlen; i += 2, buf++)
		sum += *buf;

	while ((sum >> 16) != 0)
		sum = (sum & 0xffff) + (sum >> 16);

	return (sum & 0xffff);
}

/*
 * Proxying NDP is much more involved than proxying ARP. For starters, NDP
 * neighbor solicitations are implemented in terms of IPv6 ICMP as opposed to
 * its own Ethertype. Therefore, we're going to have to grab a packet if it's a
 * multicast packet and then determine if we actually want to do anything with
 * it.
 */
void
libvarpd_plugin_proxy_ndp(varpd_provider_handle_t *hdl,
    varpd_query_handle_t *vqh, const overlay_targ_lookup_t *otl)
{
	size_t bsize, plen;
	varpd_arp_query_t *vaq;
	ip6_t *v6hdr;
	nd_neighbor_solicit_t *ns;
	nd_opt_hdr_t *opt;
	struct sockaddr_in6 *s6;

	varpd_instance_t *inst = (varpd_instance_t *)hdl;
	uint8_t *eth = NULL;

	vaq = umem_alloc(sizeof (varpd_arp_query_t), UMEM_DEFAULT);
	if (vaq == NULL) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		return;
	}
	vaq->vaq_bsize = sizeof (vaq->vaq_buf);

	if (otl->otl_dstaddr[0] != 0x33 ||
	    otl->otl_dstaddr[1] != 0x33) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	/*
	 * If we have more than a standard frame size for the ICMP neighbor
	 * solicitation, drop it. Similarly if there isn't enough data present
	 * for us, drop it.
	 */
	if (otl->otl_hdrsize + otl->otl_pktsize > vaq->vaq_bsize) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	if (otl->otl_pktsize < sizeof (ip6_t) +
	    sizeof (nd_neighbor_solicit_t)) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	if (libvarpd_overlay_packet(inst->vri_impl, otl, vaq->vaq_buf,
	    &vaq->vaq_bsize) != 0) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	bsize = vaq->vaq_bsize;
	bsize -= otl->otl_hdrsize;
	assert(bsize > sizeof (ip6_t));

	v6hdr = (ip6_t *)(vaq->vaq_buf + otl->otl_hdrsize);
	if (((v6hdr->ip6_vfc & 0xf0) >> 4) != IPV6_VERSION) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	if (v6hdr->ip6_nxt != IPPROTO_ICMPV6) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	/*
	 * In addition to getting these requests on the multicast address for
	 * node solicitation, we may also end up getting them on a generic
	 * multicast address due to timeouts or other choices by various OSes.
	 * We should fairly liberal and accept both, even though the standard
	 * wants them to a solicitation address.
	 */
	if (!IN6_IS_ADDR_MC_SOLICITEDNODE(&v6hdr->ip6_dst) &&
	    !IN6_IS_ADDR_MC_LINKLOCAL(&v6hdr->ip6_dst)) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	bsize -= sizeof (ip6_t);
	plen = ntohs(v6hdr->ip6_plen);
	if (bsize < plen) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	/*
	 * Now we know that this is an ICMPv6 request targeting the right
	 * IPv6 multicast prefix. Let's go through and verify that ICMPv6
	 * indicates that we have the real thing and ensure that per RFC 4861
	 * the target address is not a multicast address. Further, because this
	 * is a multicast on Ethernet, we must have a source link-layer address.
	 *
	 * We should probably enforce that we have a valid ICMP checksum at some
	 * point.
	 */
	ns = (nd_neighbor_solicit_t *)(vaq->vaq_buf + otl->otl_hdrsize +
	    sizeof (ip6_t));
	if (ns->nd_ns_type != ND_NEIGHBOR_SOLICIT && ns->nd_ns_code != 0) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	if (IN6_IS_ADDR_MULTICAST(&ns->nd_ns_target) ||
	    IN6_IS_ADDR_V4MAPPED(&ns->nd_ns_target) ||
	    IN6_IS_ADDR_LOOPBACK(&ns->nd_ns_target)) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	plen -= sizeof (nd_neighbor_solicit_t);
	opt = (nd_opt_hdr_t *)(ns+1);
	while (plen >= sizeof (struct nd_opt_hdr)) {
		/* If we have an option with no lenght, that's clear bogus */
		if (opt->nd_opt_len == 0) {
			libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
			umem_free(vaq, sizeof (varpd_arp_query_t));
			return;
		}

		if (opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR) {
			eth = (uint8_t *)((uintptr_t)opt +
			    sizeof (nd_opt_hdr_t));
		}
		plen -= opt->nd_opt_len * 8;
		opt = (nd_opt_hdr_t *)((uintptr_t)opt +
		    opt->nd_opt_len * 8);
	}

	if (eth == NULL) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	}

	bzero(&vaq->vaq_sock, sizeof (struct sockaddr_storage));
	s6 = (struct sockaddr_in6 *)&vaq->vaq_sock;
	s6->sin6_family = AF_INET6;
	bcopy(&ns->nd_ns_target, &s6->sin6_addr, sizeof (s6->sin6_addr));

	if (inst->vri_plugin->vpp_ops->vpo_arp == NULL)
		libvarpd_panic("%s plugin asked to do arp, but has no method",
		    inst->vri_plugin->vpp_name);

	vaq->vaq_type = AF_INET6;
	vaq->vaq_inst = inst;
	vaq->vaq_ea = NULL;
	vaq->vaq_query = vqh;
	vaq->vaq_otl = otl;
	vaq->vaq_ns = ns;
	vaq->vaq_ip6 = v6hdr;
	inst->vri_plugin->vpp_ops->vpo_arp(inst->vri_private,
	    (varpd_arp_handle_t *)vaq,  VARPD_QTYPE_ETHERNET,
	    (struct sockaddr *)s6, vaq->vaq_lookup);
}

static void
libvarpd_proxy_ndp_fini(varpd_arp_query_t *vaq)
{
	char resp[ETHERMAX + VLAN_TAGSZ];
	struct ether_header *ether;
	nd_neighbor_advert_t *na;
	nd_opt_hdr_t *opt;
	ip6_t *v6hdr;
	size_t roff = 0;

	/*
	 * Now we need to assemble an RA as a response. Unlike with arp, we opt
	 * to use a new packet just to make things a bit simpler saner here.
	 */
	v6hdr = vaq->vaq_ip6;
	bcopy(vaq->vaq_buf, resp, vaq->vaq_otl->otl_hdrsize);
	ether = (struct ether_header *)resp;
	bcopy(&ether->ether_shost, &ether->ether_dhost, ETHERADDRL);
	bcopy(vaq->vaq_lookup, &ether->ether_shost, ETHERADDRL);
	roff += vaq->vaq_otl->otl_hdrsize;
	bcopy(v6hdr, resp + roff, sizeof (ip6_t));
	v6hdr = (ip6_t *)(resp + roff);
	bcopy(&v6hdr->ip6_src, &v6hdr->ip6_dst, sizeof (struct in6_addr));
	bcopy(&vaq->vaq_ns->nd_ns_target, &v6hdr->ip6_src,
	    sizeof (struct in6_addr));
	roff += sizeof (ip6_t);
	na = (nd_neighbor_advert_t *)(resp + roff);
	na->nd_na_type = ND_NEIGHBOR_ADVERT;
	na->nd_na_code = 0;
	/*
	 * RFC 4443 defines that we should set the checksum to zero before we
	 * calculate it.
	 */
	na->nd_na_cksum = 0;
	/*
	 * Nota bene, the header <netinet/icmp6.h> has already transformed this
	 * into the appropriate host order. Don't use htonl.
	 */
	na->nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
	bcopy(&vaq->vaq_ns->nd_ns_target, &na->nd_na_target,
	    sizeof (struct in6_addr));
	roff += sizeof (nd_neighbor_advert_t);

	opt = (nd_opt_hdr_t *)(resp + roff);
	opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	opt->nd_opt_len = 1;
	roff += sizeof (nd_opt_hdr_t);
	bcopy(vaq->vaq_lookup, resp + roff, ETHERADDRL);
	roff += ETHERADDRL;

	/*
	 * Now that we've filled in the packet, go back and compute the checksum
	 * and fill in the IPv6 payload size.
	 */
	v6hdr->ip6_plen = htons(roff - sizeof (ip6_t) -
	    vaq->vaq_otl->otl_hdrsize);
	na->nd_na_cksum = ~libvarpd_icmpv6_checksum(v6hdr, (uint16_t *)na,
	    ntohs(v6hdr->ip6_plen)) & 0xffff;

	(void) libvarpd_overlay_inject(vaq->vaq_inst->vri_impl, vaq->vaq_otl,
	    resp, roff);

	libvarpd_plugin_query_reply(vaq->vaq_query, VARPD_LOOKUP_DROP);
	umem_free(vaq, sizeof (varpd_arp_query_t));
}

void
libvarpd_plugin_arp_reply(varpd_arp_handle_t *vah, int action)
{
	varpd_arp_query_t *vaq = (varpd_arp_query_t *)vah;

	if (vaq == NULL)
		libvarpd_panic("unknown plugin passed invalid "
		    "varpd_arp_handle_t");

	if (action == VARPD_LOOKUP_DROP) {
		libvarpd_plugin_query_reply(vaq->vaq_query, VARPD_LOOKUP_DROP);
		umem_free(vaq, sizeof (varpd_arp_query_t));
		return;
	} else if (action != VARPD_LOOKUP_OK)
		libvarpd_panic("%s plugin returned invalid action %d",
		    vaq->vaq_inst->vri_plugin->vpp_name, action);

	switch (vaq->vaq_type) {
	case AF_INET:
		libvarpd_proxy_arp_fini(vaq);
		break;
	case AF_INET6:
		libvarpd_proxy_ndp_fini(vaq);
		break;
	default:
		libvarpd_panic("encountered unknown vaq_type: %d",
		    vaq->vaq_type);
	}
}

void
libvarpd_plugin_proxy_dhcp(varpd_provider_handle_t *hdl,
    varpd_query_handle_t *vqh, const overlay_targ_lookup_t *otl)
{
	varpd_dhcp_query_t *vdq;
	struct ether_header *ether;
	struct ip *ip;
	struct udphdr *udp;
	varpd_instance_t *inst = (varpd_instance_t *)hdl;

	vdq = umem_alloc(sizeof (varpd_dhcp_query_t), UMEM_DEFAULT);
	if (vdq == NULL) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		return;
	}
	vdq->vdq_bsize = sizeof (vdq->vdq_buf);

	if (otl->otl_sap != ETHERTYPE_IP) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vdq, sizeof (varpd_dhcp_query_t));
		return;
	}

	if (bcmp(otl->otl_dstaddr, libvarpd_arp_bcast, ETHERADDRL) != 0) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vdq, sizeof (varpd_dhcp_query_t));
		return;
	}

	if (otl->otl_hdrsize + otl->otl_pktsize > vdq->vdq_bsize ||
	    otl->otl_pktsize < sizeof (struct ip) + sizeof (struct udphdr) +
	    sizeof (struct dhcp) ||
	    otl->otl_hdrsize < sizeof (struct ether_header)) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vdq, sizeof (varpd_dhcp_query_t));
		return;
	}

	if (libvarpd_overlay_packet(inst->vri_impl, otl, vdq->vdq_buf,
	    &vdq->vdq_bsize) != 0) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vdq, sizeof (varpd_dhcp_query_t));
		return;
	}

	if (vdq->vdq_bsize != otl->otl_hdrsize + otl->otl_pktsize) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vdq, sizeof (varpd_dhcp_query_t));
		return;
	}

	ether = (struct ether_header *)vdq->vdq_buf;
	ip = (struct ip *)(vdq->vdq_buf + otl->otl_hdrsize);

	if (ip->ip_v != IPVERSION && ip->ip_p != IPPROTO_UDP) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vdq, sizeof (varpd_dhcp_query_t));
		return;
	}

	if (otl->otl_hdrsize + ip->ip_hl * 4 + sizeof (struct udphdr) >
	    vdq->vdq_bsize) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vdq, sizeof (varpd_dhcp_query_t));
		return;
	}

	udp = (struct udphdr *)(vdq->vdq_buf + otl->otl_hdrsize +
	    ip->ip_hl * 4);

	if (ntohs(udp->uh_sport) != IPPORT_BOOTPC ||
	    ntohs(udp->uh_dport) != IPPORT_BOOTPS) {
		libvarpd_plugin_query_reply(vqh, VARPD_LOOKUP_DROP);
		umem_free(vdq, sizeof (varpd_dhcp_query_t));
		return;
	}

	vdq->vdq_ether = ether;
	vdq->vdq_inst = inst;
	vdq->vdq_query = vqh;
	vdq->vdq_otl = otl;

	if (inst->vri_plugin->vpp_ops->vpo_dhcp == NULL)
		libvarpd_panic("%s plugin asked to do dhcp, but has no method",
		    inst->vri_plugin->vpp_name);

	inst->vri_plugin->vpp_ops->vpo_dhcp(inst->vri_private,
	    (varpd_dhcp_handle_t *)vdq, VARPD_QTYPE_ETHERNET, otl,
	    vdq->vdq_lookup);
}

void
libvarpd_plugin_dhcp_reply(varpd_dhcp_handle_t *vdh, int action)
{
	varpd_dhcp_query_t *vdq = (varpd_dhcp_query_t *)vdh;

	if (vdq == NULL)
		libvarpd_panic("unknown plugin passed invalid "
		    "varpd_dhcp_handle_t");

	if (action == VARPD_LOOKUP_DROP) {
		libvarpd_plugin_query_reply(vdq->vdq_query, VARPD_LOOKUP_DROP);
		umem_free(vdq, sizeof (varpd_dhcp_query_t));
		return;
	} else if (action != VARPD_LOOKUP_OK)
		libvarpd_panic("%s plugin returned invalid action %d",
		    vdq->vdq_inst->vri_plugin->vpp_name, action);

	bcopy(vdq->vdq_lookup, &vdq->vdq_ether->ether_dhost, ETHERADDRL);
	(void) libvarpd_overlay_resend(vdq->vdq_inst->vri_impl, vdq->vdq_otl,
	    vdq->vdq_buf, vdq->vdq_bsize);

	libvarpd_plugin_query_reply(vdq->vdq_query, VARPD_LOOKUP_DROP);
	umem_free(vdq, sizeof (varpd_dhcp_query_t));
}

/*
 * Inject a gratuitous ARP packet to the specified mac address.
 */
void
libvarpd_inject_arp(varpd_provider_handle_t *vph, const uint16_t vlan,
    const uint8_t *srcmac, const struct in_addr *srcip, const uint8_t *dstmac)
{
	char buf[500];
	size_t bsize = 0;
	struct ether_arp *ea;
	varpd_instance_t *inst = (varpd_instance_t *)vph;

	if (vlan != 0) {
		struct ether_vlan_header *eh;
		eh = (struct ether_vlan_header *)(buf + bsize);
		bsize += sizeof (struct ether_vlan_header);
		bcopy(dstmac, &eh->ether_dhost, ETHERADDRL);
		bcopy(srcmac, &eh->ether_shost, ETHERADDRL);
		eh->ether_tpid = htons(ETHERTYPE_VLAN);
		eh->ether_tci = htons(VLAN_TCI(0, ETHER_CFI, vlan));
		eh->ether_type = htons(ETHERTYPE_ARP);
	} else {
		struct ether_header *eh;
		eh = (struct ether_header *)(buf + bsize);
		bsize += sizeof (struct ether_header);
		bcopy(dstmac, &eh->ether_dhost, ETHERADDRL);
		bcopy(srcmac, &eh->ether_shost, ETHERADDRL);
		eh->ether_type = htons(ETHERTYPE_ARP);
	}

	ea = (struct ether_arp *)(buf + bsize);
	bsize += sizeof (struct ether_arp);
	ea->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	ea->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
	ea->ea_hdr.ar_hln = ETHERADDRL;
	ea->ea_hdr.ar_pln = sizeof (struct in_addr);
	ea->ea_hdr.ar_op = htons(ARPOP_REQUEST);
	bcopy(srcmac, ea->arp_sha, ETHERADDRL);
	bcopy(srcip, ea->arp_spa, sizeof (struct in_addr));
	bcopy(libvarpd_arp_bcast, ea->arp_tha, ETHERADDRL);
	bcopy(srcip, ea->arp_tpa, sizeof (struct in_addr));

	(void) libvarpd_overlay_instance_inject(inst, buf, bsize);
}
