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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/zone.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/atomic.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/sdt.h>
#include <sys/socket.h>
#include <sys/mac.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <net/if_dl.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/arp.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>

#include <netinet/igmp_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/sctp.h>

#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <inet/ip6_asp.h>
#include <inet/tcp.h>
#include <inet/ip_multi.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_rts.h>
#include <inet/optcom.h>
#include <inet/ip_ndp.h>
#include <inet/ip_listutils.h>
#include <netinet/igmp.h>
#include <netinet/ip_mroute.h>
#include <inet/ipp_common.h>

#include <net/pfkeyv2.h>
#include <inet/sadb.h>
#include <inet/ipsec_impl.h>
#include <inet/ipdrop.h>
#include <inet/ip_netinfo.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>

#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>
#include <inet/sctp/sctp_impl.h>
#include <inet/udp_impl.h>
#include <sys/sunddi.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

/*
 * Release a reference on ip_xmit_attr.
 * The reference is acquired by conn_get_ixa()
 */
#define	IXA_REFRELE(ixa)					\
{								\
	if (atomic_add_32_nv(&(ixa)->ixa_refcnt, -1) == 0)	\
		ixa_inactive(ixa);				\
}

#define	IXA_REFHOLD(ixa)					\
{								\
	ASSERT((ixa)->ixa_refcnt != 0);				\
	atomic_add_32(&(ixa)->ixa_refcnt, 1);			\
}

/*
 * When we need to handle a transmit side asynchronous operation, then we need
 * to save sufficient information so that we can call the fragment and postfrag
 * functions. That information is captured in an mblk containing this structure.
 *
 * Since this is currently only used for IPsec, we include information for
 * the kernel crypto framework.
 */
typedef struct ixamblk_s {
	boolean_t	ixm_inbound;	/* B_FALSE */
	iaflags_t	ixm_flags;	/* ixa_flags */
	netstackid_t	ixm_stackid;	/* Verify it didn't go away */
	uint_t		ixm_ifindex;	/* Used to find the nce */
	in6_addr_t	ixm_nceaddr_v6;	/* Used to find nce */
#define	ixm_nceaddr_v4	V4_PART_OF_V6(ixm_nceaddr_v6)
	uint32_t	ixm_fragsize;
	uint_t		ixm_pktlen;
	uint16_t	ixm_ip_hdr_length; /* Points to ULP header */
	uint8_t		ixm_protocol;	/* Protocol number for ULP cksum */
	pfirepostfrag_t	ixm_postfragfn;

	zoneid_t	ixm_zoneid;		/* Needed for ipobs */
	zoneid_t	ixm_no_loop_zoneid;	/* IXAF_NO_LOOP_ZONEID_SET */

	uint_t		ixm_scopeid;		/* For IPv6 link-locals */

	uint32_t	ixm_ident;		/* For IPv6 fragment header */
	uint32_t	ixm_xmit_hint;

	uint64_t	ixm_conn_id;		/* Used by DTrace */
	cred_t		*ixm_cred;	/* For getpeerucred - refhold if set */
	pid_t		ixm_cpid;	/* For getpeerucred */

	ts_label_t	*ixm_tsl;	/* Refhold if set. */

	/*
	 * When the pointers below are set they have a refhold on the struct.
	 */
	ipsec_latch_t		*ixm_ipsec_latch;
	struct ipsa_s		*ixm_ipsec_ah_sa;	/* SA for AH */
	struct ipsa_s		*ixm_ipsec_esp_sa;	/* SA for ESP */
	struct ipsec_policy_s 	*ixm_ipsec_policy;	/* why are we here? */
	struct ipsec_action_s	*ixm_ipsec_action; /* For reflected packets */

	ipsa_ref_t		ixm_ipsec_ref[2]; /* Soft reference to SA */

	/* Need these while waiting for SA */
	uint16_t ixm_ipsec_src_port;	/* Source port number of d-gram. */
	uint16_t ixm_ipsec_dst_port;	/* Destination port number of d-gram. */
	uint8_t  ixm_ipsec_icmp_type;	/* ICMP type of d-gram */
	uint8_t  ixm_ipsec_icmp_code;	/* ICMP code of d-gram */

	sa_family_t ixm_ipsec_inaf;	/* Inner address family */
	uint32_t ixm_ipsec_insrc[IXA_MAX_ADDRLEN];	/* Inner src address */
	uint32_t ixm_ipsec_indst[IXA_MAX_ADDRLEN];	/* Inner dest address */
	uint8_t  ixm_ipsec_insrcpfx;	/* Inner source prefix */
	uint8_t  ixm_ipsec_indstpfx;	/* Inner destination prefix */

	uint8_t ixm_ipsec_proto;	/* IP protocol number for d-gram. */
} ixamblk_t;


/*
 * When we need to handle a receive side asynchronous operation, then we need
 * to save sufficient information so that we can call ip_fanout.
 * That information is captured in an mblk containing this structure.
 *
 * Since this is currently only used for IPsec, we include information for
 * the kernel crypto framework.
 */
typedef struct iramblk_s {
	boolean_t	irm_inbound;	/* B_TRUE */
	iaflags_t	irm_flags;	/* ira_flags */
	netstackid_t	irm_stackid;	/* Verify it didn't go away */
	uint_t		irm_ifindex;	/* To find ira_ill */

	uint_t		irm_rifindex;	/* ira_rifindex */
	uint_t		irm_ruifindex;	/* ira_ruifindex */
	uint_t		irm_pktlen;
	uint16_t	irm_ip_hdr_length; /* Points to ULP header */
	uint8_t		irm_protocol;	/* Protocol number for ULP cksum */
	zoneid_t	irm_zoneid;	/* ALL_ZONES unless local delivery */

	squeue_t	*irm_sqp;
	ill_rx_ring_t	*irm_ring;

	ipaddr_t	irm_mroute_tunnel;	/* IRAF_MROUTE_TUNNEL_SET */
	zoneid_t	irm_no_loop_zoneid;	/* IRAF_NO_LOOP_ZONEID_SET */
	uint32_t	irm_esp_udp_ports;	/* IRAF_ESP_UDP_PORTS */

	char		irm_l2src[IRA_L2SRC_SIZE];	/* If IRAF_L2SRC_SET */

	cred_t		*irm_cred;	/* For getpeerucred - refhold if set */
	pid_t		irm_cpid;	/* For getpeerucred */

	ts_label_t	*irm_tsl;	/* Refhold if set. */

	/*
	 * When set these correspond to a refhold on the object.
	 */
	struct ipsa_s		*irm_ipsec_ah_sa;	/* SA for AH */
	struct ipsa_s		*irm_ipsec_esp_sa;	/* SA for ESP */
	struct ipsec_action_s	*irm_ipsec_action; /* For reflected packets */
} iramblk_t;


/*
 * Take the information in ip_xmit_attr_t and stick it in an mblk
 * that can later be passed to ip_xmit_attr_from_mblk to recreate the
 * ip_xmit_attr_t.
 *
 * Returns NULL on memory allocation failure.
 */
mblk_t *
ip_xmit_attr_to_mblk(ip_xmit_attr_t *ixa)
{
	mblk_t		*ixamp;
	ixamblk_t	*ixm;
	nce_t		*nce = ixa->ixa_nce;

	ASSERT(nce != NULL);
	ixamp = allocb(sizeof (*ixm), BPRI_MED);
	if (ixamp == NULL)
		return (NULL);

	ixamp->b_datap->db_type = M_BREAK;
	ixamp->b_wptr += sizeof (*ixm);
	ixm = (ixamblk_t *)ixamp->b_rptr;

	bzero(ixm, sizeof (*ixm));
	ixm->ixm_inbound = B_FALSE;
	ixm->ixm_flags = ixa->ixa_flags;
	ixm->ixm_stackid = ixa->ixa_ipst->ips_netstack->netstack_stackid;
	ixm->ixm_ifindex = nce->nce_ill->ill_phyint->phyint_ifindex;
	ixm->ixm_nceaddr_v6 = nce->nce_addr;
	ixm->ixm_fragsize = ixa->ixa_fragsize;
	ixm->ixm_pktlen = ixa->ixa_pktlen;
	ixm->ixm_ip_hdr_length = ixa->ixa_ip_hdr_length;
	ixm->ixm_protocol = ixa->ixa_protocol;
	ixm->ixm_postfragfn = ixa->ixa_postfragfn;
	ixm->ixm_zoneid = ixa->ixa_zoneid;
	ixm->ixm_no_loop_zoneid = ixa->ixa_no_loop_zoneid;
	ixm->ixm_scopeid = ixa->ixa_scopeid;
	ixm->ixm_ident = ixa->ixa_ident;
	ixm->ixm_xmit_hint = ixa->ixa_xmit_hint;

	if (ixa->ixa_tsl != NULL) {
		ixm->ixm_tsl = ixa->ixa_tsl;
		label_hold(ixm->ixm_tsl);
	}
	if (ixa->ixa_cred != NULL) {
		ixm->ixm_cred = ixa->ixa_cred;
		crhold(ixa->ixa_cred);
	}
	ixm->ixm_cpid = ixa->ixa_cpid;
	ixm->ixm_conn_id = ixa->ixa_conn_id;

	if (ixa->ixa_flags & IXAF_IPSEC_SECURE) {
		if (ixa->ixa_ipsec_ah_sa != NULL) {
			ixm->ixm_ipsec_ah_sa = ixa->ixa_ipsec_ah_sa;
			IPSA_REFHOLD(ixa->ixa_ipsec_ah_sa);
		}
		if (ixa->ixa_ipsec_esp_sa != NULL) {
			ixm->ixm_ipsec_esp_sa = ixa->ixa_ipsec_esp_sa;
			IPSA_REFHOLD(ixa->ixa_ipsec_esp_sa);
		}
		if (ixa->ixa_ipsec_policy != NULL) {
			ixm->ixm_ipsec_policy = ixa->ixa_ipsec_policy;
			IPPOL_REFHOLD(ixa->ixa_ipsec_policy);
		}
		if (ixa->ixa_ipsec_action != NULL) {
			ixm->ixm_ipsec_action = ixa->ixa_ipsec_action;
			IPACT_REFHOLD(ixa->ixa_ipsec_action);
		}
		if (ixa->ixa_ipsec_latch != NULL) {
			ixm->ixm_ipsec_latch = ixa->ixa_ipsec_latch;
			IPLATCH_REFHOLD(ixa->ixa_ipsec_latch);
		}
		ixm->ixm_ipsec_ref[0] = ixa->ixa_ipsec_ref[0];
		ixm->ixm_ipsec_ref[1] = ixa->ixa_ipsec_ref[1];
		ixm->ixm_ipsec_src_port = ixa->ixa_ipsec_src_port;
		ixm->ixm_ipsec_dst_port = ixa->ixa_ipsec_dst_port;
		ixm->ixm_ipsec_icmp_type = ixa->ixa_ipsec_icmp_type;
		ixm->ixm_ipsec_icmp_code = ixa->ixa_ipsec_icmp_code;
		ixm->ixm_ipsec_inaf = ixa->ixa_ipsec_inaf;
		ixm->ixm_ipsec_insrc[0] = ixa->ixa_ipsec_insrc[0];
		ixm->ixm_ipsec_insrc[1] = ixa->ixa_ipsec_insrc[1];
		ixm->ixm_ipsec_insrc[2] = ixa->ixa_ipsec_insrc[2];
		ixm->ixm_ipsec_insrc[3] = ixa->ixa_ipsec_insrc[3];
		ixm->ixm_ipsec_indst[0] = ixa->ixa_ipsec_indst[0];
		ixm->ixm_ipsec_indst[1] = ixa->ixa_ipsec_indst[1];
		ixm->ixm_ipsec_indst[2] = ixa->ixa_ipsec_indst[2];
		ixm->ixm_ipsec_indst[3] = ixa->ixa_ipsec_indst[3];
		ixm->ixm_ipsec_insrcpfx = ixa->ixa_ipsec_insrcpfx;
		ixm->ixm_ipsec_indstpfx = ixa->ixa_ipsec_indstpfx;
		ixm->ixm_ipsec_proto = ixa->ixa_ipsec_proto;
	}
	return (ixamp);
}

/*
 * Extract the ip_xmit_attr_t from the mblk, checking that the
 * ip_stack_t, ill_t, and nce_t still exist. Returns B_FALSE if that is
 * not the case.
 *
 * Otherwise ixa is updated.
 * Caller needs to release references on the ixa by calling ixa_refrele()
 * which will imediately call ixa_inactive to release the references.
 */
boolean_t
ip_xmit_attr_from_mblk(mblk_t *ixamp, ip_xmit_attr_t *ixa)
{
	ixamblk_t	*ixm;
	netstack_t	*ns;
	ip_stack_t	*ipst;
	ill_t		*ill;
	nce_t		*nce;

	/* We assume the caller hasn't initialized ixa */
	bzero(ixa, sizeof (*ixa));

	ASSERT(DB_TYPE(ixamp) == M_BREAK);
	ASSERT(ixamp->b_cont == NULL);

	ixm = (ixamblk_t *)ixamp->b_rptr;
	ASSERT(!ixm->ixm_inbound);

	/* Verify the netstack is still around */
	ns = netstack_find_by_stackid(ixm->ixm_stackid);
	if (ns == NULL) {
		/* Disappeared on us */
		(void) ip_xmit_attr_free_mblk(ixamp);
		return (B_FALSE);
	}
	ipst = ns->netstack_ip;

	/* Verify the ill is still around */
	ill = ill_lookup_on_ifindex(ixm->ixm_ifindex,
	    !(ixm->ixm_flags & IXAF_IS_IPV4), ipst);

	/* We have the ill, hence the netstack can't go away */
	netstack_rele(ns);
	if (ill == NULL) {
		/* Disappeared on us */
		(void) ip_xmit_attr_free_mblk(ixamp);
		return (B_FALSE);
	}
	/*
	 * Find the nce. We don't load-spread (only lookup nce's on the ill)
	 * because we want to find the same nce as the one we had when
	 * ip_xmit_attr_to_mblk was called.
	 */
	if (ixm->ixm_flags & IXAF_IS_IPV4) {
		nce = nce_lookup_v4(ill, &ixm->ixm_nceaddr_v4);
	} else {
		nce = nce_lookup_v6(ill, &ixm->ixm_nceaddr_v6);
	}

	/* We have the nce, hence the ill can't go away */
	ill_refrele(ill);
	if (nce == NULL) {
		/*
		 * Since this is unusual and we don't know what type of
		 * nce it was, we drop the packet.
		 */
		(void) ip_xmit_attr_free_mblk(ixamp);
		return (B_FALSE);
	}

	ixa->ixa_flags = ixm->ixm_flags;
	ixa->ixa_refcnt = 1;
	ixa->ixa_ipst = ipst;
	ixa->ixa_fragsize = ixm->ixm_fragsize;
	ixa->ixa_pktlen =  ixm->ixm_pktlen;
	ixa->ixa_ip_hdr_length = ixm->ixm_ip_hdr_length;
	ixa->ixa_protocol = ixm->ixm_protocol;
	ixa->ixa_nce = nce;
	ixa->ixa_postfragfn = ixm->ixm_postfragfn;
	ixa->ixa_zoneid = ixm->ixm_zoneid;
	ixa->ixa_no_loop_zoneid = ixm->ixm_no_loop_zoneid;
	ixa->ixa_scopeid = ixm->ixm_scopeid;
	ixa->ixa_ident = ixm->ixm_ident;
	ixa->ixa_xmit_hint = ixm->ixm_xmit_hint;

	if (ixm->ixm_tsl != NULL) {
		ixa->ixa_tsl = ixm->ixm_tsl;
		ixa->ixa_free_flags |= IXA_FREE_TSL;
		ixm->ixm_tsl = NULL;
	}
	if (ixm->ixm_cred != NULL) {
		ixa->ixa_cred = ixm->ixm_cred;
		ixa->ixa_free_flags |= IXA_FREE_CRED;
		ixm->ixm_cred = NULL;
	}
	ixa->ixa_cpid = ixm->ixm_cpid;
	ixa->ixa_conn_id = ixm->ixm_conn_id;

	ixa->ixa_ipsec_ah_sa = ixm->ixm_ipsec_ah_sa;
	ixa->ixa_ipsec_esp_sa = ixm->ixm_ipsec_esp_sa;
	ixa->ixa_ipsec_policy = ixm->ixm_ipsec_policy;
	ixa->ixa_ipsec_action = ixm->ixm_ipsec_action;
	ixa->ixa_ipsec_latch = ixm->ixm_ipsec_latch;

	ixa->ixa_ipsec_ref[0] = ixm->ixm_ipsec_ref[0];
	ixa->ixa_ipsec_ref[1] = ixm->ixm_ipsec_ref[1];
	ixa->ixa_ipsec_src_port = ixm->ixm_ipsec_src_port;
	ixa->ixa_ipsec_dst_port = ixm->ixm_ipsec_dst_port;
	ixa->ixa_ipsec_icmp_type = ixm->ixm_ipsec_icmp_type;
	ixa->ixa_ipsec_icmp_code = ixm->ixm_ipsec_icmp_code;
	ixa->ixa_ipsec_inaf = ixm->ixm_ipsec_inaf;
	ixa->ixa_ipsec_insrc[0] = ixm->ixm_ipsec_insrc[0];
	ixa->ixa_ipsec_insrc[1] = ixm->ixm_ipsec_insrc[1];
	ixa->ixa_ipsec_insrc[2] = ixm->ixm_ipsec_insrc[2];
	ixa->ixa_ipsec_insrc[3] = ixm->ixm_ipsec_insrc[3];
	ixa->ixa_ipsec_indst[0] = ixm->ixm_ipsec_indst[0];
	ixa->ixa_ipsec_indst[1] = ixm->ixm_ipsec_indst[1];
	ixa->ixa_ipsec_indst[2] = ixm->ixm_ipsec_indst[2];
	ixa->ixa_ipsec_indst[3] = ixm->ixm_ipsec_indst[3];
	ixa->ixa_ipsec_insrcpfx = ixm->ixm_ipsec_insrcpfx;
	ixa->ixa_ipsec_indstpfx = ixm->ixm_ipsec_indstpfx;
	ixa->ixa_ipsec_proto = ixm->ixm_ipsec_proto;

	freeb(ixamp);
	return (B_TRUE);
}

/*
 * Free the ixm mblk and any references it holds
 * Returns b_cont.
 */
mblk_t *
ip_xmit_attr_free_mblk(mblk_t *ixamp)
{
	ixamblk_t	*ixm;
	mblk_t		*mp;

	/* Consume mp */
	ASSERT(DB_TYPE(ixamp) == M_BREAK);
	mp = ixamp->b_cont;

	ixm = (ixamblk_t *)ixamp->b_rptr;
	ASSERT(!ixm->ixm_inbound);

	if (ixm->ixm_ipsec_ah_sa != NULL) {
		IPSA_REFRELE(ixm->ixm_ipsec_ah_sa);
		ixm->ixm_ipsec_ah_sa = NULL;
	}
	if (ixm->ixm_ipsec_esp_sa != NULL) {
		IPSA_REFRELE(ixm->ixm_ipsec_esp_sa);
		ixm->ixm_ipsec_esp_sa = NULL;
	}
	if (ixm->ixm_ipsec_policy != NULL) {
		IPPOL_REFRELE(ixm->ixm_ipsec_policy);
		ixm->ixm_ipsec_policy = NULL;
	}
	if (ixm->ixm_ipsec_action != NULL) {
		IPACT_REFRELE(ixm->ixm_ipsec_action);
		ixm->ixm_ipsec_action = NULL;
	}
	if (ixm->ixm_ipsec_latch) {
		IPLATCH_REFRELE(ixm->ixm_ipsec_latch);
		ixm->ixm_ipsec_latch = NULL;
	}

	if (ixm->ixm_tsl != NULL) {
		label_rele(ixm->ixm_tsl);
		ixm->ixm_tsl = NULL;
	}
	if (ixm->ixm_cred != NULL) {
		crfree(ixm->ixm_cred);
		ixm->ixm_cred = NULL;
	}
	freeb(ixamp);
	return (mp);
}

/*
 * Take the information in ip_recv_attr_t and stick it in an mblk
 * that can later be passed to ip_recv_attr_from_mblk to recreate the
 * ip_recv_attr_t.
 *
 * Returns NULL on memory allocation failure.
 */
mblk_t *
ip_recv_attr_to_mblk(ip_recv_attr_t *ira)
{
	mblk_t		*iramp;
	iramblk_t	*irm;
	ill_t		*ill = ira->ira_ill;

	ASSERT(ira->ira_ill != NULL || ira->ira_ruifindex != 0);

	iramp = allocb(sizeof (*irm), BPRI_MED);
	if (iramp == NULL)
		return (NULL);

	iramp->b_datap->db_type = M_BREAK;
	iramp->b_wptr += sizeof (*irm);
	irm = (iramblk_t *)iramp->b_rptr;

	bzero(irm, sizeof (*irm));
	irm->irm_inbound = B_TRUE;
	irm->irm_flags = ira->ira_flags;
	if (ill != NULL) {
		/* Internal to IP - preserve ip_stack_t, ill and rill */
		irm->irm_stackid =
		    ill->ill_ipst->ips_netstack->netstack_stackid;
		irm->irm_ifindex = ira->ira_ill->ill_phyint->phyint_ifindex;
		ASSERT(ira->ira_rill->ill_phyint->phyint_ifindex ==
		    ira->ira_rifindex);
	} else {
		/* Let ip_recv_attr_from_stackid know there isn't one */
		irm->irm_stackid = -1;
	}
	irm->irm_rifindex = ira->ira_rifindex;
	irm->irm_ruifindex = ira->ira_ruifindex;
	irm->irm_pktlen = ira->ira_pktlen;
	irm->irm_ip_hdr_length = ira->ira_ip_hdr_length;
	irm->irm_protocol = ira->ira_protocol;

	irm->irm_sqp = ira->ira_sqp;
	irm->irm_ring = ira->ira_ring;

	irm->irm_zoneid = ira->ira_zoneid;
	irm->irm_mroute_tunnel = ira->ira_mroute_tunnel;
	irm->irm_no_loop_zoneid = ira->ira_no_loop_zoneid;
	irm->irm_esp_udp_ports = ira->ira_esp_udp_ports;

	if (ira->ira_tsl != NULL) {
		irm->irm_tsl = ira->ira_tsl;
		label_hold(irm->irm_tsl);
	}
	if (ira->ira_cred != NULL) {
		irm->irm_cred = ira->ira_cred;
		crhold(ira->ira_cred);
	}
	irm->irm_cpid = ira->ira_cpid;

	if (ira->ira_flags & IRAF_L2SRC_SET)
		bcopy(ira->ira_l2src, irm->irm_l2src, IRA_L2SRC_SIZE);

	if (ira->ira_flags & IRAF_IPSEC_SECURE) {
		if (ira->ira_ipsec_ah_sa != NULL) {
			irm->irm_ipsec_ah_sa = ira->ira_ipsec_ah_sa;
			IPSA_REFHOLD(ira->ira_ipsec_ah_sa);
		}
		if (ira->ira_ipsec_esp_sa != NULL) {
			irm->irm_ipsec_esp_sa = ira->ira_ipsec_esp_sa;
			IPSA_REFHOLD(ira->ira_ipsec_esp_sa);
		}
		if (ira->ira_ipsec_action != NULL) {
			irm->irm_ipsec_action = ira->ira_ipsec_action;
			IPACT_REFHOLD(ira->ira_ipsec_action);
		}
	}
	return (iramp);
}

/*
 * Extract the ip_recv_attr_t from the mblk. If we are used inside IP
 * then irm_stackid is not -1, in which case we check that the
 * ip_stack_t and ill_t still exist. Returns B_FALSE if that is
 * not the case.
 * If irm_stackid is zero then we are used by an ULP (e.g., squeue_enter)
 * and we just proceed with ira_ill and ira_rill as NULL.
 *
 * The caller needs to release any references on the pointers inside the ire
 * by calling ira_cleanup.
 */
boolean_t
ip_recv_attr_from_mblk(mblk_t *iramp, ip_recv_attr_t *ira)
{
	iramblk_t	*irm;
	netstack_t	*ns;
	ip_stack_t	*ipst = NULL;
	ill_t		*ill = NULL, *rill = NULL;

	/* We assume the caller hasn't initialized ira */
	bzero(ira, sizeof (*ira));

	ASSERT(DB_TYPE(iramp) == M_BREAK);
	ASSERT(iramp->b_cont == NULL);

	irm = (iramblk_t *)iramp->b_rptr;
	ASSERT(irm->irm_inbound);

	if (irm->irm_stackid != -1) {
		/* Verify the netstack is still around */
		ns = netstack_find_by_stackid(irm->irm_stackid);
		if (ns == NULL) {
			/* Disappeared on us */
			(void) ip_recv_attr_free_mblk(iramp);
			return (B_FALSE);
		}
		ipst = ns->netstack_ip;

		/* Verify the ill is still around */
		ill = ill_lookup_on_ifindex(irm->irm_ifindex,
		    !(irm->irm_flags & IRAF_IS_IPV4), ipst);

		if (irm->irm_ifindex == irm->irm_rifindex) {
			rill = ill;
		} else {
			rill = ill_lookup_on_ifindex(irm->irm_rifindex,
			    !(irm->irm_flags & IRAF_IS_IPV4), ipst);
		}

		/* We have the ill, hence the netstack can't go away */
		netstack_rele(ns);
		if (ill == NULL || rill == NULL) {
			/* Disappeared on us */
			if (ill != NULL)
				ill_refrele(ill);
			if (rill != NULL && rill != ill)
				ill_refrele(rill);
			(void) ip_recv_attr_free_mblk(iramp);
			return (B_FALSE);
		}
	}

	ira->ira_flags = irm->irm_flags;
	/* Caller must ill_refele(ira_ill) by using ira_cleanup() */
	ira->ira_ill = ill;
	ira->ira_rill = rill;

	ira->ira_rifindex = irm->irm_rifindex;
	ira->ira_ruifindex = irm->irm_ruifindex;
	ira->ira_pktlen = irm->irm_pktlen;
	ira->ira_ip_hdr_length = irm->irm_ip_hdr_length;
	ira->ira_protocol = irm->irm_protocol;

	ira->ira_sqp = irm->irm_sqp;
	/* The rest of IP assumes that the rings never go away. */
	ira->ira_ring = irm->irm_ring;

	ira->ira_zoneid = irm->irm_zoneid;
	ira->ira_mroute_tunnel = irm->irm_mroute_tunnel;
	ira->ira_no_loop_zoneid = irm->irm_no_loop_zoneid;
	ira->ira_esp_udp_ports = irm->irm_esp_udp_ports;

	if (irm->irm_tsl != NULL) {
		ira->ira_tsl = irm->irm_tsl;
		ira->ira_free_flags |= IRA_FREE_TSL;
		irm->irm_tsl = NULL;
	}
	if (irm->irm_cred != NULL) {
		ira->ira_cred = irm->irm_cred;
		ira->ira_free_flags |= IRA_FREE_CRED;
		irm->irm_cred = NULL;
	}
	ira->ira_cpid = irm->irm_cpid;

	if (ira->ira_flags & IRAF_L2SRC_SET)
		bcopy(irm->irm_l2src, ira->ira_l2src, IRA_L2SRC_SIZE);

	ira->ira_ipsec_ah_sa = irm->irm_ipsec_ah_sa;
	ira->ira_ipsec_esp_sa = irm->irm_ipsec_esp_sa;
	ira->ira_ipsec_action = irm->irm_ipsec_action;

	freeb(iramp);
	return (B_TRUE);
}

/*
 * Free the irm mblk and any references it holds
 * Returns b_cont.
 */
mblk_t *
ip_recv_attr_free_mblk(mblk_t *iramp)
{
	iramblk_t	*irm;
	mblk_t		*mp;

	/* Consume mp */
	ASSERT(DB_TYPE(iramp) == M_BREAK);
	mp = iramp->b_cont;

	irm = (iramblk_t *)iramp->b_rptr;
	ASSERT(irm->irm_inbound);

	if (irm->irm_ipsec_ah_sa != NULL) {
		IPSA_REFRELE(irm->irm_ipsec_ah_sa);
		irm->irm_ipsec_ah_sa = NULL;
	}
	if (irm->irm_ipsec_esp_sa != NULL) {
		IPSA_REFRELE(irm->irm_ipsec_esp_sa);
		irm->irm_ipsec_esp_sa = NULL;
	}
	if (irm->irm_ipsec_action != NULL) {
		IPACT_REFRELE(irm->irm_ipsec_action);
		irm->irm_ipsec_action = NULL;
	}
	if (irm->irm_tsl != NULL) {
		label_rele(irm->irm_tsl);
		irm->irm_tsl = NULL;
	}
	if (irm->irm_cred != NULL) {
		crfree(irm->irm_cred);
		irm->irm_cred = NULL;
	}

	freeb(iramp);
	return (mp);
}

/*
 * Returns true if the mblk contains an ip_recv_attr_t
 * For now we just check db_type.
 */
boolean_t
ip_recv_attr_is_mblk(mblk_t *mp)
{
	/*
	 * Need to handle the various forms of tcp_timermp which are tagged
	 * with b_wptr and might have a NULL b_datap.
	 */
	if (mp->b_wptr == NULL || mp->b_wptr == (uchar_t *)-1)
		return (B_FALSE);

#ifdef	DEBUG
	iramblk_t	*irm;

	if (DB_TYPE(mp) != M_BREAK)
		return (B_FALSE);

	irm = (iramblk_t *)mp->b_rptr;
	ASSERT(irm->irm_inbound);
	return (B_TRUE);
#else
	return (DB_TYPE(mp) == M_BREAK);
#endif
}

static ip_xmit_attr_t *
conn_get_ixa_impl(conn_t *connp, boolean_t replace, int kmflag)
{
	ip_xmit_attr_t	*ixa;
	ip_xmit_attr_t	*oldixa;

	mutex_enter(&connp->conn_lock);
	ixa = connp->conn_ixa;

	/* At least one references for the conn_t */
	ASSERT(ixa->ixa_refcnt >= 1);
	if (atomic_add_32_nv(&ixa->ixa_refcnt, 1) == 2) {
		/* No other thread using conn_ixa */
		mutex_exit(&connp->conn_lock);
		return (ixa);
	}
	ixa = kmem_alloc(sizeof (*ixa), kmflag);
	if (ixa == NULL) {
		mutex_exit(&connp->conn_lock);
		ixa_refrele(connp->conn_ixa);
		return (NULL);
	}
	ixa_safe_copy(connp->conn_ixa, ixa);

	/* Make sure we drop conn_lock before any refrele */
	if (replace) {
		ixa->ixa_refcnt++;	/* No atomic needed - not visible */
		oldixa = connp->conn_ixa;
		connp->conn_ixa = ixa;
		mutex_exit(&connp->conn_lock);
		IXA_REFRELE(oldixa);	/* Undo refcnt from conn_t */
	} else {
		oldixa = connp->conn_ixa;
		mutex_exit(&connp->conn_lock);
	}
	IXA_REFRELE(oldixa);	/* Undo above atomic_add_32_nv */

	return (ixa);
}

/*
 * Return an ip_xmit_attr_t to use with a conn_t that ensures that only
 * the caller can access the ip_xmit_attr_t.
 *
 * If nobody else is using conn_ixa we return it.
 * Otherwise we make a "safe" copy of conn_ixa
 * and return it. The "safe" copy has the pointers set to NULL
 * (since the pointers might be changed by another thread using
 * conn_ixa). The caller needs to check for NULL pointers to see
 * if ip_set_destination needs to be called to re-establish the pointers.
 *
 * If 'replace' is set then we replace conn_ixa with the new ip_xmit_attr_t.
 * That is used when we connect() the ULP.
 */
ip_xmit_attr_t *
conn_get_ixa(conn_t *connp, boolean_t replace)
{
	return (conn_get_ixa_impl(connp, replace, KM_NOSLEEP));
}

/*
 * Used only when the option is to have the kernel hang due to not
 * cleaning up ixa references on ills etc.
 */
ip_xmit_attr_t *
conn_get_ixa_tryhard(conn_t *connp, boolean_t replace)
{
	return (conn_get_ixa_impl(connp, replace, KM_SLEEP));
}

/*
 * Replace conn_ixa with the ixa argument.
 *
 * The caller must hold conn_lock.
 *
 * We return the old ixa; the caller must ixa_refrele that after conn_lock
 * has been dropped.
 */
ip_xmit_attr_t *
conn_replace_ixa(conn_t *connp, ip_xmit_attr_t *ixa)
{
	ip_xmit_attr_t	*oldixa;

	ASSERT(MUTEX_HELD(&connp->conn_lock));

	oldixa = connp->conn_ixa;
	IXA_REFHOLD(ixa);
	ixa->ixa_conn_id = oldixa->ixa_conn_id;
	connp->conn_ixa = ixa;
	return (oldixa);
}

/*
 * Return a ip_xmit_attr_t to use with a conn_t that is based on but
 * separate from conn_ixa.
 *
 * This "safe" copy has the pointers set to NULL
 * (since the pointers might be changed by another thread using
 * conn_ixa). The caller needs to check for NULL pointers to see
 * if ip_set_destination needs to be called to re-establish the pointers.
 */
ip_xmit_attr_t *
conn_get_ixa_exclusive(conn_t *connp)
{
	ip_xmit_attr_t *ixa;

	mutex_enter(&connp->conn_lock);
	ixa = connp->conn_ixa;

	/* At least one references for the conn_t */
	ASSERT(ixa->ixa_refcnt >= 1);

	/* Make sure conn_ixa doesn't disappear while we copy it */
	atomic_add_32(&ixa->ixa_refcnt, 1);

	ixa = kmem_alloc(sizeof (*ixa), KM_NOSLEEP);
	if (ixa == NULL) {
		mutex_exit(&connp->conn_lock);
		ixa_refrele(connp->conn_ixa);
		return (NULL);
	}
	ixa_safe_copy(connp->conn_ixa, ixa);
	mutex_exit(&connp->conn_lock);
	IXA_REFRELE(connp->conn_ixa);
	return (ixa);
}

void
ixa_safe_copy(ip_xmit_attr_t *src, ip_xmit_attr_t *ixa)
{
	bcopy(src, ixa, sizeof (*ixa));
	ixa->ixa_refcnt = 1;
	/*
	 * Clear any pointers that have references and might be changed
	 * by ip_set_destination or the ULP
	 */
	ixa->ixa_ire = NULL;
	ixa->ixa_nce = NULL;
	ixa->ixa_dce = NULL;
	ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
	ixa->ixa_dce_generation = DCE_GENERATION_VERIFY;
#ifdef DEBUG
	ixa->ixa_curthread = NULL;
#endif
	/* Clear all the IPsec pointers and the flag as well. */
	ixa->ixa_flags &= ~IXAF_IPSEC_SECURE;

	ixa->ixa_ipsec_latch = NULL;
	ixa->ixa_ipsec_ah_sa = NULL;
	ixa->ixa_ipsec_esp_sa = NULL;
	ixa->ixa_ipsec_policy = NULL;
	ixa->ixa_ipsec_action = NULL;

	/*
	 * We leave ixa_tsl unchanged, but if it has a refhold we need
	 * to get an extra refhold.
	 */
	if (ixa->ixa_free_flags & IXA_FREE_TSL)
		label_hold(ixa->ixa_tsl);

	/*
	 * We leave ixa_cred unchanged, but if it has a refhold we need
	 * to get an extra refhold.
	 */
	if (ixa->ixa_free_flags & IXA_FREE_CRED)
		crhold(ixa->ixa_cred);
}

/*
 * Duplicate an ip_xmit_attr_t.
 * Assumes that the caller controls the ixa, hence we do not need to use
 * a safe copy. We just have to increase the refcnt on any pointers.
 */
ip_xmit_attr_t *
ip_xmit_attr_duplicate(ip_xmit_attr_t *src_ixa)
{
	ip_xmit_attr_t *ixa;

	ixa = kmem_alloc(sizeof (*ixa), KM_NOSLEEP);
	if (ixa == NULL)
		return (NULL);
	bcopy(src_ixa, ixa, sizeof (*ixa));
	ixa->ixa_refcnt = 1;

	if (ixa->ixa_ire != NULL)
		ire_refhold_notr(ixa->ixa_ire);
	if (ixa->ixa_nce != NULL)
		nce_refhold(ixa->ixa_nce);
	if (ixa->ixa_dce != NULL)
		dce_refhold_notr(ixa->ixa_dce);

#ifdef DEBUG
	ixa->ixa_curthread = NULL;
#endif

	if (ixa->ixa_ipsec_latch != NULL)
		IPLATCH_REFHOLD(ixa->ixa_ipsec_latch);
	if (ixa->ixa_ipsec_ah_sa != NULL)
		IPSA_REFHOLD(ixa->ixa_ipsec_ah_sa);
	if (ixa->ixa_ipsec_esp_sa != NULL)
		IPSA_REFHOLD(ixa->ixa_ipsec_esp_sa);
	if (ixa->ixa_ipsec_policy != NULL)
		IPPOL_REFHOLD(ixa->ixa_ipsec_policy);
	if (ixa->ixa_ipsec_action != NULL)
		IPACT_REFHOLD(ixa->ixa_ipsec_action);

	if (ixa->ixa_tsl != NULL) {
		label_hold(ixa->ixa_tsl);
		ixa->ixa_free_flags |= IXA_FREE_TSL;
	}
	if (ixa->ixa_cred != NULL) {
		crhold(ixa->ixa_cred);
		ixa->ixa_free_flags |= IXA_FREE_CRED;
	}
	return (ixa);
}

/*
 * Used to replace the ixa_label field.
 * The caller should have a reference on the label, which we transfer to
 * the attributes so that when the attribute is freed/cleaned up
 * we will release that reference.
 */
void
ip_xmit_attr_replace_tsl(ip_xmit_attr_t *ixa, ts_label_t *tsl)
{
	ASSERT(tsl != NULL);

	if (ixa->ixa_free_flags & IXA_FREE_TSL) {
		ASSERT(ixa->ixa_tsl != NULL);
		label_rele(ixa->ixa_tsl);
	} else {
		ixa->ixa_free_flags |= IXA_FREE_TSL;
	}
	ixa->ixa_tsl = tsl;
}

/*
 * Replace the ip_recv_attr_t's label.
 * Due to kernel RPC's use of db_credp we also need to replace ira_cred;
 * TCP/UDP uses ira_cred to set db_credp for non-socket users.
 * This can fail (and return B_FALSE) due to lack of memory.
 */
boolean_t
ip_recv_attr_replace_label(ip_recv_attr_t *ira, ts_label_t *tsl)
{
	cred_t	*newcr;

	if (ira->ira_free_flags & IRA_FREE_TSL) {
		ASSERT(ira->ira_tsl != NULL);
		label_rele(ira->ira_tsl);
	}
	label_hold(tsl);
	ira->ira_tsl = tsl;
	ira->ira_free_flags |= IRA_FREE_TSL;

	/*
	 * Reset zoneid if we have a shared address. That allows
	 * ip_fanout_tx_v4/v6 to determine the zoneid again.
	 */
	if (ira->ira_flags & IRAF_TX_SHARED_ADDR)
		ira->ira_zoneid = ALL_ZONES;

	/* We update ira_cred for RPC */
	newcr = copycred_from_tslabel(ira->ira_cred, ira->ira_tsl, KM_NOSLEEP);
	if (newcr == NULL)
		return (B_FALSE);
	if (ira->ira_free_flags & IRA_FREE_CRED)
		crfree(ira->ira_cred);
	ira->ira_cred = newcr;
	ira->ira_free_flags |= IRA_FREE_CRED;
	return (B_TRUE);
}

/*
 * This needs to be called after ip_set_destination/tsol_check_dest might
 * have changed ixa_tsl to be specific for a destination, and we now want to
 * send to a different destination.
 * We have to restart with crgetlabel() since ip_set_destination/
 * tsol_check_dest will start with ixa_tsl.
 */
void
ip_xmit_attr_restore_tsl(ip_xmit_attr_t *ixa, cred_t *cr)
{
	if (!is_system_labeled())
		return;

	if (ixa->ixa_free_flags & IXA_FREE_TSL) {
		ASSERT(ixa->ixa_tsl != NULL);
		label_rele(ixa->ixa_tsl);
		ixa->ixa_free_flags &= ~IXA_FREE_TSL;
	}
	ixa->ixa_tsl = crgetlabel(cr);
}

void
ixa_refrele(ip_xmit_attr_t *ixa)
{
	IXA_REFRELE(ixa);
}

void
ixa_inactive(ip_xmit_attr_t *ixa)
{
	ASSERT(ixa->ixa_refcnt == 0);

	ixa_cleanup(ixa);
	kmem_free(ixa, sizeof (*ixa));
}

/*
 * Release any references contained in the ixa.
 * Also clear any fields that are not controlled by ixa_flags.
 */
void
ixa_cleanup(ip_xmit_attr_t *ixa)
{
	if (ixa->ixa_ire != NULL) {
		ire_refrele_notr(ixa->ixa_ire);
		ixa->ixa_ire = NULL;
	}
	if (ixa->ixa_dce != NULL) {
		dce_refrele_notr(ixa->ixa_dce);
		ixa->ixa_dce = NULL;
	}
	if (ixa->ixa_nce != NULL) {
		nce_refrele(ixa->ixa_nce);
		ixa->ixa_nce = NULL;
	}
	ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
	ixa->ixa_dce_generation = DCE_GENERATION_VERIFY;
	if (ixa->ixa_flags & IXAF_IPSEC_SECURE) {
		ipsec_out_release_refs(ixa);
	}
	if (ixa->ixa_free_flags & IXA_FREE_TSL) {
		ASSERT(ixa->ixa_tsl != NULL);
		label_rele(ixa->ixa_tsl);
		ixa->ixa_free_flags &= ~IXA_FREE_TSL;
	}
	ixa->ixa_tsl = NULL;
	if (ixa->ixa_free_flags & IXA_FREE_CRED) {
		ASSERT(ixa->ixa_cred != NULL);
		crfree(ixa->ixa_cred);
		ixa->ixa_free_flags &= ~IXA_FREE_CRED;
	}
	ixa->ixa_cred = NULL;
	ixa->ixa_src_preferences = 0;
	ixa->ixa_ifindex = 0;
	ixa->ixa_multicast_ifindex = 0;
	ixa->ixa_multicast_ifaddr = INADDR_ANY;
}

/*
 * Release any references contained in the ira.
 * Callers which use ip_recv_attr_from_mblk() would pass B_TRUE as the second
 * argument.
 */
void
ira_cleanup(ip_recv_attr_t *ira, boolean_t refrele_ill)
{
	if (ira->ira_ill != NULL) {
		if (ira->ira_rill != ira->ira_ill) {
			/* Caused by async processing */
			ill_refrele(ira->ira_rill);
		}
		if (refrele_ill)
			ill_refrele(ira->ira_ill);
	}
	if (ira->ira_flags & IRAF_IPSEC_SECURE) {
		ipsec_in_release_refs(ira);
	}
	if (ira->ira_free_flags & IRA_FREE_TSL) {
		ASSERT(ira->ira_tsl != NULL);
		label_rele(ira->ira_tsl);
		ira->ira_free_flags &= ~IRA_FREE_TSL;
	}
	ira->ira_tsl = NULL;
	if (ira->ira_free_flags & IRA_FREE_CRED) {
		ASSERT(ira->ira_cred != NULL);
		crfree(ira->ira_cred);
		ira->ira_free_flags &= ~IRA_FREE_CRED;
	}
	ira->ira_cred = NULL;
}

/*
 * Function to help release any IRE, NCE, or DCEs that
 * have been deleted and are marked as condemned.
 * The caller is responsible for any serialization which is different
 * for TCP, SCTP, and others.
 */
static void
ixa_cleanup_stale(ip_xmit_attr_t *ixa)
{
	ire_t		*ire;
	nce_t		*nce;
	dce_t		*dce;

	ire = ixa->ixa_ire;
	nce = ixa->ixa_nce;
	dce = ixa->ixa_dce;

	if (ire != NULL && IRE_IS_CONDEMNED(ire)) {
		ire_refrele_notr(ire);
		ire = ire_blackhole(ixa->ixa_ipst,
		    !(ixa->ixa_flags & IXAF_IS_IPV4));
		ASSERT(ire != NULL);
#ifdef DEBUG
		ire_refhold_notr(ire);
		ire_refrele(ire);
#endif
		ixa->ixa_ire = ire;
		ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
	}
	if (nce != NULL && nce->nce_is_condemned) {
		/* Can make it NULL as long as we set IRE_GENERATION_VERIFY */
		nce_refrele(nce);
		ixa->ixa_nce = NULL;
		ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
	}
	if (dce != NULL && DCE_IS_CONDEMNED(dce)) {
		dce_refrele_notr(dce);
		dce = dce_get_default(ixa->ixa_ipst);
		ASSERT(dce != NULL);
#ifdef DEBUG
		dce_refhold_notr(dce);
		dce_refrele(dce);
#endif
		ixa->ixa_dce = dce;
		ixa->ixa_dce_generation = DCE_GENERATION_VERIFY;
	}
}

static mblk_t *
tcp_ixa_cleanup_getmblk(conn_t *connp)
{
	tcp_stack_t *tcps = connp->conn_netstack->netstack_tcp;
	int need_retry;
	mblk_t *mp;

	mutex_enter(&tcps->tcps_ixa_cleanup_lock);

	/*
	 * It's possible that someone else came in and started cleaning up
	 * another connection between the time we verified this one is not being
	 * cleaned up and the time we actually get the shared mblk.  If that's
	 * the case, we've dropped the lock, and some other thread may have
	 * cleaned up this connection again, and is still waiting for
	 * notification of that cleanup's completion.  Therefore we need to
	 * recheck.
	 */
	do {
		need_retry = 0;
		while (connp->conn_ixa->ixa_tcpcleanup != IXATC_IDLE) {
			cv_wait(&tcps->tcps_ixa_cleanup_done_cv,
			    &tcps->tcps_ixa_cleanup_lock);
		}

		while ((mp = tcps->tcps_ixa_cleanup_mp) == NULL) {
			/*
			 * Multiple concurrent cleanups; need to have the last
			 * one run since it could be an unplumb.
			 */
			need_retry = 1;
			cv_wait(&tcps->tcps_ixa_cleanup_ready_cv,
			    &tcps->tcps_ixa_cleanup_lock);
		}
	} while (need_retry);

	/*
	 * We now have the lock and the mblk; now make sure that no one else can
	 * try to clean up this connection or enqueue it for cleanup, clear the
	 * mblk pointer for this stack, drop the lock, and return the mblk.
	 */
	ASSERT(MUTEX_HELD(&tcps->tcps_ixa_cleanup_lock));
	ASSERT(connp->conn_ixa->ixa_tcpcleanup == IXATC_IDLE);
	ASSERT(tcps->tcps_ixa_cleanup_mp == mp);
	ASSERT(mp != NULL);

	connp->conn_ixa->ixa_tcpcleanup = IXATC_INPROGRESS;
	tcps->tcps_ixa_cleanup_mp = NULL;
	mutex_exit(&tcps->tcps_ixa_cleanup_lock);

	return (mp);
}

/*
 * Used to run ixa_cleanup_stale inside the tcp squeue.
 * When done we hand the mp back by assigning it to tcps_ixa_cleanup_mp
 * and waking up the caller.
 */
/* ARGSUSED2 */
static void
tcp_ixa_cleanup(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *dummy)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_stack_t	*tcps;

	tcps = connp->conn_netstack->netstack_tcp;

	ixa_cleanup_stale(connp->conn_ixa);

	mutex_enter(&tcps->tcps_ixa_cleanup_lock);
	ASSERT(tcps->tcps_ixa_cleanup_mp == NULL);
	connp->conn_ixa->ixa_tcpcleanup = IXATC_COMPLETE;
	tcps->tcps_ixa_cleanup_mp = mp;
	cv_signal(&tcps->tcps_ixa_cleanup_ready_cv);
	/*
	 * It is possible for any number of threads to be waiting for cleanup of
	 * different connections.  Absent a per-connection (or per-IXA) CV, we
	 * need to wake them all up even though only one can be waiting on this
	 * particular cleanup.
	 */
	cv_broadcast(&tcps->tcps_ixa_cleanup_done_cv);
	mutex_exit(&tcps->tcps_ixa_cleanup_lock);
}

static void
tcp_ixa_cleanup_wait_and_finish(conn_t *connp)
{
	tcp_stack_t *tcps = connp->conn_netstack->netstack_tcp;

	mutex_enter(&tcps->tcps_ixa_cleanup_lock);

	ASSERT(connp->conn_ixa->ixa_tcpcleanup != IXATC_IDLE);

	while (connp->conn_ixa->ixa_tcpcleanup == IXATC_INPROGRESS) {
		cv_wait(&tcps->tcps_ixa_cleanup_done_cv,
		    &tcps->tcps_ixa_cleanup_lock);
	}

	ASSERT(connp->conn_ixa->ixa_tcpcleanup == IXATC_COMPLETE);
	connp->conn_ixa->ixa_tcpcleanup = IXATC_IDLE;
	cv_broadcast(&tcps->tcps_ixa_cleanup_done_cv);

	mutex_exit(&tcps->tcps_ixa_cleanup_lock);
}

/*
 * ipcl_walk() function to help release any IRE, NCE, or DCEs that
 * have been deleted and are marked as condemned.
 * Note that we can't cleanup the pointers since there can be threads
 * in conn_ip_output() sending while we are called.
 */
void
conn_ixa_cleanup(conn_t *connp, void *arg)
{
	boolean_t tryhard = (boolean_t)arg;

	if (IPCL_IS_TCP(connp)) {
		mblk_t		*mp;

		mp = tcp_ixa_cleanup_getmblk(connp);

		if (connp->conn_sqp->sq_run == curthread) {
			/* Already on squeue */
			tcp_ixa_cleanup(connp, mp, NULL, NULL);
		} else {
			CONN_INC_REF(connp);
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_ixa_cleanup,
			    connp, NULL, SQ_PROCESS, SQTAG_TCP_IXA_CLEANUP);
		}
		tcp_ixa_cleanup_wait_and_finish(connp);
	} else if (IPCL_IS_SCTP(connp)) {
		sctp_t	*sctp;
		sctp_faddr_t *fp;

		sctp = CONN2SCTP(connp);
		RUN_SCTP(sctp);
		ixa_cleanup_stale(connp->conn_ixa);
		for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->sf_next)
			ixa_cleanup_stale(fp->sf_ixa);
		WAKE_SCTP(sctp);
	} else {
		ip_xmit_attr_t	*ixa;

		/*
		 * If there is a different thread using conn_ixa then we get a
		 * new copy and cut the old one loose from conn_ixa. Otherwise
		 * we use conn_ixa and prevent any other thread from
		 * using/changing it. Anybody using conn_ixa (e.g., a thread in
		 * conn_ip_output) will do an ixa_refrele which will remove any
		 * references on the ire etc.
		 *
		 * Once we are done other threads can use conn_ixa since the
		 * refcnt will be back at one.
		 *
		 * We are called either because an ill is going away, or
		 * due to memory reclaim. In the former case we wait for
		 * memory since we must remove the refcnts on the ill.
		 */
		if (tryhard) {
			ixa = conn_get_ixa_tryhard(connp, B_TRUE);
			ASSERT(ixa != NULL);
		} else {
			ixa = conn_get_ixa(connp, B_TRUE);
			if (ixa == NULL) {
				/*
				 * Somebody else was using it and kmem_alloc
				 * failed! Next memory reclaim will try to
				 * clean up.
				 */
				DTRACE_PROBE1(conn__ixa__cleanup__bail,
				    conn_t *, connp);
				return;
			}
		}
		ixa_cleanup_stale(ixa);
		ixa_refrele(ixa);
	}
}

/*
 * ixa needs to be an exclusive copy so that no one changes the cookie
 * or the ixa_nce.
 */
boolean_t
ixa_check_drain_insert(conn_t *connp, ip_xmit_attr_t *ixa)
{
	uintptr_t cookie = ixa->ixa_cookie;
	ill_dld_direct_t *idd;
	idl_tx_list_t *idl_txl;
	ill_t *ill = ixa->ixa_nce->nce_ill;
	boolean_t inserted = B_FALSE;

	idd = &(ill)->ill_dld_capab->idc_direct;
	idl_txl = &ixa->ixa_ipst->ips_idl_tx_list[IDLHASHINDEX(cookie)];
	mutex_enter(&idl_txl->txl_lock);

	/*
	 * If `cookie' is zero, ip_xmit() -> canputnext() failed -- i.e., flow
	 * control is asserted on an ill that does not support direct calls.
	 * Jump to insert.
	 */
	if (cookie == 0)
		goto tryinsert;

	ASSERT(ILL_DIRECT_CAPABLE(ill));

	if (idd->idd_tx_fctl_df(idd->idd_tx_fctl_dh, cookie) == 0) {
		DTRACE_PROBE1(ill__tx__not__blocked, uintptr_t, cookie);
	} else if (idl_txl->txl_cookie != NULL &&
	    idl_txl->txl_cookie != ixa->ixa_cookie) {
		DTRACE_PROBE2(ill__tx__cookie__collision, uintptr_t, cookie,
		    uintptr_t, idl_txl->txl_cookie);
		/* TODO: bump kstat for cookie collision */
	} else {
		/*
		 * Check/set conn_blocked under conn_lock.  Note that txl_lock
		 * will not suffice since two separate UDP threads may be
		 * racing to send to different destinations that are
		 * associated with different cookies and thus may not be
		 * holding the same txl_lock.  Further, since a given conn_t
		 * can only be on a single drain list, the conn_t will be
		 * enqueued on whichever thread wins this race.
		 */
tryinsert:	mutex_enter(&connp->conn_lock);
		if (connp->conn_blocked) {
			DTRACE_PROBE1(ill__tx__conn__already__blocked,
			    conn_t *, connp);
			mutex_exit(&connp->conn_lock);
		} else {
			connp->conn_blocked = B_TRUE;
			mutex_exit(&connp->conn_lock);
			idl_txl->txl_cookie = cookie;
			conn_drain_insert(connp, idl_txl);
			if (!IPCL_IS_NONSTR(connp))
				noenable(connp->conn_wq);
			inserted = B_TRUE;
		}
	}
	mutex_exit(&idl_txl->txl_lock);
	return (inserted);
}
