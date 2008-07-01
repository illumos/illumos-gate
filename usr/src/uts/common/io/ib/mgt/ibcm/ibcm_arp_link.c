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

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/strlog.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/socket.h>
#include <sys/tihdr.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/ethernet.h>
#include <inet/common.h>	/* for various inet/mi.h and inet/nd.h needs */
#include <inet/mi.h>
#include <inet/arp.h>
#include <inet/ip.h>
#include <inet/ip_multi.h>
#include <inet/ip_ire.h>
#include <inet/ip_rts.h>
#include <inet/ip_if.h>
#include <sys/ib/mgt/ibcm/ibcm_arp.h>
#include <inet/ip_ftable.h>

static areq_t ibcm_arp_areq_template = {
	AR_ENTRY_QUERY,	/* cmd */
	sizeof (areq_t) + (2 * IP_ADDR_LEN),	/* name offset */
	sizeof (areq_t),	/* name len */
	IP_ARP_PROTO_TYPE,	/* protocol, from arps perspective */
	sizeof (areq_t),	/* target addr offset */
	IP_ADDR_LEN,	/* target ADDR_length */
	0,	/* flags */
	sizeof (areq_t) + IP_ADDR_LEN,	/* sender addr offset */
	IP_ADDR_LEN,	/* sender addr length */
	IBCM_ARP_XMIT_COUNT,	/* xmit_count */
	IBCM_ARP_XMIT_INTERVAL,	/* (re)xmit_interval in milliseconds */
	4	/* max # of requests to buffer */
		/*
		 * anything else filled in by the code
		 */
};

static area_t ibcm_arp_area_template = {
	AR_ENTRY_ADD,			/* cmd */
	sizeof (area_t) + IPOIB_ADDRL + (2 * IP_ADDR_LEN), /* name offset */
	sizeof (area_t),		/* name len */
	IP_ARP_PROTO_TYPE,		/* protocol, from arps perspective */
	sizeof (area_t),		/* proto addr offset */
	IP_ADDR_LEN,			/* proto ADDR_length */
	sizeof (area_t) + (IP_ADDR_LEN),	/* proto mask offset */
	0,				/* flags */
	sizeof (area_t) + (2 * IP_ADDR_LEN),	/* hw addr offset */
	IPOIB_ADDRL				/* hw addr length */
};

extern char cmlog[];

_NOTE(SCHEME_PROTECTS_DATA("Unshared data", msgb))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", area_t))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibcm_arp_streams_t))

static void ibcm_arp_timeout(void *arg);
void ibcm_arp_pr_callback(ibcm_arp_prwqn_t *wqnp, int status);

/*
 * issue a AR_ENTRY_QUERY to arp driver and schedule a timeout.
 */
int
ibcm_arp_query_arp(ibcm_arp_prwqn_t *wqnp)
{
	int len;
	int name_len;
	int name_offset;
	char *cp;
	mblk_t *mp;
	mblk_t *mp1;
	areq_t *areqp;
	ibcm_arp_streams_t *ib_s = (ibcm_arp_streams_t *)wqnp->arg;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_query_arp(ib_s: %p wqnp: %p)",
	    ib_s, wqnp);

	name_offset = ibcm_arp_areq_template.areq_name_offset;

	/*
	 * allocate mblk for AR_ENTRY_QUERY
	 */
	name_len = strlen(wqnp->ifname) + 1;
	len = name_len + name_offset;
	if ((mp = allocb(len, BPRI_HI)) == NULL) {
		return (ENOMEM);
	}
	bzero(mp->b_rptr, len);
	mp->b_wptr += len;

	/*
	 * allocate a mblk and set wqnp in the data
	 */
	if ((mp1 = allocb(sizeof (void *), BPRI_HI)) == NULL) {
		freeb(mp);
		return (ENOMEM);
	}

	mp1->b_wptr += sizeof (void *);
	*(uintptr_t *)(void *)mp1->b_rptr = (uintptr_t)wqnp;	/* store wqnp */

	cp = (char *)mp->b_rptr;
	bcopy(&ibcm_arp_areq_template, cp, sizeof (areq_t));
	areqp = (void *)cp;
	areqp->areq_name_length = name_len;

	cp = (char *)areqp + areqp->areq_name_offset;
	bcopy(wqnp->ifname, cp, name_len);

	areqp->areq_proto = wqnp->ifproto;
	bcopy(&wqnp->ifproto, areqp->areq_sap, 2);
	cp = (char *)areqp + areqp->areq_target_addr_offset;
	bcopy(&wqnp->dst_addr.un.ip4addr, cp, IP_ADDR_LEN);
	cp = (char *)areqp + areqp->areq_sender_addr_offset;
	bcopy(&wqnp->src_addr.un.ip4addr, cp, IP_ADDR_LEN);

	mp->b_cont = mp1;

	DB_TYPE(mp) = M_PROTO;

	/*
	 * issue the request to arp
	 */
	wqnp->flags |= IBCM_ARP_PR_ARP_PENDING;
	wqnp->timeout_id = timeout(ibcm_arp_timeout, wqnp,
	    drv_usectohz(IBCM_ARP_TIMEOUT * 1000));
	if (canputnext(ib_s->arpqueue)) {
		putnext(ib_s->arpqueue, mp);
	} else {
		(void) putq(ib_s->arpqueue, mp);
		qenable(ib_s->arpqueue);
	}

	return (0);
}

/*
 * issue AR_ENTRY_SQUERY to arp driver
 */
int
ibcm_arp_squery_arp(ibcm_arp_prwqn_t *wqnp)
{
	int len;
	int name_len;
	char *cp;
	mblk_t *mp;
	mblk_t *mp1;
	area_t *areap;
	uint32_t  proto_mask = 0xffffffff;
	struct iocblk *ioc;
	ibcm_arp_streams_t *ib_s = (ibcm_arp_streams_t *)wqnp->arg;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_squery_arp(ib_s: %p wqnp: %p)",
	    ib_s, wqnp);

	/*
	 * allocate mblk for AR_ENTRY_SQUERY
	 */
	name_len = strlen(wqnp->ifname) + 1;
	len = ibcm_arp_area_template.area_name_offset + name_len +
	    sizeof (uintptr_t);
	if ((mp = allocb(len, BPRI_HI)) == NULL) {
		return (ENOMEM);
	}
	bzero(mp->b_rptr, len);
	mp->b_wptr += len + sizeof (uintptr_t);

	*(uintptr_t *)(void *)mp->b_rptr = (uintptr_t)wqnp;	/* store wqnp */
	mp->b_rptr += sizeof (uintptr_t);


	cp = (char *)mp->b_rptr;
	bcopy(&ibcm_arp_area_template, cp, sizeof (area_t));

	areap = (void *)cp;
	areap->area_cmd = AR_ENTRY_SQUERY;
	areap->area_name_length = name_len;
	cp = (char *)areap + areap->area_name_offset;
	bcopy(wqnp->ifname, cp, name_len);

	cp = (char *)areap + areap->area_proto_addr_offset;
	bcopy(&wqnp->dst_addr.un.ip4addr, cp, IP_ADDR_LEN);

	cp = (char *)areap + areap->area_proto_mask_offset;
	bcopy(&proto_mask, cp, IP_ADDR_LEN);

	mp1 = allocb(sizeof (struct iocblk), BPRI_HI);
	if (mp1 == NULL) {
		freeb(mp);
		return (ENOMEM);
	}
	ioc = (void *)mp1->b_rptr;
	ioc->ioc_cmd = AR_ENTRY_SQUERY;
	ioc->ioc_error = 0;
	ioc->ioc_cr = NULL;
	ioc->ioc_count = msgdsize(mp);
	mp1->b_wptr += sizeof (struct iocblk);
	mp1->b_cont = mp;

	DB_TYPE(mp1) = M_IOCTL;

	if (canputnext(ib_s->arpqueue)) {
		putnext(ib_s->arpqueue, mp1);
	} else {
		(void) putq(ib_s->arpqueue, mp1);
		qenable(ib_s->arpqueue);
	}
	return (0);
}

/*
 * issue a AR_ENTRY_ADD to arp driver
 * This is required as arp driver does not maintain a cache.
 */
int
ibcm_arp_add(ibcm_arp_prwqn_t *wqnp)
{
	int len;
	int name_len;
	char *cp;
	mblk_t *mp;
	area_t *areap;
	uint32_t  proto_mask = 0xffffffff;
	ibcm_arp_streams_t *ib_s = (ibcm_arp_streams_t *)wqnp->arg;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_add(ib_s: %p wqnp: %p)", ib_s, wqnp);

	/*
	 * allocate mblk for AR_ENTRY_ADD
	 */

	name_len = strlen(wqnp->ifname) + 1;
	len = ibcm_arp_area_template.area_name_offset + name_len;
	if ((mp = allocb(len, BPRI_HI)) == NULL) {
		return (ENOMEM);
	}
	bzero(mp->b_rptr, len);
	mp->b_wptr += len;

	cp = (char *)mp->b_rptr;
	bcopy(&ibcm_arp_area_template, cp, sizeof (area_t));

	areap = (void *)mp->b_rptr;
	areap->area_name_length = name_len;
	cp = (char *)areap + areap->area_name_offset;
	bcopy(wqnp->ifname, cp, name_len);

	cp = (char *)areap + areap->area_proto_addr_offset;
	bcopy(&wqnp->dst_addr.un.ip4addr, cp, IP_ADDR_LEN);

	cp = (char *)areap + areap->area_proto_mask_offset;
	bcopy(&proto_mask, cp, IP_ADDR_LEN);

	cp = (char *)areap + areap->area_hw_addr_offset;
	bcopy(&wqnp->dst_mac, cp, IPOIB_ADDRL);

	DB_TYPE(mp) = M_PROTO;

	if (canputnext(ib_s->arpqueue)) {
		putnext(ib_s->arpqueue, mp);
	} else {
		(void) putq(ib_s->arpqueue, mp);
		qenable(ib_s->arpqueue);
	}
	return (0);
}


/*
 * timeout routine when there is no response to AR_ENTRY_QUERY
 */
static void
ibcm_arp_timeout(void *arg)
{
	ibcm_arp_prwqn_t *wqnp = (ibcm_arp_prwqn_t *)arg;
	ibcm_arp_streams_t *ib_s = (ibcm_arp_streams_t *)wqnp->arg;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_timeout(ib_s: %p wqnp: %p)",
	    ib_s, wqnp);

	/*
	 * indicate to user
	 */
	ibcm_arp_pr_callback(wqnp, EHOSTUNREACH);
}

/*
 * delete a wait queue node from the list.
 * assumes mutex is acquired
 */
void
ibcm_arp_prwqn_delete(ibcm_arp_prwqn_t *wqnp)
{
	ibcm_arp_streams_t *ib_s;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_prwqn_delete(%p)", wqnp);

	ib_s = (ibcm_arp_streams_t *)wqnp->arg;
	ib_s->wqnp = NULL;
	kmem_free(wqnp, sizeof (ibcm_arp_prwqn_t));
}

/*
 * allocate a wait queue node, and insert it in the list
 */
ibcm_arp_prwqn_t *
ibcm_arp_create_prwqn(ibcm_arp_streams_t *ib_s, ibt_ip_addr_t *dst_addr,
    ibt_ip_addr_t *src_addr, uint32_t localroute, uint32_t bound_dev_if,
    ibcm_arp_pr_comp_func_t func)
{
	ibcm_arp_prwqn_t *wqnp;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_create_prwqn(ib_s: 0x%p)", ib_s);

	if (dst_addr == NULL) {
		return (NULL);
	}
	if ((wqnp = kmem_zalloc(sizeof (ibcm_arp_prwqn_t), KM_NOSLEEP)) ==
	    NULL) {
		return (NULL);
	}
	wqnp->dst_addr = *dst_addr;

	if (src_addr) {
		wqnp->usrc_addr = *src_addr;
	}
	wqnp->func = func;
	wqnp->arg = ib_s;
	wqnp->localroute = localroute;
	wqnp->bound_dev_if = bound_dev_if;
	wqnp->ifproto = ETHERTYPE_IP;

	ib_s->wqnp = wqnp;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_create_prwqn: Return wqnp: %p", wqnp);

	return (wqnp);
}

/*
 * call the user function
 * called with lock held
 */
void
ibcm_arp_pr_callback(ibcm_arp_prwqn_t *wqnp, int status)
{
	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_pr_callback(%p, %d)", wqnp, status);

	wqnp->func((void *)wqnp, status);
}

static int
ibcm_arp_check_interface(ibcm_arp_prwqn_t *wqnp, int length)
{
	/*
	 * if the i/f is not ib or lo device, fail the request
	 */
	if (bcmp(wqnp->ifname, "ibd", 3) == 0) {
		if (length != IPOIB_ADDRL) {
			return (EINVAL);
		}
	} else if (bcmp(wqnp->ifname, "lo", 2)) {
		return (ETIMEDOUT);
	}

	return (0);
}

#define	IBTL_IPV4_ADDR(a)	(a->un.ip4addr)

int
ibcm_arp_pr_lookup(ibcm_arp_streams_t *ib_s, ibt_ip_addr_t *dst_addr,
    ibt_ip_addr_t *src_addr, uint8_t localroute, uint32_t bound_dev_if,
    ibcm_arp_pr_comp_func_t func)
{
	ibcm_arp_prwqn_t *wqnp;
	ire_t	*ire;
	ire_t	*src_ire;
	ipif_t	*ipif;
	ill_t	*ill;
	int length;
	ip_stack_t *ipst;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_pr_lookup(src %p dest %p)",
	    src_addr, dst_addr);

	if (dst_addr->family != AF_INET_OFFLOAD) {
		ib_s->status = EAFNOSUPPORT;
		return (1);
	}

	if ((wqnp = ibcm_arp_create_prwqn(ib_s, dst_addr,
	    src_addr, localroute, bound_dev_if, func)) == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_pr_lookup: "
		    "ibcm_arp_create_prwqn failed");
		ib_s->status = ENOMEM;
		return (1);
	}

	ipst = netstack_find_by_zoneid(GLOBAL_ZONEID)->netstack_ip;
	/*
	 * Get the ire for the local address
	 */
	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_pr_lookup: srcip %lX destip %lX",
	    IBTL_IPV4_ADDR(src_addr), IBTL_IPV4_ADDR(dst_addr));

	src_ire = ire_ctable_lookup(IBTL_IPV4_ADDR(src_addr), NULL,
	    IRE_LOCAL, NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
	if (src_ire == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_pr_lookup: "
		    "ire_ctable_lookup failed");
		netstack_rele(ipst->ips_netstack);
		ibcm_arp_prwqn_delete(wqnp);
		ib_s->status = EFAULT;
		return (1);
	}


	/*
	 * get an ire for the destination adress with the matching source
	 * address
	 */
	ire = ire_ftable_lookup(IBTL_IPV4_ADDR(dst_addr), 0, 0, 0,
	    src_ire->ire_ipif, 0, src_ire->ire_zoneid, 0, NULL, MATCH_IRE_SRC,
	    ipst);

	netstack_rele(ipst->ips_netstack);

	if (ire == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_pr_lookup: "
		    "ire_ftable_lookup failed");
		IRE_REFRELE(src_ire);
		ibcm_arp_prwqn_delete(wqnp);
		ib_s->status = EFAULT;
		return (1);
	}

	wqnp->src_addr.un.ip4addr = ire->ire_src_addr;
	wqnp->src_addr.family = AF_INET_OFFLOAD;

	ipif = src_ire->ire_ipif;
	ill = ipif->ipif_ill;
	length = ill->ill_name_length;
	bcopy(ill->ill_name, &wqnp->ifname, ill->ill_name_length);
	wqnp->ifname[length] = '\0';
	bcopy(ill->ill_phys_addr, &wqnp->src_mac,
	    ill->ill_phys_addr_length);

	IRE_REFRELE(ire);
	IRE_REFRELE(src_ire);

	ib_s->status =
	    ibcm_arp_check_interface(wqnp, ill->ill_phys_addr_length);
	if (ib_s->status) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_pr_lookup: "
		    "ibcm_arp_check_interface failed");
		ibcm_arp_prwqn_delete(wqnp);
		return (1);
	}

	ib_s->status = ibcm_arp_squery_arp(wqnp);
	if (ib_s->status) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_arp_pr_lookup: "
		    "ibcm_arp_squery_arp failed");
		ibcm_arp_prwqn_delete(wqnp);
		return (1);
	}

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_pr_lookup: Return: 0x%p", wqnp);

	return (0);
}

#define	IBCM_H2N_GID(gid) \
{ \
	uint32_t	*ptr; \
	ptr = (uint32_t *)&gid.gid_prefix; \
	gid.gid_prefix = (uint64_t)(((uint64_t)ntohl(ptr[0]) << 32) | \
			(ntohl(ptr[1]))); \
	ptr = (uint32_t *)&gid.gid_guid; \
	gid.gid_guid = (uint64_t)(((uint64_t)ntohl(ptr[0]) << 32) | \
			(ntohl(ptr[1]))); \
}

/*
 * called from lrsrv.
 * process a AR_ENTRY_QUERY reply from arp
 * the message should be M_DATA -->> dl_unitdata_req
 */
void
ibcm_arp_pr_arp_query_ack(mblk_t *mp)
{
	ibcm_arp_prwqn_t 	*wqnp;
	dl_unitdata_req_t *dlreq;
	ibcm_arp_streams_t *ib_s;
	char *cp;
	int rc;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_pr_arp_query_ack(%p)", mp);

	/*
	 * the first mblk contains the wqnp pointer for the request
	 */
	if (MBLKL(mp) != sizeof (void *)) {
		freemsg(mp);
		return;
	}

	wqnp = *(ibcm_arp_prwqn_t **)(void *)mp->b_rptr; /* retrieve wqnp */
	ib_s = (ibcm_arp_streams_t *)wqnp->arg;

	mutex_enter(&ib_s->lock);

	/*
	 * cancel the timeout for this request
	 */
	(void) untimeout(wqnp->timeout_id);

	/*
	 * sanity checks on the dl_unitdata_req block
	 */
	if (!mp->b_cont) {
		IBTF_DPRINTF_L2(cmlog, "areq_ack: b_cont = NULL\n");
		rc = EPROTO;
		goto user_callback;
	}
	if (MBLKL(mp->b_cont) < (sizeof (dl_unitdata_req_t) + IPOIB_ADDRL)) {
		IBTF_DPRINTF_L2(cmlog, "areq_ack: invalid len in "
		    "dl_unitdatareq_t block\n");
		rc = EPROTO;
		goto user_callback;
	}
	dlreq = (void *)mp->b_cont->b_rptr;
	if (dlreq->dl_primitive != DL_UNITDATA_REQ) {
		IBTF_DPRINTF_L2(cmlog, "areq_ack: invalid dl_primitive "
		    "in dl_unitdatareq_t block\n");
		rc = EPROTO;
		goto user_callback;
	}
	if (dlreq->dl_dest_addr_length != (IPOIB_ADDRL + 2)) {
		IBTF_DPRINTF_L2(cmlog, "areq_ack: invalid hw len in "
		    "dl_unitdatareq_t block %d\n", dlreq->dl_dest_addr_length);
		rc = EPROTO;
		goto user_callback;
	}
	cp = (char *)mp->b_cont->b_rptr + dlreq->dl_dest_addr_offset;
	bcopy(cp, &wqnp->dst_mac, IPOIB_ADDRL);

	/*
	 * at this point we have src/dst gid's derived from the mac addresses
	 * now get the hca, port
	 */
	bcopy(&wqnp->src_mac.ipoib_gidpref, &wqnp->sgid, sizeof (ib_gid_t));
	bcopy(&wqnp->dst_mac.ipoib_gidpref, &wqnp->dgid, sizeof (ib_gid_t));
	freemsg(mp);

	IBCM_H2N_GID(wqnp->sgid);
	IBCM_H2N_GID(wqnp->dgid);

	(void) ibcm_arp_add(wqnp);

	mutex_exit(&ib_s->lock);
	ibcm_arp_pr_callback(wqnp, 0);

	return;
user_callback:
	freemsg(mp);
	mutex_exit(&ib_s->lock);

	/*
	 * indicate to user
	 */
	ibcm_arp_pr_callback(wqnp, rc);
}

/*
 * process a AR_ENTRY_SQUERY reply from arp
 * the message should be M_IOCACK -->> area_t
 */
void
ibcm_arp_pr_arp_squery_ack(mblk_t *mp)
{
	struct iocblk *ioc;
	mblk_t	*mp1;
	ibcm_arp_prwqn_t 	*wqnp;
	ibcm_arp_streams_t *ib_s;
	area_t *areap;
	char *cp;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_pr_arp_squery_ack(%p)", mp);

	if (MBLKL(mp) < sizeof (struct iocblk)) {
		freemsg(mp);
		return;
	}

	ioc = (void *)mp->b_rptr;
	if ((ioc->ioc_cmd != AR_ENTRY_SQUERY) || (mp->b_cont == NULL)) {
		freemsg(mp);
		return;
	}

	mp1 = mp->b_cont;

	wqnp = *(ibcm_arp_prwqn_t **)((uintptr_t)mp1->b_rptr -
	    sizeof (uintptr_t));
	ib_s = (ibcm_arp_streams_t *)wqnp->arg;

	mutex_enter(&ib_s->lock);

	/* If the entry was not in arp cache, ioc_error is set */
	if (ioc->ioc_error) {

		/*
		 * send out AR_ENTRY_QUERY which would send
		 * arp-request on wire
		 */
		IBTF_DPRINTF_L3(cmlog, "Sending a Query_ARP");

		(void) ibcm_arp_query_arp(wqnp);
		freemsg(mp);
		mutex_exit(&ib_s->lock);
		return;
	}

	areap = (void *)mp1->b_rptr;
	cp = (char *)areap + areap->area_hw_addr_offset;
	bcopy(cp, &wqnp->dst_mac, IPOIB_ADDRL);

	/*
	 * at this point we have src/dst gid's derived from the mac addresses
	 * now get the hca, port
	 */
	bcopy(&wqnp->src_mac.ipoib_gidpref, &wqnp->sgid, sizeof (ib_gid_t));
	bcopy(&wqnp->dst_mac.ipoib_gidpref, &wqnp->dgid, sizeof (ib_gid_t));
	freemsg(mp);

	IBCM_H2N_GID(wqnp->sgid);
	IBCM_H2N_GID(wqnp->dgid);

	mutex_exit(&ib_s->lock);
	ibcm_arp_pr_callback(wqnp, 0);
}

/*
 * Process arp ack's.
 */
void
ibcm_arp_pr_arp_ack(mblk_t *mp)
{
	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_pr_arp_ack(0x%p, DB_TYPE %lX)",
	    mp, DB_TYPE(mp));

	if (DB_TYPE(mp) == M_DATA) {
		ibcm_arp_pr_arp_query_ack(mp);
	} else if ((DB_TYPE(mp) == M_IOCACK) ||
	    (DB_TYPE(mp) == M_IOCNAK)) {
		ibcm_arp_pr_arp_squery_ack(mp);
	} else {
		freemsg(mp);
	}
}
