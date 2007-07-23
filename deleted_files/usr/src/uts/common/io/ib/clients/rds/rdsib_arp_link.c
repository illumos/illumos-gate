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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/ib/clients/ibd/ibd.h>
#include <sys/ib/clients/rds/rdsib_arp.h>
#include <sys/ib/clients/rds/rdsib_debug.h>
#include <inet/ip_ftable.h>

extern int rds_pr_cache;

#define	RDS_RTM_LEN		0x158
#define	RDS_ARP_XMIT_COUNT	6
#define	RDS_ARP_XMIT_INTERVAL	1000

static areq_t rds_areq_template = {
	AR_ENTRY_QUERY,	/* cmd */
	sizeof (areq_t) + (2 * IP_ADDR_LEN),	/* name offset */
	sizeof (areq_t),	/* name len */
	IP_ARP_PROTO_TYPE,	/* protocol, from arps perspective */
	sizeof (areq_t),	/* target addr offset */
	IP_ADDR_LEN,	/* target ADDR_length */
	0,	/* flags */
	sizeof (areq_t) + IP_ADDR_LEN,	/* sender addr offset */
	IP_ADDR_LEN,	/* sender addr length */
	RDS_ARP_XMIT_COUNT,	/* xmit_count */
	RDS_ARP_XMIT_INTERVAL,	/* (re)xmit_interval in milliseconds */
	4	/* max # of requests to buffer */
		/*
		 * anything else filled in by the code
		 */
};

static area_t rds_area_template = {
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

static void rds_arp_timeout(void *arg);
#ifdef DEBUG
void print_ib_mac(char *str, uint8_t *mac);
void print_ib_gid(char *str, uint8_t *mac);
#endif
extern int rds_get_hca_info(rds_prwqn_t *wqnp);
void rds_pr_callback(rds_prwqn_t *wqnp, int status);

/*
 * issue a AR_ENTRY_QUERY to arp driver and schedule a timeout.
 */
int
rds_query_arp(rds_prwqn_t *wqnp)
{
	int len;
	int name_len;
	int name_offset;
	char *cp;
	mblk_t *mp;
	mblk_t *mp1;
	areq_t *areqp;
	rds_streams_t *rdss = (rds_streams_t *)wqnp->arg;

	RDS_DPRINTF4("rds_query_arp", "Enter: rdss: 0x%p wqnp: 0x%p", rdss,
	    wqnp);

	name_offset = rds_areq_template.areq_name_offset;

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
	/* LINTED */
	*(uintptr_t *)mp1->b_rptr = (uintptr_t)wqnp;	/* store wqnp */

	cp = (char *)mp->b_rptr;
	bcopy(&rds_areq_template, cp, sizeof (areq_t));
	/* LINTED */
	areqp = (areq_t *)cp;
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
	wqnp->flags |= RDS_PR_ARP_PENDING;
	wqnp->timeout_id = timeout(rds_arp_timeout, wqnp,
		drv_usectohz(RDS_ARP_TIMEOUT * 1000));
	if (canputnext(rdss->arpqueue)) {
		putnext(rdss->arpqueue, mp);
	} else {
		(void) putq(rdss->arpqueue, mp);
		qenable(rdss->arpqueue);
	}

	RDS_DPRINTF4("rds_query_arp", "Return: 0x%p", wqnp);
	return (0);
}

/*
 * issue AR_ENTRY_SQUERY to arp driver
 */
int
rds_squery_arp(rds_prwqn_t *wqnp)
{
	int len;
	int name_len;
	char *cp;
	mblk_t *mp;
	mblk_t *mp1;
	area_t *areap;
	uint32_t  proto_mask = 0xffffffff;
	struct iocblk *ioc;
	rds_streams_t *rdss = (rds_streams_t *)wqnp->arg;

	RDS_DPRINTF4("rds_squery_arp", "Enter: rdss: 0x%p wqnp: 0x%p", rdss,
	    wqnp);

	/*
	 * allocate mblk for AR_ENTRY_SQUERY
	 */
	name_len = strlen(wqnp->ifname) + 1;
	len = rds_area_template.area_name_offset +
			name_len + sizeof (uintptr_t);
	if ((mp = allocb(len, BPRI_HI)) == NULL) {
		return (ENOMEM);
	}
	bzero(mp->b_rptr, len);
	mp->b_wptr += len + sizeof (uintptr_t);

	/* LINTED */
	*(uintptr_t *)mp->b_rptr = (uintptr_t)wqnp;	/* store wqnp */
	mp->b_rptr += sizeof (uintptr_t);


	cp = (char *)mp->b_rptr;
	bcopy(&rds_area_template, cp, sizeof (area_t));

	/* LINTED */
	areap = (area_t *)cp;
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
	/* LINTED */
	ioc = (struct iocblk *)mp1->b_rptr;
	ioc->ioc_cmd = AR_ENTRY_SQUERY;
	ioc->ioc_error = 0;
	ioc->ioc_cr = NULL;
	ioc->ioc_count = msgdsize(mp);
	mp1->b_wptr += sizeof (struct iocblk);
	mp1->b_cont = mp;

	DB_TYPE(mp1) = M_IOCTL;

	if (canputnext(rdss->arpqueue)) {
		putnext(rdss->arpqueue, mp1);
	} else {
		(void) putq(rdss->arpqueue, mp1);
		qenable(rdss->arpqueue);
	}
	RDS_DPRINTF4("rds_squery_arp", "Return: 0x%p", wqnp);
	return (0);
}

/*
 * issue a AR_ENTRY_ADD to arp driver
 * This is required as arp driver does not maintain a cache.
 */
int
rds_arp_add(rds_prwqn_t *wqnp)
{
	int len;
	int name_len;
	char *cp;
	mblk_t *mp;
	area_t *areap;
	uint32_t  proto_mask = 0xffffffff;
	rds_streams_t *rdss = (rds_streams_t *)wqnp->arg;

	RDS_DPRINTF4("rds_arp_add", "Enter: rdss: 0x%p wqnp: 0x%p", rdss,
	    wqnp);

	/*
	 * allocate mblk for AR_ENTRY_ADD
	 */

	name_len = strlen(wqnp->ifname) + 1;
	len = rds_area_template.area_name_offset + name_len;
	if ((mp = allocb(len, BPRI_HI)) == NULL) {
		return (ENOMEM);
	}
	bzero(mp->b_rptr, len);
	mp->b_wptr += len;

	cp = (char *)mp->b_rptr;
	bcopy(&rds_area_template, cp, sizeof (area_t));

	/* LINTED */
	areap = (area_t *)mp->b_rptr;
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

	if (canputnext(rdss->arpqueue)) {
		putnext(rdss->arpqueue, mp);
	} else {
		(void) putq(rdss->arpqueue, mp);
		qenable(rdss->arpqueue);
	}
	RDS_DPRINTF4("rds_arp_add", "Return: 0x%p", wqnp);
	return (0);
}


/*
 * timeout routine when there is no response to AR_ENTRY_QUERY
 */
static void
rds_arp_timeout(void *arg)
{
	rds_prwqn_t *wqnp = (rds_prwqn_t *)arg;
	rds_streams_t *rdss = (rds_streams_t *)wqnp->arg;

	RDS_DPRINTF4("rds_arp_timeout", "Enter: rdss: 0x%p wqnp: 0x%p", rdss,
	    wqnp);

	/*
	 * indicate to user
	 */
	rds_pr_callback(wqnp, EHOSTUNREACH);

	RDS_DPRINTF4("rds_arp_timeout", "Return: 0x%p", wqnp);
}

/*
 * delete a wait queue node from the list.
 * assumes mutex is acquired
 */
void
rds_prwqn_delete(rds_prwqn_t *wqnp)
{
	rds_streams_t *rdss;

	RDS_DPRINTF4("rds_prwqn_delete", "Enter: 0x%p", wqnp);

	rdss = (rds_streams_t *)wqnp->arg;
	rdss->wqnp = NULL;
	kmem_free(wqnp, sizeof (rds_prwqn_t));

	RDS_DPRINTF4("rds_prwqn_delete", "Return: 0x%p", wqnp);
}

/*
 * allocate a wait queue node, and insert it in the list
 */
rds_prwqn_t *
rds_create_prwqn(rds_streams_t *rdss, rds_ipx_addr_t *dst_addr,
    rds_ipx_addr_t *src_addr, uint32_t localroute, uint32_t bound_dev_if,
    rds_pr_comp_func_t func)
{
	rds_prwqn_t *wqnp;

	RDS_DPRINTF4("rds_create_prwqn", "Enter: rdss: 0x%p", rdss);

	if (dst_addr == NULL) {
		return (NULL);
	}
	if ((wqnp = kmem_zalloc(sizeof (rds_prwqn_t), KM_NOSLEEP)) == NULL) {
		return (NULL);
	}

	if (src_addr) {
		wqnp->usrc_addr = *src_addr;
	}
	wqnp->dst_addr = *dst_addr;
	wqnp->func = func;
	wqnp->arg = rdss;
	wqnp->localroute = localroute;
	wqnp->bound_dev_if = bound_dev_if;
	wqnp->ifproto = ETHERTYPE_IP;

	rdss->wqnp = wqnp;

	RDS_DPRINTF4("rds_create_prwqn", "Return: wqnp: 0x%p", wqnp);

	return (wqnp);
}

/*
 * call the user function
 * called with lock held
 */
void
rds_pr_callback(rds_prwqn_t *wqnp, int status)
{
	RDS_DPRINTF4("rds_pr_callback", "Enter: 0x%p", wqnp);

	wqnp->func((void *)wqnp, status);

	RDS_DPRINTF4("rds_pr_callback", "Return: 0x%p", wqnp);
}

static int
rds_check_interface(rds_prwqn_t *wqnp, int length)
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

int
rds_pr_lookup(rds_streams_t *rdss, rds_ipx_addr_t *dst_addr,
    rds_ipx_addr_t *src_addr, uint8_t localroute, uint32_t bound_dev_if,
    rds_pr_comp_func_t func)
{
	rds_prwqn_t *wqnp;
	ire_t	*ire;
	ire_t	*src_ire;
	ipif_t	*ipif;
	ill_t	*ill;
	int length;
	ip_stack_t *ipst;



	RDS_DPRINTF4("rds_pr_lookup", "Enter: src 0x%x dest 0x%x", src_addr,
	    dst_addr);

	if (dst_addr->family != AF_INET_OFFLOAD) {
		rdss->status = EAFNOSUPPORT;
		return (1);
	}

	if ((wqnp = rds_create_prwqn(rdss, dst_addr,
		src_addr, localroute, bound_dev_if, func)) == NULL) {
		rdss->status = ENOMEM;
		return (1);
	}

	ipst = netstack_find_by_zoneid(GLOBAL_ZONEID)->netstack_ip;
	/*
	 * Get the ire for the local address
	 */

	src_ire = ire_ctable_lookup(RDS_IPV4_ADDR(src_addr), NULL,
	    IRE_LOCAL, NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);


	if (src_ire == NULL) {
		netstack_rele(ipst->ips_netstack);
		rds_prwqn_delete(wqnp);
		rdss->status = EFAULT;
		return (1);
	}


	/*
	 * get an ire for the destination adress with the matching source
	 * address
	 */
	ire = ire_ftable_lookup(RDS_IPV4_ADDR(dst_addr), 0, 0, 0,
	    src_ire->ire_ipif, 0, src_ire->ire_zoneid, 0, NULL, MATCH_IRE_SRC,
	    ipst);

	netstack_rele(ipst->ips_netstack);

	if (ire == NULL) {
		IRE_REFRELE(src_ire);
		rds_prwqn_delete(wqnp);
		rdss->status = EFAULT;
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

	rdss->status = rds_check_interface(wqnp, ill->ill_phys_addr_length);
	if (rdss->status) {
		rds_prwqn_delete(wqnp);
		return (1);
	}

	rdss->status = rds_squery_arp(wqnp);
	if (rdss->status) {
		rds_prwqn_delete(wqnp);
		return (1);
	}

	RDS_DPRINTF4("rds_pr_lookup", "Return: 0x%p", wqnp);

	return (0);
}

#define	H2N_GID(gid) \
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
rds_pr_arp_query_ack(mblk_t *mp)
{
	rds_prwqn_t 	*wqnp;
	dl_unitdata_req_t *dlreq;
	rds_streams_t *rdss;
	char *cp;
	int rc;

	RDS_DPRINTF4("rds_pr_arp_query_ack", "Enter: 0x%p", mp);

	/*
	 * the first mblk contains the wqnp pointer for the request
	 */
	/* LINTED */
	if (MBLKL(mp) != sizeof (void *)) {
		freemsg(mp);
		return;
	}

	/* LINTED */
	wqnp = *(rds_prwqn_t **)mp->b_rptr;	/* retrieve wqnp */
	rdss = (rds_streams_t *)wqnp->arg;

	mutex_enter(&rdss->lock);

	/*
	 * cancel the timeout for this request
	 */
	(void) untimeout(wqnp->timeout_id);

	/*
	 * sanity checks on the dl_unitdata_req block
	 */
	if (!mp->b_cont) {
		RDS_DPRINTF1(LABEL, "areq_ack: b_cont = NULL\n");
		rc = EPROTO;
		goto user_callback;
	}
	/* LINTED */
	if (MBLKL(mp->b_cont) < (sizeof (dl_unitdata_req_t) + IPOIB_ADDRL)) {
		RDS_DPRINTF1(LABEL, "areq_ack: invalid len in "
			"dl_unitdatareq_t block\n");
		rc = EPROTO;
		goto user_callback;
	}
	/* LINTED */
	dlreq = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	if (dlreq->dl_primitive != DL_UNITDATA_REQ) {
		RDS_DPRINTF1(LABEL, "areq_ack: invalid dl_primitive in "
			"dl_unitdatareq_t block\n");
		rc = EPROTO;
		goto user_callback;
	}
	if (dlreq->dl_dest_addr_length != (IPOIB_ADDRL + 2)) {
		RDS_DPRINTF1(LABEL, "areq_ack: invalid hw len in "
			"dl_unitdatareq_t block %d\n",
			dlreq->dl_dest_addr_length);
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

	H2N_GID(wqnp->sgid);
	H2N_GID(wqnp->dgid);

	(void) rds_arp_add(wqnp);

	mutex_exit(&rdss->lock);
	rds_pr_callback(wqnp, 0);

	RDS_DPRINTF4("rds_pr_arp_query_ack", "Return: 0x%p", mp);

	return;
user_callback:
	freemsg(mp);
	mutex_exit(&rdss->lock);

	/*
	 * indicate to user
	 */
	rds_pr_callback(wqnp, rc);
}

/*
 * process a AR_ENTRY_SQUERY reply from arp
 * the message should be M_IOCACK -->> area_t
 */
void
rds_pr_arp_squery_ack(mblk_t *mp)
{
	struct iocblk *ioc;
	mblk_t	*mp1;
	rds_prwqn_t 	*wqnp;
	rds_streams_t *rdss;
	area_t *areap;
	char *cp;

	RDS_DPRINTF4("rds_pr_arp_squery_ack", "Enter: 0x%p", mp);

	/* LINTED */
	if (MBLKL(mp) < sizeof (struct iocblk)) {
		freemsg(mp);
		return;
	}

	/* LINTED */
	ioc = (struct iocblk *)mp->b_rptr;
	if ((ioc->ioc_cmd != AR_ENTRY_SQUERY) || (mp->b_cont == NULL)) {
		freemsg(mp);
		return;
	}

	mp1 = mp->b_cont;

	wqnp = *(rds_prwqn_t **)((uintptr_t)mp1->b_rptr - sizeof (uintptr_t));
	rdss = (rds_streams_t *)wqnp->arg;

	mutex_enter(&rdss->lock);

	/* If the entry was not in arp cache, ioc_error is set */
	if (ioc->ioc_error) {

		/*
		 * send out AR_ENTRY_QUERY which would send
		 * arp-request on wire
		 */
		RDS_DPRINTF3(LABEL, "Sending a Query_ARP");

		(void) rds_query_arp(wqnp);
		freemsg(mp);
		mutex_exit(&rdss->lock);
		return;
	}

	/* LINTED */
	areap = (area_t *)mp1->b_rptr;
	cp = (char *)areap + areap->area_hw_addr_offset;
	bcopy(cp, &wqnp->dst_mac, IPOIB_ADDRL);

	/*
	 * at this point we have src/dst gid's derived from the mac addresses
	 * now get the hca, port
	 */
	bcopy(&wqnp->src_mac.ipoib_gidpref, &wqnp->sgid, sizeof (ib_gid_t));
	bcopy(&wqnp->dst_mac.ipoib_gidpref, &wqnp->dgid, sizeof (ib_gid_t));
	freemsg(mp);

	H2N_GID(wqnp->sgid);
	H2N_GID(wqnp->dgid);

	mutex_exit(&rdss->lock);
	rds_pr_callback(wqnp, 0);

	RDS_DPRINTF4("rds_pr_arp_squery_ack", "Return: 0x%p", mp);
}

/*
 * Process arp ack's.
 */
void
rds_pr_arp_ack(mblk_t *mp)
{
	RDS_DPRINTF4("rds_pr_arp_ack", "Enter: 0x%p", mp);

	if (DB_TYPE(mp) == M_DATA) {
		rds_pr_arp_query_ack(mp);
	} else if ((DB_TYPE(mp) == M_IOCACK) ||
	    (DB_TYPE(mp) == M_IOCNAK)) {
		rds_pr_arp_squery_ack(mp);
	} else {
		freemsg(mp);
	}

	RDS_DPRINTF4("rds_pr_arp_ack", "Return: 0x%p", mp);
}

#ifdef DEBUG
void
print_ib_mac(char *str, uint8_t *mac)
{
	cmn_err(CE_CONT, "%s:"
		"%02x:" "%02x:" "%02x:" "%02x:" "%02x:"
		"%02x:" "%02x:" "%02x:" "%02x:" "%02x:"
		"%02x:" "%02x:" "%02x:" "%02x:" "%02x:"
		"%02x:" "%02x:" "%02x:" "%02x:" "%02x:\n",
		str,
		mac[0] & 0xff, mac[1] & 0xff,
		mac[2] & 0xff, mac[3] & 0xff,
		mac[4] & 0xff, mac[5] & 0xff,
		mac[6] & 0xff, mac[7] & 0xff,
		mac[8] & 0xff, mac[9] & 0xff,
		mac[10] & 0xff, mac[11] & 0xff,
		mac[12] & 0xff, mac[13] & 0xff,
		mac[14] & 0xff, mac[15] & 0xff,
		mac[16] & 0xff, mac[17] & 0xff, mac[18] & 0xff, mac[19] & 0xff);
}

void
print_ib_gid(char *str, uint8_t *mac)
{
	cmn_err(CE_CONT, "%s:"
		"%02x:" "%02x:" "%02x:" "%02x:" "%02x:"
		"%02x:" "%02x:" "%02x:" "%02x:" "%02x:"
		"%02x:" "%02x:" "%02x:" "%02x:" "%02x:"
		"%02x:\n",
		str,
		mac[0] & 0xff, mac[1] & 0xff,
		mac[2] & 0xff, mac[3] & 0xff,
		mac[4] & 0xff, mac[5] & 0xff,
		mac[6] & 0xff, mac[7] & 0xff,
		mac[8] & 0xff, mac[9] & 0xff,
		mac[10] & 0xff, mac[11] & 0xff,
		mac[12] & 0xff, mac[13] & 0xff, mac[14] & 0xff, mac[15] & 0xff);
}
#endif
