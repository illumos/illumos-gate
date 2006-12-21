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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
void print_ib_mac(char *str, uint8_t *mac);
void print_ib_gid(char *str, uint8_t *mac);
extern int rds_get_hca_info(rds_prwqn_t *wqnp);
void rds_pr_callback(rds_prwqn_t *wqnp, int status);
extern int v4tol2addr(in_addr_t ipv4, uchar_t *l2addr);

/*
 * send a IP_IOC_RTS_REQUEST to IP driver. this way we receive route
 * responses.
 * the message should be M_IOCTL -->>  IP_IOC_RTS_REQUEST-->> NULL
 */
int
rds_rts_announce(rds_streams_t *rdss)
{
	mblk_t *mp = NULL;
	mblk_t *mp1 = NULL;
	ipllc_t *ipllc;
	struct iocblk *ioc;

	RDS_DPRINTF4("rds_rts_announce", "Enter");

	mp = allocb(sizeof (ipllc_t), BPRI_HI);
	if (mp == NULL)
		return (ENOMEM);
	mp1 = allocb(sizeof (struct iocblk), BPRI_HI);
	if (mp1 == NULL) {
		freeb(mp);
		return (ENOMEM);
	}

	/* LINTED */
	ipllc = (ipllc_t *)mp->b_rptr;
	ipllc->ipllc_cmd = IP_IOC_RTS_REQUEST;
	ipllc->ipllc_name_offset = 0;
	ipllc->ipllc_name_length = 0;
	mp->b_wptr += sizeof (ipllc_t);

	/* LINTED */
	ioc = (struct iocblk *)mp1->b_rptr;
	ioc->ioc_cmd = IP_IOCTL;
	ioc->ioc_error = 0;
	ioc->ioc_cr = NULL;
	ioc->ioc_count = msgdsize(mp);
	mp1->b_wptr += sizeof (struct iocblk);
	mp1->b_datap->db_type = M_IOCTL;
	mp1->b_cont = mp;

	if (rdss->ipqueue) {
		if (canputnext(rdss->ipqueue)) {
			putnext(rdss->ipqueue, mp1);
		} else {
			(void) putq(rdss->ipqueue, mp1);
			qenable(rdss->ipqueue);
		}
		RDS_DPRINTF4("rds_rts_announce", "Return");
		return (0);
	} else {
		RDS_DPRINTF1(LABEL, "arp: ip driver not linked yet\n");
		RDS_DPRINTF4("rds_rts_announce", "Return: EBUSY");
		return (EBUSY);
	}
}

/*
 * get routing info from ip driver
 * the message is M_IOCTL -->> IP_IOC_RTS_REQUEST -->> struct (rt_msghdr_t)
 */
int
rds_get_route(rds_streams_t *rdss, rds_ipx_addr_t *dst_addr, rds_prwqn_t *wqnp)
{
	mblk_t *mp = NULL;
	mblk_t *mp1 = NULL;
	mblk_t *bp = NULL;
	ipllc_t *ipllc;
	struct iocblk *ioc;
	rt_msghdr_t *rtm;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	RDS_DPRINTF4("rds_get_route", "Enter");

	mp = allocb(sizeof (ipllc_t), BPRI_HI);
	if (mp == NULL) {
		return (NULL);
	}
	mp1 = allocb(sizeof (struct iocblk), BPRI_HI);
	if (mp1 == NULL) {
		freeb(mp);
		return (NULL);
	}
	bp = allocb(RDS_RTM_LEN, BPRI_HI);
	if (bp == NULL) {
		freeb(mp);
		freeb(mp1);
		return (NULL);
	}
	bzero(bp->b_rptr, RDS_RTM_LEN);
	/* LINTED */
	ipllc = (ipllc_t *)mp->b_rptr;
	ipllc->ipllc_cmd = IP_IOC_RTS_REQUEST;
	ipllc->ipllc_name_offset = 0;
	ipllc->ipllc_name_length = 0;
	mp->b_wptr += sizeof (ipllc_t);
	mp->b_cont = bp;

	/* LINTED */
	ioc = (struct iocblk *)mp1->b_rptr;
	ioc->ioc_cmd = IP_IOCTL;
	ioc->ioc_error = 0;
	ioc->ioc_cr = NULL;
	ioc->ioc_count = msgdsize(mp);
	mp1->b_wptr += sizeof (struct iocblk);
	mp1->b_datap->db_type = M_IOCTL;
	mp1->b_cont = mp;

	/* LINTED */
	rtm = (rt_msghdr_t *)bp->b_rptr;
	rtm->rtm_msglen = RDS_RTM_LEN;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = RTM_GET;
	rtm->rtm_flags = (RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_STATIC);
	rtm->rtm_addrs = (RTA_DST | RTA_IFP | RTA_SRC);

	/*
	 * set wqnp in pid and seq fields
	 * will be used to retrieve wqnp when the reply comes back
	 */
	rtm->rtm_pid = (pid_t)((uint64_t)(uintptr_t)wqnp & 0xffffffff);
	rtm->rtm_seq = ((uint64_t)(uintptr_t)wqnp >> 32);

	if (RDS_IS_V4_ADDR(dst_addr)) {
		sin = (struct sockaddr_in *)&rtm[1];
		/*
		 * Nitin: Change AF_RDS to AF_INET since rtsock does not
		 * Know anything about AF_RDS
		 * sin->sin_family = dst_addr->family;
		 */
		sin->sin_family = AF_INET;
		sin->sin_port = 0;
		sin->sin_addr.s_addr = RDS_IPV4_ADDR(dst_addr);
		sin++;
		sin->sin_family = AF_LINK;
	} else {
		sin6 = (struct sockaddr_in6 *)&rtm[1];
		sin6->sin6_family = dst_addr->family;
		sin6->sin6_port = 0;
		sin6->sin6_addr = RDS_IPV6_ADDR(dst_addr);
		sin6++;
		sin6->sin6_family = AF_LINK;
	}

	bp->b_wptr += RDS_RTM_LEN;

	wqnp->flags |= RDS_PR_RT_PENDING;
	if (rdss->ipqueue) {
		if (canputnext(rdss->ipqueue)) {
			putnext(rdss->ipqueue, mp1);
		} else {
			(void) putq(rdss->ipqueue, mp1);
			qenable(rdss->ipqueue);
		}
		RDS_DPRINTF4("rds_get_route", "Return");
		return (0);
	} else {
		RDS_DPRINTF1(LABEL, "arp: ip driver not linked yet\n");
		RDS_DPRINTF4("rds_get_route", "Return: EBUSY");
		return (EBUSY);
	}
}

/*
 * issue SIOCLIFGETND ioctl to ipv6 driver. this would
 * query the ipv6 driver cache for ipv6 to mac address mapping.
 */
int
rds_query_ip6(rds_prwqn_t *wqnp)
{
	mblk_t	*mp = NULL;
	mblk_t	*mp1 = NULL;
	mblk_t 	*mp2 = NULL;
	struct iocblk *iocb;
	struct sockaddr_in6 *sin6;
	struct lifreq *lifr;
	rds_streams_t *rdss = (rds_streams_t *)wqnp->arg;

	RDS_DPRINTF4("rds_query_ip6", "Enter: rdss: 0x%p, wqnp: 0x%p", rdss,
	    wqnp);

	if ((mp = allocb(sizeof (struct iocblk) + sizeof (void *),
		BPRI_HI)) == NULL) {
		RDS_DPRINTF1(LABEL, "ip6_query: allocb failed\n");
		return (ENOMEM);
	}
	mp->b_wptr += sizeof (struct iocblk);
	/* LINTED */
	iocb = (struct iocblk *)mp->b_rptr;
	iocb->ioc_cmd = SIOCLIFGETND;
	DB_TYPE(mp) = M_IOCTL;
	iocb->ioc_count = msgdsize(mp);
	iocb->ioc_error = 0;
	iocb->ioc_cr = NULL;

	if ((mp1 = allocb(sizeof (void *), BPRI_HI)) == NULL) {
		freeb(mp);
		RDS_DPRINTF1(LABEL, "ip6_query: allocb1 failed\n");
		return (ENOMEM);
	}

	/* LINTED */
	*(uintptr_t *)mp->b_wptr = (uintptr_t)wqnp; /* store wqnp */

	if ((mp2 = allocb(sizeof (struct lifreq) + 8, BPRI_HI)) == NULL) {
		RDS_DPRINTF1(LABEL, "ip6_query: allocb2 failed\n");
		freeb(mp);
		freeb(mp1);
		return (ENOMEM);
	}

	bzero(mp2->b_rptr, sizeof (struct lifreq));
	/* LINTED */
	lifr = (struct lifreq *)mp2->b_rptr;
	sin6 = (struct sockaddr_in6 *)&lifr->lifr_addr;
	sin6->sin6_family = AF_INET6;
	bcopy(&wqnp->dst_addr.un.ip6addr,
		&sin6->sin6_addr, sizeof (in6_addr_t));
	(void) sprintf(lifr->lifr_name, "%s", wqnp->ifname);

	mp2->b_wptr += sizeof (struct lifreq);
	mp->b_cont = mp1;
	mp1->b_cont = mp2;
	iocb->ioc_count = msgdsize(mp);
	if (rdss->ip6queue) {
		(void) putq(rdss->ip6queue, mp);
		qenable(rdss->ip6queue);
		RDS_DPRINTF4("rds_query_ip6", "Return: 0x%p", wqnp);
		return (0);
	} else {
		RDS_DPRINTF1(LABEL, "arp: ipv6 driver not linked yet\n");
		freemsg(mp);
		RDS_DPRINTF4("rds_query_ip6", "Return: EBUSY");
		return (EBUSY);
	}
}

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

	if (RDS_IS_V4_ADDR(&wqnp->src_addr)) {
		name_offset = rds_areq_template.areq_name_offset;
	} else {
		name_offset = sizeof (areq_t) + (2 * sizeof (in6_addr_t));
	}

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
	if (RDS_IS_V4_ADDR(&wqnp->dst_addr)) {
		cp = (char *)areqp + areqp->areq_target_addr_offset;
		bcopy(&wqnp->dst_addr.un.ip4addr, cp, IP_ADDR_LEN);
		cp = (char *)areqp + areqp->areq_sender_addr_offset;
		bcopy(&wqnp->src_addr.un.ip4addr, cp, IP_ADDR_LEN);
	} else {
		/*
		 * adjust the offsets for ipv6
		 */
		areqp->areq_name_offset = sizeof (areq_t) +
			(2 * sizeof (in6_addr_t));
		cp = (char *)areqp + areqp->areq_target_addr_offset;
		bcopy(&wqnp->dst_addr.un.ip6addr, cp, sizeof (in6_addr_t));

		areqp->areq_sender_addr_offset = sizeof (areq_t) +
			(sizeof (in6_addr_t));
		cp = (char *)areqp + areqp->areq_sender_addr_offset;
		bcopy(&wqnp->src_addr.un.ip6addr, cp, sizeof (in6_addr_t));
	}

	mp->b_cont = mp1;

	DB_TYPE(mp) = M_PROTO;

	/*
	 * issue the request to arp
	 */
	wqnp->flags |= RDS_PR_ARP_PENDING;
	wqnp->timeout_id = timeout(rds_arp_timeout, wqnp,
		drv_usectohz(RDS_ARP_TIMEOUT * 1000));
	if (rdss->arpqueue) {
		if (canputnext(rdss->arpqueue)) {
			putnext(rdss->arpqueue, mp);
		} else {
			(void) putq(rdss->arpqueue, mp);
			qenable(rdss->arpqueue);
		}
		RDS_DPRINTF4("rds_query_arp", "Return: 0x%p", wqnp);
		return (0);
	} else {
		RDS_DPRINTF4("rds_query_arp", "Return: EBUSY");
		return (EBUSY);
	}
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

	if (rdss->arpqueue) {
		if (canputnext(rdss->arpqueue)) {
			putnext(rdss->arpqueue, mp1);
		} else {
			(void) putq(rdss->arpqueue, mp1);
			qenable(rdss->arpqueue);
		}
		RDS_DPRINTF4("rds_squery_arp", "Return: 0x%p", wqnp);
		return (0);
	} else {
		RDS_DPRINTF1(LABEL, "arp: arp driver not linked yet\n");
		RDS_DPRINTF4("rds_squery_arp", "Return: EBUSY");
		return (EBUSY);
	}


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

	if (rdss->arpqueue) {
		if (canputnext(rdss->arpqueue)) {
			putnext(rdss->arpqueue, mp);
		} else {
			(void) putq(rdss->arpqueue, mp);
			qenable(rdss->arpqueue);
		}
		RDS_DPRINTF4("rds_arp_add", "Return: 0x%p", wqnp);
		return (0);
	} else {
		RDS_DPRINTF1(LABEL, "arp: arp driver not linked yet\n");
		RDS_DPRINTF4("rds_arp_add", "Return: EBUSY");
		return (EBUSY);
	}

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
 * timeout routine for ipv6 after sending a dummp icmp packet.
 */
static void
rds_ip6_timeout(void *arg)
{
	rds_prwqn_t *wqnp = (rds_prwqn_t *)arg;
	rds_streams_t *rdss = (rds_streams_t *)wqnp->arg;
	int rc;

	RDS_DPRINTF4("rds_ip6_timeout", "Enter: rdss: 0x%p wqnp: 0x%p",
	    rdss, wqnp);

	/*
	 * make sure this is a valid request. the request could have been
	 * cancelled
	 */
	mutex_enter(&rdss->lock);

	wqnp->retries++;
	if (wqnp->retries == RDS_MAX_IP6_RETRIES) {
		rc = EHOSTUNREACH;
		goto user_callback;
	}

	/*
	 * check if ND succeded
	 */
	if ((rc = rds_query_ip6(wqnp)) != 0) {
		goto user_callback;
	}
	mutex_exit(&rdss->lock);
	return;

user_callback:
	mutex_exit(&rdss->lock);
	rds_pr_callback(wqnp, rc);

	RDS_DPRINTF4("rds_ip6_timeout", "Return: 0x%p", wqnp);
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

	wqnp->ifproto = (dst_addr->family == AF_INET) ?
	    ETHERTYPE_IP : ETHERTYPE_IPV6;

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

#define	AF_RDS 30
int
rds_pr_lookup(rds_streams_t *rdss, rds_ipx_addr_t *dst_addr,
    rds_ipx_addr_t *src_addr, uint8_t localroute, uint32_t bound_dev_if,
    rds_pr_comp_func_t func)
{
	int rc;
	rds_prwqn_t *wqnp;

	RDS_DPRINTF4("rds_pr_lookup", "Enter: src 0x%x dest 0x%x", src_addr,
	    dst_addr);

	/*
	 * make sure address in not multicast
	 */
	if (dst_addr->family == AF_RDS || dst_addr->family == AF_INET) {
		if (IN_MULTICAST(dst_addr->un.ip4addr)) {
			return (EINVAL);
		}
	} else if (dst_addr->family == AF_INET6) {
		if (IN6_IS_ADDR_MULTICAST(&dst_addr->un.ip6addr)) {
			return (EINVAL);
		}
	} else {
		return (EAFNOSUPPORT);
	}


	if ((wqnp = rds_create_prwqn(rdss, dst_addr,
		src_addr, localroute, bound_dev_if, func)) == NULL) {
		return (ENOMEM);
	}

	/*
	 * get the routing info
	 */
	if (rc = rds_get_route(rdss, dst_addr, wqnp)) {
		return (rc);
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

int
rds_copy_sockaddr(struct sockaddr *sa, rds_ipx_addr_t *addr)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	RDS_DPRINTF4("rds_copy_sockaddr", "Enter");

	addr->family = sa->sa_family;
	switch (sa->sa_family) {
		case AF_INET:
			/* LINTED */
			sin = (struct sockaddr_in *)sa;
			addr->un.ip4addr = sin->sin_addr.s_addr;
			RDS_DPRINTF4("rds_copy_sockaddr", "Return: AF_INET");
			return (sizeof (struct sockaddr_in));
		case AF_INET6:
			/* LINTED */
			sin6 = (struct sockaddr_in6 *)sa;
			bcopy(&sin6->sin6_addr.s6_addr,
				&addr->un.ip6addr, sizeof (in6_addr_t));
			RDS_DPRINTF4("rds_copy_sockaddr", "Return: AF_INET6");
			return (sizeof (struct sockaddr_in6));
		default:
			RDS_DPRINTF4("rds_copy_sockaddr", "Return: Default");
			return (0);
	}
}

/*
 * do sanity checks on the link-level sockaddr
 * the i/f has has to be an ib or lo device
 */
int
rds_copy_sockdl(struct sockaddr_dl *sdl, rds_prwqn_t *wqnp)
{
	RDS_DPRINTF4("rds_copy_sockdl", "Enter: 0x%p", wqnp);

	if (!sdl->sdl_nlen) {
		RDS_DPRINTF1(LABEL, "copy_sockdl: invalid name len %d\n",
			sdl->sdl_nlen);
		return (EINVAL);
	}
	bcopy(sdl->sdl_data, wqnp->ifname, sdl->sdl_nlen);
	wqnp->ifname[sdl->sdl_nlen] = '\0';

	/*
	 * if the i/f is not ib or lo device, fail the request
	 */
	if (bcmp(wqnp->ifname, "ibd", 3) == 0) {
		if (sdl->sdl_alen != IPOIB_ADDRL) {
			RDS_DPRINTF1(LABEL, "Error: i/f is not ibd: <%s>\n",
					wqnp->ifname);
			return (EINVAL);
		}

		bcopy(&sdl->sdl_data[sdl->sdl_nlen],
			&wqnp->src_mac, IPOIB_ADDRL);
	} else if (bcmp(wqnp->ifname, "lo", 2)) {
		RDS_DPRINTF2(LABEL, "Invalid Interface: %s", wqnp->ifname);
		return (EINVAL);
	}

	RDS_DPRINTF4("rds_copy_sockdl", "Return: 0x%p", wqnp);

	return (0);
}

int
rds_extract_route_fields(rt_msghdr_t *rtm, rds_prwqn_t *wqnp)
{
	int rtm_addrs;
	struct sockaddr_dl *sdl;
	uchar_t *cp;
	int i;
	struct sockaddr *sa;
	int addr_bits;
	rds_ipx_addr_t addr;
	int rc;

	RDS_DPRINTF4("rds_extract_route_fields", "Enter: 0x%p", wqnp);

	/*
	 * go thru' the packed data at the end of rtm
	 */
	cp = (uchar_t *)&rtm[1];
	rtm_addrs = rtm->rtm_addrs;
	for (i = 0; i < RTA_NUMBITS; i++) {
		addr_bits = (rtm_addrs & (1 << i));
		if (addr_bits == 0) {
			continue;
		}
		/* LINTED */
		sa = (struct sockaddr *)cp;
		switch (addr_bits) {
			case RTA_DST:
				cp += rds_copy_sockaddr(sa, &addr);
				break;
			case RTA_GATEWAY:
				cp += rds_copy_sockaddr(sa, &wqnp->gateway);
				break;
			case RTA_NETMASK:
				cp += rds_copy_sockaddr(sa, &wqnp->netmask);
				break;
			case RTA_IFP:
				/* LINTED */
				sdl = (struct sockaddr_dl *)cp;

				if ((rc = rds_copy_sockdl(sdl, wqnp)) != 0) {
					goto error;
				}
				cp += sizeof (struct sockaddr_dl);
				break;
			case RTA_IFA:
			case RTA_SRC:
				cp += rds_copy_sockaddr(sa, &wqnp->src_addr);
				break;
			case RTA_AUTHOR:
				cp += rds_copy_sockaddr(sa, &addr);
				break;
			case RTA_BRD:
				cp += rds_copy_sockaddr(sa, &addr);
				break;
			default:
				RDS_DPRINTF1(LABEL, "got %d in rts msg\n",
					(rtm_addrs & (1 << i)));
				break;

		}
	}

	RDS_DPRINTF4("rds_extract_route_fields", "Return: 0x%p", wqnp);

	return (0);

error:
	return (rc);
}

/*
 * called from lrput.
 * process a IP_IOCTL reply from ip
 */
void
rds_pr_ip_ack(mblk_t *mp)
{
	rt_msghdr_t *rtm;
	rds_prwqn_t *wqnp;
	rds_streams_t *rdss;
	uintptr_t l;
	int rc;
	int len;

	RDS_DPRINTF4("rds_pr_ip_ack", "Enter: 0x%p", mp);

	/*
	 * RTS info is present in a single mblk. if more than one mblk
	 * is present, then this should be the original RTM_GET request
	 */
	if (mp->b_cont) {
		freemsg(mp);
		return;
	}

	/*
	 * sanity checks on the mblk
	 */
	/* LINTED */
	rtm = (rt_msghdr_t *)mp->b_rptr;
	/* LINTED */
	if ((MBLKL(mp) < sizeof (rt_msghdr_t)) ||
	    (rtm->rtm_version != RTM_VERSION) ||
	    /* LINTED */
	    (rtm->rtm_type != RTM_GET) || (MBLKL(mp) != rtm->rtm_msglen)) {
		freemsg(mp);
		return;
	}

	l = ((uint64_t)rtm->rtm_seq << 32) | (uint32_t)rtm->rtm_pid;
	wqnp = (rds_prwqn_t *)l;
	rdss = (rds_streams_t *)wqnp->arg;

	mutex_enter(&rdss->lock);

	/*
	 * check for rts error
	 */
	if (rtm->rtm_errno) {
		rc = rtm->rtm_errno;
		RDS_DPRINTF1(LABEL, "ip_ioctl_ack: got rtm errono:%d\n", rc);
		goto user_callback;
	}

	/*
	 * extract all the route fields
	 */
	if (rc = rds_extract_route_fields(rtm, wqnp)) {
		freemsg(mp);
		goto user_callback;
	}
	freemsg(mp);

	if (bcmp(wqnp->ifname, "lo", 2) != 0) {
		/*
		 * issue AR_ENTRY_QUERY to get the arp address of dest
		 */
		wqnp->flags &= ~RDS_PR_RT_PENDING;

		RDS_DPRINTF3(LABEL, "ip_ack: outgoing if: %s dst: %d usr: %d",
			wqnp->ifname, wqnp->dst_addr.family,
			wqnp->usrc_addr.family);

		/*
		 * if localroute is set, then make sure the rts
		 * returned gateway address is the same as the
		 * supplied source address
		 */
		if (wqnp->localroute) {
			len = (wqnp->dst_addr.family == AF_INET) ?
				IP_ADDR_LEN : sizeof (in6_addr_t);

			if (bcmp(&wqnp->gateway.un, &wqnp->src_addr.un, len)) {
				rc = ENETUNREACH;
				RDS_DPRINTF1(LABEL,
					"ip_ack: local route error:%d\n", rc);
				goto user_callback;
			}
		}

		/*
		 * if the user supplied a address, then verify rts returned
		 * the same address
		 */
		if (wqnp->usrc_addr.family) {
			len = (wqnp->usrc_addr.family == AF_INET) ?
				IP_ADDR_LEN : sizeof (in6_addr_t);

			if (bcmp(&wqnp->usrc_addr.un,
				&wqnp->src_addr.un, len)) {
				rc = ENETUNREACH;
				RDS_DPRINTF1(LABEL,
					"ip_ack: src addr mismatch:%d\n", rc);
				goto user_callback;
			}
		}

		/*
		 * at this stage, we have the source address and the IB
		 * interface, now get the destination mac address from
		 * arp or ipv6 drivers
		 */
		if (wqnp->dst_addr.family == AF_INET) {
			if ((rc = rds_squery_arp(wqnp)) != 0) {
				RDS_DPRINTF1(LABEL,
					"ip_ack: arp_req  error:%d\n", rc);
				goto user_callback;
			}
		} else {
			if ((rc = rds_query_ip6(wqnp)) != 0) {
				RDS_DPRINTF1(LABEL,
					"ip_ack: ip6_query  error:%d\n", rc);
				goto user_callback;
			}
		}
	}
	mutex_exit(&rdss->lock);

	RDS_DPRINTF4("rds_pr_ip_ack", "Return: 0x%p", wqnp);

	return;

user_callback:
	mutex_exit(&rdss->lock);
	/*
	 * indicate to user
	 */
	rds_pr_callback(wqnp, rc);
}

/*
 * send down a T_unitdata_req, which would trigger
 * neighbour discovery process
 */
void
rds_ip6_send_pkt(rds_prwqn_t *wqnp)
{
	mblk_t *mp;
	mblk_t *mp1;
	struct T_unitdata_req *tur;
	struct sockaddr_in6 *sin6;
	rds_streams_t *rdss = (rds_streams_t *)wqnp->arg;
	uint8_t *rptr;
	int rc;

	RDS_DPRINTF4("rds_ip6_send_pkt", "Enter: rdss: 0x%p wqnp: 0x%p", rdss,
	    wqnp);

	if ((mp = allocb(sizeof (struct T_unitdata_req) +
		sizeof (struct sockaddr_in6), BPRI_HI)) == NULL) {
		rc = ENOMEM;
		goto user_callback;
	}
	if ((mp1 = allocb(100, BPRI_HI)) == NULL) {
		rc = ENOMEM;
		freemsg(mp);
		goto user_callback;
	}
	/* LINTED */
	tur = (struct T_unitdata_req *)mp->b_rptr;
	tur->PRIM_type = T_UNITDATA_REQ;
	tur->DEST_length = sizeof (struct sockaddr_in6);
	tur->DEST_offset = sizeof (struct T_unitdata_req);
	tur->OPT_length = 0;
	tur->OPT_offset = 0;

	rptr = mp->b_rptr;
	/* LINTED */
	sin6 = (struct sockaddr_in6 *)&rptr[tur->DEST_offset];
	sin6->sin6_family = AF_INET6;
	bcopy(&wqnp->dst_addr.un.ip6addr,
		&sin6->sin6_addr, sizeof (in6_addr_t));
	sin6->sin6_port = 9;
	sin6->sin6_flowinfo = 0;
	sin6->sin6_scope_id = 0;
	sin6->__sin6_src_id = 0;
	mp->b_wptr += sizeof (struct T_unitdata_req) +
	    sizeof (struct sockaddr_in6);

	mp1->b_wptr += 100;
	mp1->b_rptr += 90;
	mp->b_cont = mp1;
	DB_TYPE(mp) = M_PROTO;

	wqnp->timeout_id = timeout(rds_ip6_timeout, wqnp,
		drv_usectohz(RDS_IP6_TIMEOUT));
	if (rdss->ip6queue) {
		if (canputnext(rdss->ip6queue)) {
			putnext(rdss->ip6queue, mp);
		} else {
			(void) putq(rdss->ip6queue, mp);
			qenable(rdss->ip6queue);
		}
		return;
	} else {
		RDS_DPRINTF1(LABEL, "arp: ipv6 driver not linked yet\n");
		(void) untimeout(wqnp->timeout_id);
		freemsg(mp);
		rc = EBUSY;
	}
user_callback:
	/*
	 * indicate to user
	 */
	rds_pr_callback(wqnp, rc);

	RDS_DPRINTF4("rds_ip6_send_pkt", "Return: 0x%p", wqnp);
}

/*
 * called from lrput.
 * process SIOCLIFGETND reply from ip6
 */
void
rds_pr_ip6_ack(mblk_t *mp)
{
	rds_prwqn_t *wqnp;
	mblk_t *bp;
	struct iocblk *iocb;
	struct lifreq *lifreq;
	rds_streams_t *rdss;

	RDS_DPRINTF4("rds_pr_ip6_ack", "Enter");

	if (DB_TYPE(mp) != M_IOCACK) {
		RDS_DPRINTF1(LABEL, "ip6_ioctl: got  %d type\n", DB_TYPE(mp));
		freemsg(mp);
	}
	/* LINTED */
	iocb = (struct iocblk *)mp->b_rptr;
	if (iocb->ioc_cmd != SIOCLIFGETND) {
		RDS_DPRINTF1(LABEL, "ip6_ioctl: got  %d cmd\n", iocb->ioc_cmd);
		freemsg(mp);
	}

	/* LINTED */
	wqnp = *(rds_prwqn_t **)mp->b_wptr;	/* retrieve wqnp */
	rdss = (rds_streams_t *)wqnp->arg;

	RDS_DPRINTF4("rds_pr_ip6_ack", "rdss: 0x%p wqnp: 0x%p", rdss, wqnp);

	mutex_enter(&rdss->lock);

	/*
	 * if there is an error, then trigger a ND by sending a
	 * dummy udp apcket
	 */
	/* LINTED */
	iocb = (struct iocblk *)mp->b_rptr;
	if (iocb->ioc_error) {
		goto send_packet;
	}

	/*
	 * on successfull completion of SIOCLIFGETND, the second mblock
	 * has the lifreq struct
	 */
	bp = mp->b_cont;
	if (bp == NULL) {
		goto user_callback;
	}

	/*
	 * if hdw_len is zero, then trigger a ND by sending
	 * a dummy packet
	 */
	/* LINTED */
	if (MBLKL(bp) < sizeof (struct lifreq)) {
		goto user_callback;
	}
	/* LINTED */
	lifreq = (struct lifreq *)bp->b_rptr;
	if (lifreq->lifr_nd.lnr_hdw_len == 0) {
		goto send_packet;
	}

	/*
	 * the request was successfull. complete the lookup
	 */
	bcopy(lifreq->lifr_nd.lnr_hdw_addr,
		&wqnp->dst_mac, sizeof (ipoib_mac_t));

	bcopy(&wqnp->src_mac.ipoib_gidpref, &wqnp->sgid, sizeof (ib_gid_t));
	bcopy(&wqnp->dst_mac.ipoib_gidpref, &wqnp->dgid, sizeof (ib_gid_t));
	freemsg(mp);

	H2N_GID(wqnp->sgid);
	H2N_GID(wqnp->dgid);

	mutex_exit(&rdss->lock);

	rds_pr_callback(wqnp, 0);

	return;

send_packet:

	freemsg(mp);
	mutex_exit(&rdss->lock);
	rds_ip6_send_pkt(wqnp);

	RDS_DPRINTF4("rds_pr_ip6_ack", "Return: 0x%p", wqnp);

	return;

user_callback:
	freemsg(mp);
	mutex_exit(&rdss->lock);

	rds_pr_callback(wqnp, ENXIO);
}

/*
 * process PROTO message.
 * we should get T_BIND_ACK for icmp T_BIND_REQ on ipv6 stream. if T_BIND_REQ
 * had failed, then diable ipv6 stream
 */
void
rds_pr_proto(queue_t *q, mblk_t *mp)
{
	struct T_error_ack *tea;
	rds_streams_t *rdss = (rds_streams_t *)q->q_ptr;

	RDS_DPRINTF4("rds_pr_proto", "Enter: q: 0x%p rdss: 0x%p", q, rdss);

	if (WR(q) != rdss->ip6queue) {
		freemsg(mp);
		return;
	}
	/* LINTED */
	tea = (struct T_error_ack *)mp->b_rptr;
	if (tea->PRIM_type == T_ERROR_ACK) {
		if (tea->ERROR_prim == T_BIND_REQ) {
			rdss->ip6queue = NULL;
			RDS_DPRINTF1(LABEL,
				"arp: icmp bind failed. ipv6 stream down\n");
		}
	}
	freemsg(mp);

	RDS_DPRINTF4("rds_pr_proto", "Return: 0x%p", q);
}

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
