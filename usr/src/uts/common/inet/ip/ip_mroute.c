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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

/*
 * Procedures for the kernel part of DVMRP,
 * a Distance-Vector Multicast Routing Protocol.
 * (See RFC-1075)
 * Written by David Waitzman, BBN Labs, August 1988.
 * Modified by Steve Deering, Stanford, February 1989.
 * Modified by Mark J. Steiglitz, Stanford, May, 1991
 * Modified by Van Jacobson, LBL, January 1993
 * Modified by Ajit Thyagarajan, PARC, August 1993
 * Modified by Bill Fenner, PARC, April 1995
 *
 * MROUTING 3.5
 */

/*
 * TODO
 * - function pointer field in vif, void *vif_sendit()
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/zone.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/vtrace.h>
#include <sys/debug.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <net/if_dl.h>

#include <inet/ipsec_impl.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <inet/tunables.h>
#include <inet/mib2.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <inet/snmpcom.h>

#include <netinet/igmp.h>
#include <netinet/igmp_var.h>
#include <netinet/udp.h>
#include <netinet/ip_mroute.h>
#include <inet/ip_multi.h>
#include <inet/ip_ire.h>
#include <inet/ip_ndp.h>
#include <inet/ip_if.h>
#include <inet/ipclassifier.h>

#include <netinet/pim.h>


/*
 * MT Design:
 *
 * There are three main data structures viftable, mfctable and tbftable that
 * need to be protected against MT races.
 *
 * vitable is a fixed length array of vif structs. There is no lock to protect
 * the whole array, instead each struct is protected by its own indiviual lock.
 * The value of v_marks in conjuction with the value of v_refcnt determines the
 * current state of a vif structure. One special state that needs mention
 * is when the vif is marked VIF_MARK_NOTINUSE but refcnt != 0. This indicates
 * that vif is being initalized.
 * Each structure is freed when the refcnt goes down to zero. If a delete comes
 * in when the recfnt is > 1, the vif structure is marked VIF_MARK_CONDEMNED
 * which prevents the struct from further use.  When the refcnt goes to zero
 * the struct is freed and is marked VIF_MARK_NOTINUSE.
 * vif struct stores a pointer to the ipif in v_ipif, to prevent ipif/ill
 * from  going away a refhold is put on the ipif before using it. see
 * lock_good_vif() and unlock_good_vif().
 *
 * VIF_REFHOLD and VIF_REFRELE macros have been provided to manipulate refcnts
 * of the vif struct.
 *
 * tbftable is also a fixed length array of tbf structs and is only accessed
 * via v_tbf.  It is protected by its own lock tbf_lock.
 *
 * Lock Ordering is
 * v_lock --> tbf_lock
 * v_lock --> ill_locK
 *
 * mfctable is a fixed size hash table of mfc buckets strcuts (struct mfcb).
 * Each mfc bucket struct (struct mfcb) maintains a refcnt for each walker,
 * it also maintains a state. These fields are protected by a lock (mfcb_lock).
 * mfc structs only maintain a state and have no refcnt. mfc_mutex is used to
 * protect the struct elements.
 *
 * mfc structs are dynamically allocated and are singly linked
 * at the head of the chain. When an mfc structure is to be deleted
 * it is marked condemned and so is the state in the bucket struct.
 * When the last walker of the hash bucket exits all the mfc structs
 * marked condemed are freed.
 *
 * Locking Hierarchy:
 * The bucket lock should be acquired before the mfc struct lock.
 * MFCB_REFHOLD and MFCB_REFRELE macros are provided for locking
 * operations on the bucket struct.
 *
 * last_encap_lock and numvifs_mutex should be acquired after
 * acquring vif or mfc locks. These locks protect some global variables.
 *
 * The statistics are not currently protected by a lock
 * causing the stats be be approximate, not exact.
 */

#define	NO_VIF	MAXVIFS 	/* from mrouted, no route for src */

/*
 * Timeouts:
 * 	Upcall timeouts - BSD uses boolean_t mfc->expire and
 *	nexpire[MFCTBLSIZE], the number of times expire has been called.
 *	SunOS 5.x uses mfc->timeout for each mfc.
 *	Some Unixes are limited in the number of simultaneous timeouts
 * 	that can be run, SunOS 5.x does not have this restriction.
 */

/*
 * In BSD, EXPIRE_TIMEOUT is how often expire_upcalls() is called and
 * UPCALL_EXPIRE is the nmber of timeouts before a particular upcall
 * expires. Thus the time till expiration is EXPIRE_TIMEOUT * UPCALL_EXPIRE
 */
#define		EXPIRE_TIMEOUT	(hz/4)	/* 4x / second	*/
#define		UPCALL_EXPIRE	6	/* number of timeouts	*/

/*
 * Hash function for a source, group entry
 */
#define	MFCHASH(a, g) MFCHASHMOD(((a) >> 20) ^ ((a) >> 10) ^ (a) ^ \
	((g) >> 20) ^ ((g) >> 10) ^ (g))

#define			TBF_REPROCESS	(hz / 100)	/* 100x /second	*/

/* Identify PIM packet that came on a Register interface */
#define	PIM_REGISTER_MARKER	0xffffffff

/* Function declarations */
static int	add_mfc(struct mfcctl *, ip_stack_t *);
static int	add_vif(struct vifctl *, conn_t *, ip_stack_t *);
static int	del_mfc(struct mfcctl *, ip_stack_t *);
static int	del_vif(vifi_t *, ip_stack_t *);
static void	del_vifp(struct vif *);
static void	encap_send(ipha_t *, mblk_t *, struct vif *, ipaddr_t);
static void	expire_upcalls(void *);
static void	fill_route(struct mfc *, struct mfcctl *, ip_stack_t *);
static void	free_queue(struct mfc *);
static int	get_assert(uchar_t *, ip_stack_t *);
static int	get_lsg_cnt(struct sioc_lsg_req *, ip_stack_t *);
static int	get_sg_cnt(struct sioc_sg_req *, ip_stack_t *);
static int	get_version(uchar_t *);
static int	get_vif_cnt(struct sioc_vif_req *, ip_stack_t *);
static int	ip_mdq(mblk_t *, ipha_t *, ill_t *,
		    ipaddr_t, struct mfc *);
static int	ip_mrouter_init(conn_t *, uchar_t *, int, ip_stack_t *);
static void	phyint_send(ipha_t *, mblk_t *, struct vif *, ipaddr_t);
static int	register_mforward(mblk_t *, ip_recv_attr_t *);
static void	register_send(ipha_t *, mblk_t *, struct vif *, ipaddr_t);
static int	set_assert(int *, ip_stack_t *);

/*
 * Token Bucket Filter functions
 */
static int  priority(struct vif *, ipha_t *);
static void tbf_control(struct vif *, mblk_t *, ipha_t *);
static int  tbf_dq_sel(struct vif *, ipha_t *);
static void tbf_process_q(struct vif *);
static void tbf_queue(struct vif *, mblk_t *);
static void tbf_reprocess_q(void *);
static void tbf_send_packet(struct vif *, mblk_t *);
static void tbf_update_tokens(struct vif *);
static void release_mfc(struct mfcb *);

static boolean_t is_mrouter_off(ip_stack_t *);
/*
 * Encapsulation packets
 */

#define	ENCAP_TTL	64

/* prototype IP hdr for encapsulated packets */
static ipha_t multicast_encap_iphdr = {
	IP_SIMPLE_HDR_VERSION,
	0,				/* tos */
	sizeof (ipha_t),		/* total length */
	0,				/* id */
	0,				/* frag offset */
	ENCAP_TTL, IPPROTO_ENCAP,
	0,				/* checksum */
};

/*
 * Rate limit for assert notification messages, in nsec.
 */
#define	ASSERT_MSG_TIME		3000000000


#define	VIF_REFHOLD(vifp) {			\
	mutex_enter(&(vifp)->v_lock);		\
	(vifp)->v_refcnt++;			\
	mutex_exit(&(vifp)->v_lock);		\
}

#define	VIF_REFRELE_LOCKED(vifp) {				\
	(vifp)->v_refcnt--;					\
	if ((vifp)->v_refcnt == 0 &&				\
		((vifp)->v_marks & VIF_MARK_CONDEMNED)) {	\
			del_vifp(vifp);				\
	} else {						\
		mutex_exit(&(vifp)->v_lock);			\
	}							\
}

#define	VIF_REFRELE(vifp) {					\
	mutex_enter(&(vifp)->v_lock);				\
	(vifp)->v_refcnt--;					\
	if ((vifp)->v_refcnt == 0 &&				\
		((vifp)->v_marks & VIF_MARK_CONDEMNED)) {	\
			del_vifp(vifp);				\
	} else {						\
		mutex_exit(&(vifp)->v_lock);			\
	}							\
}

#define	MFCB_REFHOLD(mfcb) {				\
	mutex_enter(&(mfcb)->mfcb_lock);		\
	(mfcb)->mfcb_refcnt++;				\
	ASSERT((mfcb)->mfcb_refcnt != 0);		\
	mutex_exit(&(mfcb)->mfcb_lock);			\
}

#define	MFCB_REFRELE(mfcb) {					\
	mutex_enter(&(mfcb)->mfcb_lock);			\
	ASSERT((mfcb)->mfcb_refcnt != 0);			\
	if (--(mfcb)->mfcb_refcnt == 0 &&			\
		((mfcb)->mfcb_marks & MFCB_MARK_CONDEMNED)) {	\
			release_mfc(mfcb);			\
	}							\
	mutex_exit(&(mfcb)->mfcb_lock);				\
}

/*
 * MFCFIND:
 * Find a route for a given origin IP address and multicast group address.
 * Skip entries with pending upcalls.
 * Type of service parameter to be added in the future!
 */
#define	MFCFIND(mfcbp, o, g, rt) { \
	struct mfc *_mb_rt = NULL; \
	rt = NULL; \
	_mb_rt = mfcbp->mfcb_mfc; \
	while (_mb_rt) { \
		if ((_mb_rt->mfc_origin.s_addr == o) && \
		    (_mb_rt->mfc_mcastgrp.s_addr == g) && \
		    (_mb_rt->mfc_rte == NULL) && \
		    (!(_mb_rt->mfc_marks & MFCB_MARK_CONDEMNED))) {        \
		    rt = _mb_rt; \
		    break; \
		} \
	_mb_rt = _mb_rt->mfc_next; \
	} \
}

/*
 * BSD uses timeval with sec and usec. In SunOS 5.x uniqtime() and gethrtime()
 * are inefficient. We use gethrestime() which returns a timespec_t with
 * sec and nsec, the resolution is machine dependent.
 * The following 2 macros have been changed to use nsec instead of usec.
 */
/*
 * Macros to compute elapsed time efficiently.
 * Borrowed from Van Jacobson's scheduling code.
 * Delta should be a hrtime_t.
 */
#define	TV_DELTA(a, b, delta) { \
	int xxs; \
 \
	delta = (a).tv_nsec - (b).tv_nsec; \
	if ((xxs = (a).tv_sec - (b).tv_sec) != 0) { \
		switch (xxs) { \
		case 2: \
		    delta += 1000000000; \
		    /*FALLTHROUGH*/ \
		case 1: \
		    delta += 1000000000; \
		    break; \
		default: \
		    delta += (1000000000 * xxs); \
		} \
	} \
}

#define	TV_LT(a, b) (((a).tv_nsec < (b).tv_nsec && \
	(a).tv_sec <= (b).tv_sec) || (a).tv_sec < (b).tv_sec)

/*
 * Handle MRT setsockopt commands to modify the multicast routing tables.
 */
int
ip_mrouter_set(int cmd, conn_t *connp, int checkonly, uchar_t *data,
    int datalen)
{
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	mutex_enter(&ipst->ips_ip_g_mrouter_mutex);
	if (cmd != MRT_INIT && connp != ipst->ips_ip_g_mrouter) {
		mutex_exit(&ipst->ips_ip_g_mrouter_mutex);
		return (EACCES);
	}
	mutex_exit(&ipst->ips_ip_g_mrouter_mutex);

	if (checkonly) {
		/*
		 * do not do operation, just pretend to - new T_CHECK
		 * Note: Even routines further on can probably fail but
		 * this T_CHECK stuff is only to please XTI so it not
		 * necessary to be perfect.
		 */
		switch (cmd) {
		case MRT_INIT:
		case MRT_DONE:
		case MRT_ADD_VIF:
		case MRT_DEL_VIF:
		case MRT_ADD_MFC:
		case MRT_DEL_MFC:
		case MRT_ASSERT:
			return (0);
		default:
			return (EOPNOTSUPP);
		}
	}

	/*
	 * make sure no command is issued after multicast routing has been
	 * turned off.
	 */
	if (cmd != MRT_INIT && cmd != MRT_DONE) {
		if (is_mrouter_off(ipst))
			return (EINVAL);
	}

	switch (cmd) {
	case MRT_INIT:	return (ip_mrouter_init(connp, data, datalen, ipst));
	case MRT_DONE:	return (ip_mrouter_done(ipst));
	case MRT_ADD_VIF:  return (add_vif((struct vifctl *)data, connp, ipst));
	case MRT_DEL_VIF:  return (del_vif((vifi_t *)data, ipst));
	case MRT_ADD_MFC:  return (add_mfc((struct mfcctl *)data, ipst));
	case MRT_DEL_MFC:  return (del_mfc((struct mfcctl *)data, ipst));
	case MRT_ASSERT:   return (set_assert((int *)data, ipst));
	default:	   return (EOPNOTSUPP);
	}
}

/*
 * Handle MRT getsockopt commands
 */
int
ip_mrouter_get(int cmd, conn_t *connp, uchar_t *data)
{
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	if (connp != ipst->ips_ip_g_mrouter)
		return (EACCES);

	switch (cmd) {
	case MRT_VERSION:	return (get_version((uchar_t *)data));
	case MRT_ASSERT:	return (get_assert((uchar_t *)data, ipst));
	default:		return (EOPNOTSUPP);
	}
}

/*
 * Handle ioctl commands to obtain information from the cache.
 * Called with shared access to IP. These are read_only ioctls.
 */
/* ARGSUSED */
int
mrt_ioctl(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	mblk_t	*mp1;
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	conn_t		*connp = Q_TO_CONN(q);
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	/* Existence verified in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;

	switch (iocp->ioc_cmd) {
	case (SIOCGETVIFCNT):
		return (get_vif_cnt((struct sioc_vif_req *)mp1->b_rptr, ipst));
	case (SIOCGETSGCNT):
		return (get_sg_cnt((struct sioc_sg_req *)mp1->b_rptr, ipst));
	case (SIOCGETLSGCNT):
		return (get_lsg_cnt((struct sioc_lsg_req *)mp1->b_rptr, ipst));
	default:
		return (EINVAL);
	}
}

/*
 * Returns the packet, byte, rpf-failure count for the source, group provided.
 */
static int
get_sg_cnt(struct sioc_sg_req *req, ip_stack_t *ipst)
{
	struct mfc *rt;
	struct mfcb *mfcbp;

	mfcbp = &ipst->ips_mfcs[MFCHASH(req->src.s_addr, req->grp.s_addr)];
	MFCB_REFHOLD(mfcbp);
	MFCFIND(mfcbp, req->src.s_addr, req->grp.s_addr, rt);

	if (rt != NULL) {
		mutex_enter(&rt->mfc_mutex);
		req->pktcnt   = rt->mfc_pkt_cnt;
		req->bytecnt  = rt->mfc_byte_cnt;
		req->wrong_if = rt->mfc_wrong_if;
		mutex_exit(&rt->mfc_mutex);
	} else
		req->pktcnt = req->bytecnt = req->wrong_if = 0xffffffffU;

	MFCB_REFRELE(mfcbp);
	return (0);
}

/*
 * Returns the packet, byte, rpf-failure count for the source, group provided.
 * Uses larger counters and IPv6 addresses.
 */
/* ARGSUSED XXX until implemented */
static int
get_lsg_cnt(struct sioc_lsg_req *req, ip_stack_t *ipst)
{
	/* XXX TODO SIOCGETLSGCNT */
	return (ENXIO);
}

/*
 * Returns the input and output packet and byte counts on the vif provided.
 */
static int
get_vif_cnt(struct sioc_vif_req *req, ip_stack_t *ipst)
{
	vifi_t vifi = req->vifi;

	if (vifi >= ipst->ips_numvifs)
		return (EINVAL);

	/*
	 * No locks here, an approximation is fine.
	 */
	req->icount = ipst->ips_vifs[vifi].v_pkt_in;
	req->ocount = ipst->ips_vifs[vifi].v_pkt_out;
	req->ibytes = ipst->ips_vifs[vifi].v_bytes_in;
	req->obytes = ipst->ips_vifs[vifi].v_bytes_out;

	return (0);
}

static int
get_version(uchar_t *data)
{
	int *v = (int *)data;

	*v = 0x0305;	/* XXX !!!! */

	return (0);
}

/*
 * Set PIM assert processing global.
 */
static int
set_assert(int *i, ip_stack_t *ipst)
{
	if ((*i != 1) && (*i != 0))
		return (EINVAL);

	ipst->ips_pim_assert = *i;

	return (0);
}

/*
 * Get PIM assert processing global.
 */
static int
get_assert(uchar_t *data, ip_stack_t *ipst)
{
	int *i = (int *)data;

	*i = ipst->ips_pim_assert;

	return (0);
}

/*
 * Enable multicast routing.
 */
static int
ip_mrouter_init(conn_t *connp, uchar_t *data, int datalen, ip_stack_t *ipst)
{
	int	*v;

	if (data == NULL || (datalen != sizeof (int)))
		return (ENOPROTOOPT);

	v = (int *)data;
	if (*v != 1)
		return (ENOPROTOOPT);

	mutex_enter(&ipst->ips_ip_g_mrouter_mutex);
	if (ipst->ips_ip_g_mrouter != NULL) {
		mutex_exit(&ipst->ips_ip_g_mrouter_mutex);
		return (EADDRINUSE);
	}

	/*
	 * MRT_INIT should only be allowed for RAW sockets, but we double
	 * check.
	 */
	if (!IPCL_IS_RAWIP(connp)) {
		mutex_exit(&ipst->ips_ip_g_mrouter_mutex);
		return (EINVAL);
	}

	ipst->ips_ip_g_mrouter = connp;
	connp->conn_multi_router = 1;
	/* In order for tunnels to work we have to turn ip_g_forward on */
	if (!WE_ARE_FORWARDING(ipst)) {
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(connp->conn_rq, 1, SL_TRACE,
			    "ip_mrouter_init: turning on forwarding");
		}
		ipst->ips_saved_ip_forwarding = ipst->ips_ip_forwarding;
		ipst->ips_ip_forwarding = IP_FORWARD_ALWAYS;
	}

	mutex_exit(&ipst->ips_ip_g_mrouter_mutex);
	return (0);
}

void
ip_mrouter_stack_init(ip_stack_t *ipst)
{
	mutex_init(&ipst->ips_ip_g_mrouter_mutex, NULL, MUTEX_DEFAULT, NULL);

	ipst->ips_vifs = kmem_zalloc(sizeof (struct vif) * (MAXVIFS+1),
	    KM_SLEEP);
	ipst->ips_mrtstat = kmem_zalloc(sizeof (struct mrtstat), KM_SLEEP);
	/*
	 * mfctable:
	 * Includes all mfcs, including waiting upcalls.
	 * Multiple mfcs per bucket.
	 */
	ipst->ips_mfcs = kmem_zalloc(sizeof (struct mfcb) * MFCTBLSIZ,
	    KM_SLEEP);
	/*
	 * Define the token bucket filter structures.
	 * tbftable -> each vif has one of these for storing info.
	 */
	ipst->ips_tbfs = kmem_zalloc(sizeof (struct tbf) * MAXVIFS, KM_SLEEP);

	mutex_init(&ipst->ips_last_encap_lock, NULL, MUTEX_DEFAULT, NULL);

	ipst->ips_mrtstat->mrts_vifctlSize = sizeof (struct vifctl);
	ipst->ips_mrtstat->mrts_mfcctlSize = sizeof (struct mfcctl);
}

/*
 * Disable multicast routing.
 * Didn't use global timeout_val (BSD version), instead check the mfctable.
 */
int
ip_mrouter_done(ip_stack_t *ipst)
{
	conn_t		*mrouter;
	vifi_t 		vifi;
	struct mfc	*mfc_rt;
	int		i;

	mutex_enter(&ipst->ips_ip_g_mrouter_mutex);
	if (ipst->ips_ip_g_mrouter == NULL) {
		mutex_exit(&ipst->ips_ip_g_mrouter_mutex);
		return (EINVAL);
	}

	mrouter = ipst->ips_ip_g_mrouter;

	if (ipst->ips_saved_ip_forwarding != -1) {
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "ip_mrouter_done: turning off forwarding");
		}
		ipst->ips_ip_forwarding = ipst->ips_saved_ip_forwarding;
		ipst->ips_saved_ip_forwarding = -1;
	}

	/*
	 * Always clear cache when vifs change.
	 * No need to get ipst->ips_last_encap_lock since we are running as
	 * a writer.
	 */
	mutex_enter(&ipst->ips_last_encap_lock);
	ipst->ips_last_encap_src = 0;
	ipst->ips_last_encap_vif = NULL;
	mutex_exit(&ipst->ips_last_encap_lock);
	mrouter->conn_multi_router = 0;

	mutex_exit(&ipst->ips_ip_g_mrouter_mutex);

	/*
	 * For each phyint in use,
	 * disable promiscuous reception of all IP multicasts.
	 */
	for (vifi = 0; vifi < MAXVIFS; vifi++) {
		struct vif *vifp = ipst->ips_vifs + vifi;

		mutex_enter(&vifp->v_lock);
		/*
		 * if the vif is active mark it condemned.
		 */
		if (vifp->v_marks & VIF_MARK_GOOD) {
			ASSERT(vifp->v_ipif != NULL);
			ipif_refhold(vifp->v_ipif);
			/* Phyint only */
			if (!(vifp->v_flags & (VIFF_TUNNEL | VIFF_REGISTER))) {
				ipif_t *ipif = vifp->v_ipif;
				ilm_t *ilm = vifp->v_ilm;

				vifp->v_ilm = NULL;
				vifp->v_marks &= ~VIF_MARK_GOOD;
				vifp->v_marks |= VIF_MARK_CONDEMNED;

				mutex_exit(&(vifp)->v_lock);
				if (ilm != NULL) {
					ill_t *ill = ipif->ipif_ill;

					(void) ip_delmulti(ilm);
					ASSERT(ill->ill_mrouter_cnt > 0);
					atomic_dec_32(&ill->ill_mrouter_cnt);
				}
				mutex_enter(&vifp->v_lock);
			}
			ipif_refrele(vifp->v_ipif);
			/*
			 * decreases the refcnt added in add_vif.
			 * and release v_lock.
			 */
			VIF_REFRELE_LOCKED(vifp);
		} else {
			mutex_exit(&vifp->v_lock);
			continue;
		}
	}

	mutex_enter(&ipst->ips_numvifs_mutex);
	ipst->ips_numvifs = 0;
	ipst->ips_pim_assert = 0;
	ipst->ips_reg_vif_num = ALL_VIFS;
	mutex_exit(&ipst->ips_numvifs_mutex);

	/*
	 * Free upcall msgs.
	 * Go through mfctable and stop any outstanding upcall
	 * timeouts remaining on mfcs.
	 */
	for (i = 0; i < MFCTBLSIZ; i++) {
		mutex_enter(&ipst->ips_mfcs[i].mfcb_lock);
		ipst->ips_mfcs[i].mfcb_refcnt++;
		ipst->ips_mfcs[i].mfcb_marks |= MFCB_MARK_CONDEMNED;
		mutex_exit(&ipst->ips_mfcs[i].mfcb_lock);
		mfc_rt = ipst->ips_mfcs[i].mfcb_mfc;
		while (mfc_rt) {
			/* Free upcalls */
			mutex_enter(&mfc_rt->mfc_mutex);
			if (mfc_rt->mfc_rte != NULL) {
				if (mfc_rt->mfc_timeout_id != 0) {
					/*
					 * OK to drop the lock as we have
					 * a refcnt on the bucket. timeout
					 * can fire but it will see that
					 * mfc_timeout_id == 0 and not do
					 * anything. see expire_upcalls().
					 */
					mfc_rt->mfc_timeout_id = 0;
					mutex_exit(&mfc_rt->mfc_mutex);
					(void) untimeout(
					    mfc_rt->mfc_timeout_id);
						mfc_rt->mfc_timeout_id = 0;
					mutex_enter(&mfc_rt->mfc_mutex);

					/*
					 * all queued upcall packets
					 * and mblk will be freed in
					 * release_mfc().
					 */
				}
			}

			mfc_rt->mfc_marks |= MFCB_MARK_CONDEMNED;

			mutex_exit(&mfc_rt->mfc_mutex);
			mfc_rt = mfc_rt->mfc_next;
		}
		MFCB_REFRELE(&ipst->ips_mfcs[i]);
	}

	mutex_enter(&ipst->ips_ip_g_mrouter_mutex);
	ipst->ips_ip_g_mrouter = NULL;
	mutex_exit(&ipst->ips_ip_g_mrouter_mutex);
	return (0);
}

void
ip_mrouter_stack_destroy(ip_stack_t *ipst)
{
	struct mfcb *mfcbp;
	struct mfc  *rt;
	int i;

	for (i = 0; i < MFCTBLSIZ; i++) {
		mfcbp = &ipst->ips_mfcs[i];

		while ((rt = mfcbp->mfcb_mfc) != NULL) {
			(void) printf("ip_mrouter_stack_destroy: free for %d\n",
			    i);

			mfcbp->mfcb_mfc = rt->mfc_next;
			free_queue(rt);
			mi_free(rt);
		}
	}
	kmem_free(ipst->ips_vifs, sizeof (struct vif) * (MAXVIFS+1));
	ipst->ips_vifs = NULL;
	kmem_free(ipst->ips_mrtstat, sizeof (struct mrtstat));
	ipst->ips_mrtstat = NULL;
	kmem_free(ipst->ips_mfcs, sizeof (struct mfcb) * MFCTBLSIZ);
	ipst->ips_mfcs = NULL;
	kmem_free(ipst->ips_tbfs, sizeof (struct tbf) * MAXVIFS);
	ipst->ips_tbfs = NULL;

	mutex_destroy(&ipst->ips_last_encap_lock);
	mutex_destroy(&ipst->ips_ip_g_mrouter_mutex);
}

static boolean_t
is_mrouter_off(ip_stack_t *ipst)
{
	conn_t	*mrouter;

	mutex_enter(&ipst->ips_ip_g_mrouter_mutex);
	if (ipst->ips_ip_g_mrouter == NULL) {
		mutex_exit(&ipst->ips_ip_g_mrouter_mutex);
		return (B_TRUE);
	}

	mrouter = ipst->ips_ip_g_mrouter;
	if (mrouter->conn_multi_router == 0) {
		mutex_exit(&ipst->ips_ip_g_mrouter_mutex);
		return (B_TRUE);
	}
	mutex_exit(&ipst->ips_ip_g_mrouter_mutex);
	return (B_FALSE);
}

static void
unlock_good_vif(struct vif *vifp)
{
	ASSERT(vifp->v_ipif != NULL);
	ipif_refrele(vifp->v_ipif);
	VIF_REFRELE(vifp);
}

static boolean_t
lock_good_vif(struct vif *vifp)
{
	mutex_enter(&vifp->v_lock);
	if (!(vifp->v_marks & VIF_MARK_GOOD)) {
		mutex_exit(&vifp->v_lock);
		return (B_FALSE);
	}

	ASSERT(vifp->v_ipif != NULL);
	mutex_enter(&vifp->v_ipif->ipif_ill->ill_lock);
	if (!IPIF_CAN_LOOKUP(vifp->v_ipif)) {
		mutex_exit(&vifp->v_ipif->ipif_ill->ill_lock);
		mutex_exit(&vifp->v_lock);
		return (B_FALSE);
	}
	ipif_refhold_locked(vifp->v_ipif);
	mutex_exit(&vifp->v_ipif->ipif_ill->ill_lock);
	vifp->v_refcnt++;
	mutex_exit(&vifp->v_lock);
	return (B_TRUE);
}

/*
 * Add a vif to the vif table.
 */
static int
add_vif(struct vifctl *vifcp, conn_t *connp, ip_stack_t *ipst)
{
	struct vif	*vifp = ipst->ips_vifs + vifcp->vifc_vifi;
	ipif_t		*ipif;
	int		error = 0;
	struct tbf	*v_tbf = ipst->ips_tbfs + vifcp->vifc_vifi;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;
	ilm_t		*ilm;
	ill_t		*ill;

	ASSERT(connp != NULL);

	if (vifcp->vifc_vifi >= MAXVIFS)
		return (EINVAL);

	if (is_mrouter_off(ipst))
		return (EINVAL);

	mutex_enter(&vifp->v_lock);
	/*
	 * Viftable entry should be 0.
	 * if v_marks == 0 but v_refcnt != 0 means struct is being
	 * initialized.
	 *
	 * Also note that it is very unlikely that we will get a MRT_ADD_VIF
	 * request while the delete is in progress, mrouted only sends add
	 * requests when a new interface is added and the new interface cannot
	 * have the same vifi as an existing interface. We make sure that
	 * ill_delete will block till the vif is deleted by adding a refcnt
	 * to ipif in del_vif().
	 */
	if (vifp->v_lcl_addr.s_addr != 0 ||
	    vifp->v_marks != 0 ||
	    vifp->v_refcnt != 0) {
		mutex_exit(&vifp->v_lock);
		return (EADDRINUSE);
	}

	/* Incoming vif should not be 0 */
	if (vifcp->vifc_lcl_addr.s_addr == 0) {
		mutex_exit(&vifp->v_lock);
		return (EINVAL);
	}

	vifp->v_refcnt++;
	mutex_exit(&vifp->v_lock);
	/* Find the interface with the local address */
	ipif = ipif_lookup_addr((ipaddr_t)vifcp->vifc_lcl_addr.s_addr, NULL,
	    IPCL_ZONEID(connp), ipst);
	if (ipif == NULL) {
		VIF_REFRELE(vifp);
		return (EADDRNOTAVAIL);
	}

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "add_vif: src 0x%x enter",
		    vifcp->vifc_lcl_addr.s_addr);
	}

	mutex_enter(&vifp->v_lock);
	/*
	 * Always clear cache when vifs change.
	 * Needed to ensure that src isn't left over from before vif was added.
	 * No need to get last_encap_lock, since we are running as a writer.
	 */

	mutex_enter(&ipst->ips_last_encap_lock);
	ipst->ips_last_encap_src = 0;
	ipst->ips_last_encap_vif = NULL;
	mutex_exit(&ipst->ips_last_encap_lock);

	if (vifcp->vifc_flags & VIFF_TUNNEL) {
		if ((vifcp->vifc_flags & VIFF_SRCRT) != 0) {
			cmn_err(CE_WARN,
			    "add_vif: source route tunnels not supported\n");
			VIF_REFRELE_LOCKED(vifp);
			ipif_refrele(ipif);
			return (EOPNOTSUPP);
		}
		vifp->v_rmt_addr  = vifcp->vifc_rmt_addr;

	} else {
		/* Phyint or Register vif */
		if (vifcp->vifc_flags & VIFF_REGISTER) {
			/*
			 * Note: Since all IPPROTO_IP level options (including
			 * MRT_ADD_VIF) are done exclusively via
			 * ip_optmgmt_writer(), a lock is not necessary to
			 * protect reg_vif_num.
			 */
			mutex_enter(&ipst->ips_numvifs_mutex);
			if (ipst->ips_reg_vif_num == ALL_VIFS) {
				ipst->ips_reg_vif_num = vifcp->vifc_vifi;
				mutex_exit(&ipst->ips_numvifs_mutex);
			} else {
				mutex_exit(&ipst->ips_numvifs_mutex);
				VIF_REFRELE_LOCKED(vifp);
				ipif_refrele(ipif);
				return (EADDRINUSE);
			}
		}

		/* Make sure the interface supports multicast */
		if ((ipif->ipif_ill->ill_flags & ILLF_MULTICAST) == 0) {
			VIF_REFRELE_LOCKED(vifp);
			ipif_refrele(ipif);
			if (vifcp->vifc_flags & VIFF_REGISTER) {
				mutex_enter(&ipst->ips_numvifs_mutex);
				ipst->ips_reg_vif_num = ALL_VIFS;
				mutex_exit(&ipst->ips_numvifs_mutex);
			}
			return (EOPNOTSUPP);
		}
		/* Enable promiscuous reception of all IP mcasts from the if */
		mutex_exit(&vifp->v_lock);

		ill = ipif->ipif_ill;
		if (IS_UNDER_IPMP(ill))
			ill = ipmp_ill_hold_ipmp_ill(ill);

		if (ill == NULL) {
			ilm = NULL;
		} else {
			ilm = ip_addmulti(&ipv6_all_zeros, ill,
			    ipif->ipif_zoneid, &error);
			if (ilm != NULL)
				atomic_inc_32(&ill->ill_mrouter_cnt);
			if (IS_UNDER_IPMP(ipif->ipif_ill)) {
				ill_refrele(ill);
				ill = ipif->ipif_ill;
			}
		}

		mutex_enter(&vifp->v_lock);
		/*
		 * since we released the lock lets make sure that
		 * ip_mrouter_done() has not been called.
		 */
		if (ilm == NULL || is_mrouter_off(ipst)) {
			if (ilm != NULL) {
				(void) ip_delmulti(ilm);
				ASSERT(ill->ill_mrouter_cnt > 0);
				atomic_dec_32(&ill->ill_mrouter_cnt);
			}
			if (vifcp->vifc_flags & VIFF_REGISTER) {
				mutex_enter(&ipst->ips_numvifs_mutex);
				ipst->ips_reg_vif_num = ALL_VIFS;
				mutex_exit(&ipst->ips_numvifs_mutex);
			}
			VIF_REFRELE_LOCKED(vifp);
			ipif_refrele(ipif);
			return (error?error:EINVAL);
		}
		vifp->v_ilm = ilm;
	}
	/* Define parameters for the tbf structure */
	vifp->v_tbf = v_tbf;
	gethrestime(&vifp->v_tbf->tbf_last_pkt_t);
	vifp->v_tbf->tbf_n_tok = 0;
	vifp->v_tbf->tbf_q_len = 0;
	vifp->v_tbf->tbf_max_q_len = MAXQSIZE;
	vifp->v_tbf->tbf_q = vifp->v_tbf->tbf_t = NULL;

	vifp->v_flags = vifcp->vifc_flags;
	vifp->v_threshold = vifcp->vifc_threshold;
	vifp->v_lcl_addr = vifcp->vifc_lcl_addr;
	vifp->v_ipif = ipif;
	ipif_refrele(ipif);
	/* Scaling up here, allows division by 1024 in critical code.	*/
	vifp->v_rate_limit = vifcp->vifc_rate_limit * (1024/1000);
	vifp->v_timeout_id = 0;
	/* initialize per vif pkt counters */
	vifp->v_pkt_in = 0;
	vifp->v_pkt_out = 0;
	vifp->v_bytes_in = 0;
	vifp->v_bytes_out = 0;
	mutex_init(&vifp->v_tbf->tbf_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Adjust numvifs up, if the vifi is higher than numvifs */
	mutex_enter(&ipst->ips_numvifs_mutex);
	if (ipst->ips_numvifs <= vifcp->vifc_vifi)
		ipst->ips_numvifs = vifcp->vifc_vifi + 1;
	mutex_exit(&ipst->ips_numvifs_mutex);

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "add_vif: #%d, lcladdr %x, %s %x, thresh %x, rate %d",
		    vifcp->vifc_vifi,
		    ntohl(vifcp->vifc_lcl_addr.s_addr),
		    (vifcp->vifc_flags & VIFF_TUNNEL) ? "rmtaddr" : "mask",
		    ntohl(vifcp->vifc_rmt_addr.s_addr),
		    vifcp->vifc_threshold, vifcp->vifc_rate_limit);
	}

	vifp->v_marks = VIF_MARK_GOOD;
	mutex_exit(&vifp->v_lock);
	return (0);
}


/* Delete a vif from the vif table. */
static void
del_vifp(struct vif *vifp)
{
	struct tbf	*t = vifp->v_tbf;
	mblk_t  *mp0;
	vifi_t  vifi;
	ip_stack_t	*ipst = vifp->v_ipif->ipif_ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	ASSERT(vifp->v_marks & VIF_MARK_CONDEMNED);
	ASSERT(t != NULL);

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "del_vif: src 0x%x\n", vifp->v_lcl_addr.s_addr);
	}

	if (vifp->v_timeout_id != 0) {
		(void) untimeout(vifp->v_timeout_id);
		vifp->v_timeout_id = 0;
	}

	/*
	 * Free packets queued at the interface.
	 * Mrouted takes care of cleaning up mfcs - makes calls to del_mfc.
	 */
	mutex_enter(&t->tbf_lock);
	while (t->tbf_q != NULL) {
		mp0 = t->tbf_q;
		t->tbf_q = t->tbf_q->b_next;
		mp0->b_prev = mp0->b_next = NULL;
		freemsg(mp0);
	}
	mutex_exit(&t->tbf_lock);

	/*
	 * Always clear cache when vifs change.
	 * No need to get last_encap_lock since we are running as a writer.
	 */
	mutex_enter(&ipst->ips_last_encap_lock);
	if (vifp == ipst->ips_last_encap_vif) {
		ipst->ips_last_encap_vif = NULL;
		ipst->ips_last_encap_src = 0;
	}
	mutex_exit(&ipst->ips_last_encap_lock);

	mutex_destroy(&t->tbf_lock);

	bzero(vifp->v_tbf, sizeof (*(vifp->v_tbf)));

	/* Adjust numvifs down */
	mutex_enter(&ipst->ips_numvifs_mutex);
	for (vifi = ipst->ips_numvifs; vifi != 0; vifi--) /* vifi is unsigned */
		if (ipst->ips_vifs[vifi - 1].v_lcl_addr.s_addr != 0)
			break;
	ipst->ips_numvifs = vifi;
	mutex_exit(&ipst->ips_numvifs_mutex);

	bzero(vifp, sizeof (*vifp));
}

static int
del_vif(vifi_t *vifip, ip_stack_t *ipst)
{
	struct vif	*vifp = ipst->ips_vifs + *vifip;

	if (*vifip >= ipst->ips_numvifs)
		return (EINVAL);

	mutex_enter(&vifp->v_lock);
	/*
	 * Not initialized
	 * Here we are not looking at the vif that is being initialized
	 * i.e vifp->v_marks == 0 and refcnt > 0.
	 */
	if (vifp->v_lcl_addr.s_addr == 0 ||
	    !(vifp->v_marks & VIF_MARK_GOOD)) {
		mutex_exit(&vifp->v_lock);
		return (EADDRNOTAVAIL);
	}

	/* Clear VIF_MARK_GOOD and set VIF_MARK_CONDEMNED. */
	vifp->v_marks &= ~VIF_MARK_GOOD;
	vifp->v_marks |= VIF_MARK_CONDEMNED;

	/* Phyint only */
	if (!(vifp->v_flags & (VIFF_TUNNEL | VIFF_REGISTER))) {
		ipif_t *ipif = vifp->v_ipif;
		ilm_t *ilm = vifp->v_ilm;

		vifp->v_ilm = NULL;

		ASSERT(ipif != NULL);
		/*
		 * should be OK to drop the lock as we
		 * have marked this as CONDEMNED.
		 */
		mutex_exit(&(vifp)->v_lock);
		if (ilm != NULL) {
			(void) ip_delmulti(ilm);
			ASSERT(ipif->ipif_ill->ill_mrouter_cnt > 0);
			atomic_dec_32(&ipif->ipif_ill->ill_mrouter_cnt);
		}
		mutex_enter(&(vifp)->v_lock);
	}

	if (vifp->v_flags & VIFF_REGISTER) {
		mutex_enter(&ipst->ips_numvifs_mutex);
		ipst->ips_reg_vif_num = ALL_VIFS;
		mutex_exit(&ipst->ips_numvifs_mutex);
	}

	/*
	 * decreases the refcnt added in add_vif.
	 */
	VIF_REFRELE_LOCKED(vifp);
	return (0);
}

/*
 * Add an mfc entry.
 */
static int
add_mfc(struct mfcctl *mfccp, ip_stack_t *ipst)
{
	struct mfc *rt;
	struct rtdetq *rte;
	ushort_t nstl;
	int i;
	struct mfcb *mfcbp;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	/*
	 * The value of vifi is NO_VIF (==MAXVIFS) if Mrouted
	 * did not have a real route for pkt.
	 * We want this pkt without rt installed in the mfctable to prevent
	 * multiiple tries, so go ahead and put it in mfctable, it will
	 * be discarded later in ip_mdq() because the child is NULL.
	 */

	/* Error checking, out of bounds? */
	if (mfccp->mfcc_parent > MAXVIFS) {
		ip0dbg(("ADD_MFC: mfcc_parent out of range %d",
		    (int)mfccp->mfcc_parent));
		return (EINVAL);
	}

	if ((mfccp->mfcc_parent != NO_VIF) &&
	    (ipst->ips_vifs[mfccp->mfcc_parent].v_ipif == NULL)) {
		ip0dbg(("ADD_MFC: NULL ipif for parent vif %d\n",
		    (int)mfccp->mfcc_parent));
		return (EINVAL);
	}

	if (is_mrouter_off(ipst)) {
		return (EINVAL);
	}

	mfcbp = &ipst->ips_mfcs[MFCHASH(mfccp->mfcc_origin.s_addr,
	    mfccp->mfcc_mcastgrp.s_addr)];
	MFCB_REFHOLD(mfcbp);
	MFCFIND(mfcbp, mfccp->mfcc_origin.s_addr,
	    mfccp->mfcc_mcastgrp.s_addr, rt);

	/* If an entry already exists, just update the fields */
	if (rt) {
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "add_mfc: update o %x grp %x parent %x",
			    ntohl(mfccp->mfcc_origin.s_addr),
			    ntohl(mfccp->mfcc_mcastgrp.s_addr),
			    mfccp->mfcc_parent);
		}
		mutex_enter(&rt->mfc_mutex);
		rt->mfc_parent = mfccp->mfcc_parent;

		mutex_enter(&ipst->ips_numvifs_mutex);
		for (i = 0; i < (int)ipst->ips_numvifs; i++)
			rt->mfc_ttls[i] = mfccp->mfcc_ttls[i];
		mutex_exit(&ipst->ips_numvifs_mutex);
		mutex_exit(&rt->mfc_mutex);

		MFCB_REFRELE(mfcbp);
		return (0);
	}

	/*
	 * Find the entry for which the upcall was made and update.
	 */
	for (rt = mfcbp->mfcb_mfc, nstl = 0; rt; rt = rt->mfc_next) {
		mutex_enter(&rt->mfc_mutex);
		if ((rt->mfc_origin.s_addr == mfccp->mfcc_origin.s_addr) &&
		    (rt->mfc_mcastgrp.s_addr == mfccp->mfcc_mcastgrp.s_addr) &&
		    (rt->mfc_rte != NULL) &&
		    !(rt->mfc_marks & MFCB_MARK_CONDEMNED)) {
			if (nstl++ != 0)
				cmn_err(CE_WARN,
				    "add_mfc: %s o %x g %x p %x",
				    "multiple kernel entries",
				    ntohl(mfccp->mfcc_origin.s_addr),
				    ntohl(mfccp->mfcc_mcastgrp.s_addr),
				    mfccp->mfcc_parent);

			if (ipst->ips_ip_mrtdebug > 1) {
				(void) mi_strlog(mrouter->conn_rq, 1,
				    SL_TRACE,
				    "add_mfc: o %x g %x p %x",
				    ntohl(mfccp->mfcc_origin.s_addr),
				    ntohl(mfccp->mfcc_mcastgrp.s_addr),
				    mfccp->mfcc_parent);
			}
			fill_route(rt, mfccp, ipst);

			/*
			 * Prevent cleanup of cache entry.
			 * Timer starts in ip_mforward.
			 */
			if (rt->mfc_timeout_id != 0) {
				timeout_id_t id;
				id = rt->mfc_timeout_id;
				/*
				 * setting id to zero will avoid this
				 * entry from being cleaned up in
				 * expire_up_calls().
				 */
				rt->mfc_timeout_id = 0;
				/*
				 * dropping the lock is fine as we
				 * have a refhold on the bucket.
				 * so mfc cannot be freed.
				 * The timeout can fire but it will see
				 * that mfc_timeout_id == 0 and not cleanup.
				 */
				mutex_exit(&rt->mfc_mutex);
				(void) untimeout(id);
				mutex_enter(&rt->mfc_mutex);
			}

			/*
			 * Send all pkts that are queued waiting for the upcall.
			 * ip_mdq param tun set to 0 -
			 * the return value of ip_mdq() isn't used here,
			 * so value we send doesn't matter.
			 */
			while (rt->mfc_rte != NULL) {
				rte = rt->mfc_rte;
				rt->mfc_rte = rte->rte_next;
				mutex_exit(&rt->mfc_mutex);
				(void) ip_mdq(rte->mp, (ipha_t *)
				    rte->mp->b_rptr, rte->ill, 0, rt);
				freemsg(rte->mp);
				mi_free((char *)rte);
				mutex_enter(&rt->mfc_mutex);
			}
		}
		mutex_exit(&rt->mfc_mutex);
	}


	/*
	 * It is possible that an entry is being inserted without an upcall
	 */
	if (nstl == 0) {
		mutex_enter(&(mfcbp->mfcb_lock));
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "add_mfc: no upcall o %x g %x p %x",
			    ntohl(mfccp->mfcc_origin.s_addr),
			    ntohl(mfccp->mfcc_mcastgrp.s_addr),
			    mfccp->mfcc_parent);
		}
		if (is_mrouter_off(ipst)) {
			mutex_exit(&mfcbp->mfcb_lock);
			MFCB_REFRELE(mfcbp);
			return (EINVAL);
		}

		for (rt = mfcbp->mfcb_mfc; rt; rt = rt->mfc_next) {

			mutex_enter(&rt->mfc_mutex);
			if ((rt->mfc_origin.s_addr ==
			    mfccp->mfcc_origin.s_addr) &&
			    (rt->mfc_mcastgrp.s_addr ==
			    mfccp->mfcc_mcastgrp.s_addr) &&
			    (!(rt->mfc_marks & MFCB_MARK_CONDEMNED))) {
				fill_route(rt, mfccp, ipst);
				mutex_exit(&rt->mfc_mutex);
				break;
			}
			mutex_exit(&rt->mfc_mutex);
		}

		/* No upcall, so make a new entry into mfctable */
		if (rt == NULL) {
			rt = (struct mfc *)mi_zalloc(sizeof (struct mfc));
			if (rt == NULL) {
				ip1dbg(("add_mfc: out of memory\n"));
				mutex_exit(&mfcbp->mfcb_lock);
				MFCB_REFRELE(mfcbp);
				return (ENOBUFS);
			}

			/* Insert new entry at head of hash chain */
			mutex_enter(&rt->mfc_mutex);
			fill_route(rt, mfccp, ipst);

			/* Link into table */
			rt->mfc_next   = mfcbp->mfcb_mfc;
			mfcbp->mfcb_mfc = rt;
			mutex_exit(&rt->mfc_mutex);
		}
		mutex_exit(&mfcbp->mfcb_lock);
	}

	MFCB_REFRELE(mfcbp);
	return (0);
}

/*
 * Fills in mfc structure from mrouted mfcctl.
 */
static void
fill_route(struct mfc *rt, struct mfcctl *mfccp, ip_stack_t *ipst)
{
	int i;

	rt->mfc_origin		= mfccp->mfcc_origin;
	rt->mfc_mcastgrp	= mfccp->mfcc_mcastgrp;
	rt->mfc_parent		= mfccp->mfcc_parent;
	mutex_enter(&ipst->ips_numvifs_mutex);
	for (i = 0; i < (int)ipst->ips_numvifs; i++) {
		rt->mfc_ttls[i] = mfccp->mfcc_ttls[i];
	}
	mutex_exit(&ipst->ips_numvifs_mutex);
	/* Initialize pkt counters per src-grp */
	rt->mfc_pkt_cnt	= 0;
	rt->mfc_byte_cnt	= 0;
	rt->mfc_wrong_if	= 0;
	rt->mfc_last_assert.tv_sec = rt->mfc_last_assert.tv_nsec = 0;

}

static void
free_queue(struct mfc *mfcp)
{
	struct rtdetq *rte0;

	/*
	 * Drop all queued upcall packets.
	 * Free the mbuf with the pkt.
	 */
	while ((rte0 = mfcp->mfc_rte) != NULL) {
		mfcp->mfc_rte = rte0->rte_next;
		freemsg(rte0->mp);
		mi_free((char *)rte0);
	}
}
/*
 * go thorugh the hash bucket and free all the entries marked condemned.
 */
void
release_mfc(struct mfcb *mfcbp)
{
	struct mfc *current_mfcp;
	struct mfc *prev_mfcp;

	prev_mfcp = current_mfcp = mfcbp->mfcb_mfc;

	while (current_mfcp != NULL) {
		if (current_mfcp->mfc_marks & MFCB_MARK_CONDEMNED) {
			if (current_mfcp == mfcbp->mfcb_mfc) {
				mfcbp->mfcb_mfc = current_mfcp->mfc_next;
				free_queue(current_mfcp);
				mi_free(current_mfcp);
				prev_mfcp = current_mfcp = mfcbp->mfcb_mfc;
				continue;
			}
			ASSERT(prev_mfcp != NULL);
			prev_mfcp->mfc_next = current_mfcp->mfc_next;
			free_queue(current_mfcp);
			mi_free(current_mfcp);
			current_mfcp = NULL;
		} else {
			prev_mfcp = current_mfcp;
		}

		current_mfcp = prev_mfcp->mfc_next;

	}
	mfcbp->mfcb_marks &= ~MFCB_MARK_CONDEMNED;
	ASSERT(mfcbp->mfcb_mfc != NULL || mfcbp->mfcb_marks == 0);
}

/*
 * Delete an mfc entry.
 */
static int
del_mfc(struct mfcctl *mfccp, ip_stack_t *ipst)
{
	struct in_addr	origin;
	struct in_addr	mcastgrp;
	struct mfc 	*rt;
	uint_t		hash;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	origin = mfccp->mfcc_origin;
	mcastgrp = mfccp->mfcc_mcastgrp;
	hash = MFCHASH(origin.s_addr, mcastgrp.s_addr);

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "del_mfc: o %x g %x",
		    ntohl(origin.s_addr),
		    ntohl(mcastgrp.s_addr));
	}

	MFCB_REFHOLD(&ipst->ips_mfcs[hash]);

	/* Find mfc in mfctable, finds only entries without upcalls */
	for (rt = ipst->ips_mfcs[hash].mfcb_mfc; rt; rt = rt->mfc_next) {
		mutex_enter(&rt->mfc_mutex);
		if (origin.s_addr == rt->mfc_origin.s_addr &&
		    mcastgrp.s_addr == rt->mfc_mcastgrp.s_addr &&
		    rt->mfc_rte == NULL &&
		    !(rt->mfc_marks & MFCB_MARK_CONDEMNED))
			break;
		mutex_exit(&rt->mfc_mutex);
	}

	/*
	 * Return if there was an upcall (mfc_rte != NULL,
	 * or rt not in mfctable.
	 */
	if (rt == NULL) {
		MFCB_REFRELE(&ipst->ips_mfcs[hash]);
		return (EADDRNOTAVAIL);
	}


	/*
	 * no need to hold lock as we have a reference.
	 */
	ipst->ips_mfcs[hash].mfcb_marks |= MFCB_MARK_CONDEMNED;
	/* error checking */
	if (rt->mfc_timeout_id != 0) {
		ip0dbg(("del_mfc: TIMEOUT NOT 0, rte not null"));
		/*
		 * Its ok to drop the lock,  the struct cannot be freed
		 * since we have a ref on the hash bucket.
		 */
		rt->mfc_timeout_id = 0;
		mutex_exit(&rt->mfc_mutex);
		(void) untimeout(rt->mfc_timeout_id);
		mutex_enter(&rt->mfc_mutex);
	}

	ASSERT(rt->mfc_rte == NULL);


	/*
	 * Delete the entry from the cache
	 */
	rt->mfc_marks |= MFCB_MARK_CONDEMNED;
	mutex_exit(&rt->mfc_mutex);

	MFCB_REFRELE(&ipst->ips_mfcs[hash]);

	return (0);
}

#define	TUNNEL_LEN  12  /* # bytes of IP option for tunnel encapsulation  */

/*
 * IP multicast forwarding function. This function assumes that the packet
 * pointed to by ipha has arrived on (or is about to be sent to) the interface
 * pointed to by "ill", and the packet is to be relayed to other networks
 * that have members of the packet's destination IP multicast group.
 *
 * The packet is returned unscathed to the caller, unless it is
 * erroneous, in which case a -1 value tells the caller (IP)
 * to discard it.
 *
 * Unlike BSD, SunOS 5.x needs to return to IP info about
 * whether pkt came in thru a tunnel, so it can be discarded, unless
 * it's IGMP. In BSD, the ifp is bogus for tunnels, so pkt won't try
 * to be delivered.
 * Return values are 0 - pkt is okay and phyint
 *		    -1 - pkt is malformed and to be tossed
 *                   1 - pkt came in on tunnel
 */
int
ip_mforward(mblk_t *mp, ip_recv_attr_t *ira)
{
	ipha_t		*ipha = (ipha_t *)mp->b_rptr;
	ill_t		*ill = ira->ira_ill;
	struct mfc 	*rt;
	ipaddr_t	src, dst, tunnel_src = 0;
	static int	srctun = 0;
	vifi_t		vifi;
	boolean_t	pim_reg_packet = B_FALSE;
	struct mfcb	*mfcbp;
	ip_stack_t	*ipst = ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;
	ill_t		*rill = ira->ira_rill;

	ASSERT(ira->ira_pktlen == msgdsize(mp));

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "ip_mforward: RECV ipha_src %x, ipha_dst %x, ill %s",
		    ntohl(ipha->ipha_src), ntohl(ipha->ipha_dst),
		    ill->ill_name);
	}

	dst = ipha->ipha_dst;
	if (ira->ira_flags & IRAF_PIM_REGISTER)
		pim_reg_packet = B_TRUE;
	else if (ira->ira_flags & IRAF_MROUTE_TUNNEL_SET)
		tunnel_src = ira->ira_mroute_tunnel;

	/*
	 * Don't forward a packet with time-to-live of zero or one,
	 * or a packet destined to a local-only group.
	 */
	if (CLASSD(dst) && (ipha->ipha_ttl <= 1 ||
	    (ipaddr_t)ntohl(dst) <= INADDR_MAX_LOCAL_GROUP)) {
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "ip_mforward: not forwarded ttl %d,"
			    " dst 0x%x ill %s",
			    ipha->ipha_ttl, ntohl(dst), ill->ill_name);
		}
		if (tunnel_src != 0)
			return (1);
		else
			return (0);
	}

	if ((tunnel_src != 0) || pim_reg_packet) {
		/*
		 * Packet arrived over an encapsulated tunnel or via a PIM
		 * register message.
		 */
		if (ipst->ips_ip_mrtdebug > 1) {
			if (tunnel_src != 0) {
				(void) mi_strlog(mrouter->conn_rq, 1,
				    SL_TRACE,
				    "ip_mforward: ill %s arrived via ENCAP TUN",
				    ill->ill_name);
			} else if (pim_reg_packet) {
				(void) mi_strlog(mrouter->conn_rq, 1,
				    SL_TRACE,
				    "ip_mforward: ill %s arrived via"
				    "  REGISTER VIF",
				    ill->ill_name);
			}
		}
	} else if ((ipha->ipha_version_and_hdr_length & 0xf) <
	    (uint_t)(IP_SIMPLE_HDR_LENGTH + TUNNEL_LEN) >> 2 ||
	    ((uchar_t *)(ipha + 1))[1] != IPOPT_LSRR) {
		/* Packet arrived via a physical interface. */
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "ip_mforward: ill %s arrived via PHYINT",
			    ill->ill_name);
		}

	} else {
		/*
		 * Packet arrived through a SRCRT tunnel.
		 * Source-route tunnels are no longer supported.
		 * Error message printed every 1000 times.
		 */
		if ((srctun++ % 1000) == 0) {
			cmn_err(CE_WARN,
			    "ip_mforward: received source-routed pkt from %x",
			    ntohl(ipha->ipha_src));
		}
		return (-1);
	}

	ipst->ips_mrtstat->mrts_fwd_in++;
	src = ipha->ipha_src;

	/* Find route in cache, return NULL if not there or upcalls q'ed. */

	/*
	 * Lock the mfctable against changes made by ip_mforward.
	 * Note that only add_mfc and del_mfc can remove entries and
	 * they run with exclusive access to IP. So we do not need to
	 * guard against the rt being deleted, so release lock after reading.
	 */

	if (is_mrouter_off(ipst))
		return (-1);

	mfcbp = &ipst->ips_mfcs[MFCHASH(src, dst)];
	MFCB_REFHOLD(mfcbp);
	MFCFIND(mfcbp, src, dst, rt);

	/* Entry exists, so forward if necessary */
	if (rt != NULL) {
		int ret = 0;
		ipst->ips_mrtstat->mrts_mfc_hits++;
		if (pim_reg_packet) {
			ASSERT(ipst->ips_reg_vif_num != ALL_VIFS);
			ret = ip_mdq(mp, ipha,
			    ipst->ips_vifs[ipst->ips_reg_vif_num].
			    v_ipif->ipif_ill,
			    0, rt);
		} else {
			ret = ip_mdq(mp, ipha, ill, tunnel_src, rt);
		}

		MFCB_REFRELE(mfcbp);
		return (ret);

		/*
		 * Don't forward if we don't have a cache entry.  Mrouted will
		 * always provide a cache entry in response to an upcall.
		 */
	} else {
		/*
		 * If we don't have a route for packet's origin, make a copy
		 * of the packet and send message to routing daemon.
		 */
		struct mfc	*mfc_rt	 = NULL;
		mblk_t		*mp0	 = NULL;
		mblk_t		*mp_copy = NULL;
		struct rtdetq	*rte	 = NULL;
		struct rtdetq	*rte_m, *rte1, *prev_rte;
		uint_t		hash;
		int		npkts;
		boolean_t	new_mfc = B_FALSE;
		ipst->ips_mrtstat->mrts_mfc_misses++;
		/* BSD uses mrts_no_route++ */
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "ip_mforward: no rte ill %s src %x g %x misses %d",
			    ill->ill_name, ntohl(src), ntohl(dst),
			    (int)ipst->ips_mrtstat->mrts_mfc_misses);
		}
		/*
		 * The order of the following code differs from the BSD code.
		 * Pre-mc3.5, the BSD code was incorrect and SunOS 5.x
		 * code works, so SunOS 5.x wasn't changed to conform to the
		 * BSD version.
		 */

		/* Lock mfctable. */
		hash = MFCHASH(src, dst);
		mutex_enter(&(ipst->ips_mfcs[hash].mfcb_lock));

		/*
		 * If we are turning off mrouted return an error
		 */
		if (is_mrouter_off(ipst)) {
			mutex_exit(&mfcbp->mfcb_lock);
			MFCB_REFRELE(mfcbp);
			return (-1);
		}

		/* Is there an upcall waiting for this packet? */
		for (mfc_rt = ipst->ips_mfcs[hash].mfcb_mfc; mfc_rt;
		    mfc_rt = mfc_rt->mfc_next) {
			mutex_enter(&mfc_rt->mfc_mutex);
			if (ipst->ips_ip_mrtdebug > 1) {
				(void) mi_strlog(mrouter->conn_rq, 1,
				    SL_TRACE,
				    "ip_mforward: MFCTAB hash %d o 0x%x"
				    " g 0x%x\n",
				    hash, ntohl(mfc_rt->mfc_origin.s_addr),
				    ntohl(mfc_rt->mfc_mcastgrp.s_addr));
			}
			/* There is an upcall */
			if ((src == mfc_rt->mfc_origin.s_addr) &&
			    (dst == mfc_rt->mfc_mcastgrp.s_addr) &&
			    (mfc_rt->mfc_rte != NULL) &&
			    !(mfc_rt->mfc_marks & MFCB_MARK_CONDEMNED)) {
				break;
			}
			mutex_exit(&mfc_rt->mfc_mutex);
		}
		/* No upcall, so make a new entry into mfctable */
		if (mfc_rt == NULL) {
			mfc_rt = (struct mfc *)mi_zalloc(sizeof (struct mfc));
			if (mfc_rt == NULL) {
				ipst->ips_mrtstat->mrts_fwd_drop++;
				ip1dbg(("ip_mforward: out of memory "
				    "for mfc, mfc_rt\n"));
				goto error_return;
			} else
				new_mfc = B_TRUE;
			/* Get resources */
			/* TODO could copy header and dup rest */
			mp_copy = copymsg(mp);
			if (mp_copy == NULL) {
				ipst->ips_mrtstat->mrts_fwd_drop++;
				ip1dbg(("ip_mforward: out of memory for "
				    "mblk, mp_copy\n"));
				goto error_return;
			}
			mutex_enter(&mfc_rt->mfc_mutex);
		}
		/* Get resources for rte, whether first rte or not first. */
		/* Add this packet into rtdetq */
		rte = (struct rtdetq *)mi_zalloc(sizeof (struct rtdetq));
		if (rte == NULL) {
			ipst->ips_mrtstat->mrts_fwd_drop++;
			mutex_exit(&mfc_rt->mfc_mutex);
			ip1dbg(("ip_mforward: out of memory for"
			    " rtdetq, rte\n"));
			goto error_return;
		}

		mp0 = copymsg(mp);
		if (mp0 == NULL) {
			ipst->ips_mrtstat->mrts_fwd_drop++;
			ip1dbg(("ip_mforward: out of memory for mblk, mp0\n"));
			mutex_exit(&mfc_rt->mfc_mutex);
			goto error_return;
		}
		rte->mp		= mp0;
		if (pim_reg_packet) {
			ASSERT(ipst->ips_reg_vif_num != ALL_VIFS);
			rte->ill =
			    ipst->ips_vifs[ipst->ips_reg_vif_num].
			    v_ipif->ipif_ill;
		} else {
			rte->ill = ill;
		}
		rte->rte_next	= NULL;

		/*
		 * Determine if upcall q (rtdetq) has overflowed.
		 * mfc_rt->mfc_rte is null by mi_zalloc
		 * if it is the first message.
		 */
		for (rte_m = mfc_rt->mfc_rte, npkts = 0; rte_m;
		    rte_m = rte_m->rte_next)
			npkts++;
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "ip_mforward: upcalls %d\n", npkts);
		}
		if (npkts > MAX_UPQ) {
			ipst->ips_mrtstat->mrts_upq_ovflw++;
			mutex_exit(&mfc_rt->mfc_mutex);
			goto error_return;
		}

		if (npkts == 0) {	/* first upcall */
			int i = 0;
			/*
			 * Now finish installing the new mfc! Now that we have
			 * resources!  Insert new entry at head of hash chain.
			 * Use src and dst which are ipaddr_t's.
			 */
			mfc_rt->mfc_origin.s_addr = src;
			mfc_rt->mfc_mcastgrp.s_addr = dst;

			mutex_enter(&ipst->ips_numvifs_mutex);
			for (i = 0; i < (int)ipst->ips_numvifs; i++)
				mfc_rt->mfc_ttls[i] = 0;
			mutex_exit(&ipst->ips_numvifs_mutex);
			mfc_rt->mfc_parent = ALL_VIFS;

			/* Link into table */
			if (ipst->ips_ip_mrtdebug > 1) {
				(void) mi_strlog(mrouter->conn_rq, 1,
				    SL_TRACE,
				    "ip_mforward: NEW MFCTAB hash %d o 0x%x "
				    "g 0x%x\n", hash,
				    ntohl(mfc_rt->mfc_origin.s_addr),
				    ntohl(mfc_rt->mfc_mcastgrp.s_addr));
			}
			mfc_rt->mfc_next = ipst->ips_mfcs[hash].mfcb_mfc;
			ipst->ips_mfcs[hash].mfcb_mfc = mfc_rt;
			mfc_rt->mfc_rte = NULL;
		}

		/* Link in the upcall */
		/* First upcall */
		if (mfc_rt->mfc_rte == NULL)
			mfc_rt->mfc_rte = rte;
		else {
			/* not the first upcall */
			prev_rte = mfc_rt->mfc_rte;
			for (rte1 = mfc_rt->mfc_rte->rte_next; rte1;
			    prev_rte = rte1, rte1 = rte1->rte_next)
				;
			prev_rte->rte_next = rte;
		}

		/*
		 * No upcalls waiting, this is first one, so send a message to
		 * routing daemon to install a route into kernel table.
		 */
		if (npkts == 0) {
			struct igmpmsg	*im;
			/* ipha_protocol is 0, for upcall */
			ASSERT(mp_copy != NULL);
			im = (struct igmpmsg *)mp_copy->b_rptr;
			im->im_msgtype	= IGMPMSG_NOCACHE;
			im->im_mbz = 0;
			mutex_enter(&ipst->ips_numvifs_mutex);
			if (pim_reg_packet) {
				im->im_vif = (uchar_t)ipst->ips_reg_vif_num;
				mutex_exit(&ipst->ips_numvifs_mutex);
			} else {
				/*
				 * XXX do we need to hold locks here ?
				 */
				for (vifi = 0;
				    vifi < ipst->ips_numvifs;
				    vifi++) {
					if (ipst->ips_vifs[vifi].v_ipif == NULL)
						continue;
					if (ipst->ips_vifs[vifi].
					    v_ipif->ipif_ill == ill) {
						im->im_vif = (uchar_t)vifi;
						break;
					}
				}
				mutex_exit(&ipst->ips_numvifs_mutex);
				ASSERT(vifi < ipst->ips_numvifs);
			}

			ipst->ips_mrtstat->mrts_upcalls++;
			/* Timer to discard upcalls if mrouted is too slow */
			mfc_rt->mfc_timeout_id = timeout(expire_upcalls,
			    mfc_rt, EXPIRE_TIMEOUT * UPCALL_EXPIRE);
			mutex_exit(&mfc_rt->mfc_mutex);
			mutex_exit(&(ipst->ips_mfcs[hash].mfcb_lock));
			/* Pass to RAWIP */
			ira->ira_ill = ira->ira_rill = NULL;
			(mrouter->conn_recv)(mrouter, mp_copy, NULL, ira);
			ira->ira_ill = ill;
			ira->ira_rill = rill;
		} else {
			mutex_exit(&mfc_rt->mfc_mutex);
			mutex_exit(&(ipst->ips_mfcs[hash].mfcb_lock));
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ip_mforward - upcall already waiting",
			    mp_copy, ill);
			freemsg(mp_copy);
		}

		MFCB_REFRELE(mfcbp);
		if (tunnel_src != 0)
			return (1);
		else
			return (0);
	error_return:
		mutex_exit(&(ipst->ips_mfcs[hash].mfcb_lock));
		MFCB_REFRELE(mfcbp);
		if (mfc_rt != NULL && (new_mfc == B_TRUE))
			mi_free((char *)mfc_rt);
		if (rte != NULL)
			mi_free((char *)rte);
		if (mp_copy != NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ip_mforward error", mp_copy, ill);
			freemsg(mp_copy);
		}
		if (mp0 != NULL)
			freemsg(mp0);
		return (-1);
	}
}

/*
 * Clean up the mfctable cache entry if upcall is not serviced.
 * SunOS 5.x has timeout per mfc, unlike BSD which has one timer.
 */
static void
expire_upcalls(void *arg)
{
	struct mfc *mfc_rt = arg;
	uint_t hash;
	struct mfc *prev_mfc, *mfc0;
	ip_stack_t	*ipst;
	conn_t		*mrouter;

	if (mfc_rt->mfc_rte == NULL || mfc_rt->mfc_rte->ill != NULL) {
		cmn_err(CE_WARN, "expire_upcalls: no ILL\n");
		return;
	}
	ipst = mfc_rt->mfc_rte->ill->ill_ipst;
	mrouter = ipst->ips_ip_g_mrouter;

	hash = MFCHASH(mfc_rt->mfc_origin.s_addr, mfc_rt->mfc_mcastgrp.s_addr);
	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "expire_upcalls: hash %d s %x g %x",
		    hash, ntohl(mfc_rt->mfc_origin.s_addr),
		    ntohl(mfc_rt->mfc_mcastgrp.s_addr));
	}
	MFCB_REFHOLD(&ipst->ips_mfcs[hash]);
	mutex_enter(&mfc_rt->mfc_mutex);
	/*
	 * if timeout has been set to zero, than the
	 * entry has been filled, no need to delete it.
	 */
	if (mfc_rt->mfc_timeout_id == 0)
		goto done;
	ipst->ips_mrtstat->mrts_cache_cleanups++;
	mfc_rt->mfc_timeout_id = 0;

	/* Determine entry to be cleaned up in cache table. */
	for (prev_mfc = mfc0 = ipst->ips_mfcs[hash].mfcb_mfc; mfc0;
	    prev_mfc = mfc0, mfc0 = mfc0->mfc_next)
		if (mfc0 == mfc_rt)
			break;

	/* del_mfc takes care of gone mfcs */
	ASSERT(prev_mfc != NULL);
	ASSERT(mfc0 != NULL);

	/*
	 * Delete the entry from the cache
	 */
	ipst->ips_mfcs[hash].mfcb_marks |= MFCB_MARK_CONDEMNED;
	mfc_rt->mfc_marks |= MFCB_MARK_CONDEMNED;

	/*
	 * release_mfc will drop all queued upcall packets.
	 * and will free the mbuf with the pkt, if, timing info.
	 */
done:
	mutex_exit(&mfc_rt->mfc_mutex);
	MFCB_REFRELE(&ipst->ips_mfcs[hash]);
}

/*
 * Packet forwarding routine once entry in the cache is made.
 */
static int
ip_mdq(mblk_t *mp, ipha_t *ipha, ill_t *ill, ipaddr_t tunnel_src,
    struct mfc *rt)
{
	vifi_t vifi;
	struct vif *vifp;
	ipaddr_t dst = ipha->ipha_dst;
	size_t  plen = msgdsize(mp);
	vifi_t num_of_vifs;
	ip_stack_t	*ipst = ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;
	ip_recv_attr_t	iras;

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "ip_mdq: SEND src %x, ipha_dst %x, ill %s",
		    ntohl(ipha->ipha_src), ntohl(ipha->ipha_dst),
		    ill->ill_name);
	}

	/* Macro to send packet on vif */
#define	MC_SEND(ipha, mp, vifp, dst) { \
	if ((vifp)->v_flags & VIFF_TUNNEL) \
		encap_send((ipha), (mp), (vifp), (dst)); \
	else if ((vifp)->v_flags & VIFF_REGISTER) \
		register_send((ipha), (mp), (vifp), (dst)); \
	else \
		phyint_send((ipha), (mp), (vifp), (dst)); \
}

	vifi = rt->mfc_parent;

	/*
	 * The value of vifi is MAXVIFS if the pkt had no parent, i.e.,
	 * Mrouted had no route.
	 * We wanted the route installed in the mfctable to prevent multiple
	 * tries, so it passed add_mfc(), but is discarded here. The v_ipif is
	 * NULL so we don't want to check the ill. Still needed as of Mrouted
	 * 3.6.
	 */
	if (vifi == NO_VIF) {
		ip1dbg(("ip_mdq: no route for origin ill %s, vifi is NO_VIF\n",
		    ill->ill_name));
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "ip_mdq: vifi is NO_VIF ill = %s", ill->ill_name);
		}
		return (-1);	/* drop pkt */
	}

	if (!lock_good_vif(&ipst->ips_vifs[vifi]))
		return (-1);
	/*
	 * The MFC entries are not cleaned up when an ipif goes
	 * away thus this code has to guard against an MFC referencing
	 * an ipif that has been closed. Note: reset_mrt_vif_ipif
	 * sets the v_ipif to NULL when the ipif disappears.
	 */
	ASSERT(ipst->ips_vifs[vifi].v_ipif != NULL);

	if (vifi >= ipst->ips_numvifs) {
		cmn_err(CE_WARN, "ip_mdq: illegal vifi %d numvifs "
		    "%d ill %s viftable ill %s\n",
		    (int)vifi, (int)ipst->ips_numvifs, ill->ill_name,
		    ipst->ips_vifs[vifi].v_ipif->ipif_ill->ill_name);
		unlock_good_vif(&ipst->ips_vifs[vifi]);
		return (-1);
	}
	/*
	 * Don't forward if it didn't arrive from the parent vif for its
	 * origin.
	 */
	if ((ipst->ips_vifs[vifi].v_ipif->ipif_ill != ill) ||
	    (ipst->ips_vifs[vifi].v_rmt_addr.s_addr != tunnel_src)) {
		/* Came in the wrong interface */
		ip1dbg(("ip_mdq: arrived wrong if, vifi %d "
			"numvifs %d ill %s viftable ill %s\n",
			(int)vifi, (int)ipst->ips_numvifs, ill->ill_name,
			ipst->ips_vifs[vifi].v_ipif->ipif_ill->ill_name));
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "ip_mdq: arrived wrong if, vifi %d ill "
			    "%s viftable ill %s\n",
			    (int)vifi, ill->ill_name,
			    ipst->ips_vifs[vifi].v_ipif->ipif_ill->ill_name);
		}
		ipst->ips_mrtstat->mrts_wrong_if++;
		rt->mfc_wrong_if++;

		/*
		 * If we are doing PIM assert processing and we are forwarding
		 * packets on this interface, and it is a broadcast medium
		 * interface (and not a tunnel), send a message to the routing.
		 *
		 * We use the first ipif on the list, since it's all we have.
		 * Chances are the ipif_flags are the same for ipifs on the ill.
		 */
		if (ipst->ips_pim_assert && rt->mfc_ttls[vifi] > 0 &&
		    (ill->ill_ipif->ipif_flags & IPIF_BROADCAST) &&
		    !(ipst->ips_vifs[vifi].v_flags & VIFF_TUNNEL)) {
			mblk_t		*mp_copy;
			struct igmpmsg	*im;

			/* TODO could copy header and dup rest */
			mp_copy = copymsg(mp);
			if (mp_copy == NULL) {
				ipst->ips_mrtstat->mrts_fwd_drop++;
				ip1dbg(("ip_mdq: out of memory "
				    "for mblk, mp_copy\n"));
				unlock_good_vif(&ipst->ips_vifs[vifi]);
				return (-1);
			}

			im = (struct igmpmsg *)mp_copy->b_rptr;
			im->im_msgtype = IGMPMSG_WRONGVIF;
			im->im_mbz = 0;
			im->im_vif = (ushort_t)vifi;
			/* Pass to RAWIP */

			bzero(&iras, sizeof (iras));
			iras.ira_flags = IRAF_IS_IPV4;
			iras.ira_ip_hdr_length =
			    IPH_HDR_LENGTH(mp_copy->b_rptr);
			iras.ira_pktlen = msgdsize(mp_copy);
			(mrouter->conn_recv)(mrouter, mp_copy, NULL, &iras);
			ASSERT(!(iras.ira_flags & IRAF_IPSEC_SECURE));
		}
		unlock_good_vif(&ipst->ips_vifs[vifi]);
		if (tunnel_src != 0)
			return (1);
		else
			return (0);
	}
	/*
	 * If I sourced this packet, it counts as output, else it was input.
	 */
	if (ipha->ipha_src == ipst->ips_vifs[vifi].v_lcl_addr.s_addr) {
		ipst->ips_vifs[vifi].v_pkt_out++;
		ipst->ips_vifs[vifi].v_bytes_out += plen;
	} else {
		ipst->ips_vifs[vifi].v_pkt_in++;
		ipst->ips_vifs[vifi].v_bytes_in += plen;
	}
	mutex_enter(&rt->mfc_mutex);
	rt->mfc_pkt_cnt++;
	rt->mfc_byte_cnt += plen;
	mutex_exit(&rt->mfc_mutex);
	unlock_good_vif(&ipst->ips_vifs[vifi]);
	/*
	 * For each vif, decide if a copy of the packet should be forwarded.
	 * Forward if:
	 *		- the vif threshold ttl is non-zero AND
	 *		- the pkt ttl exceeds the vif's threshold
	 * A non-zero mfc_ttl indicates that the vif is part of
	 * the output set for the mfc entry.
	 */
	mutex_enter(&ipst->ips_numvifs_mutex);
	num_of_vifs = ipst->ips_numvifs;
	mutex_exit(&ipst->ips_numvifs_mutex);
	for (vifp = ipst->ips_vifs, vifi = 0;
	    vifi < num_of_vifs;
	    vifp++, vifi++) {
		if (!lock_good_vif(vifp))
			continue;
		if ((rt->mfc_ttls[vifi] > 0) &&
		    (ipha->ipha_ttl > rt->mfc_ttls[vifi])) {
			/*
			 * lock_good_vif should not have succedded if
			 * v_ipif is null.
			 */
			ASSERT(vifp->v_ipif != NULL);
			vifp->v_pkt_out++;
			vifp->v_bytes_out += plen;
			MC_SEND(ipha, mp, vifp, dst);
			ipst->ips_mrtstat->mrts_fwd_out++;
		}
		unlock_good_vif(vifp);
	}
	if (tunnel_src != 0)
		return (1);
	else
		return (0);
}

/*
 * Send the packet on physical interface.
 * Caller assumes can continue to use mp on return.
 */
/* ARGSUSED */
static void
phyint_send(ipha_t *ipha, mblk_t *mp, struct vif *vifp, ipaddr_t dst)
{
	mblk_t 	*mp_copy;
	ip_stack_t	*ipst = vifp->v_ipif->ipif_ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	/* Make a new reference to the packet */
	mp_copy = copymsg(mp);	/* TODO could copy header and dup rest */
	if (mp_copy == NULL) {
		ipst->ips_mrtstat->mrts_fwd_drop++;
		ip1dbg(("phyint_send: out of memory for mblk, mp_copy\n"));
		return;
	}
	if (vifp->v_rate_limit <= 0)
		tbf_send_packet(vifp, mp_copy);
	else  {
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "phyint_send: tbf_contr rate %d "
			    "vifp 0x%p mp 0x%p dst 0x%x",
			    vifp->v_rate_limit, (void *)vifp, (void *)mp, dst);
		}
		tbf_control(vifp, mp_copy, (ipha_t *)mp_copy->b_rptr);
	}
}

/*
 * Send the whole packet for REGISTER encapsulation to PIM daemon
 * Caller assumes it can continue to use mp on return.
 */
/* ARGSUSED */
static void
register_send(ipha_t *ipha, mblk_t *mp, struct vif *vifp, ipaddr_t dst)
{
	struct igmpmsg	*im;
	mblk_t		*mp_copy;
	ipha_t		*ipha_copy;
	ill_t		*ill = vifp->v_ipif->ipif_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;
	ip_recv_attr_t	iras;

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "register_send: src %x, dst %x\n",
		    ntohl(ipha->ipha_src), ntohl(ipha->ipha_dst));
	}

	/*
	 * Copy the old packet & pullup its IP header into the new mblk_t so we
	 * can modify it.  Try to fill the new mblk_t since if we don't the
	 * ethernet driver will.
	 */
	mp_copy = allocb(sizeof (struct igmpmsg) + sizeof (ipha_t), BPRI_MED);
	if (mp_copy == NULL) {
		++ipst->ips_mrtstat->mrts_pim_nomemory;
		if (ipst->ips_ip_mrtdebug > 3) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "register_send: allocb failure.");
		}
		return;
	}

	/*
	 * Bump write pointer to account for igmpmsg being added.
	 */
	mp_copy->b_wptr = mp_copy->b_rptr + sizeof (struct igmpmsg);

	/*
	 * Chain packet to new mblk_t.
	 */
	if ((mp_copy->b_cont = copymsg(mp)) == NULL) {
		++ipst->ips_mrtstat->mrts_pim_nomemory;
		if (ipst->ips_ip_mrtdebug > 3) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "register_send: copymsg failure.");
		}
		freeb(mp_copy);
		return;
	}

	/*
	 * icmp_input() asserts that IP version field is set to an
	 * appropriate version. Hence, the struct igmpmsg that this really
	 * becomes, needs to have the correct IP version field.
	 */
	ipha_copy = (ipha_t *)mp_copy->b_rptr;
	*ipha_copy = multicast_encap_iphdr;

	/*
	 * The kernel uses the struct igmpmsg header to encode the messages to
	 * the multicast routing daemon. Fill in the fields in the header
	 * starting with the message type which is IGMPMSG_WHOLEPKT
	 */
	im = (struct igmpmsg *)mp_copy->b_rptr;
	im->im_msgtype = IGMPMSG_WHOLEPKT;
	im->im_src.s_addr = ipha->ipha_src;
	im->im_dst.s_addr = ipha->ipha_dst;

	/*
	 * Must Be Zero. This is because the struct igmpmsg is really an IP
	 * header with renamed fields and the multicast routing daemon uses
	 * an ipha_protocol (aka im_mbz) of 0 to distinguish these messages.
	 */
	im->im_mbz = 0;

	++ipst->ips_mrtstat->mrts_upcalls;
	if (IPCL_IS_NONSTR(mrouter) ? mrouter->conn_flow_cntrld :
	    !canputnext(mrouter->conn_rq)) {
		++ipst->ips_mrtstat->mrts_pim_regsend_drops;
		if (ipst->ips_ip_mrtdebug > 3) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "register_send: register upcall failure.");
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("mrts_pim_regsend_drops", mp_copy, ill);
		freemsg(mp_copy);
	} else {
		/* Pass to RAWIP */
		bzero(&iras, sizeof (iras));
		iras.ira_flags = IRAF_IS_IPV4;
		iras.ira_ip_hdr_length = sizeof (ipha_t);
		iras.ira_pktlen = msgdsize(mp_copy);
		(mrouter->conn_recv)(mrouter, mp_copy, NULL, &iras);
		ASSERT(!(iras.ira_flags & IRAF_IPSEC_SECURE));
	}
}

/*
 * pim_validate_cksum handles verification of the checksum in the
 * pim header.  For PIM Register packets, the checksum is calculated
 * across the PIM header only.  For all other packets, the checksum
 * is for the PIM header and remainder of the packet.
 *
 * returns: B_TRUE, if checksum is okay.
 *          B_FALSE, if checksum is not valid.
 */
static boolean_t
pim_validate_cksum(mblk_t *mp, ipha_t *ip, struct pim *pimp)
{
	mblk_t *mp_dup;

	if ((mp_dup = dupmsg(mp)) == NULL)
		return (B_FALSE);

	mp_dup->b_rptr += IPH_HDR_LENGTH(ip);
	if (pimp->pim_type == PIM_REGISTER)
		mp_dup->b_wptr = mp_dup->b_rptr + PIM_MINLEN;
	if (IP_CSUM(mp_dup, 0, 0)) {
		freemsg(mp_dup);
		return (B_FALSE);
	}
	freemsg(mp_dup);
	return (B_TRUE);
}

/*
 * Process PIM protocol packets i.e. IP Protocol 103.
 * Register messages are decapsulated and sent onto multicast forwarding.
 *
 * Return NULL for a bad packet that is discarded here.
 * Return mp if the message is OK and should be handed to "raw" receivers.
 * Callers of pim_input() may need to reinitialize variables that were copied
 * from the mblk as this calls pullupmsg().
 */
mblk_t *
pim_input(mblk_t *mp, ip_recv_attr_t *ira)
{
	ipha_t		*eip, *ip;
	int		iplen, pimlen, iphlen;
	struct pim	*pimp;	/* pointer to a pim struct */
	uint32_t	*reghdr;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	/*
	 * Pullup the msg for PIM protocol processing.
	 */
	if (pullupmsg(mp, -1) == 0) {
		++ipst->ips_mrtstat->mrts_pim_nomemory;
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("mrts_pim_nomemory", mp, ill);
		freemsg(mp);
		return (NULL);
	}

	ip = (ipha_t *)mp->b_rptr;
	iplen = ip->ipha_length;
	iphlen = IPH_HDR_LENGTH(ip);
	pimlen = ntohs(iplen) - iphlen;

	/*
	 * Validate lengths
	 */
	if (pimlen < PIM_MINLEN) {
		++ipst->ips_mrtstat->mrts_pim_malformed;
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "pim_input: length not at least minlen");
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("mrts_pim_malformed", mp, ill);
		freemsg(mp);
		return (NULL);
	}

	/*
	 * Point to the PIM header.
	 */
	pimp = (struct pim *)((caddr_t)ip + iphlen);

	/*
	 * Check the version number.
	 */
	if (pimp->pim_vers != PIM_VERSION) {
		++ipst->ips_mrtstat->mrts_pim_badversion;
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "pim_input: unknown version of PIM");
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("mrts_pim_badversion", mp, ill);
		freemsg(mp);
		return (NULL);
	}

	/*
	 * Validate the checksum
	 */
	if (!pim_validate_cksum(mp, ip, pimp)) {
		++ipst->ips_mrtstat->mrts_pim_rcv_badcsum;
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "pim_input: invalid checksum");
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("pim_rcv_badcsum", mp, ill);
		freemsg(mp);
		return (NULL);
	}

	if (pimp->pim_type != PIM_REGISTER)
		return (mp);

	reghdr = (uint32_t *)(pimp + 1);
	eip = (ipha_t *)(reghdr + 1);

	/*
	 * check if the inner packet is destined to mcast group
	 */
	if (!CLASSD(eip->ipha_dst)) {
		++ipst->ips_mrtstat->mrts_pim_badregisters;
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "pim_input: Inner pkt not mcast .. !");
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("mrts_pim_badregisters", mp, ill);
		freemsg(mp);
		return (NULL);
	}
	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "register from %x, to %x, len %d",
		    ntohl(eip->ipha_src),
		    ntohl(eip->ipha_dst),
		    ntohs(eip->ipha_length));
	}
	/*
	 * If the null register bit is not set, decapsulate
	 * the packet before forwarding it.
	 * Avoid this in no register vif
	 */
	if (!(ntohl(*reghdr) & PIM_NULL_REGISTER) &&
	    ipst->ips_reg_vif_num != ALL_VIFS) {
		mblk_t *mp_copy;
		uint_t saved_pktlen;

		/* Copy the message */
		if ((mp_copy = copymsg(mp)) == NULL) {
			++ipst->ips_mrtstat->mrts_pim_nomemory;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("mrts_pim_nomemory", mp, ill);
			freemsg(mp);
			return (NULL);
		}

		/*
		 * Decapsulate the packet and give it to
		 * register_mforward.
		 */
		mp_copy->b_rptr += iphlen + sizeof (pim_t) + sizeof (*reghdr);
		saved_pktlen = ira->ira_pktlen;
		ira->ira_pktlen -= iphlen + sizeof (pim_t) + sizeof (*reghdr);
		if (register_mforward(mp_copy, ira) != 0) {
			/* register_mforward already called ip_drop_input */
			freemsg(mp);
			ira->ira_pktlen = saved_pktlen;
			return (NULL);
		}
		ira->ira_pktlen = saved_pktlen;
	}

	/*
	 * Pass all valid PIM packets up to any process(es) listening on a raw
	 * PIM socket. For Solaris it is done right after pim_input() is
	 * called.
	 */
	return (mp);
}

/*
 * PIM sparse mode hook.  Called by pim_input after decapsulating
 * the packet. Loop back the packet, as if we have received it.
 * In pim_input() we have to check if the destination is a multicast address.
 */
static int
register_mforward(mblk_t *mp, ip_recv_attr_t *ira)
{
	ire_t		*ire;
	ipha_t		*ipha = (ipha_t *)mp->b_rptr;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	ASSERT(ipst->ips_reg_vif_num <= ipst->ips_numvifs);

	if (ipst->ips_ip_mrtdebug > 3) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "register_mforward: src %x, dst %x\n",
		    ntohl(ipha->ipha_src), ntohl(ipha->ipha_dst));
	}
	/*
	 * Need to pass in to ip_mforward() the information that the
	 * packet has arrived on the register_vif. We mark it with
	 * the IRAF_PIM_REGISTER attribute.
	 * pim_input verified that the (inner) destination is multicast,
	 * hence we skip the generic code in ip_input.
	 */
	ira->ira_flags |= IRAF_PIM_REGISTER;
	++ipst->ips_mrtstat->mrts_pim_regforwards;

	if (!CLASSD(ipha->ipha_dst)) {
		ire = ire_route_recursive_v4(ipha->ipha_dst, 0, NULL, ALL_ZONES,
		    ira->ira_tsl, MATCH_IRE_SECATTR, IRR_ALLOCATE, 0, ipst,
		    NULL, NULL, NULL);
	} else {
		ire = ire_multicast(ill);
	}
	ASSERT(ire != NULL);
	/* Normally this will return the IRE_MULTICAST */
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("mrts_pim RTF_REJECT", mp, ill);
		freemsg(mp);
		ire_refrele(ire);
		return (-1);
	}
	ASSERT(ire->ire_type & IRE_MULTICAST);
	(*ire->ire_recvfn)(ire, mp, ipha, ira);
	ire_refrele(ire);

	return (0);
}

/*
 * Send an encapsulated packet.
 * Caller assumes can continue to use mp when routine returns.
 */
/* ARGSUSED */
static void
encap_send(ipha_t *ipha, mblk_t *mp, struct vif *vifp, ipaddr_t dst)
{
	mblk_t 	*mp_copy;
	ipha_t 	*ipha_copy;
	size_t	len;
	ip_stack_t	*ipst = vifp->v_ipif->ipif_ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "encap_send: vif %ld enter",
		    (ptrdiff_t)(vifp - ipst->ips_vifs));
	}
	len = ntohs(ipha->ipha_length);

	/*
	 * Copy the old packet & pullup it's IP header into the
	 * new mbuf so we can modify it.  Try to fill the new
	 * mbuf since if we don't the ethernet driver will.
	 */
	mp_copy = allocb(32 + sizeof (multicast_encap_iphdr), BPRI_MED);
	if (mp_copy == NULL)
		return;
	mp_copy->b_rptr += 32;
	mp_copy->b_wptr = mp_copy->b_rptr + sizeof (multicast_encap_iphdr);
	if ((mp_copy->b_cont = copymsg(mp)) == NULL) {
		freeb(mp_copy);
		return;
	}

	/*
	 * Fill in the encapsulating IP header.
	 * Remote tunnel dst in rmt_addr, from add_vif().
	 */
	ipha_copy = (ipha_t *)mp_copy->b_rptr;
	*ipha_copy = multicast_encap_iphdr;
	ASSERT((len + sizeof (ipha_t)) <= IP_MAXPACKET);
	ipha_copy->ipha_length = htons(len + sizeof (ipha_t));
	ipha_copy->ipha_src = vifp->v_lcl_addr.s_addr;
	ipha_copy->ipha_dst = vifp->v_rmt_addr.s_addr;
	ASSERT(ipha_copy->ipha_ident == 0);

	/* Turn the encapsulated IP header back into a valid one. */
	ipha = (ipha_t *)mp_copy->b_cont->b_rptr;
	ipha->ipha_ttl--;
	ipha->ipha_hdr_checksum = 0;
	ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);

	ipha_copy->ipha_ttl = ipha->ipha_ttl;

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "encap_send: group 0x%x", ntohl(ipha->ipha_dst));
	}
	if (vifp->v_rate_limit <= 0)
		tbf_send_packet(vifp, mp_copy);
	else
		/* ipha is from the original header */
		tbf_control(vifp, mp_copy, ipha);
}

/*
 * De-encapsulate a packet and feed it back through IP input if it
 * matches one of our multicast tunnels.
 *
 * This routine is called whenever IP gets a packet with prototype
 * IPPROTO_ENCAP and a local destination address and the packet didn't
 * match one of our configured IP-in-IP tunnels.
 */
void
ip_mroute_decap(mblk_t *mp, ip_recv_attr_t *ira)
{
	ipha_t		*ipha = (ipha_t *)mp->b_rptr;
	ipha_t		*ipha_encap;
	int		hlen = IPH_HDR_LENGTH(ipha);
	int		hlen_encap;
	ipaddr_t	src;
	struct vif	*vifp;
	ire_t		*ire;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	/* Make sure we have all of the inner header */
	ipha_encap = (ipha_t *)((char *)ipha + hlen);
	if (mp->b_wptr - mp->b_rptr < hlen + IP_SIMPLE_HDR_LENGTH) {
		ipha = ip_pullup(mp, hlen + IP_SIMPLE_HDR_LENGTH, ira);
		if (ipha == NULL) {
			ipst->ips_mrtstat->mrts_bad_tunnel++;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ip_mroute_decap: too short", mp, ill);
			freemsg(mp);
			return;
		}
		ipha_encap = (ipha_t *)((char *)ipha + hlen);
	}
	hlen_encap = IPH_HDR_LENGTH(ipha_encap);
	if (mp->b_wptr - mp->b_rptr < hlen + hlen_encap) {
		ipha = ip_pullup(mp, hlen + hlen_encap, ira);
		if (ipha == NULL) {
			ipst->ips_mrtstat->mrts_bad_tunnel++;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ip_mroute_decap: too short", mp, ill);
			freemsg(mp);
			return;
		}
		ipha_encap = (ipha_t *)((char *)ipha + hlen);
	}

	/*
	 * Dump the packet if it's not to a multicast destination or if
	 * we don't have an encapsulating tunnel with the source.
	 * Note:  This code assumes that the remote site IP address
	 * uniquely identifies the tunnel (i.e., that this site has
	 * at most one tunnel with the remote site).
	 */
	if (!CLASSD(ipha_encap->ipha_dst)) {
		ipst->ips_mrtstat->mrts_bad_tunnel++;
		ip1dbg(("ip_mroute_decap: bad tunnel\n"));
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("mrts_bad_tunnel", mp, ill);
		freemsg(mp);
		return;
	}
	src = (ipaddr_t)ipha->ipha_src;
	mutex_enter(&ipst->ips_last_encap_lock);
	if (src != ipst->ips_last_encap_src) {
		struct vif *vife;

		vifp = ipst->ips_vifs;
		vife = vifp + ipst->ips_numvifs;
		ipst->ips_last_encap_src = src;
		ipst->ips_last_encap_vif = 0;
		for (; vifp < vife; ++vifp) {
			if (!lock_good_vif(vifp))
				continue;
			if (vifp->v_rmt_addr.s_addr == src) {
				if (vifp->v_flags & VIFF_TUNNEL)
					ipst->ips_last_encap_vif = vifp;
				if (ipst->ips_ip_mrtdebug > 1) {
					(void) mi_strlog(mrouter->conn_rq,
					    1, SL_TRACE,
					    "ip_mroute_decap: good tun "
					    "vif %ld with %x",
					    (ptrdiff_t)(vifp - ipst->ips_vifs),
					    ntohl(src));
				}
				unlock_good_vif(vifp);
				break;
			}
			unlock_good_vif(vifp);
		}
	}
	if ((vifp = ipst->ips_last_encap_vif) == 0) {
		mutex_exit(&ipst->ips_last_encap_lock);
		ipst->ips_mrtstat->mrts_bad_tunnel++;
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("mrts_bad_tunnel", mp, ill);
		freemsg(mp);
		ip1dbg(("ip_mroute_decap: vif %ld no tunnel with %x\n",
		    (ptrdiff_t)(vifp - ipst->ips_vifs), ntohl(src)));
		return;
	}
	mutex_exit(&ipst->ips_last_encap_lock);

	/*
	 * Need to pass in the tunnel source to ip_mforward (so that it can
	 * verify that the packet arrived over the correct vif.)
	 */
	ira->ira_flags |= IRAF_MROUTE_TUNNEL_SET;
	ira->ira_mroute_tunnel = src;
	mp->b_rptr += hlen;
	ira->ira_pktlen -= hlen;
	ira->ira_ip_hdr_length = hlen_encap;

	/*
	 * We don't redo any of the filtering in ill_input_full_v4 and we
	 * have checked that all of ipha_encap and any IP options are
	 * pulled up. Hence we call ire_recv_multicast_v4 directly.
	 * However, we have to check for RSVP as in ip_input_full_v4
	 * and if so we pass it to ire_recv_broadcast_v4 for local delivery
	 * to the rsvpd.
	 */
	if (ipha_encap->ipha_protocol == IPPROTO_RSVP &&
	    ipst->ips_ipcl_proto_fanout_v4[IPPROTO_RSVP].connf_head != NULL) {
		ire = ire_route_recursive_v4(INADDR_BROADCAST, 0, ill,
		    ALL_ZONES, ira->ira_tsl, MATCH_IRE_ILL|MATCH_IRE_SECATTR,
		    IRR_ALLOCATE, 0, ipst, NULL, NULL, NULL);
	} else {
		ire = ire_multicast(ill);
	}
	ASSERT(ire != NULL);
	/* Normally this will return the IRE_MULTICAST or IRE_BROADCAST */
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ip_mroute_decap: RTF_REJECT", mp, ill);
		freemsg(mp);
		ire_refrele(ire);
		return;
	}
	ire->ire_ib_pkt_count++;
	ASSERT(ire->ire_type & (IRE_MULTICAST|IRE_BROADCAST));
	(*ire->ire_recvfn)(ire, mp, ipha_encap, ira);
	ire_refrele(ire);
}

/*
 * Remove all records with v_ipif == ipif.  Called when an interface goes away
 * (stream closed).  Called as writer.
 */
void
reset_mrt_vif_ipif(ipif_t *ipif)
{
	vifi_t vifi, tmp_vifi;
	vifi_t num_of_vifs;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	/* Can't check vifi >= 0 since vifi_t is unsigned! */

	mutex_enter(&ipst->ips_numvifs_mutex);
	num_of_vifs = ipst->ips_numvifs;
	mutex_exit(&ipst->ips_numvifs_mutex);

	for (vifi = num_of_vifs; vifi != 0; vifi--) {
		tmp_vifi = vifi - 1;
		if (ipst->ips_vifs[tmp_vifi].v_ipif == ipif) {
			(void) del_vif(&tmp_vifi, ipst);
		}
	}
}

/* Remove pending upcall msgs when ill goes away.  Called by ill_delete.  */
void
reset_mrt_ill(ill_t *ill)
{
	struct mfc	*rt;
	struct rtdetq	*rte;
	int		i;
	ip_stack_t	*ipst = ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;
	timeout_id_t	id;

	for (i = 0; i < MFCTBLSIZ; i++) {
		MFCB_REFHOLD(&ipst->ips_mfcs[i]);
		if ((rt = ipst->ips_mfcs[i].mfcb_mfc) != NULL) {
			if (ipst->ips_ip_mrtdebug > 1) {
				(void) mi_strlog(mrouter->conn_rq, 1,
				    SL_TRACE,
				    "reset_mrt_ill: mfctable [%d]", i);
			}
			while (rt != NULL) {
				mutex_enter(&rt->mfc_mutex);
				while ((rte = rt->mfc_rte) != NULL) {
					if (rte->ill == ill &&
					    (id = rt->mfc_timeout_id) != 0) {
						/*
						 * Its ok to drop the lock,  the
						 * struct cannot be freed since
						 * we have a ref on the hash
						 * bucket.
						 */
						mutex_exit(&rt->mfc_mutex);
						(void) untimeout(id);
						mutex_enter(&rt->mfc_mutex);
					}
					if (rte->ill == ill) {
						if (ipst->ips_ip_mrtdebug > 1) {
						(void) mi_strlog(
						    mrouter->conn_rq,
						    1, SL_TRACE,
						    "reset_mrt_ill: "
						    "ill 0x%p", (void *)ill);
						}
						rt->mfc_rte = rte->rte_next;
						freemsg(rte->mp);
						mi_free((char *)rte);
					}
				}
				mutex_exit(&rt->mfc_mutex);
				rt = rt->mfc_next;
			}
		}
		MFCB_REFRELE(&ipst->ips_mfcs[i]);
	}
}

/*
 * Token bucket filter module.
 * The ipha is for mcastgrp destination for phyint and encap.
 */
static void
tbf_control(struct vif *vifp, mblk_t *mp, ipha_t *ipha)
{
	size_t 	p_len =  msgdsize(mp);
	struct tbf	*t    = vifp->v_tbf;
	timeout_id_t id = 0;
	ill_t		*ill = vifp->v_ipif->ipif_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	/* Drop if packet is too large */
	if (p_len > MAX_BKT_SIZE) {
		ipst->ips_mrtstat->mrts_pkt2large++;
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("tbf_control - too large", mp, ill);
		freemsg(mp);
		return;
	}
	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "tbf_ctrl: SEND vif %ld, qlen %d, ipha_dst 0x%x",
		    (ptrdiff_t)(vifp - ipst->ips_vifs), t->tbf_q_len,
		    ntohl(ipha->ipha_dst));
	}

	mutex_enter(&t->tbf_lock);

	tbf_update_tokens(vifp);

	/*
	 * If there are enough tokens,
	 * and the queue is empty, send this packet out.
	 */
	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "tbf_control: vif %ld, TOKENS  %d, pkt len  %lu, qlen  %d",
		    (ptrdiff_t)(vifp - ipst->ips_vifs), t->tbf_n_tok, p_len,
		    t->tbf_q_len);
	}
	/* No packets are queued */
	if (t->tbf_q_len == 0) {
		/* queue empty, send packet if enough tokens */
		if (p_len <= t->tbf_n_tok) {
			t->tbf_n_tok -= p_len;
			mutex_exit(&t->tbf_lock);
			tbf_send_packet(vifp, mp);
			return;
		} else {
			/* Queue packet and timeout till later */
			tbf_queue(vifp, mp);
			ASSERT(vifp->v_timeout_id == 0);
			vifp->v_timeout_id = timeout(tbf_reprocess_q, vifp,
			    TBF_REPROCESS);
		}
	} else if (t->tbf_q_len < t->tbf_max_q_len) {
		/* Finite queue length, so queue pkts and process queue */
		tbf_queue(vifp, mp);
		tbf_process_q(vifp);
	} else {
		/* Check that we have UDP header with IP header */
		size_t hdr_length = IPH_HDR_LENGTH(ipha) +
		    sizeof (struct udphdr);

		if ((mp->b_wptr - mp->b_rptr) < hdr_length) {
			if (!pullupmsg(mp, hdr_length)) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsOutDiscards);
				ip_drop_output("tbf_control - pullup", mp, ill);
				freemsg(mp);
				ip1dbg(("tbf_ctl: couldn't pullup udp hdr, "
				    "vif %ld src 0x%x dst 0x%x\n",
				    (ptrdiff_t)(vifp - ipst->ips_vifs),
				    ntohl(ipha->ipha_src),
				    ntohl(ipha->ipha_dst)));
				mutex_exit(&vifp->v_tbf->tbf_lock);
				return;
			} else
				/* Have to reassign ipha after pullupmsg */
				ipha = (ipha_t *)mp->b_rptr;
		}
		/*
		 * Queue length too much,
		 * try to selectively dq, or queue and process
		 */
		if (!tbf_dq_sel(vifp, ipha)) {
			ipst->ips_mrtstat->mrts_q_overflow++;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("mrts_q_overflow", mp, ill);
			freemsg(mp);
		} else {
			tbf_queue(vifp, mp);
			tbf_process_q(vifp);
		}
	}
	if (t->tbf_q_len == 0) {
		id = vifp->v_timeout_id;
		vifp->v_timeout_id = 0;
	}
	mutex_exit(&vifp->v_tbf->tbf_lock);
	if (id != 0)
		(void) untimeout(id);
}

/*
 * Adds a packet to the tbf queue at the interface.
 * The ipha is for mcastgrp destination for phyint and encap.
 */
static void
tbf_queue(struct vif *vifp, mblk_t *mp)
{
	struct tbf	*t = vifp->v_tbf;
	ip_stack_t	*ipst = vifp->v_ipif->ipif_ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "tbf_queue: vif %ld", (ptrdiff_t)(vifp - ipst->ips_vifs));
	}
	ASSERT(MUTEX_HELD(&t->tbf_lock));

	if (t->tbf_t == NULL) {
		/* Queue was empty */
		t->tbf_q = mp;
	} else {
		/* Insert at tail */
		t->tbf_t->b_next = mp;
	}
	/* set new tail pointer */
	t->tbf_t = mp;

	mp->b_next = mp->b_prev = NULL;

	t->tbf_q_len++;
}

/*
 * Process the queue at the vif interface.
 * Drops the tbf_lock when sending packets.
 *
 * NOTE : The caller should quntimeout if the queue length is 0.
 */
static void
tbf_process_q(struct vif *vifp)
{
	mblk_t	*mp;
	struct tbf	*t = vifp->v_tbf;
	size_t	len;
	ip_stack_t	*ipst = vifp->v_ipif->ipif_ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "tbf_process_q 1: vif %ld qlen = %d",
		    (ptrdiff_t)(vifp - ipst->ips_vifs), t->tbf_q_len);
	}

	/*
	 * Loop through the queue at the interface and send
	 * as many packets as possible.
	 */
	ASSERT(MUTEX_HELD(&t->tbf_lock));

	while (t->tbf_q_len > 0) {
		mp = t->tbf_q;
		len = (size_t)msgdsize(mp); /* length of ip pkt */

		/* Determine if the packet can be sent */
		if (len <= t->tbf_n_tok) {
			/*
			 * If so, reduce no. of tokens, dequeue the packet,
			 * send the packet.
			 */
			t->tbf_n_tok -= len;

			t->tbf_q = mp->b_next;
			if (--t->tbf_q_len == 0) {
				t->tbf_t = NULL;
			}
			mp->b_next = NULL;
			/* Exit mutex before sending packet, then re-enter */
			mutex_exit(&t->tbf_lock);
			tbf_send_packet(vifp, mp);
			mutex_enter(&t->tbf_lock);
		} else
			break;
	}
}

/* Called at tbf timeout to update tokens, process q and reset timer.  */
static void
tbf_reprocess_q(void *arg)
{
	struct vif *vifp = arg;
	ip_stack_t	*ipst = vifp->v_ipif->ipif_ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	mutex_enter(&vifp->v_tbf->tbf_lock);
	vifp->v_timeout_id = 0;
	tbf_update_tokens(vifp);

	tbf_process_q(vifp);

	if (vifp->v_tbf->tbf_q_len > 0) {
		vifp->v_timeout_id = timeout(tbf_reprocess_q, vifp,
		    TBF_REPROCESS);
	}
	mutex_exit(&vifp->v_tbf->tbf_lock);

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "tbf_reprcess_q: vif %ld timeout id = %p",
		    (ptrdiff_t)(vifp - ipst->ips_vifs), vifp->v_timeout_id);
	}
}

/*
 * Function that will selectively discard a member of the tbf queue,
 * based on the precedence value and the priority.
 *
 * NOTE : The caller should quntimeout if the queue length is 0.
 */
static int
tbf_dq_sel(struct vif *vifp, ipha_t *ipha)
{
	uint_t		p;
	struct tbf		*t = vifp->v_tbf;
	mblk_t		**np;
	mblk_t		*last, *mp;
	ill_t		*ill = vifp->v_ipif->ipif_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "dq_sel: vif %ld dst 0x%x",
		    (ptrdiff_t)(vifp - ipst->ips_vifs), ntohl(ipha->ipha_dst));
	}

	ASSERT(MUTEX_HELD(&t->tbf_lock));
	p = priority(vifp, ipha);

	np = &t->tbf_q;
	last = NULL;
	while ((mp = *np) != NULL) {
		if (p > (priority(vifp, (ipha_t *)mp->b_rptr))) {
			*np = mp->b_next;
			/* If removing the last packet, fix the tail pointer */
			if (mp == t->tbf_t)
				t->tbf_t = last;
			mp->b_prev = mp->b_next = NULL;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("tbf_dq_send", mp, ill);
			freemsg(mp);
			/*
			 * It's impossible for the queue to be empty, but
			 * we check anyway.
			 */
			if (--t->tbf_q_len == 0) {
				t->tbf_t = NULL;
			}
			ipst->ips_mrtstat->mrts_drop_sel++;
			return (1);
		}
		np = &mp->b_next;
		last = mp;
	}
	return (0);
}

/* Sends packet, 2 cases - encap tunnel, phyint.  */
static void
tbf_send_packet(struct vif *vifp, mblk_t *mp)
{
	ipif_t		*ipif = vifp->v_ipif;
	ill_t		*ill = ipif->ipif_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;
	ipha_t		*ipha;

	ipha = (ipha_t *)mp->b_rptr;
	/* If encap tunnel options */
	if (vifp->v_flags & VIFF_TUNNEL)  {
		ip_xmit_attr_t	ixas;

		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "tbf_send_packet: ENCAP tunnel vif %ld",
			    (ptrdiff_t)(vifp - ipst->ips_vifs));
		}
		bzero(&ixas, sizeof (ixas));
		ixas.ixa_flags =
		    IXAF_IS_IPV4 | IXAF_NO_TTL_CHANGE | IXAF_VERIFY_SOURCE;
		ixas.ixa_ipst = ipst;
		ixas.ixa_ifindex = 0;
		ixas.ixa_cred = kcred;
		ixas.ixa_cpid = NOPID;
		ixas.ixa_tsl = NULL;
		ixas.ixa_zoneid = GLOBAL_ZONEID; /* Multicast router in GZ */
		ixas.ixa_pktlen = ntohs(ipha->ipha_length);
		ixas.ixa_ip_hdr_length = IPH_HDR_LENGTH(ipha);

		/*
		 * Feed into ip_output_simple which will set the ident field
		 * and checksum the encapsulating header.
		 * BSD gets the cached route vifp->v_route from ip_output()
		 * to speed up route table lookups. Not necessary in SunOS 5.x.
		 * One could make multicast forwarding faster by putting an
		 * ip_xmit_attr_t in each vif thereby caching the ire/nce.
		 */
		(void) ip_output_simple(mp, &ixas);
		ixa_cleanup(&ixas);
		return;

		/* phyint */
	} else {
		/* Need to loop back to members on the outgoing interface. */
		ipaddr_t	dst;
		ip_recv_attr_t	iras;
		nce_t		*nce;

		bzero(&iras, sizeof (iras));
		iras.ira_flags = IRAF_IS_IPV4;
		iras.ira_ill = iras.ira_rill = ill;
		iras.ira_ruifindex = ill->ill_phyint->phyint_ifindex;
		iras.ira_zoneid = GLOBAL_ZONEID; /* Multicast router in GZ */
		iras.ira_pktlen = ntohs(ipha->ipha_length);
		iras.ira_ip_hdr_length = IPH_HDR_LENGTH(ipha);

		dst = ipha->ipha_dst;
		if (ill_hasmembers_v4(ill, dst)) {
			iras.ira_flags |= IRAF_LOOPBACK_COPY;
		}
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "tbf_send_pkt: phyint forward  vif %ld dst = 0x%x",
			    (ptrdiff_t)(vifp - ipst->ips_vifs), ntohl(dst));
		}
		/*
		 * Find an NCE which matches the nexthop.
		 * For a pt-pt interface we use the other end of the pt-pt
		 * link.
		 */
		if (ipif->ipif_flags & IPIF_POINTOPOINT) {
			dst = ipif->ipif_pp_dst_addr;
			nce = arp_nce_init(ill, dst, ill->ill_net_type);
		} else {
			nce = arp_nce_init(ill, dst, IRE_MULTICAST);
		}
		if (nce == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("tbf_send_packet - no nce", mp, ill);
			freemsg(mp);
			return;
		}

		/*
		 * We don't remeber the incoming ill. Thus we
		 * pretend the  packet arrived on the outbound ill. This means
		 * statistics for input errors will be increased on the wrong
		 * ill but that isn't a big deal.
		 */
		ip_forward_xmit_v4(nce, ill, mp, ipha, &iras, ill->ill_mc_mtu,
		    0);
		ASSERT(!(iras.ira_flags & IRAF_IPSEC_SECURE));

		nce_refrele(nce);
	}
}

/*
 * Determine the current time and then the elapsed time (between the last time
 * and time now).  Update the no. of tokens in the bucket.
 */
static void
tbf_update_tokens(struct vif *vifp)
{
	timespec_t	tp;
	hrtime_t	tm;
	struct tbf	*t = vifp->v_tbf;
	ip_stack_t	*ipst = vifp->v_ipif->ipif_ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	ASSERT(MUTEX_HELD(&t->tbf_lock));

	/* Time in secs and nsecs, rate limit in kbits/sec */
	gethrestime(&tp);

	/*LINTED*/
	TV_DELTA(tp, t->tbf_last_pkt_t, tm);

	/*
	 * This formula is actually
	 * "time in seconds" * "bytes/second".  Scaled for nsec.
	 * (tm/1000000000) * (v_rate_limit * 1000 * (1000/1024) /8)
	 *
	 * The (1000/1024) was introduced in add_vif to optimize
	 * this divide into a shift.
	 */
	t->tbf_n_tok += (tm/1000) * vifp->v_rate_limit / 1024 / 8;
	t->tbf_last_pkt_t = tp;

	if (t->tbf_n_tok > MAX_BKT_SIZE)
		t->tbf_n_tok = MAX_BKT_SIZE;
	if (ipst->ips_ip_mrtdebug > 1) {
		(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
		    "tbf_update_tok: tm %lld tok %d vif %ld",
		    tm, t->tbf_n_tok, (ptrdiff_t)(vifp - ipst->ips_vifs));
	}
}

/*
 * Priority currently is based on port nos.
 * Different forwarding mechanisms have different ways
 * of obtaining the port no. Hence, the vif must be
 * given along with the packet itself.
 *
 */
static int
priority(struct vif *vifp, ipha_t *ipha)
{
	int prio;
	ip_stack_t	*ipst = vifp->v_ipif->ipif_ill->ill_ipst;
	conn_t		*mrouter = ipst->ips_ip_g_mrouter;

	/* Temporary hack; may add general packet classifier some day */

	ASSERT(MUTEX_HELD(&vifp->v_tbf->tbf_lock));

	/*
	 * The UDP port space is divided up into four priority ranges:
	 * [0, 16384)	: unclassified - lowest priority
	 * [16384, 32768)	: audio - highest priority
	 * [32768, 49152)	: whiteboard - medium priority
	 * [49152, 65536)	: video - low priority
	 */

	if (ipha->ipha_protocol == IPPROTO_UDP) {
		struct udphdr *udp =
		    (struct udphdr *)((char *)ipha + IPH_HDR_LENGTH(ipha));
		switch (ntohs(udp->uh_dport) & 0xc000) {
		case 0x4000:
			prio = 70;
			break;
		case 0x8000:
			prio = 60;
			break;
		case 0xc000:
			prio = 55;
			break;
		default:
			prio = 50;
			break;
		}
		if (ipst->ips_ip_mrtdebug > 1) {
			(void) mi_strlog(mrouter->conn_rq, 1, SL_TRACE,
			    "priority: port %x prio %d\n",
			    ntohs(udp->uh_dport), prio);
		}
	} else
		prio = 50;  /* default priority */
	return (prio);
}

/*
 * End of token bucket filter modifications
 */



/*
 * Produces data for netstat -M.
 */
int
ip_mroute_stats(mblk_t *mp, ip_stack_t *ipst)
{
	ipst->ips_mrtstat->mrts_vifctlSize = sizeof (struct vifctl);
	ipst->ips_mrtstat->mrts_mfcctlSize = sizeof (struct mfcctl);
	if (!snmp_append_data(mp, (char *)ipst->ips_mrtstat,
		sizeof (struct mrtstat))) {
		ip0dbg(("ip_mroute_stats: failed %ld bytes\n",
		    (size_t)sizeof (struct mrtstat)));
		return (0);
	}
	return (1);
}

/*
 * Sends info for SNMP's MIB.
 */
int
ip_mroute_vif(mblk_t *mp, ip_stack_t *ipst)
{
	struct vifctl 	vi;
	vifi_t		vifi;

	mutex_enter(&ipst->ips_numvifs_mutex);
	for (vifi = 0; vifi < ipst->ips_numvifs; vifi++) {
		if (ipst->ips_vifs[vifi].v_lcl_addr.s_addr == 0)
			continue;
		/*
		 * No locks here, an approximation is fine.
		 */
		vi.vifc_vifi = vifi;
		vi.vifc_flags = ipst->ips_vifs[vifi].v_flags;
		vi.vifc_threshold = ipst->ips_vifs[vifi].v_threshold;
		vi.vifc_rate_limit	= ipst->ips_vifs[vifi].v_rate_limit;
		vi.vifc_lcl_addr	= ipst->ips_vifs[vifi].v_lcl_addr;
		vi.vifc_rmt_addr	= ipst->ips_vifs[vifi].v_rmt_addr;
		vi.vifc_pkt_in		= ipst->ips_vifs[vifi].v_pkt_in;
		vi.vifc_pkt_out		= ipst->ips_vifs[vifi].v_pkt_out;

		if (!snmp_append_data(mp, (char *)&vi, sizeof (vi))) {
			ip0dbg(("ip_mroute_vif: failed %ld bytes\n",
			    (size_t)sizeof (vi)));
			mutex_exit(&ipst->ips_numvifs_mutex);
			return (0);
		}
	}
	mutex_exit(&ipst->ips_numvifs_mutex);
	return (1);
}

/*
 * Called by ip_snmp_get to send up multicast routing table.
 */
int
ip_mroute_mrt(mblk_t *mp, ip_stack_t *ipst)
{
	int			i, j;
	struct mfc		*rt;
	struct mfcctl	mfcc;

	/*
	 * Make sure multicast has not been turned off.
	 */
	if (is_mrouter_off(ipst))
		return (1);

	/* Loop over all hash buckets and their chains */
	for (i = 0; i < MFCTBLSIZ; i++) {
		MFCB_REFHOLD(&ipst->ips_mfcs[i]);
		for (rt = ipst->ips_mfcs[i].mfcb_mfc; rt; rt = rt->mfc_next) {
			mutex_enter(&rt->mfc_mutex);
			if (rt->mfc_rte != NULL ||
			    (rt->mfc_marks & MFCB_MARK_CONDEMNED)) {
				mutex_exit(&rt->mfc_mutex);
				continue;
			}
			mfcc.mfcc_origin = rt->mfc_origin;
			mfcc.mfcc_mcastgrp = rt->mfc_mcastgrp;
			mfcc.mfcc_parent = rt->mfc_parent;
			mfcc.mfcc_pkt_cnt = rt->mfc_pkt_cnt;
			mutex_enter(&ipst->ips_numvifs_mutex);
			for (j = 0; j < (int)ipst->ips_numvifs; j++)
				mfcc.mfcc_ttls[j] = rt->mfc_ttls[j];
			for (j = (int)ipst->ips_numvifs; j < MAXVIFS; j++)
				mfcc.mfcc_ttls[j] = 0;
			mutex_exit(&ipst->ips_numvifs_mutex);

			mutex_exit(&rt->mfc_mutex);
			if (!snmp_append_data(mp, (char *)&mfcc,
			    sizeof (mfcc))) {
				MFCB_REFRELE(&ipst->ips_mfcs[i]);
				ip0dbg(("ip_mroute_mrt: failed %ld bytes\n",
				    (size_t)sizeof (mfcc)));
				return (0);
			}
		}
		MFCB_REFRELE(&ipst->ips_mfcs[i]);
	}
	return (1);
}
