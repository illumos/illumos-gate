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
/* Copyright (c) 1990 Mentat Inc. */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/sdt.h>
#include <sys/zone.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <sys/systm.h>
#include <sys/strsubr.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <inet/arp.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_if.h>
#include <inet/ip_ndp.h>
#include <inet/ip_multi.h>
#include <inet/ipclassifier.h>
#include <inet/ipsec_impl.h>
#include <inet/sctp_ip.h>
#include <inet/ip_listutils.h>
#include <inet/udp_impl.h>

/* igmpv3/mldv2 source filter manipulation */
static void	ilm_bld_flists(conn_t *conn, void *arg);
static void	ilm_gen_filter(ilm_t *ilm, mcast_record_t *fmode,
    slist_t *flist);

static ilm_t	*ilm_add_v6(ipif_t *ipif, const in6_addr_t *group,
    ilg_stat_t ilgstat, mcast_record_t ilg_fmode, slist_t *ilg_flist,
    int orig_ifindex, zoneid_t zoneid);
static void	ilm_delete(ilm_t *ilm);
static int	ip_ll_addmulti_v6(ipif_t *ipif, const in6_addr_t *group);
static int	ip_ll_delmulti_v6(ipif_t *ipif, const in6_addr_t *group);
static ilg_t	*ilg_lookup_ill_index_v6(conn_t *connp,
    const in6_addr_t *v6group, int index);
static ilg_t	*ilg_lookup_ipif(conn_t *connp, ipaddr_t group,
    ipif_t *ipif);
static int	ilg_add(conn_t *connp, ipaddr_t group, ipif_t *ipif,
    mcast_record_t fmode, ipaddr_t src);
static int	ilg_add_v6(conn_t *connp, const in6_addr_t *group, ill_t *ill,
    mcast_record_t fmode, const in6_addr_t *v6src);
static void	ilg_delete(conn_t *connp, ilg_t *ilg, const in6_addr_t *src);
static mblk_t	*ill_create_dl(ill_t *ill, uint32_t dl_primitive,
    uint32_t length, uint32_t *addr_lenp, uint32_t *addr_offp);
static mblk_t	*ill_create_squery(ill_t *ill, ipaddr_t ipaddr,
    uint32_t addrlen, uint32_t addroff, mblk_t *mp_tail);
static void	conn_ilg_reap(conn_t *connp);
static int	ip_opt_delete_group_excl(conn_t *connp, ipaddr_t group,
    ipif_t *ipif, mcast_record_t fmode, ipaddr_t src);
static int	ip_opt_delete_group_excl_v6(conn_t *connp,
    const in6_addr_t *v6group, ill_t *ill, mcast_record_t fmode,
    const in6_addr_t *v6src);

/*
 * MT notes:
 *
 * Multicast joins operate on both the ilg and ilm structures. Multiple
 * threads operating on an conn (socket) trying to do multicast joins
 * need to synchronize  when operating on the ilg. Multiple threads
 * potentially operating on different conn (socket endpoints) trying to
 * do multicast joins could eventually end up trying to manipulate the
 * ilm simulatenously and need to synchronize on the access to the ilm.
 * Both are amenable to standard Solaris MT techniques, but it would be
 * complex to handle a failover or failback which needs to manipulate
 * ilg/ilms if an applications can also simultaenously join/leave
 * multicast groups. Hence multicast join/leave also go through the ipsq_t
 * serialization.
 *
 * Multicast joins and leaves are single-threaded per phyint/IPMP group
 * using the ipsq serialization mechanism.
 *
 * An ilm is an IP data structure used to track multicast join/leave.
 * An ilm is associated with a <multicast group, ipif> tuple in IPv4 and
 * with just <multicast group> in IPv6. ilm_refcnt is the number of ilg's
 * referencing the ilm. ilms are created / destroyed only as writer. ilms
 * are not passed around, instead they are looked up and used under the
 * ill_lock or as writer. So we don't need a dynamic refcount of the number
 * of threads holding reference to an ilm.
 *
 * Multicast Join operation:
 *
 * The first step is to determine the ipif (v4) or ill (v6) on which
 * the join operation is to be done. The join is done after becoming
 * exclusive on the ipsq associated with the ipif or ill. The conn->conn_ilg
 * and ill->ill_ilm are thus accessed and modified exclusively per ill.
 * Multiple threads can attempt to join simultaneously on different ipif/ill
 * on the same conn. In this case the ipsq serialization does not help in
 * protecting the ilg. It is the conn_lock that is used to protect the ilg.
 * The conn_lock also protects all the ilg_t members.
 *
 * Leave operation.
 *
 * Similar to the join operation, the first step is to determine the ipif
 * or ill (v6) on which the leave operation is to be done. The leave operation
 * is done after becoming exclusive on the ipsq associated with the ipif or ill.
 * As with join ilg modification is done under the protection of the conn lock.
 */

#define	IPSQ_ENTER_IPIF(ipif, connp, first_mp, func, ipsq, type)	\
	ASSERT(connp != NULL);					\
	(ipsq) = ipsq_try_enter((ipif), NULL, CONNP_TO_WQ(connp),	\
	    (first_mp), (func), (type), B_TRUE);		\
	if ((ipsq) == NULL) {					\
		ipif_refrele(ipif);				\
		return (EINPROGRESS);				\
	}

#define	IPSQ_ENTER_ILL(ill, connp, first_mp, func, ipsq, type)	\
	ASSERT(connp != NULL);					\
	(ipsq) = ipsq_try_enter(NULL, ill, CONNP_TO_WQ(connp),	\
	    (first_mp),	(func), (type), B_TRUE);		\
	if ((ipsq) == NULL) {					\
		ill_refrele(ill);				\
		return (EINPROGRESS);				\
	}

#define	IPSQ_EXIT(ipsq)	\
	if (ipsq != NULL)	\
		ipsq_exit(ipsq, B_TRUE, B_TRUE);

#define	ILG_WALKER_HOLD(connp)	(connp)->conn_ilg_walker_cnt++

#define	ILG_WALKER_RELE(connp)				\
	{						\
		(connp)->conn_ilg_walker_cnt--;		\
		if ((connp)->conn_ilg_walker_cnt == 0)	\
			conn_ilg_reap(connp);		\
	}

static void
conn_ilg_reap(conn_t *connp)
{
	int	to;
	int	from;
	ilg_t	*ilg;

	ASSERT(MUTEX_HELD(&connp->conn_lock));

	to = 0;
	from = 0;
	while (from < connp->conn_ilg_inuse) {
		if (connp->conn_ilg[from].ilg_flags & ILG_DELETED) {
			ilg = &connp->conn_ilg[from];
			FREE_SLIST(ilg->ilg_filter);
			ilg->ilg_flags &= ~ILG_DELETED;
			from++;
			continue;
		}
		if (to != from)
			connp->conn_ilg[to] = connp->conn_ilg[from];
		to++;
		from++;
	}

	connp->conn_ilg_inuse = to;

	if (connp->conn_ilg_inuse == 0) {
		mi_free((char *)connp->conn_ilg);
		connp->conn_ilg = NULL;
		cv_broadcast(&connp->conn_refcv);
	}
}

#define	GETSTRUCT(structure, number)	\
	((structure *)mi_zalloc(sizeof (structure) * (number)))

#define	ILG_ALLOC_CHUNK	16

/*
 * Returns a pointer to the next available ilg in conn_ilg.  Allocs more
 * buffers in size of ILG_ALLOC_CHUNK ilgs when needed, and updates conn's
 * ilg tracking fields appropriately (conn_ilg_inuse reflects usage of the
 * returned ilg).  Returns NULL on failure (ENOMEM).
 *
 * Assumes connp->conn_lock is held.
 */
static ilg_t *
conn_ilg_alloc(conn_t *connp)
{
	ilg_t *new, *ret;
	int curcnt;

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	ASSERT(connp->conn_ilg_inuse <= connp->conn_ilg_allocated);

	if (connp->conn_ilg == NULL) {
		connp->conn_ilg = GETSTRUCT(ilg_t, ILG_ALLOC_CHUNK);
		if (connp->conn_ilg == NULL)
			return (NULL);
		connp->conn_ilg_allocated = ILG_ALLOC_CHUNK;
		connp->conn_ilg_inuse = 0;
	}
	if (connp->conn_ilg_inuse == connp->conn_ilg_allocated) {
		if (connp->conn_ilg_walker_cnt != 0) {
			/*
			 * XXX We cannot grow the array at this point
			 * because a list walker could be in progress, and
			 * we cannot wipe out the existing array until the
			 * walker is done. Just return NULL for now.
			 * ilg_delete_all() will have to be changed when
			 * this logic is changed.
			 */
			return (NULL);
		}
		curcnt = connp->conn_ilg_allocated;
		new = GETSTRUCT(ilg_t, curcnt + ILG_ALLOC_CHUNK);
		if (new == NULL)
			return (NULL);
		bcopy(connp->conn_ilg, new, sizeof (ilg_t) * curcnt);
		mi_free((char *)connp->conn_ilg);
		connp->conn_ilg = new;
		connp->conn_ilg_allocated += ILG_ALLOC_CHUNK;
	}

	ret = &connp->conn_ilg[connp->conn_ilg_inuse++];
	ASSERT((ret->ilg_flags & ILG_DELETED) == 0);
	bzero(ret, sizeof (*ret));
	return (ret);
}

typedef struct ilm_fbld_s {
	ilm_t		*fbld_ilm;
	int		fbld_in_cnt;
	int		fbld_ex_cnt;
	slist_t		fbld_in;
	slist_t		fbld_ex;
	boolean_t	fbld_in_overflow;
} ilm_fbld_t;

static void
ilm_bld_flists(conn_t *conn, void *arg)
{
	int i;
	ilm_fbld_t *fbld = (ilm_fbld_t *)(arg);
	ilm_t *ilm = fbld->fbld_ilm;
	in6_addr_t *v6group = &ilm->ilm_v6addr;

	if (conn->conn_ilg_inuse == 0)
		return;

	/*
	 * Since we can't break out of the ipcl_walk once started, we still
	 * have to look at every conn.  But if we've already found one
	 * (EXCLUDE, NULL) list, there's no need to keep checking individual
	 * ilgs--that will be our state.
	 */
	if (fbld->fbld_ex_cnt > 0 && fbld->fbld_ex.sl_numsrc == 0)
		return;

	/*
	 * Check this conn's ilgs to see if any are interested in our
	 * ilm (group, interface match).  If so, update the master
	 * include and exclude lists we're building in the fbld struct
	 * with this ilg's filter info.
	 */
	mutex_enter(&conn->conn_lock);
	for (i = 0; i < conn->conn_ilg_inuse; i++) {
		ilg_t *ilg = &conn->conn_ilg[i];
		if ((ilg->ilg_ill == ilm->ilm_ill) &&
		    (ilg->ilg_ipif == ilm->ilm_ipif) &&
		    IN6_ARE_ADDR_EQUAL(&ilg->ilg_v6group, v6group)) {
			if (ilg->ilg_fmode == MODE_IS_INCLUDE) {
				fbld->fbld_in_cnt++;
				if (!fbld->fbld_in_overflow)
					l_union_in_a(&fbld->fbld_in,
					    ilg->ilg_filter,
					    &fbld->fbld_in_overflow);
			} else {
				fbld->fbld_ex_cnt++;
				/*
				 * On the first exclude list, don't try to do
				 * an intersection, as the master exclude list
				 * is intentionally empty.  If the master list
				 * is still empty on later iterations, that
				 * means we have at least one ilg with an empty
				 * exclude list, so that should be reflected
				 * when we take the intersection.
				 */
				if (fbld->fbld_ex_cnt == 1) {
					if (ilg->ilg_filter != NULL)
						l_copy(ilg->ilg_filter,
						    &fbld->fbld_ex);
				} else {
					l_intersection_in_a(&fbld->fbld_ex,
					    ilg->ilg_filter);
				}
			}
			/* there will only be one match, so break now. */
			break;
		}
	}
	mutex_exit(&conn->conn_lock);
}

static void
ilm_gen_filter(ilm_t *ilm, mcast_record_t *fmode, slist_t *flist)
{
	ilm_fbld_t fbld;
	ip_stack_t *ipst = ilm->ilm_ipst;

	fbld.fbld_ilm = ilm;
	fbld.fbld_in_cnt = fbld.fbld_ex_cnt = 0;
	fbld.fbld_in.sl_numsrc = fbld.fbld_ex.sl_numsrc = 0;
	fbld.fbld_in_overflow = B_FALSE;

	/* first, construct our master include and exclude lists */
	ipcl_walk(ilm_bld_flists, (caddr_t)&fbld, ipst);

	/* now use those master lists to generate the interface filter */

	/* if include list overflowed, filter is (EXCLUDE, NULL) */
	if (fbld.fbld_in_overflow) {
		*fmode = MODE_IS_EXCLUDE;
		flist->sl_numsrc = 0;
		return;
	}

	/* if nobody interested, interface filter is (INCLUDE, NULL) */
	if (fbld.fbld_in_cnt == 0 && fbld.fbld_ex_cnt == 0) {
		*fmode = MODE_IS_INCLUDE;
		flist->sl_numsrc = 0;
		return;
	}

	/*
	 * If there are no exclude lists, then the interface filter
	 * is INCLUDE, with its filter list equal to fbld_in.  A single
	 * exclude list makes the interface filter EXCLUDE, with its
	 * filter list equal to (fbld_ex - fbld_in).
	 */
	if (fbld.fbld_ex_cnt == 0) {
		*fmode = MODE_IS_INCLUDE;
		l_copy(&fbld.fbld_in, flist);
	} else {
		*fmode = MODE_IS_EXCLUDE;
		l_difference(&fbld.fbld_ex, &fbld.fbld_in, flist);
	}
}

/*
 * If the given interface has failed, choose a new one to join on so
 * that we continue to receive packets.  ilg_orig_ifindex remembers
 * what the application used to join on so that we know the ilg to
 * delete even though we change the ill here.  Callers will store the
 * ilg returned from this function in ilg_ill.  Thus when we receive
 * a packet on ilg_ill, conn_wantpacket_v6 will deliver the packets.
 *
 * This function must be called as writer so we can walk the group
 * list and examine flags without holding a lock.
 */
ill_t *
ip_choose_multi_ill(ill_t *ill, const in6_addr_t *grp)
{
	ill_t	*till;
	ill_group_t *illgrp = ill->ill_group;

	ASSERT(IAM_WRITER_ILL(ill));

	if (IN6_IS_ADDR_UNSPECIFIED(grp) || illgrp == NULL)
		return (ill);

	if ((ill->ill_phyint->phyint_flags & (PHYI_FAILED|PHYI_INACTIVE)) == 0)
		return (ill);

	till = illgrp->illgrp_ill;
	while (till != NULL &&
	    (till->ill_phyint->phyint_flags & (PHYI_FAILED|PHYI_INACTIVE))) {
		till = till->ill_group_next;
	}
	if (till != NULL)
		return (till);

	return (ill);
}

static int
ilm_update_add(ilm_t *ilm, ilg_stat_t ilgstat, slist_t *ilg_flist,
    boolean_t isv6)
{
	mcast_record_t fmode;
	slist_t *flist;
	boolean_t fdefault;
	char buf[INET6_ADDRSTRLEN];
	ill_t *ill = isv6 ? ilm->ilm_ill : ilm->ilm_ipif->ipif_ill;

	/*
	 * There are several cases where the ilm's filter state
	 * defaults to (EXCLUDE, NULL):
	 *	- we've had previous joins without associated ilgs
	 *	- this join has no associated ilg
	 *	- the ilg's filter state is (EXCLUDE, NULL)
	 */
	fdefault = (ilm->ilm_no_ilg_cnt > 0) ||
	    (ilgstat == ILGSTAT_NONE) || SLIST_IS_EMPTY(ilg_flist);

	/* attempt mallocs (if needed) before doing anything else */
	if ((flist = l_alloc()) == NULL)
		return (ENOMEM);
	if (!fdefault && ilm->ilm_filter == NULL) {
		ilm->ilm_filter = l_alloc();
		if (ilm->ilm_filter == NULL) {
			l_free(flist);
			return (ENOMEM);
		}
	}

	if (ilgstat != ILGSTAT_CHANGE)
		ilm->ilm_refcnt++;

	if (ilgstat == ILGSTAT_NONE)
		ilm->ilm_no_ilg_cnt++;

	/*
	 * Determine new filter state.  If it's not the default
	 * (EXCLUDE, NULL), we must walk the conn list to find
	 * any ilgs interested in this group, and re-build the
	 * ilm filter.
	 */
	if (fdefault) {
		fmode = MODE_IS_EXCLUDE;
		flist->sl_numsrc = 0;
	} else {
		ilm_gen_filter(ilm, &fmode, flist);
	}

	/* make sure state actually changed; nothing to do if not. */
	if ((ilm->ilm_fmode == fmode) &&
	    !lists_are_different(ilm->ilm_filter, flist)) {
		l_free(flist);
		return (0);
	}

	/* send the state change report */
	if (!IS_LOOPBACK(ill)) {
		if (isv6)
			mld_statechange(ilm, fmode, flist);
		else
			igmp_statechange(ilm, fmode, flist);
	}

	/* update the ilm state */
	ilm->ilm_fmode = fmode;
	if (flist->sl_numsrc > 0)
		l_copy(flist, ilm->ilm_filter);
	else
		CLEAR_SLIST(ilm->ilm_filter);

	ip1dbg(("ilm_update: new if filter mode %d, group %s\n", ilm->ilm_fmode,
	    inet_ntop(AF_INET6, &ilm->ilm_v6addr, buf, sizeof (buf))));

	l_free(flist);
	return (0);
}

static int
ilm_update_del(ilm_t *ilm, boolean_t isv6)
{
	mcast_record_t fmode;
	slist_t *flist;
	ill_t *ill = isv6 ? ilm->ilm_ill : ilm->ilm_ipif->ipif_ill;

	ip1dbg(("ilm_update_del: still %d left; updating state\n",
	    ilm->ilm_refcnt));

	if ((flist = l_alloc()) == NULL)
		return (ENOMEM);

	/*
	 * If present, the ilg in question has already either been
	 * updated or removed from our list; so all we need to do
	 * now is walk the list to update the ilm filter state.
	 *
	 * Skip the list walk if we have any no-ilg joins, which
	 * cause the filter state to revert to (EXCLUDE, NULL).
	 */
	if (ilm->ilm_no_ilg_cnt != 0) {
		fmode = MODE_IS_EXCLUDE;
		flist->sl_numsrc = 0;
	} else {
		ilm_gen_filter(ilm, &fmode, flist);
	}

	/* check to see if state needs to be updated */
	if ((ilm->ilm_fmode == fmode) &&
	    (!lists_are_different(ilm->ilm_filter, flist))) {
		l_free(flist);
		return (0);
	}

	if (!IS_LOOPBACK(ill)) {
		if (isv6)
			mld_statechange(ilm, fmode, flist);
		else
			igmp_statechange(ilm, fmode, flist);
	}

	ilm->ilm_fmode = fmode;
	if (flist->sl_numsrc > 0) {
		if (ilm->ilm_filter == NULL) {
			ilm->ilm_filter = l_alloc();
			if (ilm->ilm_filter == NULL) {
				char buf[INET6_ADDRSTRLEN];
				ip1dbg(("ilm_update_del: failed to alloc ilm "
				    "filter; no source filtering for %s on %s",
				    inet_ntop(AF_INET6, &ilm->ilm_v6addr,
				    buf, sizeof (buf)), ill->ill_name));
				ilm->ilm_fmode = MODE_IS_EXCLUDE;
				l_free(flist);
				return (0);
			}
		}
		l_copy(flist, ilm->ilm_filter);
	} else {
		CLEAR_SLIST(ilm->ilm_filter);
	}

	l_free(flist);
	return (0);
}

/*
 * INADDR_ANY means all multicast addresses. This is only used
 * by the multicast router.
 * INADDR_ANY is stored as IPv6 unspecified addr.
 */
int
ip_addmulti(ipaddr_t group, ipif_t *ipif, ilg_stat_t ilgstat,
    mcast_record_t ilg_fmode, slist_t *ilg_flist)
{
	ill_t	*ill = ipif->ipif_ill;
	ilm_t 	*ilm;
	in6_addr_t v6group;
	int	ret;

	ASSERT(IAM_WRITER_IPIF(ipif));

	if (!CLASSD(group) && group != INADDR_ANY)
		return (EINVAL);

	/*
	 * INADDR_ANY is represented as the IPv6 unspecifed addr.
	 */
	if (group == INADDR_ANY)
		v6group = ipv6_all_zeros;
	else
		IN6_IPADDR_TO_V4MAPPED(group, &v6group);

	mutex_enter(&ill->ill_lock);
	ilm = ilm_lookup_ipif(ipif, group);
	mutex_exit(&ill->ill_lock);
	/*
	 * Since we are writer, we know the ilm_flags itself cannot
	 * change at this point, and ilm_lookup_ipif would not have
	 * returned a DELETED ilm. However, the data path can free
	 * ilm->next via ilm_walker_cleanup() so we can safely
	 * access anything in ilm except ilm_next (for safe access to
	 * ilm_next we'd have  to take the ill_lock).
	 */
	if (ilm != NULL)
		return (ilm_update_add(ilm, ilgstat, ilg_flist, B_FALSE));

	/*
	 * ilms are associated with ipifs in IPv4. It moves with the
	 * ipif if the ipif moves to a new ill when the interface
	 * fails. Thus we really don't check whether the ipif_ill
	 * has failed like in IPv6. If it has FAILED the ipif
	 * will move (daemon will move it) and hence the ilm, if the
	 * ipif is not IPIF_NOFAILOVER. For the IPIF_NOFAILOVER ipifs,
	 * we continue to receive in the same place even if the
	 * interface fails.
	 */
	ilm = ilm_add_v6(ipif, &v6group, ilgstat, ilg_fmode, ilg_flist,
	    ill->ill_phyint->phyint_ifindex, ipif->ipif_zoneid);
	if (ilm == NULL)
		return (ENOMEM);

	if (group == INADDR_ANY) {
		/*
		 * Check how many ipif's have members in this group -
		 * if more then one we should not tell the driver to join
		 * this time
		 */
		if (ilm_numentries_v6(ill, &v6group) > 1)
			return (0);
		if (ill->ill_group == NULL)
			ret = ip_join_allmulti(ipif);
		else
			ret = ill_nominate_mcast_rcv(ill->ill_group);
		if (ret != 0)
			ilm_delete(ilm);
		return (ret);
	}

	if (!IS_LOOPBACK(ill))
		igmp_joingroup(ilm);

	if (ilm_numentries_v6(ill, &v6group) > 1)
		return (0);

	ret = ip_ll_addmulti_v6(ipif, &v6group);
	if (ret != 0)
		ilm_delete(ilm);
	return (ret);
}

/*
 * The unspecified address means all multicast addresses.
 * This is only used by the multicast router.
 *
 * ill identifies the interface to join on; it may not match the
 * interface requested by the application of a failover has taken
 * place.  orig_ifindex always identifies the interface requested
 * by the app.
 *
 * ilgstat tells us if there's an ilg associated with this join,
 * and if so, if it's a new ilg or a change to an existing one.
 * ilg_fmode and ilg_flist give us the current filter state of
 * the ilg (and will be EXCLUDE {NULL} in the case of no ilg).
 */
int
ip_addmulti_v6(const in6_addr_t *v6group, ill_t *ill, int orig_ifindex,
    zoneid_t zoneid, ilg_stat_t ilgstat, mcast_record_t ilg_fmode,
    slist_t *ilg_flist)
{
	ilm_t	*ilm;
	int	ret;

	ASSERT(IAM_WRITER_ILL(ill));

	if (!IN6_IS_ADDR_MULTICAST(v6group) &&
	    !IN6_IS_ADDR_UNSPECIFIED(v6group)) {
		return (EINVAL);
	}

	/*
	 * An ilm is uniquely identified by the tuple of (group, ill,
	 * orig_ill).  group is the multicast group address, ill is
	 * the interface on which it is currently joined, and orig_ill
	 * is the interface on which the application requested the
	 * join.  orig_ill and ill are the same unless orig_ill has
	 * failed over.
	 *
	 * Both orig_ill and ill are required, which means we may have
	 * 2 ilms on an ill for the same group, but with different
	 * orig_ills.  These must be kept separate, so that when failback
	 * occurs, the appropriate ilms are moved back to their orig_ill
	 * without disrupting memberships on the ill to which they had
	 * been moved.
	 *
	 * In order to track orig_ill, we store orig_ifindex in the
	 * ilm and ilg.
	 */
	mutex_enter(&ill->ill_lock);
	ilm = ilm_lookup_ill_index_v6(ill, v6group, orig_ifindex, zoneid);
	mutex_exit(&ill->ill_lock);
	if (ilm != NULL)
		return (ilm_update_add(ilm, ilgstat, ilg_flist, B_TRUE));

	/*
	 * We need to remember where the application really wanted
	 * to join. This will be used later if we want to failback
	 * to the original interface.
	 */
	ilm = ilm_add_v6(ill->ill_ipif, v6group, ilgstat, ilg_fmode,
	    ilg_flist, orig_ifindex, zoneid);
	if (ilm == NULL)
		return (ENOMEM);

	if (IN6_IS_ADDR_UNSPECIFIED(v6group)) {
		/*
		 * Check how many ipif's that have members in this group -
		 * if more then one we should not tell the driver to join
		 * this time
		 */
		if (ilm_numentries_v6(ill, v6group) > 1)
			return (0);
		if (ill->ill_group == NULL)
			ret = ip_join_allmulti(ill->ill_ipif);
		else
			ret = ill_nominate_mcast_rcv(ill->ill_group);

		if (ret != 0)
			ilm_delete(ilm);
		return (ret);
	}

	if (!IS_LOOPBACK(ill))
		mld_joingroup(ilm);

	/*
	 * If we have more then one we should not tell the driver
	 * to join this time.
	 */
	if (ilm_numentries_v6(ill, v6group) > 1)
		return (0);

	ret = ip_ll_addmulti_v6(ill->ill_ipif, v6group);
	if (ret != 0)
		ilm_delete(ilm);
	return (ret);
}

/*
 * Send a multicast request to the driver for enabling multicast reception
 * for v6groupp address. The caller has already checked whether it is
 * appropriate to send one or not.
 */
int
ip_ll_send_enabmulti_req(ill_t *ill, const in6_addr_t *v6groupp)
{
	mblk_t	*mp;
	uint32_t addrlen, addroff;
	char	group_buf[INET6_ADDRSTRLEN];

	ASSERT(IAM_WRITER_ILL(ill));

	/*
	 * Create a AR_ENTRY_SQUERY message with a dl_enabmulti_req tacked
	 * on.
	 */
	mp = ill_create_dl(ill, DL_ENABMULTI_REQ, sizeof (dl_enabmulti_req_t),
	    &addrlen, &addroff);
	if (!mp)
		return (ENOMEM);
	if (IN6_IS_ADDR_V4MAPPED(v6groupp)) {
		ipaddr_t v4group;

		IN6_V4MAPPED_TO_IPADDR(v6groupp, v4group);
		/*
		 * NOTE!!!
		 * The "addroff" passed in here was calculated by
		 * ill_create_dl(), and will be used by ill_create_squery()
		 * to perform some twisted coding magic. It is the offset
		 * into the dl_xxx_req of the hw addr. Here, it will be
		 * added to b_wptr - b_rptr to create a magic number that
		 * is not an offset into this squery mblk.
		 * The actual hardware address will be accessed only in the
		 * dl_xxx_req, not in the squery. More importantly,
		 * that hardware address can *only* be accessed in this
		 * mblk chain by calling mi_offset_param_c(), which uses
		 * the magic number in the squery hw offset field to go
		 * to the *next* mblk (the dl_xxx_req), subtract the
		 * (b_wptr - b_rptr), and find the actual offset into
		 * the dl_xxx_req.
		 * Any method that depends on using the
		 * offset field in the dl_disabmulti_req or squery
		 * to find either hardware address will similarly fail.
		 *
		 * Look in ar_entry_squery() in arp.c to see how this offset
		 * is used.
		 */
		mp = ill_create_squery(ill, v4group, addrlen, addroff, mp);
		if (!mp)
			return (ENOMEM);
		ip1dbg(("ip_ll_send_enabmulti_req: IPv4 putnext %s on %s\n",
		    inet_ntop(AF_INET6, v6groupp, group_buf,
		    sizeof (group_buf)),
		    ill->ill_name));
		putnext(ill->ill_rq, mp);
	} else {
		ip1dbg(("ip_ll_send_enabmulti_req: IPv6 ndp_mcastreq %s on"
		    " %s\n",
		    inet_ntop(AF_INET6, v6groupp, group_buf,
		    sizeof (group_buf)),
		    ill->ill_name));
		return (ndp_mcastreq(ill, v6groupp, addrlen, addroff, mp));
	}
	return (0);
}

/*
 * Send a multicast request to the driver for enabling multicast
 * membership for v6group if appropriate.
 */
static int
ip_ll_addmulti_v6(ipif_t *ipif, const in6_addr_t *v6groupp)
{
	ill_t	*ill = ipif->ipif_ill;

	ASSERT(IAM_WRITER_IPIF(ipif));

	if (ill->ill_net_type != IRE_IF_RESOLVER ||
	    ipif->ipif_flags & IPIF_POINTOPOINT) {
		ip1dbg(("ip_ll_addmulti_v6: not resolver\n"));
		return (0);	/* Must be IRE_IF_NORESOLVER */
	}

	if (ill->ill_phyint->phyint_flags & PHYI_MULTI_BCAST) {
		ip1dbg(("ip_ll_addmulti_v6: MULTI_BCAST\n"));
		return (0);
	}
	if (!ill->ill_dl_up) {
		/*
		 * Nobody there. All multicast addresses will be re-joined
		 * when we get the DL_BIND_ACK bringing the interface up.
		 */
		ip1dbg(("ip_ll_addmulti_v6: nobody up\n"));
		return (0);
	}
	return (ip_ll_send_enabmulti_req(ill, v6groupp));
}

/*
 * INADDR_ANY means all multicast addresses. This is only used
 * by the multicast router.
 * INADDR_ANY is stored as the IPv6 unspecifed addr.
 */
int
ip_delmulti(ipaddr_t group, ipif_t *ipif, boolean_t no_ilg, boolean_t leaving)
{
	ill_t	*ill = ipif->ipif_ill;
	ilm_t *ilm;
	in6_addr_t v6group;
	int	ret;

	ASSERT(IAM_WRITER_IPIF(ipif));

	if (!CLASSD(group) && group != INADDR_ANY)
		return (EINVAL);

	/*
	 * INADDR_ANY is represented as the IPv6 unspecifed addr.
	 */
	if (group == INADDR_ANY)
		v6group = ipv6_all_zeros;
	else
		IN6_IPADDR_TO_V4MAPPED(group, &v6group);

	/*
	 * Look for a match on the ipif.
	 * (IP_DROP_MEMBERSHIP specifies an ipif using an IP address).
	 */
	mutex_enter(&ill->ill_lock);
	ilm = ilm_lookup_ipif(ipif, group);
	mutex_exit(&ill->ill_lock);
	if (ilm == NULL)
		return (ENOENT);

	/* Update counters */
	if (no_ilg)
		ilm->ilm_no_ilg_cnt--;

	if (leaving)
		ilm->ilm_refcnt--;

	if (ilm->ilm_refcnt > 0)
		return (ilm_update_del(ilm, B_FALSE));

	if (group == INADDR_ANY) {
		ilm_delete(ilm);
		/*
		 * Check how many ipif's that have members in this group -
		 * if there are still some left then don't tell the driver
		 * to drop it.
		 */
		if (ilm_numentries_v6(ill, &v6group) != 0)
			return (0);

		/*
		 * If we never joined, then don't leave.  This can happen
		 * if we're in an IPMP group, since only one ill per IPMP
		 * group receives all multicast packets.
		 */
		if (!ill->ill_join_allmulti) {
			ASSERT(ill->ill_group != NULL);
			return (0);
		}

		ret = ip_leave_allmulti(ipif);
		if (ill->ill_group != NULL)
			(void) ill_nominate_mcast_rcv(ill->ill_group);
		return (ret);
	}

	if (!IS_LOOPBACK(ill))
		igmp_leavegroup(ilm);

	ilm_delete(ilm);
	/*
	 * Check how many ipif's that have members in this group -
	 * if there are still some left then don't tell the driver
	 * to drop it.
	 */
	if (ilm_numentries_v6(ill, &v6group) != 0)
		return (0);
	return (ip_ll_delmulti_v6(ipif, &v6group));
}

/*
 * The unspecified address means all multicast addresses.
 * This is only used by the multicast router.
 */
int
ip_delmulti_v6(const in6_addr_t *v6group, ill_t *ill, int orig_ifindex,
    zoneid_t zoneid, boolean_t no_ilg, boolean_t leaving)
{
	ipif_t	*ipif;
	ilm_t *ilm;
	int	ret;

	ASSERT(IAM_WRITER_ILL(ill));

	if (!IN6_IS_ADDR_MULTICAST(v6group) &&
	    !IN6_IS_ADDR_UNSPECIFIED(v6group))
		return (EINVAL);

	/*
	 * Look for a match on the ill.
	 * (IPV6_LEAVE_GROUP specifies an ill using an ifindex).
	 *
	 * Similar to ip_addmulti_v6, we should always look using
	 * the orig_ifindex.
	 *
	 * 1) If orig_ifindex is different from ill's ifindex
	 *    we should have an ilm with orig_ifindex created in
	 *    ip_addmulti_v6. We should delete that here.
	 *
	 * 2) If orig_ifindex is same as ill's ifindex, we should
	 *    not delete the ilm that is temporarily here because of
	 *    a FAILOVER. Those ilms will have a ilm_orig_ifindex
	 *    different from ill's ifindex.
	 *
	 * Thus, always lookup using orig_ifindex.
	 */
	mutex_enter(&ill->ill_lock);
	ilm = ilm_lookup_ill_index_v6(ill, v6group, orig_ifindex, zoneid);
	mutex_exit(&ill->ill_lock);
	if (ilm == NULL)
		return (ENOENT);

	ASSERT(ilm->ilm_ill == ill);

	ipif = ill->ill_ipif;

	/* Update counters */
	if (no_ilg)
		ilm->ilm_no_ilg_cnt--;

	if (leaving)
		ilm->ilm_refcnt--;

	if (ilm->ilm_refcnt > 0)
		return (ilm_update_del(ilm, B_TRUE));

	if (IN6_IS_ADDR_UNSPECIFIED(v6group)) {
		ilm_delete(ilm);
		/*
		 * Check how many ipif's that have members in this group -
		 * if there are still some left then don't tell the driver
		 * to drop it.
		 */
		if (ilm_numentries_v6(ill, v6group) != 0)
			return (0);

		/*
		 * If we never joined, then don't leave.  This can happen
		 * if we're in an IPMP group, since only one ill per IPMP
		 * group receives all multicast packets.
		 */
		if (!ill->ill_join_allmulti) {
			ASSERT(ill->ill_group != NULL);
			return (0);
		}

		ret = ip_leave_allmulti(ipif);
		if (ill->ill_group != NULL)
			(void) ill_nominate_mcast_rcv(ill->ill_group);
		return (ret);
	}

	if (!IS_LOOPBACK(ill))
		mld_leavegroup(ilm);

	ilm_delete(ilm);
	/*
	 * Check how many ipif's that have members in this group -
	 * if there are still some left then don't tell the driver
	 * to drop it.
	 */
	if (ilm_numentries_v6(ill, v6group) != 0)
		return (0);
	return (ip_ll_delmulti_v6(ipif, v6group));
}

/*
 * Send a multicast request to the driver for disabling multicast reception
 * for v6groupp address. The caller has already checked whether it is
 * appropriate to send one or not.
 */
int
ip_ll_send_disabmulti_req(ill_t *ill, const in6_addr_t *v6groupp)
{
	mblk_t	*mp;
	char	group_buf[INET6_ADDRSTRLEN];
	uint32_t	addrlen, addroff;

	ASSERT(IAM_WRITER_ILL(ill));
	/*
	 * Create a AR_ENTRY_SQUERY message with a dl_disabmulti_req tacked
	 * on.
	 */
	mp = ill_create_dl(ill, DL_DISABMULTI_REQ,
	    sizeof (dl_disabmulti_req_t), &addrlen, &addroff);

	if (!mp)
		return (ENOMEM);

	if (IN6_IS_ADDR_V4MAPPED(v6groupp)) {
		ipaddr_t v4group;

		IN6_V4MAPPED_TO_IPADDR(v6groupp, v4group);
		/*
		 * NOTE!!!
		 * The "addroff" passed in here was calculated by
		 * ill_create_dl(), and will be used by ill_create_squery()
		 * to perform some twisted coding magic. It is the offset
		 * into the dl_xxx_req of the hw addr. Here, it will be
		 * added to b_wptr - b_rptr to create a magic number that
		 * is not an offset into this mblk.
		 *
		 * Please see the comment in ip_ll_send)enabmulti_req()
		 * for a complete explanation.
		 *
		 * Look in ar_entry_squery() in arp.c to see how this offset
		 * is used.
		 */
		mp = ill_create_squery(ill, v4group, addrlen, addroff, mp);
		if (!mp)
			return (ENOMEM);
		ip1dbg(("ip_ll_send_disabmulti_req: IPv4 putnext %s on %s\n",
		    inet_ntop(AF_INET6, v6groupp, group_buf,
		    sizeof (group_buf)),
		    ill->ill_name));
		putnext(ill->ill_rq, mp);
	} else {
		ip1dbg(("ip_ll_send_disabmulti_req: IPv6 ndp_mcastreq %s on"
		    " %s\n",
		    inet_ntop(AF_INET6, v6groupp, group_buf,
		    sizeof (group_buf)),
		    ill->ill_name));
		return (ndp_mcastreq(ill, v6groupp, addrlen, addroff, mp));
	}
	return (0);
}

/*
 * Send a multicast request to the driver for disabling multicast
 * membership for v6group if appropriate.
 */
static int
ip_ll_delmulti_v6(ipif_t *ipif, const in6_addr_t *v6group)
{
	ill_t	*ill = ipif->ipif_ill;

	ASSERT(IAM_WRITER_IPIF(ipif));

	if (ill->ill_net_type != IRE_IF_RESOLVER ||
	    ipif->ipif_flags & IPIF_POINTOPOINT) {
		return (0);	/* Must be IRE_IF_NORESOLVER */
	}
	if (ill->ill_phyint->phyint_flags & PHYI_MULTI_BCAST) {
		ip1dbg(("ip_ll_delmulti_v6: MULTI_BCAST\n"));
		return (0);
	}
	if (!ill->ill_dl_up) {
		/*
		 * Nobody there. All multicast addresses will be re-joined
		 * when we get the DL_BIND_ACK bringing the interface up.
		 */
		ip1dbg(("ip_ll_delmulti_v6: nobody up\n"));
		return (0);
	}
	return (ip_ll_send_disabmulti_req(ill, v6group));
}

/*
 * Make the driver pass up all multicast packets
 *
 * With ill groups, the caller makes sure that there is only
 * one ill joining the allmulti group.
 */
int
ip_join_allmulti(ipif_t *ipif)
{
	ill_t	*ill = ipif->ipif_ill;
	mblk_t	*mp;
	uint32_t	addrlen, addroff;

	ASSERT(IAM_WRITER_IPIF(ipif));

	if (!ill->ill_dl_up) {
		/*
		 * Nobody there. All multicast addresses will be re-joined
		 * when we get the DL_BIND_ACK bringing the interface up.
		 */
		return (0);
	}

	ASSERT(!ill->ill_join_allmulti);

	/*
	 * Create a DL_PROMISCON_REQ message and send it directly to
	 * the DLPI provider.  We don't need to do this for certain
	 * media types for which we never need to turn promiscuous
	 * mode on.
	 */
	if ((ill->ill_net_type == IRE_IF_RESOLVER) &&
	    !(ill->ill_phyint->phyint_flags & PHYI_MULTI_BCAST)) {
		mp = ill_create_dl(ill, DL_PROMISCON_REQ,
		    sizeof (dl_promiscon_req_t), &addrlen, &addroff);
		if (mp == NULL)
			return (ENOMEM);
		ill_dlpi_send(ill, mp);
	}

	ill->ill_join_allmulti = B_TRUE;
	return (0);
}

/*
 * Make the driver stop passing up all multicast packets
 *
 * With ill groups, we need to nominate some other ill as
 * this ipif->ipif_ill is leaving the group.
 */
int
ip_leave_allmulti(ipif_t *ipif)
{
	ill_t	*ill = ipif->ipif_ill;
	mblk_t	*mp;
	uint32_t	addrlen, addroff;

	ASSERT(IAM_WRITER_IPIF(ipif));

	if (!ill->ill_dl_up) {
		/*
		 * Nobody there. All multicast addresses will be re-joined
		 * when we get the DL_BIND_ACK bringing the interface up.
		 */
		return (0);
	}

	ASSERT(ill->ill_join_allmulti);

	/*
	 * Create a DL_PROMISCOFF_REQ message and send it directly to
	 * the DLPI provider.  We don't need to do this for certain
	 * media types for which we never need to turn promiscuous
	 * mode on.
	 */
	if ((ill->ill_net_type == IRE_IF_RESOLVER) &&
	    !(ill->ill_phyint->phyint_flags & PHYI_MULTI_BCAST)) {
		mp = ill_create_dl(ill, DL_PROMISCOFF_REQ,
		    sizeof (dl_promiscoff_req_t), &addrlen, &addroff);
		if (mp == NULL)
			return (ENOMEM);
		ill_dlpi_send(ill, mp);
	}

	ill->ill_join_allmulti = B_FALSE;
	return (0);
}

/*
 * Copy mp_orig and pass it in as a local message.
 */
void
ip_multicast_loopback(queue_t *q, ill_t *ill, mblk_t *mp_orig, int fanout_flags,
    zoneid_t zoneid)
{
	mblk_t	*mp;
	mblk_t	*ipsec_mp;
	ipha_t	*iph;
	ip_stack_t *ipst = ill->ill_ipst;

	if (DB_TYPE(mp_orig) == M_DATA &&
	    ((ipha_t *)mp_orig->b_rptr)->ipha_protocol == IPPROTO_UDP) {
		uint_t hdrsz;

		hdrsz = IPH_HDR_LENGTH((ipha_t *)mp_orig->b_rptr) +
		    sizeof (udpha_t);
		ASSERT(MBLKL(mp_orig) >= hdrsz);

		if (((mp = allocb(hdrsz, BPRI_MED)) != NULL) &&
		    (mp_orig = dupmsg(mp_orig)) != NULL) {
			bcopy(mp_orig->b_rptr, mp->b_rptr, hdrsz);
			mp->b_wptr += hdrsz;
			mp->b_cont = mp_orig;
			mp_orig->b_rptr += hdrsz;
			if (is_system_labeled() && DB_CRED(mp_orig) != NULL)
				mblk_setcred(mp, DB_CRED(mp_orig));
			if (MBLKL(mp_orig) == 0) {
				mp->b_cont = mp_orig->b_cont;
				mp_orig->b_cont = NULL;
				freeb(mp_orig);
			}
		} else if (mp != NULL) {
			freeb(mp);
			mp = NULL;
		}
	} else {
		mp = ip_copymsg(mp_orig); /* No refcnt on ipsec_out netstack */
	}

	if (mp == NULL)
		return;
	if (DB_TYPE(mp) == M_CTL) {
		ipsec_mp = mp;
		mp = mp->b_cont;
	} else {
		ipsec_mp = mp;
	}

	iph = (ipha_t *)mp->b_rptr;

	DTRACE_PROBE4(ip4__loopback__out__start,
	    ill_t *, NULL, ill_t *, ill,
	    ipha_t *, iph, mblk_t *, ipsec_mp);

	FW_HOOKS(ipst->ips_ip4_loopback_out_event,
	    ipst->ips_ipv4firewall_loopback_out,
	    NULL, ill, iph, ipsec_mp, mp, HPE_MULTICAST, ipst);

	DTRACE_PROBE1(ip4__loopback__out__end, mblk_t *, ipsec_mp);

	if (ipsec_mp != NULL)
		ip_wput_local(q, ill, iph, ipsec_mp, NULL,
		    fanout_flags, zoneid);
}

static area_t	ip_aresq_template = {
	AR_ENTRY_SQUERY,		/* cmd */
	sizeof (area_t)+IP_ADDR_LEN,	/* name offset */
	sizeof (area_t),	/* name len (filled by ill_arp_alloc) */
	IP_ARP_PROTO_TYPE,		/* protocol, from arps perspective */
	sizeof (area_t),			/* proto addr offset */
	IP_ADDR_LEN,			/* proto addr_length */
	0,				/* proto mask offset */
	/* Rest is initialized when used */
	0,				/* flags */
	0,				/* hw addr offset */
	0,				/* hw addr length */
};

static mblk_t *
ill_create_squery(ill_t *ill, ipaddr_t ipaddr, uint32_t addrlen,
    uint32_t addroff, mblk_t *mp_tail)
{
	mblk_t	*mp;
	area_t	*area;

	mp = ill_arp_alloc(ill, (uchar_t *)&ip_aresq_template,
	    (caddr_t)&ipaddr);
	if (!mp) {
		freemsg(mp_tail);
		return (NULL);
	}
	area = (area_t *)mp->b_rptr;
	area->area_hw_addr_length = addrlen;
	area->area_hw_addr_offset = mp->b_wptr - mp->b_rptr + addroff;
	/*
	 * NOTE!
	 *
	 * The area_hw_addr_offset, as can be seen, does not hold the
	 * actual hardware address offset. Rather, it holds the offset
	 * to the hw addr in the dl_xxx_req in mp_tail, modified by
	 * adding (mp->b_wptr - mp->b_rptr). This allows the function
	 * mi_offset_paramc() to find the hardware address in the
	 * *second* mblk (dl_xxx_req), not this mblk.
	 *
	 * Using mi_offset_paramc() is thus the *only* way to access
	 * the dl_xxx_hw address.
	 *
	 * The squery hw address should *not* be accessed.
	 *
	 * See ar_entry_squery() in arp.c for an example of how all this works.
	 */

	mp->b_cont = mp_tail;
	return (mp);
}

/*
 * Create a dlpi message with room for phys+sap. When we come back in
 * ip_wput_ctl() we will strip the sap for those primitives which
 * only need a physical address.
 */
static mblk_t *
ill_create_dl(ill_t *ill, uint32_t dl_primitive, uint32_t length,
    uint32_t *addr_lenp, uint32_t *addr_offp)
{
	mblk_t	*mp;
	uint32_t	hw_addr_length;
	char		*cp;
	uint32_t	offset;
	uint32_t 	size;

	*addr_lenp = *addr_offp = 0;

	hw_addr_length = ill->ill_phys_addr_length;
	if (!hw_addr_length) {
		ip0dbg(("ip_create_dl: hw addr length = 0\n"));
		return (NULL);
	}

	size = length;
	switch (dl_primitive) {
	case DL_ENABMULTI_REQ:
	case DL_DISABMULTI_REQ:
		size += hw_addr_length;
		break;
	case DL_PROMISCON_REQ:
	case DL_PROMISCOFF_REQ:
		break;
	default:
		return (NULL);
	}
	mp = allocb(size, BPRI_HI);
	if (!mp)
		return (NULL);
	mp->b_wptr += size;
	mp->b_datap->db_type = M_PROTO;

	cp = (char *)mp->b_rptr;
	offset = length;

	switch (dl_primitive) {
	case DL_ENABMULTI_REQ: {
		dl_enabmulti_req_t *dl = (dl_enabmulti_req_t *)cp;

		dl->dl_primitive = dl_primitive;
		dl->dl_addr_offset = offset;
		*addr_lenp = dl->dl_addr_length = hw_addr_length;
		*addr_offp = offset;
		break;
	}
	case DL_DISABMULTI_REQ: {
		dl_disabmulti_req_t *dl = (dl_disabmulti_req_t *)cp;

		dl->dl_primitive = dl_primitive;
		dl->dl_addr_offset = offset;
		*addr_lenp = dl->dl_addr_length = hw_addr_length;
		*addr_offp = offset;
		break;
	}
	case DL_PROMISCON_REQ:
	case DL_PROMISCOFF_REQ: {
		dl_promiscon_req_t *dl = (dl_promiscon_req_t *)cp;

		dl->dl_primitive = dl_primitive;
		dl->dl_level = DL_PROMISC_MULTI;
		break;
	}
	}
	ip1dbg(("ill_create_dl: addr_len %d, addr_off %d\n",
	    *addr_lenp, *addr_offp));
	return (mp);
}

void
ip_wput_ctl(queue_t *q, mblk_t *mp_orig)
{
	ill_t	*ill = (ill_t *)q->q_ptr;
	mblk_t	*mp = mp_orig;
	area_t	*area = (area_t *)mp->b_rptr;

	/* Check that we have a AR_ENTRY_SQUERY with a tacked on mblk */
	if (MBLKL(mp) < sizeof (area_t) || mp->b_cont == NULL ||
	    area->area_cmd != AR_ENTRY_SQUERY) {
		putnext(q, mp);
		return;
	}
	mp = mp->b_cont;

	/*
	 * Update dl_addr_length and dl_addr_offset for primitives that
	 * have physical addresses as opposed to full saps
	 */
	switch (((union DL_primitives *)mp->b_rptr)->dl_primitive) {
	case DL_ENABMULTI_REQ:
		/* Track the state if this is the first enabmulti */
		if (ill->ill_dlpi_multicast_state == IDS_UNKNOWN)
			ill->ill_dlpi_multicast_state = IDS_INPROGRESS;
		ip1dbg(("ip_wput_ctl: ENABMULTI\n"));
		break;
	case DL_DISABMULTI_REQ:
		ip1dbg(("ip_wput_ctl: DISABMULTI\n"));
		break;
	default:
		ip1dbg(("ip_wput_ctl: default\n"));
		break;
	}
	freeb(mp_orig);
	ill_dlpi_send(ill, mp);
}

/*
 * Rejoin any groups which have been explicitly joined by the application (we
 * left all explicitly joined groups as part of ill_leave_multicast() prior to
 * bringing the interface down).  Note that because groups can be joined and
 * left while an interface is down, this may not be the same set of groups
 * that we left in ill_leave_multicast().
 */
void
ill_recover_multicast(ill_t *ill)
{
	ilm_t	*ilm;
	char    addrbuf[INET6_ADDRSTRLEN];

	ASSERT(IAM_WRITER_ILL(ill));
	ILM_WALKER_HOLD(ill);
	for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
		/*
		 * Check how many ipif's that have members in this group -
		 * if more then one we make sure that this entry is first
		 * in the list.
		 */
		if (ilm_numentries_v6(ill, &ilm->ilm_v6addr) > 1 &&
		    ilm_lookup_ill_v6(ill, &ilm->ilm_v6addr, ALL_ZONES) != ilm)
			continue;
		ip1dbg(("ill_recover_multicast: %s\n",
		    inet_ntop(AF_INET6, &ilm->ilm_v6addr, addrbuf,
		    sizeof (addrbuf))));
		if (IN6_IS_ADDR_UNSPECIFIED(&ilm->ilm_v6addr)) {
			if (ill->ill_group == NULL) {
				(void) ip_join_allmulti(ill->ill_ipif);
			} else {
				/*
				 * We don't want to join on this ill,
				 * if somebody else in the group has
				 * already been nominated.
				 */
				(void) ill_nominate_mcast_rcv(ill->ill_group);
			}
		} else {
			(void) ip_ll_addmulti_v6(ill->ill_ipif,
			    &ilm->ilm_v6addr);
		}
	}
	ILM_WALKER_RELE(ill);
}

/*
 * The opposite of ill_recover_multicast() -- leaves all multicast groups
 * that were explicitly joined.  Note that both these functions could be
 * disposed of if we enhanced ARP to allow us to handle DL_DISABMULTI_REQ
 * and DL_ENABMULTI_REQ messages when an interface is down.
 */
void
ill_leave_multicast(ill_t *ill)
{
	ilm_t	*ilm;
	char    addrbuf[INET6_ADDRSTRLEN];

	ASSERT(IAM_WRITER_ILL(ill));
	ILM_WALKER_HOLD(ill);
	for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
		/*
		 * Check how many ipif's that have members in this group -
		 * if more then one we make sure that this entry is first
		 * in the list.
		 */
		if (ilm_numentries_v6(ill, &ilm->ilm_v6addr) > 1 &&
		    ilm_lookup_ill_v6(ill, &ilm->ilm_v6addr, ALL_ZONES) != ilm)
			continue;
		ip1dbg(("ill_leave_multicast: %s\n",
		    inet_ntop(AF_INET6, &ilm->ilm_v6addr, addrbuf,
		    sizeof (addrbuf))));
		if (IN6_IS_ADDR_UNSPECIFIED(&ilm->ilm_v6addr)) {
			(void) ip_leave_allmulti(ill->ill_ipif);
			/*
			 * If we were part of an IPMP group, then
			 * ill_handoff_responsibility() has already
			 * nominated a new member (so we don't).
			 */
			ASSERT(ill->ill_group == NULL);
		} else {
			(void) ip_ll_delmulti_v6(ill->ill_ipif,
			    &ilm->ilm_v6addr);
		}
	}
	ILM_WALKER_RELE(ill);
}

/* Find an ilm for matching the ill */
ilm_t *
ilm_lookup_ill(ill_t *ill, ipaddr_t group, zoneid_t zoneid)
{
	in6_addr_t	v6group;

	ASSERT(ill->ill_ilm_walker_cnt != 0 || MUTEX_HELD(&ill->ill_lock));
	/*
	 * INADDR_ANY is represented as the IPv6 unspecifed addr.
	 */
	if (group == INADDR_ANY)
		v6group = ipv6_all_zeros;
	else
		IN6_IPADDR_TO_V4MAPPED(group, &v6group);

	return (ilm_lookup_ill_v6(ill, &v6group, zoneid));
}

/*
 * Find an ilm for matching the ill. All the ilm lookup functions
 * ignore ILM_DELETED ilms. These have been logically deleted, and
 * igmp and linklayer disable multicast have been done. Only mi_free
 * yet to be done. Still there in the list due to ilm_walkers. The
 * last walker will release it.
 */
ilm_t *
ilm_lookup_ill_v6(ill_t *ill, const in6_addr_t *v6group, zoneid_t zoneid)
{
	ilm_t	*ilm;

	ASSERT(ill->ill_ilm_walker_cnt != 0 || MUTEX_HELD(&ill->ill_lock));

	for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
		if (ilm->ilm_flags & ILM_DELETED)
			continue;
		if (IN6_ARE_ADDR_EQUAL(&ilm->ilm_v6addr, v6group) &&
		    (zoneid == ALL_ZONES || zoneid == ilm->ilm_zoneid))
			return (ilm);
	}
	return (NULL);
}

ilm_t *
ilm_lookup_ill_index_v6(ill_t *ill, const in6_addr_t *v6group, int index,
    zoneid_t zoneid)
{
	ilm_t *ilm;

	ASSERT(ill->ill_ilm_walker_cnt != 0 || MUTEX_HELD(&ill->ill_lock));

	for (ilm = ill->ill_ilm; ilm != NULL; ilm = ilm->ilm_next) {
		if (ilm->ilm_flags & ILM_DELETED)
			continue;
		if (IN6_ARE_ADDR_EQUAL(&ilm->ilm_v6addr, v6group) &&
		    (zoneid == ALL_ZONES || zoneid == ilm->ilm_zoneid) &&
		    ilm->ilm_orig_ifindex == index) {
			return (ilm);
		}
	}
	return (NULL);
}


/*
 * Found an ilm for the ipif. Only needed for IPv4 which does
 * ipif specific socket options.
 */
ilm_t *
ilm_lookup_ipif(ipif_t *ipif, ipaddr_t group)
{
	ill_t	*ill = ipif->ipif_ill;
	ilm_t	*ilm;
	in6_addr_t	v6group;

	ASSERT(ill->ill_ilm_walker_cnt != 0 || MUTEX_HELD(&ill->ill_lock));
	/*
	 * INADDR_ANY is represented as the IPv6 unspecifed addr.
	 */
	if (group == INADDR_ANY)
		v6group = ipv6_all_zeros;
	else
		IN6_IPADDR_TO_V4MAPPED(group, &v6group);

	for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
		if (ilm->ilm_flags & ILM_DELETED)
			continue;
		if (ilm->ilm_ipif == ipif &&
		    IN6_ARE_ADDR_EQUAL(&ilm->ilm_v6addr, &v6group))
			return (ilm);
	}
	return (NULL);
}

/*
 * How many members on this ill?
 */
int
ilm_numentries_v6(ill_t *ill, const in6_addr_t *v6group)
{
	ilm_t	*ilm;
	int i = 0;

	mutex_enter(&ill->ill_lock);
	for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
		if (ilm->ilm_flags & ILM_DELETED)
			continue;
		if (IN6_ARE_ADDR_EQUAL(&ilm->ilm_v6addr, v6group)) {
			i++;
		}
	}
	mutex_exit(&ill->ill_lock);
	return (i);
}

/* Caller guarantees that the group is not already on the list */
static ilm_t *
ilm_add_v6(ipif_t *ipif, const in6_addr_t *v6group, ilg_stat_t ilgstat,
    mcast_record_t ilg_fmode, slist_t *ilg_flist, int orig_ifindex,
    zoneid_t zoneid)
{
	ill_t	*ill = ipif->ipif_ill;
	ilm_t	*ilm;
	ilm_t	*ilm_cur;
	ilm_t	**ilm_ptpn;

	ASSERT(IAM_WRITER_IPIF(ipif));

	ilm = GETSTRUCT(ilm_t, 1);
	if (ilm == NULL)
		return (NULL);
	if (ilgstat != ILGSTAT_NONE && !SLIST_IS_EMPTY(ilg_flist)) {
		ilm->ilm_filter = l_alloc();
		if (ilm->ilm_filter == NULL) {
			mi_free(ilm);
			return (NULL);
		}
	}
	ilm->ilm_v6addr = *v6group;
	ilm->ilm_refcnt = 1;
	ilm->ilm_zoneid = zoneid;
	ilm->ilm_timer = INFINITY;
	ilm->ilm_rtx.rtx_timer = INFINITY;

	/*
	 * IPv4 Multicast groups are joined using ipif.
	 * IPv6 Multicast groups are joined using ill.
	 */
	if (ill->ill_isv6) {
		ilm->ilm_ill = ill;
		ilm->ilm_ipif = NULL;
		DTRACE_PROBE3(ill__incr__cnt, (ill_t *), ill,
		    (char *), "ilm", (void *), ilm);
		ill->ill_ilm_cnt++;
	} else {
		ASSERT(ilm->ilm_zoneid == ipif->ipif_zoneid);
		ilm->ilm_ipif = ipif;
		ilm->ilm_ill = NULL;
		DTRACE_PROBE3(ipif__incr__cnt, (ipif_t *), ipif,
		    (char *), "ilm", (void *), ilm);
		ipif->ipif_ilm_cnt++;
	}
	ASSERT(ill->ill_ipst);
	ilm->ilm_ipst = ill->ill_ipst;	/* No netstack_hold */

	/*
	 * After this if ilm moves to a new ill, we don't change
	 * the ilm_orig_ifindex. Thus, if ill_index != ilm_orig_ifindex,
	 * it has been moved. Indexes don't match even when the application
	 * wants to join on a FAILED/INACTIVE interface because we choose
	 * a new interface to join in. This is considered as an implicit
	 * move.
	 */
	ilm->ilm_orig_ifindex = orig_ifindex;

	ASSERT(!(ipif->ipif_state_flags & IPIF_CONDEMNED));
	ASSERT(!(ill->ill_state_flags & ILL_CONDEMNED));

	/*
	 * Grab lock to give consistent view to readers
	 */
	mutex_enter(&ill->ill_lock);
	/*
	 * All ilms in the same zone are contiguous in the ill_ilm list.
	 * The loops in ip_proto_input() and ip_wput_local() use this to avoid
	 * sending duplicates up when two applications in the same zone join the
	 * same group on different logical interfaces.
	 */
	ilm_cur = ill->ill_ilm;
	ilm_ptpn = &ill->ill_ilm;
	while (ilm_cur != NULL && ilm_cur->ilm_zoneid != ilm->ilm_zoneid) {
		ilm_ptpn = &ilm_cur->ilm_next;
		ilm_cur = ilm_cur->ilm_next;
	}
	ilm->ilm_next = ilm_cur;
	*ilm_ptpn = ilm;

	/*
	 * If we have an associated ilg, use its filter state; if not,
	 * default to (EXCLUDE, NULL) and set no_ilg_cnt to track this.
	 */
	if (ilgstat != ILGSTAT_NONE) {
		if (!SLIST_IS_EMPTY(ilg_flist))
			l_copy(ilg_flist, ilm->ilm_filter);
		ilm->ilm_fmode = ilg_fmode;
	} else {
		ilm->ilm_no_ilg_cnt = 1;
		ilm->ilm_fmode = MODE_IS_EXCLUDE;
	}

	mutex_exit(&ill->ill_lock);
	return (ilm);
}

void
ilm_inactive(ilm_t *ilm)
{
	FREE_SLIST(ilm->ilm_filter);
	FREE_SLIST(ilm->ilm_pendsrcs);
	FREE_SLIST(ilm->ilm_rtx.rtx_allow);
	FREE_SLIST(ilm->ilm_rtx.rtx_block);
	ilm->ilm_ipst = NULL;
	mi_free((char *)ilm);
}

void
ilm_walker_cleanup(ill_t *ill)
{
	ilm_t	**ilmp;
	ilm_t	*ilm;
	boolean_t need_wakeup = B_FALSE;

	ASSERT(MUTEX_HELD(&ill->ill_lock));
	ASSERT(ill->ill_ilm_walker_cnt == 0);

	ilmp = &ill->ill_ilm;
	while (*ilmp != NULL) {
		if ((*ilmp)->ilm_flags & ILM_DELETED) {
			ilm = *ilmp;
			*ilmp = ilm->ilm_next;
			/*
			 * check if there are any pending FREE or unplumb
			 * operations that need to be restarted.
			 */
			if (ilm->ilm_ipif != NULL) {
				/*
				 * IPv4 ilms hold a ref on the ipif.
				 */
				DTRACE_PROBE3(ipif__decr__cnt,
				    (ipif_t *), ilm->ilm_ipif,
				    (char *), "ilm", (void *), ilm);
				ilm->ilm_ipif->ipif_ilm_cnt--;
				if (IPIF_FREE_OK(ilm->ilm_ipif))
					need_wakeup = B_TRUE;
			} else {
				/*
				 * IPv6 ilms hold a ref on the ill.
				 */
				ASSERT(ilm->ilm_ill == ill);
				DTRACE_PROBE3(ill__decr__cnt,
				    (ill_t *), ill,
				    (char *), "ilm", (void *), ilm);
				ASSERT(ill->ill_ilm_cnt > 0);
				ill->ill_ilm_cnt--;
				if (ILL_FREE_OK(ill))
					need_wakeup = B_TRUE;
			}
			ilm_inactive(ilm); /* frees ilm */
		} else {
			ilmp = &(*ilmp)->ilm_next;
		}
	}
	ill->ill_ilm_cleanup_reqd = 0;
	if (need_wakeup)
		ipif_ill_refrele_tail(ill);
	else
		mutex_exit(&ill->ill_lock);
}

/*
 * Unlink ilm and free it.
 */
static void
ilm_delete(ilm_t *ilm)
{
	ill_t		*ill;
	ilm_t		**ilmp;
	boolean_t	need_wakeup;


	if (ilm->ilm_ipif != NULL) {
		ASSERT(IAM_WRITER_IPIF(ilm->ilm_ipif));
		ASSERT(ilm->ilm_ill == NULL);
		ill = ilm->ilm_ipif->ipif_ill;
		ASSERT(!ill->ill_isv6);
	} else {
		ASSERT(IAM_WRITER_ILL(ilm->ilm_ill));
		ASSERT(ilm->ilm_ipif == NULL);
		ill = ilm->ilm_ill;
		ASSERT(ill->ill_isv6);
	}
	/*
	 * Delete under lock protection so that readers don't stumble
	 * on bad ilm_next
	 */
	mutex_enter(&ill->ill_lock);
	if (ill->ill_ilm_walker_cnt != 0) {
		ilm->ilm_flags |= ILM_DELETED;
		ill->ill_ilm_cleanup_reqd = 1;
		mutex_exit(&ill->ill_lock);
		return;
	}

	for (ilmp = &ill->ill_ilm; *ilmp != ilm; ilmp = &(*ilmp)->ilm_next)
				;
	*ilmp = ilm->ilm_next;

	/*
	 * if we are the last reference to the ipif (for IPv4 ilms)
	 * or the ill (for IPv6 ilms), we may need to wakeup any
	 * pending FREE or unplumb operations.
	 */
	need_wakeup = B_FALSE;
	if (ilm->ilm_ipif != NULL) {
		DTRACE_PROBE3(ipif__decr__cnt, (ipif_t *), ilm->ilm_ipif,
		    (char *), "ilm", (void *), ilm);
		ilm->ilm_ipif->ipif_ilm_cnt--;
		if (IPIF_FREE_OK(ilm->ilm_ipif))
			need_wakeup = B_TRUE;
	} else {
		DTRACE_PROBE3(ill__decr__cnt, (ill_t *), ill,
		    (char *), "ilm", (void *), ilm);
		ASSERT(ill->ill_ilm_cnt > 0);
		ill->ill_ilm_cnt--;
		if (ILL_FREE_OK(ill))
			need_wakeup = B_TRUE;
	}

	ilm_inactive(ilm); /* frees this ilm */

	if (need_wakeup) {
		/* drops ill lock */
		ipif_ill_refrele_tail(ill);
	} else {
		mutex_exit(&ill->ill_lock);
	}
}


/*
 * Looks up the appropriate ipif given a v4 multicast group and interface
 * address.  On success, returns 0, with *ipifpp pointing to the found
 * struct.  On failure, returns an errno and *ipifpp is NULL.
 */
int
ip_opt_check(conn_t *connp, ipaddr_t group, ipaddr_t src, ipaddr_t ifaddr,
    uint_t *ifindexp, mblk_t *first_mp, ipsq_func_t func, ipif_t **ipifpp)
{
	ipif_t *ipif;
	int err = 0;
	zoneid_t zoneid;
	ip_stack_t	*ipst =  connp->conn_netstack->netstack_ip;

	if (!CLASSD(group) || CLASSD(src)) {
		return (EINVAL);
	}
	*ipifpp = NULL;

	zoneid = IPCL_ZONEID(connp);

	ASSERT(!(ifaddr != INADDR_ANY && ifindexp != NULL && *ifindexp != 0));
	if (ifaddr != INADDR_ANY) {
		ipif = ipif_lookup_addr(ifaddr, NULL, zoneid,
		    CONNP_TO_WQ(connp), first_mp, func, &err, ipst);
		if (err != 0 && err != EINPROGRESS)
			err = EADDRNOTAVAIL;
	} else if (ifindexp != NULL && *ifindexp != 0) {
		ipif = ipif_lookup_on_ifindex(*ifindexp, B_FALSE, zoneid,
		    CONNP_TO_WQ(connp), first_mp, func, &err, ipst);
	} else {
		ipif = ipif_lookup_group(group, zoneid, ipst);
		if (ipif == NULL)
			return (EADDRNOTAVAIL);
	}
	if (ipif == NULL)
		return (err);

	*ipifpp = ipif;
	return (0);
}

/*
 * Looks up the appropriate ill (or ipif if v4mapped) given an interface
 * index and IPv6 multicast group.  On success, returns 0, with *illpp (or
 * *ipifpp if v4mapped) pointing to the found struct.  On failure, returns
 * an errno and *illpp and *ipifpp are undefined.
 */
int
ip_opt_check_v6(conn_t *connp, const in6_addr_t *v6group, ipaddr_t *v4group,
    const in6_addr_t *v6src, ipaddr_t *v4src, boolean_t *isv6, int ifindex,
    mblk_t *first_mp, ipsq_func_t func, ill_t **illpp, ipif_t **ipifpp)
{
	boolean_t src_unspec;
	ill_t *ill = NULL;
	ipif_t *ipif = NULL;
	int err;
	zoneid_t zoneid = connp->conn_zoneid;
	queue_t *wq = CONNP_TO_WQ(connp);
	ip_stack_t *ipst = connp->conn_netstack->netstack_ip;

	src_unspec = IN6_IS_ADDR_UNSPECIFIED(v6src);

	if (IN6_IS_ADDR_V4MAPPED(v6group)) {
		if (!IN6_IS_ADDR_V4MAPPED(v6src) && !src_unspec)
			return (EINVAL);
		IN6_V4MAPPED_TO_IPADDR(v6group, *v4group);
		if (src_unspec) {
			*v4src = INADDR_ANY;
		} else {
			IN6_V4MAPPED_TO_IPADDR(v6src, *v4src);
		}
		if (!CLASSD(*v4group) || CLASSD(*v4src))
			return (EINVAL);
		*ipifpp = NULL;
		*isv6 = B_FALSE;
	} else {
		if (IN6_IS_ADDR_V4MAPPED(v6src) && !src_unspec)
			return (EINVAL);
		if (!IN6_IS_ADDR_MULTICAST(v6group) ||
		    IN6_IS_ADDR_MULTICAST(v6src)) {
			return (EINVAL);
		}
		*illpp = NULL;
		*isv6 = B_TRUE;
	}

	if (ifindex == 0) {
		if (*isv6)
			ill = ill_lookup_group_v6(v6group, zoneid, ipst);
		else
			ipif = ipif_lookup_group(*v4group, zoneid, ipst);
		if (ill == NULL && ipif == NULL)
			return (EADDRNOTAVAIL);
	} else {
		if (*isv6) {
			ill = ill_lookup_on_ifindex(ifindex, B_TRUE,
			    wq, first_mp, func, &err, ipst);
			if (ill != NULL &&
			    !ipif_lookup_zoneid(ill, zoneid, 0, NULL)) {
				ill_refrele(ill);
				ill = NULL;
				err = EADDRNOTAVAIL;
			}
		} else {
			ipif = ipif_lookup_on_ifindex(ifindex, B_FALSE,
			    zoneid, wq, first_mp, func, &err, ipst);
		}
		if (ill == NULL && ipif == NULL)
			return (err);
	}

	*ipifpp = ipif;
	*illpp = ill;
	return (0);
}

static int
ip_get_srcfilter(conn_t *connp, struct group_filter *gf,
    struct ip_msfilter *imsf, ipaddr_t grp, ipif_t *ipif, boolean_t isv4mapped)
{
	ilg_t *ilg;
	int i, numsrc, fmode, outsrcs;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct in_addr *addrp;
	slist_t *fp;
	boolean_t is_v4only_api;

	mutex_enter(&connp->conn_lock);

	ilg = ilg_lookup_ipif(connp, grp, ipif);
	if (ilg == NULL) {
		mutex_exit(&connp->conn_lock);
		return (EADDRNOTAVAIL);
	}

	if (gf == NULL) {
		ASSERT(imsf != NULL);
		ASSERT(!isv4mapped);
		is_v4only_api = B_TRUE;
		outsrcs = imsf->imsf_numsrc;
	} else {
		ASSERT(imsf == NULL);
		is_v4only_api = B_FALSE;
		outsrcs = gf->gf_numsrc;
	}

	/*
	 * In the kernel, we use the state definitions MODE_IS_[IN|EX]CLUDE
	 * to identify the filter mode; but the API uses MCAST_[IN|EX]CLUDE.
	 * So we need to translate here.
	 */
	fmode = (ilg->ilg_fmode == MODE_IS_INCLUDE) ?
	    MCAST_INCLUDE : MCAST_EXCLUDE;
	if ((fp = ilg->ilg_filter) == NULL) {
		numsrc = 0;
	} else {
		for (i = 0; i < outsrcs; i++) {
			if (i == fp->sl_numsrc)
				break;
			if (isv4mapped) {
				sin6 = (struct sockaddr_in6 *)&gf->gf_slist[i];
				sin6->sin6_family = AF_INET6;
				sin6->sin6_addr = fp->sl_addr[i];
			} else {
				if (is_v4only_api) {
					addrp = &imsf->imsf_slist[i];
				} else {
					sin = (struct sockaddr_in *)
					    &gf->gf_slist[i];
					sin->sin_family = AF_INET;
					addrp = &sin->sin_addr;
				}
				IN6_V4MAPPED_TO_INADDR(&fp->sl_addr[i], addrp);
			}
		}
		numsrc = fp->sl_numsrc;
	}

	if (is_v4only_api) {
		imsf->imsf_numsrc = numsrc;
		imsf->imsf_fmode = fmode;
	} else {
		gf->gf_numsrc = numsrc;
		gf->gf_fmode = fmode;
	}

	mutex_exit(&connp->conn_lock);

	return (0);
}

static int
ip_get_srcfilter_v6(conn_t *connp, struct group_filter *gf,
    const struct in6_addr *grp, ill_t *ill)
{
	ilg_t *ilg;
	int i;
	struct sockaddr_storage *sl;
	struct sockaddr_in6 *sin6;
	slist_t *fp;

	mutex_enter(&connp->conn_lock);

	ilg = ilg_lookup_ill_v6(connp, grp, ill);
	if (ilg == NULL) {
		mutex_exit(&connp->conn_lock);
		return (EADDRNOTAVAIL);
	}

	/*
	 * In the kernel, we use the state definitions MODE_IS_[IN|EX]CLUDE
	 * to identify the filter mode; but the API uses MCAST_[IN|EX]CLUDE.
	 * So we need to translate here.
	 */
	gf->gf_fmode = (ilg->ilg_fmode == MODE_IS_INCLUDE) ?
	    MCAST_INCLUDE : MCAST_EXCLUDE;
	if ((fp = ilg->ilg_filter) == NULL) {
		gf->gf_numsrc = 0;
	} else {
		for (i = 0, sl = gf->gf_slist; i < gf->gf_numsrc; i++, sl++) {
			if (i == fp->sl_numsrc)
				break;
			sin6 = (struct sockaddr_in6 *)sl;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = fp->sl_addr[i];
		}
		gf->gf_numsrc = fp->sl_numsrc;
	}

	mutex_exit(&connp->conn_lock);

	return (0);
}

static int
ip_set_srcfilter(conn_t *connp, struct group_filter *gf,
    struct ip_msfilter *imsf, ipaddr_t grp, ipif_t *ipif, boolean_t isv4mapped)
{
	ilg_t *ilg;
	int i, err, infmode, new_fmode;
	uint_t insrcs;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct in_addr *addrp;
	slist_t *orig_filter = NULL;
	slist_t *new_filter = NULL;
	mcast_record_t orig_fmode;
	boolean_t leave_grp, is_v4only_api;
	ilg_stat_t ilgstat;

	if (gf == NULL) {
		ASSERT(imsf != NULL);
		ASSERT(!isv4mapped);
		is_v4only_api = B_TRUE;
		insrcs = imsf->imsf_numsrc;
		infmode = imsf->imsf_fmode;
	} else {
		ASSERT(imsf == NULL);
		is_v4only_api = B_FALSE;
		insrcs = gf->gf_numsrc;
		infmode = gf->gf_fmode;
	}

	/* Make sure we can handle the source list */
	if (insrcs > MAX_FILTER_SIZE)
		return (ENOBUFS);

	/*
	 * setting the filter to (INCLUDE, NULL) is treated
	 * as a request to leave the group.
	 */
	leave_grp = (infmode == MCAST_INCLUDE && insrcs == 0);

	ASSERT(IAM_WRITER_IPIF(ipif));

	mutex_enter(&connp->conn_lock);

	ilg = ilg_lookup_ipif(connp, grp, ipif);
	if (ilg == NULL) {
		/*
		 * if the request was actually to leave, and we
		 * didn't find an ilg, there's nothing to do.
		 */
		if (!leave_grp)
			ilg = conn_ilg_alloc(connp);
		if (leave_grp || ilg == NULL) {
			mutex_exit(&connp->conn_lock);
			return (leave_grp ? 0 : ENOMEM);
		}
		ilgstat = ILGSTAT_NEW;
		IN6_IPADDR_TO_V4MAPPED(grp, &ilg->ilg_v6group);
		ilg->ilg_ipif = ipif;
		ilg->ilg_ill = NULL;
		ilg->ilg_orig_ifindex = 0;
	} else if (leave_grp) {
		ilg_delete(connp, ilg, NULL);
		mutex_exit(&connp->conn_lock);
		(void) ip_delmulti(grp, ipif, B_FALSE, B_TRUE);
		return (0);
	} else {
		ilgstat = ILGSTAT_CHANGE;
		/* Preserve existing state in case ip_addmulti() fails */
		orig_fmode = ilg->ilg_fmode;
		if (ilg->ilg_filter == NULL) {
			orig_filter = NULL;
		} else {
			orig_filter = l_alloc_copy(ilg->ilg_filter);
			if (orig_filter == NULL) {
				mutex_exit(&connp->conn_lock);
				return (ENOMEM);
			}
		}
	}

	/*
	 * Alloc buffer to copy new state into (see below) before
	 * we make any changes, so we can bail if it fails.
	 */
	if ((new_filter = l_alloc()) == NULL) {
		mutex_exit(&connp->conn_lock);
		err = ENOMEM;
		goto free_and_exit;
	}

	if (insrcs == 0) {
		CLEAR_SLIST(ilg->ilg_filter);
	} else {
		slist_t *fp;
		if (ilg->ilg_filter == NULL) {
			fp = l_alloc();
			if (fp == NULL) {
				if (ilgstat == ILGSTAT_NEW)
					ilg_delete(connp, ilg, NULL);
				mutex_exit(&connp->conn_lock);
				err = ENOMEM;
				goto free_and_exit;
			}
		} else {
			fp = ilg->ilg_filter;
		}
		for (i = 0; i < insrcs; i++) {
			if (isv4mapped) {
				sin6 = (struct sockaddr_in6 *)&gf->gf_slist[i];
				fp->sl_addr[i] = sin6->sin6_addr;
			} else {
				if (is_v4only_api) {
					addrp = &imsf->imsf_slist[i];
				} else {
					sin = (struct sockaddr_in *)
					    &gf->gf_slist[i];
					addrp = &sin->sin_addr;
				}
				IN6_INADDR_TO_V4MAPPED(addrp, &fp->sl_addr[i]);
			}
		}
		fp->sl_numsrc = insrcs;
		ilg->ilg_filter = fp;
	}
	/*
	 * In the kernel, we use the state definitions MODE_IS_[IN|EX]CLUDE
	 * to identify the filter mode; but the API uses MCAST_[IN|EX]CLUDE.
	 * So we need to translate here.
	 */
	ilg->ilg_fmode = (infmode == MCAST_INCLUDE) ?
	    MODE_IS_INCLUDE : MODE_IS_EXCLUDE;

	/*
	 * Save copy of ilg's filter state to pass to other functions,
	 * so we can release conn_lock now.
	 */
	new_fmode = ilg->ilg_fmode;
	l_copy(ilg->ilg_filter, new_filter);

	mutex_exit(&connp->conn_lock);

	err = ip_addmulti(grp, ipif, ilgstat, new_fmode, new_filter);
	if (err != 0) {
		/*
		 * Restore the original filter state, or delete the
		 * newly-created ilg.  We need to look up the ilg
		 * again, though, since we've not been holding the
		 * conn_lock.
		 */
		mutex_enter(&connp->conn_lock);
		ilg = ilg_lookup_ipif(connp, grp, ipif);
		ASSERT(ilg != NULL);
		if (ilgstat == ILGSTAT_NEW) {
			ilg_delete(connp, ilg, NULL);
		} else {
			ilg->ilg_fmode = orig_fmode;
			if (SLIST_IS_EMPTY(orig_filter)) {
				CLEAR_SLIST(ilg->ilg_filter);
			} else {
				/*
				 * We didn't free the filter, even if we
				 * were trying to make the source list empty;
				 * so if orig_filter isn't empty, the ilg
				 * must still have a filter alloc'd.
				 */
				l_copy(orig_filter, ilg->ilg_filter);
			}
		}
		mutex_exit(&connp->conn_lock);
	}

free_and_exit:
	l_free(orig_filter);
	l_free(new_filter);

	return (err);
}

static int
ip_set_srcfilter_v6(conn_t *connp, struct group_filter *gf,
    const struct in6_addr *grp, ill_t *ill)
{
	ilg_t *ilg;
	int i, orig_ifindex, orig_fmode, new_fmode, err;
	slist_t *orig_filter = NULL;
	slist_t *new_filter = NULL;
	struct sockaddr_storage *sl;
	struct sockaddr_in6 *sin6;
	boolean_t leave_grp;
	ilg_stat_t ilgstat;

	/* Make sure we can handle the source list */
	if (gf->gf_numsrc > MAX_FILTER_SIZE)
		return (ENOBUFS);

	/*
	 * setting the filter to (INCLUDE, NULL) is treated
	 * as a request to leave the group.
	 */
	leave_grp = (gf->gf_fmode == MCAST_INCLUDE && gf->gf_numsrc == 0);

	ASSERT(IAM_WRITER_ILL(ill));

	/*
	 * Use the ifindex to do the lookup.  We can't use the ill
	 * directly because ilg_ill could point to a different ill
	 * if things have moved.
	 */
	orig_ifindex = ill->ill_phyint->phyint_ifindex;

	mutex_enter(&connp->conn_lock);
	ilg = ilg_lookup_ill_index_v6(connp, grp, orig_ifindex);
	if (ilg == NULL) {
		/*
		 * if the request was actually to leave, and we
		 * didn't find an ilg, there's nothing to do.
		 */
		if (!leave_grp)
			ilg = conn_ilg_alloc(connp);
		if (leave_grp || ilg == NULL) {
			mutex_exit(&connp->conn_lock);
			return (leave_grp ? 0 : ENOMEM);
		}
		ilgstat = ILGSTAT_NEW;
		ilg->ilg_v6group = *grp;
		ilg->ilg_ipif = NULL;
		/*
		 * Choose our target ill to join on. This might be
		 * different from the ill we've been given if it's
		 * currently down and part of a group.
		 *
		 * new ill is not refheld; we are writer.
		 */
		ill = ip_choose_multi_ill(ill, grp);
		ASSERT(!(ill->ill_state_flags & ILL_CONDEMNED));
		ilg->ilg_ill = ill;
		/*
		 * Remember the index that we joined on, so that we can
		 * successfully delete them later on and also search for
		 * duplicates if the application wants to join again.
		 */
		ilg->ilg_orig_ifindex = orig_ifindex;
	} else if (leave_grp) {
		/*
		 * Use the ilg's current ill for the deletion,
		 * we might have failed over.
		 */
		ill = ilg->ilg_ill;
		ilg_delete(connp, ilg, NULL);
		mutex_exit(&connp->conn_lock);
		(void) ip_delmulti_v6(grp, ill, orig_ifindex,
		    connp->conn_zoneid, B_FALSE, B_TRUE);
		return (0);
	} else {
		ilgstat = ILGSTAT_CHANGE;
		/*
		 * The current ill might be different from the one we were
		 * asked to join on (if failover has occurred); we should
		 * join on the ill stored in the ilg.  The original ill
		 * is noted in ilg_orig_ifindex, which matched our request.
		 */
		ill = ilg->ilg_ill;
		/* preserve existing state in case ip_addmulti() fails */
		orig_fmode = ilg->ilg_fmode;
		if (ilg->ilg_filter == NULL) {
			orig_filter = NULL;
		} else {
			orig_filter = l_alloc_copy(ilg->ilg_filter);
			if (orig_filter == NULL) {
				mutex_exit(&connp->conn_lock);
				return (ENOMEM);
			}
		}
	}

	/*
	 * Alloc buffer to copy new state into (see below) before
	 * we make any changes, so we can bail if it fails.
	 */
	if ((new_filter = l_alloc()) == NULL) {
		mutex_exit(&connp->conn_lock);
		err = ENOMEM;
		goto free_and_exit;
	}

	if (gf->gf_numsrc == 0) {
		CLEAR_SLIST(ilg->ilg_filter);
	} else {
		slist_t *fp;
		if (ilg->ilg_filter == NULL) {
			fp = l_alloc();
			if (fp == NULL) {
				if (ilgstat == ILGSTAT_NEW)
					ilg_delete(connp, ilg, NULL);
				mutex_exit(&connp->conn_lock);
				err = ENOMEM;
				goto free_and_exit;
			}
		} else {
			fp = ilg->ilg_filter;
		}
		for (i = 0, sl = gf->gf_slist; i < gf->gf_numsrc; i++, sl++) {
			sin6 = (struct sockaddr_in6 *)sl;
			fp->sl_addr[i] = sin6->sin6_addr;
		}
		fp->sl_numsrc = gf->gf_numsrc;
		ilg->ilg_filter = fp;
	}
	/*
	 * In the kernel, we use the state definitions MODE_IS_[IN|EX]CLUDE
	 * to identify the filter mode; but the API uses MCAST_[IN|EX]CLUDE.
	 * So we need to translate here.
	 */
	ilg->ilg_fmode = (gf->gf_fmode == MCAST_INCLUDE) ?
	    MODE_IS_INCLUDE : MODE_IS_EXCLUDE;

	/*
	 * Save copy of ilg's filter state to pass to other functions,
	 * so we can release conn_lock now.
	 */
	new_fmode = ilg->ilg_fmode;
	l_copy(ilg->ilg_filter, new_filter);

	mutex_exit(&connp->conn_lock);

	err = ip_addmulti_v6(grp, ill, orig_ifindex, connp->conn_zoneid,
	    ilgstat, new_fmode, new_filter);
	if (err != 0) {
		/*
		 * Restore the original filter state, or delete the
		 * newly-created ilg.  We need to look up the ilg
		 * again, though, since we've not been holding the
		 * conn_lock.
		 */
		mutex_enter(&connp->conn_lock);
		ilg = ilg_lookup_ill_index_v6(connp, grp, orig_ifindex);
		ASSERT(ilg != NULL);
		if (ilgstat == ILGSTAT_NEW) {
			ilg_delete(connp, ilg, NULL);
		} else {
			ilg->ilg_fmode = orig_fmode;
			if (SLIST_IS_EMPTY(orig_filter)) {
				CLEAR_SLIST(ilg->ilg_filter);
			} else {
				/*
				 * We didn't free the filter, even if we
				 * were trying to make the source list empty;
				 * so if orig_filter isn't empty, the ilg
				 * must still have a filter alloc'd.
				 */
				l_copy(orig_filter, ilg->ilg_filter);
			}
		}
		mutex_exit(&connp->conn_lock);
	}

free_and_exit:
	l_free(orig_filter);
	l_free(new_filter);

	return (err);
}

/*
 * Process the SIOC[GS]MSFILTER and SIOC[GS]IPMSFILTER ioctls.
 */
/* ARGSUSED */
int
ip_sioctl_msfilter(ipif_t *ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	/* existence verified in ip_wput_nondata() */
	mblk_t *data_mp = mp->b_cont->b_cont;
	int datalen, err, cmd, minsize;
	uint_t expsize = 0;
	conn_t *connp;
	boolean_t isv6, is_v4only_api, getcmd;
	struct sockaddr_in *gsin;
	struct sockaddr_in6 *gsin6;
	ipaddr_t v4grp;
	in6_addr_t v6grp;
	struct group_filter *gf = NULL;
	struct ip_msfilter *imsf = NULL;
	mblk_t *ndp;

	if (data_mp->b_cont != NULL) {
		if ((ndp = msgpullup(data_mp, -1)) == NULL)
			return (ENOMEM);
		freemsg(data_mp);
		data_mp = ndp;
		mp->b_cont->b_cont = data_mp;
	}

	cmd = iocp->ioc_cmd;
	getcmd = (cmd == SIOCGIPMSFILTER || cmd == SIOCGMSFILTER);
	is_v4only_api = (cmd == SIOCGIPMSFILTER || cmd == SIOCSIPMSFILTER);
	minsize = (is_v4only_api) ? IP_MSFILTER_SIZE(0) : GROUP_FILTER_SIZE(0);
	datalen = MBLKL(data_mp);

	if (datalen < minsize)
		return (EINVAL);

	/*
	 * now we know we have at least have the initial structure,
	 * but need to check for the source list array.
	 */
	if (is_v4only_api) {
		imsf = (struct ip_msfilter *)data_mp->b_rptr;
		isv6 = B_FALSE;
		expsize = IP_MSFILTER_SIZE(imsf->imsf_numsrc);
	} else {
		gf = (struct group_filter *)data_mp->b_rptr;
		if (gf->gf_group.ss_family == AF_INET6) {
			gsin6 = (struct sockaddr_in6 *)&gf->gf_group;
			isv6 = !(IN6_IS_ADDR_V4MAPPED(&gsin6->sin6_addr));
		} else {
			isv6 = B_FALSE;
		}
		expsize = GROUP_FILTER_SIZE(gf->gf_numsrc);
	}
	if (datalen < expsize)
		return (EINVAL);

	connp = Q_TO_CONN(q);

	/* operation not supported on the virtual network interface */
	if (IS_VNI(ipif->ipif_ill))
		return (EINVAL);

	if (isv6) {
		ill_t *ill = ipif->ipif_ill;
		ill_refhold(ill);

		gsin6 = (struct sockaddr_in6 *)&gf->gf_group;
		v6grp = gsin6->sin6_addr;
		if (getcmd)
			err = ip_get_srcfilter_v6(connp, gf, &v6grp, ill);
		else
			err = ip_set_srcfilter_v6(connp, gf, &v6grp, ill);

		ill_refrele(ill);
	} else {
		boolean_t isv4mapped = B_FALSE;
		if (is_v4only_api) {
			v4grp = (ipaddr_t)imsf->imsf_multiaddr.s_addr;
		} else {
			if (gf->gf_group.ss_family == AF_INET) {
				gsin = (struct sockaddr_in *)&gf->gf_group;
				v4grp = (ipaddr_t)gsin->sin_addr.s_addr;
			} else {
				gsin6 = (struct sockaddr_in6 *)&gf->gf_group;
				IN6_V4MAPPED_TO_IPADDR(&gsin6->sin6_addr,
				    v4grp);
				isv4mapped = B_TRUE;
			}
		}
		if (getcmd)
			err = ip_get_srcfilter(connp, gf, imsf, v4grp, ipif,
			    isv4mapped);
		else
			err = ip_set_srcfilter(connp, gf, imsf, v4grp, ipif,
			    isv4mapped);
	}

	return (err);
}

/*
 * Finds the ipif based on information in the ioctl headers.  Needed to make
 * ip_process_ioctl() happy (it needs to know the ipif for IPI_WR-flagged
 * ioctls prior to calling the ioctl's handler function).
 */
int
ip_extract_msfilter(queue_t *q, mblk_t *mp, const ip_ioctl_cmd_t *ipip,
    cmd_info_t *ci, ipsq_func_t func)
{
	int cmd = ipip->ipi_cmd;
	int err = 0;
	conn_t *connp;
	ipif_t *ipif;
	/* caller has verified this mblk exists */
	char *dbuf = (char *)mp->b_cont->b_cont->b_rptr;
	struct ip_msfilter *imsf;
	struct group_filter *gf;
	ipaddr_t v4addr, v4grp;
	in6_addr_t v6grp;
	uint32_t index;
	zoneid_t zoneid;
	ip_stack_t *ipst;

	connp = Q_TO_CONN(q);
	zoneid = connp->conn_zoneid;
	ipst = connp->conn_netstack->netstack_ip;

	/* don't allow multicast operations on a tcp conn */
	if (IPCL_IS_TCP(connp))
		return (ENOPROTOOPT);

	if (cmd == SIOCSIPMSFILTER || cmd == SIOCGIPMSFILTER) {
		/* don't allow v4-specific ioctls on v6 socket */
		if (connp->conn_af_isv6)
			return (EAFNOSUPPORT);

		imsf = (struct ip_msfilter *)dbuf;
		v4addr = imsf->imsf_interface.s_addr;
		v4grp = imsf->imsf_multiaddr.s_addr;
		if (v4addr == INADDR_ANY) {
			ipif = ipif_lookup_group(v4grp, zoneid, ipst);
			if (ipif == NULL)
				err = EADDRNOTAVAIL;
		} else {
			ipif = ipif_lookup_addr(v4addr, NULL, zoneid, q, mp,
			    func, &err, ipst);
		}
	} else {
		boolean_t isv6 = B_FALSE;
		gf = (struct group_filter *)dbuf;
		index = gf->gf_interface;
		if (gf->gf_group.ss_family == AF_INET6) {
			struct sockaddr_in6 *sin6;
			sin6 = (struct sockaddr_in6 *)&gf->gf_group;
			v6grp = sin6->sin6_addr;
			if (IN6_IS_ADDR_V4MAPPED(&v6grp))
				IN6_V4MAPPED_TO_IPADDR(&v6grp, v4grp);
			else
				isv6 = B_TRUE;
		} else if (gf->gf_group.ss_family == AF_INET) {
			struct sockaddr_in *sin;
			sin = (struct sockaddr_in *)&gf->gf_group;
			v4grp = sin->sin_addr.s_addr;
		} else {
			return (EAFNOSUPPORT);
		}
		if (index == 0) {
			if (isv6) {
				ipif = ipif_lookup_group_v6(&v6grp, zoneid,
				    ipst);
			} else {
				ipif = ipif_lookup_group(v4grp, zoneid, ipst);
			}
			if (ipif == NULL)
				err = EADDRNOTAVAIL;
		} else {
			ipif = ipif_lookup_on_ifindex(index, isv6, zoneid,
			    q, mp, func, &err, ipst);
		}
	}

	ci->ci_ipif = ipif;
	return (err);
}

/*
 * The structures used for the SIOC*MSFILTER ioctls usually must be copied
 * in in two stages, as the first copyin tells us the size of the attached
 * source buffer.  This function is called by ip_wput_nondata() after the
 * first copyin has completed; it figures out how big the second stage
 * needs to be, and kicks it off.
 *
 * In some cases (numsrc < 2), the second copyin is not needed as the
 * first one gets a complete structure containing 1 source addr.
 *
 * The function returns 0 if a second copyin has been started (i.e. there's
 * no more work to be done right now), or 1 if the second copyin is not
 * needed and ip_wput_nondata() can continue its processing.
 */
int
ip_copyin_msfilter(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	int cmd = iocp->ioc_cmd;
	/* validity of this checked in ip_wput_nondata() */
	mblk_t *mp1 = mp->b_cont->b_cont;
	int copysize = 0;
	int offset;

	if (cmd == SIOCSMSFILTER || cmd == SIOCGMSFILTER) {
		struct group_filter *gf = (struct group_filter *)mp1->b_rptr;
		if (gf->gf_numsrc >= 2) {
			offset = sizeof (struct group_filter);
			copysize = GROUP_FILTER_SIZE(gf->gf_numsrc) - offset;
		}
	} else {
		struct ip_msfilter *imsf = (struct ip_msfilter *)mp1->b_rptr;
		if (imsf->imsf_numsrc >= 2) {
			offset = sizeof (struct ip_msfilter);
			copysize = IP_MSFILTER_SIZE(imsf->imsf_numsrc) - offset;
		}
	}
	if (copysize > 0) {
		mi_copyin_n(q, mp, offset, copysize);
		return (0);
	}
	return (1);
}

/*
 * Handle the following optmgmt:
 *	IP_ADD_MEMBERSHIP		must not have joined already
 *	MCAST_JOIN_GROUP		must not have joined already
 *	IP_BLOCK_SOURCE			must have joined already
 *	MCAST_BLOCK_SOURCE		must have joined already
 *	IP_JOIN_SOURCE_GROUP		may have joined already
 *	MCAST_JOIN_SOURCE_GROUP		may have joined already
 *
 * fmode and src parameters may be used to determine which option is
 * being set, as follows (the IP_* and MCAST_* versions of each option
 * are functionally equivalent):
 *	opt			fmode			src
 *	IP_ADD_MEMBERSHIP	MODE_IS_EXCLUDE		INADDR_ANY
 *	MCAST_JOIN_GROUP	MODE_IS_EXCLUDE		INADDR_ANY
 *	IP_BLOCK_SOURCE		MODE_IS_EXCLUDE		v4 addr
 *	MCAST_BLOCK_SOURCE	MODE_IS_EXCLUDE		v4 addr
 *	IP_JOIN_SOURCE_GROUP	MODE_IS_INCLUDE		v4 addr
 *	MCAST_JOIN_SOURCE_GROUP	MODE_IS_INCLUDE		v4 addr
 *
 * Changing the filter mode is not allowed; if a matching ilg already
 * exists and fmode != ilg->ilg_fmode, EINVAL is returned.
 *
 * Verifies that there is a source address of appropriate scope for
 * the group; if not, EADDRNOTAVAIL is returned.
 *
 * The interface to be used may be identified by an address or by an
 * index.  A pointer to the index is passed; if it is NULL, use the
 * address, otherwise, use the index.
 */
int
ip_opt_add_group(conn_t *connp, boolean_t checkonly, ipaddr_t group,
    ipaddr_t ifaddr, uint_t *ifindexp, mcast_record_t fmode, ipaddr_t src,
    mblk_t *first_mp)
{
	ipif_t	*ipif;
	ipsq_t	*ipsq;
	int err = 0;
	ill_t	*ill;

	err = ip_opt_check(connp, group, src, ifaddr, ifindexp, first_mp,
	    ip_restart_optmgmt, &ipif);
	if (err != 0) {
		if (err != EINPROGRESS) {
			ip1dbg(("ip_opt_add_group: no ipif for group 0x%x, "
			    "ifaddr 0x%x, ifindex %d\n", ntohl(group),
			    ntohl(ifaddr), (ifindexp == NULL) ? 0 : *ifindexp));
		}
		return (err);
	}
	ASSERT(ipif != NULL);

	ill = ipif->ipif_ill;
	/* Operation not supported on a virtual network interface */
	if (IS_VNI(ill)) {
		ipif_refrele(ipif);
		return (EINVAL);
	}

	if (checkonly) {
		/*
		 * do not do operation, just pretend to - new T_CHECK
		 * semantics. The error return case above if encountered
		 * considered a good enough "check" here.
		 */
		ipif_refrele(ipif);
		return (0);
	}

	IPSQ_ENTER_IPIF(ipif, connp, first_mp, ip_restart_optmgmt, ipsq,
	    NEW_OP);

	/* unspecified source addr => no source filtering */
	err = ilg_add(connp, group, ipif, fmode, src);

	IPSQ_EXIT(ipsq);

	ipif_refrele(ipif);
	return (err);
}

/*
 * Handle the following optmgmt:
 *	IPV6_JOIN_GROUP			must not have joined already
 *	MCAST_JOIN_GROUP		must not have joined already
 *	MCAST_BLOCK_SOURCE		must have joined already
 *	MCAST_JOIN_SOURCE_GROUP		may have joined already
 *
 * fmode and src parameters may be used to determine which option is
 * being set, as follows (IPV6_JOIN_GROUP and MCAST_JOIN_GROUP options
 * are functionally equivalent):
 *	opt			fmode			v6src
 *	IPV6_JOIN_GROUP		MODE_IS_EXCLUDE		unspecified
 *	MCAST_JOIN_GROUP	MODE_IS_EXCLUDE		unspecified
 *	MCAST_BLOCK_SOURCE	MODE_IS_EXCLUDE		v6 addr
 *	MCAST_JOIN_SOURCE_GROUP	MODE_IS_INCLUDE		v6 addr
 *
 * Changing the filter mode is not allowed; if a matching ilg already
 * exists and fmode != ilg->ilg_fmode, EINVAL is returned.
 *
 * Verifies that there is a source address of appropriate scope for
 * the group; if not, EADDRNOTAVAIL is returned.
 *
 * Handles IPv4-mapped IPv6 multicast addresses by associating them
 * with the link-local ipif.  Assumes that if v6group is v4-mapped,
 * v6src is also v4-mapped.
 */
int
ip_opt_add_group_v6(conn_t *connp, boolean_t checkonly,
    const in6_addr_t *v6group, int ifindex, mcast_record_t fmode,
    const in6_addr_t *v6src, mblk_t *first_mp)
{
	ill_t *ill;
	ipif_t	*ipif;
	char buf[INET6_ADDRSTRLEN];
	ipaddr_t v4group, v4src;
	boolean_t isv6;
	ipsq_t	*ipsq;
	int	err;

	err = ip_opt_check_v6(connp, v6group, &v4group, v6src, &v4src, &isv6,
	    ifindex, first_mp, ip_restart_optmgmt, &ill, &ipif);
	if (err != 0) {
		if (err != EINPROGRESS) {
			ip1dbg(("ip_opt_add_group_v6: no ill for group %s/"
			    "index %d\n", inet_ntop(AF_INET6, v6group, buf,
			    sizeof (buf)), ifindex));
		}
		return (err);
	}
	ASSERT((!isv6 && ipif != NULL) || (isv6 && ill != NULL));

	/* operation is not supported on the virtual network interface */
	if (isv6) {
		if (IS_VNI(ill)) {
			ill_refrele(ill);
			return (EINVAL);
		}
	} else {
		if (IS_VNI(ipif->ipif_ill)) {
			ipif_refrele(ipif);
			return (EINVAL);
		}
	}

	if (checkonly) {
		/*
		 * do not do operation, just pretend to - new T_CHECK
		 * semantics. The error return case above if encountered
		 * considered a good enough "check" here.
		 */
		if (isv6)
			ill_refrele(ill);
		else
			ipif_refrele(ipif);
		return (0);
	}

	if (!isv6) {
		IPSQ_ENTER_IPIF(ipif, connp, first_mp, ip_restart_optmgmt,
		    ipsq, NEW_OP);
		err = ilg_add(connp, v4group, ipif, fmode, v4src);
		IPSQ_EXIT(ipsq);
		ipif_refrele(ipif);
	} else {
		IPSQ_ENTER_ILL(ill, connp, first_mp, ip_restart_optmgmt,
		    ipsq, NEW_OP);
		err = ilg_add_v6(connp, v6group, ill, fmode, v6src);
		IPSQ_EXIT(ipsq);
		ill_refrele(ill);
	}

	return (err);
}

static int
ip_opt_delete_group_excl(conn_t *connp, ipaddr_t group, ipif_t *ipif,
    mcast_record_t fmode, ipaddr_t src)
{
	ilg_t	*ilg;
	in6_addr_t v6src;
	boolean_t leaving = B_FALSE;

	ASSERT(IAM_WRITER_IPIF(ipif));

	/*
	 * The ilg is valid only while we hold the conn lock. Once we drop
	 * the lock, another thread can locate another ilg on this connp,
	 * but on a different ipif, and delete it, and cause the ilg array
	 * to be reallocated and copied. Hence do the ilg_delete before
	 * dropping the lock.
	 */
	mutex_enter(&connp->conn_lock);
	ilg = ilg_lookup_ipif(connp, group, ipif);
	if ((ilg == NULL) || (ilg->ilg_flags & ILG_DELETED)) {
		mutex_exit(&connp->conn_lock);
		return (EADDRNOTAVAIL);
	}

	/*
	 * Decide if we're actually deleting the ilg or just removing a
	 * source filter address; if just removing an addr, make sure we
	 * aren't trying to change the filter mode, and that the addr is
	 * actually in our filter list already.  If we're removing the
	 * last src in an include list, just delete the ilg.
	 */
	if (src == INADDR_ANY) {
		v6src = ipv6_all_zeros;
		leaving = B_TRUE;
	} else {
		int err = 0;
		IN6_IPADDR_TO_V4MAPPED(src, &v6src);
		if (fmode != ilg->ilg_fmode)
			err = EINVAL;
		else if (ilg->ilg_filter == NULL ||
		    !list_has_addr(ilg->ilg_filter, &v6src))
			err = EADDRNOTAVAIL;
		if (err != 0) {
			mutex_exit(&connp->conn_lock);
			return (err);
		}
		if (fmode == MODE_IS_INCLUDE &&
		    ilg->ilg_filter->sl_numsrc == 1) {
			v6src = ipv6_all_zeros;
			leaving = B_TRUE;
		}
	}

	ilg_delete(connp, ilg, &v6src);
	mutex_exit(&connp->conn_lock);

	(void) ip_delmulti(group, ipif, B_FALSE, leaving);
	return (0);
}

static int
ip_opt_delete_group_excl_v6(conn_t *connp, const in6_addr_t *v6group,
    ill_t *ill, mcast_record_t fmode, const in6_addr_t *v6src)
{
	ilg_t	*ilg;
	ill_t	*ilg_ill;
	uint_t	ilg_orig_ifindex;
	boolean_t leaving = B_TRUE;

	ASSERT(IAM_WRITER_ILL(ill));

	/*
	 * Use the index that we originally used to join. We can't
	 * use the ill directly because ilg_ill could point to
	 * a new ill if things have moved.
	 */
	mutex_enter(&connp->conn_lock);
	ilg = ilg_lookup_ill_index_v6(connp, v6group,
	    ill->ill_phyint->phyint_ifindex);
	if ((ilg == NULL) || (ilg->ilg_flags & ILG_DELETED)) {
		mutex_exit(&connp->conn_lock);
		return (EADDRNOTAVAIL);
	}

	/*
	 * Decide if we're actually deleting the ilg or just removing a
	 * source filter address; if just removing an addr, make sure we
	 * aren't trying to change the filter mode, and that the addr is
	 * actually in our filter list already.  If we're removing the
	 * last src in an include list, just delete the ilg.
	 */
	if (!IN6_IS_ADDR_UNSPECIFIED(v6src)) {
		int err = 0;
		if (fmode != ilg->ilg_fmode)
			err = EINVAL;
		else if (ilg->ilg_filter == NULL ||
		    !list_has_addr(ilg->ilg_filter, v6src))
			err = EADDRNOTAVAIL;
		if (err != 0) {
			mutex_exit(&connp->conn_lock);
			return (err);
		}
		if (fmode == MODE_IS_INCLUDE &&
		    ilg->ilg_filter->sl_numsrc == 1)
			v6src = NULL;
		else
			leaving = B_FALSE;
	}

	ilg_ill = ilg->ilg_ill;
	ilg_orig_ifindex = ilg->ilg_orig_ifindex;
	ilg_delete(connp, ilg, v6src);
	mutex_exit(&connp->conn_lock);
	(void) ip_delmulti_v6(v6group, ilg_ill, ilg_orig_ifindex,
	    connp->conn_zoneid, B_FALSE, leaving);

	return (0);
}

/*
 * Handle the following optmgmt:
 *	IP_DROP_MEMBERSHIP		will leave
 *	MCAST_LEAVE_GROUP		will leave
 *	IP_UNBLOCK_SOURCE		will not leave
 *	MCAST_UNBLOCK_SOURCE		will not leave
 *	IP_LEAVE_SOURCE_GROUP		may leave (if leaving last source)
 *	MCAST_LEAVE_SOURCE_GROUP	may leave (if leaving last source)
 *
 * fmode and src parameters may be used to determine which option is
 * being set, as follows (the IP_* and MCAST_* versions of each option
 * are functionally equivalent):
 *	opt			 fmode			src
 *	IP_DROP_MEMBERSHIP	 MODE_IS_INCLUDE	INADDR_ANY
 *	MCAST_LEAVE_GROUP	 MODE_IS_INCLUDE	INADDR_ANY
 *	IP_UNBLOCK_SOURCE	 MODE_IS_EXCLUDE	v4 addr
 *	MCAST_UNBLOCK_SOURCE	 MODE_IS_EXCLUDE	v4 addr
 *	IP_LEAVE_SOURCE_GROUP	 MODE_IS_INCLUDE	v4 addr
 *	MCAST_LEAVE_SOURCE_GROUP MODE_IS_INCLUDE	v4 addr
 *
 * Changing the filter mode is not allowed; if a matching ilg already
 * exists and fmode != ilg->ilg_fmode, EINVAL is returned.
 *
 * The interface to be used may be identified by an address or by an
 * index.  A pointer to the index is passed; if it is NULL, use the
 * address, otherwise, use the index.
 */
int
ip_opt_delete_group(conn_t *connp, boolean_t checkonly, ipaddr_t group,
    ipaddr_t ifaddr, uint_t *ifindexp, mcast_record_t fmode, ipaddr_t src,
    mblk_t *first_mp)
{
	ipif_t	*ipif;
	ipsq_t	*ipsq;
	int	err;
	ill_t	*ill;

	err = ip_opt_check(connp, group, src, ifaddr, ifindexp, first_mp,
	    ip_restart_optmgmt, &ipif);
	if (err != 0) {
		if (err != EINPROGRESS) {
			ip1dbg(("ip_opt_delete_group: no ipif for group "
			    "0x%x, ifaddr 0x%x\n",
			    (int)ntohl(group), (int)ntohl(ifaddr)));
		}
		return (err);
	}
	ASSERT(ipif != NULL);

	ill = ipif->ipif_ill;
	/* Operation not supported on a virtual network interface */
	if (IS_VNI(ill)) {
		ipif_refrele(ipif);
		return (EINVAL);
	}

	if (checkonly) {
		/*
		 * do not do operation, just pretend to - new T_CHECK
		 * semantics. The error return case above if encountered
		 * considered a good enough "check" here.
		 */
		ipif_refrele(ipif);
		return (0);
	}

	IPSQ_ENTER_IPIF(ipif, connp, first_mp, ip_restart_optmgmt, ipsq,
	    NEW_OP);
	err = ip_opt_delete_group_excl(connp, group, ipif, fmode, src);
	IPSQ_EXIT(ipsq);

	ipif_refrele(ipif);
	return (err);
}

/*
 * Handle the following optmgmt:
 *	IPV6_LEAVE_GROUP		will leave
 *	MCAST_LEAVE_GROUP		will leave
 *	MCAST_UNBLOCK_SOURCE		will not leave
 *	MCAST_LEAVE_SOURCE_GROUP	may leave (if leaving last source)
 *
 * fmode and src parameters may be used to determine which option is
 * being set, as follows (IPV6_LEAVE_GROUP and MCAST_LEAVE_GROUP options
 * are functionally equivalent):
 *	opt			 fmode			v6src
 *	IPV6_LEAVE_GROUP	 MODE_IS_INCLUDE	unspecified
 *	MCAST_LEAVE_GROUP	 MODE_IS_INCLUDE	unspecified
 *	MCAST_UNBLOCK_SOURCE	 MODE_IS_EXCLUDE	v6 addr
 *	MCAST_LEAVE_SOURCE_GROUP MODE_IS_INCLUDE	v6 addr
 *
 * Changing the filter mode is not allowed; if a matching ilg already
 * exists and fmode != ilg->ilg_fmode, EINVAL is returned.
 *
 * Handles IPv4-mapped IPv6 multicast addresses by associating them
 * with the link-local ipif.  Assumes that if v6group is v4-mapped,
 * v6src is also v4-mapped.
 */
int
ip_opt_delete_group_v6(conn_t *connp, boolean_t checkonly,
    const in6_addr_t *v6group, int ifindex, mcast_record_t fmode,
    const in6_addr_t *v6src, mblk_t *first_mp)
{
	ill_t *ill;
	ipif_t	*ipif;
	char	buf[INET6_ADDRSTRLEN];
	ipaddr_t v4group, v4src;
	boolean_t isv6;
	ipsq_t	*ipsq;
	int	err;

	err = ip_opt_check_v6(connp, v6group, &v4group, v6src, &v4src, &isv6,
	    ifindex, first_mp, ip_restart_optmgmt, &ill, &ipif);
	if (err != 0) {
		if (err != EINPROGRESS) {
			ip1dbg(("ip_opt_delete_group_v6: no ill for group %s/"
			    "index %d\n", inet_ntop(AF_INET6, v6group, buf,
			    sizeof (buf)), ifindex));
		}
		return (err);
	}
	ASSERT((isv6 && ill != NULL) || (!isv6 && ipif != NULL));

	/* operation is not supported on the virtual network interface */
	if (isv6) {
		if (IS_VNI(ill)) {
			ill_refrele(ill);
			return (EINVAL);
		}
	} else {
		if (IS_VNI(ipif->ipif_ill)) {
			ipif_refrele(ipif);
			return (EINVAL);
		}
	}

	if (checkonly) {
		/*
		 * do not do operation, just pretend to - new T_CHECK
		 * semantics. The error return case above if encountered
		 * considered a good enough "check" here.
		 */
		if (isv6)
			ill_refrele(ill);
		else
			ipif_refrele(ipif);
		return (0);
	}

	if (!isv6) {
		IPSQ_ENTER_IPIF(ipif, connp, first_mp, ip_restart_optmgmt,
		    ipsq, NEW_OP);
		err = ip_opt_delete_group_excl(connp, v4group, ipif, fmode,
		    v4src);
		IPSQ_EXIT(ipsq);
		ipif_refrele(ipif);
	} else {
		IPSQ_ENTER_ILL(ill, connp, first_mp, ip_restart_optmgmt,
		    ipsq, NEW_OP);
		err = ip_opt_delete_group_excl_v6(connp, v6group, ill, fmode,
		    v6src);
		IPSQ_EXIT(ipsq);
		ill_refrele(ill);
	}

	return (err);
}

/*
 * Group mgmt for upper conn that passes things down
 * to the interface multicast list (and DLPI)
 * These routines can handle new style options that specify an interface name
 * as opposed to an interface address (needed for general handling of
 * unnumbered interfaces.)
 */

/*
 * Add a group to an upper conn group data structure and pass things down
 * to the interface multicast list (and DLPI)
 */
static int
ilg_add(conn_t *connp, ipaddr_t group, ipif_t *ipif, mcast_record_t fmode,
    ipaddr_t src)
{
	int	error = 0;
	ill_t	*ill;
	ilg_t	*ilg;
	ilg_stat_t ilgstat;
	slist_t	*new_filter = NULL;
	int	new_fmode;

	ASSERT(IAM_WRITER_IPIF(ipif));

	ill = ipif->ipif_ill;

	if (!(ill->ill_flags & ILLF_MULTICAST))
		return (EADDRNOTAVAIL);

	/*
	 * conn_ilg[] is protected by conn_lock. Need to hold the conn_lock
	 * to walk the conn_ilg[] list in ilg_lookup_ipif(); also needed to
	 * serialize 2 threads doing join (sock, group1, hme0:0) and
	 * (sock, group2, hme1:0) where hme0 and hme1 map to different ipsqs,
	 * but both operations happen on the same conn.
	 */
	mutex_enter(&connp->conn_lock);
	ilg = ilg_lookup_ipif(connp, group, ipif);

	/*
	 * Depending on the option we're handling, may or may not be okay
	 * if group has already been added.  Figure out our rules based
	 * on fmode and src params.  Also make sure there's enough room
	 * in the filter if we're adding a source to an existing filter.
	 */
	if (src == INADDR_ANY) {
		/* we're joining for all sources, must not have joined */
		if (ilg != NULL)
			error = EADDRINUSE;
	} else {
		if (fmode == MODE_IS_EXCLUDE) {
			/* (excl {addr}) => block source, must have joined */
			if (ilg == NULL)
				error = EADDRNOTAVAIL;
		}
		/* (incl {addr}) => join source, may have joined */

		if (ilg != NULL &&
		    SLIST_CNT(ilg->ilg_filter) == MAX_FILTER_SIZE)
			error = ENOBUFS;
	}
	if (error != 0) {
		mutex_exit(&connp->conn_lock);
		return (error);
	}

	ASSERT(!(ipif->ipif_state_flags & IPIF_CONDEMNED));

	/*
	 * Alloc buffer to copy new state into (see below) before
	 * we make any changes, so we can bail if it fails.
	 */
	if ((new_filter = l_alloc()) == NULL) {
		mutex_exit(&connp->conn_lock);
		return (ENOMEM);
	}

	if (ilg == NULL) {
		ilgstat = ILGSTAT_NEW;
		if ((ilg = conn_ilg_alloc(connp)) == NULL) {
			mutex_exit(&connp->conn_lock);
			l_free(new_filter);
			return (ENOMEM);
		}
		if (src != INADDR_ANY) {
			ilg->ilg_filter = l_alloc();
			if (ilg->ilg_filter == NULL) {
				ilg_delete(connp, ilg, NULL);
				mutex_exit(&connp->conn_lock);
				l_free(new_filter);
				return (ENOMEM);
			}
			ilg->ilg_filter->sl_numsrc = 1;
			IN6_IPADDR_TO_V4MAPPED(src,
			    &ilg->ilg_filter->sl_addr[0]);
		}
		if (group == INADDR_ANY) {
			ilg->ilg_v6group = ipv6_all_zeros;
		} else {
			IN6_IPADDR_TO_V4MAPPED(group, &ilg->ilg_v6group);
		}
		ilg->ilg_ipif = ipif;
		ilg->ilg_ill = NULL;
		ilg->ilg_orig_ifindex = 0;
		ilg->ilg_fmode = fmode;
	} else {
		int index;
		in6_addr_t v6src;
		ilgstat = ILGSTAT_CHANGE;
		if (ilg->ilg_fmode != fmode || src == INADDR_ANY) {
			mutex_exit(&connp->conn_lock);
			l_free(new_filter);
			return (EINVAL);
		}
		if (ilg->ilg_filter == NULL) {
			ilg->ilg_filter = l_alloc();
			if (ilg->ilg_filter == NULL) {
				mutex_exit(&connp->conn_lock);
				l_free(new_filter);
				return (ENOMEM);
			}
		}
		IN6_IPADDR_TO_V4MAPPED(src, &v6src);
		if (list_has_addr(ilg->ilg_filter, &v6src)) {
			mutex_exit(&connp->conn_lock);
			l_free(new_filter);
			return (EADDRNOTAVAIL);
		}
		index = ilg->ilg_filter->sl_numsrc++;
		ilg->ilg_filter->sl_addr[index] = v6src;
	}

	/*
	 * Save copy of ilg's filter state to pass to other functions,
	 * so we can release conn_lock now.
	 */
	new_fmode = ilg->ilg_fmode;
	l_copy(ilg->ilg_filter, new_filter);

	mutex_exit(&connp->conn_lock);

	error = ip_addmulti(group, ipif, ilgstat, new_fmode, new_filter);
	if (error != 0) {
		/*
		 * Need to undo what we did before calling ip_addmulti()!
		 * Must look up the ilg again since we've not been holding
		 * conn_lock.
		 */
		in6_addr_t v6src;
		if (ilgstat == ILGSTAT_NEW)
			v6src = ipv6_all_zeros;
		else
			IN6_IPADDR_TO_V4MAPPED(src, &v6src);
		mutex_enter(&connp->conn_lock);
		ilg = ilg_lookup_ipif(connp, group, ipif);
		ASSERT(ilg != NULL);
		ilg_delete(connp, ilg, &v6src);
		mutex_exit(&connp->conn_lock);
		l_free(new_filter);
		return (error);
	}

	l_free(new_filter);
	return (0);
}

static int
ilg_add_v6(conn_t *connp, const in6_addr_t *v6group, ill_t *ill,
    mcast_record_t fmode, const in6_addr_t *v6src)
{
	int	error = 0;
	int	orig_ifindex;
	ilg_t	*ilg;
	ilg_stat_t ilgstat;
	slist_t	*new_filter = NULL;
	int	new_fmode;

	ASSERT(IAM_WRITER_ILL(ill));

	if (!(ill->ill_flags & ILLF_MULTICAST))
		return (EADDRNOTAVAIL);

	/*
	 * conn_lock protects the ilg list.  Serializes 2 threads doing
	 * join (sock, group1, hme0) and (sock, group2, hme1) where hme0
	 * and hme1 map to different ipsq's, but both operations happen
	 * on the same conn.
	 */
	mutex_enter(&connp->conn_lock);

	/*
	 * Use the ifindex to do the lookup. We can't use the ill
	 * directly because ilg_ill could point to a different ill if
	 * things have moved.
	 */
	orig_ifindex = ill->ill_phyint->phyint_ifindex;
	ilg = ilg_lookup_ill_index_v6(connp, v6group, orig_ifindex);

	/*
	 * Depending on the option we're handling, may or may not be okay
	 * if group has already been added.  Figure out our rules based
	 * on fmode and src params.  Also make sure there's enough room
	 * in the filter if we're adding a source to an existing filter.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(v6src)) {
		/* we're joining for all sources, must not have joined */
		if (ilg != NULL)
			error = EADDRINUSE;
	} else {
		if (fmode == MODE_IS_EXCLUDE) {
			/* (excl {addr}) => block source, must have joined */
			if (ilg == NULL)
				error = EADDRNOTAVAIL;
		}
		/* (incl {addr}) => join source, may have joined */

		if (ilg != NULL &&
		    SLIST_CNT(ilg->ilg_filter) == MAX_FILTER_SIZE)
			error = ENOBUFS;
	}
	if (error != 0) {
		mutex_exit(&connp->conn_lock);
		return (error);
	}

	/*
	 * Alloc buffer to copy new state into (see below) before
	 * we make any changes, so we can bail if it fails.
	 */
	if ((new_filter = l_alloc()) == NULL) {
		mutex_exit(&connp->conn_lock);
		return (ENOMEM);
	}

	if (ilg == NULL) {
		if ((ilg = conn_ilg_alloc(connp)) == NULL) {
			mutex_exit(&connp->conn_lock);
			l_free(new_filter);
			return (ENOMEM);
		}
		if (!IN6_IS_ADDR_UNSPECIFIED(v6src)) {
			ilg->ilg_filter = l_alloc();
			if (ilg->ilg_filter == NULL) {
				ilg_delete(connp, ilg, NULL);
				mutex_exit(&connp->conn_lock);
				l_free(new_filter);
				return (ENOMEM);
			}
			ilg->ilg_filter->sl_numsrc = 1;
			ilg->ilg_filter->sl_addr[0] = *v6src;
		}
		ilgstat = ILGSTAT_NEW;
		ilg->ilg_v6group = *v6group;
		ilg->ilg_fmode = fmode;
		ilg->ilg_ipif = NULL;
		/*
		 * Choose our target ill to join on. This might be different
		 * from the ill we've been given if it's currently down and
		 * part of a group.
		 *
		 * new ill is not refheld; we are writer.
		 */
		ill = ip_choose_multi_ill(ill, v6group);
		ASSERT(!(ill->ill_state_flags & ILL_CONDEMNED));
		ilg->ilg_ill = ill;
		/*
		 * Remember the orig_ifindex that we joined on, so that we
		 * can successfully delete them later on and also search
		 * for duplicates if the application wants to join again.
		 */
		ilg->ilg_orig_ifindex = orig_ifindex;
	} else {
		int index;
		if (ilg->ilg_fmode != fmode || IN6_IS_ADDR_UNSPECIFIED(v6src)) {
			mutex_exit(&connp->conn_lock);
			l_free(new_filter);
			return (EINVAL);
		}
		if (ilg->ilg_filter == NULL) {
			ilg->ilg_filter = l_alloc();
			if (ilg->ilg_filter == NULL) {
				mutex_exit(&connp->conn_lock);
				l_free(new_filter);
				return (ENOMEM);
			}
		}
		if (list_has_addr(ilg->ilg_filter, v6src)) {
			mutex_exit(&connp->conn_lock);
			l_free(new_filter);
			return (EADDRNOTAVAIL);
		}
		ilgstat = ILGSTAT_CHANGE;
		index = ilg->ilg_filter->sl_numsrc++;
		ilg->ilg_filter->sl_addr[index] = *v6src;
		/*
		 * The current ill might be different from the one we were
		 * asked to join on (if failover has occurred); we should
		 * join on the ill stored in the ilg.  The original ill
		 * is noted in ilg_orig_ifindex, which matched our request.
		 */
		ill = ilg->ilg_ill;
	}

	/*
	 * Save copy of ilg's filter state to pass to other functions,
	 * so we can release conn_lock now.
	 */
	new_fmode = ilg->ilg_fmode;
	l_copy(ilg->ilg_filter, new_filter);

	mutex_exit(&connp->conn_lock);

	/*
	 * Now update the ill. We wait to do this until after the ilg
	 * has been updated because we need to update the src filter
	 * info for the ill, which involves looking at the status of
	 * all the ilgs associated with this group/interface pair.
	 */
	error = ip_addmulti_v6(v6group, ill, orig_ifindex, connp->conn_zoneid,
	    ilgstat, new_fmode, new_filter);
	if (error != 0) {
		/*
		 * But because we waited, we have to undo the ilg update
		 * if ip_addmulti_v6() fails.  We also must lookup ilg
		 * again, since we've not been holding conn_lock.
		 */
		in6_addr_t delsrc =
		    (ilgstat == ILGSTAT_NEW) ? ipv6_all_zeros : *v6src;
		mutex_enter(&connp->conn_lock);
		ilg = ilg_lookup_ill_index_v6(connp, v6group, orig_ifindex);
		ASSERT(ilg != NULL);
		ilg_delete(connp, ilg, &delsrc);
		mutex_exit(&connp->conn_lock);
		l_free(new_filter);
		return (error);
	}

	l_free(new_filter);

	return (0);
}

/*
 * Find an IPv4 ilg matching group, ill and source
 */
ilg_t *
ilg_lookup_ill_withsrc(conn_t *connp, ipaddr_t group, ipaddr_t src, ill_t *ill)
{
	in6_addr_t v6group, v6src;
	int i;
	boolean_t isinlist;
	ilg_t *ilg;
	ipif_t *ipif;
	ill_t *ilg_ill;

	ASSERT(MUTEX_HELD(&connp->conn_lock));

	/*
	 * INADDR_ANY is represented as the IPv6 unspecified addr.
	 */
	if (group == INADDR_ANY)
		v6group = ipv6_all_zeros;
	else
		IN6_IPADDR_TO_V4MAPPED(group, &v6group);

	for (i = 0; i < connp->conn_ilg_inuse; i++) {
		ilg = &connp->conn_ilg[i];
		if ((ipif = ilg->ilg_ipif) == NULL ||
		    (ilg->ilg_flags & ILG_DELETED) != 0)
			continue;
		ASSERT(ilg->ilg_ill == NULL);
		ilg_ill = ipif->ipif_ill;
		ASSERT(!ilg_ill->ill_isv6);
		if (ilg_ill == ill &&
		    IN6_ARE_ADDR_EQUAL(&ilg->ilg_v6group, &v6group)) {
			if (SLIST_IS_EMPTY(ilg->ilg_filter)) {
				/* no source filter, so this is a match */
				return (ilg);
			}
			break;
		}
	}
	if (i == connp->conn_ilg_inuse)
		return (NULL);

	/*
	 * we have an ilg with matching ill and group; but
	 * the ilg has a source list that we must check.
	 */
	IN6_IPADDR_TO_V4MAPPED(src, &v6src);
	isinlist = B_FALSE;
	for (i = 0; i < ilg->ilg_filter->sl_numsrc; i++) {
		if (IN6_ARE_ADDR_EQUAL(&v6src, &ilg->ilg_filter->sl_addr[i])) {
			isinlist = B_TRUE;
			break;
		}
	}

	if ((isinlist && ilg->ilg_fmode == MODE_IS_INCLUDE) ||
	    (!isinlist && ilg->ilg_fmode == MODE_IS_EXCLUDE))
		return (ilg);

	return (NULL);
}

/*
 * Find an IPv6 ilg matching group, ill, and source
 */
ilg_t *
ilg_lookup_ill_withsrc_v6(conn_t *connp, const in6_addr_t *v6group,
    const in6_addr_t *v6src, ill_t *ill)
{
	int i;
	boolean_t isinlist;
	ilg_t *ilg;
	ill_t *ilg_ill;

	ASSERT(MUTEX_HELD(&connp->conn_lock));

	for (i = 0; i < connp->conn_ilg_inuse; i++) {
		ilg = &connp->conn_ilg[i];
		if ((ilg_ill = ilg->ilg_ill) == NULL ||
		    (ilg->ilg_flags & ILG_DELETED) != 0)
			continue;
		ASSERT(ilg->ilg_ipif == NULL);
		ASSERT(ilg_ill->ill_isv6);
		if (ilg_ill == ill &&
		    IN6_ARE_ADDR_EQUAL(&ilg->ilg_v6group, v6group)) {
			if (SLIST_IS_EMPTY(ilg->ilg_filter)) {
				/* no source filter, so this is a match */
				return (ilg);
			}
			break;
		}
	}
	if (i == connp->conn_ilg_inuse)
		return (NULL);

	/*
	 * we have an ilg with matching ill and group; but
	 * the ilg has a source list that we must check.
	 */
	isinlist = B_FALSE;
	for (i = 0; i < ilg->ilg_filter->sl_numsrc; i++) {
		if (IN6_ARE_ADDR_EQUAL(v6src, &ilg->ilg_filter->sl_addr[i])) {
			isinlist = B_TRUE;
			break;
		}
	}

	if ((isinlist && ilg->ilg_fmode == MODE_IS_INCLUDE) ||
	    (!isinlist && ilg->ilg_fmode == MODE_IS_EXCLUDE))
		return (ilg);

	return (NULL);
}

/*
 * Get the ilg whose ilg_orig_ifindex is associated with ifindex.
 * This is useful when the interface fails and we have moved
 * to a new ill, but still would like to locate using the index
 * that we originally used to join. Used only for IPv6 currently.
 */
static ilg_t *
ilg_lookup_ill_index_v6(conn_t *connp, const in6_addr_t *v6group, int ifindex)
{
	ilg_t	*ilg;
	int	i;

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	for (i = 0; i < connp->conn_ilg_inuse; i++) {
		ilg = &connp->conn_ilg[i];
		if (ilg->ilg_ill == NULL ||
		    (ilg->ilg_flags & ILG_DELETED) != 0)
			continue;
		/* ilg_ipif is NULL for V6 */
		ASSERT(ilg->ilg_ipif == NULL);
		ASSERT(ilg->ilg_orig_ifindex != 0);
		if (IN6_ARE_ADDR_EQUAL(&ilg->ilg_v6group, v6group) &&
		    ilg->ilg_orig_ifindex == ifindex) {
			return (ilg);
		}
	}
	return (NULL);
}

/*
 * Find an IPv6 ilg matching group and ill
 */
ilg_t *
ilg_lookup_ill_v6(conn_t *connp, const in6_addr_t *v6group, ill_t *ill)
{
	ilg_t	*ilg;
	int	i;
	ill_t 	*mem_ill;

	ASSERT(MUTEX_HELD(&connp->conn_lock));

	for (i = 0; i < connp->conn_ilg_inuse; i++) {
		ilg = &connp->conn_ilg[i];
		if ((mem_ill = ilg->ilg_ill) == NULL ||
		    (ilg->ilg_flags & ILG_DELETED) != 0)
			continue;
		ASSERT(ilg->ilg_ipif == NULL);
		ASSERT(mem_ill->ill_isv6);
		if (mem_ill == ill &&
		    IN6_ARE_ADDR_EQUAL(&ilg->ilg_v6group, v6group))
			return (ilg);
	}
	return (NULL);
}

/*
 * Find an IPv4 ilg matching group and ipif
 */
static ilg_t *
ilg_lookup_ipif(conn_t *connp, ipaddr_t group, ipif_t *ipif)
{
	in6_addr_t v6group;
	int	i;
	ilg_t	*ilg;

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	ASSERT(!ipif->ipif_ill->ill_isv6);

	if (group == INADDR_ANY)
		v6group = ipv6_all_zeros;
	else
		IN6_IPADDR_TO_V4MAPPED(group, &v6group);

	for (i = 0; i < connp->conn_ilg_inuse; i++) {
		ilg = &connp->conn_ilg[i];
		if ((ilg->ilg_flags & ILG_DELETED) == 0 &&
		    IN6_ARE_ADDR_EQUAL(&ilg->ilg_v6group, &v6group) &&
		    ilg->ilg_ipif == ipif)
			return (ilg);
	}
	return (NULL);
}

/*
 * If a source address is passed in (src != NULL and src is not
 * unspecified), remove the specified src addr from the given ilg's
 * filter list, else delete the ilg.
 */
static void
ilg_delete(conn_t *connp, ilg_t *ilg, const in6_addr_t *src)
{
	int	i;

	ASSERT((ilg->ilg_ipif != NULL) ^ (ilg->ilg_ill != NULL));
	ASSERT(ilg->ilg_ipif == NULL || IAM_WRITER_IPIF(ilg->ilg_ipif));
	ASSERT(ilg->ilg_ill == NULL || IAM_WRITER_ILL(ilg->ilg_ill));
	ASSERT(MUTEX_HELD(&connp->conn_lock));
	ASSERT(!(ilg->ilg_flags & ILG_DELETED));

	if (src == NULL || IN6_IS_ADDR_UNSPECIFIED(src)) {
		if (connp->conn_ilg_walker_cnt != 0) {
			ilg->ilg_flags |= ILG_DELETED;
			return;
		}

		FREE_SLIST(ilg->ilg_filter);

		i = ilg - &connp->conn_ilg[0];
		ASSERT(i >= 0 && i < connp->conn_ilg_inuse);

		/* Move other entries up one step */
		connp->conn_ilg_inuse--;
		for (; i < connp->conn_ilg_inuse; i++)
			connp->conn_ilg[i] = connp->conn_ilg[i+1];

		if (connp->conn_ilg_inuse == 0) {
			mi_free((char *)connp->conn_ilg);
			connp->conn_ilg = NULL;
			cv_broadcast(&connp->conn_refcv);
		}
	} else {
		l_remove(ilg->ilg_filter, src);
	}
}

/*
 * Called from conn close. No new ilg can be added or removed.
 * because CONN_CLOSING has been set by ip_close. ilg_add / ilg_delete
 * will return error if conn has started closing.
 */
void
ilg_delete_all(conn_t *connp)
{
	int	i;
	ipif_t	*ipif = NULL;
	ill_t	*ill = NULL;
	ilg_t	*ilg;
	in6_addr_t v6group;
	boolean_t success;
	ipsq_t	*ipsq;
	int	orig_ifindex;

	mutex_enter(&connp->conn_lock);
retry:
	ILG_WALKER_HOLD(connp);
	for (i = connp->conn_ilg_inuse - 1; i >= 0; ) {
		ilg = &connp->conn_ilg[i];
		/*
		 * Since this walk is not atomic (we drop the
		 * conn_lock and wait in ipsq_enter) we need
		 * to check for the ILG_DELETED flag.
		 */
		if (ilg->ilg_flags & ILG_DELETED) {
			/* Go to the next ilg */
			i--;
			continue;
		}
		v6group = ilg->ilg_v6group;

		if (IN6_IS_ADDR_V4MAPPED(&v6group)) {
			ipif = ilg->ilg_ipif;
			ill = ipif->ipif_ill;
		} else {
			ipif = NULL;
			ill = ilg->ilg_ill;
		}
		/*
		 * We may not be able to refhold the ill if the ill/ipif
		 * is changing. But we need to make sure that the ill will
		 * not vanish. So we just bump up the ill_waiter count.
		 * If we are unable to do even that, then the ill is closing,
		 * in which case the unplumb thread will handle the cleanup,
		 * and we move on to the next ilg.
		 */
		if (!ill_waiter_inc(ill)) {
			/* Go to the next ilg */
			i--;
			continue;
		}
		mutex_exit(&connp->conn_lock);
		/*
		 * To prevent deadlock between ill close which waits inside
		 * the perimeter, and conn close, ipsq_enter returns error,
		 * the moment ILL_CONDEMNED is set, in which case ill close
		 * takes responsibility to cleanup the ilgs. Note that we
		 * have not yet set condemned flag, otherwise the conn can't
		 * be refheld for cleanup by those routines and it would be
		 * a mutual deadlock.
		 */
		success = ipsq_enter(ill, B_FALSE);
		ipsq = ill->ill_phyint->phyint_ipsq;
		ill_waiter_dcr(ill);
		mutex_enter(&connp->conn_lock);
		if (!success) {
			/* Go to the next ilg */
			i--;
			continue;
		}

		/*
		 * Make sure that nothing has changed under. For eg.
		 * a failover/failback can change ilg_ill while we were
		 * waiting to become exclusive above
		 */
		if (IN6_IS_ADDR_V4MAPPED(&v6group)) {
			ipif = ilg->ilg_ipif;
			ill = ipif->ipif_ill;
		} else {
			ipif = NULL;
			ill = ilg->ilg_ill;
		}
		if (!IAM_WRITER_ILL(ill) || (ilg->ilg_flags & ILG_DELETED)) {
			/*
			 * The ilg has changed under us probably due
			 * to a failover or unplumb. Retry on the same ilg.
			 */
			mutex_exit(&connp->conn_lock);
			ipsq_exit(ipsq, B_TRUE, B_TRUE);
			mutex_enter(&connp->conn_lock);
			continue;
		}
		v6group = ilg->ilg_v6group;
		orig_ifindex = ilg->ilg_orig_ifindex;
		ilg_delete(connp, ilg, NULL);
		mutex_exit(&connp->conn_lock);

		if (ipif != NULL)
			(void) ip_delmulti(V4_PART_OF_V6(v6group), ipif,
			    B_FALSE, B_TRUE);

		else
			(void) ip_delmulti_v6(&v6group, ill, orig_ifindex,
			    connp->conn_zoneid, B_FALSE, B_TRUE);

		ipsq_exit(ipsq, B_TRUE, B_TRUE);
		mutex_enter(&connp->conn_lock);
		/* Go to the next ilg */
		i--;
	}
	ILG_WALKER_RELE(connp);

	/* If any ill was skipped above wait and retry */
	if (connp->conn_ilg_inuse != 0) {
		cv_wait(&connp->conn_refcv, &connp->conn_lock);
		goto retry;
	}
	mutex_exit(&connp->conn_lock);
}

/*
 * Called from ill close by ipcl_walk for clearing conn_ilg and
 * conn_multicast_ipif for a given ipif. conn is held by caller.
 * Note that ipcl_walk only walks conns that are not yet condemned.
 * condemned conns can't be refheld. For this reason, conn must become clean
 * first, i.e. it must not refer to any ill/ire/ipif and then only set
 * condemned flag.
 */
static void
conn_delete_ipif(conn_t *connp, caddr_t arg)
{
	ipif_t	*ipif = (ipif_t *)arg;
	int	i;
	char	group_buf1[INET6_ADDRSTRLEN];
	char	group_buf2[INET6_ADDRSTRLEN];
	ipaddr_t group;
	ilg_t	*ilg;

	/*
	 * Even though conn_ilg_inuse can change while we are in this loop,
	 * i.e.ilgs can be created or deleted on this connp, no new ilgs can
	 * be created or deleted for this connp, on this ill, since this ill
	 * is the perimeter. So we won't miss any ilg in this cleanup.
	 */
	mutex_enter(&connp->conn_lock);

	/*
	 * Increment the walker count, so that ilg repacking does not
	 * occur while we are in the loop.
	 */
	ILG_WALKER_HOLD(connp);
	for (i = connp->conn_ilg_inuse - 1; i >= 0; i--) {
		ilg = &connp->conn_ilg[i];
		if (ilg->ilg_ipif != ipif || (ilg->ilg_flags & ILG_DELETED))
			continue;
		/*
		 * ip_close cannot be cleaning this ilg at the same time.
		 * since it also has to execute in this ill's perimeter which
		 * we are now holding. Only a clean conn can be condemned.
		 */
		ASSERT(!(connp->conn_state_flags & CONN_CONDEMNED));

		/* Blow away the membership */
		ip1dbg(("conn_delete_ilg_ipif: %s on %s (%s)\n",
		    inet_ntop(AF_INET6, &connp->conn_ilg[i].ilg_v6group,
		    group_buf1, sizeof (group_buf1)),
		    inet_ntop(AF_INET6, &ipif->ipif_v6lcl_addr,
		    group_buf2, sizeof (group_buf2)),
		    ipif->ipif_ill->ill_name));

		/* ilg_ipif is NULL for V6, so we won't be here */
		ASSERT(IN6_IS_ADDR_V4MAPPED(&ilg->ilg_v6group));

		group = V4_PART_OF_V6(ilg->ilg_v6group);
		ilg_delete(connp, &connp->conn_ilg[i], NULL);
		mutex_exit(&connp->conn_lock);

		(void) ip_delmulti(group, ipif, B_FALSE, B_TRUE);
		mutex_enter(&connp->conn_lock);
	}

	/*
	 * If we are the last walker, need to physically delete the
	 * ilgs and repack.
	 */
	ILG_WALKER_RELE(connp);

	if (connp->conn_multicast_ipif == ipif) {
		/* Revert to late binding */
		connp->conn_multicast_ipif = NULL;
	}
	mutex_exit(&connp->conn_lock);

	conn_delete_ire(connp, (caddr_t)ipif);
}

/*
 * Called from ill close by ipcl_walk for clearing conn_ilg and
 * conn_multicast_ill for a given ill. conn is held by caller.
 * Note that ipcl_walk only walks conns that are not yet condemned.
 * condemned conns can't be refheld. For this reason, conn must become clean
 * first, i.e. it must not refer to any ill/ire/ipif and then only set
 * condemned flag.
 */
static void
conn_delete_ill(conn_t *connp, caddr_t arg)
{
	ill_t	*ill = (ill_t *)arg;
	int	i;
	char	group_buf[INET6_ADDRSTRLEN];
	in6_addr_t v6group;
	int	orig_ifindex;
	ilg_t	*ilg;

	/*
	 * Even though conn_ilg_inuse can change while we are in this loop,
	 * no new ilgs can be created/deleted for this connp, on this
	 * ill, since this ill is the perimeter. So we won't miss any ilg
	 * in this cleanup.
	 */
	mutex_enter(&connp->conn_lock);

	/*
	 * Increment the walker count, so that ilg repacking does not
	 * occur while we are in the loop.
	 */
	ILG_WALKER_HOLD(connp);
	for (i = connp->conn_ilg_inuse - 1; i >= 0; i--) {
		ilg = &connp->conn_ilg[i];
		if ((ilg->ilg_ill == ill) && !(ilg->ilg_flags & ILG_DELETED)) {
			/*
			 * ip_close cannot be cleaning this ilg at the same
			 * time, since it also has to execute in this ill's
			 * perimeter which we are now holding. Only a clean
			 * conn can be condemned.
			 */
			ASSERT(!(connp->conn_state_flags & CONN_CONDEMNED));

			/* Blow away the membership */
			ip1dbg(("conn_delete_ilg_ill: %s on %s\n",
			    inet_ntop(AF_INET6, &ilg->ilg_v6group,
			    group_buf, sizeof (group_buf)),
			    ill->ill_name));

			v6group = ilg->ilg_v6group;
			orig_ifindex = ilg->ilg_orig_ifindex;
			ilg_delete(connp, ilg, NULL);
			mutex_exit(&connp->conn_lock);

			(void) ip_delmulti_v6(&v6group, ill, orig_ifindex,
			    connp->conn_zoneid, B_FALSE, B_TRUE);
			mutex_enter(&connp->conn_lock);
		}
	}
	/*
	 * If we are the last walker, need to physically delete the
	 * ilgs and repack.
	 */
	ILG_WALKER_RELE(connp);

	if (connp->conn_multicast_ill == ill) {
		/* Revert to late binding */
		connp->conn_multicast_ill = NULL;
		connp->conn_orig_multicast_ifindex = 0;
	}
	mutex_exit(&connp->conn_lock);
}

/*
 * Called when an ipif is unplumbed to make sure that there are no
 * dangling conn references to that ipif.
 * Handles ilg_ipif and conn_multicast_ipif
 */
void
reset_conn_ipif(ipif)
	ipif_t	*ipif;
{
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ipcl_walk(conn_delete_ipif, (caddr_t)ipif, ipst);
}

/*
 * Called when an ill is unplumbed to make sure that there are no
 * dangling conn references to that ill.
 * Handles ilg_ill, conn_multicast_ill.
 */
void
reset_conn_ill(ill_t *ill)
{
	ip_stack_t	*ipst = ill->ill_ipst;

	ipcl_walk(conn_delete_ill, (caddr_t)ill, ipst);
}

#ifdef DEBUG
/*
 * Walk functions walk all the interfaces in the system to make
 * sure that there is no refernece to the ipif or ill that is
 * going away.
 */
int
ilm_walk_ill(ill_t *ill)
{
	int cnt = 0;
	ill_t *till;
	ilm_t *ilm;
	ill_walk_context_t ctx;
	ip_stack_t	*ipst = ill->ill_ipst;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	till = ILL_START_WALK_ALL(&ctx, ipst);
	for (; till != NULL; till = ill_next(&ctx, till)) {
		mutex_enter(&till->ill_lock);
		for (ilm = till->ill_ilm; ilm != NULL; ilm = ilm->ilm_next) {
			if (ilm->ilm_ill == ill) {
				cnt++;
			}
		}
		mutex_exit(&till->ill_lock);
	}
	rw_exit(&ipst->ips_ill_g_lock);

	return (cnt);
}

/*
 * This function is called before the ipif is freed.
 */
int
ilm_walk_ipif(ipif_t *ipif)
{
	int cnt = 0;
	ill_t *till;
	ilm_t *ilm;
	ill_walk_context_t ctx;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	till = ILL_START_WALK_ALL(&ctx, ipst);
	for (; till != NULL; till = ill_next(&ctx, till)) {
		mutex_enter(&till->ill_lock);
		for (ilm = till->ill_ilm; ilm != NULL; ilm = ilm->ilm_next) {
			if (ilm->ilm_ipif == ipif) {
					cnt++;
			}
		}
		mutex_exit(&till->ill_lock);
	}
	return (cnt);
}
#endif
