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
 * Copyright (c) 1990 Mentat Inc.
 */

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

static ilm_t	*ilm_add(ill_t *ill, const in6_addr_t *group,
    ilg_stat_t ilgstat, mcast_record_t ilg_fmode, slist_t *ilg_flist,
    zoneid_t zoneid);
static void	ilm_delete(ilm_t *ilm);
static int	ilm_numentries(ill_t *, const in6_addr_t *);

static ilm_t	*ip_addmulti_serial(const in6_addr_t *, ill_t *, zoneid_t,
    ilg_stat_t, mcast_record_t, slist_t *, int *);
static ilm_t	*ip_addmulti_impl(const in6_addr_t *, ill_t *,
    zoneid_t, ilg_stat_t, mcast_record_t, slist_t *, int *);
static int	ip_delmulti_serial(ilm_t *, boolean_t, boolean_t);
static int	ip_delmulti_impl(ilm_t *, boolean_t, boolean_t);

static int	ip_ll_multireq(ill_t *ill, const in6_addr_t *group,
    t_uscalar_t);
static ilg_t	*ilg_lookup(conn_t *, const in6_addr_t *, ipaddr_t ifaddr,
    uint_t ifindex);

static int	ilg_add(conn_t *connp, const in6_addr_t *group,
    ipaddr_t ifaddr, uint_t ifindex, ill_t *ill, mcast_record_t fmode,
    const in6_addr_t *v6src);
static void	ilg_delete(conn_t *connp, ilg_t *ilg, const in6_addr_t *src);
static mblk_t	*ill_create_dl(ill_t *ill, uint32_t dl_primitive,
    uint32_t *addr_lenp, uint32_t *addr_offp);
static int	ip_opt_delete_group_excl(conn_t *connp,
    const in6_addr_t *v6group, ipaddr_t ifaddr, uint_t ifindex,
    mcast_record_t fmode, const in6_addr_t *v6src);

static	ilm_t	*ilm_lookup(ill_t *, const in6_addr_t *, zoneid_t);

static int	ip_msfilter_ill(conn_t *, mblk_t *, const ip_ioctl_cmd_t *,
    ill_t **);

static void	ilg_check_detach(conn_t *, ill_t *);
static void	ilg_check_reattach(conn_t *, ill_t *);

/*
 * MT notes:
 *
 * Multicast joins operate on both the ilg and ilm structures. Multiple
 * threads operating on an conn (socket) trying to do multicast joins
 * need to synchronize when operating on the ilg. Multiple threads
 * potentially operating on different conn (socket endpoints) trying to
 * do multicast joins could eventually end up trying to manipulate the
 * ilm simulatenously and need to synchronize on the access to the ilm.
 * The access and lookup of the ilm, as well as other ill multicast state,
 * is under ill_mcast_lock.
 * The modifications and lookup of ilg entries is serialized using conn_ilg_lock
 * rwlock. An ilg will not be freed until ilg_refcnt drops to zero.
 *
 * In some cases we hold ill_mcast_lock and then acquire conn_ilg_lock, but
 * never the other way around.
 *
 * An ilm is an IP data structure used to track multicast join/leave.
 * An ilm is associated with a <multicast group, ipif> tuple in IPv4 and
 * with just <multicast group> in IPv6. ilm_refcnt is the number of ilg's
 * referencing the ilm.
 * The modifications and lookup of ilm entries is serialized using the
 * ill_mcast_lock rwlock; that lock handles all the igmp/mld modifications
 * of the ilm state.
 * ilms are created / destroyed only as writer. ilms
 * are not passed around. The datapath (anything outside of this file
 * and igmp.c) use functions that do not return ilms - just the number
 * of members. So we don't need a dynamic refcount of the number
 * of threads holding reference to an ilm.
 *
 * In the cases where we serially access the ilg and ilm, which happens when
 * we handle the applications requests to join or leave groups and sources,
 * we use the ill_mcast_serializer mutex to ensure that a multithreaded
 * application which does concurrent joins and/or leaves on the same group on
 * the same socket always results in a consistent order for the ilg and ilm
 * modifications.
 *
 * When a multicast operation results in needing to send a message to
 * the driver (to join/leave a L2 multicast address), we use ill_dlpi_queue()
 * which serialized the DLPI requests. The IGMP/MLD code uses ill_mcast_queue()
 * to send IGMP/MLD IP packet to avoid dropping the lock just to send a packet.
 */

#define	GETSTRUCT(structure, number)	\
	((structure *)mi_zalloc(sizeof (structure) * (number)))

/*
 * Caller must ensure that the ilg has not been condemned
 * The condemned flag is only set in ilg_delete under conn_ilg_lock.
 *
 * The caller must hold conn_ilg_lock as writer.
 */
static void
ilg_refhold(ilg_t *ilg)
{
	ASSERT(ilg->ilg_refcnt != 0);
	ASSERT(!ilg->ilg_condemned);
	ASSERT(RW_WRITE_HELD(&ilg->ilg_connp->conn_ilg_lock));

	ilg->ilg_refcnt++;
}

static void
ilg_inactive(ilg_t *ilg)
{
	ASSERT(ilg->ilg_ill == NULL);
	ASSERT(ilg->ilg_ilm == NULL);
	ASSERT(ilg->ilg_filter == NULL);
	ASSERT(ilg->ilg_condemned);

	/* Unlink from list */
	*ilg->ilg_ptpn = ilg->ilg_next;
	if (ilg->ilg_next != NULL)
		ilg->ilg_next->ilg_ptpn = ilg->ilg_ptpn;
	ilg->ilg_next = NULL;
	ilg->ilg_ptpn = NULL;

	ilg->ilg_connp = NULL;
	kmem_free(ilg, sizeof (*ilg));
}

/*
 * The caller must hold conn_ilg_lock as writer.
 */
static void
ilg_refrele(ilg_t *ilg)
{
	ASSERT(RW_WRITE_HELD(&ilg->ilg_connp->conn_ilg_lock));
	ASSERT(ilg->ilg_refcnt != 0);
	if (--ilg->ilg_refcnt == 0)
		ilg_inactive(ilg);
}

/*
 * Acquire reference on ilg and drop reference on held_ilg.
 * In the case when held_ilg is the same as ilg we already have
 * a reference, but the held_ilg might be condemned. In that case
 * we avoid the ilg_refhold/rele so that we can assert in ire_refhold
 * that the ilg isn't condemned.
 */
static void
ilg_transfer_hold(ilg_t *held_ilg, ilg_t *ilg)
{
	if (held_ilg == ilg)
		return;

	ilg_refhold(ilg);
	if (held_ilg != NULL)
		ilg_refrele(held_ilg);
}

/*
 * Allocate a new ilg_t and links it into conn_ilg.
 * Returns NULL on failure, in which case `*errp' will be
 * filled in with the reason.
 *
 * Assumes connp->conn_ilg_lock is held.
 */
static ilg_t *
conn_ilg_alloc(conn_t *connp, int *errp)
{
	ilg_t *ilg;

	ASSERT(RW_WRITE_HELD(&connp->conn_ilg_lock));

	/*
	 * If CONN_CLOSING is set, conn_ilg cleanup has begun and we must not
	 * create any ilgs.
	 */
	if (connp->conn_state_flags & CONN_CLOSING) {
		*errp = EINVAL;
		return (NULL);
	}

	ilg = kmem_zalloc(sizeof (ilg_t), KM_NOSLEEP);
	if (ilg == NULL) {
		*errp = ENOMEM;
		return (NULL);
	}

	ilg->ilg_refcnt = 1;

	/* Insert at head */
	if (connp->conn_ilg != NULL)
		connp->conn_ilg->ilg_ptpn = &ilg->ilg_next;
	ilg->ilg_next = connp->conn_ilg;
	ilg->ilg_ptpn = &connp->conn_ilg;
	connp->conn_ilg = ilg;

	ilg->ilg_connp = connp;
	return (ilg);
}

typedef struct ilm_fbld_s {
	ilm_t		*fbld_ilm;
	int		fbld_in_cnt;
	int		fbld_ex_cnt;
	slist_t		fbld_in;
	slist_t		fbld_ex;
	boolean_t	fbld_in_overflow;
} ilm_fbld_t;

/*
 * Caller must hold ill_mcast_lock
 */
static void
ilm_bld_flists(conn_t *connp, void *arg)
{
	ilg_t *ilg;
	ilm_fbld_t *fbld = (ilm_fbld_t *)(arg);
	ilm_t *ilm = fbld->fbld_ilm;
	in6_addr_t *v6group = &ilm->ilm_v6addr;

	if (connp->conn_ilg == NULL)
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
	 *
	 * Note that the caller has already serialized on the ill we care
	 * about.
	 */
	ASSERT(MUTEX_HELD(&ilm->ilm_ill->ill_mcast_serializer));

	rw_enter(&connp->conn_ilg_lock, RW_READER);
	for (ilg = connp->conn_ilg; ilg != NULL; ilg = ilg->ilg_next) {
		if (ilg->ilg_condemned)
			continue;

		/*
		 * Since we are under the ill_mcast_serializer we know
		 * that any ilg+ilm operations on this ilm have either
		 * not started or completed, except for the last ilg
		 * (the one that caused us to be called) which doesn't
		 * have ilg_ilm set yet. Hence we compare using ilg_ill
		 * and the address.
		 */
		if ((ilg->ilg_ill == ilm->ilm_ill) &&
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
	rw_exit(&connp->conn_ilg_lock);
}

/*
 * Caller must hold ill_mcast_lock
 */
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
 * Caller must hold ill_mcast_lock
 */
static int
ilm_update_add(ilm_t *ilm, ilg_stat_t ilgstat, slist_t *ilg_flist)
{
	mcast_record_t fmode;
	slist_t *flist;
	boolean_t fdefault;
	char buf[INET6_ADDRSTRLEN];
	ill_t *ill = ilm->ilm_ill;

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
		if (ill->ill_isv6)
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

/*
 * Caller must hold ill_mcast_lock
 */
static int
ilm_update_del(ilm_t *ilm)
{
	mcast_record_t fmode;
	slist_t *flist;
	ill_t *ill = ilm->ilm_ill;

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
		if (ill->ill_isv6)
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
 * Create/update the ilm for the group/ill. Used by other parts of IP to
 * do the ILGSTAT_NONE (no ilg), MODE_IS_EXCLUDE, with no slist join.
 * Returns with a refhold on the ilm.
 *
 * The unspecified address means all multicast addresses for in both the
 * case of IPv4 and IPv6.
 *
 * The caller should have already mapped an IPMP under ill to the upper.
 */
ilm_t *
ip_addmulti(const in6_addr_t *v6group, ill_t *ill, zoneid_t zoneid,
    int *errorp)
{
	ilm_t *ilm;

	/* Acquire serializer to keep assert in ilm_bld_flists happy */
	mutex_enter(&ill->ill_mcast_serializer);
	ilm = ip_addmulti_serial(v6group, ill, zoneid, ILGSTAT_NONE,
	    MODE_IS_EXCLUDE, NULL, errorp);
	mutex_exit(&ill->ill_mcast_serializer);
	/*
	 * Now that all locks have been dropped, we can send any
	 * deferred/queued DLPI or IP packets
	 */
	ill_mcast_send_queued(ill);
	ill_dlpi_send_queued(ill);
	return (ilm);
}

/*
 * Create/update the ilm for the group/ill. If ILGSTAT_CHANGE is not set
 * then this returns with a refhold on the ilm.
 *
 * Internal routine which assumes the caller has already acquired
 * ill_mcast_serializer. It is the caller's responsibility to send out
 * queued DLPI/multicast packets after all locks are dropped.
 *
 * The unspecified address means all multicast addresses for in both the
 * case of IPv4 and IPv6.
 *
 * ilgstat tells us if there's an ilg associated with this join,
 * and if so, if it's a new ilg or a change to an existing one.
 * ilg_fmode and ilg_flist give us the current filter state of
 * the ilg (and will be EXCLUDE {NULL} in the case of no ilg).
 *
 * The caller should have already mapped an IPMP under ill to the upper.
 */
static ilm_t *
ip_addmulti_serial(const in6_addr_t *v6group, ill_t *ill, zoneid_t zoneid,
    ilg_stat_t ilgstat, mcast_record_t ilg_fmode, slist_t *ilg_flist,
    int *errorp)
{
	ilm_t *ilm;

	ASSERT(MUTEX_HELD(&ill->ill_mcast_serializer));

	if (ill->ill_isv6) {
		if (!IN6_IS_ADDR_MULTICAST(v6group) &&
		    !IN6_IS_ADDR_UNSPECIFIED(v6group)) {
			*errorp = EINVAL;
			return (NULL);
		}
	} else {
		if (IN6_IS_ADDR_V4MAPPED(v6group)) {
			ipaddr_t v4group;

			IN6_V4MAPPED_TO_IPADDR(v6group, v4group);
			ASSERT(!IS_UNDER_IPMP(ill));
			if (!CLASSD(v4group)) {
				*errorp = EINVAL;
				return (NULL);
			}
		} else if (!IN6_IS_ADDR_UNSPECIFIED(v6group)) {
			*errorp = EINVAL;
			return (NULL);
		}
	}

	if (IS_UNDER_IPMP(ill)) {
		*errorp = EINVAL;
		return (NULL);
	}

	rw_enter(&ill->ill_mcast_lock, RW_WRITER);
	/*
	 * We do the equivalent of a lookup by checking after we get the lock
	 * This is needed since the ill could have been condemned after
	 * we looked it up, and we need to check condemned after we hold
	 * ill_mcast_lock to synchronize with the unplumb code.
	 */
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		rw_exit(&ill->ill_mcast_lock);
		*errorp = ENXIO;
		return (NULL);
	}
	ilm = ip_addmulti_impl(v6group, ill, zoneid, ilgstat, ilg_fmode,
	    ilg_flist, errorp);
	rw_exit(&ill->ill_mcast_lock);

	ill_mcast_timer_start(ill->ill_ipst);
	return (ilm);
}

static ilm_t *
ip_addmulti_impl(const in6_addr_t *v6group, ill_t *ill, zoneid_t zoneid,
    ilg_stat_t ilgstat, mcast_record_t ilg_fmode, slist_t *ilg_flist,
    int *errorp)
{
	ilm_t	*ilm;
	int	ret = 0;

	ASSERT(RW_WRITE_HELD(&ill->ill_mcast_lock));
	*errorp = 0;

	/*
	 * An ilm is uniquely identified by the tuple of (group, ill) where
	 * `group' is the multicast group address, and `ill' is the interface
	 * on which it is currently joined.
	 */

	ilm = ilm_lookup(ill, v6group, zoneid);
	if (ilm != NULL) {
		/* ilm_update_add bumps ilm_refcnt unless ILGSTAT_CHANGE */
		ret = ilm_update_add(ilm, ilgstat, ilg_flist);
		if (ret == 0)
			return (ilm);

		*errorp = ret;
		return (NULL);
	}

	/*
	 * The callers checks on the ilg and the ilg+ilm consistency under
	 * ill_mcast_serializer ensures that we can not have ILGSTAT_CHANGE
	 * and no ilm.
	 */
	ASSERT(ilgstat != ILGSTAT_CHANGE);
	ilm = ilm_add(ill, v6group, ilgstat, ilg_fmode, ilg_flist, zoneid);
	if (ilm == NULL) {
		*errorp = ENOMEM;
		return (NULL);
	}

	if (IN6_IS_ADDR_UNSPECIFIED(v6group)) {
		/*
		 * If we have more then one we should not tell the driver
		 * to join this time.
		 */
		if (ilm_numentries(ill, v6group) == 1) {
			ret = ill_join_allmulti(ill);
		}
	} else {
		if (!IS_LOOPBACK(ill)) {
			if (ill->ill_isv6)
				mld_joingroup(ilm);
			else
				igmp_joingroup(ilm);
		}

		/*
		 * If we have more then one we should not tell the driver
		 * to join this time.
		 */
		if (ilm_numentries(ill, v6group) == 1) {
			ret = ip_ll_multireq(ill, v6group, DL_ENABMULTI_REQ);
		}
	}
	if (ret != 0) {
		if (ret == ENETDOWN) {
			char buf[INET6_ADDRSTRLEN];

			ip0dbg(("ip_addmulti: ENETDOWN for %s on %s",
			    inet_ntop(AF_INET6, &ilm->ilm_v6addr,
			    buf, sizeof (buf)), ill->ill_name));
		}
		ilm_delete(ilm);
		*errorp = ret;
		return (NULL);
	} else {
		return (ilm);
	}
}

/*
 * Looks up the list of multicast physical addresses this interface
 * listens to. Add to the list if not present already.
 */
boolean_t
ip_mphysaddr_add(ill_t *ill, uchar_t *hw_addr)
{
	multiphysaddr_t *mpa = NULL;
	int	hw_addr_length = ill->ill_phys_addr_length;

	mutex_enter(&ill->ill_lock);
	for (mpa = ill->ill_mphysaddr_list; mpa != NULL; mpa = mpa->mpa_next) {
		if (bcmp(hw_addr, &(mpa->mpa_addr[0]), hw_addr_length) == 0) {
			mpa->mpa_refcnt++;
			mutex_exit(&ill->ill_lock);
			return (B_FALSE);
		}
	}

	mpa = kmem_zalloc(sizeof (multiphysaddr_t), KM_NOSLEEP);
	if (mpa == NULL) {
		/*
		 * We risk not having the multiphysadd structure. At this
		 * point we can't fail. We can't afford to not send a
		 * DL_ENABMULTI_REQ also. It is better than pre-allocating
		 * the structure and having the code to track it also.
		 */
		ip0dbg(("ip_mphysaddr_add: ENOMEM. Some multicast apps"
		    " may have issues. hw_addr: %p ill_name: %s\n",
		    (void *)hw_addr, ill->ill_name));
		mutex_exit(&ill->ill_lock);
		return (B_TRUE);
	}
	bcopy(hw_addr, &(mpa->mpa_addr[0]), hw_addr_length);
	mpa->mpa_refcnt = 1;
	mpa->mpa_next = ill->ill_mphysaddr_list;
	ill->ill_mphysaddr_list = mpa;
	mutex_exit(&ill->ill_lock);
	return (B_TRUE);
}

/*
 * Look up hw_addr from the list of physical multicast addresses this interface
 * listens to.
 * Remove the entry if the refcnt is 0
 */
boolean_t
ip_mphysaddr_del(ill_t *ill, uchar_t *hw_addr)
{
	multiphysaddr_t *mpap = NULL, **mpapp = NULL;
	int hw_addr_length = ill->ill_phys_addr_length;
	boolean_t ret = B_FALSE;

	mutex_enter(&ill->ill_lock);
	for (mpapp = &ill->ill_mphysaddr_list; (mpap = *mpapp) != NULL;
	    mpapp = &(mpap->mpa_next)) {
		if (bcmp(hw_addr, &(mpap->mpa_addr[0]), hw_addr_length) == 0)
			break;
	}
	if (mpap == NULL) {
		/*
		 * Should be coming here only when there was a memory
		 * exhaustion and we were not able to allocate
		 * a multiphysaddr_t. We still send a DL_DISABMULTI_REQ down.
		 */

		ip0dbg(("ip_mphysaddr_del: No entry for this addr. Some "
		    "multicast apps might have had issues. hw_addr: %p "
		    " ill_name: %s\n", (void *)hw_addr, ill->ill_name));
		ret = B_TRUE;
	} else if (--mpap->mpa_refcnt == 0) {
		*mpapp = mpap->mpa_next;
		kmem_free(mpap, sizeof (multiphysaddr_t));
		ret = B_TRUE;
	}
	mutex_exit(&ill->ill_lock);
	return (ret);
}

/*
 * Send a multicast request to the driver for enabling or disabling
 * multicast reception for v6groupp address. The caller has already
 * checked whether it is appropriate to send one or not.
 *
 * For IPMP we switch to the cast_ill since it has the right hardware
 * information.
 */
static int
ip_ll_send_multireq(ill_t *ill, const in6_addr_t *v6groupp, t_uscalar_t prim)
{
	mblk_t	*mp;
	uint32_t addrlen, addroff;
	ill_t *release_ill = NULL;
	uchar_t *cp;
	int err = 0;

	ASSERT(RW_LOCK_HELD(&ill->ill_mcast_lock));

	if (IS_IPMP(ill)) {
		/* On the upper IPMP ill. */
		release_ill = ipmp_illgrp_hold_cast_ill(ill->ill_grp);
		if (release_ill == NULL) {
			/*
			 * Avoid sending it down to the ipmpstub.
			 * We will be called again once the members of the
			 * group are in place
			 */
			ip1dbg(("ip_ll_send_multireq: no cast_ill for %s %d\n",
			    ill->ill_name, ill->ill_isv6));
			return (0);
		}
		ill = release_ill;
	}
	/* Create a DL_ENABMULTI_REQ or DL_DISABMULTI_REQ message. */
	mp = ill_create_dl(ill, prim, &addrlen, &addroff);
	if (mp == NULL) {
		err = ENOMEM;
		goto done;
	}

	mp = ndp_mcastreq(ill, v6groupp, addrlen, addroff, mp);
	if (mp == NULL) {
		ip0dbg(("null from ndp_mcastreq(ill %s)\n", ill->ill_name));
		err = ENOMEM;
		goto done;
	}
	cp = mp->b_rptr;

	switch (((union DL_primitives *)cp)->dl_primitive) {
	case DL_ENABMULTI_REQ:
		cp += ((dl_enabmulti_req_t *)cp)->dl_addr_offset;
		if (!ip_mphysaddr_add(ill, cp)) {
			freemsg(mp);
			err = 0;
			goto done;
		}
		mutex_enter(&ill->ill_lock);
		/* Track the state if this is the first enabmulti */
		if (ill->ill_dlpi_multicast_state == IDS_UNKNOWN)
			ill->ill_dlpi_multicast_state = IDS_INPROGRESS;
		mutex_exit(&ill->ill_lock);
		break;
	case DL_DISABMULTI_REQ:
		cp += ((dl_disabmulti_req_t *)cp)->dl_addr_offset;
		if (!ip_mphysaddr_del(ill, cp)) {
			freemsg(mp);
			err = 0;
			goto done;
		}
	}
	ill_dlpi_queue(ill, mp);
done:
	if (release_ill != NULL)
		ill_refrele(release_ill);
	return (err);
}

/*
 * Send a multicast request to the driver for enabling multicast
 * membership for v6group if appropriate.
 */
static int
ip_ll_multireq(ill_t *ill, const in6_addr_t *v6groupp, t_uscalar_t prim)
{
	if (ill->ill_net_type != IRE_IF_RESOLVER ||
	    ill->ill_ipif->ipif_flags & IPIF_POINTOPOINT) {
		ip1dbg(("ip_ll_multireq: not resolver\n"));
		return (0);	/* Must be IRE_IF_NORESOLVER */
	}

	if (ill->ill_phyint->phyint_flags & PHYI_MULTI_BCAST) {
		ip1dbg(("ip_ll_multireq: MULTI_BCAST\n"));
		return (0);
	}
	return (ip_ll_send_multireq(ill, v6groupp, prim));
}

/*
 * Delete the ilm. Used by other parts of IP for the case of no_ilg/leaving
 * being true.
 */
int
ip_delmulti(ilm_t *ilm)
{
	ill_t *ill = ilm->ilm_ill;
	int error;

	/* Acquire serializer to keep assert in ilm_bld_flists happy */
	mutex_enter(&ill->ill_mcast_serializer);
	error = ip_delmulti_serial(ilm, B_TRUE, B_TRUE);
	mutex_exit(&ill->ill_mcast_serializer);
	/*
	 * Now that all locks have been dropped, we can send any
	 * deferred/queued DLPI or IP packets
	 */
	ill_mcast_send_queued(ill);
	ill_dlpi_send_queued(ill);
	return (error);
}


/*
 * Delete the ilm.
 * Assumes ill_mcast_serializer is held by the caller.
 * Caller must send out queued dlpi/multicast packets after dropping
 * all locks.
 */
static int
ip_delmulti_serial(ilm_t *ilm, boolean_t no_ilg, boolean_t leaving)
{
	ill_t *ill = ilm->ilm_ill;
	int ret;

	ASSERT(MUTEX_HELD(&ill->ill_mcast_serializer));
	ASSERT(!(IS_UNDER_IPMP(ill)));

	rw_enter(&ill->ill_mcast_lock, RW_WRITER);
	ret = ip_delmulti_impl(ilm, no_ilg, leaving);
	rw_exit(&ill->ill_mcast_lock);
	ill_mcast_timer_start(ill->ill_ipst);
	return (ret);
}

static int
ip_delmulti_impl(ilm_t *ilm, boolean_t no_ilg, boolean_t leaving)
{
	ill_t *ill = ilm->ilm_ill;
	int error;
	in6_addr_t v6group;

	ASSERT(RW_WRITE_HELD(&ill->ill_mcast_lock));

	/* Update counters */
	if (no_ilg)
		ilm->ilm_no_ilg_cnt--;

	if (leaving)
		ilm->ilm_refcnt--;

	if (ilm->ilm_refcnt > 0)
		return (ilm_update_del(ilm));

	v6group = ilm->ilm_v6addr;

	if (IN6_IS_ADDR_UNSPECIFIED(&ilm->ilm_v6addr)) {
		ilm_delete(ilm);
		/*
		 * If we have some left then one we should not tell the driver
		 * to leave.
		 */
		if (ilm_numentries(ill, &v6group) != 0)
			return (0);

		ill_leave_allmulti(ill);

		return (0);
	}

	if (!IS_LOOPBACK(ill)) {
		if (ill->ill_isv6)
			mld_leavegroup(ilm);
		else
			igmp_leavegroup(ilm);
	}

	ilm_delete(ilm);
	/*
	 * If we have some left then one we should not tell the driver
	 * to leave.
	 */
	if (ilm_numentries(ill, &v6group) != 0)
		return (0);

	error = ip_ll_multireq(ill, &v6group, DL_DISABMULTI_REQ);
	/* We ignore the case when ill_dl_up is not set */
	if (error == ENETDOWN) {
		char buf[INET6_ADDRSTRLEN];

		ip0dbg(("ip_delmulti: ENETDOWN for %s on %s",
		    inet_ntop(AF_INET6, &v6group, buf, sizeof (buf)),
		    ill->ill_name));
	}
	return (error);
}

/*
 * Make the driver pass up all multicast packets.
 */
int
ill_join_allmulti(ill_t *ill)
{
	mblk_t		*promiscon_mp, *promiscoff_mp = NULL;
	uint32_t	addrlen, addroff;
	ill_t		*release_ill = NULL;

	ASSERT(RW_WRITE_HELD(&ill->ill_mcast_lock));

	if (IS_LOOPBACK(ill))
		return (0);

	if (!ill->ill_dl_up) {
		/*
		 * Nobody there. All multicast addresses will be re-joined
		 * when we get the DL_BIND_ACK bringing the interface up.
		 */
		return (ENETDOWN);
	}

	if (IS_IPMP(ill)) {
		/* On the upper IPMP ill. */
		release_ill = ipmp_illgrp_hold_cast_ill(ill->ill_grp);
		if (release_ill == NULL) {
			/*
			 * Avoid sending it down to the ipmpstub.
			 * We will be called again once the members of the
			 * group are in place
			 */
			ip1dbg(("ill_join_allmulti: no cast_ill for %s %d\n",
			    ill->ill_name, ill->ill_isv6));
			return (0);
		}
		ill = release_ill;
		if (!ill->ill_dl_up) {
			ill_refrele(ill);
			return (ENETDOWN);
		}
	}

	/*
	 * Create a DL_PROMISCON_REQ message and send it directly to the DLPI
	 * provider.  We don't need to do this for certain media types for
	 * which we never need to turn promiscuous mode on.  While we're here,
	 * pre-allocate a DL_PROMISCOFF_REQ message to make sure that
	 * ill_leave_allmulti() will not fail due to low memory conditions.
	 */
	if ((ill->ill_net_type == IRE_IF_RESOLVER) &&
	    !(ill->ill_phyint->phyint_flags & PHYI_MULTI_BCAST)) {
		promiscon_mp = ill_create_dl(ill, DL_PROMISCON_REQ,
		    &addrlen, &addroff);
		if (ill->ill_promiscoff_mp == NULL)
			promiscoff_mp = ill_create_dl(ill, DL_PROMISCOFF_REQ,
			    &addrlen, &addroff);
		if (promiscon_mp == NULL ||
		    (ill->ill_promiscoff_mp == NULL && promiscoff_mp == NULL)) {
			freemsg(promiscon_mp);
			freemsg(promiscoff_mp);
			if (release_ill != NULL)
				ill_refrele(release_ill);
			return (ENOMEM);
		}
		if (ill->ill_promiscoff_mp == NULL)
			ill->ill_promiscoff_mp = promiscoff_mp;
		ill_dlpi_queue(ill, promiscon_mp);
	}
	if (release_ill != NULL)
		ill_refrele(release_ill);
	return (0);
}

/*
 * Make the driver stop passing up all multicast packets
 */
void
ill_leave_allmulti(ill_t *ill)
{
	mblk_t	*promiscoff_mp;
	ill_t	*release_ill = NULL;

	ASSERT(RW_WRITE_HELD(&ill->ill_mcast_lock));

	if (IS_LOOPBACK(ill))
		return;

	if (!ill->ill_dl_up) {
		/*
		 * Nobody there. All multicast addresses will be re-joined
		 * when we get the DL_BIND_ACK bringing the interface up.
		 */
		return;
	}

	if (IS_IPMP(ill)) {
		/* On the upper IPMP ill. */
		release_ill = ipmp_illgrp_hold_cast_ill(ill->ill_grp);
		if (release_ill == NULL) {
			/*
			 * Avoid sending it down to the ipmpstub.
			 * We will be called again once the members of the
			 * group are in place
			 */
			ip1dbg(("ill_leave_allmulti: no cast_ill on %s %d\n",
			    ill->ill_name, ill->ill_isv6));
			return;
		}
		ill = release_ill;
		if (!ill->ill_dl_up)
			goto done;
	}

	/*
	 * In the case of IPMP and ill_dl_up not being set when we joined
	 * we didn't allocate a promiscoff_mp. In that case we have
	 * nothing to do when we leave.
	 * Ditto for PHYI_MULTI_BCAST
	 */
	promiscoff_mp = ill->ill_promiscoff_mp;
	if (promiscoff_mp != NULL) {
		ill->ill_promiscoff_mp = NULL;
		ill_dlpi_queue(ill, promiscoff_mp);
	}
done:
	if (release_ill != NULL)
		ill_refrele(release_ill);
}

int
ip_join_allmulti(uint_t ifindex, boolean_t isv6, ip_stack_t *ipst)
{
	ill_t		*ill;
	int		ret;
	ilm_t		*ilm;

	ill = ill_lookup_on_ifindex(ifindex, isv6, ipst);
	if (ill == NULL)
		return (ENODEV);

	/*
	 * The ip_addmulti() function doesn't allow IPMP underlying interfaces
	 * to join allmulti since only the nominated underlying interface in
	 * the group should receive multicast.  We silently succeed to avoid
	 * having to teach IPobs (currently the only caller of this routine)
	 * to ignore failures in this case.
	 */
	if (IS_UNDER_IPMP(ill)) {
		ill_refrele(ill);
		return (0);
	}
	mutex_enter(&ill->ill_lock);
	if (ill->ill_ipallmulti_cnt > 0) {
		/* Already joined */
		ASSERT(ill->ill_ipallmulti_ilm != NULL);
		ill->ill_ipallmulti_cnt++;
		mutex_exit(&ill->ill_lock);
		goto done;
	}
	mutex_exit(&ill->ill_lock);

	ilm = ip_addmulti(&ipv6_all_zeros, ill, ill->ill_zoneid, &ret);
	if (ilm == NULL) {
		ASSERT(ret != 0);
		ill_refrele(ill);
		return (ret);
	}

	mutex_enter(&ill->ill_lock);
	if (ill->ill_ipallmulti_cnt > 0) {
		/* Another thread added it concurrently */
		(void) ip_delmulti(ilm);
		mutex_exit(&ill->ill_lock);
		goto done;
	}
	ASSERT(ill->ill_ipallmulti_ilm == NULL);
	ill->ill_ipallmulti_ilm = ilm;
	ill->ill_ipallmulti_cnt++;
	mutex_exit(&ill->ill_lock);
done:
	ill_refrele(ill);
	return (0);
}

int
ip_leave_allmulti(uint_t ifindex, boolean_t isv6, ip_stack_t *ipst)
{
	ill_t		*ill;
	ilm_t		*ilm;

	ill = ill_lookup_on_ifindex(ifindex, isv6, ipst);
	if (ill == NULL)
		return (ENODEV);

	if (IS_UNDER_IPMP(ill)) {
		ill_refrele(ill);
		return (0);
	}

	mutex_enter(&ill->ill_lock);
	if (ill->ill_ipallmulti_cnt == 0) {
		/* ip_purge_allmulti could have removed them all */
		mutex_exit(&ill->ill_lock);
		goto done;
	}
	ill->ill_ipallmulti_cnt--;
	if (ill->ill_ipallmulti_cnt == 0) {
		/* Last one */
		ilm = ill->ill_ipallmulti_ilm;
		ill->ill_ipallmulti_ilm = NULL;
	} else {
		ilm = NULL;
	}
	mutex_exit(&ill->ill_lock);
	if (ilm != NULL)
		(void) ip_delmulti(ilm);

done:
	ill_refrele(ill);
	return (0);
}

/*
 * Delete the allmulti memberships that were added as part of
 * ip_join_allmulti().
 */
void
ip_purge_allmulti(ill_t *ill)
{
	ilm_t	*ilm;

	ASSERT(IAM_WRITER_ILL(ill));

	mutex_enter(&ill->ill_lock);
	ilm = ill->ill_ipallmulti_ilm;
	ill->ill_ipallmulti_ilm = NULL;
	ill->ill_ipallmulti_cnt = 0;
	mutex_exit(&ill->ill_lock);

	if (ilm != NULL)
		(void) ip_delmulti(ilm);
}

/*
 * Create a dlpi message with room for phys+sap. Later
 * we will strip the sap for those primitives which
 * only need a physical address.
 */
static mblk_t *
ill_create_dl(ill_t *ill, uint32_t dl_primitive,
    uint32_t *addr_lenp, uint32_t *addr_offp)
{
	mblk_t	*mp;
	uint32_t	hw_addr_length;
	char		*cp;
	uint32_t	offset;
	uint32_t	length;
	uint32_t 	size;

	*addr_lenp = *addr_offp = 0;

	hw_addr_length = ill->ill_phys_addr_length;
	if (!hw_addr_length) {
		ip0dbg(("ip_create_dl: hw addr length = 0\n"));
		return (NULL);
	}

	switch (dl_primitive) {
	case DL_ENABMULTI_REQ:
		length = sizeof (dl_enabmulti_req_t);
		size = length + hw_addr_length;
		break;
	case DL_DISABMULTI_REQ:
		length = sizeof (dl_disabmulti_req_t);
		size = length + hw_addr_length;
		break;
	case DL_PROMISCON_REQ:
	case DL_PROMISCOFF_REQ:
		size = length = sizeof (dl_promiscon_req_t);
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

/*
 * Rejoin any groups for which we have ilms.
 *
 * This is only needed for IPMP when the cast_ill changes since that
 * change is invisible to the ilm. Other interface changes are handled
 * by conn_update_ill.
 */
void
ill_recover_multicast(ill_t *ill)
{
	ilm_t	*ilm;
	char    addrbuf[INET6_ADDRSTRLEN];

	ill->ill_need_recover_multicast = 0;

	rw_enter(&ill->ill_mcast_lock, RW_WRITER);
	for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
		/*
		 * If we have more then one ilm for the group (e.g., with
		 * different zoneid) then we should not tell the driver
		 * to join unless this is the first ilm for the group.
		 */
		if (ilm_numentries(ill, &ilm->ilm_v6addr) > 1 &&
		    ilm_lookup(ill, &ilm->ilm_v6addr, ALL_ZONES) != ilm) {
			continue;
		}

		ip1dbg(("ill_recover_multicast: %s\n", inet_ntop(AF_INET6,
		    &ilm->ilm_v6addr, addrbuf, sizeof (addrbuf))));

		if (IN6_IS_ADDR_UNSPECIFIED(&ilm->ilm_v6addr)) {
			(void) ill_join_allmulti(ill);
		} else {
			if (ill->ill_isv6)
				mld_joingroup(ilm);
			else
				igmp_joingroup(ilm);

			(void) ip_ll_multireq(ill, &ilm->ilm_v6addr,
			    DL_ENABMULTI_REQ);
		}
	}
	rw_exit(&ill->ill_mcast_lock);
	/* Send any deferred/queued DLPI or IP packets */
	ill_mcast_send_queued(ill);
	ill_dlpi_send_queued(ill);
	ill_mcast_timer_start(ill->ill_ipst);
}

/*
 * The opposite of ill_recover_multicast() -- leaves all multicast groups
 * that were explicitly joined.
 *
 * This is only needed for IPMP when the cast_ill changes since that
 * change is invisible to the ilm. Other interface changes are handled
 * by conn_update_ill.
 */
void
ill_leave_multicast(ill_t *ill)
{
	ilm_t	*ilm;
	char    addrbuf[INET6_ADDRSTRLEN];

	ill->ill_need_recover_multicast = 1;

	rw_enter(&ill->ill_mcast_lock, RW_WRITER);
	for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
		/*
		 * If we have more then one ilm for the group (e.g., with
		 * different zoneid) then we should not tell the driver
		 * to leave unless this is the first ilm for the group.
		 */
		if (ilm_numentries(ill, &ilm->ilm_v6addr) > 1 &&
		    ilm_lookup(ill, &ilm->ilm_v6addr, ALL_ZONES) != ilm) {
			continue;
		}

		ip1dbg(("ill_leave_multicast: %s\n", inet_ntop(AF_INET6,
		    &ilm->ilm_v6addr, addrbuf, sizeof (addrbuf))));

		if (IN6_IS_ADDR_UNSPECIFIED(&ilm->ilm_v6addr)) {
			ill_leave_allmulti(ill);
		} else {
			if (ill->ill_isv6)
				mld_leavegroup(ilm);
			else
				igmp_leavegroup(ilm);

			(void) ip_ll_multireq(ill, &ilm->ilm_v6addr,
			    DL_DISABMULTI_REQ);
		}
	}
	rw_exit(&ill->ill_mcast_lock);
	/* Send any deferred/queued DLPI or IP packets */
	ill_mcast_send_queued(ill);
	ill_dlpi_send_queued(ill);
	ill_mcast_timer_start(ill->ill_ipst);
}

/*
 * Interface used by IP input/output.
 * Returns true if there is a member on the ill for any zoneid.
 */
boolean_t
ill_hasmembers_v6(ill_t *ill, const in6_addr_t *v6group)
{
	ilm_t		*ilm;

	rw_enter(&ill->ill_mcast_lock, RW_READER);
	ilm = ilm_lookup(ill, v6group, ALL_ZONES);
	rw_exit(&ill->ill_mcast_lock);
	return (ilm != NULL);
}

/*
 * Interface used by IP input/output.
 * Returns true if there is a member on the ill for any zoneid.
 *
 * The group and source can't be INADDR_ANY here so no need to translate to
 * the unspecified IPv6 address.
 */
boolean_t
ill_hasmembers_v4(ill_t *ill, ipaddr_t group)
{
	in6_addr_t	v6group;

	IN6_IPADDR_TO_V4MAPPED(group, &v6group);
	return (ill_hasmembers_v6(ill, &v6group));
}

/*
 * Interface used by IP input/output.
 * Returns true if there is a member on the ill for any zoneid except skipzone.
 */
boolean_t
ill_hasmembers_otherzones_v6(ill_t *ill, const in6_addr_t *v6group,
    zoneid_t skipzone)
{
	ilm_t		*ilm;

	rw_enter(&ill->ill_mcast_lock, RW_READER);
	for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
		if (IN6_ARE_ADDR_EQUAL(&ilm->ilm_v6addr, v6group) &&
		    ilm->ilm_zoneid != skipzone) {
			rw_exit(&ill->ill_mcast_lock);
			return (B_TRUE);
		}
	}
	rw_exit(&ill->ill_mcast_lock);
	return (B_FALSE);
}

/*
 * Interface used by IP input/output.
 * Returns true if there is a member on the ill for any zoneid except skipzone.
 *
 * The group and source can't be INADDR_ANY here so no need to translate to
 * the unspecified IPv6 address.
 */
boolean_t
ill_hasmembers_otherzones_v4(ill_t *ill, ipaddr_t group, zoneid_t skipzone)
{
	in6_addr_t	v6group;

	IN6_IPADDR_TO_V4MAPPED(group, &v6group);
	return (ill_hasmembers_otherzones_v6(ill, &v6group, skipzone));
}

/*
 * Interface used by IP input.
 * Returns the next numerically larger zoneid that has a member. If none exist
 * then returns -1 (ALL_ZONES).
 * The normal usage is for the caller to start with a -1 zoneid (ALL_ZONES)
 * to find the first zoneid which has a member, and then pass that in for
 * subsequent calls until ALL_ZONES is returned.
 *
 * The implementation of ill_hasmembers_nextzone() assumes the ilms
 * are sorted by zoneid for efficiency.
 */
zoneid_t
ill_hasmembers_nextzone_v6(ill_t *ill, const in6_addr_t *v6group,
    zoneid_t zoneid)
{
	ilm_t		*ilm;

	rw_enter(&ill->ill_mcast_lock, RW_READER);
	for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
		if (IN6_ARE_ADDR_EQUAL(&ilm->ilm_v6addr, v6group) &&
		    ilm->ilm_zoneid > zoneid) {
			zoneid = ilm->ilm_zoneid;
			rw_exit(&ill->ill_mcast_lock);
			return (zoneid);
		}
	}
	rw_exit(&ill->ill_mcast_lock);
	return (ALL_ZONES);
}

/*
 * Interface used by IP input.
 * Returns the next numerically larger zoneid that has a member. If none exist
 * then returns -1 (ALL_ZONES).
 *
 * The group and source can't be INADDR_ANY here so no need to translate to
 * the unspecified IPv6 address.
 */
zoneid_t
ill_hasmembers_nextzone_v4(ill_t *ill, ipaddr_t group, zoneid_t zoneid)
{
	in6_addr_t	v6group;

	IN6_IPADDR_TO_V4MAPPED(group, &v6group);

	return (ill_hasmembers_nextzone_v6(ill, &v6group, zoneid));
}

/*
 * Find an ilm matching the ill, group, and zoneid.
 */
static ilm_t *
ilm_lookup(ill_t *ill, const in6_addr_t *v6group, zoneid_t zoneid)
{
	ilm_t	*ilm;

	ASSERT(RW_LOCK_HELD(&ill->ill_mcast_lock));

	for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
		if (!IN6_ARE_ADDR_EQUAL(&ilm->ilm_v6addr, v6group))
			continue;
		if (zoneid != ALL_ZONES && zoneid != ilm->ilm_zoneid)
			continue;

		ASSERT(ilm->ilm_ill == ill);
		return (ilm);
	}
	return (NULL);
}

/*
 * How many members on this ill?
 * Since each shared-IP zone has a separate ilm for the same group/ill
 * we can have several.
 */
static int
ilm_numentries(ill_t *ill, const in6_addr_t *v6group)
{
	ilm_t	*ilm;
	int i = 0;

	ASSERT(RW_LOCK_HELD(&ill->ill_mcast_lock));
	for (ilm = ill->ill_ilm; ilm; ilm = ilm->ilm_next) {
		if (IN6_ARE_ADDR_EQUAL(&ilm->ilm_v6addr, v6group)) {
			i++;
		}
	}
	return (i);
}

/* Caller guarantees that the group is not already on the list */
static ilm_t *
ilm_add(ill_t *ill, const in6_addr_t *v6group, ilg_stat_t ilgstat,
    mcast_record_t ilg_fmode, slist_t *ilg_flist, zoneid_t zoneid)
{
	ilm_t	*ilm;
	ilm_t	*ilm_cur;
	ilm_t	**ilm_ptpn;

	ASSERT(RW_WRITE_HELD(&ill->ill_mcast_lock));
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

	ilm->ilm_ill = ill;
	DTRACE_PROBE3(ill__incr__cnt, (ill_t *), ill,
	    (char *), "ilm", (void *), ilm);
	ill->ill_ilm_cnt++;

	ASSERT(ill->ill_ipst);
	ilm->ilm_ipst = ill->ill_ipst;	/* No netstack_hold */

	/* The ill/ipif could have just been marked as condemned */

	/*
	 * To make ill_hasmembers_nextzone_v6 work we keep the list
	 * sorted by zoneid.
	 */
	ilm_cur = ill->ill_ilm;
	ilm_ptpn = &ill->ill_ilm;
	while (ilm_cur != NULL && ilm_cur->ilm_zoneid < ilm->ilm_zoneid) {
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

/*
 * Unlink ilm and free it.
 */
static void
ilm_delete(ilm_t *ilm)
{
	ill_t		*ill = ilm->ilm_ill;
	ilm_t		**ilmp;
	boolean_t	need_wakeup;

	/*
	 * Delete under lock protection so that readers don't stumble
	 * on bad ilm_next
	 */
	ASSERT(RW_WRITE_HELD(&ill->ill_mcast_lock));

	for (ilmp = &ill->ill_ilm; *ilmp != ilm; ilmp = &(*ilmp)->ilm_next)
		;

	*ilmp = ilm->ilm_next;

	mutex_enter(&ill->ill_lock);
	/*
	 * if we are the last reference to the ill, we may need to wakeup any
	 * pending FREE or unplumb operations. This is because conn_update_ill
	 * bails if there is a ilg_delete_all in progress.
	 */
	need_wakeup = B_FALSE;
	DTRACE_PROBE3(ill__decr__cnt, (ill_t *), ill,
	    (char *), "ilm", (void *), ilm);
	ASSERT(ill->ill_ilm_cnt > 0);
	ill->ill_ilm_cnt--;
	if (ILL_FREE_OK(ill))
		need_wakeup = B_TRUE;

	ilm_inactive(ilm); /* frees this ilm */

	if (need_wakeup) {
		/* drops ill lock */
		ipif_ill_refrele_tail(ill);
	} else {
		mutex_exit(&ill->ill_lock);
	}
}

/*
 * Lookup an ill based on the group, ifindex, ifaddr, and zoneid.
 * Applies to both IPv4 and IPv6, although ifaddr is only used with
 * IPv4.
 * Returns an error for IS_UNDER_IPMP and VNI interfaces.
 * On error it sets *errorp.
 */
static ill_t *
ill_mcast_lookup(const in6_addr_t *group, ipaddr_t ifaddr, uint_t ifindex,
    zoneid_t zoneid, ip_stack_t *ipst, int *errorp)
{
	ill_t *ill;
	ipaddr_t v4group;

	if (IN6_IS_ADDR_V4MAPPED(group)) {
		IN6_V4MAPPED_TO_IPADDR(group, v4group);

		if (ifindex != 0) {
			ill = ill_lookup_on_ifindex_zoneid(ifindex, zoneid,
			    B_FALSE, ipst);
		} else if (ifaddr != INADDR_ANY) {
			ipif_t *ipif;

			ipif = ipif_lookup_addr(ifaddr, NULL, zoneid, ipst);
			if (ipif == NULL) {
				ill = NULL;
			} else {
				ill = ipif->ipif_ill;
				ill_refhold(ill);
				ipif_refrele(ipif);
			}
		} else {
			ill = ill_lookup_group_v4(v4group, zoneid, ipst, NULL,
			    NULL);
		}
	} else {
		if (ifindex != 0) {
			ill = ill_lookup_on_ifindex_zoneid(ifindex, zoneid,
			    B_TRUE, ipst);
		} else {
			ill = ill_lookup_group_v6(group, zoneid, ipst, NULL,
			    NULL);
		}
	}
	if (ill == NULL) {
		if (ifindex != 0)
			*errorp = ENXIO;
		else
			*errorp = EADDRNOTAVAIL;
		return (NULL);
	}
	/* operation not supported on the virtual network interface */
	if (IS_UNDER_IPMP(ill) || IS_VNI(ill)) {
		ill_refrele(ill);
		*errorp = EINVAL;
		return (NULL);
	}
	return (ill);
}

/*
 * Looks up the appropriate ill given an interface index (or interface address)
 * and multicast group.  On success, returns 0, with *illpp pointing to the
 * found struct.  On failure, returns an errno and *illpp is set to NULL.
 *
 * Returns an error for IS_UNDER_IPMP and VNI interfaces.
 *
 * Handles both IPv4 and IPv6. The ifaddr argument only applies in the
 * case of IPv4.
 */
int
ip_opt_check(conn_t *connp, const in6_addr_t *v6group,
    const in6_addr_t *v6src, ipaddr_t ifaddr, uint_t ifindex, ill_t **illpp)
{
	boolean_t src_unspec;
	ill_t *ill = NULL;
	ip_stack_t *ipst = connp->conn_netstack->netstack_ip;
	int error = 0;

	*illpp = NULL;

	src_unspec = IN6_IS_ADDR_UNSPECIFIED(v6src);

	if (IN6_IS_ADDR_V4MAPPED(v6group)) {
		ipaddr_t v4group;
		ipaddr_t v4src;

		if (!IN6_IS_ADDR_V4MAPPED(v6src) && !src_unspec)
			return (EINVAL);
		IN6_V4MAPPED_TO_IPADDR(v6group, v4group);
		if (src_unspec) {
			v4src = INADDR_ANY;
		} else {
			IN6_V4MAPPED_TO_IPADDR(v6src, v4src);
		}
		if (!CLASSD(v4group) || CLASSD(v4src))
			return (EINVAL);
	} else {
		if (IN6_IS_ADDR_V4MAPPED(v6src) && !src_unspec)
			return (EINVAL);
		if (!IN6_IS_ADDR_MULTICAST(v6group) ||
		    IN6_IS_ADDR_MULTICAST(v6src)) {
			return (EINVAL);
		}
	}

	ill = ill_mcast_lookup(v6group, ifaddr, ifindex, IPCL_ZONEID(connp),
	    ipst, &error);
	*illpp = ill;
	return (error);
}

static int
ip_get_srcfilter(conn_t *connp, struct group_filter *gf,
    struct ip_msfilter *imsf, const struct in6_addr *group, boolean_t issin6)
{
	ilg_t *ilg;
	int i, numsrc, fmode, outsrcs;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct in_addr *addrp;
	slist_t *fp;
	boolean_t is_v4only_api;
	ipaddr_t ifaddr;
	uint_t ifindex;

	if (gf == NULL) {
		ASSERT(imsf != NULL);
		ASSERT(!issin6);
		is_v4only_api = B_TRUE;
		outsrcs = imsf->imsf_numsrc;
		ifaddr = imsf->imsf_interface.s_addr;
		ifindex = 0;
	} else {
		ASSERT(imsf == NULL);
		is_v4only_api = B_FALSE;
		outsrcs = gf->gf_numsrc;
		ifaddr = INADDR_ANY;
		ifindex = gf->gf_interface;
	}

	/* No need to use ill_mcast_serializer for the reader */
	rw_enter(&connp->conn_ilg_lock, RW_READER);
	ilg = ilg_lookup(connp, group, ifaddr, ifindex);
	if (ilg == NULL) {
		rw_exit(&connp->conn_ilg_lock);
		return (EADDRNOTAVAIL);
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
			if (issin6) {
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

	rw_exit(&connp->conn_ilg_lock);

	return (0);
}

/*
 * Common for IPv4 and IPv6.
 */
static int
ip_set_srcfilter(conn_t *connp, struct group_filter *gf,
    struct ip_msfilter *imsf, const struct in6_addr *group, ill_t *ill,
    boolean_t issin6)
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
	boolean_t leave_group, is_v4only_api;
	ilg_stat_t ilgstat;
	ilm_t *ilm;
	ipaddr_t ifaddr;
	uint_t ifindex;

	if (gf == NULL) {
		ASSERT(imsf != NULL);
		ASSERT(!issin6);
		is_v4only_api = B_TRUE;
		insrcs = imsf->imsf_numsrc;
		infmode = imsf->imsf_fmode;
		ifaddr = imsf->imsf_interface.s_addr;
		ifindex = 0;
	} else {
		ASSERT(imsf == NULL);
		is_v4only_api = B_FALSE;
		insrcs = gf->gf_numsrc;
		infmode = gf->gf_fmode;
		ifaddr = INADDR_ANY;
		ifindex = gf->gf_interface;
	}

	/* Make sure we can handle the source list */
	if (insrcs > MAX_FILTER_SIZE)
		return (ENOBUFS);

	/*
	 * setting the filter to (INCLUDE, NULL) is treated
	 * as a request to leave the group.
	 */
	leave_group = (infmode == MCAST_INCLUDE && insrcs == 0);

	mutex_enter(&ill->ill_mcast_serializer);
	rw_enter(&connp->conn_ilg_lock, RW_WRITER);
	ilg = ilg_lookup(connp, group, ifaddr, ifindex);
	if (ilg == NULL) {
		/*
		 * if the request was actually to leave, and we
		 * didn't find an ilg, there's nothing to do.
		 */
		if (leave_group) {
			rw_exit(&connp->conn_ilg_lock);
			mutex_exit(&ill->ill_mcast_serializer);
			return (0);
		}
		ilg = conn_ilg_alloc(connp, &err);
		if (ilg == NULL) {
			rw_exit(&connp->conn_ilg_lock);
			mutex_exit(&ill->ill_mcast_serializer);
			return (err);
		}
		ilgstat = ILGSTAT_NEW;
		ilg->ilg_v6group = *group;
		ilg->ilg_ill = ill;
		ilg->ilg_ifaddr = ifaddr;
		ilg->ilg_ifindex = ifindex;
	} else if (leave_group) {
		/*
		 * Make sure we have the correct serializer. The ill argument
		 * might not match ilg_ill.
		 */
		ilg_refhold(ilg);
		mutex_exit(&ill->ill_mcast_serializer);
		ill = ilg->ilg_ill;
		rw_exit(&connp->conn_ilg_lock);

		mutex_enter(&ill->ill_mcast_serializer);
		rw_enter(&connp->conn_ilg_lock, RW_WRITER);
		ilm = ilg->ilg_ilm;
		ilg->ilg_ilm = NULL;
		ilg_delete(connp, ilg, NULL);
		ilg_refrele(ilg);
		rw_exit(&connp->conn_ilg_lock);
		if (ilm != NULL)
			(void) ip_delmulti_serial(ilm, B_FALSE, B_TRUE);
		mutex_exit(&ill->ill_mcast_serializer);
		/*
		 * Now that all locks have been dropped, we can send any
		 * deferred/queued DLPI or IP packets
		 */
		ill_mcast_send_queued(ill);
		ill_dlpi_send_queued(ill);
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
				rw_exit(&connp->conn_ilg_lock);
				mutex_exit(&ill->ill_mcast_serializer);
				return (ENOMEM);
			}
		}
	}

	/*
	 * Alloc buffer to copy new state into (see below) before
	 * we make any changes, so we can bail if it fails.
	 */
	if ((new_filter = l_alloc()) == NULL) {
		rw_exit(&connp->conn_ilg_lock);
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
				rw_exit(&connp->conn_ilg_lock);
				err = ENOMEM;
				goto free_and_exit;
			}
		} else {
			fp = ilg->ilg_filter;
		}
		for (i = 0; i < insrcs; i++) {
			if (issin6) {
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
	 * so we can release conn_ilg_lock now.
	 */
	new_fmode = ilg->ilg_fmode;
	l_copy(ilg->ilg_filter, new_filter);

	rw_exit(&connp->conn_ilg_lock);

	/*
	 * Now update the ill. We wait to do this until after the ilg
	 * has been updated because we need to update the src filter
	 * info for the ill, which involves looking at the status of
	 * all the ilgs associated with this group/interface pair.
	 */
	ilm = ip_addmulti_serial(group, ill, connp->conn_zoneid, ilgstat,
	    new_fmode, new_filter, &err);

	rw_enter(&connp->conn_ilg_lock, RW_WRITER);
	/*
	 * Must look up the ilg again since we've not been holding
	 * conn_ilg_lock. The ilg could have disappeared due to an unplumb
	 * having called conn_update_ill, which can run once we dropped the
	 * conn_ilg_lock above.
	 */
	ilg = ilg_lookup(connp, group, ifaddr, ifindex);
	if (ilg == NULL) {
		rw_exit(&connp->conn_ilg_lock);
		if (ilm != NULL) {
			(void) ip_delmulti_serial(ilm, B_FALSE,
			    (ilgstat == ILGSTAT_NEW));
		}
		err = ENXIO;
		goto free_and_exit;
	}

	if (ilm != NULL) {
		if (ilg->ilg_ill == NULL) {
			/* some other thread is re-attaching this.  */
			rw_exit(&connp->conn_ilg_lock);
			(void) ip_delmulti_serial(ilm, B_FALSE,
			    (ilgstat == ILGSTAT_NEW));
			err = 0;
			goto free_and_exit;
		}
		/* Succeeded. Update the ilg to point at the ilm */
		if (ilgstat == ILGSTAT_NEW) {
			if (ilg->ilg_ilm == NULL) {
				ilg->ilg_ilm = ilm;
				ilm->ilm_ifaddr = ifaddr; /* For netstat */
			} else {
				/* some other thread is re-attaching this. */
				rw_exit(&connp->conn_ilg_lock);
				(void) ip_delmulti_serial(ilm, B_FALSE, B_TRUE);
				err = 0;
				goto free_and_exit;
			}
		} else {
			/*
			 * ip_addmulti didn't get a held ilm for
			 * ILGSTAT_CHANGE; ilm_refcnt was unchanged.
			 */
			ASSERT(ilg->ilg_ilm == ilm);
		}
	} else {
		ASSERT(err != 0);
		/*
		 * Failed to allocate the ilm.
		 * Restore the original filter state, or delete the
		 * newly-created ilg.
		 * If ENETDOWN just clear ill_ilg since so that we
		 * will rejoin when the ill comes back; don't report ENETDOWN
		 * to application.
		 */
		if (ilgstat == ILGSTAT_NEW) {
			if (err == ENETDOWN) {
				ilg->ilg_ill = NULL;
				err = 0;
			} else {
				ilg_delete(connp, ilg, NULL);
			}
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
	}
	rw_exit(&connp->conn_ilg_lock);

free_and_exit:
	mutex_exit(&ill->ill_mcast_serializer);
	ill_mcast_send_queued(ill);
	ill_dlpi_send_queued(ill);
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
	ipaddr_t v4group;
	in6_addr_t v6group;
	struct group_filter *gf = NULL;
	struct ip_msfilter *imsf = NULL;
	mblk_t *ndp;
	ill_t *ill;

	connp = Q_TO_CONN(q);
	err = ip_msfilter_ill(connp, mp, ipip, &ill);
	if (err != 0)
		return (err);

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

	if (isv6) {
		gsin6 = (struct sockaddr_in6 *)&gf->gf_group;
		v6group = gsin6->sin6_addr;
		if (getcmd) {
			err = ip_get_srcfilter(connp, gf, NULL, &v6group,
			    B_TRUE);
		} else {
			err = ip_set_srcfilter(connp, gf, NULL, &v6group, ill,
			    B_TRUE);
		}
	} else {
		boolean_t issin6 = B_FALSE;
		if (is_v4only_api) {
			v4group = (ipaddr_t)imsf->imsf_multiaddr.s_addr;
			IN6_IPADDR_TO_V4MAPPED(v4group, &v6group);
		} else {
			if (gf->gf_group.ss_family == AF_INET) {
				gsin = (struct sockaddr_in *)&gf->gf_group;
				v4group = (ipaddr_t)gsin->sin_addr.s_addr;
				IN6_IPADDR_TO_V4MAPPED(v4group, &v6group);
			} else {
				gsin6 = (struct sockaddr_in6 *)&gf->gf_group;
				IN6_V4MAPPED_TO_IPADDR(&gsin6->sin6_addr,
				    v4group);
				issin6 = B_TRUE;
			}
		}
		/*
		 * INADDR_ANY is represented as the IPv6 unspecifed addr.
		 */
		if (v4group == INADDR_ANY)
			v6group = ipv6_all_zeros;
		else
			IN6_IPADDR_TO_V4MAPPED(v4group, &v6group);

		if (getcmd) {
			err = ip_get_srcfilter(connp, gf, imsf, &v6group,
			    issin6);
		} else {
			err = ip_set_srcfilter(connp, gf, imsf, &v6group, ill,
			    issin6);
		}
	}
	ill_refrele(ill);

	return (err);
}

/*
 * Determine the ill for the SIOC*MSFILTER ioctls
 *
 * Returns an error for IS_UNDER_IPMP interfaces.
 *
 * Finds the ill based on information in the ioctl headers.
 */
static int
ip_msfilter_ill(conn_t *connp, mblk_t *mp, const ip_ioctl_cmd_t *ipip,
    ill_t **illp)
{
	int cmd = ipip->ipi_cmd;
	int err = 0;
	ill_t *ill;
	/* caller has verified this mblk exists */
	char *dbuf = (char *)mp->b_cont->b_cont->b_rptr;
	struct ip_msfilter *imsf;
	struct group_filter *gf;
	ipaddr_t v4addr, v4group;
	in6_addr_t v6group;
	uint32_t index;
	ip_stack_t *ipst;

	ipst = connp->conn_netstack->netstack_ip;

	*illp = NULL;

	/* don't allow multicast operations on a tcp conn */
	if (IPCL_IS_TCP(connp))
		return (ENOPROTOOPT);

	if (cmd == SIOCSIPMSFILTER || cmd == SIOCGIPMSFILTER) {
		/* don't allow v4-specific ioctls on v6 socket */
		if (connp->conn_family == AF_INET6)
			return (EAFNOSUPPORT);

		imsf = (struct ip_msfilter *)dbuf;
		v4addr = imsf->imsf_interface.s_addr;
		v4group = imsf->imsf_multiaddr.s_addr;
		IN6_IPADDR_TO_V4MAPPED(v4group, &v6group);
		ill = ill_mcast_lookup(&v6group, v4addr, 0, IPCL_ZONEID(connp),
		    ipst, &err);
		if (ill == NULL && v4addr != INADDR_ANY)
			err = ENXIO;
	} else {
		gf = (struct group_filter *)dbuf;
		index = gf->gf_interface;
		if (gf->gf_group.ss_family == AF_INET6) {
			struct sockaddr_in6 *sin6;

			sin6 = (struct sockaddr_in6 *)&gf->gf_group;
			v6group = sin6->sin6_addr;
		} else if (gf->gf_group.ss_family == AF_INET) {
			struct sockaddr_in *sin;

			sin = (struct sockaddr_in *)&gf->gf_group;
			v4group = sin->sin_addr.s_addr;
			IN6_IPADDR_TO_V4MAPPED(v4group, &v6group);
		} else {
			return (EAFNOSUPPORT);
		}
		ill = ill_mcast_lookup(&v6group, INADDR_ANY, index,
		    IPCL_ZONEID(connp), ipst, &err);
	}
	*illp = ill;
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
 *	IPV6_JOIN_GROUP			must not have joined already
 *	MCAST_JOIN_GROUP		must not have joined already
 *	IP_BLOCK_SOURCE			must have joined already
 *	MCAST_BLOCK_SOURCE		must have joined already
 *	IP_JOIN_SOURCE_GROUP		may have joined already
 *	MCAST_JOIN_SOURCE_GROUP		may have joined already
 *
 * fmode and src parameters may be used to determine which option is
 * being set, as follows (IPV6_JOIN_GROUP and MCAST_JOIN_GROUP options
 * are functionally equivalent):
 *	opt			fmode			v6src
 *	IP_ADD_MEMBERSHIP	MODE_IS_EXCLUDE		unspecified
 *	IPV6_JOIN_GROUP		MODE_IS_EXCLUDE		unspecified
 *	MCAST_JOIN_GROUP	MODE_IS_EXCLUDE		unspecified
 *	IP_BLOCK_SOURCE		MODE_IS_EXCLUDE		IPv4-mapped addr
 *	MCAST_BLOCK_SOURCE	MODE_IS_EXCLUDE		v6 addr
 *	IP_JOIN_SOURCE_GROUP	MODE_IS_INCLUDE		IPv4-mapped addr
 *	MCAST_JOIN_SOURCE_GROUP	MODE_IS_INCLUDE		v6 addr
 *
 * Changing the filter mode is not allowed; if a matching ilg already
 * exists and fmode != ilg->ilg_fmode, EINVAL is returned.
 *
 * Verifies that there is a source address of appropriate scope for
 * the group; if not, EADDRNOTAVAIL is returned.
 *
 * The interface to be used may be identified by an IPv4 address or by an
 * interface index.
 *
 * Handles IPv4-mapped IPv6 multicast addresses by associating them
 * with the IPv4 address.  Assumes that if v6group is v4-mapped,
 * v6src is also v4-mapped.
 */
int
ip_opt_add_group(conn_t *connp, boolean_t checkonly,
    const in6_addr_t *v6group, ipaddr_t ifaddr, uint_t ifindex,
    mcast_record_t fmode, const in6_addr_t *v6src)
{
	ill_t *ill;
	char buf[INET6_ADDRSTRLEN];
	int	err;

	err = ip_opt_check(connp, v6group, v6src, ifaddr, ifindex, &ill);
	if (err != 0) {
		ip1dbg(("ip_opt_add_group: no ill for group %s/"
		    "index %d\n", inet_ntop(AF_INET6, v6group, buf,
		    sizeof (buf)), ifindex));
		return (err);
	}

	if (checkonly) {
		/*
		 * do not do operation, just pretend to - new T_CHECK
		 * semantics. The error return case above if encountered
		 * considered a good enough "check" here.
		 */
		ill_refrele(ill);
		return (0);
	}
	mutex_enter(&ill->ill_mcast_serializer);
	/*
	 * Multicast groups may not be joined on interfaces that are either
	 * already underlying interfaces in an IPMP group, or in the process
	 * of joining the IPMP group. The latter condition is enforced by
	 * checking the value of ill->ill_grp_pending under the
	 * ill_mcast_serializer lock.  We cannot serialize the
	 * ill_grp_pending check on the ill_g_lock across ilg_add() because
	 *  ill_mcast_send_queued -> ip_output_simple -> ill_lookup_on_ifindex
	 * will take the ill_g_lock itself. Instead, we hold the
	 * ill_mcast_serializer.
	 */
	if (ill->ill_grp_pending || IS_UNDER_IPMP(ill)) {
		DTRACE_PROBE2(group__add__on__under, ill_t *, ill,
		    in6_addr_t *, v6group);
		mutex_exit(&ill->ill_mcast_serializer);
		ill_refrele(ill);
		return (EADDRNOTAVAIL);
	}
	err = ilg_add(connp, v6group, ifaddr, ifindex, ill, fmode, v6src);
	mutex_exit(&ill->ill_mcast_serializer);
	/*
	 * We have done an addmulti_impl and/or delmulti_impl.
	 * All locks have been dropped, we can send any
	 * deferred/queued DLPI or IP packets
	 */
	ill_mcast_send_queued(ill);
	ill_dlpi_send_queued(ill);
	ill_refrele(ill);
	return (err);
}

/*
 * Common for IPv6 and IPv4.
 * Here we handle ilgs that are still attached to their original ill
 * (the one ifaddr/ifindex points at), as well as detached ones.
 * The detached ones might have been attached to some other ill.
 */
static int
ip_opt_delete_group_excl(conn_t *connp, const in6_addr_t *v6group,
    ipaddr_t ifaddr, uint_t ifindex, mcast_record_t fmode,
    const in6_addr_t *v6src)
{
	ilg_t	*ilg;
	boolean_t leaving;
	ilm_t *ilm;
	ill_t *ill;
	int err = 0;

retry:
	rw_enter(&connp->conn_ilg_lock, RW_WRITER);
	ilg = ilg_lookup(connp, v6group, ifaddr, ifindex);
	if (ilg == NULL) {
		rw_exit(&connp->conn_ilg_lock);
		/*
		 * Since we didn't have any ilg we now do the error checks
		 * to determine the best errno.
		 */
		err = ip_opt_check(connp, v6group, v6src, ifaddr, ifindex,
		    &ill);
		if (ill != NULL) {
			/* The only error was a missing ilg for the group */
			ill_refrele(ill);
			err = EADDRNOTAVAIL;
		}
		return (err);
	}

	/* If the ilg is attached then we serialize using that ill */
	ill = ilg->ilg_ill;
	if (ill != NULL) {
		/* Prevent the ill and ilg from being freed */
		ill_refhold(ill);
		ilg_refhold(ilg);
		rw_exit(&connp->conn_ilg_lock);
		mutex_enter(&ill->ill_mcast_serializer);
		rw_enter(&connp->conn_ilg_lock, RW_WRITER);
		if (ilg->ilg_condemned) {
			/* Disappeared */
			ilg_refrele(ilg);
			rw_exit(&connp->conn_ilg_lock);
			mutex_exit(&ill->ill_mcast_serializer);
			ill_refrele(ill);
			goto retry;
		}
	}

	/*
	 * Decide if we're actually deleting the ilg or just removing a
	 * source filter address; if just removing an addr, make sure we
	 * aren't trying to change the filter mode, and that the addr is
	 * actually in our filter list already.  If we're removing the
	 * last src in an include list, just delete the ilg.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(v6src)) {
		leaving = B_TRUE;
	} else {
		if (fmode != ilg->ilg_fmode)
			err = EINVAL;
		else if (ilg->ilg_filter == NULL ||
		    !list_has_addr(ilg->ilg_filter, v6src))
			err = EADDRNOTAVAIL;
		if (err != 0) {
			if (ill != NULL)
				ilg_refrele(ilg);
			rw_exit(&connp->conn_ilg_lock);
			goto done;
		}
		if (fmode == MODE_IS_INCLUDE &&
		    ilg->ilg_filter->sl_numsrc == 1) {
			leaving = B_TRUE;
			v6src = NULL;
		} else {
			leaving = B_FALSE;
		}
	}
	ilm = ilg->ilg_ilm;
	if (leaving)
		ilg->ilg_ilm = NULL;

	ilg_delete(connp, ilg, v6src);
	if (ill != NULL)
		ilg_refrele(ilg);
	rw_exit(&connp->conn_ilg_lock);

	if (ilm != NULL) {
		ASSERT(ill != NULL);
		(void) ip_delmulti_serial(ilm, B_FALSE, leaving);
	}
done:
	if (ill != NULL) {
		mutex_exit(&ill->ill_mcast_serializer);
		/*
		 * Now that all locks have been dropped, we can
		 * send any deferred/queued DLPI or IP packets
		 */
		ill_mcast_send_queued(ill);
		ill_dlpi_send_queued(ill);
		ill_refrele(ill);
	}
	return (err);
}

/*
 * Handle the following optmgmt:
 *	IP_DROP_MEMBERSHIP		will leave
 *	IPV6_LEAVE_GROUP		will leave
 *	MCAST_LEAVE_GROUP		will leave
 *	IP_UNBLOCK_SOURCE		will not leave
 *	MCAST_UNBLOCK_SOURCE		will not leave
 *	IP_LEAVE_SOURCE_GROUP		may leave (if leaving last source)
 *	MCAST_LEAVE_SOURCE_GROUP	may leave (if leaving last source)
 *
 * fmode and src parameters may be used to determine which option is
 * being set, as follows:
 *	opt			 fmode			v6src
 *	IP_DROP_MEMBERSHIP	 MODE_IS_INCLUDE	unspecified
 *	IPV6_LEAVE_GROUP	 MODE_IS_INCLUDE	unspecified
 *	MCAST_LEAVE_GROUP	 MODE_IS_INCLUDE	unspecified
 *	IP_UNBLOCK_SOURCE	 MODE_IS_EXCLUDE	IPv4-mapped addr
 *	MCAST_UNBLOCK_SOURCE	 MODE_IS_EXCLUDE	v6 addr
 *	IP_LEAVE_SOURCE_GROUP	 MODE_IS_INCLUDE	IPv4-mapped addr
 *	MCAST_LEAVE_SOURCE_GROUP MODE_IS_INCLUDE	v6 addr
 *
 * Changing the filter mode is not allowed; if a matching ilg already
 * exists and fmode != ilg->ilg_fmode, EINVAL is returned.
 *
 * The interface to be used may be identified by an IPv4 address or by an
 * interface index.
 *
 * Handles IPv4-mapped IPv6 multicast addresses by associating them
 * with the IPv4 address.  Assumes that if v6group is v4-mapped,
 * v6src is also v4-mapped.
 */
int
ip_opt_delete_group(conn_t *connp, boolean_t checkonly,
    const in6_addr_t *v6group, ipaddr_t ifaddr, uint_t ifindex,
    mcast_record_t fmode, const in6_addr_t *v6src)
{

	/*
	 * In the normal case below we don't check for the ill existing.
	 * Instead we look for an existing ilg in _excl.
	 * If checkonly we sanity check the arguments
	 */
	if (checkonly) {
		ill_t	*ill;
		int	err;

		err = ip_opt_check(connp, v6group, v6src, ifaddr, ifindex,
		    &ill);
		/*
		 * do not do operation, just pretend to - new T_CHECK semantics.
		 * ip_opt_check is considered a good enough "check" here.
		 */
		if (ill != NULL)
			ill_refrele(ill);
		return (err);
	}
	return (ip_opt_delete_group_excl(connp, v6group, ifaddr, ifindex,
	    fmode, v6src));
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
 * Common for IPv4 and IPv6; for IPv4 we can have an ifaddr.
 */
static int
ilg_add(conn_t *connp, const in6_addr_t *v6group, ipaddr_t ifaddr,
    uint_t ifindex, ill_t *ill, mcast_record_t fmode, const in6_addr_t *v6src)
{
	int	error = 0;
	ilg_t	*ilg;
	ilg_stat_t ilgstat;
	slist_t	*new_filter = NULL;
	int	new_fmode;
	ilm_t *ilm;

	if (!(ill->ill_flags & ILLF_MULTICAST))
		return (EADDRNOTAVAIL);

	/* conn_ilg_lock protects the ilg list. */
	ASSERT(MUTEX_HELD(&ill->ill_mcast_serializer));
	rw_enter(&connp->conn_ilg_lock, RW_WRITER);
	ilg = ilg_lookup(connp, v6group, ifaddr, ifindex);

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
		rw_exit(&connp->conn_ilg_lock);
		return (error);
	}

	/*
	 * Alloc buffer to copy new state into (see below) before
	 * we make any changes, so we can bail if it fails.
	 */
	if ((new_filter = l_alloc()) == NULL) {
		rw_exit(&connp->conn_ilg_lock);
		return (ENOMEM);
	}

	if (ilg == NULL) {
		if ((ilg = conn_ilg_alloc(connp, &error)) == NULL) {
			rw_exit(&connp->conn_ilg_lock);
			l_free(new_filter);
			return (error);
		}
		ilg->ilg_ifindex = ifindex;
		ilg->ilg_ifaddr = ifaddr;
		if (!IN6_IS_ADDR_UNSPECIFIED(v6src)) {
			ilg->ilg_filter = l_alloc();
			if (ilg->ilg_filter == NULL) {
				ilg_delete(connp, ilg, NULL);
				rw_exit(&connp->conn_ilg_lock);
				l_free(new_filter);
				return (ENOMEM);
			}
			ilg->ilg_filter->sl_numsrc = 1;
			ilg->ilg_filter->sl_addr[0] = *v6src;
		}
		ilgstat = ILGSTAT_NEW;
		ilg->ilg_v6group = *v6group;
		ilg->ilg_fmode = fmode;
		ilg->ilg_ill = ill;
	} else {
		int index;

		if (ilg->ilg_fmode != fmode || IN6_IS_ADDR_UNSPECIFIED(v6src)) {
			rw_exit(&connp->conn_ilg_lock);
			l_free(new_filter);
			return (EINVAL);
		}
		if (ilg->ilg_filter == NULL) {
			ilg->ilg_filter = l_alloc();
			if (ilg->ilg_filter == NULL) {
				rw_exit(&connp->conn_ilg_lock);
				l_free(new_filter);
				return (ENOMEM);
			}
		}
		if (list_has_addr(ilg->ilg_filter, v6src)) {
			rw_exit(&connp->conn_ilg_lock);
			l_free(new_filter);
			return (EADDRNOTAVAIL);
		}
		ilgstat = ILGSTAT_CHANGE;
		index = ilg->ilg_filter->sl_numsrc++;
		ilg->ilg_filter->sl_addr[index] = *v6src;
	}

	/*
	 * Save copy of ilg's filter state to pass to other functions,
	 * so we can release conn_ilg_lock now.
	 */
	new_fmode = ilg->ilg_fmode;
	l_copy(ilg->ilg_filter, new_filter);

	rw_exit(&connp->conn_ilg_lock);

	/*
	 * Now update the ill. We wait to do this until after the ilg
	 * has been updated because we need to update the src filter
	 * info for the ill, which involves looking at the status of
	 * all the ilgs associated with this group/interface pair.
	 */
	ilm = ip_addmulti_serial(v6group, ill, connp->conn_zoneid, ilgstat,
	    new_fmode, new_filter, &error);

	rw_enter(&connp->conn_ilg_lock, RW_WRITER);
	/*
	 * Must look up the ilg again since we've not been holding
	 * conn_ilg_lock. The ilg could have disappeared due to an unplumb
	 * having called conn_update_ill, which can run once we dropped the
	 * conn_ilg_lock above.
	 */
	ilg = ilg_lookup(connp, v6group, ifaddr, ifindex);
	if (ilg == NULL) {
		rw_exit(&connp->conn_ilg_lock);
		if (ilm != NULL) {
			(void) ip_delmulti_serial(ilm, B_FALSE,
			    (ilgstat == ILGSTAT_NEW));
		}
		error = ENXIO;
		goto free_and_exit;
	}
	if (ilm != NULL) {
		if (ilg->ilg_ill == NULL) {
			/* some other thread is re-attaching this.  */
			rw_exit(&connp->conn_ilg_lock);
			(void) ip_delmulti_serial(ilm, B_FALSE,
			    (ilgstat == ILGSTAT_NEW));
			error = 0;
			goto free_and_exit;
		}
		/* Succeeded. Update the ilg to point at the ilm */
		if (ilgstat == ILGSTAT_NEW) {
			if (ilg->ilg_ilm == NULL) {
				ilg->ilg_ilm = ilm;
				ilm->ilm_ifaddr = ifaddr; /* For netstat */
			} else {
				/* some other thread is re-attaching this. */
				rw_exit(&connp->conn_ilg_lock);
				(void) ip_delmulti_serial(ilm, B_FALSE, B_TRUE);
				error = 0;
				goto free_and_exit;
			}
		} else {
			/*
			 * ip_addmulti didn't get a held ilm for
			 * ILGSTAT_CHANGE; ilm_refcnt was unchanged.
			 */
			ASSERT(ilg->ilg_ilm == ilm);
		}
	} else {
		ASSERT(error != 0);
		/*
		 * Failed to allocate the ilm.
		 * Need to undo what we did before calling ip_addmulti()
		 * If ENETDOWN just clear ill_ilg since so that we
		 * will rejoin when the ill comes back; don't report ENETDOWN
		 * to application.
		 */
		if (ilgstat == ILGSTAT_NEW && error == ENETDOWN) {
			ilg->ilg_ill = NULL;
			error = 0;
		} else {
			in6_addr_t delsrc =
			    (ilgstat == ILGSTAT_NEW) ? ipv6_all_zeros : *v6src;

			ilg_delete(connp, ilg, &delsrc);
		}
	}
	rw_exit(&connp->conn_ilg_lock);

free_and_exit:
	l_free(new_filter);
	return (error);
}

/*
 * Find an IPv4 ilg matching group, ill and source.
 * The group and source can't be INADDR_ANY here so no need to translate to
 * the unspecified IPv6 address.
 */
boolean_t
conn_hasmembers_ill_withsrc_v4(conn_t *connp, ipaddr_t group, ipaddr_t src,
    ill_t *ill)
{
	in6_addr_t v6group, v6src;
	int i;
	boolean_t isinlist;
	ilg_t *ilg;

	rw_enter(&connp->conn_ilg_lock, RW_READER);
	IN6_IPADDR_TO_V4MAPPED(group, &v6group);
	for (ilg = connp->conn_ilg; ilg != NULL; ilg = ilg->ilg_next) {
		if (ilg->ilg_condemned)
			continue;

		/* ilg_ill could be NULL if an add is in progress */
		if (ilg->ilg_ill != ill)
			continue;

		/* The callers use upper ill for IPMP */
		ASSERT(!IS_UNDER_IPMP(ill));
		if (IN6_ARE_ADDR_EQUAL(&ilg->ilg_v6group, &v6group)) {
			if (SLIST_IS_EMPTY(ilg->ilg_filter)) {
				/* no source filter, so this is a match */
				rw_exit(&connp->conn_ilg_lock);
				return (B_TRUE);
			}
			break;
		}
	}
	if (ilg == NULL) {
		rw_exit(&connp->conn_ilg_lock);
		return (B_FALSE);
	}

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
	    (!isinlist && ilg->ilg_fmode == MODE_IS_EXCLUDE)) {
		rw_exit(&connp->conn_ilg_lock);
		return (B_TRUE);
	}
	rw_exit(&connp->conn_ilg_lock);
	return (B_FALSE);
}

/*
 * Find an IPv6 ilg matching group, ill, and source
 */
boolean_t
conn_hasmembers_ill_withsrc_v6(conn_t *connp, const in6_addr_t *v6group,
    const in6_addr_t *v6src, ill_t *ill)
{
	int i;
	boolean_t isinlist;
	ilg_t *ilg;

	rw_enter(&connp->conn_ilg_lock, RW_READER);
	for (ilg = connp->conn_ilg; ilg != NULL; ilg = ilg->ilg_next) {
		if (ilg->ilg_condemned)
			continue;

		/* ilg_ill could be NULL if an add is in progress */
		if (ilg->ilg_ill != ill)
			continue;

		/* The callers use upper ill for IPMP */
		ASSERT(!IS_UNDER_IPMP(ill));
		if (IN6_ARE_ADDR_EQUAL(&ilg->ilg_v6group, v6group)) {
			if (SLIST_IS_EMPTY(ilg->ilg_filter)) {
				/* no source filter, so this is a match */
				rw_exit(&connp->conn_ilg_lock);
				return (B_TRUE);
			}
			break;
		}
	}
	if (ilg == NULL) {
		rw_exit(&connp->conn_ilg_lock);
		return (B_FALSE);
	}

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
	    (!isinlist && ilg->ilg_fmode == MODE_IS_EXCLUDE)) {
		rw_exit(&connp->conn_ilg_lock);
		return (B_TRUE);
	}
	rw_exit(&connp->conn_ilg_lock);
	return (B_FALSE);
}

/*
 * Find an ilg matching group and ifaddr/ifindex.
 * We check both ifaddr and ifindex even though at most one of them
 * will be non-zero; that way we always find the right one.
 */
static ilg_t *
ilg_lookup(conn_t *connp, const in6_addr_t *v6group, ipaddr_t ifaddr,
    uint_t ifindex)
{
	ilg_t	*ilg;

	ASSERT(RW_LOCK_HELD(&connp->conn_ilg_lock));

	for (ilg = connp->conn_ilg; ilg != NULL; ilg = ilg->ilg_next) {
		if (ilg->ilg_condemned)
			continue;

		if (ilg->ilg_ifaddr == ifaddr &&
		    ilg->ilg_ifindex == ifindex &&
		    IN6_ARE_ADDR_EQUAL(&ilg->ilg_v6group, v6group))
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
	ASSERT(RW_WRITE_HELD(&connp->conn_ilg_lock));
	ASSERT(ilg->ilg_ptpn != NULL);
	ASSERT(!ilg->ilg_condemned);

	if (src == NULL || IN6_IS_ADDR_UNSPECIFIED(src)) {
		FREE_SLIST(ilg->ilg_filter);
		ilg->ilg_filter = NULL;

		ASSERT(ilg->ilg_ilm == NULL);
		ilg->ilg_ill = NULL;
		ilg->ilg_condemned = B_TRUE;

		/* ilg_inactive will unlink from the list */
		ilg_refrele(ilg);
	} else {
		l_remove(ilg->ilg_filter, src);
	}
}

/*
 * Called from conn close. No new ilg can be added or removed
 * because CONN_CLOSING has been set by ip_close. ilg_add / ilg_delete
 * will return error if conn has started closing.
 *
 * We handle locking as follows.
 * Under conn_ilg_lock we get the first ilg. As we drop the conn_ilg_lock to
 * proceed with the ilm part of the delete we hold a reference on both the ill
 * and the ilg. This doesn't prevent changes to the ilg, but prevents it from
 * being deleted.
 *
 * Since the ilg_add code path uses two locks (conn_ilg_lock for the ilg part,
 * and ill_mcast_lock for the ip_addmulti part) we can run at a point between
 * the two. At that point ilg_ill is set, but ilg_ilm hasn't yet been set. In
 * that case we delete the ilg here, which makes ilg_add discover that the ilg
 * has disappeared when ip_addmulti returns, so it will discard the ilm it just
 * added.
 */
void
ilg_delete_all(conn_t *connp)
{
	ilg_t	*ilg, *next_ilg, *held_ilg;
	ilm_t	*ilm;
	ill_t	*ill;
	boolean_t need_refrele;

	/*
	 * Can not run if there is a conn_update_ill already running.
	 * Wait for it to complete. Caller should have already set CONN_CLOSING
	 * which prevents any new threads to run in conn_update_ill.
	 */
	mutex_enter(&connp->conn_lock);
	ASSERT(connp->conn_state_flags & CONN_CLOSING);
	while (connp->conn_state_flags & CONN_UPDATE_ILL)
		cv_wait(&connp->conn_cv, &connp->conn_lock);
	mutex_exit(&connp->conn_lock);

	rw_enter(&connp->conn_ilg_lock, RW_WRITER);
	ilg = connp->conn_ilg;
	held_ilg = NULL;
	while (ilg != NULL) {
		if (ilg->ilg_condemned) {
			ilg = ilg->ilg_next;
			continue;
		}
		/* If the ilg is detached then no need to serialize */
		if (ilg->ilg_ilm == NULL) {
			next_ilg = ilg->ilg_next;
			ilg_delete(connp, ilg, NULL);
			ilg = next_ilg;
			continue;
		}
		ill = ilg->ilg_ilm->ilm_ill;

		/*
		 * In order to serialize on the ill we try to enter
		 * and if that fails we unlock and relock and then
		 * check that we still have an ilm.
		 */
		need_refrele = B_FALSE;
		if (!mutex_tryenter(&ill->ill_mcast_serializer)) {
			ill_refhold(ill);
			need_refrele = B_TRUE;
			ilg_refhold(ilg);
			if (held_ilg != NULL)
				ilg_refrele(held_ilg);
			held_ilg = ilg;
			rw_exit(&connp->conn_ilg_lock);
			mutex_enter(&ill->ill_mcast_serializer);
			rw_enter(&connp->conn_ilg_lock, RW_WRITER);
			if (ilg->ilg_condemned) {
				ilg = ilg->ilg_next;
				goto next;
			}
		}
		ilm = ilg->ilg_ilm;
		ilg->ilg_ilm = NULL;
		next_ilg = ilg->ilg_next;
		ilg_delete(connp, ilg, NULL);
		ilg = next_ilg;
		rw_exit(&connp->conn_ilg_lock);

		if (ilm != NULL)
			(void) ip_delmulti_serial(ilm, B_FALSE, B_TRUE);

	next:
		mutex_exit(&ill->ill_mcast_serializer);
		/*
		 * Now that all locks have been dropped, we can send any
		 * deferred/queued DLPI or IP packets
		 */
		ill_mcast_send_queued(ill);
		ill_dlpi_send_queued(ill);
		if (need_refrele) {
			/* Drop ill reference while we hold no locks */
			ill_refrele(ill);
		}
		rw_enter(&connp->conn_ilg_lock, RW_WRITER);
	}
	if (held_ilg != NULL)
		ilg_refrele(held_ilg);
	rw_exit(&connp->conn_ilg_lock);
}

/*
 * Attach the ilg to an ilm on the ill. If it fails we leave ilg_ill as NULL so
 * that a subsequent attempt can attach it. Drops and reacquires conn_ilg_lock.
 */
static void
ilg_attach(conn_t *connp, ilg_t *ilg, ill_t *ill)
{
	ilg_stat_t	ilgstat;
	slist_t		*new_filter;
	int		new_fmode;
	in6_addr_t	v6group;
	ipaddr_t	ifaddr;
	uint_t		ifindex;
	ilm_t		*ilm;
	int		error = 0;

	ASSERT(RW_WRITE_HELD(&connp->conn_ilg_lock));
	/*
	 * Alloc buffer to copy new state into (see below) before
	 * we make any changes, so we can bail if it fails.
	 */
	if ((new_filter = l_alloc()) == NULL)
		return;

	/*
	 * Save copy of ilg's filter state to pass to other functions, so
	 * we can release conn_ilg_lock now.
	 * Set ilg_ill so that an unplumb can find us.
	 */
	new_fmode = ilg->ilg_fmode;
	l_copy(ilg->ilg_filter, new_filter);
	v6group = ilg->ilg_v6group;
	ifaddr = ilg->ilg_ifaddr;
	ifindex = ilg->ilg_ifindex;
	ilgstat = ILGSTAT_NEW;

	ilg->ilg_ill = ill;
	ASSERT(ilg->ilg_ilm == NULL);
	rw_exit(&connp->conn_ilg_lock);

	ilm = ip_addmulti_serial(&v6group, ill, connp->conn_zoneid, ilgstat,
	    new_fmode, new_filter, &error);
	l_free(new_filter);

	rw_enter(&connp->conn_ilg_lock, RW_WRITER);
	/*
	 * Must look up the ilg again since we've not been holding
	 * conn_ilg_lock. The ilg could have disappeared due to an unplumb
	 * having called conn_update_ill, which can run once we dropped the
	 * conn_ilg_lock above. Alternatively, the ilg could have been attached
	 * when the lock was dropped
	 */
	ilg = ilg_lookup(connp, &v6group, ifaddr, ifindex);
	if (ilg == NULL || ilg->ilg_ilm != NULL) {
		if (ilm != NULL) {
			rw_exit(&connp->conn_ilg_lock);
			(void) ip_delmulti_serial(ilm, B_FALSE,
			    (ilgstat == ILGSTAT_NEW));
			rw_enter(&connp->conn_ilg_lock, RW_WRITER);
		}
		return;
	}
	if (ilm == NULL) {
		ilg->ilg_ill = NULL;
		return;
	}
	ilg->ilg_ilm = ilm;
	ilm->ilm_ifaddr = ifaddr;	/* For netstat */
}

/*
 * Called when an ill is unplumbed to make sure that there are no
 * dangling conn references to that ill. In that case ill is non-NULL and
 * we make sure we remove all references to it.
 * Also called when we should revisit the ilg_ill used for multicast
 * memberships, in which case ill is NULL.
 *
 * conn is held by caller.
 *
 * Note that ipcl_walk only walks conns that are not yet condemned.
 * condemned conns can't be refheld. For this reason, conn must become clean
 * first, i.e. it must not refer to any ill/ire and then only set
 * condemned flag.
 *
 * We leave ixa_multicast_ifindex in place. We prefer dropping
 * packets instead of sending them out the wrong interface.
 *
 * We keep the ilg around in a detached state (with ilg_ill and ilg_ilm being
 * NULL) so that the application can leave it later. Also, if ilg_ifaddr and
 * ilg_ifindex are zero, indicating that the system should pick the interface,
 * then we attempt to reselect the ill and join on it.
 *
 * Locking notes:
 * Under conn_ilg_lock we get the first ilg. As we drop the conn_ilg_lock to
 * proceed with the ilm part of the delete we hold a reference on both the ill
 * and the ilg. This doesn't prevent changes to the ilg, but prevents it from
 * being deleted.
 *
 * Note: if this function is called when new ill/ipif's arrive or change status
 * (SIOCSLIFINDEX, SIOCSLIFADDR) then we will attempt to attach any ilgs with
 * a NULL ilg_ill to an ill/ilm.
 */
static void
conn_update_ill(conn_t *connp, caddr_t arg)
{
	ill_t	*ill = (ill_t *)arg;

	/*
	 * We have to prevent ip_close/ilg_delete_all from running at
	 * the same time. ip_close sets CONN_CLOSING before doing the ilg_delete
	 * all, and we set CONN_UPDATE_ILL. That ensures that only one of
	 * ilg_delete_all and conn_update_ill run at a time for a given conn.
	 * If ilg_delete_all got here first, then we have nothing to do.
	 */
	mutex_enter(&connp->conn_lock);
	if (connp->conn_state_flags & (CONN_CLOSING|CONN_UPDATE_ILL)) {
		/* Caller has to wait for ill_ilm_cnt to drop to zero */
		mutex_exit(&connp->conn_lock);
		return;
	}
	connp->conn_state_flags |= CONN_UPDATE_ILL;
	mutex_exit(&connp->conn_lock);

	if (ill != NULL)
		ilg_check_detach(connp, ill);

	ilg_check_reattach(connp, ill);

	/* Do we need to wake up a thread in ilg_delete_all? */
	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_UPDATE_ILL;
	if (connp->conn_state_flags & CONN_CLOSING)
		cv_broadcast(&connp->conn_cv);
	mutex_exit(&connp->conn_lock);
}

/* Detach from an ill that is going away */
static void
ilg_check_detach(conn_t *connp, ill_t *ill)
{
	char	group_buf[INET6_ADDRSTRLEN];
	ilg_t	*ilg, *held_ilg;
	ilm_t	*ilm;

	mutex_enter(&ill->ill_mcast_serializer);
	rw_enter(&connp->conn_ilg_lock, RW_WRITER);
	held_ilg = NULL;
	for (ilg = connp->conn_ilg; ilg != NULL; ilg = ilg->ilg_next) {
		if (ilg->ilg_condemned)
			continue;

		if (ilg->ilg_ill != ill)
			continue;

		/* Detach from current ill */
		ip1dbg(("ilg_check_detach: detach %s on %s\n",
		    inet_ntop(AF_INET6, &ilg->ilg_v6group,
		    group_buf, sizeof (group_buf)),
		    ilg->ilg_ill->ill_name));

		/* Detach this ilg from the ill/ilm */
		ilm = ilg->ilg_ilm;
		ilg->ilg_ilm = NULL;
		ilg->ilg_ill = NULL;
		if (ilm == NULL)
			continue;

		/* Prevent ilg from disappearing */
		ilg_transfer_hold(held_ilg, ilg);
		held_ilg = ilg;
		rw_exit(&connp->conn_ilg_lock);

		(void) ip_delmulti_serial(ilm, B_FALSE, B_TRUE);
		rw_enter(&connp->conn_ilg_lock, RW_WRITER);
	}
	if (held_ilg != NULL)
		ilg_refrele(held_ilg);
	rw_exit(&connp->conn_ilg_lock);
	mutex_exit(&ill->ill_mcast_serializer);
	/*
	 * Now that all locks have been dropped, we can send any
	 * deferred/queued DLPI or IP packets
	 */
	ill_mcast_send_queued(ill);
	ill_dlpi_send_queued(ill);
}

/*
 * Check if there is a place to attach the conn_ilgs. We do this for both
 * detached ilgs and attached ones, since for the latter there could be
 * a better ill to attach them to. oill is non-null if we just detached from
 * that ill.
 */
static void
ilg_check_reattach(conn_t *connp, ill_t *oill)
{
	ill_t	*ill;
	char	group_buf[INET6_ADDRSTRLEN];
	ilg_t	*ilg, *held_ilg;
	ilm_t	*ilm;
	zoneid_t zoneid = IPCL_ZONEID(connp);
	int	error;
	ip_stack_t *ipst = connp->conn_netstack->netstack_ip;

	rw_enter(&connp->conn_ilg_lock, RW_WRITER);
	held_ilg = NULL;
	for (ilg = connp->conn_ilg; ilg != NULL; ilg = ilg->ilg_next) {
		if (ilg->ilg_condemned)
			continue;

		/* Check if the conn_ill matches what we would pick now */
		ill = ill_mcast_lookup(&ilg->ilg_v6group, ilg->ilg_ifaddr,
		    ilg->ilg_ifindex, zoneid, ipst, &error);

		/*
		 * Make sure the ill is usable for multicast and that
		 * we can send the DL_ADDMULTI_REQ before we create an
		 * ilm.
		 */
		if (ill != NULL &&
		    (!(ill->ill_flags & ILLF_MULTICAST) || !ill->ill_dl_up)) {
			/* Drop locks across ill_refrele */
			ilg_transfer_hold(held_ilg, ilg);
			held_ilg = ilg;
			rw_exit(&connp->conn_ilg_lock);
			ill_refrele(ill);
			ill = NULL;
			rw_enter(&connp->conn_ilg_lock, RW_WRITER);
			/* Note that ilg could have become condemned */
		}

		/*
		 * Is the ill unchanged, even if both are NULL?
		 * Did we just detach from that ill?
		 */
		if (ill == ilg->ilg_ill || (ill != NULL && ill == oill)) {
			if (ill != NULL) {
				/* Drop locks across ill_refrele */
				ilg_transfer_hold(held_ilg, ilg);
				held_ilg = ilg;
				rw_exit(&connp->conn_ilg_lock);
				ill_refrele(ill);
				rw_enter(&connp->conn_ilg_lock, RW_WRITER);
			}
			continue;
		}

		/* Something changed; detach from old first if needed */
		if (ilg->ilg_ill != NULL) {
			ill_t *ill2 = ilg->ilg_ill;
			boolean_t need_refrele = B_FALSE;

			/*
			 * In order to serialize on the ill we try to enter
			 * and if that fails we unlock and relock.
			 */
			if (!mutex_tryenter(&ill2->ill_mcast_serializer)) {
				ill_refhold(ill2);
				need_refrele = B_TRUE;
				ilg_transfer_hold(held_ilg, ilg);
				held_ilg = ilg;
				rw_exit(&connp->conn_ilg_lock);
				mutex_enter(&ill2->ill_mcast_serializer);
				rw_enter(&connp->conn_ilg_lock, RW_WRITER);
				/* Note that ilg could have become condemned */
			}
			/*
			 * Check that nobody else re-attached the ilg while we
			 * dropped the lock.
			 */
			if (ilg->ilg_ill == ill2) {
				ASSERT(!ilg->ilg_condemned);
				/* Detach from current ill */
				ip1dbg(("conn_check_reattach: detach %s/%s\n",
				    inet_ntop(AF_INET6, &ilg->ilg_v6group,
				    group_buf, sizeof (group_buf)),
				    ill2->ill_name));

				ilm = ilg->ilg_ilm;
				ilg->ilg_ilm = NULL;
				ilg->ilg_ill = NULL;
			} else {
				ilm = NULL;
			}
			ilg_transfer_hold(held_ilg, ilg);
			held_ilg = ilg;
			rw_exit(&connp->conn_ilg_lock);
			if (ilm != NULL)
				(void) ip_delmulti_serial(ilm, B_FALSE, B_TRUE);
			mutex_exit(&ill2->ill_mcast_serializer);
			/*
			 * Now that all locks have been dropped, we can send any
			 * deferred/queued DLPI or IP packets
			 */
			ill_mcast_send_queued(ill2);
			ill_dlpi_send_queued(ill2);
			if (need_refrele) {
				/* Drop ill reference while we hold no locks */
				ill_refrele(ill2);
			}
			rw_enter(&connp->conn_ilg_lock, RW_WRITER);
			/*
			 * While we dropped conn_ilg_lock some other thread
			 * could have attached this ilg, thus we check again.
			 */
			if (ilg->ilg_ill != NULL) {
				if (ill != NULL) {
					/* Drop locks across ill_refrele */
					ilg_transfer_hold(held_ilg, ilg);
					held_ilg = ilg;
					rw_exit(&connp->conn_ilg_lock);
					ill_refrele(ill);
					rw_enter(&connp->conn_ilg_lock,
					    RW_WRITER);
				}
				continue;
			}
		}
		if (ill != NULL) {
			/*
			 * In order to serialize on the ill we try to enter
			 * and if that fails we unlock and relock.
			 */
			if (!mutex_tryenter(&ill->ill_mcast_serializer)) {
				/* Already have a refhold on ill */
				ilg_transfer_hold(held_ilg, ilg);
				held_ilg = ilg;
				rw_exit(&connp->conn_ilg_lock);
				mutex_enter(&ill->ill_mcast_serializer);
				rw_enter(&connp->conn_ilg_lock, RW_WRITER);
				/* Note that ilg could have become condemned */
			}
			ilg_transfer_hold(held_ilg, ilg);
			held_ilg = ilg;
			/*
			 * Check that nobody else attached the ilg and that
			 * it wasn't condemned while we dropped the lock.
			 */
			if (ilg->ilg_ill == NULL && !ilg->ilg_condemned) {
				/*
				 * Attach to the new ill. Can fail in which
				 * case ilg_ill will remain NULL. ilg_attach
				 * drops and reacquires conn_ilg_lock.
				 */
				ip1dbg(("conn_check_reattach: attach %s/%s\n",
				    inet_ntop(AF_INET6, &ilg->ilg_v6group,
				    group_buf, sizeof (group_buf)),
				    ill->ill_name));
				ilg_attach(connp, ilg, ill);
				ASSERT(RW_WRITE_HELD(&connp->conn_ilg_lock));
			}
			/* Drop locks across ill_refrele */
			rw_exit(&connp->conn_ilg_lock);
			mutex_exit(&ill->ill_mcast_serializer);
			/*
			 * Now that all locks have been
			 * dropped, we can send any
			 * deferred/queued DLPI or IP packets
			 */
			ill_mcast_send_queued(ill);
			ill_dlpi_send_queued(ill);
			ill_refrele(ill);
			rw_enter(&connp->conn_ilg_lock, RW_WRITER);
		}
	}
	if (held_ilg != NULL)
		ilg_refrele(held_ilg);
	rw_exit(&connp->conn_ilg_lock);
}

/*
 * Called when an ill is unplumbed to make sure that there are no
 * dangling conn references to that ill. In that case ill is non-NULL and
 * we make sure we remove all references to it.
 * Also called when we should revisit the ilg_ill used for multicast
 * memberships, in which case ill is NULL.
 */
void
update_conn_ill(ill_t *ill, ip_stack_t *ipst)
{
	ipcl_walk(conn_update_ill, (caddr_t)ill, ipst);
}
