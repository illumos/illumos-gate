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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016, Joyent, Inc. All rights reserved.
 */

/*
 * iptun - IP Tunneling Driver
 *
 * This module is a GLDv3 driver that implements virtual datalinks over IP
 * (a.k.a, IP tunneling).  The datalinks are managed through a dld ioctl
 * interface (see iptun_ctl.c), and registered with GLDv3 using
 * mac_register().  It implements the logic for various forms of IP (IPv4 or
 * IPv6) encapsulation within IP (IPv4 or IPv6) by interacting with the ip
 * module below it.  Each virtual IP tunnel datalink has a conn_t associated
 * with it representing the "outer" IP connection.
 *
 * The module implements the following locking semantics:
 *
 * Lookups and deletions in iptun_hash are synchronized using iptun_hash_lock.
 * See comments above iptun_hash_lock for details.
 *
 * No locks are ever held while calling up to GLDv3.  The general architecture
 * of GLDv3 requires this, as the mac perimeter (essentially a lock) for a
 * given link will be held while making downcalls (iptun_m_*() callbacks).
 * Because we need to hold locks while handling downcalls, holding these locks
 * while issuing upcalls results in deadlock scenarios.  See the block comment
 * above iptun_task_cb() for details on how we safely issue upcalls without
 * holding any locks.
 *
 * The contents of each iptun_t is protected by an iptun_mutex which is held
 * in iptun_enter() (called by iptun_enter_by_linkid()), and exited in
 * iptun_exit().
 *
 * See comments in iptun_delete() and iptun_free() for details on how the
 * iptun_t is deleted safely.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/modhash.h>
#include <sys/list.h>
#include <sys/strsun.h>
#include <sys/file.h>
#include <sys/systm.h>
#include <sys/tihdr.h>
#include <sys/param.h>
#include <sys/mac_provider.h>
#include <sys/mac_ipv4.h>
#include <sys/mac_ipv6.h>
#include <sys/mac_6to4.h>
#include <sys/tsol/tnet.h>
#include <sys/sunldi.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <inet/ip_ire.h>
#include <inet/ipsec_impl.h>
#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>
#include <inet/iptun.h>
#include "iptun_impl.h"

/* Do the tunnel type and address family match? */
#define	IPTUN_ADDR_MATCH(iptun_type, family)				\
	((iptun_type == IPTUN_TYPE_IPV4 && family == AF_INET) ||	\
	(iptun_type == IPTUN_TYPE_IPV6 && family == AF_INET6) ||	\
	(iptun_type == IPTUN_TYPE_6TO4 && family == AF_INET))

#define	IPTUN_HASH_KEY(key)	((mod_hash_key_t)(uintptr_t)(key))

#define	IPTUN_MIN_IPV4_MTU	576		/* ip.h still uses 68 (!) */
#define	IPTUN_MIN_IPV6_MTU	IPV6_MIN_MTU
#define	IPTUN_MAX_IPV4_MTU	(IP_MAXPACKET - sizeof (ipha_t))
#define	IPTUN_MAX_IPV6_MTU	(IP_MAXPACKET - sizeof (ip6_t) -	\
				    sizeof (iptun_encaplim_t))

#define	IPTUN_MIN_HOPLIMIT	1
#define	IPTUN_MAX_HOPLIMIT	UINT8_MAX

#define	IPTUN_MIN_ENCAPLIMIT	0
#define	IPTUN_MAX_ENCAPLIMIT	UINT8_MAX

#define	IPTUN_IPSEC_REQ_MASK	(IPSEC_PREF_REQUIRED | IPSEC_PREF_NEVER)

static iptun_encaplim_t	iptun_encaplim_init = {
	{ IPPROTO_NONE, 0 },
	IP6OPT_TUNNEL_LIMIT,
	1,
	IPTUN_DEFAULT_ENCAPLIMIT,	/* filled in with actual value later */
	IP6OPT_PADN,
	1,
	0
};

/*
 * Table containing per-iptun-type information.
 * Since IPv6 can run over all of these we have the IPv6 min as the min MTU.
 */
static iptun_typeinfo_t	iptun_type_table[] = {
	{ IPTUN_TYPE_IPV4, MAC_PLUGIN_IDENT_IPV4, IPV4_VERSION,
	    IPTUN_MIN_IPV6_MTU,	IPTUN_MAX_IPV4_MTU,	B_TRUE },
	{ IPTUN_TYPE_IPV6, MAC_PLUGIN_IDENT_IPV6, IPV6_VERSION,
	    IPTUN_MIN_IPV6_MTU,	IPTUN_MAX_IPV6_MTU,	B_TRUE },
	{ IPTUN_TYPE_6TO4, MAC_PLUGIN_IDENT_6TO4, IPV4_VERSION,
	    IPTUN_MIN_IPV6_MTU,	IPTUN_MAX_IPV4_MTU,	B_FALSE },
	{ IPTUN_TYPE_UNKNOWN, NULL, 0, 0, 0, B_FALSE }
};

/*
 * iptun_hash is an iptun_t lookup table by link ID protected by
 * iptun_hash_lock.  While the hash table's integrity is maintained via
 * internal locking in the mod_hash_*() functions, we need additional locking
 * so that an iptun_t cannot be deleted after a hash lookup has returned an
 * iptun_t and before iptun_lock has been entered.  As such, we use
 * iptun_hash_lock when doing lookups and removals from iptun_hash.
 */
mod_hash_t	*iptun_hash;
static kmutex_t	iptun_hash_lock;

static uint_t	iptun_tunnelcount;	/* total for all stacks */
kmem_cache_t	*iptun_cache;
ddi_taskq_t 	*iptun_taskq;

typedef enum {
	IPTUN_TASK_MTU_UPDATE,	/* tell mac about new tunnel link MTU */
	IPTUN_TASK_LADDR_UPDATE, /* tell mac about new local address */
	IPTUN_TASK_RADDR_UPDATE, /* tell mac about new remote address */
	IPTUN_TASK_LINK_UPDATE,	/* tell mac about new link state */
	IPTUN_TASK_PDATA_UPDATE	/* tell mac about updated plugin data */
} iptun_task_t;

typedef struct iptun_task_data_s {
	iptun_task_t	itd_task;
	datalink_id_t	itd_linkid;
} iptun_task_data_t;

static void iptun_task_dispatch(iptun_t *, iptun_task_t);
static int iptun_enter(iptun_t *);
static void iptun_exit(iptun_t *);
static void iptun_headergen(iptun_t *, boolean_t);
static void iptun_drop_pkt(mblk_t *, uint64_t *);
static void iptun_input(void *, mblk_t *, void *, ip_recv_attr_t *);
static void iptun_input_icmp(void *, mblk_t *, void *, ip_recv_attr_t *);
static void iptun_output(iptun_t *, mblk_t *);
static uint32_t iptun_get_maxmtu(iptun_t *, ip_xmit_attr_t *, uint32_t);
static uint32_t iptun_update_mtu(iptun_t *, ip_xmit_attr_t *, uint32_t);
static uint32_t iptun_get_dst_pmtu(iptun_t *, ip_xmit_attr_t *);
static void iptun_update_dst_pmtu(iptun_t *, ip_xmit_attr_t *);
static int iptun_setladdr(iptun_t *, const struct sockaddr_storage *);

static void iptun_output_6to4(iptun_t *, mblk_t *);
static void iptun_output_common(iptun_t *, ip_xmit_attr_t *, mblk_t *);
static boolean_t iptun_verifyicmp(conn_t *, void *, icmph_t *, icmp6_t *,
    ip_recv_attr_t *);

static void iptun_notify(void *, ip_xmit_attr_t *, ixa_notify_type_t,
    ixa_notify_arg_t);

static mac_callbacks_t iptun_m_callbacks;

static int
iptun_m_getstat(void *arg, uint_t stat, uint64_t *val)
{
	iptun_t	*iptun = arg;
	int	err = 0;

	switch (stat) {
	case MAC_STAT_IERRORS:
		*val = iptun->iptun_ierrors;
		break;
	case MAC_STAT_OERRORS:
		*val = iptun->iptun_oerrors;
		break;
	case MAC_STAT_RBYTES:
		*val = iptun->iptun_rbytes;
		break;
	case MAC_STAT_IPACKETS:
		*val = iptun->iptun_ipackets;
		break;
	case MAC_STAT_OBYTES:
		*val = iptun->iptun_obytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = iptun->iptun_opackets;
		break;
	case MAC_STAT_NORCVBUF:
		*val = iptun->iptun_norcvbuf;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = iptun->iptun_noxmtbuf;
		break;
	default:
		err = ENOTSUP;
	}

	return (err);
}

static int
iptun_m_start(void *arg)
{
	iptun_t	*iptun = arg;
	int	err;

	if ((err = iptun_enter(iptun)) == 0) {
		iptun->iptun_flags |= IPTUN_MAC_STARTED;
		iptun_task_dispatch(iptun, IPTUN_TASK_LINK_UPDATE);
		iptun_exit(iptun);
	}
	return (err);
}

static void
iptun_m_stop(void *arg)
{
	iptun_t *iptun = arg;

	if (iptun_enter(iptun) == 0) {
		iptun->iptun_flags &= ~IPTUN_MAC_STARTED;
		iptun_task_dispatch(iptun, IPTUN_TASK_LINK_UPDATE);
		iptun_exit(iptun);
	}
}

/*
 * iptun_m_setpromisc() does nothing and always succeeds.  This is because a
 * tunnel data-link only ever receives packets that are destined exclusively
 * for the local address of the tunnel.
 */
/* ARGSUSED */
static int
iptun_m_setpromisc(void *arg, boolean_t on)
{
	return (0);
}

/* ARGSUSED */
static int
iptun_m_multicst(void *arg, boolean_t add, const uint8_t *addrp)
{
	return (ENOTSUP);
}

/*
 * iptun_m_unicst() sets the local address.
 */
/* ARGSUSED */
static int
iptun_m_unicst(void *arg, const uint8_t *addrp)
{
	iptun_t			*iptun = arg;
	int			err;
	struct sockaddr_storage	ss;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;

	if ((err = iptun_enter(iptun)) == 0) {
		switch (iptun->iptun_typeinfo->iti_ipvers) {
		case IPV4_VERSION:
			sin = (struct sockaddr_in *)&ss;
			sin->sin_family = AF_INET;
			bcopy(addrp, &sin->sin_addr, sizeof (in_addr_t));
			break;
		case IPV6_VERSION:
			sin6 = (struct sockaddr_in6 *)&ss;
			sin6->sin6_family = AF_INET6;
			bcopy(addrp, &sin6->sin6_addr, sizeof (in6_addr_t));
			break;
		default:
			ASSERT(0);
		}
		err = iptun_setladdr(iptun, &ss);
		iptun_exit(iptun);
	}
	return (err);
}

static mblk_t *
iptun_m_tx(void *arg, mblk_t *mpchain)
{
	mblk_t	*mp, *nmp;
	iptun_t	*iptun = arg;

	if (!IS_IPTUN_RUNNING(iptun)) {
		iptun_drop_pkt(mpchain, &iptun->iptun_noxmtbuf);
		return (NULL);
	}

	for (mp = mpchain; mp != NULL; mp = nmp) {
		nmp = mp->b_next;
		mp->b_next = NULL;
		iptun_output(iptun, mp);
	}

	return (NULL);
}

/* ARGSUSED */
static int
iptun_m_setprop(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	iptun_t		*iptun = barg;
	uint32_t	value = *(uint32_t *)pr_val;
	int		err;

	/*
	 * We need to enter this iptun_t since we'll be modifying the outer
	 * header.
	 */
	if ((err = iptun_enter(iptun)) != 0)
		return (err);

	switch (pr_num) {
	case MAC_PROP_IPTUN_HOPLIMIT:
		if (value < IPTUN_MIN_HOPLIMIT || value > IPTUN_MAX_HOPLIMIT) {
			err = EINVAL;
			break;
		}
		if (value != iptun->iptun_hoplimit) {
			iptun->iptun_hoplimit = (uint8_t)value;
			iptun_headergen(iptun, B_TRUE);
		}
		break;
	case MAC_PROP_IPTUN_ENCAPLIMIT:
		if (iptun->iptun_typeinfo->iti_type != IPTUN_TYPE_IPV6 ||
		    value > IPTUN_MAX_ENCAPLIMIT) {
			err = EINVAL;
			break;
		}
		if (value != iptun->iptun_encaplimit) {
			iptun->iptun_encaplimit = (uint8_t)value;
			iptun_headergen(iptun, B_TRUE);
		}
		break;
	case MAC_PROP_MTU: {
		uint32_t maxmtu = iptun_get_maxmtu(iptun, NULL, 0);

		if (value < iptun->iptun_typeinfo->iti_minmtu ||
		    value > maxmtu) {
			err = EINVAL;
			break;
		}
		iptun->iptun_flags |= IPTUN_FIXED_MTU;
		if (value != iptun->iptun_mtu) {
			iptun->iptun_mtu = value;
			iptun_task_dispatch(iptun, IPTUN_TASK_MTU_UPDATE);
		}
		break;
	}
	default:
		err = EINVAL;
	}
	iptun_exit(iptun);
	return (err);
}

/* ARGSUSED */
static int
iptun_m_getprop(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	iptun_t			*iptun = barg;
	int			err;

	if ((err = iptun_enter(iptun)) != 0)
		return (err);

	switch (pr_num) {
	case MAC_PROP_IPTUN_HOPLIMIT:
		ASSERT(pr_valsize >= sizeof (uint32_t));
		*(uint32_t *)pr_val = iptun->iptun_hoplimit;
		break;

	case MAC_PROP_IPTUN_ENCAPLIMIT:
		*(uint32_t *)pr_val = iptun->iptun_encaplimit;
		break;
	default:
		err = ENOTSUP;
	}
done:
	iptun_exit(iptun);
	return (err);
}

/* ARGSUSED */
static void
iptun_m_propinfo(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	iptun_t			*iptun = barg;

	switch (pr_num) {
	case MAC_PROP_IPTUN_HOPLIMIT:
		mac_prop_info_set_range_uint32(prh,
		    IPTUN_MIN_HOPLIMIT, IPTUN_MAX_HOPLIMIT);
		mac_prop_info_set_default_uint32(prh, IPTUN_DEFAULT_HOPLIMIT);
		break;

	case MAC_PROP_IPTUN_ENCAPLIMIT:
		if (iptun->iptun_typeinfo->iti_type != IPTUN_TYPE_IPV6)
			break;
		mac_prop_info_set_range_uint32(prh,
		    IPTUN_MIN_ENCAPLIMIT, IPTUN_MAX_ENCAPLIMIT);
		mac_prop_info_set_default_uint32(prh, IPTUN_DEFAULT_ENCAPLIMIT);
		break;
	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(prh,
		    iptun->iptun_typeinfo->iti_minmtu,
		    iptun_get_maxmtu(iptun, NULL, 0));
		break;
	}
}

uint_t
iptun_count(void)
{
	return (iptun_tunnelcount);
}

/*
 * Enter an iptun_t exclusively.  This is essentially just a mutex, but we
 * don't allow iptun_enter() to succeed on a tunnel if it's in the process of
 * being deleted.
 */
static int
iptun_enter(iptun_t *iptun)
{
	mutex_enter(&iptun->iptun_lock);
	while (iptun->iptun_flags & IPTUN_DELETE_PENDING)
		cv_wait(&iptun->iptun_enter_cv, &iptun->iptun_lock);
	if (iptun->iptun_flags & IPTUN_CONDEMNED) {
		mutex_exit(&iptun->iptun_lock);
		return (ENOENT);
	}
	return (0);
}

/*
 * Exit the tunnel entered in iptun_enter().
 */
static void
iptun_exit(iptun_t *iptun)
{
	mutex_exit(&iptun->iptun_lock);
}

/*
 * Enter the IP tunnel instance by datalink ID.
 */
static int
iptun_enter_by_linkid(datalink_id_t linkid, iptun_t **iptun)
{
	int err;

	mutex_enter(&iptun_hash_lock);
	if (mod_hash_find(iptun_hash, IPTUN_HASH_KEY(linkid),
	    (mod_hash_val_t *)iptun) == 0)
		err = iptun_enter(*iptun);
	else
		err = ENOENT;
	if (err != 0)
		*iptun = NULL;
	mutex_exit(&iptun_hash_lock);
	return (err);
}

/*
 * Handle tasks that were deferred through the iptun_taskq because they require
 * calling up to the mac module, and we can't call up to the mac module while
 * holding locks.
 *
 * This is tricky to get right without introducing race conditions and
 * deadlocks with the mac module, as we cannot issue an upcall while in the
 * iptun_t.  The reason is that upcalls may try and enter the mac perimeter,
 * while iptun callbacks (such as iptun_m_setprop()) called from the mac
 * module will already have the perimeter held, and will then try and enter
 * the iptun_t.  You can see the lock ordering problem with this; this will
 * deadlock.
 *
 * The safe way to do this is to enter the iptun_t in question and copy the
 * information we need out of it so that we can exit it and know that the
 * information being passed up to the upcalls won't be subject to modification
 * by other threads.  The problem now is that we need to exit it prior to
 * issuing the upcall, but once we do this, a thread could come along and
 * delete the iptun_t and thus the mac handle required to issue the upcall.
 * To prevent this, we set the IPTUN_UPCALL_PENDING flag prior to exiting the
 * iptun_t.  This flag is the condition associated with iptun_upcall_cv, which
 * iptun_delete() will cv_wait() on.  When the upcall completes, we clear
 * IPTUN_UPCALL_PENDING and cv_signal() any potentially waiting
 * iptun_delete().  We can thus still safely use iptun->iptun_mh after having
 * exited the iptun_t.
 */
static void
iptun_task_cb(void *arg)
{
	iptun_task_data_t	*itd = arg;
	iptun_task_t		task = itd->itd_task;
	datalink_id_t		linkid = itd->itd_linkid;
	iptun_t			*iptun;
	uint32_t		mtu;
	iptun_addr_t		addr;
	link_state_t		linkstate;
	size_t			header_size;
	iptun_header_t		header;

	kmem_free(itd, sizeof (*itd));

	/*
	 * Note that if the lookup fails, it's because the tunnel was deleted
	 * between the time the task was dispatched and now.  That isn't an
	 * error.
	 */
	if (iptun_enter_by_linkid(linkid, &iptun) != 0)
		return;

	iptun->iptun_flags |= IPTUN_UPCALL_PENDING;

	switch (task) {
	case IPTUN_TASK_MTU_UPDATE:
		mtu = iptun->iptun_mtu;
		break;
	case IPTUN_TASK_LADDR_UPDATE:
		addr = iptun->iptun_laddr;
		break;
	case IPTUN_TASK_RADDR_UPDATE:
		addr = iptun->iptun_raddr;
		break;
	case IPTUN_TASK_LINK_UPDATE:
		linkstate = IS_IPTUN_RUNNING(iptun) ?
		    LINK_STATE_UP : LINK_STATE_DOWN;
		break;
	case IPTUN_TASK_PDATA_UPDATE:
		header_size = iptun->iptun_header_size;
		header = iptun->iptun_header;
		break;
	default:
		ASSERT(0);
	}

	iptun_exit(iptun);

	switch (task) {
	case IPTUN_TASK_MTU_UPDATE:
		(void) mac_maxsdu_update(iptun->iptun_mh, mtu);
		break;
	case IPTUN_TASK_LADDR_UPDATE:
		mac_unicst_update(iptun->iptun_mh, (uint8_t *)&addr.ia_addr);
		break;
	case IPTUN_TASK_RADDR_UPDATE:
		mac_dst_update(iptun->iptun_mh, (uint8_t *)&addr.ia_addr);
		break;
	case IPTUN_TASK_LINK_UPDATE:
		mac_link_update(iptun->iptun_mh, linkstate);
		break;
	case IPTUN_TASK_PDATA_UPDATE:
		if (mac_pdata_update(iptun->iptun_mh,
		    header_size == 0 ? NULL : &header, header_size) != 0)
			atomic_inc_64(&iptun->iptun_taskq_fail);
		break;
	}

	mutex_enter(&iptun->iptun_lock);
	iptun->iptun_flags &= ~IPTUN_UPCALL_PENDING;
	cv_signal(&iptun->iptun_upcall_cv);
	mutex_exit(&iptun->iptun_lock);
}

static void
iptun_task_dispatch(iptun_t *iptun, iptun_task_t iptun_task)
{
	iptun_task_data_t *itd;

	itd = kmem_alloc(sizeof (*itd), KM_NOSLEEP);
	if (itd == NULL) {
		atomic_inc_64(&iptun->iptun_taskq_fail);
		return;
	}
	itd->itd_task = iptun_task;
	itd->itd_linkid = iptun->iptun_linkid;
	if (ddi_taskq_dispatch(iptun_taskq, iptun_task_cb, itd, DDI_NOSLEEP)) {
		atomic_inc_64(&iptun->iptun_taskq_fail);
		kmem_free(itd, sizeof (*itd));
	}
}

/*
 * Convert an iptun_addr_t to sockaddr_storage.
 */
static void
iptun_getaddr(iptun_addr_t *iptun_addr, struct sockaddr_storage *ss)
{
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;

	bzero(ss, sizeof (*ss));
	switch (iptun_addr->ia_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)ss;
		sin->sin_addr.s_addr = iptun_addr->ia_addr.iau_addr4;
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)ss;
		sin6->sin6_addr = iptun_addr->ia_addr.iau_addr6;
		break;
	default:
		ASSERT(0);
	}
	ss->ss_family = iptun_addr->ia_family;
}

/*
 * General purpose function to set an IP tunnel source or destination address.
 */
static int
iptun_setaddr(iptun_type_t iptun_type, iptun_addr_t *iptun_addr,
    const struct sockaddr_storage *ss)
{
	if (!IPTUN_ADDR_MATCH(iptun_type, ss->ss_family))
		return (EINVAL);

	switch (ss->ss_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;

		if ((sin->sin_addr.s_addr == INADDR_ANY) ||
		    (sin->sin_addr.s_addr == INADDR_BROADCAST) ||
		    CLASSD(sin->sin_addr.s_addr)) {
			return (EADDRNOTAVAIL);
		}
		iptun_addr->ia_addr.iau_addr4 = sin->sin_addr.s_addr;
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ||
		    IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr) ||
		    IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			return (EADDRNOTAVAIL);
		}
		iptun_addr->ia_addr.iau_addr6 = sin6->sin6_addr;
		break;
	}
	default:
		return (EAFNOSUPPORT);
	}
	iptun_addr->ia_family = ss->ss_family;
	return (0);
}

static int
iptun_setladdr(iptun_t *iptun, const struct sockaddr_storage *laddr)
{
	return (iptun_setaddr(iptun->iptun_typeinfo->iti_type,
	    &iptun->iptun_laddr, laddr));
}

static int
iptun_setraddr(iptun_t *iptun, const struct sockaddr_storage *raddr)
{
	if (!(iptun->iptun_typeinfo->iti_hasraddr))
		return (EINVAL);
	return (iptun_setaddr(iptun->iptun_typeinfo->iti_type,
	    &iptun->iptun_raddr, raddr));
}

static boolean_t
iptun_canbind(iptun_t *iptun)
{
	/*
	 * A tunnel may bind when its source address has been set, and if its
	 * tunnel type requires one, also its destination address.
	 */
	return ((iptun->iptun_flags & IPTUN_LADDR) &&
	    ((iptun->iptun_flags & IPTUN_RADDR) ||
	    !(iptun->iptun_typeinfo->iti_hasraddr)));
}

/*
 * Verify that the local address is valid, and insert in the fanout
 */
static int
iptun_bind(iptun_t *iptun)
{
	conn_t			*connp = iptun->iptun_connp;
	int			error = 0;
	ip_xmit_attr_t		*ixa;
	ip_xmit_attr_t		*oldixa;
	iulp_t			uinfo;
	ip_stack_t		*ipst = connp->conn_netstack->netstack_ip;

	/*
	 * Get an exclusive ixa for this thread.
	 * We defer updating conn_ixa until later to handle any concurrent
	 * conn_ixa_cleanup thread.
	 */
	ixa = conn_get_ixa(connp, B_FALSE);
	if (ixa == NULL)
		return (ENOMEM);

	/* We create PMTU state including for 6to4 */
	ixa->ixa_flags |= IXAF_PMTU_DISCOVERY;

	ASSERT(iptun_canbind(iptun));

	mutex_enter(&connp->conn_lock);
	/*
	 * Note that conn_proto can't be set since the upper protocol
	 * can be both 41 and 4 when IPv6 and IPv4 are over the same tunnel.
	 * ipcl_iptun_classify doesn't use conn_proto.
	 */
	connp->conn_ipversion = iptun->iptun_typeinfo->iti_ipvers;

	switch (iptun->iptun_typeinfo->iti_type) {
	case IPTUN_TYPE_IPV4:
		IN6_IPADDR_TO_V4MAPPED(iptun->iptun_laddr4,
		    &connp->conn_laddr_v6);
		IN6_IPADDR_TO_V4MAPPED(iptun->iptun_raddr4,
		    &connp->conn_faddr_v6);
		ixa->ixa_flags |= IXAF_IS_IPV4;
		if (ip_laddr_verify_v4(iptun->iptun_laddr4, IPCL_ZONEID(connp),
		    ipst, B_FALSE) != IPVL_UNICAST_UP) {
			mutex_exit(&connp->conn_lock);
			error = EADDRNOTAVAIL;
			goto done;
		}
		break;
	case IPTUN_TYPE_IPV6:
		connp->conn_laddr_v6 = iptun->iptun_laddr6;
		connp->conn_faddr_v6 = iptun->iptun_raddr6;
		ixa->ixa_flags &= ~IXAF_IS_IPV4;
		/* We use a zero scopeid for now */
		if (ip_laddr_verify_v6(&iptun->iptun_laddr6, IPCL_ZONEID(connp),
		    ipst, B_FALSE, 0) != IPVL_UNICAST_UP) {
			mutex_exit(&connp->conn_lock);
			error = EADDRNOTAVAIL;
			goto done;
		}
		break;
	case IPTUN_TYPE_6TO4:
		IN6_IPADDR_TO_V4MAPPED(iptun->iptun_laddr4,
		    &connp->conn_laddr_v6);
		IN6_IPADDR_TO_V4MAPPED(INADDR_ANY, &connp->conn_faddr_v6);
		ixa->ixa_flags |= IXAF_IS_IPV4;
		mutex_exit(&connp->conn_lock);

		switch (ip_laddr_verify_v4(iptun->iptun_laddr4,
		    IPCL_ZONEID(connp), ipst, B_FALSE)) {
		case IPVL_UNICAST_UP:
		case IPVL_UNICAST_DOWN:
			break;
		default:
			error = EADDRNOTAVAIL;
			goto done;
		}
		goto insert;
	}

	/* In case previous destination was multirt */
	ip_attr_newdst(ixa);

	/*
	 * When we set a tunnel's destination address, we do not
	 * care if the destination is reachable.  Transient routing
	 * issues should not inhibit the creation of a tunnel
	 * interface, for example. Thus we pass B_FALSE here.
	 */
	connp->conn_saddr_v6 = connp->conn_laddr_v6;
	mutex_exit(&connp->conn_lock);

	/* As long as the MTU is large we avoid fragmentation */
	ixa->ixa_flags |= IXAF_DONTFRAG | IXAF_PMTU_IPV4_DF;

	/* We handle IPsec in iptun_output_common */
	error = ip_attr_connect(connp, ixa, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, &connp->conn_faddr_v6, 0,
	    &connp->conn_saddr_v6, &uinfo, 0);

	if (error != 0)
		goto done;

	/* saddr shouldn't change since it was already set */
	ASSERT(IN6_ARE_ADDR_EQUAL(&connp->conn_laddr_v6,
	    &connp->conn_saddr_v6));

	/* We set IXAF_VERIFY_PMTU to catch PMTU increases */
	ixa->ixa_flags |= IXAF_VERIFY_PMTU;
	ASSERT(uinfo.iulp_mtu != 0);

	/*
	 * Allow setting new policies.
	 * The addresses/ports are already set, thus the IPsec policy calls
	 * can handle their passed-in conn's.
	 */
	connp->conn_policy_cached = B_FALSE;

insert:
	error = ipcl_conn_insert(connp);
	if (error != 0)
		goto done;

	/* Atomically update v6lastdst and conn_ixa */
	mutex_enter(&connp->conn_lock);
	/* Record this as the "last" send even though we haven't sent any */
	connp->conn_v6lastdst = connp->conn_faddr_v6;

	iptun->iptun_flags |= IPTUN_BOUND;

	oldixa = conn_replace_ixa(connp, ixa);
	/* Done with conn_t */
	mutex_exit(&connp->conn_lock);
	ixa_refrele(oldixa);

	/*
	 * Now that we're bound with ip below us, this is a good
	 * time to initialize the destination path MTU and to
	 * re-calculate the tunnel's link MTU.
	 */
	(void) iptun_update_mtu(iptun, ixa, 0);

	if (IS_IPTUN_RUNNING(iptun))
		iptun_task_dispatch(iptun, IPTUN_TASK_LINK_UPDATE);

done:
	ixa_refrele(ixa);
	return (error);
}

static void
iptun_unbind(iptun_t *iptun)
{
	ASSERT(iptun->iptun_flags & IPTUN_BOUND);
	ASSERT(mutex_owned(&iptun->iptun_lock) ||
	    (iptun->iptun_flags & IPTUN_CONDEMNED));
	ip_unbind(iptun->iptun_connp);
	iptun->iptun_flags &= ~IPTUN_BOUND;
	if (!(iptun->iptun_flags & IPTUN_CONDEMNED))
		iptun_task_dispatch(iptun, IPTUN_TASK_LINK_UPDATE);
}

/*
 * Re-generate the template data-link header for a given IP tunnel given the
 * tunnel's current parameters.
 */
static void
iptun_headergen(iptun_t *iptun, boolean_t update_mac)
{
	switch (iptun->iptun_typeinfo->iti_ipvers) {
	case IPV4_VERSION:
		/*
		 * We only need to use a custom IP header if the administrator
		 * has supplied a non-default hoplimit.
		 */
		if (iptun->iptun_hoplimit == IPTUN_DEFAULT_HOPLIMIT) {
			iptun->iptun_header_size = 0;
			break;
		}
		iptun->iptun_header_size = sizeof (ipha_t);
		iptun->iptun_header4.ipha_version_and_hdr_length =
		    IP_SIMPLE_HDR_VERSION;
		iptun->iptun_header4.ipha_fragment_offset_and_flags =
		    htons(IPH_DF);
		iptun->iptun_header4.ipha_ttl = iptun->iptun_hoplimit;
		break;
	case IPV6_VERSION: {
		ip6_t	*ip6hp = &iptun->iptun_header6.it6h_ip6h;

		/*
		 * We only need to use a custom IPv6 header if either the
		 * administrator has supplied a non-default hoplimit, or we
		 * need to include an encapsulation limit option in the outer
		 * header.
		 */
		if (iptun->iptun_hoplimit == IPTUN_DEFAULT_HOPLIMIT &&
		    iptun->iptun_encaplimit == 0) {
			iptun->iptun_header_size = 0;
			break;
		}

		(void) memset(ip6hp, 0, sizeof (*ip6hp));
		if (iptun->iptun_encaplimit == 0) {
			iptun->iptun_header_size = sizeof (ip6_t);
			ip6hp->ip6_nxt = IPPROTO_NONE;
		} else {
			iptun_encaplim_t	*iel;

			iptun->iptun_header_size = sizeof (iptun_ipv6hdrs_t);
			/*
			 * The mac_ipv6 plugin requires ip6_plen to be in host
			 * byte order and reflect the extension headers
			 * present in the template.  The actual network byte
			 * order ip6_plen will be set on a per-packet basis on
			 * transmit.
			 */
			ip6hp->ip6_plen = sizeof (*iel);
			ip6hp->ip6_nxt = IPPROTO_DSTOPTS;
			iel = &iptun->iptun_header6.it6h_encaplim;
			*iel = iptun_encaplim_init;
			iel->iel_telopt.ip6ot_encap_limit =
			    iptun->iptun_encaplimit;
		}

		ip6hp->ip6_hlim = iptun->iptun_hoplimit;
		break;
	}
	}

	if (update_mac)
		iptun_task_dispatch(iptun, IPTUN_TASK_PDATA_UPDATE);
}

/*
 * Insert inbound and outbound IPv4 and IPv6 policy into the given policy
 * head.
 */
static boolean_t
iptun_insert_simple_policies(ipsec_policy_head_t *ph, ipsec_act_t *actp,
    uint_t n, netstack_t *ns)
{
	int f = IPSEC_AF_V4;

	if (!ipsec_polhead_insert(ph, actp, n, f, IPSEC_TYPE_INBOUND, ns) ||
	    !ipsec_polhead_insert(ph, actp, n, f, IPSEC_TYPE_OUTBOUND, ns))
		return (B_FALSE);

	f = IPSEC_AF_V6;
	return (ipsec_polhead_insert(ph, actp, n, f, IPSEC_TYPE_INBOUND, ns) &&
	    ipsec_polhead_insert(ph, actp, n, f, IPSEC_TYPE_OUTBOUND, ns));
}

/*
 * Used to set IPsec policy when policy is set through the IPTUN_CREATE or
 * IPTUN_MODIFY ioctls.
 */
static int
iptun_set_sec_simple(iptun_t *iptun, const ipsec_req_t *ipsr)
{
	int		rc = 0;
	uint_t		nact;
	ipsec_act_t	*actp = NULL;
	boolean_t	clear_all, old_policy = B_FALSE;
	ipsec_tun_pol_t	*itp;
	char		name[MAXLINKNAMELEN];
	uint64_t	gen;
	netstack_t	*ns = iptun->iptun_ns;

	/* Can't specify self-encap on a tunnel. */
	if (ipsr->ipsr_self_encap_req != 0)
		return (EINVAL);

	/*
	 * If it's a "clear-all" entry, unset the security flags and resume
	 * normal cleartext (or inherit-from-global) policy.
	 */
	clear_all = ((ipsr->ipsr_ah_req & IPTUN_IPSEC_REQ_MASK) == 0 &&
	    (ipsr->ipsr_esp_req & IPTUN_IPSEC_REQ_MASK) == 0);

	ASSERT(mutex_owned(&iptun->iptun_lock));
	itp = iptun->iptun_itp;
	if (itp == NULL) {
		if (clear_all)
			goto bail;
		if ((rc = dls_mgmt_get_linkinfo(iptun->iptun_linkid, name, NULL,
		    NULL, NULL)) != 0)
			goto bail;
		ASSERT(name[0] != '\0');
		if ((itp = create_tunnel_policy(name, &rc, &gen, ns)) == NULL)
			goto bail;
		iptun->iptun_itp = itp;
	}

	/* Allocate the actvec now, before holding itp or polhead locks. */
	ipsec_actvec_from_req(ipsr, &actp, &nact, ns);
	if (actp == NULL) {
		rc = ENOMEM;
		goto bail;
	}

	/*
	 * Just write on the active polhead.  Save the primary/secondary stuff
	 * for spdsock operations.
	 *
	 * Mutex because we need to write to the polhead AND flags atomically.
	 * Other threads will acquire the polhead lock as a reader if the
	 * (unprotected) flag is set.
	 */
	mutex_enter(&itp->itp_lock);
	if (itp->itp_flags & ITPF_P_TUNNEL) {
		/* Oops, we lost a race.  Let's get out of here. */
		rc = EBUSY;
		goto mutex_bail;
	}
	old_policy = ((itp->itp_flags & ITPF_P_ACTIVE) != 0);

	if (old_policy) {
		ITPF_CLONE(itp->itp_flags);
		rc = ipsec_copy_polhead(itp->itp_policy, itp->itp_inactive, ns);
		if (rc != 0) {
			/* inactive has already been cleared. */
			itp->itp_flags &= ~ITPF_IFLAGS;
			goto mutex_bail;
		}
		rw_enter(&itp->itp_policy->iph_lock, RW_WRITER);
		ipsec_polhead_flush(itp->itp_policy, ns);
	} else {
		/* Else assume itp->itp_policy is already flushed. */
		rw_enter(&itp->itp_policy->iph_lock, RW_WRITER);
	}

	if (clear_all) {
		ASSERT(avl_numnodes(&itp->itp_policy->iph_rulebyid) == 0);
		itp->itp_flags &= ~ITPF_PFLAGS;
		rw_exit(&itp->itp_policy->iph_lock);
		old_policy = B_FALSE;	/* Clear out the inactive one too. */
		goto recover_bail;
	}

	if (iptun_insert_simple_policies(itp->itp_policy, actp, nact, ns)) {
		rw_exit(&itp->itp_policy->iph_lock);
		/*
		 * Adjust MTU and make sure the DL side knows what's up.
		 */
		itp->itp_flags = ITPF_P_ACTIVE;
		(void) iptun_update_mtu(iptun, NULL, 0);
		old_policy = B_FALSE;	/* Blank out inactive - we succeeded */
	} else {
		rw_exit(&itp->itp_policy->iph_lock);
		rc = ENOMEM;
	}

recover_bail:
	if (old_policy) {
		/* Recover policy in in active polhead. */
		ipsec_swap_policy(itp->itp_policy, itp->itp_inactive, ns);
		ITPF_SWAP(itp->itp_flags);
	}

	/* Clear policy in inactive polhead. */
	itp->itp_flags &= ~ITPF_IFLAGS;
	rw_enter(&itp->itp_inactive->iph_lock, RW_WRITER);
	ipsec_polhead_flush(itp->itp_inactive, ns);
	rw_exit(&itp->itp_inactive->iph_lock);

mutex_bail:
	mutex_exit(&itp->itp_lock);

bail:
	if (actp != NULL)
		ipsec_actvec_free(actp, nact);

	return (rc);
}

static iptun_typeinfo_t *
iptun_gettypeinfo(iptun_type_t type)
{
	int i;

	for (i = 0; iptun_type_table[i].iti_type != IPTUN_TYPE_UNKNOWN; i++) {
		if (iptun_type_table[i].iti_type == type)
			break;
	}
	return (&iptun_type_table[i]);
}

/*
 * Set the parameters included in ik on the tunnel iptun.  Parameters that can
 * only be set at creation time are set in iptun_create().
 */
static int
iptun_setparams(iptun_t *iptun, const iptun_kparams_t *ik)
{
	int		err = 0;
	netstack_t	*ns = iptun->iptun_ns;
	iptun_addr_t	orig_laddr, orig_raddr;
	uint_t		orig_flags = iptun->iptun_flags;

	if (ik->iptun_kparam_flags & IPTUN_KPARAM_LADDR) {
		if (orig_flags & IPTUN_LADDR)
			orig_laddr = iptun->iptun_laddr;
		if ((err = iptun_setladdr(iptun, &ik->iptun_kparam_laddr)) != 0)
			return (err);
		iptun->iptun_flags |= IPTUN_LADDR;
	}

	if (ik->iptun_kparam_flags & IPTUN_KPARAM_RADDR) {
		if (orig_flags & IPTUN_RADDR)
			orig_raddr = iptun->iptun_raddr;
		if ((err = iptun_setraddr(iptun, &ik->iptun_kparam_raddr)) != 0)
			goto done;
		iptun->iptun_flags |= IPTUN_RADDR;
	}

	if (ik->iptun_kparam_flags & IPTUN_KPARAM_SECINFO) {
		/*
		 * Set IPsec policy originating from the ifconfig(1M) command
		 * line.  This is traditionally called "simple" policy because
		 * the ipsec_req_t (iptun_kparam_secinfo) can only describe a
		 * simple policy of "do ESP on everything" and/or "do AH on
		 * everything" (as opposed to the rich policy that can be
		 * defined with ipsecconf(1M)).
		 */
		if (iptun->iptun_typeinfo->iti_type == IPTUN_TYPE_6TO4) {
			/*
			 * Can't set security properties for automatic
			 * tunnels.
			 */
			err = EINVAL;
			goto done;
		}

		if (!ipsec_loaded(ns->netstack_ipsec)) {
			/* If IPsec can be loaded, try and load it now. */
			if (ipsec_failed(ns->netstack_ipsec)) {
				err = EPROTONOSUPPORT;
				goto done;
			}
			ipsec_loader_loadnow(ns->netstack_ipsec);
			/*
			 * ipsec_loader_loadnow() returns while IPsec is
			 * loaded asynchronously.  While a method exists to
			 * wait for IPsec to load (ipsec_loader_wait()), it
			 * requires use of a STREAMS queue to do a qwait().
			 * We're not in STREAMS context here, and so we can't
			 * use it.  This is not a problem in practice because
			 * in the vast majority of cases, key management and
			 * global policy will have loaded before any tunnels
			 * are plumbed, and so IPsec will already have been
			 * loaded.
			 */
			err = EAGAIN;
			goto done;
		}

		err = iptun_set_sec_simple(iptun, &ik->iptun_kparam_secinfo);
		if (err == 0) {
			iptun->iptun_flags |= IPTUN_SIMPLE_POLICY;
			iptun->iptun_simple_policy = ik->iptun_kparam_secinfo;
		}
	}
done:
	if (err != 0) {
		/* Restore original source and destination. */
		if (ik->iptun_kparam_flags & IPTUN_KPARAM_LADDR &&
		    (orig_flags & IPTUN_LADDR))
			iptun->iptun_laddr = orig_laddr;
		if ((ik->iptun_kparam_flags & IPTUN_KPARAM_RADDR) &&
		    (orig_flags & IPTUN_RADDR))
			iptun->iptun_raddr = orig_raddr;
		iptun->iptun_flags = orig_flags;
	}
	return (err);
}

static int
iptun_register(iptun_t *iptun)
{
	mac_register_t	*mac;
	int		err;

	ASSERT(!(iptun->iptun_flags & IPTUN_MAC_REGISTERED));

	if ((mac = mac_alloc(MAC_VERSION)) == NULL)
		return (EINVAL);

	mac->m_type_ident = iptun->iptun_typeinfo->iti_ident;
	mac->m_driver = iptun;
	mac->m_dip = iptun_dip;
	mac->m_instance = (uint_t)-1;
	mac->m_src_addr = (uint8_t *)&iptun->iptun_laddr.ia_addr;
	mac->m_dst_addr = iptun->iptun_typeinfo->iti_hasraddr ?
	    (uint8_t *)&iptun->iptun_raddr.ia_addr : NULL;
	mac->m_callbacks = &iptun_m_callbacks;
	mac->m_min_sdu = iptun->iptun_typeinfo->iti_minmtu;
	mac->m_max_sdu = iptun->iptun_mtu;
	if (iptun->iptun_header_size != 0) {
		mac->m_pdata = &iptun->iptun_header;
		mac->m_pdata_size = iptun->iptun_header_size;
	}
	if ((err = mac_register(mac, &iptun->iptun_mh)) == 0)
		iptun->iptun_flags |= IPTUN_MAC_REGISTERED;
	mac_free(mac);
	return (err);
}

static int
iptun_unregister(iptun_t *iptun)
{
	int err;

	ASSERT(iptun->iptun_flags & IPTUN_MAC_REGISTERED);
	if ((err = mac_unregister(iptun->iptun_mh)) == 0)
		iptun->iptun_flags &= ~IPTUN_MAC_REGISTERED;
	return (err);
}

static conn_t *
iptun_conn_create(iptun_t *iptun, netstack_t *ns, cred_t *credp)
{
	conn_t *connp;

	if ((connp = ipcl_conn_create(IPCL_IPCCONN, KM_NOSLEEP, ns)) == NULL)
		return (NULL);

	connp->conn_flags |= IPCL_IPTUN;
	connp->conn_iptun = iptun;
	connp->conn_recv = iptun_input;
	connp->conn_recvicmp = iptun_input_icmp;
	connp->conn_verifyicmp = iptun_verifyicmp;

	/*
	 * Register iptun_notify to listen to capability changes detected by IP.
	 * This upcall is made in the context of the call to conn_ip_output.
	 */
	connp->conn_ixa->ixa_notify = iptun_notify;
	connp->conn_ixa->ixa_notify_cookie = iptun;

	/*
	 * For exclusive stacks we set conn_zoneid to GLOBAL_ZONEID as is done
	 * for all other conn_t's.
	 *
	 * Note that there's an important distinction between iptun_zoneid and
	 * conn_zoneid.  The conn_zoneid is set to GLOBAL_ZONEID in non-global
	 * exclusive stack zones to make the ip module believe that the
	 * non-global zone is actually a global zone.  Therefore, when
	 * interacting with the ip module, we must always use conn_zoneid.
	 */
	connp->conn_zoneid = (ns->netstack_stackid == GLOBAL_NETSTACKID) ?
	    crgetzoneid(credp) : GLOBAL_ZONEID;
	connp->conn_cred = credp;
	/* crfree() is done in ipcl_conn_destroy(), called by CONN_DEC_REF() */
	crhold(connp->conn_cred);
	connp->conn_cpid = NOPID;

	/* conn_allzones can not be set this early, hence no IPCL_ZONEID */
	connp->conn_ixa->ixa_zoneid = connp->conn_zoneid;
	ASSERT(connp->conn_ref == 1);

	/* Cache things in ixa without an extra refhold */
	ASSERT(!(connp->conn_ixa->ixa_free_flags & IXA_FREE_CRED));
	connp->conn_ixa->ixa_cred = connp->conn_cred;
	connp->conn_ixa->ixa_cpid = connp->conn_cpid;
	if (is_system_labeled())
		connp->conn_ixa->ixa_tsl = crgetlabel(connp->conn_cred);

	/*
	 * Have conn_ip_output drop packets should our outer source
	 * go invalid
	 */
	connp->conn_ixa->ixa_flags |= IXAF_VERIFY_SOURCE;

	switch (iptun->iptun_typeinfo->iti_ipvers) {
	case IPV4_VERSION:
		connp->conn_family = AF_INET6;
		break;
	case IPV6_VERSION:
		connp->conn_family = AF_INET;
		break;
	}
	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);
	return (connp);
}

static void
iptun_conn_destroy(conn_t *connp)
{
	ip_quiesce_conn(connp);
	connp->conn_iptun = NULL;
	ASSERT(connp->conn_ref == 1);
	CONN_DEC_REF(connp);
}

static iptun_t *
iptun_alloc(void)
{
	iptun_t *iptun;

	if ((iptun = kmem_cache_alloc(iptun_cache, KM_NOSLEEP)) != NULL) {
		bzero(iptun, sizeof (*iptun));
		atomic_inc_32(&iptun_tunnelcount);
	}
	return (iptun);
}

static void
iptun_free(iptun_t *iptun)
{
	ASSERT(iptun->iptun_flags & IPTUN_CONDEMNED);

	if (iptun->iptun_flags & IPTUN_HASH_INSERTED) {
		iptun_stack_t	*iptuns = iptun->iptun_iptuns;

		mutex_enter(&iptun_hash_lock);
		VERIFY(mod_hash_remove(iptun_hash,
		    IPTUN_HASH_KEY(iptun->iptun_linkid),
		    (mod_hash_val_t *)&iptun) == 0);
		mutex_exit(&iptun_hash_lock);
		iptun->iptun_flags &= ~IPTUN_HASH_INSERTED;
		mutex_enter(&iptuns->iptuns_lock);
		list_remove(&iptuns->iptuns_iptunlist, iptun);
		mutex_exit(&iptuns->iptuns_lock);
	}

	if (iptun->iptun_flags & IPTUN_BOUND)
		iptun_unbind(iptun);

	/*
	 * After iptun_unregister(), there will be no threads executing a
	 * downcall from the mac module, including in the tx datapath.
	 */
	if (iptun->iptun_flags & IPTUN_MAC_REGISTERED)
		VERIFY(iptun_unregister(iptun) == 0);

	if (iptun->iptun_itp != NULL) {
		/*
		 * Remove from the AVL tree, AND release the reference iptun_t
		 * itself holds on the ITP.
		 */
		itp_unlink(iptun->iptun_itp, iptun->iptun_ns);
		ITP_REFRELE(iptun->iptun_itp, iptun->iptun_ns);
		iptun->iptun_itp = NULL;
		iptun->iptun_flags &= ~IPTUN_SIMPLE_POLICY;
	}

	/*
	 * After ipcl_conn_destroy(), there will be no threads executing an
	 * upcall from ip (i.e., iptun_input()), and it is then safe to free
	 * the iptun_t.
	 */
	if (iptun->iptun_connp != NULL) {
		iptun_conn_destroy(iptun->iptun_connp);
		iptun->iptun_connp = NULL;
	}

	netstack_rele(iptun->iptun_ns);
	kmem_cache_free(iptun_cache, iptun);
	atomic_dec_32(&iptun_tunnelcount);
}

int
iptun_create(iptun_kparams_t *ik, cred_t *credp)
{
	iptun_t		*iptun = NULL;
	int		err = 0, mherr;
	char		linkname[MAXLINKNAMELEN];
	ipsec_tun_pol_t	*itp;
	netstack_t	*ns = NULL;
	iptun_stack_t	*iptuns;
	datalink_id_t	tmpid;
	zoneid_t	zoneid = crgetzoneid(credp);
	boolean_t	link_created = B_FALSE;

	/* The tunnel type is mandatory */
	if (!(ik->iptun_kparam_flags & IPTUN_KPARAM_TYPE))
		return (EINVAL);

	/*
	 * Is the linkid that the caller wishes to associate with this new
	 * tunnel assigned to this zone?
	 */
	if (zone_check_datalink(&zoneid, ik->iptun_kparam_linkid) != 0) {
		if (zoneid != GLOBAL_ZONEID)
			return (EINVAL);
	} else if (zoneid == GLOBAL_ZONEID) {
		return (EINVAL);
	}

	/*
	 * Make sure that we're not trying to create a tunnel that has already
	 * been created.
	 */
	if (iptun_enter_by_linkid(ik->iptun_kparam_linkid, &iptun) == 0) {
		iptun_exit(iptun);
		iptun = NULL;
		err = EEXIST;
		goto done;
	}

	ns = netstack_find_by_cred(credp);
	iptuns = ns->netstack_iptun;

	if ((iptun = iptun_alloc()) == NULL) {
		err = ENOMEM;
		goto done;
	}

	iptun->iptun_linkid = ik->iptun_kparam_linkid;
	iptun->iptun_zoneid = zoneid;
	iptun->iptun_ns = ns;

	iptun->iptun_typeinfo = iptun_gettypeinfo(ik->iptun_kparam_type);
	if (iptun->iptun_typeinfo->iti_type == IPTUN_TYPE_UNKNOWN) {
		err = EINVAL;
		goto done;
	}

	if (ik->iptun_kparam_flags & IPTUN_KPARAM_IMPLICIT)
		iptun->iptun_flags |= IPTUN_IMPLICIT;

	if ((err = iptun_setparams(iptun, ik)) != 0)
		goto done;

	iptun->iptun_hoplimit = IPTUN_DEFAULT_HOPLIMIT;
	if (iptun->iptun_typeinfo->iti_type == IPTUN_TYPE_IPV6)
		iptun->iptun_encaplimit = IPTUN_DEFAULT_ENCAPLIMIT;

	iptun_headergen(iptun, B_FALSE);

	iptun->iptun_connp = iptun_conn_create(iptun, ns, credp);
	if (iptun->iptun_connp == NULL) {
		err = ENOMEM;
		goto done;
	}

	iptun->iptun_mtu = iptun->iptun_typeinfo->iti_maxmtu;
	iptun->iptun_dpmtu = iptun->iptun_mtu;

	/*
	 * Find an ITP based on linkname.  If we have parms already set via
	 * the iptun_setparams() call above, it may have created an ITP for
	 * us.  We always try get_tunnel_policy() for DEBUG correctness
	 * checks, and we may wish to refactor this to only check when
	 * iptun_itp is NULL.
	 */
	if ((err = dls_mgmt_get_linkinfo(iptun->iptun_linkid, linkname, NULL,
	    NULL, NULL)) != 0)
		goto done;
	if ((itp = get_tunnel_policy(linkname, ns)) != NULL)
		iptun->iptun_itp = itp;

	/*
	 * See if we have the necessary IP addresses assigned to this tunnel
	 * to try and bind them with ip underneath us.  If we're not ready to
	 * bind yet, then we'll defer the bind operation until the addresses
	 * are modified.
	 */
	if (iptun_canbind(iptun) && ((err = iptun_bind(iptun)) != 0))
		goto done;

	if ((err = iptun_register(iptun)) != 0)
		goto done;

	err = dls_devnet_create(iptun->iptun_mh, iptun->iptun_linkid,
	    iptun->iptun_zoneid);
	if (err != 0)
		goto done;
	link_created = B_TRUE;

	/*
	 * We hash by link-id as that is the key used by all other iptun
	 * interfaces (modify, delete, etc.).
	 */
	if ((mherr = mod_hash_insert(iptun_hash,
	    IPTUN_HASH_KEY(iptun->iptun_linkid), (mod_hash_val_t)iptun)) == 0) {
		mutex_enter(&iptuns->iptuns_lock);
		list_insert_head(&iptuns->iptuns_iptunlist, iptun);
		mutex_exit(&iptuns->iptuns_lock);
		iptun->iptun_flags |= IPTUN_HASH_INSERTED;
	} else if (mherr == MH_ERR_NOMEM) {
		err = ENOMEM;
	} else if (mherr == MH_ERR_DUPLICATE) {
		err = EEXIST;
	} else {
		err = EINVAL;
	}

done:
	if (iptun == NULL && ns != NULL)
		netstack_rele(ns);
	if (err != 0 && iptun != NULL) {
		if (link_created) {
			(void) dls_devnet_destroy(iptun->iptun_mh, &tmpid,
			    B_TRUE);
		}
		iptun->iptun_flags |= IPTUN_CONDEMNED;
		iptun_free(iptun);
	}
	return (err);
}

int
iptun_delete(datalink_id_t linkid, cred_t *credp)
{
	int	err;
	iptun_t	*iptun = NULL;

	if ((err = iptun_enter_by_linkid(linkid, &iptun)) != 0)
		return (err);

	/* One cannot delete a tunnel that belongs to another zone. */
	if (iptun->iptun_zoneid != crgetzoneid(credp)) {
		iptun_exit(iptun);
		return (EACCES);
	}

	/*
	 * We need to exit iptun in order to issue calls up the stack such as
	 * dls_devnet_destroy().  If we call up while still in iptun, deadlock
	 * with calls coming down the stack is possible.  We prevent other
	 * threads from entering this iptun after we've exited it by setting
	 * the IPTUN_DELETE_PENDING flag.  This will cause callers of
	 * iptun_enter() to block waiting on iptun_enter_cv.  The assumption
	 * here is that the functions we're calling while IPTUN_DELETE_PENDING
	 * is set dont resuult in an iptun_enter() call, as that would result
	 * in deadlock.
	 */
	iptun->iptun_flags |= IPTUN_DELETE_PENDING;

	/* Wait for any pending upcall to the mac module to complete. */
	while (iptun->iptun_flags & IPTUN_UPCALL_PENDING)
		cv_wait(&iptun->iptun_upcall_cv, &iptun->iptun_lock);

	iptun_exit(iptun);

	if ((err = dls_devnet_destroy(iptun->iptun_mh, &linkid, B_TRUE)) == 0) {
		/*
		 * mac_disable() will fail with EBUSY if there are references
		 * to the iptun MAC.  If there are none, then mac_disable()
		 * will assure that none can be acquired until the MAC is
		 * unregistered.
		 *
		 * XXX CR 6791335 prevents us from calling mac_disable() prior
		 * to dls_devnet_destroy(), so we unfortunately need to
		 * attempt to re-create the devnet node if mac_disable()
		 * fails.
		 */
		if ((err = mac_disable(iptun->iptun_mh)) != 0) {
			(void) dls_devnet_create(iptun->iptun_mh, linkid,
			    iptun->iptun_zoneid);
		}
	}

	/*
	 * Now that we know the fate of this iptun_t, we need to clear
	 * IPTUN_DELETE_PENDING, and set IPTUN_CONDEMNED if the iptun_t is
	 * slated to be freed.  Either way, we need to signal the threads
	 * waiting in iptun_enter() so that they can either fail if
	 * IPTUN_CONDEMNED is set, or continue if it's not.
	 */
	mutex_enter(&iptun->iptun_lock);
	iptun->iptun_flags &= ~IPTUN_DELETE_PENDING;
	if (err == 0)
		iptun->iptun_flags |= IPTUN_CONDEMNED;
	cv_broadcast(&iptun->iptun_enter_cv);
	mutex_exit(&iptun->iptun_lock);

	/*
	 * Note that there is no danger in calling iptun_free() after having
	 * dropped the iptun_lock since callers of iptun_enter() at this point
	 * are doing so from iptun_enter_by_linkid() (mac_disable() got rid of
	 * threads entering from mac callbacks which call iptun_enter()
	 * directly) which holds iptun_hash_lock, and iptun_free() grabs this
	 * lock in order to remove the iptun_t from the hash table.
	 */
	if (err == 0)
		iptun_free(iptun);

	return (err);
}

int
iptun_modify(const iptun_kparams_t *ik, cred_t *credp)
{
	iptun_t		*iptun;
	boolean_t	laddr_change = B_FALSE, raddr_change = B_FALSE;
	int		err;

	if ((err = iptun_enter_by_linkid(ik->iptun_kparam_linkid, &iptun)) != 0)
		return (err);

	/* One cannot modify a tunnel that belongs to another zone. */
	if (iptun->iptun_zoneid != crgetzoneid(credp)) {
		err = EACCES;
		goto done;
	}

	/* The tunnel type cannot be changed */
	if (ik->iptun_kparam_flags & IPTUN_KPARAM_TYPE) {
		err = EINVAL;
		goto done;
	}

	if ((err = iptun_setparams(iptun, ik)) != 0)
		goto done;
	iptun_headergen(iptun, B_FALSE);

	/*
	 * If any of the tunnel's addresses has been modified and the tunnel
	 * has the necessary addresses assigned to it, we need to try to bind
	 * with ip underneath us.  If we're not ready to bind yet, then we'll
	 * try again when the addresses are modified later.
	 */
	laddr_change = (ik->iptun_kparam_flags & IPTUN_KPARAM_LADDR);
	raddr_change = (ik->iptun_kparam_flags & IPTUN_KPARAM_RADDR);
	if (laddr_change || raddr_change) {
		if (iptun->iptun_flags & IPTUN_BOUND)
			iptun_unbind(iptun);
		if (iptun_canbind(iptun) && (err = iptun_bind(iptun)) != 0) {
			if (laddr_change)
				iptun->iptun_flags &= ~IPTUN_LADDR;
			if (raddr_change)
				iptun->iptun_flags &= ~IPTUN_RADDR;
			goto done;
		}
	}

	if (laddr_change)
		iptun_task_dispatch(iptun, IPTUN_TASK_LADDR_UPDATE);
	if (raddr_change)
		iptun_task_dispatch(iptun, IPTUN_TASK_RADDR_UPDATE);

done:
	iptun_exit(iptun);
	return (err);
}

/* Given an IP tunnel's datalink id, fill in its parameters. */
int
iptun_info(iptun_kparams_t *ik, cred_t *credp)
{
	iptun_t	*iptun;
	int	err;

	/* Is the tunnel link visible from the caller's zone? */
	if (!dls_devnet_islinkvisible(ik->iptun_kparam_linkid,
	    crgetzoneid(credp)))
		return (ENOENT);

	if ((err = iptun_enter_by_linkid(ik->iptun_kparam_linkid, &iptun)) != 0)
		return (err);

	bzero(ik, sizeof (iptun_kparams_t));

	ik->iptun_kparam_linkid = iptun->iptun_linkid;
	ik->iptun_kparam_type = iptun->iptun_typeinfo->iti_type;
	ik->iptun_kparam_flags |= IPTUN_KPARAM_TYPE;

	if (iptun->iptun_flags & IPTUN_LADDR) {
		iptun_getaddr(&iptun->iptun_laddr, &ik->iptun_kparam_laddr);
		ik->iptun_kparam_flags |= IPTUN_KPARAM_LADDR;
	}
	if (iptun->iptun_flags & IPTUN_RADDR) {
		iptun_getaddr(&iptun->iptun_raddr, &ik->iptun_kparam_raddr);
		ik->iptun_kparam_flags |= IPTUN_KPARAM_RADDR;
	}

	if (iptun->iptun_flags & IPTUN_IMPLICIT)
		ik->iptun_kparam_flags |= IPTUN_KPARAM_IMPLICIT;

	if (iptun->iptun_itp != NULL) {
		mutex_enter(&iptun->iptun_itp->itp_lock);
		if (iptun->iptun_itp->itp_flags & ITPF_P_ACTIVE) {
			ik->iptun_kparam_flags |= IPTUN_KPARAM_IPSECPOL;
			if (iptun->iptun_flags & IPTUN_SIMPLE_POLICY) {
				ik->iptun_kparam_flags |= IPTUN_KPARAM_SECINFO;
				ik->iptun_kparam_secinfo =
				    iptun->iptun_simple_policy;
			}
		}
		mutex_exit(&iptun->iptun_itp->itp_lock);
	}

done:
	iptun_exit(iptun);
	return (err);
}

int
iptun_set_6to4relay(netstack_t *ns, ipaddr_t relay_addr)
{
	if (relay_addr == INADDR_BROADCAST || CLASSD(relay_addr))
		return (EADDRNOTAVAIL);
	ns->netstack_iptun->iptuns_relay_rtr_addr = relay_addr;
	return (0);
}

void
iptun_get_6to4relay(netstack_t *ns, ipaddr_t *relay_addr)
{
	*relay_addr = ns->netstack_iptun->iptuns_relay_rtr_addr;
}

void
iptun_set_policy(datalink_id_t linkid, ipsec_tun_pol_t *itp)
{
	iptun_t	*iptun;

	if (iptun_enter_by_linkid(linkid, &iptun) != 0)
		return;
	if (iptun->iptun_itp != itp) {
		ASSERT(iptun->iptun_itp == NULL);
		ITP_REFHOLD(itp);
		iptun->iptun_itp = itp;
	}
	/*
	 * IPsec policy means IPsec overhead, which means lower MTU.
	 * Refresh the MTU for this tunnel.
	 */
	(void) iptun_update_mtu(iptun, NULL, 0);
	iptun_exit(iptun);
}

/*
 * Obtain the path MTU to the tunnel destination.
 * Can return zero in some cases.
 */
static uint32_t
iptun_get_dst_pmtu(iptun_t *iptun, ip_xmit_attr_t *ixa)
{
	uint32_t	pmtu = 0;
	conn_t		*connp = iptun->iptun_connp;
	boolean_t	need_rele = B_FALSE;

	/*
	 * We only obtain the pmtu for tunnels that have a remote tunnel
	 * address.
	 */
	if (!(iptun->iptun_flags & IPTUN_RADDR))
		return (0);

	if (ixa == NULL) {
		ixa = conn_get_ixa(connp, B_FALSE);
		if (ixa == NULL)
			return (0);
		need_rele = B_TRUE;
	}
	/*
	 * Guard against ICMP errors before we have sent, as well as against
	 * and a thread which held conn_ixa.
	 */
	if (ixa->ixa_ire != NULL) {
		pmtu = ip_get_pmtu(ixa);

		/*
		 * For both IPv4 and IPv6 we can have indication that the outer
		 * header needs fragmentation.
		 */
		if (ixa->ixa_flags & IXAF_PMTU_TOO_SMALL) {
			/* Must allow fragmentation in ip_output */
			ixa->ixa_flags &= ~IXAF_DONTFRAG;
		} else if (iptun->iptun_typeinfo->iti_type != IPTUN_TYPE_6TO4) {
			ixa->ixa_flags |= IXAF_DONTFRAG;
		} else {
			/* ip_get_pmtu might have set this - we don't want it */
			ixa->ixa_flags &= ~IXAF_PMTU_IPV4_DF;
		}
	}

	if (need_rele)
		ixa_refrele(ixa);
	return (pmtu);
}

/*
 * Update the ip_xmit_attr_t to capture the current lower path mtu as known
 * by ip.
 */
static void
iptun_update_dst_pmtu(iptun_t *iptun, ip_xmit_attr_t *ixa)
{
	uint32_t	pmtu;
	conn_t		*connp = iptun->iptun_connp;
	boolean_t	need_rele = B_FALSE;

	/* IXAF_VERIFY_PMTU is not set if we don't have a fixed destination */
	if (!(iptun->iptun_flags & IPTUN_RADDR))
		return;

	if (ixa == NULL) {
		ixa = conn_get_ixa(connp, B_FALSE);
		if (ixa == NULL)
			return;
		need_rele = B_TRUE;
	}
	/*
	 * Guard against ICMP errors before we have sent, as well as against
	 * and a thread which held conn_ixa.
	 */
	if (ixa->ixa_ire != NULL) {
		pmtu = ip_get_pmtu(ixa);
		/*
		 * Update ixa_fragsize and ixa_pmtu.
		 */
		ixa->ixa_fragsize = ixa->ixa_pmtu = pmtu;

		/*
		 * For both IPv4 and IPv6 we can have indication that the outer
		 * header needs fragmentation.
		 */
		if (ixa->ixa_flags & IXAF_PMTU_TOO_SMALL) {
			/* Must allow fragmentation in ip_output */
			ixa->ixa_flags &= ~IXAF_DONTFRAG;
		} else if (iptun->iptun_typeinfo->iti_type != IPTUN_TYPE_6TO4) {
			ixa->ixa_flags |= IXAF_DONTFRAG;
		} else {
			/* ip_get_pmtu might have set this - we don't want it */
			ixa->ixa_flags &= ~IXAF_PMTU_IPV4_DF;
		}
	}

	if (need_rele)
		ixa_refrele(ixa);
}

/*
 * There is nothing that iptun can verify in addition to IP having
 * verified the IP addresses in the fanout.
 */
/* ARGSUSED */
static boolean_t
iptun_verifyicmp(conn_t *connp, void *arg2, icmph_t *icmph, icmp6_t *icmp6,
    ip_recv_attr_t *ira)
{
	return (B_TRUE);
}

/*
 * Notify function registered with ip_xmit_attr_t.
 */
static void
iptun_notify(void *arg, ip_xmit_attr_t *ixa, ixa_notify_type_t ntype,
    ixa_notify_arg_t narg)
{
	iptun_t		*iptun = (iptun_t *)arg;

	switch (ntype) {
	case IXAN_PMTU:
		(void) iptun_update_mtu(iptun, ixa, narg);
		break;
	}
}

/*
 * Returns the max of old_ovhd and the overhead associated with pol.
 */
static uint32_t
iptun_max_policy_overhead(ipsec_policy_t *pol, uint32_t old_ovhd)
{
	uint32_t new_ovhd = old_ovhd;

	while (pol != NULL) {
		new_ovhd = max(new_ovhd,
		    ipsec_act_ovhd(&pol->ipsp_act->ipa_act));
		pol = pol->ipsp_hash.hash_next;
	}
	return (new_ovhd);
}

static uint32_t
iptun_get_ipsec_overhead(iptun_t *iptun)
{
	ipsec_policy_root_t	*ipr;
	ipsec_policy_head_t	*iph;
	ipsec_policy_t		*pol;
	ipsec_selector_t	sel;
	int			i;
	uint32_t		ipsec_ovhd = 0;
	ipsec_tun_pol_t		*itp = iptun->iptun_itp;
	netstack_t		*ns = iptun->iptun_ns;

	if (itp == NULL || !(itp->itp_flags & ITPF_P_ACTIVE)) {
		/*
		 * Consult global policy, just in case.  This will only work
		 * if we have both source and destination addresses to work
		 * with.
		 */
		if ((iptun->iptun_flags & (IPTUN_LADDR|IPTUN_RADDR)) !=
		    (IPTUN_LADDR|IPTUN_RADDR))
			return (0);

		iph = ipsec_system_policy(ns);
		bzero(&sel, sizeof (sel));
		sel.ips_isv4 =
		    (iptun->iptun_typeinfo->iti_ipvers == IPV4_VERSION);
		switch (iptun->iptun_typeinfo->iti_ipvers) {
		case IPV4_VERSION:
			sel.ips_local_addr_v4 = iptun->iptun_laddr4;
			sel.ips_remote_addr_v4 = iptun->iptun_raddr4;
			break;
		case IPV6_VERSION:
			sel.ips_local_addr_v6 = iptun->iptun_laddr6;
			sel.ips_remote_addr_v6 = iptun->iptun_raddr6;
			break;
		}
		/* Check for both IPv4 and IPv6. */
		sel.ips_protocol = IPPROTO_ENCAP;
		pol = ipsec_find_policy_head(NULL, iph, IPSEC_TYPE_OUTBOUND,
		    &sel);
		if (pol != NULL) {
			ipsec_ovhd = ipsec_act_ovhd(&pol->ipsp_act->ipa_act);
			IPPOL_REFRELE(pol);
		}
		sel.ips_protocol = IPPROTO_IPV6;
		pol = ipsec_find_policy_head(NULL, iph, IPSEC_TYPE_OUTBOUND,
		    &sel);
		if (pol != NULL) {
			ipsec_ovhd = max(ipsec_ovhd,
			    ipsec_act_ovhd(&pol->ipsp_act->ipa_act));
			IPPOL_REFRELE(pol);
		}
		IPPH_REFRELE(iph, ns);
	} else {
		/*
		 * Look through all of the possible IPsec actions for the
		 * tunnel, and find the largest potential IPsec overhead.
		 */
		iph = itp->itp_policy;
		rw_enter(&iph->iph_lock, RW_READER);
		ipr = &(iph->iph_root[IPSEC_TYPE_OUTBOUND]);
		ipsec_ovhd = iptun_max_policy_overhead(
		    ipr->ipr_nonhash[IPSEC_AF_V4], 0);
		ipsec_ovhd = iptun_max_policy_overhead(
		    ipr->ipr_nonhash[IPSEC_AF_V6], ipsec_ovhd);
		for (i = 0; i < ipr->ipr_nchains; i++) {
			ipsec_ovhd = iptun_max_policy_overhead(
			    ipr->ipr_hash[i].hash_head, ipsec_ovhd);
		}
		rw_exit(&iph->iph_lock);
	}

	return (ipsec_ovhd);
}

/*
 * Calculate and return the maximum possible upper MTU for the given tunnel.
 *
 * If new_pmtu is set then we also need to update the lower path MTU information
 * in the ip_xmit_attr_t. That is needed since we set IXAF_VERIFY_PMTU so that
 * we are notified by conn_ip_output() when the path MTU increases.
 */
static uint32_t
iptun_get_maxmtu(iptun_t *iptun, ip_xmit_attr_t *ixa, uint32_t new_pmtu)
{
	size_t		header_size, ipsec_overhead;
	uint32_t	maxmtu, pmtu;

	/*
	 * Start with the path-MTU to the remote address, which is either
	 * provided as the new_pmtu argument, or obtained using
	 * iptun_get_dst_pmtu().
	 */
	if (new_pmtu != 0) {
		if (iptun->iptun_flags & IPTUN_RADDR)
			iptun->iptun_dpmtu = new_pmtu;
		pmtu = new_pmtu;
	} else if (iptun->iptun_flags & IPTUN_RADDR) {
		if ((pmtu = iptun_get_dst_pmtu(iptun, ixa)) == 0) {
			/*
			 * We weren't able to obtain the path-MTU of the
			 * destination.  Use the previous value.
			 */
			pmtu = iptun->iptun_dpmtu;
		} else {
			iptun->iptun_dpmtu = pmtu;
		}
	} else {
		/*
		 * We have no path-MTU information to go on, use the maximum
		 * possible value.
		 */
		pmtu = iptun->iptun_typeinfo->iti_maxmtu;
	}

	/*
	 * Now calculate tunneling overhead and subtract that from the
	 * path-MTU information obtained above.
	 */
	if (iptun->iptun_header_size != 0) {
		header_size = iptun->iptun_header_size;
	} else {
		switch (iptun->iptun_typeinfo->iti_ipvers) {
		case IPV4_VERSION:
			header_size = sizeof (ipha_t);
			if (is_system_labeled())
				header_size += IP_MAX_OPT_LENGTH;
			break;
		case IPV6_VERSION:
			header_size = sizeof (iptun_ipv6hdrs_t);
			break;
		}
	}

	ipsec_overhead = iptun_get_ipsec_overhead(iptun);

	maxmtu = pmtu - (header_size + ipsec_overhead);
	return (max(maxmtu, iptun->iptun_typeinfo->iti_minmtu));
}

/*
 * Re-calculate the tunnel's MTU as seen from above and notify the MAC layer
 * of any change in MTU.  The new_pmtu argument is the new lower path MTU to
 * the tunnel destination to be used in the tunnel MTU calculation.  Passing
 * in 0 for new_pmtu causes the lower path MTU to be dynamically updated using
 * ip_get_pmtu().
 *
 * If the calculated tunnel MTU is different than its previous value, then we
 * notify the MAC layer above us of this change using mac_maxsdu_update().
 */
static uint32_t
iptun_update_mtu(iptun_t *iptun, ip_xmit_attr_t *ixa, uint32_t new_pmtu)
{
	uint32_t newmtu;

	/* We always update the ixa since we might have set IXAF_VERIFY_PMTU */
	iptun_update_dst_pmtu(iptun, ixa);

	/*
	 * We return the current MTU without updating it if it was pegged to a
	 * static value using the MAC_PROP_MTU link property.
	 */
	if (iptun->iptun_flags & IPTUN_FIXED_MTU)
		return (iptun->iptun_mtu);

	/* If the MTU isn't fixed, then use the maximum possible value. */
	newmtu = iptun_get_maxmtu(iptun, ixa, new_pmtu);
	/*
	 * We only dynamically adjust the tunnel MTU for tunnels with
	 * destinations because dynamic MTU calculations are based on the
	 * destination path-MTU.
	 */
	if ((iptun->iptun_flags & IPTUN_RADDR) && newmtu != iptun->iptun_mtu) {
		iptun->iptun_mtu = newmtu;
		if (iptun->iptun_flags & IPTUN_MAC_REGISTERED)
			iptun_task_dispatch(iptun, IPTUN_TASK_MTU_UPDATE);
	}

	return (newmtu);
}

/*
 * Frees a packet or packet chain and bumps stat for each freed packet.
 */
static void
iptun_drop_pkt(mblk_t *mp, uint64_t *stat)
{
	mblk_t *pktmp;

	for (pktmp = mp; pktmp != NULL; pktmp = mp) {
		mp = mp->b_next;
		pktmp->b_next = NULL;
		if (stat != NULL)
			atomic_inc_64(stat);
		freemsg(pktmp);
	}
}

/*
 * Allocate and return a new mblk to hold an IP and ICMP header, and chain the
 * original packet to its b_cont.  Returns NULL on failure.
 */
static mblk_t *
iptun_build_icmperr(size_t hdrs_size, mblk_t *orig_pkt)
{
	mblk_t *icmperr_mp;

	if ((icmperr_mp = allocb(hdrs_size, BPRI_MED)) != NULL) {
		icmperr_mp->b_wptr += hdrs_size;
		/* tack on the offending packet */
		icmperr_mp->b_cont = orig_pkt;
	}
	return (icmperr_mp);
}

/*
 * Transmit an ICMP error.  mp->b_rptr points at the packet to be included in
 * the ICMP error.
 */
static void
iptun_sendicmp_v4(iptun_t *iptun, icmph_t *icmp, ipha_t *orig_ipha, mblk_t *mp,
    ts_label_t *tsl)
{
	size_t	orig_pktsize, hdrs_size;
	mblk_t	*icmperr_mp;
	ipha_t	*new_ipha;
	icmph_t	*new_icmp;
	ip_xmit_attr_t	ixas;
	conn_t	*connp = iptun->iptun_connp;

	orig_pktsize = msgdsize(mp);
	hdrs_size = sizeof (ipha_t) + sizeof (icmph_t);
	if ((icmperr_mp = iptun_build_icmperr(hdrs_size, mp)) == NULL) {
		iptun_drop_pkt(mp, &iptun->iptun_noxmtbuf);
		return;
	}

	new_ipha = (ipha_t *)icmperr_mp->b_rptr;
	new_icmp = (icmph_t *)(new_ipha + 1);

	new_ipha->ipha_version_and_hdr_length = IP_SIMPLE_HDR_VERSION;
	new_ipha->ipha_type_of_service = 0;
	new_ipha->ipha_ident = 0;
	new_ipha->ipha_fragment_offset_and_flags = 0;
	new_ipha->ipha_ttl = orig_ipha->ipha_ttl;
	new_ipha->ipha_protocol = IPPROTO_ICMP;
	new_ipha->ipha_src = orig_ipha->ipha_dst;
	new_ipha->ipha_dst = orig_ipha->ipha_src;
	new_ipha->ipha_hdr_checksum = 0; /* will be computed by ip */
	new_ipha->ipha_length = htons(hdrs_size + orig_pktsize);

	*new_icmp = *icmp;
	new_icmp->icmph_checksum = 0;
	new_icmp->icmph_checksum = IP_CSUM(icmperr_mp, sizeof (ipha_t), 0);

	bzero(&ixas, sizeof (ixas));
	ixas.ixa_flags = IXAF_BASIC_SIMPLE_V4;
	if (new_ipha->ipha_src == INADDR_ANY) {
		ixas.ixa_flags &= ~IXAF_VERIFY_SOURCE;
		ixas.ixa_flags |= IXAF_SET_SOURCE;
	}

	ixas.ixa_zoneid = IPCL_ZONEID(connp);
	ixas.ixa_ipst = connp->conn_netstack->netstack_ip;
	ixas.ixa_cred = connp->conn_cred;
	ixas.ixa_cpid = NOPID;
	if (is_system_labeled())
		ixas.ixa_tsl = tsl;

	ixas.ixa_ifindex = 0;
	ixas.ixa_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;

	(void) ip_output_simple(icmperr_mp, &ixas);
	ixa_cleanup(&ixas);
}

static void
iptun_sendicmp_v6(iptun_t *iptun, icmp6_t *icmp6, ip6_t *orig_ip6h, mblk_t *mp,
    ts_label_t *tsl)
{
	size_t	orig_pktsize, hdrs_size;
	mblk_t	*icmp6err_mp;
	ip6_t	*new_ip6h;
	icmp6_t	*new_icmp6;
	ip_xmit_attr_t	ixas;
	conn_t	*connp = iptun->iptun_connp;

	orig_pktsize = msgdsize(mp);
	hdrs_size = sizeof (ip6_t) + sizeof (icmp6_t);
	if ((icmp6err_mp = iptun_build_icmperr(hdrs_size, mp)) == NULL) {
		iptun_drop_pkt(mp, &iptun->iptun_noxmtbuf);
		return;
	}

	new_ip6h = (ip6_t *)icmp6err_mp->b_rptr;
	new_icmp6 = (icmp6_t *)(new_ip6h + 1);

	new_ip6h->ip6_vcf = orig_ip6h->ip6_vcf;
	new_ip6h->ip6_plen = htons(sizeof (icmp6_t) + orig_pktsize);
	new_ip6h->ip6_hops = orig_ip6h->ip6_hops;
	new_ip6h->ip6_nxt = IPPROTO_ICMPV6;
	new_ip6h->ip6_src = orig_ip6h->ip6_dst;
	new_ip6h->ip6_dst = orig_ip6h->ip6_src;

	*new_icmp6 = *icmp6;
	/* The checksum is calculated in ip_output_simple and friends. */
	new_icmp6->icmp6_cksum = new_ip6h->ip6_plen;

	bzero(&ixas, sizeof (ixas));
	ixas.ixa_flags = IXAF_BASIC_SIMPLE_V6;
	if (IN6_IS_ADDR_UNSPECIFIED(&new_ip6h->ip6_src)) {
		ixas.ixa_flags &= ~IXAF_VERIFY_SOURCE;
		ixas.ixa_flags |= IXAF_SET_SOURCE;
	}

	ixas.ixa_zoneid = IPCL_ZONEID(connp);
	ixas.ixa_ipst = connp->conn_netstack->netstack_ip;
	ixas.ixa_cred = connp->conn_cred;
	ixas.ixa_cpid = NOPID;
	if (is_system_labeled())
		ixas.ixa_tsl = tsl;

	ixas.ixa_ifindex = 0;
	ixas.ixa_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;

	(void) ip_output_simple(icmp6err_mp, &ixas);
	ixa_cleanup(&ixas);
}

static void
iptun_icmp_error_v4(iptun_t *iptun, ipha_t *orig_ipha, mblk_t *mp,
    uint8_t type, uint8_t code, ts_label_t *tsl)
{
	icmph_t icmp;

	bzero(&icmp, sizeof (icmp));
	icmp.icmph_type = type;
	icmp.icmph_code = code;

	iptun_sendicmp_v4(iptun, &icmp, orig_ipha, mp, tsl);
}

static void
iptun_icmp_fragneeded_v4(iptun_t *iptun, uint32_t newmtu, ipha_t *orig_ipha,
    mblk_t *mp, ts_label_t *tsl)
{
	icmph_t	icmp;

	icmp.icmph_type = ICMP_DEST_UNREACHABLE;
	icmp.icmph_code = ICMP_FRAGMENTATION_NEEDED;
	icmp.icmph_du_zero = 0;
	icmp.icmph_du_mtu = htons(newmtu);

	iptun_sendicmp_v4(iptun, &icmp, orig_ipha, mp, tsl);
}

static void
iptun_icmp_error_v6(iptun_t *iptun, ip6_t *orig_ip6h, mblk_t *mp,
    uint8_t type, uint8_t code, uint32_t offset, ts_label_t *tsl)
{
	icmp6_t icmp6;

	bzero(&icmp6, sizeof (icmp6));
	icmp6.icmp6_type = type;
	icmp6.icmp6_code = code;
	if (type == ICMP6_PARAM_PROB)
		icmp6.icmp6_pptr = htonl(offset);

	iptun_sendicmp_v6(iptun, &icmp6, orig_ip6h, mp, tsl);
}

static void
iptun_icmp_toobig_v6(iptun_t *iptun, uint32_t newmtu, ip6_t *orig_ip6h,
    mblk_t *mp, ts_label_t *tsl)
{
	icmp6_t icmp6;

	icmp6.icmp6_type = ICMP6_PACKET_TOO_BIG;
	icmp6.icmp6_code = 0;
	icmp6.icmp6_mtu = htonl(newmtu);

	iptun_sendicmp_v6(iptun, &icmp6, orig_ip6h, mp, tsl);
}

/*
 * Determines if the packet pointed to by ipha or ip6h is an ICMP error.  The
 * mp argument is only used to do bounds checking.
 */
static boolean_t
is_icmp_error(mblk_t *mp, ipha_t *ipha, ip6_t *ip6h)
{
	uint16_t hlen;

	if (ipha != NULL) {
		icmph_t	*icmph;

		ASSERT(ip6h == NULL);
		if (ipha->ipha_protocol != IPPROTO_ICMP)
			return (B_FALSE);

		hlen = IPH_HDR_LENGTH(ipha);
		icmph = (icmph_t *)((uint8_t *)ipha + hlen);
		return (ICMP_IS_ERROR(icmph->icmph_type) ||
		    icmph->icmph_type == ICMP_REDIRECT);
	} else {
		icmp6_t	*icmp6;
		uint8_t	*nexthdrp;

		ASSERT(ip6h != NULL);
		if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &hlen, &nexthdrp) ||
		    *nexthdrp != IPPROTO_ICMPV6) {
			return (B_FALSE);
		}

		icmp6 = (icmp6_t *)((uint8_t *)ip6h + hlen);
		return (ICMP6_IS_ERROR(icmp6->icmp6_type) ||
		    icmp6->icmp6_type == ND_REDIRECT);
	}
}

/*
 * Find inner and outer IP headers from a tunneled packet as setup for calls
 * into ipsec_tun_{in,out}bound().
 * Note that we need to allow the outer header to be in a separate mblk from
 * the inner header.
 * If the caller knows the outer_hlen, the caller passes it in. Otherwise zero.
 */
static size_t
iptun_find_headers(mblk_t *mp, size_t outer_hlen, ipha_t **outer4,
    ipha_t **inner4, ip6_t **outer6, ip6_t **inner6)
{
	ipha_t	*ipha;
	size_t	first_mblkl = MBLKL(mp);
	mblk_t	*inner_mp;

	/*
	 * Don't bother handling packets that don't have a full IP header in
	 * the fist mblk.  For the input path, the ip module ensures that this
	 * won't happen, and on the output path, the IP tunneling MAC-type
	 * plugins ensure that this also won't happen.
	 */
	if (first_mblkl < sizeof (ipha_t))
		return (0);
	ipha = (ipha_t *)(mp->b_rptr);
	switch (IPH_HDR_VERSION(ipha)) {
	case IPV4_VERSION:
		*outer4 = ipha;
		*outer6 = NULL;
		if (outer_hlen == 0)
			outer_hlen = IPH_HDR_LENGTH(ipha);
		break;
	case IPV6_VERSION:
		*outer4 = NULL;
		*outer6 = (ip6_t *)ipha;
		if (outer_hlen == 0)
			outer_hlen = ip_hdr_length_v6(mp, (ip6_t *)ipha);
		break;
	default:
		return (0);
	}

	if (first_mblkl < outer_hlen ||
	    (first_mblkl == outer_hlen && mp->b_cont == NULL))
		return (0);

	/*
	 * We don't bother doing a pullup here since the outer header will
	 * just get stripped off soon on input anyway.  We just want to ensure
	 * that the inner* pointer points to a full header.
	 */
	if (first_mblkl == outer_hlen) {
		inner_mp = mp->b_cont;
		ipha = (ipha_t *)inner_mp->b_rptr;
	} else {
		inner_mp = mp;
		ipha = (ipha_t *)(mp->b_rptr + outer_hlen);
	}
	switch (IPH_HDR_VERSION(ipha)) {
	case IPV4_VERSION:
		if (inner_mp->b_wptr - (uint8_t *)ipha < sizeof (ipha_t))
			return (0);
		*inner4 = ipha;
		*inner6 = NULL;
		break;
	case IPV6_VERSION:
		if (inner_mp->b_wptr - (uint8_t *)ipha < sizeof (ip6_t))
			return (0);
		*inner4 = NULL;
		*inner6 = (ip6_t *)ipha;
		break;
	default:
		return (0);
	}

	return (outer_hlen);
}

/*
 * Received ICMP error in response to an X over IPv4 packet that we
 * transmitted.
 *
 * NOTE: "outer" refers to what's inside the ICMP payload.  We will get one of
 * the following:
 *
 * [IPv4(0)][ICMPv4][IPv4(1)][IPv4(2)][ULP]
 *
 *	or
 *
 * [IPv4(0)][ICMPv4][IPv4(1)][IPv6][ULP]
 *
 * And "outer4" will get set to IPv4(1), and inner[46] will correspond to
 * whatever the very-inner packet is (IPv4(2) or IPv6).
 */
static void
iptun_input_icmp_v4(iptun_t *iptun, mblk_t *data_mp, icmph_t *icmph,
    ip_recv_attr_t *ira)
{
	uint8_t	*orig;
	ipha_t	*outer4, *inner4;
	ip6_t	*outer6, *inner6;
	int	outer_hlen;
	uint8_t	type, code;

	ASSERT(data_mp->b_cont == NULL);
	/*
	 * Temporarily move b_rptr forward so that iptun_find_headers() can
	 * find headers in the ICMP packet payload.
	 */
	orig = data_mp->b_rptr;
	data_mp->b_rptr = (uint8_t *)(icmph + 1);
	/*
	 * The ip module ensures that ICMP errors contain at least the
	 * original IP header (otherwise, the error would never have made it
	 * here).
	 */
	ASSERT(MBLKL(data_mp) >= 0);
	outer_hlen = iptun_find_headers(data_mp, 0, &outer4, &inner4, &outer6,
	    &inner6);
	ASSERT(outer6 == NULL);
	data_mp->b_rptr = orig;
	if (outer_hlen == 0) {
		iptun_drop_pkt(data_mp, &iptun->iptun_ierrors);
		return;
	}

	/* Only ICMP errors due to tunneled packets should reach here. */
	ASSERT(outer4->ipha_protocol == IPPROTO_ENCAP ||
	    outer4->ipha_protocol == IPPROTO_IPV6);

	data_mp = ipsec_tun_inbound(ira, data_mp, iptun->iptun_itp,
	    inner4, inner6, outer4, outer6, -outer_hlen, iptun->iptun_ns);
	if (data_mp == NULL) {
		/* Callee did all of the freeing. */
		atomic_inc_64(&iptun->iptun_ierrors);
		return;
	}
	/* We should never see reassembled fragment here. */
	ASSERT(data_mp->b_next == NULL);

	data_mp->b_rptr = (uint8_t *)outer4 + outer_hlen;

	/*
	 * If the original packet being transmitted was itself an ICMP error,
	 * then drop this packet.  We don't want to generate an ICMP error in
	 * response to an ICMP error.
	 */
	if (is_icmp_error(data_mp, inner4, inner6)) {
		iptun_drop_pkt(data_mp, &iptun->iptun_norcvbuf);
		return;
	}

	switch (icmph->icmph_type) {
	case ICMP_DEST_UNREACHABLE:
		type = (inner4 != NULL ? icmph->icmph_type : ICMP6_DST_UNREACH);
		switch (icmph->icmph_code) {
		case ICMP_FRAGMENTATION_NEEDED: {
			uint32_t newmtu;

			/*
			 * We reconcile this with the fact that the tunnel may
			 * also have IPsec policy by letting iptun_update_mtu
			 * take care of it.
			 */
			newmtu = iptun_update_mtu(iptun, NULL,
			    ntohs(icmph->icmph_du_mtu));

			if (inner4 != NULL) {
				iptun_icmp_fragneeded_v4(iptun, newmtu, inner4,
				    data_mp, ira->ira_tsl);
			} else {
				iptun_icmp_toobig_v6(iptun, newmtu, inner6,
				    data_mp, ira->ira_tsl);
			}
			return;
		}
		case ICMP_DEST_NET_UNREACH_ADMIN:
		case ICMP_DEST_HOST_UNREACH_ADMIN:
			code = (inner4 != NULL ? ICMP_DEST_NET_UNREACH_ADMIN :
			    ICMP6_DST_UNREACH_ADMIN);
			break;
		default:
			code = (inner4 != NULL ? ICMP_HOST_UNREACHABLE :
			    ICMP6_DST_UNREACH_ADDR);
			break;
		}
		break;
	case ICMP_TIME_EXCEEDED:
		if (inner6 != NULL) {
			type = ICMP6_TIME_EXCEEDED;
			code = 0;
		} /* else we're already set. */
		break;
	case ICMP_PARAM_PROBLEM:
		/*
		 * This is a problem with the outer header we transmitted.
		 * Treat this as an output error.
		 */
		iptun_drop_pkt(data_mp, &iptun->iptun_oerrors);
		return;
	default:
		iptun_drop_pkt(data_mp, &iptun->iptun_norcvbuf);
		return;
	}

	if (inner4 != NULL) {
		iptun_icmp_error_v4(iptun, inner4, data_mp, type, code,
		    ira->ira_tsl);
	} else {
		iptun_icmp_error_v6(iptun, inner6, data_mp, type, code, 0,
		    ira->ira_tsl);
	}
}

/*
 * Return B_TRUE if the IPv6 packet pointed to by ip6h contains a Tunnel
 * Encapsulation Limit destination option.  If there is one, set encaplim_ptr
 * to point to the option value.
 */
static boolean_t
iptun_find_encaplimit(mblk_t *mp, ip6_t *ip6h, uint8_t **encaplim_ptr)
{
	ip_pkt_t	pkt;
	uint8_t		*endptr;
	ip6_dest_t	*destp;
	struct ip6_opt	*optp;

	pkt.ipp_fields = 0; /* must be initialized */
	(void) ip_find_hdr_v6(mp, ip6h, B_FALSE, &pkt, NULL);
	if ((pkt.ipp_fields & IPPF_DSTOPTS) != 0) {
		destp = pkt.ipp_dstopts;
	} else if ((pkt.ipp_fields & IPPF_RTHDRDSTOPTS) != 0) {
		destp = pkt.ipp_rthdrdstopts;
	} else {
		return (B_FALSE);
	}

	endptr = (uint8_t *)destp + 8 * (destp->ip6d_len + 1);
	optp = (struct ip6_opt *)(destp + 1);
	while (endptr - (uint8_t *)optp > sizeof (*optp)) {
		if (optp->ip6o_type == IP6OPT_TUNNEL_LIMIT) {
			if ((uint8_t *)(optp + 1) >= endptr)
				return (B_FALSE);
			*encaplim_ptr = (uint8_t *)&optp[1];
			return (B_TRUE);
		}
		optp = (struct ip6_opt *)((uint8_t *)optp + optp->ip6o_len + 2);
	}
	return (B_FALSE);
}

/*
 * Received ICMPv6 error in response to an X over IPv6 packet that we
 * transmitted.
 *
 * NOTE: "outer" refers to what's inside the ICMP payload.  We will get one of
 * the following:
 *
 * [IPv6(0)][ICMPv6][IPv6(1)][IPv4][ULP]
 *
 *	or
 *
 * [IPv6(0)][ICMPv6][IPv6(1)][IPv6(2)][ULP]
 *
 * And "outer6" will get set to IPv6(1), and inner[46] will correspond to
 * whatever the very-inner packet is (IPv4 or IPv6(2)).
 */
static void
iptun_input_icmp_v6(iptun_t *iptun, mblk_t *data_mp, icmp6_t *icmp6h,
    ip_recv_attr_t *ira)
{
	uint8_t	*orig;
	ipha_t	*outer4, *inner4;
	ip6_t	*outer6, *inner6;
	int	outer_hlen;
	uint8_t	type, code;

	ASSERT(data_mp->b_cont == NULL);

	/*
	 * Temporarily move b_rptr forward so that iptun_find_headers() can
	 * find IP headers in the ICMP packet payload.
	 */
	orig = data_mp->b_rptr;
	data_mp->b_rptr = (uint8_t *)(icmp6h + 1);
	/*
	 * The ip module ensures that ICMP errors contain at least the
	 * original IP header (otherwise, the error would never have made it
	 * here).
	 */
	ASSERT(MBLKL(data_mp) >= 0);
	outer_hlen = iptun_find_headers(data_mp, 0, &outer4, &inner4, &outer6,
	    &inner6);
	ASSERT(outer4 == NULL);
	data_mp->b_rptr = orig;	/* Restore r_ptr */
	if (outer_hlen == 0) {
		iptun_drop_pkt(data_mp, &iptun->iptun_ierrors);
		return;
	}

	data_mp = ipsec_tun_inbound(ira, data_mp, iptun->iptun_itp,
	    inner4, inner6, outer4, outer6, -outer_hlen, iptun->iptun_ns);
	if (data_mp == NULL) {
		/* Callee did all of the freeing. */
		atomic_inc_64(&iptun->iptun_ierrors);
		return;
	}
	/* We should never see reassembled fragment here. */
	ASSERT(data_mp->b_next == NULL);

	data_mp->b_rptr = (uint8_t *)outer6 + outer_hlen;

	/*
	 * If the original packet being transmitted was itself an ICMP error,
	 * then drop this packet.  We don't want to generate an ICMP error in
	 * response to an ICMP error.
	 */
	if (is_icmp_error(data_mp, inner4, inner6)) {
		iptun_drop_pkt(data_mp, &iptun->iptun_norcvbuf);
		return;
	}

	switch (icmp6h->icmp6_type) {
	case ICMP6_PARAM_PROB: {
		uint8_t *encaplim_ptr;

		/*
		 * If the ICMPv6 error points to a valid Tunnel Encapsulation
		 * Limit option and the limit value is 0, then fall through
		 * and send a host unreachable message.  Otherwise, treat the
		 * error as an output error, as there must have been a problem
		 * with a packet we sent.
		 */
		if (!iptun_find_encaplimit(data_mp, outer6, &encaplim_ptr) ||
		    (icmp6h->icmp6_pptr !=
		    ((ptrdiff_t)encaplim_ptr - (ptrdiff_t)outer6)) ||
		    *encaplim_ptr != 0) {
			iptun_drop_pkt(data_mp, &iptun->iptun_oerrors);
			return;
		}
	}
	/* FALLTHROUGH */
	case ICMP6_TIME_EXCEEDED:
	case ICMP6_DST_UNREACH:
		type = (inner4 != NULL ? ICMP_DEST_UNREACHABLE :
		    ICMP6_DST_UNREACH);
		code = (inner4 != NULL ? ICMP_HOST_UNREACHABLE :
		    ICMP6_DST_UNREACH_ADDR);
		break;
	case ICMP6_PACKET_TOO_BIG: {
		uint32_t newmtu;

		/*
		 * We reconcile this with the fact that the tunnel may also
		 * have IPsec policy by letting iptun_update_mtu take care of
		 * it.
		 */
		newmtu = iptun_update_mtu(iptun, NULL,
		    ntohl(icmp6h->icmp6_mtu));

		if (inner4 != NULL) {
			iptun_icmp_fragneeded_v4(iptun, newmtu, inner4,
			    data_mp, ira->ira_tsl);
		} else {
			iptun_icmp_toobig_v6(iptun, newmtu, inner6, data_mp,
			    ira->ira_tsl);
		}
		return;
	}
	default:
		iptun_drop_pkt(data_mp, &iptun->iptun_norcvbuf);
		return;
	}

	if (inner4 != NULL) {
		iptun_icmp_error_v4(iptun, inner4, data_mp, type, code,
		    ira->ira_tsl);
	} else {
		iptun_icmp_error_v6(iptun, inner6, data_mp, type, code, 0,
		    ira->ira_tsl);
	}
}

/*
 * Called as conn_recvicmp from IP for ICMP errors.
 */
/* ARGSUSED2 */
static void
iptun_input_icmp(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	conn_t		*connp = arg;
	iptun_t		*iptun = connp->conn_iptun;
	mblk_t		*tmpmp;
	size_t		hlen;

	ASSERT(IPCL_IS_IPTUN(connp));

	if (mp->b_cont != NULL) {
		/*
		 * Since ICMP error processing necessitates access to bits
		 * that are within the ICMP error payload (the original packet
		 * that caused the error), pull everything up into a single
		 * block for convenience.
		 */
		if ((tmpmp = msgpullup(mp, -1)) == NULL) {
			iptun_drop_pkt(mp, &iptun->iptun_norcvbuf);
			return;
		}
		freemsg(mp);
		mp = tmpmp;
	}

	hlen = ira->ira_ip_hdr_length;
	switch (iptun->iptun_typeinfo->iti_ipvers) {
	case IPV4_VERSION:
		/*
		 * The outer IP header coming up from IP is always ipha_t
		 * alligned (otherwise, we would have crashed in ip).
		 */
		iptun_input_icmp_v4(iptun, mp, (icmph_t *)(mp->b_rptr + hlen),
		    ira);
		break;
	case IPV6_VERSION:
		iptun_input_icmp_v6(iptun, mp, (icmp6_t *)(mp->b_rptr + hlen),
		    ira);
		break;
	}
}

static boolean_t
iptun_in_6to4_ok(iptun_t *iptun, ipha_t *outer4, ip6_t *inner6)
{
	ipaddr_t v4addr;

	/*
	 * It's possible that someone sent us an IPv4-in-IPv4 packet with the
	 * IPv4 address of a 6to4 tunnel as the destination.
	 */
	if (inner6 == NULL)
		return (B_FALSE);

	/*
	 * Make sure that the IPv6 destination is within the site that this
	 * 6to4 tunnel is routing for.  We don't want people bouncing random
	 * tunneled IPv6 packets through this 6to4 router.
	 */
	IN6_6TO4_TO_V4ADDR(&inner6->ip6_dst, (struct in_addr *)&v4addr);
	if (outer4->ipha_dst != v4addr)
		return (B_FALSE);

	if (IN6_IS_ADDR_6TO4(&inner6->ip6_src)) {
		/*
		 * Section 9 of RFC 3056 (security considerations) suggests
		 * that when a packet is from a 6to4 site (i.e., it's not a
		 * global address being forwarded froma relay router), make
		 * sure that the packet was tunneled by that site's 6to4
		 * router.
		 */
		IN6_6TO4_TO_V4ADDR(&inner6->ip6_src, (struct in_addr *)&v4addr);
		if (outer4->ipha_src != v4addr)
			return (B_FALSE);
	} else {
		/*
		 * Only accept packets from a relay router if we've configured
		 * outbound relay router functionality.
		 */
		if (iptun->iptun_iptuns->iptuns_relay_rtr_addr == INADDR_ANY)
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Input function for everything that comes up from the ip module below us.
 * This is called directly from the ip module via connp->conn_recv().
 *
 * We receive M_DATA messages with IP-in-IP tunneled packets.
 */
/* ARGSUSED2 */
static void
iptun_input(void *arg, mblk_t *data_mp, void *arg2, ip_recv_attr_t *ira)
{
	conn_t	*connp = arg;
	iptun_t	*iptun = connp->conn_iptun;
	int	outer_hlen;
	ipha_t	*outer4, *inner4;
	ip6_t	*outer6, *inner6;

	ASSERT(IPCL_IS_IPTUN(connp));
	ASSERT(DB_TYPE(data_mp) == M_DATA);

	outer_hlen = iptun_find_headers(data_mp, ira->ira_ip_hdr_length,
	    &outer4, &inner4, &outer6, &inner6);
	if (outer_hlen == 0)
		goto drop;

	/*
	 * If the system is labeled, we call tsol_check_dest() on the packet
	 * destination (our local tunnel address) to ensure that the packet as
	 * labeled should be allowed to be sent to us.  We don't need to call
	 * the more involved tsol_receive_local() since the tunnel link itself
	 * cannot be assigned to shared-stack non-global zones.
	 */
	if (ira->ira_flags & IRAF_SYSTEM_LABELED) {
		if (ira->ira_tsl == NULL)
			goto drop;
		if (tsol_check_dest(ira->ira_tsl, (outer4 != NULL ?
		    (void *)&outer4->ipha_dst : (void *)&outer6->ip6_dst),
		    (outer4 != NULL ? IPV4_VERSION : IPV6_VERSION),
		    CONN_MAC_DEFAULT, B_FALSE, NULL) != 0)
			goto drop;
	}

	data_mp = ipsec_tun_inbound(ira, data_mp, iptun->iptun_itp,
	    inner4, inner6, outer4, outer6, outer_hlen, iptun->iptun_ns);
	if (data_mp == NULL) {
		/* Callee did all of the freeing. */
		return;
	}

	if (iptun->iptun_typeinfo->iti_type == IPTUN_TYPE_6TO4 &&
	    !iptun_in_6to4_ok(iptun, outer4, inner6))
		goto drop;

	/*
	 * We need to statistically account for each packet individually, so
	 * we might as well split up any b_next chains here.
	 */
	do {
		mblk_t	*mp;

		mp = data_mp->b_next;
		data_mp->b_next = NULL;

		atomic_inc_64(&iptun->iptun_ipackets);
		atomic_add_64(&iptun->iptun_rbytes, msgdsize(data_mp));
		mac_rx(iptun->iptun_mh, NULL, data_mp);

		data_mp = mp;
	} while (data_mp != NULL);
	return;
drop:
	iptun_drop_pkt(data_mp, &iptun->iptun_ierrors);
}

/*
 * Do 6to4-specific header-processing on output.  Return B_TRUE if the packet
 * was processed without issue, or B_FALSE if the packet had issues and should
 * be dropped.
 */
static boolean_t
iptun_out_process_6to4(iptun_t *iptun, ipha_t *outer4, ip6_t *inner6)
{
	ipaddr_t v4addr;

	/*
	 * IPv6 source must be a 6to4 address.  This is because a conscious
	 * decision was made to not allow a Solaris system to be used as a
	 * relay router (for security reasons) when 6to4 was initially
	 * integrated.  If this decision is ever reversed, the following check
	 * can be removed.
	 */
	if (!IN6_IS_ADDR_6TO4(&inner6->ip6_src))
		return (B_FALSE);

	/*
	 * RFC3056 mandates that the IPv4 source MUST be set to the IPv4
	 * portion of the 6to4 IPv6 source address.  In other words, make sure
	 * that we're tunneling packets from our own 6to4 site.
	 */
	IN6_6TO4_TO_V4ADDR(&inner6->ip6_src, (struct in_addr *)&v4addr);
	if (outer4->ipha_src != v4addr)
		return (B_FALSE);

	/*
	 * Automatically set the destination of the outer IPv4 header as
	 * described in RFC3056.  There are two possibilities:
	 *
	 * a. If the IPv6 destination is a 6to4 address, set the IPv4 address
	 *    to the IPv4 portion of the 6to4 address.
	 * b. If the IPv6 destination is a native IPv6 address, set the IPv4
	 *    destination to the address of a relay router.
	 *
	 * Design Note: b shouldn't be necessary here, and this is a flaw in
	 * the design of the 6to4relay command.  Instead of setting a 6to4
	 * relay address in this module via an ioctl, the 6to4relay command
	 * could simply add a IPv6 route for native IPv6 addresses (such as a
	 * default route) in the forwarding table that uses a 6to4 destination
	 * as its next hop, and the IPv4 portion of that address could be a
	 * 6to4 relay address.  In order for this to work, IP would have to
	 * resolve the next hop address, which would necessitate a link-layer
	 * address resolver for 6to4 links, which doesn't exist today.
	 *
	 * In fact, if a resolver existed for 6to4 links, then setting the
	 * IPv4 destination in the outer header could be done as part of
	 * link-layer address resolution and fast-path header generation, and
	 * not here.
	 */
	if (IN6_IS_ADDR_6TO4(&inner6->ip6_dst)) {
		/* destination is a 6to4 router */
		IN6_6TO4_TO_V4ADDR(&inner6->ip6_dst,
		    (struct in_addr *)&outer4->ipha_dst);

		/* Reject attempts to send to INADDR_ANY */
		if (outer4->ipha_dst == INADDR_ANY)
			return (B_FALSE);
	} else {
		/*
		 * The destination is a native IPv6 address.  If output to a
		 * relay-router is enabled, use the relay-router's IPv4
		 * address as the destination.
		 */
		if (iptun->iptun_iptuns->iptuns_relay_rtr_addr == INADDR_ANY)
			return (B_FALSE);
		outer4->ipha_dst = iptun->iptun_iptuns->iptuns_relay_rtr_addr;
	}

	/*
	 * If the outer source and destination are equal, this means that the
	 * 6to4 router somehow forwarded an IPv6 packet destined for its own
	 * 6to4 site to its 6to4 tunnel interface, which will result in this
	 * packet infinitely bouncing between ip and iptun.
	 */
	return (outer4->ipha_src != outer4->ipha_dst);
}

/*
 * Process output packets with outer IPv4 headers.  Frees mp and bumps stat on
 * error.
 */
static mblk_t *
iptun_out_process_ipv4(iptun_t *iptun, mblk_t *mp, ipha_t *outer4,
    ipha_t *inner4, ip6_t *inner6, ip_xmit_attr_t *ixa)
{
	uint8_t	*innerptr = (inner4 != NULL ?
	    (uint8_t *)inner4 : (uint8_t *)inner6);
	size_t	minmtu = iptun->iptun_typeinfo->iti_minmtu;

	if (inner4 != NULL) {
		ASSERT(outer4->ipha_protocol == IPPROTO_ENCAP);
		/*
		 * Copy the tos from the inner IPv4 header. We mask off ECN
		 * bits (bits 6 and 7) because there is currently no
		 * tunnel-tunnel communication to determine if both sides
		 * support ECN.  We opt for the safe choice: don't copy the
		 * ECN bits when doing encapsulation.
		 */
		outer4->ipha_type_of_service =
		    inner4->ipha_type_of_service & ~0x03;
	} else {
		ASSERT(outer4->ipha_protocol == IPPROTO_IPV6 &&
		    inner6 != NULL);
	}
	if (ixa->ixa_flags & IXAF_PMTU_IPV4_DF)
		outer4->ipha_fragment_offset_and_flags |= IPH_DF_HTONS;
	else
		outer4->ipha_fragment_offset_and_flags &= ~IPH_DF_HTONS;

	/*
	 * As described in section 3.2.2 of RFC4213, if the packet payload is
	 * less than or equal to the minimum MTU size, then we need to allow
	 * IPv4 to fragment the packet.  The reason is that even if we end up
	 * receiving an ICMP frag-needed, the interface above this tunnel
	 * won't be allowed to drop its MTU as a result, since the packet was
	 * already smaller than the smallest allowable MTU for that interface.
	 */
	if (mp->b_wptr - innerptr <= minmtu) {
		outer4->ipha_fragment_offset_and_flags = 0;
		ixa->ixa_flags &= ~IXAF_DONTFRAG;
	} else if (!(ixa->ixa_flags & IXAF_PMTU_TOO_SMALL) &&
	    (iptun->iptun_typeinfo->iti_type != IPTUN_TYPE_6TO4)) {
		ixa->ixa_flags |= IXAF_DONTFRAG;
	}

	ixa->ixa_ip_hdr_length = IPH_HDR_LENGTH(outer4);
	ixa->ixa_pktlen = msgdsize(mp);
	ixa->ixa_protocol = outer4->ipha_protocol;

	outer4->ipha_length = htons(ixa->ixa_pktlen);
	return (mp);
}

/*
 * Insert an encapsulation limit destination option in the packet provided.
 * Always consumes the mp argument and returns a new mblk pointer.
 */
static mblk_t *
iptun_insert_encaplimit(iptun_t *iptun, mblk_t *mp, ip6_t *outer6,
    uint8_t limit)
{
	mblk_t			*newmp;
	iptun_ipv6hdrs_t	*newouter6;

	ASSERT(outer6->ip6_nxt == IPPROTO_IPV6);
	ASSERT(mp->b_cont == NULL);

	mp->b_rptr += sizeof (ip6_t);
	newmp = allocb(sizeof (iptun_ipv6hdrs_t) + MBLKL(mp), BPRI_MED);
	if (newmp == NULL) {
		iptun_drop_pkt(mp, &iptun->iptun_noxmtbuf);
		return (NULL);
	}
	newmp->b_wptr += sizeof (iptun_ipv6hdrs_t);
	/* Copy the payload (Starting with the inner IPv6 header). */
	bcopy(mp->b_rptr, newmp->b_wptr, MBLKL(mp));
	newmp->b_wptr += MBLKL(mp);
	newouter6 = (iptun_ipv6hdrs_t *)newmp->b_rptr;
	/* Now copy the outer IPv6 header. */
	bcopy(outer6, &newouter6->it6h_ip6h, sizeof (ip6_t));
	newouter6->it6h_ip6h.ip6_nxt = IPPROTO_DSTOPTS;
	newouter6->it6h_encaplim = iptun_encaplim_init;
	newouter6->it6h_encaplim.iel_destopt.ip6d_nxt = outer6->ip6_nxt;
	newouter6->it6h_encaplim.iel_telopt.ip6ot_encap_limit = limit;

	/*
	 * The payload length will be set at the end of
	 * iptun_out_process_ipv6().
	 */

	freemsg(mp);
	return (newmp);
}

/*
 * Process output packets with outer IPv6 headers.  Frees mp and bumps stats
 * on error.
 */
static mblk_t *
iptun_out_process_ipv6(iptun_t *iptun, mblk_t *mp, ip6_t *outer6,
    ipha_t *inner4, ip6_t *inner6, ip_xmit_attr_t *ixa)
{
	uint8_t		*innerptr = (inner4 != NULL ?
	    (uint8_t *)inner4 : (uint8_t *)inner6);
	size_t		minmtu = iptun->iptun_typeinfo->iti_minmtu;
	uint8_t		*limit, *configlimit;
	uint32_t	offset;
	iptun_ipv6hdrs_t *v6hdrs;

	if (inner6 != NULL && iptun_find_encaplimit(mp, inner6, &limit)) {
		/*
		 * The inner packet is an IPv6 packet which itself contains an
		 * encapsulation limit option.  The limit variable points to
		 * the value in the embedded option.  Process the
		 * encapsulation limit option as specified in RFC 2473.
		 *
		 * If limit is 0, then we've exceeded the limit and we need to
		 * send back an ICMPv6 parameter problem message.
		 *
		 * If limit is > 0, then we decrement it by 1 and make sure
		 * that the encapsulation limit option in the outer header
		 * reflects that (adding an option if one isn't already
		 * there).
		 */
		ASSERT(limit > mp->b_rptr && limit < mp->b_wptr);
		if (*limit == 0) {
			mp->b_rptr = (uint8_t *)inner6;
			offset = limit - mp->b_rptr;
			iptun_icmp_error_v6(iptun, inner6, mp, ICMP6_PARAM_PROB,
			    0, offset, ixa->ixa_tsl);
			atomic_inc_64(&iptun->iptun_noxmtbuf);
			return (NULL);
		}

		/*
		 * The outer header requires an encapsulation limit option.
		 * If there isn't one already, add one.
		 */
		if (iptun->iptun_encaplimit == 0) {
			if ((mp = iptun_insert_encaplimit(iptun, mp, outer6,
			    (*limit - 1))) == NULL)
				return (NULL);
			v6hdrs = (iptun_ipv6hdrs_t *)mp->b_rptr;
		} else {
			/*
			 * There is an existing encapsulation limit option in
			 * the outer header.  If the inner encapsulation limit
			 * is less than the configured encapsulation limit,
			 * update the outer encapsulation limit to reflect
			 * this lesser value.
			 */
			v6hdrs = (iptun_ipv6hdrs_t *)mp->b_rptr;
			configlimit =
			    &v6hdrs->it6h_encaplim.iel_telopt.ip6ot_encap_limit;
			if ((*limit - 1) < *configlimit)
				*configlimit = (*limit - 1);
		}
		ixa->ixa_ip_hdr_length = sizeof (iptun_ipv6hdrs_t);
		ixa->ixa_protocol = v6hdrs->it6h_encaplim.iel_destopt.ip6d_nxt;
	} else {
		ixa->ixa_ip_hdr_length = sizeof (ip6_t);
		ixa->ixa_protocol = outer6->ip6_nxt;
	}
	/*
	 * See iptun_output_process_ipv4() why we allow fragmentation for
	 * small packets
	 */
	if (mp->b_wptr - innerptr <= minmtu)
		ixa->ixa_flags &= ~IXAF_DONTFRAG;
	else if (!(ixa->ixa_flags & IXAF_PMTU_TOO_SMALL))
		ixa->ixa_flags |= IXAF_DONTFRAG;

	ixa->ixa_pktlen = msgdsize(mp);
	outer6->ip6_plen = htons(ixa->ixa_pktlen - sizeof (ip6_t));
	return (mp);
}

/*
 * The IP tunneling MAC-type plugins have already done most of the header
 * processing and validity checks.  We are simply responsible for multiplexing
 * down to the ip module below us.
 */
static void
iptun_output(iptun_t *iptun, mblk_t *mp)
{
	conn_t	*connp = iptun->iptun_connp;
	mblk_t	*newmp;
	int	error;
	ip_xmit_attr_t	*ixa;

	ASSERT(mp->b_datap->db_type == M_DATA);

	if (mp->b_cont != NULL) {
		if ((newmp = msgpullup(mp, -1)) == NULL) {
			iptun_drop_pkt(mp, &iptun->iptun_noxmtbuf);
			return;
		}
		freemsg(mp);
		mp = newmp;
	}

	if (iptun->iptun_typeinfo->iti_type == IPTUN_TYPE_6TO4) {
		iptun_output_6to4(iptun, mp);
		return;
	}

	if (is_system_labeled()) {
		/*
		 * Since the label can be different meaning a potentially
		 * different IRE,we always use a unique ip_xmit_attr_t.
		 */
		ixa = conn_get_ixa_exclusive(connp);
	} else {
		/*
		 * If no other thread is using conn_ixa this just gets a
		 * reference to conn_ixa. Otherwise we get a safe copy of
		 * conn_ixa.
		 */
		ixa = conn_get_ixa(connp, B_FALSE);
	}
	if (ixa == NULL) {
		iptun_drop_pkt(mp, &iptun->iptun_oerrors);
		return;
	}

	/*
	 * In case we got a safe copy of conn_ixa, then we need
	 * to fill in any pointers in it.
	 */
	if (ixa->ixa_ire == NULL) {
		error = ip_attr_connect(connp, ixa, &connp->conn_saddr_v6,
		    &connp->conn_faddr_v6, &connp->conn_faddr_v6, 0,
		    NULL, NULL, 0);
		if (error != 0) {
			if (ixa->ixa_ire != NULL &&
			    (error == EHOSTUNREACH || error == ENETUNREACH)) {
				/*
				 * Let conn_ip_output/ire_send_noroute return
				 * the error and send any local ICMP error.
				 */
				error = 0;
			} else {
				ixa_refrele(ixa);
				iptun_drop_pkt(mp, &iptun->iptun_oerrors);
				return;
			}
		}
	}

	iptun_output_common(iptun, ixa, mp);
	ixa_refrele(ixa);
}

/*
 * We use an ixa based on the last destination.
 */
static void
iptun_output_6to4(iptun_t *iptun, mblk_t *mp)
{
	conn_t		*connp = iptun->iptun_connp;
	ipha_t		*outer4, *inner4;
	ip6_t		*outer6, *inner6;
	ip_xmit_attr_t	*ixa;
	ip_xmit_attr_t	*oldixa;
	int		error;
	boolean_t	need_connect;
	in6_addr_t	v6dst;

	ASSERT(mp->b_cont == NULL);	/* Verified by iptun_output */

	/* Make sure we set ipha_dst before we look at ipha_dst */

	(void) iptun_find_headers(mp, 0, &outer4, &inner4, &outer6, &inner6);
	ASSERT(outer4 != NULL);
	if (!iptun_out_process_6to4(iptun, outer4, inner6)) {
		iptun_drop_pkt(mp, &iptun->iptun_oerrors);
		return;
	}

	if (is_system_labeled()) {
		/*
		 * Since the label can be different meaning a potentially
		 * different IRE,we always use a unique ip_xmit_attr_t.
		 */
		ixa = conn_get_ixa_exclusive(connp);
	} else {
		/*
		 * If no other thread is using conn_ixa this just gets a
		 * reference to conn_ixa. Otherwise we get a safe copy of
		 * conn_ixa.
		 */
		ixa = conn_get_ixa(connp, B_FALSE);
	}
	if (ixa == NULL) {
		iptun_drop_pkt(mp, &iptun->iptun_oerrors);
		return;
	}

	mutex_enter(&connp->conn_lock);
	if (connp->conn_v4lastdst == outer4->ipha_dst) {
		need_connect = (ixa->ixa_ire == NULL);
	} else {
		/* In case previous destination was multirt */
		ip_attr_newdst(ixa);

		/*
		 * We later update conn_ixa when we update conn_v4lastdst
		 * which enables subsequent packets to avoid redoing
		 * ip_attr_connect
		 */
		need_connect = B_TRUE;
	}
	mutex_exit(&connp->conn_lock);

	/*
	 * In case we got a safe copy of conn_ixa, or otherwise we don't
	 * have a current ixa_ire, then we need to fill in any pointers in
	 * the ixa.
	 */
	if (need_connect) {
		IN6_IPADDR_TO_V4MAPPED(outer4->ipha_dst, &v6dst);

		/* We handle IPsec in iptun_output_common */
		error = ip_attr_connect(connp, ixa, &connp->conn_saddr_v6,
		    &v6dst, &v6dst, 0, NULL, NULL, 0);
		if (error != 0) {
			if (ixa->ixa_ire != NULL &&
			    (error == EHOSTUNREACH || error == ENETUNREACH)) {
				/*
				 * Let conn_ip_output/ire_send_noroute return
				 * the error and send any local ICMP error.
				 */
				error = 0;
			} else {
				ixa_refrele(ixa);
				iptun_drop_pkt(mp, &iptun->iptun_oerrors);
				return;
			}
		}
	}

	iptun_output_common(iptun, ixa, mp);

	/* Atomically replace conn_ixa and conn_v4lastdst */
	mutex_enter(&connp->conn_lock);
	if (connp->conn_v4lastdst != outer4->ipha_dst) {
		/* Remember the dst which corresponds to conn_ixa */
		connp->conn_v6lastdst = v6dst;
		oldixa = conn_replace_ixa(connp, ixa);
	} else {
		oldixa = NULL;
	}
	mutex_exit(&connp->conn_lock);
	ixa_refrele(ixa);
	if (oldixa != NULL)
		ixa_refrele(oldixa);
}

/*
 * Check the destination/label. Modifies *mpp by adding/removing CIPSO.
 *
 * We get the label from the message in order to honor the
 * ULPs/IPs choice of label. This will be NULL for forwarded
 * packets, neighbor discovery packets and some others.
 */
static int
iptun_output_check_label(mblk_t **mpp, ip_xmit_attr_t *ixa)
{
	cred_t	*cr;
	int	adjust;
	int	iplen;
	int	err;
	ts_label_t *effective_tsl = NULL;


	ASSERT(is_system_labeled());

	cr = msg_getcred(*mpp, NULL);
	if (cr == NULL)
		return (0);

	/*
	 * We need to start with a label based on the IP/ULP above us
	 */
	ip_xmit_attr_restore_tsl(ixa, cr);

	/*
	 * Need to update packet with any CIPSO option since
	 * conn_ip_output doesn't do that.
	 */
	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha_t *ipha;

		ipha = (ipha_t *)(*mpp)->b_rptr;
		iplen = ntohs(ipha->ipha_length);
		err = tsol_check_label_v4(ixa->ixa_tsl,
		    ixa->ixa_zoneid, mpp, CONN_MAC_DEFAULT, B_FALSE,
		    ixa->ixa_ipst, &effective_tsl);
		if (err != 0)
			return (err);

		ipha = (ipha_t *)(*mpp)->b_rptr;
		adjust = (int)ntohs(ipha->ipha_length) - iplen;
	} else {
		ip6_t *ip6h;

		ip6h = (ip6_t *)(*mpp)->b_rptr;
		iplen = ntohs(ip6h->ip6_plen);

		err = tsol_check_label_v6(ixa->ixa_tsl,
		    ixa->ixa_zoneid, mpp, CONN_MAC_DEFAULT, B_FALSE,
		    ixa->ixa_ipst, &effective_tsl);
		if (err != 0)
			return (err);

		ip6h = (ip6_t *)(*mpp)->b_rptr;
		adjust = (int)ntohs(ip6h->ip6_plen) - iplen;
	}

	if (effective_tsl != NULL) {
		/* Update the label */
		ip_xmit_attr_replace_tsl(ixa, effective_tsl);
	}
	ixa->ixa_pktlen += adjust;
	ixa->ixa_ip_hdr_length += adjust;
	return (0);
}


static void
iptun_output_common(iptun_t *iptun, ip_xmit_attr_t *ixa, mblk_t *mp)
{
	ipsec_tun_pol_t	*itp = iptun->iptun_itp;
	int		outer_hlen;
	mblk_t		*newmp;
	ipha_t		*outer4, *inner4;
	ip6_t		*outer6, *inner6;
	int		error;
	boolean_t	update_pktlen;

	ASSERT(ixa->ixa_ire != NULL);

	outer_hlen = iptun_find_headers(mp, 0, &outer4, &inner4, &outer6,
	    &inner6);
	if (outer_hlen == 0) {
		iptun_drop_pkt(mp, &iptun->iptun_oerrors);
		return;
	}

	/* Save IXAF_DONTFRAG value */
	iaflags_t dontfrag = ixa->ixa_flags & IXAF_DONTFRAG;

	/* Perform header processing. */
	if (outer4 != NULL) {
		mp = iptun_out_process_ipv4(iptun, mp, outer4, inner4, inner6,
		    ixa);
	} else {
		mp = iptun_out_process_ipv6(iptun, mp, outer6, inner4, inner6,
		    ixa);
	}
	if (mp == NULL)
		return;

	/*
	 * Let's hope the compiler optimizes this with "branch taken".
	 */
	if (itp != NULL && (itp->itp_flags & ITPF_P_ACTIVE)) {
		/* This updates the ip_xmit_attr_t */
		mp = ipsec_tun_outbound(mp, iptun, inner4, inner6, outer4,
		    outer6, outer_hlen, ixa);
		if (mp == NULL) {
			atomic_inc_64(&iptun->iptun_oerrors);
			return;
		}
		if (is_system_labeled()) {
			/*
			 * Might change the packet by adding/removing CIPSO.
			 * After this caller inner* and outer* and outer_hlen
			 * might be invalid.
			 */
			error = iptun_output_check_label(&mp, ixa);
			if (error != 0) {
				ip2dbg(("label check failed (%d)\n", error));
				iptun_drop_pkt(mp, &iptun->iptun_oerrors);
				return;
			}
		}

		/*
		 * ipsec_tun_outbound() returns a chain of tunneled IP
		 * fragments linked with b_next (or a single message if the
		 * tunneled packet wasn't a fragment).
		 * If fragcache returned a list then we need to update
		 * ixa_pktlen for all packets in the list.
		 */
		update_pktlen = (mp->b_next != NULL);

		/*
		 * Otherwise, we're good to go.  The ixa has been updated with
		 * instructions for outbound IPsec processing.
		 */
		for (newmp = mp; newmp != NULL; newmp = mp) {
			size_t minmtu = iptun->iptun_typeinfo->iti_minmtu;

			atomic_inc_64(&iptun->iptun_opackets);
			atomic_add_64(&iptun->iptun_obytes, ixa->ixa_pktlen);
			mp = mp->b_next;
			newmp->b_next = NULL;

			/*
			 * The IXAF_DONTFRAG flag is global, but there is
			 * a chain here.  Check if we're really already
			 * smaller than the minimum allowed MTU and reset here
			 * appropriately.  Otherwise one small packet can kill
			 * the whole chain's path mtu discovery.
			 * In addition, update the pktlen to the length of
			 * the actual packet being processed.
			 */
			if (update_pktlen) {
				ixa->ixa_pktlen = msgdsize(newmp);
				if (ixa->ixa_pktlen <= minmtu)
					ixa->ixa_flags &= ~IXAF_DONTFRAG;
			}

			atomic_inc_64(&iptun->iptun_opackets);
			atomic_add_64(&iptun->iptun_obytes, ixa->ixa_pktlen);

			error = conn_ip_output(newmp, ixa);

			/* Restore IXAF_DONTFRAG value */
			ixa->ixa_flags |= dontfrag;

			if (error == EMSGSIZE) {
				/* IPsec policy might have changed */
				(void) iptun_update_mtu(iptun, ixa, 0);
			}
		}
	} else {
		/*
		 * The ip module will potentially apply global policy to the
		 * packet in its output path if there's no active tunnel
		 * policy.
		 */
		ASSERT(ixa->ixa_ipsec_policy == NULL);
		mp = ip_output_attach_policy(mp, outer4, outer6, NULL, ixa);
		if (mp == NULL) {
			atomic_inc_64(&iptun->iptun_oerrors);
			return;
		}
		if (is_system_labeled()) {
			/*
			 * Might change the packet by adding/removing CIPSO.
			 * After this caller inner* and outer* and outer_hlen
			 * might be invalid.
			 */
			error = iptun_output_check_label(&mp, ixa);
			if (error != 0) {
				ip2dbg(("label check failed (%d)\n", error));
				iptun_drop_pkt(mp, &iptun->iptun_oerrors);
				return;
			}
		}

		atomic_inc_64(&iptun->iptun_opackets);
		atomic_add_64(&iptun->iptun_obytes, ixa->ixa_pktlen);

		error = conn_ip_output(mp, ixa);
		if (error == EMSGSIZE) {
			/* IPsec policy might have changed */
			(void) iptun_update_mtu(iptun, ixa, 0);
		}
	}
	if (ixa->ixa_flags & IXAF_IPSEC_SECURE)
		ipsec_out_release_refs(ixa);
}

static mac_callbacks_t iptun_m_callbacks = {
	.mc_callbacks	= (MC_SETPROP | MC_GETPROP | MC_PROPINFO),
	.mc_getstat	= iptun_m_getstat,
	.mc_start	= iptun_m_start,
	.mc_stop	= iptun_m_stop,
	.mc_setpromisc	= iptun_m_setpromisc,
	.mc_multicst	= iptun_m_multicst,
	.mc_unicst	= iptun_m_unicst,
	.mc_tx		= iptun_m_tx,
	.mc_reserved	= NULL,
	.mc_setprop	= iptun_m_setprop,
	.mc_getprop	= iptun_m_getprop,
	.mc_propinfo	= iptun_m_propinfo
};
