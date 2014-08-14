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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/list.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/sctp.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_ire.h>
#include <inet/ip_if.h>
#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>
#include "sctp_impl.h"
#include "sctp_addr.h"

static void		sctp_ipif_inactive(sctp_ipif_t *);
static sctp_ipif_t	*sctp_lookup_ipif_addr(in6_addr_t *, boolean_t,
			    zoneid_t, boolean_t, uint_t, uint_t, boolean_t,
			    sctp_stack_t *);
static int		sctp_get_all_ipifs(sctp_t *, int);
static int		sctp_ipif_hash_insert(sctp_t *, sctp_ipif_t *, int,
			    boolean_t, boolean_t);
static void		sctp_ipif_hash_remove(sctp_t *, sctp_ipif_t *,
			    boolean_t);
static void		sctp_fix_saddr(sctp_t *, in6_addr_t *);
static int		sctp_compare_ipif_list(sctp_ipif_hash_t *,
			    sctp_ipif_hash_t *);
static int		sctp_copy_ipifs(sctp_ipif_hash_t *, sctp_t *, int);

#define	SCTP_ADDR4_HASH(addr)	\
	(((addr) ^ ((addr) >> 8) ^ ((addr) >> 16) ^ ((addr) >> 24)) &	\
	(SCTP_IPIF_HASH - 1))

#define	SCTP_ADDR6_HASH(addr)	\
	(((addr).s6_addr32[3] ^						\
	(((addr).s6_addr32[3] ^ (addr).s6_addr32[2]) >> 12)) &		\
	(SCTP_IPIF_HASH - 1))

#define	SCTP_IPIF_ADDR_HASH(addr, isv6)					\
	((isv6) ? SCTP_ADDR6_HASH((addr)) : 				\
	SCTP_ADDR4_HASH((addr)._S6_un._S6_u32[3]))

#define	SCTP_IPIF_USABLE(sctp_ipif_state)	\
	((sctp_ipif_state) == SCTP_IPIFS_UP ||	\
	(sctp_ipif_state) ==  SCTP_IPIFS_DOWN)

#define	SCTP_IPIF_DISCARD(sctp_ipif_flags)	\
	((sctp_ipif_flags) & (IPIF_PRIVATE | IPIF_DEPRECATED))

#define	SCTP_IS_IPIF_LOOPBACK(ipif)		\
	((ipif)->sctp_ipif_ill->sctp_ill_flags & PHYI_LOOPBACK)

#define	SCTP_IS_IPIF_LINKLOCAL(ipif)		\
	((ipif)->sctp_ipif_isv6 && 		\
	IN6_IS_ADDR_LINKLOCAL(&(ipif)->sctp_ipif_saddr))

#define	SCTP_UNSUPP_AF(ipif, supp_af)	\
	((!(ipif)->sctp_ipif_isv6 && !((supp_af) & PARM_SUPP_V4)) ||	\
	((ipif)->sctp_ipif_isv6 && !((supp_af) & PARM_SUPP_V6)))

#define	SCTP_IPIF_ZONE_MATCH(sctp, ipif) 				\
	IPCL_ZONE_MATCH((sctp)->sctp_connp, (ipif)->sctp_ipif_zoneid)

#define	SCTP_ILL_HASH_FN(index)		((index) % SCTP_ILL_HASH)
#define	SCTP_ILL_TO_PHYINDEX(ill)	((ill)->ill_phyint->phyint_ifindex)

/*
 * SCTP Interface list manipulation functions, locking used.
 */

/*
 * Delete an SCTP IPIF from the list if the refcount goes to 0 and it is
 * marked as condemned. Also, check if the ILL needs to go away.
 */
static void
sctp_ipif_inactive(sctp_ipif_t *sctp_ipif)
{
	sctp_ill_t	*sctp_ill;
	uint_t		hindex;
	uint_t		ill_index;
	sctp_stack_t	*sctps = sctp_ipif->sctp_ipif_ill->
	    sctp_ill_netstack->netstack_sctp;

	rw_enter(&sctps->sctps_g_ills_lock, RW_READER);
	rw_enter(&sctps->sctps_g_ipifs_lock, RW_WRITER);

	hindex = SCTP_IPIF_ADDR_HASH(sctp_ipif->sctp_ipif_saddr,
	    sctp_ipif->sctp_ipif_isv6);

	sctp_ill = sctp_ipif->sctp_ipif_ill;
	ASSERT(sctp_ill != NULL);
	ill_index = SCTP_ILL_HASH_FN(sctp_ill->sctp_ill_index);
	if (sctp_ipif->sctp_ipif_state != SCTP_IPIFS_CONDEMNED ||
	    sctp_ipif->sctp_ipif_refcnt != 0) {
		rw_exit(&sctps->sctps_g_ipifs_lock);
		rw_exit(&sctps->sctps_g_ills_lock);
		return;
	}
	list_remove(&sctps->sctps_g_ipifs[hindex].sctp_ipif_list,
	    sctp_ipif);
	sctps->sctps_g_ipifs[hindex].ipif_count--;
	sctps->sctps_g_ipifs_count--;
	rw_destroy(&sctp_ipif->sctp_ipif_lock);
	kmem_free(sctp_ipif, sizeof (sctp_ipif_t));

	atomic_dec_32(&sctp_ill->sctp_ill_ipifcnt);
	if (rw_tryupgrade(&sctps->sctps_g_ills_lock) != 0) {
		rw_downgrade(&sctps->sctps_g_ipifs_lock);
		if (sctp_ill->sctp_ill_ipifcnt == 0 &&
		    sctp_ill->sctp_ill_state == SCTP_ILLS_CONDEMNED) {
			list_remove(&sctps->sctps_g_ills[ill_index].
			    sctp_ill_list, (void *)sctp_ill);
			sctps->sctps_g_ills[ill_index].ill_count--;
			sctps->sctps_ills_count--;
			kmem_free(sctp_ill->sctp_ill_name,
			    sctp_ill->sctp_ill_name_length);
			kmem_free(sctp_ill, sizeof (sctp_ill_t));
		}
	}
	rw_exit(&sctps->sctps_g_ipifs_lock);
	rw_exit(&sctps->sctps_g_ills_lock);
}

/*
 * Lookup an SCTP IPIF given an IP address. Increments sctp_ipif refcnt.
 * We are either looking for a IPIF with the given address before
 * inserting it into the global list or looking for an IPIF for an
 * address given an SCTP. In the former case we always check the zoneid,
 * but for the latter case, check_zid could be B_FALSE if the connp
 * for the sctp has conn_all_zones set. When looking for an address we
 * give preference to one that is up, so even though we may find one that
 * is not up we keep looking if there is one up, we hold the down addr
 * in backup_ipif in case we don't find one that is up - i.e. we return
 * the backup_ipif in that case. Note that if we are looking for. If we
 * are specifically looking for an up address, then usable will be set
 * to true.
 */
static sctp_ipif_t *
sctp_lookup_ipif_addr(in6_addr_t *addr, boolean_t refhold, zoneid_t zoneid,
    boolean_t check_zid, uint_t ifindex, uint_t seqid, boolean_t usable,
    sctp_stack_t *sctps)
{
	int		j;
	sctp_ipif_t	*sctp_ipif;
	sctp_ipif_t	*backup_ipif = NULL;
	int		hindex;

	hindex = SCTP_IPIF_ADDR_HASH(*addr, !IN6_IS_ADDR_V4MAPPED(addr));

	rw_enter(&sctps->sctps_g_ipifs_lock, RW_READER);
	if (sctps->sctps_g_ipifs[hindex].ipif_count == 0) {
		rw_exit(&sctps->sctps_g_ipifs_lock);
		return (NULL);
	}
	sctp_ipif = list_head(&sctps->sctps_g_ipifs[hindex].sctp_ipif_list);
	for (j = 0; j < sctps->sctps_g_ipifs[hindex].ipif_count; j++) {
		rw_enter(&sctp_ipif->sctp_ipif_lock, RW_READER);
		if ((!check_zid ||
		    (sctp_ipif->sctp_ipif_zoneid == ALL_ZONES ||
		    zoneid == sctp_ipif->sctp_ipif_zoneid)) &&
		    (ifindex == 0 || ifindex ==
		    sctp_ipif->sctp_ipif_ill->sctp_ill_index) &&
		    ((seqid != 0 && seqid == sctp_ipif->sctp_ipif_id) ||
		    (IN6_ARE_ADDR_EQUAL(&sctp_ipif->sctp_ipif_saddr,
		    addr)))) {
			if (!usable || sctp_ipif->sctp_ipif_state ==
			    SCTP_IPIFS_UP) {
				rw_exit(&sctp_ipif->sctp_ipif_lock);
				if (refhold)
					SCTP_IPIF_REFHOLD(sctp_ipif);
				rw_exit(&sctps->sctps_g_ipifs_lock);
				return (sctp_ipif);
			} else if (sctp_ipif->sctp_ipif_state ==
			    SCTP_IPIFS_DOWN && backup_ipif == NULL) {
				backup_ipif = sctp_ipif;
			}
		}
		rw_exit(&sctp_ipif->sctp_ipif_lock);
		sctp_ipif = list_next(
		    &sctps->sctps_g_ipifs[hindex].sctp_ipif_list, sctp_ipif);
	}
	if (backup_ipif != NULL) {
		if (refhold)
			SCTP_IPIF_REFHOLD(backup_ipif);
		rw_exit(&sctps->sctps_g_ipifs_lock);
		return (backup_ipif);
	}
	rw_exit(&sctps->sctps_g_ipifs_lock);
	return (NULL);
}

/*
 * Populate the list with all the SCTP ipifs for a given ipversion.
 * Increments sctp_ipif refcnt.
 * Called with no locks held.
 */
static int
sctp_get_all_ipifs(sctp_t *sctp, int sleep)
{
	sctp_ipif_t		*sctp_ipif;
	int			i;
	int			j;
	int			error = 0;
	sctp_stack_t		*sctps = sctp->sctp_sctps;
	boolean_t		isv6;
	conn_t			*connp = sctp->sctp_connp;

	rw_enter(&sctps->sctps_g_ipifs_lock, RW_READER);
	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		if (sctps->sctps_g_ipifs[i].ipif_count == 0)
			continue;
		sctp_ipif = list_head(&sctps->sctps_g_ipifs[i].sctp_ipif_list);
		for (j = 0; j < sctps->sctps_g_ipifs[i].ipif_count; j++) {
			rw_enter(&sctp_ipif->sctp_ipif_lock, RW_READER);
			isv6 = sctp_ipif->sctp_ipif_isv6;
			if (SCTP_IPIF_DISCARD(sctp_ipif->sctp_ipif_flags) ||
			    !SCTP_IPIF_USABLE(sctp_ipif->sctp_ipif_state) ||
			    !SCTP_IPIF_ZONE_MATCH(sctp, sctp_ipif) ||
			    SCTP_IS_ADDR_UNSPEC(!isv6,
			    sctp_ipif->sctp_ipif_saddr) ||
			    (connp->conn_family == AF_INET && isv6) ||
			    (connp->conn_ipv6_v6only && !isv6)) {
				rw_exit(&sctp_ipif->sctp_ipif_lock);
				sctp_ipif = list_next(
				    &sctps->sctps_g_ipifs[i].sctp_ipif_list,
				    sctp_ipif);
				continue;
			}
			rw_exit(&sctp_ipif->sctp_ipif_lock);
			SCTP_IPIF_REFHOLD(sctp_ipif);
			error = sctp_ipif_hash_insert(sctp, sctp_ipif, sleep,
			    B_FALSE, B_FALSE);
			if (error != 0 && error != EALREADY)
				goto free_stuff;
			sctp_ipif = list_next(
			    &sctps->sctps_g_ipifs[i].sctp_ipif_list,
			    sctp_ipif);
		}
	}
	rw_exit(&sctps->sctps_g_ipifs_lock);
	return (0);
free_stuff:
	rw_exit(&sctps->sctps_g_ipifs_lock);
	sctp_free_saddrs(sctp);
	return (ENOMEM);
}

/*
 * Given a list of address, fills in the list of SCTP ipifs if all the addresses
 * are present in the SCTP interface list, return number of addresses filled
 * or error. If the caller wants the list of addresses, it sends a pre-allocated
 * buffer - list. Currently, this list is only used on a clustered node when
 * the SCTP is in the listen state (from sctp_bind_add()). When called on a
 * clustered node, the input is always a list of addresses (even if the
 * original bind() was to INADDR_ANY).
 * Called with no locks held.
 */
int
sctp_valid_addr_list(sctp_t *sctp, const void *addrs, uint32_t addrcnt,
    uchar_t *list, size_t lsize)
{
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;
	struct in_addr		*addr4;
	in6_addr_t		addr;
	int			cnt;
	int			err = 0;
	int			saddr_cnt = 0;
	sctp_ipif_t		*ipif;
	boolean_t		bind_to_all = B_FALSE;
	boolean_t		check_addrs = B_FALSE;
	boolean_t		check_lport = B_FALSE;
	uchar_t			*p = list;
	conn_t			*connp = sctp->sctp_connp;

	/*
	 * Need to check for port and address depending on the state.
	 * After a socket is bound, we need to make sure that subsequent
	 * bindx() has correct port.  After an association is established,
	 * we need to check for changing the bound address to invalid
	 * addresses.
	 */
	if (sctp->sctp_state >= SCTPS_BOUND) {
		check_lport = B_TRUE;
		if (sctp->sctp_state > SCTPS_LISTEN)
			check_addrs = B_TRUE;
	}

	if (sctp->sctp_conn_tfp != NULL)
		mutex_enter(&sctp->sctp_conn_tfp->tf_lock);
	if (sctp->sctp_listen_tfp != NULL)
		mutex_enter(&sctp->sctp_listen_tfp->tf_lock);
	for (cnt = 0; cnt < addrcnt; cnt++) {
		boolean_t	lookup_saddr = B_TRUE;
		uint_t		ifindex = 0;

		switch (connp->conn_family) {
		case AF_INET:
			sin4 = (struct sockaddr_in *)addrs + cnt;
			if (sin4->sin_family != AF_INET || (check_lport &&
			    sin4->sin_port != connp->conn_lport)) {
				err = EINVAL;
				goto free_ret;
			}
			addr4 = &sin4->sin_addr;
			if (check_addrs &&
			    (addr4->s_addr == INADDR_ANY ||
			    addr4->s_addr == INADDR_BROADCAST ||
			    CLASSD(addr4->s_addr))) {
				err = EINVAL;
				goto free_ret;
			}
			IN6_INADDR_TO_V4MAPPED(addr4, &addr);
			if (!check_addrs && addr4->s_addr == INADDR_ANY) {
				lookup_saddr = B_FALSE;
				bind_to_all = B_TRUE;
			}

			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)addrs + cnt;
			if (sin6->sin6_family != AF_INET6 || (check_lport &&
			    sin6->sin6_port != connp->conn_lport)) {
				err = EINVAL;
				goto free_ret;
			}
			addr = sin6->sin6_addr;
			/* Contains the interface index */
			ifindex = sin6->sin6_scope_id;
			if (connp->conn_ipv6_v6only &&
			    IN6_IS_ADDR_V4MAPPED(&addr)) {
				err = EAFNOSUPPORT;
				goto free_ret;
			}
			if (check_addrs &&
			    (IN6_IS_ADDR_LINKLOCAL(&addr) ||
			    IN6_IS_ADDR_MULTICAST(&addr) ||
			    IN6_IS_ADDR_UNSPECIFIED(&addr))) {
				err = EINVAL;
				goto free_ret;
			}
			if (!check_addrs && IN6_IS_ADDR_UNSPECIFIED(&addr)) {
				lookup_saddr = B_FALSE;
				bind_to_all = B_TRUE;
			}

			break;
		default:
			err = EAFNOSUPPORT;
			goto free_ret;
		}
		if (lookup_saddr) {
			ipif = sctp_lookup_ipif_addr(&addr, B_TRUE,
			    IPCL_ZONEID(connp), !connp->conn_allzones,
			    ifindex, 0, B_TRUE, sctp->sctp_sctps);
			if (ipif == NULL) {
				/* Address not in the list */
				err = EINVAL;
				goto free_ret;
			} else if (check_addrs && SCTP_IS_IPIF_LOOPBACK(ipif) &&
			    cl_sctp_check_addrs == NULL) {
				SCTP_IPIF_REFRELE(ipif);
				err = EINVAL;
				goto free_ret;
			}
		}
		if (!bind_to_all) {
			/*
			 * If an address is added after association setup,
			 * we need to wait for the peer to send us an ASCONF
			 * ACK before we can start using it.
			 * saddr_ipif_dontsrc will be reset (to 0) when we
			 * get the ASCONF ACK for this address.
			 */
			err = sctp_ipif_hash_insert(sctp, ipif, KM_SLEEP,
			    check_addrs ? B_TRUE : B_FALSE, B_FALSE);
			if (err != 0) {
				SCTP_IPIF_REFRELE(ipif);
				if (check_addrs && err == EALREADY)
					err = EADDRINUSE;
				goto free_ret;
			}
			saddr_cnt++;
			if (lsize >= sizeof (addr)) {
				bcopy(&addr, p, sizeof (addr));
				p += sizeof (addr);
				lsize -= sizeof (addr);
			}
		}
	}
	if (bind_to_all) {
		/*
		 * Free whatever we might have added before encountering
		 * inaddr_any.
		 */
		if (sctp->sctp_nsaddrs > 0) {
			sctp_free_saddrs(sctp);
			ASSERT(sctp->sctp_nsaddrs == 0);
		}
		err = sctp_get_all_ipifs(sctp, KM_SLEEP);
		if (err != 0)
			return (err);
		sctp->sctp_bound_to_all = 1;
	}
	if (sctp->sctp_listen_tfp != NULL)
		mutex_exit(&sctp->sctp_listen_tfp->tf_lock);
	if (sctp->sctp_conn_tfp != NULL)
		mutex_exit(&sctp->sctp_conn_tfp->tf_lock);
	return (0);
free_ret:
	if (saddr_cnt != 0)
		sctp_del_saddr_list(sctp, addrs, saddr_cnt, B_TRUE);
	if (sctp->sctp_listen_tfp != NULL)
		mutex_exit(&sctp->sctp_listen_tfp->tf_lock);
	if (sctp->sctp_conn_tfp != NULL)
		mutex_exit(&sctp->sctp_conn_tfp->tf_lock);
	return (err);
}

static int
sctp_ipif_hash_insert(sctp_t *sctp, sctp_ipif_t *ipif, int sleep,
    boolean_t dontsrc, boolean_t allow_dup)
{
	int			cnt;
	sctp_saddr_ipif_t	*ipif_obj;
	int			hindex;

	hindex = SCTP_IPIF_ADDR_HASH(ipif->sctp_ipif_saddr,
	    ipif->sctp_ipif_isv6);
	rw_enter(&sctp->sctp_saddrs[hindex].ipif_hash_lock, RW_WRITER);
	ipif_obj = list_head(&sctp->sctp_saddrs[hindex].sctp_ipif_list);
	for (cnt = 0; cnt < sctp->sctp_saddrs[hindex].ipif_count; cnt++) {
		if (IN6_ARE_ADDR_EQUAL(&ipif_obj->saddr_ipifp->sctp_ipif_saddr,
		    &ipif->sctp_ipif_saddr)) {
			if (ipif->sctp_ipif_id !=
			    ipif_obj->saddr_ipifp->sctp_ipif_id &&
			    ipif_obj->saddr_ipifp->sctp_ipif_state ==
			    SCTP_IPIFS_DOWN && ipif->sctp_ipif_state ==
			    SCTP_IPIFS_UP) {
				SCTP_IPIF_REFRELE(ipif_obj->saddr_ipifp);
				ipif_obj->saddr_ipifp = ipif;
				ipif_obj->saddr_ipif_dontsrc = dontsrc ? 1 : 0;
				rw_exit(
				    &sctp->sctp_saddrs[hindex].ipif_hash_lock);
				return (0);
			} else if (!allow_dup || ipif->sctp_ipif_id ==
			    ipif_obj->saddr_ipifp->sctp_ipif_id) {
				rw_exit(
				    &sctp->sctp_saddrs[hindex].ipif_hash_lock);
				return (EALREADY);
			}
		}
		ipif_obj = list_next(&sctp->sctp_saddrs[hindex].sctp_ipif_list,
		    ipif_obj);
	}
	ipif_obj = kmem_zalloc(sizeof (sctp_saddr_ipif_t), sleep);
	if (ipif_obj == NULL) {
		rw_exit(&sctp->sctp_saddrs[hindex].ipif_hash_lock);
		/* Need to do something */
		return (ENOMEM);
	}
	ipif_obj->saddr_ipifp = ipif;
	ipif_obj->saddr_ipif_dontsrc = dontsrc ? 1 : 0;
	list_insert_tail(&sctp->sctp_saddrs[hindex].sctp_ipif_list, ipif_obj);
	sctp->sctp_saddrs[hindex].ipif_count++;
	sctp->sctp_nsaddrs++;
	rw_exit(&sctp->sctp_saddrs[hindex].ipif_hash_lock);
	return (0);
}

/*
 * Given a source address, walk through the peer address list to see
 * if the source address is being used.  If it is, reset that.
 * A cleared saddr will then make sctp_make_mp lookup the destination again
 * and as part of that look for a new source.
 */
static void
sctp_fix_saddr(sctp_t *sctp, in6_addr_t *saddr)
{
	sctp_faddr_t	*fp;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->sf_next) {
		if (!IN6_ARE_ADDR_EQUAL(&fp->sf_saddr, saddr))
			continue;
		V6_SET_ZERO(fp->sf_saddr);
	}
}

static void
sctp_ipif_hash_remove(sctp_t *sctp, sctp_ipif_t *ipif, boolean_t locked)
{
	int			cnt;
	sctp_saddr_ipif_t	*ipif_obj;
	int			hindex;

	hindex = SCTP_IPIF_ADDR_HASH(ipif->sctp_ipif_saddr,
	    ipif->sctp_ipif_isv6);
	if (!locked)
		rw_enter(&sctp->sctp_saddrs[hindex].ipif_hash_lock, RW_WRITER);
	ipif_obj = list_head(&sctp->sctp_saddrs[hindex].sctp_ipif_list);
	for (cnt = 0; cnt < sctp->sctp_saddrs[hindex].ipif_count; cnt++) {
		if (IN6_ARE_ADDR_EQUAL(&ipif_obj->saddr_ipifp->sctp_ipif_saddr,
		    &ipif->sctp_ipif_saddr)) {
			list_remove(&sctp->sctp_saddrs[hindex].sctp_ipif_list,
			    ipif_obj);
			sctp->sctp_saddrs[hindex].ipif_count--;
			sctp->sctp_nsaddrs--;
			sctp_fix_saddr(sctp, &ipif->sctp_ipif_saddr);
			SCTP_IPIF_REFRELE(ipif_obj->saddr_ipifp);
			kmem_free(ipif_obj, sizeof (sctp_saddr_ipif_t));
			break;
		}
		ipif_obj = list_next(&sctp->sctp_saddrs[hindex].sctp_ipif_list,
		    ipif_obj);
	}
	if (!locked)
		rw_exit(&sctp->sctp_saddrs[hindex].ipif_hash_lock);
}

static int
sctp_compare_ipif_list(sctp_ipif_hash_t *list1, sctp_ipif_hash_t *list2)
{
	int			i;
	int			j;
	sctp_saddr_ipif_t	*obj1;
	sctp_saddr_ipif_t	*obj2;
	int			overlap = 0;

	rw_enter(&list1->ipif_hash_lock, RW_READER);
	rw_enter(&list2->ipif_hash_lock, RW_READER);
	obj1 = list_head(&list1->sctp_ipif_list);
	for (i = 0; i < list1->ipif_count; i++) {
		obj2 = list_head(&list2->sctp_ipif_list);
		for (j = 0; j < list2->ipif_count; j++) {
			if (IN6_ARE_ADDR_EQUAL(
			    &obj1->saddr_ipifp->sctp_ipif_saddr,
			    &obj2->saddr_ipifp->sctp_ipif_saddr)) {
				overlap++;
				break;
			}
			obj2 = list_next(&list2->sctp_ipif_list,
			    obj2);
		}
		obj1 = list_next(&list1->sctp_ipif_list, obj1);
	}
	rw_exit(&list1->ipif_hash_lock);
	rw_exit(&list2->ipif_hash_lock);
	return (overlap);
}

int
sctp_compare_saddrs(sctp_t *sctp1, sctp_t *sctp2)
{
	int		i;
	int		overlap = 0;

	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		overlap += sctp_compare_ipif_list(&sctp1->sctp_saddrs[i],
		    &sctp2->sctp_saddrs[i]);
	}

	if (sctp1->sctp_nsaddrs == sctp2->sctp_nsaddrs &&
	    overlap == sctp1->sctp_nsaddrs) {
		return (SCTP_ADDR_EQUAL);
	}

	if (overlap == sctp1->sctp_nsaddrs)
		return (SCTP_ADDR_SUBSET);

	if (overlap > 0)
		return (SCTP_ADDR_OVERLAP);

	return (SCTP_ADDR_DISJOINT);
}

static int
sctp_copy_ipifs(sctp_ipif_hash_t *list1, sctp_t *sctp2, int sleep)
{
	int			i;
	sctp_saddr_ipif_t	*obj;
	int			error = 0;

	rw_enter(&list1->ipif_hash_lock, RW_READER);
	obj = list_head(&list1->sctp_ipif_list);
	for (i = 0; i < list1->ipif_count; i++) {
		SCTP_IPIF_REFHOLD(obj->saddr_ipifp);
		error = sctp_ipif_hash_insert(sctp2, obj->saddr_ipifp, sleep,
		    B_FALSE, B_FALSE);
		ASSERT(error != EALREADY);
		if (error != 0) {
			rw_exit(&list1->ipif_hash_lock);
			return (error);
		}
		obj = list_next(&list1->sctp_ipif_list, obj);
	}
	rw_exit(&list1->ipif_hash_lock);
	return (error);
}

int
sctp_dup_saddrs(sctp_t *sctp1, sctp_t *sctp2, int sleep)
{
	int	error = 0;
	int	i;

	if (sctp1 == NULL || sctp1->sctp_bound_to_all == 1)
		return (sctp_get_all_ipifs(sctp2, sleep));

	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		rw_enter(&sctp1->sctp_saddrs[i].ipif_hash_lock, RW_READER);
		if (sctp1->sctp_saddrs[i].ipif_count == 0) {
			rw_exit(&sctp1->sctp_saddrs[i].ipif_hash_lock);
			continue;
		}
		error = sctp_copy_ipifs(&sctp1->sctp_saddrs[i], sctp2, sleep);
		if (error != 0) {
			rw_exit(&sctp1->sctp_saddrs[i].ipif_hash_lock);
			sctp_free_saddrs(sctp2);
			return (error);
		}
		rw_exit(&sctp1->sctp_saddrs[i].ipif_hash_lock);
	}
	return (0);
}

void
sctp_free_saddrs(sctp_t *sctp)
{
	int			i;
	int			l;
	sctp_saddr_ipif_t	*obj;

	if (sctp->sctp_nsaddrs == 0)
		return;
	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		rw_enter(&sctp->sctp_saddrs[i].ipif_hash_lock, RW_WRITER);
		if (sctp->sctp_saddrs[i].ipif_count == 0) {
			rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
			continue;
		}
		obj = list_tail(&sctp->sctp_saddrs[i].sctp_ipif_list);
		for (l = 0; l < sctp->sctp_saddrs[i].ipif_count; l++) {
			list_remove(&sctp->sctp_saddrs[i].sctp_ipif_list, obj);
			SCTP_IPIF_REFRELE(obj->saddr_ipifp);
			sctp->sctp_nsaddrs--;
			kmem_free(obj, sizeof (sctp_saddr_ipif_t));
			obj = list_tail(&sctp->sctp_saddrs[i].sctp_ipif_list);
		}
		sctp->sctp_saddrs[i].ipif_count = 0;
		rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
	}
	if (sctp->sctp_bound_to_all == 1)
		sctp->sctp_bound_to_all = 0;
	ASSERT(sctp->sctp_nsaddrs == 0);
}

/*
 * Add/Delete the given ILL from the SCTP ILL list. Called with no locks
 * held.
 */
void
sctp_update_ill(ill_t *ill, int op)
{
	int		i;
	sctp_ill_t	*sctp_ill = NULL;
	uint_t		index;
	netstack_t	*ns = ill->ill_ipst->ips_netstack;
	sctp_stack_t	*sctps = ns->netstack_sctp;

	rw_enter(&sctps->sctps_g_ills_lock, RW_WRITER);

	index = SCTP_ILL_HASH_FN(SCTP_ILL_TO_PHYINDEX(ill));
	sctp_ill = list_head(&sctps->sctps_g_ills[index].sctp_ill_list);
	for (i = 0; i < sctps->sctps_g_ills[index].ill_count; i++) {
		if ((sctp_ill->sctp_ill_index == SCTP_ILL_TO_PHYINDEX(ill)) &&
		    (sctp_ill->sctp_ill_isv6 == ill->ill_isv6)) {
			break;
		}
		sctp_ill = list_next(&sctps->sctps_g_ills[index].sctp_ill_list,
		    sctp_ill);
	}

	switch (op) {
	case SCTP_ILL_INSERT:
		if (sctp_ill != NULL) {
			/* Unmark it if it is condemned */
			if (sctp_ill->sctp_ill_state == SCTP_ILLS_CONDEMNED)
				sctp_ill->sctp_ill_state = 0;
			rw_exit(&sctps->sctps_g_ills_lock);
			return;
		}
		sctp_ill = kmem_zalloc(sizeof (sctp_ill_t), KM_NOSLEEP);
		/* Need to re-try? */
		if (sctp_ill == NULL) {
			cmn_err(CE_WARN, "sctp_update_ill: error adding "
			    "ILL %p to SCTP's ILL list", (void *)ill);
			rw_exit(&sctps->sctps_g_ills_lock);
			return;
		}
		sctp_ill->sctp_ill_name = kmem_zalloc(ill->ill_name_length,
		    KM_NOSLEEP);
		if (sctp_ill->sctp_ill_name == NULL) {
			cmn_err(CE_WARN, "sctp_update_ill: error adding "
			    "ILL %p to SCTP's ILL list", (void *)ill);
			kmem_free(sctp_ill, sizeof (sctp_ill_t));
			rw_exit(&sctps->sctps_g_ills_lock);
			return;
		}
		bcopy(ill->ill_name, sctp_ill->sctp_ill_name,
		    ill->ill_name_length);
		sctp_ill->sctp_ill_name_length = ill->ill_name_length;
		sctp_ill->sctp_ill_index = SCTP_ILL_TO_PHYINDEX(ill);
		sctp_ill->sctp_ill_flags = ill->ill_phyint->phyint_flags;
		sctp_ill->sctp_ill_netstack = ns;	/* No netstack_hold */
		sctp_ill->sctp_ill_isv6 = ill->ill_isv6;
		list_insert_tail(&sctps->sctps_g_ills[index].sctp_ill_list,
		    (void *)sctp_ill);
		sctps->sctps_g_ills[index].ill_count++;
		sctps->sctps_ills_count++;

		break;

	case SCTP_ILL_REMOVE:

		if (sctp_ill == NULL) {
			rw_exit(&sctps->sctps_g_ills_lock);
			return;
		}
		if (sctp_ill->sctp_ill_ipifcnt == 0) {
			list_remove(&sctps->sctps_g_ills[index].sctp_ill_list,
			    (void *)sctp_ill);
			sctps->sctps_g_ills[index].ill_count--;
			sctps->sctps_ills_count--;
			kmem_free(sctp_ill->sctp_ill_name,
			    ill->ill_name_length);
			kmem_free(sctp_ill, sizeof (sctp_ill_t));
		} else {
			sctp_ill->sctp_ill_state = SCTP_ILLS_CONDEMNED;
		}

		break;
	}
	rw_exit(&sctps->sctps_g_ills_lock);
}

/*
 * The ILL's index is being changed, just remove it from the old list,
 * change the SCTP ILL's index and re-insert using the new index.
 */
void
sctp_ill_reindex(ill_t *ill, uint_t orig_ill_index)
{
	sctp_ill_t	*sctp_ill = NULL;
	sctp_ill_t	*nxt_sill;
	uint_t		indx;
	uint_t		nindx;
	boolean_t	once = B_FALSE;
	netstack_t	*ns = ill->ill_ipst->ips_netstack;
	sctp_stack_t	*sctps = ns->netstack_sctp;

	rw_enter(&sctps->sctps_g_ills_lock, RW_WRITER);

	indx = SCTP_ILL_HASH_FN(orig_ill_index);
	nindx = SCTP_ILL_HASH_FN(SCTP_ILL_TO_PHYINDEX(ill));
	sctp_ill = list_head(&sctps->sctps_g_ills[indx].sctp_ill_list);
	while (sctp_ill != NULL) {
		nxt_sill = list_next(&sctps->sctps_g_ills[indx].sctp_ill_list,
		    sctp_ill);
		if (sctp_ill->sctp_ill_index == orig_ill_index) {
			sctp_ill->sctp_ill_index = SCTP_ILL_TO_PHYINDEX(ill);
			/*
			 * if the new index hashes to the same value, all's
			 * done.
			 */
			if (nindx != indx) {
				list_remove(
				    &sctps->sctps_g_ills[indx].sctp_ill_list,
				    (void *)sctp_ill);
				sctps->sctps_g_ills[indx].ill_count--;
				list_insert_tail(
				    &sctps->sctps_g_ills[nindx].sctp_ill_list,
				    (void *)sctp_ill);
				sctps->sctps_g_ills[nindx].ill_count++;
			}
			if (once)
				break;
			/* We might have one for v4 and for v6 */
			once = B_TRUE;
		}
		sctp_ill = nxt_sill;
	}
	rw_exit(&sctps->sctps_g_ills_lock);
}

/* move ipif from f_ill to t_ill */
void
sctp_move_ipif(ipif_t *ipif, ill_t *f_ill, ill_t *t_ill)
{
	sctp_ill_t	*fsctp_ill = NULL;
	sctp_ill_t	*tsctp_ill = NULL;
	sctp_ipif_t	*sctp_ipif;
	uint_t		hindex;
	int		i;
	netstack_t	*ns = ipif->ipif_ill->ill_ipst->ips_netstack;
	sctp_stack_t	*sctps = ns->netstack_sctp;

	rw_enter(&sctps->sctps_g_ills_lock, RW_READER);
	rw_enter(&sctps->sctps_g_ipifs_lock, RW_READER);

	hindex = SCTP_ILL_HASH_FN(SCTP_ILL_TO_PHYINDEX(f_ill));
	fsctp_ill = list_head(&sctps->sctps_g_ills[hindex].sctp_ill_list);
	for (i = 0; i < sctps->sctps_g_ills[hindex].ill_count; i++) {
		if (fsctp_ill->sctp_ill_index == SCTP_ILL_TO_PHYINDEX(f_ill) &&
		    fsctp_ill->sctp_ill_isv6 == f_ill->ill_isv6) {
			break;
		}
		fsctp_ill = list_next(
		    &sctps->sctps_g_ills[hindex].sctp_ill_list, fsctp_ill);
	}

	hindex = SCTP_ILL_HASH_FN(SCTP_ILL_TO_PHYINDEX(t_ill));
	tsctp_ill = list_head(&sctps->sctps_g_ills[hindex].sctp_ill_list);
	for (i = 0; i < sctps->sctps_g_ills[hindex].ill_count; i++) {
		if (tsctp_ill->sctp_ill_index == SCTP_ILL_TO_PHYINDEX(t_ill) &&
		    tsctp_ill->sctp_ill_isv6 == t_ill->ill_isv6) {
			break;
		}
		tsctp_ill = list_next(
		    &sctps->sctps_g_ills[hindex].sctp_ill_list, tsctp_ill);
	}

	hindex = SCTP_IPIF_ADDR_HASH(ipif->ipif_v6lcl_addr,
	    ipif->ipif_ill->ill_isv6);
	sctp_ipif = list_head(&sctps->sctps_g_ipifs[hindex].sctp_ipif_list);
	for (i = 0; i < sctps->sctps_g_ipifs[hindex].ipif_count; i++) {
		if (sctp_ipif->sctp_ipif_id == ipif->ipif_seqid)
			break;
		sctp_ipif = list_next(
		    &sctps->sctps_g_ipifs[hindex].sctp_ipif_list, sctp_ipif);
	}
	/* Should be an ASSERT? */
	if (fsctp_ill == NULL || tsctp_ill == NULL || sctp_ipif == NULL) {
		ip1dbg(("sctp_move_ipif: error moving ipif %p from %p to %p\n",
		    (void *)ipif, (void *)f_ill, (void *)t_ill));
		rw_exit(&sctps->sctps_g_ipifs_lock);
		rw_exit(&sctps->sctps_g_ills_lock);
		return;
	}
	rw_enter(&sctp_ipif->sctp_ipif_lock, RW_WRITER);
	ASSERT(sctp_ipif->sctp_ipif_ill == fsctp_ill);
	sctp_ipif->sctp_ipif_ill = tsctp_ill;
	rw_exit(&sctp_ipif->sctp_ipif_lock);
	atomic_dec_32(&fsctp_ill->sctp_ill_ipifcnt);
	atomic_inc_32(&tsctp_ill->sctp_ill_ipifcnt);
	rw_exit(&sctps->sctps_g_ipifs_lock);
	rw_exit(&sctps->sctps_g_ills_lock);
}

/*
 * Walk the list of SCTPs and find each that has oipif in it's saddr list, and
 * if so replace it with nipif.
 */
void
sctp_update_saddrs(sctp_ipif_t *oipif, sctp_ipif_t *nipif, int idx,
    sctp_stack_t *sctps)
{
	sctp_t			*sctp;
	sctp_t			*sctp_prev = NULL;
	sctp_saddr_ipif_t	*sobj;
	int			count;

	mutex_enter(&sctps->sctps_g_lock);
	sctp = list_head(&sctps->sctps_g_list);
	while (sctp != NULL && oipif->sctp_ipif_refcnt > 0) {
		mutex_enter(&sctp->sctp_reflock);
		if (sctp->sctp_condemned ||
		    sctp->sctp_saddrs[idx].ipif_count <= 0) {
			mutex_exit(&sctp->sctp_reflock);
			sctp = list_next(&sctps->sctps_g_list, sctp);
			continue;
		}
		sctp->sctp_refcnt++;
		mutex_exit(&sctp->sctp_reflock);
		mutex_exit(&sctps->sctps_g_lock);
		if (sctp_prev != NULL)
			SCTP_REFRELE(sctp_prev);

		RUN_SCTP(sctp);
		sobj = list_head(&sctp->sctp_saddrs[idx].sctp_ipif_list);
		for (count = 0; count <
		    sctp->sctp_saddrs[idx].ipif_count; count++) {
			if (sobj->saddr_ipifp == oipif) {
				SCTP_IPIF_REFHOLD(nipif);
				sobj->saddr_ipifp = nipif;
				ASSERT(oipif->sctp_ipif_refcnt > 0);
				/* We have the writer lock */
				oipif->sctp_ipif_refcnt--;
				/*
				 * Can't have more than one referring
				 * to the same sctp_ipif.
				 */
				break;
			}
			sobj = list_next(&sctp->sctp_saddrs[idx].sctp_ipif_list,
			    sobj);
		}
		WAKE_SCTP(sctp);
		sctp_prev = sctp;
		mutex_enter(&sctps->sctps_g_lock);
		sctp = list_next(&sctps->sctps_g_list, sctp);
	}
	mutex_exit(&sctps->sctps_g_lock);
	if (sctp_prev != NULL)
		SCTP_REFRELE(sctp_prev);
}

/*
 * Given an ipif, walk the hash list in the global ipif table and for
 * any other SCTP ipif with the same address and non-zero reference, walk
 * the SCTP list and update the saddr list, if required, to point to the
 * new SCTP ipif. If it is a loopback interface, then there could be
 * multiple interfaces with 127.0.0.1 if there are zones configured, so
 * check the zoneid in addition to the address.
 */
void
sctp_chk_and_updt_saddr(int hindex, sctp_ipif_t *ipif, sctp_stack_t *sctps)
{
	int		cnt;
	sctp_ipif_t	*sipif;

	ASSERT(sctps->sctps_g_ipifs[hindex].ipif_count > 0);
	ASSERT(ipif->sctp_ipif_state == SCTP_IPIFS_UP);

	sipif = list_head(&sctps->sctps_g_ipifs[hindex].sctp_ipif_list);
	for (cnt = 0; cnt < sctps->sctps_g_ipifs[hindex].ipif_count; cnt++) {
		rw_enter(&sipif->sctp_ipif_lock, RW_WRITER);
		if (sipif->sctp_ipif_id != ipif->sctp_ipif_id &&
		    IN6_ARE_ADDR_EQUAL(&sipif->sctp_ipif_saddr,
		    &ipif->sctp_ipif_saddr) && sipif->sctp_ipif_refcnt > 0 &&
		    (!SCTP_IS_IPIF_LOOPBACK(ipif) || ipif->sctp_ipif_zoneid ==
		    sipif->sctp_ipif_zoneid)) {
			/*
			 * There can only be one address up at any time
			 * and we are here because ipif has been brought
			 * up.
			 */
			ASSERT(sipif->sctp_ipif_state != SCTP_IPIFS_UP);
			/*
			 * Someone has a reference to this we need to update to
			 * point to the new sipif.
			 */
			sctp_update_saddrs(sipif, ipif, hindex, sctps);
		}
		rw_exit(&sipif->sctp_ipif_lock);
		sipif = list_next(&sctps->sctps_g_ipifs[hindex].sctp_ipif_list,
		    sipif);
	}
}

/*
 * Insert a new SCTP ipif using 'ipif'. v6addr is the address that existed
 * prior to the current address in 'ipif'. Only when an existing address
 * is changed on an IPIF, will v6addr be specified. If the IPIF already
 * exists in the global SCTP ipif table, then we either removed it, if
 * it doesn't have any existing reference, or mark it condemned otherwise.
 * If an address is being brought up (IPIF_UP), then we need to scan
 * the SCTP list to check if there is any SCTP that points to the *same*
 * address on a different SCTP ipif and update in that case.
 */
void
sctp_update_ipif_addr(ipif_t *ipif, in6_addr_t v6addr)
{
	ill_t		*ill = ipif->ipif_ill;
	int		i;
	sctp_ill_t	*sctp_ill;
	sctp_ill_t	*osctp_ill;
	sctp_ipif_t	*sctp_ipif = NULL;
	sctp_ipif_t	*osctp_ipif = NULL;
	uint_t		ill_index;
	int		hindex;
	sctp_stack_t	*sctps;

	sctps = ipif->ipif_ill->ill_ipst->ips_netstack->netstack_sctp;

	/* Index for new address */
	hindex = SCTP_IPIF_ADDR_HASH(ipif->ipif_v6lcl_addr, ill->ill_isv6);

	/*
	 * The address on this IPIF is changing, we need to look for
	 * this old address and mark it condemned, before creating
	 * one for the new address.
	 */
	osctp_ipif = sctp_lookup_ipif_addr(&v6addr, B_FALSE,
	    ipif->ipif_zoneid, B_TRUE, SCTP_ILL_TO_PHYINDEX(ill),
	    ipif->ipif_seqid, B_FALSE, sctps);

	rw_enter(&sctps->sctps_g_ills_lock, RW_READER);
	rw_enter(&sctps->sctps_g_ipifs_lock, RW_WRITER);

	ill_index = SCTP_ILL_HASH_FN(SCTP_ILL_TO_PHYINDEX(ill));
	sctp_ill = list_head(&sctps->sctps_g_ills[ill_index].sctp_ill_list);
	for (i = 0; i < sctps->sctps_g_ills[ill_index].ill_count; i++) {
		if (sctp_ill->sctp_ill_index == SCTP_ILL_TO_PHYINDEX(ill) &&
		    sctp_ill->sctp_ill_isv6 == ill->ill_isv6) {
			break;
		}
		sctp_ill = list_next(
		    &sctps->sctps_g_ills[ill_index].sctp_ill_list, sctp_ill);
	}

	if (sctp_ill == NULL) {
		ip1dbg(("sctp_update_ipif_addr: ill not found ..\n"));
		rw_exit(&sctps->sctps_g_ipifs_lock);
		rw_exit(&sctps->sctps_g_ills_lock);
		return;
	}

	if (osctp_ipif != NULL) {

		/* The address is the same? */
		if (IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6lcl_addr, &v6addr)) {
			boolean_t	chk_n_updt = B_FALSE;

			rw_downgrade(&sctps->sctps_g_ipifs_lock);
			rw_enter(&osctp_ipif->sctp_ipif_lock, RW_WRITER);
			if (ipif->ipif_flags & IPIF_UP &&
			    osctp_ipif->sctp_ipif_state != SCTP_IPIFS_UP) {
				osctp_ipif->sctp_ipif_state = SCTP_IPIFS_UP;
				chk_n_updt = B_TRUE;
			} else {
				osctp_ipif->sctp_ipif_state = SCTP_IPIFS_DOWN;
			}
			osctp_ipif->sctp_ipif_flags = ipif->ipif_flags;
			rw_exit(&osctp_ipif->sctp_ipif_lock);
			if (chk_n_updt) {
				sctp_chk_and_updt_saddr(hindex, osctp_ipif,
				    sctps);
			}
			rw_exit(&sctps->sctps_g_ipifs_lock);
			rw_exit(&sctps->sctps_g_ills_lock);
			return;
		}
		/*
		 * We are effectively removing this address from the ILL.
		 */
		if (osctp_ipif->sctp_ipif_refcnt != 0) {
			osctp_ipif->sctp_ipif_state = SCTP_IPIFS_CONDEMNED;
		} else {
			list_t		*ipif_list;
			int		ohindex;

			osctp_ill = osctp_ipif->sctp_ipif_ill;
			/* hash index for the old one */
			ohindex = SCTP_IPIF_ADDR_HASH(
			    osctp_ipif->sctp_ipif_saddr,
			    osctp_ipif->sctp_ipif_isv6);

			ipif_list =
			    &sctps->sctps_g_ipifs[ohindex].sctp_ipif_list;

			list_remove(ipif_list, (void *)osctp_ipif);
			sctps->sctps_g_ipifs[ohindex].ipif_count--;
			sctps->sctps_g_ipifs_count--;
			rw_destroy(&osctp_ipif->sctp_ipif_lock);
			kmem_free(osctp_ipif, sizeof (sctp_ipif_t));
			atomic_dec_32(&osctp_ill->sctp_ill_ipifcnt);
		}
	}

	sctp_ipif = kmem_zalloc(sizeof (sctp_ipif_t), KM_NOSLEEP);
	/* Try again? */
	if (sctp_ipif == NULL) {
		cmn_err(CE_WARN, "sctp_update_ipif_addr: error adding "
		    "IPIF %p to SCTP's IPIF list", (void *)ipif);
		rw_exit(&sctps->sctps_g_ipifs_lock);
		rw_exit(&sctps->sctps_g_ills_lock);
		return;
	}
	sctps->sctps_g_ipifs_count++;
	rw_init(&sctp_ipif->sctp_ipif_lock, NULL, RW_DEFAULT, NULL);
	sctp_ipif->sctp_ipif_saddr = ipif->ipif_v6lcl_addr;
	sctp_ipif->sctp_ipif_ill = sctp_ill;
	sctp_ipif->sctp_ipif_isv6 = ill->ill_isv6;
	sctp_ipif->sctp_ipif_zoneid = ipif->ipif_zoneid;
	sctp_ipif->sctp_ipif_id = ipif->ipif_seqid;
	if (ipif->ipif_flags & IPIF_UP)
		sctp_ipif->sctp_ipif_state = SCTP_IPIFS_UP;
	else
		sctp_ipif->sctp_ipif_state = SCTP_IPIFS_DOWN;
	sctp_ipif->sctp_ipif_flags = ipif->ipif_flags;
	/*
	 * We add it to the head so that it is quicker to find good/recent
	 * additions.
	 */
	list_insert_head(&sctps->sctps_g_ipifs[hindex].sctp_ipif_list,
	    (void *)sctp_ipif);
	sctps->sctps_g_ipifs[hindex].ipif_count++;
	atomic_inc_32(&sctp_ill->sctp_ill_ipifcnt);
	if (sctp_ipif->sctp_ipif_state == SCTP_IPIFS_UP)
		sctp_chk_and_updt_saddr(hindex, sctp_ipif, sctps);
	rw_exit(&sctps->sctps_g_ipifs_lock);
	rw_exit(&sctps->sctps_g_ills_lock);
}

/* Insert, Remove,  Mark up or Mark down the ipif */
void
sctp_update_ipif(ipif_t *ipif, int op)
{
	ill_t		*ill = ipif->ipif_ill;
	int		i;
	sctp_ill_t	*sctp_ill;
	sctp_ipif_t	*sctp_ipif;
	uint_t		ill_index;
	uint_t		hindex;
	netstack_t	*ns = ipif->ipif_ill->ill_ipst->ips_netstack;
	sctp_stack_t	*sctps = ns->netstack_sctp;

	ip2dbg(("sctp_update_ipif: %s %d\n", ill->ill_name, ipif->ipif_seqid));

	rw_enter(&sctps->sctps_g_ills_lock, RW_READER);
	rw_enter(&sctps->sctps_g_ipifs_lock, RW_WRITER);

	ill_index = SCTP_ILL_HASH_FN(SCTP_ILL_TO_PHYINDEX(ill));
	sctp_ill = list_head(&sctps->sctps_g_ills[ill_index].sctp_ill_list);
	for (i = 0; i < sctps->sctps_g_ills[ill_index].ill_count; i++) {
		if (sctp_ill->sctp_ill_index == SCTP_ILL_TO_PHYINDEX(ill) &&
		    sctp_ill->sctp_ill_isv6 == ill->ill_isv6) {
			break;
		}
		sctp_ill = list_next(
		    &sctps->sctps_g_ills[ill_index].sctp_ill_list, sctp_ill);
	}
	if (sctp_ill == NULL) {
		rw_exit(&sctps->sctps_g_ipifs_lock);
		rw_exit(&sctps->sctps_g_ills_lock);
		return;
	}

	hindex = SCTP_IPIF_ADDR_HASH(ipif->ipif_v6lcl_addr,
	    ipif->ipif_ill->ill_isv6);
	sctp_ipif = list_head(&sctps->sctps_g_ipifs[hindex].sctp_ipif_list);
	for (i = 0; i < sctps->sctps_g_ipifs[hindex].ipif_count; i++) {
		if (sctp_ipif->sctp_ipif_id == ipif->ipif_seqid) {
			ASSERT(IN6_ARE_ADDR_EQUAL(&sctp_ipif->sctp_ipif_saddr,
			    &ipif->ipif_v6lcl_addr));
			break;
		}
		sctp_ipif = list_next(
		    &sctps->sctps_g_ipifs[hindex].sctp_ipif_list,
		    sctp_ipif);
	}
	if (sctp_ipif == NULL) {
		ip1dbg(("sctp_update_ipif: null sctp_ipif for %d\n", op));
		rw_exit(&sctps->sctps_g_ipifs_lock);
		rw_exit(&sctps->sctps_g_ills_lock);
		return;
	}
	ASSERT(sctp_ill == sctp_ipif->sctp_ipif_ill);
	switch (op) {
	case SCTP_IPIF_REMOVE:
	{
		list_t		*ipif_list;
		list_t		*ill_list;

		ill_list = &sctps->sctps_g_ills[ill_index].sctp_ill_list;
		ipif_list = &sctps->sctps_g_ipifs[hindex].sctp_ipif_list;
		if (sctp_ipif->sctp_ipif_refcnt != 0) {
			sctp_ipif->sctp_ipif_state = SCTP_IPIFS_CONDEMNED;
			rw_exit(&sctps->sctps_g_ipifs_lock);
			rw_exit(&sctps->sctps_g_ills_lock);
			return;
		}
		list_remove(ipif_list, (void *)sctp_ipif);
		sctps->sctps_g_ipifs[hindex].ipif_count--;
		sctps->sctps_g_ipifs_count--;
		rw_destroy(&sctp_ipif->sctp_ipif_lock);
		kmem_free(sctp_ipif, sizeof (sctp_ipif_t));
		atomic_dec_32(&sctp_ill->sctp_ill_ipifcnt);
		if (rw_tryupgrade(&sctps->sctps_g_ills_lock) != 0) {
			rw_downgrade(&sctps->sctps_g_ipifs_lock);
			if (sctp_ill->sctp_ill_ipifcnt == 0 &&
			    sctp_ill->sctp_ill_state == SCTP_ILLS_CONDEMNED) {
				list_remove(ill_list, (void *)sctp_ill);
				sctps->sctps_ills_count--;
				sctps->sctps_g_ills[ill_index].ill_count--;
				kmem_free(sctp_ill->sctp_ill_name,
				    sctp_ill->sctp_ill_name_length);
				kmem_free(sctp_ill, sizeof (sctp_ill_t));
			}
		}
		break;
	}

	case SCTP_IPIF_UP:

		rw_downgrade(&sctps->sctps_g_ipifs_lock);
		rw_enter(&sctp_ipif->sctp_ipif_lock, RW_WRITER);
		sctp_ipif->sctp_ipif_state = SCTP_IPIFS_UP;
		sctp_ipif->sctp_ipif_flags = ipif->ipif_flags;
		rw_exit(&sctp_ipif->sctp_ipif_lock);
		sctp_chk_and_updt_saddr(hindex, sctp_ipif,
		    ipif->ipif_ill->ill_ipst->ips_netstack->netstack_sctp);

		break;

	case SCTP_IPIF_UPDATE:

		rw_downgrade(&sctps->sctps_g_ipifs_lock);
		rw_enter(&sctp_ipif->sctp_ipif_lock, RW_WRITER);
		sctp_ipif->sctp_ipif_zoneid = ipif->ipif_zoneid;
		sctp_ipif->sctp_ipif_flags = ipif->ipif_flags;
		rw_exit(&sctp_ipif->sctp_ipif_lock);

		break;

	case SCTP_IPIF_DOWN:

		rw_downgrade(&sctps->sctps_g_ipifs_lock);
		rw_enter(&sctp_ipif->sctp_ipif_lock, RW_WRITER);
		sctp_ipif->sctp_ipif_state = SCTP_IPIFS_DOWN;
		sctp_ipif->sctp_ipif_flags = ipif->ipif_flags;
		rw_exit(&sctp_ipif->sctp_ipif_lock);

		break;
	}
	rw_exit(&sctps->sctps_g_ipifs_lock);
	rw_exit(&sctps->sctps_g_ills_lock);
}

/*
 * SCTP source address list manipulaton, locking not used (except for
 * sctp locking by the caller.
 */

/* Remove a specific saddr from the list */
void
sctp_del_saddr(sctp_t *sctp, sctp_saddr_ipif_t *sp)
{
	if (sctp->sctp_conn_tfp != NULL)
		mutex_enter(&sctp->sctp_conn_tfp->tf_lock);

	if (sctp->sctp_listen_tfp != NULL)
		mutex_enter(&sctp->sctp_listen_tfp->tf_lock);

	sctp_ipif_hash_remove(sctp, sp->saddr_ipifp, B_FALSE);

	if (sctp->sctp_bound_to_all == 1)
		sctp->sctp_bound_to_all = 0;

	if (sctp->sctp_conn_tfp != NULL)
		mutex_exit(&sctp->sctp_conn_tfp->tf_lock);

	if (sctp->sctp_listen_tfp != NULL)
		mutex_exit(&sctp->sctp_listen_tfp->tf_lock);
}

/*
 * Delete source address from the existing list. No error checking done here
 * Called with no locks held.
 */
void
sctp_del_saddr_list(sctp_t *sctp, const void *addrs, int addcnt,
    boolean_t fanout_locked)
{
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;
	int			cnt;
	in6_addr_t		addr;
	sctp_ipif_t		*sctp_ipif;
	int			ifindex = 0;
	conn_t			*connp = sctp->sctp_connp;

	ASSERT(sctp->sctp_nsaddrs >= addcnt);

	if (!fanout_locked) {
		if (sctp->sctp_conn_tfp != NULL)
			mutex_enter(&sctp->sctp_conn_tfp->tf_lock);
		if (sctp->sctp_listen_tfp != NULL)
			mutex_enter(&sctp->sctp_listen_tfp->tf_lock);
	}

	for (cnt = 0; cnt < addcnt; cnt++) {
		switch (connp->conn_family) {
		case AF_INET:
			sin4 = (struct sockaddr_in *)addrs + cnt;
			IN6_INADDR_TO_V4MAPPED(&sin4->sin_addr, &addr);
			break;

		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)addrs + cnt;
			addr = sin6->sin6_addr;
			ifindex = sin6->sin6_scope_id;
			break;
		}
		sctp_ipif = sctp_lookup_ipif_addr(&addr, B_FALSE,
		    IPCL_ZONEID(connp), !connp->conn_allzones,
		    ifindex, 0, B_TRUE, sctp->sctp_sctps);
		ASSERT(sctp_ipif != NULL);
		sctp_ipif_hash_remove(sctp, sctp_ipif, B_FALSE);
	}
	if (sctp->sctp_bound_to_all == 1)
		sctp->sctp_bound_to_all = 0;

	if (!fanout_locked) {
		if (sctp->sctp_conn_tfp != NULL)
			mutex_exit(&sctp->sctp_conn_tfp->tf_lock);
		if (sctp->sctp_listen_tfp != NULL)
			mutex_exit(&sctp->sctp_listen_tfp->tf_lock);
	}
}

/*
 * Given an address get the corresponding entry from the list
 * Called with no locks held.
 */
sctp_saddr_ipif_t *
sctp_saddr_lookup(sctp_t *sctp, in6_addr_t *addr, uint_t ifindex)
{
	int			cnt;
	sctp_saddr_ipif_t	*ipif_obj;
	int			hindex;
	sctp_ipif_t		*sctp_ipif;

	hindex = SCTP_IPIF_ADDR_HASH(*addr, !IN6_IS_ADDR_V4MAPPED(addr));
	rw_enter(&sctp->sctp_saddrs[hindex].ipif_hash_lock, RW_READER);
	if (sctp->sctp_saddrs[hindex].ipif_count == 0) {
		rw_exit(&sctp->sctp_saddrs[hindex].ipif_hash_lock);
		return (NULL);
	}

	ipif_obj = list_head(&sctp->sctp_saddrs[hindex].sctp_ipif_list);
	for (cnt = 0; cnt < sctp->sctp_saddrs[hindex].ipif_count; cnt++) {
		sctp_ipif = ipif_obj->saddr_ipifp;
		/*
		 * Zone check shouldn't be needed.
		 */
		if (IN6_ARE_ADDR_EQUAL(addr, &sctp_ipif->sctp_ipif_saddr) &&
		    (ifindex == 0 ||
		    ifindex == sctp_ipif->sctp_ipif_ill->sctp_ill_index) &&
		    SCTP_IPIF_USABLE(sctp_ipif->sctp_ipif_state)) {
			rw_exit(&sctp->sctp_saddrs[hindex].ipif_hash_lock);
			return (ipif_obj);
		}
		ipif_obj = list_next(&sctp->sctp_saddrs[hindex].sctp_ipif_list,
		    ipif_obj);
	}
	rw_exit(&sctp->sctp_saddrs[hindex].ipif_hash_lock);
	return (NULL);
}

/* Given an address, add it to the source address list */
int
sctp_saddr_add_addr(sctp_t *sctp, in6_addr_t *addr, uint_t ifindex)
{
	sctp_ipif_t		*sctp_ipif;
	conn_t			*connp = sctp->sctp_connp;

	sctp_ipif = sctp_lookup_ipif_addr(addr, B_TRUE, IPCL_ZONEID(connp),
	    !connp->conn_allzones, ifindex, 0, B_TRUE, sctp->sctp_sctps);
	if (sctp_ipif == NULL)
		return (EINVAL);

	if (sctp_ipif_hash_insert(sctp, sctp_ipif, KM_NOSLEEP, B_FALSE,
	    B_FALSE) != 0) {
		SCTP_IPIF_REFRELE(sctp_ipif);
		return (EINVAL);
	}
	return (0);
}

/*
 * Remove or mark as dontsrc addresses that are currently not part of the
 * association. One would delete addresses when processing an INIT and
 * mark as dontsrc when processing an INIT-ACK.
 */
void
sctp_check_saddr(sctp_t *sctp, int supp_af, boolean_t delete,
    in6_addr_t *no_del_addr)
{
	int			i;
	int			l;
	sctp_saddr_ipif_t	*obj;
	int			scanned = 0;
	int			naddr;
	int			nsaddr;
	conn_t			*connp = sctp->sctp_connp;

	ASSERT(!sctp->sctp_loopback && !sctp->sctp_linklocal && supp_af != 0);

	/*
	 * Irregardless of the supported address in the INIT, v4
	 * must be supported.
	 */
	if (connp->conn_family == AF_INET)
		supp_af = PARM_SUPP_V4;

	nsaddr = sctp->sctp_nsaddrs;
	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		rw_enter(&sctp->sctp_saddrs[i].ipif_hash_lock, RW_WRITER);
		if (sctp->sctp_saddrs[i].ipif_count == 0) {
			rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
			continue;
		}
		obj = list_head(&sctp->sctp_saddrs[i].sctp_ipif_list);
		naddr = sctp->sctp_saddrs[i].ipif_count;
		for (l = 0; l < naddr; l++) {
			sctp_ipif_t	*ipif;

			ipif = obj->saddr_ipifp;
			scanned++;

			if (IN6_ARE_ADDR_EQUAL(&ipif->sctp_ipif_saddr,
			    no_del_addr)) {
				goto next_obj;
			}

			/*
			 * Delete/mark dontsrc loopback/linklocal addresses and
			 * unsupported address.
			 * On a clustered node, we trust the clustering module
			 * to do the right thing w.r.t loopback addresses, so
			 * we ignore loopback addresses in this check.
			 */
			if ((SCTP_IS_IPIF_LOOPBACK(ipif) &&
			    cl_sctp_check_addrs == NULL) ||
			    SCTP_IS_IPIF_LINKLOCAL(ipif) ||
			    SCTP_UNSUPP_AF(ipif, supp_af)) {
				if (!delete) {
					obj->saddr_ipif_unconfirmed = 1;
					goto next_obj;
				}
				if (sctp->sctp_bound_to_all == 1)
					sctp->sctp_bound_to_all = 0;
				if (scanned < nsaddr) {
					obj = list_next(&sctp->sctp_saddrs[i].
					    sctp_ipif_list, obj);
					sctp_ipif_hash_remove(sctp, ipif,
					    B_TRUE);
					continue;
				}
				sctp_ipif_hash_remove(sctp, ipif, B_TRUE);
			}
	next_obj:
			if (scanned >= nsaddr) {
				rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
				return;
			}
			obj = list_next(&sctp->sctp_saddrs[i].sctp_ipif_list,
			    obj);
		}
		rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
	}
}


/* Get the first valid address from the list. Called with no locks held */
in6_addr_t
sctp_get_valid_addr(sctp_t *sctp, boolean_t isv6, boolean_t *addr_set)
{
	int			i;
	int			l;
	sctp_saddr_ipif_t	*obj;
	int			scanned = 0;
	in6_addr_t		addr;

	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		rw_enter(&sctp->sctp_saddrs[i].ipif_hash_lock, RW_READER);
		if (sctp->sctp_saddrs[i].ipif_count == 0) {
			rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
			continue;
		}
		obj = list_head(&sctp->sctp_saddrs[i].sctp_ipif_list);
		for (l = 0; l < sctp->sctp_saddrs[i].ipif_count; l++) {
			sctp_ipif_t	*ipif;

			ipif = obj->saddr_ipifp;
			if (!SCTP_DONT_SRC(obj) &&
			    ipif->sctp_ipif_isv6 == isv6 &&
			    ipif->sctp_ipif_state == SCTP_IPIFS_UP) {
				*addr_set = B_TRUE;
				rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
				return (ipif->sctp_ipif_saddr);
			}
			scanned++;
			if (scanned >= sctp->sctp_nsaddrs) {
				rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
				goto got_none;
			}
			obj = list_next(&sctp->sctp_saddrs[i].sctp_ipif_list,
			    obj);
		}
		rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
	}
got_none:
	/* Need to double check this */
	if (isv6 == B_TRUE)
		addr =  ipv6_all_zeros;
	else
		IN6_IPADDR_TO_V4MAPPED(0, &addr);
	*addr_set = B_FALSE;
	return (addr);
}

/*
 * Return the list of local addresses of an association.  The parameter
 * myaddrs is supposed to be either (struct sockaddr_in *) or (struct
 * sockaddr_in6 *) depending on the address family.
 */
int
sctp_getmyaddrs(void *conn, void *myaddrs, int *addrcnt)
{
	int			i;
	int			l;
	sctp_saddr_ipif_t	*obj;
	sctp_t			*sctp = (sctp_t *)conn;
	conn_t			*connp = sctp->sctp_connp;
	int			family = connp->conn_family;
	int			max = *addrcnt;
	size_t			added = 0;
	struct sockaddr_in6	*sin6;
	struct sockaddr_in	*sin4;
	int			scanned = 0;
	boolean_t		skip_lback = B_FALSE;
	ip_xmit_attr_t		*ixa = connp->conn_ixa;

	if (sctp->sctp_nsaddrs == 0)
		return (EINVAL);

	/*
	 * Skip loopback addresses for non-loopback assoc., ignore
	 * this on a clustered node.
	 */
	if (sctp->sctp_state >= SCTPS_ESTABLISHED && !sctp->sctp_loopback &&
	    (cl_sctp_check_addrs == NULL)) {
		skip_lback = B_TRUE;
	}

	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		rw_enter(&sctp->sctp_saddrs[i].ipif_hash_lock, RW_READER);
		if (sctp->sctp_saddrs[i].ipif_count == 0) {
			rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
			continue;
		}
		obj = list_head(&sctp->sctp_saddrs[i].sctp_ipif_list);
		for (l = 0; l < sctp->sctp_saddrs[i].ipif_count; l++) {
			sctp_ipif_t	*ipif = obj->saddr_ipifp;
			in6_addr_t	addr = ipif->sctp_ipif_saddr;

			scanned++;
			if ((ipif->sctp_ipif_state == SCTP_IPIFS_CONDEMNED) ||
			    SCTP_DONT_SRC(obj) ||
			    (SCTP_IS_IPIF_LOOPBACK(ipif) && skip_lback)) {
				if (scanned >= sctp->sctp_nsaddrs) {
					rw_exit(&sctp->
					    sctp_saddrs[i].ipif_hash_lock);
					goto done;
				}
				obj = list_next(&sctp->sctp_saddrs[i].
				    sctp_ipif_list, obj);
				continue;
			}
			switch (family) {
			case AF_INET:
				sin4 = (struct sockaddr_in *)myaddrs + added;
				sin4->sin_family = AF_INET;
				sin4->sin_port = connp->conn_lport;
				IN6_V4MAPPED_TO_INADDR(&addr, &sin4->sin_addr);
				break;

			case AF_INET6:
				sin6 = (struct sockaddr_in6 *)myaddrs + added;
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = connp->conn_lport;
				sin6->sin6_addr = addr;
				/*
				 * Note that flowinfo is only returned for
				 * getpeername just like for TCP and UDP.
				 */
				sin6->sin6_flowinfo = 0;

				if (IN6_IS_ADDR_LINKSCOPE(&sin6->sin6_addr) &&
				    (ixa->ixa_flags & IXAF_SCOPEID_SET))
					sin6->sin6_scope_id = ixa->ixa_scopeid;
				else
					sin6->sin6_scope_id = 0;
				sin6->__sin6_src_id = 0;
				break;
			}
			added++;
			if (added >= max || scanned >= sctp->sctp_nsaddrs) {
				rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
				goto done;
			}
			obj = list_next(&sctp->sctp_saddrs[i].sctp_ipif_list,
			    obj);
		}
		rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
	}
done:
	*addrcnt = added;
	return (0);
}

/*
 * Given the supported address family, walk through the source address list
 * and return the total length of the available addresses. If 'p' is not
 * null, construct the parameter list for the addresses in 'p'.
 * 'modify' will only be set when we want the source address list to
 * be modified. The source address list will be modified only when
 * generating an INIT chunk. For generating an INIT-ACK 'modify' will
 * be false since the 'sctp' will be that of the listener.
 */
size_t
sctp_saddr_info(sctp_t *sctp, int supp_af, uchar_t *p, boolean_t modify)
{
	int			i;
	int			l;
	sctp_saddr_ipif_t	*obj;
	size_t			paramlen = 0;
	sctp_parm_hdr_t		*hdr;
	int			scanned = 0;
	int			naddr;
	int			nsaddr;
	boolean_t		del_ll = B_FALSE;
	boolean_t		del_lb = B_FALSE;


	/*
	 * On a clustered node don't bother changing anything
	 * on the loopback interface.
	 */
	if (modify && !sctp->sctp_loopback && (cl_sctp_check_addrs == NULL))
		del_lb = B_TRUE;

	if (modify && !sctp->sctp_linklocal)
		del_ll = B_TRUE;

	nsaddr = sctp->sctp_nsaddrs;
	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		rw_enter(&sctp->sctp_saddrs[i].ipif_hash_lock, RW_WRITER);
		if (sctp->sctp_saddrs[i].ipif_count == 0) {
			rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
			continue;
		}
		obj = list_head(&sctp->sctp_saddrs[i].sctp_ipif_list);
		naddr = sctp->sctp_saddrs[i].ipif_count;
		for (l = 0; l < naddr; l++) {
			in6_addr_t	addr;
			sctp_ipif_t	*ipif;
			boolean_t	ipif_lb;
			boolean_t	ipif_ll;
			boolean_t	unsupp_af;

			ipif = obj->saddr_ipifp;
			scanned++;

			ipif_lb = SCTP_IS_IPIF_LOOPBACK(ipif);
			ipif_ll = SCTP_IS_IPIF_LINKLOCAL(ipif);
			unsupp_af = SCTP_UNSUPP_AF(ipif, supp_af);
			/*
			 * We need to either delete or skip loopback/linklocal
			 * or unsupported addresses, if required.
			 */
			if ((ipif_ll && del_ll) || (ipif_lb && del_lb) ||
			    (unsupp_af && modify)) {
				if (sctp->sctp_bound_to_all == 1)
					sctp->sctp_bound_to_all = 0;
				if (scanned < nsaddr) {
					obj = list_next(&sctp->sctp_saddrs[i].
					    sctp_ipif_list, obj);
					sctp_ipif_hash_remove(sctp, ipif,
					    B_TRUE);
					continue;
				}
				sctp_ipif_hash_remove(sctp, ipif, B_TRUE);

				goto next_addr;
			} else if (ipif_ll || unsupp_af ||
			    (ipif_lb && (cl_sctp_check_addrs == NULL))) {
				goto next_addr;
			}

			if (!SCTP_IPIF_USABLE(ipif->sctp_ipif_state))
				goto next_addr;
			if (p != NULL)
				hdr = (sctp_parm_hdr_t *)(p + paramlen);
			addr = ipif->sctp_ipif_saddr;
			if (!ipif->sctp_ipif_isv6) {
				struct in_addr	*v4;

				if (p != NULL) {
					hdr->sph_type = htons(PARM_ADDR4);
					hdr->sph_len = htons(PARM_ADDR4_LEN);
					v4 = (struct in_addr *)(hdr + 1);
					IN6_V4MAPPED_TO_INADDR(&addr, v4);
				}
				paramlen += PARM_ADDR4_LEN;
			} else {
				if (p != NULL) {
					hdr->sph_type = htons(PARM_ADDR6);
					hdr->sph_len = htons(PARM_ADDR6_LEN);
					bcopy(&addr, hdr + 1, sizeof (addr));
				}
				paramlen += PARM_ADDR6_LEN;
			}
next_addr:
			if (scanned >= nsaddr) {
				rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
				return (paramlen);
			}
			obj = list_next(&sctp->sctp_saddrs[i].sctp_ipif_list,
			    obj);
		}
		rw_exit(&sctp->sctp_saddrs[i].ipif_hash_lock);
	}
	return (paramlen);
}

/*
 * This is used on a clustered node to obtain a list of addresses, the list
 * consists of sockaddr_in structs for v4 and sockaddr_in6 for v6. The list
 * is then passed onto the clustering module which sends back the correct
 * list based on the port info. Regardless of the input, i.e INADDR_ANY
 * or specific address(es), we create the list since it could be modified by
 * the clustering module. When given a list of addresses, we simply
 * create the list of sockaddr_in or sockaddr_in6 structs using those
 * addresses. If there is an INADDR_ANY in the input list, or if the
 * input is INADDR_ANY, we create a list of sockaddr_in or sockaddr_in6
 * structs consisting all the addresses in the global interface list
 * except those that are hosted on the loopback interface. We create
 * a list of sockaddr_in[6] structs just so that it can be directly input
 * to sctp_valid_addr_list() once the clustering module has processed it.
 */
int
sctp_get_addrlist(sctp_t *sctp, const void *addrs, uint32_t *addrcnt,
    uchar_t **addrlist, int *uspec, size_t *size)
{
	int			cnt;
	int			icnt;
	sctp_ipif_t		*sctp_ipif;
	struct sockaddr_in	*s4;
	struct sockaddr_in6	*s6;
	uchar_t			*p;
	int			err = 0;
	sctp_stack_t		*sctps = sctp->sctp_sctps;
	conn_t			*connp = sctp->sctp_connp;

	*addrlist = NULL;
	*size = 0;

	/*
	 * Create a list of sockaddr_in[6] structs using the input list.
	 */
	if (connp->conn_family == AF_INET) {
		*size = sizeof (struct sockaddr_in) * *addrcnt;
		*addrlist = kmem_zalloc(*size,  KM_SLEEP);
		p = *addrlist;
		for (cnt = 0; cnt < *addrcnt; cnt++) {
			s4 = (struct sockaddr_in *)addrs + cnt;
			/*
			 * We need to create a list of all the available
			 * addresses if there is an INADDR_ANY. However,
			 * if we are beyond LISTEN, then this is invalid
			 * (see sctp_valid_addr_list(). So, we just fail
			 * it here rather than wait till it fails in
			 * sctp_valid_addr_list().
			 */
			if (s4->sin_addr.s_addr == INADDR_ANY) {
				kmem_free(*addrlist, *size);
				*addrlist = NULL;
				*size = 0;
				if (sctp->sctp_state > SCTPS_LISTEN) {
					*addrcnt = 0;
					return (EINVAL);
				}
				if (uspec != NULL)
					*uspec = 1;
				goto get_all_addrs;
			} else {
				bcopy(s4, p, sizeof (*s4));
				p += sizeof (*s4);
			}
		}
	} else {
		*size = sizeof (struct sockaddr_in6) * *addrcnt;
		*addrlist = kmem_zalloc(*size, KM_SLEEP);
		p = *addrlist;
		for (cnt = 0; cnt < *addrcnt; cnt++) {
			s6 = (struct sockaddr_in6 *)addrs + cnt;
			/*
			 * Comments for INADDR_ANY, above, apply here too.
			 */
			if (IN6_IS_ADDR_UNSPECIFIED(&s6->sin6_addr)) {
				kmem_free(*addrlist, *size);
				*size = 0;
				*addrlist = NULL;
				if (sctp->sctp_state > SCTPS_LISTEN) {
					*addrcnt = 0;
					return (EINVAL);
				}
				if (uspec != NULL)
					*uspec = 1;
				goto get_all_addrs;
			} else {
				bcopy(addrs, p, sizeof (*s6));
				p += sizeof (*s6);
			}
		}
	}
	return (err);
get_all_addrs:

	/*
	 * Allocate max possible size. We allocate the max. size here because
	 * the clustering module could end up adding addresses to the list.
	 * We allocate upfront so that the clustering module need to bother
	 * re-sizing the list.
	 */
	if (connp->conn_family == AF_INET) {
		*size = sizeof (struct sockaddr_in) *
		    sctps->sctps_g_ipifs_count;
	} else {
		*size = sizeof (struct sockaddr_in6) *
		    sctps->sctps_g_ipifs_count;
	}
	*addrlist = kmem_zalloc(*size, KM_SLEEP);
	*addrcnt = 0;
	p = *addrlist;
	rw_enter(&sctps->sctps_g_ipifs_lock, RW_READER);

	/*
	 * Walk through the global interface list and add all addresses,
	 * except those that are hosted on loopback interfaces.
	 */
	for (cnt = 0; cnt <  SCTP_IPIF_HASH; cnt++) {
		if (sctps->sctps_g_ipifs[cnt].ipif_count == 0)
			continue;
		sctp_ipif = list_head(
		    &sctps->sctps_g_ipifs[cnt].sctp_ipif_list);
		for (icnt = 0;
		    icnt < sctps->sctps_g_ipifs[cnt].ipif_count;
		    icnt++) {
			in6_addr_t	addr;

			rw_enter(&sctp_ipif->sctp_ipif_lock, RW_READER);
			addr = sctp_ipif->sctp_ipif_saddr;
			if (SCTP_IPIF_DISCARD(sctp_ipif->sctp_ipif_flags) ||
			    !SCTP_IPIF_USABLE(sctp_ipif->sctp_ipif_state) ||
			    SCTP_IS_IPIF_LOOPBACK(sctp_ipif) ||
			    SCTP_IS_IPIF_LINKLOCAL(sctp_ipif) ||
			    !SCTP_IPIF_ZONE_MATCH(sctp, sctp_ipif) ||
			    (connp->conn_family == AF_INET &&
			    sctp_ipif->sctp_ipif_isv6) ||
			    (sctp->sctp_connp->conn_ipv6_v6only &&
			    !sctp_ipif->sctp_ipif_isv6)) {
				rw_exit(&sctp_ipif->sctp_ipif_lock);
				sctp_ipif = list_next(
				    &sctps->sctps_g_ipifs[cnt].sctp_ipif_list,
				    sctp_ipif);
				continue;
			}
			rw_exit(&sctp_ipif->sctp_ipif_lock);
			if (connp->conn_family == AF_INET) {
				s4 = (struct sockaddr_in *)p;
				IN6_V4MAPPED_TO_INADDR(&addr, &s4->sin_addr);
				s4->sin_family = AF_INET;
				p += sizeof (*s4);
			} else {
				s6 = (struct sockaddr_in6 *)p;
				s6->sin6_addr = addr;
				s6->sin6_family = AF_INET6;
				s6->sin6_scope_id =
				    sctp_ipif->sctp_ipif_ill->sctp_ill_index;
				p += sizeof (*s6);
			}
			(*addrcnt)++;
			sctp_ipif = list_next(
			    &sctps->sctps_g_ipifs[cnt].sctp_ipif_list,
			    sctp_ipif);
		}
	}
	rw_exit(&sctps->sctps_g_ipifs_lock);
	return (err);
}

/*
 * Get a list of addresses from the source address list. The  caller is
 * responsible for allocating sufficient buffer for this.
 */
void
sctp_get_saddr_list(sctp_t *sctp, uchar_t *p, size_t psize)
{
	int			cnt;
	int			icnt;
	sctp_saddr_ipif_t	*obj;
	int			naddr;
	int			scanned = 0;

	for (cnt = 0; cnt < SCTP_IPIF_HASH; cnt++) {
		rw_enter(&sctp->sctp_saddrs[cnt].ipif_hash_lock, RW_READER);
		if (sctp->sctp_saddrs[cnt].ipif_count == 0) {
			rw_exit(&sctp->sctp_saddrs[cnt].ipif_hash_lock);
			continue;
		}
		obj = list_head(&sctp->sctp_saddrs[cnt].sctp_ipif_list);
		naddr = sctp->sctp_saddrs[cnt].ipif_count;
		for (icnt = 0; icnt < naddr; icnt++) {
			sctp_ipif_t	*ipif;

			if (psize < sizeof (ipif->sctp_ipif_saddr)) {
				rw_exit(&sctp->sctp_saddrs[cnt].ipif_hash_lock);
				return;
			}

			scanned++;
			ipif = obj->saddr_ipifp;
			bcopy(&ipif->sctp_ipif_saddr, p,
			    sizeof (ipif->sctp_ipif_saddr));
			p += sizeof (ipif->sctp_ipif_saddr);
			psize -= sizeof (ipif->sctp_ipif_saddr);
			if (scanned >= sctp->sctp_nsaddrs) {
				rw_exit(&sctp->sctp_saddrs[cnt].ipif_hash_lock);
				return;
			}
			obj = list_next(
			    &sctp->sctp_saddrs[icnt].sctp_ipif_list,
			    obj);
		}
		rw_exit(&sctp->sctp_saddrs[cnt].ipif_hash_lock);
	}
}

/*
 * Get a list of addresses from the remote address list. The  caller is
 * responsible for allocating sufficient buffer for this.
 */
void
sctp_get_faddr_list(sctp_t *sctp, uchar_t *p, size_t psize)
{
	sctp_faddr_t	*fp;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->sf_next) {
		if (psize < sizeof (fp->sf_faddr))
			return;
		bcopy(&fp->sf_faddr, p, sizeof (fp->sf_faddr));
		p += sizeof (fp->sf_faddr);
		psize -= sizeof (fp->sf_faddr);
	}
}

static void
sctp_free_ills(sctp_stack_t *sctps)
{
	int			i;
	int			l;
	sctp_ill_t	*sctp_ill;

	if (sctps->sctps_ills_count == 0)
		return;

	for (i = 0; i < SCTP_ILL_HASH; i++) {
		sctp_ill = list_tail(&sctps->sctps_g_ills[i].sctp_ill_list);
		for (l = 0; l < sctps->sctps_g_ills[i].ill_count; l++) {
			ASSERT(sctp_ill->sctp_ill_ipifcnt == 0);
			list_remove(&sctps->sctps_g_ills[i].sctp_ill_list,
			    sctp_ill);
			sctps->sctps_ills_count--;
			kmem_free(sctp_ill->sctp_ill_name,
			    sctp_ill->sctp_ill_name_length);
			kmem_free(sctp_ill, sizeof (sctp_ill_t));
			sctp_ill =
			    list_tail(&sctps->sctps_g_ills[i].sctp_ill_list);
		}
		sctps->sctps_g_ills[i].ill_count = 0;
	}
	ASSERT(sctps->sctps_ills_count == 0);
}

static void
sctp_free_ipifs(sctp_stack_t *sctps)
{
	int			i;
	int			l;
	sctp_ipif_t	*sctp_ipif;
	sctp_ill_t	*sctp_ill;

	if (sctps->sctps_g_ipifs_count == 0)
		return;

	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		sctp_ipif = list_tail(&sctps->sctps_g_ipifs[i].sctp_ipif_list);
		for (l = 0; l < sctps->sctps_g_ipifs[i].ipif_count; l++) {
			sctp_ill = sctp_ipif->sctp_ipif_ill;

			list_remove(&sctps->sctps_g_ipifs[i].sctp_ipif_list,
			    sctp_ipif);
			sctps->sctps_g_ipifs_count--;
			atomic_dec_32(&sctp_ill->sctp_ill_ipifcnt);
			kmem_free(sctp_ipif, sizeof (sctp_ipif_t));
			sctp_ipif =
			    list_tail(&sctps->sctps_g_ipifs[i].sctp_ipif_list);
		}
		sctps->sctps_g_ipifs[i].ipif_count = 0;
	}
	ASSERT(sctps->sctps_g_ipifs_count == 0);
}


/* Initialize the SCTP ILL list and lock */
void
sctp_saddr_init(sctp_stack_t *sctps)
{
	int	i;

	sctps->sctps_g_ills = kmem_zalloc(sizeof (sctp_ill_hash_t) *
	    SCTP_ILL_HASH, KM_SLEEP);
	sctps->sctps_g_ipifs = kmem_zalloc(sizeof (sctp_ipif_hash_t) *
	    SCTP_IPIF_HASH, KM_SLEEP);

	rw_init(&sctps->sctps_g_ills_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&sctps->sctps_g_ipifs_lock, NULL, RW_DEFAULT, NULL);

	for (i = 0; i < SCTP_ILL_HASH; i++) {
		sctps->sctps_g_ills[i].ill_count = 0;
		list_create(&sctps->sctps_g_ills[i].sctp_ill_list,
		    sizeof (sctp_ill_t),
		    offsetof(sctp_ill_t, sctp_ills));
	}
	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		sctps->sctps_g_ipifs[i].ipif_count = 0;
		list_create(&sctps->sctps_g_ipifs[i].sctp_ipif_list,
		    sizeof (sctp_ipif_t), offsetof(sctp_ipif_t, sctp_ipifs));
	}
}

void
sctp_saddr_fini(sctp_stack_t *sctps)
{
	int	i;

	sctp_free_ipifs(sctps);
	sctp_free_ills(sctps);

	for (i = 0; i < SCTP_ILL_HASH; i++)
		list_destroy(&sctps->sctps_g_ills[i].sctp_ill_list);
	for (i = 0; i < SCTP_IPIF_HASH; i++)
		list_destroy(&sctps->sctps_g_ipifs[i].sctp_ipif_list);

	ASSERT(sctps->sctps_ills_count == 0 && sctps->sctps_g_ipifs_count == 0);
	kmem_free(sctps->sctps_g_ills, sizeof (sctp_ill_hash_t) *
	    SCTP_ILL_HASH);
	sctps->sctps_g_ills = NULL;
	kmem_free(sctps->sctps_g_ipifs, sizeof (sctp_ipif_hash_t) *
	    SCTP_IPIF_HASH);
	sctps->sctps_g_ipifs = NULL;
	rw_destroy(&sctps->sctps_g_ills_lock);
	rw_destroy(&sctps->sctps_g_ipifs_lock);
}
