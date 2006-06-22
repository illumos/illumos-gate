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
#include <sys/systm.h>
#include <sys/stream.h>
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
#include <inet/ip_if.h>
#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>
#include "sctp_impl.h"
#include "sctp_addr.h"

static void		sctp_ipif_inactive(sctp_ipif_t *);
static sctp_ipif_t	*sctp_lookup_ipif_addr(in6_addr_t *, boolean_t,
			    sctp_t *, uint_t);
static int		sctp_get_all_ipifs(sctp_t *, int);
int			sctp_valid_addr_list(sctp_t *, const void *, uint32_t,
			    uchar_t *, size_t);
sctp_saddr_ipif_t	*sctp_ipif_lookup(sctp_t *, uint_t);
static int		sctp_ipif_hash_insert(sctp_t *, sctp_ipif_t *, int,
			    boolean_t dontsrc);
static void		sctp_ipif_hash_remove(sctp_t *, sctp_ipif_t *);
static int		sctp_compare_ipif_list(sctp_ipif_hash_t *,
			    sctp_ipif_hash_t *);
int			sctp_compare_saddrs(sctp_t *, sctp_t *);
static int		sctp_copy_ipifs(sctp_ipif_hash_t *, sctp_t *, int);
int			sctp_dup_saddrs(sctp_t *, sctp_t *, int);
void			sctp_free_saddrs(sctp_t *);
void			sctp_update_ill(ill_t *, int);
void			sctp_update_ipif(ipif_t *, int);
void			sctp_move_ipif(ipif_t *, ill_t *, ill_t *);
void			sctp_del_saddr(sctp_t *, sctp_saddr_ipif_t *);
void			sctp_del_saddr_list(sctp_t *, const void *, int,
			    boolean_t);
sctp_saddr_ipif_t	*sctp_saddr_lookup(sctp_t *, in6_addr_t *, uint_t);
in6_addr_t		sctp_get_valid_addr(sctp_t *, boolean_t);
int			sctp_getmyaddrs(void *, void *, int *);
void			sctp_saddr_init();
void			sctp_saddr_fini();

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
#define	SCTP_IPIF_HASH_FN(seqid)	((seqid) % SCTP_IPIF_HASH)
#define	SCTP_ILL_TO_PHYINDEX(ill)	((ill)->ill_phyint->phyint_ifindex)

/* Global list of SCTP ILLs */
sctp_ill_hash_t	sctp_g_ills[SCTP_ILL_HASH];
uint32_t	sctp_ills_count = 0;

/* Global list of SCTP IPIFs */
sctp_ipif_hash_t	sctp_g_ipifs[SCTP_IPIF_HASH];
uint32_t		sctp_g_ipifs_count = 0;
/*
 *
 *
 * SCTP Interface list manipulation functions, locking used.
 *
 *
 */

/*
 * Delete an SCTP IPIF from the list if the refcount goes to 0 and it is
 * marked as condemned. Also, check if the ILL needs to go away.
 * Called with no locks held.
 */
static void
sctp_ipif_inactive(sctp_ipif_t *sctp_ipif)
{
	sctp_ill_t	*sctp_ill;
	uint_t		ipif_index;
	uint_t		ill_index;

	rw_enter(&sctp_g_ills_lock, RW_READER);
	rw_enter(&sctp_g_ipifs_lock, RW_WRITER);

	ipif_index = SCTP_IPIF_HASH_FN(sctp_ipif->sctp_ipif_id);
	sctp_ill = sctp_ipif->sctp_ipif_ill;
	ASSERT(sctp_ill != NULL);
	ill_index = SCTP_ILL_HASH_FN(sctp_ill->sctp_ill_index);
	if (sctp_ipif->sctp_ipif_state != SCTP_IPIFS_CONDEMNED ||
	    sctp_ipif->sctp_ipif_refcnt != 0) {
		rw_exit(&sctp_g_ipifs_lock);
		rw_exit(&sctp_g_ills_lock);
		return;
	}
	list_remove(&sctp_g_ipifs[ipif_index].sctp_ipif_list, sctp_ipif);
	sctp_g_ipifs[ipif_index].ipif_count--;
	sctp_g_ipifs_count--;
	rw_destroy(&sctp_ipif->sctp_ipif_lock);
	kmem_free(sctp_ipif, sizeof (sctp_ipif_t));

	(void) atomic_add_32_nv(&sctp_ill->sctp_ill_ipifcnt, -1);
	if (rw_tryupgrade(&sctp_g_ills_lock) != 0) {
		rw_downgrade(&sctp_g_ipifs_lock);
		if (sctp_ill->sctp_ill_ipifcnt == 0 &&
		    sctp_ill->sctp_ill_state == SCTP_ILLS_CONDEMNED) {
			list_remove(&sctp_g_ills[ill_index].sctp_ill_list,
			    (void *)sctp_ill);
			sctp_g_ills[ill_index].ill_count--;
			sctp_ills_count--;
			kmem_free(sctp_ill->sctp_ill_name,
			    sctp_ill->sctp_ill_name_length);
			kmem_free(sctp_ill, sizeof (sctp_ill_t));
		}
	}
	rw_exit(&sctp_g_ipifs_lock);
	rw_exit(&sctp_g_ills_lock);
}

/*
 * Lookup an SCTP IPIF given an IP address. Increments sctp_ipif refcnt.
 * Called with no locks held.
 */
static sctp_ipif_t *
sctp_lookup_ipif_addr(in6_addr_t *addr, boolean_t refhold, sctp_t *sctp,
    uint_t ifindex)
{
	int		i;
	int		j;
	sctp_ipif_t	*sctp_ipif;

	ASSERT(sctp->sctp_zoneid != ALL_ZONES);
	rw_enter(&sctp_g_ipifs_lock, RW_READER);
	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		if (sctp_g_ipifs[i].ipif_count == 0)
			continue;
		sctp_ipif = list_head(&sctp_g_ipifs[i].sctp_ipif_list);
		for (j = 0; j < sctp_g_ipifs[i].ipif_count; j++) {
			rw_enter(&sctp_ipif->sctp_ipif_lock, RW_READER);
			if (SCTP_IPIF_ZONE_MATCH(sctp, sctp_ipif) &&
			    SCTP_IPIF_USABLE(sctp_ipif->sctp_ipif_state) &&
			    (ifindex == 0 || ifindex ==
			    sctp_ipif->sctp_ipif_ill->sctp_ill_index) &&
			    IN6_ARE_ADDR_EQUAL(&sctp_ipif->sctp_ipif_saddr,
			    addr)) {
				rw_exit(&sctp_ipif->sctp_ipif_lock);
				if (refhold)
					SCTP_IPIF_REFHOLD(sctp_ipif);
				rw_exit(&sctp_g_ipifs_lock);
				return (sctp_ipif);
			}
			rw_exit(&sctp_ipif->sctp_ipif_lock);
			sctp_ipif = list_next(&sctp_g_ipifs[i].sctp_ipif_list,
			    sctp_ipif);
		}
	}
	rw_exit(&sctp_g_ipifs_lock);
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

	rw_enter(&sctp_g_ipifs_lock, RW_READER);
	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		if (sctp_g_ipifs[i].ipif_count == 0)
			continue;
		sctp_ipif = list_head(&sctp_g_ipifs[i].sctp_ipif_list);
		for (j = 0; j < sctp_g_ipifs[i].ipif_count; j++) {
			rw_enter(&sctp_ipif->sctp_ipif_lock, RW_READER);
			if (SCTP_IPIF_DISCARD(sctp_ipif->sctp_ipif_flags) ||
			    !SCTP_IPIF_USABLE(sctp_ipif->sctp_ipif_state) ||
			    !SCTP_IPIF_ZONE_MATCH(sctp, sctp_ipif) ||
			    (sctp->sctp_ipversion == IPV4_VERSION &&
			    sctp_ipif->sctp_ipif_isv6) ||
			    (sctp->sctp_connp->conn_ipv6_v6only &&
			    !sctp_ipif->sctp_ipif_isv6)) {
				rw_exit(&sctp_ipif->sctp_ipif_lock);
				sctp_ipif = list_next(
				    &sctp_g_ipifs[i].sctp_ipif_list, sctp_ipif);
				continue;
			}
			rw_exit(&sctp_ipif->sctp_ipif_lock);
			SCTP_IPIF_REFHOLD(sctp_ipif);
			error = sctp_ipif_hash_insert(sctp, sctp_ipif, sleep,
			    B_FALSE);
			if (error != 0)
				goto free_stuff;
			sctp_ipif = list_next(&sctp_g_ipifs[i].sctp_ipif_list,
			    sctp_ipif);
		}
	}
	rw_exit(&sctp_g_ipifs_lock);
	return (0);
free_stuff:
	rw_exit(&sctp_g_ipifs_lock);
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

		switch (sctp->sctp_family) {
		case AF_INET:
			sin4 = (struct sockaddr_in *)addrs + cnt;
			if (sin4->sin_family != AF_INET || (check_lport &&
			    sin4->sin_port != sctp->sctp_lport)) {
				err = EINVAL;
				goto free_ret;
			}
			addr4 = &sin4->sin_addr;
			if (check_addrs &&
			    (addr4->s_addr == INADDR_ANY ||
			    addr4->s_addr == INADDR_BROADCAST ||
			    IN_MULTICAST(addr4->s_addr))) {
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
			    sin6->sin6_port != sctp->sctp_lport)) {
				err = EINVAL;
				goto free_ret;
			}
			addr = sin6->sin6_addr;
			/* Contains the interface index */
			ifindex = sin6->sin6_scope_id;
			if (sctp->sctp_connp->conn_ipv6_v6only &&
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
			ipif = sctp_lookup_ipif_addr(&addr, B_TRUE, sctp,
			    ifindex);
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
			    check_addrs ? B_TRUE : B_FALSE);
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

sctp_saddr_ipif_t *
sctp_ipif_lookup(sctp_t *sctp, uint_t ipif_index)
{
	int			cnt;
	int			seqid = SCTP_IPIF_HASH_FN(ipif_index);
	sctp_saddr_ipif_t	*ipif_obj;

	if (sctp->sctp_saddrs[seqid].ipif_count == 0)
		return (NULL);

	ipif_obj = list_head(&sctp->sctp_saddrs[seqid].sctp_ipif_list);
	for (cnt = 0; cnt < sctp->sctp_saddrs[seqid].ipif_count; cnt++) {
		if (ipif_obj->saddr_ipifp->sctp_ipif_id == ipif_index)
			return (ipif_obj);
		ipif_obj = list_next(&sctp->sctp_saddrs[seqid].sctp_ipif_list,
		    ipif_obj);
	}
	return (NULL);
}

static int
sctp_ipif_hash_insert(sctp_t *sctp, sctp_ipif_t *ipif, int sleep,
    boolean_t dontsrc)
{
	int			cnt;
	sctp_saddr_ipif_t	*ipif_obj;
	int			seqid = SCTP_IPIF_HASH_FN(ipif->sctp_ipif_id);

	ipif_obj = list_head(&sctp->sctp_saddrs[seqid].sctp_ipif_list);
	for (cnt = 0; cnt < sctp->sctp_saddrs[seqid].ipif_count; cnt++) {
		if (ipif_obj->saddr_ipifp->sctp_ipif_id == ipif->sctp_ipif_id)
			return (EALREADY);
		ipif_obj = list_next(&sctp->sctp_saddrs[seqid].sctp_ipif_list,
		    ipif_obj);
	}
	ipif_obj = kmem_zalloc(sizeof (sctp_saddr_ipif_t), sleep);
	if (ipif_obj == NULL) {
		/* Need to do something */
		return (ENOMEM);
	}
	ipif_obj->saddr_ipifp = ipif;
	ipif_obj->saddr_ipif_dontsrc = dontsrc ? 1 : 0;
	list_insert_tail(&sctp->sctp_saddrs[seqid].sctp_ipif_list, ipif_obj);
	sctp->sctp_saddrs[seqid].ipif_count++;
	sctp->sctp_nsaddrs++;
	return (0);
}

static void
sctp_ipif_hash_remove(sctp_t *sctp, sctp_ipif_t *ipif)
{
	int			cnt;
	sctp_saddr_ipif_t	*ipif_obj;
	int			seqid = SCTP_IPIF_HASH_FN(ipif->sctp_ipif_id);

	ipif_obj = list_head(&sctp->sctp_saddrs[seqid].sctp_ipif_list);
	for (cnt = 0; cnt < sctp->sctp_saddrs[seqid].ipif_count; cnt++) {
		if (ipif_obj->saddr_ipifp->sctp_ipif_id == ipif->sctp_ipif_id) {
			list_remove(&sctp->sctp_saddrs[seqid].sctp_ipif_list,
			    ipif_obj);
			sctp->sctp_nsaddrs--;
			sctp->sctp_saddrs[seqid].ipif_count--;
			SCTP_IPIF_REFRELE(ipif_obj->saddr_ipifp);
			kmem_free(ipif_obj, sizeof (sctp_saddr_ipif_t));
			break;
		}
		ipif_obj = list_next(&sctp->sctp_saddrs[seqid].sctp_ipif_list,
		    ipif_obj);
	}
}

static int
sctp_compare_ipif_list(sctp_ipif_hash_t *list1, sctp_ipif_hash_t *list2)
{
	int			i;
	int			j;
	sctp_saddr_ipif_t	*obj1;
	sctp_saddr_ipif_t	*obj2;
	int			overlap = 0;

	obj1 = list_head(&list1->sctp_ipif_list);
	for (i = 0; i < list1->ipif_count; i++) {
		obj2 = list_head(&list2->sctp_ipif_list);
		for (j = 0; j < list2->ipif_count; j++) {
			if (obj1->saddr_ipifp->sctp_ipif_id ==
			    obj2->saddr_ipifp->sctp_ipif_id) {
				overlap++;
				break;
			}
			obj2 = list_next(&list2->sctp_ipif_list,
			    obj2);
		}
		obj1 = list_next(&list1->sctp_ipif_list, obj1);
	}
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

	obj = list_head(&list1->sctp_ipif_list);
	for (i = 0; i < list1->ipif_count; i++) {
		SCTP_IPIF_REFHOLD(obj->saddr_ipifp);
		error = sctp_ipif_hash_insert(sctp2, obj->saddr_ipifp, sleep,
		    B_FALSE);
		if (error != 0)
			return (error);
		obj = list_next(&list1->sctp_ipif_list, obj);
	}
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
		if (sctp1->sctp_saddrs[i].ipif_count == 0)
			continue;
		error = sctp_copy_ipifs(&sctp1->sctp_saddrs[i], sctp2, sleep);
		if (error != 0) {
			sctp_free_saddrs(sctp2);
			return (error);
		}
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
		if (sctp->sctp_saddrs[i].ipif_count == 0)
			continue;
		obj = list_tail(&sctp->sctp_saddrs[i].sctp_ipif_list);
		for (l = 0; l < sctp->sctp_saddrs[i].ipif_count; l++) {
			list_remove(&sctp->sctp_saddrs[i].sctp_ipif_list, obj);
			SCTP_IPIF_REFRELE(obj->saddr_ipifp);
			sctp->sctp_nsaddrs--;
			kmem_free(obj, sizeof (sctp_saddr_ipif_t));
			obj = list_tail(&sctp->sctp_saddrs[i].sctp_ipif_list);
		}
		sctp->sctp_saddrs[i].ipif_count = 0;
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

	ip2dbg(("sctp_update_ill: %s\n", ill->ill_name));

	rw_enter(&sctp_g_ills_lock, RW_WRITER);

	index = SCTP_ILL_HASH_FN(SCTP_ILL_TO_PHYINDEX(ill));
	sctp_ill = list_head(&sctp_g_ills[index].sctp_ill_list);
	for (i = 0; i < sctp_g_ills[index].ill_count; i++) {
		if (sctp_ill->sctp_ill_index == SCTP_ILL_TO_PHYINDEX(ill))
			break;
		sctp_ill = list_next(&sctp_g_ills[index].sctp_ill_list,
		    sctp_ill);
	}

	switch (op) {
	case SCTP_ILL_INSERT:
		if (sctp_ill != NULL) {
			/* Unmark it if it is condemned */
			if (sctp_ill->sctp_ill_state == SCTP_ILLS_CONDEMNED)
				sctp_ill->sctp_ill_state = 0;
			rw_exit(&sctp_g_ills_lock);
			return;
		}
		sctp_ill = kmem_zalloc(sizeof (sctp_ill_t), KM_NOSLEEP);
		/* Need to re-try? */
		if (sctp_ill == NULL) {
			ip1dbg(("sctp_ill_insert: mem error..\n"));
			rw_exit(&sctp_g_ills_lock);
			return;
		}
		sctp_ill->sctp_ill_name =
		    kmem_zalloc(ill->ill_name_length, KM_NOSLEEP);
		if (sctp_ill->sctp_ill_name == NULL) {
			ip1dbg(("sctp_ill_insert: mem error..\n"));
			kmem_free(sctp_ill, sizeof (sctp_ill_t));
			rw_exit(&sctp_g_ills_lock);
			return;
		}
		bcopy(ill->ill_name, sctp_ill->sctp_ill_name,
		    ill->ill_name_length);
		sctp_ill->sctp_ill_name_length = ill->ill_name_length;
		sctp_ill->sctp_ill_index = SCTP_ILL_TO_PHYINDEX(ill);
		sctp_ill->sctp_ill_flags = ill->ill_phyint->phyint_flags;
		list_insert_tail(&sctp_g_ills[index].sctp_ill_list,
		    (void *)sctp_ill);
		sctp_g_ills[index].ill_count++;
		sctp_ills_count++;

		break;

	case SCTP_ILL_REMOVE:

		if (sctp_ill == NULL) {
			rw_exit(&sctp_g_ills_lock);
			return;
		}
		if (sctp_ill->sctp_ill_ipifcnt == 0) {
			list_remove(&sctp_g_ills[index].sctp_ill_list,
			    (void *)sctp_ill);
			sctp_g_ills[index].ill_count--;
			sctp_ills_count--;
			kmem_free(sctp_ill->sctp_ill_name,
			    ill->ill_name_length);
			kmem_free(sctp_ill, sizeof (sctp_ill_t));
		} else {
			sctp_ill->sctp_ill_state = SCTP_ILLS_CONDEMNED;
		}

		break;
	}
	rw_exit(&sctp_g_ills_lock);
}

/* move ipif from f_ill to t_ill */
void
sctp_move_ipif(ipif_t *ipif, ill_t *f_ill, ill_t *t_ill)
{
	sctp_ill_t	*fsctp_ill = NULL;
	sctp_ill_t	*tsctp_ill = NULL;
	sctp_ipif_t	*sctp_ipif;
	uint_t		index;
	int		i;

	rw_enter(&sctp_g_ills_lock, RW_READER);
	rw_enter(&sctp_g_ipifs_lock, RW_READER);

	index = SCTP_ILL_HASH_FN(SCTP_ILL_TO_PHYINDEX(f_ill));
	fsctp_ill = list_head(&sctp_g_ills[index].sctp_ill_list);
	for (i = 0; i < sctp_g_ills[index].ill_count; i++) {
		if (fsctp_ill->sctp_ill_index == SCTP_ILL_TO_PHYINDEX(f_ill))
			break;
		fsctp_ill = list_next(&sctp_g_ills[index].sctp_ill_list,
		    fsctp_ill);
	}

	index = SCTP_ILL_HASH_FN(SCTP_ILL_TO_PHYINDEX(t_ill));
	tsctp_ill = list_head(&sctp_g_ills[index].sctp_ill_list);
	for (i = 0; i < sctp_g_ills[index].ill_count; i++) {
		if (tsctp_ill->sctp_ill_index == SCTP_ILL_TO_PHYINDEX(t_ill))
			break;
		tsctp_ill = list_next(&sctp_g_ills[index].sctp_ill_list,
		    tsctp_ill);
	}

	index = SCTP_IPIF_HASH_FN(ipif->ipif_seqid);
	sctp_ipif = list_head(&sctp_g_ipifs[index].sctp_ipif_list);
	for (i = 0; i < sctp_g_ipifs[index].ipif_count; i++) {
		if (sctp_ipif->sctp_ipif_id == ipif->ipif_seqid)
			break;
		sctp_ipif = list_next(&sctp_g_ipifs[index].sctp_ipif_list,
		    sctp_ipif);
	}
	/* Should be an ASSERT? */
	if (fsctp_ill == NULL || tsctp_ill == NULL || sctp_ipif == NULL) {
		ip1dbg(("sctp_move_ipif: error moving ipif %p from %p to %p\n",
		    (void *)ipif, (void *)f_ill, (void *)t_ill));
		rw_exit(&sctp_g_ipifs_lock);
		rw_exit(&sctp_g_ills_lock);
		return;
	}
	rw_enter(&sctp_ipif->sctp_ipif_lock, RW_WRITER);
	ASSERT(sctp_ipif->sctp_ipif_ill == fsctp_ill);
	sctp_ipif->sctp_ipif_ill = tsctp_ill;
	rw_exit(&sctp_ipif->sctp_ipif_lock);
	(void) atomic_add_32_nv(&fsctp_ill->sctp_ill_ipifcnt, -1);
	atomic_add_32(&tsctp_ill->sctp_ill_ipifcnt, 1);
	rw_exit(&sctp_g_ipifs_lock);
	rw_exit(&sctp_g_ills_lock);
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
	uint_t		ipif_index;

	ip2dbg(("sctp_update_ipif: %s %d\n", ill->ill_name, ipif->ipif_seqid));

	rw_enter(&sctp_g_ills_lock, RW_READER);
	rw_enter(&sctp_g_ipifs_lock, RW_WRITER);

	ill_index = SCTP_ILL_HASH_FN(SCTP_ILL_TO_PHYINDEX(ill));
	sctp_ill = list_head(&sctp_g_ills[ill_index].sctp_ill_list);
	for (i = 0; i < sctp_g_ills[ill_index].ill_count; i++) {
		if (sctp_ill->sctp_ill_index == SCTP_ILL_TO_PHYINDEX(ill))
			break;
		sctp_ill = list_next(&sctp_g_ills[ill_index].sctp_ill_list,
		    sctp_ill);
	}
	if (sctp_ill == NULL) {
		rw_exit(&sctp_g_ipifs_lock);
		rw_exit(&sctp_g_ills_lock);
		return;
	}

	ipif_index = SCTP_IPIF_HASH_FN(ipif->ipif_seqid);
	sctp_ipif = list_head(&sctp_g_ipifs[ipif_index].sctp_ipif_list);
	for (i = 0; i < sctp_g_ipifs[ipif_index].ipif_count; i++) {
		if (sctp_ipif->sctp_ipif_id == ipif->ipif_seqid)
			break;
		sctp_ipif = list_next(&sctp_g_ipifs[ipif_index].sctp_ipif_list,
		    sctp_ipif);
	}
	if (op != SCTP_IPIF_INSERT && sctp_ipif == NULL) {
		ip1dbg(("sctp_update_ipif: null sctp_ipif for %d\n", op));
		rw_exit(&sctp_g_ipifs_lock);
		rw_exit(&sctp_g_ills_lock);
		return;
	}
#ifdef	DEBUG
	if (sctp_ipif != NULL)
		ASSERT(sctp_ill == sctp_ipif->sctp_ipif_ill);
#endif
	switch (op) {
	case SCTP_IPIF_INSERT:
		if (sctp_ipif != NULL) {
			if (sctp_ipif->sctp_ipif_state == SCTP_IPIFS_CONDEMNED)
				sctp_ipif->sctp_ipif_state = SCTP_IPIFS_INVALID;
			rw_exit(&sctp_g_ipifs_lock);
			rw_exit(&sctp_g_ills_lock);
			return;
		}
		sctp_ipif = kmem_zalloc(sizeof (sctp_ipif_t), KM_NOSLEEP);
		/* Try again? */
		if (sctp_ipif == NULL) {
			ip1dbg(("sctp_ipif_insert: mem failure..\n"));
			rw_exit(&sctp_g_ipifs_lock);
			rw_exit(&sctp_g_ills_lock);
			return;
		}
		sctp_ipif->sctp_ipif_id = ipif->ipif_seqid;
		sctp_ipif->sctp_ipif_ill = sctp_ill;
		sctp_ipif->sctp_ipif_state = SCTP_IPIFS_INVALID;
		sctp_ipif->sctp_ipif_mtu = ipif->ipif_mtu;
		sctp_ipif->sctp_ipif_zoneid = ipif->ipif_zoneid;
		sctp_ipif->sctp_ipif_isv6 = ill->ill_isv6;
		sctp_ipif->sctp_ipif_flags = ipif->ipif_flags;
		rw_init(&sctp_ipif->sctp_ipif_lock, NULL, RW_DEFAULT, NULL);
		list_insert_tail(&sctp_g_ipifs[ipif_index].sctp_ipif_list,
		    (void *)sctp_ipif);
		sctp_g_ipifs[ipif_index].ipif_count++;
		sctp_g_ipifs_count++;
		atomic_add_32(&sctp_ill->sctp_ill_ipifcnt, 1);

		break;

	case SCTP_IPIF_REMOVE:
	{
		list_t		*ipif_list;
		list_t		*ill_list;

		ill_list = &sctp_g_ills[ill_index].sctp_ill_list;
		ipif_list = &sctp_g_ipifs[ipif_index].sctp_ipif_list;
		if (sctp_ipif->sctp_ipif_refcnt != 0) {
			sctp_ipif->sctp_ipif_state = SCTP_IPIFS_CONDEMNED;
			rw_exit(&sctp_g_ipifs_lock);
			rw_exit(&sctp_g_ills_lock);
			return;
		}
		list_remove(ipif_list, (void *)sctp_ipif);
		sctp_g_ipifs[ipif_index].ipif_count--;
		sctp_g_ipifs_count--;
		rw_destroy(&sctp_ipif->sctp_ipif_lock);
		kmem_free(sctp_ipif, sizeof (sctp_ipif_t));
		(void) atomic_add_32_nv(&sctp_ill->sctp_ill_ipifcnt, -1);
		if (rw_tryupgrade(&sctp_g_ills_lock) != 0) {
			rw_downgrade(&sctp_g_ipifs_lock);
			if (sctp_ill->sctp_ill_ipifcnt == 0 &&
			    sctp_ill->sctp_ill_state == SCTP_ILLS_CONDEMNED) {
				list_remove(ill_list, (void *)sctp_ill);
				sctp_ills_count--;
				sctp_g_ills[ill_index].ill_count--;
				kmem_free(sctp_ill->sctp_ill_name,
				    sctp_ill->sctp_ill_name_length);
				kmem_free(sctp_ill, sizeof (sctp_ill_t));
			}
		}
		break;
	}

	case SCTP_IPIF_UP:

		rw_downgrade(&sctp_g_ipifs_lock);
		rw_enter(&sctp_ipif->sctp_ipif_lock, RW_WRITER);
		sctp_ipif->sctp_ipif_state = SCTP_IPIFS_UP;
		sctp_ipif->sctp_ipif_saddr = ipif->ipif_v6lcl_addr;
		sctp_ipif->sctp_ipif_flags = ipif->ipif_flags;
		sctp_ipif->sctp_ipif_mtu = ipif->ipif_mtu;
		rw_exit(&sctp_ipif->sctp_ipif_lock);

		break;

	case SCTP_IPIF_UPDATE:

		rw_downgrade(&sctp_g_ipifs_lock);
		rw_enter(&sctp_ipif->sctp_ipif_lock, RW_WRITER);
		sctp_ipif->sctp_ipif_mtu = ipif->ipif_mtu;
		sctp_ipif->sctp_ipif_saddr = ipif->ipif_v6lcl_addr;
		sctp_ipif->sctp_ipif_zoneid = ipif->ipif_zoneid;
		sctp_ipif->sctp_ipif_flags = ipif->ipif_flags;
		rw_exit(&sctp_ipif->sctp_ipif_lock);

		break;

	case SCTP_IPIF_DOWN:

		rw_downgrade(&sctp_g_ipifs_lock);
		rw_enter(&sctp_ipif->sctp_ipif_lock, RW_WRITER);
		sctp_ipif->sctp_ipif_state = SCTP_IPIFS_DOWN;
		rw_exit(&sctp_ipif->sctp_ipif_lock);

		break;
	}
	rw_exit(&sctp_g_ipifs_lock);
	rw_exit(&sctp_g_ills_lock);
}

/*
 *
 *
 * SCTP source address list manipulaton, locking not used (except for
 * sctp locking by the caller.
 *
 *
 */

/* Remove a specific saddr from the list */
void
sctp_del_saddr(sctp_t *sctp, sctp_saddr_ipif_t *sp)
{
	if (sctp->sctp_conn_tfp != NULL)
		mutex_enter(&sctp->sctp_conn_tfp->tf_lock);

	if (sctp->sctp_listen_tfp != NULL)
		mutex_enter(&sctp->sctp_listen_tfp->tf_lock);

	sctp_ipif_hash_remove(sctp, sp->saddr_ipifp);

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

	ASSERT(sctp->sctp_nsaddrs >= addcnt);

	if (!fanout_locked) {
		if (sctp->sctp_conn_tfp != NULL)
			mutex_enter(&sctp->sctp_conn_tfp->tf_lock);
		if (sctp->sctp_listen_tfp != NULL)
			mutex_enter(&sctp->sctp_listen_tfp->tf_lock);
	}

	for (cnt = 0; cnt < addcnt; cnt++) {
		switch (sctp->sctp_family) {
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
		sctp_ipif = sctp_lookup_ipif_addr(&addr, B_FALSE, sctp,
		    ifindex);
		ASSERT(sctp_ipif != NULL);
		sctp_ipif_hash_remove(sctp, sctp_ipif);
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
	sctp_saddr_ipif_t	*saddr_ipifs;
	sctp_ipif_t		*sctp_ipif;

	sctp_ipif = sctp_lookup_ipif_addr(addr, B_FALSE, sctp, ifindex);
	if (sctp_ipif == NULL)
		return (NULL);

	saddr_ipifs = sctp_ipif_lookup(sctp, sctp_ipif->sctp_ipif_id);
	return (saddr_ipifs);
}

/* Given an address, add it to the source address list */
int
sctp_saddr_add_addr(sctp_t *sctp, in6_addr_t *addr, uint_t ifindex)
{
	sctp_ipif_t		*sctp_ipif;

	sctp_ipif = sctp_lookup_ipif_addr(addr, B_TRUE, sctp, ifindex);
	if (sctp_ipif == NULL)
		return (EINVAL);

	if (sctp_ipif_hash_insert(sctp, sctp_ipif, KM_NOSLEEP, B_FALSE) != 0) {
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
sctp_check_saddr(sctp_t *sctp, int supp_af, boolean_t delete)
{
	int			i;
	int			l;
	sctp_saddr_ipif_t	*obj;
	int			scanned = 0;
	int			naddr;
	int			nsaddr;

	ASSERT(!sctp->sctp_loopback && !sctp->sctp_linklocal && supp_af != 0);

	/*
	 * Irregardless of the supported address in the INIT, v4
	 * must be supported.
	 */
	if (sctp->sctp_family == AF_INET)
		supp_af = PARM_SUPP_V4;

	nsaddr = sctp->sctp_nsaddrs;
	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		if (sctp->sctp_saddrs[i].ipif_count == 0)
			continue;
		obj = list_head(&sctp->sctp_saddrs[i].sctp_ipif_list);
		naddr = sctp->sctp_saddrs[i].ipif_count;
		for (l = 0; l < naddr; l++) {
			sctp_ipif_t	*ipif;

			ipif = obj->saddr_ipifp;
			scanned++;

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
					sctp_ipif_hash_remove(sctp, ipif);
					continue;
				}
				sctp_ipif_hash_remove(sctp, ipif);
			}
	next_obj:
			if (scanned >= nsaddr)
				return;
			obj = list_next(&sctp->sctp_saddrs[i].sctp_ipif_list,
			    obj);
		}
	}
}


/* Get the first valid address from the list. Called with no locks held */
in6_addr_t
sctp_get_valid_addr(sctp_t *sctp, boolean_t isv6)
{
	int			i;
	int			l;
	sctp_saddr_ipif_t	*obj;
	int			scanned = 0;
	in6_addr_t		addr;

	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		if (sctp->sctp_saddrs[i].ipif_count == 0)
			continue;
		obj = list_head(&sctp->sctp_saddrs[i].sctp_ipif_list);
		for (l = 0; l < sctp->sctp_saddrs[i].ipif_count; l++) {
			sctp_ipif_t	*ipif;

			ipif = obj->saddr_ipifp;
			if (!SCTP_DONT_SRC(obj) &&
			    ipif->sctp_ipif_isv6 == isv6 &&
			    ipif->sctp_ipif_state == SCTP_IPIFS_UP) {
				return (ipif->sctp_ipif_saddr);
			}
			scanned++;
			if (scanned >= sctp->sctp_nsaddrs)
				goto got_none;
			obj = list_next(&sctp->sctp_saddrs[i].sctp_ipif_list,
			    obj);
		}
	}
got_none:
	/* Need to double check this */
	if (isv6 == B_TRUE)
		addr =  ipv6_all_zeros;
	else
		IN6_IPADDR_TO_V4MAPPED(0, &addr);

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
	int			family = sctp->sctp_family;
	int			max = *addrcnt;
	size_t			added = 0;
	struct sockaddr_in6	*sin6;
	struct sockaddr_in	*sin4;
	int			scanned = 0;
	boolean_t		skip_lback = B_FALSE;

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
		if (sctp->sctp_saddrs[i].ipif_count == 0)
			continue;
		obj = list_head(&sctp->sctp_saddrs[i].sctp_ipif_list);
		for (l = 0; l < sctp->sctp_saddrs[i].ipif_count; l++) {
			sctp_ipif_t	*ipif = obj->saddr_ipifp;
			in6_addr_t	addr = ipif->sctp_ipif_saddr;

			scanned++;
			if ((ipif->sctp_ipif_state == SCTP_IPIFS_CONDEMNED) ||
			    SCTP_DONT_SRC(obj) ||
			    (SCTP_IS_IPIF_LOOPBACK(ipif) && skip_lback)) {
				if (scanned >= sctp->sctp_nsaddrs)
					goto done;
				obj = list_next(&sctp->sctp_saddrs[i].
				    sctp_ipif_list, obj);
				continue;
			}
			switch (family) {
			case AF_INET:
				sin4 = (struct sockaddr_in *)myaddrs + added;
				sin4->sin_family = AF_INET;
				sin4->sin_port = sctp->sctp_lport;
				IN6_V4MAPPED_TO_INADDR(&addr, &sin4->sin_addr);
				break;

			case AF_INET6:
				sin6 = (struct sockaddr_in6 *)myaddrs + added;
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = sctp->sctp_lport;
				sin6->sin6_addr = addr;
				break;
			}
			added++;
			if (added >= max || scanned >= sctp->sctp_nsaddrs)
				goto done;
			obj = list_next(&sctp->sctp_saddrs[i].sctp_ipif_list,
			    obj);
		}
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
		if (sctp->sctp_saddrs[i].ipif_count == 0)
			continue;
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
					sctp_ipif_hash_remove(sctp, ipif);
					continue;
				}
				sctp_ipif_hash_remove(sctp, ipif);
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
			if (scanned >= nsaddr)
				return (paramlen);
			obj = list_next(&sctp->sctp_saddrs[i].sctp_ipif_list,
			    obj);
		}
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

	*addrlist = NULL;
	*size = 0;

	/*
	 * Create a list of sockaddr_in[6] structs using the input list.
	 */
	if (sctp->sctp_family == AF_INET) {
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
	if (sctp->sctp_family == AF_INET)
		*size = sizeof (struct sockaddr_in) * sctp_g_ipifs_count;
	else
		*size = sizeof (struct sockaddr_in6) * sctp_g_ipifs_count;

	*addrlist = kmem_zalloc(*size, KM_SLEEP);
	*addrcnt = 0;
	p = *addrlist;
	rw_enter(&sctp_g_ipifs_lock, RW_READER);

	/*
	 * Walk through the global interface list and add all addresses,
	 * except those that are hosted on loopback interfaces.
	 */
	for (cnt = 0; cnt <  SCTP_IPIF_HASH; cnt++) {
		if (sctp_g_ipifs[cnt].ipif_count == 0)
			continue;
		sctp_ipif = list_head(&sctp_g_ipifs[cnt].sctp_ipif_list);
		for (icnt = 0; icnt < sctp_g_ipifs[cnt].ipif_count; icnt++) {
			in6_addr_t	addr;

			rw_enter(&sctp_ipif->sctp_ipif_lock, RW_READER);
			addr = sctp_ipif->sctp_ipif_saddr;
			if (SCTP_IPIF_DISCARD(sctp_ipif->sctp_ipif_flags) ||
			    !SCTP_IPIF_USABLE(sctp_ipif->sctp_ipif_state) ||
			    SCTP_IS_IPIF_LOOPBACK(sctp_ipif) ||
			    SCTP_IS_IPIF_LINKLOCAL(sctp_ipif) ||
			    !SCTP_IPIF_ZONE_MATCH(sctp, sctp_ipif) ||
			    (sctp->sctp_ipversion == IPV4_VERSION &&
			    sctp_ipif->sctp_ipif_isv6) ||
			    (sctp->sctp_connp->conn_ipv6_v6only &&
			    !sctp_ipif->sctp_ipif_isv6)) {
				rw_exit(&sctp_ipif->sctp_ipif_lock);
				sctp_ipif = list_next(
				    &sctp_g_ipifs[cnt].sctp_ipif_list,
				    sctp_ipif);
				continue;
			}
			rw_exit(&sctp_ipif->sctp_ipif_lock);
			if (sctp->sctp_family == AF_INET) {
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
			sctp_ipif = list_next(&sctp_g_ipifs[cnt].sctp_ipif_list,
			    sctp_ipif);
		}
	}
	rw_exit(&sctp_g_ipifs_lock);
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
		if (sctp->sctp_saddrs[cnt].ipif_count == 0)
			continue;
		obj = list_head(&sctp->sctp_saddrs[cnt].sctp_ipif_list);
		naddr = sctp->sctp_saddrs[cnt].ipif_count;
		for (icnt = 0; icnt < naddr; icnt++) {
			sctp_ipif_t	*ipif;

			if (psize < sizeof (ipif->sctp_ipif_saddr))
				return;

			scanned++;
			ipif = obj->saddr_ipifp;
			bcopy(&ipif->sctp_ipif_saddr, p,
			    sizeof (ipif->sctp_ipif_saddr));
			p += sizeof (ipif->sctp_ipif_saddr);
			psize -= sizeof (ipif->sctp_ipif_saddr);
			if (scanned >= sctp->sctp_nsaddrs)
				return;
			obj = list_next(&sctp->sctp_saddrs[icnt].sctp_ipif_list,
			    obj);
		}
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

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
		if (psize < sizeof (fp->faddr))
			return;
		bcopy(&fp->faddr, p, sizeof (fp->faddr));
		p += sizeof (fp->faddr);
		psize -= sizeof (fp->faddr);
	}
}

/* Initialize the SCTP ILL list and lock */
void
sctp_saddr_init()
{
	int	i;

	rw_init(&sctp_g_ills_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&sctp_g_ipifs_lock, NULL, RW_DEFAULT, NULL);

	for (i = 0; i < SCTP_ILL_HASH; i++) {
		sctp_g_ills[i].ill_count = 0;
		list_create(&sctp_g_ills[i].sctp_ill_list, sizeof (sctp_ill_t),
		    offsetof(sctp_ill_t, sctp_ills));
	}
	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		sctp_g_ipifs[i].ipif_count = 0;
		list_create(&sctp_g_ipifs[i].sctp_ipif_list,
		    sizeof (sctp_ipif_t), offsetof(sctp_ipif_t, sctp_ipifs));
	}
}

void
sctp_saddr_fini()
{
	int	i;

	rw_destroy(&sctp_g_ills_lock);
	rw_destroy(&sctp_g_ipifs_lock);
	ASSERT(sctp_ills_count == 0 && sctp_g_ipifs_count == 0);
	for (i = 0; i < SCTP_ILL_HASH; i++)
		list_destroy(&sctp_g_ills[i].sctp_ill_list);
	for (i = 0; i < SCTP_IPIF_HASH; i++)
		list_destroy(&sctp_g_ipifs[i].sctp_ipif_list);
}
