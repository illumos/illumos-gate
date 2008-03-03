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
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/policy.h>
#include <sys/tsol/tndb.h>
#include <sys/tsol/tnet.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ipclassifier.h>
#include "sctp_impl.h"
#include "sctp_asconf.h"
#include "sctp_addr.h"

/*
 * Returns 0 on success, EACCES on permission failure.
 */
static int
sctp_select_port(sctp_t *sctp, in_port_t *requested_port, int *user_specified)
{
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	/*
	 * Get a valid port (within the anonymous range and should not
	 * be a privileged one) to use if the user has not given a port.
	 * If multiple threads are here, they may all start with
	 * with the same initial port. But, it should be fine as long as
	 * sctp_bindi will ensure that no two threads will be assigned
	 * the same port.
	 */
	if (*requested_port == 0) {
		*requested_port = sctp_update_next_port(
		    sctps->sctps_next_port_to_try,
		    crgetzone(sctp->sctp_credp), sctps);
		if (*requested_port == 0)
			return (EACCES);
		*user_specified = 0;
	} else {
		int i;
		boolean_t priv = B_FALSE;

		/*
		 * If the requested_port is in the well-known privileged range,
		 * verify that the stream was opened by a privileged user.
		 * Note: No locks are held when inspecting sctp_g_*epriv_ports
		 * but instead the code relies on:
		 * - the fact that the address of the array and its size never
		 *   changes
		 * - the atomic assignment of the elements of the array
		 */
		if (*requested_port < sctps->sctps_smallest_nonpriv_port) {
			priv = B_TRUE;
		} else {
			for (i = 0; i < sctps->sctps_g_num_epriv_ports; i++) {
				if (*requested_port ==
				    sctps->sctps_g_epriv_ports[i]) {
					priv = B_TRUE;
					break;
				}
			}
		}
		if (priv) {
			/*
			 * sctp_bind() should take a cred_t argument so that
			 * we can use it here.
			 */
			if (secpolicy_net_privaddr(sctp->sctp_credp,
			    *requested_port, IPPROTO_SCTP) != 0) {
				dprint(1,
				    ("sctp_bind(x): no prive for port %d",
				    *requested_port));
				return (EACCES);
			}
		}
		*user_specified = 1;
	}

	return (0);
}

int
sctp_listen(sctp_t *sctp)
{
	sctp_tf_t	*tf;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	RUN_SCTP(sctp);
	/*
	 * TCP handles listen() increasing the backlog, need to check
	 * if it should be handled here too
	 */
	if (sctp->sctp_state > SCTPS_BOUND ||
	    (sctp->sctp_connp->conn_state_flags & CONN_CLOSING)) {
		WAKE_SCTP(sctp);
		return (EINVAL);
	}

	/* Do an anonymous bind for unbound socket doing listen(). */
	if (sctp->sctp_nsaddrs == 0) {
		struct sockaddr_storage ss;
		int ret;

		bzero(&ss, sizeof (ss));
		ss.ss_family = sctp->sctp_family;

		WAKE_SCTP(sctp);
		if ((ret = sctp_bind(sctp, (struct sockaddr *)&ss,
		    sizeof (ss))) != 0)
			return (ret);
		RUN_SCTP(sctp)
	}

	sctp->sctp_state = SCTPS_LISTEN;
	(void) random_get_pseudo_bytes(sctp->sctp_secret, SCTP_SECRET_LEN);
	sctp->sctp_last_secret_update = lbolt64;
	bzero(sctp->sctp_old_secret, SCTP_SECRET_LEN);
	tf = &sctps->sctps_listen_fanout[SCTP_LISTEN_HASH(
	    ntohs(sctp->sctp_lport))];
	sctp_listen_hash_insert(tf, sctp);
	WAKE_SCTP(sctp);
	return (0);
}

/*
 * Bind the sctp_t to a sockaddr, which includes an address and other
 * information, such as port or flowinfo.
 */
int
sctp_bind(sctp_t *sctp, struct sockaddr *sa, socklen_t len)
{
	int		user_specified;
	boolean_t	bind_to_req_port_only;
	in_port_t	requested_port;
	in_port_t	allocated_port;
	int		err = 0;

	ASSERT(sctp != NULL);
	ASSERT(sa);

	RUN_SCTP(sctp);

	if (sctp->sctp_state > SCTPS_BOUND ||
	    (sctp->sctp_connp->conn_state_flags & CONN_CLOSING)) {
		err = EINVAL;
		goto done;
	}

	switch (sa->sa_family) {
	case AF_INET:
		if (len < sizeof (struct sockaddr_in) ||
		    sctp->sctp_family == AF_INET6) {
			err = EINVAL;
			goto done;
		}
		requested_port = ntohs(((struct sockaddr_in *)sa)->sin_port);
		break;
	case AF_INET6:
		if (len < sizeof (struct sockaddr_in6) ||
		    sctp->sctp_family == AF_INET) {
			err = EINVAL;
			goto done;
		}
		requested_port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
		/* Set the flowinfo. */
		sctp->sctp_ip6h->ip6_vcf =
		    (IPV6_DEFAULT_VERS_AND_FLOW & IPV6_VERS_AND_FLOW_MASK) |
		    (((struct sockaddr_in6 *)sa)->sin6_flowinfo &
		    ~IPV6_VERS_AND_FLOW_MASK);
		break;
	default:
		err = EAFNOSUPPORT;
		goto done;
	}
	bind_to_req_port_only = requested_port == 0 ? B_FALSE : B_TRUE;

	err = sctp_select_port(sctp, &requested_port, &user_specified);
	if (err != 0)
		goto done;

	if ((err = sctp_bind_add(sctp, sa, 1, B_TRUE,
	    user_specified == 1 ? htons(requested_port) : 0)) != 0) {
		goto done;
	}
	err = sctp_bindi(sctp, requested_port, bind_to_req_port_only,
	    user_specified, &allocated_port);
	if (err != 0) {
		sctp_free_saddrs(sctp);
	} else {
		ASSERT(sctp->sctp_state == SCTPS_BOUND);
	}
done:
	WAKE_SCTP(sctp);
	return (err);
}

/*
 * Perform bind/unbind operation of a list of addresses on a sctp_t
 */
int
sctp_bindx(sctp_t *sctp, const void *addrs, int addrcnt, int bindop)
{
	ASSERT(sctp != NULL);
	ASSERT(addrs != NULL);
	ASSERT(addrcnt > 0);

	switch (bindop) {
	case SCTP_BINDX_ADD_ADDR:
		return (sctp_bind_add(sctp, addrs, addrcnt, B_FALSE,
		    sctp->sctp_lport));
	case SCTP_BINDX_REM_ADDR:
		return (sctp_bind_del(sctp, addrs, addrcnt, B_FALSE));
	default:
		return (EINVAL);
	}
}

/*
 * Add a list of addresses to a sctp_t.
 */
int
sctp_bind_add(sctp_t *sctp, const void *addrs, uint32_t addrcnt,
    boolean_t caller_hold_lock, in_port_t port)
{
	int		err = 0;
	boolean_t	do_asconf = B_FALSE;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (!caller_hold_lock)
		RUN_SCTP(sctp);

	if (sctp->sctp_state > SCTPS_ESTABLISHED ||
	    (sctp->sctp_connp->conn_state_flags & CONN_CLOSING)) {
		if (!caller_hold_lock)
			WAKE_SCTP(sctp);
		return (EINVAL);
	}

	if (sctp->sctp_state > SCTPS_LISTEN) {
		/*
		 * Let's do some checking here rather than undoing the
		 * add later (for these reasons).
		 */
		if (!sctps->sctps_addip_enabled ||
		    !sctp->sctp_understands_asconf ||
		    !sctp->sctp_understands_addip) {
			if (!caller_hold_lock)
				WAKE_SCTP(sctp);
			return (EINVAL);
		}
		do_asconf = B_TRUE;
	}
	/*
	 * On a clustered node, for an inaddr_any bind, we will pass the list
	 * of all the addresses in the global list, minus any address on the
	 * loopback interface, and expect the clustering susbsystem to give us
	 * the correct list for the 'port'. For explicit binds we give the
	 * list of addresses  and the clustering module validates it for the
	 * 'port'.
	 *
	 * On a non-clustered node, cl_sctp_check_addrs will be NULL and
	 * we proceed as usual.
	 */
	if (cl_sctp_check_addrs != NULL) {
		uchar_t		*addrlist = NULL;
		size_t		size = 0;
		int		unspec = 0;
		boolean_t	do_listen;
		uchar_t		*llist = NULL;
		size_t		lsize = 0;

		/*
		 * If we are adding addresses after listening, but before
		 * an association is established, we need to update the
		 * clustering module with this info.
		 */
		do_listen = !do_asconf && sctp->sctp_state > SCTPS_BOUND &&
		    cl_sctp_listen != NULL;

		err = sctp_get_addrlist(sctp, addrs, &addrcnt, &addrlist,
		    &unspec, &size);
		if (err != 0) {
			ASSERT(addrlist == NULL);
			ASSERT(addrcnt == 0);
			ASSERT(size == 0);
			if (!caller_hold_lock)
				WAKE_SCTP(sctp);
			SCTP_KSTAT(sctps, sctp_cl_check_addrs);
			return (err);
		}
		ASSERT(addrlist != NULL);
		(*cl_sctp_check_addrs)(sctp->sctp_family, port, &addrlist,
		    size, &addrcnt, unspec == 1);
		if (addrcnt == 0) {
			/* We free the list */
			kmem_free(addrlist, size);
			if (!caller_hold_lock)
				WAKE_SCTP(sctp);
			return (EINVAL);
		}
		if (do_listen) {
			lsize = sizeof (in6_addr_t) * addrcnt;
			llist = kmem_alloc(lsize, KM_SLEEP);
		}
		err = sctp_valid_addr_list(sctp, addrlist, addrcnt, llist,
		    lsize);
		if (err == 0 && do_listen) {
			(*cl_sctp_listen)(sctp->sctp_family, llist,
			    addrcnt, sctp->sctp_lport);
			/* list will be freed by the clustering module */
		} else if (err != 0 && llist != NULL) {
			kmem_free(llist, lsize);
		}
		/* free the list we allocated */
		kmem_free(addrlist, size);
	} else {
		err = sctp_valid_addr_list(sctp, addrs, addrcnt, NULL, 0);
	}
	if (err != 0) {
		if (!caller_hold_lock)
			WAKE_SCTP(sctp);
		return (err);
	}
	/* Need to send  ASCONF messages */
	if (do_asconf) {
		err = sctp_add_ip(sctp, addrs, addrcnt);
		if (err != 0) {
			sctp_del_saddr_list(sctp, addrs, addrcnt, B_FALSE);
			if (!caller_hold_lock)
				WAKE_SCTP(sctp);
			return (err);
		}
	}
	if (!caller_hold_lock)
		WAKE_SCTP(sctp);
	if (do_asconf)
		sctp_process_sendq(sctp);
	return (0);
}

/*
 * Remove one or more addresses bound to the sctp_t.
 */
int
sctp_bind_del(sctp_t *sctp, const void *addrs, uint32_t addrcnt,
    boolean_t caller_hold_lock)
{
	int		error = 0;
	boolean_t	do_asconf = B_FALSE;
	uchar_t		*ulist = NULL;
	size_t		usize = 0;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (!caller_hold_lock)
		RUN_SCTP(sctp);

	if (sctp->sctp_state > SCTPS_ESTABLISHED ||
	    (sctp->sctp_connp->conn_state_flags & CONN_CLOSING)) {
		if (!caller_hold_lock)
			WAKE_SCTP(sctp);
		return (EINVAL);
	}
	/*
	 * Fail the remove if we are beyond listen, but can't send this
	 * to the peer.
	 */
	if (sctp->sctp_state > SCTPS_LISTEN) {
		if (!sctps->sctps_addip_enabled ||
		    !sctp->sctp_understands_asconf ||
		    !sctp->sctp_understands_addip) {
			if (!caller_hold_lock)
				WAKE_SCTP(sctp);
			return (EINVAL);
		}
		do_asconf = B_TRUE;
	}

	/* Can't delete the last address nor all of the addresses */
	if (sctp->sctp_nsaddrs == 1 || addrcnt >= sctp->sctp_nsaddrs) {
		if (!caller_hold_lock)
			WAKE_SCTP(sctp);
		return (EINVAL);
	}

	if (cl_sctp_unlisten != NULL && !do_asconf &&
	    sctp->sctp_state > SCTPS_BOUND) {
		usize = sizeof (in6_addr_t) * addrcnt;
		ulist = kmem_alloc(usize, KM_SLEEP);
	}

	error = sctp_del_ip(sctp, addrs, addrcnt, ulist, usize);
	if (error != 0) {
		if (ulist != NULL)
			kmem_free(ulist, usize);
		if (!caller_hold_lock)
			WAKE_SCTP(sctp);
		return (error);
	}
	/* ulist will be non-NULL only if cl_sctp_unlisten is non-NULL */
	if (ulist != NULL) {
		ASSERT(cl_sctp_unlisten != NULL);
		(*cl_sctp_unlisten)(sctp->sctp_family, ulist, addrcnt,
		    sctp->sctp_lport);
		/* ulist will be freed by the clustering module */
	}
	if (!caller_hold_lock)
		WAKE_SCTP(sctp);
	if (do_asconf)
		sctp_process_sendq(sctp);
	return (error);
}

/*
 * Returns 0 for success, errno value otherwise.
 *
 * If the "bind_to_req_port_only" parameter is set and the requested port
 * number is available, then set allocated_port to it.  If not available,
 * return an error.
 *
 * If the "bind_to_req_port_only" parameter is not set and the requested port
 * number is available, then set allocated_port to it.  If not available,
 * find the first anonymous port we can and set allocated_port to that.  If no
 * anonymous ports are available, return an error.
 *
 * In either case, when succeeding, update the sctp_t to record the port number
 * and insert it in the bind hash table.
 */
int
sctp_bindi(sctp_t *sctp, in_port_t port, boolean_t bind_to_req_port_only,
    int user_specified, in_port_t *allocated_port)
{
	/* number of times we have run around the loop */
	int count = 0;
	/* maximum number of times to run around the loop */
	int loopmax;
	zoneid_t zoneid = sctp->sctp_zoneid;
	zone_t *zone = crgetzone(sctp->sctp_credp);
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	/*
	 * Lookup for free addresses is done in a loop and "loopmax"
	 * influences how long we spin in the loop
	 */
	if (bind_to_req_port_only) {
		/*
		 * If the requested port is busy, don't bother to look
		 * for a new one. Setting loop maximum count to 1 has
		 * that effect.
		 */
		loopmax = 1;
	} else {
		/*
		 * If the requested port is busy, look for a free one
		 * in the anonymous port range.
		 * Set loopmax appropriately so that one does not look
		 * forever in the case all of the anonymous ports are in use.
		 */
		loopmax = (sctps->sctps_largest_anon_port -
		    sctps->sctps_smallest_anon_port + 1);
	}
	do {
		uint16_t	lport;
		sctp_tf_t	*tbf;
		sctp_t		*lsctp;
		int		addrcmp;

		lport = htons(port);

		/*
		 * Ensure that the sctp_t is not currently in the bind hash.
		 * Hold the lock on the hash bucket to ensure that
		 * the duplicate check plus the insertion is an atomic
		 * operation.
		 *
		 * This function does an inline lookup on the bind hash list
		 * Make sure that we access only members of sctp_t
		 * and that we don't look at sctp_sctp, since we are not
		 * doing a SCTPB_REFHOLD. For more details please see the notes
		 * in sctp_compress()
		 */
		sctp_bind_hash_remove(sctp);
		tbf = &sctps->sctps_bind_fanout[SCTP_BIND_HASH(port)];
		mutex_enter(&tbf->tf_lock);
		for (lsctp = tbf->tf_sctp; lsctp != NULL;
		    lsctp = lsctp->sctp_bind_hash) {

			if (lport != lsctp->sctp_lport ||
			    lsctp->sctp_state < SCTPS_BOUND)
				continue;

			/*
			 * On a labeled system, we must treat bindings to ports
			 * on shared IP addresses by sockets with MAC exemption
			 * privilege as being in all zones, as there's
			 * otherwise no way to identify the right receiver.
			 */
			if (lsctp->sctp_zoneid != zoneid &&
			    !lsctp->sctp_mac_exempt && !sctp->sctp_mac_exempt)
				continue;

			addrcmp = sctp_compare_saddrs(sctp, lsctp);
			if (addrcmp != SCTP_ADDR_DISJOINT) {
				if (!sctp->sctp_reuseaddr) {
					/* in use */
					break;
				} else if (lsctp->sctp_state == SCTPS_BOUND ||
				    lsctp->sctp_state == SCTPS_LISTEN) {
					/*
					 * socket option SO_REUSEADDR is set
					 * on the binding sctp_t.
					 *
					 * We have found a match of IP source
					 * address and source port, which is
					 * refused regardless of the
					 * SO_REUSEADDR setting, so we break.
					 */
					break;
				}
			}
		}
		if (lsctp != NULL) {
			/* The port number is busy */
			mutex_exit(&tbf->tf_lock);
		} else {
			conn_t *connp = sctp->sctp_connp;

			if (is_system_labeled()) {
				mlp_type_t addrtype, mlptype;

				/*
				 * On a labeled system we must check the type
				 * of the binding requested by the user (either
				 * MLP or SLP on shared and private addresses),
				 * and that the user's requested binding
				 * is permitted.
				 */
				addrtype = tsol_mlp_addr_type(zone->zone_id,
				    sctp->sctp_ipversion,
				    sctp->sctp_ipversion == IPV4_VERSION ?
				    (void *)&sctp->sctp_ipha->ipha_src :
				    (void *)&sctp->sctp_ip6h->ip6_src,
				    sctps->sctps_netstack->netstack_ip);

				/*
				 * tsol_mlp_addr_type returns the possibilities
				 * for the selected address.  Since all local
				 * addresses are either private or shared, the
				 * return value mlptSingle means "local address
				 * not valid (interface not present)."
				 */
				if (addrtype == mlptSingle) {
					mutex_exit(&tbf->tf_lock);
					return (EADDRNOTAVAIL);
				}
				mlptype = tsol_mlp_port_type(zone, IPPROTO_SCTP,
				    port, addrtype);
				if (mlptype != mlptSingle) {
					if (secpolicy_net_bindmlp(connp->
					    conn_cred) != 0) {
						mutex_exit(&tbf->tf_lock);
						return (EACCES);
					}
					/*
					 * If we're binding a shared MLP, then
					 * make sure that this zone is the one
					 * that owns that MLP.  Shared MLPs can
					 * be owned by at most one zone.
					 *
					 * No need to handle exclusive-stack
					 * zones since ALL_ZONES only applies
					 * to the shared stack.
					 */

					if (mlptype == mlptShared &&
					    addrtype == mlptShared &&
					    connp->conn_zoneid !=
					    tsol_mlp_findzone(IPPROTO_SCTP,
					    lport)) {
						mutex_exit(&tbf->tf_lock);
						return (EACCES);
					}
					connp->conn_mlp_type = mlptype;
				}
			}
			/*
			 * This port is ours. Insert in fanout and mark as
			 * bound to prevent others from getting the port
			 * number.
			 */
			sctp->sctp_state = SCTPS_BOUND;
			sctp->sctp_lport = lport;
			sctp->sctp_sctph->sh_sport = lport;

			ASSERT(&sctps->sctps_bind_fanout[
			    SCTP_BIND_HASH(port)] == tbf);
			sctp_bind_hash_insert(tbf, sctp, 1);

			mutex_exit(&tbf->tf_lock);

			/*
			 * We don't want sctp_next_port_to_try to "inherit"
			 * a port number supplied by the user in a bind.
			 *
			 * This is the only place where sctp_next_port_to_try
			 * is updated. After the update, it may or may not
			 * be in the valid range.
			 */
			if (user_specified == 0)
				sctps->sctps_next_port_to_try = port + 1;

			*allocated_port = port;

			return (0);
		}

		if ((count == 0) && (user_specified)) {
			/*
			 * We may have to return an anonymous port. So
			 * get one to start with.
			 */
			port = sctp_update_next_port(
			    sctps->sctps_next_port_to_try,
			    zone, sctps);
			user_specified = 0;
		} else {
			port = sctp_update_next_port(port + 1, zone, sctps);
		}
		if (port == 0)
			break;

		/*
		 * Don't let this loop run forever in the case where
		 * all of the anonymous ports are in use.
		 */
	} while (++count < loopmax);

	return (bind_to_req_port_only ? EADDRINUSE : EADDRNOTAVAIL);
}

/*
 * Don't let port fall into the privileged range.
 * Since the extra privileged ports can be arbitrary we also
 * ensure that we exclude those from consideration.
 * sctp_g_epriv_ports is not sorted thus we loop over it until
 * there are no changes.
 *
 * Note: No locks are held when inspecting sctp_g_*epriv_ports
 * but instead the code relies on:
 * - the fact that the address of the array and its size never changes
 * - the atomic assignment of the elements of the array
 */
in_port_t
sctp_update_next_port(in_port_t port, zone_t *zone, sctp_stack_t *sctps)
{
	int i;
	boolean_t restart = B_FALSE;

retry:
	if (port < sctps->sctps_smallest_anon_port)
		port = sctps->sctps_smallest_anon_port;

	if (port > sctps->sctps_largest_anon_port) {
		if (restart)
			return (0);
		restart = B_TRUE;
		port = sctps->sctps_smallest_anon_port;
	}

	if (port < sctps->sctps_smallest_nonpriv_port)
		port = sctps->sctps_smallest_nonpriv_port;

	for (i = 0; i < sctps->sctps_g_num_epriv_ports; i++) {
		if (port == sctps->sctps_g_epriv_ports[i]) {
			port++;
			/*
			 * Make sure whether the port is in the
			 * valid range.
			 *
			 * XXX Note that if sctp_g_epriv_ports contains
			 * all the anonymous ports this will be an
			 * infinite loop.
			 */
			goto retry;
		}
	}

	if (is_system_labeled() &&
	    (i = tsol_next_port(zone, port, IPPROTO_SCTP, B_TRUE)) != 0) {
		port = i;
		goto retry;
	}

	return (port);
}
