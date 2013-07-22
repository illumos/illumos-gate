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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/suntpi.h>
#include <sys/xti_inet.h>
#include <sys/policy.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>
#include <sys/tsol/tnet.h>

#include <rpc/pmap_prot.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/proto_set.h>
#include <inet/ipsec_impl.h>

/* Setable in /etc/system */
/* If set to 0, pick ephemeral port sequentially; otherwise randomly. */
static uint32_t tcp_random_anon_port = 1;

static int	tcp_bind_select_lport(tcp_t *, in_port_t *, boolean_t,
		    cred_t *cr);
static in_port_t	tcp_get_next_priv_port(const tcp_t *);

/*
 * Hash list insertion routine for tcp_t structures. Each hash bucket
 * contains a list of tcp_t entries, and each entry is bound to a unique
 * port. If there are multiple tcp_t's that are bound to the same port, then
 * one of them will be linked into the hash bucket list, and the rest will
 * hang off of that one entry. For each port, entries bound to a specific IP
 * address will be inserted before those those bound to INADDR_ANY.
 */
void
tcp_bind_hash_insert(tf_t *tbf, tcp_t *tcp, int caller_holds_lock)
{
	tcp_t	**tcpp;
	tcp_t	*tcpnext;
	tcp_t	*tcphash;
	conn_t	*connp = tcp->tcp_connp;
	conn_t	*connext;

	if (tcp->tcp_ptpbhn != NULL) {
		ASSERT(!caller_holds_lock);
		tcp_bind_hash_remove(tcp);
	}
	tcpp = &tbf->tf_tcp;
	if (!caller_holds_lock) {
		mutex_enter(&tbf->tf_lock);
	} else {
		ASSERT(MUTEX_HELD(&tbf->tf_lock));
	}
	tcphash = tcpp[0];
	tcpnext = NULL;
	if (tcphash != NULL) {
		/* Look for an entry using the same port */
		while ((tcphash = tcpp[0]) != NULL &&
		    connp->conn_lport != tcphash->tcp_connp->conn_lport)
			tcpp = &(tcphash->tcp_bind_hash);

		/* The port was not found, just add to the end */
		if (tcphash == NULL)
			goto insert;

		/*
		 * OK, there already exists an entry bound to the
		 * same port.
		 *
		 * If the new tcp bound to the INADDR_ANY address
		 * and the first one in the list is not bound to
		 * INADDR_ANY we skip all entries until we find the
		 * first one bound to INADDR_ANY.
		 * This makes sure that applications binding to a
		 * specific address get preference over those binding to
		 * INADDR_ANY.
		 */
		tcpnext = tcphash;
		connext = tcpnext->tcp_connp;
		tcphash = NULL;
		if (V6_OR_V4_INADDR_ANY(connp->conn_bound_addr_v6) &&
		    !V6_OR_V4_INADDR_ANY(connext->conn_bound_addr_v6)) {
			while ((tcpnext = tcpp[0]) != NULL) {
				connext = tcpnext->tcp_connp;
				if (!V6_OR_V4_INADDR_ANY(
				    connext->conn_bound_addr_v6))
					tcpp = &(tcpnext->tcp_bind_hash_port);
				else
					break;
			}
			if (tcpnext != NULL) {
				tcpnext->tcp_ptpbhn = &tcp->tcp_bind_hash_port;
				tcphash = tcpnext->tcp_bind_hash;
				if (tcphash != NULL) {
					tcphash->tcp_ptpbhn =
					    &(tcp->tcp_bind_hash);
					tcpnext->tcp_bind_hash = NULL;
				}
			}
		} else {
			tcpnext->tcp_ptpbhn = &tcp->tcp_bind_hash_port;
			tcphash = tcpnext->tcp_bind_hash;
			if (tcphash != NULL) {
				tcphash->tcp_ptpbhn =
				    &(tcp->tcp_bind_hash);
				tcpnext->tcp_bind_hash = NULL;
			}
		}
	}
insert:
	tcp->tcp_bind_hash_port = tcpnext;
	tcp->tcp_bind_hash = tcphash;
	tcp->tcp_ptpbhn = tcpp;
	tcpp[0] = tcp;
	if (!caller_holds_lock)
		mutex_exit(&tbf->tf_lock);
}

/*
 * Hash list removal routine for tcp_t structures.
 */
void
tcp_bind_hash_remove(tcp_t *tcp)
{
	tcp_t	*tcpnext;
	kmutex_t *lockp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;

	if (tcp->tcp_ptpbhn == NULL)
		return;

	/*
	 * Extract the lock pointer in case there are concurrent
	 * hash_remove's for this instance.
	 */
	ASSERT(connp->conn_lport != 0);
	lockp = &tcps->tcps_bind_fanout[TCP_BIND_HASH(
	    connp->conn_lport)].tf_lock;

	ASSERT(lockp != NULL);
	mutex_enter(lockp);
	if (tcp->tcp_ptpbhn) {
		tcpnext = tcp->tcp_bind_hash_port;
		if (tcpnext != NULL) {
			tcp->tcp_bind_hash_port = NULL;
			tcpnext->tcp_ptpbhn = tcp->tcp_ptpbhn;
			tcpnext->tcp_bind_hash = tcp->tcp_bind_hash;
			if (tcpnext->tcp_bind_hash != NULL) {
				tcpnext->tcp_bind_hash->tcp_ptpbhn =
				    &(tcpnext->tcp_bind_hash);
				tcp->tcp_bind_hash = NULL;
			}
		} else if ((tcpnext = tcp->tcp_bind_hash) != NULL) {
			tcpnext->tcp_ptpbhn = tcp->tcp_ptpbhn;
			tcp->tcp_bind_hash = NULL;
		}
		*tcp->tcp_ptpbhn = tcpnext;
		tcp->tcp_ptpbhn = NULL;
	}
	mutex_exit(lockp);
}

/*
 * Don't let port fall into the privileged range.
 * Since the extra privileged ports can be arbitrary we also
 * ensure that we exclude those from consideration.
 * tcp_g_epriv_ports is not sorted thus we loop over it until
 * there are no changes.
 *
 * Note: No locks are held when inspecting tcp_g_*epriv_ports
 * but instead the code relies on:
 * - the fact that the address of the array and its size never changes
 * - the atomic assignment of the elements of the array
 *
 * Returns 0 if there are no more ports available.
 *
 * TS note: skip multilevel ports.
 */
in_port_t
tcp_update_next_port(in_port_t port, const tcp_t *tcp, boolean_t random)
{
	int i, bump;
	boolean_t restart = B_FALSE;
	tcp_stack_t *tcps = tcp->tcp_tcps;

	if (random && tcp_random_anon_port != 0) {
		(void) random_get_pseudo_bytes((uint8_t *)&port,
		    sizeof (in_port_t));
		/*
		 * Unless changed by a sys admin, the smallest anon port
		 * is 32768 and the largest anon port is 65535.  It is
		 * very likely (50%) for the random port to be smaller
		 * than the smallest anon port.  When that happens,
		 * add port % (anon port range) to the smallest anon
		 * port to get the random port.  It should fall into the
		 * valid anon port range.
		 */
		if ((port < tcps->tcps_smallest_anon_port) ||
		    (port > tcps->tcps_largest_anon_port)) {
			if (tcps->tcps_smallest_anon_port ==
			    tcps->tcps_largest_anon_port) {
				bump = 0;
			} else {
				bump = port % (tcps->tcps_largest_anon_port -
				    tcps->tcps_smallest_anon_port);
			}
			port = tcps->tcps_smallest_anon_port + bump;
		}
	}

retry:
	if (port < tcps->tcps_smallest_anon_port)
		port = (in_port_t)tcps->tcps_smallest_anon_port;

	if (port > tcps->tcps_largest_anon_port) {
		if (restart)
			return (0);
		restart = B_TRUE;
		port = (in_port_t)tcps->tcps_smallest_anon_port;
	}

	if (port < tcps->tcps_smallest_nonpriv_port)
		port = (in_port_t)tcps->tcps_smallest_nonpriv_port;

	for (i = 0; i < tcps->tcps_g_num_epriv_ports; i++) {
		if (port == tcps->tcps_g_epriv_ports[i]) {
			port++;
			/*
			 * Make sure whether the port is in the
			 * valid range.
			 */
			goto retry;
		}
	}
	if (is_system_labeled() &&
	    (i = tsol_next_port(crgetzone(tcp->tcp_connp->conn_cred), port,
	    IPPROTO_TCP, B_TRUE)) != 0) {
		port = i;
		goto retry;
	}
	return (port);
}

/*
 * Return the next anonymous port in the privileged port range for
 * bind checking.  It starts at IPPORT_RESERVED - 1 and goes
 * downwards.  This is the same behavior as documented in the userland
 * library call rresvport(3N).
 *
 * TS note: skip multilevel ports.
 */
static in_port_t
tcp_get_next_priv_port(const tcp_t *tcp)
{
	static in_port_t next_priv_port = IPPORT_RESERVED - 1;
	in_port_t nextport;
	boolean_t restart = B_FALSE;
	tcp_stack_t *tcps = tcp->tcp_tcps;
retry:
	if (next_priv_port < tcps->tcps_min_anonpriv_port ||
	    next_priv_port >= IPPORT_RESERVED) {
		next_priv_port = IPPORT_RESERVED - 1;
		if (restart)
			return (0);
		restart = B_TRUE;
	}
	if (is_system_labeled() &&
	    (nextport = tsol_next_port(crgetzone(tcp->tcp_connp->conn_cred),
	    next_priv_port, IPPROTO_TCP, B_FALSE)) != 0) {
		next_priv_port = nextport;
		goto retry;
	}
	return (next_priv_port--);
}

static int
tcp_bind_select_lport(tcp_t *tcp, in_port_t *requested_port_ptr,
    boolean_t bind_to_req_port_only, cred_t *cr)
{
	in_port_t	mlp_port;
	mlp_type_t 	addrtype, mlptype;
	boolean_t	user_specified;
	in_port_t	allocated_port;
	in_port_t	requested_port = *requested_port_ptr;
	conn_t		*connp = tcp->tcp_connp;
	zone_t		*zone;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	in6_addr_t	v6addr = connp->conn_laddr_v6;

	/*
	 * XXX It's up to the caller to specify bind_to_req_port_only or not.
	 */
	ASSERT(cr != NULL);

	/*
	 * Get a valid port (within the anonymous range and should not
	 * be a privileged one) to use if the user has not given a port.
	 * If multiple threads are here, they may all start with
	 * with the same initial port. But, it should be fine as long as
	 * tcp_bindi will ensure that no two threads will be assigned
	 * the same port.
	 *
	 * NOTE: XXX If a privileged process asks for an anonymous port, we
	 * still check for ports only in the range > tcp_smallest_non_priv_port,
	 * unless TCP_ANONPRIVBIND option is set.
	 */
	mlptype = mlptSingle;
	mlp_port = requested_port;
	if (requested_port == 0) {
		requested_port = connp->conn_anon_priv_bind ?
		    tcp_get_next_priv_port(tcp) :
		    tcp_update_next_port(tcps->tcps_next_port_to_try,
		    tcp, B_TRUE);
		if (requested_port == 0) {
			return (-TNOADDR);
		}
		user_specified = B_FALSE;

		/*
		 * If the user went through one of the RPC interfaces to create
		 * this socket and RPC is MLP in this zone, then give him an
		 * anonymous MLP.
		 */
		if (connp->conn_anon_mlp && is_system_labeled()) {
			zone = crgetzone(cr);
			addrtype = tsol_mlp_addr_type(
			    connp->conn_allzones ? ALL_ZONES : zone->zone_id,
			    IPV6_VERSION, &v6addr,
			    tcps->tcps_netstack->netstack_ip);
			if (addrtype == mlptSingle) {
				return (-TNOADDR);
			}
			mlptype = tsol_mlp_port_type(zone, IPPROTO_TCP,
			    PMAPPORT, addrtype);
			mlp_port = PMAPPORT;
		}
	} else {
		int i;
		boolean_t priv = B_FALSE;

		/*
		 * If the requested_port is in the well-known privileged range,
		 * verify that the stream was opened by a privileged user.
		 * Note: No locks are held when inspecting tcp_g_*epriv_ports
		 * but instead the code relies on:
		 * - the fact that the address of the array and its size never
		 *   changes
		 * - the atomic assignment of the elements of the array
		 */
		if (requested_port < tcps->tcps_smallest_nonpriv_port) {
			priv = B_TRUE;
		} else {
			for (i = 0; i < tcps->tcps_g_num_epriv_ports; i++) {
				if (requested_port ==
				    tcps->tcps_g_epriv_ports[i]) {
					priv = B_TRUE;
					break;
				}
			}
		}
		if (priv) {
			if (secpolicy_net_privaddr(cr, requested_port,
			    IPPROTO_TCP) != 0) {
				if (connp->conn_debug) {
					(void) strlog(TCP_MOD_ID, 0, 1,
					    SL_ERROR|SL_TRACE,
					    "tcp_bind: no priv for port %d",
					    requested_port);
				}
				return (-TACCES);
			}
		}
		user_specified = B_TRUE;

		connp = tcp->tcp_connp;
		if (is_system_labeled()) {
			zone = crgetzone(cr);
			addrtype = tsol_mlp_addr_type(
			    connp->conn_allzones ? ALL_ZONES : zone->zone_id,
			    IPV6_VERSION, &v6addr,
			    tcps->tcps_netstack->netstack_ip);
			if (addrtype == mlptSingle) {
				return (-TNOADDR);
			}
			mlptype = tsol_mlp_port_type(zone, IPPROTO_TCP,
			    requested_port, addrtype);
		}
	}

	if (mlptype != mlptSingle) {
		if (secpolicy_net_bindmlp(cr) != 0) {
			if (connp->conn_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_bind: no priv for multilevel port %d",
				    requested_port);
			}
			return (-TACCES);
		}

		/*
		 * If we're specifically binding a shared IP address and the
		 * port is MLP on shared addresses, then check to see if this
		 * zone actually owns the MLP.  Reject if not.
		 */
		if (mlptype == mlptShared && addrtype == mlptShared) {
			/*
			 * No need to handle exclusive-stack zones since
			 * ALL_ZONES only applies to the shared stack.
			 */
			zoneid_t mlpzone;

			mlpzone = tsol_mlp_findzone(IPPROTO_TCP,
			    htons(mlp_port));
			if (connp->conn_zoneid != mlpzone) {
				if (connp->conn_debug) {
					(void) strlog(TCP_MOD_ID, 0, 1,
					    SL_ERROR|SL_TRACE,
					    "tcp_bind: attempt to bind port "
					    "%d on shared addr in zone %d "
					    "(should be %d)",
					    mlp_port, connp->conn_zoneid,
					    mlpzone);
				}
				return (-TACCES);
			}
		}

		if (!user_specified) {
			int err;
			err = tsol_mlp_anon(zone, mlptype, connp->conn_proto,
			    requested_port, B_TRUE);
			if (err != 0) {
				if (connp->conn_debug) {
					(void) strlog(TCP_MOD_ID, 0, 1,
					    SL_ERROR|SL_TRACE,
					    "tcp_bind: cannot establish anon "
					    "MLP for port %d",
					    requested_port);
				}
				return (err);
			}
			connp->conn_anon_port = B_TRUE;
		}
		connp->conn_mlp_type = mlptype;
	}

	allocated_port = tcp_bindi(tcp, requested_port, &v6addr,
	    connp->conn_reuseaddr, B_FALSE, bind_to_req_port_only,
	    user_specified);

	if (allocated_port == 0) {
		connp->conn_mlp_type = mlptSingle;
		if (connp->conn_anon_port) {
			connp->conn_anon_port = B_FALSE;
			(void) tsol_mlp_anon(zone, mlptype, connp->conn_proto,
			    requested_port, B_FALSE);
		}
		if (bind_to_req_port_only) {
			if (connp->conn_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_bind: requested addr busy");
			}
			return (-TADDRBUSY);
		} else {
			/* If we are out of ports, fail the bind. */
			if (connp->conn_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_bind: out of ports?");
			}
			return (-TNOADDR);
		}
	}

	/* Pass the allocated port back */
	*requested_port_ptr = allocated_port;
	return (0);
}

/*
 * Check the address and check/pick a local port number.
 */
int
tcp_bind_check(conn_t *connp, struct sockaddr *sa, socklen_t len, cred_t *cr,
    boolean_t bind_to_req_port_only)
{
	tcp_t	*tcp = connp->conn_tcp;
	sin_t	*sin;
	sin6_t  *sin6;
	in_port_t	requested_port;
	ipaddr_t	v4addr;
	in6_addr_t	v6addr;
	ip_laddr_t	laddr_type = IPVL_UNICAST_UP;	/* INADDR_ANY */
	zoneid_t	zoneid = IPCL_ZONEID(connp);
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;
	uint_t		scopeid = 0;
	int		error = 0;
	ip_xmit_attr_t	*ixa = connp->conn_ixa;

	ASSERT((uintptr_t)len <= (uintptr_t)INT_MAX);

	if (tcp->tcp_state == TCPS_BOUND) {
		return (0);
	} else if (tcp->tcp_state > TCPS_BOUND) {
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_bind: bad state, %d", tcp->tcp_state);
		}
		return (-TOUTSTATE);
	}

	ASSERT(sa != NULL && len != 0);

	if (!OK_32PTR((char *)sa)) {
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1,
			    SL_ERROR|SL_TRACE,
			    "tcp_bind: bad address parameter, "
			    "address %p, len %d",
			    (void *)sa, len);
		}
		return (-TPROTO);
	}

	error = proto_verify_ip_addr(connp->conn_family, sa, len);
	if (error != 0) {
		return (error);
	}

	switch (len) {
	case sizeof (sin_t):	/* Complete IPv4 address */
		sin = (sin_t *)sa;
		requested_port = ntohs(sin->sin_port);
		v4addr = sin->sin_addr.s_addr;
		IN6_IPADDR_TO_V4MAPPED(v4addr, &v6addr);
		if (v4addr != INADDR_ANY) {
			laddr_type = ip_laddr_verify_v4(v4addr, zoneid, ipst,
			    B_FALSE);
		}
		break;

	case sizeof (sin6_t): /* Complete IPv6 address */
		sin6 = (sin6_t *)sa;
		v6addr = sin6->sin6_addr;
		requested_port = ntohs(sin6->sin6_port);
		if (IN6_IS_ADDR_V4MAPPED(&v6addr)) {
			if (connp->conn_ipv6_v6only)
				return (EADDRNOTAVAIL);

			IN6_V4MAPPED_TO_IPADDR(&v6addr, v4addr);
			if (v4addr != INADDR_ANY) {
				laddr_type = ip_laddr_verify_v4(v4addr,
				    zoneid, ipst, B_FALSE);
			}
		} else {
			if (!IN6_IS_ADDR_UNSPECIFIED(&v6addr)) {
				if (IN6_IS_ADDR_LINKSCOPE(&v6addr))
					scopeid = sin6->sin6_scope_id;
				laddr_type = ip_laddr_verify_v6(&v6addr,
				    zoneid, ipst, B_FALSE, scopeid);
			}
		}
		break;

	default:
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_bind: bad address length, %d", len);
		}
		return (EAFNOSUPPORT);
		/* return (-TBADADDR); */
	}

	/* Is the local address a valid unicast address? */
	if (laddr_type == IPVL_BAD)
		return (EADDRNOTAVAIL);

	connp->conn_bound_addr_v6 = v6addr;
	if (scopeid != 0) {
		ixa->ixa_flags |= IXAF_SCOPEID_SET;
		ixa->ixa_scopeid = scopeid;
		connp->conn_incoming_ifindex = scopeid;
	} else {
		ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
		connp->conn_incoming_ifindex = connp->conn_bound_if;
	}

	connp->conn_laddr_v6 = v6addr;
	connp->conn_saddr_v6 = v6addr;

	bind_to_req_port_only = requested_port != 0 && bind_to_req_port_only;

	error = tcp_bind_select_lport(tcp, &requested_port,
	    bind_to_req_port_only, cr);
	if (error != 0) {
		connp->conn_laddr_v6 = ipv6_all_zeros;
		connp->conn_saddr_v6 = ipv6_all_zeros;
		connp->conn_bound_addr_v6 = ipv6_all_zeros;
	}
	return (error);
}

/*
 * If the "bind_to_req_port_only" parameter is set, if the requested port
 * number is available, return it, If not return 0
 *
 * If "bind_to_req_port_only" parameter is not set and
 * If the requested port number is available, return it.  If not, return
 * the first anonymous port we happen across.  If no anonymous ports are
 * available, return 0. addr is the requested local address, if any.
 *
 * In either case, when succeeding update the tcp_t to record the port number
 * and insert it in the bind hash table.
 *
 * Note that TCP over IPv4 and IPv6 sockets can use the same port number
 * without setting SO_REUSEADDR. This is needed so that they
 * can be viewed as two independent transport protocols.
 */
in_port_t
tcp_bindi(tcp_t *tcp, in_port_t port, const in6_addr_t *laddr,
    int reuseaddr, boolean_t quick_connect,
    boolean_t bind_to_req_port_only, boolean_t user_specified)
{
	/* number of times we have run around the loop */
	int count = 0;
	/* maximum number of times to run around the loop */
	int loopmax;
	conn_t *connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

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
		if (connp->conn_anon_priv_bind) {
			/*
			 * loopmax =
			 * 	(IPPORT_RESERVED-1) - tcp_min_anonpriv_port + 1
			 */
			loopmax = IPPORT_RESERVED -
			    tcps->tcps_min_anonpriv_port;
		} else {
			loopmax = (tcps->tcps_largest_anon_port -
			    tcps->tcps_smallest_anon_port + 1);
		}
	}
	do {
		uint16_t	lport;
		tf_t		*tbf;
		tcp_t		*ltcp;
		conn_t		*lconnp;

		lport = htons(port);

		/*
		 * Ensure that the tcp_t is not currently in the bind hash.
		 * Hold the lock on the hash bucket to ensure that
		 * the duplicate check plus the insertion is an atomic
		 * operation.
		 *
		 * This function does an inline lookup on the bind hash list
		 * Make sure that we access only members of tcp_t
		 * and that we don't look at tcp_tcp, since we are not
		 * doing a CONN_INC_REF.
		 */
		tcp_bind_hash_remove(tcp);
		tbf = &tcps->tcps_bind_fanout[TCP_BIND_HASH(lport)];
		mutex_enter(&tbf->tf_lock);
		for (ltcp = tbf->tf_tcp; ltcp != NULL;
		    ltcp = ltcp->tcp_bind_hash) {
			if (lport == ltcp->tcp_connp->conn_lport)
				break;
		}

		for (; ltcp != NULL; ltcp = ltcp->tcp_bind_hash_port) {
			boolean_t not_socket;
			boolean_t exclbind;

			lconnp = ltcp->tcp_connp;

			/*
			 * On a labeled system, we must treat bindings to ports
			 * on shared IP addresses by sockets with MAC exemption
			 * privilege as being in all zones, as there's
			 * otherwise no way to identify the right receiver.
			 */
			if (!IPCL_BIND_ZONE_MATCH(lconnp, connp))
				continue;

			/*
			 * If TCP_EXCLBIND is set for either the bound or
			 * binding endpoint, the semantics of bind
			 * is changed according to the following.
			 *
			 * spec = specified address (v4 or v6)
			 * unspec = unspecified address (v4 or v6)
			 * A = specified addresses are different for endpoints
			 *
			 * bound	bind to		allowed
			 * -------------------------------------
			 * unspec	unspec		no
			 * unspec	spec		no
			 * spec		unspec		no
			 * spec		spec		yes if A
			 *
			 * For labeled systems, SO_MAC_EXEMPT behaves the same
			 * as TCP_EXCLBIND, except that zoneid is ignored.
			 *
			 * Note:
			 *
			 * 1. Because of TLI semantics, an endpoint can go
			 * back from, say TCP_ESTABLISHED to TCPS_LISTEN or
			 * TCPS_BOUND, depending on whether it is originally
			 * a listener or not.  That is why we need to check
			 * for states greater than or equal to TCPS_BOUND
			 * here.
			 *
			 * 2. Ideally, we should only check for state equals
			 * to TCPS_LISTEN. And the following check should be
			 * added.
			 *
			 * if (ltcp->tcp_state == TCPS_LISTEN ||
			 *	!reuseaddr || !lconnp->conn_reuseaddr) {
			 *		...
			 * }
			 *
			 * The semantics will be changed to this.  If the
			 * endpoint on the list is in state not equal to
			 * TCPS_LISTEN and both endpoints have SO_REUSEADDR
			 * set, let the bind succeed.
			 *
			 * Because of (1), we cannot do that for TLI
			 * endpoints.  But we can do that for socket endpoints.
			 * If in future, we can change this going back
			 * semantics, we can use the above check for TLI also.
			 */
			not_socket = !(TCP_IS_SOCKET(ltcp) &&
			    TCP_IS_SOCKET(tcp));
			exclbind = lconnp->conn_exclbind ||
			    connp->conn_exclbind;

			if ((lconnp->conn_mac_mode != CONN_MAC_DEFAULT) ||
			    (connp->conn_mac_mode != CONN_MAC_DEFAULT) ||
			    (exclbind && (not_socket ||
			    ltcp->tcp_state <= TCPS_ESTABLISHED))) {
				if (V6_OR_V4_INADDR_ANY(
				    lconnp->conn_bound_addr_v6) ||
				    V6_OR_V4_INADDR_ANY(*laddr) ||
				    IN6_ARE_ADDR_EQUAL(laddr,
				    &lconnp->conn_bound_addr_v6)) {
					break;
				}
				continue;
			}

			/*
			 * Check ipversion to allow IPv4 and IPv6 sockets to
			 * have disjoint port number spaces, if *_EXCLBIND
			 * is not set and only if the application binds to a
			 * specific port. We use the same autoassigned port
			 * number space for IPv4 and IPv6 sockets.
			 */
			if (connp->conn_ipversion != lconnp->conn_ipversion &&
			    bind_to_req_port_only)
				continue;

			/*
			 * Ideally, we should make sure that the source
			 * address, remote address, and remote port in the
			 * four tuple for this tcp-connection is unique.
			 * However, trying to find out the local source
			 * address would require too much code duplication
			 * with IP, since IP needs needs to have that code
			 * to support userland TCP implementations.
			 */
			if (quick_connect &&
			    (ltcp->tcp_state > TCPS_LISTEN) &&
			    ((connp->conn_fport != lconnp->conn_fport) ||
			    !IN6_ARE_ADDR_EQUAL(&connp->conn_faddr_v6,
			    &lconnp->conn_faddr_v6)))
				continue;

			if (!reuseaddr) {
				/*
				 * No socket option SO_REUSEADDR.
				 * If existing port is bound to
				 * a non-wildcard IP address
				 * and the requesting stream is
				 * bound to a distinct
				 * different IP addresses
				 * (non-wildcard, also), keep
				 * going.
				 */
				if (!V6_OR_V4_INADDR_ANY(*laddr) &&
				    !V6_OR_V4_INADDR_ANY(
				    lconnp->conn_bound_addr_v6) &&
				    !IN6_ARE_ADDR_EQUAL(laddr,
				    &lconnp->conn_bound_addr_v6))
					continue;
				if (ltcp->tcp_state >= TCPS_BOUND) {
					/*
					 * This port is being used and
					 * its state is >= TCPS_BOUND,
					 * so we can't bind to it.
					 */
					break;
				}
			} else {
				/*
				 * socket option SO_REUSEADDR is set on the
				 * binding tcp_t.
				 *
				 * If two streams are bound to
				 * same IP address or both addr
				 * and bound source are wildcards
				 * (INADDR_ANY), we want to stop
				 * searching.
				 * We have found a match of IP source
				 * address and source port, which is
				 * refused regardless of the
				 * SO_REUSEADDR setting, so we break.
				 */
				if (IN6_ARE_ADDR_EQUAL(laddr,
				    &lconnp->conn_bound_addr_v6) &&
				    (ltcp->tcp_state == TCPS_LISTEN ||
				    ltcp->tcp_state == TCPS_BOUND))
					break;
			}
		}
		if (ltcp != NULL) {
			/* The port number is busy */
			mutex_exit(&tbf->tf_lock);
		} else {
			/*
			 * This port is ours. Insert in fanout and mark as
			 * bound to prevent others from getting the port
			 * number.
			 */
			tcp->tcp_state = TCPS_BOUND;
			DTRACE_TCP6(state__change, void, NULL,
			    ip_xmit_attr_t *, connp->conn_ixa,
			    void, NULL, tcp_t *, tcp, void, NULL,
			    int32_t, TCPS_IDLE);

			connp->conn_lport = htons(port);

			ASSERT(&tcps->tcps_bind_fanout[TCP_BIND_HASH(
			    connp->conn_lport)] == tbf);
			tcp_bind_hash_insert(tbf, tcp, 1);

			mutex_exit(&tbf->tf_lock);

			/*
			 * We don't want tcp_next_port_to_try to "inherit"
			 * a port number supplied by the user in a bind.
			 */
			if (user_specified)
				return (port);

			/*
			 * This is the only place where tcp_next_port_to_try
			 * is updated. After the update, it may or may not
			 * be in the valid range.
			 */
			if (!connp->conn_anon_priv_bind)
				tcps->tcps_next_port_to_try = port + 1;
			return (port);
		}

		if (connp->conn_anon_priv_bind) {
			port = tcp_get_next_priv_port(tcp);
		} else {
			if (count == 0 && user_specified) {
				/*
				 * We may have to return an anonymous port. So
				 * get one to start with.
				 */
				port =
				    tcp_update_next_port(
				    tcps->tcps_next_port_to_try,
				    tcp, B_TRUE);
				user_specified = B_FALSE;
			} else {
				port = tcp_update_next_port(port + 1, tcp,
				    B_FALSE);
			}
		}
		if (port == 0)
			break;

		/*
		 * Don't let this loop run forever in the case where
		 * all of the anonymous ports are in use.
		 */
	} while (++count < loopmax);
	return (0);
}
