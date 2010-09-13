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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_TCP_CLUSTER_H
#define	_INET_TCP_CLUSTER_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Cluster hooks defined in tcp_cluster.c.
 */
extern void (*cl_inet_listen)(netstackid_t, uint8_t, sa_family_t, uint8_t *,
    in_port_t, void *);
extern void (*cl_inet_unlisten)(netstackid_t, uint8_t, sa_family_t, uint8_t *,
    in_port_t, void *);
extern int (*cl_inet_connect2)(netstackid_t, uint8_t, boolean_t, sa_family_t,
    uint8_t *, in_port_t, uint8_t *, in_port_t, void *);
extern void (*cl_inet_disconnect)(netstackid_t, uint8_t, sa_family_t,
    uint8_t *, in_port_t, uint8_t *, in_port_t, void *);


/*
 * Cluster networking hook for traversing current connection list.
 * This routine is used to extract the current list of live connections
 * which must continue to to be dispatched to this node.
 */
extern int cl_tcp_walk_list(netstackid_t,
    int (*callback)(cl_tcp_info_t *, void *), void *);

/*
 * int CL_INET_CONNECT(conn_t *cp, tcp_t *tcp, boolean_t is_outgoing, int err)
 */
#define	CL_INET_CONNECT(connp, is_outgoing, err) {		\
	(err) = 0;						\
	if (cl_inet_connect2 != NULL) {				\
		/*						\
		 * Running in cluster mode - register active connection	\
		 * information						\
		 */							\
		if ((connp)->conn_ipversion == IPV4_VERSION) {		\
			if ((connp)->conn_laddr_v4 != 0) {		\
				(err) = (*cl_inet_connect2)(		\
				    (connp)->conn_netstack->netstack_stackid,\
				    IPPROTO_TCP, is_outgoing, AF_INET,	\
				    (uint8_t *)(&((connp)->conn_laddr_v4)),\
				    (in_port_t)(connp)->conn_lport,	\
				    (uint8_t *)(&((connp)->conn_faddr_v4)),\
				    (in_port_t)(connp)->conn_fport, NULL); \
			}						\
		} else {						\
			if (!IN6_IS_ADDR_UNSPECIFIED(			\
			    &(connp)->conn_laddr_v6)) {			\
				(err) = (*cl_inet_connect2)(		\
				    (connp)->conn_netstack->netstack_stackid,\
				    IPPROTO_TCP, is_outgoing, AF_INET6,	\
				    (uint8_t *)(&((connp)->conn_laddr_v6)),\
				    (in_port_t)(connp)->conn_lport,	\
				    (uint8_t *)(&((connp)->conn_faddr_v6)), \
				    (in_port_t)(connp)->conn_fport, NULL); \
			}						\
		}							\
	}								\
}

#define	CL_INET_DISCONNECT(connp)	{				\
	if (cl_inet_disconnect != NULL) {				\
		/*							\
		 * Running in cluster mode - deregister active		\
		 * connection information				\
		 */							\
		if ((connp)->conn_ipversion == IPV4_VERSION) {		\
			if ((connp)->conn_laddr_v4 != 0) {		\
				(*cl_inet_disconnect)(			\
				    (connp)->conn_netstack->netstack_stackid,\
				    IPPROTO_TCP, AF_INET,		\
				    (uint8_t *)(&((connp)->conn_laddr_v4)),\
				    (in_port_t)(connp)->conn_lport,	\
				    (uint8_t *)(&((connp)->conn_faddr_v4)),\
				    (in_port_t)(connp)->conn_fport, NULL); \
			}						\
		} else {						\
			if (!IN6_IS_ADDR_UNSPECIFIED(			\
			    &(connp)->conn_laddr_v6)) {			\
				(*cl_inet_disconnect)(			\
				    (connp)->conn_netstack->netstack_stackid,\
				    IPPROTO_TCP, AF_INET6,		\
				    (uint8_t *)(&((connp)->conn_laddr_v6)),\
				    (in_port_t)(connp)->conn_lport,	\
				    (uint8_t *)(&((connp)->conn_faddr_v6)), \
				    (in_port_t)(connp)->conn_fport, NULL); \
			}						\
		}							\
	}								\
}

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TCP_CLUSTER_H */
