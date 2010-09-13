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

/* This file contains Solaris Cluster related TCP hooks and functions. */

#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/tcp_cluster.h>

static int cl_tcp_walk_list_stack(int (*callback)(cl_tcp_info_t *, void *),
    void *arg, tcp_stack_t *tcps);

/*
 * Hook functions to enable cluster networking
 * On non-clustered systems these vectors must always be NULL.
 */
void (*cl_inet_listen)(netstackid_t stack_id, uint8_t protocol,
			    sa_family_t addr_family, uint8_t *laddrp,
			    in_port_t lport, void *args) = NULL;
void (*cl_inet_unlisten)(netstackid_t stack_id, uint8_t protocol,
			    sa_family_t addr_family, uint8_t *laddrp,
			    in_port_t lport, void *args) = NULL;

int (*cl_inet_connect2)(netstackid_t stack_id, uint8_t protocol,
			    boolean_t is_outgoing,
			    sa_family_t addr_family,
			    uint8_t *laddrp, in_port_t lport,
			    uint8_t *faddrp, in_port_t fport,
			    void *args) = NULL;
void (*cl_inet_disconnect)(netstackid_t stack_id, uint8_t protocol,
			    sa_family_t addr_family, uint8_t *laddrp,
			    in_port_t lport, uint8_t *faddrp,
			    in_port_t fport, void *args) = NULL;

/*
 * Exported routine for extracting active tcp connection status.
 *
 * This is used by the Solaris Cluster Networking software to
 * gather a list of connections that need to be forwarded to
 * specific nodes in the cluster when configuration changes occur.
 *
 * The callback is invoked for each tcp_t structure from all netstacks,
 * if 'stack_id' is less than 0. Otherwise, only for tcp_t structures
 * from the netstack with the specified stack_id. Returning
 * non-zero from the callback routine terminates the search.
 */
int
cl_tcp_walk_list(netstackid_t stack_id,
    int (*cl_callback)(cl_tcp_info_t *, void *), void *arg)
{
	netstack_handle_t nh;
	netstack_t *ns;
	int ret = 0;

	if (stack_id >= 0) {
		if ((ns = netstack_find_by_stackid(stack_id)) == NULL)
			return (EINVAL);

		ret = cl_tcp_walk_list_stack(cl_callback, arg,
		    ns->netstack_tcp);
		netstack_rele(ns);
		return (ret);
	}

	netstack_next_init(&nh);
	while ((ns = netstack_next(&nh)) != NULL) {
		ret = cl_tcp_walk_list_stack(cl_callback, arg,
		    ns->netstack_tcp);
		netstack_rele(ns);
	}
	netstack_next_fini(&nh);
	return (ret);
}

static int
cl_tcp_walk_list_stack(int (*callback)(cl_tcp_info_t *, void *), void *arg,
    tcp_stack_t *tcps)
{
	tcp_t *tcp;
	cl_tcp_info_t	cl_tcpi;
	connf_t	*connfp;
	conn_t	*connp;
	int	i;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	ASSERT(callback != NULL);

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		connfp = &ipst->ips_ipcl_globalhash_fanout[i];
		connp = NULL;

		while ((connp =
		    ipcl_get_next_conn(connfp, connp, IPCL_TCPCONN)) != NULL) {

			tcp = connp->conn_tcp;
			cl_tcpi.cl_tcpi_version = CL_TCPI_V1;
			cl_tcpi.cl_tcpi_ipversion = connp->conn_ipversion;
			cl_tcpi.cl_tcpi_state = tcp->tcp_state;
			cl_tcpi.cl_tcpi_lport = connp->conn_lport;
			cl_tcpi.cl_tcpi_fport = connp->conn_fport;
			cl_tcpi.cl_tcpi_laddr_v6 = connp->conn_laddr_v6;
			cl_tcpi.cl_tcpi_faddr_v6 = connp->conn_faddr_v6;

			/*
			 * If the callback returns non-zero
			 * we terminate the traversal.
			 */
			if ((*callback)(&cl_tcpi, arg) != 0) {
				CONN_DEC_REF(tcp->tcp_connp);
				return (1);
			}
		}
	}

	return (0);
}
