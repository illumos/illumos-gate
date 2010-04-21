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
 */

/*
 * Copyright (c) 2009 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <sys/ib/clients/of/rdma/ib_verbs.h>
#include <sys/ib/clients/of/rdma/ib_addr.h>
#include <sys/ib/clients/of/rdma/rdma_cm.h>

#include <sys/ib/clients/rdsv3/ib.h>
#include <sys/ib/clients/rdsv3/rdma_transport.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

kmutex_t rdsv3_rdma_listen_id_lock;
struct rdma_cm_id *rdsv3_rdma_listen_id = NULL;

int
rdsv3_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
    struct rdma_cm_event *event)
{
	/* this can be null in the listening path */
	struct rdsv3_connection *conn = cm_id->context;
	struct rdsv3_transport *trans;
	int ret = 0;

	RDSV3_DPRINTF2("rdsv3_rdma_cm_event_handler",
	    "conn %p id %p handling event %u", conn, cm_id, event->event);

	trans = &rdsv3_ib_transport;

	/*
	 * Prevent shutdown from tearing down the connection
	 * while we're executing.
	 */
	if (conn) {
		mutex_enter(&conn->c_cm_lock);

		/*
		 * If the connection is being shut down, bail out
		 * right away. We return 0 so cm_id doesn't get
		 * destroyed prematurely
		 */
		if (rdsv3_conn_state(conn) == RDSV3_CONN_DISCONNECTING) {
			/*
			 * Reject incoming connections while we're tearing
			 * down an existing one.
			 */
			if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST)
				ret = 1;
			RDSV3_DPRINTF2("rdsv3_rdma_cm_event_handler",
			    "conn %p id %p incoming event %u when "
			    "disconnecting", conn, cm_id, event->event);
			goto out;
		}
	}

	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		ret = trans->cm_handle_connect(cm_id, event);
		break;

	case RDMA_CM_EVENT_ADDR_RESOLVED:
		/* XXX do we need to clean up if this fails? */
		ret = rdma_resolve_route(cm_id,
		    RDSV3_RDMA_RESOLVE_TIMEOUT_MS);
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		/* XXX worry about racing with listen acceptance */
		ret = trans->cm_initiate_connect(cm_id);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		trans->cm_connect_complete(conn, event);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
	case RDMA_CM_EVENT_ADDR_CHANGE:
		if (conn)
			rdsv3_conn_drop(conn);
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		RDSV3_DPRINTF2("rdsv3_rdma_cm_event_handler",
		    "RDS/RDMA: DISCONNECT event - dropping connection "
		    "cm_id: %p", cm_id);
		if (conn) {
			RDSV3_DPRINTF0("rdsv3_rdma_cm_event_handler",
			    "RDS/RDMA: DISCONNECT event - dropping connection "
			    "%u.%u.%u.%u ->%u.%u.%u.%u", NIPQUAD(conn->c_laddr),
			    NIPQUAD(conn->c_faddr));
			rdsv3_conn_drop(conn);
		}
		break;

	default:
		/* things like device disconnect? */
		RDSV3_DPRINTF0("rdsv3_rdma_cm_event_handler",
		    "unknown event %u\n", event->event);
		RDSV3_PANIC();
		break;
	}

out:
	if (conn) {
#ifndef __lock_lint
		// struct rds_iw_connection *ic = conn->c_transport_data;

		/* If we return non-zero, we must to hang on to the cm_id */
		// BUG_ON(ic->i_cm_id == cm_id && ret);
#endif

		mutex_exit(&conn->c_cm_lock);
	}

	RDSV3_DPRINTF2("rdsv3_rdma_cm_event_handler",
	    "id %p event %u handling ret %d", cm_id, event->event, ret);

	return (ret);
}

static int
rdsv3_rdma_listen_init(void)
{
	struct sockaddr_in sin;
	struct rdma_cm_id *cm_id;
	int ret;

	RDSV3_DPRINTF2("rdsv3_rdma_listen_init", "Enter");

	cm_id = rdma_create_id(rdsv3_rdma_cm_event_handler, NULL, RDMA_PS_TCP);
	if (IS_ERR(cm_id)) {
		ret = PTR_ERR(cm_id);
		RDSV3_DPRINTF0("rdsv3_rdma_listen_init",
		    "RDS/RDMA: failed to setup listener, "
		    "rdma_create_id() returned %d", ret);
		goto out;
	}

	sin.sin_family = PF_INET;
	sin.sin_addr.s_addr = (uint32_t)htonl(INADDR_ANY);
	sin.sin_port = (uint16_t)htons(RDSV3_PORT);

	/*
	 * XXX I bet this binds the cm_id to a device.  If we want to support
	 * fail-over we'll have to take this into consideration.
	 */
	ret = rdma_bind_addr(cm_id, (struct sockaddr *)&sin);
	if (ret) {
		RDSV3_DPRINTF0("rdsv3_rdma_listen_init",
		    "RDS/RDMA: failed to setup listener, "
		    "rdma_bind_addr() returned %d", ret);
		goto out;
	}

	ret = rdma_listen(cm_id, 128);
	if (ret) {
		RDSV3_DPRINTF0("rdsv3_rdma_listen_init",
		    "RDS/RDMA: failed to setup listener, "
		    "rdma_listen() returned %d", ret);
		goto out;
	}

	RDSV3_DPRINTF5("rdsv3_rdma_listen_init",
	    "cm %p listening on port %u", cm_id, RDSV3_PORT);

	rdsv3_rdma_listen_id = cm_id;
	cm_id = NULL;

	RDSV3_DPRINTF2("rdsv3_rdma_listen_init",
	    "Return: rdsv3_rdma_listen_id: %p", rdsv3_rdma_listen_id);
out:
	if (cm_id)
		rdma_destroy_id(cm_id);
	return (ret);
}

static void rdsv3_rdma_listen_stop(void)
{
	RDSV3_DPRINTF2("rdsv3_rdma_listen_stop", "cm %p", rdsv3_rdma_listen_id);
	rdma_destroy_id(rdsv3_rdma_listen_id);

	RDSV3_DPRINTF2("rdsv3_rdma_listen_stop", "Return");
}

/*
 * This function can be called via two routes.
 * 	1. During attach on a worker thread.
 *	2. From rdsv3_create() for 1st socket.
 */
void
rdsv3_rdma_init()
{
	int ret;

	RDSV3_DPRINTF2("rdsv3_rdma_init", "Enter");

	mutex_enter(&rdsv3_rdma_listen_id_lock);
	if (rdsv3_rdma_listen_id != NULL) {
		RDSV3_DPRINTF2("rdsv3_rdma_init",
		    "rdsv3_rdma_listen_id is already initialized: %p",
		    rdsv3_rdma_listen_id);
		mutex_exit(&rdsv3_rdma_listen_id_lock);
		return;
	}

	ret = rdsv3_rdma_listen_init();
	if (ret) {
		mutex_exit(&rdsv3_rdma_listen_id_lock);
		return;
	}

	ret = rdsv3_ib_init();
	if (ret) {
		rdsv3_rdma_listen_stop();
	}
	mutex_exit(&rdsv3_rdma_listen_id_lock);

	RDSV3_DPRINTF2("rdsv3_rdma_init", "Return");
}

/*ARGSUSED*/
void
rdsv3_rdma_exit(void *arg)
{
	RDSV3_DPRINTF2("rdsv3_rdma_exit", "Enter");

	/* stop listening first to ensure no new connections are attempted */
	if (rdsv3_rdma_listen_id) {
		rdsv3_rdma_listen_stop();
		rdsv3_ib_exit();
		rdsv3_rdma_listen_id = NULL;
	}

	RDSV3_DPRINTF2("rdsv3_rdma_exit", "Return");
}
