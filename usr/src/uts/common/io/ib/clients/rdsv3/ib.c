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
 * Copyright (c) 2006 Oracle.  All rights reserved.
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
#include <sys/sysmacros.h>
#include <sys/rds.h>

#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/ib.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

unsigned int rdsv3_ib_retry_count = RDSV3_IB_DEFAULT_RETRY_COUNT;

struct list	rdsv3_ib_devices;

/* NOTE: if also grabbing ibdev lock, grab this first */
kmutex_t ib_nodev_conns_lock;
list_t ib_nodev_conns;

void
rdsv3_ib_add_one(ib_device_t *device)
{
	struct rdsv3_ib_device *rds_ibdev;
	ibt_hca_attr_t *dev_attr;

	RDSV3_DPRINTF4("rdsv3_ib_add_one", "device: %p", device);

	/* Only handle IB (no iWARP) devices */
	if (device->node_type != RDMA_NODE_IB_CA)
		return;

	dev_attr = (ibt_hca_attr_t *)kmem_alloc(sizeof (*dev_attr),
	    KM_NOSLEEP);
	if (!dev_attr)
		return;

	if (ibt_query_hca(ib_get_ibt_hca_hdl(device), dev_attr)) {
		RDSV3_DPRINTF5("rdsv3_ib_add_one",
		    "Query device failed for %s", device->name);
		goto free_attr;
	}

	/* We depend on Reserved Lkey */
	if (!(dev_attr->hca_flags2 & IBT_HCA2_RES_LKEY)) {
		RDSV3_DPRINTF5("rdsv3_ib_add_one",
		    "Reserved Lkey support is required: %s",
		    device->name);
		goto free_attr;
	}

	rds_ibdev = kmem_zalloc(sizeof (*rds_ibdev), KM_NOSLEEP);
	if (!rds_ibdev)
		goto free_attr;

	mutex_init(&rds_ibdev->spinlock, NULL, MUTEX_DRIVER, NULL);

	rds_ibdev->max_wrs = dev_attr->hca_max_chan_sz;
	rds_ibdev->max_sge = min(dev_attr->hca_max_sgl, RDSV3_IB_MAX_SGE);

	rds_ibdev->dev = device;
	rds_ibdev->pd = ib_alloc_pd(device);
	if (IS_ERR(rds_ibdev->pd))
		goto free_dev;

	if (rdsv3_ib_create_mr_pool(rds_ibdev) != 0) {
		goto free_dev;
	}

	list_create(&rds_ibdev->ipaddr_list, sizeof (struct rdsv3_ib_ipaddr),
	    offsetof(struct rdsv3_ib_ipaddr, list));
	list_create(&rds_ibdev->conn_list, sizeof (struct rdsv3_ib_connection),
	    offsetof(struct rdsv3_ib_connection, ib_node));

	list_insert_tail(&rdsv3_ib_devices, rds_ibdev);

	ib_set_client_data(device, &rdsv3_ib_client, rds_ibdev);

	RDSV3_DPRINTF4("rdsv3_ib_add_one", "Return: device: %p", device);

	goto free_attr;

err_pd:
	(void) ib_dealloc_pd(rds_ibdev->pd);
free_dev:
	kmem_free(rds_ibdev, sizeof (*rds_ibdev));
free_attr:
	kmem_free(dev_attr, sizeof (*dev_attr));
}

void
rdsv3_ib_remove_one(struct ib_device *device)
{
	struct rdsv3_ib_device *rds_ibdev;
	struct rdsv3_ib_ipaddr *i_ipaddr, *i_next;

	RDSV3_DPRINTF4("rdsv3_ib_remove_one", "device: %p", device);

	rds_ibdev = ib_get_client_data(device, &rdsv3_ib_client);
	if (!rds_ibdev)
		return;

	RDSV3_FOR_EACH_LIST_NODE_SAFE(i_ipaddr, i_next, &rds_ibdev->ipaddr_list,
	    list) {
		list_remove_node(&i_ipaddr->list);
		kmem_free(i_ipaddr, sizeof (*i_ipaddr));
	}

	rdsv3_ib_destroy_conns(rds_ibdev);

	rdsv3_ib_destroy_mr_pool(rds_ibdev);

#if 0
	while (ib_dealloc_pd(rds_ibdev->pd)) {
#ifndef __lock_lint
		RDSV3_DPRINTF5("rdsv3_ib_remove_one",
		    "%s-%d Failed to dealloc pd %p",
		    __func__, __LINE__, rds_ibdev->pd);
#endif
		delay(drv_usectohz(1000));
	}
#else
	if (ib_dealloc_pd(rds_ibdev->pd)) {
#ifndef __lock_lint
		RDSV3_DPRINTF2("rdsv3_ib_remove_one",
		    "%s-%d Failed to dealloc pd %p",
		    __func__, __LINE__, rds_ibdev->pd);
#endif
	}
#endif

	list_destroy(&rds_ibdev->ipaddr_list);
	list_destroy(&rds_ibdev->conn_list);
	list_remove_node(&rds_ibdev->list);
	kmem_free(rds_ibdev, sizeof (*rds_ibdev));

	RDSV3_DPRINTF4("rdsv3_ib_remove_one", "Return: device: %p", device);
}

#ifndef __lock_lint
struct ib_client rdsv3_ib_client = {
	.name		= "rdsv3_ib",
	.add		= rdsv3_ib_add_one,
	.remove		= rdsv3_ib_remove_one,
	.clnt_hdl	= NULL,
	.state		= IB_CLNT_UNINITIALIZED
};
#else
struct ib_client rdsv3_ib_client = {
	"rdsv3_ib",
	rdsv3_ib_add_one,
	rdsv3_ib_remove_one,
	NULL,
	NULL,
	IB_CLNT_UNINITIALIZED
};
#endif

static int
rds_ib_conn_info_visitor(struct rdsv3_connection *conn,
    void *buffer)
{
	struct rdsv3_info_rdma_connection *iinfo = buffer;
	struct rdsv3_ib_connection *ic;

	RDSV3_DPRINTF4("rds_ib_conn_info_visitor", "conn: %p buffer: %p",
	    conn, buffer);

	/* We will only ever look at IB transports */
	if (conn->c_trans != &rdsv3_ib_transport)
		return (0);

	iinfo->src_addr = conn->c_laddr;
	iinfo->dst_addr = conn->c_faddr;

	(void) memset(&iinfo->src_gid, 0, sizeof (iinfo->src_gid));
	(void) memset(&iinfo->dst_gid, 0, sizeof (iinfo->dst_gid));
	if (rdsv3_conn_state(conn) == RDSV3_CONN_UP) {
		struct rdsv3_ib_device *rds_ibdev;
		struct rdma_dev_addr *dev_addr;

		ic = conn->c_transport_data;
		dev_addr = &ic->i_cm_id->route.addr.dev_addr;

		ib_addr_get_sgid(dev_addr, (union ib_gid *)&iinfo->src_gid);
		ib_addr_get_dgid(dev_addr, (union ib_gid *)&iinfo->dst_gid);

		rds_ibdev = ib_get_client_data(ic->i_cm_id->device,
		    &rdsv3_ib_client);
		iinfo->max_send_wr = ic->i_send_ring.w_nr;
		iinfo->max_recv_wr = ic->i_recv_ring.w_nr;
		iinfo->max_send_sge = rds_ibdev->max_sge;
	}

	RDSV3_DPRINTF4("rds_ib_conn_info_visitor", "conn: %p buffer: %p",
	    conn, buffer);
	return (1);
}

static void
rds_ib_ic_info(struct rsock *sock, unsigned int len,
    struct rdsv3_info_iterator *iter,
    struct rdsv3_info_lengths *lens)
{
	RDSV3_DPRINTF4("rds_ib_ic_info", "sk: %p iter: %p, lens: %p, len: %d",
	    sock, iter, lens, len);

	rdsv3_for_each_conn_info(sock, len, iter, lens,
	    rds_ib_conn_info_visitor,
	    sizeof (struct rdsv3_info_rdma_connection));
}

/*
 * Early RDS/IB was built to only bind to an address if there is an IPoIB
 * device with that address set.
 *
 * If it were me, I'd advocate for something more flexible.  Sending and
 * receiving should be device-agnostic.  Transports would try and maintain
 * connections between peers who have messages queued.  Userspace would be
 * allowed to influence which paths have priority.  We could call userspace
 * asserting this policy "routing".
 */
static int
rds_ib_laddr_check(uint32_be_t addr)
{
	int ret;
	struct rdma_cm_id *cm_id;
	struct sockaddr_in sin;

	RDSV3_DPRINTF4("rds_ib_laddr_check", "addr: %x", ntohl(addr));

	/*
	 * Create a CMA ID and try to bind it. This catches both
	 * IB and iWARP capable NICs.
	 */
	cm_id = rdma_create_id(NULL, NULL, RDMA_PS_TCP);
	if (IS_ERR(cm_id))
		return (PTR_ERR(cm_id));

	(void) memset(&sin, 0, sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = rdsv3_scaddr_to_ibaddr(addr);

	/* rdma_bind_addr will only succeed for IB & iWARP devices */
	ret = rdma_bind_addr(cm_id, (struct sockaddr *)&sin);
	/*
	 * due to this, we will claim to support iWARP devices unless we
	 * check node_type.
	 */
	if (ret || cm_id->device->node_type != RDMA_NODE_IB_CA)
		ret = -EADDRNOTAVAIL;

	RDSV3_DPRINTF5("rds_ib_laddr_check",
	    "addr %u.%u.%u.%u ret %d node type %d",
	    NIPQUAD(addr), ret,
	    cm_id->device ? cm_id->device->node_type : -1);

	rdma_destroy_id(cm_id);

	return (ret);
}

void
rdsv3_ib_exit(void)
{
	RDSV3_DPRINTF4("rds_ib_exit", "Enter");

	rdsv3_info_deregister_func(RDSV3_INFO_IB_CONNECTIONS, rds_ib_ic_info);
	rdsv3_ib_destroy_nodev_conns();
	ib_unregister_client(&rdsv3_ib_client);
	rdsv3_ib_sysctl_exit();
	rdsv3_ib_recv_exit();
	rdsv3_trans_unregister(&rdsv3_ib_transport);
	mutex_destroy(&ib_nodev_conns_lock);
	list_destroy(&ib_nodev_conns);
	list_destroy(&rdsv3_ib_devices);

	RDSV3_DPRINTF4("rds_ib_exit", "Return");
}

#ifndef __lock_lint
struct rdsv3_transport rdsv3_ib_transport = {
	.laddr_check		= rds_ib_laddr_check,
	.xmit_complete		= rdsv3_ib_xmit_complete,
	.xmit			= rdsv3_ib_xmit,
	.xmit_cong_map		= NULL,
	.xmit_rdma		= rdsv3_ib_xmit_rdma,
	.recv			= rdsv3_ib_recv,
	.conn_alloc		= rdsv3_ib_conn_alloc,
	.conn_free		= rdsv3_ib_conn_free,
	.conn_connect		= rdsv3_ib_conn_connect,
	.conn_shutdown		= rdsv3_ib_conn_shutdown,
	.inc_copy_to_user	= rdsv3_ib_inc_copy_to_user,
	.inc_purge		= rdsv3_ib_inc_purge,
	.inc_free		= rdsv3_ib_inc_free,
	.cm_initiate_connect	= rdsv3_ib_cm_initiate_connect,
	.cm_handle_connect	= rdsv3_ib_cm_handle_connect,
	.cm_connect_complete	= rdsv3_ib_cm_connect_complete,
	.stats_info_copy	= rdsv3_ib_stats_info_copy,
	.exit			= rdsv3_ib_exit,
	.get_mr			= rdsv3_ib_get_mr,
	.sync_mr		= rdsv3_ib_sync_mr,
	.free_mr		= rdsv3_ib_free_mr,
	.flush_mrs		= rdsv3_ib_flush_mrs,
	.t_name			= "infiniband",
};
#else
struct rdsv3_transport rdsv3_ib_transport;
#endif

int
rdsv3_ib_init(void)
{
	int ret;

	RDSV3_DPRINTF4("rds_ib_init", "Enter");

	list_create(&rdsv3_ib_devices, sizeof (struct rdsv3_ib_device),
	    offsetof(struct rdsv3_ib_device, list));
	list_create(&ib_nodev_conns, sizeof (struct rdsv3_ib_connection),
	    offsetof(struct rdsv3_ib_connection, ib_node));
	mutex_init(&ib_nodev_conns_lock, NULL, MUTEX_DRIVER, NULL);

	rdsv3_ib_client.dip = rdsv3_dev_info;
	ret = ib_register_client(&rdsv3_ib_client);
	if (ret)
		goto out;

	ret = rdsv3_ib_sysctl_init();
	if (ret)
		goto out_ibreg;

	ret = rdsv3_ib_recv_init();
	if (ret)
		goto out_sysctl;

	ret = rdsv3_trans_register(&rdsv3_ib_transport);
	if (ret)
		goto out_recv;

	rdsv3_info_register_func(RDSV3_INFO_IB_CONNECTIONS, rds_ib_ic_info);

	RDSV3_DPRINTF4("rds_ib_init", "Return");

	return (0);

out_recv:
	rdsv3_ib_recv_exit();
out_sysctl:
	rdsv3_ib_sysctl_exit();
out_ibreg:
	ib_unregister_client(&rdsv3_ib_client);
out:
	mutex_destroy(&ib_nodev_conns_lock);
	list_destroy(&ib_nodev_conns);
	list_destroy(&rdsv3_ib_devices);
	return (ret);
}
