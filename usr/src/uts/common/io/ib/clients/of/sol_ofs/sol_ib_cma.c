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
 * IB specific routines for RDMA CM functionality
 */
/* Standard driver includes */
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/stat.h>

#include <sys/ib/clients/of/sol_ofs/sol_ofs_common.h>
#include <sys/ib/clients/of/ofed_kernel.h>
#include <sys/ib/clients/of/rdma/ib_addr.h>
#include <sys/ib/clients/of/rdma/rdma_cm.h>

#include <sys/ib/clients/of/sol_ofs/sol_cma.h>
#include <sys/ib/clients/of/sol_ofs/sol_ib_cma.h>

extern char 	*sol_rdmacm_dbg_str;

/* Delay of 5 secs */
#define	SOL_OFS_REQ_DELAY	5000000

/*	Solaris CM Event Callbacks 	*/
static ibt_cm_status_t ibcma_rc_hdlr(void *, ibt_cm_event_t *,
    ibt_cm_return_args_t *, void *, ibt_priv_data_len_t);
static ibt_cm_status_t ibcma_ud_hdlr(void *, ibt_cm_ud_event_t *,
    ibt_cm_ud_return_args_t *, void *, ibt_priv_data_len_t);
static void ibcma_multicast_hdlr(void *, ibt_status_t, ibt_mcg_info_t *);

/*	Local functions 	*/
static int ibcma_tcp_connect(struct rdma_cm_id *, ibcma_chan_t *,
    struct rdma_conn_param *);
static int ibcma_udp_connect(struct rdma_cm_id *, ibcma_chan_t *,
    struct rdma_conn_param *);
static struct rdma_cm_id *ibcma_create_new_id(struct rdma_cm_id *);
static int ibcma_query_local_ip(struct rdma_cm_id *, sol_cma_chan_t *,
    ibcma_chan_t *);
static int ibcma_get_paths(struct rdma_cm_id *, sol_cma_chan_t *,
    ibcma_chan_t *);
static void ibcma_get_devlist(sol_cma_chan_t *, ib_guid_t *, int,
    genlist_t *);
static int ibcma_any_addr(ibt_ip_addr_t *);
static int ibcma_get_first_ib_ipaddr(struct rdma_cm_id *);

/* Utility Conversion Routines */
static void 	ipaddr2mgid(struct sockaddr *, ib_gid_t *, ib_pkey_t);
static void 	ibt_path2ah(ibt_path_info_t *, struct ib_ah_attr *);
static void	ibt_addsvect2ah(ibt_adds_vect_t *, struct ib_ah_attr *);
static void	ibt_addsvect2sa_path(ibt_adds_vect_t *,
    struct ib_sa_path_rec *, ib_lid_t);
static void	ibt_path2sa_path(ibt_path_info_t *, struct ib_sa_path_rec *,
    ib_lid_t);
static void 	mcginfo2ah(ibt_mcg_info_t *, struct ib_ah_attr *);
static void	sockaddr2ibtaddr_port(struct rdma_cm_id *, struct sockaddr *,
    ibt_ip_addr_t *, in_port_t *);
static void ipaddr2sockaddr(ibt_ip_addr_t *, struct sockaddr *,
    in_port_t *);

#ifdef	QP_DEBUG
static void 	dump_qp_info(ibt_qp_hdl_t);
#endif
static void	dump_priv_data(void *, ibt_priv_data_len_t,
    ibt_priv_data_len_t, char *);

extern cma_chan_state_t cma_get_chan_state(sol_cma_chan_t *);

/*
 * RDMA CM API - Transport specific functions
 */
void
rdma_ib_destroy_id(struct rdma_cm_id *idp)
{
	sol_cma_chan_t		*chanp = (sol_cma_chan_t *)idp;
	ibcma_chan_t		*ibchanp;
	ibt_status_t		status;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_ib_destroy_id(%p)", idp);
	ASSERT(chanp);
	ibchanp = &(chanp->chan_ib);

	if (ibchanp->chan_mcast_cnt) {
		genlist_entry_t	*entry;
		ibcma_mcast_t	*ibmcastp;
		ib_gid_t	zero_gid;

		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "rdma_ib_destroy_id: pending mcast!!");
		entry = remove_genlist_head(&ibchanp->chan_mcast_list);
		while (entry) {
			ibmcastp = (ibcma_mcast_t *)entry->data;

			bzero(&zero_gid, sizeof (ib_gid_t));
			status = ibt_leave_mcg(ibchanp->chan_devp->dev_sgid,
			    ibmcastp->mcast_gid, zero_gid, IB_MC_JSTATE_FULL);
			if (status != IBT_SUCCESS)
				SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
				    "destroy_id: ibt_leave_mcg failed %d",
				    status);
			kmem_free(ibmcastp, sizeof (ibcma_mcast_t));

			entry = remove_genlist_head(&ibchanp->chan_mcast_list);
		}
	}
	if (ibchanp->chan_devp) {
		kmem_free(ibchanp->chan_devp, sizeof (ibcma_dev_t));
		ibchanp->chan_devp = NULL;
	}
	if (ibchanp->chan_pathp) {
		kmem_free(ibchanp->chan_pathp, ibchanp->chan_path_size);
		ibchanp->chan_pathp = NULL;
	}

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_ib_destroy_id: return");
}

int
rdma_ib_bind_addr(struct rdma_cm_id *idp, struct sockaddr *addr)
{
	sol_cma_chan_t	*chanp = (sol_cma_chan_t *)idp;
	ibcma_chan_t	*ibchanp;
	int		ret;
	in_port_t	port;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_ib_bind_addr(%p, %p)",
	    idp, addr);
	ASSERT(chanp);
	ibchanp = &(chanp->chan_ib);

	sockaddr2ibtaddr_port(idp, addr, &ibchanp->chan_local_addr, &port);
	ibchanp->chan_addr_flag = IBCMA_LOCAL_ADDR_SET_FLAG;

	/*
	 * If this is IF_ADDR_ANY, get info of IB port with IP @.
	 * Return Failure, if there are no IB ports with IP @.
	 */
	if (sol_cma_any_addr(addr)) {
		ibchanp->chan_port = port;
		ibchanp->chan_addr_flag |= IBCMA_LOCAL_ADDR_IFADDRANY;
		return (ibcma_get_first_ib_ipaddr(idp));
	}

	ret = ibcma_query_local_ip(idp, chanp, ibchanp);
	if (ret == 0) {
		init_genlist(&ibchanp->chan_mcast_list);
		ibchanp->chan_sid = ibt_get_ip_sid(idp->ps, port);
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "chan SID %llx , ps %x, port %x",
		    ibchanp->chan_sid, idp->ps, port);
		ibchanp->chan_port = port;
		chanp->chan_xport_type = SOL_CMA_XPORT_IB;
	}
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_ib_bind_addr: return %x",
	    ret);
	return (ret);
}

int
rdma_ib_resolve_addr(struct rdma_cm_id *idp, struct sockaddr *src_addr,
    struct sockaddr *dst_addr, int timeout_ms)
{
	sol_cma_chan_t	*chanp = (sol_cma_chan_t *)idp;
	ibcma_chan_t	*ibchanp;
	int		ret;
	in_port_t	port;
	in_addr_t	remote_addr;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_ib_resolve_addr("
	    "%p, %p, %p, %x)", idp, src_addr, dst_addr, timeout_ms);
	ASSERT(chanp);
	ibchanp = &(chanp->chan_ib);

	/*
	 * Copy src_addr if the passed src @ is valid IP address and
	 * the local @ has not been set for this CMID.
	 */
	if ((ibchanp->chan_addr_flag & IBCMA_LOCAL_ADDR_SET_FLAG) == 0 &&
	    IS_VALID_SOCKADDR(src_addr)) {
		sockaddr2ibtaddr_port(idp, src_addr, &ibchanp->chan_local_addr,
		    &port);
		ibchanp->chan_addr_flag |= IBCMA_LOCAL_ADDR_SET_FLAG;
		if (port) {
			ibchanp->chan_sid = ibt_get_ip_sid(idp->ps, port);
			SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "resolve_addr, "
			    "local @ SID %llx, ps %x, port %x",
			    ibchanp->chan_sid, idp->ps, port);
			ibchanp->chan_port = port;
		}
	}

	sockaddr2ibtaddr_port(idp, dst_addr, &ibchanp->chan_remote_addr,
	    &port);
	ibchanp->chan_addr_flag |= IBCMA_REMOTE_ADDR_SET_FLAG;
	if (ibchanp->chan_sid == 0) {
		ASSERT(!sol_cma_any_addr(dst_addr));
		ibchanp->chan_sid = ibt_get_ip_sid(idp->ps, port);
		ibchanp->chan_port = port;
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "resolve_addr, remote @ "
		    "SID %llx , ps %x, port %x", ibchanp->chan_sid,
		    idp->ps, port);
		init_genlist(&ibchanp->chan_mcast_list);
	}

	/*
	 * Return SUCCESS if remote address is a MCAST address
	 * and local address is not IF_ADDR_ANY. If local_addr
	 * is IF_ADDR_ANY and remote is MCAST, return FAILURE.
	 */
	remote_addr = htonl((ibchanp->chan_remote_addr).un.ip4addr);
	if ((ibchanp->chan_remote_addr).family == AF_INET &&
	    (remote_addr >= 0xE0000000 && remote_addr <= 0xEFFFFFFF)) {
		if (ibchanp->chan_devp) {
			SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
			    "ib_resolve_addr - mcast dest @, local IP");
			(idp->route).num_paths = 0;
			ret = 0;
		} else {
			ret = ibcma_get_first_ib_ipaddr(idp);
		}

		if (ret == 0 && idp->device == NULL)
			idp->device = sol_cma_acquire_device(ntohll(
			    ibchanp->chan_devp->dev_node_guid));
		return (0);
	}

	if ((ret = ibcma_get_paths(idp, chanp, ibchanp)) == 0)
		chanp->chan_xport_type = SOL_CMA_XPORT_IB;

	return (ret);
}

/*
 * Linux OFED implementation is as below :
 *	1. librdmacm sends INIT_QP_ATTR command to get QP attributes
 *	   which the kernel CM expects QP attribute to be in. Kernel
 *	   CM sets the QP attribute to be set and passes it back to
 *	   user library.
 *	2. librdmacm calls ibv_modify_qp() to modify the QP attribute.
 *         The QP attribute used is the same as the that passed by
 *		   kernel sol_ucma.
 *
 * For RC connections, Solaris ibcm manages the QP state after :
 *	CM Event Handler is called	- Passive side
 *	ibv_open_rc_channel(9f)  	- Active Side
 * The client will *not* have to do an explcit modify_qp(). To fit this
 * INIT_QP_ATTR commands *marks* the QP to fake it's attributes and
 * ignore ibv_modify_qp() for this QP. Solaris ibcm manages QP state.
 *
 * Before the above calls, the client will have to maintain the QP state.
 * The sol_ucma driver will pass the appropriate QP atrributes, for the
 * clients to pass to ibv_modify_qp().
 *
 * For UD, OFED model is adhered to till the QP is transitioned to RTS.
 * Any transitions after the QP has transitioned to RTS are ignored.
 */
int
rdma_ib_init_qp_attr(struct rdma_cm_id *idp, struct ib_qp_attr *qpattr,
    int *qp_attr_mask)
{
	sol_cma_chan_t	*chanp;
	ibcma_chan_t	*ibchanp;
	ibcma_dev_t	*devp;
	uint32_t	qpstate;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	ibchanp = &chanp->chan_ib;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_ib_init_qp_attr("
	    "%p, %p, %p)", idp, qpattr, qp_attr_mask);

	if (ibchanp->chan_qpmodifyflag == 1) {
		SOL_OFS_DPRINTF_L4(sol_rdmacm_dbg_str,
		    "Ignoring Init QP Attr");
		return (0);
	}

	qpstate = qpattr->qp_state;
	bzero(qpattr, sizeof (struct ib_qp_attr));
	qpattr->qp_state = qpstate;

	devp = ibchanp->chan_devp;
	if (devp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "init_qp_attr, devp NULL");
		return (EINVAL);
	}
	qpattr->pkey_index = devp->dev_pkey_ix;
	qpattr->port_num = devp->dev_port_num;

	if (idp->ps == RDMA_PS_TCP && qpstate == IB_QPS_INIT) {
		qpattr->qp_access_flags = IB_ACCESS_REMOTE_WRITE |
		    IB_ACCESS_REMOTE_READ;
		*qp_attr_mask = IB_QP_STATE | IB_QP_PKEY_INDEX | IB_QP_PORT |
		    IB_QP_ACCESS_FLAGS;
		return (0);
	} else if (idp->ps == RDMA_PS_TCP &&
	    qpstate == IB_QPS_RTR) {
		*qp_attr_mask = IB_QP_STATE | IB_QP_AV | IB_QP_PATH_MTU  |
		    IB_QP_DEST_QPN | IB_QP_RQ_PSN |
		    IB_QP_MAX_DEST_RD_ATOMIC | IB_QP_MIN_RNR_TIMER;
		/*
		 * Fill in valid values for address vector & Remote QPN.
		 * Fill in MTU as MTU_256 & PSN as 0. This QP will be
		 * reset anyway.
		 */
		ibt_addsvect2ah(&ibchanp->chan_rcreq_addr, &qpattr->ah_attr);
		qpattr->path_mtu = (uint32_t)
		    ((ibchanp->chan_rtr_data).req_path_mtu);
		qpattr->dest_qp_num = ibchanp->chan_rcreq_qpn;
		qpattr->rq_psn = (ibchanp->chan_rtr_data).req_rq_psn;
		qpattr->max_dest_rd_atomic = ibchanp->chan_rcreq_ra_in;
		qpattr->min_rnr_timer =
		    (ibchanp->chan_rtr_data).req_rnr_nak_time;
		return (0);
	} else if (IS_UDP_CMID(idp)) {
		qpattr->qkey = RDMA_UDP_QKEY;
		*qp_attr_mask = IB_QP_STATE | IB_QP_PKEY_INDEX |
		    IB_QP_PORT | IB_QP_QKEY;
		return (0);
	} else
		return (EINVAL);
}

int
rdma_ib_connect(struct rdma_cm_id *idp, struct rdma_conn_param *conn_param)
{
	sol_cma_chan_t	*chanp;
	ibcma_chan_t	*ibchanp;
	int		ret;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	ibchanp = &chanp->chan_ib;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_ib_connect(%p, %p)", idp,
	    conn_param);

	ASSERT(chanp->chan_xport_type == SOL_CMA_XPORT_IB);
	if (ibchanp->chan_devp == NULL || ibchanp->chan_pathp == NULL) {
		SOL_OFS_DPRINTF_L3(sol_rdmacm_dbg_str, "rdma_ib_connect : "
		    "invalid IP @");
		return (EINVAL);
	}
	ASSERT(ibchanp->chan_devp);

	ibchanp->chan_qpmodifyflag  = 1;
	if (idp->ps == RDMA_PS_TCP)
		ret = ibcma_tcp_connect(idp, ibchanp, conn_param);
	else
		ret = ibcma_udp_connect(idp, ibchanp, conn_param);

	return (ret);
}

extern void sol_cma_add_hca_list(sol_cma_chan_t *, ib_guid_t);
void
ibcma_append_listen_list(struct rdma_cm_id  *root_idp)
{
	int			num_hcas;
	ib_guid_t		*hca_guidp;
	struct rdma_cm_id	*ep_idp;
	sol_cma_chan_t		*root_chanp, *ep_chanp;
	ibcma_chan_t		*root_ibchanp, *ep_ibchanp;
	genlist_t		dev_genlist;
	genlist_entry_t		*entry;

	sol_cma_listen_info_t	*listenp;
	ibcma_dev_t		*devp;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "append_listen(%p)", root_idp);
	root_chanp = (sol_cma_chan_t *)root_idp;
	root_ibchanp = &root_chanp->chan_ib;

	/*
	 * Address other than IF_ADDR_ANY bound to this channel. Listen on
	 * this IP address alone.
	 */
	if (root_ibchanp->chan_devp &&
	    (root_ibchanp->chan_addr_flag & IBCMA_LOCAL_ADDR_IFADDRANY) == 0) {
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "Create listen chan");
		ep_idp = ibcma_create_new_id(root_idp);
		ASSERT(ep_idp);

		ep_chanp = (sol_cma_chan_t *)ep_idp;
		listenp = kmem_zalloc(sizeof (sol_cma_listen_info_t),
		    KM_SLEEP);
		ep_chanp->chan_listenp = listenp;

		ep_ibchanp = &ep_chanp->chan_ib;
		ep_ibchanp->chan_port = root_ibchanp->chan_port;
		listenp->listen_ep_root_entry = add_genlist(
		    &(CHAN_LISTEN_LIST(root_chanp)),
		    (uintptr_t)ep_idp, root_idp);
		devp = ep_ibchanp->chan_devp;
		sol_cma_add_hca_list(ep_chanp, ntohll(devp->dev_node_guid));
		return;
	}

	/*
	 * Get the list of IB devs with valid IP addresses
	 * Append to the list of listeners for root_idp
	 */
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "Search IP @");
	num_hcas = ibt_get_hca_list(&hca_guidp);
	ibcma_get_devlist(root_chanp, hca_guidp, num_hcas,
	    &dev_genlist);
	entry = remove_genlist_head(&dev_genlist);
	while (entry) {
		devp = (ibcma_dev_t *)(entry->data);
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "Create listen chan- ALL");
		ep_idp = ibcma_create_new_id(root_idp);
		ASSERT(ep_idp);

		ep_chanp = (sol_cma_chan_t *)ep_idp;
		ipaddr2sockaddr(&devp->dev_ipaddr,
		    &(ep_idp->route.addr.src_addr), NULL);
		listenp = kmem_zalloc(sizeof (sol_cma_listen_info_t),
		    KM_SLEEP);
		ep_chanp->chan_listenp = listenp;

		ep_ibchanp = &ep_chanp->chan_ib;
		kmem_free(ep_ibchanp->chan_devp, sizeof (ibcma_dev_t));
		ep_ibchanp->chan_devp = devp;
		ep_ibchanp->chan_port = root_ibchanp->chan_port;

		listenp->listen_ep_root_entry = add_genlist(
		    &(CHAN_LISTEN_LIST(root_chanp)),
		    (uintptr_t)ep_idp, root_idp);
		sol_cma_add_hca_list(ep_chanp, ntohll(devp->dev_node_guid));
		kmem_free(entry, sizeof (genlist_entry_t));
		entry = remove_genlist_head(&dev_genlist);
	}
	ibt_free_hca_list(hca_guidp, num_hcas);
}

int
ibcma_init_root_chan(sol_cma_chan_t *root_chanp, sol_cma_glbl_listen_t *listenp)
{
	ibcma_chan_t		*root_ibchanp;
	ibt_srv_desc_t		service;
	ibt_status_t		status;
	struct rdma_cm_id	*root_idp;

	root_idp = &(root_chanp->chan_rdma_cm);
	root_ibchanp = &root_chanp->chan_ib;

	if (root_idp->ps == RDMA_PS_TCP)
		service.sd_handler = ibcma_rc_hdlr;
	else
		service.sd_ud_handler = ibcma_ud_hdlr;
	service.sd_flags = IBT_SRV_NO_FLAGS;
	status = ibt_register_service(root_chanp->chan_ib_client_hdl,
	    &service, root_ibchanp->chan_sid,
	    root_ibchanp->chan_port ? 1 : 0xffff,
	    &((root_chanp->chan_listenp)->listen_ib_srv_hdl),
	    NULL);
	if (status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "init_root_chan: ibt_register_service ret %x"
		    "SID %x, port %x", status, root_ibchanp->chan_sid,
		    root_ibchanp->chan_port);
		return (EINVAL);
	}
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "init_root_chan: "
	    "ibt_register_service: SID %x, port %x: done",
	    root_ibchanp->chan_sid, root_ibchanp->chan_port);
	listenp->cma_listen_svc_hdl =
	    (void *)(root_chanp->chan_listenp)->listen_ib_srv_hdl;
	return (0);
}

int
ibcma_fini_root_chan(sol_cma_chan_t *rchanp)
{
	ibt_status_t	status;

	status = ibt_deregister_service(rchanp->chan_ib_client_hdl,
	    (rchanp->chan_listenp)->listen_ib_srv_hdl);
	if (status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "fini_root_chan: ibt_deregister_service ret %x",
		    status);
		return (EINVAL);
	}
	return (0);
}

void
ibcma_copy_srv_hdl(sol_cma_chan_t *root_chanp, sol_cma_glbl_listen_t *listenp)
{
	(root_chanp->chan_listenp)->listen_ib_srv_hdl =
	    (ibt_srv_hdl_t)listenp->cma_listen_svc_hdl;
}

int
ibcma_fini_ep_chan(sol_cma_chan_t *ep_chanp)
{
	struct rdma_cm_id	*root_idp;
	sol_cma_chan_t		*root_chanp;
	sol_cma_listen_info_t	*root_listenp, *ep_listenp;
	ibt_status_t		status;
	ibcma_chan_t		*ep_ibchanp = &ep_chanp->chan_ib;

	ASSERT(ep_chanp);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "fini_ep_chan(%p)", ep_chanp);
	root_idp  = CHAN_LISTEN_ROOT(ep_chanp);
	root_chanp = (sol_cma_chan_t *)root_idp;
	root_listenp = root_chanp->chan_listenp;
	ep_listenp = ep_chanp->chan_listenp;

	if (ep_ibchanp->chan_devp)
		kmem_free(ep_ibchanp->chan_devp, sizeof (ibcma_dev_t));
	if (ep_ibchanp->chan_pathp)
		kmem_free(ep_ibchanp->chan_pathp,
		    ep_ibchanp->chan_path_size);

	if (!ep_listenp->listen_ib_sbind_hdl)
		return (0);
	status = ibt_unbind_service(root_listenp->listen_ib_srv_hdl,
	    ep_listenp->listen_ib_sbind_hdl);
	if (status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "fini_ep_chan(%p) : ibt_unbind_service() ret %d",
		    status);
		return (-1);
	}

	return (0);
}

uint64_t
ibcma_init_root_sid(sol_cma_chan_t *root_chanp)
{
	ibcma_chan_t		*root_ibchanp;
	struct rdma_cm_id	*root_idp;

	root_ibchanp = &root_chanp->chan_ib;
	root_idp = (struct rdma_cm_id *)root_chanp;
	if (root_ibchanp->chan_sid == 0) {
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "listen No SID : ps %x",
		    root_idp->ps);
		root_ibchanp->chan_sid = ibt_get_ip_sid(root_idp->ps,
		    root_ibchanp->chan_port);
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "chan SID %llx , ps %x, "
		    "port %x", root_ibchanp->chan_sid, root_idp->ps,
		    root_ibchanp->chan_port);
	}
	return ((uint64_t)root_ibchanp->chan_sid);
}

/*ARGSUSED*/
int
rdma_ib_listen(struct rdma_cm_id *ep_idp, int bklog)
{
	struct rdma_cm_id	*root_idp;
	ibcma_chan_t		*ep_ibchanp;
	sol_cma_chan_t		*root_chanp, *ep_chanp;
	ibcma_dev_t		*ep_devp;
	ibt_status_t		status;

	ASSERT(ep_idp);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "ib_listen(%p)", ep_idp);
	ep_chanp = (sol_cma_chan_t *)ep_idp;
	root_idp  = CHAN_LISTEN_ROOT(ep_chanp);
	root_chanp = (sol_cma_chan_t *)root_idp;
	ep_ibchanp = &ep_chanp->chan_ib;

	ep_devp = ep_ibchanp->chan_devp;
	ASSERT(ep_devp);
	status = ibt_bind_service(
	    (root_chanp->chan_listenp)->listen_ib_srv_hdl,
	    ep_devp->dev_sgid, NULL, ep_idp,
	    &((ep_chanp->chan_listenp)->listen_ib_sbind_hdl));
	if (status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "rdma_listen_ep: "
		    "ibt_bind_service failed with %x", status);
		return (EINVAL);
	}
	return (0);
}

#define	SOL_REP_PRIV_DATA_SZ 208
int
rdma_ib_accept(struct rdma_cm_id *idp, struct rdma_conn_param *conn_param)
{
	sol_cma_chan_t	*chanp;
	ibcma_chan_t	*ibchanp;
	ibt_status_t	status;
	void		*privp = NULL;
	uint8_t		priv_len;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	ibchanp = &chanp->chan_ib;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_ib_accept(%p, %p)",
	    idp, conn_param);
	if (chanp->chan_session_id == NULL) {
		SOL_OFS_DPRINTF_L4(sol_rdmacm_dbg_str,
		    "Active side, cm_proceed not needed");
		return (0);
	}

	if (!conn_param) {
		SOL_OFS_DPRINTF_L4(sol_rdmacm_dbg_str, "conn_param NULL");
		return (0);
	}

	ibchanp->chan_qpmodifyflag  = 1;
	if (idp->ps == RDMA_PS_TCP)  {
		ibt_cm_proceed_reply_t	cm_reply;

		/* Fill cm_reply */
		cm_reply.rep.cm_channel =
		    (ibt_channel_hdl_t)chanp->chan_qp_hdl;
		cm_reply.rep.cm_rdma_ra_out = conn_param->initiator_depth;
		cm_reply.rep.cm_rdma_ra_in = conn_param->responder_resources;
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "accept: "
		    "init_dept %x, resp_res %x", conn_param->initiator_depth,
		    conn_param->responder_resources);
		cm_reply.rep.cm_rnr_retry_cnt = conn_param->rnr_retry_count;
		priv_len = conn_param->private_data_len;
		if (priv_len) {
			privp = (void *)kmem_zalloc(
			    SOL_REP_PRIV_DATA_SZ, KM_SLEEP);
			bcopy((void *)conn_param->private_data,
			    privp, priv_len);
#ifdef	DEBUG
			dump_priv_data(privp, SOL_REP_PRIV_DATA_SZ,
			    conn_param->private_data_len, "ib_accept");
#endif
		}

		status = ibt_ofuvcm_proceed(IBT_CM_EVENT_REQ_RCV,
		    chanp->chan_session_id, IBT_CM_ACCEPT, &cm_reply,
		    privp, priv_len);
		if (status != IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "ib_accept: "
			    "ibt_ofuvcm_proceed failed %x", status);
			if (privp)
				kmem_free(privp, SOL_REP_PRIV_DATA_SZ);
			return (EINVAL);
		}
		if (privp)
			kmem_free(privp, SOL_REP_PRIV_DATA_SZ);
		chanp->chan_session_id = NULL;
	} else  {
		ibt_qp_hdl_t	qphdl = chanp->chan_qp_hdl;

		priv_len = conn_param->private_data_len;
		if (priv_len) {
			privp = (void *)kmem_zalloc(
			    SOL_REP_PRIV_DATA_SZ, KM_SLEEP);
			bcopy((void *)conn_param->private_data,
			    privp, priv_len);
#ifdef DEBUG
			dump_priv_data(privp, SOL_REP_PRIV_DATA_SZ,
			    conn_param->private_data_len, "ib_accept");
#endif
		}

		status = ibt_cm_ud_proceed(chanp->chan_session_id, qphdl,
		    IBT_CM_ACCEPT, NULL, privp, priv_len);
		if (status != IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "ib_accept: "
			    "ibt_cm_ud_proceed failed %x", status);
			if (privp)
				kmem_free(privp, SOL_REP_PRIV_DATA_SZ);
			return (EINVAL);
		}
		chanp->chan_connect_flag = SOL_CMA_CONNECT_SERVER_DONE;

		if (privp)
			kmem_free(privp, SOL_REP_PRIV_DATA_SZ);
	}
	return (0);
}

int
rdma_ib_reject(struct rdma_cm_id *idp, const void *private_data,
    uint8_t private_data_len)
{
	sol_cma_chan_t	*chanp;
	ibt_status_t	status;
	void		*privp = NULL;

	ASSERT(idp);
	chanp = (sol_cma_chan_t *)idp;
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "rdma_ib_reject(%p, %p, %x)", idp,
	    private_data, private_data_len);

	if (chanp->chan_session_id == NULL) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "rdma_ib_reject :"
		    "chan_session_id NULL");
		return (EINVAL);
	}

	if (private_data_len) {
		privp = (void *)kmem_zalloc(SOL_REP_PRIV_DATA_SZ,
		    KM_SLEEP);
		bcopy((void *)private_data, privp,
		    private_data_len);
#ifdef	DEBUG
		dump_priv_data(privp, SOL_REP_PRIV_DATA_SZ,
		    private_data_len, "ib_reject");
#endif
	}

	if (idp->ps == RDMA_PS_TCP)  {
		ibt_cm_proceed_reply_t cm_reply;

		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_ib_reject :"
		    "calling ibt_cm_proceed");
		status = ibt_cm_proceed(IBT_CM_EVENT_REQ_RCV,
		    chanp->chan_session_id, IBT_CM_REJECT, &cm_reply,
		    privp, private_data_len);
		if (status != IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "ib_reject: "
			    "ibt_cm_proceed failed %x", status);
			if (privp)
				kmem_free(privp, SOL_REP_PRIV_DATA_SZ);
			return (EINVAL);
		}
		mutex_enter(&chanp->chan_mutex);
		chanp->chan_connect_flag = SOL_CMA_CONNECT_SERVER_DONE;
		mutex_exit(&chanp->chan_mutex);
	} else  {
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "rdma_ib_reject :"
		    "calling ibt_cm_ud_proceed");
		status = ibt_cm_ud_proceed(chanp->chan_session_id, NULL,
		    IBT_CM_REJECT, NULL, privp, private_data_len);
		if (status != IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "ib_reject: "
			    "ibt_cm_ud_proceed failed %x", status);
			if (privp)
				kmem_free(privp, SOL_REP_PRIV_DATA_SZ);
			return (EINVAL);
		}
		mutex_enter(&chanp->chan_mutex);
		chanp->chan_connect_flag = SOL_CMA_CONNECT_SERVER_DONE;
		mutex_exit(&chanp->chan_mutex);
	}

	if (privp)
		kmem_free(privp, SOL_REP_PRIV_DATA_SZ);
	return (0);
}

int
rdma_ib_disconnect(struct rdma_cm_id *idp)
{
	sol_cma_chan_t		*root_chanp, *chanp;
	ibt_status_t		status;

	ASSERT(idp);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "ib_disconnect(%p)", idp);
	chanp = (sol_cma_chan_t *)idp;
	mutex_enter(&chanp->chan_mutex);

	root_chanp = (sol_cma_chan_t *)CHAN_LISTEN_ROOT(chanp);
	if (IS_UDP_CMID(idp) && chanp->chan_connect_flag ==
	    SOL_CMA_CONNECT_SERVER_RCVD && root_chanp) {
		CHAN_LISTEN_ROOT(chanp) = NULL;
		mutex_exit(&chanp->chan_mutex);

		status = ibt_cm_ud_proceed(chanp->chan_session_id,
		    NULL, IBT_CM_NO_CHANNEL, NULL, NULL, 0);
		if (status != IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "ib_disconnect(%p) Reject for incoming REQ "
			    "failed, status %d", status);
			return (EINVAL);
		}
		mutex_enter(&chanp->chan_mutex);
		if (chanp->chan_req_state == REQ_CMID_CREATED ||
		    chanp->chan_req_state == REQ_CMID_NOTIFIED) {
			mutex_enter(&root_chanp->chan_mutex);
			avl_remove(&root_chanp->chan_req_avl_tree, idp);
			mutex_exit(&root_chanp->chan_mutex);
		}
		chanp->chan_connect_flag = SOL_CMA_CONNECT_NONE;
	}
	if (idp->ps == RDMA_PS_TCP && chanp->chan_connect_flag ==
	    SOL_CMA_CONNECT_SERVER_RCVD && chanp->chan_session_id) {
		ibt_cm_proceed_reply_t	cm_reply;

		mutex_exit(&chanp->chan_mutex);
		bzero(&cm_reply, sizeof (cm_reply));
		status = ibt_cm_proceed(IBT_CM_EVENT_REQ_RCV,
		    chanp->chan_session_id, IBT_CM_REJECT, &cm_reply,
		    NULL, 0);
		if (status != IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "ib_disconnect(%p) Reject for incoming REQ "
			    "failed, status %d", status);
			return (EINVAL);
		}
		mutex_enter(&chanp->chan_mutex);
		if (chanp->chan_req_state == REQ_CMID_CREATED ||
		    chanp->chan_req_state == REQ_CMID_NOTIFIED) {
			mutex_enter(&root_chanp->chan_mutex);
			avl_remove(&root_chanp->chan_req_avl_tree, idp);
			mutex_exit(&root_chanp->chan_mutex);
		}
		chanp->chan_connect_flag = SOL_CMA_CONNECT_NONE;
	}

	/*
	 * Close RC channel for RC.
	 * No explicit Disconnect required for UD
	 */
	if (idp->ps == RDMA_PS_TCP && chanp->chan_qp_hdl &&
	    chanp->chan_connect_flag != SOL_CMA_CONNECT_NONE) {
		ibt_execution_mode_t	mode;
		void			*qp_hdl = chanp->chan_qp_hdl;


		/*
		 * No callbacks for CMIDs for which CONNECT has been
		 * initiated but not completed.
		 */
		mode = (SOL_CMAID_IS_CONNECTED(chanp)) ? IBT_BLOCKING :
		    IBT_NOCALLBACKS;
		mutex_exit(&chanp->chan_mutex);
		status = ibt_close_rc_channel(qp_hdl,
		    mode, NULL, 0, NULL, NULL, NULL);
		if (status != IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "disconnect: close_rc_channel failed %x",
			    status);
			return (EINVAL);
		}
	} else
		mutex_exit(&chanp->chan_mutex);

	return (0);
}

int
rdma_ib_join_multicast(struct rdma_cm_id *idp, struct sockaddr *addr,
    void *context)
{
	sol_cma_chan_t	*chanp = (sol_cma_chan_t *)idp;
	ibcma_chan_t	*ibchanp;
	ibt_mcg_attr_t	mcg_attr;
	ibt_ip_addr_t	mcast_addr;
	ibt_mcg_info_t	*mcg_infop;
	ibt_status_t	status;
	ib_gid_t	mcast_gid, mcast_gid_horder;
	ibcma_dev_t	*devp;
	ibcma_mcast_t	*ibmcastp = NULL;

	ibchanp = &chanp->chan_ib;
	devp = ibchanp->chan_devp;
	if (devp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "join_mcast: devp NULL");
		return (EINVAL);
	}

	ibmcastp = kmem_zalloc(sizeof (ibcma_mcast_t), KM_SLEEP);
	ibmcastp->mcast_idp = idp;
	ibmcastp->mcast_ctx = context;
	bcopy(addr, &ibmcastp->mcast_addr, sizeof (struct sockaddr));
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "join_mcast: ibmcastp %p",
	    ibmcastp);

	sockaddr2ibtaddr_port(idp, addr, &mcast_addr, NULL);

	/* Check if input @ to rdma_join_mcast is multicast IP @ */
	if (!(mcast_addr.family == AF_INET &&
	    ((htonl(mcast_addr.un.ip4addr) & 0xE0000000) ==
	    0xE0000000))) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "Invalid IP addr specified");
		kmem_free(ibmcastp, sizeof (ibcma_mcast_t));
		return (EINVAL);
	}

	bzero(&mcg_attr, sizeof (mcg_attr));
	if (sol_cma_any_addr(addr)) {
		bzero(&mcast_gid, sizeof (mcast_gid));
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "ANY mcast addr input");
	} else {
		ipaddr2mgid(addr, &mcast_gid_horder, devp->dev_pkey);

		mcast_gid.gid_prefix = htonll(
		    mcast_gid_horder.gid_prefix);
		mcast_gid.gid_guid = htonll(
		    mcast_gid_horder.gid_guid);
	}
	bcopy(&mcast_gid, &(mcg_attr.mc_mgid), sizeof (ib_gid_t));
	mcg_attr.mc_mtu_req.r_selector = IBT_BEST;
	mcg_attr.mc_flow = 0;
	mcg_attr.mc_hop = 0xFF;
	mcg_attr.mc_tclass = 0;
	mcg_attr.mc_sl = 0;
	mcg_attr.mc_pkt_lt_req.p_selector = IBT_BEST;
	mcg_attr.mc_pkey = devp->dev_pkey;
	mcg_attr.mc_rate_req.r_selector = IBT_BEST;
	mcg_attr.mc_join_state = IB_MC_JSTATE_FULL;
	mcg_attr.mc_qkey = RDMA_UDP_QKEY;
	mcg_infop = kmem_zalloc(sizeof (ibt_mcg_info_t), KM_SLEEP);

	status = ibt_join_mcg(ibchanp->chan_devp->dev_sgid,
	    &mcg_attr, mcg_infop, ibcma_multicast_hdlr, ibmcastp);
	if (status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "\t join_mcast : "
		    "ibt_join_mcg failed with status %d", status);
		kmem_free(ibmcastp, sizeof (ibcma_mcast_t));
		return (EINVAL);
	}

	(void) add_genlist(&ibchanp->chan_mcast_list, (uintptr_t)ibmcastp,
	    NULL);
	ibchanp->chan_mcast_cnt++;

	return (0);
}

void
rdma_ib_leave_multicast(struct rdma_cm_id *idp, struct sockaddr *addr)
{
	sol_cma_chan_t	*chanp = (sol_cma_chan_t *)idp;
	ibcma_chan_t	*ibchanp;
	ibcma_mcast_t	*ibmcastp = NULL;
	genlist_entry_t	*entry;
	ib_gid_t	zero_gid;
	ibt_status_t	status;

	ibchanp = &chanp->chan_ib;
	genlist_for_each(entry, &ibchanp->chan_mcast_list) {
		ibmcastp = (ibcma_mcast_t *)entry->data;
		ASSERT(ibmcastp);
		if (bcmp(&ibmcastp->mcast_addr, addr,
		    sizeof (struct sockaddr)) == 0) {
			delete_genlist(&ibchanp->chan_mcast_list, entry);
			break;
		}
		ibmcastp = NULL;
	}
	if (ibmcastp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "leave_mcast: No matching @");
		return;
	}
	ibchanp->chan_mcast_cnt--;
	bzero(&zero_gid, sizeof (ib_gid_t));
	status = ibt_leave_mcg(ibchanp->chan_devp->dev_sgid,
	    ibmcastp->mcast_gid, zero_gid, IB_MC_JSTATE_FULL);
	if (status != IBT_SUCCESS)
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "leave_mcast: "
		    "ibt_leave_mcg failed %d", status);
	kmem_free(ibmcastp, sizeof (ibcma_mcast_t));
}

/* Local Functions */
#define	SOL_REQ_PRIV_DATA_SZ	96
static int
ibcma_tcp_connect(struct rdma_cm_id *idp, ibcma_chan_t *ibchanp,
    struct rdma_conn_param *conn_paramp)
{
	sol_cma_chan_t		*chanp = (sol_cma_chan_t *)idp;
	ibt_chan_open_flags_t	flags;
	ibt_chan_open_args_t	args;
	ibt_status_t		status;
	ibt_ip_cm_info_t	ipcm_info;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "tcp_connect(%p, %p, %p)", idp,
	    ibchanp, conn_paramp);
	bzero(&args, sizeof (args));
	args.oc_path_retry_cnt = conn_paramp->retry_count;
	args.oc_path_rnr_retry_cnt = conn_paramp->rnr_retry_count;
	flags = IBT_OCHAN_OFUV;
	args.oc_path = ibchanp->chan_pathp;
	(args.oc_path)->pi_sid = ibchanp->chan_sid;
	args.oc_cm_handler =  ibcma_rc_hdlr;
	args.oc_cm_clnt_private = idp;
	args.oc_rdma_ra_out = conn_paramp->initiator_depth;
	args.oc_rdma_ra_in = conn_paramp->responder_resources;
	args.oc_priv_data_len = IBT_IP_HDR_PRIV_DATA_SZ +
	    conn_paramp->private_data_len;
	args.oc_priv_data = kmem_zalloc(SOL_REQ_PRIV_DATA_SZ, KM_SLEEP);

	bcopy(&ibchanp->chan_local_addr, &ipcm_info.src_addr,
	    sizeof (ibt_ip_addr_t));
	bcopy(&ibchanp->chan_remote_addr, &ipcm_info.dst_addr,
	    sizeof (ibt_ip_addr_t));
	ipcm_info.src_port = ibchanp->chan_port;
	status = ibt_format_ip_private_data(&ipcm_info, args.oc_priv_data_len,
	    args.oc_priv_data);
	if (status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "ibt_format_ip_private_data failed!!");
		kmem_free(args.oc_priv_data, SOL_REQ_PRIV_DATA_SZ);
		return (EINVAL);
	}

	if (conn_paramp->private_data_len) {
		void	*dest;

		dest = (void *)((uint8_t *)args.oc_priv_data +
		    IBT_IP_HDR_PRIV_DATA_SZ);
		bcopy(conn_paramp->private_data, dest,
		    conn_paramp->private_data_len);
	}

	/*
	 * Set the RDMA related flags for this QP, if required.
	 */
	if (conn_paramp->initiator_depth || conn_paramp->responder_resources) {
		ibt_cep_modify_flags_t	cep_flags = IBT_CEP_SET_NOTHING;
		ibt_cep_flags_t		flags = IBT_CEP_NO_FLAGS;

		if (conn_paramp->initiator_depth) {
			cep_flags |= IBT_CEP_SET_RDMA_R;
			flags |= IBT_CEP_RDMA_RD;
		}
		if (conn_paramp->responder_resources) {
			cep_flags |= IBT_CEP_SET_RDMA_W;
			flags |= IBT_CEP_RDMA_WR;
		}

		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "tcp_connect: Calling  ibt_modify_rdma(%p, %x)",
		    chanp->chan_qp_hdl, cep_flags);
		status = ibt_modify_rdma(chanp->chan_qp_hdl,
		    cep_flags, flags);
		if (status != IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "tcp_connect: "
			    "ibt_open_rdma failed %x", status);
			kmem_free(args.oc_priv_data, SOL_REQ_PRIV_DATA_SZ);
			return (EINVAL);
		}
	}

	dump_priv_data(args.oc_priv_data, SOL_REQ_PRIV_DATA_SZ,
	    args.oc_priv_data_len, "tcp_connect");
	chanp->chan_connect_flag = SOL_CMA_CONNECT_INITIATED;
	status = ibt_open_rc_channel(chanp->chan_qp_hdl, flags,
	    IBT_NONBLOCKING, &args, NULL);
	if (status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "tcp_connect: ibv_open_rc_channel failed %x",
		    status);
		kmem_free(args.oc_priv_data, SOL_REQ_PRIV_DATA_SZ);
		chanp->chan_connect_flag = SOL_CMA_CONNECT_NONE;
		return (EINVAL);
	}
	kmem_free(args.oc_priv_data, SOL_REQ_PRIV_DATA_SZ);

	return (0);
}

static int
ibcma_udp_connect(struct rdma_cm_id *idp, ibcma_chan_t *ibchanp,
    struct rdma_conn_param *conn_paramp)
{
	ibt_status_t		status;
	ibt_ud_dest_attr_t	attr;
	ibt_path_info_t		*pathp;
	ibt_adds_vect_t		*addr_vect;
	ibcma_dev_t		*devp;
	ibt_ip_cm_info_t	ipcm_info;
	sol_cma_chan_t		*chanp = (sol_cma_chan_t *)idp;

	devp = ibchanp->chan_devp;
	ASSERT(devp);

	/* We always select the first path */
	pathp = ibchanp->chan_pathp;
	addr_vect = &((pathp->pi_prim_cep_path).cep_adds_vect);

	bzero(&attr, sizeof (attr));
	attr.ud_pkey_ix = devp->dev_pkey_ix;
	attr.ud_cm_handler = ibcma_ud_hdlr;
	attr.ud_cm_private = idp;
	attr.ud_priv_data_len = IBT_IP_HDR_PRIV_DATA_SZ +
	    conn_paramp->private_data_len;
	attr.ud_priv_data = kmem_zalloc(attr.ud_priv_data_len, KM_SLEEP);
	if (conn_paramp->private_data_len) {
		bcopy(conn_paramp->private_data,
		    (void *)(((char *)attr.ud_priv_data) +
		    IBT_IP_HDR_PRIV_DATA_SZ),
		    conn_paramp->private_data_len);
	}

	bcopy((void *)&ibchanp->chan_local_addr, &ipcm_info.src_addr,
	    sizeof (ibt_ip_addr_t));
	bcopy((void *)&ibchanp->chan_remote_addr, &ipcm_info.dst_addr,
	    sizeof (ibt_ip_addr_t));
	ipcm_info.src_port = ibchanp->chan_port;
	status = ibt_format_ip_private_data(&ipcm_info, attr.ud_priv_data_len,
	    attr.ud_priv_data);
	if (status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "\tibudp_connect: "
		    "ibt_format_ip_private_data() failed with status %d",
		    status);
		kmem_free(attr.ud_priv_data, attr.ud_priv_data_len);
		return (EINVAL);
	}
	attr.ud_sid = ibchanp->chan_sid;
	attr.ud_addr = addr_vect;

	chanp->chan_connect_flag = SOL_CMA_CONNECT_INITIATED;
	status = ibt_ud_get_dqpn(&attr, IBT_NONBLOCKING, NULL);

	if (status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "\tibudp_connect: "
		    "ibt_ud_get_dqpn failed with status %x", status);
		kmem_free(attr.ud_priv_data, attr.ud_priv_data_len);
		chanp->chan_connect_flag = SOL_CMA_CONNECT_NONE;
		return (EINVAL);
	}

	kmem_free(attr.ud_priv_data, attr.ud_priv_data_len);

	return (0);
}

static int
ibcma_init_devinfo(struct rdma_cm_id *idp, ibcma_chan_t	*ibchanp,
    ibt_path_info_t *pathp)
{
	ibcma_dev_t		*devp;
	ibt_status_t		status;
	uint_t			nports, psize;
	ib_pkey_t		pkey;
	ibt_hca_portinfo_t	*pinfop;

	if (ibchanp->chan_devp)
		return (-1);

	/* Get the port_info and the pkey */
	status = ibt_query_hca_ports_byguid(pathp->pi_hca_guid,
	    pathp->pi_prim_cep_path.cep_hca_port_num,
	    &pinfop, &nports, &psize);
	if (status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "init_devinfo - "
		    "query_hca_port failed rc %d", status);
		return (-1);
	} else {
		int	index;

		index = pathp->pi_prim_cep_path.cep_pkey_ix;
		pkey = (pinfop->p_pkey_tbl)[index];
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "init_devinfo - pkey %x",
		    pkey);
		ibt_free_portinfo(pinfop, psize);
	}
	devp = kmem_zalloc(sizeof (ibcma_dev_t), KM_SLEEP);
	ibchanp->chan_devp = devp;
	devp->dev_node_guid = pathp->pi_hca_guid;
	devp->dev_port_num = pathp->pi_prim_cep_path.cep_hca_port_num;
	devp->dev_pkey_ix = pathp->pi_prim_cep_path.cep_pkey_ix;
	devp->dev_pkey = pkey;
	devp->dev_sgid = pathp->pi_prim_cep_path.cep_adds_vect.av_sgid;

	idp->device = sol_cma_acquire_device(ntohll(devp->dev_node_guid));
	idp->port_num = devp->dev_port_num;
	return (0);
}

static int
ibcma_query_local_ip(struct rdma_cm_id *idp, sol_cma_chan_t *chanp,
    ibcma_chan_t *ibchanp)
{
	ibt_status_t		status;
	ibt_ip_addr_t		*local_addrp;
	ibt_ip_path_attr_t	path_attr;
	ibt_path_info_t		local_path;

	if (ibchanp->chan_pathp != NULL) {
		return (0);
	}
	local_addrp = &ibchanp->chan_local_addr;
	bzero(&path_attr, sizeof (path_attr));
	path_attr.ipa_dst_ip = local_addrp;
	bcopy(local_addrp, &path_attr.ipa_src_ip, sizeof (ibt_ip_addr_t));
	path_attr.ipa_ndst = 1;
	path_attr.ipa_max_paths = 1;

	if ((status = ibt_get_ip_paths(chanp->chan_ib_client_hdl,
	    IBT_PATH_NO_FLAGS, &path_attr, &local_path, NULL, NULL)) !=
	    IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "ib_cma_get_devinfo:status %d,  %p not IB IP @",
		    status, local_addrp);
		return (EINVAL);
	}
	if (ibcma_init_devinfo(idp, ibchanp, &local_path)) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "ib_cma_get_devinfo:init_devinfo failed");
		return (EINVAL);
	}

	return (0);
}

static int
ibcma_get_paths(struct rdma_cm_id *idp, sol_cma_chan_t *chanp,
    ibcma_chan_t *ibchanp)
{
	ibt_ip_path_attr_t	path_attr;
	ibt_status_t		status;
	ibt_path_ip_src_t	*src_ip_p = NULL;
	uint8_t			max_paths;
	ibcma_dev_t		*devp;
	ibt_ip_addr_t		*dst_addrp;
	ib_lid_t		base_lid;
	int			i;

	ASSERT(ibchanp);

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "ibcma_get_paths(%p, %p)", idp,
	    ibchanp);
	max_paths = 2;
	ibchanp->chan_path_size = max_paths * sizeof (ibt_path_info_t);
	ibchanp->chan_pathp = kmem_zalloc(ibchanp->chan_path_size, KM_SLEEP);

	devp = ibchanp->chan_devp;
	if (devp == NULL) {
		src_ip_p = kmem_zalloc(sizeof (ibt_path_ip_src_t) * max_paths,
		    KM_SLEEP);
	}
	bzero(&path_attr, sizeof (ibt_ip_path_attr_t));
	dst_addrp = kmem_zalloc(sizeof (ibt_ip_addr_t), KM_SLEEP);
	bcopy(&ibchanp->chan_remote_addr, dst_addrp, sizeof (ibt_ip_addr_t));
	path_attr.ipa_dst_ip = dst_addrp;
	bcopy(&ibchanp->chan_local_addr, &path_attr.ipa_src_ip,
	    sizeof (ibt_ip_addr_t));
	path_attr.ipa_ndst = 1;
	path_attr.ipa_max_paths = max_paths;
	if (ibcma_any_addr(&path_attr.ipa_src_ip))
		path_attr.ipa_src_ip.family = AF_UNSPEC;

	status = ibt_get_ip_paths(chanp->chan_ib_client_hdl, IBT_PATH_NO_FLAGS,
	    &path_attr, ibchanp->chan_pathp, &ibchanp->chan_numpaths,
	    src_ip_p);
	if (status != IBT_SUCCESS && status != IBT_INSUFF_DATA) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "cma_get_paths : failed %d", status);
		kmem_free(dst_addrp, sizeof (ibt_ip_addr_t));
		if (src_ip_p)
			kmem_free(src_ip_p,
			    sizeof (ibt_path_ip_src_t) * max_paths);
		kmem_free(ibchanp->chan_pathp, ibchanp->chan_path_size);
		ibchanp->chan_pathp = NULL;
		return (EINVAL);
	}

	if (src_ip_p) {
		ipaddr2sockaddr(&(src_ip_p[0].ip_primary),
		    &(idp->route.addr.src_addr), NULL);
		bcopy(&(src_ip_p[0].ip_primary), &ibchanp->chan_local_addr,
		    sizeof (ibt_ip_addr_t));
		if (ibcma_init_devinfo(idp, ibchanp, ibchanp->chan_pathp)) {
			kmem_free(src_ip_p, sizeof (ibt_path_ip_src_t) *
			    max_paths);
			kmem_free(dst_addrp, sizeof (ibt_ip_addr_t));
			kmem_free(ibchanp->chan_pathp,
			    ibchanp->chan_path_size);
			return (EINVAL);
		}
		kmem_free(src_ip_p, sizeof (ibt_path_ip_src_t) * max_paths);
	}
	if (!ibchanp->chan_devp) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "cma_get_paths : devp ERROR");
		kmem_free(dst_addrp, sizeof (ibt_ip_addr_t));
		return (EINVAL);
	}
	devp = ibchanp->chan_devp;
	(idp->route).num_paths = ibchanp->chan_numpaths;
	idp->route.path_rec = kmem_zalloc(sizeof (struct ib_sa_path_rec) *
	    ibchanp->chan_numpaths, KM_SLEEP);
	base_lid = ibt_get_port_state_byguid(devp->dev_node_guid,
	    devp->dev_port_num, NULL, &base_lid);
	for (i = 0; i < ibchanp->chan_numpaths; i++)
		ibt_path2sa_path(&((ibchanp->chan_pathp)[i]),
		    &((idp->route.path_rec)[i]), base_lid);

	kmem_free(dst_addrp, sizeof (ibt_ip_addr_t));
	return (0);
}

/*
 * Solaris Event Handlers
 */

/* UD Event Handler */
/*ARGSUSED*/
static ibt_cm_status_t
ibcma_ud_hdlr(void *inp, ibt_cm_ud_event_t *eventp,
    ibt_cm_ud_return_args_t *ret_args, void *priv_data,
    ibt_priv_data_len_t priv_datalen)
{
	struct rdma_cm_id	*root_idp, *event_idp, *idp;
	sol_cma_chan_t		*root_chanp, *chanp, *event_chanp;
	ibcma_chan_t		*ibchanp, *event_ibchanp;
	struct rdma_ud_param	ud_param, *ud_paramp = &ud_param;
	enum rdma_cm_event_type event;
	int			evt_status = -1;
	ibt_priv_data_len_t	cm_privlen;
	void			*cm_priv;
	ibt_status_t		ibt_status;
	ibt_ip_cm_info_t	info;
	cma_chan_state_t	chan_state;

	event_idp = idp = (struct rdma_cm_id *)inp;
	chanp = (sol_cma_chan_t *)idp;
	ibchanp = &chanp->chan_ib;
	root_idp = CHAN_LISTEN_ROOT(chanp);
	root_chanp = (sol_cma_chan_t *)root_idp;
	SOL_OFS_DPRINTF_L3(sol_rdmacm_dbg_str, "cma_ud_hdlr(%p, %p)",
	    inp, eventp);

	bzero(&ud_param, sizeof (struct rdma_ud_param));
	cm_privlen = eventp->cm_priv_data_len;
	cm_priv = eventp->cm_priv_data;
	if (eventp->cm_type == IBT_CM_UD_EVENT_SIDR_REQ) {
		ibt_cm_sidr_req_t	*sidr_req;
		void			*find_ret;
		avl_index_t		where;

		ASSERT(root_chanp);

		/*
		 * Reject further REQs if destroy of listen CMID
		 * has been called.
		 */
		mutex_enter(&root_chanp->chan_mutex);
		chan_state = cma_get_chan_state(root_chanp);
		mutex_exit(&root_chanp->chan_mutex);
		if (chan_state == SOL_CMA_CHAN_DESTROY_PENDING ||
		    chan_state == SOL_CMA_CHAN_DESTROY_WAIT) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "UD Req Hdlr, "
			    "listen CMID destroy called");
			return (IBT_CM_REJECT);
		}

		sidr_req = &((eventp->cm_event).sidr_req);
		SOL_OFS_DPRINTF_L4(sol_rdmacm_dbg_str, "SIDR REQ");

		if (cm_privlen < IBT_IP_HDR_PRIV_DATA_SZ) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "UD Req Hdlr, "
			    "Priv data len %x < %x", cm_privlen,
			    IBT_IP_HDR_PRIV_DATA_SZ);
			return (IBT_CM_REJECT);
		}
		ibt_status = ibt_get_ip_data(cm_privlen, cm_priv, &info);
		if (ibt_status != IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "UD Req Hdlr, "
			    "ibt_get_ip_data failed, %x", ibt_status);
			return (IBT_CM_REJECT);
		}
		cm_privlen -= IBT_IP_HDR_PRIV_DATA_SZ;
		cm_priv = (void *)(((uchar_t *)cm_priv) +
		    IBT_IP_HDR_PRIV_DATA_SZ);

		event_idp = ibcma_create_new_id(idp);
		if (event_idp == NULL) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "create_new_id failed!!");
			return (IBT_CM_REJECT);
		}
		event_idp->device = sol_cma_acquire_device(ntohll(
		    sidr_req->sreq_hca_guid));
		event_idp->port_num = sidr_req->sreq_hca_port;
		(event_idp->route).num_paths = 0;

		event_chanp = (sol_cma_chan_t *)event_idp;
		event_chanp->chan_req_state = REQ_CMID_CREATED;
		event_ibchanp = &event_chanp->chan_ib;
		event_chanp->chan_session_id = eventp->cm_session_id;
		event_chanp->chan_connect_flag =
		    SOL_CMA_CONNECT_SERVER_RCVD;
		bcopy(&info.src_addr, &event_ibchanp->chan_remote_addr,
		    sizeof (ibt_ip_addr_t));
		ipaddr2sockaddr(&info.src_addr,
		    &(event_idp->route.addr.dst_addr), &info.src_port);

		/*
		 * Increment number of Reqs for listening CMID,
		 * so that listening CMID is not deleted, till this
		 * connection expects no more events.
		 * chan_req_cnt is decremented connection is
		 * notified to the consumer.
		 *
		 * Insert the CMID into the REQ_AVL_TREE. This is
		 * deleted when the connection is accepted or rejected.
		 */
		mutex_enter(&root_chanp->chan_mutex);
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "Add to REQ AVL of %p IDP, idp %p, session_id %p",
		    root_idp, event_idp, event_chanp->chan_session_id);
		find_ret = avl_find(&root_chanp->chan_req_avl_tree,
		    (void *)event_chanp->chan_session_id, &where);
		if (find_ret) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "DUPLICATE ENTRY in REQ AVL : root %p, "
			    "idp %p, session_id %p",
			    root_idp, event_idp,
			    event_chanp->chan_session_id);
			mutex_exit(&root_chanp->chan_mutex);
			rdma_destroy_id(event_idp);
			return (IBT_CM_REJECT);
		}
		root_chanp->chan_req_cnt++;
		root_chanp->chan_req_state = REQ_CMID_CREATED;
		root_chanp->chan_req_total_cnt++;
		avl_insert(&root_chanp->chan_req_avl_tree,
		    (void *)event_idp, where);
		mutex_exit(&root_chanp->chan_mutex);

		event = RDMA_CM_EVENT_CONNECT_REQUEST;
		evt_status = 0;
	} else if (eventp->cm_type == IBT_CM_UD_EVENT_SIDR_REP) {
		ibt_cm_sidr_rep_t	*sidr_rep;

		ASSERT(chanp->chan_connect_flag == SOL_CMA_CONNECT_INITIATED);
		mutex_enter(&chanp->chan_mutex);
		chanp->chan_connect_flag = SOL_CMA_CONNECT_NONE;
		mutex_exit(&chanp->chan_mutex);
		sidr_rep = &((eventp->cm_event).sidr_rep);
		if (sidr_rep->srep_status == IBT_CM_SREP_CHAN_VALID) {
			evt_status = 0;
			event = RDMA_CM_EVENT_ESTABLISHED;
			ud_paramp->qp_num = sidr_rep->srep_remote_qpn;
			ud_paramp->qkey = sidr_rep->srep_remote_qkey;
			ibt_path2ah(ibchanp->chan_pathp, &ud_paramp->ah_attr);
		} else {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "SIDR Response err with status %x",
			    sidr_rep->srep_status);
			event = RDMA_CM_EVENT_UNREACHABLE;
			evt_status = sidr_rep->srep_status;
			goto ud_gen_event;
		}
	}

	ud_paramp->private_data_len = cm_privlen;
	if (evt_status == 0 && cm_privlen) {
		ud_paramp->private_data = kmem_zalloc(cm_privlen, KM_SLEEP);
		bcopy(cm_priv, (void *)ud_paramp->private_data,
		    cm_privlen);
#ifdef DEBUG
		dump_priv_data((void *)ud_paramp->private_data,
		    SOL_REP_PRIV_DATA_SZ, cm_privlen, "ibcma_ud_hdlr");
#endif
	}

ud_gen_event:
	/* Pass back the event to sol_cma consumer */
	cma_generate_event(event_idp, event, evt_status, NULL, ud_paramp);

	if (ud_paramp->private_data)
		kmem_free((void *)ud_paramp->private_data, cm_privlen);

	if (eventp->cm_type == IBT_CM_UD_EVENT_SIDR_REQ)
		return (IBT_CM_DEFER);
	else
		return (IBT_CM_DEFAULT);
}

static ibt_cm_status_t
ibcma_handle_req(struct rdma_cm_id *idp, struct rdma_cm_id **event_id_ptr,
    ibt_cm_event_t *eventp, struct rdma_conn_param *paramp,
    enum rdma_cm_event_type *event, int *evt_status)
{
	struct rdma_cm_id	*root_idp, *event_idp;
	sol_cma_chan_t		*root_chanp, *event_chanp, *chanp;
	ibcma_chan_t		*event_ibchanp, *ibchanp;
	ibt_status_t		ibt_status;
	ibt_cm_req_rcv_t	*reqp;
	ibt_priv_data_len_t	cm_privlen;
	ibt_ofuvcm_req_data_t	rtr_data;
	ibt_ip_cm_info_t	info;
	void			*cm_priv, *priv_data;
	ib_lid_t		base_lid;
	void			*find_ret;
	avl_index_t		where;
	cma_chan_state_t	chan_state;
#ifdef  DEBUG
	void			*dump_priv;
#endif

	chanp = (sol_cma_chan_t *)idp;
	ibchanp = &chanp->chan_ib;
	root_idp = CHAN_LISTEN_ROOT(chanp);
	root_chanp = (sol_cma_chan_t *)root_idp;
	ASSERT(chanp->chan_listenp);
	ASSERT(root_idp);

	/*
	 * Reject further REQs if destroy of listen CMID
	 * has been called.
	 */
	mutex_enter(&root_chanp->chan_mutex);
	chan_state = cma_get_chan_state(root_chanp);
	mutex_exit(&root_chanp->chan_mutex);
	if (chan_state == SOL_CMA_CHAN_DESTROY_PENDING ||
	    chan_state == SOL_CMA_CHAN_DESTROY_WAIT) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "RC Req Hdlr, "
		    "listen CMID destroy called");
		return (IBT_CM_REJECT);
	}

	*event = RDMA_CM_EVENT_CONNECT_REQUEST;
	*evt_status = 0;
	reqp = &(eventp->cm_event.req);
	paramp->qp_num = reqp->req_remote_qpn;
	paramp->srq = (reqp->req_flags & IBT_CM_SRQ_EXISTS) ? 1 : 0;
	paramp->responder_resources = reqp->req_rdma_ra_in;
	paramp->initiator_depth = reqp->req_rdma_ra_out;
	paramp->flow_control = (reqp->req_flags & IBT_CM_FLOW_CONTROL)
	    ? 1 : 0;
	paramp->retry_count = reqp->req_retry_cnt;
	paramp->rnr_retry_count = reqp->req_rnr_retry_cnt;

#ifdef	DEBUG
	dump_priv = kmem_zalloc(SOL_REQ_PRIV_DATA_SZ, KM_SLEEP);
	bcopy(eventp->cm_priv_data, dump_priv, eventp->cm_priv_data_len);
	dump_priv_data(dump_priv, SOL_REQ_PRIV_DATA_SZ,
	    eventp->cm_priv_data_len, "handle_req");
	kmem_free(dump_priv, SOL_REQ_PRIV_DATA_SZ);
#endif	/* DEBUG */

	cm_privlen = eventp->cm_priv_data_len;
	cm_priv = eventp->cm_priv_data;
	if (cm_privlen < IBT_IP_HDR_PRIV_DATA_SZ) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "RC Req Hdlr, "
		    "Priv data len %x < %x", cm_privlen,
		    IBT_IP_HDR_PRIV_DATA_SZ);
		return (IBT_CM_REJECT);
	}
	ibt_status = ibt_get_ip_data(cm_privlen, cm_priv, &info);
	if (ibt_status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "RC Req Hdlr, "
		    "ibt_get_ip_data failed, %x", ibt_status);
		return (IBT_CM_REJECT);
	}
	bcopy(&info.dst_addr, &ibchanp->chan_remote_addr,
	    sizeof (ibt_ip_addr_t));

	ibt_status = ibt_ofuvcm_get_req_data(eventp->cm_session_id, &rtr_data);
	if (ibt_status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "RC Req Hdlr, "
		    "ibt_ofuvcm_get_req_data failed, %x", ibt_status);
		return (IBT_CM_REJECT);
	}

	paramp->private_data_len = cm_privlen - IBT_IP_HDR_PRIV_DATA_SZ;
	if (paramp->private_data_len) {
		priv_data = (void *)((uint8_t *)cm_priv +
		    IBT_IP_HDR_PRIV_DATA_SZ);
		paramp->private_data = kmem_zalloc(paramp->private_data_len,
		    KM_SLEEP);
		bcopy(priv_data, (void *)paramp->private_data,
		    paramp->private_data_len);
	}
	event_idp = ibcma_create_new_id(idp);
	if (event_idp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "create_new_id failed!!");
		if (paramp->private_data)
			kmem_free((void *)paramp->private_data,
			    paramp->private_data_len);
		return (IBT_CM_REJECT);
	}

	/*
	 * Fill the route, device and port_num.
	 * TBD - Fill up packet_life_time
	 */
	event_idp->device = sol_cma_acquire_device(ntohll(
	    reqp->req_hca_guid));
	event_idp->port_num = reqp->req_prim_hca_port;
	(event_idp->route).num_paths = reqp->req_alt_hca_port ? 2 : 1;
	event_idp->route.path_rec = kmem_zalloc(
	    sizeof (struct ib_sa_path_rec) * ((event_idp->route).num_paths),
	    KM_SLEEP);
	base_lid = ibt_get_port_state_byguid(reqp->req_hca_guid,
	    reqp->req_prim_hca_port, NULL, &base_lid);
	ibt_addsvect2sa_path(&reqp->req_prim_addr,
	    &(event_idp->route.path_rec[0]), base_lid);
	(event_idp->route.path_rec[0]).mtu = (uint8_t)rtr_data.req_path_mtu;
	if (reqp->req_alt_hca_port) {
		base_lid = ibt_get_port_state_byguid(
		    reqp->req_hca_guid, reqp->req_alt_hca_port,
		    NULL, &base_lid);
		ibt_addsvect2sa_path(&reqp->req_alt_addr,
		    &(event_idp->route.path_rec[1]), base_lid);
		(event_idp->route.path_rec[1]).mtu =
		    (uint8_t)rtr_data.req_path_mtu;
	}

	*event_id_ptr = event_idp;

	event_chanp = (sol_cma_chan_t *)event_idp;
	event_chanp->chan_req_state = REQ_CMID_CREATED;
	event_ibchanp = &event_chanp->chan_ib;
	event_chanp->chan_session_id = eventp->cm_session_id;
	event_chanp->chan_connect_flag = SOL_CMA_CONNECT_SERVER_RCVD;
	bcopy((void *)(&reqp->req_prim_addr),
	    (void *)(&event_ibchanp->chan_rcreq_addr),
	    sizeof (ibt_adds_vect_t));
	bcopy(&rtr_data, &(event_ibchanp->chan_rtr_data),
	    sizeof (ibt_ofuvcm_req_data_t));
	event_ibchanp->chan_rcreq_qpn = reqp->req_remote_qpn;
	event_ibchanp->chan_rcreq_ra_in = reqp->req_rdma_ra_in;

	/*
	 * Increment number of Reqs for listening CMID, so that
	 * listening CMID is not deleted, till this connection
	 * expects no more events. chan_req_cnt is decremented
	 * when connection is notified to the consumer.
	 *
	 * Insert the CMID into the REQ_AVL_TREE. This is
	 * deleted when the connection is accepted or rejected.
	 */
	mutex_enter(&root_chanp->chan_mutex);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "Add to REQ AVL of %p IDP, idp %p, session_id %p",
	    root_idp, event_idp, event_chanp->chan_session_id);
	find_ret = avl_find(&root_chanp->chan_req_avl_tree,
	    (void *)event_chanp->chan_session_id, &where);
	if (find_ret) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "DUPLICATE ENTRY in REQ AVL : root %p, "
		    "idp %p, session_id %p",
		    root_idp, event_idp,
		    event_chanp->chan_session_id);
		mutex_exit(&root_chanp->chan_mutex);
		rdma_destroy_id(event_idp);
		return (IBT_CM_REJECT);
	}
	root_chanp->chan_req_cnt++;
	root_chanp->chan_req_state = REQ_CMID_CREATED;
	root_chanp->chan_req_total_cnt++;
	avl_insert(&root_chanp->chan_req_avl_tree, (void *)event_idp, where);
	mutex_exit(&root_chanp->chan_mutex);

	return (IBT_CM_DEFER);
}

static void
ibcma_handle_rep(struct rdma_cm_id *idp, ibt_cm_event_t *eventp)
{
	sol_cma_chan_t		*chanp;
	ibt_cm_rep_rcv_t	*repp;
	struct rdma_conn_param	*paramp;

	chanp = (sol_cma_chan_t *)idp;

	paramp = &chanp->chan_param;
	bzero(paramp, sizeof (chanp->chan_param));
	repp = &((eventp->cm_event).rep);
	paramp->srq = (repp->rep_flags & IBT_CM_SRQ_EXISTS) ? 1 : 0;
	paramp->responder_resources = repp->rep_rdma_ra_in;
	paramp->initiator_depth = repp->rep_rdma_ra_out;
	paramp->flow_control = (repp->rep_flags & IBT_CM_FLOW_CONTROL) ? 1 : 0;

#ifdef DEBUG
	dump_priv_data(eventp->cm_priv_data, SOL_REP_PRIV_DATA_SZ,
	    eventp->cm_priv_data_len, "handle_rep");
#endif
	paramp->private_data_len =  eventp->cm_priv_data_len;
	if (paramp->private_data_len) {
		paramp->private_data = kmem_zalloc(paramp->private_data_len,
		    KM_SLEEP);
		bcopy((void *)eventp->cm_priv_data,
		    (void *)paramp->private_data, paramp->private_data_len);
	}
}

static ibt_cm_status_t
ibcma_handle_est(struct rdma_cm_id *idp, struct rdma_cm_id **event_id_ptr,
    ibt_cm_event_t *eventp, struct rdma_conn_param *paramp,
    enum rdma_cm_event_type *event, int *evt_status)
{
	struct rdma_cm_id	*event_idp, *root_idp;
	sol_cma_chan_t		*event_chanp, *chanp, *root_chanp;
	ibcma_chan_t		*event_ibchanp;

	/* Established event on active / client side */
	chanp = (sol_cma_chan_t *)idp;
	if (chanp->chan_listenp == NULL) {
		ASSERT(chanp->chan_connect_flag == SOL_CMA_CONNECT_INITIATED);
		chanp->chan_connect_flag = SOL_CMA_CONNECT_CLIENT_DONE;
		bcopy(&chanp->chan_param, paramp,
		    sizeof (struct rdma_conn_param));
		if (paramp->private_data_len) {
			paramp->private_data = kmem_zalloc(
			    paramp->private_data_len, KM_SLEEP);
			bcopy((void *)((chanp->chan_param).private_data),
			    (void *)paramp->private_data,
			    paramp->private_data_len);
			kmem_free((void *)((chanp->chan_param).private_data),
			    paramp->private_data_len);
		}
		event_chanp = chanp;
		goto est_common;
	}

	root_idp = CHAN_LISTEN_ROOT((chanp));
	ASSERT(root_idp);
	root_chanp = (sol_cma_chan_t *)root_idp;
	event_chanp = NULL;

	event_idp = cma_get_acpt_idp(root_idp, eventp->cm_channel);
	if (event_idp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str, "ibcma_handle_est: "
		    "No matching CMID for qp_hdl %p in ACPT AVL of CMID %p",
		    eventp->cm_channel, root_chanp);
		return (IBT_CM_REJECT);
	}
	*event_id_ptr = event_idp;
	event_chanp = (sol_cma_chan_t *)event_idp;
	event_chanp->chan_connect_flag = SOL_CMA_CONNECT_SERVER_DONE;

est_common:
#ifdef QP_DEBUG
	dump_qp_info(event_chanp->chan_qp_hdl);
#endif

	/*
	 * Pass back CONNECT_ESTABLISHED event to consumer.
	 */
	*event = RDMA_CM_EVENT_ESTABLISHED;
	event_ibchanp = &event_chanp->chan_ib;
	event_ibchanp->chan_qpmodifyflag  = 1;

	*evt_status = 0;
	return (IBT_CM_DEFAULT);
}

static ibt_cm_status_t
ibcma_handle_closed(struct rdma_cm_id *idp, struct rdma_cm_id **event_id_ptr,
    ibt_cm_event_t *eventp, enum rdma_cm_event_type *event, int *evt_status)
{
	struct rdma_cm_id	*root_idp, *event_idp;
	sol_cma_chan_t		*chanp, *event_chanp;

	*event = RDMA_CM_EVENT_DISCONNECTED;
	*evt_status = 0;
	chanp = (sol_cma_chan_t *)idp;
	mutex_enter(&chanp->chan_mutex);
	root_idp = CHAN_LISTEN_ROOT((chanp));
	chanp->chan_qp_hdl = NULL;
	if (!root_idp) {
		chanp->chan_connect_flag = 0;
		mutex_exit(&chanp->chan_mutex);
		return (IBT_CM_DEFAULT);
	}
	mutex_exit(&chanp->chan_mutex);

	/* On the passive side, search ACPT AVL Tree */
	event_idp = cma_get_acpt_idp(root_idp, eventp->cm_channel);
	if (event_idp == NULL) {
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "ibcma_handle_closed: "
		    "No matching CMID for qp hdl %p in EST AVL of CMID %p",
		    eventp->cm_channel, root_idp);
		return (IBT_CM_DEFAULT);
	}
	event_chanp = (sol_cma_chan_t *)event_idp;
	mutex_enter(&event_chanp->chan_mutex);
	event_chanp->chan_connect_flag = SOL_CMA_CONNECT_NONE;
	mutex_exit(&event_chanp->chan_mutex);
	*event_id_ptr = event_idp;
	return (IBT_CM_DEFAULT);
}

static ibt_cm_status_t
ibcma_handle_failed(struct rdma_cm_id *idp, struct rdma_cm_id **event_id_ptr,
    ibt_cm_event_t *eventp, struct rdma_conn_param *paramp,
    enum rdma_cm_event_type *event, int *evt_status)
{

	struct rdma_cm_id	*root_idp, *event_idp;
	sol_cma_chan_t		*event_chanp, *chanp, *root_chanp;
	ibt_cm_conn_failed_t	*failedp;

	failedp = &(eventp->cm_event.failed);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "ibcma_handle_failed - idp %p, "
	    "cf_code %x, cf_msg %x, cf_arej_info_valid %x, cf_reason %x",
	    idp, failedp->cf_code, failedp->cf_msg,
	    failedp->cf_arej_info_valid, failedp->cf_reason);
	chanp = (sol_cma_chan_t *)idp;
	root_idp = CHAN_LISTEN_ROOT((chanp));
	root_chanp = (sol_cma_chan_t *)root_idp;

	*evt_status = 0;
	switch (failedp->cf_code) {
	case IBT_CM_FAILURE_REJ_SENT :
		/*  Reject sent. No event to userland. */
		break;

	case IBT_CM_FAILURE_REJ_RCV :
		/*
		 * Reject recieved. If this is a consumer reject, copy the
		 * private * data. Send RDMA_CM_EVENT_REJECTED to user land.
		 */
		if (failedp->cf_reason == IBT_CM_CONSUMER &&
		    eventp->cm_priv_data_len) {
			paramp->private_data_len = eventp->cm_priv_data_len;
			paramp->private_data = kmem_zalloc(
			    paramp->private_data_len, KM_SLEEP);
			bcopy(eventp->cm_priv_data,
			    (void *)paramp->private_data,
			    paramp->private_data_len);
		}

		/*
		 * If this an REJECT for an accepted CMID, pass the
		 * event to accepted CMID.
		 */
		if (root_idp) {
			ASSERT(eventp->cm_channel);
			event_idp = cma_get_acpt_idp(root_idp,
			    eventp->cm_channel);
			if (event_idp == NULL) {
				SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
				    "ibcma_handle_failed: No matching CMID "
				    "for qp_hdl %p in ACPT AVL of CMID %p",
				    eventp->cm_channel, idp);
				break;
			}

			event_chanp = (sol_cma_chan_t *)event_idp;
			mutex_enter(&event_chanp->chan_mutex);
			event_chanp->chan_connect_flag =
			    SOL_CMA_CONNECT_NONE;
			event_chanp->chan_qp_hdl = NULL;
			mutex_exit(&event_chanp->chan_mutex);
			*event_id_ptr = event_idp;
			mutex_enter(&root_chanp->chan_mutex);
			avl_remove(&root_chanp->chan_acpt_avl_tree,
			    event_idp);
			mutex_exit(&root_chanp->chan_mutex);
		} else
			chanp->chan_connect_flag = SOL_CMA_CONNECT_NONE;
		*evt_status = failedp->cf_reason;
		*event = RDMA_CM_EVENT_REJECTED;
		break;

	case IBT_CM_FAILURE_TIMEOUT :
		/*
		 * Connection Timeout, Send RDMA_CM_EVENT_REJECTED event and
		 * status as IBT_CM_TIMEOUT.
		 */
		if (eventp->cm_session_id && root_idp) {
			event_idp = cma_get_req_idp(root_idp,
			    eventp->cm_session_id);
			if (event_idp == NULL) {
				SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
				    "ibcma_handle_failed: No matching CMID "
				    "for qp_hdl %p in REQ AVL of CMID %p",
				    eventp->cm_session_id, idp);
				break;
			}

			event_chanp = (sol_cma_chan_t *)event_idp;
			mutex_enter(&event_chanp->chan_mutex);
			event_chanp->chan_connect_flag =
			    SOL_CMA_CONNECT_NONE;
			event_chanp->chan_qp_hdl = NULL;
			mutex_exit(&event_chanp->chan_mutex);
			*event_id_ptr = event_idp;
			mutex_enter(&root_chanp->chan_mutex);
			avl_remove(&root_chanp->chan_req_avl_tree,
			    event_idp);
			root_chanp->chan_req_cnt--;
			mutex_exit(&root_chanp->chan_mutex);

			*evt_status = IBT_CM_TIMEOUT;
			*event = RDMA_CM_EVENT_REJECTED;
		}
		if (!eventp->cm_session_id && root_idp) {
			SOL_OFS_DPRINTF_L0(sol_rdmacm_dbg_str,
			    "ibcma_handle_failed: timeout "
			    "session_id NULL");
		}
		if (!root_idp) {
			chanp->chan_connect_flag = SOL_CMA_CONNECT_NONE;
			*evt_status = IBT_CM_TIMEOUT;
			*event = RDMA_CM_EVENT_REJECTED;
		}
		chanp->chan_connect_flag = SOL_CMA_CONNECT_NONE;
		chanp->chan_qp_hdl = NULL;
		break;

	case IBT_CM_FAILURE_STALE :
		/* Stale connection, ignore */
		break;
	}
	return (IBT_CM_DEFAULT);
}

static ibt_cm_status_t
ibcma_rc_hdlr(void *inp, ibt_cm_event_t *eventp,
    ibt_cm_return_args_t *ret_args, void *priv_data,
    ibt_priv_data_len_t priv_datalen)
{
	struct rdma_cm_id	*idp, *event_idp;
	sol_cma_chan_t		*chanp;
	ibt_cm_status_t		status;
	ibt_status_t		ibt_status;
	enum rdma_cm_event_type event;
	struct rdma_conn_param	conn_param, *paramp = &conn_param;
	int	event_status;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "ib_cma_rc_hdlr(%p, %p, %p, "
	    "%p, %x)", inp, eventp, ret_args, priv_data, priv_datalen);
	idp = event_idp = (struct rdma_cm_id *)inp;
	chanp = (sol_cma_chan_t *)idp;
	chanp->chan_session_id = NULL;

	bzero(paramp, sizeof (struct rdma_conn_param));
	switch (eventp->cm_type) {

	case IBT_CM_EVENT_REQ_RCV :
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "ibcma_rc_hdlr : REQ Event");

		/*
		 * We need to do a round trip to userland. Send a MRA
		 * so that the client does not send multiple REQs. Then
		 * continue the processing of REQs.
		 */
		ibt_status =  ibt_cm_delay(IBT_CM_DELAY_REQ,
		    eventp->cm_session_id, SOL_OFS_REQ_DELAY, NULL, 0);
		if (ibt_status != IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "ibcma_rc_hdlr : ibt_cma_delay failed %x",
			    ibt_status);
			return (IBT_CM_REJECT);
		}
		status = ibcma_handle_req(idp, &event_idp, eventp, paramp,
		    &event, &event_status);
		if (status == IBT_CM_REJECT)
			return (status);
		break;
	case IBT_CM_EVENT_REP_RCV :
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "ibcma_rc_hdlr : REP Event");

		ibcma_handle_rep(idp, eventp);
		return (IBT_CM_DEFAULT);
		/* NOTREACHED */
		/* break; */
	case IBT_CM_EVENT_LAP_RCV :
	case IBT_CM_EVENT_APR_RCV :
		/*
		 * Alternate Paths not supported from userland. Return
		 * IBT_CM_REJECT.
		 */
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "ibcma_rc_hdlr : AP Event");
		return (IBT_CM_REJECT);
		/* NOTREACHED */
		/* break; */
	case IBT_CM_EVENT_MRA_RCV :
		/* Let Solaris ibcm take default action for MRA */
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "ibcma_rc_hdlr : MRA Event");
		return (IBT_CM_DEFAULT);
		/* NOTREACHED */
		/* break; */
	case IBT_CM_EVENT_CONN_EST :
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "ibcma_rc_hdlr : EST Event");
		status = ibcma_handle_est(idp, &event_idp, eventp, paramp,
		    &event, &event_status);
		break;
	case IBT_CM_EVENT_CONN_CLOSED :
		/*
		 * Pass on RDMA_CM_EVENT_DISCONNECTED to consumer
		 */
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "ibcma_rc_hdlr : CLOSED Event");
		status = ibcma_handle_closed(idp, &event_idp, eventp,
		    &event, &event_status);
		break;

	case IBT_CM_EVENT_FAILURE :
		/* Handle Failure Event */
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "ibcma_rc_hdlr : FAIL Event");
		status = ibcma_handle_failed(idp, &event_idp, eventp, paramp,
		    &event, &event_status);

		/*
		 * Check if there is an event to be send to the userland.
		 * Return if there are none.
		 */
		if (event_status == 0)
			return (status);
		break;
	}

	/* Pass back the event to sol_cma consumer */
	if (event_idp) {
		cma_generate_event(event_idp, event, event_status,
		    paramp, NULL);
	} else
		SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
		    "No Event to userland!!");
	if (paramp->private_data)
		kmem_free((void *)paramp->private_data,
		    paramp->private_data_len);

	return (status);
}

static void
ibcma_multicast_hdlr(void *arg, ibt_status_t status, ibt_mcg_info_t *mcg_infop)
{
	struct rdma_cm_id	*idp;
	ibcma_mcast_t		*ib_mcastp = (ibcma_mcast_t *)arg;
	int			evt_status;
	struct rdma_ud_param	uddata, *ud_param = &uddata;
	enum rdma_cm_event_type event;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "multicast_hdlr(%p, %x, %p)",
	    arg, status, mcg_infop);
	idp = ib_mcastp->mcast_idp;

	bzero(ud_param, sizeof (struct rdma_ud_param));
	bcopy(&(mcg_infop->mc_adds_vect.av_dgid),
	    &(ib_mcastp->mcast_gid), sizeof (ib_gid_t));
	ud_param->private_data = ib_mcastp->mcast_ctx;

	event = (status == IBT_SUCCESS) ?
	    RDMA_CM_EVENT_MULTICAST_JOIN : RDMA_CM_EVENT_MULTICAST_ERROR;
	evt_status = (status == IBT_SUCCESS) ? 0 : -1;
	if (status == IBT_SUCCESS) {
		mcginfo2ah(mcg_infop, &ud_param->ah_attr);
		ud_param->qp_num = IB_MC_QPN;
		ud_param->qkey = RDMA_UDP_QKEY;
	}

	/* Send the event to consumer of sol_cma.  */
	cma_generate_event(idp, event, evt_status, NULL, ud_param);
	kmem_free(mcg_infop, sizeof (ibt_mcg_info_t));
}

static int
ibcma_get_first_ib_ipaddr(struct rdma_cm_id *idp)
{
	sol_cma_chan_t	*chanp = (sol_cma_chan_t *)idp;
	ibcma_chan_t	*ibchanp;
	int		num_hcas, info_inited = 0;
	ib_guid_t	*hca_guidp;
	genlist_t	devlist;
	genlist_entry_t	*entry;
	ibcma_dev_t	*devp;

	ASSERT(idp);
	ibchanp = &(chanp->chan_ib);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "get_first_ib_ipaddr(%p)", idp);

	num_hcas = ibt_get_hca_list(&hca_guidp);
	ibcma_get_devlist(chanp, hca_guidp, num_hcas, &devlist);
	entry = remove_genlist_head(&devlist);
	while (entry) {
		devp = (ibcma_dev_t *)entry->data;
		if (info_inited == 0) {
			(idp->route).num_paths = 0;
			idp->port_num = devp->dev_port_num;
			chanp->chan_xport_type = SOL_CMA_XPORT_IB;
			ibchanp->chan_devp = devp;
			info_inited = 1;
		} else {
			kmem_free(devp, sizeof (ibcma_dev_t));
		}
		kmem_free(entry, sizeof (genlist_entry_t));
		entry = remove_genlist_head(&devlist);
	}
	ibt_free_hca_list(hca_guidp, num_hcas);

	if (info_inited)
		return (0);
	else
		return (ENODEV);
}

/* Utility Conversion functions */
static void
ipaddr2sockaddr(ibt_ip_addr_t *ibt_addrp, struct sockaddr *sock_addrp,
    in_port_t *portp)
{
		sock_addrp->sa_family = ibt_addrp->family;
		if (ibt_addrp->family == AF_INET) {
			struct sockaddr_in	*sock_in4p;
			sock_in4p = (struct sockaddr_in *)sock_addrp;

			sock_in4p->sin_addr.s_addr = ibt_addrp->un.ip4addr;
			if (portp)
				sock_in4p->sin_port = ntohs(*portp);
		} else {
			struct sockaddr_in6 *in6_addr;
			in6_addr = (struct sockaddr_in6 *)sock_addrp;

			bcopy(&(ibt_addrp->un.ip6addr), &(in6_addr->sin6_addr),
			    sizeof (in6_addr_t));
			if (portp)
				in6_addr->sin6_port = *portp;
		}
}

static void
sockaddr2ibtaddr_port(struct rdma_cm_id *idp, struct sockaddr *sock_addrp,
    ibt_ip_addr_t *ibt_addrp, in_port_t *portp)
{
	in_port_t	ip_port;

	ibt_addrp->family = sock_addrp->sa_family;
	if (sock_addrp->sa_family == AF_INET) {
		struct sockaddr_in	*sock_in4p;
		sock_in4p = (struct sockaddr_in *)sock_addrp;

		ibt_addrp->un.ip4addr = sock_in4p->sin_addr.s_addr;
		if (IS_UDP_CMID(idp))
			ip_port = ddi_swap16(sock_in4p->sin_port);
		else
			ip_port = htons(sock_in4p->sin_port);

		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "sockaddr2ibtaddr : "
		    "AF_INET addr %x, port %x, %x", ibt_addrp->un.ip4addr,
		    sock_in4p->sin_port, ip_port);

		if (portp)
			*portp = ip_port;

	} else {
		struct sockaddr_in6	*in6_addr;
		in6_addr = (struct sockaddr_in6 *)sock_addrp;
		bcopy(&(in6_addr->sin6_addr), &(ibt_addrp->un.ip6addr),
		    sizeof (in6_addr_t));
		if (portp)
			*portp = in6_addr->sin6_port;
	}
}

static void
mcginfo2ah(ibt_mcg_info_t *mcgp, struct ib_ah_attr *ah_attr)
{
	ibt_adds_vect_t	*adds_vectp;
	ib_gid_t	dgid_nworder;

	adds_vectp = &(mcgp->mc_adds_vect);

	/*
	 * Libraries expect the GID to be in network order. Convert
	 * to network order before passing it to the library.
	 */
	dgid_nworder.gid_prefix = htonll(
	    (adds_vectp->av_dgid).gid_prefix);
	dgid_nworder.gid_guid = htonll(
	    (adds_vectp->av_dgid).gid_guid);
	bcopy(&dgid_nworder, &((ah_attr->grh).dgid), sizeof (ib_gid_t));

	(ah_attr->grh).flow_label =  adds_vectp->av_flow;
	(ah_attr->grh).sgid_index = adds_vectp->av_sgid_ix;
	(ah_attr->grh).hop_limit = adds_vectp->av_hop;
	(ah_attr->grh).traffic_class = adds_vectp->av_tclass;

	ah_attr->dlid = adds_vectp->av_dlid;
	ah_attr->sl = adds_vectp->av_srvl;
	ah_attr->src_path_bits = adds_vectp->av_src_path;
	ah_attr->static_rate = adds_vectp->av_srate;
	ah_attr->ah_flags = (adds_vectp->av_send_grh) ? 1 : 0;
	ah_attr->port_num = adds_vectp->av_port_num;
}

static void
ibt_path2ah(ibt_path_info_t *pathp, struct ib_ah_attr *ah_attr)
{

	ibt_addsvect2ah(&((pathp->pi_prim_cep_path).cep_adds_vect), ah_attr);
}

static void
ibt_addsvect2ah(ibt_adds_vect_t *adds_vectp, struct ib_ah_attr *ah_attr)
{
	ib_gid_t	dgid_nworder;

	/*
	 * Libraries expect the GID to be in network order. Convert
	 * to network order before passing it to the library.
	 */
	dgid_nworder.gid_prefix = htonll(
	    (adds_vectp->av_dgid).gid_prefix);
	dgid_nworder.gid_guid = htonll(
	    (adds_vectp->av_dgid).gid_guid);
	bcopy(&dgid_nworder, &((ah_attr->grh).dgid), sizeof (ib_gid_t));
	(ah_attr->grh).flow_label =  adds_vectp->av_flow;
	(ah_attr->grh).sgid_index = adds_vectp->av_sgid_ix;
	(ah_attr->grh).hop_limit = adds_vectp->av_hop;
	(ah_attr->grh).traffic_class = adds_vectp->av_tclass;

	ah_attr->dlid = adds_vectp->av_dlid;
	ah_attr->sl = adds_vectp->av_srvl;
	ah_attr->src_path_bits = adds_vectp->av_src_path;
	ah_attr->static_rate = adds_vectp->av_srate;
	ah_attr->ah_flags = (adds_vectp->av_send_grh) ? 1 : 0;
	ah_attr->port_num = adds_vectp->av_port_num;
}

static void
ibt_path2sa_path(ibt_path_info_t *pathp, struct ib_sa_path_rec *sa_pathp,
    ib_lid_t base_lid)
{
	ibt_adds_vect_t	*adds_vectp;

	adds_vectp = &((pathp->pi_prim_cep_path).cep_adds_vect);
	ibt_addsvect2sa_path(adds_vectp, sa_pathp, base_lid);
	sa_pathp->mtu = pathp->pi_path_mtu;
	sa_pathp->packet_life_time = pathp->pi_prim_pkt_lt;
}

static void
ibt_addsvect2sa_path(ibt_adds_vect_t *adds_vectp,
    struct ib_sa_path_rec *sa_pathp, ib_lid_t base_lid)
{
	bcopy(&(adds_vectp->av_dgid), &(sa_pathp->dgid), 16);
	bcopy(&(adds_vectp->av_sgid), &(sa_pathp->sgid), 16);
	sa_pathp->dlid = adds_vectp->av_dlid;
	sa_pathp->slid = base_lid + adds_vectp->av_src_path;
	sa_pathp->flow_label =  adds_vectp->av_flow;
	sa_pathp->reversible = 1;
	sa_pathp->hop_limit = adds_vectp->av_hop;
	sa_pathp->traffic_class  = adds_vectp->av_tclass;
	sa_pathp->sl = adds_vectp->av_srvl;
	sa_pathp->rate = adds_vectp->av_srate;
	sa_pathp->mtu_selector = IBT_EQU;
	sa_pathp->rate_selector = IBT_EQU;
	sa_pathp->packet_life_time_selector = IBT_EQU;
}

/*
 * Map a multicast IP onto multicast MAC for type IP-over-InfiniBand.
 * Leave P_Key as 0 to be filled in by caller
 */
static void
ip_ib_mc_map(uint32_t addr, char *buf)
{
	buf[0]  = 0;		/* Reserved */
	buf[1]  = 0xff;		/* Multicast QPN */
	buf[2]  = 0xff;
	buf[3]  = 0xff;
	addr    = ntohl(addr);
	buf[4]  = 0xff;
	buf[5]  = 0x12;		/* link local scope */
	buf[6]  = 0x40;		/* IPv4 signature */
	buf[7]  = 0x1b;
	buf[8]  = 0;		/* P_Key */
	buf[9]  = 0;
	buf[10] = 0;
	buf[11] = 0;
	buf[12] = 0;
	buf[13] = 0;
	buf[14] = 0;
	buf[15] = 0;
	buf[19] = addr & 0xff;
	addr  >>= 8;
	buf[18] = addr & 0xff;
	addr  >>= 8;
	buf[17] = addr & 0xff;
	addr  >>= 8;
	buf[16] = addr & 0x0f;
}

static void
ipaddr2mgid(struct sockaddr *addrp, ib_gid_t *mgidp, ib_pkey_t pkey)
{
	char			mc_map[32];	/* Max H/W addr len */
	struct sockaddr_in	*sin = (struct sockaddr_in *)addrp;
	struct sockaddr_in6	*sin6 = (struct sockaddr_in6 *)addrp;

	if ((addrp->sa_family ==  AF_INET6) &&
	    b2h32((sin6->sin6_addr.s6_addr32[0]) & 0xFF10A01B) ==
	    0xFF10A01B) {
		bcopy(&sin6->sin6_addr, mgidp, sizeof (ib_gid_t));
	} else {
		ip_ib_mc_map(sin->sin_addr.s_addr, mc_map);
		mc_map[7] = 0x01;   /* Use RDMA CM signature */
		mc_map[8] = (char)(pkey >> 8);
		mc_map[9] = (char)(pkey);
		bcopy(mc_map+4, mgidp, sizeof (ib_gid_t));
	}
}

static int
ibcma_any_addr(ibt_ip_addr_t *addr)
{
	ASSERT(addr);
	if (addr->family == AF_INET)
		return (addr->un.ip4addr == INADDR_ANY);
	else if (addr->family == AF_INET6)
		return (IN6_IS_ADDR_UNSPECIFIED(&(addr->un.ip6addr)));
	return (0);
}

static struct rdma_cm_id *
ibcma_create_new_id(struct rdma_cm_id *idp)
{
	struct rdma_cm_id	*new_idp;
	sol_cma_chan_t		*chanp, *new_chanp;
	ibcma_chan_t		*ibchanp, *new_ibchanp;

	new_idp = cma_create_new_id(idp);
	if (new_idp == NULL)
		return (new_idp);
	new_chanp = (sol_cma_chan_t *)new_idp;
	new_ibchanp = &new_chanp->chan_ib;
	chanp = (sol_cma_chan_t *)idp;
	ibchanp = &chanp->chan_ib;
	if (ibchanp->chan_devp) {
		ibcma_dev_t	*devp;

		devp = (ibcma_dev_t *)kmem_zalloc(sizeof (ibcma_dev_t),
		    KM_SLEEP);
		new_ibchanp->chan_devp = devp;
		bcopy(ibchanp->chan_devp, devp, sizeof (ibcma_dev_t));
	}

	if (ibchanp->chan_pathp && ibchanp->chan_numpaths &&
	    ibchanp->chan_path_size) {
		new_ibchanp->chan_pathp = (ibt_path_info_t *)kmem_zalloc(
		    ibchanp->chan_path_size, KM_SLEEP);
		bcopy(ibchanp->chan_pathp, new_ibchanp->chan_pathp,
		    ibchanp->chan_path_size);
		new_ibchanp->chan_path_size = ibchanp->chan_path_size;
		new_ibchanp->chan_numpaths = ibchanp->chan_numpaths;
	}
	bcopy(&ibchanp->chan_local_addr, &new_ibchanp->chan_local_addr,
	    sizeof (ibt_ip_addr_t));
	bcopy(&ibchanp->chan_remote_addr, &new_ibchanp->chan_remote_addr,
	    sizeof (ibt_ip_addr_t));
	new_ibchanp->chan_port = ibchanp->chan_port;
	new_ibchanp->chan_sid = ibchanp->chan_sid;

	return (new_idp);
}

static void
ibcma_get_devlist(sol_cma_chan_t *root_chanp, ib_guid_t *hca_guidp,
    int num_hcas, genlist_t *ret_devlist)
{
	int			i;
	ibt_status_t		status;
	ibcma_dev_t		*devp;
	uint_t			num_ports, p;
	uint_t			port_size;
	ibt_hca_portinfo_t	*port_info, *tmp;
	ibt_ip_addr_t		hca_ipaddr;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "get_devlist(%p, %p, %x, %p)",
	    root_chanp, hca_guidp, num_hcas, ret_devlist);

	init_genlist(ret_devlist);
	for (i = 0; i < num_hcas; i++) {
		status = ibt_query_hca_ports_byguid(hca_guidp[i], 0, &port_info,
		    &num_ports, &port_size);
		if (status !=  IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_rdmacm_dbg_str,
			    "ibt_query_hca_ports_byguid failed %d", status);
			continue;
		}

		for (p = 0, tmp = port_info; p < num_ports; p++, tmp++) {
			uint_t		s, num_sgids;
			uint16_t	pk;
			uint_t		num_pkeys;

			if (tmp->p_linkstate != IBT_PORT_ACTIVE)
				continue;

			num_sgids = tmp->p_sgid_tbl_sz / sizeof (ib_gid_t);
			num_pkeys = tmp->p_pkey_tbl_sz / sizeof (ib_pkey_t);

			for (s = 0; s < num_sgids; s++) {
				/* Skip holes in sgid table */
				if (tmp->p_sgid_tbl[s].gid_guid == 0x0LL)
					continue;
				for (pk = 0; pk < num_pkeys; pk++) {
					/* Skip holes in pkey table */
					if (tmp->p_pkey_tbl[pk] == 0)
						continue;
					status = ibt_get_src_ip(
					    tmp->p_sgid_tbl[s],
					    tmp->p_pkey_tbl[pk],
					    &hca_ipaddr);
					if (status != IBT_SUCCESS)
						continue;

					/* allocate devinfo & fill in info */
					devp = kmem_zalloc(
					    sizeof (ibcma_dev_t), KM_SLEEP);
					devp->dev_node_guid = hca_guidp[i];
					devp->dev_port_num = p + 1;
					devp->dev_pkey_ix = pk;
					devp->dev_pkey = tmp->p_pkey_tbl[pk];
					devp->dev_sgid = tmp->p_sgid_tbl[s];
					bcopy(&hca_ipaddr, &devp->dev_ipaddr,
					    sizeof (ibt_ip_addr_t));

					SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
					    "get_devlist: add2devlist "
					    "node_guid %llx", hca_guidp[i]);
					(void) add_genlist(ret_devlist,
					    (uintptr_t)devp, NULL);
				}
			}
		}
		ibt_free_portinfo(port_info, port_size);
	}
}


#ifdef	QP_DEBUG
static void
dump_qp_info(ibt_qp_hdl_t qphdl)
{
	ibt_qp_query_attr_t	qp_query;
	ibt_qp_info_t		*qp_info;
	ibt_status_t		status;
	ibt_qp_rc_attr_t	*rcp;

	bzero(&qp_query, sizeof (qp_query));
	status = ibt_query_qp(qphdl, &qp_query);
	if (status != IBT_SUCCESS) {
		cmn_err(CE_WARN, "query_qp failed!!");
		return;
	}
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "QP HDL : %p, qp_sq_cq %p, qp_rq_cq %p, "
	    "qp_rdd_hdl %p, qp_qpn %x, qp_sq_sgl %x, qp_rq_sgl %x, "
	    "qp_srq %p, quer_attr.qp_flags %x",
	    qphdl, qp_query.qp_sq_cq, qp_query.qp_rq_cq,
	    qp_query.qp_rdd_hdl, qp_query.qp_qpn,
	    qp_query.qp_sq_sgl, qp_query.qp_rq_sgl,
	    qp_query.qp_srq, qp_query.qp_flags);
	qp_info = &(qp_query.qp_info);
	rcp = &((qp_info->qp_transport).rc);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "qp_sq_sz %x, qp_rq_sz %x, qp_state %x, "
	    "qp_current_state %x, qp_info.qp_flags %x, qp_trans %x",
	    qp_info->qp_sq_sz, qp_info->qp_rq_sz, qp_info->qp_state,
	    qp_info->qp_current_state, qp_info->qp_flags,
	    qp_info->qp_trans);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "rc_sq_psn %x, rc_rq_psn %x, rc_dst_qpn %x, "
	    "rc_mig_state %x, rc_rnr_retry_cnt %x, rc_retry_cnt %x, "
	    "rc_rdma_ra_out %x, rc_rdma_ra_in %x, rc_min_rnr_nak %x, "
	    "rc_path_mtu %x", rcp->rc_sq_psn, rcp->rc_rq_psn,
	    rcp->rc_dst_qpn, rcp->rc_mig_state, rcp->rc_rnr_retry_cnt,
	    rcp->rc_retry_cnt, rcp->rc_rdma_ra_out, rcp->rc_rdma_ra_in,
	    rcp->rc_min_rnr_nak, rcp->rc_path_mtu);
	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
	    "av_dgid %llx: %llx, av_sgid: %llx, "
	    "srate %x, srvl %x, flow %x, tclass %x, hop %x, "
	    "av_port_num %x, av_send_grh %x, av_dlid %x, "
	    "av_src_path %x, av_sgid_ix %x, pkey_index %x, "
	    "port_num %x",
	    (rcp->rc_path).cep_adds_vect.av_sgid.gid_prefix,
	    (rcp->rc_path).cep_adds_vect.av_sgid.gid_guid,
	    (rcp->rc_path).cep_adds_vect.av_dgid.gid_prefix,
	    (rcp->rc_path).cep_adds_vect.av_dgid.gid_guid,
	    (rcp->rc_path).cep_adds_vect.av_srate,
	    (rcp->rc_path).cep_adds_vect.av_srvl,
	    (rcp->rc_path).cep_adds_vect.av_flow,
	    (rcp->rc_path).cep_adds_vect.av_tclass,
	    (rcp->rc_path).cep_adds_vect.av_hop,
	    (rcp->rc_path).cep_adds_vect.av_port_num,
	    (rcp->rc_path).cep_adds_vect.av_opaque1,
	    (rcp->rc_path).cep_adds_vect.av_opaque2,
	    (rcp->rc_path).cep_adds_vect.av_opaque3,
	    (rcp->rc_path).cep_adds_vect.av_opaque4,
	    (rcp->rc_path).cep_pkey_ix,
	    (rcp->rc_path).cep_hca_port_num);
}
#endif

static void
dump_priv_data(void *priv_data, ibt_priv_data_len_t arr_len,
    ibt_priv_data_len_t priv_len, char *caller)
{
	uint8_t	i;
	uchar_t *c = (uchar_t *)priv_data;

	SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str, "priv_data to %s: %p, len %d",
	    caller, priv_data, priv_len);
	if (!priv_len || !priv_data)
		return;

	/* Display in rows of 16 uchar_t */
	for (i = 0; i < arr_len; i += 16)
		SOL_OFS_DPRINTF_L5(sol_rdmacm_dbg_str,
		    "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
		    c[i], c[i + 1], c[i + 2], c[i + 3], c[i + 4], c[i + 5],
		    c[i + 6], c[i + 7], c[i + 8], c[i + 9], c[i + 10],
		    c[i + 11], c[i + 12], c[i + 13], c[i + 14], c[i + 15]);

}
