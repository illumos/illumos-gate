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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ISER_IB_H
#define	_ISER_IB_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/iscsi_protocol.h>

/*
 * iser_ib.h
 *	Definitions and macros related to iSER InfiniBand transport,
 * 	and the use of the Solaris IBTI (InfiniBand Transport Interface).
 */

struct iser_state_s;

extern struct iser_state_s	*iser_state;
extern ddi_taskq_t	*iser_taskq;

/*
 * iser_hca_s holds all the information about the Infinband HCAs in use.
 */
typedef struct iser_hca_s {
	list_node_t		hca_node;
	boolean_t		hca_failed;
	ibt_clnt_hdl_t		hca_clnt_hdl;
	ibt_hca_hdl_t		hca_hdl;
	ibt_hca_attr_t		hca_attr;
	ibt_pd_hdl_t		hca_pdhdl;
	ib_guid_t		hca_guid;
	uint_t			hca_num_ports;
	ibt_hca_portinfo_t	*hca_port_info;
	uint_t			hca_port_info_sz;

	/* Per PD (per HCA) message and data buffer caches */
	struct iser_vmem_mr_pool_s *hca_msg_pool; /* Use iser_msg_cache */
	kmem_cache_t		*iser_msg_cache;
	struct iser_vmem_mr_pool_s *hca_buf_pool; /* Use iser_buf_cache */
	kmem_cache_t		*iser_buf_cache;
} iser_hca_t;

/* RQ low water mark percentage */
#define	ISER_IB_RQ_LWM_PCT	80

/* Maximum number of WRs to post on the RQ at a time */
#define	ISER_IB_RQ_POST_MAX	64

/* Maximum number of SCQ WCs to poll at a time */
#define	ISER_IB_SCQ_POLL_MAX	8

/*
 * iser_qp_t encodes data related to a Queue Pair (QP) in use by
 * iSER. Each QP consists of two Work Queues (WQs), one Send Queue
 * (SQ) and on Receive Queue (RQ). Most of the data in the QP
 * handle relates to monitoring the posted depth of the RQ.
 *
 * Note that we are explicitly using slightly less than a power-of-2
 * number for our queue sizes.  The HCA driver will round up for us,
 * and this affords us some headroom.
 */
#ifdef _LP64
#define	ISER_IB_RECVQ_SIZE	400
#else
/* Memory is very limited on 32-bit kernels */
#define	ISER_IB_RECVQ_SIZE	100
#endif
#define	ISER_IB_SENDQ_SIZE	2000
#define	ISER_IB_SGLIST_SIZE	1

#define	ISER_IB_DEFAULT_IRD	2
#define	ISER_IB_DEFAULT_ORD	4

typedef struct iser_qp_s {
	kmutex_t	qp_lock;
	uint_t		sq_size;
	uint_t		rq_size;
	uint32_t	rq_depth;
	uint32_t	rq_level;
	uint32_t	rq_min_post_level;
	uint32_t	rq_lwm;
	boolean_t	rq_taskqpending;
} iser_qp_t;

/*
 * iSER RC channel information
 */
typedef struct iser_chan_s {
	kmutex_t		ic_chan_lock;

	/* IBT channel handle */
	ibt_channel_hdl_t	ic_chanhdl;

	/* local and remote IP addresses and port numbers */
	ibt_ip_addr_t		ic_localip;
	ibt_ip_addr_t		ic_remoteip;
	in_port_t		ic_lport;
	in_port_t		ic_rport;

	/*
	 * The local HCA GUID, the service ID, Destination GID, Source GID
	 * the primary hca port on which the channel is connected is
	 * stored in ic_ibt_path
	 */
	ibt_path_info_t		ic_ibt_path;

	/*
	 * Information related to the HCA handle and the queues.
	 */
	iser_hca_t		*ic_hca;
	ibt_cq_hdl_t		ic_sendcq;
	ibt_cq_hdl_t		ic_recvcq;
	uint_t			ic_sendcq_sz;
	uint_t			ic_recvcq_sz;
	iser_qp_t		ic_qp;

	/* Used to track the number of WRs posted on the SQ */
	kmutex_t		ic_sq_post_lock;
	uint_t			ic_sq_post_count;
	uint_t			ic_sq_max_post_count;

	/*
	 * To help identify the channel end point and some connection
	 * specifics, maintain a pointer to the connection on which
	 * this channel originated
	 */
	struct iser_conn_s	*ic_conn;
} iser_chan_t;

int iser_ib_init(void);

int iser_ib_fini(void);

int iser_ib_register_service(idm_svc_t *idm_svc);

int iser_ib_bind_service(idm_svc_t *idm_svc);

void iser_ib_unbind_service(idm_svc_t *idm_svc);

void iser_ib_deregister_service(idm_svc_t *idm_svc);

void iser_ib_conv_sockaddr2ibtaddr(idm_sockaddr_t *saddr,
    ibt_ip_addr_t *ibt_addr);

void iser_ib_conv_ibtaddr2sockaddr(struct sockaddr_storage *ss,
    ibt_ip_addr_t *ibt_addr, in_port_t port);

int iser_ib_get_paths(
    ibt_ip_addr_t *local_ip, ibt_ip_addr_t *remote_ip, ibt_path_info_t *path,
    ibt_path_ip_src_t *path_src_ip);

iser_chan_t *iser_ib_alloc_channel_pathlookup(
    ibt_ip_addr_t *local_ip, ibt_ip_addr_t *remote_ip);

iser_chan_t *iser_ib_alloc_channel_nopathlookup(
    ib_guid_t hca_guid, uint8_t hca_port);

iser_chan_t *iser_ib_alloc_rc_channel(iser_hca_t *hca, uint8_t hca_port);

int iser_ib_open_rc_channel(iser_chan_t *chan);

void iser_ib_close_rc_channel(iser_chan_t *chan);

void iser_ib_free_rc_channel(iser_chan_t *chan);

int iser_ib_post_recv_async(ibt_channel_hdl_t chanhdl);

void iser_ib_post_recv(ibt_channel_hdl_t chanhdl);

void iser_ib_recvcq_handler(ibt_cq_hdl_t cq_hdl, void *arg);

void iser_ib_sendcq_handler(ibt_cq_hdl_t cq_hdl, void *arg);

void iser_ib_async_handler(void *clntp, ibt_hca_hdl_t hdl,
    ibt_async_code_t code, ibt_async_event_t *event);

#ifdef	__cplusplus
}
#endif

#endif /* _ISER_IB_H */
