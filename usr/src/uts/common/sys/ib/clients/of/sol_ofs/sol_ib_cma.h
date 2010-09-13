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

#ifndef	_SYS_IB_CLIENTS_OF_SOL_OFS_SOL_IB_CMA_H
#define	_SYS_IB_CLIENTS_OF_SOL_OFS_SOL_IB_CMA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/ib/ibtl/ibvti.h>

/* Global qkey for UDP QPs and multicast groups. */
#define	RDMA_UDP_QKEY 0x01234567

typedef struct {
	uint64_t		dev_node_guid;
	uint8_t			dev_port_num;
	uint16_t		dev_pkey_ix;
	ib_pkey_t		dev_pkey;
	ib_gid_t		dev_sgid;
	ibt_ip_addr_t		dev_ipaddr;
} ibcma_dev_t;

#define	IBCMA_LOCAL_ADDR_SET_FLAG	0x01
#define	IBCMA_REMOTE_ADDR_SET_FLAG	0x02
#define	IBCMA_LOCAL_ADDR_IFADDRANY	0x10

typedef struct ibcma_chan_s {
	/* Pathinfo for CM ID */
	ibt_path_info_t		*chan_pathp;
	uint8_t			chan_numpaths;
	size_t			chan_path_size;

	/* Address & Service ID for CM ID */
	ibt_ip_addr_t		chan_local_addr;
	ibt_ip_addr_t		chan_remote_addr;
	in_port_t		chan_port;
	ib_svc_id_t		chan_sid;
	uint8_t			chan_addr_flag;

	/* RC REQ information */
	struct rdma_cm_id	*chan_req_idp;	/* Chan created for Req */
	ibt_adds_vect_t		chan_rcreq_addr;
	ib_qpn_t		chan_rcreq_qpn;
	uint8_t			chan_rcreq_ra_in;
	ibt_ofuvcm_req_data_t	chan_rtr_data;

	/* QP Information for CM ID */
	uint8_t			chan_qpmodifyflag;

	/* Local device Information */
	ibcma_dev_t		*chan_devp;

	/* Multicast list for the CM ID */
	genlist_t		chan_mcast_list;
	int			chan_mcast_cnt;
} ibcma_chan_t;

typedef struct ibcma_mcast_s {
	struct rdma_cm_id	*mcast_idp;
	void			*mcast_ctx;
	struct sockaddr_in6	mcast_addr;
	ib_gid_t		mcast_gid;
} ibcma_mcast_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_CLIENTS_OF_SOL_OFS_SOL_IB_CMA_H */
