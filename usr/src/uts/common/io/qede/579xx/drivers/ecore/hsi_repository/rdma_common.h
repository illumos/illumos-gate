/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef __RDMA_COMMON__
#define __RDMA_COMMON__ 
/************************/
/* RDMA FW CONSTANTS */
/************************/

#define RDMA_RESERVED_LKEY			(0)			//Reserved lkey
#define RDMA_RING_PAGE_SIZE			(0x1000)	//4KB pages

#define	RDMA_MAX_SGE_PER_SQ_WQE		(4)		//max number of SGEs in a single request
#define	RDMA_MAX_SGE_PER_RQ_WQE		(4)		//max number of SGEs in a single request

#define RDMA_MAX_DATA_SIZE_IN_WQE	(0x80000000)	//max size of data in single request

#define RDMA_REQ_RD_ATOMIC_ELM_SIZE		(0x50)
#define RDMA_RESP_RD_ATOMIC_ELM_SIZE	(0x20)

#define RDMA_MAX_CQS				(64*1024)
#define RDMA_MAX_TIDS				(128*1024-1)
#define RDMA_MAX_PDS				(64*1024)

#define RDMA_NUM_STATISTIC_COUNTERS			MAX_NUM_VPORTS
#define RDMA_NUM_STATISTIC_COUNTERS_K2			MAX_NUM_VPORTS_K2
#define RDMA_NUM_STATISTIC_COUNTERS_BB			MAX_NUM_VPORTS_BB

#define RDMA_TASK_TYPE (PROTOCOLID_ROCE)


struct rdma_srq_id
{
	__le16 srq_idx /* SRQ index */;
	__le16 opaque_fid;
};


struct rdma_srq_producers
{
	__le32 sge_prod /* Current produced sge in SRQ */;
	__le32 wqe_prod /* Current produced WQE to SRQ */;
};

#endif /* __RDMA_COMMON__ */
