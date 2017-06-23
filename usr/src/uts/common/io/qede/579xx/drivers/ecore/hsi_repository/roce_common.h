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

#ifndef __ROCE_COMMON__
#define __ROCE_COMMON__ 
/************************************************************************/
/* Add include to common rdma target for both eCore and protocol rdma driver */
/************************************************************************/
#include "rdma_common.h"
/************************/
/* ROCE FW CONSTANTS */
/************************/

#define ROCE_REQ_MAX_INLINE_DATA_SIZE (256)	//max size of inline data in single request
#define ROCE_REQ_MAX_SINGLE_SQ_WQE_SIZE	(288)	//Maximum size of single SQ WQE (rdma wqe and inline data)

#define ROCE_MAX_QPS				(32*1024)
#define ROCE_DCQCN_NP_MAX_QPS  (64)	/* notification point max QPs*/
#define ROCE_DCQCN_RP_MAX_QPS  (64)		/* reaction point max QPs*/


/*
 * Affiliated asynchronous events / errors enumeration
 */
enum roce_async_events_type
{
	ROCE_ASYNC_EVENT_NONE=0,
	ROCE_ASYNC_EVENT_COMM_EST=1,
	ROCE_ASYNC_EVENT_SQ_DRAINED,
	ROCE_ASYNC_EVENT_SRQ_LIMIT,
	ROCE_ASYNC_EVENT_LAST_WQE_REACHED,
	ROCE_ASYNC_EVENT_CQ_ERR,
	ROCE_ASYNC_EVENT_LOCAL_INVALID_REQUEST_ERR,
	ROCE_ASYNC_EVENT_LOCAL_CATASTROPHIC_ERR,
	ROCE_ASYNC_EVENT_LOCAL_ACCESS_ERR,
	ROCE_ASYNC_EVENT_QP_CATASTROPHIC_ERR,
	ROCE_ASYNC_EVENT_CQ_OVERFLOW_ERR,
	ROCE_ASYNC_EVENT_SRQ_EMPTY,
	ROCE_ASYNC_EVENT_DESTROY_QP_DONE,
	MAX_ROCE_ASYNC_EVENTS_TYPE
};

#endif /* __ROCE_COMMON__ */
