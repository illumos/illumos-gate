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

#ifndef __IWARP_COMMON__
#define __IWARP_COMMON__ 
/************************************************************************/
/* Add include to common rdma target for both eCore and protocol rdma driver */
/************************************************************************/
#include "rdma_common.h"
/************************/
/* IWARP FW CONSTANTS	*/
/************************/

#define IWARP_ACTIVE_MODE 0
#define IWARP_PASSIVE_MODE 1

#define IWARP_SHARED_QUEUE_PAGE_SIZE			(0x8000)		//32KB page for Shared Queue Page
#define IWARP_SHARED_QUEUE_PAGE_RQ_PBL_OFFSET	(0x4000)		//First 12KB of Shared Queue Page is reserved for FW
#define IWARP_SHARED_QUEUE_PAGE_RQ_PBL_MAX_SIZE (0x1000)		//Max RQ PBL Size is 4KB
#define IWARP_SHARED_QUEUE_PAGE_SQ_PBL_OFFSET	(0x5000)		
#define IWARP_SHARED_QUEUE_PAGE_SQ_PBL_MAX_SIZE	(0x3000)		//Max SQ PBL Size is 12KB

#define IWARP_REQ_MAX_INLINE_DATA_SIZE		(128)	//max size of inline data in single request
#define IWARP_REQ_MAX_SINGLE_SQ_WQE_SIZE	(176)	//Maximum size of single SQ WQE (rdma wqe and inline data)

#define IWARP_MAX_QPS				(64*1024)

#endif /* __IWARP_COMMON__ */
