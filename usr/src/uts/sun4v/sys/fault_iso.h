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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FAULT_ISO_H
#define	_FAULT_ISO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* FMA CPU message numbers */
#define	FMA_CPU_REQ_STATUS	0x0
#define	FMA_CPU_REQ_OFFLINE	0x1
#define	FMA_CPU_REQ_ONLINE	0x2

typedef struct {
	uint64_t	req_num;
	uint32_t	msg_type;
	uint32_t	cpu_id;
} fma_cpu_service_req_t;

/* FMA CPU result codes */
#define	FMA_CPU_RESP_OK		0x0
#define	FMA_CPU_RESP_FAILURE	0x1

/* FMA CPU status codes */
#define	FMA_CPU_STAT_ONLINE	0x0
#define	FMA_CPU_STAT_OFFLINE	0x1
#define	FMA_CPU_STAT_ILLEGAL	0x2

typedef struct {
	uint64_t	req_num;
	uint32_t	result;
	uint32_t	status;
} fma_cpu_resp_t;

/* FMA memory services message numbers */
#define	FMA_MEM_REQ_STATUS	0x0
#define	FMA_MEM_REQ_RETIRE	0x1
#define	FMA_MEM_REQ_RESURRECT	0x2

typedef struct {
	uint64_t	req_num;
	uint32_t	msg_type;
	uint32_t	_resvd;
	uint64_t	real_addr;
	uint64_t	length;
} fma_mem_service_req_t;

/* FMA result codes */
#define	FMA_MEM_RESP_OK		0x0
#define	FMA_MEM_RESP_FAILURE	0x1

/* FMA status codes */
#define	FMA_MEM_STAT_NOTRETIRED		0x0
#define	FMA_MEM_STAT_RETIRED		0x1
#define	FMA_MEM_STAT_ILLEGAL		0x2

typedef struct {
	uint64_t	req_num;
	uint32_t	result;
	uint32_t	status;
	uint64_t	res_addr;
	uint64_t	res_length;
} fma_mem_resp_t;

#ifdef __cplusplus
}
#endif

#endif /* _FAULT_ISO_H */
