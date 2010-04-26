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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _PLATSVC_H
#define	_PLATSVC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ds.h>

#define	MAX_REASON_SIZE		1
#define	SUSPEND_MAX_REASON_SIZE	256

/*
 * PLATSVC STATUS
 */
#define	PLATSVC_SUCCESS		0x0
#define	PLATSVC_FAILURE		0x1
#define	PLATSVC_INVALID_MESG	0x2

#define	MD_UPDATE_SUCCESS		PLATSVC_SUCCESS
#define	MD_UPDATE_FAILURE		PLATSVC_FAILURE
#define	MD_UPDATE_INVALID_MSG		PLATSVC_INVALID_MESG

#define	DOMAIN_SHUTDOWN_SUCCESS		PLATSVC_SUCCESS
#define	DOMAIN_SHUTDOWN_FAILURE		PLATSVC_FAILURE
#define	DOMAIN_SHUTDOWN_INVALID_MSG	PLATSVC_INVALID_MESG

#define	DOMAIN_PANIC_SUCCESS		PLATSVC_SUCCESS
#define	DOMAIN_PANIC_FAILURE		PLATSVC_FAILURE
#define	DOMAIN_PANIC_INVALID_MSG	PLATSVC_INVALID_MESG

/*
 * Suspend message types.
 */
#define	DOMAIN_SUSPEND_SUSPEND		0x0

/*
 * Suspend response result values.
 */
#define	DOMAIN_SUSPEND_PRE_SUCCESS	PLATSVC_SUCCESS
#define	DOMAIN_SUSPEND_PRE_FAILURE	PLATSVC_FAILURE
#define	DOMAIN_SUSPEND_INVALID_MSG	PLATSVC_INVALID_MESG
#define	DOMAIN_SUSPEND_INPROGRESS	0x3
#define	DOMAIN_SUSPEND_SUSPEND_FAILURE	0x4
#define	DOMAIN_SUSPEND_POST_SUCCESS	0x5
#define	DOMAIN_SUSPEND_POST_FAILURE	0x6

/*
 * Suspend recovery result values.
 */
#define	DOMAIN_SUSPEND_REC_SUCCESS	0x0
#define	DOMAIN_SUSPEND_REC_FAILURE	0x1

/*
 * String used as the error reason in the failure response when a
 * suspend request is denied due to an ongoing DR operation.
 */
#define	DOMAIN_SUSPEND_DR_ERROR_STR	\
	"suspend failure: DR operation in progress"

typedef struct platsvc_md_update_req {
	uint64_t	req_num;
} platsvc_md_update_req_t;

typedef struct platsvc_md_update_resp {
	uint64_t	req_num;
	uint32_t	result;
} platsvc_md_update_resp_t;

typedef struct platsvc_shutdown_req {
	uint64_t	req_num;
	uint32_t	delay;
} platsvc_shutdown_req_t;

typedef struct platsvc_shutdown_resp {
	uint64_t	req_num;
	uint32_t	result;
	char		reason[MAX_REASON_SIZE];
} platsvc_shutdown_resp_t;

typedef struct platsvc_panic_req {
	uint64_t	req_num;
} platsvc_panic_req_t;

typedef struct platsvc_panic_resp {
	uint64_t	req_num;
	uint32_t	result;
	char		reason[MAX_REASON_SIZE];
} platsvc_panic_resp_t;

typedef struct platsvc_suspend_req {
	uint64_t	req_num;
	uint64_t	type;
} platsvc_suspend_req_t;

typedef struct platsvc_suspend_resp {
	uint64_t	req_num;
	uint32_t	result;
	uint32_t	rec_result;
	char		reason[MAX_REASON_SIZE];
} platsvc_suspend_resp_t;

#ifdef __cplusplus
}
#endif

#endif /* _PLATSVC_H */
