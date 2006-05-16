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

#ifndef _PLATSVC_H
#define	_PLATSVC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ds.h>

#define	MAX_REASON_SIZE		1

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

#ifdef __cplusplus
}
#endif

#endif /* _PLATSVC_H */
