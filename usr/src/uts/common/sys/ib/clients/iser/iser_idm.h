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

#ifndef _ISER_IDM_H
#define	_ISER_IDM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/idm/idm.h>
#include <sys/idm/idm_text.h>

/*
 * iSER transport routines
 *
 * All transport functions except iser_tgt_svc_create() are called through
 * the ops vector, iser_tgt_svc_create() is called from the async handler
 * inaddition to being called by the ULP
 */

/*
 * For small transfers, it is both CPU and time intensive to register the
 * memory used for the RDMA, So the transport does bcopy into memory that
 * is already pre-registered and maintained in a cache.
 */
#define	ISER_BCOPY_THRESHOLD	0x20000	/* 128k */

idm_status_t iser_tgt_svc_create(idm_svc_req_t *sr, struct idm_svc_s *is);


#ifdef	__cplusplus
}
#endif

#endif /* _ISER_IDM_H */
