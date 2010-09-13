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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_BLK_COMMON_H
#define	_SYS_BLK_COMMON_H


#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/xendev.h>


typedef uint_t (*blk_intr_t)(caddr_t arg);
typedef void (*blk_ring_cb_t)(caddr_t arg);

typedef struct blk_ringinit_args_s {
	dev_info_t	*ar_dip;

	/* callbacks */
	blk_intr_t	ar_intr;
	caddr_t		ar_intr_arg;
	blk_ring_cb_t	ar_ringup;
	caddr_t		ar_ringup_arg;
	blk_ring_cb_t	ar_ringdown;
	caddr_t		ar_ringdown_arg;
} blk_ringinit_args_t;

typedef struct blk_ring_s *blk_ring_t;

int blk_ring_init(blk_ringinit_args_t *args, blk_ring_t *ring);
void blk_ring_fini(blk_ring_t *ring);

boolean_t blk_ring_request_get(blk_ring_t ring, blkif_request_t *req);
void blk_ring_request_requeue(blk_ring_t ring);
void blk_ring_request_dump(blkif_request_t *req);

void blk_ring_response_put(blk_ring_t ring, blkif_response_t *resp);
void blk_ring_response_dump(blkif_response_t *req);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BLK_COMMON_H */
