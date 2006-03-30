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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _GHD_DMA_H
#define	_GHD_DMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "ghd.h"

int	ghd_dmaget_attr(ccc_t *cccp, gcmd_t *gcmdp, long count, int sg_size,
			uint_t *xfer);

int	ghd_dma_buf_bind_attr(ccc_t *ccp, gcmd_t *gcmdp, struct buf *bp,
		int dma_flags, int (*callback)(), caddr_t arg,
		ddi_dma_attr_t *sg_attrp);

void	ghd_dmafree_attr(gcmd_t *gcmdp);

uint_t	ghd_dmaget_next_attr(ccc_t *cccp, gcmd_t *gcmdp, long max_transfer_cnt,
		int sg_size, ddi_dma_cookie_t cookie);

#ifdef	__cplusplus
}
#endif

#endif /* _GHD_DMA_H */
