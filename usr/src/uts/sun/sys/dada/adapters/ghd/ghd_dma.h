/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1996, Sun Microsystems, Inc.
 * All Rights Reserved.
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

void	 ghd_dmafree(gcmd_t *gcmdp);

int	 ghd_dmaget(dev_info_t *dip, gcmd_t *gcmdp, struct buf *bp,
		int flags, int (*callback)(), caddr_t arg,
		ddi_dma_lim_t *sg_limitp, void (*sg_func)());

#ifdef	__cplusplus
}
#endif

#endif /* _GHD_DMA_H */
