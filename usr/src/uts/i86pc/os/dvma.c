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
 * Copyright (c) 1990-1998, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/cpu.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>

/*ARGSUSED*/
unsigned long
dvma_pagesize(dev_info_t *dip)
{
	return (0);
}

/*ARGSUSED*/
int
dvma_reserve(dev_info_t *dip,  ddi_dma_lim_t *limp, u_int pages,
    ddi_dma_handle_t *handlep)
{
	return (DDI_DMA_NORESOURCES);
}

/*ARGSUSED*/
void
dvma_release(ddi_dma_handle_t h)
{
}

/*ARGSUSED*/
void
dvma_kaddr_load(ddi_dma_handle_t h, caddr_t a, u_int len, u_int index,
	ddi_dma_cookie_t *cp)
{
}

/*ARGSUSED*/
void
dvma_unload(ddi_dma_handle_t h, u_int objindex, u_int type)
{
}

/*ARGSUSED*/
void
dvma_sync(ddi_dma_handle_t h, u_int objindex, u_int type)
{
}
