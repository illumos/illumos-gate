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
 * Copyright 1999, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddidmareq.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/fcode.h>

/*
 * We want to call the attachment point's dma ctl op, not his parent's
 * dma ctl op, so we have to code this ourselves. (the dma setup functions
 * already implement this functionality for us.)
 */
int
fc_ddi_dma_htoc(dev_info_t *ap, ddi_dma_handle_t h, off_t o,
	ddi_dma_cookie_t *c)
{
	int (*fp)();

	fp = DEVI(ap)->devi_ops->devo_bus_ops->bus_dma_ctl;
	return ((*fp) (ap, ap, h, DDI_DMA_HTOC, &o, 0, (caddr_t *)c, 0));
}

int
fc_ddi_dma_free(dev_info_t *ap, ddi_dma_handle_t h)
{
	int (*fp)();

	fp = DEVI(ap)->devi_ops->devo_bus_ops->bus_dma_ctl;
	return ((*fp) (ap, ap, h, DDI_DMA_FREE, 0, 0, 0, 0));
}

int
fc_ddi_dma_sync(ddi_dma_handle_t h, off_t o, size_t l, uint_t whom)
{
	ddi_dma_impl_t *hp = (ddi_dma_impl_t *)h;
	dev_info_t *dip;
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_handle_t, off_t,
		size_t, uint_t);

	/*
	 * the DMA nexus driver will set DMP_NOSYNC if the
	 * platform does not require any sync operation. For
	 * example if the memory is uncached or consistent
	 * and without any I/O write buffers involved.
	 */
	if ((hp->dmai_rflags & DMP_NOSYNC) == DMP_NOSYNC)
		return (DDI_SUCCESS);

	dip = hp->dmai_rdip;
	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_flush;
	return ((*funcp)(dip, dip, h, o, l, whom));
}

/*
 * Create untyped properties, just like 1275 properties.
 * XXX: Assumes property encoding is the natural byte order.
 */
int
fc_ndi_prop_update(dev_t match_dev, dev_info_t *dip,
    char *name, uchar_t *data, uint_t nelements)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_HW_DEF | DDI_PROP_TYPE_ANY,
	    name, data, nelements, ddi_prop_fm_encode_bytes));
}
