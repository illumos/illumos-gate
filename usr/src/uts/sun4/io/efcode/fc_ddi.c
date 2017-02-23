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
 * Copyright (c) 2016 by Delphix. All rights reserved.
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
 * We want to call the attachment point's dma ctl op, not its parent's
 * dma ctl op, so we have to code this ourselves.
 */

int
fc_ddi_dma_alloc_handle(dev_info_t *dip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_attr_t *,
	    int (*)(caddr_t), caddr_t, ddi_dma_handle_t *);

	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_allochdl;
	return ((*funcp)(dip, dip, attr, waitfp, arg, handlep));
}

int
fc_ddi_dma_buf_bind_handle(ddi_dma_handle_t handle, struct buf *bp,
    uint_t flags, int (*waitfp)(caddr_t), caddr_t arg,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	struct ddi_dma_req dmareq;
	ddi_dma_impl_t *hp;
	dev_info_t *dip;
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_handle_t,
	    struct ddi_dma_req *, ddi_dma_cookie_t *, uint_t *);

	hp = (ddi_dma_impl_t *)handle;
	dip = hp->dmai_rdip;

	dmareq.dmar_flags = flags;
	dmareq.dmar_fp = waitfp;
	dmareq.dmar_arg = arg;
	dmareq.dmar_object.dmao_size = (uint_t)bp->b_bcount;

	if ((bp->b_flags & (B_PAGEIO|B_REMAPPED)) == B_PAGEIO) {
		dmareq.dmar_object.dmao_type = DMA_OTYP_PAGES;
		dmareq.dmar_object.dmao_obj.pp_obj.pp_pp = bp->b_pages;
		dmareq.dmar_object.dmao_obj.pp_obj.pp_offset =
		    (uint_t)(((uintptr_t)bp->b_un.b_addr) & MMU_PAGEOFFSET);
	} else {
		dmareq.dmar_object.dmao_obj.virt_obj.v_addr = bp->b_un.b_addr;
		if ((bp->b_flags & (B_SHADOW|B_REMAPPED)) == B_SHADOW) {
			dmareq.dmar_object.dmao_obj.virt_obj.v_priv =
							bp->b_shadow;
			dmareq.dmar_object.dmao_type = DMA_OTYP_BUFVADDR;
		} else {
			dmareq.dmar_object.dmao_type =
				(bp->b_flags & (B_PHYS | B_REMAPPED))?
				DMA_OTYP_BUFVADDR : DMA_OTYP_VADDR;
			dmareq.dmar_object.dmao_obj.virt_obj.v_priv = NULL;
		}

		/*
		 * If the buffer has no proc pointer, or the proc
		 * struct has the kernel address space, or the buffer has
		 * been marked B_REMAPPED (meaning that it is now
		 * mapped into the kernel's address space), then
		 * the address space is kas (kernel address space).
		 */
		if (bp->b_proc == NULL || bp->b_proc->p_as == &kas ||
		    (bp->b_flags & B_REMAPPED) != 0) {
			dmareq.dmar_object.dmao_obj.virt_obj.v_as = 0;
		} else {
			dmareq.dmar_object.dmao_obj.virt_obj.v_as =
			    bp->b_proc->p_as;
		}
	}

	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_bindhdl;
	return ((*funcp)(dip, dip, handle, &dmareq, cookiep, ccountp));
}

int
fc_ddi_dma_unbind_handle(ddi_dma_handle_t handle)
{
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_handle_t);
	ddi_dma_impl_t *hp;
	dev_info_t *dip;

	hp = (ddi_dma_impl_t *)handle;
	dip = hp->dmai_rdip;
	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_unbindhdl;
	return ((*funcp)(dip, dip, handle));
}

void
fc_ddi_dma_free_handle(ddi_dma_handle_t *handlep)
{
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_handle_t);
	ddi_dma_impl_t *hp;
	dev_info_t *dip;

	hp = (ddi_dma_impl_t *)*handlep;
	dip = hp->dmai_rdip;
	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_freehdl;
	(void) (*funcp)(dip, dip, *handlep);
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
