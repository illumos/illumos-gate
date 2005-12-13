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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/cpu.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pte.h>
#include <sys/machsystm.h>
#include <sys/mmu.h>
#include <sys/dvma.h>
#include <sys/debug.h>

#define	HD	((ddi_dma_impl_t *)h)->dmai_rdip

unsigned long
dvma_pagesize(dev_info_t *dip)
{
	auto unsigned long dvmapgsz;

	(void) ddi_ctlops(dip, dip, DDI_CTLOPS_DVMAPAGESIZE,
	    NULL, (void *) &dvmapgsz);
	return (dvmapgsz);
}

int
dvma_reserve(dev_info_t *dip,  ddi_dma_lim_t *limp, uint_t pages,
    ddi_dma_handle_t *handlep)
{
	auto ddi_dma_lim_t dma_lim;
	auto ddi_dma_impl_t implhdl;
	struct ddi_dma_req dmareq;
	ddi_dma_handle_t reqhdl;
	ddi_dma_impl_t *mp;
	int ret;

	if (limp == (ddi_dma_lim_t *)0) {
		return (DDI_DMA_BADLIMITS);
	} else {
		dma_lim = *limp;
	}
	bzero(&dmareq, sizeof (dmareq));
	dmareq.dmar_fp = DDI_DMA_DONTWAIT;
	dmareq.dmar_flags = DDI_DMA_RDWR | DDI_DMA_STREAMING;
	dmareq.dmar_limits = &dma_lim;
	dmareq.dmar_object.dmao_size = pages;
	/*
	 * pass in a dummy handle. This avoids the problem when
	 * somebody is dereferencing the handle before checking
	 * the operation. This can be avoided once we separate
	 * handle allocation and actual operation.
	 */
	bzero((caddr_t)&implhdl, sizeof (ddi_dma_impl_t));
	reqhdl = (ddi_dma_handle_t)&implhdl;

	ret = ddi_dma_mctl(dip, dip, reqhdl, DDI_DMA_RESERVE, (off_t *)&dmareq,
	    0, (caddr_t *)handlep, 0);

	if (ret == DDI_SUCCESS) {
		mp = (ddi_dma_impl_t *)(*handlep);
		if (!(mp->dmai_rflags & DMP_BYPASSNEXUS)) {
			uint_t np = mp->dmai_ndvmapages;

			mp->dmai_mapping = (ulong_t)kmem_alloc(
				sizeof (ddi_dma_lim_t), KM_SLEEP);
			bcopy((char *)&dma_lim, (char *)mp->dmai_mapping,
			    sizeof (ddi_dma_lim_t));
			mp->dmai_minfo = kmem_alloc(
				np * sizeof (ddi_dma_handle_t), KM_SLEEP);
		}
	}
	return (ret);
}

void
dvma_release(ddi_dma_handle_t h)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	uint_t np = mp->dmai_ndvmapages;

	if (!(mp->dmai_rflags & DMP_BYPASSNEXUS)) {
		kmem_free((void *)mp->dmai_mapping, sizeof (ddi_dma_lim_t));
		kmem_free(mp->dmai_minfo, np * sizeof (ddi_dma_handle_t));
	}
	(void) ddi_dma_mctl(HD, HD, h, DDI_DMA_RELEASE, 0, 0, 0, 0);

}

void
dvma_kaddr_load(ddi_dma_handle_t h, caddr_t a, uint_t len, uint_t index,
	ddi_dma_cookie_t *cp)
{
	register ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	struct fast_dvma *nexus_private;
	struct dvma_ops *nexus_funcptr;
	ddi_dma_attr_t dma_attr;
	uint_t ccnt;

	if (mp->dmai_rflags & DMP_BYPASSNEXUS) {
		nexus_private = (struct fast_dvma *)mp->dmai_nexus_private;
		nexus_funcptr = (struct dvma_ops *)nexus_private->ops;
		(void) (*nexus_funcptr->dvma_kaddr_load)(h, a, len, index, cp);
	} else {
		ddi_dma_handle_t handle;
		ddi_dma_lim_t *limp;

		limp = (ddi_dma_lim_t *)mp->dmai_mapping;
		dma_attr.dma_attr_version = DMA_ATTR_V0;
		dma_attr.dma_attr_addr_lo = limp->dlim_addr_lo;
		dma_attr.dma_attr_addr_hi = limp->dlim_addr_hi;
		dma_attr.dma_attr_count_max = limp->dlim_cntr_max;
		dma_attr.dma_attr_align = 1;
		dma_attr.dma_attr_burstsizes = limp->dlim_burstsizes;
		dma_attr.dma_attr_minxfer = limp->dlim_minxfer;
		dma_attr.dma_attr_maxxfer = 0xFFFFFFFFull;
		dma_attr.dma_attr_seg = 0xFFFFFFFFull;
		dma_attr.dma_attr_sgllen = 1;
		dma_attr.dma_attr_granular = 1;
		dma_attr.dma_attr_flags = 0;
		(void) ddi_dma_alloc_handle(HD, &dma_attr, DDI_DMA_SLEEP, NULL,
		    &handle);
		(void) ddi_dma_addr_bind_handle(handle, NULL, a, len,
		    DDI_DMA_RDWR, DDI_DMA_SLEEP, NULL, cp, &ccnt);
		((ddi_dma_handle_t *)mp->dmai_minfo)[index] = handle;
	}
}

/*ARGSUSED*/
void
dvma_unload(ddi_dma_handle_t h, uint_t objindex, uint_t type)
{
	register ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	struct fast_dvma *nexus_private;
	struct dvma_ops *nexus_funcptr;

	if (mp->dmai_rflags & DMP_BYPASSNEXUS) {
		nexus_private = (struct fast_dvma *)mp->dmai_nexus_private;
		nexus_funcptr = (struct dvma_ops *)nexus_private->ops;
		(void) (*nexus_funcptr->dvma_unload)(h, objindex, type);
	} else {
		ddi_dma_handle_t handle;

		handle = ((ddi_dma_handle_t *)mp->dmai_minfo)[objindex];
		(void) ddi_dma_unbind_handle(handle);
		(void) ddi_dma_free_handle(&handle);
	}
}

void
dvma_sync(ddi_dma_handle_t h, uint_t objindex, uint_t type)
{
	register ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	struct fast_dvma *nexus_private;
	struct dvma_ops *nexus_funcptr;

	if (mp->dmai_rflags & DMP_BYPASSNEXUS) {
		nexus_private = (struct fast_dvma *)mp->dmai_nexus_private;
		nexus_funcptr = (struct dvma_ops *)nexus_private->ops;
		(void) (*nexus_funcptr->dvma_sync)(h, objindex, type);
	} else {
		ddi_dma_handle_t handle;

		handle = ((ddi_dma_handle_t *)mp->dmai_minfo)[objindex];
		(void) ddi_dma_sync(handle, 0, 0, type);
	}
}
