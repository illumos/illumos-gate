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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/debug.h>

#include "ata_common.h"
#include "ata_disk.h"
#include "atapi.h"
#include "pciide.h"

/*
 * grap the PCI-IDE status byte
 */
#define	PCIIDE_STATUS_GET(hdl, addr)	\
	ddi_get8((hdl), ((uchar_t *)(addr) + PCIIDE_BMISX_REG))

/*
 * DMA attributes for device I/O
 */

ddi_dma_attr_t ata_pciide_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffU,		/* dma_attr_addr_hi */
	0xffff,			/* dma_attr_count_max */
	sizeof (int),		/* dma_attr_align */
	1,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x100 << SCTRSHFT,	/* dma_attr_maxxfer */
				/* note that this value can change */
				/* based on max_transfer property */
	0xffff,			/* dma_attr_seg */
	ATA_DMA_NSEGS,		/* dma_attr_sgllen */
	512,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

/*
 * DMA attributes for the Bus Mastering PRD table
 *
 * PRD table Must not cross 4k boundary.
 *
 * NOTE: the SFF-8038i spec says don't cross a 64k boundary but
 * some chip specs seem to think the spec says 4k boundary, Intel
 * 82371AB, section 5.2.3. I don't know whether the 4k restriction
 * is for real or just a typo. I've specified 4k just to be safe.
 * The same Intel spec says the buffer must be 64K aligned, I don't
 * believe that and have specified 4 byte alignment.
 *
 */

#define	PCIIDE_BOUNDARY	(0x1000)

ddi_dma_attr_t ata_prd_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffU,		/* dma_attr_addr_hi */
	PCIIDE_BOUNDARY - 1,	/* dma_attr_count_max */
	sizeof (int),		/* dma_attr_align */
	1,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	PCIIDE_BOUNDARY,	/* dma_attr_maxxfer */
	PCIIDE_BOUNDARY - 1,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};



size_t	prd_size = sizeof (prde_t) * ATA_DMA_NSEGS;

int
ata_pciide_alloc(
	dev_info_t *dip,
	ata_ctl_t *ata_ctlp)
{
	ddi_device_acc_attr_t	dev_attr;
	ddi_dma_cookie_t	cookie;
	size_t			buf_size;
	uint_t			count;
	int			rc;

	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;


	rc = ddi_dma_alloc_handle(dip, &ata_prd_dma_attr, DDI_DMA_SLEEP, NULL,
		&ata_ctlp->ac_sg_handle);
	if (rc != DDI_SUCCESS) {
		ADBG_ERROR(("ata_pciide_alloc 0x%p handle %d\n",
		    (void *)ata_ctlp, rc));
		goto err3;
	}

	rc = ddi_dma_mem_alloc(ata_ctlp->ac_sg_handle, prd_size, &dev_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &ata_ctlp->ac_sg_list, &buf_size, &ata_ctlp->ac_sg_acc_handle);
	if (rc != DDI_SUCCESS) {
		ADBG_ERROR(("ata_pciide_alloc 0x%p mem %d\n",
		    (void *)ata_ctlp, rc));
		goto err2;
	}

	rc = ddi_dma_addr_bind_handle(ata_ctlp->ac_sg_handle, NULL,
	    ata_ctlp->ac_sg_list, buf_size,
	    DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &cookie, &count);
	if (rc != DDI_DMA_MAPPED) {
		ADBG_ERROR(("ata_pciide_alloc 0x%p bind %d\n",
		    (void *)ata_ctlp, rc));
		goto err1;
	}

	ASSERT(count == 1);
	ASSERT((cookie.dmac_address & (sizeof (int) - 1)) == 0);
#define	Mask4K	0xfffff000
	ASSERT((cookie.dmac_address & Mask4K)
		== ((cookie.dmac_address + cookie.dmac_size - 1) & Mask4K));

	ata_ctlp->ac_sg_paddr = cookie.dmac_address;
	return (TRUE);
err1:
	ddi_dma_mem_free(&ata_ctlp->ac_sg_acc_handle);
	ata_ctlp->ac_sg_acc_handle = NULL;
err2:
	ddi_dma_free_handle(&ata_ctlp->ac_sg_handle);
	ata_ctlp->ac_sg_handle = NULL;
err3:
	return (FALSE);
}


void
ata_pciide_free(ata_ctl_t *ata_ctlp)
{
	if (ata_ctlp->ac_sg_handle == NULL)
		return;

	(void) ddi_dma_unbind_handle(ata_ctlp->ac_sg_handle);
	ddi_dma_mem_free(&ata_ctlp->ac_sg_acc_handle);
	ddi_dma_free_handle(&ata_ctlp->ac_sg_handle);
	ata_ctlp->ac_sg_handle = NULL;
	ata_ctlp->ac_sg_acc_handle = NULL;
}



void
ata_pciide_dma_setup(
	ata_ctl_t *ata_ctlp,
	prde_t	  *srcp,
	int	   sg_cnt)
{
	ddi_acc_handle_t bmhandle = ata_ctlp->ac_bmhandle;
	caddr_t		 bmaddr = ata_ctlp->ac_bmaddr;
	ddi_acc_handle_t sg_acc_handle = ata_ctlp->ac_sg_acc_handle;
	uint_t		*dstp = (uint_t *)ata_ctlp->ac_sg_list;
	int		 idx;

	ASSERT(dstp != 0);
	ASSERT(sg_cnt != 0);

	ADBG_DMA(("ata dma_setup 0x%p 0x%p %d\n", ata_ctlp, srcp, sg_cnt));
	/*
	 * Copy the PRD list to controller's phys buffer.
	 * Copying to a fixed location avoids having to check
	 * every ata_pkt for alignment and page boundaries.
	 */
	for (idx = 0; idx < sg_cnt - 1; idx++, srcp++) {
		ddi_put32(sg_acc_handle, dstp++, srcp->p_address);
		ddi_put32(sg_acc_handle, dstp++, srcp->p_count);
	}

	/*
	 * set the end of table flag in the last entry
	 */
	srcp->p_count |= PCIIDE_PRDE_EOT;
	ddi_put32(sg_acc_handle, dstp++, srcp->p_address);
	ddi_put32(sg_acc_handle, dstp++, srcp->p_count);

	/*
	 * give the pciide chip the physical address of the PRDE table
	 */
	ddi_put32(bmhandle, (uint_t *)(bmaddr + PCIIDE_BMIDTPX_REG),
		ata_ctlp->ac_sg_paddr);

	ADBG_DMA(("ata dma_setup 0x%p 0x%llx\n",
		bmaddr, (unsigned long long)ata_ctlp->ac_sg_paddr));
}



void
ata_pciide_dma_start(
	ata_ctl_t *ata_ctlp,
	uchar_t direction)
{
	ddi_acc_handle_t bmhandle = ata_ctlp->ac_bmhandle;
	caddr_t		 bmaddr = ata_ctlp->ac_bmaddr;
	uchar_t		 tmp;

	ASSERT((ata_ctlp->ac_sg_paddr & PCIIDE_BMIDTPX_MASK) == 0);
	ASSERT((direction == PCIIDE_BMICX_RWCON_WRITE_TO_MEMORY) ||
		(direction == PCIIDE_BMICX_RWCON_READ_FROM_MEMORY));

	/*
	 * Set the direction control and start the PCIIDE DMA controller
	 */
	tmp = ddi_get8(bmhandle, (uchar_t *)bmaddr + PCIIDE_BMICX_REG);
	tmp &= PCIIDE_BMICX_MASK;
	ddi_put8(bmhandle, (uchar_t *)bmaddr + PCIIDE_BMICX_REG,
		(tmp |  direction));

	ddi_put8(bmhandle, (uchar_t *)bmaddr + PCIIDE_BMICX_REG,
		(tmp | PCIIDE_BMICX_SSBM_E | direction));

	return;

}


void
ata_pciide_dma_stop(
	ata_ctl_t *ata_ctlp)
{
	ddi_acc_handle_t bmhandle = ata_ctlp->ac_bmhandle;
	caddr_t		 bmaddr = ata_ctlp->ac_bmaddr;
	uchar_t		 tmp;

	/*
	 * Stop the PCIIDE DMA controller
	 */
	tmp = ddi_get8(bmhandle, (uchar_t *)bmaddr + PCIIDE_BMICX_REG);
	tmp &= (PCIIDE_BMICX_MASK & (~PCIIDE_BMICX_SSBM));

	ADBG_DMA(("ata_pciide_dma_stop 0x%p 0x%x\n", bmaddr, tmp));

	ddi_put8(bmhandle, (uchar_t *)bmaddr + PCIIDE_BMICX_REG, tmp);
}

/* ARGSUSED */
void
ata_pciide_dma_sg_func(
	gcmd_t	*gcmdp,
	ddi_dma_cookie_t *dmackp,
	int	 single_segment,
	int	 seg_index)
{
	ata_pkt_t *ata_pktp = GCMD2APKT(gcmdp);
	prde_t	  *dmap;

	ASSERT(seg_index < ATA_DMA_NSEGS);
	ASSERT(((uint_t)dmackp->dmac_address & PCIIDE_PRDE_ADDR_MASK) == 0);
	ASSERT((dmackp->dmac_size & PCIIDE_PRDE_CNT_MASK) == 0);
	ASSERT(dmackp->dmac_size <= PCIIDE_PRDE_CNT_MAX);

	ADBG_TRACE(("adp_dma_sg_func: gcmdp 0x%p dmackp 0x%p s %d idx %d\n",
		    gcmdp, dmackp, single_segment, seg_index));

	/* set address of current entry in scatter/gather list */
	dmap = ata_pktp->ap_sg_list + seg_index;

	/* store the phys addr and count from the cookie */
	dmap->p_address = (uint_t)dmackp->dmac_address;
	dmap->p_count = (uint_t)dmackp->dmac_size;

	/* save the count of scatter/gather segments */
	ata_pktp->ap_sg_cnt = seg_index + 1;

	/* compute the total bytes in this request */
	if (seg_index == 0)
		ata_pktp->ap_bcount = 0;
	ata_pktp->ap_bcount += dmackp->dmac_size;
}



int
ata_pciide_status_clear(
	ata_ctl_t *ata_ctlp)
{
	ddi_acc_handle_t bmhandle = ata_ctlp->ac_bmhandle;
	caddr_t		 bmaddr = ata_ctlp->ac_bmaddr;
	uchar_t		 status;
	uchar_t		 tmp;

	/*
	 * Get the current PCIIDE status
	 */
	status = PCIIDE_STATUS_GET(ata_ctlp->ac_bmhandle, ata_ctlp->ac_bmaddr);
	tmp = status & PCIIDE_BMISX_MASK;
	tmp |= (PCIIDE_BMISX_IDERR | PCIIDE_BMISX_IDEINTS);

	ADBG_DMA(("ata_pciide_status_clear 0x%p 0x%x\n",
		bmaddr, status));

	/*
	 * Clear the latches (and preserve the other bits)
	 */
	ddi_put8(bmhandle, (uchar_t *)bmaddr + PCIIDE_BMISX_REG, tmp);

#ifdef NAT_SEMI_PC87415_BUG
	/* ??? chip errata ??? */
	if (ata_ctlp->ac_nat_semi_bug) {
		tmp = ddi_get8(bmhandle, bmaddr + PCIIDE_BMICX_REG);
		tmp &= PCIIDE_BMICX_MASK;
		ddi_put8(bmhandle, bmaddr + PCIIDE_BMICX_REG,
			(tmp | PCIIDE_BMISX_IDERR | PCIIDE_BMISX_IDEINTS));
	}
#endif
	return (status);
}

int
ata_pciide_status_dmacheck_clear(
	ata_ctl_t *ata_ctlp)
{
	uchar_t		 status;

	/*
	 * Get the PCIIDE DMA controller's current status
	 */
	status = ata_pciide_status_clear(ata_ctlp);

	ADBG_DMA(("ata_pciide_status_dmacheck_clear 0x%p 0x%x\n",
		ata_ctlp->ac_bmaddr, status));
	/*
	 * check for errors
	 */
	if (status & PCIIDE_BMISX_IDERR) {
		ADBG_WARN(("ata_pciide_status: 0x%x\n", status));
		return (TRUE);
	}
	return (FALSE);
}



/*
 * Check for a pending PCI-IDE interrupt
 */

int
ata_pciide_status_pending(
	ata_ctl_t *ata_ctlp)
{
	uchar_t status;

	status = PCIIDE_STATUS_GET(ata_ctlp->ac_bmhandle, ata_ctlp->ac_bmaddr);
	ADBG_DMA(("ata_pciide_status_pending 0x%p 0x%x\n",
		ata_ctlp->ac_bmaddr, status));
	if (status & PCIIDE_BMISX_IDEINTS)
		return (TRUE);
	return (FALSE);
}
