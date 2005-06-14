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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PCI nexus driver general debug support
 */
#include <sys/promif.h>		/* prom_printf */
#include <sys/async.h>
#include <sys/sunddi.h>		/* dev_info_t */
#include <sys/ddi_impldefs.h>
#include <sys/pci/pci_obj.h>

/*LINTLIBRARY*/

#ifdef DEBUG
extern uint64_t pci_debug_flags;

pci_debug_flag_to_string_t pci_flags_to_string [] = {
	{DBG_ATTACH,		"attach"},
	{DBG_DETACH,		"detach"},
	{DBG_MAP,		"map"},
	{DBG_RSV1,		"reserved"},
	{DBG_A_INTX,		"add_intx"},
	{DBG_R_INTX,		"rem_intx"},
	{DBG_INIT_CLD,		"init_child"},
	{DBG_CTLOPS,		"ctlops"},
	{DBG_INTR,		"intr_wrapper"},
	{DBG_ERR_INTR,		"pbm_error_intr"},
	{DBG_BUS_FAULT,		"pci_fault"},
	{DBG_DMA_ALLOCH,	"dma_alloc_handle"},
	{DBG_DMA_FREEH,		"dma_free_handle"},
	{DBG_DMA_BINDH,		"dma_bind_handle"},
	{DBG_DMA_UNBINDH,	"dma_unbind_handle"},
	{DBG_DMA_MAP,		"dma_map"},
	{DBG_CHK_MOD,		"check_dma_mode"},
	{DBG_BYPASS,		"bypass"},
	{DBG_IOMMU,		"iommu"},
	{DBG_DMA_WIN,		"dma_win"},
	{DBG_MAP_WIN,		"map_window"},
	{DBG_UNMAP_WIN,		"unmap_window"},
	{DBG_DMA_CTL,		"dma_ctl"},
	{DBG_DMA_SYNC,		"dma_sync"},
	{DBG_DMA_SYNC_PBM,	"dma_sync_pbm"},
	{DBG_FAST_DVMA,		"fast_dvma"},
	{DBG_IB,		"ib"},
	{DBG_CB,		"cb"},
	{DBG_PBM,		"pbm"},
	{DBG_OPEN,		"open"},
	{DBG_CLOSE,		"close"},
	{DBG_IOCTL,		"ioctl"},
	{DBG_SC,		"sc"},
	{DBG_PWR,		"pwr"},
	{DBG_RELOC,		"dma_reloc"},
	{DBG_TOOLS,		"tools"},
	{DBG_PHYS_ACC,		"phys_acc"}
};

void
pci_debug(uint64_t flag, dev_info_t *dip, char *fmt,
	uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
	char *s = NULL;
	uint_t cont = 0;

	if (flag & DBG_CONT) {
		flag &= ~DBG_CONT;
		cont = 1;
	}
	if ((pci_debug_flags & flag) == flag) {
		int i;
		int no_rec = (sizeof (pci_flags_to_string) /
		    sizeof (pci_debug_flag_to_string_t));
		for (i = 0; i < no_rec; i++) {
			if (pci_flags_to_string[i].flag == flag) {
				s = pci_flags_to_string[i].string;
				break;
			}
		}

		if (i >= no_rec)
			s = "PCI debug unknown";

		if (s && cont == 0) {
			prom_printf("%s(%d): %s: ", ddi_driver_name(dip),
			    ddi_get_instance(dip), s);
		}
		prom_printf(fmt, a1, a2, a3, a4, a5);
	}
}
#endif
