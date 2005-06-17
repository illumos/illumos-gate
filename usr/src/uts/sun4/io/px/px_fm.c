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
 * PX Fault Management Architecture
 */
#include <sys/types.h>
#include <sys/sunndi.h>
#include <sys/sunddi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/membar.h>
#include "px_obj.h"

/*
 * Initialize px FMA support
 */
int
px_fm_attach(px_t *px_p)
{
	px_p->px_fm_cap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
		DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;

	/*
	 * check parents' capability
	 */
	ddi_fm_init(px_p->px_dip, &px_p->px_fm_cap, &px_p->px_fm_ibc);

	/*
	 * parents need to be ereport and error handling capable
	 */
	ASSERT(px_p->px_fm_cap &&
	    (DDI_FM_ERRCB_CAPABLE | DDI_FM_EREPORT_CAPABLE));

	/*
	 * register error callback in parent
	 */
	ddi_fm_handler_register(px_p->px_dip, px_fm_callback, px_p);

	return (DDI_SUCCESS);
}

/*
 * Deregister FMA
 */
void
px_fm_detach(px_t *px_p)
{
	ddi_fm_handler_unregister(px_p->px_dip);
	ddi_fm_fini(px_p->px_dip);
}

/*
 * Function used to setup access functions depending on level of desired
 * protection.
 */
void
px_fm_acc_setup(ddi_map_req_t *mp, dev_info_t *rdip)
{
	uchar_t fflag;
	ddi_acc_hdl_t *hp;
	ddi_acc_impl_t *ap;

	hp = mp->map_handlep;
	ap = (ddi_acc_impl_t *)hp->ah_platform_private;
	fflag = ap->ahi_common.ah_acc.devacc_attr_access;

	if (mp->map_op == DDI_MO_MAP_LOCKED) {
		ndi_fmc_insert(rdip, ACC_HANDLE, (void *)hp, NULL);
		switch (fflag) {
		case DDI_FLAGERR_ACC:
			ap->ahi_get8 = i_ddi_prot_get8;
			ap->ahi_get16 = i_ddi_prot_get16;
			ap->ahi_get32 = i_ddi_prot_get32;
			ap->ahi_get64 = i_ddi_prot_get64;
			ap->ahi_put8 = i_ddi_prot_put8;
			ap->ahi_put16 = i_ddi_prot_put16;
			ap->ahi_put32 = i_ddi_prot_put32;
			ap->ahi_put64 = i_ddi_prot_put64;
			ap->ahi_rep_get8 = i_ddi_prot_rep_get8;
			ap->ahi_rep_get16 = i_ddi_prot_rep_get16;
			ap->ahi_rep_get32 = i_ddi_prot_rep_get32;
			ap->ahi_rep_get64 = i_ddi_prot_rep_get64;
			ap->ahi_rep_put8 = i_ddi_prot_rep_put8;
			ap->ahi_rep_put16 = i_ddi_prot_rep_put16;
			ap->ahi_rep_put32 = i_ddi_prot_rep_put32;
			ap->ahi_rep_put64 = i_ddi_prot_rep_put64;
			break;
		case DDI_CAUTIOUS_ACC :
			ap->ahi_get8 = i_ddi_caut_get8;
			ap->ahi_get16 = i_ddi_caut_get16;
			ap->ahi_get32 = i_ddi_caut_get32;
			ap->ahi_get64 = i_ddi_caut_get64;
			ap->ahi_put8 = i_ddi_caut_put8;
			ap->ahi_put16 = i_ddi_caut_put16;
			ap->ahi_put32 = i_ddi_caut_put32;
			ap->ahi_put64 = i_ddi_caut_put64;
			ap->ahi_rep_get8 = i_ddi_caut_rep_get8;
			ap->ahi_rep_get16 = i_ddi_caut_rep_get16;
			ap->ahi_rep_get32 = i_ddi_caut_rep_get32;
			ap->ahi_rep_get64 = i_ddi_caut_rep_get64;
			ap->ahi_rep_put8 = i_ddi_caut_rep_put8;
			ap->ahi_rep_put16 = i_ddi_caut_rep_put16;
			ap->ahi_rep_put32 = i_ddi_caut_rep_put32;
			ap->ahi_rep_put64 = i_ddi_caut_rep_put64;
			break;
		default:
			break;
		}
	} else if (mp->map_op == DDI_MO_UNMAP) {
		ndi_fmc_remove(rdip, ACC_HANDLE, (void *)hp);
	}
}

/*
 * Function called after a dma fault occurred to find out whether the
 * fault address is associated with a driver that is able to handle faults
 * and recover from faults. The driver has to set DDI_DMA_FLAGERR and
 * cache dma handles in order to make this checking effective to help
 * recovery from dma faults.
 */
/* ARGSUSED */
static int
px_dma_check(dev_info_t *dip, const void *handle, const void *comp_addr,
    const void *not_used)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	pfn_t fault_pfn = mmu_btop(*(uint64_t *)comp_addr);
	pfn_t comp_pfn;
	int page;

	/*
	 * Assertion failure if DDI_FM_DMACHK_CAPABLE capability has not
	 * been effectively initialized during attach.
	 */
	ASSERT(mp);

	for (page = 0; page < mp->dmai_ndvmapages; page++) {
		comp_pfn = PX_GET_MP_PFN(mp, page);
		if (fault_pfn == comp_pfn)
			return (DDI_FM_NONFATAL);
	}

	return (DDI_FM_UNKNOWN);
}

/*
 * Function used to check if a given access handle owns the failing address.
 * Called by ndi_fmc_error, when we detect a PIO error.
 */
/* ARGSUSED */
static int
px_acc_check(dev_info_t *dip, const void *handle, const void *comp_addr,
    const void *not_used)
{
	pfn_t pfn, fault_pfn;
	ddi_acc_hdl_t *hp = impl_acc_hdl_get((ddi_acc_handle_t)handle);

	/*
	 * Assertion failure if DDI_FM_ACCCHK_CAPABLE capability has not
	 * been effectively initialized during attach.
	 */
	ASSERT(hp);

	pfn = hp->ah_pfn;
	fault_pfn = mmu_btop(*(uint64_t *)comp_addr);
	if (fault_pfn >= pfn && fault_pfn < (pfn + hp->ah_pnum))
		return (DDI_FM_NONFATAL);

	return (DDI_FM_UNKNOWN);
}

/*
 * Function used by PCI error handlers to check if captured address is stored
 * in the DMA or ACC handle caches.
 */
int
px_handle_lookup(dev_info_t *dip, int type, uint64_t fme_ena, void *afar)
{
	uint32_t cap = ((px_t *)DIP_TO_STATE(dip))->px_fm_cap;
	int (*f)() = type == DMA_HANDLE ?
	    (DDI_FM_DMA_ERR_CAP(cap) ? px_dma_check : NULL) :
	    (DDI_FM_ACC_ERR_CAP(cap) ? px_acc_check : NULL);

	return (f ? ndi_fmc_error(dip, NULL, type, f, fme_ena, afar) :
	    DDI_FM_UNKNOWN);
}

/*
 * Function used to initialize FMA for our children nodes. Called
 * through pci busops when child node calls ddi_fm_init.
 */
/*ARGSUSED*/
int
px_fm_init_child(dev_info_t *dip, dev_info_t *cdip, int cap,
    ddi_iblock_cookie_t *ibc_p)
{
	px_t *px_p = DIP_TO_STATE(dip);

	ASSERT(ibc_p != NULL);
	*ibc_p = px_p->px_fm_ibc;

	return (px_p->px_fm_cap);
}

/*
 * lock access for exclusive PCIe access
 */
void
px_bus_enter(dev_info_t *dip, ddi_acc_handle_t handle)
{
	px_pec_t	*pec_p = ((px_t *)DIP_TO_STATE(dip))->px_pec_p;

	/*
	 * Exclusive access has been used for cautious put/get,
	 * Both utilize i_ddi_ontrap which, on sparcv9, implements
	 * similar protection as what on_trap() does, and which calls
	 * membar  #Sync to flush out all cpu deferred errors
	 * prior to get/put operation, so here we're not calling
	 * membar  #Sync - a difference from what's in pci_bus_enter().
	 */
	mutex_enter(&pec_p->pec_pokefault_mutex);
	pec_p->pec_acc_hdl = handle;
}

/*
 * unlock access for exclusive PCIe access
 */
/* ARGSUSED */
void
px_bus_exit(dev_info_t *dip, ddi_acc_handle_t handle)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	px_pec_t	*pec_p = px_p->px_pec_p;

	pec_p->pec_acc_hdl = NULL;
	mutex_exit(&pec_p->pec_pokefault_mutex);
}


/*
 * PCI error callback which is registered with our parent to call
 * for PCIe logging when the CPU traps due to PCIe Uncorrectable Errors
 * and PCI BERR/TO/UE
 *
 * Dispatch on all known leaves of this fire device because we cannot tell
 * which side the error came from.
 */
/*ARGSUSED*/
int
px_fm_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *impl_data)
{
	px_t	*px_p = (px_t *)impl_data;
	px_cb_t	*cb_p = px_p->px_cb_p;
	int	err = PX_OK;
	int	fatal = 0;
	int	nonfatal = 0;
	int	unknown = 0;
	int	ret = DDI_FM_OK;
	int	i;

	mutex_enter(&cb_p->xbc_fm_mutex);

	for (i = 0; i < PX_CB_MAX_LEAF; i++) {
		px_p = cb_p->xbc_px_list[i];
		if (px_p != NULL)
			err |= px_err_handle(px_p, derr, PX_TRAP_CALL,
			    (i == 0));
	}

	for (i = 0; i < PX_CB_MAX_LEAF; i++) {
		px_p = cb_p->xbc_px_list[i];
		if (px_p != NULL) {
			ret = ndi_fm_handler_dispatch(px_p->px_dip, NULL, derr);
			switch (ret) {
			case DDI_FM_FATAL:
				fatal++;
				break;
			case DDI_FM_NONFATAL:
				nonfatal++;
				break;
			case DDI_FM_UNKNOWN:
				unknown++;
				break;
			default:
				break;
			}
		}
	}
	mutex_exit(&cb_p->xbc_fm_mutex);

	ret = (fatal != 0) ? DDI_FM_FATAL :
	    ((nonfatal != 0) ? DDI_FM_NONFATAL :
	    (((unknown != 0) ? DDI_FM_UNKNOWN : DDI_FM_OK)));

	/* fire fatal error overrides device error */
	if (err & (PX_FATAL_GOS | PX_FATAL_SW))
		ret = DDI_FM_FATAL;
	/* if fire encounts no error, then take whatever device error */
	else if ((err != PX_OK) && (ret != DDI_FM_FATAL))
		ret = DDI_FM_NONFATAL;

	return (ret);
}

/*
 * px_err_dmc_pec_intr:
 * Interrupt handler for the DMC/PEC block.
 * o lock
 * o create derr
 * o px_err_handle(leaf, with jbc)
 * o send ereport(fire fmri, derr, payload = BDF)
 * o dispatch (leaf)
 * o unlock
 * o handle error: fatal? fm_panic() : return INTR_CLAIMED)
 */
/* ARGSUSED */
uint_t
px_err_fabric_intr(px_t *px_p, msgcode_t msg_code,
    pcie_req_id_t rid)
{
	dev_info_t	*rpdip = px_p->px_dip;
	px_cb_t		*cb_p = px_p->px_cb_p;
	int		err = PX_OK, ret;
	ddi_fm_error_t	derr;

	mutex_enter(&cb_p->xbc_fm_mutex);

	/* Create the derr */
	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	derr.fme_flag = DDI_FM_ERR_UNEXPECTED;

	/* send ereport/handle/clear fire registers */
	err |= px_err_handle(px_p, &derr, PX_INTR_CALL, B_TRUE);

	/* Check all child devices for errors */
	ret = ndi_fm_handler_dispatch(rpdip, NULL, &derr);

	mutex_exit(&cb_p->xbc_fm_mutex);

	/*
	 * PX_FATAL_HW indicates a condition recovered from Fatal-Reset,
	 * therefore it does not cause panic.
	 */
	if ((err & (PX_FATAL_GOS | PX_FATAL_SW)) || (ret == DDI_FM_FATAL))
		fm_panic("Fatal PCIe Fabric Error has occurred\n");

	return (DDI_INTR_CLAIMED);
}

/*
 * px_err_safeacc_check:
 * Check to see if a peek/poke and cautious access is currently being
 * done on a particular leaf.
 *
 * Safe access reads induced fire errors will be handled by cpu trap handler
 * which will call px_fm_callback() which calls this function. In that
 * case, the derr fields will be set by trap handler with the correct values.
 *
 * Safe access writes induced errors will be handled by px interrupt
 * handlers, this function will fill in the derr fields.
 *
 * If a cpu trap does occur, it will quiesce all other interrupts allowing
 * the cpu trap error handling to finish before Fire receives an interrupt.
 *
 * If fire does indeed have an error when a cpu trap occurs as a result of
 * a safe access, a trap followed by a Mondo/Fabric interrupt will occur.
 * In which case derr will be initialized as "UNEXPECTED" by the interrupt
 * handler and this function will need to find if this error occured in the
 * middle of a safe access operation.
 *
 * @param px_p		leaf in which to check access
 * @param derr		fm err data structure to be updated
 */
void
px_err_safeacc_check(px_t *px_p, ddi_fm_error_t *derr)
{
	px_pec_t 	*pec_p = px_p->px_pec_p;
	px_cb_t		*cb_p = px_p->px_cb_p;
	int		acctype = pec_p->pec_safeacc_type;

	ASSERT(MUTEX_HELD(&cb_p->xbc_fm_mutex));

	if (derr->fme_flag != DDI_FM_ERR_UNEXPECTED) {
		return;
	}

	/* safe access checking */
	switch (acctype) {
	case DDI_FM_ERR_EXPECTED:
		/*
		 * cautious access protection, protected from all err.
		 */
		ASSERT(MUTEX_HELD(&pec_p->pec_pokefault_mutex));
		ddi_fm_acc_err_get(pec_p->pec_acc_hdl, derr,
		    DDI_FME_VERSION);
		derr->fme_flag = acctype;
		derr->fme_acc_handle = pec_p->pec_acc_hdl;
		break;
	case DDI_FM_ERR_POKE:
		/*
		 * ddi_poke protection, check nexus and children for
		 * expected errors.
		 */
		ASSERT(MUTEX_HELD(&pec_p->pec_pokefault_mutex));
		membar_sync();
		derr->fme_flag = acctype;
		break;
	case DDI_FM_ERR_PEEK:
		derr->fme_flag = acctype;
		break;
	}
}
