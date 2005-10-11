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

typedef struct px_fabric_cfgspace {
	/* Error information */
	msgcode_t	msg_code;
	pcie_req_id_t	rid;

	/* Config space header and device type */
	uint8_t		hdr_type;
	uint16_t	dev_type;

	/* Register pointers */
	uint16_t	cap_off;
	uint16_t	aer_off;

	/* PCI register values */
	uint32_t	sts_reg;
	uint32_t	sts_sreg;

	/* PCIE register values */
	uint32_t	dev_sts_reg;
	uint32_t	aer_ce_reg;
	uint32_t	aer_ue_reg;
	uint32_t	aer_sev_reg;
	uint32_t	aer_ue_sreg;
	uint32_t	aer_sev_sreg;

	/* PCIE Header Log Registers */
	uint32_t	aer_h1;
	uint32_t	aer_h2;
	uint32_t	aer_h3;
	uint32_t	aer_h4;
	uint32_t	aer_sh1;
	uint32_t	aer_sh2;
	uint32_t	aer_sh3;
	uint32_t	aer_sh4;
} px_fabric_cfgspace_t;

static uint16_t px_fabric_get_aer(px_t *px_p, pcie_req_id_t rid);
static uint16_t px_fabric_get_pciecap(px_t *px_p, pcie_req_id_t rid);
static int px_fabric_handle_psts(px_fabric_cfgspace_t *cs);
static int px_fabric_handle_ssts(px_fabric_cfgspace_t *cs);
static int px_fabric_handle_paer(px_t *px_p, px_fabric_cfgspace_t *cs);
static int px_fabric_handle_saer(px_t *px_p, px_fabric_cfgspace_t *cs);
static int px_fabric_handle(px_t *px_p, px_fabric_cfgspace_t *cs);
static void px_fabric_fill_cs(px_t *px_p, px_fabric_cfgspace_t *cs);
static uint_t px_fabric_check(px_t *px_p, msgcode_t msg_code,
    pcie_req_id_t rid, ddi_fm_error_t *derr);

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

static uint16_t
px_fabric_get_aer(px_t *px_p, pcie_req_id_t rid)
{
	uint32_t	hdr, hdr_next_ptr, hdr_cap_id;
	uint16_t	offset = PCIE_EXT_CAP;
	int		deadcount = 0;

	/* Find the Advanced Error Register */
	hdr = px_fab_get(px_p, rid, offset);
	hdr_next_ptr = (hdr >> PCIE_EXT_CAP_NEXT_PTR_SHIFT) &
	    PCIE_EXT_CAP_NEXT_PTR_MASK;
	hdr_cap_id = (hdr >> PCIE_EXT_CAP_ID_SHIFT) &
	    PCIE_EXT_CAP_ID_MASK;

	while ((hdr_next_ptr != PCIE_EXT_CAP_NEXT_PTR_NULL) &&
	    (hdr_cap_id != PCIE_EXT_CAP_ID_AER)) {
		offset = hdr_next_ptr;
		hdr = px_fab_get(px_p, rid, offset);
		hdr_next_ptr = (hdr >> PCIE_EXT_CAP_NEXT_PTR_SHIFT) &
		    PCIE_EXT_CAP_NEXT_PTR_MASK;
		hdr_cap_id = (hdr >> PCIE_EXT_CAP_ID_SHIFT) &
		    PCIE_EXT_CAP_ID_MASK;

		if (deadcount++ > 100)
			break;
	}

	if (hdr_cap_id == PCIE_EXT_CAP_ID_AER)
		return (offset);

	return (0);
}

static uint16_t
px_fabric_get_pciecap(px_t *px_p, pcie_req_id_t rid)
{
	uint32_t	hdr, hdr_next_ptr, hdr_cap_id;
	uint16_t	offset = PCI_CONF_STAT;
	int		deadcount = 0;

	hdr = px_fab_get(px_p, rid, PCI_CONF_COMM) >> 16;
	if (!(hdr & PCI_STAT_CAP)) {
		/* This is not a PCIE device */
		return (0);
	}

	hdr = px_fab_get(px_p, rid, PCI_CONF_CAP_PTR);
	hdr_next_ptr = hdr & 0xFF;
	hdr_cap_id = 0;

	while ((hdr_next_ptr != PCI_CAP_NEXT_PTR_NULL) &&
	    (hdr_cap_id != PCI_CAP_ID_PCI_E)) {
		offset = hdr_next_ptr;

		if (hdr_next_ptr < 0x40) {
			break;
		}

		hdr = px_fab_get(px_p, rid, hdr_next_ptr);
		hdr_next_ptr = (hdr >> 8) & 0xFF;
		hdr_cap_id = hdr & 0xFF;

		if (deadcount++ > 100)
			break;
	}

	if (hdr_cap_id == PCI_CAP_ID_PCI_E)
		return (offset);

	return (0);
}

/*
 * This function checks the primary status registers.
 * Take the PCI status register and translate it to PCIe equivalent.
 */
static int
px_fabric_handle_psts(px_fabric_cfgspace_t *cs) {
	uint16_t	sts_reg = cs->sts_reg >> 16;
	uint16_t	pci_status;
	uint32_t	pcie_status;
	int		ret = PX_NONFATAL;

	/* Parity Err == Send/Recv Poisoned TLP */
	pci_status = PCI_STAT_S_PERROR | PCI_STAT_PERROR;
	pcie_status = PCIE_AER_UCE_PTLP | PCIE_AER_UCE_ECRC;
	if (sts_reg & pci_status)
		ret |= PX_FABRIC_ERR_SEV(pcie_status,
		    px_fabric_die_ue, px_fabric_die_ue_gos);

	/* Target Abort == Completer Abort */
	pci_status = PCI_STAT_S_TARG_AB | PCI_STAT_R_TARG_AB;
	pcie_status = PCIE_AER_UCE_CA;
	if (sts_reg & pci_status)
		ret |= PX_FABRIC_ERR_SEV(pcie_status,
		    px_fabric_die_ue, px_fabric_die_ue_gos);

	/* Master Abort == Unsupport Request */
	pci_status = PCI_STAT_R_MAST_AB;
	pcie_status = PCIE_AER_UCE_UR;
	if (sts_reg & pci_status)
		ret |= PX_FABRIC_ERR_SEV(pcie_status,
		    px_fabric_die_ue, px_fabric_die_ue_gos);

	/* System Error == Uncorrectable Error */
	pci_status = PCI_STAT_S_SYSERR;
	pcie_status = -1;
	if (sts_reg & pci_status)
		ret |= PX_FABRIC_ERR_SEV(pcie_status,
		    px_fabric_die_ue, px_fabric_die_ue_gos);

	return (ret);
}

/*
 * This function checks the secondary status registers.
 * Switches and Bridges have a different behavior.
 */
static int
px_fabric_handle_ssts(px_fabric_cfgspace_t *cs) {
	uint16_t	sts_reg = cs->sts_sreg >> 16;
	int		ret = PX_NONFATAL;

	if (cs->dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
		/*
		 * This is a PCIE-PCI bridge, but only check the severity
		 * if this device doesn't support AERs.
		 */
		if (!cs->aer_off)
			ret |= PX_FABRIC_ERR_SEV(sts_reg, px_fabric_die_bdg_sts,
			    px_fabric_die_bdg_sts_gos);
	} else {
		/* This is most likely a PCIE switch */
		ret |= PX_FABRIC_ERR_SEV(sts_reg, px_fabric_die_sw_sts,
		    px_fabric_die_sw_sts_gos);
	}

	return (ret);
}

/*
 * This function checks and clears the primary AER.
 */
static int
px_fabric_handle_paer(px_t *px_p, px_fabric_cfgspace_t *cs) {
	uint32_t	chk_reg, chk_reg_gos, off_reg, reg;
	int		ret = PX_NONFATAL;

	/* Determine severity and clear the AER */
	switch (cs->msg_code) {
	case PCIE_MSG_CODE_ERR_COR:
		off_reg = PCIE_AER_CE_STS;
		chk_reg = px_fabric_die_ce;
		chk_reg_gos = px_fabric_die_ce_gos;
		reg = cs->aer_ce_reg;
		break;
	case PCIE_MSG_CODE_ERR_NONFATAL:
		off_reg = PCIE_AER_UCE_STS;
		chk_reg = px_fabric_die_ue;
		chk_reg_gos = px_fabric_die_ue_gos;
		reg = cs->aer_ue_reg & ~(cs->aer_sev_reg);
		break;
	case PCIE_MSG_CODE_ERR_FATAL:
		off_reg = PCIE_AER_UCE_STS;
		chk_reg = px_fabric_die_ue;
		chk_reg_gos = px_fabric_die_ue_gos;
		reg = cs->aer_ue_reg & cs->aer_sev_reg;
		break;
	default:
		/* Major error force a panic */
		return (PX_FATAL_GOS);
	}
	px_fab_set(px_p, cs->rid, cs->aer_off + off_reg, reg);
	ret |= PX_FABRIC_ERR_SEV(reg, chk_reg, chk_reg_gos);

	return (ret);
}

/*
 * This function checks and clears the secondary AER.
 */
static int
px_fabric_handle_saer(px_t *px_p, px_fabric_cfgspace_t *cs) {
	uint32_t	chk_reg, chk_reg_gos, off_reg, reg;
	uint32_t	sev;
	int		ret = PX_NONFATAL;

	/* Determine severity and clear the AER */
	switch (cs->msg_code) {
	case PCIE_MSG_CODE_ERR_COR:
		/* Ignore Correctable Errors */
		sev = 0;
		break;
	case PCIE_MSG_CODE_ERR_NONFATAL:
		sev = ~(cs->aer_sev_sreg);
		break;
	case PCIE_MSG_CODE_ERR_FATAL:
		sev = cs->aer_sev_sreg;
		break;
	default:
		/* Major error force a panic */
		return (DDI_FM_FATAL);
	}
	off_reg = PCIE_AER_SUCE_STS;
	chk_reg = px_fabric_die_sue;
	chk_reg_gos = px_fabric_die_sue_gos;
	reg = cs->aer_ue_sreg & sev;
	px_fab_set(px_p, cs->rid, cs->aer_off + off_reg, reg);
	ret |= PX_FABRIC_ERR_SEV(reg, chk_reg, chk_reg_gos);

	return (ret);
}

static int
px_fabric_handle(px_t *px_p, px_fabric_cfgspace_t *cs)
{
	pcie_req_id_t	rid = cs->rid;
	uint16_t	cap_off = cs->cap_off;
	uint16_t	aer_off = cs->aer_off;
	uint8_t		hdr_type = cs->hdr_type;
	uint16_t	dev_type = cs->dev_type;
	int		ret = PX_NONFATAL;

	if (hdr_type == PCI_HEADER_PPB) {
		ret |= px_fabric_handle_ssts(cs);
	}

	if (!aer_off) {
		ret |= px_fabric_handle_psts(cs);
	}

	if (aer_off) {
		ret |= px_fabric_handle_paer(px_p, cs);
	}

	if (aer_off && (dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI)) {
		ret |= px_fabric_handle_saer(px_p, cs);
	}

	/* Clear the standard PCIe error registers */
	px_fab_set(px_p, rid, cap_off + PCIE_DEVCTL, cs->dev_sts_reg);

	/* Clear the legacy error registers */
	px_fab_set(px_p, rid, PCI_CONF_COMM, cs->sts_reg);

	/* Clear the legacy secondary error registers */
	if (hdr_type == PCI_HEADER_PPB) {
		px_fab_set(px_p, rid, PCI_BCNF_IO_BASE_LOW,
		    cs->sts_sreg);
	}

	return (ret);
}

static void
px_fabric_fill_cs(px_t *px_p, px_fabric_cfgspace_t *cs)
{
	uint16_t	cap_off, aer_off;
	pcie_req_id_t	rid = cs->rid;

	/* Gather Basic Device Information */
	cs->hdr_type = (px_fab_get(px_p, rid,
			    PCI_CONF_CACHE_LINESZ) >> 16) & 0xFF;

	cs->cap_off = px_fabric_get_pciecap(px_p, rid);
	cap_off = cs->cap_off;
	if (!cap_off)
		return;

	cs->aer_off = px_fabric_get_aer(px_p, rid);
	aer_off = cs->aer_off;

	cs->dev_type = px_fab_get(px_p, rid, cap_off) >> 16;
	cs->dev_type &= PCIE_PCIECAP_DEV_TYPE_MASK;

	/* Get the Primary Sts Reg */
	cs->sts_reg = px_fab_get(px_p, rid, PCI_CONF_COMM);

	/* If it is a bridge/switch get the Secondary Sts Reg */
	if (cs->hdr_type == PCI_HEADER_PPB)
		cs->sts_sreg = px_fab_get(px_p, rid,
		    PCI_BCNF_IO_BASE_LOW);

	/* Get the PCIe Dev Sts Reg */
	cs->dev_sts_reg = px_fab_get(px_p, rid,
	    cap_off + PCIE_DEVCTL);

	if (!aer_off)
		return;

	/* Get the AER register information */
	cs->aer_ce_reg = px_fab_get(px_p, rid, aer_off + PCIE_AER_CE_STS);
	cs->aer_ue_reg = px_fab_get(px_p, rid, aer_off + PCIE_AER_UCE_STS);
	cs->aer_sev_reg = px_fab_get(px_p, rid, aer_off + PCIE_AER_UCE_SERV);
	cs->aer_h1 = px_fab_get(px_p, rid, aer_off + PCIE_AER_HDR_LOG + 0x0);
	cs->aer_h2 = px_fab_get(px_p, rid, aer_off + PCIE_AER_HDR_LOG + 0x4);
	cs->aer_h3 = px_fab_get(px_p, rid, aer_off + PCIE_AER_HDR_LOG + 0x8);
	cs->aer_h4 = px_fab_get(px_p, rid, aer_off + PCIE_AER_HDR_LOG + 0xC);

	if (cs->dev_type != PCIE_PCIECAP_DEV_TYPE_PCIE2PCI)
		return;

	/* If this is a bridge check secondary aer */
	cs->aer_ue_sreg = px_fab_get(px_p, rid, aer_off + PCIE_AER_SUCE_STS);
	cs->aer_sev_sreg = px_fab_get(px_p, rid, aer_off + PCIE_AER_SUCE_SERV);
	cs->aer_sh1 = px_fab_get(px_p, rid, aer_off + PCIE_AER_SHDR_LOG + 0x0);
	cs->aer_sh2 = px_fab_get(px_p, rid, aer_off + PCIE_AER_SHDR_LOG + 0x4);
	cs->aer_sh3 = px_fab_get(px_p, rid, aer_off + PCIE_AER_SHDR_LOG + 0x8);
	cs->aer_sh4 = px_fab_get(px_p, rid, aer_off + PCIE_AER_SHDR_LOG + 0xC);
}

/*
 * If a fabric intr occurs, query and clear the error registers on that device.
 * Based on the error found return DDI_FM_OK or DDI_FM_FATAL.
 */
static uint_t
px_fabric_check(px_t *px_p, msgcode_t msg_code,
    pcie_req_id_t rid, ddi_fm_error_t *derr)
{
	dev_info_t	*dip = px_p->px_dip;
	char		buf[FM_MAX_CLASS];
	px_fabric_cfgspace_t cs;
	int		ret;

	/* clear cs */
	bzero(&cs, sizeof (px_fabric_cfgspace_t));

	cs.msg_code = msg_code;
	cs.rid = rid;

	px_fabric_fill_cs(px_p, &cs);
	if (cs.cap_off)
		ret = px_fabric_handle(px_p, &cs);
	else
		ret = PX_FATAL_GOS;

	(void) snprintf(buf, FM_MAX_CLASS, "%s", PX_FM_FABRIC_CLASS);
	ddi_fm_ereport_post(dip, buf, derr->fme_ena,
	    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
	    PX_FM_FABRIC_MSG_CODE, DATA_TYPE_UINT8, msg_code,
	    PX_FM_FABRIC_REQ_ID, DATA_TYPE_UINT16, rid,
	    "cap_off", DATA_TYPE_UINT16, cs.cap_off,
	    "aer_off", DATA_TYPE_UINT16, cs.aer_off,
	    "sts_reg", DATA_TYPE_UINT16, cs.sts_reg >> 16,
	    "sts_sreg", DATA_TYPE_UINT16, cs.sts_sreg >> 16,
	    "dev_sts_reg", DATA_TYPE_UINT16, cs.dev_sts_reg >> 16,
	    "aer_ce", DATA_TYPE_UINT32, cs.aer_ce_reg,
	    "aer_ue", DATA_TYPE_UINT32, cs.aer_ue_reg,
	    "aer_sev", DATA_TYPE_UINT32, cs.aer_sev_reg,
	    "aer_h1", DATA_TYPE_UINT32, cs.aer_h1,
	    "aer_h2", DATA_TYPE_UINT32, cs.aer_h2,
	    "aer_h3", DATA_TYPE_UINT32, cs.aer_h3,
	    "aer_h4", DATA_TYPE_UINT32, cs.aer_h4,
	    "saer_ue", DATA_TYPE_UINT32, cs.aer_ue_sreg,
	    "saer_sev", DATA_TYPE_UINT32, cs.aer_sev_sreg,
	    "saer_h1", DATA_TYPE_UINT32, cs.aer_sh1,
	    "saer_h2", DATA_TYPE_UINT32, cs.aer_sh2,
	    "saer_h3", DATA_TYPE_UINT32, cs.aer_sh3,
	    "saer_h4", DATA_TYPE_UINT32, cs.aer_sh4,
	    "severity", DATA_TYPE_UINT32, ret,
	    NULL);

	/* Check for protected access */
	switch (derr->fme_flag) {
	case DDI_FM_ERR_EXPECTED:
	case DDI_FM_ERR_PEEK:
	case DDI_FM_ERR_POKE:
		ret &= PX_FATAL_GOS;
		break;
	}


	if (px_fabric_die &&
	    (ret & (PX_FATAL_GOS | PX_FATAL_SW)))
			ret = DDI_FM_FATAL;

	return (ret);
}

/*
 * px_err_fabric_intr:
 * Interrupt handler for PCIE fabric block.
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
	int		err = PX_OK, ret = DDI_FM_OK, fab_err = DDI_FM_OK;
	ddi_fm_error_t	derr;

	mutex_enter(&cb_p->xbc_fm_mutex);

	/* Create the derr */
	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	derr.fme_flag = DDI_FM_ERR_UNEXPECTED;

	/* send ereport/handle/clear fire registers */
	err |= px_err_handle(px_p, &derr, PX_INTR_CALL, B_TRUE);

	/* Check and clear the fabric error */
	fab_err = px_fabric_check(px_p, msg_code, rid, &derr);

	/* Check all child devices for errors */
	ret = ndi_fm_handler_dispatch(rpdip, NULL, &derr);

	mutex_exit(&cb_p->xbc_fm_mutex);

	/*
	 * PX_FATAL_HW indicates a condition recovered from Fatal-Reset,
	 * therefore it does not cause panic.
	 */
	if ((err & (PX_FATAL_GOS | PX_FATAL_SW)) ||
	    (ret == DDI_FM_FATAL) || (fab_err == DDI_FM_FATAL))
		PX_FM_PANIC("Fatal PCIe Fabric Error has occurred\n");

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
