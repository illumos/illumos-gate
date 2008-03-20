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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

#define	PX_PCIE_PANIC_BITS \
	(PCIE_AER_UCE_DLP | PCIE_AER_UCE_FCP | PCIE_AER_UCE_TO | \
	PCIE_AER_UCE_RO | PCIE_AER_UCE_MTLP | PCIE_AER_UCE_ECRC)
#define	PX_PCIE_NO_PANIC_BITS \
	(PCIE_AER_UCE_TRAINING | PCIE_AER_UCE_SD | PCIE_AER_UCE_CA | \
	PCIE_AER_UCE_UC | PCIE_AER_UCE_UR)

static void px_err_fill_pfd(dev_info_t *rpdip, px_err_pcie_t *regs);
static int px_pcie_ptlp(dev_info_t *dip, ddi_fm_error_t *derr,
    px_err_pcie_t *regs);

#if defined(DEBUG)
static void px_pcie_log(dev_info_t *dip, px_err_pcie_t *regs, int severity);
#else	/* DEBUG */
#define	px_pcie_log 0 &&
#endif	/* DEBUG */

/* external functions */
extern int pci_xcap_locate(ddi_acc_handle_t h, uint16_t id, uint16_t *base_p);
extern int pci_lcap_locate(ddi_acc_handle_t h, uint8_t id, uint16_t *base_p);

/*
 * Initialize px FMA support
 */
int
px_fm_attach(px_t *px_p)
{
	px_p->px_fm_cap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;

	/*
	 * Initialize pci_target_queue for FMA handling of
	 * pci errors.
	 */
	pci_targetq_init();

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
	 * Initialize lock to synchronize fabric error handling
	 */
	mutex_init(&px_p->px_fm_mutex, NULL, MUTEX_DRIVER,
	    (void *)px_p->px_fm_ibc);

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
	mutex_destroy(&px_p->px_fm_mutex);
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
 * and PCI BERR/TO/UE on IO Loads.
 */
/*ARGSUSED*/
int
px_fm_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *impl_data)
{
	dev_info_t	*pdip = ddi_get_parent(dip);
	px_t		*px_p = (px_t *)impl_data;
	int		i, acc_type = 0;
	int		lookup, rc_err, fab_err = PF_NO_PANIC;
	uint32_t	addr, addr_high, addr_low;
	pcie_req_id_t	bdf;
	px_ranges_t	*ranges_p;
	int		range_len;

	/*
	 * If the current thread already owns the px_fm_mutex, then we
	 * have encountered an error while processing a previous
	 * error.  Attempting to take the mutex again will cause the
	 * system to deadlock.
	 */
	if (px_p->px_fm_mutex_owner == curthread)
		return (DDI_FM_FATAL);

	i_ddi_fm_handler_exit(pdip);
	mutex_enter(&px_p->px_fm_mutex);
	px_p->px_fm_mutex_owner = curthread;

	addr_high = (uint32_t)((uint64_t)derr->fme_bus_specific >> 32);
	addr_low = (uint32_t)((uint64_t)derr->fme_bus_specific);

	/*
	 * Make sure this failed load came from this PCIe port.	 Check by
	 * matching the upper 32 bits of the address with the ranges property.
	 */
	range_len = px_p->px_ranges_length / sizeof (px_ranges_t);
	i = 0;
	for (ranges_p = px_p->px_ranges_p; i < range_len; i++, ranges_p++) {
		if (ranges_p->parent_high == addr_high) {
			switch (ranges_p->child_high & PCI_ADDR_MASK) {
			case PCI_ADDR_CONFIG:
				acc_type = PF_CFG_ADDR;
				addr = NULL;
				bdf = (pcie_req_id_t)(addr_low >> 12);
				break;
			case PCI_ADDR_IO:
				acc_type = PF_IO_ADDR;
				addr = addr_low;
				bdf = NULL;
				break;
			case PCI_ADDR_MEM32:
				acc_type = PF_DMA_ADDR;
				addr = addr_low;
				bdf = NULL;
				break;
			}
			break;
		}
	}

	/* This address doesn't belong to this leaf, just return with OK */
	if (!acc_type) {
		px_p->px_fm_mutex_owner = NULL;
		mutex_exit(&px_p->px_fm_mutex);
		i_ddi_fm_handler_enter(pdip);
		return (DDI_FM_OK);
	} else if (acc_type == PF_IO_ADDR) {
		px_p->px_fm_mutex_owner = NULL;
		mutex_exit(&px_p->px_fm_mutex);
		i_ddi_fm_handler_enter(pdip);
		return (DDI_FM_FATAL);
	}

	rc_err = px_err_cmn_intr(px_p, derr, PX_TRAP_CALL, PX_FM_BLOCK_ALL);
	lookup = pf_hdl_lookup(dip, derr->fme_ena, acc_type, addr, bdf);

	if (!px_lib_is_in_drain_state(px_p)) {
		/*
		 * This is to ensure that device corresponding to the addr of
		 * the failed PIO/CFG load gets scanned.
		 */
		px_rp_en_q(px_p, bdf, addr,
		    (PCI_STAT_R_MAST_AB | PCI_STAT_R_TARG_AB));
		fab_err = pf_scan_fabric(dip, derr, px_p->px_dq_p,
		    &px_p->px_dq_tail);
	}

	px_p->px_fm_mutex_owner = NULL;
	mutex_exit(&px_p->px_fm_mutex);
	i_ddi_fm_handler_enter(pdip);

	if ((rc_err & (PX_PANIC | PX_PROTECTED)) || (fab_err & PF_PANIC) ||
	    (lookup == PF_HDL_NOTFOUND))
		return (DDI_FM_FATAL);
	else if ((rc_err == PX_NO_ERROR) && (fab_err == PF_NO_ERROR))
		return (DDI_FM_OK);

	return (DDI_FM_NONFATAL);
}

/*
 * px_err_fabric_intr:
 * Interrupt handler for PCIE fabric block.
 * o lock
 * o create derr
 * o px_err_cmn_intr(leaf, with jbc)
 * o send ereport(fire fmri, derr, payload = BDF)
 * o dispatch (leaf)
 * o unlock
 * o handle error: fatal? fm_panic() : return INTR_CLAIMED)
 */
/* ARGSUSED */
uint_t
px_err_fabric_intr(px_t *px_p, msgcode_t msg_code, pcie_req_id_t rid)
{
	dev_info_t	*rpdip = px_p->px_dip;
	int		rc_err, fab_err = PF_NO_PANIC;
	ddi_fm_error_t	derr;

	mutex_enter(&px_p->px_fm_mutex);
	px_p->px_fm_mutex_owner = curthread;

	/* Create the derr */
	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	derr.fme_flag = DDI_FM_ERR_UNEXPECTED;

	/* Ensure that the rid of the fabric message will get scanned. */
	px_rp_en_q(px_p, rid, NULL, NULL);

	rc_err = px_err_cmn_intr(px_p, &derr, PX_INTR_CALL, PX_FM_BLOCK_PCIE);

	/* call rootport dispatch */
	if (!px_lib_is_in_drain_state(px_p)) {
		fab_err = pf_scan_fabric(rpdip, &derr, px_p->px_dq_p,
		    &px_p->px_dq_tail);
	}

	px_p->px_fm_mutex_owner = NULL;
	mutex_exit(&px_p->px_fm_mutex);

	px_err_panic(rc_err, PX_RC, fab_err);

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
	int		acctype = pec_p->pec_safeacc_type;

	ASSERT(MUTEX_HELD(&px_p->px_fm_mutex));

	if (derr->fme_flag != DDI_FM_ERR_UNEXPECTED) {
		return;
	}

	/* safe access checking */
	switch (acctype) {
	case DDI_FM_ERR_EXPECTED:
		/*
		 * cautious access protection, protected from all err.
		 */
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
		membar_sync();
		derr->fme_flag = acctype;
		break;
	case DDI_FM_ERR_PEEK:
		derr->fme_flag = acctype;
		break;
	}
}

/*
 * Suggest panic if any EQ (except CE q) has overflown.
 */
int
px_err_check_eq(dev_info_t *dip)
{
	px_t			*px_p = DIP_TO_STATE(dip);
	px_msiq_state_t 	*msiq_state_p = &px_p->px_ib_p->ib_msiq_state;
	px_pec_t		*pec_p = px_p->px_pec_p;
	msiqid_t		eq_no = msiq_state_p->msiq_1st_msiq_id;
	pci_msiq_state_t	msiq_state;
	int			i;

	for (i = 0; i < msiq_state_p->msiq_cnt; i++) {
		if (i + eq_no == pec_p->pec_corr_msg_msiq_id) /* skip CE q */
			continue;
		if ((px_lib_msiq_getstate(dip, i + eq_no, &msiq_state) !=
		    DDI_SUCCESS) || msiq_state == PCI_MSIQ_STATE_ERROR)
			return (PX_PANIC);
	}
	return (PX_NO_PANIC);
}

static void
px_err_fill_pfd(dev_info_t *rpdip, px_err_pcie_t *regs)
{
	px_t		*px_p = DIP_TO_STATE(rpdip);
	pf_data_t	pf_data = {0};
	pcie_req_id_t	fault_bdf = 0;
	uint32_t	fault_addr = 0;
	uint16_t	s_status = 0;

	pf_data.rp_bdf = px_p->px_bdf;

	/*
	 * set RC s_status in PCI term to coordinate with downstream fabric
	 * errors ananlysis.
	 */
	if (regs->primary_ue & PCIE_AER_UCE_UR)
		s_status = PCI_STAT_R_MAST_AB;
	if (regs->primary_ue & PCIE_AER_UCE_CA)
		s_status = PCI_STAT_R_TARG_AB;
	if (regs->primary_ue & (PCIE_AER_UCE_PTLP | PCIE_AER_UCE_ECRC))
		s_status = PCI_STAT_PERROR;

	if (regs->primary_ue & (PCIE_AER_UCE_UR | PCIE_AER_UCE_CA)) {
		pf_data.aer_h0 = regs->rx_hdr1;
		pf_data.aer_h1 = regs->rx_hdr2;
		pf_data.aer_h2 = regs->rx_hdr3;
		pf_data.aer_h3 = regs->rx_hdr4;

		pf_tlp_decode(rpdip, &pf_data, &fault_bdf, NULL, NULL);
	} else if (regs->primary_ue & PCIE_AER_UCE_PTLP) {
		pcie_tlp_hdr_t	*tlp_p;

		pf_data.aer_h0 = regs->rx_hdr1;
		pf_data.aer_h1 = regs->rx_hdr2;
		pf_data.aer_h2 = regs->rx_hdr3;
		pf_data.aer_h3 = regs->rx_hdr4;

		tlp_p = (pcie_tlp_hdr_t *)&pf_data.aer_h0;
		if (tlp_p->type == PCIE_TLP_TYPE_CPL)
			pf_tlp_decode(rpdip, &pf_data, &fault_bdf, NULL, NULL);

		pf_data.aer_h0 = regs->tx_hdr1;
		pf_data.aer_h1 = regs->tx_hdr2;
		pf_data.aer_h2 = regs->tx_hdr3;
		pf_data.aer_h3 = regs->tx_hdr4;

		pf_tlp_decode(rpdip, &pf_data, NULL, &fault_addr, NULL);
	}

	px_rp_en_q(px_p, fault_bdf, fault_addr, s_status);
}

int
px_err_check_pcie(dev_info_t *dip, ddi_fm_error_t *derr, px_err_pcie_t *regs)
{
	uint32_t ce_reg, ue_reg;
	int err = PX_NO_ERROR;

	ce_reg = regs->ce_reg;
	if (ce_reg)
		err |= (ce_reg & px_fabric_die_rc_ce) ? PX_PANIC : PX_NO_ERROR;

	ue_reg = regs->ue_reg;
	if (!ue_reg)
		goto done;

	if (ue_reg & PCIE_AER_UCE_PTLP)
		err |= px_pcie_ptlp(dip, derr, regs);

	if (ue_reg & PX_PCIE_PANIC_BITS)
		err |= PX_PANIC;

	if (ue_reg & PX_PCIE_NO_PANIC_BITS)
		err |= PX_NO_PANIC;

	/* Scan the fabric to clean up error bits, for the following errors. */
	if (ue_reg & (PCIE_AER_UCE_PTLP | PCIE_AER_UCE_CA | PCIE_AER_UCE_UR))
		px_err_fill_pfd(dip, regs);
done:
	px_pcie_log(dip, regs, err);
	return (err);
}

#if defined(DEBUG)
static void
px_pcie_log(dev_info_t *dip, px_err_pcie_t *regs, int severity)
{
	DBG(DBG_ERR_INTR, dip,
	    "A PCIe RC error has occured with a severity of \"%s\"\n"
	    "\tCE: 0x%x UE: 0x%x Primary UE: 0x%x\n"
	    "\tTX Hdr: 0x%x 0x%x 0x%x 0x%x\n\tRX Hdr: 0x%x 0x%x 0x%x 0x%x\n",
	    (severity & PX_PANIC) ? "PANIC" : "NO PANIC", regs->ce_reg,
	    regs->ue_reg, regs->primary_ue, regs->tx_hdr1, regs->tx_hdr2,
	    regs->tx_hdr3, regs->tx_hdr4, regs->rx_hdr1, regs->rx_hdr2,
	    regs->rx_hdr3, regs->rx_hdr4);
}
#endif	/* DEBUG */

/*
 * look through poisoned TLP cases and suggest panic/no panic depend on
 * handle lookup.
 */
static int
px_pcie_ptlp(dev_info_t *dip, ddi_fm_error_t *derr, px_err_pcie_t *regs)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	pf_data_t	pf_data;
	pcie_req_id_t	bdf;
	uint32_t	addr, trans_type;
	int		tlp_sts, tlp_cmd;
	int		sts = PF_HDL_NOTFOUND;

	if (regs->primary_ue != PCIE_AER_UCE_PTLP)
		return (PX_PANIC);

	if (!regs->rx_hdr1)
		goto done;

	pf_data.rp_bdf = px_p->px_bdf;
	pf_data.aer_h0 = regs->rx_hdr1;
	pf_data.aer_h1 = regs->rx_hdr2;
	pf_data.aer_h2 = regs->rx_hdr3;
	pf_data.aer_h3 = regs->rx_hdr4;

	tlp_sts = pf_tlp_decode(dip, &pf_data, &bdf, &addr, &trans_type);
	tlp_cmd = ((pcie_tlp_hdr_t *)(&pf_data.aer_h0))->type;

	if (tlp_sts == DDI_FAILURE)
		goto done;

	switch (tlp_cmd) {
	case PCIE_TLP_TYPE_CPL:
	case PCIE_TLP_TYPE_CPLLK:
		/*
		 * Usually a PTLP is a CPL with data.  Grab the completer BDF
		 * from the RX TLP, and the original address from the TX TLP.
		 */
		if (regs->tx_hdr1) {
			pf_data.aer_h0 = regs->tx_hdr1;
			pf_data.aer_h1 = regs->tx_hdr2;
			pf_data.aer_h2 = regs->tx_hdr3;
			pf_data.aer_h3 = regs->tx_hdr4;

			sts = pf_tlp_decode(dip, &pf_data, NULL, &addr,
			    &trans_type);
		} /* FALLTHRU */
	case PCIE_TLP_TYPE_IO:
	case PCIE_TLP_TYPE_MEM:
	case PCIE_TLP_TYPE_MEMLK:
		sts = pf_hdl_lookup(dip, derr->fme_ena, trans_type, addr, bdf);
		break;
	default:
		sts = PF_HDL_NOTFOUND;
	}
done:
	return (sts == PF_HDL_NOTFOUND ? PX_PANIC : PX_NO_PANIC);
}

/*
 * This function appends a pf_data structure to the error q which is used later
 * during PCIe fabric scan.  It signifies:
 * o errs rcvd in RC, that may have been propagated to/from the fabric
 * o the fabric scan code should scan the device path of fault bdf/addr
 *
 * fault_bdf: The bdf that caused the fault, which may have error bits set.
 * fault_addr: The PIO addr that caused the fault, such as failed PIO, but not
 *	       failed DMAs.
 * s_status: Secondary Status equivalent to why the fault occured.
 *	     (ie S-TA/MA, R-TA)
 * Either the fault bdf or addr may be NULL, but not both.
 */
int px_foo = 0;
void
px_rp_en_q(px_t *px_p, pcie_req_id_t fault_bdf, uint32_t fault_addr,
    uint16_t s_status)
{
	pf_data_t pf_data = {0};

	if (!fault_bdf && !fault_addr)
		return;

	pf_data.dev_type = PCIE_PCIECAP_DEV_TYPE_ROOT;
	if (px_foo) {
		pf_data.fault_bdf = px_foo;
		px_foo = 0;
	} else
		pf_data.fault_bdf = fault_bdf;

	pf_data.bdf = px_p->px_bdf;
	pf_data.rp_bdf = px_p->px_bdf;
	pf_data.fault_addr = fault_addr;
	pf_data.s_status = s_status;
	pf_data.send_erpt = PF_SEND_ERPT_NO;

	(void) pf_en_dq(&pf_data, px_p->px_dq_p, &px_p->px_dq_tail, -1);
}

/*
 * Panic if the err tunable is set and that we are not already in the middle
 * of panic'ing.
 */
#define	MSZ (sizeof (fm_msg) -strlen(fm_msg) - 1)
void
px_err_panic(int err, int msg, int fab_err)
{
	char fm_msg[96] = "";
	int ferr = PX_NO_ERROR;

	if (panicstr)
		return;

	if (!(err & px_die))
		goto fabric;
	if (msg & PX_RC)
		(void) strncat(fm_msg, px_panic_rc_msg, MSZ);
	if (msg & PX_RP)
		(void) strncat(fm_msg, px_panic_rp_msg, MSZ);
	if (msg & PX_HB)
		(void) strncat(fm_msg, px_panic_hb_msg, MSZ);

fabric:
	if (fab_err & PF_PANIC)
		ferr = PX_PANIC;
	else if (fab_err & ~(PF_PANIC | PF_NO_ERROR))
		ferr = PX_NO_PANIC;

	if (ferr & px_die) {
		if (strlen(fm_msg))
			(void) strncat(fm_msg, " and", MSZ);
		(void) strncat(fm_msg, px_panic_fab_msg, MSZ);
	}

	if (strlen(fm_msg))
		fm_panic("Fatal error has occured in:%s.", fm_msg);
}
