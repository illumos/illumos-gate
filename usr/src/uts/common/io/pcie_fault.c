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

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/promif.h>
#include <sys/disp.h>
#include <sys/pcie.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>

/* size of error queue */
uint_t pf_dq_size = 32;

#define	PF_AER_FATAL_ERR (PCIE_AER_UCE_DLP | PCIE_AER_UCE_SD |\
	PCIE_AER_UCE_FCP | PCIE_AER_UCE_RO | PCIE_AER_UCE_MTLP)
#define	PF_AER_NON_FATAL_ERR (PCIE_AER_UCE_PTLP | PCIE_AER_UCE_TO | \
	PCIE_AER_UCE_CA | PCIE_AER_UCE_ECRC | PCIE_AER_UCE_UR)

#define	PF_SAER_FATAL_ERR (PCIE_AER_SUCE_USC_MSG_DATA_ERR | \
	PCIE_AER_SUCE_UC_ATTR_ERR | PCIE_AER_SUCE_UC_ADDR_ERR | \
	PCIE_AER_SUCE_SERR_ASSERT)
#define	PF_SAER_NON_FATAL_ERR (PCIE_AER_SUCE_TA_ON_SC | \
	PCIE_AER_SUCE_MA_ON_SC | PCIE_AER_SUCE_RCVD_TA | \
	PCIE_AER_SUCE_RCVD_MA | PCIE_AER_SUCE_USC_ERR | \
	PCIE_AER_SUCE_UC_DATA_ERR | PCIE_AER_SUCE_TIMER_EXPIRED | \
	PCIE_AER_SUCE_PERR_ASSERT | PCIE_AER_SUCE_INTERNAL_ERR)

#define	PF_PCIE_BDG_ERR (PCIE_DEVSTS_FE_DETECTED | PCIE_DEVSTS_NFE_DETECTED | \
	PCIE_DEVSTS_CE_DETECTED)

#define	PF_PCI_BDG_ERR (PCI_STAT_S_SYSERR | PCI_STAT_S_TARG_AB | \
	PCI_STAT_R_MAST_AB | PCI_STAT_R_TARG_AB | PCI_STAT_S_PERROR)


#define	PF_DATA_NOT_FOUND -1

#define	HAS_AER_LOGS(pf_data_p, bit)	\
	(pf_data_p->aer_off && (bit & (1 << (pf_data_p->aer_control & \
	PCIE_AER_CTL_FST_ERR_PTR_MASK))))

#define	HAS_SAER_LOGS(pf_data_p, bit)	\
	(pf_data_p->aer_off && (bit & (1 << (pf_data_p->s_aer_control & \
	PCIE_AER_SCTL_FST_ERR_PTR_MASK))))

#define	GET_SAER_CMD(pf_data_p)	\
	(pf_data_p->s_aer_h1 >> PCIE_AER_SUCE_HDR_CMD_LWR_SHIFT) & \
	    PCIE_AER_SUCE_HDR_CMD_LWR_MASK;

#define	CE_ADVISORY(pf_data_p)	\
	(pf_data_p->aer_ce_status & PCIE_AER_CE_AD_NFE)

#define	IS_RC(pf_data_p) \
	(pf_data_p->dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT)

/* PCIe Fault Fabric Error analysis table */
typedef struct pf_fab_err_tbl {
	uint32_t	bit;		/* Error bit */
	int		(*handler)();	/* Error handling fuction */
} pf_fab_err_tbl_t;

/* DMA/PIO/CFG Handle Comparason Function Declaration */
typedef int (*pf_hdl_compare_t)(struct i_ddi_fmhdl *, ddi_fm_error_t *,
    uint32_t, pcie_req_id_t);

/* PCIe Fault Support Functions. */
static int pf_find_in_q(pcie_req_id_t bdf, pf_data_t *dq_p, int dq_tail);
static boolean_t pf_in_bus_range(pcie_ppd_t *ppd_p, pcie_req_id_t bdf);
static boolean_t pf_in_addr_range(pcie_ppd_t *ppd_p, uint32_t addr);
static int pf_pcie_dispatch(dev_info_t *pdip, pf_impl_t *impl);
static int pf_pci_dispatch(dev_info_t *pdip, pf_impl_t *impl);
static int pf_default_hdl(dev_info_t *dip, dev_info_t *pdip,
    pcie_ppd_t *ppd_p, pf_impl_t *impl);

/* PCIe Fabric Handle Lookup Support Functions. */
static int pf_hdl_child_lookup(dev_info_t *rpdip, dev_info_t *dip,
    ddi_fm_error_t *derr, uint32_t addr, pcie_req_id_t bdf,
    pf_hdl_compare_t cf);
static int pf_cfg_hdl_check(struct i_ddi_fmhdl *fmhdl,
    ddi_fm_error_t *derr, uint32_t notused, pcie_req_id_t bdf);
static int pf_pio_hdl_check(struct i_ddi_fmhdl *fmhdl,
    ddi_fm_error_t *derr, uint32_t addr, pcie_req_id_t bdf);
static int pf_dma_hdl_check(struct i_ddi_fmhdl *fmhdl,
    ddi_fm_error_t *derr, uint32_t addr, pcie_req_id_t bdf);


/* PCIe/PCI Fault Handling Support Functions. */
static int pf_pci_decode(dev_info_t *rpdip, pf_data_t *pf_data_p, uint16_t *cmd,
    pcie_req_id_t *bdf, uint32_t *addr, uint32_t *trans_type);
static int pf_analyse_error(dev_info_t *rpdip, ddi_fm_error_t *derr,
    pf_data_t *q, int last_index);
static void pf_send_ereport(dev_info_t *rpdip, ddi_fm_error_t *derr,
    pf_data_t *dq_p, int dq_tail);
static void pf_adjust_for_no_aer(pf_data_t *pf_data_p);
static void pf_adjust_for_no_saer(pf_data_t *pf_data_p);
static pf_data_t *pf_get_parent_pcie_bridge(pf_data_t *dq_p,
    pf_data_t *pf_data_p);
static boolean_t pf_matched_in_rc(pf_data_t *dq_p, pf_data_t *pf_data_p,
    uint32_t abort_type);
static int pf_analyse_error_tbl(dev_info_t *rpdip, ddi_fm_error_t *derr,
    pf_data_t *dq_p, pf_data_t *pf_data_p, const pf_fab_err_tbl_t *tbl,
    uint32_t err_reg);
static int pf_analyse_ca_ur(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static int pf_analyse_ma_ta(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static int pf_analyse_pci(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static int pf_analyse_perr_assert(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static int pf_analyse_ptlp(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static int pf_analyse_sc(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static int pf_analyse_to(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static int pf_analyse_uc(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static int pf_analyse_uc_data(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static int pf_matched_device(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static int pf_no_panic(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static int pf_panic(dev_info_t *rpdip, ddi_fm_error_t *derr,
    uint32_t bit, pf_data_t *dq_p, pf_data_t *pf_data_p);
static void pf_check_ce(pf_data_t *dq_p, int dq_tail);
static void pf_set_parent_erpt(pf_data_t *dq_p, int index, int erpt_val);

int
pf_held(dev_info_t *dip)
{
	pcie_ppd_t	*ppd_p = pcie_get_ppd(dip);
	return (mutex_owned(&ppd_p->ppd_fm_lock));
}

boolean_t
pf_enter(dev_info_t *dip)
{
	pcie_ppd_t	*ppd_p = pcie_get_ppd(dip);
	if (!(ppd_p->ppd_fm_flags & PF_FM_READY))
		return (B_FALSE);
	if (!pf_held(dip))
		mutex_enter(&ppd_p->ppd_fm_lock);
	return (B_TRUE);
}

void
pf_exit(dev_info_t *dip)
{
	pcie_ppd_t	*ppd_p = pcie_get_ppd(dip);
	mutex_exit(&ppd_p->ppd_fm_lock);
}

/*
 * Default pci/pci-x/pci-e error handler callbacks for
 * SPARC PCI-E platforms
 */

/* Called during postattach to initalize FM lock */
void
pf_init(dev_info_t *dip, ddi_iblock_cookie_t ibc, ddi_attach_cmd_t cmd)
{
	pcie_ppd_t		*ppd_p = pcie_get_ppd(dip);
	struct i_ddi_fmhdl	*fmhdl = DEVI(dip)->devi_fmhdl;
	int			cap = DDI_FM_EREPORT_CAPABLE;

	if (fmhdl) {
		fmhdl->fh_cap |= cap;
	} else {
		ppd_p->ppd_fm_flags |= PF_IS_NH;

		if (cmd == DDI_ATTACH)
			ddi_fm_init(dip, &cap, &ibc);

		fmhdl = DEVI(dip)->devi_fmhdl;
	}

	/* If ddi_fm_init fails for any reason RETURN */
	if (!fmhdl || !(cap & DDI_FM_EREPORT_CAPABLE)) {
		ppd_p->ppd_fm_flags = 0;
		return;
	}

	mutex_init(&ppd_p->ppd_fm_lock, NULL, MUTEX_DRIVER, (void *)ibc);
	ppd_p->ppd_fm_flags |= PF_FM_READY;
}

/* undo OPL FMA lock, called at predetach */
void
pf_fini(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	pcie_ppd_t	*ppd_p = pcie_get_ppd(dip);

	/* Don't fini anything if device isn't FM Ready */
	if (!(ppd_p->ppd_fm_flags & PF_FM_READY))
		return;

	/* undo non-hardened drivers */
	if (ppd_p->ppd_fm_flags & PF_IS_NH) {
		if (cmd == DDI_DETACH) {
			ppd_p->ppd_fm_flags &= ~PF_IS_NH;
			ddi_fm_fini(dip);
		}
	}

	/* no other code should set the flag to false */
	ppd_p->ppd_fm_flags &= ~PF_FM_READY;
	while (pf_held(dip))
		;
	mutex_destroy(&ppd_p->ppd_fm_lock);
}

/* Returns whether the "bdf" is in the bus range of a switch/bridge */
static boolean_t
pf_in_bus_range(pcie_ppd_t *ppd_p, pcie_req_id_t bdf)
{
	pci_bus_range_t *br_p = &ppd_p->ppd_bus_range;
	uint16_t	hdr_type = ppd_p->ppd_hdr_type;
	uint8_t		bus_no = (bdf & PCIE_REQ_ID_BUS_MASK) >>
	    PCIE_REQ_ID_BUS_SHIFT;

	/* check if given bdf falls within bridge's bus range */
	if ((hdr_type == PCI_HEADER_ONE) &&
	    ((bus_no >= br_p->lo) && (bus_no <= br_p->hi)))
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * Returns whether the "addr" is in the addr range of a switch/bridge, or if the
 * "addr" is in the assigned addr of a device.
 */
static boolean_t
pf_in_addr_range(pcie_ppd_t *ppd_p, uint32_t addr)
{
	uint_t		i, low, hi;
	ppb_ranges_t	*ranges_p = ppd_p->ppd_addr_ranges;
	pci_regspec_t	*assign_p = ppd_p->ppd_assigned_addr;

	/* check if given address belongs to this device */
	for (i = 0; i < ppd_p->ppd_assigned_entries; i++, assign_p++) {
		low = assign_p->pci_phys_low;
		hi = low + assign_p->pci_size_low;
		if ((addr < hi) && (addr >= low))
			return (B_TRUE);
	}

	/* check if given address belongs to a child below this device */
	if (ppd_p->ppd_hdr_type == PCI_HEADER_ONE) {
		for (i = 0; i < ppd_p->ppd_addr_entries; i++, ranges_p++) {
			if (ranges_p->child_high & PCI_ADDR_MEM32) {
				low = ranges_p->child_low;
				hi = low + ranges_p->size_low;
				if ((addr < hi) && (addr >= low))
					return (B_TRUE);
				break;
			}
		}
	}

	return (B_FALSE);
}

int
pf_pci_dispatch(dev_info_t *pdip, pf_impl_t *impl)
{
	dev_info_t	*dip;
	pcie_ppd_t	*ppd_p;
	int		sts = 0, ret = 0;

	/* for bridge, check all downstream */
	dip = ddi_get_child(pdip);
	for (; dip; dip = ddi_get_next_sibling(dip)) {
		/* make sure dip is attached, ie. fm_ready */
		if (!(ppd_p = pcie_get_ppd(dip)) ||
		    !pf_enter(dip))
			continue;

		sts = pf_default_hdl(dip, pdip, ppd_p, impl);
		ret |= (sts & PF_FAILURE) ? DDI_FAILURE : DDI_SUCCESS;

		if (sts & PF_DO_NOT_SCAN)
			continue;

		if (ppd_p->ppd_hdr_type == PCI_HEADER_ONE)
			ret |= pf_pci_dispatch(dip, impl);
	}
	return (ret);
}

int
pf_pcie_dispatch(dev_info_t *pdip, pf_impl_t *impl)
{
	dev_info_t	*dip;
	pcie_req_id_t	rid = impl->pf_fbdf;
	pcie_ppd_t	*ppd_p;
	int		sts, ret = DDI_SUCCESS;

	dip = ddi_get_child(pdip);
	for (; dip; dip = ddi_get_next_sibling(dip)) {
		/* Make sure dip is attached and fm_ready */
		if (!(ppd_p = pcie_get_ppd(dip)) ||
		    !pf_enter(dip))
			continue;

		if ((ppd_p->ppd_bdf == rid) ||
		    pf_in_bus_range(ppd_p, rid) ||
		    pf_in_addr_range(ppd_p, impl->pf_faddr)) {
			sts = pf_default_hdl(dip, pdip, ppd_p, impl);

			ret |= (sts & PF_FAILURE) ? DDI_FAILURE : DDI_SUCCESS;

			if (sts & PF_DO_NOT_SCAN)
				continue;
		} else {
			pf_exit(dip);
			continue;
		}

		/* match or in bridge bus-range */
		switch (ppd_p->ppd_dev_type) {
		case PCIE_PCIECAP_DEV_TYPE_PCIE2PCI:
			ret |= pf_pci_dispatch(dip, impl);
			return (ret);
		case PCIE_PCIECAP_DEV_TYPE_UP:
		case PCIE_PCIECAP_DEV_TYPE_DOWN:
			if (ppd_p->ppd_bdf != rid)
				ret |= pf_pcie_dispatch(dip, impl);
			/* FALLTHROUGH */
		case PCIE_PCIECAP_DEV_TYPE_PCIE_DEV:
			return (ret);
		case PCIE_PCIECAP_DEV_TYPE_ROOT:
		default:
			ASSERT(B_FALSE);
		}
	}
	return (ret);
}

/*
 * Called by the RC to scan the fabric.
 *
 * After all the necessary fabric devices are scanned, the error queue will be
 * analyzed for error severity and ereports will be sent.
 */
int
pf_scan_fabric(dev_info_t *rpdip, ddi_fm_error_t *derr,
    pf_data_t *dq_p, int *dq_tail_p)
{
	pf_impl_t	impl;
	pf_data_t	*rc_pf_data_p;
	int		i, sts, ret = DDI_SUCCESS;
	int		last_rc_index = *dq_tail_p;

	impl.pf_rpdip = rpdip;
	impl.pf_derr = derr;
	impl.pf_dq_p = dq_p;
	impl.pf_dq_tail_p = dq_tail_p;

	i = 0;

	/*
	 * Scan the fabric using the fault_bdf and fault_addr in error q.
	 * fault_bdf will be valid in the following cases:
	 *	- Fabric message
	 *	- Poisoned TLP
	 *	- Signaled UR/CA
	 *	- Received UR/CA
	 *	- PIO load failures
	 */
	for (rc_pf_data_p = dq_p; IS_RC(rc_pf_data_p) && i <= last_rc_index;
	    rc_pf_data_p++, i++) {
		impl.pf_fbdf = rc_pf_data_p->fault_bdf;
		impl.pf_faddr = rc_pf_data_p->fault_addr;

		if ((impl.pf_fbdf && pf_find_in_q(impl.pf_fbdf, dq_p,
		    *dq_tail_p) == PF_DATA_NOT_FOUND) ||
		    (!impl.pf_fbdf && impl.pf_faddr))
			ret |= pf_pcie_dispatch(rpdip, &impl);
	}

	/* If this is due to safe access, don't analyse the errors and return */
	if (derr->fme_flag != DDI_FM_ERR_UNEXPECTED) {
		ret = DDI_SUCCESS;
		sts = PF_NO_PANIC;
	} else {
		sts = pf_analyse_error(rpdip, derr, dq_p, *dq_tail_p);
		pf_check_ce(dq_p, *dq_tail_p);
	}

	pf_send_ereport(rpdip, derr, dq_p, *dq_tail_p);
	*dq_tail_p = -1;

	/*
	 * If ret is not SUCCESS that means we were not able to add 1 or more
	 * devices to the fault q. Since that device could have have been the
	 * one which had a error, be conservative and panic here.
	 */
	if (ret != DDI_SUCCESS)
		return (PF_PANIC | sts);
	else
		return (sts);
}

/*
 * For each device in the fault queue ensure that no ereport is sent if that
 * device was scanned as a result of a CE in one of its children.
 */
void
pf_check_ce(pf_data_t *dq_p, int dq_tail) {
	int i = dq_tail;
	pf_data_t *pf_data_p;

	for (pf_data_p = &dq_p[dq_tail]; i >= 0; pf_data_p = &dq_p[--i]) {
		if (pf_data_p->send_erpt == PF_SEND_ERPT_UNKNOWN) {
			/*
			 * Always send ereport for the last device in a
			 * particular scan path.
			 */
			pf_data_p->send_erpt = PF_SEND_ERPT_YES;

			if (pf_data_p->severity_flags == (PF_CE |
			    PF_NO_ERROR)) {
				/*
				 * Since this device had a CE don't send ereport
				 * for parents.
				 */
				pf_set_parent_erpt(dq_p,
				    pf_data_p->parent_index, PF_SEND_ERPT_NO);
			} else {
				/* Send ereports for all parents */
				pf_set_parent_erpt(dq_p,
				    pf_data_p->parent_index, PF_SEND_ERPT_YES);
			}
		}
	}

}

void
pf_set_parent_erpt(pf_data_t *dq_p, int index, int erpt_val) {
	int i;
	pf_data_t *pf_data_p;

	for (i = index; i != PF_DATA_NOT_FOUND; i = pf_data_p->parent_index) {
		pf_data_p = &dq_p[i];

		if (pf_data_p->send_erpt != PF_SEND_ERPT_YES)
			pf_data_p->send_erpt = erpt_val;

	}
}

/*
 * Returns the index of the bdf if found in the PCIe Fault Data Queue
 * Returns PF_DATA_NOT_FOUND of the index if the bdf is not found.
 * This function should not be called by RC.
 */
static int
pf_find_in_q(pcie_req_id_t bdf, pf_data_t *dq_p, int dq_tail)
{
	int i;

	/* Check if this is the first item in queue */
	if (dq_tail == -1)
		return (PF_DATA_NOT_FOUND);

	for (i = dq_tail; i >= 0; i--) {
		if (dq_p[i].bdf == bdf)
			return (i);
	}

	return (PF_DATA_NOT_FOUND);
}

int
pf_get_dq_size()
{
	return (pf_dq_size);
}

/*
 * Add PFD to queue.
 * Return true if successfully added.
 * Return false if out of space or already in queue.
 * Pass in pbdf = -1 if pfd is from RC.
 */
int
pf_en_dq(pf_data_t *pf_data_p, pf_data_t *dq_p, int *dq_tail_p,
    pcie_req_id_t pbdf)
{
	int parent_index = PF_DATA_NOT_FOUND;

	if (*dq_tail_p >= (int)pf_dq_size)
		return (DDI_FAILURE);

	/* Look for parent BDF if pfd is not from RC and save rp_bdf */
	if (pbdf != (uint16_t)0xFFFF) {
		parent_index = pf_find_in_q(pbdf, dq_p, *dq_tail_p);
		pf_data_p->rp_bdf = dq_p[0].rp_bdf;
	}

	*dq_tail_p += 1;
	dq_p[*dq_tail_p] = *pf_data_p;
	dq_p[*dq_tail_p].parent_index = parent_index;
	return (DDI_SUCCESS);
}

/* Load PCIe Fault Data for PCI/PCIe devices into PCIe Fault Data Queue */
static int
pf_default_hdl(dev_info_t *dip, dev_info_t *pdip,
    pcie_ppd_t *ppd_p, pf_impl_t *impl)
{
	ddi_acc_handle_t h = ppd_p->ppd_cfg_hdl;
	pf_data_t	pf_data = {0};
	pcie_req_id_t	pbdf;
	uint16_t	pcie_off, aer_off, pcix_off;
	uint8_t		hdr_type, dev_type;
	int		cb_sts, sts = PF_SUCCESS;

	pbdf = PCI_GET_BDF(pdip);
	pf_data.bdf = PCI_GET_BDF(dip);

	/* Make sure this device hasn't already been snapshotted and cleared */
	if (pf_find_in_q(pf_data.bdf, impl->pf_dq_p, *impl->pf_dq_tail_p) !=
	    PF_DATA_NOT_FOUND)
		return (PF_SUCCESS);

	pf_data.dip = dip;
	pf_data.bdg_secbus = ppd_p->ppd_bdg_secbus << 8;
	pf_data.vendor_id = ppd_p->ppd_dev_ven_id & 0xFFFF;
	pf_data.device_id = ppd_p->ppd_dev_ven_id >> 16;
	pf_data.send_erpt = PF_SEND_ERPT_UNKNOWN;

	/*
	 * Read vendor/device ID and check with cached data, if it doesn't match
	 * could very well be a device that isn't responding anymore.  Just
	 * stop.  Save the basic info in the error q for post mortem debugging
	 * purposes.
	 */
	if (pci_config_get32(h, PCI_CONF_VENID) != ppd_p->ppd_dev_ven_id) {
		(void) pf_en_dq(&pf_data, impl->pf_dq_p, impl->pf_dq_tail_p,
		    pbdf);
		return (DDI_FAILURE);
	}

	hdr_type = ppd_p->ppd_hdr_type;
	dev_type = ppd_p->ppd_dev_type;

	pf_data.hdr_type = hdr_type;
	pf_data.command = pci_config_get16(h, PCI_CONF_COMM);
	pf_data.status = pci_config_get16(h, PCI_CONF_STAT);
	pf_data.rev_id = pci_config_get8(h, PCI_CONF_REVID);
	pcie_off = ppd_p->ppd_pcie_off;
	aer_off = ppd_p->ppd_aer_off;

	if (hdr_type == PCI_HEADER_ONE) {
		pf_data.s_status = pci_config_get16(h, PCI_BCNF_SEC_STATUS);
	}

	pf_data.dev_type = dev_type;
	if (dev_type == PCIE_PCIECAP_DEV_TYPE_PCI_DEV) {
		if (pci_lcap_locate(h, PCI_CAP_ID_PCIX, &pcix_off)
		    != DDI_FAILURE) {
			pf_data.pcix_s_status = pci_config_get16(h,
			    pcix_off + PCI_PCIX_SEC_STATUS);
			pf_data.pcix_bdg_status = pci_config_get32(h,
			    pcix_off + PCI_PCIX_BDG_STATUS);
		}
		goto clear;
	}

	if (!pcie_off)
		goto clear;

	pf_data.dev_status = PCI_CAP_GET16(h, NULL, pcie_off, PCIE_DEVSTS);
	pf_data.pcie_off = pcie_off;

	/*
	 * If a bridge does not have any error no need to scan any further down.
	 * For PCIe devices, check the PCIe device status and PCI secondary
	 * status.
	 * - Some non-compliant PCIe devices do not utilize PCIe
	 *   error registers.  If so rely on legacy PCI error registers.
	 * For PCI devices, check the PCI secondary status.
	 */
	if (hdr_type == PCI_HEADER_ONE) {
		if ((dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) &&
		    !(pf_data.dev_status & PF_PCIE_BDG_ERR) &&
		    !(pf_data.s_status & PF_PCI_BDG_ERR))
			sts |= PF_DO_NOT_SCAN;

		if ((dev_type == PCIE_PCIECAP_DEV_TYPE_PCI_DEV) &&
		    !(pf_data.s_status & PF_PCI_BDG_ERR))
			sts |= PF_DO_NOT_SCAN;
	}

	if (!aer_off)
		goto clear;

	pf_data.aer_off = aer_off;
	pf_data.aer_ce_status = PCI_XCAP_GET32(h, NULL, aer_off,
	    PCIE_AER_CE_STS);
	pf_data.aer_ue_status = PCI_XCAP_GET32(h, NULL, aer_off,
	    PCIE_AER_UCE_STS);
	pf_data.aer_severity = PCI_XCAP_GET32(h, NULL, aer_off,
	    PCIE_AER_UCE_SERV);
	pf_data.aer_control = PCI_XCAP_GET32(h, NULL, aer_off, PCIE_AER_CTL);
	pf_data.aer_h0 = PCI_XCAP_GET32(h, NULL, aer_off,
	    PCIE_AER_HDR_LOG + 0x0);
	pf_data.aer_h1 = PCI_XCAP_GET32(h, NULL, aer_off,
	    PCIE_AER_HDR_LOG + 0x4);
	pf_data.aer_h2 = PCI_XCAP_GET32(h, NULL, aer_off,
	    PCIE_AER_HDR_LOG + 0x8);
	pf_data.aer_h3 = PCI_XCAP_GET32(h, NULL, aer_off,
	    PCIE_AER_HDR_LOG + 0xc);

	if (dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
		pf_data.s_aer_ue_status = PCI_XCAP_GET32(h, NULL, aer_off,
		    PCIE_AER_SUCE_STS);
		pf_data.s_aer_severity = PCI_XCAP_GET32(h, NULL, aer_off,
		    PCIE_AER_SUCE_SERV);
		pf_data.s_aer_control = PCI_XCAP_GET32(h, NULL, aer_off,
		    PCIE_AER_SCTL);
		pf_data.s_aer_h0 = PCI_XCAP_GET32(h, NULL, aer_off,
		    PCIE_AER_SHDR_LOG + 0x0);
		pf_data.s_aer_h1 = PCI_XCAP_GET32(h, NULL, aer_off,
		    PCIE_AER_SHDR_LOG + 0x4);
		pf_data.s_aer_h2 = PCI_XCAP_GET32(h, NULL, aer_off,
		    PCIE_AER_SHDR_LOG + 0x8);
		pf_data.s_aer_h3 = PCI_XCAP_GET32(h, NULL, aer_off,
		    PCIE_AER_SHDR_LOG + 0xc);
	}

clear:
	/* Clear the Legacy PCI Errors */
	pci_config_put16(h, PCI_CONF_STAT, pf_data.status);

	if (hdr_type == PCI_HEADER_ONE)
		pci_config_put16(h, PCI_BCNF_SEC_STATUS, pf_data.s_status);

	if (!pcie_off)
		goto queue;

	/* Clear the Advanced PCIe Errors */
	if (aer_off) {
		PCI_XCAP_PUT32(h, NULL, aer_off, PCIE_AER_CE_STS,
		    pf_data.aer_ce_status);
		PCI_XCAP_PUT32(h, NULL, aer_off, PCIE_AER_UCE_STS,
		    pf_data.aer_ue_status);

		if (dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI)
			PCI_XCAP_PUT32(h, NULL, aer_off,
			    PCIE_AER_SUCE_STS, pf_data.s_aer_ue_status);
	}

	/* Clear the PCIe Errors */
	PCI_CAP_PUT16(h, PCI_CAP_ID_PCI_E, pcie_off, PCIE_DEVSTS,
	    pf_data.dev_status);

queue:
	/*
	 * If the driver is FMA hardened and callback capable, call it's
	 * callback function
	 */
	if (DDI_FM_ERRCB_CAP(ddi_fm_capable(dip))) {
		cb_sts = ndi_fm_handler_dispatch(pdip, dip, impl->pf_derr);
		if (cb_sts == DDI_FM_FATAL || cb_sts == DDI_FM_UNKNOWN)
			sts |= PF_FAILURE;
		else
			sts |= PF_SUCCESS;
	}

	/* Add the snapshot to the error q */
	if (pf_en_dq(&pf_data, impl->pf_dq_p, impl->pf_dq_tail_p, pbdf) ==
	    DDI_FAILURE)
		sts |= PF_FAILURE;

	return (sts);
}

/*
 * Function used by PCI error handlers to check if captured address is stored
 * in the DMA or ACC handle caches.
 * return: PF_HDL_NOTFOUND if a handle is not found
 *	   PF_HDL_FOUND if a handle is found
 */
int
pf_hdl_lookup(dev_info_t *dip, uint64_t ena, uint32_t flag, uint32_t addr,
    pcie_req_id_t bdf)
{
	ddi_fm_error_t		derr;
	int			found = 0;

	/* If we don't know the addr or rid just return with UNKNOWN */
	if (addr == NULL && bdf == NULL)
		return (PF_HDL_NOTFOUND);

	if (!(flag & (PF_DMA_ADDR | PF_PIO_ADDR | PF_CFG_ADDR))) {
		return (PF_HDL_NOTFOUND);
	}

	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_flag = DDI_FM_ERR_UNEXPECTED;
	derr.fme_ena = ena;

	/* If we know the addr or bdf mark the handle as failed */
	if (flag & PF_DMA_ADDR) {
		if (pf_hdl_child_lookup(dip, dip, &derr, addr, bdf,
		    pf_dma_hdl_check) != PF_HDL_NOTFOUND)
			found++;
	}
	if (flag & PF_PIO_ADDR) {
		if (pf_hdl_child_lookup(dip, dip, &derr, addr, bdf,
		    pf_pio_hdl_check) != PF_HDL_NOTFOUND)
			found++;
	}
	if (flag & PF_CFG_ADDR) {
		if (pf_hdl_child_lookup(dip, dip, &derr, addr, bdf,
		    pf_cfg_hdl_check) != PF_HDL_NOTFOUND)
			found++;
	}

	return (found ? PF_HDL_FOUND : PF_HDL_NOTFOUND);
}

/*
 * Recursively search the tree for the handler that matches the given address.
 * If the BDF is known, only check the handlers that are associated with the
 * given BDF, otherwise search the entire tree.
 */
static int
pf_hdl_child_lookup(dev_info_t *rpdip, dev_info_t *dip,
    ddi_fm_error_t *derr, uint32_t addr, pcie_req_id_t bdf,
    pf_hdl_compare_t cf)
{
	int			status = PF_HDL_NOTFOUND;
	struct i_ddi_fmhdl	*fmhdl;
	struct i_ddi_fmtgt	*tgt;
	pcie_req_id_t		child_bdf;

	child_bdf = PCI_GET_BDF(dip);

	i_ddi_fm_handler_enter(dip);
	fmhdl = DEVI(dip)->devi_fmhdl;
	ASSERT(fmhdl);

	/* Check if dip and BDF match, if not recurse to it's children. */
	if (bdf == NULL || child_bdf == bdf) {
		/* If we found the handler stop the search */
		if ((status = cf(fmhdl, derr, addr, bdf)) != PF_HDL_NOTFOUND)
			goto done;
	}

	/* If we can't find the handler check it's children */
	for (tgt = fmhdl->fh_tgts; tgt != NULL; tgt = tgt->ft_next) {
		if ((status = pf_hdl_child_lookup(rpdip, tgt->ft_dip, derr,
		    addr, bdf, cf)) != PF_HDL_NOTFOUND)
			goto done;
	}

done:
	i_ddi_fm_handler_exit(dip);

	return (status);
}

/*
 * Find and Mark CFG Handles as failed associated with the given BDF. We should
 * always know the BDF for CFG accesses, since it is encoded in the address of
 * the TLP.  Since there can be multiple cfg handles, mark them all as failed.
 */
/* ARGSUSED */
static int
pf_cfg_hdl_check(struct i_ddi_fmhdl *fmhdl, ddi_fm_error_t *derr,
    uint32_t notused, pcie_req_id_t bdf)
{
	ndi_fmc_t		*fcp;
	ndi_fmcentry_t		*fep;
	ddi_acc_handle_t	ap;
	ddi_acc_hdl_t		*hp;
	int			status = PF_HDL_NOTFOUND;

	ASSERT(bdf);

	/* Return NOTFOUND if this driver doesn't support ACC flagerr */
	if (!DDI_FM_ACC_ERR_CAP(fmhdl->fh_cap) ||
	    ((fcp = fmhdl->fh_acc_cache) == NULL))
		return (PF_HDL_NOTFOUND);

	mutex_enter(&fcp->fc_lock);
	for (fep = fcp->fc_active->fce_next; fep; fep = fep->fce_next) {
		ap = fep->fce_resource;
		hp = impl_acc_hdl_get(ap);

		/* CFG space is always reg 0 */
		if (hp->ah_rnumber == 0) {
			i_ddi_fm_acc_err_set(ap, derr->fme_ena, DDI_FM_NONFATAL,
			    DDI_FM_ERR_UNEXPECTED);
			ddi_fm_acc_err_get(ap, derr, DDI_FME_VERSION);
			derr->fme_acc_handle = ap;
			status = PF_HDL_FOUND;
		}
	}
	mutex_exit(&fcp->fc_lock);

	return (status);
}

/*
 * Find and Mark all ACC Handles associated with a give address and BDF as
 * failed.  If the BDF != NULL, then check to see if the device has a ACC Handle
 * associated with ADDR.  If the handle is not found, mark all the handles as
 * failed.  If the BDF == NULL, mark the handle as failed if it is associated
 * with ADDR.
 */
static int
pf_pio_hdl_check(struct i_ddi_fmhdl *fmhdl, ddi_fm_error_t *derr,
    uint32_t addr, pcie_req_id_t bdf)
{
	ndi_fmc_t		*fcp;
	ndi_fmcentry_t		*fep;
	ddi_acc_handle_t	ap;
	ddi_acc_hdl_t		*hp;
	uint32_t		base_addr;
	uint_t			size;
	int			status = PF_HDL_NOTFOUND;

	if (!DDI_FM_ACC_ERR_CAP(fmhdl->fh_cap) ||
	    ((fcp = fmhdl->fh_acc_cache) == NULL))
		return (PF_HDL_NOTFOUND);

	mutex_enter(&fcp->fc_lock);
	for (fep = fcp->fc_active->fce_next; fep; fep = fep->fce_next) {
		ap = fep->fce_resource;
		hp = impl_acc_hdl_get(ap);

		/* CFG space is always reg 0, don't mark config handlers. */
		if (hp->ah_rnumber == 0)
			continue;

		/*
		 * Normalize the base addr to the addr and strip off the
		 * HB info.  All PIOs are 32 bit access only.
		 */
		base_addr = (uint32_t)(hp->ah_pfn << MMU_PAGESHIFT) +
		    hp->ah_offset;
		size = hp->ah_len;

		if (((addr >= base_addr) && (addr < (base_addr + size))) ||
		    ((addr == NULL) && (bdf != NULL))) {

			status = PF_HDL_FOUND;

			i_ddi_fm_acc_err_set(ap, derr->fme_ena, DDI_FM_NONFATAL,
			    DDI_FM_ERR_UNEXPECTED);
			ddi_fm_acc_err_get(ap, derr, DDI_FME_VERSION);
			derr->fme_acc_handle = ap;
		}
	}
	mutex_exit(&fcp->fc_lock);

	/*
	 * If no handles found and we know this is the right device mark
	 * all the handles as failed.
	 */
	if (addr && bdf != NULL && status == PF_HDL_NOTFOUND)
		status = pf_pio_hdl_check(fmhdl, derr, NULL, bdf);

	return (status);
}

/*
 * Find and Mark all DNA Handles associated with a give address and BDF as
 * failed.  If the BDF != NULL, then check to see if the device has a DMA Handle
 * associated with ADDR.  If the handle is not found, mark all the handles as
 * failed.  If the BDF == NULL, mark the handle as failed if it is associated
 * with ADDR.
 */
static int
pf_dma_hdl_check(struct i_ddi_fmhdl *fmhdl, ddi_fm_error_t *derr,
    uint32_t addr, pcie_req_id_t bdf)
{
	ndi_fmc_t		*fcp;
	ndi_fmcentry_t		*fep;
	ddi_dma_impl_t		*pcie_dp;
	ddi_dma_handle_t	dp;
	int			status = PF_HDL_NOTFOUND;
	uint32_t		base_addr;
	uint_t			size;

	if (!DDI_FM_DMA_ERR_CAP(fmhdl->fh_cap) ||
	    ((fcp = fmhdl->fh_dma_cache) == NULL))
		return (PF_HDL_NOTFOUND);

	mutex_enter(&fcp->fc_lock);
	for (fep = fcp->fc_active->fce_next; fep; fep = fep->fce_next) {
		pcie_dp = (ddi_dma_impl_t *)fep->fce_resource;
		dp = (ddi_dma_handle_t)fep->fce_resource;
		base_addr = (uint32_t)pcie_dp->dmai_mapping;
		size = pcie_dp->dmai_size;

		/*
		 * Mark the handle as failed if the ADDR is mapped, or if we
		 * know the BDF and ADDR == 0.
		 */
		if (((addr >= base_addr) && (addr < (base_addr + size))) ||
		    ((addr == NULL) && (bdf != NULL))) {

			status = PF_HDL_FOUND;

			i_ddi_fm_dma_err_set(dp, derr->fme_ena, DDI_FM_NONFATAL,
			    DDI_FM_ERR_UNEXPECTED);
			ddi_fm_dma_err_get(dp, derr, DDI_FME_VERSION);
			derr->fme_dma_handle = dp;
		}
	}
	mutex_exit(&fcp->fc_lock);

	/*
	 * If no handles found and we know this is the right device mark
	 * all the handles as failed.
	 */
	if (addr && bdf != NULL && status == PF_HDL_NOTFOUND)
		status = pf_dma_hdl_check(fmhdl, derr, NULL, bdf);

	return (status);
}

/*
 * If a PCIe device does not support AER, assume all AER statuses have been set,
 * unless other registers do not indicate a certain error occuring.
 */
static void
pf_adjust_for_no_aer(pf_data_t *pf_data_p)
{
	uint32_t aer_ue = 0;

	if (pf_data_p->aer_off)
		return;

	if (pf_data_p->dev_status & PCIE_DEVSTS_FE_DETECTED) {
		aer_ue = PF_AER_FATAL_ERR;
	} else if (pf_data_p->dev_status & PCIE_DEVSTS_NFE_DETECTED) {
		aer_ue = PF_AER_NON_FATAL_ERR;
		/* Check if the device received a PTLP */
		if (!(pf_data_p->status & PCI_STAT_PERROR))
			aer_ue &= ~PCIE_AER_UCE_PTLP;

		/* Check if the device signaled a CA */
		if (!(pf_data_p->status & PCI_STAT_S_TARG_AB))
			aer_ue &= ~PCIE_AER_UCE_CA;

		/* Check if the device sent a UR */
		if ((!pf_data_p->dev_status & PCIE_DEVSTS_UR_DETECTED))
			aer_ue &= ~PCIE_AER_UCE_UR;

		/*
		 * Ignore ECRCs as it is optional and will manefest itself as
		 * another error like PTLP and MFP
		 */
		aer_ue &= ~PCIE_AER_UCE_ECRC;
	}

	if (pf_data_p->dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
		aer_ue &= ~PCIE_AER_UCE_TRAINING;
		aer_ue &= ~PCIE_AER_UCE_SD;
	}
	pf_data_p->aer_ue_status = aer_ue;
}

static void
pf_adjust_for_no_saer(pf_data_t *pf_data_p)
{
	uint32_t s_aer_ue = 0;

	if (pf_data_p->aer_off)
		return;

	if (pf_data_p->dev_status & PCIE_DEVSTS_FE_DETECTED) {
		s_aer_ue = PF_SAER_FATAL_ERR;
	} else if (pf_data_p->dev_status & PCIE_DEVSTS_NFE_DETECTED) {
		s_aer_ue = PF_SAER_NON_FATAL_ERR;
		/* Check if the device received a UC_DATA */
		if (!(pf_data_p->s_status & PCI_STAT_PERROR))
			s_aer_ue &= ~PCIE_AER_SUCE_UC_DATA_ERR;

		/* Check if the device received a RCVD_MA/MA_ON_SC */
		if (!(pf_data_p->s_status & (PCI_STAT_R_MAST_AB))) {
			s_aer_ue &= ~PCIE_AER_SUCE_RCVD_MA;
			s_aer_ue &= ~PCIE_AER_SUCE_MA_ON_SC;
		}

		/* Check if the device received a RCVD_TA/TA_ON_SC */
		if (!(pf_data_p->s_status & (PCI_STAT_R_TARG_AB))) {
			s_aer_ue &= ~PCIE_AER_SUCE_RCVD_TA;
			s_aer_ue &= ~PCIE_AER_SUCE_TA_ON_SC;
		}
	}
	pf_data_p->s_aer_ue_status = s_aer_ue;
}

/* Find the PCIe-PCI bridge of a PCI device */
static pf_data_t *
pf_get_parent_pcie_bridge(pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	pf_data_t *bdg_pf_data_p;

	if (pf_data_p->dev_type != PCIE_PCIECAP_DEV_TYPE_PCI_DEV)
		return (NULL);

	if (pf_data_p->parent_index == PF_DATA_NOT_FOUND)
		return (NULL);

	for (bdg_pf_data_p = &dq_p[pf_data_p->parent_index];
	    bdg_pf_data_p->dev_type != PCIE_PCIECAP_DEV_TYPE_PCIE2PCI;
	    bdg_pf_data_p = &dq_p[bdg_pf_data_p->parent_index]) {
		if (!bdg_pf_data_p || (bdg_pf_data_p->parent_index ==
		    PF_DATA_NOT_FOUND))
			return (NULL);
	}

	return (bdg_pf_data_p);
}

/*
 * See if a leaf error was bubbled up to the RC and handled.
 * Check if the RC logged an error with the appropriate status type/abort type.
 * Ex: Parity Error, Received Master/Target Abort
 * Check if either the fault address found in the rc matches the device's
 * assigned address range (PIO's only) or the fault BDF in the rc matches the
 * device's BDF or Secondary Bus.
 */
static boolean_t
pf_matched_in_rc(pf_data_t *dq_p, pf_data_t *pf_data_p, uint32_t abort_type)
{
	pf_data_t *rc_pf_data_p;
	pcie_ppd_t *ppd_p;

	ppd_p = pcie_get_ppd(pf_data_p->dip);
	for (rc_pf_data_p = dq_p; IS_RC(rc_pf_data_p); rc_pf_data_p++) {
		/* If device and rc abort type does not match continue */
		if (!(rc_pf_data_p->s_status & abort_type))
			continue;

		/* The Fault BDF = Device's BDF */
		if (rc_pf_data_p->fault_bdf == pf_data_p->bdf)
			return (B_TRUE);

		/* The Fault Addr is in device's address range */
		if (pf_in_addr_range(ppd_p, rc_pf_data_p->fault_addr))
			return (B_TRUE);

		/* The Fault BDF is from PCIe-PCI Bridge's secondary bus */
		if ((pf_data_p->dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) &&
		    ((rc_pf_data_p->fault_bdf & PCIE_REQ_ID_BUS_MASK) ==
		    pf_data_p->bdg_secbus))
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Decodes the TLP and returns the BDF of the handler, address and transaction
 * type if known.
 *
 * Types of TLP logs seen in RC, and what to extract:
 *
 * Memory(DMA) - Requester BDF, address, PF_DMA_ADDR
 * Memory(PIO) - address, PF_PIO_ADDR
 * CFG - Should not occur and result in UR
 * Completion(DMA) - Requester BDF, PF_DMA_ADDR
 * Completion(PIO) - Requester BDF, PF_PIO_ADDR
 *
 * Types of TLP logs seen in SW/Leaf, and what to extract:
 *
 * Memory(DMA) - Requester BDF, address, PF_DMA_ADDR
 * Memory(PIO) - address, PF_PIO_ADDR
 * CFG - Destined BDF, address, PF_CFG_ADDR
 * Completion(DMA) - Requester BDF, PF_DMA_ADDR
 * Completion(PIO) - Requester BDF, PF_PIO_ADDR
 *
 * If the TLP can be decoded the *bdf, *addr, and *trans_type will be populated
 * with the TLP information.  The caller may pass in NULL for any of the
 * mentioned variables, if they are not interested in them.
 */
/* ARGSUSED */
int
pf_tlp_decode(dev_info_t *rpdip, pf_data_t *pf_data_p, pcie_req_id_t *bdf,
    uint32_t *addr, uint32_t *trans_type)
{
	pcie_tlp_hdr_t	*tlp_hdr = (pcie_tlp_hdr_t *)&pf_data_p->aer_h0;
	pcie_req_id_t	rp_bdf, rid_bdf, tlp_bdf;
	uint32_t	tlp_addr, tlp_trans_type;

	rp_bdf = pf_data_p->rp_bdf;

	switch (tlp_hdr->type) {
	case PCIE_TLP_TYPE_IO:
	case PCIE_TLP_TYPE_MEM:
	case PCIE_TLP_TYPE_MEMLK:
		tlp_addr = pf_data_p->aer_h3;
		/* If the RID_BDF == RP_BDF, PIO, otherwise DMA */
		rid_bdf = (pcie_req_id_t)(pf_data_p->aer_h1 >> 16);
		if (rid_bdf == rp_bdf) {
			tlp_trans_type = PF_PIO_ADDR;
			tlp_bdf = NULL;
		} else {
			tlp_trans_type = PF_DMA_ADDR;
			tlp_bdf = rid_bdf;
		}
		break;
	case PCIE_TLP_TYPE_CFG0:
	case PCIE_TLP_TYPE_CFG1:
		tlp_addr = 0;
		tlp_bdf = (pcie_req_id_t)(pf_data_p->aer_h2 >> 16);
		tlp_trans_type = PF_CFG_ADDR;
		break;
	case PCIE_TLP_TYPE_CPL:
	case PCIE_TLP_TYPE_CPLLK:
		tlp_addr = NULL;
		/*
		 * If the completer bdf == RP_BDF, DMA, otherwise PIO or a CFG
		 * completion.
		 */
		tlp_bdf = (pcie_req_id_t)(pf_data_p->aer_h1 >> 16);
		if (tlp_bdf == rp_bdf)
			tlp_trans_type = PF_DMA_ADDR;
		else
			tlp_trans_type = PF_PIO_ADDR | PF_CFG_ADDR;
		break;
	default:
		return (DDI_FAILURE);
	}

	if (addr)
		*addr = tlp_addr;
	if (trans_type)
		*trans_type = tlp_trans_type;
	if (bdf)
		*bdf = tlp_bdf;

	return (DDI_SUCCESS);
}

/*
 * pf_pci_decode function decodes the secondary aer transaction logs in
 * PCIe-PCI bridges.
 *
 * The log is 128 bits long and arranged in this manner.
 * [0:35]   Transaction Attribute	(s_aer_h0-saer_h1)
 * [36:39]  Transaction lower command	(saer_h1)
 * [40:43]  Transaction upper command	(saer_h1)
 * [44:63]  Reserved
 * [64:127] Address			(saer_h2-saer_h3)
 */
/* ARGSUSED */
static int
pf_pci_decode(dev_info_t *rpdip, pf_data_t *pf_data_p, uint16_t *cmd,
    pcie_req_id_t *bdf, uint32_t *addr, uint32_t *trans_type) {
	pcix_attr_t	*attr;
	pcie_req_id_t	rp_bdf;

	rp_bdf = pf_data_p->rp_bdf;

	*cmd = GET_SAER_CMD(pf_data_p);

	switch (*cmd) {
	case PCI_PCIX_CMD_MEMRD_DW:
	case PCI_PCIX_CMD_MEMRD_BL:
	case PCI_PCIX_CMD_MEMRDBL:
	case PCI_PCIX_CMD_MEMWR:
	case PCI_PCIX_CMD_MEMWR_BL:
	case PCI_PCIX_CMD_MEMWRBL:
		*addr = pf_data_p->s_aer_h2;
		attr = (pcix_attr_t *)&pf_data_p->s_aer_h0;

		/*
		 * Could be DMA or PIO.  Find out by look at requesting bdf.
		 * If the requester is the RC, then it's a PIO, otherwise, DMA
		 */
		*bdf = attr->rid;
		if (*bdf == rp_bdf) {
			*trans_type = PF_PIO_ADDR;
			*bdf = 0;
		} else {
			*trans_type = PF_DMA_ADDR;
		}
		break;
	case PCI_PCIX_CMD_CFRD:
	case PCI_PCIX_CMD_CFWR:
		/*
		 * CFG Access should always be down stream.  Match the BDF in
		 * the address phase.
		 */
		*addr = 0;
		attr = (pcix_attr_t *)&pf_data_p->s_aer_h2;
		*bdf = attr->rid;
		*trans_type = PF_CFG_ADDR;
		break;
	case PCI_PCIX_CMD_SPL:
		/*
		 * Check for DMA read completions.  The requesting BDF is in the
		 * Address phase.
		 */
		*addr = 0;
		attr = (pcix_attr_t *)&pf_data_p->s_aer_h0;
		*bdf = attr->rid;
		*trans_type = PF_DMA_ADDR;
		break;
	default:
		*addr = 0;
		*bdf = 0;
		*trans_type = 0;
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * For this function only the Primary AER Header Logs need to be valid in the
 * pfd (PCIe Fault Data) arg.
 */
int
pf_tlp_hdl_lookup(dev_info_t *rpdip, ddi_fm_error_t *derr, pf_data_t *pf_data_p)
{
	uint32_t	addr;
	int		err = PF_HDL_NOTFOUND;
	pcie_req_id_t	hdl_bdf;
	uint32_t	trans_type;

	if (pf_tlp_decode(rpdip, pf_data_p, &hdl_bdf, &addr, &trans_type) ==
	    DDI_SUCCESS) {
		err = pf_hdl_lookup(rpdip, derr->fme_ena, trans_type, addr,
		    hdl_bdf);
	}

	return (err);
}

/*
 * Last function called for PF Scan Fabric.
 * Sends ereports for all devices that are not dev_type = RC.
 * Will also unlock all the mutexes grabbed during fabric scan.
 */
/* ARGSUSED */
static void
pf_send_ereport(dev_info_t *rpdip, ddi_fm_error_t *derr, pf_data_t *dq_p,
    int dq_tail)
{
	char		buf[FM_MAX_CLASS];
	pf_data_t	*pfd_p;
	int		i, total = dq_tail;
	boolean_t	hasError = B_FALSE;

	i = 0;
	/*
	 * Search through the error queue and look for the number of pf_data
	 * from the RC and if the queue contains any errors.  All the pf_data's
	 * from the RC will only be at the top of the queue.
	 */
	for (pfd_p = dq_p; i <= dq_tail; pfd_p++, i++) {
		if (IS_RC(pfd_p)) {
			total--;
			if (pfd_p->s_status)
				hasError = B_TRUE;
		} else {
			if (hasError)
				break;
			if (pfd_p->severity_flags != PF_NO_ERROR) {
				hasError = B_TRUE;
				break;
			}
		}
	}

	i = dq_tail;
	for (pfd_p = &dq_p[dq_tail]; i >= 0; pfd_p--, i--) {
		if (IS_RC(pfd_p))
			continue;

		if ((!hasError) || (pfd_p->send_erpt == PF_SEND_ERPT_NO) ||
		    (derr->fme_flag != DDI_FM_ERR_UNEXPECTED))
			goto unlock;

		(void) snprintf(buf, FM_MAX_CLASS, "%s", "fire.fabric");
		ddi_fm_ereport_post(pfd_p->dip, buf, derr->fme_ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
		    "req_id", DATA_TYPE_UINT16, pfd_p->bdf,
		    "device_id", DATA_TYPE_UINT16, pfd_p->device_id,
		    "vendor_id", DATA_TYPE_UINT16, pfd_p->vendor_id,
		    "rev_id", DATA_TYPE_UINT8, pfd_p->rev_id,
		    "dev_type", DATA_TYPE_UINT16, pfd_p->dev_type,
		    "cap_off", DATA_TYPE_UINT16, pfd_p->pcie_off,
		    "aer_off", DATA_TYPE_UINT16, pfd_p->aer_off,
		    "sts_reg", DATA_TYPE_UINT16, pfd_p->status,
		    "sts_sreg", DATA_TYPE_UINT16, pfd_p->s_status,
		    "pcix_sts_reg", DATA_TYPE_UINT16, pfd_p->pcix_s_status,
		    "pcix_bdg_sts_reg", DATA_TYPE_UINT32,
		    pfd_p->pcix_bdg_status,
		    "dev_sts_reg", DATA_TYPE_UINT16, pfd_p->dev_status,
		    "aer_ce", DATA_TYPE_UINT32, pfd_p->aer_ce_status,
		    "aer_ue", DATA_TYPE_UINT32, pfd_p->aer_ue_status,
		    "aer_sev", DATA_TYPE_UINT32, pfd_p->aer_severity,
		    "aer_ctr", DATA_TYPE_UINT32, pfd_p->aer_control,
		    "aer_h1", DATA_TYPE_UINT32, pfd_p->aer_h0,
		    "aer_h2", DATA_TYPE_UINT32, pfd_p->aer_h1,
		    "aer_h3", DATA_TYPE_UINT32, pfd_p->aer_h2,
		    "aer_h4", DATA_TYPE_UINT32, pfd_p->aer_h3,
		    "saer_ue", DATA_TYPE_UINT32, pfd_p->s_aer_ue_status,
		    "saer_sev", DATA_TYPE_UINT32, pfd_p->s_aer_severity,
		    "saer_ctr", DATA_TYPE_UINT32, pfd_p->s_aer_control,
		    "saer_h1", DATA_TYPE_UINT32, pfd_p->s_aer_h0,
		    "saer_h2", DATA_TYPE_UINT32, pfd_p->s_aer_h1,
		    "saer_h3", DATA_TYPE_UINT32, pfd_p->s_aer_h2,
		    "saer_h4", DATA_TYPE_UINT32, pfd_p->s_aer_h3,
		    "remainder", DATA_TYPE_UINT32, total--,
		    "severity", DATA_TYPE_UINT32, pfd_p->severity_flags,
		    NULL);

unlock:
		pf_exit(pfd_p->dip);
	}
}

/*
 * Ignore:
 * - TRAINING: as leaves do not have children
 * - SD: as leaves do not have children
 */
const pf_fab_err_tbl_t pcie_pcie_tbl[] = {
	PCIE_AER_UCE_DLP,	pf_panic,
	PCIE_AER_UCE_PTLP,	pf_analyse_ptlp,
	PCIE_AER_UCE_FCP,	pf_panic,
	PCIE_AER_UCE_TO,	pf_analyse_to,
	PCIE_AER_UCE_CA,	pf_analyse_ca_ur,
	PCIE_AER_UCE_UC,	pf_analyse_uc,
	PCIE_AER_UCE_RO,	pf_panic,
	PCIE_AER_UCE_MTLP,	pf_panic,
	PCIE_AER_UCE_ECRC,	pf_panic,
	PCIE_AER_UCE_UR,	pf_analyse_ca_ur,
	NULL,			NULL
};

const pf_fab_err_tbl_t pcie_sw_tbl[] = {
	PCIE_AER_UCE_TRAINING,	pf_no_panic,
	PCIE_AER_UCE_DLP,	pf_panic,
	PCIE_AER_UCE_SD,	pf_no_panic,
	PCIE_AER_UCE_PTLP,	pf_analyse_ptlp,
	PCIE_AER_UCE_FCP,	pf_panic,
	PCIE_AER_UCE_TO,	pf_analyse_to,
	PCIE_AER_UCE_CA,	pf_analyse_ca_ur,
	PCIE_AER_UCE_UC,	pf_analyse_uc,
	PCIE_AER_UCE_RO,	pf_panic,
	PCIE_AER_UCE_MTLP,	pf_panic,
	PCIE_AER_UCE_ECRC,	pf_panic,
	PCIE_AER_UCE_UR,	pf_analyse_ca_ur,
	NULL,			NULL
};

const pf_fab_err_tbl_t pcie_pcie_bdg_tbl[] = {
	PCIE_AER_SUCE_TA_ON_SC,		pf_analyse_sc,
	PCIE_AER_SUCE_MA_ON_SC,		pf_analyse_sc,
	PCIE_AER_SUCE_RCVD_TA,		pf_analyse_ma_ta,
	PCIE_AER_SUCE_RCVD_MA,		pf_analyse_ma_ta,
	PCIE_AER_SUCE_USC_ERR,		pf_panic,
	PCIE_AER_SUCE_USC_MSG_DATA_ERR,	pf_analyse_ma_ta,
	PCIE_AER_SUCE_UC_DATA_ERR,	pf_analyse_uc_data,
	PCIE_AER_SUCE_UC_ATTR_ERR,	pf_panic,
	PCIE_AER_SUCE_UC_ADDR_ERR,	pf_panic,
	PCIE_AER_SUCE_TIMER_EXPIRED,	pf_panic,
	PCIE_AER_SUCE_PERR_ASSERT,	pf_analyse_perr_assert,
	PCIE_AER_SUCE_SERR_ASSERT,	pf_no_panic,
	PCIE_AER_SUCE_INTERNAL_ERR,	pf_panic,
	NULL,			NULL
};

const pf_fab_err_tbl_t pcie_pci_bdg_tbl[] = {
	PCI_STAT_PERROR,	pf_analyse_pci,
	PCI_STAT_S_PERROR,	pf_analyse_pci,
	PCI_STAT_S_SYSERR,	pf_panic,
	PCI_STAT_R_MAST_AB,	pf_analyse_pci,
	PCI_STAT_R_TARG_AB,	pf_analyse_pci,
	PCI_STAT_S_TARG_AB,	pf_analyse_pci,
	NULL,			NULL
};

const pf_fab_err_tbl_t pcie_pci_tbl[] = {
	PCI_STAT_PERROR,	pf_analyse_pci,
	PCI_STAT_S_PERROR,	pf_analyse_pci,
	PCI_STAT_S_SYSERR,	pf_panic,
	PCI_STAT_R_MAST_AB,	pf_analyse_pci,
	PCI_STAT_R_TARG_AB,	pf_analyse_pci,
	PCI_STAT_S_TARG_AB,	pf_analyse_pci,
	NULL,			NULL
};

/*
 * Analyse all the PCIe Fault Data (pfd) gathered during dispatch in the pfd
 * Queue.
 */
static int
pf_analyse_error(dev_info_t *rpdip, ddi_fm_error_t *derr, pf_data_t *dq_p,
    int dq_tail)
{
	int		i = 0, pfd_err, err = 0;
	pf_data_t	*pf_data_p;

	for (pf_data_p = &dq_p[i]; i <= dq_tail; pf_data_p = &dq_p[++i]) {
		pfd_err = 0;
		switch (pf_data_p->dev_type) {
		case PCIE_PCIECAP_DEV_TYPE_PCIE_DEV:
			if (PCIE_DEVSTS_CE_DETECTED & pf_data_p->dev_status)
				pfd_err |= PF_CE;

			pf_adjust_for_no_aer(pf_data_p);
			pfd_err |= pf_analyse_error_tbl(rpdip, derr, dq_p,
			    pf_data_p, pcie_pcie_tbl, pf_data_p->aer_ue_status);
			break;
		case PCIE_PCIECAP_DEV_TYPE_UP:
		case PCIE_PCIECAP_DEV_TYPE_DOWN:
			if (PCIE_DEVSTS_CE_DETECTED & pf_data_p->dev_status)
				pfd_err |= PF_CE;

			pf_adjust_for_no_aer(pf_data_p);
			pfd_err |= pf_analyse_error_tbl(rpdip, derr, dq_p,
			    pf_data_p, pcie_sw_tbl, pf_data_p->aer_ue_status);
			break;
		case PCIE_PCIECAP_DEV_TYPE_ROOT:
			/* Do not analyse RC info as it has already been done */
			pfd_err |= PF_NO_ERROR;
			break;
		case PCIE_PCIECAP_DEV_TYPE_PCIE2PCI:
			if (PCIE_DEVSTS_CE_DETECTED & pf_data_p->dev_status)
				pfd_err |= PF_CE;

			if ((PCIE_DEVSTS_NFE_DETECTED |
			    PCIE_DEVSTS_FE_DETECTED)
			    & pf_data_p->dev_status) {
				pf_adjust_for_no_aer(pf_data_p);
				pf_adjust_for_no_saer(pf_data_p);
				pfd_err |= pf_analyse_error_tbl(rpdip, derr,
				    dq_p, pf_data_p, pcie_pcie_tbl,
				    pf_data_p->aer_ue_status);
				pfd_err |= pf_analyse_error_tbl(rpdip, derr,
				    dq_p, pf_data_p, pcie_pcie_bdg_tbl,
				    pf_data_p->s_aer_ue_status);
				break;
			}
			/*
			 * Some non-compliant PCIe devices do not utilize PCIe
			 * error registers.  So fallthrough and rely on legacy
			 * PCI error registers.
			 */
			/* FALLTHROUGH */
		case PCIE_PCIECAP_DEV_TYPE_PCI_DEV:
			pfd_err |= pf_analyse_error_tbl(rpdip, derr, dq_p,
			    pf_data_p, pcie_pci_tbl, pf_data_p->status);
			if (pf_data_p->hdr_type == PCI_HEADER_ONE)
				pfd_err |= pf_analyse_error_tbl(rpdip, derr,
				    dq_p, pf_data_p, pcie_pci_bdg_tbl,
				    pf_data_p->s_status);
			break;
		}

		err |= pfd_err;
		pf_data_p->severity_flags = pfd_err;
	}

	return (err);
}

static int
pf_analyse_error_tbl(dev_info_t *rpdip, ddi_fm_error_t *derr, pf_data_t *dq_p,
    pf_data_t *pf_data_p, const pf_fab_err_tbl_t *tbl, uint32_t err_reg) {
	const pf_fab_err_tbl_t *row;
	int err = 0;

	for (row = tbl; err_reg && (row->bit != NULL) && !(err & PF_PANIC);
	    row++) {
		if (err_reg & row->bit)
			err |= row->handler(rpdip, derr, row->bit, dq_p,
			    pf_data_p);
	}

	if (!err)
		err = PF_NO_ERROR;

	return (err);
}

/*
 * PCIe Completer Abort and Unsupport Request error analyser.  If a PCIe device
 * issues a CA/UR a corresponding Received CA/UR should have been seen in the
 * PCIe root complex.  Check to see if RC did indeed receive a CA/UR, if so then
 * this error may be safely ignored.  If not check the logs and see if an
 * associated handler for this transaction can be found.
 */
/* ARGSUSED */
static int
pf_analyse_ca_ur(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	uint32_t	abort_type;

	if (bit == PCIE_AER_UCE_UR)
		abort_type = PCI_STAT_R_MAST_AB;
	else
		abort_type = PCI_STAT_R_TARG_AB;

	if (pf_matched_in_rc(dq_p, pf_data_p, abort_type))
		return (PF_MATCHED_RC);

	if (HAS_AER_LOGS(pf_data_p, bit)) {
		if (pf_tlp_hdl_lookup(rpdip, derr, pf_data_p) ==
		    PF_HDL_NOTFOUND)
			return (PF_PANIC);

		return (PF_MATCHED_DEVICE);
	}

	return (PF_PANIC);
}

/*
 * PCIe-PCI Bridge Received Master Abort and Target error analyser.  If a PCIe
 * Bridge receives a MA/TA a corresponding sent CA/UR should have been seen in
 * the PCIe root complex.  Check to see if RC did indeed receive a CA/UR, if so
 * then this error may be safely ignored.  If not check the logs and see if an
 * associated handler for this transaction can be found.
 */
/* ARGSUSED */
static int
pf_analyse_ma_ta(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	uint16_t	cmd;
	uint32_t	addr;
	pcie_req_id_t	bdf;
	uint32_t	abort_type, trans_type;

	if (bit == PCIE_AER_SUCE_RCVD_MA)
		abort_type = PCI_STAT_R_MAST_AB;
	else
		abort_type = PCI_STAT_R_TARG_AB;

	if (pf_matched_in_rc(dq_p, pf_data_p, abort_type))
		return (PF_MATCHED_RC);

	if (!HAS_SAER_LOGS(pf_data_p, bit))
		return (PF_PANIC);

	if (pf_pci_decode(rpdip, pf_data_p, &cmd, &bdf, &addr, &trans_type) !=
	    DDI_SUCCESS)
		return (PF_PANIC);

	if (pf_hdl_lookup(rpdip, derr->fme_ena, trans_type, addr, bdf) ==
	    PF_HDL_NOTFOUND)
		return (PF_PANIC);

	return (PF_MATCHED_DEVICE);
}

/*
 * Generic PCI error analyser.  This function is used for Parity Errors,
 * Received Master Aborts, Received Target Aborts, and Signaled Target Aborts.
 * In general PCI devices do not have error logs, it is very difficult to figure
 * out what transaction caused the error.  Instead find the nearest PCIe-PCI
 * Bridge and check to see if it has logs and if it has an error associated with
 * this PCI Device.
 */
/* ARGSUSED */
static int
pf_analyse_pci(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	pf_data_t	*parent_pfd_p;
	uint16_t	cmd;
	uint32_t	addr;
	pcie_req_id_t	bdf;
	uint32_t	trans_type, aer_ue_status;
	pcie_ppd_t	*ppd_p;

	if (pf_data_p->status & PCI_STAT_S_SYSERR)
		return (PF_PANIC);

	if (bit & (PCI_STAT_PERROR | PCI_STAT_S_PERROR)) {
		aer_ue_status = PCIE_AER_SUCE_PERR_ASSERT;
	} else {
		aer_ue_status = (PCIE_AER_SUCE_TA_ON_SC |
		    PCIE_AER_SUCE_MA_ON_SC | PCIE_AER_SUCE_RCVD_TA |
		    PCIE_AER_SUCE_RCVD_MA);
	}

	parent_pfd_p = pf_get_parent_pcie_bridge(dq_p, pf_data_p);
	if (parent_pfd_p == NULL)
		return (PF_PANIC);

	if (!(parent_pfd_p->s_aer_ue_status & aer_ue_status) ||
	    !HAS_SAER_LOGS(parent_pfd_p, aer_ue_status))
		return (PF_PANIC);

	if (pf_pci_decode(rpdip, parent_pfd_p, &cmd, &bdf, &addr, &trans_type)
	    != DDI_SUCCESS)
		return (PF_PANIC);

	/*
	 * If the addr or bdf from the parent PCIe bridge logs belong to this
	 * PCI device, assume the PCIe bridge's error handling has already taken
	 * care of this PCI device's error.
	 */
	ppd_p = pcie_get_ppd(pf_data_p->dip);
	if ((bdf == pf_data_p->bdf) || pf_in_addr_range(ppd_p, addr))
		return (PF_MATCHED_PARENT);

	/*
	 * If this device is a PCI-PCI bridge, check if the bdf in the parent
	 * PCIe bridge logs is in the range of this PCI-PCI Bridge's bus ranges.
	 * If they are, then assume the PCIe bridge's error handling has already
	 * taken care of this PCI-PCI bridge device's error.
	 */
	if ((pf_data_p->hdr_type == PCI_HEADER_ONE) &&
	    pf_in_bus_range(ppd_p, bdf))
		return (PF_MATCHED_PARENT);

	return (PF_PANIC);
}

/*
 * PCIe Bridge transactions associated with PERR.
 * o Bridge received a poisoned Non-Posted Write (CFG Writes) from PCIe
 * o Bridge received a poisoned Posted Write from (MEM Writes) from PCIe
 * o Bridge received a poisoned Completion on a Split Transction from PCIe
 * o Bridge received a poisoned Completion on a Delayed Transction from PCIe
 *
 * Check for non-poisoned PCIe transactions that got forwarded to the secondary
 * side and detects a PERR#.  Except for delayed read completions, a poisoned
 * TLP will be forwarded to the secondary bus and PERR# will be asserted.
 */
/* ARGSUSED */
static int
pf_analyse_perr_assert(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	uint16_t	cmd;
	uint32_t	addr;
	pcie_req_id_t	bdf;
	uint32_t	trans_type;
	int		sts;
	int		err = PF_NO_ERROR;

	if (HAS_SAER_LOGS(pf_data_p, bit)) {
		if (pf_pci_decode(rpdip, pf_data_p, &cmd, &bdf, &addr,
		    &trans_type) != DDI_SUCCESS)
			return (PF_PANIC);

		switch (cmd) {
		case PCI_PCIX_CMD_MEMWR:
		case PCI_PCIX_CMD_MEMWR_BL:
		case PCI_PCIX_CMD_MEMWRBL:
			/* Posted Writes Transactions */
			if (trans_type == PF_PIO_ADDR)
				sts = pf_hdl_lookup(rpdip, derr->fme_ena,
				    trans_type, addr, bdf);
			break;
		case PCI_PCIX_CMD_CFWR:
			/*
			 * Check to see if it is a non-posted write.  If so, a
			 * UR Completion would have been sent.
			 */
			if (pf_matched_in_rc(dq_p, pf_data_p,
			    PCI_STAT_R_MAST_AB)) {
				sts = PF_HDL_FOUND;
				err = PF_MATCHED_RC;
				break;
			}
			sts = pf_hdl_lookup(rpdip, derr->fme_ena,
			    trans_type, addr, bdf);
			break;
		case PCI_PCIX_CMD_SPL:
			sts = pf_hdl_lookup(rpdip, derr->fme_ena,
			    trans_type, addr, bdf);
			break;
		default:
			/* Unexpected situation, panic */
			sts = PF_HDL_NOTFOUND;
		}

		if (sts == PF_HDL_NOTFOUND)
			err = PF_PANIC;
	} else {
		/*
		 * Check to see if it is a non-posted write.  If so, a UR
		 * Completion would have been sent.
		 */
		if ((pf_data_p->dev_status & PCIE_DEVCTL_UR_REPORTING_EN) &&
		    pf_matched_in_rc(dq_p, pf_data_p, PCI_STAT_R_MAST_AB))
			err = PF_MATCHED_RC;

		/* Check for posted writes.  Transaction is lost. */
		if (pf_data_p->s_status & PCI_STAT_S_PERROR) {
			err = PF_PANIC;
		}

		/*
		 * All other scenarios are due to read completions.  Check for
		 * PERR on the primary side.  If found the primary side error
		 * handling will take care of this error.
		 */
		if (err == PF_NO_ERROR) {
			if (pf_data_p->status & PCI_STAT_PERROR)
				err = PF_MATCHED_PARENT;
			else
				err = PF_PANIC;
		}
	}

	return (err);
}

/*
 * PCIe Poisoned TLP error analyser.  If a PCIe device receives a Poisoned TLP,
 * check the logs and see if an associated handler for this transaction can be
 * found.
 */
/* ARGSUSED */
static int
pf_analyse_ptlp(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	pf_data_t	*parent_pfd_p;

	/*
	 * If AERs are supported find the logs in this device, otherwise look in
	 * it's parent's logs.
	 */
	if (HAS_AER_LOGS(pf_data_p, bit)) {
		pcie_tlp_hdr_t *hdr = (pcie_tlp_hdr_t *)&pf_data_p->aer_h0;

		/*
		 * Double check that the log contains a poisoned TLP.
		 * Some devices like PLX switch do not log poison TLP headers.
		 */
		if (hdr->ep) {
			if (pf_tlp_hdl_lookup(rpdip, derr, pf_data_p) ==
			    PF_HDL_FOUND)
				return (PF_MATCHED_DEVICE);
		}
		return (PF_PANIC);
	}

	if (pf_data_p->parent_index != PF_DATA_NOT_FOUND) {
		parent_pfd_p = &dq_p[pf_data_p->parent_index];
		if (HAS_AER_LOGS(parent_pfd_p, bit))
			return (PF_MATCHED_PARENT);
	}

	return (PF_PANIC);
}

/*
 * PCIe-PCI Bridge Received Master and Target abort error analyser on Split
 * Completions.  If a PCIe Bridge receives a MA/TA check logs and see if an
 * associated handler for this transaction can be found.
 */
/* ARGSUSED */
static int
pf_analyse_sc(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	uint16_t	cmd;
	uint32_t	addr;
	pcie_req_id_t	bdf;
	uint32_t	trans_type;
	int		sts = PF_HDL_NOTFOUND;

	if (!HAS_SAER_LOGS(pf_data_p, bit))
		return (PF_PANIC);

	if (pf_pci_decode(rpdip, pf_data_p, &cmd, &bdf, &addr, &trans_type) !=
	    DDI_SUCCESS)
		return (PF_PANIC);

	if (cmd == PCI_PCIX_CMD_SPL)
		sts = pf_hdl_lookup(rpdip, derr->fme_ena, trans_type,
		    addr, bdf);

	if (sts == PF_HDL_NOTFOUND)
		return (PF_PANIC);

	return (PF_MATCHED_DEVICE);
}

/*
 * PCIe Timeout error analyser.  This error can be forgiven if it is marked as
 * CE Advisory.  If it is marked as advisory, this means the HW can recover
 * and/or retry the transaction automatically.
 */
/* ARGSUSED */
static int
pf_analyse_to(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	/*
	 * If the Advisory Non-Fatal is set, that means HW will automatically
	 * retry the failed transaction.
	 */
	if (HAS_AER_LOGS(pf_data_p, bit) && CE_ADVISORY(pf_data_p))
		return (PF_NO_PANIC);

	return (PF_PANIC);
}

/*
 * PCIe Unexpected Completion.  This error can be forgiven if it is marked as
 * CE Advisory.  If it is marked as advisory, this means the HW can recover
 * and/or retry the transaction automatically.
 */
/* ARGSUSED */
static int
pf_analyse_uc(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	/*
	 * Check to see if this TLP was misrouted by matching the device BDF
	 * with the TLP Log.  If misrouting panic, otherwise don't panic.
	 */
	if (HAS_AER_LOGS(pf_data_p, bit) &&
	    (pf_data_p->bdf == (pf_data_p->aer_h2 >> 16)))
		return (PF_NO_PANIC);

	return (PF_PANIC);
}

/*
 * PCIe-PCI Bridge Uncorrectable Data error anlyser.  All Uncorrectable Data
 * errors should have resulted in a PCIe Poisoned TLP to the RC, except for
 * Posted Writes.  Check the logs for Posted Writes and if the RC did not see a
 * Poisoned TLP.
 *
 * Non-Posted Writes will also generate a UR in the completion status, which the
 * RC should also see.
 */
/* ARGSUSED */
static int
pf_analyse_uc_data(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	uint16_t	cmd;
	uint32_t	addr;
	pcie_req_id_t	bdf;
	uint32_t	trans_type;

	if (!HAS_SAER_LOGS(pf_data_p, bit))
		return (PF_PANIC);

	if (pf_matched_in_rc(dq_p, pf_data_p, PCI_STAT_PERROR))
		return (PF_MATCHED_RC);

	if (pf_pci_decode(rpdip, pf_data_p, &cmd, &bdf, &addr, &trans_type) !=
	    DDI_SUCCESS)
		return (PF_PANIC);

	if (pf_hdl_lookup(rpdip, derr->fme_ena, trans_type, addr, bdf) ==
	    PF_HDL_NOTFOUND)
		return (PF_PANIC);

	return (PF_MATCHED_DEVICE);
}

/* ARGSUSED */
static int
pf_no_panic(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	return (PF_NO_PANIC);
}

/* ARGSUSED */
static int
pf_matched_device(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	return (PF_MATCHED_DEVICE);
}

/* ARGSUSED */
static int
pf_panic(dev_info_t *rpdip, ddi_fm_error_t *derr, uint32_t bit,
    pf_data_t *dq_p, pf_data_t *pf_data_p)
{
	return (PF_PANIC);
}
