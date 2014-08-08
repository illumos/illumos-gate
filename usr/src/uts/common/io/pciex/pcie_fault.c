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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>
#include <sys/fm/io/pci.h>
#include <sys/promif.h>
#include <sys/disp.h>
#include <sys/atomic.h>
#include <sys/pcie.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>

#define	PF_PCIE_BDG_ERR (PCIE_DEVSTS_FE_DETECTED | PCIE_DEVSTS_NFE_DETECTED | \
	PCIE_DEVSTS_CE_DETECTED)

#define	PF_PCI_BDG_ERR (PCI_STAT_S_SYSERR | PCI_STAT_S_TARG_AB | \
	PCI_STAT_R_MAST_AB | PCI_STAT_R_TARG_AB | PCI_STAT_S_PERROR)

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

#define	PF_PCI_PARITY_ERR (PCI_STAT_S_PERROR | PCI_STAT_PERROR)

#define	PF_FIRST_AER_ERR(bit, adv) \
	(bit & (1 << (adv->pcie_adv_ctl & PCIE_AER_CTL_FST_ERR_PTR_MASK)))

#define	HAS_AER_LOGS(pfd_p, bit) \
	(PCIE_HAS_AER(pfd_p->pe_bus_p) && \
	PF_FIRST_AER_ERR(bit, PCIE_ADV_REG(pfd_p)))

#define	PF_FIRST_SAER_ERR(bit, adv) \
	(bit & (1 << (adv->pcie_sue_ctl & PCIE_AER_SCTL_FST_ERR_PTR_MASK)))

#define	HAS_SAER_LOGS(pfd_p, bit) \
	(PCIE_HAS_AER(pfd_p->pe_bus_p) && \
	PF_FIRST_SAER_ERR(bit, PCIE_ADV_BDG_REG(pfd_p)))

#define	GET_SAER_CMD(pfd_p) \
	((PCIE_ADV_BDG_HDR(pfd_p, 1) >> \
	PCIE_AER_SUCE_HDR_CMD_LWR_SHIFT) & PCIE_AER_SUCE_HDR_CMD_LWR_MASK)

#define	CE_ADVISORY(pfd_p) \
	(PCIE_ADV_REG(pfd_p)->pcie_ce_status & PCIE_AER_CE_AD_NFE)

/* PCIe Fault Fabric Error analysis table */
typedef struct pf_fab_err_tbl {
	uint32_t	bit;		/* Error bit */
	int		(*handler)();	/* Error handling fuction */
	uint16_t	affected_flags; /* Primary affected flag */
	/*
	 * Secondary affected flag, effective when the information
	 * indicated by the primary flag is not available, eg.
	 * PF_AFFECTED_AER/SAER/ADDR
	 */
	uint16_t	sec_affected_flags;
} pf_fab_err_tbl_t;

static pcie_bus_t *pf_is_ready(dev_info_t *);
/* Functions for scanning errors */
static int pf_default_hdl(dev_info_t *, pf_impl_t *);
static int pf_dispatch(dev_info_t *, pf_impl_t *, boolean_t);
static boolean_t pf_in_addr_range(pcie_bus_t *, uint64_t);

/* Functions for gathering errors */
static void pf_pcix_ecc_regs_gather(pf_pcix_ecc_regs_t *pcix_ecc_regs,
    pcie_bus_t *bus_p, boolean_t bdg);
static void pf_pcix_regs_gather(pf_data_t *pfd_p, pcie_bus_t *bus_p);
static void pf_pcie_regs_gather(pf_data_t *pfd_p, pcie_bus_t *bus_p);
static void pf_pci_regs_gather(pf_data_t *pfd_p, pcie_bus_t *bus_p);
static int pf_dummy_cb(dev_info_t *, ddi_fm_error_t *, const void *);
static void pf_en_dq(pf_data_t *pfd_p, pf_impl_t *impl_p);

/* Functions for analysing errors */
static int pf_analyse_error(ddi_fm_error_t *, pf_impl_t *);
static void pf_adjust_for_no_aer(pf_data_t *);
static void pf_adjust_for_no_saer(pf_data_t *);
static pf_data_t *pf_get_pcie_bridge(pf_data_t *, pcie_req_id_t);
static pf_data_t *pf_get_parent_pcie_bridge(pf_data_t *);
static boolean_t pf_matched_in_rc(pf_data_t *, pf_data_t *,
    uint32_t);
static int pf_analyse_error_tbl(ddi_fm_error_t *, pf_impl_t *,
    pf_data_t *, const pf_fab_err_tbl_t *, uint32_t);
static int pf_analyse_ca_ur(ddi_fm_error_t *, uint32_t,
    pf_data_t *, pf_data_t *);
static int pf_analyse_ma_ta(ddi_fm_error_t *, uint32_t,
    pf_data_t *, pf_data_t *);
static int pf_analyse_pci(ddi_fm_error_t *, uint32_t,
    pf_data_t *, pf_data_t *);
static int pf_analyse_perr_assert(ddi_fm_error_t *, uint32_t,
    pf_data_t *, pf_data_t *);
static int pf_analyse_ptlp(ddi_fm_error_t *, uint32_t,
    pf_data_t *, pf_data_t *);
static int pf_analyse_sc(ddi_fm_error_t *, uint32_t,
    pf_data_t *, pf_data_t *);
static int pf_analyse_to(ddi_fm_error_t *, uint32_t,
    pf_data_t *, pf_data_t *);
static int pf_analyse_uc(ddi_fm_error_t *, uint32_t,
    pf_data_t *, pf_data_t *);
static int pf_analyse_uc_data(ddi_fm_error_t *, uint32_t,
    pf_data_t *, pf_data_t *);
static int pf_no_panic(ddi_fm_error_t *, uint32_t,
    pf_data_t *, pf_data_t *);
static int pf_panic(ddi_fm_error_t *, uint32_t,
    pf_data_t *, pf_data_t *);
static void pf_send_ereport(ddi_fm_error_t *, pf_impl_t *);
static int pf_fm_callback(dev_info_t *dip, ddi_fm_error_t *derr);

/* PCIe Fabric Handle Lookup Support Functions. */
static int pf_hdl_child_lookup(dev_info_t *, ddi_fm_error_t *, uint32_t,
    uint64_t, pcie_req_id_t);
static int pf_hdl_compare(dev_info_t *, ddi_fm_error_t *, uint32_t, uint64_t,
    pcie_req_id_t, ndi_fmc_t *);
static int pf_log_hdl_lookup(dev_info_t *, ddi_fm_error_t *, pf_data_t *,
	boolean_t);

static int pf_handler_enter(dev_info_t *, pf_impl_t *);
static void pf_handler_exit(dev_info_t *);
static void pf_reset_pfd(pf_data_t *);

boolean_t pcie_full_scan = B_FALSE;	/* Force to always do a full scan */
int pcie_disable_scan = 0;		/* Disable fabric scan */

/* Inform interested parties that error handling is about to begin. */
/* ARGSUSED */
void
pf_eh_enter(pcie_bus_t *bus_p) {
}

/* Inform interested parties that error handling has ended. */
void
pf_eh_exit(pcie_bus_t *bus_p)
{
	pcie_bus_t *rbus_p = PCIE_DIP2BUS(bus_p->bus_rp_dip);
	pf_data_t *root_pfd_p = PCIE_BUS2PFD(rbus_p);
	pf_data_t *pfd_p;
	uint_t intr_type = PCIE_ROOT_EH_SRC(root_pfd_p)->intr_type;

	pciev_eh_exit(root_pfd_p, intr_type);

	/* Clear affected device info and INTR SRC */
	for (pfd_p = root_pfd_p; pfd_p; pfd_p = pfd_p->pe_next) {
		PFD_AFFECTED_DEV(pfd_p)->pe_affected_flags = 0;
		PFD_AFFECTED_DEV(pfd_p)->pe_affected_bdf = PCIE_INVALID_BDF;
		if (PCIE_IS_ROOT(PCIE_PFD2BUS(pfd_p))) {
			PCIE_ROOT_EH_SRC(pfd_p)->intr_type = PF_INTR_TYPE_NONE;
			PCIE_ROOT_EH_SRC(pfd_p)->intr_data = NULL;
		}
	}
}

/*
 * Scan Fabric is the entry point for PCI/PCIe IO fabric errors.  The
 * caller may create a local pf_data_t with the "root fault"
 * information populated to either do a precise or full scan.  More
 * than one pf_data_t maybe linked together if there are multiple
 * errors.  Only a PCIe compliant Root Port device may pass in NULL
 * for the root_pfd_p.
 *
 * "Root Complexes" such as NPE and PX should call scan_fabric using itself as
 * the rdip.  PCIe Root ports should call pf_scan_fabric using it's parent as
 * the rdip.
 *
 * Scan fabric initiated from RCs are likely due to a fabric message, traps or
 * any RC detected errors that propagated to/from the fabric.
 *
 * This code assumes that by the time pf_scan_fabric is
 * called, pf_handler_enter has NOT been called on the rdip.
 */
int
pf_scan_fabric(dev_info_t *rdip, ddi_fm_error_t *derr, pf_data_t *root_pfd_p)
{
	pf_impl_t	impl;
	pf_data_t	*pfd_p, *pfd_head_p, *pfd_tail_p;
	int		scan_flag = PF_SCAN_SUCCESS;
	int		analyse_flag = PF_ERR_NO_ERROR;
	boolean_t	full_scan = pcie_full_scan;

	if (pcie_disable_scan)
		return (analyse_flag);

	/* Find the head and tail of this link list */
	pfd_head_p = root_pfd_p;
	for (pfd_tail_p = root_pfd_p; pfd_tail_p && pfd_tail_p->pe_next;
	    pfd_tail_p = pfd_tail_p->pe_next)
		;

	/* Save head/tail */
	impl.pf_total = 0;
	impl.pf_derr = derr;
	impl.pf_dq_head_p = pfd_head_p;
	impl.pf_dq_tail_p = pfd_tail_p;

	/* If scan is initiated from RP then RP itself must be scanned. */
	if (PCIE_IS_RP(PCIE_DIP2BUS(rdip)) && pf_is_ready(rdip) &&
	    !root_pfd_p) {
		scan_flag = pf_handler_enter(rdip, &impl);
		if (scan_flag & PF_SCAN_DEADLOCK)
			goto done;

		scan_flag = pf_default_hdl(rdip, &impl);
		if (scan_flag & PF_SCAN_NO_ERR_IN_CHILD)
			goto done;
	}

	/*
	 * Scan the fabric using the scan_bdf and scan_addr in error q.
	 * scan_bdf will be valid in the following cases:
	 *	- Fabric message
	 *	- Poisoned TLP
	 *	- Signaled UR/CA
	 *	- Received UR/CA
	 *	- PIO load failures
	 */
	for (pfd_p = impl.pf_dq_head_p; pfd_p && PFD_IS_ROOT(pfd_p);
	    pfd_p = pfd_p->pe_next) {
		impl.pf_fault = PCIE_ROOT_FAULT(pfd_p);

		if (PFD_IS_RC(pfd_p))
			impl.pf_total++;

		if (impl.pf_fault->full_scan)
			full_scan = B_TRUE;

		if (full_scan ||
		    PCIE_CHECK_VALID_BDF(impl.pf_fault->scan_bdf) ||
		    impl.pf_fault->scan_addr)
			scan_flag |= pf_dispatch(rdip, &impl, full_scan);

		if (full_scan)
			break;
	}

done:
	/*
	 * If this is due to safe access, don't analyze the errors and return
	 * success regardless of how scan fabric went.
	 */
	if (derr->fme_flag != DDI_FM_ERR_UNEXPECTED) {
		analyse_flag = PF_ERR_NO_PANIC;
	} else {
		analyse_flag = pf_analyse_error(derr, &impl);
	}

	pf_send_ereport(derr, &impl);

	/*
	 * Check if any hardened driver's callback reported a panic.
	 * If so panic.
	 */
	if (scan_flag & PF_SCAN_CB_FAILURE)
		analyse_flag |= PF_ERR_PANIC;

	/*
	 * If a deadlock was detected, panic the system as error analysis has
	 * been compromised.
	 */
	if (scan_flag & PF_SCAN_DEADLOCK)
		analyse_flag |= PF_ERR_PANIC_DEADLOCK;

	derr->fme_status = PF_ERR2DDIFM_ERR(scan_flag);

	return (analyse_flag);
}

void
pcie_force_fullscan() {
	pcie_full_scan = B_TRUE;
}

/*
 * pf_dispatch walks the device tree and calls the pf_default_hdl if the device
 * falls in the error path.
 *
 * Returns PF_SCAN_* flags
 */
static int
pf_dispatch(dev_info_t *pdip, pf_impl_t *impl, boolean_t full_scan)
{
	dev_info_t	*dip;
	pcie_req_id_t	rid = impl->pf_fault->scan_bdf;
	pcie_bus_t	*bus_p;
	int		scan_flag = PF_SCAN_SUCCESS;

	for (dip = ddi_get_child(pdip); dip; dip = ddi_get_next_sibling(dip)) {
		/* Make sure dip is attached and ready */
		if (!(bus_p = pf_is_ready(dip)))
			continue;

		scan_flag |= pf_handler_enter(dip, impl);
		if (scan_flag & PF_SCAN_DEADLOCK)
			break;

		/*
		 * Handle this device if it is a:
		 * o Full Scan
		 * o PCI/PCI-X Device
		 * o Fault BDF = Device BDF
		 * o BDF/ADDR is in range of the Bridge/Switch
		 */
		if (full_scan ||
		    (bus_p->bus_bdf == rid) ||
		    pf_in_bus_range(bus_p, rid) ||
		    pf_in_addr_range(bus_p, impl->pf_fault->scan_addr)) {
			int hdl_flag = pf_default_hdl(dip, impl);
			scan_flag |= hdl_flag;

			/*
			 * A bridge may have detected no errors in which case
			 * there is no need to scan further down.
			 */
			if (hdl_flag & PF_SCAN_NO_ERR_IN_CHILD)
				continue;
		} else {
			pf_handler_exit(dip);
			continue;
		}

		/* match or in bridge bus-range */
		switch (bus_p->bus_dev_type) {
		case PCIE_PCIECAP_DEV_TYPE_PCIE2PCI:
		case PCIE_PCIECAP_DEV_TYPE_PCI2PCIE:
			scan_flag |= pf_dispatch(dip, impl, B_TRUE);
			break;
		case PCIE_PCIECAP_DEV_TYPE_UP:
		case PCIE_PCIECAP_DEV_TYPE_DOWN:
		case PCIE_PCIECAP_DEV_TYPE_ROOT:
		{
			pf_data_t *pfd_p = PCIE_BUS2PFD(bus_p);
			pf_pci_err_regs_t *err_p = PCI_ERR_REG(pfd_p);
			pf_pci_bdg_err_regs_t *serr_p = PCI_BDG_ERR_REG(pfd_p);
			/*
			 * Continue if the fault BDF != the switch or there is a
			 * parity error
			 */
			if ((bus_p->bus_bdf != rid) ||
			    (err_p->pci_err_status & PF_PCI_PARITY_ERR) ||
			    (serr_p->pci_bdg_sec_stat & PF_PCI_PARITY_ERR))
				scan_flag |= pf_dispatch(dip, impl, full_scan);
			break;
		}
		case PCIE_PCIECAP_DEV_TYPE_PCIE_DEV:
		case PCIE_PCIECAP_DEV_TYPE_PCI_DEV:
			/*
			 * Reached a PCIe end point so stop. Note dev_type
			 * PCI_DEV is just a PCIe device that requires IO Space
			 */
			break;
		case PCIE_PCIECAP_DEV_TYPE_PCI_PSEUDO:
			if (PCIE_IS_BDG(bus_p))
				scan_flag |= pf_dispatch(dip, impl, B_TRUE);
			break;
		default:
			ASSERT(B_FALSE);
		}
	}
	return (scan_flag);
}

/* Returns whether the "bdf" is in the bus range of a switch/bridge */
boolean_t
pf_in_bus_range(pcie_bus_t *bus_p, pcie_req_id_t bdf)
{
	pci_bus_range_t *br_p = &bus_p->bus_bus_range;
	uint8_t		bus_no = (bdf & PCIE_REQ_ID_BUS_MASK) >>
	    PCIE_REQ_ID_BUS_SHIFT;

	/* check if given bdf falls within bridge's bus range */
	if (PCIE_IS_BDG(bus_p) &&
	    ((bus_no >= br_p->lo) && (bus_no <= br_p->hi)))
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * Return whether the "addr" is in the assigned addr of a device.
 */
boolean_t
pf_in_assigned_addr(pcie_bus_t *bus_p, uint64_t addr)
{
	uint_t		i;
	uint64_t	low, hi;
	pci_regspec_t	*assign_p = bus_p->bus_assigned_addr;

	for (i = 0; i < bus_p->bus_assigned_entries; i++, assign_p++) {
		low = assign_p->pci_phys_low;
		hi = low + assign_p->pci_size_low;
		if ((addr < hi) && (addr >= low))
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Returns whether the "addr" is in the addr range of a switch/bridge, or if the
 * "addr" is in the assigned addr of a device.
 */
static boolean_t
pf_in_addr_range(pcie_bus_t *bus_p, uint64_t addr)
{
	uint_t		i;
	uint64_t	low, hi;
	ppb_ranges_t	*ranges_p = bus_p->bus_addr_ranges;

	if (!addr)
		return (B_FALSE);

	/* check if given address belongs to this device */
	if (pf_in_assigned_addr(bus_p, addr))
		return (B_TRUE);

	/* check if given address belongs to a child below this device */
	if (!PCIE_IS_BDG(bus_p))
		return (B_FALSE);

	for (i = 0; i < bus_p->bus_addr_entries; i++, ranges_p++) {
		switch (ranges_p->child_high & PCI_ADDR_MASK) {
		case PCI_ADDR_IO:
		case PCI_ADDR_MEM32:
			low = ranges_p->child_low;
			hi = ranges_p->size_low + low;
			if ((addr < hi) && (addr >= low))
				return (B_TRUE);
			break;
		case PCI_ADDR_MEM64:
			low = ((uint64_t)ranges_p->child_mid << 32) |
			    (uint64_t)ranges_p->child_low;
			hi = (((uint64_t)ranges_p->size_high << 32) |
			    (uint64_t)ranges_p->size_low) + low;
			if ((addr < hi) && (addr >= low))
				return (B_TRUE);
			break;
		}
	}
	return (B_FALSE);
}

static pcie_bus_t *
pf_is_ready(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	if (!bus_p)
		return (NULL);

	if (!(bus_p->bus_fm_flags & PF_FM_READY))
		return (NULL);
	return (bus_p);
}

static void
pf_pcix_ecc_regs_gather(pf_pcix_ecc_regs_t *pcix_ecc_regs,
    pcie_bus_t *bus_p, boolean_t bdg)
{
	if (bdg) {
		pcix_ecc_regs->pcix_ecc_ctlstat = PCIX_CAP_GET(32, bus_p,
		    PCI_PCIX_BDG_ECC_STATUS);
		pcix_ecc_regs->pcix_ecc_fstaddr = PCIX_CAP_GET(32, bus_p,
		    PCI_PCIX_BDG_ECC_FST_AD);
		pcix_ecc_regs->pcix_ecc_secaddr = PCIX_CAP_GET(32, bus_p,
		    PCI_PCIX_BDG_ECC_SEC_AD);
		pcix_ecc_regs->pcix_ecc_attr = PCIX_CAP_GET(32, bus_p,
		    PCI_PCIX_BDG_ECC_ATTR);
	} else {
		pcix_ecc_regs->pcix_ecc_ctlstat = PCIX_CAP_GET(32, bus_p,
		    PCI_PCIX_ECC_STATUS);
		pcix_ecc_regs->pcix_ecc_fstaddr = PCIX_CAP_GET(32, bus_p,
		    PCI_PCIX_ECC_FST_AD);
		pcix_ecc_regs->pcix_ecc_secaddr = PCIX_CAP_GET(32, bus_p,
		    PCI_PCIX_ECC_SEC_AD);
		pcix_ecc_regs->pcix_ecc_attr = PCIX_CAP_GET(32, bus_p,
		    PCI_PCIX_ECC_ATTR);
	}
}


static void
pf_pcix_regs_gather(pf_data_t *pfd_p, pcie_bus_t *bus_p)
{
	/*
	 * For PCI-X device PCI-X Capability only exists for Type 0 Headers.
	 * PCI-X Bridge Capability only exists for Type 1 Headers.
	 * Both capabilities do not exist at the same time.
	 */
	if (PCIE_IS_BDG(bus_p)) {
		pf_pcix_bdg_err_regs_t *pcix_bdg_regs;

		pcix_bdg_regs = PCIX_BDG_ERR_REG(pfd_p);

		pcix_bdg_regs->pcix_bdg_sec_stat = PCIX_CAP_GET(16, bus_p,
		    PCI_PCIX_SEC_STATUS);
		pcix_bdg_regs->pcix_bdg_stat = PCIX_CAP_GET(32, bus_p,
		    PCI_PCIX_BDG_STATUS);

		if (PCIX_ECC_VERSION_CHECK(bus_p)) {
			/*
			 * PCI Express to PCI-X bridges only implement the
			 * secondary side of the PCI-X ECC registers, bit one is
			 * read-only so we make sure we do not write to it.
			 */
			if (!PCIE_IS_PCIE_BDG(bus_p)) {
				PCIX_CAP_PUT(32, bus_p, PCI_PCIX_BDG_ECC_STATUS,
				    0);
				pf_pcix_ecc_regs_gather(
				    PCIX_BDG_ECC_REG(pfd_p, 0), bus_p, B_TRUE);
				PCIX_CAP_PUT(32, bus_p, PCI_PCIX_BDG_ECC_STATUS,
				    1);
			}
			pf_pcix_ecc_regs_gather(PCIX_BDG_ECC_REG(pfd_p, 0),
			    bus_p, B_TRUE);
		}
	} else {
		pf_pcix_err_regs_t *pcix_regs = PCIX_ERR_REG(pfd_p);

		pcix_regs->pcix_command = PCIX_CAP_GET(16, bus_p,
		    PCI_PCIX_COMMAND);
		pcix_regs->pcix_status = PCIX_CAP_GET(32, bus_p,
		    PCI_PCIX_STATUS);
		if (PCIX_ECC_VERSION_CHECK(bus_p))
			pf_pcix_ecc_regs_gather(PCIX_ECC_REG(pfd_p), bus_p,
			    B_TRUE);
	}
}

static void
pf_pcie_regs_gather(pf_data_t *pfd_p, pcie_bus_t *bus_p)
{
	pf_pcie_err_regs_t *pcie_regs = PCIE_ERR_REG(pfd_p);
	pf_pcie_adv_err_regs_t *pcie_adv_regs = PCIE_ADV_REG(pfd_p);

	pcie_regs->pcie_err_status = PCIE_CAP_GET(16, bus_p, PCIE_DEVSTS);
	pcie_regs->pcie_err_ctl = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL);
	pcie_regs->pcie_dev_cap = PCIE_CAP_GET(32, bus_p, PCIE_DEVCAP);

	if (PCIE_IS_BDG(bus_p) && PCIE_IS_PCIX(bus_p))
		pf_pcix_regs_gather(pfd_p, bus_p);

	if (PCIE_IS_ROOT(bus_p)) {
		pf_pcie_rp_err_regs_t *pcie_rp_regs = PCIE_RP_REG(pfd_p);

		pcie_rp_regs->pcie_rp_status = PCIE_CAP_GET(32, bus_p,
		    PCIE_ROOTSTS);
		pcie_rp_regs->pcie_rp_ctl = PCIE_CAP_GET(16, bus_p,
		    PCIE_ROOTCTL);
	}

	if (!PCIE_HAS_AER(bus_p))
		return;

	/* Gather UE AERs */
	pcie_adv_regs->pcie_adv_ctl = PCIE_AER_GET(32, bus_p,
	    PCIE_AER_CTL);
	pcie_adv_regs->pcie_ue_status = PCIE_AER_GET(32, bus_p,
	    PCIE_AER_UCE_STS);
	pcie_adv_regs->pcie_ue_mask = PCIE_AER_GET(32, bus_p,
	    PCIE_AER_UCE_MASK);
	pcie_adv_regs->pcie_ue_sev = PCIE_AER_GET(32, bus_p,
	    PCIE_AER_UCE_SERV);
	PCIE_ADV_HDR(pfd_p, 0) = PCIE_AER_GET(32, bus_p,
	    PCIE_AER_HDR_LOG);
	PCIE_ADV_HDR(pfd_p, 1) = PCIE_AER_GET(32, bus_p,
	    PCIE_AER_HDR_LOG + 0x4);
	PCIE_ADV_HDR(pfd_p, 2) = PCIE_AER_GET(32, bus_p,
	    PCIE_AER_HDR_LOG + 0x8);
	PCIE_ADV_HDR(pfd_p, 3) = PCIE_AER_GET(32, bus_p,
	    PCIE_AER_HDR_LOG + 0xc);

	/* Gather CE AERs */
	pcie_adv_regs->pcie_ce_status = PCIE_AER_GET(32, bus_p,
	    PCIE_AER_CE_STS);
	pcie_adv_regs->pcie_ce_mask = PCIE_AER_GET(32, bus_p,
	    PCIE_AER_CE_MASK);

	/*
	 * If pci express to pci bridge then grab the bridge
	 * error registers.
	 */
	if (PCIE_IS_PCIE_BDG(bus_p)) {
		pf_pcie_adv_bdg_err_regs_t *pcie_bdg_regs =
		    PCIE_ADV_BDG_REG(pfd_p);

		pcie_bdg_regs->pcie_sue_ctl = PCIE_AER_GET(32, bus_p,
		    PCIE_AER_SCTL);
		pcie_bdg_regs->pcie_sue_status = PCIE_AER_GET(32, bus_p,
		    PCIE_AER_SUCE_STS);
		pcie_bdg_regs->pcie_sue_mask = PCIE_AER_GET(32, bus_p,
		    PCIE_AER_SUCE_MASK);
		pcie_bdg_regs->pcie_sue_sev = PCIE_AER_GET(32, bus_p,
		    PCIE_AER_SUCE_SERV);
		PCIE_ADV_BDG_HDR(pfd_p, 0) = PCIE_AER_GET(32, bus_p,
		    PCIE_AER_SHDR_LOG);
		PCIE_ADV_BDG_HDR(pfd_p, 1) = PCIE_AER_GET(32, bus_p,
		    PCIE_AER_SHDR_LOG + 0x4);
		PCIE_ADV_BDG_HDR(pfd_p, 2) = PCIE_AER_GET(32, bus_p,
		    PCIE_AER_SHDR_LOG + 0x8);
		PCIE_ADV_BDG_HDR(pfd_p, 3) = PCIE_AER_GET(32, bus_p,
		    PCIE_AER_SHDR_LOG + 0xc);
	}

	/*
	 * If PCI Express root port then grab the root port
	 * error registers.
	 */
	if (PCIE_IS_ROOT(bus_p)) {
		pf_pcie_adv_rp_err_regs_t *pcie_rp_regs =
		    PCIE_ADV_RP_REG(pfd_p);

		pcie_rp_regs->pcie_rp_err_cmd = PCIE_AER_GET(32, bus_p,
		    PCIE_AER_RE_CMD);
		pcie_rp_regs->pcie_rp_err_status = PCIE_AER_GET(32, bus_p,
		    PCIE_AER_RE_STS);
		pcie_rp_regs->pcie_rp_ce_src_id = PCIE_AER_GET(16, bus_p,
		    PCIE_AER_CE_SRC_ID);
		pcie_rp_regs->pcie_rp_ue_src_id = PCIE_AER_GET(16, bus_p,
		    PCIE_AER_ERR_SRC_ID);
	}
}

static void
pf_pci_regs_gather(pf_data_t *pfd_p, pcie_bus_t *bus_p)
{
	pf_pci_err_regs_t *pci_regs = PCI_ERR_REG(pfd_p);

	/*
	 * Start by reading all the error registers that are available for
	 * pci and pci express and for leaf devices and bridges/switches
	 */
	pci_regs->pci_err_status = PCIE_GET(16, bus_p, PCI_CONF_STAT);
	pci_regs->pci_cfg_comm = PCIE_GET(16, bus_p, PCI_CONF_COMM);

	/*
	 * If pci-pci bridge grab PCI bridge specific error registers.
	 */
	if (PCIE_IS_BDG(bus_p)) {
		pf_pci_bdg_err_regs_t *pci_bdg_regs = PCI_BDG_ERR_REG(pfd_p);
		pci_bdg_regs->pci_bdg_sec_stat =
		    PCIE_GET(16, bus_p, PCI_BCNF_SEC_STATUS);
		pci_bdg_regs->pci_bdg_ctrl =
		    PCIE_GET(16, bus_p, PCI_BCNF_BCNTRL);
	}

	/*
	 * If pci express device grab pci express error registers and
	 * check for advanced error reporting features and grab them if
	 * available.
	 */
	if (PCIE_IS_PCIE(bus_p))
		pf_pcie_regs_gather(pfd_p, bus_p);
	else if (PCIE_IS_PCIX(bus_p))
		pf_pcix_regs_gather(pfd_p, bus_p);

}

static void
pf_pcix_regs_clear(pf_data_t *pfd_p, pcie_bus_t *bus_p)
{
	if (PCIE_IS_BDG(bus_p)) {
		pf_pcix_bdg_err_regs_t *pcix_bdg_regs;

		pcix_bdg_regs = PCIX_BDG_ERR_REG(pfd_p);

		PCIX_CAP_PUT(16, bus_p, PCI_PCIX_SEC_STATUS,
		    pcix_bdg_regs->pcix_bdg_sec_stat);

		PCIX_CAP_PUT(32, bus_p, PCI_PCIX_BDG_STATUS,
		    pcix_bdg_regs->pcix_bdg_stat);

		if (PCIX_ECC_VERSION_CHECK(bus_p)) {
			pf_pcix_ecc_regs_t *pcix_bdg_ecc_regs;
			/*
			 * PCI Express to PCI-X bridges only implement the
			 * secondary side of the PCI-X ECC registers.  For
			 * clearing, there is no need to "select" the ECC
			 * register, just write what was originally read.
			 */
			if (!PCIE_IS_PCIE_BDG(bus_p)) {
				pcix_bdg_ecc_regs = PCIX_BDG_ECC_REG(pfd_p, 0);
				PCIX_CAP_PUT(32, bus_p, PCI_PCIX_BDG_ECC_STATUS,
				    pcix_bdg_ecc_regs->pcix_ecc_ctlstat);

			}
			pcix_bdg_ecc_regs = PCIX_BDG_ECC_REG(pfd_p, 1);
			PCIX_CAP_PUT(32, bus_p, PCI_PCIX_BDG_ECC_STATUS,
			    pcix_bdg_ecc_regs->pcix_ecc_ctlstat);
		}
	} else {
		pf_pcix_err_regs_t *pcix_regs = PCIX_ERR_REG(pfd_p);

		PCIX_CAP_PUT(32, bus_p, PCI_PCIX_STATUS,
		    pcix_regs->pcix_status);

		if (PCIX_ECC_VERSION_CHECK(bus_p)) {
			pf_pcix_ecc_regs_t *pcix_ecc_regs = PCIX_ECC_REG(pfd_p);

			PCIX_CAP_PUT(32, bus_p, PCI_PCIX_ECC_STATUS,
			    pcix_ecc_regs->pcix_ecc_ctlstat);
		}
	}
}

static void
pf_pcie_regs_clear(pf_data_t *pfd_p, pcie_bus_t *bus_p)
{
	pf_pcie_err_regs_t *pcie_regs = PCIE_ERR_REG(pfd_p);
	pf_pcie_adv_err_regs_t *pcie_adv_regs = PCIE_ADV_REG(pfd_p);

	PCIE_CAP_PUT(16, bus_p, PCIE_DEVSTS, pcie_regs->pcie_err_status);

	if (PCIE_IS_BDG(bus_p) && PCIE_IS_PCIX(bus_p))
		pf_pcix_regs_clear(pfd_p, bus_p);

	if (!PCIE_HAS_AER(bus_p))
		return;

	PCIE_AER_PUT(32, bus_p, PCIE_AER_UCE_STS,
	    pcie_adv_regs->pcie_ue_status);

	PCIE_AER_PUT(32, bus_p, PCIE_AER_CE_STS,
	    pcie_adv_regs->pcie_ce_status);

	if (PCIE_IS_PCIE_BDG(bus_p)) {
		pf_pcie_adv_bdg_err_regs_t *pcie_bdg_regs =
		    PCIE_ADV_BDG_REG(pfd_p);

		PCIE_AER_PUT(32, bus_p, PCIE_AER_SUCE_STS,
		    pcie_bdg_regs->pcie_sue_status);
	}

	/*
	 * If PCI Express root complex then clear the root complex
	 * error registers.
	 */
	if (PCIE_IS_ROOT(bus_p)) {
		pf_pcie_adv_rp_err_regs_t *pcie_rp_regs;

		pcie_rp_regs = PCIE_ADV_RP_REG(pfd_p);

		PCIE_AER_PUT(32, bus_p, PCIE_AER_RE_STS,
		    pcie_rp_regs->pcie_rp_err_status);
	}
}

static void
pf_pci_regs_clear(pf_data_t *pfd_p, pcie_bus_t *bus_p)
{
	if (PCIE_IS_PCIE(bus_p))
		pf_pcie_regs_clear(pfd_p, bus_p);
	else if (PCIE_IS_PCIX(bus_p))
		pf_pcix_regs_clear(pfd_p, bus_p);

	PCIE_PUT(16, bus_p, PCI_CONF_STAT, pfd_p->pe_pci_regs->pci_err_status);

	if (PCIE_IS_BDG(bus_p)) {
		pf_pci_bdg_err_regs_t *pci_bdg_regs = PCI_BDG_ERR_REG(pfd_p);
		PCIE_PUT(16, bus_p, PCI_BCNF_SEC_STATUS,
		    pci_bdg_regs->pci_bdg_sec_stat);
	}
}

/* ARGSUSED */
void
pcie_clear_errors(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);
	pf_data_t *pfd_p = PCIE_DIP2PFD(dip);

	ASSERT(bus_p);

	pf_pci_regs_gather(pfd_p, bus_p);
	pf_pci_regs_clear(pfd_p, bus_p);
}

/* Find the fault BDF, fault Addr or full scan on a PCIe Root Port. */
static void
pf_pci_find_rp_fault(pf_data_t *pfd_p, pcie_bus_t *bus_p)
{
	pf_root_fault_t *root_fault = PCIE_ROOT_FAULT(pfd_p);
	pf_pcie_adv_rp_err_regs_t *rp_regs = PCIE_ADV_RP_REG(pfd_p);
	uint32_t root_err = rp_regs->pcie_rp_err_status;
	uint32_t ue_err = PCIE_ADV_REG(pfd_p)->pcie_ue_status;
	int num_faults = 0;

	/* Since this data structure is reused, make sure to reset it */
	root_fault->full_scan = B_FALSE;
	root_fault->scan_bdf = PCIE_INVALID_BDF;
	root_fault->scan_addr = 0;

	if (!PCIE_HAS_AER(bus_p) &&
	    (PCI_BDG_ERR_REG(pfd_p)->pci_bdg_sec_stat & PF_PCI_BDG_ERR)) {
		PCIE_ROOT_FAULT(pfd_p)->full_scan = B_TRUE;
		return;
	}

	/*
	 * Check to see if an error has been received that
	 * requires a scan of the fabric.  Count the number of
	 * faults seen.  If MUL CE/FE_NFE that counts for
	 * atleast 2 faults, so just return with full_scan.
	 */
	if ((root_err & PCIE_AER_RE_STS_MUL_CE_RCVD) ||
	    (root_err & PCIE_AER_RE_STS_MUL_FE_NFE_RCVD)) {
		PCIE_ROOT_FAULT(pfd_p)->full_scan = B_TRUE;
		return;
	}

	if (root_err & PCIE_AER_RE_STS_CE_RCVD)
		num_faults++;

	if (root_err & PCIE_AER_RE_STS_FE_NFE_RCVD)
		num_faults++;

	if (ue_err & PCIE_AER_UCE_CA)
		num_faults++;

	if (ue_err & PCIE_AER_UCE_UR)
		num_faults++;

	/* If no faults just return */
	if (num_faults == 0)
		return;

	/* If faults > 1 do full scan */
	if (num_faults > 1) {
		PCIE_ROOT_FAULT(pfd_p)->full_scan = B_TRUE;
		return;
	}

	/* By this point, there is only 1 fault detected */
	if (root_err & PCIE_AER_RE_STS_CE_RCVD) {
		PCIE_ROOT_FAULT(pfd_p)->scan_bdf = rp_regs->pcie_rp_ce_src_id;
		num_faults--;
	} else if (root_err & PCIE_AER_RE_STS_FE_NFE_RCVD) {
		PCIE_ROOT_FAULT(pfd_p)->scan_bdf = rp_regs->pcie_rp_ue_src_id;
		num_faults--;
	} else if ((HAS_AER_LOGS(pfd_p, PCIE_AER_UCE_CA) ||
	    HAS_AER_LOGS(pfd_p, PCIE_AER_UCE_UR)) &&
	    (pf_tlp_decode(PCIE_PFD2BUS(pfd_p), PCIE_ADV_REG(pfd_p)) ==
	    DDI_SUCCESS)) {
		PCIE_ROOT_FAULT(pfd_p)->scan_addr =
		    PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_addr;
		num_faults--;
	}

	/*
	 * This means an error did occur, but we couldn't extract the fault BDF
	 */
	if (num_faults > 0)
		PCIE_ROOT_FAULT(pfd_p)->full_scan = B_TRUE;

}


/*
 * Load PCIe Fault Data for PCI/PCIe devices into PCIe Fault Data Queue
 *
 * Returns a scan flag.
 * o PF_SCAN_SUCCESS - Error gathered and cleared sucessfuly, data added to
 *   Fault Q
 * o PF_SCAN_BAD_RESPONSE - Unable to talk to device, item added to fault Q
 * o PF_SCAN_CB_FAILURE - A hardened device deemed that the error was fatal.
 * o PF_SCAN_NO_ERR_IN_CHILD - Only applies to bridge to prevent further
 *   unnecessary scanning
 * o PF_SCAN_IN_DQ - This device has already been scanned; it was skipped this
 *   time.
 */
static int
pf_default_hdl(dev_info_t *dip, pf_impl_t *impl)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);
	pf_data_t *pfd_p = PCIE_DIP2PFD(dip);
	int cb_sts, scan_flag = PF_SCAN_SUCCESS;

	/* Make sure this device hasn't already been snapshotted and cleared */
	if (pfd_p->pe_valid == B_TRUE) {
		scan_flag |= PF_SCAN_IN_DQ;
		goto done;
	}

	/*
	 * Read vendor/device ID and check with cached data, if it doesn't match
	 * could very well be a device that isn't responding anymore.  Just
	 * stop.  Save the basic info in the error q for post mortem debugging
	 * purposes.
	 */
	if (PCIE_GET(32, bus_p, PCI_CONF_VENID) != bus_p->bus_dev_ven_id) {
		char buf[FM_MAX_CLASS];

		(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
		    PCI_ERROR_SUBCLASS, PCI_NR);
		ddi_fm_ereport_post(dip, buf, fm_ena_generate(0, FM_ENA_FMT1),
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0, NULL);

		/*
		 * For IOV/Hotplug purposes skip gathering info fo this device,
		 * but populate affected info and severity.  Clear out any data
		 * that maybe been saved in the last fabric scan.
		 */
		pf_reset_pfd(pfd_p);
		pfd_p->pe_severity_flags = PF_ERR_PANIC_BAD_RESPONSE;
		PFD_AFFECTED_DEV(pfd_p)->pe_affected_flags = PF_AFFECTED_SELF;

		/* Add the snapshot to the error q */
		pf_en_dq(pfd_p, impl);
		pfd_p->pe_valid = B_TRUE;

		return (PF_SCAN_BAD_RESPONSE);
	}

	pf_pci_regs_gather(pfd_p, bus_p);
	pf_pci_regs_clear(pfd_p, bus_p);
	if (PCIE_IS_RP(bus_p))
		pf_pci_find_rp_fault(pfd_p, bus_p);

	cb_sts = pf_fm_callback(dip, impl->pf_derr);

	if (cb_sts == DDI_FM_FATAL || cb_sts == DDI_FM_UNKNOWN)
		scan_flag |= PF_SCAN_CB_FAILURE;

	/* Add the snapshot to the error q */
	pf_en_dq(pfd_p, impl);

done:
	/*
	 * If a bridge does not have any error no need to scan any further down.
	 * For PCIe devices, check the PCIe device status and PCI secondary
	 * status.
	 * - Some non-compliant PCIe devices do not utilize PCIe
	 *   error registers.  If so rely on legacy PCI error registers.
	 * For PCI devices, check the PCI secondary status.
	 */
	if (PCIE_IS_PCIE_BDG(bus_p) &&
	    !(PCIE_ERR_REG(pfd_p)->pcie_err_status & PF_PCIE_BDG_ERR) &&
	    !(PCI_BDG_ERR_REG(pfd_p)->pci_bdg_sec_stat & PF_PCI_BDG_ERR))
		scan_flag |= PF_SCAN_NO_ERR_IN_CHILD;

	if (PCIE_IS_PCI_BDG(bus_p) &&
	    !(PCI_BDG_ERR_REG(pfd_p)->pci_bdg_sec_stat & PF_PCI_BDG_ERR))
		scan_flag |= PF_SCAN_NO_ERR_IN_CHILD;

	pfd_p->pe_valid = B_TRUE;
	return (scan_flag);
}

/*
 * Called during postattach to initialize a device's error handling
 * capabilities.  If the devices has already been hardened, then there isn't
 * much needed.  Otherwise initialize the device's default FMA capabilities.
 *
 * In a future project where PCIe support is removed from pcifm, several
 * "properties" that are setup in ddi_fm_init and pci_ereport_setup need to be
 * created here so that the PCI/PCIe eversholt rules will work properly.
 */
void
pf_init(dev_info_t *dip, ddi_iblock_cookie_t ibc, ddi_attach_cmd_t cmd)
{
	pcie_bus_t		*bus_p = PCIE_DIP2BUS(dip);
	struct i_ddi_fmhdl	*fmhdl = DEVI(dip)->devi_fmhdl;
	boolean_t		need_cb_register = B_FALSE;

	if (!bus_p) {
		cmn_err(CE_WARN, "devi_bus information is not set for %s%d.\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return;
	}

	if (fmhdl) {
		/*
		 * If device is only ereport capable and not callback capable
		 * make it callback capable. The only downside is that the
		 * "fm-errcb-capable" property is not created for this device
		 * which should be ok since it's not used anywhere.
		 */
		if (!(fmhdl->fh_cap & DDI_FM_ERRCB_CAPABLE))
			need_cb_register = B_TRUE;
	} else {
		int cap;
		/*
		 * fm-capable in driver.conf can be used to set fm_capabilities.
		 * If fm-capable is not defined, set the default
		 * DDI_FM_EREPORT_CAPABLE and DDI_FM_ERRCB_CAPABLE.
		 */
		cap = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "fm-capable",
		    DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE);
		cap &= (DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE);

		bus_p->bus_fm_flags |= PF_FM_IS_NH;

		if (cmd == DDI_ATTACH) {
			ddi_fm_init(dip, &cap, &ibc);
			pci_ereport_setup(dip);
		}

		if (cap & DDI_FM_ERRCB_CAPABLE)
			need_cb_register = B_TRUE;

		fmhdl = DEVI(dip)->devi_fmhdl;
	}

	/* If ddi_fm_init fails for any reason RETURN */
	if (!fmhdl) {
		bus_p->bus_fm_flags = 0;
		return;
	}

	fmhdl->fh_cap |=  DDI_FM_ERRCB_CAPABLE;
	if (cmd == DDI_ATTACH) {
		if (need_cb_register)
			ddi_fm_handler_register(dip, pf_dummy_cb, NULL);
	}

	bus_p->bus_fm_flags |= PF_FM_READY;
}

/* undo FMA lock, called at predetach */
void
pf_fini(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	if (!bus_p)
		return;

	/* Don't fini anything if device isn't FM Ready */
	if (!(bus_p->bus_fm_flags & PF_FM_READY))
		return;

	/* no other code should set the flag to false */
	bus_p->bus_fm_flags &= ~PF_FM_READY;

	/*
	 * Grab the mutex to make sure device isn't in the middle of
	 * error handling.  Setting the bus_fm_flag to ~PF_FM_READY
	 * should prevent this device from being error handled after
	 * the mutex has been released.
	 */
	(void) pf_handler_enter(dip, NULL);
	pf_handler_exit(dip);

	/* undo non-hardened drivers */
	if (bus_p->bus_fm_flags & PF_FM_IS_NH) {
		if (cmd == DDI_DETACH) {
			bus_p->bus_fm_flags &= ~PF_FM_IS_NH;
			pci_ereport_teardown(dip);
			/*
			 * ddi_fini itself calls ddi_handler_unregister,
			 * so no need to explicitly call unregister.
			 */
			ddi_fm_fini(dip);
		}
	}
}

/*ARGSUSED*/
static int
pf_dummy_cb(dev_info_t *dip, ddi_fm_error_t *derr, const void *not_used)
{
	return (DDI_FM_OK);
}

/*
 * Add PFD to queue.  If it is an RC add it to the beginning,
 * otherwise add it to the end.
 */
static void
pf_en_dq(pf_data_t *pfd_p, pf_impl_t *impl)
{
	pf_data_t *head_p = impl->pf_dq_head_p;
	pf_data_t *tail_p = impl->pf_dq_tail_p;

	impl->pf_total++;

	if (!head_p) {
		ASSERT(PFD_IS_ROOT(pfd_p));
		impl->pf_dq_head_p = pfd_p;
		impl->pf_dq_tail_p = pfd_p;
		pfd_p->pe_prev = NULL;
		pfd_p->pe_next = NULL;
		return;
	}

	/* Check if this is a Root Port eprt */
	if (PFD_IS_ROOT(pfd_p)) {
		pf_data_t *root_p, *last_p = NULL;

		/* The first item must be a RP */
		root_p = head_p;
		for (last_p = head_p; last_p && PFD_IS_ROOT(last_p);
		    last_p = last_p->pe_next)
			root_p = last_p;

		/* root_p is the last RP pfd. last_p is the first non-RP pfd. */
		root_p->pe_next = pfd_p;
		pfd_p->pe_prev = root_p;
		pfd_p->pe_next = last_p;

		if (last_p)
			last_p->pe_prev = pfd_p;
		else
			tail_p = pfd_p;
	} else {
		tail_p->pe_next = pfd_p;
		pfd_p->pe_prev = tail_p;
		pfd_p->pe_next = NULL;
		tail_p = pfd_p;
	}

	impl->pf_dq_head_p = head_p;
	impl->pf_dq_tail_p = tail_p;
}

/*
 * Ignore:
 * - TRAINING: as leaves do not have children
 * - SD: as leaves do not have children
 */
const pf_fab_err_tbl_t pcie_pcie_tbl[] = {
	{PCIE_AER_UCE_DLP,	pf_panic,
	    PF_AFFECTED_PARENT, 0},

	{PCIE_AER_UCE_PTLP,	pf_analyse_ptlp,
	    PF_AFFECTED_SELF, 0},

	{PCIE_AER_UCE_FCP,	pf_panic,
	    PF_AFFECTED_PARENT, 0},

	{PCIE_AER_UCE_TO,	pf_analyse_to,
	    PF_AFFECTED_SELF, 0},

	{PCIE_AER_UCE_CA,	pf_analyse_ca_ur,
	    PF_AFFECTED_SELF, 0},

	{PCIE_AER_UCE_UC,	pf_analyse_uc,
	    0, 0},

	{PCIE_AER_UCE_RO,	pf_panic,
	    PF_AFFECTED_PARENT, 0},

	{PCIE_AER_UCE_MTLP,	pf_panic,
	    PF_AFFECTED_PARENT, 0},

	{PCIE_AER_UCE_ECRC,	pf_panic,
	    PF_AFFECTED_SELF, 0},

	{PCIE_AER_UCE_UR,	pf_analyse_ca_ur,
	    PF_AFFECTED_SELF, 0},

	{NULL, NULL, NULL, NULL}
};

const pf_fab_err_tbl_t pcie_rp_tbl[] = {
	{PCIE_AER_UCE_TRAINING,	pf_no_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_UCE_DLP,	pf_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_UCE_SD,	pf_no_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_UCE_PTLP,	pf_analyse_ptlp,
	    PF_AFFECTED_AER, PF_AFFECTED_CHILDREN},

	{PCIE_AER_UCE_FCP,	pf_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_UCE_TO,	pf_panic,
	    PF_AFFECTED_ADDR, PF_AFFECTED_CHILDREN},

	{PCIE_AER_UCE_CA,	pf_no_panic,
	    PF_AFFECTED_AER, PF_AFFECTED_CHILDREN},

	{PCIE_AER_UCE_UC,	pf_analyse_uc,
	    0, 0},

	{PCIE_AER_UCE_RO,	pf_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_UCE_MTLP,	pf_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_AER,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN},

	{PCIE_AER_UCE_ECRC,	pf_panic,
	    PF_AFFECTED_AER, PF_AFFECTED_CHILDREN},

	{PCIE_AER_UCE_UR,	pf_no_panic,
	    PF_AFFECTED_AER, PF_AFFECTED_CHILDREN},

	{NULL, NULL, NULL, NULL}
};

const pf_fab_err_tbl_t pcie_sw_tbl[] = {
	{PCIE_AER_UCE_TRAINING,	pf_no_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_UCE_DLP,	pf_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_UCE_SD,	pf_no_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_UCE_PTLP,	pf_analyse_ptlp,
	    PF_AFFECTED_AER, PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN},

	{PCIE_AER_UCE_FCP,	pf_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_UCE_TO,	pf_analyse_to,
	    PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_UCE_CA,	pf_analyse_ca_ur,
	    PF_AFFECTED_AER, PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN},

	{PCIE_AER_UCE_UC,	pf_analyse_uc,
	    0, 0},

	{PCIE_AER_UCE_RO,	pf_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_UCE_MTLP,	pf_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_AER,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN},

	{PCIE_AER_UCE_ECRC,	pf_panic,
	    PF_AFFECTED_AER, PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN},

	{PCIE_AER_UCE_UR,	pf_analyse_ca_ur,
	    PF_AFFECTED_AER, PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN},

	{NULL, NULL, NULL, NULL}
};

const pf_fab_err_tbl_t pcie_pcie_bdg_tbl[] = {
	{PCIE_AER_SUCE_TA_ON_SC,	pf_analyse_sc,
	    0, 0},

	{PCIE_AER_SUCE_MA_ON_SC,	pf_analyse_sc,
	    0, 0},

	{PCIE_AER_SUCE_RCVD_TA,		pf_analyse_ma_ta,
	    0, 0},

	{PCIE_AER_SUCE_RCVD_MA,		pf_analyse_ma_ta,
	    0, 0},

	{PCIE_AER_SUCE_USC_ERR,		pf_panic,
	    PF_AFFECTED_SAER, PF_AFFECTED_CHILDREN},

	{PCIE_AER_SUCE_USC_MSG_DATA_ERR, pf_analyse_ma_ta,
	    PF_AFFECTED_SAER, PF_AFFECTED_CHILDREN},

	{PCIE_AER_SUCE_UC_DATA_ERR,	pf_analyse_uc_data,
	    PF_AFFECTED_SAER, PF_AFFECTED_CHILDREN},

	{PCIE_AER_SUCE_UC_ATTR_ERR,	pf_panic,
	    PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_SUCE_UC_ADDR_ERR,	pf_panic,
	    PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_SUCE_TIMER_EXPIRED,	pf_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{PCIE_AER_SUCE_PERR_ASSERT,	pf_analyse_perr_assert,
	    0, 0},

	{PCIE_AER_SUCE_SERR_ASSERT,	pf_no_panic,
	    0, 0},

	{PCIE_AER_SUCE_INTERNAL_ERR,	pf_panic,
	    PF_AFFECTED_SELF | PF_AFFECTED_CHILDREN, 0},

	{NULL, NULL, NULL, NULL}
};

const pf_fab_err_tbl_t pcie_pci_bdg_tbl[] = {
	{PCI_STAT_PERROR,	pf_analyse_pci,
	    PF_AFFECTED_SELF, 0},

	{PCI_STAT_S_PERROR,	pf_analyse_pci,
	    PF_AFFECTED_SELF, 0},

	{PCI_STAT_S_SYSERR,	pf_panic,
	    PF_AFFECTED_SELF, 0},

	{PCI_STAT_R_MAST_AB,	pf_analyse_pci,
	    PF_AFFECTED_SELF, 0},

	{PCI_STAT_R_TARG_AB,	pf_analyse_pci,
	    PF_AFFECTED_SELF, 0},

	{PCI_STAT_S_TARG_AB,	pf_analyse_pci,
	    PF_AFFECTED_SELF, 0},

	{NULL, NULL, NULL, NULL}
};

const pf_fab_err_tbl_t pcie_pci_tbl[] = {
	{PCI_STAT_PERROR,	pf_analyse_pci,
	    PF_AFFECTED_SELF, 0},

	{PCI_STAT_S_PERROR,	pf_analyse_pci,
	    PF_AFFECTED_SELF, 0},

	{PCI_STAT_S_SYSERR,	pf_panic,
	    PF_AFFECTED_SELF, 0},

	{PCI_STAT_R_MAST_AB,	pf_analyse_pci,
	    PF_AFFECTED_SELF, 0},

	{PCI_STAT_R_TARG_AB,	pf_analyse_pci,
	    PF_AFFECTED_SELF, 0},

	{PCI_STAT_S_TARG_AB,	pf_analyse_pci,
	    PF_AFFECTED_SELF, 0},

	{NULL, NULL, NULL, NULL}
};

#define	PF_MASKED_AER_ERR(pfd_p) \
	(PCIE_ADV_REG(pfd_p)->pcie_ue_status & \
	    ((PCIE_ADV_REG(pfd_p)->pcie_ue_mask) ^ 0xFFFFFFFF))
#define	PF_MASKED_SAER_ERR(pfd_p) \
	(PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_status & \
	    ((PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_mask) ^ 0xFFFFFFFF))
/*
 * Analyse all the PCIe Fault Data (erpt) gathered during dispatch in the erpt
 * Queue.
 */
static int
pf_analyse_error(ddi_fm_error_t *derr, pf_impl_t *impl)
{
	int		sts_flags, error_flags = 0;
	pf_data_t	*pfd_p;

	for (pfd_p = impl->pf_dq_head_p; pfd_p; pfd_p = pfd_p->pe_next) {
		sts_flags = 0;

		/* skip analysing error when no error info is gathered */
		if (pfd_p->pe_severity_flags == PF_ERR_PANIC_BAD_RESPONSE)
			goto done;

		switch (PCIE_PFD2BUS(pfd_p)->bus_dev_type) {
		case PCIE_PCIECAP_DEV_TYPE_PCIE_DEV:
		case PCIE_PCIECAP_DEV_TYPE_PCI_DEV:
			if (PCIE_DEVSTS_CE_DETECTED &
			    PCIE_ERR_REG(pfd_p)->pcie_err_status)
				sts_flags |= PF_ERR_CE;

			pf_adjust_for_no_aer(pfd_p);
			sts_flags |= pf_analyse_error_tbl(derr, impl,
			    pfd_p, pcie_pcie_tbl, PF_MASKED_AER_ERR(pfd_p));
			break;
		case PCIE_PCIECAP_DEV_TYPE_ROOT:
			pf_adjust_for_no_aer(pfd_p);
			sts_flags |= pf_analyse_error_tbl(derr, impl,
			    pfd_p, pcie_rp_tbl, PF_MASKED_AER_ERR(pfd_p));
			break;
		case PCIE_PCIECAP_DEV_TYPE_RC_PSEUDO:
			/* no adjust_for_aer for pseudo RC */
			/* keep the severity passed on from RC if any */
			sts_flags |= pfd_p->pe_severity_flags;
			sts_flags |= pf_analyse_error_tbl(derr, impl, pfd_p,
			    pcie_rp_tbl, PF_MASKED_AER_ERR(pfd_p));
			break;
		case PCIE_PCIECAP_DEV_TYPE_UP:
		case PCIE_PCIECAP_DEV_TYPE_DOWN:
			if (PCIE_DEVSTS_CE_DETECTED &
			    PCIE_ERR_REG(pfd_p)->pcie_err_status)
				sts_flags |= PF_ERR_CE;

			pf_adjust_for_no_aer(pfd_p);
			sts_flags |= pf_analyse_error_tbl(derr, impl,
			    pfd_p, pcie_sw_tbl, PF_MASKED_AER_ERR(pfd_p));
			break;
		case PCIE_PCIECAP_DEV_TYPE_PCIE2PCI:
			if (PCIE_DEVSTS_CE_DETECTED &
			    PCIE_ERR_REG(pfd_p)->pcie_err_status)
				sts_flags |= PF_ERR_CE;

			pf_adjust_for_no_aer(pfd_p);
			pf_adjust_for_no_saer(pfd_p);
			sts_flags |= pf_analyse_error_tbl(derr,
			    impl, pfd_p, pcie_pcie_tbl,
			    PF_MASKED_AER_ERR(pfd_p));
			sts_flags |= pf_analyse_error_tbl(derr,
			    impl, pfd_p, pcie_pcie_bdg_tbl,
			    PF_MASKED_SAER_ERR(pfd_p));
			/*
			 * Some non-compliant PCIe devices do not utilize PCIe
			 * error registers.  So fallthrough and rely on legacy
			 * PCI error registers.
			 */
			if ((PCIE_DEVSTS_NFE_DETECTED | PCIE_DEVSTS_FE_DETECTED)
			    & PCIE_ERR_REG(pfd_p)->pcie_err_status)
				break;
			/* FALLTHROUGH */
		case PCIE_PCIECAP_DEV_TYPE_PCI_PSEUDO:
			sts_flags |= pf_analyse_error_tbl(derr, impl,
			    pfd_p, pcie_pci_tbl,
			    PCI_ERR_REG(pfd_p)->pci_err_status);

			if (!PCIE_IS_BDG(PCIE_PFD2BUS(pfd_p)))
				break;

			sts_flags |= pf_analyse_error_tbl(derr,
			    impl, pfd_p, pcie_pci_bdg_tbl,
			    PCI_BDG_ERR_REG(pfd_p)->pci_bdg_sec_stat);
		}

		pfd_p->pe_severity_flags = sts_flags;

done:
		pfd_p->pe_orig_severity_flags = pfd_p->pe_severity_flags;
		/* Have pciev_eh adjust the severity */
		pfd_p->pe_severity_flags = pciev_eh(pfd_p, impl);

		error_flags |= pfd_p->pe_severity_flags;
	}

	return (error_flags);
}

static int
pf_analyse_error_tbl(ddi_fm_error_t *derr, pf_impl_t *impl,
    pf_data_t *pfd_p, const pf_fab_err_tbl_t *tbl, uint32_t err_reg)
{
	const pf_fab_err_tbl_t *row;
	int err = 0;
	uint16_t flags;
	uint32_t bit;

	for (row = tbl; err_reg && (row->bit != NULL); row++) {
		bit = row->bit;
		if (!(err_reg & bit))
			continue;
		err |= row->handler(derr, bit, impl->pf_dq_head_p, pfd_p);

		flags = row->affected_flags;
		/*
		 * check if the primary flag is valid;
		 * if not, use the secondary flag
		 */
		if (flags & PF_AFFECTED_AER) {
			if (!HAS_AER_LOGS(pfd_p, bit)) {
				flags = row->sec_affected_flags;
			}
		} else if (flags & PF_AFFECTED_SAER) {
			if (!HAS_SAER_LOGS(pfd_p, bit)) {
				flags = row->sec_affected_flags;
			}
		} else if (flags & PF_AFFECTED_ADDR) {
			/* only Root has this flag */
			if (PCIE_ROOT_FAULT(pfd_p)->scan_addr == 0) {
				flags = row->sec_affected_flags;
			}
		}

		PFD_AFFECTED_DEV(pfd_p)->pe_affected_flags |= flags;
	}

	if (!err)
		err = PF_ERR_NO_ERROR;

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
pf_analyse_ca_ur(ddi_fm_error_t *derr, uint32_t bit, pf_data_t *dq_head_p,
    pf_data_t *pfd_p)
{
	uint32_t	abort_type;
	dev_info_t	*rpdip = PCIE_PFD2BUS(pfd_p)->bus_rp_dip;

	/* If UR's are masked forgive this error */
	if ((pcie_get_aer_uce_mask() & PCIE_AER_UCE_UR) &&
	    (bit == PCIE_AER_UCE_UR))
		return (PF_ERR_NO_PANIC);

	/*
	 * If a RP has an CA/UR it means a leaf sent a bad request to the RP
	 * such as a config read or a bad DMA address.
	 */
	if (PCIE_IS_RP(PCIE_PFD2BUS(pfd_p)))
		goto handle_lookup;

	if (bit == PCIE_AER_UCE_UR)
		abort_type = PCI_STAT_R_MAST_AB;
	else
		abort_type = PCI_STAT_R_TARG_AB;

	if (pf_matched_in_rc(dq_head_p, pfd_p, abort_type))
		return (PF_ERR_MATCHED_RC);

handle_lookup:
	if (HAS_AER_LOGS(pfd_p, bit) &&
	    pf_log_hdl_lookup(rpdip, derr, pfd_p, B_TRUE) == PF_HDL_FOUND)
			return (PF_ERR_MATCHED_DEVICE);

	return (PF_ERR_PANIC);
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
pf_analyse_ma_ta(ddi_fm_error_t *derr, uint32_t bit, pf_data_t *dq_head_p,
    pf_data_t *pfd_p)
{
	dev_info_t	*rpdip = PCIE_PFD2BUS(pfd_p)->bus_rp_dip;
	uint32_t	abort_type;

	/* If UR's are masked forgive this error */
	if ((pcie_get_aer_uce_mask() & PCIE_AER_UCE_UR) &&
	    (bit == PCIE_AER_SUCE_RCVD_MA))
		return (PF_ERR_NO_PANIC);

	if (bit == PCIE_AER_SUCE_RCVD_MA)
		abort_type = PCI_STAT_R_MAST_AB;
	else
		abort_type = PCI_STAT_R_TARG_AB;

	if (pf_matched_in_rc(dq_head_p, pfd_p, abort_type))
		return (PF_ERR_MATCHED_RC);

	if (!HAS_SAER_LOGS(pfd_p, bit))
		return (PF_ERR_PANIC);

	if (pf_log_hdl_lookup(rpdip, derr, pfd_p, B_FALSE) == PF_HDL_FOUND)
		return (PF_ERR_MATCHED_DEVICE);

	return (PF_ERR_PANIC);
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
pf_analyse_pci(ddi_fm_error_t *derr, uint32_t bit, pf_data_t *dq_head_p,
    pf_data_t *pfd_p)
{
	pf_data_t	*parent_pfd_p;
	uint16_t	cmd;
	uint32_t	aer_ue_status;
	pcie_bus_t	*bus_p = PCIE_PFD2BUS(pfd_p);
	pf_pcie_adv_bdg_err_regs_t *parent_saer_p;

	if (PCI_ERR_REG(pfd_p)->pci_err_status & PCI_STAT_S_SYSERR)
		return (PF_ERR_PANIC);

	/* If UR's are masked forgive this error */
	if ((pcie_get_aer_uce_mask() & PCIE_AER_UCE_UR) &&
	    (bit == PCI_STAT_R_MAST_AB))
		return (PF_ERR_NO_PANIC);


	if (bit & (PCI_STAT_PERROR | PCI_STAT_S_PERROR)) {
		aer_ue_status = PCIE_AER_SUCE_PERR_ASSERT;
	} else {
		aer_ue_status = (PCIE_AER_SUCE_TA_ON_SC |
		    PCIE_AER_SUCE_MA_ON_SC | PCIE_AER_SUCE_RCVD_TA |
		    PCIE_AER_SUCE_RCVD_MA);
	}

	parent_pfd_p = pf_get_parent_pcie_bridge(pfd_p);
	if (parent_pfd_p == NULL)
		return (PF_ERR_PANIC);

	/* Check if parent bridge has seen this error */
	parent_saer_p = PCIE_ADV_BDG_REG(parent_pfd_p);
	if (!(parent_saer_p->pcie_sue_status & aer_ue_status) ||
	    !HAS_SAER_LOGS(parent_pfd_p, aer_ue_status))
		return (PF_ERR_PANIC);

	/*
	 * If the addr or bdf from the parent PCIe bridge logs belong to this
	 * PCI device, assume the PCIe bridge's error handling has already taken
	 * care of this PCI device's error.
	 */
	if (pf_pci_decode(parent_pfd_p, &cmd) != DDI_SUCCESS)
		return (PF_ERR_PANIC);

	if ((parent_saer_p->pcie_sue_tgt_bdf == bus_p->bus_bdf) ||
	    pf_in_addr_range(bus_p, parent_saer_p->pcie_sue_tgt_addr))
		return (PF_ERR_MATCHED_PARENT);

	/*
	 * If this device is a PCI-PCI bridge, check if the bdf in the parent
	 * PCIe bridge logs is in the range of this PCI-PCI Bridge's bus ranges.
	 * If they are, then assume the PCIe bridge's error handling has already
	 * taken care of this PCI-PCI bridge device's error.
	 */
	if (PCIE_IS_BDG(bus_p) &&
	    pf_in_bus_range(bus_p, parent_saer_p->pcie_sue_tgt_bdf))
		return (PF_ERR_MATCHED_PARENT);

	return (PF_ERR_PANIC);
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
pf_analyse_perr_assert(ddi_fm_error_t *derr, uint32_t bit, pf_data_t *dq_head_p,
    pf_data_t *pfd_p)
{
	dev_info_t	*rpdip = PCIE_PFD2BUS(pfd_p)->bus_rp_dip;
	uint16_t	cmd;
	int		hdl_sts = PF_HDL_NOTFOUND;
	int		err = PF_ERR_NO_ERROR;
	pf_pcie_adv_bdg_err_regs_t *saer_p;


	if (HAS_SAER_LOGS(pfd_p, bit)) {
		saer_p = PCIE_ADV_BDG_REG(pfd_p);
		if (pf_pci_decode(pfd_p, &cmd) != DDI_SUCCESS)
			return (PF_ERR_PANIC);

cmd_switch:
		switch (cmd) {
		case PCI_PCIX_CMD_IOWR:
		case PCI_PCIX_CMD_MEMWR:
		case PCI_PCIX_CMD_MEMWR_BL:
		case PCI_PCIX_CMD_MEMWRBL:
			/* Posted Writes Transactions */
			if (saer_p->pcie_sue_tgt_trans == PF_ADDR_PIO)
				hdl_sts = pf_log_hdl_lookup(rpdip, derr, pfd_p,
				    B_FALSE);
			break;
		case PCI_PCIX_CMD_CFWR:
			/*
			 * Check to see if it is a non-posted write.  If so, a
			 * UR Completion would have been sent.
			 */
			if (pf_matched_in_rc(dq_head_p, pfd_p,
			    PCI_STAT_R_MAST_AB)) {
				hdl_sts = PF_HDL_FOUND;
				err = PF_ERR_MATCHED_RC;
				goto done;
			}
			hdl_sts = pf_log_hdl_lookup(rpdip, derr, pfd_p,
			    B_FALSE);
			break;
		case PCI_PCIX_CMD_SPL:
			hdl_sts = pf_log_hdl_lookup(rpdip, derr, pfd_p,
			    B_FALSE);
			break;
		case PCI_PCIX_CMD_DADR:
			cmd = (PCIE_ADV_BDG_HDR(pfd_p, 1) >>
			    PCIE_AER_SUCE_HDR_CMD_UP_SHIFT) &
			    PCIE_AER_SUCE_HDR_CMD_UP_MASK;
			if (cmd != PCI_PCIX_CMD_DADR)
				goto cmd_switch;
			/* FALLTHROUGH */
		default:
			/* Unexpected situation, panic */
			hdl_sts = PF_HDL_NOTFOUND;
		}

		if (hdl_sts == PF_HDL_FOUND)
			err = PF_ERR_MATCHED_DEVICE;
		else
			err = PF_ERR_PANIC;
	} else {
		/*
		 * Check to see if it is a non-posted write.  If so, a UR
		 * Completion would have been sent.
		 */
		if ((PCIE_ERR_REG(pfd_p)->pcie_err_status &
		    PCIE_DEVSTS_UR_DETECTED) &&
		    pf_matched_in_rc(dq_head_p, pfd_p, PCI_STAT_R_MAST_AB))
			err = PF_ERR_MATCHED_RC;

		/* Check for posted writes.  Transaction is lost. */
		if (PCI_BDG_ERR_REG(pfd_p)->pci_bdg_sec_stat &
		    PCI_STAT_S_PERROR)
			err = PF_ERR_PANIC;

		/*
		 * All other scenarios are due to read completions.  Check for
		 * PERR on the primary side.  If found the primary side error
		 * handling will take care of this error.
		 */
		if (err == PF_ERR_NO_ERROR) {
			if (PCI_ERR_REG(pfd_p)->pci_err_status &
			    PCI_STAT_PERROR)
				err = PF_ERR_MATCHED_PARENT;
			else
				err = PF_ERR_PANIC;
		}
	}

done:
	return (err);
}

/*
 * PCIe Poisoned TLP error analyser.  If a PCIe device receives a Poisoned TLP,
 * check the logs and see if an associated handler for this transaction can be
 * found.
 */
/* ARGSUSED */
static int
pf_analyse_ptlp(ddi_fm_error_t *derr, uint32_t bit, pf_data_t *dq_head_p,
    pf_data_t *pfd_p)
{
	dev_info_t	*rpdip = PCIE_PFD2BUS(pfd_p)->bus_rp_dip;

	/*
	 * If AERs are supported find the logs in this device, otherwise look in
	 * it's parent's logs.
	 */
	if (HAS_AER_LOGS(pfd_p, bit)) {
		pcie_tlp_hdr_t *hdr = (pcie_tlp_hdr_t *)&PCIE_ADV_HDR(pfd_p, 0);

		/*
		 * Double check that the log contains a poisoned TLP.
		 * Some devices like PLX switch do not log poison TLP headers.
		 */
		if (hdr->ep) {
			if (pf_log_hdl_lookup(rpdip, derr, pfd_p, B_TRUE) ==
			    PF_HDL_FOUND)
				return (PF_ERR_MATCHED_DEVICE);
		}

		/*
		 * If an address is found and hdl lookup failed panic.
		 * Otherwise check parents to see if there was enough
		 * information recover.
		 */
		if (PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_addr)
			return (PF_ERR_PANIC);
	}

	/*
	 * Check to see if the rc has already handled this error or a parent has
	 * already handled this error.
	 *
	 * If the error info in the RC wasn't enough to find the fault device,
	 * such as if the faulting device lies behind a PCIe-PCI bridge from a
	 * poisoned completion, check to see if the PCIe-PCI bridge has enough
	 * info to recover.  For completion TLP's, the AER header logs only
	 * contain the faulting BDF in the Root Port.  For PCIe device the fault
	 * BDF is the fault device.  But if the fault device is behind a
	 * PCIe-PCI bridge the fault BDF could turn out just to be a PCIe-PCI
	 * bridge's secondary bus number.
	 */
	if (!PFD_IS_ROOT(pfd_p)) {
		dev_info_t *pdip = ddi_get_parent(PCIE_PFD2DIP(pfd_p));
		pf_data_t *parent_pfd_p;

		if (PCIE_PFD2BUS(pfd_p)->bus_rp_dip == pdip) {
			if (pf_matched_in_rc(dq_head_p, pfd_p, PCI_STAT_PERROR))
				return (PF_ERR_MATCHED_RC);
		}

		parent_pfd_p = PCIE_DIP2PFD(pdip);

		if (HAS_AER_LOGS(parent_pfd_p, bit))
			return (PF_ERR_MATCHED_PARENT);
	} else {
		pf_data_t *bdg_pfd_p;
		pcie_req_id_t secbus;

		/*
		 * Looking for a pcie bridge only makes sense if the BDF
		 * Dev/Func = 0/0
		 */
		if (!PCIE_HAS_AER(PCIE_PFD2BUS(pfd_p)))
			goto done;

		secbus = PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_bdf;

		if (!PCIE_CHECK_VALID_BDF(secbus) || (secbus & 0xFF))
			goto done;

		bdg_pfd_p = pf_get_pcie_bridge(pfd_p, secbus);

		if (bdg_pfd_p && HAS_SAER_LOGS(bdg_pfd_p,
		    PCIE_AER_SUCE_PERR_ASSERT)) {
			return pf_analyse_perr_assert(derr,
			    PCIE_AER_SUCE_PERR_ASSERT, dq_head_p, pfd_p);
		}
	}
done:
	return (PF_ERR_PANIC);
}

/*
 * PCIe-PCI Bridge Received Master and Target abort error analyser on Split
 * Completions.  If a PCIe Bridge receives a MA/TA check logs and see if an
 * associated handler for this transaction can be found.
 */
/* ARGSUSED */
static int
pf_analyse_sc(ddi_fm_error_t *derr, uint32_t bit, pf_data_t *dq_head_p,
    pf_data_t *pfd_p)
{
	dev_info_t	*rpdip = PCIE_PFD2BUS(pfd_p)->bus_rp_dip;
	uint16_t	cmd;
	int		sts = PF_HDL_NOTFOUND;

	if (!HAS_SAER_LOGS(pfd_p, bit))
		return (PF_ERR_PANIC);

	if (pf_pci_decode(pfd_p, &cmd) != DDI_SUCCESS)
		return (PF_ERR_PANIC);

	if (cmd == PCI_PCIX_CMD_SPL)
		sts = pf_log_hdl_lookup(rpdip, derr, pfd_p, B_FALSE);

	if (sts == PF_HDL_FOUND)
		return (PF_ERR_MATCHED_DEVICE);

	return (PF_ERR_PANIC);
}

/*
 * PCIe Timeout error analyser.  This error can be forgiven if it is marked as
 * CE Advisory.  If it is marked as advisory, this means the HW can recover
 * and/or retry the transaction automatically.
 */
/* ARGSUSED */
static int
pf_analyse_to(ddi_fm_error_t *derr, uint32_t bit, pf_data_t *dq_head_p,
    pf_data_t *pfd_p)
{
	if (HAS_AER_LOGS(pfd_p, bit) && CE_ADVISORY(pfd_p))
		return (PF_ERR_NO_PANIC);

	return (PF_ERR_PANIC);
}

/*
 * PCIe Unexpected Completion.  Check to see if this TLP was misrouted by
 * matching the device BDF with the TLP Log.  If misrouting panic, otherwise
 * don't panic.
 */
/* ARGSUSED */
static int
pf_analyse_uc(ddi_fm_error_t *derr, uint32_t bit, pf_data_t *dq_head_p,
    pf_data_t *pfd_p)
{
	if (HAS_AER_LOGS(pfd_p, bit) &&
	    (PCIE_PFD2BUS(pfd_p)->bus_bdf == (PCIE_ADV_HDR(pfd_p, 2) >> 16)))
		return (PF_ERR_NO_PANIC);

	/*
	 * This is a case of mis-routing. Any of the switches above this
	 * device could be at fault.
	 */
	PFD_AFFECTED_DEV(pfd_p)->pe_affected_flags = PF_AFFECTED_ROOT;

	return (PF_ERR_PANIC);
}

/*
 * PCIe-PCI Bridge Uncorrectable Data error analyser.  All Uncorrectable Data
 * errors should have resulted in a PCIe Poisoned TLP to the RC, except for
 * Posted Writes.  Check the logs for Posted Writes and if the RC did not see a
 * Poisoned TLP.
 *
 * Non-Posted Writes will also generate a UR in the completion status, which the
 * RC should also see.
 */
/* ARGSUSED */
static int
pf_analyse_uc_data(ddi_fm_error_t *derr, uint32_t bit, pf_data_t *dq_head_p,
    pf_data_t *pfd_p)
{
	dev_info_t	*rpdip = PCIE_PFD2BUS(pfd_p)->bus_rp_dip;

	if (!HAS_SAER_LOGS(pfd_p, bit))
		return (PF_ERR_PANIC);

	if (pf_matched_in_rc(dq_head_p, pfd_p, PCI_STAT_PERROR))
		return (PF_ERR_MATCHED_RC);

	if (pf_log_hdl_lookup(rpdip, derr, pfd_p, B_FALSE) == PF_HDL_FOUND)
		return (PF_ERR_MATCHED_DEVICE);

	return (PF_ERR_PANIC);
}

/* ARGSUSED */
static int
pf_no_panic(ddi_fm_error_t *derr, uint32_t bit, pf_data_t *dq_head_p,
    pf_data_t *pfd_p)
{
	return (PF_ERR_NO_PANIC);
}

/* ARGSUSED */
static int
pf_panic(ddi_fm_error_t *derr, uint32_t bit, pf_data_t *dq_head_p,
    pf_data_t *pfd_p)
{
	return (PF_ERR_PANIC);
}

/*
 * If a PCIe device does not support AER, assume all AER statuses have been set,
 * unless other registers do not indicate a certain error occuring.
 */
static void
pf_adjust_for_no_aer(pf_data_t *pfd_p)
{
	uint32_t	aer_ue = 0;
	uint16_t	status;

	if (PCIE_HAS_AER(PCIE_PFD2BUS(pfd_p)))
		return;

	if (PCIE_ERR_REG(pfd_p)->pcie_err_status & PCIE_DEVSTS_FE_DETECTED)
		aer_ue = PF_AER_FATAL_ERR;

	if (PCIE_ERR_REG(pfd_p)->pcie_err_status & PCIE_DEVSTS_NFE_DETECTED) {
		aer_ue = PF_AER_NON_FATAL_ERR;
		status = PCI_ERR_REG(pfd_p)->pci_err_status;

		/* Check if the device received a PTLP */
		if (!(status & PCI_STAT_PERROR))
			aer_ue &= ~PCIE_AER_UCE_PTLP;

		/* Check if the device signaled a CA */
		if (!(status & PCI_STAT_S_TARG_AB))
			aer_ue &= ~PCIE_AER_UCE_CA;

		/* Check if the device sent a UR */
		if (!(PCIE_ERR_REG(pfd_p)->pcie_err_status &
		    PCIE_DEVSTS_UR_DETECTED))
			aer_ue &= ~PCIE_AER_UCE_UR;

		/*
		 * Ignore ECRCs as it is optional and will manefest itself as
		 * another error like PTLP and MFP
		 */
		aer_ue &= ~PCIE_AER_UCE_ECRC;

		/*
		 * Generally if NFE is set, SERR should also be set. Exception:
		 * When certain non-fatal errors are masked, and some of them
		 * happened to be the cause of the NFE, SERR will not be set and
		 * they can not be the source of this interrupt.
		 *
		 * On x86, URs are masked (NFE + UR can be set), if any other
		 * non-fatal errors (i.e, PTLP, CTO, CA, UC, ECRC, ACS) did
		 * occur, SERR should be set since they are not masked. So if
		 * SERR is not set, none of them occurred.
		 */
		if (!(status & PCI_STAT_S_SYSERR))
			aer_ue &= ~PCIE_AER_UCE_TO;
	}

	if (!PCIE_IS_BDG(PCIE_PFD2BUS(pfd_p))) {
		aer_ue &= ~PCIE_AER_UCE_TRAINING;
		aer_ue &= ~PCIE_AER_UCE_SD;
	}

	PCIE_ADV_REG(pfd_p)->pcie_ue_status = aer_ue;
}

static void
pf_adjust_for_no_saer(pf_data_t *pfd_p)
{
	uint32_t	s_aer_ue = 0;
	uint16_t	status;

	if (PCIE_HAS_AER(PCIE_PFD2BUS(pfd_p)))
		return;

	if (PCIE_ERR_REG(pfd_p)->pcie_err_status & PCIE_DEVSTS_FE_DETECTED)
		s_aer_ue = PF_SAER_FATAL_ERR;

	if (PCIE_ERR_REG(pfd_p)->pcie_err_status & PCIE_DEVSTS_NFE_DETECTED) {
		s_aer_ue = PF_SAER_NON_FATAL_ERR;
		status = PCI_BDG_ERR_REG(pfd_p)->pci_bdg_sec_stat;

		/* Check if the device received a UC_DATA */
		if (!(status & PCI_STAT_PERROR))
			s_aer_ue &= ~PCIE_AER_SUCE_UC_DATA_ERR;

		/* Check if the device received a RCVD_MA/MA_ON_SC */
		if (!(status & (PCI_STAT_R_MAST_AB))) {
			s_aer_ue &= ~PCIE_AER_SUCE_RCVD_MA;
			s_aer_ue &= ~PCIE_AER_SUCE_MA_ON_SC;
		}

		/* Check if the device received a RCVD_TA/TA_ON_SC */
		if (!(status & (PCI_STAT_R_TARG_AB))) {
			s_aer_ue &= ~PCIE_AER_SUCE_RCVD_TA;
			s_aer_ue &= ~PCIE_AER_SUCE_TA_ON_SC;
		}
	}

	PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_status = s_aer_ue;
}

/* Find the PCIe-PCI bridge based on secondary bus number */
static pf_data_t *
pf_get_pcie_bridge(pf_data_t *pfd_p, pcie_req_id_t secbus)
{
	pf_data_t *bdg_pfd_p;

	/* Search down for the PCIe-PCI device. */
	for (bdg_pfd_p = pfd_p->pe_next; bdg_pfd_p;
	    bdg_pfd_p = bdg_pfd_p->pe_next) {
		if (PCIE_IS_PCIE_BDG(PCIE_PFD2BUS(bdg_pfd_p)) &&
		    PCIE_PFD2BUS(bdg_pfd_p)->bus_bdg_secbus == secbus)
			return (bdg_pfd_p);
	}

	return (NULL);
}

/* Find the PCIe-PCI bridge of a PCI device */
static pf_data_t *
pf_get_parent_pcie_bridge(pf_data_t *pfd_p)
{
	dev_info_t	*dip, *rp_dip = PCIE_PFD2BUS(pfd_p)->bus_rp_dip;

	/* This only makes sense if the device is a PCI device */
	if (!PCIE_IS_PCI(PCIE_PFD2BUS(pfd_p)))
		return (NULL);

	/*
	 * Search up for the PCIe-PCI device.  Watchout for x86 where pci
	 * devices hang directly off of NPE.
	 */
	for (dip = PCIE_PFD2DIP(pfd_p); dip; dip = ddi_get_parent(dip)) {
		if (dip == rp_dip)
			dip = NULL;

		if (PCIE_IS_PCIE_BDG(PCIE_DIP2BUS(dip)))
			return (PCIE_DIP2PFD(dip));
	}

	return (NULL);
}

/*
 * See if a leaf error was bubbled up to the Root Complex (RC) and handled.
 * As of right now only RC's have enough information to have errors found in the
 * fabric to be matched to the RC.  Note that Root Port's (RP) do not carry
 * enough information.  Currently known RC's are SPARC Fire architecture and
 * it's equivalents, and x86's NPE.
 * SPARC Fire architectures have a plethora of error registers, while currently
 * NPE only have the address of a failed load.
 *
 * Check if the RC logged an error with the appropriate status type/abort type.
 * Ex: Parity Error, Received Master/Target Abort
 * Check if either the fault address found in the rc matches the device's
 * assigned address range (PIO's only) or the fault BDF in the rc matches the
 * device's BDF or Secondary Bus/Bus Range.
 */
static boolean_t
pf_matched_in_rc(pf_data_t *dq_head_p, pf_data_t *pfd_p,
    uint32_t abort_type)
{
	pcie_bus_t	*bus_p = PCIE_PFD2BUS(pfd_p);
	pf_data_t	*rc_pfd_p;
	pcie_req_id_t	fault_bdf;

	for (rc_pfd_p = dq_head_p; PFD_IS_ROOT(rc_pfd_p);
	    rc_pfd_p = rc_pfd_p->pe_next) {
		/* Only root complex's have enough information to match */
		if (!PCIE_IS_RC(PCIE_PFD2BUS(rc_pfd_p)))
			continue;

		/* If device and rc abort type does not match continue */
		if (!(PCI_BDG_ERR_REG(rc_pfd_p)->pci_bdg_sec_stat & abort_type))
			continue;

		fault_bdf = PCIE_ROOT_FAULT(rc_pfd_p)->scan_bdf;

		/* The Fault BDF = Device's BDF */
		if (fault_bdf == bus_p->bus_bdf)
			return (B_TRUE);

		/* The Fault Addr is in device's address range */
		if (pf_in_addr_range(bus_p,
		    PCIE_ROOT_FAULT(rc_pfd_p)->scan_addr))
			return (B_TRUE);

		/* The Fault BDF is from PCIe-PCI Bridge's secondary bus */
		if (PCIE_IS_PCIE_BDG(bus_p) &&
		    pf_in_bus_range(bus_p, fault_bdf))
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Check the RP and see if the error is PIO/DMA.  If the RP also has a PERR then
 * it is a DMA, otherwise it's a PIO
 */
static void
pf_pci_find_trans_type(pf_data_t *pfd_p, uint64_t *addr, uint32_t *trans_type,
    pcie_req_id_t *bdf) {
	pf_data_t *rc_pfd_p;

	/* Could be DMA or PIO.  Find out by look at error type. */
	switch (PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_status) {
	case PCIE_AER_SUCE_TA_ON_SC:
	case PCIE_AER_SUCE_MA_ON_SC:
		*trans_type = PF_ADDR_DMA;
		return;
	case PCIE_AER_SUCE_RCVD_TA:
	case PCIE_AER_SUCE_RCVD_MA:
		*bdf = PCIE_INVALID_BDF;
		*trans_type = PF_ADDR_PIO;
		return;
	case PCIE_AER_SUCE_USC_ERR:
	case PCIE_AER_SUCE_UC_DATA_ERR:
	case PCIE_AER_SUCE_PERR_ASSERT:
		break;
	default:
		*addr = 0;
		*bdf = PCIE_INVALID_BDF;
		*trans_type = 0;
		return;
	}

	*bdf = PCIE_INVALID_BDF;
	*trans_type = PF_ADDR_PIO;
	for (rc_pfd_p = pfd_p->pe_prev; rc_pfd_p;
	    rc_pfd_p = rc_pfd_p->pe_prev) {
		if (PFD_IS_ROOT(rc_pfd_p) &&
		    (PCI_BDG_ERR_REG(rc_pfd_p)->pci_bdg_sec_stat &
		    PCI_STAT_PERROR)) {
			*trans_type = PF_ADDR_DMA;
			return;
		}
	}
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
int
pf_pci_decode(pf_data_t *pfd_p, uint16_t *cmd) {
	pcix_attr_t	*attr;
	uint64_t	addr;
	uint32_t	trans_type;
	pcie_req_id_t	bdf = PCIE_INVALID_BDF;

	attr = (pcix_attr_t *)&PCIE_ADV_BDG_HDR(pfd_p, 0);
	*cmd = GET_SAER_CMD(pfd_p);

cmd_switch:
	switch (*cmd) {
	case PCI_PCIX_CMD_IORD:
	case PCI_PCIX_CMD_IOWR:
		/* IO Access should always be down stream */
		addr = PCIE_ADV_BDG_HDR(pfd_p, 2);
		bdf = attr->rid;
		trans_type = PF_ADDR_PIO;
		break;
	case PCI_PCIX_CMD_MEMRD_DW:
	case PCI_PCIX_CMD_MEMRD_BL:
	case PCI_PCIX_CMD_MEMRDBL:
	case PCI_PCIX_CMD_MEMWR:
	case PCI_PCIX_CMD_MEMWR_BL:
	case PCI_PCIX_CMD_MEMWRBL:
		addr = ((uint64_t)PCIE_ADV_BDG_HDR(pfd_p, 3) <<
		    PCIE_AER_SUCE_HDR_ADDR_SHIFT) | PCIE_ADV_BDG_HDR(pfd_p, 2);
		bdf = attr->rid;

		pf_pci_find_trans_type(pfd_p, &addr, &trans_type, &bdf);
		break;
	case PCI_PCIX_CMD_CFRD:
	case PCI_PCIX_CMD_CFWR:
		/*
		 * CFG Access should always be down stream.  Match the BDF in
		 * the address phase.
		 */
		addr = 0;
		bdf = attr->rid;
		trans_type = PF_ADDR_CFG;
		break;
	case PCI_PCIX_CMD_SPL:
		/*
		 * Check for DMA read completions.  The requesting BDF is in the
		 * Address phase.
		 */
		addr = 0;
		bdf = attr->rid;
		trans_type = PF_ADDR_DMA;
		break;
	case PCI_PCIX_CMD_DADR:
		/*
		 * For Dual Address Cycles the transaction command is in the 2nd
		 * address phase.
		 */
		*cmd = (PCIE_ADV_BDG_HDR(pfd_p, 1) >>
		    PCIE_AER_SUCE_HDR_CMD_UP_SHIFT) &
		    PCIE_AER_SUCE_HDR_CMD_UP_MASK;
		if (*cmd != PCI_PCIX_CMD_DADR)
			goto cmd_switch;
		/* FALLTHROUGH */
	default:
		PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_trans = 0;
		PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_bdf = PCIE_INVALID_BDF;
		PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_addr = 0;
		return (DDI_FAILURE);
	}
	PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_trans = trans_type;
	PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_bdf = bdf;
	PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_addr = addr;
	return (DDI_SUCCESS);
}

/*
 * Based on either the BDF/ADDR find and mark the faulting DMA/ACC handler.
 * Returns either PF_HDL_NOTFOUND or PF_HDL_FOUND.
 */
int
pf_hdl_lookup(dev_info_t *dip, uint64_t ena, uint32_t flag, uint64_t addr,
    pcie_req_id_t bdf)
{
	ddi_fm_error_t		derr;

	/* If we don't know the addr or rid just return with NOTFOUND */
	if ((addr == NULL) && !PCIE_CHECK_VALID_BDF(bdf))
		return (PF_HDL_NOTFOUND);

	/*
	 * Disable DMA handle lookup until DMA errors can be handled and
	 * reported synchronously.  When enabled again, check for the
	 * PF_ADDR_DMA flag
	 */
	if (!(flag & (PF_ADDR_PIO | PF_ADDR_CFG))) {
		return (PF_HDL_NOTFOUND);
	}

	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_flag = DDI_FM_ERR_UNEXPECTED;
	derr.fme_ena = ena;

	return (pf_hdl_child_lookup(dip, &derr, flag, addr, bdf));
}

static int
pf_hdl_child_lookup(dev_info_t *dip, ddi_fm_error_t *derr, uint32_t flag,
    uint64_t addr, pcie_req_id_t bdf)
{
	int			status = PF_HDL_NOTFOUND;
	ndi_fmc_t		*fcp = NULL;
	struct i_ddi_fmhdl	*fmhdl = DEVI(dip)->devi_fmhdl;
	pcie_req_id_t		dip_bdf;
	boolean_t		have_lock = B_FALSE;
	pcie_bus_t		*bus_p;
	dev_info_t		*cdip;

	if (!(bus_p = pf_is_ready(dip))) {
		return (status);
	}

	ASSERT(fmhdl);
	if (!i_ddi_fm_handler_owned(dip)) {
		/*
		 * pf_handler_enter always returns SUCCESS if the 'impl' arg is
		 * NULL.
		 */
		(void) pf_handler_enter(dip, NULL);
		have_lock = B_TRUE;
	}

	dip_bdf = PCI_GET_BDF(dip);

	/* Check if dip and BDF match, if not recurse to it's children. */
	if (!PCIE_IS_RC(bus_p) && (!PCIE_CHECK_VALID_BDF(bdf) ||
	    dip_bdf == bdf)) {
		if ((flag & PF_ADDR_DMA) && DDI_FM_DMA_ERR_CAP(fmhdl->fh_cap))
			fcp = fmhdl->fh_dma_cache;
		else
			fcp = NULL;

		if (fcp)
			status = pf_hdl_compare(dip, derr, DMA_HANDLE, addr,
			    bdf, fcp);


		if (((flag & PF_ADDR_PIO) || (flag & PF_ADDR_CFG)) &&
		    DDI_FM_ACC_ERR_CAP(fmhdl->fh_cap))
			fcp = fmhdl->fh_acc_cache;
		else
			fcp = NULL;

		if (fcp)
			status = pf_hdl_compare(dip, derr, ACC_HANDLE, addr,
			    bdf, fcp);
	}

	/* If we found the handler or know it's this device, we're done */
	if (!PCIE_IS_RC(bus_p) && ((dip_bdf == bdf) ||
	    (status == PF_HDL_FOUND)))
		goto done;

	/*
	 * If the current devuce us a PCIe-PCI bridge need to check for special
	 * cases:
	 *
	 * If it is a PIO and we don't have an address or this is a DMA, check
	 * to see if the BDF = secondary bus.  If so stop.  The BDF isn't a real
	 * BDF and the fault device could have come from any device in the PCI
	 * bus.
	 */
	if (PCIE_IS_PCIE_BDG(bus_p) &&
	    ((flag & PF_ADDR_DMA || flag & PF_ADDR_PIO)) &&
	    ((bus_p->bus_bdg_secbus << PCIE_REQ_ID_BUS_SHIFT) == bdf))
		goto done;


	/* If we can't find the handler check it's children */
	for (cdip = ddi_get_child(dip); cdip;
	    cdip = ddi_get_next_sibling(cdip)) {
		if ((bus_p = PCIE_DIP2BUS(cdip)) == NULL)
			continue;

		if (pf_in_bus_range(bus_p, bdf) ||
		    pf_in_addr_range(bus_p, addr))
			status = pf_hdl_child_lookup(cdip, derr, flag, addr,
			    bdf);

		if (status == PF_HDL_FOUND)
			goto done;
	}

done:
	if (have_lock == B_TRUE)
		pf_handler_exit(dip);

	return (status);
}

static int
pf_hdl_compare(dev_info_t *dip, ddi_fm_error_t *derr, uint32_t flag,
    uint64_t addr, pcie_req_id_t bdf, ndi_fmc_t *fcp) {
	ndi_fmcentry_t	*fep;
	int		found = 0;
	int		status;

	mutex_enter(&fcp->fc_lock);
	for (fep = fcp->fc_head; fep != NULL; fep = fep->fce_next) {
		ddi_fmcompare_t compare_func;

		/*
		 * Compare captured error state with handle
		 * resources.  During the comparison and
		 * subsequent error handling, we block
		 * attempts to free the cache entry.
		 */
		compare_func = (flag == ACC_HANDLE) ?
		    i_ddi_fm_acc_err_cf_get((ddi_acc_handle_t)
			fep->fce_resource) :
		    i_ddi_fm_dma_err_cf_get((ddi_dma_handle_t)
			fep->fce_resource);

		if (compare_func == NULL) /* unbound or not FLAGERR */
			continue;

		status = compare_func(dip, fep->fce_resource,
			    (void *)&addr, (void *)&bdf);

		if (status == DDI_FM_NONFATAL) {
			found++;

			/* Set the error for this resource handle */
			if (flag == ACC_HANDLE) {
				ddi_acc_handle_t ap = fep->fce_resource;

				i_ddi_fm_acc_err_set(ap, derr->fme_ena, status,
				    DDI_FM_ERR_UNEXPECTED);
				ddi_fm_acc_err_get(ap, derr, DDI_FME_VERSION);
				derr->fme_acc_handle = ap;
			} else {
				ddi_dma_handle_t dp = fep->fce_resource;

				i_ddi_fm_dma_err_set(dp, derr->fme_ena, status,
				    DDI_FM_ERR_UNEXPECTED);
				ddi_fm_dma_err_get(dp, derr, DDI_FME_VERSION);
				derr->fme_dma_handle = dp;
			}
		}
	}
	mutex_exit(&fcp->fc_lock);

	/*
	 * If a handler isn't found and we know this is the right device mark
	 * them all failed.
	 */
	if ((addr != NULL) && PCIE_CHECK_VALID_BDF(bdf) && (found == 0)) {
		status = pf_hdl_compare(dip, derr, flag, addr, bdf, fcp);
		if (status == PF_HDL_FOUND)
			found++;
	}

	return ((found) ? PF_HDL_FOUND : PF_HDL_NOTFOUND);
}

/*
 * Automatically decode AER header logs and does a handling look up based on the
 * AER header decoding.
 *
 * For this function only the Primary/Secondary AER Header Logs need to be valid
 * in the pfd (PCIe Fault Data) arg.
 *
 * Returns either PF_HDL_NOTFOUND or PF_HDL_FOUND.
 */
/* ARGSUSED */
static int
pf_log_hdl_lookup(dev_info_t *rpdip, ddi_fm_error_t *derr, pf_data_t *pfd_p,
	boolean_t is_primary)
{
	/*
	 * Disabling this function temporarily until errors can be handled
	 * synchronously.
	 *
	 * This function is currently only called during the middle of a fabric
	 * scan.  If the fabric scan is called synchronously with an error seen
	 * in the RP/RC, then the related errors in the fabric will have a
	 * PF_ERR_MATCHED_RC error severity.  pf_log_hdl_lookup code will be by
	 * passed when the severity is PF_ERR_MATCHED_RC.  Handle lookup would
	 * have already happened in RP/RC error handling in a synchronous
	 * manner.  Errors unrelated should panic, because they are being
	 * handled asynchronously.
	 *
	 * If fabric scan is called asynchronously from any RP/RC error, then
	 * DMA/PIO UE errors seen in the fabric should panic.  pf_lop_hdl_lookup
	 * will return PF_HDL_NOTFOUND to ensure that the system panics.
	 */
	return (PF_HDL_NOTFOUND);
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
 * The adv_reg_p must be passed in separately for use with SPARC RPs.  A
 * SPARC RP could have multiple AER header logs which cannot be directly
 * accessed via the bus_p.
 */
int
pf_tlp_decode(pcie_bus_t *bus_p, pf_pcie_adv_err_regs_t *adv_reg_p) {
	pcie_tlp_hdr_t	*tlp_hdr = (pcie_tlp_hdr_t *)adv_reg_p->pcie_ue_hdr;
	pcie_req_id_t	my_bdf, tlp_bdf, flt_bdf = PCIE_INVALID_BDF;
	uint64_t	flt_addr = 0;
	uint32_t	flt_trans_type = 0;

	adv_reg_p->pcie_ue_tgt_addr = 0;
	adv_reg_p->pcie_ue_tgt_bdf = PCIE_INVALID_BDF;
	adv_reg_p->pcie_ue_tgt_trans = 0;

	my_bdf = bus_p->bus_bdf;
	switch (tlp_hdr->type) {
	case PCIE_TLP_TYPE_IO:
	case PCIE_TLP_TYPE_MEM:
	case PCIE_TLP_TYPE_MEMLK:
		/* Grab the 32/64bit fault address */
		if (tlp_hdr->fmt & 0x1) {
			flt_addr = ((uint64_t)adv_reg_p->pcie_ue_hdr[2] << 32);
			flt_addr |= adv_reg_p->pcie_ue_hdr[3];
		} else {
			flt_addr = adv_reg_p->pcie_ue_hdr[2];
		}

		tlp_bdf = (pcie_req_id_t)(adv_reg_p->pcie_ue_hdr[1] >> 16);

		/*
		 * If the req bdf >= this.bdf, then it means the request is this
		 * device or came from a device below it.  Unless this device is
		 * a PCIe root port then it means is a DMA, otherwise PIO.
		 */
		if ((tlp_bdf >= my_bdf) && !PCIE_IS_ROOT(bus_p)) {
			flt_trans_type = PF_ADDR_DMA;
			flt_bdf = tlp_bdf;
		} else if (PCIE_IS_ROOT(bus_p) &&
		    (PF_FIRST_AER_ERR(PCIE_AER_UCE_PTLP, adv_reg_p) ||
			(PF_FIRST_AER_ERR(PCIE_AER_UCE_CA, adv_reg_p)))) {
			flt_trans_type = PF_ADDR_DMA;
			flt_bdf = tlp_bdf;
		} else {
			flt_trans_type = PF_ADDR_PIO;
			flt_bdf = PCIE_INVALID_BDF;
		}
		break;
	case PCIE_TLP_TYPE_CFG0:
	case PCIE_TLP_TYPE_CFG1:
		flt_addr = 0;
		flt_bdf = (pcie_req_id_t)(adv_reg_p->pcie_ue_hdr[2] >> 16);
		flt_trans_type = PF_ADDR_CFG;
		break;
	case PCIE_TLP_TYPE_CPL:
	case PCIE_TLP_TYPE_CPLLK:
	{
		pcie_cpl_t *cpl_tlp = (pcie_cpl_t *)&adv_reg_p->pcie_ue_hdr[1];

		flt_addr = NULL;
		flt_bdf = (cpl_tlp->rid > cpl_tlp->cid) ? cpl_tlp->rid :
		    cpl_tlp->cid;

		/*
		 * If the cpl bdf < this.bdf, then it means the request is this
		 * device or came from a device below it.  Unless this device is
		 * a PCIe root port then it means is a DMA, otherwise PIO.
		 */
		if (cpl_tlp->rid > cpl_tlp->cid) {
			flt_trans_type = PF_ADDR_DMA;
		} else {
			flt_trans_type = PF_ADDR_PIO | PF_ADDR_CFG;
		}
		break;
	}
	default:
		return (DDI_FAILURE);
	}

	adv_reg_p->pcie_ue_tgt_addr = flt_addr;
	adv_reg_p->pcie_ue_tgt_bdf = flt_bdf;
	adv_reg_p->pcie_ue_tgt_trans = flt_trans_type;

	return (DDI_SUCCESS);
}

#define	PCIE_EREPORT	DDI_IO_CLASS "." PCI_ERROR_SUBCLASS "." PCIEX_FABRIC
static int
pf_ereport_setup(dev_info_t *dip, uint64_t ena, nvlist_t **ereport,
    nvlist_t **detector, errorq_elem_t **eqep)
{
	struct i_ddi_fmhdl *fmhdl = DEVI(dip)->devi_fmhdl;
	char device_path[MAXPATHLEN];
	nv_alloc_t *nva;

	*eqep = errorq_reserve(fmhdl->fh_errorq);
	if (*eqep == NULL) {
		atomic_inc_64(&fmhdl->fh_kstat.fek_erpt_dropped.value.ui64);
		return (DDI_FAILURE);
	}

	*ereport = errorq_elem_nvl(fmhdl->fh_errorq, *eqep);
	nva = errorq_elem_nva(fmhdl->fh_errorq, *eqep);

	ASSERT(*ereport);
	ASSERT(nva);

	/*
	 * Use the dev_path/devid for this device instance.
	 */
	*detector = fm_nvlist_create(nva);
	if (dip == ddi_root_node()) {
		device_path[0] = '/';
		device_path[1] = '\0';
	} else {
		(void) ddi_pathname(dip, device_path);
	}

	fm_fmri_dev_set(*detector, FM_DEV_SCHEME_VERSION, NULL,
	    device_path, NULL, NULL);

	if (ena == 0)
		ena = fm_ena_generate(0, FM_ENA_FMT1);

	fm_ereport_set(*ereport, 0, PCIE_EREPORT, ena, *detector, NULL);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static void
pf_ereport_post(dev_info_t *dip, nvlist_t **ereport, nvlist_t **detector,
    errorq_elem_t **eqep)
{
	struct i_ddi_fmhdl *fmhdl = DEVI(dip)->devi_fmhdl;

	errorq_commit(fmhdl->fh_errorq, *eqep, ERRORQ_ASYNC);
}

static void
pf_send_ereport(ddi_fm_error_t *derr, pf_impl_t *impl)
{
	nvlist_t	*ereport;
	nvlist_t	*detector;
	errorq_elem_t	*eqep;
	pcie_bus_t	*bus_p;
	pf_data_t	*pfd_p;
	uint32_t	total = impl->pf_total;

	/*
	 * Ereports need to be sent in a top down fashion. The fabric translator
	 * expects the ereports from the Root first. This is needed to tell if
	 * the system contains a PCIe complaint RC/RP.
	 */
	for (pfd_p = impl->pf_dq_head_p; pfd_p; pfd_p = pfd_p->pe_next) {
		bus_p = PCIE_PFD2BUS(pfd_p);
		pfd_p->pe_valid = B_FALSE;

		if (derr->fme_flag != DDI_FM_ERR_UNEXPECTED ||
		    !DDI_FM_EREPORT_CAP(ddi_fm_capable(PCIE_PFD2DIP(pfd_p))))
			continue;

		if (pf_ereport_setup(PCIE_BUS2DIP(bus_p), derr->fme_ena,
		    &ereport, &detector, &eqep) != DDI_SUCCESS)
			continue;

		if (PFD_IS_RC(pfd_p)) {
			fm_payload_set(ereport,
			    "scan_bdf", DATA_TYPE_UINT16,
			    PCIE_ROOT_FAULT(pfd_p)->scan_bdf,
			    "scan_addr", DATA_TYPE_UINT64,
			    PCIE_ROOT_FAULT(pfd_p)->scan_addr,
			    "intr_src", DATA_TYPE_UINT16,
			    PCIE_ROOT_EH_SRC(pfd_p)->intr_type,
			    NULL);
			goto generic;
		}

		/* Generic PCI device information */
		fm_payload_set(ereport,
		    "bdf", DATA_TYPE_UINT16, bus_p->bus_bdf,
		    "device_id", DATA_TYPE_UINT16,
		    (bus_p->bus_dev_ven_id >> 16),
		    "vendor_id", DATA_TYPE_UINT16,
		    (bus_p->bus_dev_ven_id & 0xFFFF),
		    "rev_id", DATA_TYPE_UINT8, bus_p->bus_rev_id,
		    "dev_type", DATA_TYPE_UINT16, bus_p->bus_dev_type,
		    "pcie_off", DATA_TYPE_UINT16, bus_p->bus_pcie_off,
		    "pcix_off", DATA_TYPE_UINT16, bus_p->bus_pcix_off,
		    "aer_off", DATA_TYPE_UINT16, bus_p->bus_aer_off,
		    "ecc_ver", DATA_TYPE_UINT16, bus_p->bus_ecc_ver,
		    NULL);

		/* PCI registers */
		fm_payload_set(ereport,
		    "pci_status", DATA_TYPE_UINT16,
		    PCI_ERR_REG(pfd_p)->pci_err_status,
		    "pci_command", DATA_TYPE_UINT16,
		    PCI_ERR_REG(pfd_p)->pci_cfg_comm,
		    NULL);

		/* PCI bridge registers */
		if (PCIE_IS_BDG(bus_p)) {
			fm_payload_set(ereport,
			    "pci_bdg_sec_status", DATA_TYPE_UINT16,
			    PCI_BDG_ERR_REG(pfd_p)->pci_bdg_sec_stat,
			    "pci_bdg_ctrl", DATA_TYPE_UINT16,
			    PCI_BDG_ERR_REG(pfd_p)->pci_bdg_ctrl,
			    NULL);
		}

		/* PCIx registers */
		if (PCIE_IS_PCIX(bus_p) && !PCIE_IS_BDG(bus_p)) {
			fm_payload_set(ereport,
			    "pcix_status", DATA_TYPE_UINT32,
			    PCIX_ERR_REG(pfd_p)->pcix_status,
			    "pcix_command", DATA_TYPE_UINT16,
			    PCIX_ERR_REG(pfd_p)->pcix_command,
			    NULL);
		}

		/* PCIx ECC Registers */
		if (PCIX_ECC_VERSION_CHECK(bus_p)) {
			pf_pcix_ecc_regs_t *ecc_bdg_reg;
			pf_pcix_ecc_regs_t *ecc_reg;

			if (PCIE_IS_BDG(bus_p))
				ecc_bdg_reg = PCIX_BDG_ECC_REG(pfd_p, 0);
			ecc_reg = PCIX_ECC_REG(pfd_p);
			fm_payload_set(ereport,
			    "pcix_ecc_control_0", DATA_TYPE_UINT16,
			    PCIE_IS_BDG(bus_p) ?
			    (ecc_bdg_reg->pcix_ecc_ctlstat >> 16) :
			    (ecc_reg->pcix_ecc_ctlstat >> 16),
			    "pcix_ecc_status_0", DATA_TYPE_UINT16,
			    PCIE_IS_BDG(bus_p) ?
			    (ecc_bdg_reg->pcix_ecc_ctlstat & 0xFFFF) :
			    (ecc_reg->pcix_ecc_ctlstat & 0xFFFF),
			    "pcix_ecc_fst_addr_0", DATA_TYPE_UINT32,
			    PCIE_IS_BDG(bus_p) ?
			    ecc_bdg_reg->pcix_ecc_fstaddr :
			    ecc_reg->pcix_ecc_fstaddr,
			    "pcix_ecc_sec_addr_0", DATA_TYPE_UINT32,
			    PCIE_IS_BDG(bus_p) ?
			    ecc_bdg_reg->pcix_ecc_secaddr :
			    ecc_reg->pcix_ecc_secaddr,
			    "pcix_ecc_attr_0", DATA_TYPE_UINT32,
			    PCIE_IS_BDG(bus_p) ?
			    ecc_bdg_reg->pcix_ecc_attr :
			    ecc_reg->pcix_ecc_attr,
			    NULL);
		}

		/* PCIx ECC Bridge Registers */
		if (PCIX_ECC_VERSION_CHECK(bus_p) && PCIE_IS_BDG(bus_p)) {
			pf_pcix_ecc_regs_t *ecc_bdg_reg;

			ecc_bdg_reg = PCIX_BDG_ECC_REG(pfd_p, 1);
			fm_payload_set(ereport,
			    "pcix_ecc_control_1", DATA_TYPE_UINT16,
			    (ecc_bdg_reg->pcix_ecc_ctlstat >> 16),
			    "pcix_ecc_status_1", DATA_TYPE_UINT16,
			    (ecc_bdg_reg->pcix_ecc_ctlstat & 0xFFFF),
			    "pcix_ecc_fst_addr_1", DATA_TYPE_UINT32,
			    ecc_bdg_reg->pcix_ecc_fstaddr,
			    "pcix_ecc_sec_addr_1", DATA_TYPE_UINT32,
			    ecc_bdg_reg->pcix_ecc_secaddr,
			    "pcix_ecc_attr_1", DATA_TYPE_UINT32,
			    ecc_bdg_reg->pcix_ecc_attr,
			    NULL);
		}

		/* PCIx Bridge */
		if (PCIE_IS_PCIX(bus_p) && PCIE_IS_BDG(bus_p)) {
			fm_payload_set(ereport,
			    "pcix_bdg_status", DATA_TYPE_UINT32,
			    PCIX_BDG_ERR_REG(pfd_p)->pcix_bdg_stat,
			    "pcix_bdg_sec_status", DATA_TYPE_UINT16,
			    PCIX_BDG_ERR_REG(pfd_p)->pcix_bdg_sec_stat,
			    NULL);
		}

		/* PCIe registers */
		if (PCIE_IS_PCIE(bus_p)) {
			fm_payload_set(ereport,
			    "pcie_status", DATA_TYPE_UINT16,
			    PCIE_ERR_REG(pfd_p)->pcie_err_status,
			    "pcie_command", DATA_TYPE_UINT16,
			    PCIE_ERR_REG(pfd_p)->pcie_err_ctl,
			    "pcie_dev_cap", DATA_TYPE_UINT32,
			    PCIE_ERR_REG(pfd_p)->pcie_dev_cap,
			    NULL);
		}

		/* PCIe AER registers */
		if (PCIE_HAS_AER(bus_p)) {
			fm_payload_set(ereport,
			    "pcie_adv_ctl", DATA_TYPE_UINT32,
			    PCIE_ADV_REG(pfd_p)->pcie_adv_ctl,
			    "pcie_ue_status", DATA_TYPE_UINT32,
			    PCIE_ADV_REG(pfd_p)->pcie_ue_status,
			    "pcie_ue_mask", DATA_TYPE_UINT32,
			    PCIE_ADV_REG(pfd_p)->pcie_ue_mask,
			    "pcie_ue_sev", DATA_TYPE_UINT32,
			    PCIE_ADV_REG(pfd_p)->pcie_ue_sev,
			    "pcie_ue_hdr0", DATA_TYPE_UINT32,
			    PCIE_ADV_REG(pfd_p)->pcie_ue_hdr[0],
			    "pcie_ue_hdr1", DATA_TYPE_UINT32,
			    PCIE_ADV_REG(pfd_p)->pcie_ue_hdr[1],
			    "pcie_ue_hdr2", DATA_TYPE_UINT32,
			    PCIE_ADV_REG(pfd_p)->pcie_ue_hdr[2],
			    "pcie_ue_hdr3", DATA_TYPE_UINT32,
			    PCIE_ADV_REG(pfd_p)->pcie_ue_hdr[3],
			    "pcie_ce_status", DATA_TYPE_UINT32,
			    PCIE_ADV_REG(pfd_p)->pcie_ce_status,
			    "pcie_ce_mask", DATA_TYPE_UINT32,
			    PCIE_ADV_REG(pfd_p)->pcie_ce_mask,
			    NULL);
		}

		/* PCIe AER decoded header */
		if (HAS_AER_LOGS(pfd_p, PCIE_ADV_REG(pfd_p)->pcie_ue_status)) {
			fm_payload_set(ereport,
			    "pcie_ue_tgt_trans", DATA_TYPE_UINT32,
			    PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_trans,
			    "pcie_ue_tgt_addr", DATA_TYPE_UINT64,
			    PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_addr,
			    "pcie_ue_tgt_bdf", DATA_TYPE_UINT16,
			    PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_bdf,
			    NULL);
			/* Clear these values as they no longer valid */
			PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_trans = 0;
			PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_addr = 0;
			PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_bdf = PCIE_INVALID_BDF;
		}

		/* PCIe BDG AER registers */
		if (PCIE_IS_PCIE_BDG(bus_p) && PCIE_HAS_AER(bus_p)) {
			fm_payload_set(ereport,
			    "pcie_sue_adv_ctl", DATA_TYPE_UINT32,
			    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_ctl,
			    "pcie_sue_status", DATA_TYPE_UINT32,
			    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_status,
			    "pcie_sue_mask", DATA_TYPE_UINT32,
			    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_mask,
			    "pcie_sue_sev", DATA_TYPE_UINT32,
			    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_sev,
			    "pcie_sue_hdr0", DATA_TYPE_UINT32,
			    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_hdr[0],
			    "pcie_sue_hdr1", DATA_TYPE_UINT32,
			    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_hdr[1],
			    "pcie_sue_hdr2", DATA_TYPE_UINT32,
			    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_hdr[2],
			    "pcie_sue_hdr3", DATA_TYPE_UINT32,
			    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_hdr[3],
			    NULL);
		}

		/* PCIe BDG AER decoded header */
		if (PCIE_IS_PCIE_BDG(bus_p) && HAS_SAER_LOGS(pfd_p,
		    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_status)) {
			fm_payload_set(ereport,
			    "pcie_sue_tgt_trans", DATA_TYPE_UINT32,
			    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_trans,
			    "pcie_sue_tgt_addr", DATA_TYPE_UINT64,
			    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_addr,
			    "pcie_sue_tgt_bdf", DATA_TYPE_UINT16,
			    PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_bdf,
			    NULL);
			/* Clear these values as they no longer valid */
			PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_trans = 0;
			PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_addr = 0;
			PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_bdf =
			    PCIE_INVALID_BDF;
		}

		/* PCIe RP registers */
		if (PCIE_IS_RP(bus_p)) {
			fm_payload_set(ereport,
			    "pcie_rp_status", DATA_TYPE_UINT32,
			    PCIE_RP_REG(pfd_p)->pcie_rp_status,
			    "pcie_rp_control", DATA_TYPE_UINT16,
			    PCIE_RP_REG(pfd_p)->pcie_rp_ctl,
			    NULL);
		}

		/* PCIe RP AER registers */
		if (PCIE_IS_RP(bus_p) && PCIE_HAS_AER(bus_p)) {
			fm_payload_set(ereport,
			    "pcie_adv_rp_status", DATA_TYPE_UINT32,
			    PCIE_ADV_RP_REG(pfd_p)->pcie_rp_err_status,
			    "pcie_adv_rp_command", DATA_TYPE_UINT32,
			    PCIE_ADV_RP_REG(pfd_p)->pcie_rp_err_cmd,
			    "pcie_adv_rp_ce_src_id", DATA_TYPE_UINT16,
			    PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ce_src_id,
			    "pcie_adv_rp_ue_src_id", DATA_TYPE_UINT16,
			    PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ue_src_id,
			    NULL);
		}

generic:
		/* IOV related information */
		if (!PCIE_BDG_IS_UNASSIGNED(PCIE_PFD2BUS(impl->pf_dq_head_p))) {
			fm_payload_set(ereport,
			    "pcie_aff_flags", DATA_TYPE_UINT16,
			    PFD_AFFECTED_DEV(pfd_p)->pe_affected_flags,
			    "pcie_aff_bdf", DATA_TYPE_UINT16,
			    PFD_AFFECTED_DEV(pfd_p)->pe_affected_bdf,
			    "orig_sev", DATA_TYPE_UINT32,
			    pfd_p->pe_orig_severity_flags,
			    NULL);
		}

		/* Misc ereport information */
		fm_payload_set(ereport,
		    "remainder", DATA_TYPE_UINT32, --total,
		    "severity", DATA_TYPE_UINT32, pfd_p->pe_severity_flags,
		    NULL);

		pf_ereport_post(PCIE_BUS2DIP(bus_p), &ereport, &detector,
		    &eqep);
	}

	/* Unlock all the devices in the queue */
	for (pfd_p = impl->pf_dq_tail_p; pfd_p; pfd_p = pfd_p->pe_prev) {
		if (pfd_p->pe_lock) {
			pf_handler_exit(PCIE_PFD2DIP(pfd_p));
		}
	}
}

/*
 * pf_handler_enter must be called to serial access to each device's pf_data_t.
 * Once error handling is finished with the device call pf_handler_exit to allow
 * other threads to access it.  The same thread may call pf_handler_enter
 * several times without any consequences.
 *
 * The "impl" variable is passed in during scan fabric to double check that
 * there is not a recursive algorithm and to ensure only one thread is doing a
 * fabric scan at all times.
 *
 * In some cases "impl" is not available, such as "child lookup" being called
 * from outside of scan fabric, just pass in NULL for this variable and this
 * extra check will be skipped.
 */
static int
pf_handler_enter(dev_info_t *dip, pf_impl_t *impl)
{
	pf_data_t *pfd_p = PCIE_DIP2PFD(dip);

	ASSERT(pfd_p);

	/*
	 * Check to see if the lock has already been taken by this
	 * thread.  If so just return and don't take lock again.
	 */
	if (!pfd_p->pe_lock || !impl) {
		i_ddi_fm_handler_enter(dip);
		pfd_p->pe_lock = B_TRUE;
		return (PF_SCAN_SUCCESS);
	}

	/* Check to see that this dip is already in the "impl" error queue */
	for (pfd_p = impl->pf_dq_head_p; pfd_p; pfd_p = pfd_p->pe_next) {
		if (PCIE_PFD2DIP(pfd_p) == dip) {
			return (PF_SCAN_SUCCESS);
		}
	}

	return (PF_SCAN_DEADLOCK);
}

static void
pf_handler_exit(dev_info_t *dip)
{
	pf_data_t *pfd_p = PCIE_DIP2PFD(dip);

	ASSERT(pfd_p);

	ASSERT(pfd_p->pe_lock == B_TRUE);
	i_ddi_fm_handler_exit(dip);
	pfd_p->pe_lock = B_FALSE;
}

/*
 * This function calls the driver's callback function (if it's FMA hardened
 * and callback capable). This function relies on the current thread already
 * owning the driver's fmhdl lock.
 */
static int
pf_fm_callback(dev_info_t *dip, ddi_fm_error_t *derr)
{
	int cb_sts = DDI_FM_OK;

	if (DDI_FM_ERRCB_CAP(ddi_fm_capable(dip))) {
		dev_info_t *pdip = ddi_get_parent(dip);
		struct i_ddi_fmhdl *hdl = DEVI(pdip)->devi_fmhdl;
		struct i_ddi_fmtgt *tgt = hdl->fh_tgts;
		struct i_ddi_errhdl *errhdl;
		while (tgt != NULL) {
			if (dip == tgt->ft_dip) {
				errhdl = tgt->ft_errhdl;
				cb_sts = errhdl->eh_func(dip, derr,
				    errhdl->eh_impl);
				break;
			}
			tgt = tgt->ft_next;
		}
	}
	return (cb_sts);
}

static void
pf_reset_pfd(pf_data_t *pfd_p)
{
	pcie_bus_t	*bus_p = PCIE_PFD2BUS(pfd_p);

	pfd_p->pe_severity_flags = 0;
	pfd_p->pe_orig_severity_flags = 0;
	/* pe_lock and pe_valid were reset in pf_send_ereport */

	PFD_AFFECTED_DEV(pfd_p)->pe_affected_flags = 0;
	PFD_AFFECTED_DEV(pfd_p)->pe_affected_bdf = PCIE_INVALID_BDF;

	if (PCIE_IS_ROOT(bus_p)) {
		PCIE_ROOT_FAULT(pfd_p)->scan_bdf = PCIE_INVALID_BDF;
		PCIE_ROOT_FAULT(pfd_p)->scan_addr = 0;
		PCIE_ROOT_FAULT(pfd_p)->full_scan = B_FALSE;
		PCIE_ROOT_EH_SRC(pfd_p)->intr_type = PF_INTR_TYPE_NONE;
		PCIE_ROOT_EH_SRC(pfd_p)->intr_data = NULL;
	}

	if (PCIE_IS_BDG(bus_p)) {
		bzero(PCI_BDG_ERR_REG(pfd_p), sizeof (pf_pci_bdg_err_regs_t));
	}

	PCI_ERR_REG(pfd_p)->pci_err_status = 0;
	PCI_ERR_REG(pfd_p)->pci_cfg_comm = 0;

	if (PCIE_IS_PCIE(bus_p)) {
		if (PCIE_IS_ROOT(bus_p)) {
			bzero(PCIE_RP_REG(pfd_p),
			    sizeof (pf_pcie_rp_err_regs_t));
			bzero(PCIE_ADV_RP_REG(pfd_p),
			    sizeof (pf_pcie_adv_rp_err_regs_t));
			PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ce_src_id =
			    PCIE_INVALID_BDF;
			PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ue_src_id =
			    PCIE_INVALID_BDF;
		} else if (PCIE_IS_PCIE_BDG(bus_p)) {
			bzero(PCIE_ADV_BDG_REG(pfd_p),
			    sizeof (pf_pcie_adv_bdg_err_regs_t));
			PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_bdf =
			    PCIE_INVALID_BDF;
		}

		if (PCIE_IS_PCIE_BDG(bus_p) && PCIE_IS_PCIX(bus_p)) {
			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				bzero(PCIX_BDG_ECC_REG(pfd_p, 0),
				    sizeof (pf_pcix_ecc_regs_t));
				bzero(PCIX_BDG_ECC_REG(pfd_p, 1),
				    sizeof (pf_pcix_ecc_regs_t));
			}
			PCIX_BDG_ERR_REG(pfd_p)->pcix_bdg_sec_stat = 0;
			PCIX_BDG_ERR_REG(pfd_p)->pcix_bdg_stat = 0;
		}

		PCIE_ADV_REG(pfd_p)->pcie_adv_ctl = 0;
		PCIE_ADV_REG(pfd_p)->pcie_ue_status = 0;
		PCIE_ADV_REG(pfd_p)->pcie_ue_mask = 0;
		PCIE_ADV_REG(pfd_p)->pcie_ue_sev = 0;
		PCIE_ADV_HDR(pfd_p, 0) = 0;
		PCIE_ADV_HDR(pfd_p, 1) = 0;
		PCIE_ADV_HDR(pfd_p, 2) = 0;
		PCIE_ADV_HDR(pfd_p, 3) = 0;
		PCIE_ADV_REG(pfd_p)->pcie_ce_status = 0;
		PCIE_ADV_REG(pfd_p)->pcie_ce_mask = 0;
		PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_trans = 0;
		PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_addr = 0;
		PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_bdf = PCIE_INVALID_BDF;

		PCIE_ERR_REG(pfd_p)->pcie_err_status = 0;
		PCIE_ERR_REG(pfd_p)->pcie_err_ctl = 0;
		PCIE_ERR_REG(pfd_p)->pcie_dev_cap = 0;

	} else if (PCIE_IS_PCIX(bus_p)) {
		if (PCIE_IS_BDG(bus_p)) {
			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				bzero(PCIX_BDG_ECC_REG(pfd_p, 0),
				    sizeof (pf_pcix_ecc_regs_t));
				bzero(PCIX_BDG_ECC_REG(pfd_p, 1),
				    sizeof (pf_pcix_ecc_regs_t));
			}
			PCIX_BDG_ERR_REG(pfd_p)->pcix_bdg_sec_stat = 0;
			PCIX_BDG_ERR_REG(pfd_p)->pcix_bdg_stat = 0;
		} else {
			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				bzero(PCIX_ECC_REG(pfd_p),
				    sizeof (pf_pcix_ecc_regs_t));
			}
			PCIX_ERR_REG(pfd_p)->pcix_command = 0;
			PCIX_ERR_REG(pfd_p)->pcix_status = 0;
		}
	}

	pfd_p->pe_prev = NULL;
	pfd_p->pe_next = NULL;
	pfd_p->pe_rber_fatal = B_FALSE;
}

pcie_bus_t *
pf_find_busp_by_bdf(pf_impl_t *impl, pcie_req_id_t bdf)
{
	pcie_bus_t *temp_bus_p;
	pf_data_t *temp_pfd_p;

	for (temp_pfd_p = impl->pf_dq_head_p;
	    temp_pfd_p;
	    temp_pfd_p = temp_pfd_p->pe_next) {
		temp_bus_p = PCIE_PFD2BUS(temp_pfd_p);

		if (bdf == temp_bus_p->bus_bdf) {
			return (temp_bus_p);
		}
	}

	return (NULL);
}

pcie_bus_t *
pf_find_busp_by_addr(pf_impl_t *impl, uint64_t addr)
{
	pcie_bus_t *temp_bus_p;
	pf_data_t *temp_pfd_p;

	for (temp_pfd_p = impl->pf_dq_head_p;
	    temp_pfd_p;
	    temp_pfd_p = temp_pfd_p->pe_next) {
		temp_bus_p = PCIE_PFD2BUS(temp_pfd_p);

		if (pf_in_assigned_addr(temp_bus_p, addr)) {
			return (temp_bus_p);
		}
	}

	return (NULL);
}

pcie_bus_t *
pf_find_busp_by_aer(pf_impl_t *impl, pf_data_t *pfd_p)
{
	pf_pcie_adv_err_regs_t *reg_p = PCIE_ADV_REG(pfd_p);
	pcie_bus_t *temp_bus_p = NULL;
	pcie_req_id_t bdf;
	uint64_t addr;
	pcie_tlp_hdr_t *tlp_hdr = (pcie_tlp_hdr_t *)reg_p->pcie_ue_hdr;
	uint32_t trans_type = reg_p->pcie_ue_tgt_trans;

	if ((tlp_hdr->type == PCIE_TLP_TYPE_CPL) ||
	    (tlp_hdr->type == PCIE_TLP_TYPE_CPLLK)) {
		pcie_cpl_t *cpl_tlp = (pcie_cpl_t *)&reg_p->pcie_ue_hdr[1];

		bdf = (cpl_tlp->rid > cpl_tlp->cid) ? cpl_tlp->rid :
		    cpl_tlp->cid;
		temp_bus_p = pf_find_busp_by_bdf(impl, bdf);
	} else if (trans_type == PF_ADDR_PIO) {
		addr = reg_p->pcie_ue_tgt_addr;
		temp_bus_p = pf_find_busp_by_addr(impl, addr);
	} else {
		/* PF_ADDR_DMA type */
		bdf = reg_p->pcie_ue_tgt_bdf;
		temp_bus_p = pf_find_busp_by_bdf(impl, bdf);
	}

	return (temp_bus_p);
}

pcie_bus_t *
pf_find_busp_by_saer(pf_impl_t *impl, pf_data_t *pfd_p)
{
	pf_pcie_adv_bdg_err_regs_t *reg_p = PCIE_ADV_BDG_REG(pfd_p);
	pcie_bus_t *temp_bus_p = NULL;
	pcie_req_id_t bdf;
	uint64_t addr;

	addr = reg_p->pcie_sue_tgt_addr;
	bdf = reg_p->pcie_sue_tgt_bdf;

	if (addr != NULL) {
		temp_bus_p = pf_find_busp_by_addr(impl, addr);
	} else if (PCIE_CHECK_VALID_BDF(bdf)) {
		temp_bus_p = pf_find_busp_by_bdf(impl, bdf);
	}

	return (temp_bus_p);
}
