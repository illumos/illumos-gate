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

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/async.h>
#include <sys/membar.h>
#include <sys/spl.h>
#include <sys/iommu.h>
#include <sys/pci/pci_obj.h>
#include <sys/fm/util.h>
#include <sys/fm/io/pci.h>
#include <sys/fm/io/ddi.h>
#include <sys/fm/io/sun4upci.h>
#include <sys/fm/protocol.h>
#include <sys/intr.h>

/*LINTLIBRARY*/

/*
 * The routines below are generic sun4u PCI interfaces to support
 * Fault Management.
 *
 * pci_dma_check, pci_acc_check, pci_handle_lookup are functions used
 * to associate a captured PCI address to a particular dma/acc handle.
 *
 * pci_fm_acc_setup, pci_fm_init_child, pci_fm_create,
 * pci_fm_destroy are constructors/destructors used to setup and teardown
 * necessary resources.
 *
 * pci_bus_enter, pci_bus_exit are registered via busops and are used to
 * provide exclusive access to the PCI bus.
 *
 * pci_err_callback is the registered callback for PCI which is called
 * by the CPU code when it detects a UE/TO/BERR.
 *
 * pbm_ereport_post is used by the PBM code to generically report all
 * PBM errors.
 *
 */

/*
 * Function called after a dma fault occurred to find out whether the
 * fault address is associated with a driver that is able to handle faults
 * and recover from faults.
 */
/* ARGSUSED */
static int
pci_dma_check(dev_info_t *dip, const void *handle, const void *comp_addr,
    const void *not_used)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	pfn_t fault_pfn = mmu_btop(*(uint64_t *)comp_addr);
	pfn_t comp_pfn;
	int page;

	/*
	 * The driver has to set DDI_DMA_FLAGERR to recover from dma faults.
	 */
	ASSERT(mp);

	for (page = 0; page < mp->dmai_ndvmapages; page++) {
		comp_pfn = PCI_GET_MP_PFN(mp, page);
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
pci_acc_check(dev_info_t *dip, const void *handle, const void *comp_addr,
    const void *not_used)
{
	pfn_t pfn, fault_pfn;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get((ddi_acc_handle_t)handle);

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
pci_handle_lookup(dev_info_t *dip, int type, uint64_t fme_ena, void *afar)
{
	int status = DDI_FM_UNKNOWN;
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));

	if (type == DMA_HANDLE && DDI_FM_DMA_ERR_CAP(pci_p->pci_fm_cap))
		status = ndi_fmc_error(dip, NULL, type, pci_dma_check,
		    fme_ena, afar);
	else if (DDI_FM_ACC_ERR_CAP(pci_p->pci_fm_cap))
		status = ndi_fmc_error(dip, NULL, type, pci_acc_check,
		    fme_ena, afar);

	return (status);
}

/*
 * Function used to setup access functions depending on level of desired
 * protection.
 */
void
pci_fm_acc_setup(ddi_map_req_t *mp, dev_info_t *rdip)
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
/* ARGSUSED */
int
pci_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));

	ASSERT(ibc != NULL);
	*ibc = pci_p->pci_pbm_p->pbm_iblock_cookie;

	return (pci_p->pci_fm_cap);
}

/*
 * Lock accesses to the pci bus, to be able to protect against bus errors.
 */
void
pci_bus_enter(dev_info_t *dip, ddi_acc_handle_t handle)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	pbm_t *pbm_p = pci_p->pci_pbm_p;

	membar_sync();

	mutex_enter(&pbm_p->pbm_pokefault_mutex);
	pbm_p->pbm_excl_handle = handle;
}

/*
 * Unlock access to bus and clear errors before exiting.
 */
/* ARGSUSED */
void
pci_bus_exit(dev_info_t *dip, ddi_acc_handle_t handle)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	ddi_fm_error_t derr;

	ASSERT(MUTEX_HELD(&pbm_p->pbm_pokefault_mutex));

	membar_sync();

	mutex_enter(&pci_p->pci_common_p->pci_fm_mutex);
	ddi_fm_acc_err_get(pbm_p->pbm_excl_handle, &derr, DDI_FME_VERSION);

	if (derr.fme_status == DDI_FM_OK) {
		if (pci_check_error(pci_p) != 0) {
			(void) pci_pbm_err_handler(pci_p->pci_dip, &derr,
					(const void *)pci_p, PCI_BUS_EXIT_CALL);
		}
	}
	mutex_exit(&pci_p->pci_common_p->pci_fm_mutex);

	pbm_p->pbm_excl_handle = NULL;
	mutex_exit(&pbm_p->pbm_pokefault_mutex);
}

/*
 * PCI error callback which is registered with our parent to call
 * for PCI logging when the CPU traps due to BERR/TO/UE.
 */
int
pci_err_callback(dev_info_t *dip, ddi_fm_error_t *derr,
    const void *impl_data)
{
	pci_t *pci_p = (pci_t *)impl_data;
	pci_common_t *cmn_p = pci_p->pci_common_p;
	ecc_t *ecc_p = cmn_p->pci_common_ecc_p;
	ecc_errstate_t ecc_err;
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;
	int ret = DDI_FM_OK;

	bzero(&ecc_err, sizeof (ecc_err));
	mutex_enter(&cmn_p->pci_fm_mutex);
	/*
	 * Check and log ecc and pbm errors
	 */
	ecc_err.ecc_ii_p = ecc_p->ecc_ue;
	ecc_err.ecc_ena = derr->fme_ena;
	ecc_err.ecc_caller = PCI_TRAP_CALL;

	if ((ret = ecc_err_handler(&ecc_err)) == DDI_FM_FATAL)
		fatal++;
	else if (ret == DDI_FM_NONFATAL)
		nonfatal++;
	else if (ret == DDI_FM_UNKNOWN)
		unknown++;

	if (pci_check_error(pci_p) != 0) {
		int err = pci_pbm_err_handler(pci_p->pci_dip, derr,
				(const void *)pci_p, PCI_TRAP_CALL);
		if (err == DDI_FM_FATAL)
			fatal++;
		else if (err == DDI_FM_NONFATAL)
			nonfatal++;
		else if (err == DDI_FM_UNKNOWN)
			unknown++;
	}

	mutex_exit(&cmn_p->pci_fm_mutex);

	if (fatal)
		return (DDI_FM_FATAL);
	else if (nonfatal)
		return (DDI_FM_NONFATAL);
	else if (unknown)
		return (DDI_FM_UNKNOWN);
	else
		return (DDI_FM_OK);
}

/*
 * private version of walk_devs() that can be used during panic. No
 * sleeping or locking required.
 */
static int
pci_tgt_walk_devs(dev_info_t *dip, int (*f)(dev_info_t *, void *), void *arg)
{
	while (dip) {
		switch ((*f)(dip, arg)) {
		case DDI_WALK_TERMINATE:
			return (DDI_WALK_TERMINATE);
		case DDI_WALK_CONTINUE:
			if (pci_tgt_walk_devs(ddi_get_child(dip), f,
			    arg) == DDI_WALK_TERMINATE)
				return (DDI_WALK_TERMINATE);
			break;
		case DDI_WALK_PRUNECHILD:
			break;
		}
		dip = ddi_get_next_sibling(dip);
	}
	return (DDI_WALK_CONTINUE);
}

static int
pci_check_regs(dev_info_t *dip, void *arg)
{
	int reglen;
	int rn;
	int totreg;
	pci_regspec_t *drv_regp;
	pci_target_err_t *tgt_err = (pci_target_err_t *)arg;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&drv_regp, &reglen) != DDI_SUCCESS)
		return (DDI_WALK_CONTINUE);

	totreg = reglen / sizeof (pci_regspec_t);
	for (rn = 0; rn < totreg; rn++) {
		if (tgt_err->tgt_pci_space ==
		    PCI_REG_ADDR_G(drv_regp[rn].pci_phys_hi) &&
		    (tgt_err->tgt_pci_addr >=
		    (uint64_t)drv_regp[rn].pci_phys_low +
		    ((uint64_t)drv_regp[rn].pci_phys_mid << 32)) &&
		    (tgt_err->tgt_pci_addr <
		    (uint64_t)drv_regp[rn].pci_phys_low +
		    ((uint64_t)drv_regp[rn].pci_phys_mid << 32) +
		    (uint64_t)drv_regp[rn].pci_size_low +
		    ((uint64_t)drv_regp[rn].pci_size_hi << 32))) {
			tgt_err->tgt_dip = dip;
			kmem_free(drv_regp, reglen);
			return (DDI_WALK_TERMINATE);
		}
	}
	kmem_free(drv_regp, reglen);
	return (DDI_WALK_CONTINUE);
}

static int
pci_check_ranges(dev_info_t *dip, void *arg)
{
	uint64_t range_parent_begin;
	uint64_t range_parent_size;
	uint64_t range_parent_end;
	uint32_t space_type;
	uint32_t bus_num;
	uint32_t range_offset;
	pci_ranges_t *pci_ranges, *rangep;
	pci_bus_range_t *pci_bus_rangep;
	int pci_ranges_length;
	int nrange;
	pci_target_err_t *tgt_err = (pci_target_err_t *)arg;
	int i, size;

	if (strcmp(ddi_node_name(dip), "pci") != 0)
		return (DDI_WALK_CONTINUE);

	/*
	 * Get the ranges property.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "ranges",
		(caddr_t)&pci_ranges, &pci_ranges_length) != DDI_SUCCESS) {
		return (DDI_WALK_CONTINUE);
	}
	nrange = pci_ranges_length / sizeof (pci_ranges_t);
	rangep = pci_ranges;
	pci_fix_ranges(pci_ranges, nrange);

	for (i = 0; i < nrange; i++, rangep++) {
		range_parent_begin = ((uint64_t)rangep->parent_high << 32) +
		    rangep->parent_low;
		range_parent_size = ((uint64_t)rangep->size_high << 32) +
		    rangep->size_low;
		range_parent_end = range_parent_begin + range_parent_size - 1;

		if ((tgt_err->tgt_err_addr < range_parent_begin) ||
		    (tgt_err->tgt_err_addr > range_parent_end)) {
			/* Not in range */
			continue;
		}
		space_type = PCI_REG_ADDR_G(rangep->child_high);
		if (space_type == PCI_REG_ADDR_G(PCI_ADDR_CONFIG)) {
			/* Config space address - check bus range */
			range_offset = tgt_err->tgt_err_addr -
			    range_parent_begin;
			bus_num = PCI_REG_BUS_G(range_offset);
			if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "bus-range",
			    (caddr_t)&pci_bus_rangep, &size) != DDI_SUCCESS) {
				continue;
			}
			if ((bus_num < pci_bus_rangep->lo) ||
			    (bus_num > pci_bus_rangep->hi)) {
				/*
				 * Bus number not appropriate for this
				 * pci nexus.
				 */
				kmem_free(pci_bus_rangep, size);
				continue;
			}
			kmem_free(pci_bus_rangep, size);
		}

		/* We have a match if we get here - compute pci address */
		tgt_err->tgt_pci_addr = tgt_err->tgt_err_addr -
		    range_parent_begin;
		tgt_err->tgt_pci_addr += (((uint64_t)rangep->child_mid << 32) +
		    rangep->child_low);
		tgt_err->tgt_pci_space = space_type;
		if (panicstr)
			pci_tgt_walk_devs(dip, pci_check_regs, (void *)tgt_err);
		else
			ddi_walk_devs(dip, pci_check_regs, (void *)tgt_err);
		if (tgt_err->tgt_dip != NULL) {
			kmem_free(pci_ranges, pci_ranges_length);
			return (DDI_WALK_TERMINATE);
		}
	}
	kmem_free(pci_ranges, pci_ranges_length);
	return (DDI_WALK_PRUNECHILD);
}

/*
 * need special version of ddi_fm_ereport_post() as the leaf driver may
 * not be hardened.
 */
void
pci_tgt_ereport_post(dev_info_t *dip, const char *error_class, uint64_t ena,
    uint8_t version, ...)
{
	char *name;
	char device_path[MAXPATHLEN];
	char ddi_error_class[FM_MAX_CLASS];
	nvlist_t *ereport, *detector;
	nv_alloc_t *nva;
	errorq_elem_t *eqep;
	va_list ap;

	if (panicstr) {
		eqep = errorq_reserve(ereport_errorq);
		if (eqep == NULL)
			return;
		ereport = errorq_elem_nvl(ereport_errorq, eqep);
		nva = errorq_elem_nva(ereport_errorq, eqep);
		detector = fm_nvlist_create(nva);
	} else {
		ereport = fm_nvlist_create(NULL);
		detector = fm_nvlist_create(NULL);
	}

	(void) ddi_pathname(dip, device_path);
	fm_fmri_dev_set(detector, FM_DEV_SCHEME_VERSION, NULL,
	    device_path, NULL);
	(void) snprintf(ddi_error_class, FM_MAX_CLASS, "%s.%s",
	    DDI_IO_CLASS, error_class);
	fm_ereport_set(ereport, version, ddi_error_class, ena, detector, NULL);

	va_start(ap, version);
	name = va_arg(ap, char *);
	(void) i_fm_payload_set(ereport, name, ap);
	va_end(ap);

	if (panicstr) {
		errorq_commit(ereport_errorq, eqep, ERRORQ_SYNC);
	} else {
		(void) fm_ereport_post(ereport, EVCH_TRYHARD);
		fm_nvlist_destroy(ereport, FM_NVA_FREE);
		fm_nvlist_destroy(detector, FM_NVA_FREE);
	}
}

/*
 * Function used to drain pci_target_queue, either during panic or after softint
 * is generated, to generate target device ereports based on captured physical
 * addresss
 */
static void
pci_target_drain(void *private_p, pci_target_err_t *tgt_err)
{
	char buf[FM_MAX_CLASS];

	/*
	 * The following assumes that all pci_pci bridge devices
	 * are configured as transparant. Find the top-level pci
	 * nexus which has tgt_err_addr in one of its ranges, converting this
	 * to a pci address in the process. Then starting at this node do
	 * another tree walk to find a device with the pci address we've
	 * found within range of one of it's assigned-addresses properties.
	 */
	tgt_err->tgt_dip = NULL;
	if (panicstr)
		pci_tgt_walk_devs(ddi_root_node(), pci_check_ranges,
		    (void *)tgt_err);
	else
		ddi_walk_devs(ddi_root_node(), pci_check_ranges,
		    (void *)tgt_err);
	if (tgt_err->tgt_dip == NULL)
		return;

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", tgt_err->tgt_bridge_type,
	    tgt_err->tgt_err_class);
	pci_tgt_ereport_post(tgt_err->tgt_dip, buf, tgt_err->tgt_err_ena, 0,
	    PCI_PA, DATA_TYPE_UINT64, tgt_err->tgt_err_addr, NULL);
}

void
pci_fm_create(pci_t *pci_p)
{
	pci_common_t *cmn_p = pci_p->pci_common_p;

	/*
	 * PCI detected ECC errorq, to schedule async handling
	 * of ECC errors and logging.
	 * The errorq is created here but destroyed when _fini is called
	 * for the pci module.
	 */
	if (pci_ecc_queue == NULL) {
		pci_ecc_queue = errorq_create("pci_ecc_queue",
				(errorq_func_t)ecc_err_drain,
				(void *)NULL,
				ECC_MAX_ERRS, sizeof (ecc_errstate_t),
				PIL_2, ERRORQ_VITAL);
		if (pci_ecc_queue == NULL)
			panic("failed to create required system error queue");
	}

	/*
	 * PCI target errorq, to schedule async handling of generation of
	 * target device ereports based on captured physical address.
	 * The errorq is created here but destroyed when _fini is called
	 * for the pci module.
	 */
	if (pci_target_queue == NULL) {
		pci_target_queue = errorq_create("pci_target_queue",
				(errorq_func_t)pci_target_drain,
				(void *)NULL,
				TARGET_MAX_ERRS, sizeof (pci_target_err_t),
				PIL_2, ERRORQ_VITAL);
		if (pci_target_queue == NULL)
			panic("failed to create required system error queue");
	}

	/*
	 * Initialize FMA support
	 * The axq workaround prevents fault management of access errors
	 */
	if (pci_p->pci_pbm_p->pbm_pio_limit == 0)
		pci_p->pci_fm_cap = DDI_FM_EREPORT_CAPABLE |
			DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE |
			DDI_FM_ERRCB_CAPABLE;
	else
		pci_p->pci_fm_cap = DDI_FM_EREPORT_CAPABLE |
			DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE;
	/*
	 * Call parent to get it's capablity
	 */
	ddi_fm_init(pci_p->pci_dip, &pci_p->pci_fm_cap,
			&pci_p->pci_fm_ibc);
	/*
	 * Need to be ereport and error handler cabable
	 */
	ASSERT((pci_p->pci_fm_cap & DDI_FM_ERRCB_CAPABLE) &&
	    (pci_p->pci_fm_cap & DDI_FM_EREPORT_CAPABLE));
	/*
	 * Initialize error handling mutex.
	 */
	if (cmn_p->pci_common_refcnt == 0) {
		mutex_init(&cmn_p->pci_fm_mutex, NULL, MUTEX_DRIVER,
				(void *)pci_p->pci_fm_ibc);
	}

	/*
	 * Register error callback with our parent.
	 */
	ddi_fm_handler_register(pci_p->pci_dip, pci_err_callback,
			pci_p);

}

void
pci_fm_destroy(pci_t *pci_p)
{
	pci_common_t *cmn_p = pci_p->pci_common_p;

	/* schizo non-shared objects */
	ddi_fm_handler_unregister(pci_p->pci_dip);
	ddi_fm_fini(pci_p->pci_dip);

	if (cmn_p->pci_common_refcnt != 0)
		return;

	mutex_destroy(&cmn_p->pci_fm_mutex);
}

/*
 * Function used to post PCI block module specific ereports.
 */
void
pbm_ereport_post(dev_info_t *dip, uint64_t ena, pbm_errstate_t *pbm_err)
{
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
	    pbm_err->pbm_bridge_type, pbm_err->pbm_err_class);

	ena = ena ? ena : fm_ena_generate(0, FM_ENA_FMT1);

	ddi_fm_ereport_post(dip, buf, ena, DDI_NOSLEEP,
	    FM_VERSION, DATA_TYPE_UINT8, 0,
	    PCI_CONFIG_STATUS, DATA_TYPE_UINT16, pbm_err->pbm_pci.pci_cfg_stat,
	    PCI_CONFIG_COMMAND, DATA_TYPE_UINT16, pbm_err->pbm_pci.pci_cfg_comm,
	    PCI_PBM_CSR, DATA_TYPE_UINT64, pbm_err->pbm_ctl_stat,
	    PCI_PBM_AFSR, DATA_TYPE_UINT64, pbm_err->pbm_afsr,
	    PCI_PBM_AFAR, DATA_TYPE_UINT64, pbm_err->pbm_afar,
	    PCI_PBM_SLOT, DATA_TYPE_UINT64, pbm_err->pbm_err_sl,
	    PCI_PBM_VALOG, DATA_TYPE_UINT64, pbm_err->pbm_va_log,
	    NULL);
}
