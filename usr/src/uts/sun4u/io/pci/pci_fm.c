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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Peter Tribble.
 */

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
	*ibc = pci_p->pci_fm_ibc;

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
		    (void *)pci_p->pci_ecc_p,
		    ECC_MAX_ERRS, sizeof (ecc_errstate_t),
		    PIL_2, ERRORQ_VITAL);
		if (pci_ecc_queue == NULL)
			panic("failed to create required system error queue");
	}

	/*
	 * Initialize pci_target_queue for FMA handling of pci errors.
	 */
	pci_targetq_init();

	/*
	 * Initialize FMA support
	 */
	pci_p->pci_fm_cap = DDI_FM_EREPORT_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE |
	    DDI_FM_ERRCB_CAPABLE;
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
	ddi_fm_handler_register(pci_p->pci_dip, pci_err_callback, pci_p);

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
