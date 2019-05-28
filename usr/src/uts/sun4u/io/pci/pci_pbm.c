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

/*
 * PCI PBM implementation:
 *	initialization
 *	Bus error interrupt handler
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/spl.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/machsystm.h>	/* ldphysio() */
#include <sys/async.h>
#include <sys/ddi_impldefs.h>
#include <sys/ontrap.h>
#include <sys/pci/pci_obj.h>
#include <sys/membar.h>
#include <sys/ivintr.h>

/*LINTLIBRARY*/

static uint_t pbm_error_intr(caddr_t a);

/* The nexus interrupt priority values */
int pci_pil[] = {14, 14, 14, 14, 14, 14};
void
pbm_create(pci_t *pci_p)
{
	pbm_t *pbm_p;
	int i, len;
	int nrange = pci_p->pci_ranges_length / sizeof (pci_ranges_t);
	dev_info_t *dip = pci_p->pci_dip;
	pci_ranges_t *rangep = pci_p->pci_ranges;
	uint64_t base_addr, last_addr;

#ifdef lint
	dip = dip;
#endif

	/*
	 * Allocate a state structure for the PBM and cross-link it
	 * to its per pci node state structure.
	 */
	pbm_p = (pbm_t *)kmem_zalloc(sizeof (pbm_t), KM_SLEEP);
	pci_p->pci_pbm_p = pbm_p;
	pbm_p->pbm_pci_p = pci_p;

	len = snprintf(pbm_p->pbm_nameinst_str,
	    sizeof (pbm_p->pbm_nameinst_str),
	    "%s%d", NAMEINST(dip));
	pbm_p->pbm_nameaddr_str = pbm_p->pbm_nameinst_str + ++len;
	(void) snprintf(pbm_p->pbm_nameaddr_str,
	    sizeof (pbm_p->pbm_nameinst_str) - len,
	    "%s@%s", NAMEADDR(dip));

	pci_pbm_setup(pbm_p);

	/*
	 * Get this pbm's mem32 and mem64 segments to determine whether
	 * a dma object originates from ths pbm. i.e. dev to dev dma
	 */
	/* Init all of our boundaries */
	base_addr = -1ull;
	last_addr = 0ull;

	for (i = 0; i < nrange; i++, rangep++) {
		uint32_t rng_type = rangep->child_high & PCI_ADDR_MASK;
		if (rng_type == PCI_ADDR_MEM32 || rng_type == PCI_ADDR_MEM64) {
			uint64_t rng_addr, rng_size;

			rng_addr = (uint64_t)rangep->parent_high << 32;
			rng_addr |= (uint64_t)rangep->parent_low;
			rng_size = (uint64_t)rangep->size_high << 32;
			rng_size |= (uint64_t)rangep->size_low;
			base_addr = MIN(rng_addr, base_addr);
			last_addr = MAX(rng_addr + rng_size, last_addr);
		}
	}
	pbm_p->pbm_base_pfn = mmu_btop(base_addr);
	pbm_p->pbm_last_pfn = mmu_btop(last_addr);

	DEBUG4(DBG_ATTACH, dip,
	    "pbm_create: ctrl=%x, afsr=%x, afar=%x, diag=%x\n",
	    pbm_p->pbm_ctrl_reg, pbm_p->pbm_async_flt_status_reg,
	    pbm_p->pbm_async_flt_addr_reg, pbm_p->pbm_diag_reg);
	DEBUG1(DBG_ATTACH, dip, "pbm_create: conf=%x\n",
	    pbm_p->pbm_config_header);

	/*
	 * Register a function to disable pbm error interrupts during a panic.
	 */
	bus_func_register(BF_TYPE_ERRDIS,
	    (busfunc_t)pbm_disable_pci_errors, pbm_p);

	/*
	 * create the interrupt-priorities property if it doesn't
	 * already exist to provide a hint as to the PIL level for
	 * our interrupt.
	 */
	if (ddi_getproplen(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "interrupt-priorities",
	    &len) != DDI_PROP_SUCCESS) {
				/* Create the interrupt-priorities property. */
		(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
		    DDI_PROP_CANSLEEP, "interrupt-priorities",
		    (caddr_t)pci_pil, sizeof (pci_pil));
	}

	pbm_configure(pbm_p);
}

int
pbm_register_intr(pbm_t *pbm_p)
{
	pci_t		*pci_p = pbm_p->pbm_pci_p;
	uint32_t	mondo;
	int		r = DDI_SUCCESS;

	ib_nintr_clear(pci_p->pci_ib_p, pci_p->pci_inos[CBNINTR_PBM]);

	/*
	 * Install the PCI error interrupt handler.
	 */
	mondo = IB_INO_TO_MONDO(pci_p->pci_ib_p, pci_p->pci_inos[CBNINTR_PBM]);
	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

	VERIFY(add_ivintr(mondo, pci_pil[CBNINTR_PBM], (intrfunc)pbm_error_intr,
	    (caddr_t)pci_p, NULL, NULL) == 0);

	pbm_p->pbm_iblock_cookie = (void *)(uintptr_t)pci_pil[CBNINTR_PBM];

	/*
	 * Create the pokefault mutex at the PIL below the error interrupt.
	 */
	mutex_init(&pbm_p->pbm_pokefault_mutex, NULL, MUTEX_DRIVER,
	    (void *)(uintptr_t)ipltospl(spltoipl(
	    (int)(uintptr_t)pbm_p->pbm_iblock_cookie) - 1));

	if (!r)
		r = pci_pbm_add_intr(pci_p);
	return (PCI_ATTACH_RETCODE(PCI_PBM_OBJ, PCI_OBJ_INTR_ADD, r));
}

void
pbm_destroy(pci_t *pci_p)
{
	pbm_t		*pbm_p = pci_p->pci_pbm_p;
	ib_t		*ib_p = pci_p->pci_ib_p;
	uint32_t	mondo;

	DEBUG0(DBG_DETACH, pci_p->pci_dip, "pbm_destroy:\n");

	mondo = IB_INO_TO_MONDO(pci_p->pci_ib_p, pci_p->pci_inos[CBNINTR_PBM]);
	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

	/*
	 * Free the pokefault mutex.
	 */
	mutex_destroy(&pbm_p->pbm_pokefault_mutex);

	/*
	 * Remove the error interrupt and consistent dma sync handler.
	 */
	intr_dist_rem(pbm_intr_dist, pbm_p);
	pci_pbm_rem_intr(pci_p);
	ib_intr_disable(ib_p, pci_p->pci_inos[CBNINTR_PBM], IB_INTR_WAIT);
	VERIFY(rem_ivintr(mondo, pci_pil[CBNINTR_PBM]) == 0);

	/*
	 * Remove the error disable function.
	 */
	bus_func_unregister(BF_TYPE_ERRDIS,
	    (busfunc_t)pbm_disable_pci_errors, pbm_p);

	pci_pbm_teardown(pbm_p);

	/*
	 * Free the pbm state structure.
	 */
	kmem_free(pbm_p, sizeof (pbm_t));
	pci_p->pci_pbm_p = NULL;
}

static uint_t
pbm_error_intr(caddr_t a)
{
	pci_t *pci_p = (pci_t *)a;
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	ddi_fm_error_t derr;
	int err = DDI_FM_OK;
	on_trap_data_t *otp = pbm_p->pbm_ontrap_data;

	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	mutex_enter(&pci_p->pci_common_p->pci_fm_mutex);
	if (pbm_p->pbm_excl_handle != NULL) {
		/*
		 * cautious write protection, protected from all errors.
		 */
		ASSERT(MUTEX_HELD(&pbm_p->pbm_pokefault_mutex));
		ddi_fm_acc_err_get(pbm_p->pbm_excl_handle, &derr,
		    DDI_FME_VERSION);
		ASSERT(derr.fme_flag == DDI_FM_ERR_EXPECTED);
		derr.fme_acc_handle = pbm_p->pbm_excl_handle;
		err = pci_pbm_err_handler(pci_p->pci_dip, &derr, (void *)pci_p,
		    PCI_INTR_CALL);
	} else if ((otp != NULL) && (otp->ot_prot & OT_DATA_ACCESS)) {
		/*
		 * ddi_poke protection, check nexus and children for
		 * expected errors.
		 */
		otp->ot_trap |= OT_DATA_ACCESS;
		membar_sync();
		derr.fme_flag = DDI_FM_ERR_POKE;
		err = pci_pbm_err_handler(pci_p->pci_dip, &derr, (void *)pci_p,
		    PCI_INTR_CALL);
	} else if (pci_check_error(pci_p) != 0) {
		/*
		 * unprotected error, check for all errors.
		 */
		if (pci_errtrig_pa)
			(void) ldphysio(pci_errtrig_pa);
		derr.fme_flag = DDI_FM_ERR_UNEXPECTED;
		err = pci_pbm_err_handler(pci_p->pci_dip, &derr, (void *)pci_p,
		    PCI_INTR_CALL);
	}

	if (err == DDI_FM_FATAL) {
		if (pci_panic_on_fatal_errors) {
			mutex_exit(&pci_p->pci_common_p->pci_fm_mutex);
			fm_panic("%s-%d: Fatal PCI bus error(s)\n",
			    ddi_driver_name(pci_p->pci_dip),
			    ddi_get_instance(pci_p->pci_dip));
		}
	}

	mutex_exit(&pci_p->pci_common_p->pci_fm_mutex);
	ib_nintr_clear(pci_p->pci_ib_p, pci_p->pci_inos[CBNINTR_PBM]);
	return (DDI_INTR_CLAIMED);
}

void
pbm_suspend(pbm_t *pbm_p)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;
	ib_ino_t ino = pci_p->pci_inos[CBNINTR_PBM];
	pbm_p->pbm_imr_save = *ib_intr_map_reg_addr(pci_p->pci_ib_p, ino);

	pci_pbm_suspend(pci_p);
}

void
pbm_resume(pbm_t *pbm_p)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;
	ib_ino_t ino = pci_p->pci_inos[CBNINTR_PBM];

	ib_nintr_clear(pci_p->pci_ib_p, ino);
	*ib_intr_map_reg_addr(pci_p->pci_ib_p, ino) = pbm_p->pbm_imr_save;

	pci_pbm_resume(pci_p);
}

void
pbm_intr_dist(void *arg)
{
	pbm_t *pbm_p = (pbm_t *)arg;
	pci_t *pci_p = pbm_p->pbm_pci_p;
	ib_t *ib_p = pci_p->pci_ib_p;
	ib_ino_t ino = IB_MONDO_TO_INO(pci_p->pci_inos[CBNINTR_PBM]);

	mutex_enter(&ib_p->ib_intr_lock);
	ib_intr_dist_nintr(ib_p, ino, ib_intr_map_reg_addr(ib_p, ino));
	pci_pbm_intr_dist(pbm_p);
	mutex_exit(&ib_p->ib_intr_lock);
}

/*
 * Function used to log PBM AFSR register bits and to lookup and fault
 * handle associated with PBM AFAR register. Called by pci_pbm_err_handler with
 * pci_fm_mutex held.
 */
int
pbm_afsr_report(dev_info_t *dip, uint64_t fme_ena, pbm_errstate_t *pbm_err_p)
{
	int fatal = 0;
	int ret = 0;
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	pci_common_t *cmn_p = pci_p->pci_common_p;

	ASSERT(MUTEX_HELD(&cmn_p->pci_fm_mutex));

	pbm_err_p->pbm_pri = PBM_PRIMARY;
	(void) pci_pbm_classify(pbm_err_p);

	pci_format_addr(dip, &pbm_err_p->pbm_pci.pci_pa, pbm_err_p->pbm_afsr);

	if (pbm_err_p->pbm_log == FM_LOG_PBM)
		pbm_ereport_post(dip, fme_ena, pbm_err_p);

	/*
	 * Lookup and fault errant handle
	 */
	if (((ret = ndi_fmc_error(dip, NULL, ACC_HANDLE, fme_ena,
	    (void *)&pbm_err_p->pbm_pci.pci_pa)) == DDI_FM_FATAL) ||
	    (ret == DDI_FM_UNKNOWN))
		fatal++;

	/*
	 * queue target ereport if appropriate
	 */
	if (pbm_err_p->pbm_terr_class)
		pci_target_enqueue(fme_ena, pbm_err_p->pbm_terr_class,
		    (pbm_err_p->pbm_log == FM_LOG_PCI) ? "pci" :
		    pbm_err_p->pbm_bridge_type, pbm_err_p->pbm_pci.pci_pa);

	/*
	 * We are currently not dealing with the multiple error
	 * case, for any secondary errors we will panic.
	 */
	pbm_err_p->pbm_pri = PBM_SECONDARY;
	if (pci_pbm_classify(pbm_err_p)) {
		fatal++;
		if (pbm_err_p->pbm_log == FM_LOG_PBM)
			pbm_ereport_post(dip, fme_ena, pbm_err_p);
	}

	if (fatal)
		return (DDI_FM_FATAL);

	return (DDI_FM_NONFATAL);
}
