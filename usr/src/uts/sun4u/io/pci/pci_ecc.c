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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * PCI ECC support
 */

#include <sys/types.h>
#include <sys/systm.h>		/* for strrchr */
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/intr.h>
#include <sys/async.h>		/* struct async_flt */
#include <sys/ddi_impldefs.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/pci.h>
#include <sys/fm/io/sun4upci.h>
#include <sys/fm/io/ddi.h>
#include <sys/pci/pci_obj.h>	/* ld/st physio */
#include <sys/cpuvar.h>
#include <sys/errclassify.h>
#include <sys/cpu_module.h>
#include <sys/async.h>

/*LINTLIBRARY*/

static void ecc_disable(ecc_t *, int);
static void ecc_delayed_ce(void *);
static uint64_t ecc_read_afsr(ecc_intr_info_t *);
static void ecc_ereport_post(dev_info_t *dip, ecc_errstate_t *ecc_err);

clock_t pci_ecc_panic_delay = 200;
int ecc_ce_delay_secs = 6;	/* number of sec to delay reenabling of CEs */
int ecc_ce_delayed = 1;		/* global for enabling/disabling CE delay */

void
ecc_create(pci_t *pci_p)
{
#ifdef DEBUG
	dev_info_t *dip = pci_p->pci_dip;
#endif
	uint64_t cb_base_pa = pci_p->pci_cb_p->cb_base_pa;
	ecc_t *ecc_p;

	ecc_p = (ecc_t *)kmem_zalloc(sizeof (ecc_t), KM_SLEEP);
	ecc_p->ecc_pci_cmn_p = pci_p->pci_common_p;
	pci_p->pci_ecc_p = ecc_p;

	ecc_p->ecc_ue.ecc_p = ecc_p;
	ecc_p->ecc_ue.ecc_type = CBNINTR_UE;
	ecc_p->ecc_ce.ecc_p = ecc_p;
	ecc_p->ecc_ce.ecc_type = CBNINTR_CE;

	pci_ecc_setup(ecc_p);

	/*
	 * Determine the virtual addresses of the streaming cache
	 * control/status and flush registers.
	 */
	ecc_p->ecc_csr_pa = cb_base_pa + COMMON_ECC_CSR_OFFSET;
	ecc_p->ecc_ue.ecc_afsr_pa = cb_base_pa + COMMON_UE_AFSR_OFFSET;
	ecc_p->ecc_ue.ecc_afar_pa = cb_base_pa + COMMON_UE_AFAR_OFFSET;
	ecc_p->ecc_ce.ecc_afsr_pa = cb_base_pa + COMMON_CE_AFSR_OFFSET;
	ecc_p->ecc_ce.ecc_afar_pa = cb_base_pa + COMMON_CE_AFAR_OFFSET;

	DEBUG1(DBG_ATTACH, dip, "ecc_create: csr=%x\n", ecc_p->ecc_csr_pa);
	DEBUG2(DBG_ATTACH, dip, "ecc_create: ue_afsr=%x, ue_afar=%x\n",
	    ecc_p->ecc_ue.ecc_afsr_pa, ecc_p->ecc_ue.ecc_afar_pa);
	DEBUG2(DBG_ATTACH, dip, "ecc_create: ce_afsr=%x, ce_afar=%x\n",
	    ecc_p->ecc_ce.ecc_afsr_pa, ecc_p->ecc_ce.ecc_afar_pa);

	ecc_configure(pci_p);

	/*
	 * Register routines to be called from system error handling code.
	 */
	bus_func_register(BF_TYPE_ERRDIS, (busfunc_t)ecc_disable_nowait, ecc_p);
}

int
ecc_register_intr(pci_t *pci_p)
{
	ecc_t *ecc_p = pci_p->pci_ecc_p;
	int ret;

	/*
	 * Install the UE and CE error interrupt handlers.
	 */
	if ((ret = pci_ecc_add_intr(pci_p, CBNINTR_UE, &ecc_p->ecc_ue)) !=
	    DDI_SUCCESS)
		return (ret);
	if ((ret = pci_ecc_add_intr(pci_p, CBNINTR_CE, &ecc_p->ecc_ce)) !=
	    DDI_SUCCESS)
		return (ret);

	return (DDI_SUCCESS);
}

void
ecc_destroy(pci_t *pci_p)
{
	ecc_t *ecc_p = pci_p->pci_ecc_p;

	DEBUG0(DBG_DETACH, pci_p->pci_dip, "ecc_destroy:\n");

	/*
	 * Disable UE and CE ECC error interrupts.
	 */
	ecc_disable_wait(ecc_p);

	/*
	 * Remove the ECC interrupt handlers.
	 */
	pci_ecc_rem_intr(pci_p, CBNINTR_UE, &ecc_p->ecc_ue);
	pci_ecc_rem_intr(pci_p, CBNINTR_CE, &ecc_p->ecc_ce);

	/*
	 * Unregister our error handling functions.
	 */
	bus_func_unregister(BF_TYPE_ERRDIS,
	    (busfunc_t)ecc_disable_nowait, ecc_p);
	/*
	 * If a timer has been set, unset it.
	 */
	(void) untimeout(ecc_p->ecc_to_id);

	kmem_free(ecc_p, sizeof (ecc_t));
	pci_p->pci_ecc_p = NULL;
}

void
ecc_configure(pci_t *pci_p)
{
	ecc_t *ecc_p = pci_p->pci_ecc_p;
	dev_info_t *dip = pci_p->pci_dip;
	uint64_t l;

	/*
	 * Clear any pending ECC errors.
	 */
	DEBUG0(DBG_ATTACH, dip, "ecc_configure: clearing UE and CE errors\n");
	l = (COMMON_ECC_UE_AFSR_E_MASK << COMMON_ECC_UE_AFSR_PE_SHIFT) |
	    (COMMON_ECC_UE_AFSR_E_MASK << COMMON_ECC_UE_AFSR_SE_SHIFT);
	stdphysio(ecc_p->ecc_ue.ecc_afsr_pa, l);

	l = (COMMON_ECC_CE_AFSR_E_MASK << COMMON_ECC_CE_AFSR_PE_SHIFT) |
	    (COMMON_ECC_CE_AFSR_E_MASK << COMMON_ECC_CE_AFSR_SE_SHIFT);
	stdphysio(ecc_p->ecc_ce.ecc_afsr_pa, l);

	/*
	 * Enable ECC error detections via the control register.
	 */
	DEBUG0(DBG_ATTACH, dip, "ecc_configure: enabling UE CE detection\n");
	l = COMMON_ECC_CTRL_ECC_EN;
	if (ecc_error_intr_enable)
		l |= COMMON_ECC_CTRL_UE_INTEN | COMMON_ECC_CTRL_CE_INTEN;
	stdphysio(ecc_p->ecc_csr_pa, l);
}

void
ecc_enable_intr(pci_t *pci_p)
{
	cb_enable_nintr(pci_p, CBNINTR_UE);
	cb_enable_nintr(pci_p, CBNINTR_CE);
}

void
ecc_disable_wait(ecc_t *ecc_p)
{
	ecc_disable(ecc_p, IB_INTR_WAIT);
}

uint_t
ecc_disable_nowait(ecc_t *ecc_p)
{
	ecc_disable(ecc_p, IB_INTR_NOWAIT);
	return (BF_NONE);
}

static void
ecc_disable(ecc_t *ecc_p, int wait)
{
	cb_t *cb_p = ecc_p->ecc_pci_cmn_p->pci_common_cb_p;
	uint64_t csr_pa = ecc_p->ecc_csr_pa;
	uint64_t csr = lddphysio(csr_pa);

	csr &= ~(COMMON_ECC_CTRL_UE_INTEN | COMMON_ECC_CTRL_CE_INTEN);
	stdphysio(csr_pa, csr);

	cb_disable_nintr(cb_p, CBNINTR_UE, wait);
	cb_disable_nintr(cb_p, CBNINTR_CE, wait);
}

/*
 * I/O ECC error handling:
 *
 * Below are the generic functions that handle PCI(pcisch, pcipsy) detected
 * ECC errors.
 *
 * The registered interrupt handler for both pcisch and pcipsy is ecc_intr(),
 * it's function is to receive the error, capture some state, and pass that on
 * to the ecc_err_handler() for reporting purposes.
 *
 * ecc_err_handler() gathers more state(via ecc_errstate_get) and attempts
 * to handle and report the error. ecc_err_handler() must determine if we need
 * to panic due to this error (via pci_ecc_classify, which also decodes the
 * ECC afsr), and if any side effects exist that may have caused or are due
 * to this error. PBM errors related to the ECC error may exist, to report
 * them we call pci_pbm_err_handler() and call ndi_fm_handler_dispatch() so
 * that the child devices can log their pci errors.
 *
 * To report the error we must also get the syndrome and unum, which can not
 * be done in high level interrupted context. Therefore we have an error
 * queue(pci_ecc_queue) which we dispatch errors to, to report the errors
 * (ecc_err_drain()).
 *
 * ecc_err_drain() will be called when either the softint is triggered
 * or the system is panicing. Either way it will gather more information
 * about the error from the CPU(via ecc_cpu_call(), ecc.c), attempt to
 * retire the faulty page(if error is a UE), and report the detected error.
 *
 * ecc_delayed_ce() is called via timeout from ecc_err_handler() following
 * the receipt of a CE interrupt.  It will be called after 6ms and check to
 * see if any new CEs are present, if so we will log and another timeout will
 * be set by(ecc_err_handler()).  If no CEs are present then it will re-enable
 * CEs by clearing the previous interrupt.  This is to keep the system going
 * in the event of a CE storm.
 */

/*
 * Function used to get ECC AFSR register
 */
static uint64_t
ecc_read_afsr(ecc_intr_info_t *ecc_ii_p)
{
	uint_t i;
	uint64_t afsr = 0ull;

	ASSERT((ecc_ii_p->ecc_type == CBNINTR_UE) ||
	    (ecc_ii_p->ecc_type == CBNINTR_CE));
	if (!ecc_ii_p->ecc_errpndg_mask)
		return (lddphysio(ecc_ii_p->ecc_afsr_pa));

	for (i = 0; i < pci_ecc_afsr_retries; i++) {

		/*
		 * If we timeout, the logging routine will
		 * know because it will see the ERRPNDG bits
		 * set in the AFSR.
		 */
		afsr = lddphysio(ecc_ii_p->ecc_afsr_pa);
		if ((afsr & ecc_ii_p->ecc_errpndg_mask) == 0)
			break;
	}
	return (afsr);
}

/*
 * IO detected ECC error interrupt handler, calls ecc_err_handler to post
 * error reports and handle the interrupt. Re-entry into ecc_err_handler
 * is protected by the per-chip mutex pci_fm_mutex.
 */
uint_t
ecc_intr(caddr_t a)
{
	ecc_intr_info_t *ecc_ii_p = (ecc_intr_info_t *)a;
	ecc_t *ecc_p = ecc_ii_p->ecc_p;
	pci_common_t *cmn_p = ecc_p->ecc_pci_cmn_p;
	ecc_errstate_t ecc_err;
	int ret = DDI_FM_OK;

	bzero(&ecc_err, sizeof (ecc_errstate_t));
	ecc_err.ecc_ena = fm_ena_generate(0, FM_ENA_FMT1);
	ecc_err.ecc_ii_p = *ecc_ii_p;
	ecc_err.ecc_p = ecc_p;
	ecc_err.ecc_caller = PCI_ECC_CALL;

	mutex_enter(&cmn_p->pci_fm_mutex);
	ret = ecc_err_handler(&ecc_err);
	mutex_exit(&cmn_p->pci_fm_mutex);
	if (ret == DDI_FM_FATAL) {
		/*
		 * Need delay here to allow CPUs to handle related traps,
		 * such as FRUs for USIIIi systems.
		 */
		DELAY(pci_ecc_panic_delay);
		fm_panic("Fatal PCI UE Error");
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * Function used to gather IO ECC error state.
 */
static void
ecc_errstate_get(ecc_errstate_t *ecc_err_p)
{
	ecc_t *ecc_p;
	uint_t bus_id;

	ASSERT(ecc_err_p);

	ecc_p = ecc_err_p->ecc_ii_p.ecc_p;
	bus_id = ecc_p->ecc_pci_cmn_p->pci_common_id;

	ASSERT(MUTEX_HELD(&ecc_p->ecc_pci_cmn_p->pci_fm_mutex));
	/*
	 * Read the fault registers.
	 */
	ecc_err_p->ecc_afsr = ecc_read_afsr(&ecc_err_p->ecc_ii_p);
	ecc_err_p->ecc_afar = lddphysio(ecc_err_p->ecc_ii_p.ecc_afar_pa);

	ecc_err_p->ecc_offset = ((ecc_err_p->ecc_afsr &
	    ecc_err_p->ecc_ii_p.ecc_offset_mask) >>
	    ecc_err_p->ecc_ii_p.ecc_offset_shift) <<
	    ecc_err_p->ecc_ii_p.ecc_size_log2;

	ecc_err_p->ecc_aflt.flt_id = gethrtime();
	ecc_err_p->ecc_aflt.flt_stat = ecc_err_p->ecc_afsr;
	ecc_err_p->ecc_aflt.flt_addr = P2ALIGN(ecc_err_p->ecc_afar, 64) +
	    ecc_err_p->ecc_offset;
	ecc_err_p->ecc_aflt.flt_bus_id = bus_id;
	ecc_err_p->ecc_aflt.flt_inst = CPU->cpu_id;
	ecc_err_p->ecc_aflt.flt_status = ECC_IOBUS;
	ecc_err_p->ecc_aflt.flt_in_memory =
	    (pf_is_memory(ecc_err_p->ecc_afar >> MMU_PAGESHIFT))? 1: 0;
	ecc_err_p->ecc_aflt.flt_class = BUS_FAULT;
}

/*
 * ecc_pci_check: Called by ecc_err_handler() this function is responsible
 * for calling pci_pbm_err_handler() for both sides of the schizo/psycho
 * and calling their children error handlers(via ndi_fm_handler_dispatch()).
 */
static int
ecc_pci_check(ecc_t *ecc_p, uint64_t fme_ena)
{
	ddi_fm_error_t derr;
	int i;
	int ret;

	ASSERT(MUTEX_HELD(&ecc_p->ecc_pci_cmn_p->pci_fm_mutex));

	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fme_ena;
	ret = DDI_FM_NONFATAL;

	/*
	 * Need to report any PBM errors which may have caused or
	 * resulted from this error.
	 *
	 * Each psycho or schizo is represented by a pair of pci nodes
	 * in the device tree.
	 */
	for (i = 0; i < 2; i++) {
		dev_info_t *dip;
		pci_t *pci_p;

		/* Make sure PBM PCI node exists */
		pci_p = ecc_p->ecc_pci_cmn_p->pci_p[i];
		if (pci_p == NULL)
			continue;

		dip = pci_p->pci_dip;
		if (pci_pbm_err_handler(dip, &derr, (void *)pci_p,
		    PCI_ECC_CALL) == DDI_FM_FATAL)
			ret = DDI_FM_FATAL;
	}
	if (ret == DDI_FM_FATAL)
		return (DDI_FM_FATAL);
	else
		return (DDI_FM_NONFATAL);
}

/*
 * Function used to handle and log IO detected ECC errors, can be called by
 * ecc_intr and pci_err_callback(trap callback). Protected by pci_fm_mutex.
 */
int
ecc_err_handler(ecc_errstate_t *ecc_err_p)
{
	uint64_t pri_err, sec_err;
	ecc_intr_info_t *ecc_ii_p = &ecc_err_p->ecc_ii_p;
	ecc_t *ecc_p = ecc_ii_p->ecc_p;
	pci_t *pci_p;
	cb_t *cb_p;
	int fatal = 0;
	int nonfatal = 0;
	ecc_errstate_t ecc_sec_err;
	uint64_t sec_tmp;
	int i;
	uint64_t afsr_err[] = { COMMON_ECC_AFSR_E_PIO,
				COMMON_ECC_AFSR_E_DRD,
				COMMON_ECC_AFSR_E_DWR };


	ASSERT(MUTEX_HELD(&ecc_p->ecc_pci_cmn_p->pci_fm_mutex));

	pci_p = ecc_p->ecc_pci_cmn_p->pci_p[0];
	if (pci_p == NULL)
		pci_p = ecc_p->ecc_pci_cmn_p->pci_p[1];

	cb_p = ecc_p->ecc_pci_cmn_p->pci_common_cb_p;

	ecc_errstate_get(ecc_err_p);
	pri_err = (ecc_err_p->ecc_afsr >> COMMON_ECC_UE_AFSR_PE_SHIFT) &
	    COMMON_ECC_UE_AFSR_E_MASK;

	sec_err = (ecc_err_p->ecc_afsr >> COMMON_ECC_UE_AFSR_SE_SHIFT) &
	    COMMON_ECC_UE_AFSR_E_MASK;

	switch (ecc_ii_p->ecc_type) {
	case CBNINTR_UE:
		if (pri_err) {
			ecc_err_p->ecc_aflt.flt_synd =
			    pci_ecc_get_synd(ecc_err_p->ecc_afsr);
			ecc_err_p->ecc_pri = 1;
			pci_ecc_classify(pri_err, ecc_err_p);
			errorq_dispatch(pci_ecc_queue, (void *)ecc_err_p,
			    sizeof (ecc_errstate_t),
			    ecc_err_p->ecc_aflt.flt_panic);
		}
		if (sec_err) {
			ecc_sec_err = *ecc_err_p;
			ecc_sec_err.ecc_pri = 0;
			/*
			 * Secondary errors are cumulative so we need to loop
			 * through to capture them all.
			 */
			for (i = 0; i < 3; i++) {
				sec_tmp = sec_err & afsr_err[i];
				if (sec_tmp) {
					pci_ecc_classify(sec_tmp, &ecc_sec_err);
					ecc_ereport_post(pci_p->pci_dip,
					    &ecc_sec_err);
				}
			}
		}
		/*
		 * Check for PCI bus errors that may have resulted from or
		 * caused this UE.
		 */
		if (ecc_err_p->ecc_caller == PCI_ECC_CALL &&
		    ecc_pci_check(ecc_p, ecc_err_p->ecc_ena) == DDI_FM_FATAL)
			ecc_err_p->ecc_aflt.flt_panic = 1;

		if (ecc_err_p->ecc_aflt.flt_panic &&
		    ecc_err_p->ecc_aflt.flt_in_memory)
			panic_aflt = ecc_err_p->ecc_aflt;

		if (ecc_err_p->ecc_aflt.flt_panic) {
			/*
			 * Disable all further errors since this will be
			 * treated as a fatal error.
			 */
			(void) ecc_disable_nowait(ecc_p);
			fatal++;
		}
		break;

	case CBNINTR_CE:
		if (pri_err) {
			ecc_err_p->ecc_pri = 1;
			pci_ecc_classify(pri_err, ecc_err_p);
			ecc_err_p->ecc_aflt.flt_synd =
			    pci_ecc_get_synd(ecc_err_p->ecc_afsr);
			ce_scrub(&ecc_err_p->ecc_aflt);
			errorq_dispatch(pci_ecc_queue, (void *)ecc_err_p,
			    sizeof (ecc_errstate_t), ERRORQ_ASYNC);
			nonfatal++;
		}
		if (sec_err) {
			ecc_sec_err = *ecc_err_p;
			ecc_sec_err.ecc_pri = 0;
			/*
			 * Secondary errors are cumulative so we need to loop
			 * through to capture them all.
			 */
			for (i = 0; i < 3; i++) {
				sec_tmp = sec_err & afsr_err[i];
				if (sec_tmp) {
					pci_ecc_classify(sec_tmp, &ecc_sec_err);
					ecc_ereport_post(pci_p->pci_dip,
					    &ecc_sec_err);
				}
			}
			nonfatal++;
		}
		break;

	default:
		return (DDI_FM_OK);
	}
	/* Clear the errors */
	stdphysio(ecc_ii_p->ecc_afsr_pa, ecc_err_p->ecc_afsr);
	/*
	 * Clear the interrupt if called by ecc_intr and UE error or if called
	 * by ecc_intr and CE error and delayed CE interrupt handling is
	 * turned off.
	 */
	if ((ecc_err_p->ecc_caller == PCI_ECC_CALL &&
	    ecc_ii_p->ecc_type == CBNINTR_UE && !fatal) ||
	    (ecc_err_p->ecc_caller == PCI_ECC_CALL &&
	    ecc_ii_p->ecc_type == CBNINTR_CE && !ecc_ce_delayed))
		cb_clear_nintr(cb_p, ecc_ii_p->ecc_type);
	if (!fatal && !nonfatal)
		return (DDI_FM_OK);
	else if (fatal)
		return (DDI_FM_FATAL);
	return (DDI_FM_NONFATAL);
}

/*
 * Called from ecc_err_drain below for CBINTR_CE case.
 */
static int
ecc_err_cexdiag(ecc_errstate_t *ecc_err, errorq_elem_t *eqep)
{
	struct async_flt *ecc = &ecc_err->ecc_aflt;
	uint64_t errors;

	if (page_retire_check(ecc->flt_addr, &errors) == EINVAL) {
		CE_XDIAG_SETSKIPCODE(ecc->flt_disp, CE_XDIAG_SKIP_NOPP);
		return (0);
	} else if (errors != PR_OK) {
		CE_XDIAG_SETSKIPCODE(ecc->flt_disp, CE_XDIAG_SKIP_PAGEDET);
		return (0);
	} else {
		return (ce_scrub_xdiag_recirc(ecc, pci_ecc_queue, eqep,
		    offsetof(ecc_errstate_t, ecc_aflt)));
	}
}

/*
 * Function used to drain pci_ecc_queue, either during panic or after softint
 * is generated, to log IO detected ECC errors.
 */
/*ARGSUSED*/
void
ecc_err_drain(void *not_used, ecc_errstate_t *ecc_err, errorq_elem_t *eqep)
{
	struct async_flt *ecc = &ecc_err->ecc_aflt;
	pci_t *pci_p = ecc_err->ecc_p->ecc_pci_cmn_p->pci_p[0];
	int ecc_type = ecc_err->ecc_ii_p.ecc_type;

	if (pci_p == NULL)
		pci_p = ecc_err->ecc_p->ecc_pci_cmn_p->pci_p[1];

	if (ecc->flt_class == RECIRC_BUS_FAULT) {
		/*
		 * Perform any additional actions that occur after the
		 * ecc_err_cexdiag below and post the ereport.
		 */
		ecc->flt_class = BUS_FAULT;
		ecc_err->ecc_err_type = flt_to_error_type(ecc);
		ecc_ereport_post(pci_p->pci_dip, ecc_err);
		return;
	}

	ecc_cpu_call(ecc, ecc_err->ecc_unum, (ecc_type == CBNINTR_UE) ?
	    ECC_IO_UE : ECC_IO_CE);

	switch (ecc_type) {
	case CBNINTR_UE:
		if (ecc_err->ecc_pg_ret == 1) {
			(void) page_retire(ecc->flt_addr, PR_UE);
		}
		ecc_err->ecc_err_type = flt_to_error_type(ecc);
		break;

	case CBNINTR_CE:
		/*
		 * Setup timeout (if CE detected via interrupt) to
		 * re-enable CE interrupts if no more CEs are detected.
		 * This is to protect against CE storms.
		 */
		if (ecc_ce_delayed &&
		    ecc_err->ecc_caller == PCI_ECC_CALL &&
		    ecc_err->ecc_p->ecc_to_id == 0) {
			ecc_err->ecc_p->ecc_to_id = timeout(ecc_delayed_ce,
			    (void *)ecc_err->ecc_p,
			    drv_usectohz((clock_t)ecc_ce_delay_secs *
			    MICROSEC));
		}

		/* ecc_err_cexdiag returns nonzero to recirculate */
		if (CE_XDIAG_EXT_ALG_APPLIED(ecc->flt_disp) &&
		    ecc_err_cexdiag(ecc_err, eqep))
			return;
		ecc_err->ecc_err_type = flt_to_error_type(ecc);
		break;
	}

	ecc_ereport_post(pci_p->pci_dip, ecc_err);
}

static void
ecc_delayed_ce(void *arg)
{
	ecc_t *ecc_p = (ecc_t *)arg;
	pci_common_t *cmn_p;
	cb_t *cb_p;

	ASSERT(ecc_p);

	cmn_p = ecc_p->ecc_pci_cmn_p;
	cb_p = cmn_p->pci_common_cb_p;
	/*
	 * If no more CE errors are found then enable interrupts(by
	 * clearing the previous interrupt), else send in for logging
	 * and the timeout should be set again.
	 */
	ecc_p->ecc_to_id = 0;
	if (!((ecc_read_afsr(&ecc_p->ecc_ce) >>
	    COMMON_ECC_UE_AFSR_PE_SHIFT) & COMMON_ECC_UE_AFSR_E_MASK)) {
		cb_clear_nintr(cb_p, ecc_p->ecc_ce.ecc_type);
	} else {
		ecc_errstate_t ecc_err;

		bzero(&ecc_err, sizeof (ecc_errstate_t));
		ecc_err.ecc_ena = fm_ena_generate(0, FM_ENA_FMT1);
		ecc_err.ecc_ii_p = ecc_p->ecc_ce;
		ecc_err.ecc_p = ecc_p;
		ecc_err.ecc_caller = PCI_ECC_CALL;

		mutex_enter(&cmn_p->pci_fm_mutex);
		(void) ecc_err_handler(&ecc_err);
		mutex_exit(&cmn_p->pci_fm_mutex);
	}
}

/*
 * Function used to post IO detected ECC ereports.
 */
static void
ecc_ereport_post(dev_info_t *dip, ecc_errstate_t *ecc_err)
{
	char buf[FM_MAX_CLASS], dev_path[MAXPATHLEN], *ptr;
	struct i_ddi_fmhdl *fmhdl = DEVI(dip)->devi_fmhdl;
	nvlist_t *ereport, *detector;
	nv_alloc_t *nva;
	errorq_elem_t *eqep;

	/*
	 * We do not use ddi_fm_ereport_post because we need to set a
	 * special detector here. Since we do not have a device path for
	 * the bridge chip we use what we think it should be to aid in
	 * diagnosis. This path fmri is created by pci_fmri_create()
	 * during initialization.
	 */
	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s.%s", DDI_IO_CLASS,
	    ecc_err->ecc_bridge_type, ecc_err->ecc_aflt.flt_erpt_class);

	ecc_err->ecc_ena = ecc_err->ecc_ena ? ecc_err->ecc_ena :
	    fm_ena_generate(0, FM_ENA_FMT1);

	eqep = errorq_reserve(fmhdl->fh_errorq);
	if (eqep == NULL)
		return;

	ereport = errorq_elem_nvl(fmhdl->fh_errorq, eqep);
	nva = errorq_elem_nva(fmhdl->fh_errorq, eqep);
	detector = fm_nvlist_create(nva);

	ASSERT(ereport);
	ASSERT(nva);
	ASSERT(detector);

	ddi_pathname(dip, dev_path);
	ptr = strrchr(dev_path, (int)',');

	if (ptr)
		*ptr = '\0';

	fm_fmri_dev_set(detector, FM_DEV_SCHEME_VERSION, NULL, dev_path,
	    NULL, NULL);

	if (ecc_err->ecc_pri) {
		if ((ecc_err->ecc_fmri = fm_nvlist_create(nva)) != NULL) {
			char sid[DIMM_SERIAL_ID_LEN] = "";
			uint64_t offset = (uint64_t)-1;
			int len;
			int ret;

			ret = cpu_get_mem_sid(ecc_err->ecc_unum, sid,
			    DIMM_SERIAL_ID_LEN, &len);

			if (ret == 0) {
				(void) cpu_get_mem_offset(
				    ecc_err->ecc_aflt.flt_addr, &offset);
			}

			fm_fmri_mem_set(ecc_err->ecc_fmri,
			    FM_MEM_SCHEME_VERSION, NULL, ecc_err->ecc_unum,
			    (ret == 0) ? sid : NULL, offset);
		}
		fm_ereport_set(ereport, FM_EREPORT_VERSION, buf,
		    ecc_err->ecc_ena, detector,
		    PCI_ECC_AFSR, DATA_TYPE_UINT64, ecc_err->ecc_afsr,
		    PCI_ECC_AFAR, DATA_TYPE_UINT64, ecc_err->ecc_aflt.flt_addr,
		    PCI_ECC_CTRL, DATA_TYPE_UINT64, ecc_err->ecc_ctrl,
		    PCI_ECC_SYND, DATA_TYPE_UINT16, ecc_err->ecc_aflt.flt_synd,
		    PCI_ECC_TYPE, DATA_TYPE_STRING, ecc_err->ecc_err_type,
		    PCI_ECC_DISP, DATA_TYPE_UINT64, ecc_err->ecc_aflt.flt_disp,
		    PCI_ECC_RESOURCE, DATA_TYPE_NVLIST, ecc_err->ecc_fmri,
		    NULL);
	} else {
		fm_ereport_set(ereport, FM_EREPORT_VERSION, buf,
		    ecc_err->ecc_ena, detector,
		    PCI_ECC_AFSR, DATA_TYPE_UINT64, ecc_err->ecc_afsr,
		    PCI_ECC_CTRL, DATA_TYPE_UINT64, ecc_err->ecc_ctrl,
		    NULL);
	}
	errorq_commit(fmhdl->fh_errorq, eqep, ERRORQ_ASYNC);
}
