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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CMU-CH ECC support
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/intr.h>
#include <sys/async.h>
#include <sys/ddi_impldefs.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/pci.h>
#include <sys/fm/io/sun4upci.h>
#include <sys/fm/io/ddi.h>
#include <sys/pcicmu/pcicmu.h>

static void pcmu_ecc_disable(pcmu_ecc_t *, int);
static uint64_t pcmu_ecc_read_afsr(pcmu_ecc_intr_info_t *);
static void pcmu_ecc_ereport_post(dev_info_t *dip,
    pcmu_ecc_errstate_t *ecc_err);

clock_t pcmu_pecc_panic_delay = 200;

void
pcmu_ecc_create(pcmu_t *pcmu_p)
{
	uint64_t pcb_base_pa = pcmu_p->pcmu_cb_p->pcb_base_pa;
	pcmu_ecc_t *pecc_p;
	/* LINTED variable */
	dev_info_t *dip = pcmu_p->pcmu_dip;

	pecc_p = (pcmu_ecc_t *)kmem_zalloc(sizeof (pcmu_ecc_t), KM_SLEEP);
	pecc_p->pecc_pcmu_p = pcmu_p;
	pcmu_p->pcmu_pecc_p = pecc_p;

	pecc_p->pecc_ue.pecc_p = pecc_p;
	pecc_p->pecc_ue.pecc_type = CBNINTR_UE;

	pcmu_ecc_setup(pecc_p);

	/*
	 * Determine the virtual addresses of the streaming cache
	 * control/status and flush registers.
	 */
	pecc_p->pecc_csr_pa = pcb_base_pa + PCMU_ECC_CSR_OFFSET;
	pecc_p->pecc_ue.pecc_afsr_pa = pcb_base_pa + PCMU_UE_AFSR_OFFSET;
	pecc_p->pecc_ue.pecc_afar_pa = pcb_base_pa + PCMU_UE_AFAR_OFFSET;

	PCMU_DBG1(PCMU_DBG_ATTACH, dip, "pcmu_ecc_create: csr=%x\n",
	    pecc_p->pecc_csr_pa);
	PCMU_DBG2(PCMU_DBG_ATTACH, dip,
	    "pcmu_ecc_create: ue_afsr=%x, ue_afar=%x\n",
	    pecc_p->pecc_ue.pecc_afsr_pa, pecc_p->pecc_ue.pecc_afar_pa);

	pcmu_ecc_configure(pcmu_p);

	/*
	 * Register routines to be called from system error handling code.
	 */
	bus_func_register(BF_TYPE_ERRDIS,
	    (busfunc_t)pcmu_ecc_disable_nowait, pecc_p);
}

int
pcmu_ecc_register_intr(pcmu_t *pcmu_p)
{
	pcmu_ecc_t *pecc_p = pcmu_p->pcmu_pecc_p;
	int ret;

	/*
	 * Install the UE error interrupt handlers.
	 */
	ret = pcmu_ecc_add_intr(pcmu_p, CBNINTR_UE, &pecc_p->pecc_ue);
	return (ret);
}

void
pcmu_ecc_destroy(pcmu_t *pcmu_p)
{
	pcmu_ecc_t *pecc_p = pcmu_p->pcmu_pecc_p;

	PCMU_DBG0(PCMU_DBG_DETACH, pcmu_p->pcmu_dip, "pcmu_ecc_destroy:\n");

	/*
	 * Disable UE ECC error interrupts.
	 */
	pcmu_ecc_disable_wait(pecc_p);

	/*
	 * Remove the ECC interrupt handlers.
	 */
	pcmu_ecc_rem_intr(pcmu_p, CBNINTR_UE, &pecc_p->pecc_ue);

	/*
	 * Unregister our error handling functions.
	 */
	bus_func_unregister(BF_TYPE_ERRDIS,
	    (busfunc_t)pcmu_ecc_disable_nowait, pecc_p);
	/*
	 * If a timer has been set, unset it.
	 */
	(void) untimeout(pecc_p->pecc_tout_id);
	kmem_free(pecc_p, sizeof (pcmu_ecc_t));
	pcmu_p->pcmu_pecc_p = NULL;
}

void
pcmu_ecc_configure(pcmu_t *pcmu_p)
{
	pcmu_ecc_t *pecc_p = pcmu_p->pcmu_pecc_p;
	uint64_t l;
	/* LINTED variable */
	dev_info_t *dip = pcmu_p->pcmu_dip;

	/*
	 * Clear any pending ECC errors.
	 */
	PCMU_DBG0(PCMU_DBG_ATTACH, dip,
	    "pcmu_ecc_configure: clearing UE errors\n");
	l = (PCMU_ECC_UE_AFSR_E_MASK << PCMU_ECC_UE_AFSR_PE_SHIFT) |
	    (PCMU_ECC_UE_AFSR_E_MASK << PCMU_ECC_UE_AFSR_SE_SHIFT);
	stdphysio(pecc_p->pecc_ue.pecc_afsr_pa, l);

	/*
	 * Enable ECC error detections via the control register.
	 */
	PCMU_DBG0(PCMU_DBG_ATTACH, dip,
	    "pcmu_ecc_configure: enabling UE detection\n");
	l = PCMU_ECC_CTRL_ECC_EN;
	if (ecc_error_intr_enable)
		l |= PCMU_ECC_CTRL_UE_INTEN;
	stdphysio(pecc_p->pecc_csr_pa, l);
}

void
pcmu_ecc_enable_intr(pcmu_t *pcmu_p)
{
	pcmu_cb_enable_nintr(pcmu_p, CBNINTR_UE);
}

void
pcmu_ecc_disable_wait(pcmu_ecc_t *pecc_p)
{
	pcmu_ecc_disable(pecc_p, PCMU_IB_INTR_WAIT);
}

uint_t
pcmu_ecc_disable_nowait(pcmu_ecc_t *pecc_p)
{
	pcmu_ecc_disable(pecc_p, PCMU_IB_INTR_NOWAIT);
	return (BF_NONE);
}

static void
pcmu_ecc_disable(pcmu_ecc_t *pecc_p, int wait)
{
	pcmu_cb_t *pcb_p = pecc_p->pecc_pcmu_p->pcmu_cb_p;
	uint64_t csr_pa = pecc_p->pecc_csr_pa;
	uint64_t csr = lddphysio(csr_pa);

	csr &= ~(PCMU_ECC_CTRL_UE_INTEN);
	stdphysio(csr_pa, csr);
	pcmu_cb_disable_nintr(pcb_p, CBNINTR_UE, wait);
}

/*
 * I/O ECC error handling:
 *
 * Below are the generic functions that handle detected ECC errors.
 *
 * The registered interrupt handler is pcmu_ecc_intr(), it's function
 * is to receive the error, capture some state, and pass that on to
 * the pcmu_ecc_err_handler() for reporting purposes.
 *
 * pcmu_ecc_err_handler() gathers more state(via pcmu_ecc_errstate_get)
 * and attempts to handle and report the error. pcmu_ecc_err_handler()
 * must determine if we need to panic due to this error (via
 * pcmu_ecc_classify, which also decodes the * ECC afsr), and if any
 * side effects exist that may have caused or are due * to this error.
 * PBM errors related to the ECC error may exist, to report
 * them we call pcmu_pbm_err_handler().
 *
 * To report the error we must also get the syndrome and unum, which can not
 * be done in high level interrupted context. Therefore we have an error
 * queue(pcmu_ecc_queue) which we dispatch errors to, to report the errors
 * (pcmu_ecc_err_drain()).
 *
 * pcmu_ecc_err_drain() will be called when either the softint is triggered
 * or the system is panicing. Either way it will gather more information
 * about the error from the CPU(via ecc_cpu_call(), ecc.c), attempt to
 * retire the faulty page(if error is a UE), and report the detected error.
 *
 */

/*
 * Function used to get ECC AFSR register
 */
static uint64_t
pcmu_ecc_read_afsr(pcmu_ecc_intr_info_t *ecc_ii_p)
{
	ASSERT(ecc_ii_p->pecc_type == CBNINTR_UE);
	return (lddphysio(ecc_ii_p->pecc_afsr_pa));
}

/*
 * IO detected ECC error interrupt handler, calls pcmu_ecc_err_handler to post
 * error reports and handle the interrupt. Re-entry into pcmu_ecc_err_handler
 * is protected by the per-chip mutex pcmu_err_mutex.
 */
uint_t
pcmu_ecc_intr(caddr_t a)
{
	pcmu_ecc_intr_info_t *ecc_ii_p = (pcmu_ecc_intr_info_t *)a;
	pcmu_ecc_t *pecc_p = ecc_ii_p->pecc_p;
	pcmu_t *pcmu_p = pecc_p->pecc_pcmu_p;
	pcmu_ecc_errstate_t ecc_err;
	int ret = DDI_FM_OK;

	bzero(&ecc_err, sizeof (pcmu_ecc_errstate_t));
	ecc_err.ecc_ena = fm_ena_generate(0, FM_ENA_FMT1); /* RAGS */
	ecc_err.ecc_ii_p = *ecc_ii_p;
	ecc_err.pecc_p = pecc_p;
	ecc_err.ecc_caller = PCI_ECC_CALL;

	mutex_enter(&pcmu_p->pcmu_err_mutex);
	ret = pcmu_ecc_err_handler(&ecc_err);
	mutex_exit(&pcmu_p->pcmu_err_mutex);
	if (ret == DDI_FM_FATAL) {
		/*
		 * Need delay here to allow CPUs to handle related traps,
		 * such as FRUs for USIIIi systems.
		 */
		DELAY(pcmu_pecc_panic_delay);
		cmn_err(CE_PANIC, "Fatal PCI UE Error");
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * Function used to gather IO ECC error state.
 */
static void
pcmu_ecc_errstate_get(pcmu_ecc_errstate_t *ecc_err_p)
{
	pcmu_ecc_t *pecc_p;
	uint_t bus_id;

	ASSERT(ecc_err_p);

	pecc_p = ecc_err_p->ecc_ii_p.pecc_p;
	bus_id = pecc_p->pecc_pcmu_p->pcmu_id;

	ASSERT(MUTEX_HELD(&pecc_p->pecc_pcmu_p->pcmu_err_mutex));
	/*
	 * Read the fault registers.
	 */
	ecc_err_p->ecc_afsr = pcmu_ecc_read_afsr(&ecc_err_p->ecc_ii_p);
	ecc_err_p->ecc_afar = lddphysio(ecc_err_p->ecc_ii_p.pecc_afar_pa);

	ecc_err_p->ecc_offset = ((ecc_err_p->ecc_afsr &
	    ecc_err_p->ecc_ii_p.pecc_offset_mask) >>
	    ecc_err_p->ecc_ii_p.pecc_offset_shift) <<
	    ecc_err_p->ecc_ii_p.pecc_size_log2;

	ecc_err_p->ecc_aflt.flt_id = gethrtime();
	ecc_err_p->ecc_aflt.flt_stat = ecc_err_p->ecc_afsr;
	ecc_err_p->ecc_aflt.flt_addr = P2ALIGN(ecc_err_p->ecc_afar, 64) +
	    ecc_err_p->ecc_offset;
	ecc_err_p->ecc_aflt.flt_bus_id = bus_id;
	ecc_err_p->ecc_aflt.flt_inst = 0;
	ecc_err_p->ecc_aflt.flt_status = ECC_IOBUS;
	ecc_err_p->ecc_aflt.flt_in_memory = 0;
	ecc_err_p->ecc_aflt.flt_class = BUS_FAULT;
}

/*
 * pcmu_ecc_check: Called by pcmu_ecc_err_handler() this function is responsible
 * for calling pcmu_pbm_err_handler() and calling their children error
 * handlers(via ndi_fm_handler_dispatch()).
 */
static int
pcmu_ecc_check(pcmu_ecc_t *pecc_p, uint64_t fme_ena)
{
	ddi_fm_error_t derr;
	int ret;
	pcmu_t *pcmu_p;


	ASSERT(MUTEX_HELD(&pecc_p->pecc_pcmu_p->pcmu_err_mutex));

	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fme_ena;
	ret = DDI_FM_NONFATAL;

	/*
	 * Need to report any PBM errors which may have caused or
	 * resulted from this error.
	 */
	pcmu_p = pecc_p->pecc_pcmu_p;
	if (pcmu_pbm_err_handler(pcmu_p->pcmu_dip, &derr, (void *)pcmu_p,
	    PCI_ECC_CALL) == DDI_FM_FATAL)
		ret = DDI_FM_FATAL;

	if (ret == DDI_FM_FATAL)
		return (DDI_FM_FATAL);
	else
		return (DDI_FM_NONFATAL);
}

/*
 * Function used to handle and log IO detected ECC errors, can be called by
 * pcmu_ecc_intr and pcmu_err_callback(trap callback). Protected by
 * pcmu_err_mutex.
 */
int
pcmu_ecc_err_handler(pcmu_ecc_errstate_t *ecc_err_p)
{
	/* LINTED variable */
	uint64_t pri_err, sec_err;
	pcmu_ecc_intr_info_t *ecc_ii_p = &ecc_err_p->ecc_ii_p;
	pcmu_ecc_t *pecc_p = ecc_ii_p->pecc_p;
	/* LINTED variable */
	pcmu_t *pcmu_p;
	pcmu_cb_t *pcb_p;
	int fatal = 0;
	int nonfatal = 0;

	ASSERT(MUTEX_HELD(&pecc_p->pecc_pcmu_p->pcmu_err_mutex));

	pcmu_p = pecc_p->pecc_pcmu_p;
	pcb_p = pecc_p->pecc_pcmu_p->pcmu_cb_p;

	pcmu_ecc_errstate_get(ecc_err_p);
	pri_err = (ecc_err_p->ecc_afsr >> PCMU_ECC_UE_AFSR_PE_SHIFT) &
		PCMU_ECC_UE_AFSR_E_MASK;

	sec_err = (ecc_err_p->ecc_afsr >> PCMU_ECC_UE_AFSR_SE_SHIFT) &
		PCMU_ECC_UE_AFSR_E_MASK;

	switch (ecc_ii_p->pecc_type) {
	case CBNINTR_UE:
		if (pri_err) {
			ecc_err_p->ecc_aflt.flt_synd = 0;
			ecc_err_p->pecc_pri = 1;
			pcmu_ecc_classify(pri_err, ecc_err_p);
			errorq_dispatch(pcmu_ecc_queue, (void *)ecc_err_p,
				sizeof (pcmu_ecc_errstate_t),
				ecc_err_p->ecc_aflt.flt_panic);
		}
		if (sec_err) {
			pcmu_ecc_errstate_t ecc_sec_err;

			ecc_sec_err = *ecc_err_p;
			ecc_sec_err.pecc_pri = 0;
			pcmu_ecc_classify(sec_err, &ecc_sec_err);
			pcmu_ecc_ereport_post(pcmu_p->pcmu_dip,
					&ecc_sec_err);
		}
		/*
		 * Check for PCI bus errors that may have resulted from or
		 * caused this UE.
		 */
		if (ecc_err_p->ecc_caller == PCI_ECC_CALL &&
		    pcmu_ecc_check(pecc_p, ecc_err_p->ecc_ena) == DDI_FM_FATAL)
			ecc_err_p->ecc_aflt.flt_panic = 1;

		if (ecc_err_p->ecc_aflt.flt_panic) {
			/*
			 * Disable all further errors since this will be
			 * treated as a fatal error.
			 */
			(void) pcmu_ecc_disable_nowait(pecc_p);
			fatal++;
		}
		break;

	default:
		return (DDI_FM_OK);
	}
	/* Clear the errors */
	stdphysio(ecc_ii_p->pecc_afsr_pa, ecc_err_p->ecc_afsr);
	/*
	 * Clear the interrupt if called by pcmu_ecc_intr and UE error
	 * or if called by pcmu_ecc_intr and CE error and delayed CE
	 * interrupt handling is turned off.
	 */
	if (ecc_err_p->ecc_caller == PCI_ECC_CALL &&
	    ecc_ii_p->pecc_type == CBNINTR_UE && !fatal)
		pcmu_cb_clear_nintr(pcb_p, ecc_ii_p->pecc_type);
	if (!fatal && !nonfatal)
		return (DDI_FM_OK);
	else if (fatal)
		return (DDI_FM_FATAL);
	return (DDI_FM_NONFATAL);
}

/*
 * Function used to drain pcmu_ecc_queue, either during panic or after softint
 * is generated, to log IO detected ECC errors.
 */
/* ARGSUSED */
void
pcmu_ecc_err_drain(void *not_used, pcmu_ecc_errstate_t *ecc_err)
{
	struct async_flt *ecc = &ecc_err->ecc_aflt;
	pcmu_t *pcmu_p = ecc_err->pecc_p->pecc_pcmu_p;

	ecc_cpu_call(ecc, ecc_err->ecc_unum, ECC_IO_UE);
	ecc_err->ecc_err_type = "U";
	pcmu_ecc_ereport_post(pcmu_p->pcmu_dip, ecc_err);
}

/*
 * Function used to post IO detected ECC ereports.
 */
static void
pcmu_ecc_ereport_post(dev_info_t *dip, pcmu_ecc_errstate_t *ecc_err)
{
	char *aux_msg;
	pcmu_t *pcmu_p;
	int instance = ddi_get_instance(dip);

	pcmu_p = get_pcmu_soft_state(instance);
	if (ecc_err->pecc_pri) {
		aux_msg = "PIO primary uncorrectable error";
	} else {
		aux_msg = "PIO secondary uncorrectable error";
	}
	cmn_err(CE_WARN, "%s %s: %s %s=0x%lx, %s=0x%lx, %s=0x%x",
		(pcmu_p->pcmu_pcbm_p)->pcbm_nameinst_str,
		(pcmu_p->pcmu_pcbm_p)->pcbm_nameaddr_str,
		aux_msg, PCI_ECC_AFSR, ecc_err->ecc_afsr,
		PCI_ECC_AFAR, ecc_err->ecc_aflt.flt_addr,
		"portid", ecc_err->ecc_aflt.flt_bus_id);
}
