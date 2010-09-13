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
 * CMU-CH PBM implementation:
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
#include <sys/machsystm.h>
#include <sys/async.h>
#include <sys/ddi_impldefs.h>
#include <sys/ontrap.h>
#include <sys/pcicmu/pcicmu.h>
#include <sys/membar.h>
#include <sys/ivintr.h>

static uint_t pcmu_pbm_error_intr(caddr_t a);

/* The nexus interrupt priority values */
int pcmu_pil[] = {14, 14, 14, 14, 14, 14};

void
pcmu_pbm_create(pcmu_t *pcmu_p)
{
	pcmu_pbm_t *pcbm_p;
	int len;
	dev_info_t *dip = pcmu_p->pcmu_dip;

	/*
	 * Allocate a state structure for the PBM and cross-link it
	 * to its per pci node state structure.
	 */
	pcbm_p = (pcmu_pbm_t *)kmem_zalloc(sizeof (pcmu_pbm_t), KM_SLEEP);
	pcmu_p->pcmu_pcbm_p = pcbm_p;
	pcbm_p->pcbm_pcmu_p = pcmu_p;

	len = snprintf(pcbm_p->pcbm_nameinst_str,
	    sizeof (pcbm_p->pcbm_nameinst_str), "%s%d", NAMEINST(dip));
	pcbm_p->pcbm_nameaddr_str = pcbm_p->pcbm_nameinst_str + ++len;
	(void) snprintf(pcbm_p->pcbm_nameaddr_str,
	    sizeof (pcbm_p->pcbm_nameinst_str) - len, "%s@%s", NAMEADDR(dip));

	pcmu_pbm_setup(pcbm_p);

	PCMU_DBG4(PCMU_DBG_ATTACH, dip,
	    "pcmu_pbm_create: ctrl=%x, afsr=%x, afar=%x, diag=%x\n",
	    pcbm_p->pcbm_ctrl_reg, pcbm_p->pcbm_async_flt_status_reg,
	    pcbm_p->pcbm_async_flt_addr_reg, pcbm_p->pcbm_diag_reg);
	PCMU_DBG1(PCMU_DBG_ATTACH, dip, "pcmu_pbm_create: conf=%x\n",
	    pcbm_p->pcbm_config_header);

	/*
	 * Register a function to disable pbm error interrupts during a panic.
	 */
	bus_func_register(BF_TYPE_ERRDIS,
	    (busfunc_t)pcmu_pbm_disable_errors, pcbm_p);

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
		    (caddr_t)pcmu_pil, sizeof (pcmu_pil));
	}
	pcmu_pbm_configure(pcbm_p);
}

int
pcmu_pbm_register_intr(pcmu_pbm_t *pcbm_p)
{
	pcmu_t		*pcmu_p = pcbm_p->pcbm_pcmu_p;
	uint32_t	mondo;
	int		r = DDI_SUCCESS;

	pcmu_ib_nintr_clear(pcmu_p->pcmu_ib_p, pcmu_p->pcmu_inos[CBNINTR_PBM]);

	/*
	 * Install the PCI error interrupt handler.
	 */
	mondo = PCMU_IB_INO_TO_MONDO(pcmu_p->pcmu_ib_p,
	    pcmu_p->pcmu_inos[CBNINTR_PBM]);

	VERIFY(add_ivintr(mondo, pcmu_pil[CBNINTR_PBM],
	    (intrfunc)pcmu_pbm_error_intr, (caddr_t)pcmu_p, NULL, NULL) == 0);

	pcbm_p->pcbm_iblock_cookie = (void *)(uintptr_t)pcmu_pil[CBNINTR_PBM];

	/*
	 * Create the pokefault mutex at the PIL below the error interrupt.
	 */

	mutex_init(&pcbm_p->pcbm_pokeflt_mutex, NULL, MUTEX_DRIVER,
	    (void *)(uintptr_t)ipltospl(spltoipl(
	    (int)(uintptr_t)pcbm_p->pcbm_iblock_cookie) - 1));

	return (PCMU_ATTACH_RETCODE(PCMU_PBM_OBJ, PCMU_OBJ_INTR_ADD, r));
}

void
pcmu_pbm_destroy(pcmu_t *pcmu_p)
{
	pcmu_pbm_t		*pcbm_p = pcmu_p->pcmu_pcbm_p;
	pcmu_ib_t		*pib_p = pcmu_p->pcmu_ib_p;
	uint32_t	mondo;

	PCMU_DBG0(PCMU_DBG_DETACH, pcmu_p->pcmu_dip, "pcmu_pbm_destroy:\n");

	mondo = PCMU_IB_INO_TO_MONDO(pcmu_p->pcmu_ib_p,
	    pcmu_p->pcmu_inos[CBNINTR_PBM]);

	/*
	 * Free the pokefault mutex.
	 */
	mutex_destroy(&pcbm_p->pcbm_pokeflt_mutex);

	/*
	 * Remove the error interrupt.
	 */
	intr_dist_rem(pcmu_pbm_intr_dist, pcbm_p);
	pcmu_ib_intr_disable(pib_p,
	    pcmu_p->pcmu_inos[CBNINTR_PBM], PCMU_IB_INTR_WAIT);

	VERIFY(rem_ivintr(mondo, pcmu_pil[CBNINTR_PBM]) == 0);

	/*
	 * Remove the error disable function.
	 */
	bus_func_unregister(BF_TYPE_ERRDIS,
	    (busfunc_t)pcmu_pbm_disable_errors, pcbm_p);

	pcmu_pbm_teardown(pcbm_p);

	/*
	 * Free the pbm state structure.
	 */
	kmem_free(pcbm_p, sizeof (pcmu_pbm_t));
	pcmu_p->pcmu_pcbm_p = NULL;
}

static uint_t
pcmu_pbm_error_intr(caddr_t a)
{
	pcmu_t *pcmu_p = (pcmu_t *)a;
	pcmu_pbm_t *pcbm_p = pcmu_p->pcmu_pcbm_p;
	ddi_fm_error_t derr;
	int err = DDI_FM_OK;
	on_trap_data_t *otp = pcbm_p->pcbm_ontrap_data;

	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	mutex_enter(&pcmu_p->pcmu_err_mutex);
	if ((otp != NULL) && (otp->ot_prot & OT_DATA_ACCESS)) {
		/*
		 * ddi_poke protection, check nexus and children for
		 * expected errors.
		 */
		otp->ot_trap |= OT_DATA_ACCESS;
		membar_sync();
		derr.fme_flag = DDI_FM_ERR_POKE;
		err = pcmu_pbm_err_handler(pcmu_p->pcmu_dip, &derr,
		    (void *)pcmu_p, PCI_INTR_CALL);
	} else if (pcmu_check_error(pcmu_p) != 0) {
		/*
		 * unprotected error, check for all errors.
		 */
		if (pcmu_errtrig_pa) {
			(void) ldphysio(pcmu_errtrig_pa);
		}
		derr.fme_flag = DDI_FM_ERR_UNEXPECTED;
		err = pcmu_pbm_err_handler(pcmu_p->pcmu_dip, &derr,
		    (void *)pcmu_p, PCI_INTR_CALL);
	}

	if (err == DDI_FM_FATAL) {
		if (pcmu_panic_on_fatal_errors) {
			mutex_exit(&pcmu_p->pcmu_err_mutex);
			cmn_err(CE_PANIC, "%s-%d: Fatal PCI bus error(s)\n",
			    ddi_driver_name(pcmu_p->pcmu_dip),
			    ddi_get_instance(pcmu_p->pcmu_dip));
		}
	}

	mutex_exit(&pcmu_p->pcmu_err_mutex);
	pcmu_ib_nintr_clear(pcmu_p->pcmu_ib_p, pcmu_p->pcmu_inos[CBNINTR_PBM]);
	return (DDI_INTR_CLAIMED);
}

void
pcmu_pbm_suspend(pcmu_pbm_t *pcbm_p)
{
	pcmu_t *pcmu_p = pcbm_p->pcbm_pcmu_p;
	pcmu_ib_ino_t ino = pcmu_p->pcmu_inos[CBNINTR_PBM];
	pcbm_p->pcbm_imr_save = *ib_intr_map_reg_addr(pcmu_p->pcmu_ib_p, ino);
}

void
pcmu_pbm_resume(pcmu_pbm_t *pcbm_p)
{
	pcmu_t *pcmu_p = pcbm_p->pcbm_pcmu_p;
	pcmu_ib_ino_t ino = pcmu_p->pcmu_inos[CBNINTR_PBM];

	pcmu_ib_nintr_clear(pcmu_p->pcmu_ib_p, ino);
	*ib_intr_map_reg_addr(pcmu_p->pcmu_ib_p, ino) = pcbm_p->pcbm_imr_save;
}

void
pcmu_pbm_intr_dist(void *arg)
{
	pcmu_pbm_t *pcbm_p = (pcmu_pbm_t *)arg;
	pcmu_t *pcmu_p = pcbm_p->pcbm_pcmu_p;
	pcmu_ib_t *pib_p = pcmu_p->pcmu_ib_p;
	pcmu_ib_ino_t ino =
	    PCMU_IB_MONDO_TO_INO(pcmu_p->pcmu_inos[CBNINTR_PBM]);
	mutex_enter(&pib_p->pib_intr_lock);
	pcmu_ib_intr_dist_nintr(pib_p, ino, ib_intr_map_reg_addr(pib_p, ino));
	mutex_exit(&pib_p->pib_intr_lock);
}

/*
 * Function used to log PBM AFSR register bits and to lookup and fault
 * handle associated with PBM AFAR register. Called by
 * pcmu_pbm_err_handler with pcmu_err_mutex held.
 */
int
pcmu_pbm_afsr_report(dev_info_t *dip, uint64_t fme_ena,
    pcmu_pbm_errstate_t *pbm_err_p)
{
	int fatal = 0;
	/* LINTED variable */
	pcmu_t *pcmu_p = get_pcmu_soft_state(ddi_get_instance(dip));

	ASSERT(MUTEX_HELD(&pcmu_p->pcmu_err_mutex));

	pbm_err_p->pcbm_pri = PBM_PRIMARY;
	(void) pcmu_pbm_classify(pbm_err_p);

	/*
	 * We are currently not dealing with the multiple error
	 * case, for any secondary errors we will panic.
	 */
	pbm_err_p->pcbm_pri = PBM_SECONDARY;
	if (pcmu_pbm_classify(pbm_err_p)) {
		fatal++;
		pcmu_pbm_ereport_post(dip, fme_ena, pbm_err_p);
	}

	if (fatal) {
		return (DDI_FM_FATAL);
	}
	return (DDI_FM_NONFATAL);
}
