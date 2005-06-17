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
 * PX fault and error handling routines.
 * error_attach and error_detach
 * error interrupt registration
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ivintr.h>
#include <sys/machsystm.h>	/* intr_dist_add */
#include <sys/ddi_impldefs.h>
#include <px_regs.h>		/* XXX - remove it later */
#include "px_obj.h"

/*LINTLIBRARY*/

px_fh_desc_t px_fhd_tbl[] = {
	{ M4(tlu_ue),	TR4(TLU_UNCORRECTABLE_ERROR),	   "TLU UE"	   },
	{ M4(tlu_ce),	TR4(TLU_CORRECTABLE_ERROR),	   "TLU CE"	   },
	{ M4(tlu_oe),	TR4(TLU_OTHER_EVENT),		   "TLU OE"	   },
	{ M4(mmu),	R4(MMU),			   "MMU Error"	   },
	{ M4(imu),	R4(IMU),			   "IMU Error"	   },
	{ M4(ilu),	R4(ILU),			   "ILU Error"	   },
	{ M4(cb),	R4(JBC),			   "JBC Error"	   },
	{ M4(lpul),	LR4(LPU_LINK_LAYER_INTERRUPT),	   "LPU Link Layer"},
	{ M4(lpup),	LR4_FIXME(LPU_PHY, INTERRUPT),	   "LPU PHY"	   },
	{ M4(lpur),	LR4(LPU_RECEIVE_PHY_INTERRUPT),	   "LPU Rcv PHY"   },
	{ M4(lpux),	LR4(LPU_TRANSMIT_PHY_INTERRUPT),   "LPU Xmt PHY"   },
	{ M4(lpus),	LR4(LPU_LTSSM_INTERRUPT),	   "LPU LTSSM"	   },
	{ M4(lpug),	LR4(LPU_GIGABLAZE_GLUE_INTERRUPT), "GigaBlaze"	   }
};

static int
px_fault_handler(dev_info_t *dip, px_fh_t *fh_p)
{
	int ret;
	px_fh_desc_t *rec_p = &px_fhd_tbl[fh_p->fh_err_id];
	char *msg_p = rec_p->fhd_msg_tbl;
	uint32_t off = rec_p->fhd_st;
	uint64_t stat = px_get_err_reg(fh_p->fh_base, off);
	uint64_t log_mask = *rec_p->fhd_lmask_p;
	uint64_t cnt_mask = *rec_p->fhd_cmask_p;

	if (stat)
		goto log_err;
	if (px_err_log_all)
		LOG(DBG_ERR_INTR, dip, "<%x>=%16llx %s\n", off, stat, msg_p);
	return (DDI_INTR_UNCLAIMED);
log_err:
	if (stat & log_mask)
		LOG(DBG_ERR_INTR, dip, "<%x>=%16llx %s\n", off, stat, msg_p);
	if (cnt_mask & stat) {
		int i;
		uint64_t *cntr_p;
		for (i = 0, cntr_p = fh_p->fh_cntrs; i < 64; i++) {
			if ((1 << i) & stat)
				cntr_p[i]++;
		}
	}

	fh_p->fh_stat = stat & log_mask;
	ret = (*rec_p->fhd_func)(dip, fh_p);

	px_set_err_reg(fh_p->fh_base, rec_p->fhd_cl, stat); /* clear intr */
	stat = px_get_err_reg(fh_p->fh_base, rec_p->fhd_st);

	if (stat & log_mask)
		LOG(DBG_ERR_INTR, dip, "{%x}=%16llx %s\n", off, stat, msg_p);
	return (ret);
}

/*
 * Recieved an interrupt from the hardware.  Scan the
 * linked list of fault handlers looking for the block
 * that interrupted.  Once we find it, call the fault handler.
 * That fault handler will print a (very) generic error
 * message and call the fault handler for that specific block.
 */
static uint_t
px_err_intr(caddr_t a)
{
	px_fault_t *fault_p = (px_fault_t *)a;
	dev_info_t *dip = fault_p->px_fh_dip;
	px_fh_t *fh_p;
	uint16_t nerr = 0;

	mutex_enter(&fault_p->px_fh_lock);
	for (fh_p = fault_p->px_fh_lst; fh_p != NULL; fh_p = fh_p->fh_next)
		nerr += px_fault_handler(dip, fh_p);
	mutex_exit(&fault_p->px_fh_lock);

	if (px_lib_intr_setstate(dip, fault_p->px_fh_sysino,
	    INTR_IDLE_STATE) != DDI_SUCCESS)
		return (DDI_INTR_UNCLAIMED);

	if (nerr)
		LOG(DBG_ERR_INTR, dip, "%d errs %llx\n", nerr, ddi_get_lbolt());

	return (DDI_INTR_CLAIMED);
}

void
px_err_add_fh(px_fault_t *px_fault_p, int id, caddr_t csr_base)
{
	px_fh_desc_t *rec_p = &px_fhd_tbl[id];
	px_fh_t *fh_p = kmem_zalloc(sizeof (px_fh_t), KM_SLEEP);
	uint64_t intr_mask = *rec_p->fhd_imask_p;

	fh_p->fh_base = csr_base;
	fh_p->fh_err_id = id;

	mutex_enter(&px_fault_p->px_fh_lock);
	if (px_fault_p->px_fh_lst == NULL)	/* XXX front insertion */
		px_fault_p->px_fh_lst = fh_p;
	else {
		px_fh_t *last = px_fault_p->px_fh_lst;
		for (; last->fh_next != NULL; last = last->fh_next)
			;
		last->fh_next = fh_p;
	}
	mutex_exit(&px_fault_p->px_fh_lock);

	if (rec_p->fhd_log != NULL)
		px_set_err_reg(csr_base, rec_p->fhd_log, intr_mask);

	px_set_err_reg(csr_base, rec_p->fhd_en, intr_mask);
}

void
px_err_rem(px_fault_t *px_fault_p, int id)
{
	px_fh_t *fh_p, *nfh_p;

	mutex_enter(&px_fault_p->px_fh_lock);
	for (fh_p = px_fault_p->px_fh_lst; fh_p != NULL; fh_p = nfh_p) {
		nfh_p = fh_p->fh_next;
		kmem_free(fh_p, sizeof (px_fh_t));
	}
	mutex_exit(&px_fault_p->px_fh_lock);
	mutex_destroy(&px_fault_p->px_fh_lock);
}

int
px_err_add_intr(px_t *px_p, px_fault_t *px_fault_p, int id)
{
	dev_info_t	*dip = px_p->px_dip;
	sysino_t	sysino;
	int		ret = DDI_SUCCESS;

	if (px_lib_intr_devino_to_sysino(dip, px_p->px_inos[id],
	    &sysino) != DDI_SUCCESS)
		return (DDI_FAILURE);

	VERIFY(add_ivintr(sysino, PX_ERR_PIL, px_err_intr,
	    (caddr_t)px_fault_p, NULL) == 0);

	px_ib_intr_enable(px_p, intr_dist_cpuid(), px_p->px_inos[id]);

	return (ret);
}

void
px_err_rem_intr(px_t *px_p, int id)
{
	dev_info_t	*dip = px_p->px_dip;
	sysino_t	sysino;

	if (px_lib_intr_devino_to_sysino(dip, px_p->px_inos[id],
	    &sysino) != DDI_SUCCESS)
		return;

	rem_ivintr(sysino, NULL);
	px_ib_intr_disable(px_p->px_ib_p, px_p->px_inos[id], IB_INTR_WAIT);
}
