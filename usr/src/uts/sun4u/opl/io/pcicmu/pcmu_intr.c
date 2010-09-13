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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CMU-CH nexus interrupt handling:
 *	PCI device interrupt handler wrapper
 *	pil lookup routine
 *	PCI device interrupt related initchild code
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/spl.h>
#include <sys/sunddi.h>
#include <sys/machsystm.h>
#include <sys/ddi_impldefs.h>
#include <sys/pcicmu/pcicmu.h>
#include <sys/sdt.h>

uint_t pcmu_intr_wrapper(caddr_t arg);

/*
 * interrupt jabber:
 *
 * When an interrupt line is jabbering, every time the state machine for the
 * associated ino is idled, a new mondo will be sent and the ino will go into
 * the pending state again. The mondo will cause a new call to
 * pcmu_intr_wrapper() which normally idles the ino's state machine which would
 * precipitate another trip round the loop.
 * The loop can be broken by preventing the ino's state machine from being
 * idled when an interrupt line is jabbering. See the comment at the
 * beginning of pcmu_intr_wrapper() explaining how the 'interrupt jabber
 * protection' code does this.
 */


/*
 * If the unclaimed interrupt count has reached the limit set by
 * pcmu_unclaimed_intr_max within the time limit, then all interrupts
 * on this ino is blocked by not idling the interrupt state machine.
 */
static int
pcmu_spurintr(pcmu_ib_ino_info_t *ino_p) {
	int i;
	ih_t *ih_p = ino_p->pino_ih_start;
	pcmu_t *pcmu_p = ino_p->pino_ib_p->pib_pcmu_p;
	char *err_fmt_str;

	if (ino_p->pino_unclaimed > pcmu_unclaimed_intr_max) {
		return (DDI_INTR_CLAIMED);
	}
	if (!ino_p->pino_unclaimed) {
		ino_p->pino_spurintr_begin = ddi_get_lbolt();
	}
	ino_p->pino_unclaimed++;
	if (ino_p->pino_unclaimed <= pcmu_unclaimed_intr_max) {
		goto clear;
	}
	if (drv_hztousec(ddi_get_lbolt() - ino_p->pino_spurintr_begin)
	    > pcmu_spurintr_duration) {
		ino_p->pino_unclaimed = 0;
		goto clear;
	}
	err_fmt_str = "%s%d: ino 0x%x blocked";
	goto warn;
clear:
	/* clear the pending state */
	PCMU_IB_INO_INTR_CLEAR(ino_p->pino_clr_reg);
	err_fmt_str = "!%s%d: spurious interrupt from ino 0x%x";
warn:
	cmn_err(CE_WARN, err_fmt_str, NAMEINST(pcmu_p->pcmu_dip),
	    ino_p->pino_ino);
	for (i = 0; i < ino_p->pino_ih_size; i++, ih_p = ih_p->ih_next) {
		cmn_err(CE_CONT, "!%s-%d#%x ", NAMEINST(ih_p->ih_dip),
		    ih_p->ih_inum);
	}
	cmn_err(CE_CONT, "!\n");
	return (DDI_INTR_CLAIMED);
}

/*
 * pcmu_intr_wrapper
 *
 * This routine is used as wrapper around interrupt handlers installed by child
 * device drivers.  This routine invokes the driver interrupt handlers and
 * examines the return codes.
 * There is a count of unclaimed interrupts kept on a per-ino basis. If at
 * least one handler claims the interrupt then the counter is halved and the
 * interrupt state machine is idled. If no handler claims the interrupt then
 * the counter is incremented by one and the state machine is idled.
 * If the count ever reaches the limit value set by pcmu_unclaimed_intr_max
 * then the interrupt state machine is not idled thus preventing any further
 * interrupts on that ino. The state machine will only be idled again if a
 * handler is subsequently added or removed.
 *
 * return value: DDI_INTR_CLAIMED if any handlers claimed the interrupt,
 * DDI_INTR_UNCLAIMED otherwise.
 */
uint_t
pcmu_intr_wrapper(caddr_t arg)
{
	pcmu_ib_ino_info_t *ino_p = (pcmu_ib_ino_info_t *)arg;
	uint_t result = 0, r;
	ih_t *ih_p = ino_p->pino_ih_start;
	int i;
#ifdef	DEBUG
	pcmu_t *pcmu_p = ino_p->pino_ib_p->pib_pcmu_p;
#endif


	for (i = 0; i < ino_p->pino_ih_size; i++, ih_p = ih_p->ih_next) {
		dev_info_t *dip = ih_p->ih_dip;
		uint_t (*handler)() = ih_p->ih_handler;
		caddr_t arg1 = ih_p->ih_handler_arg1;
		caddr_t arg2 = ih_p->ih_handler_arg2;

		if (ih_p->ih_intr_state == PCMU_INTR_STATE_DISABLE) {
			PCMU_DBG3(PCMU_DBG_INTR, pcmu_p->pcmu_dip,
			    "pcmu_intr_wrapper: %s%d interrupt %d is "
			    "disabled\n", ddi_driver_name(dip),
			    ddi_get_instance(dip), ino_p->pino_ino);
			continue;
		}

		DTRACE_PROBE4(pcmu__interrupt__start, dev_info_t, dip,
		    void *, handler, caddr_t, arg1, caddr_t, arg2);

		r = (*handler)(arg1, arg2);
		DTRACE_PROBE4(pcmu__interrupt__complete, dev_info_t, dip,
		    void *, handler, caddr_t, arg1, int, r);

		result += r;
	}

	if (!result) {
		return (pcmu_spurintr(ino_p));
	}
	ino_p->pino_unclaimed = 0;
	/* clear the pending state */
	PCMU_IB_INO_INTR_CLEAR(ino_p->pino_clr_reg);
	return (DDI_INTR_CLAIMED);
}

int
pcmu_add_intr(dev_info_t *dip, dev_info_t *rdip, ddi_intr_handle_impl_t *hdlp)
{
	pcmu_t *pcmu_p = get_pcmu_soft_state(ddi_get_instance(dip));
	pcmu_ib_t *pib_p = pcmu_p->pcmu_ib_p;
	ih_t *ih_p;
	pcmu_ib_ino_t ino;
	pcmu_ib_ino_info_t *ino_p; /* pulse interrupts have no ino */
	pcmu_ib_mondo_t mondo;
	uint32_t cpu_id;
	int ret;

	ino = PCMU_IB_MONDO_TO_INO(hdlp->ih_vector);

	PCMU_DBG3(PCMU_DBG_A_INTX, dip, "pcmu_add_intr: rdip=%s%d ino=%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), ino);

	if (ino > pib_p->pib_max_ino) {
		PCMU_DBG1(PCMU_DBG_A_INTX, dip, "ino %x is invalid\n", ino);
		return (DDI_INTR_NOTFOUND);
	}

	if ((mondo = PCMU_IB_INO_TO_MONDO(pcmu_p->pcmu_ib_p, ino)) == 0)
		goto fail1;

	ino = PCMU_IB_MONDO_TO_INO(mondo);

	mutex_enter(&pib_p->pib_ino_lst_mutex);
	ih_p = pcmu_ib_alloc_ih(rdip, hdlp->ih_inum,
	    hdlp->ih_cb_func, hdlp->ih_cb_arg1, hdlp->ih_cb_arg2);

	if (ino_p = pcmu_ib_locate_ino(pib_p, ino)) {	/* sharing ino */
		uint32_t intr_index = hdlp->ih_inum;
		if (pcmu_ib_ino_locate_intr(ino_p, rdip, intr_index)) {
			PCMU_DBG1(PCMU_DBG_A_INTX, dip,
			    "dup intr #%d\n", intr_index);
			goto fail3;
		}

		/*
		 * add default weight(0) to the cpu that we are
		 * already targeting
		 */
		cpu_id = ino_p->pino_cpuid;
		intr_dist_cpuid_add_device_weight(cpu_id, rdip, 0);
		pcmu_ib_ino_add_intr(pcmu_p, ino_p, ih_p);
		goto ino_done;
	}

	ino_p = pcmu_ib_new_ino(pib_p, ino, ih_p);
	hdlp->ih_vector = mondo;

	PCMU_DBG2(PCMU_DBG_A_INTX, dip, "pcmu_add_intr:  pil=0x%x mondo=0x%x\n",
	    hdlp->ih_pri, hdlp->ih_vector);

	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp,
	    (ddi_intr_handler_t *)pcmu_intr_wrapper, (caddr_t)ino_p, NULL);

	ret = i_ddi_add_ivintr(hdlp);

	/*
	 * Restore original interrupt handler
	 * and arguments in interrupt handle.
	 */
	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp, ih_p->ih_handler,
	    ih_p->ih_handler_arg1, ih_p->ih_handler_arg2);

	if (ret != DDI_SUCCESS) {
		goto fail4;
	}
	/* Save the pil for this ino */
	ino_p->pino_pil = hdlp->ih_pri;

	/* clear and enable interrupt */
	PCMU_IB_INO_INTR_CLEAR(ino_p->pino_clr_reg);

	/* select cpu for sharing and removal */
	cpu_id = pcmu_intr_dist_cpuid(pib_p, ino_p);
	ino_p->pino_cpuid = cpu_id;
	ino_p->pino_established = 1;
	intr_dist_cpuid_add_device_weight(cpu_id, rdip, 0);

	cpu_id = u2u_translate_tgtid(pib_p->pib_pcmu_p,
	    cpu_id, ino_p->pino_map_reg);
	*ino_p->pino_map_reg = ib_get_map_reg(mondo, cpu_id);
	*ino_p->pino_map_reg;
ino_done:
	mutex_exit(&pib_p->pib_ino_lst_mutex);
done:
	PCMU_DBG2(PCMU_DBG_A_INTX, dip, "done! Interrupt 0x%x pil=%x\n",
	    hdlp->ih_vector, hdlp->ih_pri);
	return (DDI_SUCCESS);
fail4:
	pcmu_ib_delete_ino(pib_p, ino_p);
fail3:
	if (ih_p->ih_config_handle)
		pci_config_teardown(&ih_p->ih_config_handle);
	mutex_exit(&pib_p->pib_ino_lst_mutex);
	kmem_free(ih_p, sizeof (ih_t));
fail1:
	PCMU_DBG2(PCMU_DBG_A_INTX, dip, "Failed! Interrupt 0x%x pil=%x\n",
	    hdlp->ih_vector, hdlp->ih_pri);
	return (DDI_FAILURE);
}

int
pcmu_remove_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	pcmu_t *pcmu_p = get_pcmu_soft_state(ddi_get_instance(dip));
	pcmu_ib_t *pib_p = pcmu_p->pcmu_ib_p;
	pcmu_ib_ino_t ino;
	pcmu_ib_mondo_t mondo;
	pcmu_ib_ino_info_t *ino_p;	/* non-pulse only */
	ih_t *ih_p;			/* non-pulse only */

	ino = PCMU_IB_MONDO_TO_INO(hdlp->ih_vector);

	PCMU_DBG3(PCMU_DBG_R_INTX, dip, "pcmu_rem_intr: rdip=%s%d ino=%x\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), ino);

	/* Translate the interrupt property */
	mondo = PCMU_IB_INO_TO_MONDO(pcmu_p->pcmu_ib_p, ino);
	if (mondo == 0) {
		PCMU_DBG1(PCMU_DBG_R_INTX, dip,
		    "can't get mondo for ino %x\n", ino);
		return (DDI_FAILURE);
	}
	ino = PCMU_IB_MONDO_TO_INO(mondo);

	mutex_enter(&pib_p->pib_ino_lst_mutex);
	ino_p = pcmu_ib_locate_ino(pib_p, ino);
	if (!ino_p) {
		mutex_exit(&pib_p->pib_ino_lst_mutex);
		return (DDI_SUCCESS);
	}

	ih_p = pcmu_ib_ino_locate_intr(ino_p, rdip, hdlp->ih_inum);
	if (pcmu_ib_ino_rem_intr(pcmu_p, ino_p, ih_p) != DDI_SUCCESS) {
		mutex_exit(&pib_p->pib_ino_lst_mutex);
		return (DDI_FAILURE);
	}
	intr_dist_cpuid_rem_device_weight(ino_p->pino_cpuid, rdip);
	if (ino_p->pino_ih_size == 0) {
		PCMU_IB_INO_INTR_PEND(ib_clear_intr_reg_addr(pib_p, ino));
		hdlp->ih_vector = mondo;
		i_ddi_rem_ivintr(hdlp);
		pcmu_ib_delete_ino(pib_p, ino_p);
	}

	/* re-enable interrupt only if mapping register still shared */
	if (ino_p->pino_ih_size) {
		PCMU_IB_INO_INTR_ON(ino_p->pino_map_reg);
		*ino_p->pino_map_reg;
	}
	mutex_exit(&pib_p->pib_ino_lst_mutex);
	if (ino_p->pino_ih_size == 0) {
		kmem_free(ino_p, sizeof (pcmu_ib_ino_info_t));
	}
	PCMU_DBG1(PCMU_DBG_R_INTX, dip, "success! mondo=%x\n", mondo);
	return (DDI_SUCCESS);
}

/*
 * free the pcmu_inos array allocated during pcmu_intr_setup. the actual
 * interrupts are torn down by their respective block destroy routines:
 * cb_destroy, pcmu_pbm_destroy, and ib_destroy.
 */
void
pcmu_intr_teardown(pcmu_t *pcmu_p)
{
	kmem_free(pcmu_p->pcmu_inos, pcmu_p->pcmu_inos_len);
	pcmu_p->pcmu_inos = NULL;
	pcmu_p->pcmu_inos_len = 0;
}
