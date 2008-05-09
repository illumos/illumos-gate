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
 * CMU-CH Interrupt Block
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/systm.h>
#include <sys/spl.h>
#include <sys/sunddi.h>
#include <sys/machsystm.h>
#include <sys/ddi_impldefs.h>
#include <sys/pcicmu/pcicmu.h>

static uint_t pcmu_ib_intr_reset(void *arg);

extern uint64_t	xc_tick_jump_limit;

void
pcmu_ib_create(pcmu_t *pcmu_p)
{
	pcmu_ib_t *pib_p;
	uintptr_t a;
	int i;

	/*
	 * Allocate interrupt block state structure and link it to
	 * the pci state structure.
	 */
	pib_p = kmem_zalloc(sizeof (pcmu_ib_t), KM_SLEEP);
	pcmu_p->pcmu_ib_p = pib_p;
	pib_p->pib_pcmu_p = pcmu_p;

	a = pcmu_ib_setup(pib_p);

	/*
	 * Determine virtual addresses of interrupt mapping, clear and diag
	 * registers that have common offsets.
	 */
	pib_p->pib_intr_retry_timer_reg =
	    (uint64_t *)(a + PCMU_IB_INTR_RETRY_TIMER_OFFSET);
	pib_p->pib_obio_intr_state_diag_reg =
	    (uint64_t *)(a + PCMU_IB_OBIO_INTR_STATE_DIAG_REG);

	PCMU_DBG2(PCMU_DBG_ATTACH, pcmu_p->pcmu_dip,
	    "pcmu_ib_create: obio_imr=%x, obio_cir=%x\n",
	    pib_p->pib_obio_intr_map_regs, pib_p->pib_obio_clear_intr_regs);
	PCMU_DBG2(PCMU_DBG_ATTACH, pcmu_p->pcmu_dip,
	    "pcmu_ib_create: retry_timer=%x, obio_diag=%x\n",
	    pib_p->pib_intr_retry_timer_reg,
	    pib_p->pib_obio_intr_state_diag_reg);

	pib_p->pib_ino_lst = (pcmu_ib_ino_info_t *)NULL;
	mutex_init(&pib_p->pib_intr_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pib_p->pib_ino_lst_mutex, NULL, MUTEX_DRIVER, NULL);

	PCMU_DBG1(PCMU_DBG_ATTACH, pcmu_p->pcmu_dip,
	    "pcmu_ib_create: numproxy=%x\n", pcmu_p->pcmu_numproxy);
	for (i = 1; i <= pcmu_p->pcmu_numproxy; i++) {
		set_intr_mapping_reg(pcmu_p->pcmu_id,
		    (uint64_t *)pib_p->pib_upa_imr[i - 1], i);
	}

	pcmu_ib_configure(pib_p);
	bus_func_register(BF_TYPE_RESINTR, pcmu_ib_intr_reset, pib_p);
}

void
pcmu_ib_destroy(pcmu_t *pcmu_p)
{
	pcmu_ib_t *pib_p = pcmu_p->pcmu_ib_p;

	PCMU_DBG0(PCMU_DBG_IB, pcmu_p->pcmu_dip, "pcmu_ib_destroy\n");
	bus_func_unregister(BF_TYPE_RESINTR, pcmu_ib_intr_reset, pib_p);

	intr_dist_rem_weighted(pcmu_ib_intr_dist_all, pib_p);
	mutex_destroy(&pib_p->pib_ino_lst_mutex);
	mutex_destroy(&pib_p->pib_intr_lock);

	pcmu_ib_free_ino_all(pib_p);

	kmem_free(pib_p, sizeof (pcmu_ib_t));
	pcmu_p->pcmu_ib_p = NULL;
}

void
pcmu_ib_configure(pcmu_ib_t *pib_p)
{
	*pib_p->pib_intr_retry_timer_reg = pcmu_intr_retry_intv;
}

/*
 * can only used for CMU-CH internal interrupts ue, pbm
 */
void
pcmu_ib_intr_enable(pcmu_t *pcmu_p, pcmu_ib_ino_t ino)
{
	pcmu_ib_t *pib_p = pcmu_p->pcmu_ib_p;
	pcmu_ib_mondo_t mondo = PCMU_IB_INO_TO_MONDO(pib_p, ino);
	volatile uint64_t *imr_p = ib_intr_map_reg_addr(pib_p, ino);
	uint_t cpu_id;

	/*
	 * Determine the cpu for the interrupt.
	 */
	mutex_enter(&pib_p->pib_intr_lock);
	cpu_id = intr_dist_cpuid();
	cpu_id = u2u_translate_tgtid(pcmu_p, cpu_id, imr_p);
	PCMU_DBG2(PCMU_DBG_IB, pcmu_p->pcmu_dip,
	    "pcmu_ib_intr_enable: ino=%x cpu_id=%x\n", ino, cpu_id);

	*imr_p = ib_get_map_reg(mondo, cpu_id);
	PCMU_IB_INO_INTR_CLEAR(ib_clear_intr_reg_addr(pib_p, ino));
	mutex_exit(&pib_p->pib_intr_lock);
}

/*
 * Disable the interrupt via its interrupt mapping register.
 * Can only be used for internal interrupts: ue, pbm.
 * If called under interrupt context, wait should be set to 0
 */
void
pcmu_ib_intr_disable(pcmu_ib_t *pib_p, pcmu_ib_ino_t ino, int wait)
{
	volatile uint64_t *imr_p = ib_intr_map_reg_addr(pib_p, ino);
	volatile uint64_t *state_reg_p = PCMU_IB_INO_INTR_STATE_REG(pib_p, ino);
	hrtime_t start_time;
	hrtime_t prev, curr, interval, jump;
	hrtime_t intr_timeout;

	/* disable the interrupt */
	mutex_enter(&pib_p->pib_intr_lock);
	PCMU_IB_INO_INTR_OFF(imr_p);
	*imr_p;	/* flush previous write */
	mutex_exit(&pib_p->pib_intr_lock);

	if (!wait)
		goto wait_done;

	intr_timeout = pcmu_intrpend_timeout;
	jump = TICK_TO_NSEC(xc_tick_jump_limit);
	start_time = curr = gethrtime();
	/* busy wait if there is interrupt being processed */
	while (PCMU_IB_INO_INTR_PENDING(state_reg_p, ino) && !panicstr) {
		/*
		 * If we have a really large jump in hrtime, it is most
		 * probably because we entered the debugger (or OBP,
		 * in general). So, we adjust the timeout accordingly
		 * to prevent declaring an interrupt timeout. The
		 * master-interrupt mechanism in OBP should deliver
		 * the interrupts properly.
		 */
		prev = curr;
		curr = gethrtime();
		interval = curr - prev;
		if (interval > jump)
			intr_timeout += interval;
		if (curr - start_time > intr_timeout) {
			pcmu_pbm_t *pcbm_p = pib_p->pib_pcmu_p->pcmu_pcbm_p;
			cmn_err(CE_WARN,
			    "%s:%s: pcmu_ib_intr_disable timeout %x",
			    pcbm_p->pcbm_nameinst_str,
			    pcbm_p->pcbm_nameaddr_str, ino);
			break;
		}
	}
wait_done:
	PCMU_IB_INO_INTR_PEND(ib_clear_intr_reg_addr(pib_p, ino));
	u2u_ittrans_cleanup((u2u_ittrans_data_t *)
	    (PCMU_IB2CB(pib_p)->pcb_ittrans_cookie), imr_p);
}

/* can only used for CMU-CH internal interrupts ue, pbm */
void
pcmu_ib_nintr_clear(pcmu_ib_t *pib_p, pcmu_ib_ino_t ino)
{
	uint64_t *clr_reg = ib_clear_intr_reg_addr(pib_p, ino);
	PCMU_IB_INO_INTR_CLEAR(clr_reg);
}

/*
 * distribute PBM and UPA interrupts. ino is set to 0 by caller if we
 * are dealing with UPA interrupts (without inos).
 */
void
pcmu_ib_intr_dist_nintr(pcmu_ib_t *pib_p, pcmu_ib_ino_t ino,
    volatile uint64_t *imr_p)
{
	volatile uint64_t imr = *imr_p;
	uint32_t cpu_id;

	if (!PCMU_IB_INO_INTR_ISON(imr))
		return;

	cpu_id = intr_dist_cpuid();

	if (ino) {
		cpu_id = u2u_translate_tgtid(pib_p->pib_pcmu_p, cpu_id, imr_p);
	}

	if (ib_map_reg_get_cpu(*imr_p) == cpu_id) {
		return;
	}
	*imr_p = ib_get_map_reg(PCMU_IB_IMR2MONDO(imr), cpu_id);
	imr = *imr_p;	/* flush previous write */
}

static void
pcmu_ib_intr_dist(pcmu_ib_t *pib_p, pcmu_ib_ino_info_t *ino_p)
{
	uint32_t cpu_id = ino_p->pino_cpuid;
	pcmu_ib_ino_t ino = ino_p->pino_ino;
	volatile uint64_t imr, *imr_p, *state_reg;
	hrtime_t start_time;
	hrtime_t prev, curr, interval, jump;
	hrtime_t intr_timeout;

	ASSERT(MUTEX_HELD(&pib_p->pib_ino_lst_mutex));
	imr_p = ib_intr_map_reg_addr(pib_p, ino);
	state_reg = PCMU_IB_INO_INTR_STATE_REG(pib_p, ino);

	/* disable interrupt, this could disrupt devices sharing our slot */
	PCMU_IB_INO_INTR_OFF(imr_p);
	imr = *imr_p;	/* flush previous write */

	/* busy wait if there is interrupt being processed */
	intr_timeout = pcmu_intrpend_timeout;
	jump = TICK_TO_NSEC(xc_tick_jump_limit);
	start_time = curr = gethrtime();
	while (PCMU_IB_INO_INTR_PENDING(state_reg, ino) && !panicstr) {
		/*
		 * If we have a really large jump in hrtime, it is most
		 * probably because we entered the debugger (or OBP,
		 * in general). So, we adjust the timeout accordingly
		 * to prevent declaring an interrupt timeout. The
		 * master-interrupt mechanism in OBP should deliver
		 * the interrupts properly.
		 */
		prev = curr;
		curr = gethrtime();
		interval = curr - prev;
		if (interval > jump)
			intr_timeout += interval;
		if (curr - start_time > intr_timeout) {
			pcmu_pbm_t *pcbm_p = pib_p->pib_pcmu_p->pcmu_pcbm_p;
			cmn_err(CE_WARN,
			    "%s:%s: pcmu_ib_intr_dist(%p,%x) timeout",
			    pcbm_p->pcbm_nameinst_str,
			    pcbm_p->pcbm_nameaddr_str,
			    imr_p, PCMU_IB_INO_TO_MONDO(pib_p, ino));
			break;
		}
	}
	cpu_id = u2u_translate_tgtid(pib_p->pib_pcmu_p, cpu_id, imr_p);
	*imr_p = ib_get_map_reg(PCMU_IB_IMR2MONDO(imr), cpu_id);
	imr = *imr_p;	/* flush previous write */
}

/*
 * Redistribute interrupts of the specified weight. The first call has a weight
 * of weight_max, which can be used to trigger initialization for
 * redistribution. The inos with weight [weight_max, inf.) should be processed
 * on the "weight == weight_max" call.  This first call is followed by calls
 * of decreasing weights, inos of that weight should be processed.  The final
 * call specifies a weight of zero, this can be used to trigger processing of
 * stragglers.
 */
void
pcmu_ib_intr_dist_all(void *arg, int32_t weight_max, int32_t weight)
{
	pcmu_ib_t *pib_p = (pcmu_ib_t *)arg;
	pcmu_ib_ino_info_t *ino_p;
	ih_t *ih_lst;
	int32_t dweight;
	int i;

	mutex_enter(&pib_p->pib_ino_lst_mutex);

	/* Perform special processing for first call of a redistribution. */
	if (weight == weight_max) {
		for (ino_p = pib_p->pib_ino_lst; ino_p;
		    ino_p = ino_p->pino_next) {

			/*
			 * Clear pino_established of each ino on first call.
			 * The pino_established field may be used by a pci
			 * nexus driver's pcmu_intr_dist_cpuid implementation
			 * when detection of established pci slot-cpu binding
			 * for multi function pci cards.
			 */
			ino_p->pino_established = 0;

			/*
			 * recompute the pino_intr_weight based on the device
			 * weight of all devinfo nodes sharing the ino (this
			 * will allow us to pick up new weights established by
			 * i_ddi_set_intr_weight()).
			 */
			ino_p->pino_intr_weight = 0;
			for (i = 0, ih_lst = ino_p->pino_ih_head;
			    i < ino_p->pino_ih_size;
			    i++, ih_lst = ih_lst->ih_next) {
				dweight = i_ddi_get_intr_weight(ih_lst->ih_dip);
				if (dweight > 0)
					ino_p->pino_intr_weight += dweight;
			}
		}
	}

	for (ino_p = pib_p->pib_ino_lst; ino_p; ino_p = ino_p->pino_next) {
		/*
		 * Get the weight of the ino and determine if we are going to
		 * process call.  We wait until an pcmu_ib_intr_dist_all call of
		 * the proper weight occurs to support redistribution of all
		 * heavy weighted interrupts first (across all nexus driver
		 * instances).  This is done to ensure optimal
		 * INTR_WEIGHTED_DIST behavior.
		 */
		if ((weight == ino_p->pino_intr_weight) ||
		    ((weight >= weight_max) &&
		    (ino_p->pino_intr_weight >= weight_max))) {
			/* select cpuid to target and mark ino established */
			ino_p->pino_cpuid = pcmu_intr_dist_cpuid(pib_p, ino_p);
			ino_p->pino_established = 1;

			/* Add device weight of ino devinfos to targeted cpu. */
			for (i = 0, ih_lst = ino_p->pino_ih_head;
			    i < ino_p->pino_ih_size;
			    i++, ih_lst = ih_lst->ih_next) {
				dweight = i_ddi_get_intr_weight(ih_lst->ih_dip);
				intr_dist_cpuid_add_device_weight(
				    ino_p->pino_cpuid, ih_lst->ih_dip, dweight);
			}

			/* program the hardware */
			pcmu_ib_intr_dist(pib_p, ino_p);
		}
	}
	mutex_exit(&pib_p->pib_ino_lst_mutex);
}

/*
 * Reset interrupts to IDLE.  This function is called during
 * panic handling after redistributing interrupts; it's needed to
 * support dumping to network devices after 'sync' from OBP.
 *
 * N.B.  This routine runs in a context where all other threads
 * are permanently suspended.
 */
static uint_t
pcmu_ib_intr_reset(void *arg)
{
	pcmu_ib_t *pib_p = (pcmu_ib_t *)arg;
	pcmu_ib_ino_t ino;
	uint64_t *clr_reg;

	/*
	 * Note that we only actually care about interrupts that are
	 * potentially from network devices.
	 */
	for (ino = 0; ino <= pib_p->pib_max_ino; ino++) {
		clr_reg = ib_clear_intr_reg_addr(pib_p, ino);
		PCMU_IB_INO_INTR_CLEAR(clr_reg);
	}
	return (BF_NONE);
}

void
pcmu_ib_suspend(pcmu_ib_t *pib_p)
{
	pcmu_ib_ino_info_t *ip;

	/* save ino_lst interrupts' mapping registers content */
	mutex_enter(&pib_p->pib_ino_lst_mutex);
	for (ip = pib_p->pib_ino_lst; ip; ip = ip->pino_next) {
		ip->pino_map_reg_save = *ip->pino_map_reg;
	}
	mutex_exit(&pib_p->pib_ino_lst_mutex);
}

void
pcmu_ib_resume(pcmu_ib_t *pib_p)
{
	pcmu_ib_ino_info_t *ip;

	/* restore ino_lst interrupts' mapping registers content */
	mutex_enter(&pib_p->pib_ino_lst_mutex);
	for (ip = pib_p->pib_ino_lst; ip; ip = ip->pino_next) {
		PCMU_IB_INO_INTR_CLEAR(ip->pino_clr_reg); /* set intr to idle */
		*ip->pino_map_reg = ip->pino_map_reg_save; /* restore IMR */
	}
	mutex_exit(&pib_p->pib_ino_lst_mutex);
}

/*
 * locate ino_info structure on pib_p->pib_ino_lst according to ino#
 * returns NULL if not found.
 */
pcmu_ib_ino_info_t *
pcmu_ib_locate_ino(pcmu_ib_t *pib_p, pcmu_ib_ino_t ino_num)
{
	pcmu_ib_ino_info_t *ino_p = pib_p->pib_ino_lst;
	ASSERT(MUTEX_HELD(&pib_p->pib_ino_lst_mutex));

	for (; ino_p && ino_p->pino_ino != ino_num; ino_p = ino_p->pino_next)
		;
	return (ino_p);
}

#define	PCMU_IB_INO_TO_SLOT(ino)		\
	(PCMU_IB_IS_OBIO_INO(ino) ? 0xff : ((ino) & 0x1f) >> 2)

pcmu_ib_ino_info_t *
pcmu_ib_new_ino(pcmu_ib_t *pib_p, pcmu_ib_ino_t ino_num, ih_t *ih_p)
{
	pcmu_ib_ino_info_t *ino_p = kmem_alloc(sizeof (pcmu_ib_ino_info_t),
	    KM_SLEEP);
	ino_p->pino_ino = ino_num;
	ino_p->pino_slot_no = PCMU_IB_INO_TO_SLOT(ino_num);
	ino_p->pino_ib_p = pib_p;
	ino_p->pino_clr_reg = ib_clear_intr_reg_addr(pib_p, ino_num);
	ino_p->pino_map_reg = ib_intr_map_reg_addr(pib_p, ino_num);
	ino_p->pino_unclaimed = 0;

	/*
	 * cannot disable interrupt since we might share slot
	 * PCMU_IB_INO_INTR_OFF(ino_p->pino_map_reg);
	 */

	ih_p->ih_next = ih_p;
	ino_p->pino_ih_head = ih_p;
	ino_p->pino_ih_tail = ih_p;
	ino_p->pino_ih_start = ih_p;
	ino_p->pino_ih_size = 1;

	ino_p->pino_next = pib_p->pib_ino_lst;
	pib_p->pib_ino_lst = ino_p;
	return (ino_p);
}

/* the ino_p is retrieved by previous call to pcmu_ib_locate_ino() */
void
pcmu_ib_delete_ino(pcmu_ib_t *pib_p, pcmu_ib_ino_info_t *ino_p)
{
	pcmu_ib_ino_info_t *list = pib_p->pib_ino_lst;
	ASSERT(MUTEX_HELD(&pib_p->pib_ino_lst_mutex));
	if (list == ino_p) {
		pib_p->pib_ino_lst = list->pino_next;
	} else {
		for (; list->pino_next != ino_p; list = list->pino_next)
			;
		list->pino_next = ino_p->pino_next;
	}
}

/* free all ino when we are detaching */
void
pcmu_ib_free_ino_all(pcmu_ib_t *pib_p)
{
	pcmu_ib_ino_info_t *tmp = pib_p->pib_ino_lst;
	pcmu_ib_ino_info_t *next = NULL;
	while (tmp) {
		next = tmp->pino_next;
		kmem_free(tmp, sizeof (pcmu_ib_ino_info_t));
		tmp = next;
	}
}

void
pcmu_ib_ino_add_intr(pcmu_t *pcmu_p, pcmu_ib_ino_info_t *ino_p, ih_t *ih_p)
{
	pcmu_ib_ino_t ino = ino_p->pino_ino;
	pcmu_ib_t *pib_p = ino_p->pino_ib_p;
	volatile uint64_t *state_reg = PCMU_IB_INO_INTR_STATE_REG(pib_p, ino);
	hrtime_t start_time;
	hrtime_t prev, curr, interval, jump;
	hrtime_t intr_timeout;

	ASSERT(pib_p == pcmu_p->pcmu_ib_p);
	ASSERT(MUTEX_HELD(&pib_p->pib_ino_lst_mutex));

	/* disable interrupt, this could disrupt devices sharing our slot */
	PCMU_IB_INO_INTR_OFF(ino_p->pino_map_reg);
	*ino_p->pino_map_reg;

	/* do NOT modify the link list until after the busy wait */

	/*
	 * busy wait if there is interrupt being processed.
	 * either the pending state will be cleared by the interrupt wrapper
	 * or the interrupt will be marked as blocked indicating that it was
	 * jabbering.
	 */
	intr_timeout = pcmu_intrpend_timeout;
	jump = TICK_TO_NSEC(xc_tick_jump_limit);
	start_time = curr = gethrtime();
	while ((ino_p->pino_unclaimed <= pcmu_unclaimed_intr_max) &&
	    PCMU_IB_INO_INTR_PENDING(state_reg, ino) && !panicstr) {
		/*
		 * If we have a really large jump in hrtime, it is most
		 * probably because we entered the debugger (or OBP,
		 * in general). So, we adjust the timeout accordingly
		 * to prevent declaring an interrupt timeout. The
		 * master-interrupt mechanism in OBP should deliver
		 * the interrupts properly.
		 */
		prev = curr;
		curr = gethrtime();
		interval = curr - prev;
		if (interval > jump)
			intr_timeout += interval;
		if (curr - start_time > intr_timeout) {
			pcmu_pbm_t *pcbm_p = pcmu_p->pcmu_pcbm_p;
			cmn_err(CE_WARN,
			    "%s:%s: pcmu_ib_ino_add_intr %x timeout",
			    pcbm_p->pcbm_nameinst_str,
			    pcbm_p->pcbm_nameaddr_str, ino);
			break;
		}
	}

	/* link up pcmu_ispec_t portion of the ppd */
	ih_p->ih_next = ino_p->pino_ih_head;
	ino_p->pino_ih_tail->ih_next = ih_p;
	ino_p->pino_ih_tail = ih_p;

	ino_p->pino_ih_start = ino_p->pino_ih_head;
	ino_p->pino_ih_size++;

	/*
	 * if the interrupt was previously blocked (left in pending state)
	 * because of jabber we need to clear the pending state in case the
	 * jabber has gone away.
	 */
	if (ino_p->pino_unclaimed > pcmu_unclaimed_intr_max) {
		cmn_err(CE_WARN,
		    "%s%d: pcmu_ib_ino_add_intr: ino 0x%x has been unblocked",
		    ddi_driver_name(pcmu_p->pcmu_dip),
		    ddi_get_instance(pcmu_p->pcmu_dip),
		    ino_p->pino_ino);
		ino_p->pino_unclaimed = 0;
		PCMU_IB_INO_INTR_CLEAR(ino_p->pino_clr_reg);
	}

	/* re-enable interrupt */
	PCMU_IB_INO_INTR_ON(ino_p->pino_map_reg);
	*ino_p->pino_map_reg;
}

/*
 * removes pcmu_ispec_t from the ino's link list.
 * uses hardware mutex to lock out interrupt threads.
 * Side effects: interrupt belongs to that ino is turned off on return.
 * if we are sharing PCI slot with other inos, the caller needs
 * to turn it back on.
 */
int
pcmu_ib_ino_rem_intr(pcmu_t *pcmu_p, pcmu_ib_ino_info_t *ino_p, ih_t *ih_p)
{
	int i;
	pcmu_ib_ino_t ino = ino_p->pino_ino;
	ih_t *ih_lst = ino_p->pino_ih_head;
	volatile uint64_t *state_reg =
	    PCMU_IB_INO_INTR_STATE_REG(ino_p->pino_ib_p, ino);
	hrtime_t start_time;
	hrtime_t prev, curr, interval, jump;
	hrtime_t intr_timeout;

	ASSERT(MUTEX_HELD(&ino_p->pino_ib_p->pib_ino_lst_mutex));
	/* disable interrupt, this could disrupt devices sharing our slot */
	PCMU_IB_INO_INTR_OFF(ino_p->pino_map_reg);
	*ino_p->pino_map_reg;

	/* do NOT modify the link list until after the busy wait */

	/*
	 * busy wait if there is interrupt being processed.
	 * either the pending state will be cleared by the interrupt wrapper
	 * or the interrupt will be marked as blocked indicating that it was
	 * jabbering.
	 */
	intr_timeout = pcmu_intrpend_timeout;
	jump = TICK_TO_NSEC(xc_tick_jump_limit);
	start_time = curr = gethrtime();
	while ((ino_p->pino_unclaimed <= pcmu_unclaimed_intr_max) &&
	    PCMU_IB_INO_INTR_PENDING(state_reg, ino) && !panicstr) {
		/*
		 * If we have a really large jump in hrtime, it is most
		 * probably because we entered the debugger (or OBP,
		 * in general). So, we adjust the timeout accordingly
		 * to prevent declaring an interrupt timeout. The
		 * master-interrupt mechanism in OBP should deliver
		 * the interrupts properly.
		 */
		prev = curr;
		curr = gethrtime();
		interval = curr - prev;
		if (interval > jump)
			intr_timeout += interval;
		if (curr - start_time > intr_timeout) {
			pcmu_pbm_t *pcbm_p = pcmu_p->pcmu_pcbm_p;
			cmn_err(CE_WARN,
			    "%s:%s: pcmu_ib_ino_rem_intr %x timeout",
			    pcbm_p->pcbm_nameinst_str,
			    pcbm_p->pcbm_nameaddr_str, ino);
			PCMU_IB_INO_INTR_ON(ino_p->pino_map_reg);
			*ino_p->pino_map_reg;
			return (DDI_FAILURE);
		}
	}

	if (ino_p->pino_ih_size == 1) {
		if (ih_lst != ih_p)
			goto not_found;
		/* no need to set head/tail as ino_p will be freed */
		goto reset;
	}

	/*
	 * if the interrupt was previously blocked (left in pending state)
	 * because of jabber we need to clear the pending state in case the
	 * jabber has gone away.
	 */
	if (ino_p->pino_unclaimed > pcmu_unclaimed_intr_max) {
		cmn_err(CE_WARN,
		    "%s%d: pcmu_ib_ino_rem_intr: ino 0x%x has been unblocked",
		    ddi_driver_name(pcmu_p->pcmu_dip),
		    ddi_get_instance(pcmu_p->pcmu_dip),
		    ino_p->pino_ino);
		ino_p->pino_unclaimed = 0;
		PCMU_IB_INO_INTR_CLEAR(ino_p->pino_clr_reg);
	}

	/* search the link list for ih_p */
	for (i = 0; (i < ino_p->pino_ih_size) && (ih_lst->ih_next != ih_p);
	    i++, ih_lst = ih_lst->ih_next)
		;
	if (ih_lst->ih_next != ih_p) {
		goto not_found;
	}

	/* remove ih_p from the link list and maintain the head/tail */
	ih_lst->ih_next = ih_p->ih_next;
	if (ino_p->pino_ih_head == ih_p) {
		ino_p->pino_ih_head = ih_p->ih_next;
	}
	if (ino_p->pino_ih_tail == ih_p) {
		ino_p->pino_ih_tail = ih_lst;
	}
	ino_p->pino_ih_start = ino_p->pino_ih_head;
reset:
	if (ih_p->ih_config_handle) {
		pci_config_teardown(&ih_p->ih_config_handle);
	}
	kmem_free(ih_p, sizeof (ih_t));
	ino_p->pino_ih_size--;

	return (DDI_SUCCESS);
not_found:
	PCMU_DBG2(PCMU_DBG_R_INTX, ino_p->pino_ib_p->pib_pcmu_p->pcmu_dip,
	    "ino_p=%x does not have ih_p=%x\n", ino_p, ih_p);
	return (DDI_SUCCESS);
}

ih_t *
pcmu_ib_ino_locate_intr(pcmu_ib_ino_info_t *ino_p,
    dev_info_t *rdip, uint32_t inum)
{
	ih_t *ih_lst = ino_p->pino_ih_head;
	int i;
	for (i = 0; i < ino_p->pino_ih_size; i++, ih_lst = ih_lst->ih_next) {
		if (ih_lst->ih_dip == rdip && ih_lst->ih_inum == inum) {
			return (ih_lst);
		}
	}
	return ((ih_t *)NULL);
}

ih_t *
pcmu_ib_alloc_ih(dev_info_t *rdip, uint32_t inum,
    uint_t (*int_handler)(caddr_t int_handler_arg1, caddr_t int_handler_arg2),
    caddr_t int_handler_arg1,
    caddr_t int_handler_arg2)
{
	ih_t *ih_p;

	ih_p = kmem_alloc(sizeof (ih_t), KM_SLEEP);
	ih_p->ih_dip = rdip;
	ih_p->ih_inum = inum;
	ih_p->ih_intr_state = PCMU_INTR_STATE_DISABLE;
	ih_p->ih_handler = int_handler;
	ih_p->ih_handler_arg1 = int_handler_arg1;
	ih_p->ih_handler_arg2 = int_handler_arg2;
	ih_p->ih_config_handle = NULL;
	return (ih_p);
}

int
pcmu_ib_update_intr_state(pcmu_t *pcmu_p, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, uint_t new_intr_state)
{
	pcmu_ib_t		*pib_p = pcmu_p->pcmu_ib_p;
	pcmu_ib_ino_info_t	*ino_p;
	pcmu_ib_mondo_t	mondo;
	ih_t		*ih_p;
	int		ret = DDI_FAILURE;

	mutex_enter(&pib_p->pib_ino_lst_mutex);

	if ((mondo = PCMU_IB_INO_TO_MONDO(pcmu_p->pcmu_ib_p,
	    PCMU_IB_MONDO_TO_INO((int32_t)hdlp->ih_vector))) == 0) {
		mutex_exit(&pib_p->pib_ino_lst_mutex);
		return (ret);
	}

	if (ino_p = pcmu_ib_locate_ino(pib_p, PCMU_IB_MONDO_TO_INO(mondo))) {
		if (ih_p = pcmu_ib_ino_locate_intr(ino_p,
		    rdip, hdlp->ih_inum)) {
			ih_p->ih_intr_state = new_intr_state;
			ret = DDI_SUCCESS;
		}
	}
	mutex_exit(&pib_p->pib_ino_lst_mutex);
	return (ret);
}
