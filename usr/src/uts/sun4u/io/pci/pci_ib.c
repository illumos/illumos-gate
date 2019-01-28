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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Peter Tribble.
 */

/*
 * PCI Interrupt Block (RISCx) implementation
 *	initialization
 *	interrupt enable/disable/clear and mapping register manipulation
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/systm.h>		/* panicstr */
#include <sys/spl.h>
#include <sys/sunddi.h>
#include <sys/machsystm.h>	/* intr_dist_add */
#include <sys/ddi_impldefs.h>
#include <sys/clock.h>
#include <sys/cpuvar.h>
#include <sys/pci/pci_obj.h>

/*LINTLIBRARY*/
static uint_t ib_intr_reset(void *arg);

void
ib_create(pci_t *pci_p)
{
	dev_info_t *dip = pci_p->pci_dip;
	ib_t *ib_p;
	uintptr_t a;
	int i;

	/*
	 * Allocate interrupt block state structure and link it to
	 * the pci state structure.
	 */
	ib_p = kmem_zalloc(sizeof (ib_t), KM_SLEEP);
	pci_p->pci_ib_p = ib_p;
	ib_p->ib_pci_p = pci_p;

	a = pci_ib_setup(ib_p);

	/*
	 * Determine virtual addresses of interrupt mapping, clear and diag
	 * registers that have common offsets.
	 */
	ib_p->ib_slot_clear_intr_regs =
	    a + COMMON_IB_SLOT_CLEAR_INTR_REG_OFFSET;
	ib_p->ib_intr_retry_timer_reg =
	    (uint64_t *)(a + COMMON_IB_INTR_RETRY_TIMER_OFFSET);
	ib_p->ib_slot_intr_state_diag_reg =
	    (uint64_t *)(a + COMMON_IB_SLOT_INTR_STATE_DIAG_REG);
	ib_p->ib_obio_intr_state_diag_reg =
	    (uint64_t *)(a + COMMON_IB_OBIO_INTR_STATE_DIAG_REG);

	if (CHIP_TYPE(pci_p) != PCI_CHIP_XMITS) {
		ib_p->ib_upa_imr[0] = (volatile uint64_t *)
		    (a + COMMON_IB_UPA0_INTR_MAP_REG_OFFSET);
		ib_p->ib_upa_imr[1] = (volatile uint64_t *)
		    (a + COMMON_IB_UPA1_INTR_MAP_REG_OFFSET);
	}

	DEBUG2(DBG_ATTACH, dip, "ib_create: slot_imr=%x, slot_cir=%x\n",
	    ib_p->ib_slot_intr_map_regs, ib_p->ib_obio_intr_map_regs);
	DEBUG2(DBG_ATTACH, dip, "ib_create: obio_imr=%x, obio_cir=%x\n",
	    ib_p->ib_slot_clear_intr_regs, ib_p->ib_obio_clear_intr_regs);
	DEBUG2(DBG_ATTACH, dip, "ib_create: upa0_imr=%x, upa1_imr=%x\n",
	    ib_p->ib_upa_imr[0], ib_p->ib_upa_imr[1]);
	DEBUG3(DBG_ATTACH, dip,
	    "ib_create: retry_timer=%x, obio_diag=%x slot_diag=%x\n",
	    ib_p->ib_intr_retry_timer_reg,
	    ib_p->ib_obio_intr_state_diag_reg,
	    ib_p->ib_slot_intr_state_diag_reg);

	ib_p->ib_ino_lst = (ib_ino_info_t *)NULL;
	mutex_init(&ib_p->ib_intr_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ib_p->ib_ino_lst_mutex, NULL, MUTEX_DRIVER, NULL);

	DEBUG1(DBG_ATTACH, dip, "ib_create: numproxy=%x\n",
	    pci_p->pci_numproxy);
	for (i = 1; i <= pci_p->pci_numproxy; i++) {
		set_intr_mapping_reg(pci_p->pci_id,
		    (uint64_t *)ib_p->ib_upa_imr[i - 1], i);
	}

	ib_configure(ib_p);
	bus_func_register(BF_TYPE_RESINTR, ib_intr_reset, ib_p);
}

void
ib_destroy(pci_t *pci_p)
{
	ib_t *ib_p = pci_p->pci_ib_p;
	dev_info_t *dip = pci_p->pci_dip;

	DEBUG0(DBG_IB, dip, "ib_destroy\n");
	bus_func_unregister(BF_TYPE_RESINTR, ib_intr_reset, ib_p);

	intr_dist_rem_weighted(ib_intr_dist_all, ib_p);
	mutex_destroy(&ib_p->ib_ino_lst_mutex);
	mutex_destroy(&ib_p->ib_intr_lock);

	ib_free_ino_all(ib_p);

	kmem_free(ib_p, sizeof (ib_t));
	pci_p->pci_ib_p = NULL;
}

void
ib_configure(ib_t *ib_p)
{
	/* XXX could be different between psycho and schizo */
	*ib_p->ib_intr_retry_timer_reg = pci_intr_retry_intv;
}

/*
 * can only used for psycho internal interrupts thermal, power,
 * ue, ce, pbm
 */
void
ib_intr_enable(pci_t *pci_p, ib_ino_t ino)
{
	ib_t *ib_p = pci_p->pci_ib_p;
	ib_mondo_t mondo = IB_INO_TO_MONDO(ib_p, ino);
	volatile uint64_t *imr_p = ib_intr_map_reg_addr(ib_p, ino);
	uint_t cpu_id;

	/*
	 * Determine the cpu for the interrupt.
	 */
	mutex_enter(&ib_p->ib_intr_lock);
	cpu_id = intr_dist_cpuid();
	DEBUG2(DBG_IB, pci_p->pci_dip,
	    "ib_intr_enable: ino=%x cpu_id=%x\n", ino, cpu_id);

	*imr_p = ib_get_map_reg(mondo, cpu_id);
	IB_INO_INTR_CLEAR(ib_clear_intr_reg_addr(ib_p, ino));
	mutex_exit(&ib_p->ib_intr_lock);
}

/*
 * Disable the interrupt via its interrupt mapping register.
 * Can only be used for internal interrupts: thermal, power, ue, ce, pbm.
 * If called under interrupt context, wait should be set to 0
 */
void
ib_intr_disable(ib_t *ib_p, ib_ino_t ino, int wait)
{
	volatile uint64_t *imr_p = ib_intr_map_reg_addr(ib_p, ino);
	volatile uint64_t *state_reg_p = IB_INO_INTR_STATE_REG(ib_p, ino);
	hrtime_t start_time;

	/* disable the interrupt */
	mutex_enter(&ib_p->ib_intr_lock);
	IB_INO_INTR_OFF(imr_p);
	*imr_p;	/* flush previous write */
	mutex_exit(&ib_p->ib_intr_lock);

	if (!wait)
		goto wait_done;

	start_time = gethrtime();
	/* busy wait if there is interrupt being processed */
	while (IB_INO_INTR_PENDING(state_reg_p, ino) && !panicstr) {
		if (gethrtime() - start_time > pci_intrpend_timeout) {
			pbm_t *pbm_p = ib_p->ib_pci_p->pci_pbm_p;
			cmn_err(CE_WARN, "%s:%s: ib_intr_disable timeout %x",
			    pbm_p->pbm_nameinst_str,
			    pbm_p->pbm_nameaddr_str, ino);
				break;
		}
	}
wait_done:
	IB_INO_INTR_PEND(ib_clear_intr_reg_addr(ib_p, ino));
}

/* can only used for psycho internal interrupts thermal, power, ue, ce, pbm */
void
ib_nintr_clear(ib_t *ib_p, ib_ino_t ino)
{
	uint64_t *clr_reg = ib_clear_intr_reg_addr(ib_p, ino);
	IB_INO_INTR_CLEAR(clr_reg);
}

/*
 * distribute PBM and UPA interrupts. ino is set to 0 by caller if we
 * are dealing with UPA interrupts (without inos).
 */
void
ib_intr_dist_nintr(ib_t *ib_p, ib_ino_t ino, volatile uint64_t *imr_p)
{
	volatile uint64_t imr = *imr_p;
	uint32_t cpu_id;

	if (!IB_INO_INTR_ISON(imr))
		return;

	cpu_id = intr_dist_cpuid();

	if (ib_map_reg_get_cpu(*imr_p) == cpu_id)
		return;

	*imr_p = ib_get_map_reg(IB_IMR2MONDO(imr), cpu_id);
	imr = *imr_p;	/* flush previous write */
}

/*
 * Converts into nsec, ticks logged with a given CPU.  Adds nsec to ih.
 */
/*ARGSUSED*/
void
ib_cpu_ticks_to_ih_nsec(ib_t *ib_p, ih_t *ih_p, uint32_t cpu_id)
{
	extern kmutex_t pciintr_ks_template_lock;
	hrtime_t ticks;

	/*
	 * Because we are updating two fields in ih_t we must lock
	 * pciintr_ks_template_lock to prevent someone from reading the
	 * kstats after we set ih_ticks to 0 and before we increment
	 * ih_nsec to compensate.
	 *
	 * We must also protect against the interrupt arriving and incrementing
	 * ih_ticks between the time we read it and when we reset it to 0.
	 * To do this we use atomic_swap.
	 */

	ASSERT(MUTEX_HELD(&ib_p->ib_ino_lst_mutex));

	mutex_enter(&pciintr_ks_template_lock);
	ticks = atomic_swap_64(&ih_p->ih_ticks, 0);
	ih_p->ih_nsec += (uint64_t)tick2ns(ticks, cpu_id);
	mutex_exit(&pciintr_ks_template_lock);
}

static void
ib_intr_dist(ib_t *ib_p, ib_ino_info_t *ino_p)
{
	uint32_t cpu_id = ino_p->ino_cpuid;
	ib_ino_t ino = ino_p->ino_ino;
	volatile uint64_t imr, *imr_p, *state_reg;
	hrtime_t start_time;

	ASSERT(MUTEX_HELD(&ib_p->ib_ino_lst_mutex));
	imr_p = ib_intr_map_reg_addr(ib_p, ino);
	state_reg = IB_INO_INTR_STATE_REG(ib_p, ino);

	if (ib_map_reg_get_cpu(*imr_p) == cpu_id) /* same cpu, no reprog */
		return;

	/* disable interrupt, this could disrupt devices sharing our slot */
	IB_INO_INTR_OFF(imr_p);
	imr = *imr_p;	/* flush previous write */

	/* busy wait if there is interrupt being processed */
	start_time = gethrtime();
	while (IB_INO_INTR_PENDING(state_reg, ino) && !panicstr) {
		if (gethrtime() - start_time > pci_intrpend_timeout) {
			pbm_t *pbm_p = ib_p->ib_pci_p->pci_pbm_p;
			cmn_err(CE_WARN, "%s:%s: ib_intr_dist(%p,%x) timeout",
			    pbm_p->pbm_nameinst_str,
			    pbm_p->pbm_nameaddr_str,
			    imr_p, IB_INO_TO_MONDO(ib_p, ino));
			break;
		}
	}
	*imr_p = ib_get_map_reg(IB_IMR2MONDO(imr), cpu_id);
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
ib_intr_dist_all(void *arg, int32_t weight_max, int32_t weight)
{
	ib_t *ib_p = (ib_t *)arg;
	pci_t *pci_p = ib_p->ib_pci_p;
	ib_ino_info_t *ino_p;
	ib_ino_pil_t *ipil_p;
	ih_t *ih_lst;
	int32_t dweight;
	int i;

	if (weight == 0) {
		mutex_enter(&ib_p->ib_intr_lock);
		if (CHIP_TYPE(pci_p) != PCI_CHIP_XMITS) {
			for (i = 0; i < 2; i++)
				ib_intr_dist_nintr(ib_p, 0,
				    ib_p->ib_upa_imr[i]);
		}
		mutex_exit(&ib_p->ib_intr_lock);
	}

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	/* Perform special processing for first call of a redistribution. */
	if (weight == weight_max) {
		for (ino_p = ib_p->ib_ino_lst; ino_p;
		    ino_p = ino_p->ino_next_p) {

			/*
			 * Clear ino_established of each ino on first call.
			 * The ino_established field may be used by a pci
			 * nexus driver's pci_intr_dist_cpuid implementation
			 * when detection of established pci slot-cpu binding
			 * for multi function pci cards.
			 */
			ino_p->ino_established = 0;

			/*
			 * recompute the ino_intr_weight based on the device
			 * weight of all devinfo nodes sharing the ino (this
			 * will allow us to pick up new weights established by
			 * i_ddi_set_intr_weight()).
			 */
			ino_p->ino_intr_weight = 0;

			for (ipil_p = ino_p->ino_ipil_p; ipil_p;
			    ipil_p = ipil_p->ipil_next_p) {
				for (i = 0, ih_lst = ipil_p->ipil_ih_head;
				    i < ipil_p->ipil_ih_size; i++,
				    ih_lst = ih_lst->ih_next) {
					dweight = i_ddi_get_intr_weight
					    (ih_lst->ih_dip);
					if (dweight > 0)
						ino_p->ino_intr_weight +=
						    dweight;
				}
			}
		}
	}

	for (ino_p = ib_p->ib_ino_lst; ino_p; ino_p = ino_p->ino_next_p) {
		uint32_t orig_cpuid;

		/*
		 * Get the weight of the ino and determine if we are going to
		 * process call.  We wait until an ib_intr_dist_all call of
		 * the proper weight occurs to support redistribution of all
		 * heavy weighted interrupts first (across all nexus driver
		 * instances).  This is done to ensure optimal
		 * INTR_WEIGHTED_DIST behavior.
		 */
		if ((weight == ino_p->ino_intr_weight) ||
		    ((weight >= weight_max) &&
		    (ino_p->ino_intr_weight >= weight_max))) {
			/* select cpuid to target and mark ino established */
			orig_cpuid = ino_p->ino_cpuid;
			if (cpu[orig_cpuid] == NULL)
				orig_cpuid = CPU->cpu_id;
			ino_p->ino_cpuid = pci_intr_dist_cpuid(ib_p, ino_p);
			ino_p->ino_established = 1;

			/* Add device weight of ino devinfos to targeted cpu. */
			for (ipil_p = ino_p->ino_ipil_p; ipil_p;
			    ipil_p = ipil_p->ipil_next_p) {
				for (i = 0, ih_lst = ipil_p->ipil_ih_head;
				    i < ipil_p->ipil_ih_size; i++,
				    ih_lst = ih_lst->ih_next) {

					dweight = i_ddi_get_intr_weight(
					    ih_lst->ih_dip);
					intr_dist_cpuid_add_device_weight(
					    ino_p->ino_cpuid, ih_lst->ih_dip,
					    dweight);

					/*
					 * Different cpus may have different
					 * clock speeds. to account for this,
					 * whenever an interrupt is moved to a
					 * new CPU, we convert the accumulated
					 * ticks into nsec, based upon the clock
					 * rate of the prior CPU.
					 *
					 * It is possible that the prior CPU no
					 * longer exists. In this case, fall
					 * back to using this CPU's clock rate.
					 *
					 * Note that the value in ih_ticks has
					 * already been corrected for any power
					 * savings mode which might have been
					 * in effect.
					 */
					ib_cpu_ticks_to_ih_nsec(ib_p, ih_lst,
					    orig_cpuid);
				}
			}

			/* program the hardware */
			ib_intr_dist(ib_p, ino_p);
		}
	}
	mutex_exit(&ib_p->ib_ino_lst_mutex);
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
ib_intr_reset(void *arg)
{
	ib_t *ib_p = (ib_t *)arg;
	ib_ino_t ino;
	uint64_t *clr_reg;

	/*
	 * Note that we only actually care about interrupts that are
	 * potentially from network devices.
	 */
	for (ino = 0; ino <= ib_p->ib_max_ino; ino++) {
		clr_reg = ib_clear_intr_reg_addr(ib_p, ino);
		IB_INO_INTR_CLEAR(clr_reg);
	}

	return (BF_NONE);
}

void
ib_suspend(ib_t *ib_p)
{
	ib_ino_info_t *ip;
	pci_t *pci_p = ib_p->ib_pci_p;

	/* save ino_lst interrupts' mapping registers content */
	mutex_enter(&ib_p->ib_ino_lst_mutex);
	for (ip = ib_p->ib_ino_lst; ip; ip = ip->ino_next_p)
		ip->ino_map_reg_save = *ip->ino_map_reg;
	mutex_exit(&ib_p->ib_ino_lst_mutex);

	if (CHIP_TYPE(pci_p) != PCI_CHIP_XMITS) {
		ib_p->ib_upa_imr_state[0] = *ib_p->ib_upa_imr[0];
		ib_p->ib_upa_imr_state[1] = *ib_p->ib_upa_imr[1];
	}
}

void
ib_resume(ib_t *ib_p)
{
	ib_ino_info_t *ip;
	pci_t *pci_p = ib_p->ib_pci_p;

	/* restore ino_lst interrupts' mapping registers content */
	mutex_enter(&ib_p->ib_ino_lst_mutex);
	for (ip = ib_p->ib_ino_lst; ip; ip = ip->ino_next_p) {
		IB_INO_INTR_CLEAR(ip->ino_clr_reg);	 /* set intr to idle */
		*ip->ino_map_reg = ip->ino_map_reg_save; /* restore IMR */
	}
	mutex_exit(&ib_p->ib_ino_lst_mutex);

	if (CHIP_TYPE(pci_p) != PCI_CHIP_XMITS) {
		*ib_p->ib_upa_imr[0] = ib_p->ib_upa_imr_state[0];
		*ib_p->ib_upa_imr[1] = ib_p->ib_upa_imr_state[1];
	}
}

/*
 * locate ino_info structure on ib_p->ib_ino_lst according to ino#
 * returns NULL if not found.
 */
ib_ino_info_t *
ib_locate_ino(ib_t *ib_p, ib_ino_t ino_num)
{
	ib_ino_info_t *ino_p = ib_p->ib_ino_lst;
	ASSERT(MUTEX_HELD(&ib_p->ib_ino_lst_mutex));

	for (; ino_p && ino_p->ino_ino != ino_num; ino_p = ino_p->ino_next_p)
		;
	return (ino_p);
}

#define	IB_INO_TO_SLOT(ino) (IB_IS_OBIO_INO(ino) ? 0xff : ((ino) & 0x1f) >> 2)

ib_ino_pil_t *
ib_new_ino_pil(ib_t *ib_p, ib_ino_t ino_num, uint_t pil, ih_t *ih_p)
{
	ib_ino_pil_t	*ipil_p = kmem_zalloc(sizeof (ib_ino_pil_t), KM_SLEEP);
	ib_ino_info_t	*ino_p;

	if ((ino_p = ib_locate_ino(ib_p, ino_num)) == NULL) {
		ino_p = kmem_zalloc(sizeof (ib_ino_info_t), KM_SLEEP);

		ino_p->ino_next_p = ib_p->ib_ino_lst;
		ib_p->ib_ino_lst = ino_p;

		ino_p->ino_ino = ino_num;
		ino_p->ino_slot_no = IB_INO_TO_SLOT(ino_num);
		ino_p->ino_ib_p = ib_p;
		ino_p->ino_clr_reg = ib_clear_intr_reg_addr(ib_p, ino_num);
		ino_p->ino_map_reg = ib_intr_map_reg_addr(ib_p, ino_num);
		ino_p->ino_unclaimed_intrs = 0;
		ino_p->ino_lopil = pil;
	}

	ih_p->ih_next = ih_p;
	ipil_p->ipil_pil = pil;
	ipil_p->ipil_ih_head = ih_p;
	ipil_p->ipil_ih_tail = ih_p;
	ipil_p->ipil_ih_start = ih_p;
	ipil_p->ipil_ih_size = 1;
	ipil_p->ipil_ino_p = ino_p;

	ipil_p->ipil_next_p = ino_p->ino_ipil_p;
	ino_p->ino_ipil_p = ipil_p;
	ino_p->ino_ipil_size++;

	if (ino_p->ino_lopil > pil)
		ino_p->ino_lopil = pil;

	return (ipil_p);
}

void
ib_delete_ino_pil(ib_t *ib_p, ib_ino_pil_t *ipil_p)
{
	ib_ino_info_t	*ino_p = ipil_p->ipil_ino_p;
	ib_ino_pil_t	*prev, *next;
	ushort_t	pil = ipil_p->ipil_pil;

	ASSERT(MUTEX_HELD(&ib_p->ib_ino_lst_mutex));

	if (ino_p->ino_ipil_p == ipil_p)
		ino_p->ino_ipil_p = ipil_p->ipil_next_p;
	else {
		for (prev = next = ino_p->ino_ipil_p; next != ipil_p;
		    prev = next, next = next->ipil_next_p)
			;

		if (prev)
			prev->ipil_next_p = ipil_p->ipil_next_p;
	}

	kmem_free(ipil_p, sizeof (ib_ino_pil_t));

	if ((--ino_p->ino_ipil_size) && (ino_p->ino_lopil == pil)) {
		for (next = ino_p->ino_ipil_p, pil = next->ipil_pil;
		    next; next = next->ipil_next_p) {

			if (pil > next->ipil_pil)
				pil = next->ipil_pil;
		}
		/*
		 * Value stored in pil should be the lowest pil.
		 */
		ino_p->ino_lopil = pil;
	}

	if (ino_p->ino_ipil_size)
		return;

	if (ib_p->ib_ino_lst == ino_p)
		ib_p->ib_ino_lst = ino_p->ino_next_p;
	else {
		ib_ino_info_t	*list = ib_p->ib_ino_lst;

		for (; list->ino_next_p != ino_p; list = list->ino_next_p)
			;
		list->ino_next_p = ino_p->ino_next_p;
	}
}

/* free all ino when we are detaching */
void
ib_free_ino_all(ib_t *ib_p)
{
	ib_ino_info_t *ino_p = ib_p->ib_ino_lst;
	ib_ino_info_t *next = NULL;

	while (ino_p) {
		next = ino_p->ino_next_p;
		kmem_free(ino_p, sizeof (ib_ino_info_t));
		ino_p = next;
	}
}

/*
 * Locate ib_ino_pil_t structure on ino_p->ino_ipil_p according to ino#
 * returns NULL if not found.
 */
ib_ino_pil_t *
ib_ino_locate_ipil(ib_ino_info_t *ino_p, uint_t pil)
{
	ib_ino_pil_t	*ipil_p = ino_p->ino_ipil_p;

	for (; ipil_p && ipil_p->ipil_pil != pil; ipil_p = ipil_p->ipil_next_p)
		;

	return (ipil_p);
}

void
ib_ino_add_intr(pci_t *pci_p, ib_ino_pil_t *ipil_p, ih_t *ih_p)
{
	ib_ino_info_t *ino_p = ipil_p->ipil_ino_p;
	ib_ino_t ino = ino_p->ino_ino;
	ib_t *ib_p = ino_p->ino_ib_p;
	volatile uint64_t *state_reg = IB_INO_INTR_STATE_REG(ib_p, ino);
	hrtime_t start_time;

	ASSERT(ib_p == pci_p->pci_ib_p);
	ASSERT(MUTEX_HELD(&ib_p->ib_ino_lst_mutex));

	/* disable interrupt, this could disrupt devices sharing our slot */
	IB_INO_INTR_OFF(ino_p->ino_map_reg);
	*ino_p->ino_map_reg;

	/* do NOT modify the link list until after the busy wait */

	/*
	 * busy wait if there is interrupt being processed.
	 * either the pending state will be cleared by the interrupt wrapper
	 * or the interrupt will be marked as blocked indicating that it was
	 * jabbering.
	 */
	start_time = gethrtime();
	while ((ino_p->ino_unclaimed_intrs <= pci_unclaimed_intr_max) &&
	    IB_INO_INTR_PENDING(state_reg, ino) && !panicstr) {
		if (gethrtime() - start_time > pci_intrpend_timeout) {
			pbm_t *pbm_p = pci_p->pci_pbm_p;
			cmn_err(CE_WARN, "%s:%s: ib_ino_add_intr %x timeout",
			    pbm_p->pbm_nameinst_str,
			    pbm_p->pbm_nameaddr_str, ino);
			break;
		}
	}

	/* link up ih_t */
	ih_p->ih_next = ipil_p->ipil_ih_head;
	ipil_p->ipil_ih_tail->ih_next = ih_p;
	ipil_p->ipil_ih_tail = ih_p;

	ipil_p->ipil_ih_start = ipil_p->ipil_ih_head;
	ipil_p->ipil_ih_size++;

	/*
	 * if the interrupt was previously blocked (left in pending state)
	 * because of jabber we need to clear the pending state in case the
	 * jabber has gone away.
	 */
	if (ino_p->ino_unclaimed_intrs > pci_unclaimed_intr_max) {
		cmn_err(CE_WARN,
		    "%s%d: ib_ino_add_intr: ino 0x%x has been unblocked",
		    ddi_driver_name(pci_p->pci_dip),
		    ddi_get_instance(pci_p->pci_dip),
		    ino_p->ino_ino);
		ino_p->ino_unclaimed_intrs = 0;
		IB_INO_INTR_CLEAR(ino_p->ino_clr_reg);
	}

	/* re-enable interrupt */
	IB_INO_INTR_ON(ino_p->ino_map_reg);
	*ino_p->ino_map_reg;
}

/*
 * removes pci_ispec_t from the ino's link list.
 * uses hardware mutex to lock out interrupt threads.
 * Side effects: interrupt belongs to that ino is turned off on return.
 * if we are sharing PCI slot with other inos, the caller needs
 * to turn it back on.
 */
void
ib_ino_rem_intr(pci_t *pci_p, ib_ino_pil_t *ipil_p, ih_t *ih_p)
{
	ib_ino_info_t *ino_p = ipil_p->ipil_ino_p;
	int i;
	ib_ino_t ino = ino_p->ino_ino;
	ih_t *ih_lst = ipil_p->ipil_ih_head;
	volatile uint64_t *state_reg =
	    IB_INO_INTR_STATE_REG(ino_p->ino_ib_p, ino);
	hrtime_t start_time;

	ASSERT(MUTEX_HELD(&ino_p->ino_ib_p->ib_ino_lst_mutex));
	/* disable interrupt, this could disrupt devices sharing our slot */
	IB_INO_INTR_OFF(ino_p->ino_map_reg);
	*ino_p->ino_map_reg;

	/* do NOT modify the link list until after the busy wait */

	/*
	 * busy wait if there is interrupt being processed.
	 * either the pending state will be cleared by the interrupt wrapper
	 * or the interrupt will be marked as blocked indicating that it was
	 * jabbering.
	 */
	start_time = gethrtime();
	while ((ino_p->ino_unclaimed_intrs <= pci_unclaimed_intr_max) &&
	    IB_INO_INTR_PENDING(state_reg, ino) && !panicstr) {
		if (gethrtime() - start_time > pci_intrpend_timeout) {
			pbm_t *pbm_p = pci_p->pci_pbm_p;
			cmn_err(CE_WARN, "%s:%s: ib_ino_rem_intr %x timeout",
			    pbm_p->pbm_nameinst_str,
			    pbm_p->pbm_nameaddr_str, ino);
			break;
		}
	}

	if (ipil_p->ipil_ih_size == 1) {
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
	if (ino_p->ino_unclaimed_intrs > pci_unclaimed_intr_max) {
		cmn_err(CE_WARN,
		    "%s%d: ib_ino_rem_intr: ino 0x%x has been unblocked",
		    ddi_driver_name(pci_p->pci_dip),
		    ddi_get_instance(pci_p->pci_dip),
		    ino_p->ino_ino);
		ino_p->ino_unclaimed_intrs = 0;
		IB_INO_INTR_CLEAR(ino_p->ino_clr_reg);
	}

	/* search the link list for ih_p */
	for (i = 0;
	    (i < ipil_p->ipil_ih_size) && (ih_lst->ih_next != ih_p);
	    i++, ih_lst = ih_lst->ih_next)
		;
	if (ih_lst->ih_next != ih_p)
		goto not_found;

	/* remove ih_p from the link list and maintain the head/tail */
	ih_lst->ih_next = ih_p->ih_next;
	if (ipil_p->ipil_ih_head == ih_p)
		ipil_p->ipil_ih_head = ih_p->ih_next;
	if (ipil_p->ipil_ih_tail == ih_p)
		ipil_p->ipil_ih_tail = ih_lst;
	ipil_p->ipil_ih_start = ipil_p->ipil_ih_head;
reset:
	if (ih_p->ih_config_handle)
		pci_config_teardown(&ih_p->ih_config_handle);
	if (ih_p->ih_ksp != NULL)
		kstat_delete(ih_p->ih_ksp);
	kmem_free(ih_p, sizeof (ih_t));
	ipil_p->ipil_ih_size--;

	return;
not_found:
	DEBUG2(DBG_R_INTX, ino_p->ino_ib_p->ib_pci_p->pci_dip,
	    "ino_p=%x does not have ih_p=%x\n", ino_p, ih_p);
}

ih_t *
ib_intr_locate_ih(ib_ino_pil_t *ipil_p, dev_info_t *rdip, uint32_t inum)
{
	ih_t *ih_p = ipil_p->ipil_ih_head;
	int i;

	for (i = 0; i < ipil_p->ipil_ih_size; i++, ih_p = ih_p->ih_next) {
		if (ih_p->ih_dip == rdip && ih_p->ih_inum == inum)
			return (ih_p);
	}

	return ((ih_t *)NULL);
}

ih_t *
ib_alloc_ih(dev_info_t *rdip, uint32_t inum,
	uint_t (*int_handler)(caddr_t int_handler_arg1,
	caddr_t int_handler_arg2),
	caddr_t int_handler_arg1,
	caddr_t int_handler_arg2)
{
	ih_t *ih_p;

	ih_p = kmem_alloc(sizeof (ih_t), KM_SLEEP);
	ih_p->ih_dip = rdip;
	ih_p->ih_inum = inum;
	ih_p->ih_intr_state = PCI_INTR_STATE_DISABLE;
	ih_p->ih_handler = int_handler;
	ih_p->ih_handler_arg1 = int_handler_arg1;
	ih_p->ih_handler_arg2 = int_handler_arg2;
	ih_p->ih_config_handle = NULL;
	ih_p->ih_nsec = 0;
	ih_p->ih_ticks = 0;
	ih_p->ih_ksp = NULL;

	return (ih_p);
}

int
ib_update_intr_state(pci_t *pci_p, dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp, uint_t new_intr_state)
{
	ib_t		*ib_p = pci_p->pci_ib_p;
	ib_ino_info_t	*ino_p;
	ib_ino_pil_t	*ipil_p;
	ib_mondo_t	mondo;
	ih_t		*ih_p;
	int		ret = DDI_FAILURE;

	/*
	 * For PULSE interrupts, pci driver don't allocate
	 * ib_ino_info_t and ih_t data structures and also,
	 * not maintains any interrupt state information.
	 * So, just return success from here.
	 */
	if (hdlp->ih_vector & PCI_PULSE_INO) {
		DEBUG0(DBG_IB, ib_p->ib_pci_p->pci_dip,
		    "ib_update_intr_state: PULSE interrupt, return success\n");

		return (DDI_SUCCESS);
	}

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	if ((mondo = pci_xlate_intr(pci_p->pci_dip, rdip, pci_p->pci_ib_p,
	    IB_MONDO_TO_INO(hdlp->ih_vector))) == 0) {
		mutex_exit(&ib_p->ib_ino_lst_mutex);
		return (ret);
	}

	ino_p = ib_locate_ino(ib_p, IB_MONDO_TO_INO(mondo));
	if (ino_p && (ipil_p = ib_ino_locate_ipil(ino_p, hdlp->ih_pri))) {
		if (ih_p = ib_intr_locate_ih(ipil_p, rdip, hdlp->ih_inum)) {
			ih_p->ih_intr_state = new_intr_state;
			ret = DDI_SUCCESS;
		}
	}

	mutex_exit(&ib_p->ib_ino_lst_mutex);
	return (ret);
}

/*
 * Get interrupt CPU for a given ino.
 * Return info only for inos which are already mapped to devices.
 */
/*ARGSUSED*/
int
ib_get_intr_target(pci_t *pci_p, ib_ino_t ino, int *cpu_id_p)
{
	dev_info_t		*dip = pci_p->pci_dip;
	ib_t			*ib_p = pci_p->pci_ib_p;
	volatile uint64_t	*imregp;
	uint64_t		imregval;

	DEBUG1(DBG_IB, dip, "ib_get_intr_target: ino %x\n", ino);

	imregp = ib_intr_map_reg_addr(ib_p, ino);
	imregval = *imregp;

	*cpu_id_p = ib_map_reg_get_cpu(imregval);

	DEBUG1(DBG_IB, dip, "ib_get_intr_target: cpu_id %x\n", *cpu_id_p);

	return (DDI_SUCCESS);
}

/*
 * Associate a new CPU with a given ino.
 * Operate only on inos which are already mapped to devices.
 */
int
ib_set_intr_target(pci_t *pci_p, ib_ino_t ino, int cpu_id)
{
	dev_info_t		*dip = pci_p->pci_dip;
	ib_t			*ib_p = pci_p->pci_ib_p;
	int			ret = DDI_SUCCESS;
	uint32_t		old_cpu_id;
	hrtime_t		start_time;
	uint64_t		imregval;
	uint64_t		new_imregval;
	volatile uint64_t	*imregp;
	volatile uint64_t	*idregp;
	extern const int	_ncpu;
	extern cpu_t		*cpu[];

	DEBUG2(DBG_IB, dip, "ib_set_intr_target: ino %x cpu_id %x\n",
	    ino, cpu_id);

	imregp = (uint64_t *)ib_intr_map_reg_addr(ib_p, ino);
	idregp = IB_INO_INTR_STATE_REG(ib_p, ino);

	/* Save original mapreg value. */
	imregval = *imregp;
	DEBUG1(DBG_IB, dip, "ib_set_intr_target: orig mapreg value: 0x%llx\n",
	    imregval);

	/* Operate only on inos which are already enabled. */
	if (!(imregval & COMMON_INTR_MAP_REG_VALID))
		return (DDI_FAILURE);

	/* Is this request a noop? */
	if ((old_cpu_id = ib_map_reg_get_cpu(imregval)) == cpu_id)
		return (DDI_SUCCESS);

	/* Clear the interrupt valid/enable bit for particular ino. */
	DEBUG0(DBG_IB, dip, "Clearing intr_enabled...\n");
	*imregp = imregval & ~COMMON_INTR_MAP_REG_VALID;

	/* Wait until there are no more pending interrupts. */
	start_time = gethrtime();

	DEBUG0(DBG_IB, dip, "About to check for pending interrupts...\n");

	while (IB_INO_INTR_PENDING(idregp, ino)) {
		DEBUG0(DBG_IB, dip, "Waiting for pending ints to clear\n");
		if ((gethrtime() - start_time) < pci_intrpend_timeout) {
			continue;
		} else { /* Timed out waiting. */
			DEBUG0(DBG_IB, dip, "Timed out waiting \n");
			return (DDI_EPENDING);
		}
	}

	new_imregval = *imregp;

	DEBUG1(DBG_IB, dip,
	    "after disabling intr, mapreg value: 0x%llx\n", new_imregval);

	/*
	 * Get lock, validate cpu and write new mapreg value.
	 */
	mutex_enter(&cpu_lock);
	if ((cpu_id < _ncpu) && (cpu[cpu_id] && cpu_is_online(cpu[cpu_id]))) {
		/* Prepare new mapreg value with intr enabled and new cpu_id. */
		new_imregval &=
		    COMMON_INTR_MAP_REG_IGN | COMMON_INTR_MAP_REG_INO;
		new_imregval = ib_get_map_reg(new_imregval, cpu_id);

		DEBUG1(DBG_IB, dip, "Writing new mapreg value:0x%llx\n",
		    new_imregval);

		*imregp = new_imregval;

		ib_log_new_cpu(ib_p, old_cpu_id, cpu_id, ino);
	} else {	/* Invalid cpu.  Restore original register image. */
		DEBUG0(DBG_IB, dip,
		    "Invalid cpuid: writing orig mapreg value\n");

		*imregp = imregval;
		ret = DDI_EINVAL;
	}
	mutex_exit(&cpu_lock);

	return (ret);
}


/*
 * Return the dips or number of dips associated with a given interrupt block.
 * Size of dips array arg is passed in as dips_ret arg.
 * Number of dips returned is returned in dips_ret arg.
 * Array of dips gets returned in the dips argument.
 * Function returns number of dips existing for the given interrupt block.
 *
 */
uint8_t
ib_get_ino_devs(
	ib_t *ib_p, uint32_t ino, uint8_t *devs_ret, pcitool_intr_dev_t *devs)
{
	ib_ino_info_t	*ino_p;
	ib_ino_pil_t	*ipil_p;
	ih_t		*ih_p;
	uint32_t	num_devs = 0;
	int		i, j;

	mutex_enter(&ib_p->ib_ino_lst_mutex);
	ino_p = ib_locate_ino(ib_p, ino);
	if (ino_p != NULL) {
		for (j = 0, ipil_p = ino_p->ino_ipil_p; ipil_p;
		    ipil_p = ipil_p->ipil_next_p) {
			num_devs += ipil_p->ipil_ih_size;

			for (i = 0, ih_p = ipil_p->ipil_ih_head;
			    ((i < ipil_p->ipil_ih_size) && (i < *devs_ret));
			    i++, j++, ih_p = ih_p->ih_next) {
				(void) strlcpy(devs[i].driver_name,
				    ddi_driver_name(ih_p->ih_dip),
				    MAXMODCONFNAME);
				(void) ddi_pathname(ih_p->ih_dip, devs[i].path);
				devs[i].dev_inst =
				    ddi_get_instance(ih_p->ih_dip);
			}
		}
		*devs_ret = j;
	}

	mutex_exit(&ib_p->ib_ino_lst_mutex);

	return (num_devs);
}

void ib_log_new_cpu(ib_t *ib_p, uint32_t old_cpu_id, uint32_t new_cpu_id,
	uint32_t ino)
{
	ib_ino_info_t	*ino_p;
	ib_ino_pil_t	*ipil_p;
	ih_t		*ih_p;
	int		i;

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	/* Log in OS data structures the new CPU. */
	ino_p = ib_locate_ino(ib_p, ino);
	if (ino_p != NULL) {

		/* Log in OS data structures the new CPU. */
		ino_p->ino_cpuid = new_cpu_id;

		for (ipil_p = ino_p->ino_ipil_p; ipil_p;
		    ipil_p = ipil_p->ipil_next_p) {
			for (i = 0, ih_p = ipil_p->ipil_ih_head;
			    (i < ipil_p->ipil_ih_size);
			    i++, ih_p = ih_p->ih_next) {
				/*
				 * Account for any residual time
				 * to be logged for old cpu.
				 */
				ib_cpu_ticks_to_ih_nsec(ib_p,
				    ipil_p->ipil_ih_head, old_cpu_id);
			}
		}
	}

	mutex_exit(&ib_p->ib_ino_lst_mutex);
}
