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
 * CMU-CH Control Block object
 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/async.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pcicmu/pcicmu.h>
#include <sys/machsystm.h>

extern uint64_t	xc_tick_jump_limit;

void
pcmu_cb_create(pcmu_t *pcmu_p)
{
	pcmu_cb_t *pcb_p = (pcmu_cb_t *)
	    kmem_zalloc(sizeof (pcmu_cb_t), KM_SLEEP);
	mutex_init(&pcb_p->pcb_intr_lock, NULL, MUTEX_DRIVER, NULL);
	pcmu_p->pcmu_cb_p = pcb_p;
	pcb_p->pcb_pcmu_p = pcmu_p;
	pcmu_cb_setup(pcmu_p);
}

void
pcmu_cb_destroy(pcmu_t *pcmu_p)
{
	pcmu_cb_t *pcb_p = pcmu_p->pcmu_cb_p;

	intr_dist_rem(pcmu_cb_intr_dist, pcb_p);
	pcmu_cb_teardown(pcmu_p);
	pcmu_p->pcmu_cb_p = NULL;
	mutex_destroy(&pcb_p->pcb_intr_lock);
	kmem_free(pcb_p, sizeof (pcmu_cb_t));
}

uint64_t
pcmu_cb_ino_to_map_pa(pcmu_cb_t *pcb_p, pcmu_ib_ino_t ino)
{
	return (pcb_p->pcb_map_pa + ((ino & 0x1f) << 3));
}

uint64_t
pcmu_cb_ino_to_clr_pa(pcmu_cb_t *pcb_p, pcmu_ib_ino_t ino)
{
	return (pcb_p->pcb_clr_pa + ((ino & 0x1f) << 3));
}

static void
pcmu_cb_set_nintr_reg(pcmu_cb_t *pcb_p, pcmu_ib_ino_t ino, uint64_t value)
{
	uint64_t pa = pcmu_cb_ino_to_clr_pa(pcb_p, ino);

	PCMU_DBG3(PCMU_DBG_CB|PCMU_DBG_CONT, NULL,
		"pci-%x pcmu_cb_set_nintr_reg: ino=%x PA=%016llx\n",
		pcb_p->pcb_pcmu_p->pcmu_id, ino, pa);

	stdphysio(pa, value);
	(void) lddphysio(pa);	/* flush the previous write */
}

/*
 * enable an internal interrupt source:
 * if an interrupt is shared by both sides, record it in pcb_inos[] and
 * cb will own its distribution.
 */
void
pcmu_cb_enable_nintr(pcmu_t *pcmu_p, pcmu_cb_nintr_index_t idx)
{
	pcmu_cb_t *pcb_p = pcmu_p->pcmu_cb_p;
	pcmu_ib_ino_t ino = PCMU_IB_MONDO_TO_INO(pcmu_p->pcmu_inos[idx]);
	pcmu_ib_mondo_t mondo = PCMU_CB_INO_TO_MONDO(pcb_p, ino);
	uint32_t cpu_id;
	uint64_t reg, pa;
	pcmu_ib_t *pib_p = pcb_p->pcb_pcmu_p->pcmu_ib_p;
	volatile uint64_t *imr_p = ib_intr_map_reg_addr(pib_p, ino);

	ASSERT(idx < CBNINTR_MAX);
	pa = pcmu_cb_ino_to_map_pa(pcb_p, ino);

	mutex_enter(&pcb_p->pcb_intr_lock);
	cpu_id = intr_dist_cpuid();

	cpu_id = u2u_translate_tgtid(pib_p->pib_pcmu_p, cpu_id, imr_p);

	reg = ib_get_map_reg(mondo, cpu_id);
	stdphysio(pa, reg);

	ASSERT(pcb_p->pcb_inos[idx] == 0);
	pcb_p->pcb_inos[idx] = ino;

	pcmu_cb_set_nintr_reg(pcb_p, ino, PCMU_CLEAR_INTR_REG_IDLE);
	mutex_exit(&pcb_p->pcb_intr_lock);

	PCMU_DBG3(PCMU_DBG_CB|PCMU_DBG_CONT, NULL,
	    "pci-%x pcmu_cb_enable_nintr: ino=%x cpu_id=%x\n",
	    pcmu_p->pcmu_id, ino, cpu_id);
	PCMU_DBG2(PCMU_DBG_CB|PCMU_DBG_CONT, NULL,
	    "\tPA=%016llx data=%016llx\n", pa, reg);
}

static void
pcmu_cb_disable_nintr_reg(pcmu_cb_t *pcb_p, pcmu_ib_ino_t ino, int wait)
{
	uint64_t tmp, map_reg_pa = pcmu_cb_ino_to_map_pa(pcb_p, ino);
	ASSERT(MUTEX_HELD(&pcb_p->pcb_intr_lock));

	/* mark interrupt invalid in mapping register */
	tmp = lddphysio(map_reg_pa) & ~PCMU_INTR_MAP_REG_VALID;
	stdphysio(map_reg_pa, tmp);
	(void) lddphysio(map_reg_pa);   /* flush previous write */

	if (wait) {
		hrtime_t start_time;
		hrtime_t prev, curr, interval, jump;
		hrtime_t intr_timeout;
		uint64_t state_reg_pa = pcb_p->pcb_obsta_pa;
		uint_t shift = (ino & 0x1f) << 1;

		/* busy wait if there is interrupt being processed */
		/* unless panic or timeout for interrupt pending is reached */

		intr_timeout = pcmu_intrpend_timeout;
		jump = TICK_TO_NSEC(xc_tick_jump_limit);
		start_time = curr = gethrtime();
		while ((((lddphysio(state_reg_pa) >> shift) &
			PCMU_CLEAR_INTR_REG_MASK) ==
			PCMU_CLEAR_INTR_REG_PENDING) && !panicstr) {
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
				cmn_err(CE_WARN, "pcmu@%x "
				    "pcmu_cb_disable_nintr_reg(%lx,%x) timeout",
				    pcb_p->pcb_pcmu_p->pcmu_id, map_reg_pa,
				    PCMU_CB_INO_TO_MONDO(pcb_p, ino));
				break;
			}
		}
	}
}

void
pcmu_cb_disable_nintr(pcmu_cb_t *pcb_p, pcmu_cb_nintr_index_t idx, int wait)
{
	pcmu_ib_t *pib_p = pcb_p->pcb_pcmu_p->pcmu_ib_p;
	volatile uint64_t *imr_p;
	pcmu_ib_ino_t ino = pcb_p->pcb_inos[idx];
	ASSERT(idx < CBNINTR_MAX);
	ASSERT(ino);

	imr_p = ib_intr_map_reg_addr(pib_p, ino);
	mutex_enter(&pcb_p->pcb_intr_lock);
	pcmu_cb_disable_nintr_reg(pcb_p, ino, wait);
	pcmu_cb_set_nintr_reg(pcb_p, ino, PCMU_CLEAR_INTR_REG_PENDING);
	pcb_p->pcb_inos[idx] = 0;
	mutex_exit(&pcb_p->pcb_intr_lock);
	u2u_ittrans_cleanup((u2u_ittrans_data_t *)(pcb_p->pcb_ittrans_cookie),
			imr_p);
}

void
pcmu_cb_clear_nintr(pcmu_cb_t *pcb_p, pcmu_cb_nintr_index_t idx)
{
	pcmu_ib_ino_t ino = pcb_p->pcb_inos[idx];
	ASSERT(idx < CBNINTR_MAX);
	ASSERT(ino);
	pcmu_cb_set_nintr_reg(pcb_p, ino, PCMU_CLEAR_INTR_REG_IDLE);
}

void
pcmu_cb_intr_dist(void *arg)
{
	int i;
	pcmu_cb_t *pcb_p = (pcmu_cb_t *)arg;

	mutex_enter(&pcb_p->pcb_intr_lock);
	for (i = 0; i < pcb_p->pcb_no_of_inos; i++) {
		uint64_t mr_pa;
		volatile uint64_t imr;
		pcmu_ib_mondo_t mondo;
		uint32_t cpu_id;
		pcmu_ib_t *pib_p = pcb_p->pcb_pcmu_p->pcmu_ib_p;
		volatile uint64_t *imr_p;

		pcmu_ib_ino_t ino = pcb_p->pcb_inos[i];
		if (!ino)	/* skip non-shared interrupts */
			continue;

		mr_pa = pcmu_cb_ino_to_map_pa(pcb_p, ino);
		imr = lddphysio(mr_pa);
		if (!PCMU_IB_INO_INTR_ISON(imr))
			continue;

		mondo = PCMU_CB_INO_TO_MONDO(pcb_p, ino);
		cpu_id = intr_dist_cpuid();
		imr_p = ib_intr_map_reg_addr(pib_p, ino);

		cpu_id = u2u_translate_tgtid(pib_p->pib_pcmu_p, cpu_id, imr_p);

		pcmu_cb_disable_nintr_reg(pcb_p, ino, PCMU_IB_INTR_WAIT);
		stdphysio(mr_pa, ib_get_map_reg(mondo, cpu_id));
		(void) lddphysio(mr_pa);	/* flush previous write */
	}
	mutex_exit(&pcb_p->pcb_intr_lock);
}

void
pcmu_cb_suspend(pcmu_cb_t *pcb_p)
{
	int i, inos = pcb_p->pcb_no_of_inos;
	ASSERT(!pcb_p->pcb_imr_save);
	pcb_p->pcb_imr_save = kmem_alloc(inos * sizeof (uint64_t), KM_SLEEP);

	/*
	 * save the internal interrupts' mapping registers content
	 *
	 * The PBM IMR really doesn't need to be saved, as it is
	 * different per side and is handled by pcmu_pbm_suspend/resume.
	 * But it complicates the logic.
	 */
	for (i = 0; i < inos; i++) {
		uint64_t pa;
		pcmu_ib_ino_t ino = pcb_p->pcb_inos[i];
		if (!ino)
			continue;
		pa = pcmu_cb_ino_to_map_pa(pcb_p, ino);
		pcb_p->pcb_imr_save[i] = lddphysio(pa);
	}
}

void
pcmu_cb_resume(pcmu_cb_t *pcb_p)
{
	int i;
	for (i = 0; i < pcb_p->pcb_no_of_inos; i++) {
		uint64_t pa;
		pcmu_ib_ino_t ino = pcb_p->pcb_inos[i];
		if (!ino)
			continue;
		pa = pcmu_cb_ino_to_map_pa(pcb_p, ino);
		pcmu_cb_set_nintr_reg(pcb_p, ino, PCMU_CLEAR_INTR_REG_IDLE);
		stdphysio(pa, pcb_p->pcb_imr_save[i]);	/* restore IMR */
	}
	kmem_free(pcb_p->pcb_imr_save,
	    pcb_p->pcb_no_of_inos * sizeof (uint64_t));
	pcb_p->pcb_imr_save = NULL;
}
