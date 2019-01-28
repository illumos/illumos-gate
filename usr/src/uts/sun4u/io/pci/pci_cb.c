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
/*
 * Copyright 2019 Peter Tribble.
 */

/*
 * PCI Control Block object
 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/systm.h>		/* timeout() */
#include <sys/async.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci/pci_obj.h>
#include <sys/machsystm.h>

/*LINTLIBRARY*/

void
cb_create(pci_t *pci_p)
{
	cb_t *cb_p = (cb_t *)kmem_zalloc(sizeof (cb_t), KM_SLEEP);

	mutex_init(&cb_p->cb_intr_lock, NULL, MUTEX_DRIVER, NULL);
	pci_p->pci_cb_p = cb_p;
	cb_p->cb_pci_cmn_p = pci_p->pci_common_p;

	pci_cb_setup(pci_p);
}

void
cb_destroy(pci_t *pci_p)
{
	cb_t *cb_p = pci_p->pci_cb_p;

	intr_dist_rem(cb_intr_dist, cb_p);
	pci_cb_teardown(pci_p);
	pci_p->pci_cb_p = NULL;
	mutex_destroy(&cb_p->cb_intr_lock);
	kmem_free(cb_p, sizeof (cb_t));
}

static void
cb_set_nintr_reg(cb_t *cb_p, ib_ino_t ino, uint64_t value)
{
	uint64_t pa = cb_ino_to_clr_pa(cb_p, ino);

	DEBUG3(DBG_CB|DBG_CONT, NULL,
		"pci-%x cb_set_nintr_reg: ino=%x PA=%016llx\n",
		cb_p->cb_pci_cmn_p->pci_common_id, ino, pa);

	stdphysio(pa, value);
	(void) lddphysio(pa);	/* flush the previous write */
}

/*
 * enable an internal interrupt source:
 * if an interrupt is shared by both sides, record it in cb_inos[] and
 * cb will own its distribution.
 */
void
cb_enable_nintr(pci_t *pci_p, enum cb_nintr_index idx)
{
	cb_t *cb_p = pci_p->pci_cb_p;
	ib_ino_t ino = IB_MONDO_TO_INO(pci_p->pci_inos[idx]);
	ib_mondo_t mondo = CB_INO_TO_MONDO(cb_p, ino);
	uint32_t cpu_id;
	uint64_t reg, pa;

	ASSERT(idx < CBNINTR_MAX);
	pa = cb_ino_to_map_pa(cb_p, ino);

	mutex_enter(&cb_p->cb_intr_lock);
	cpu_id = intr_dist_cpuid();

	reg = ib_get_map_reg(mondo, cpu_id);
	stdphysio(pa, reg);

	ASSERT(cb_p->cb_inos[idx] == 0);
	cb_p->cb_inos[idx] = ino;

	cb_set_nintr_reg(cb_p, ino, COMMON_CLEAR_INTR_REG_IDLE);
	mutex_exit(&cb_p->cb_intr_lock);

	DEBUG3(DBG_CB|DBG_CONT, NULL,
		"pci-%x cb_enable_nintr: ino=%x cpu_id=%x\n",
		pci_p->pci_id, ino, cpu_id);
	DEBUG2(DBG_CB|DBG_CONT, NULL, "\tPA=%016llx data=%016llx\n", pa, reg);
}

static void
cb_disable_nintr_reg(cb_t *cb_p, ib_ino_t ino, int wait)
{
	uint64_t tmp, map_reg_pa = cb_ino_to_map_pa(cb_p, ino);
	ASSERT(MUTEX_HELD(&cb_p->cb_intr_lock));

	/* mark interrupt invalid in mapping register */
	tmp = lddphysio(map_reg_pa) & ~COMMON_INTR_MAP_REG_VALID;
	stdphysio(map_reg_pa, tmp);
	(void) lddphysio(map_reg_pa);   /* flush previous write */

	if (wait) {
		hrtime_t start_time;
		uint64_t state_reg_pa = cb_p->cb_obsta_pa;
		uint_t shift = (ino & 0x1f) << 1;

		/* busy wait if there is interrupt being processed */
		/* unless panic or timeout for interrupt pending is reached */
		start_time = gethrtime();
		while ((((lddphysio(state_reg_pa) >> shift) &
			COMMON_CLEAR_INTR_REG_MASK) ==
			COMMON_CLEAR_INTR_REG_PENDING) && !panicstr) {
			if (gethrtime() - start_time > pci_intrpend_timeout) {
				cmn_err(CE_WARN,
				"pci@%x cb_disable_nintr_reg(%lx,%x) timeout",
					cb_p->cb_pci_cmn_p->pci_common_id,
					map_reg_pa,
					CB_INO_TO_MONDO(cb_p, ino));
				break;
			}
		}
	}
}

void
cb_disable_nintr(cb_t *cb_p, enum cb_nintr_index idx, int wait)
{
	ib_ino_t ino = cb_p->cb_inos[idx];
	ASSERT(idx < CBNINTR_MAX);
	ASSERT(ino);

	mutex_enter(&cb_p->cb_intr_lock);
	cb_disable_nintr_reg(cb_p, ino, wait);
	cb_set_nintr_reg(cb_p, ino, COMMON_CLEAR_INTR_REG_PENDING);
	cb_p->cb_inos[idx] = 0;
	mutex_exit(&cb_p->cb_intr_lock);
}

void
cb_clear_nintr(cb_t *cb_p, enum cb_nintr_index idx)
{
	ib_ino_t ino = cb_p->cb_inos[idx];
	ASSERT(idx < CBNINTR_MAX);
	ASSERT(ino);
	cb_set_nintr_reg(cb_p, ino, COMMON_CLEAR_INTR_REG_IDLE);
}

void
cb_intr_dist(void *arg)
{
	int i;
	cb_t *cb_p = (cb_t *)arg;

	mutex_enter(&cb_p->cb_intr_lock);
	for (i = 0; i < cb_p->cb_no_of_inos; i++) {
		uint64_t mr_pa;
		volatile uint64_t imr;
		ib_mondo_t mondo;
		uint32_t cpu_id;

		ib_ino_t ino = cb_p->cb_inos[i];
		if (!ino)	/* skip non-shared interrupts */
			continue;

		mr_pa = cb_ino_to_map_pa(cb_p, ino);
		imr = lddphysio(mr_pa);
		if (!IB_INO_INTR_ISON(imr))
			continue;

		mondo = CB_INO_TO_MONDO(cb_p, ino);
		cpu_id = intr_dist_cpuid();
		if (ib_map_reg_get_cpu(imr) == cpu_id)
			continue;	/* same cpu target, no re-program */
		cb_disable_nintr_reg(cb_p, ino, IB_INTR_WAIT);
		stdphysio(mr_pa, ib_get_map_reg(mondo, cpu_id));
		(void) lddphysio(mr_pa);	/* flush previous write */
	}
	mutex_exit(&cb_p->cb_intr_lock);
}

void
cb_suspend(cb_t *cb_p)
{
	int i, inos = cb_p->cb_no_of_inos;
	ASSERT(!cb_p->cb_imr_save);
	cb_p->cb_imr_save = kmem_alloc(inos * sizeof (uint64_t), KM_SLEEP);

	/*
	 * save the internal interrupts' mapping registers content
	 *
	 * The PBM IMR really doesn't need to be saved, as it is
	 * different per side and is handled by pbm_suspend/resume.
	 * But it complicates the logic.
	 */
	for (i = 0; i < inos; i++) {
		uint64_t pa;
		ib_ino_t ino = cb_p->cb_inos[i];
		if (!ino)
			continue;
		pa = cb_ino_to_map_pa(cb_p, ino);
		cb_p->cb_imr_save[i] = lddphysio(pa);
	}
}

void
cb_resume(cb_t *cb_p)
{
	int i;
	for (i = 0; i < cb_p->cb_no_of_inos; i++) {
		uint64_t pa;
		ib_ino_t ino = cb_p->cb_inos[i];
		if (!ino)
			continue;
		pa = cb_ino_to_map_pa(cb_p, ino);
		cb_set_nintr_reg(cb_p, ino, COMMON_CLEAR_INTR_REG_IDLE);
		stdphysio(pa, cb_p->cb_imr_save[i]);	/* restore IMR */
	}
	kmem_free(cb_p->cb_imr_save, cb_p->cb_no_of_inos * sizeof (uint64_t));
	cb_p->cb_imr_save = NULL;
}
