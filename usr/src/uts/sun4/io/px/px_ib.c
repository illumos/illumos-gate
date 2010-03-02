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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PX Interrupt Block implementation
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/systm.h>		/* panicstr */
#include <sys/spl.h>
#include <sys/sunddi.h>
#include <sys/machsystm.h>	/* intr_dist_add */
#include <sys/ddi_impldefs.h>
#include <sys/cpuvar.h>
#include <sys/time.h>
#include "px_obj.h"

/*LINTLIBRARY*/

static void px_ib_intr_redist(void *arg, int32_t weight_max, int32_t weight);
static void px_ib_cpu_ticks_to_ih_nsec(px_ib_t *ib_p, px_ih_t *ih_p,
    uint32_t cpu_id);
static uint_t px_ib_intr_reset(void *arg);
static void px_fill_in_intr_devs(pcitool_intr_dev_t *dev, char *driver_name,
    char *path_name, int instance);

extern uint64_t xc_tick_jump_limit;

int
px_ib_attach(px_t *px_p)
{
	dev_info_t	*dip = px_p->px_dip;
	px_ib_t		*ib_p;
	sysino_t	sysino;
	px_fault_t	*fault_p = &px_p->px_fault;

	DBG(DBG_IB, dip, "px_ib_attach\n");

	if (px_lib_intr_devino_to_sysino(px_p->px_dip,
	    px_p->px_inos[PX_INTR_PEC], &sysino) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate interrupt block state structure and link it to
	 * the px state structure.
	 */
	ib_p = kmem_zalloc(sizeof (px_ib_t), KM_SLEEP);
	px_p->px_ib_p = ib_p;
	ib_p->ib_px_p = px_p;
	ib_p->ib_ino_lst = (px_ino_t *)NULL;

	mutex_init(&ib_p->ib_intr_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ib_p->ib_ino_lst_mutex, NULL, MUTEX_DRIVER, NULL);

	bus_func_register(BF_TYPE_RESINTR, px_ib_intr_reset, ib_p);

	intr_dist_add_weighted(px_ib_intr_redist, ib_p);

	/*
	 * Initialize PEC fault data structure
	 */
	fault_p->px_fh_dip = dip;
	fault_p->px_fh_sysino = sysino;
	fault_p->px_err_func = px_err_dmc_pec_intr;
	fault_p->px_intr_ino = px_p->px_inos[PX_INTR_PEC];

	return (DDI_SUCCESS);
}

void
px_ib_detach(px_t *px_p)
{
	px_ib_t		*ib_p = px_p->px_ib_p;
	dev_info_t	*dip = px_p->px_dip;

	DBG(DBG_IB, dip, "px_ib_detach\n");

	bus_func_unregister(BF_TYPE_RESINTR, px_ib_intr_reset, ib_p);
	intr_dist_rem_weighted(px_ib_intr_redist, ib_p);

	mutex_destroy(&ib_p->ib_ino_lst_mutex);
	mutex_destroy(&ib_p->ib_intr_lock);

	px_ib_free_ino_all(ib_p);

	px_p->px_ib_p = NULL;
	kmem_free(ib_p, sizeof (px_ib_t));
}

void
px_ib_intr_enable(px_t *px_p, cpuid_t cpu_id, devino_t ino)
{
	px_ib_t		*ib_p = px_p->px_ib_p;
	sysino_t	sysino;

	/*
	 * Determine the cpu for the interrupt
	 */
	mutex_enter(&ib_p->ib_intr_lock);

	DBG(DBG_IB, px_p->px_dip,
	    "px_ib_intr_enable: ino=%x cpu_id=%x\n", ino, cpu_id);

	if (px_lib_intr_devino_to_sysino(px_p->px_dip, ino,
	    &sysino) != DDI_SUCCESS) {
		DBG(DBG_IB, px_p->px_dip,
		    "px_ib_intr_enable: px_intr_devino_to_sysino() failed\n");

		mutex_exit(&ib_p->ib_intr_lock);
		return;
	}

	PX_INTR_ENABLE(px_p->px_dip, sysino, cpu_id);
	px_lib_intr_setstate(px_p->px_dip, sysino, INTR_IDLE_STATE);

	mutex_exit(&ib_p->ib_intr_lock);
}

/*ARGSUSED*/
void
px_ib_intr_disable(px_ib_t *ib_p, devino_t ino, int wait)
{
	sysino_t	sysino;

	mutex_enter(&ib_p->ib_intr_lock);

	DBG(DBG_IB, ib_p->ib_px_p->px_dip, "px_ib_intr_disable: ino=%x\n", ino);

	/* Disable the interrupt */
	if (px_lib_intr_devino_to_sysino(ib_p->ib_px_p->px_dip, ino,
	    &sysino) != DDI_SUCCESS) {
		DBG(DBG_IB, ib_p->ib_px_p->px_dip,
		    "px_ib_intr_disable: px_intr_devino_to_sysino() failed\n");

		mutex_exit(&ib_p->ib_intr_lock);
		return;
	}

	PX_INTR_DISABLE(ib_p->ib_px_p->px_dip, sysino);

	mutex_exit(&ib_p->ib_intr_lock);
}


void
px_ib_intr_dist_en(dev_info_t *dip, cpuid_t cpu_id, devino_t ino,
    boolean_t wait_flag)
{
	uint32_t	old_cpu_id;
	sysino_t	sysino;
	intr_valid_state_t	enabled = 0;
	hrtime_t	start_time, prev, curr, interval, jump;
	hrtime_t	intr_timeout;
	intr_state_t	intr_state;
	int		e = DDI_SUCCESS;

	DBG(DBG_IB, dip, "px_ib_intr_dist_en: ino=0x%x\n", ino);

	if (px_lib_intr_devino_to_sysino(dip, ino, &sysino) != DDI_SUCCESS) {
		DBG(DBG_IB, dip, "px_ib_intr_dist_en: "
		    "px_intr_devino_to_sysino() failed, ino 0x%x\n", ino);
		return;
	}

	/* Skip enabling disabled interrupts */
	if (px_lib_intr_getvalid(dip, sysino, &enabled) != DDI_SUCCESS) {
		DBG(DBG_IB, dip, "px_ib_intr_dist_en: px_intr_getvalid() "
		    "failed, sysino 0x%x\n", sysino);
		return;
	}
	if (!enabled)
		return;

	/* Done if redistributed onto the same cpuid */
	if (px_lib_intr_gettarget(dip, sysino, &old_cpu_id) != DDI_SUCCESS) {
		DBG(DBG_IB, dip, "px_ib_intr_dist_en: "
		    "px_intr_gettarget() failed\n");
		return;
	}
	if (cpu_id == old_cpu_id)
		return;

	if (!wait_flag)
		goto done;

	/* Busy wait on pending interrupts */
	PX_INTR_DISABLE(dip, sysino);

	intr_timeout = px_intrpend_timeout;
	jump = TICK_TO_NSEC(xc_tick_jump_limit);

	for (curr = start_time = gethrtime(); !panicstr &&
	    ((e = px_lib_intr_getstate(dip, sysino, &intr_state)) ==
	    DDI_SUCCESS) &&
	    (intr_state == INTR_DELIVERED_STATE); /* */) {
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
			cmn_err(CE_WARN,
			    "%s%d: px_ib_intr_dist_en: sysino 0x%lx(ino 0x%x) "
			    "from cpu id 0x%x to 0x%x timeout",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    sysino, ino, old_cpu_id, cpu_id);

			e = DDI_FAILURE;
			break;
		}
	}

	if (e != DDI_SUCCESS)
		DBG(DBG_IB, dip, "px_ib_intr_dist_en: failed, "
		    "ino 0x%x sysino 0x%x\n", ino, sysino);

done:
	PX_INTR_ENABLE(dip, sysino, cpu_id);
}

static void
px_ib_cpu_ticks_to_ih_nsec(px_ib_t *ib_p, px_ih_t *ih_p, uint32_t cpu_id)
{
	extern kmutex_t pxintr_ks_template_lock;
	hrtime_t ticks;

	/*
	 * Because we are updating two fields in ih_t we must lock
	 * pxintr_ks_template_lock to prevent someone from reading the
	 * kstats after we set ih_ticks to 0 and before we increment
	 * ih_nsec to compensate.
	 *
	 * We must also protect against the interrupt arriving and incrementing
	 * ih_ticks between the time we read it and when we reset it to 0.
	 * To do this we use atomic_swap.
	 */

	ASSERT(MUTEX_HELD(&ib_p->ib_ino_lst_mutex));

	mutex_enter(&pxintr_ks_template_lock);
	ticks = atomic_swap_64(&ih_p->ih_ticks, 0);
	ih_p->ih_nsec += (uint64_t)tick2ns(ticks, cpu_id);
	mutex_exit(&pxintr_ks_template_lock);
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
static void
px_ib_intr_redist(void *arg, int32_t weight_max, int32_t weight)
{
	px_ib_t		*ib_p = (px_ib_t *)arg;
	px_t		*px_p = ib_p->ib_px_p;
	dev_info_t	*dip = px_p->px_dip;
	px_ino_t	*ino_p;
	px_ino_pil_t	*ipil_p;
	px_ih_t		*ih_lst;
	int32_t		dweight = 0;
	int		i;

	/* Redistribute internal interrupts */
	if (weight == 0) {
		mutex_enter(&ib_p->ib_intr_lock);
		px_ib_intr_dist_en(dip, intr_dist_cpuid(),
		    px_p->px_inos[PX_INTR_PEC], B_FALSE);
		mutex_exit(&ib_p->ib_intr_lock);

		px_hp_intr_redist(px_p);
	}

	/* Redistribute device interrupts */
	mutex_enter(&ib_p->ib_ino_lst_mutex);
	px_msiq_redist(px_p);

	for (ino_p = ib_p->ib_ino_lst; ino_p; ino_p = ino_p->ino_next_p) {
		/*
		 * Recomputes the sum of interrupt weights of devices that
		 * share the same ino upon first call marked by
		 * (weight == weight_max).
		 */
		if (weight == weight_max) {
			ino_p->ino_intr_weight = 0;

			for (ipil_p = ino_p->ino_ipil_p; ipil_p;
			    ipil_p = ipil_p->ipil_next_p) {
				for (i = 0, ih_lst = ipil_p->ipil_ih_head;
				    i < ipil_p->ipil_ih_size; i++,
				    ih_lst = ih_lst->ih_next) {
					dweight = i_ddi_get_intr_weight(
					    ih_lst->ih_dip);
					if (dweight > 0)
						ino_p->ino_intr_weight +=
						    dweight;
				}
			}
		}

		/*
		 * As part of redistributing weighted interrupts over cpus,
		 * nexus redistributes device interrupts and updates
		 * cpu weight. The purpose is for the most light weighted
		 * cpu to take the next interrupt and gain weight, therefore
		 * attention demanding device gains more cpu attention by
		 * making itself heavy.
		 */
		if ((weight == ino_p->ino_intr_weight) ||
		    ((weight >= weight_max) &&
		    (ino_p->ino_intr_weight >= weight_max))) {
			uint32_t orig_cpuid = ino_p->ino_cpuid;

			if (cpu[orig_cpuid] == NULL)
				orig_cpuid = CPU->cpu_id;

			DBG(DBG_IB, dip, "px_ib_intr_redist: sysino 0x%llx "
			    "current cpuid 0x%x current default cpuid 0x%x\n",
			    ino_p->ino_sysino, ino_p->ino_cpuid,
			    ino_p->ino_default_cpuid);

			/* select target cpuid and mark ino established */
			if (ino_p->ino_default_cpuid == -1)
				ino_p->ino_cpuid = ino_p->ino_default_cpuid =
				    intr_dist_cpuid();
			else if ((ino_p->ino_cpuid !=
			    ino_p->ino_default_cpuid) &&
			    cpu[ino_p->ino_default_cpuid] &&
			    cpu_intr_on(cpu[ino_p->ino_default_cpuid]))
				ino_p->ino_cpuid = ino_p->ino_default_cpuid;
			else if (!cpu_intr_on(cpu[ino_p->ino_cpuid]))
				ino_p->ino_cpuid = intr_dist_cpuid();

			DBG(DBG_IB, dip, "px_ib_intr_redist: sysino 0x%llx "
			    "new cpuid 0x%x new default cpuid 0x%x\n",
			    ino_p->ino_sysino, ino_p->ino_cpuid,
			    ino_p->ino_default_cpuid);

			/* Add device weight to targeted cpu. */
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
					px_ib_cpu_ticks_to_ih_nsec(ib_p, ih_lst,
					    orig_cpuid);
				}
			}

			/* enable interrupt on new targeted cpu */
			px_ib_intr_dist_en(dip, ino_p->ino_cpuid,
			    ino_p->ino_ino, B_TRUE);
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
px_ib_intr_reset(void *arg)
{
	px_ib_t		*ib_p = (px_ib_t *)arg;

	DBG(DBG_IB, ib_p->ib_px_p->px_dip, "px_ib_intr_reset\n");

	if (px_lib_intr_reset(ib_p->ib_px_p->px_dip) != DDI_SUCCESS)
		return (BF_FATAL);

	return (BF_NONE);
}

/*
 * Locate px_ino_t structure on ib_p->ib_ino_lst according to ino#
 * returns NULL if not found.
 */
px_ino_t *
px_ib_locate_ino(px_ib_t *ib_p, devino_t ino_num)
{
	px_ino_t	*ino_p = ib_p->ib_ino_lst;

	ASSERT(MUTEX_HELD(&ib_p->ib_ino_lst_mutex));

	for (; ino_p && ino_p->ino_ino != ino_num; ino_p = ino_p->ino_next_p)
		;

	return (ino_p);
}

px_ino_t *
px_ib_alloc_ino(px_ib_t *ib_p, devino_t ino_num)
{
	sysino_t	sysino;
	px_ino_t	*ino_p;

	if (px_lib_intr_devino_to_sysino(ib_p->ib_px_p->px_dip,
	    ino_num, &sysino) != DDI_SUCCESS)
		return (NULL);

	ino_p = kmem_zalloc(sizeof (px_ino_t), KM_SLEEP);

	ino_p->ino_next_p = ib_p->ib_ino_lst;
	ib_p->ib_ino_lst = ino_p;

	ino_p->ino_ino = ino_num;
	ino_p->ino_sysino = sysino;
	ino_p->ino_ib_p = ib_p;
	ino_p->ino_unclaimed_intrs = 0;
	ino_p->ino_lopil = 0;
	ino_p->ino_cpuid = ino_p->ino_default_cpuid = (cpuid_t)-1;

	return (ino_p);
}

px_ino_pil_t *
px_ib_new_ino_pil(px_ib_t *ib_p, devino_t ino_num, uint_t pil, px_ih_t *ih_p)
{
	px_ino_pil_t	*ipil_p = kmem_zalloc(sizeof (px_ino_pil_t), KM_SLEEP);
	px_ino_t	*ino_p;

	if ((ino_p = px_ib_locate_ino(ib_p, ino_num)) == NULL)
		ino_p = px_ib_alloc_ino(ib_p, ino_num);

	ASSERT(ino_p != NULL);

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

	if ((ino_p->ino_lopil == 0) || (ino_p->ino_lopil > pil))
		ino_p->ino_lopil = pil;

	return (ipil_p);
}

void
px_ib_delete_ino_pil(px_ib_t *ib_p, px_ino_pil_t *ipil_p)
{
	px_ino_t	*ino_p = ipil_p->ipil_ino_p;
	ushort_t	pil = ipil_p->ipil_pil;
	px_ino_pil_t	*prev, *next;

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

	kmem_free(ipil_p, sizeof (px_ino_pil_t));

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

	ino_p->ino_lopil = 0;

	if (ino_p->ino_msiq_p)
		return;

	if (ib_p->ib_ino_lst == ino_p)
		ib_p->ib_ino_lst = ino_p->ino_next_p;
	else {
		px_ino_t	*list = ib_p->ib_ino_lst;

		for (; list->ino_next_p != ino_p; list = list->ino_next_p)
			;
		list->ino_next_p = ino_p->ino_next_p;
	}
}

/*
 * Free all ino when we are detaching.
 */
void
px_ib_free_ino_all(px_ib_t *ib_p)
{
	px_ino_t	*ino_p = ib_p->ib_ino_lst;
	px_ino_t	*next = NULL;

	while (ino_p) {
		next = ino_p->ino_next_p;
		kmem_free(ino_p, sizeof (px_ino_t));
		ino_p = next;
	}
}

/*
 * Locate px_ino_pil_t structure on ino_p->ino_ipil_p according to ino#
 * returns NULL if not found.
 */
px_ino_pil_t *
px_ib_ino_locate_ipil(px_ino_t *ino_p, uint_t pil)
{
	px_ino_pil_t	*ipil_p = ino_p->ino_ipil_p;

	for (; ipil_p && ipil_p->ipil_pil != pil; ipil_p = ipil_p->ipil_next_p)
		;

	return (ipil_p);
}

int
px_ib_ino_add_intr(px_t *px_p, px_ino_pil_t *ipil_p, px_ih_t *ih_p)
{
	px_ino_t	*ino_p = ipil_p->ipil_ino_p;
	px_ib_t		*ib_p = ino_p->ino_ib_p;
	devino_t	ino = ino_p->ino_ino;
	sysino_t	sysino = ino_p->ino_sysino;
	dev_info_t	*dip = px_p->px_dip;
	cpuid_t		curr_cpu;
	hrtime_t	start_time;
	intr_state_t	intr_state;
	int		ret = DDI_SUCCESS;

	ASSERT(MUTEX_HELD(&ib_p->ib_ino_lst_mutex));
	ASSERT(ib_p == px_p->px_ib_p);

	DBG(DBG_IB, dip, "px_ib_ino_add_intr ino=%x\n", ino_p->ino_ino);

	/* Disable the interrupt */
	if ((ret = px_lib_intr_gettarget(dip, sysino,
	    &curr_cpu)) != DDI_SUCCESS) {
		DBG(DBG_IB, dip,
		    "px_ib_ino_add_intr px_intr_gettarget() failed\n");

		return (ret);
	}

	PX_INTR_DISABLE(dip, sysino);

	/* Busy wait on pending interrupt */
	for (start_time = gethrtime(); !panicstr &&
	    ((ret = px_lib_intr_getstate(dip, sysino, &intr_state))
	    == DDI_SUCCESS) && (intr_state == INTR_DELIVERED_STATE); /* */) {
		if (gethrtime() - start_time > px_intrpend_timeout) {
			cmn_err(CE_WARN, "%s%d: px_ib_ino_add_intr: pending "
			    "sysino 0x%lx(ino 0x%x) timeout",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    sysino, ino);

			ret = DDI_FAILURE;
			break;
		}
	}

	/*
	 * If the interrupt was previously blocked (left in pending state)
	 * because of jabber we need to clear the pending state in case the
	 * jabber has gone away.
	 */
	if (ino_p->ino_unclaimed_intrs > px_unclaimed_intr_max) {
		cmn_err(CE_WARN,
		    "%s%d: px_ib_ino_add_intr: ino 0x%x has been unblocked",
		    ddi_driver_name(dip), ddi_get_instance(dip), ino);

		ino_p->ino_unclaimed_intrs = 0;
		ret = px_lib_intr_setstate(dip, sysino, INTR_IDLE_STATE);
	}

	if (ret != DDI_SUCCESS) {
		DBG(DBG_IB, dip, "px_ib_ino_add_intr: failed, "
		    "ino 0x%x sysino 0x%x\n", ino, sysino);

		return (ret);
	}

	/* Link up px_ih_t */
	ih_p->ih_next = ipil_p->ipil_ih_head;
	ipil_p->ipil_ih_tail->ih_next = ih_p;
	ipil_p->ipil_ih_tail = ih_p;

	ipil_p->ipil_ih_start = ipil_p->ipil_ih_head;
	ipil_p->ipil_ih_size++;

	/* Re-enable interrupt */
	PX_INTR_ENABLE(dip, sysino, curr_cpu);

	return (ret);
}

/*
 * Removes px_ih_t from the ino's link list.
 * uses hardware mutex to lock out interrupt threads.
 * Side effects: interrupt belongs to that ino is turned off on return.
 * if we are sharing PX slot with other inos, the caller needs
 * to turn it back on.
 */
int
px_ib_ino_rem_intr(px_t *px_p, px_ino_pil_t *ipil_p, px_ih_t *ih_p)
{
	px_ino_t	*ino_p = ipil_p->ipil_ino_p;
	devino_t	ino = ino_p->ino_ino;
	sysino_t	sysino = ino_p->ino_sysino;
	dev_info_t	*dip = px_p->px_dip;
	px_ih_t		*ih_lst = ipil_p->ipil_ih_head;
	hrtime_t	start_time;
	intr_state_t	intr_state;
	int		i, ret = DDI_SUCCESS;

	ASSERT(MUTEX_HELD(&ino_p->ino_ib_p->ib_ino_lst_mutex));

	DBG(DBG_IB, px_p->px_dip, "px_ib_ino_rem_intr ino=%x\n",
	    ino_p->ino_ino);

	/* Disable the interrupt */
	PX_INTR_DISABLE(px_p->px_dip, sysino);

	/* Busy wait on pending interrupt */
	for (start_time = gethrtime(); !panicstr &&
	    ((ret = px_lib_intr_getstate(dip, sysino, &intr_state))
	    == DDI_SUCCESS) && (intr_state == INTR_DELIVERED_STATE); /* */) {
		if (gethrtime() - start_time > px_intrpend_timeout) {
			cmn_err(CE_WARN, "%s%d: px_ib_ino_rem_intr: pending "
			    "sysino 0x%lx(ino 0x%x) timeout",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    sysino, ino);

			ret = DDI_FAILURE;
			break;
		}
	}

	/*
	 * If the interrupt was previously blocked (left in pending state)
	 * because of jabber we need to clear the pending state in case the
	 * jabber has gone away.
	 */
	if (ret == DDI_SUCCESS &&
	    ino_p->ino_unclaimed_intrs > px_unclaimed_intr_max) {
		cmn_err(CE_WARN, "%s%d: px_ib_ino_rem_intr: "
		    "ino 0x%x has been unblocked",
		    ddi_driver_name(dip), ddi_get_instance(dip), ino);

		ino_p->ino_unclaimed_intrs = 0;
		ret = px_lib_intr_setstate(dip, sysino, INTR_IDLE_STATE);
	}

	if (ret != DDI_SUCCESS) {
		DBG(DBG_IB, dip, "px_ib_ino_rem_intr: failed, "
		    "ino 0x%x sysino 0x%x\n", ino, sysino);

		return (ret);
	}

	if (ipil_p->ipil_ih_size == 1) {
		if (ih_lst != ih_p)
			goto not_found;

		/* No need to set head/tail as ino_p will be freed */
		goto reset;
	}

	/* Search the link list for ih_p */
	for (i = 0; (i < ipil_p->ipil_ih_size) &&
	    (ih_lst->ih_next != ih_p); i++, ih_lst = ih_lst->ih_next)
		;

	if (ih_lst->ih_next != ih_p)
		goto not_found;

	/* Remove ih_p from the link list and maintain the head/tail */
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

	kmem_free(ih_p, sizeof (px_ih_t));
	ipil_p->ipil_ih_size--;

	return (ret);

not_found:
	DBG(DBG_R_INTX, ino_p->ino_ib_p->ib_px_p->px_dip,
	    "ino_p=%x does not have ih_p=%x\n", ino_p, ih_p);

	return (DDI_FAILURE);
}

px_ih_t *
px_ib_intr_locate_ih(px_ino_pil_t *ipil_p, dev_info_t *rdip,
    uint32_t inum, msiq_rec_type_t rec_type, msgcode_t msg_code)
{
	px_ih_t	*ih_p = ipil_p->ipil_ih_head;
	int	i;

	for (i = 0; i < ipil_p->ipil_ih_size; i++, ih_p = ih_p->ih_next) {
		if ((ih_p->ih_dip == rdip) && (ih_p->ih_inum == inum) &&
		    (ih_p->ih_rec_type == rec_type) &&
		    (ih_p->ih_msg_code == msg_code))
			return (ih_p);
	}

	return ((px_ih_t *)NULL);
}

px_ih_t *
px_ib_alloc_ih(dev_info_t *rdip, uint32_t inum,
    uint_t (*int_handler)(caddr_t int_handler_arg1, caddr_t int_handler_arg2),
    caddr_t int_handler_arg1, caddr_t int_handler_arg2,
    msiq_rec_type_t rec_type, msgcode_t msg_code)
{
	px_ih_t	*ih_p;

	ih_p = kmem_alloc(sizeof (px_ih_t), KM_SLEEP);
	ih_p->ih_dip = rdip;
	ih_p->ih_inum = inum;
	ih_p->ih_intr_state = PX_INTR_STATE_DISABLE;
	ih_p->ih_intr_flags = PX_INTR_IDLE;
	ih_p->ih_handler = int_handler;
	ih_p->ih_handler_arg1 = int_handler_arg1;
	ih_p->ih_handler_arg2 = int_handler_arg2;
	ih_p->ih_config_handle = NULL;
	ih_p->ih_rec_type = rec_type;
	ih_p->ih_msg_code = msg_code;
	ih_p->ih_nsec = 0;
	ih_p->ih_ticks = 0;
	ih_p->ih_ksp = NULL;

	return (ih_p);
}

int
px_ib_update_intr_state(px_t *px_p, dev_info_t *rdip,
    uint_t inum, devino_t ino, uint_t pil,
    uint_t new_intr_state, msiq_rec_type_t rec_type,
    msgcode_t msg_code)
{
	px_ib_t		*ib_p = px_p->px_ib_p;
	px_ino_t	*ino_p;
	px_ino_pil_t	*ipil_p;
	px_ih_t		*ih_p;
	int		ret = DDI_FAILURE;

	DBG(DBG_IB, px_p->px_dip, "px_ib_update_intr_state: %s%d "
	    "inum %x devino %x pil %x state %x\n", ddi_driver_name(rdip),
	    ddi_get_instance(rdip), inum, ino, pil, new_intr_state);

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	ino_p = px_ib_locate_ino(ib_p, ino);
	if (ino_p && (ipil_p = px_ib_ino_locate_ipil(ino_p, pil))) {
		if (ih_p = px_ib_intr_locate_ih(ipil_p, rdip, inum, rec_type,
		    msg_code)) {
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
px_ib_get_intr_target(px_t *px_p, devino_t ino, cpuid_t *cpu_id_p)
{
	dev_info_t	*dip = px_p->px_dip;
	sysino_t	sysino;
	int		ret;

	DBG(DBG_IB, px_p->px_dip, "px_ib_get_intr_target: devino %x\n", ino);

	/* Convert leaf-wide intr to system-wide intr */
	if (px_lib_intr_devino_to_sysino(dip, ino, &sysino) != DDI_SUCCESS)
		return (DDI_FAILURE);

	ret = px_lib_intr_gettarget(dip, sysino, cpu_id_p);

	DBG(DBG_IB, px_p->px_dip, "px_ib_get_intr_target: cpu_id %x\n",
	    *cpu_id_p);

	return (ret);
}


/*
 * Associate a new CPU with a given ino.
 * Operate only on INOs which are already mapped to devices.
 */
int
px_ib_set_intr_target(px_t *px_p, devino_t ino, cpuid_t cpu_id)
{
	dev_info_t		*dip = px_p->px_dip;
	cpuid_t			old_cpu_id;
	sysino_t		sysino;
	int			ret = DDI_SUCCESS;
	extern const int	_ncpu;
	extern cpu_t		*cpu[];

	DBG(DBG_IB, px_p->px_dip, "px_ib_set_intr_target: devino %x "
	    "cpu_id %x\n", ino, cpu_id);

	mutex_enter(&cpu_lock);

	/* Convert leaf-wide intr to system-wide intr */
	if (px_lib_intr_devino_to_sysino(dip, ino, &sysino) != DDI_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}

	if (px_lib_intr_gettarget(dip, sysino, &old_cpu_id) != DDI_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}

	/*
	 * Get lock, validate cpu and write it.
	 */
	if ((cpu_id < _ncpu) && (cpu[cpu_id] && cpu_is_online(cpu[cpu_id]))) {
		DBG(DBG_IB, dip, "px_ib_set_intr_target: Enabling CPU %d\n",
		    cpu_id);
		px_ib_intr_dist_en(dip, cpu_id, ino, B_TRUE);
		px_ib_log_new_cpu(px_p->px_ib_p, old_cpu_id, cpu_id, ino);
	} else {	/* Invalid cpu */
		DBG(DBG_IB, dip, "px_ib_set_intr_target: Invalid cpuid %x\n",
		    cpu_id);
		ret = DDI_EINVAL;
	}

done:
	mutex_exit(&cpu_lock);
	return (ret);
}

hrtime_t px_ib_msix_retarget_timeout = 120ll * NANOSEC;	/* 120 seconds */

/*
 * Associate a new CPU with a given MSI/X.
 * Operate only on MSI/Xs which are already mapped to devices.
 */
int
px_ib_set_msix_target(px_t *px_p, ddi_intr_handle_impl_t *hdlp,
    msinum_t msi_num, cpuid_t cpu_id)
{
	px_ib_t			*ib_p = px_p->px_ib_p;
	px_msi_state_t		*msi_state_p = &px_p->px_ib_p->ib_msi_state;
	dev_info_t		*dip = px_p->px_dip;
	dev_info_t		*rdip = hdlp->ih_dip;
	msiqid_t		msiq_id, old_msiq_id;
	pci_msi_state_t		msi_state;
	msiq_rec_type_t		msiq_rec_type;
	msi_type_t		msi_type;
	px_ino_t		*ino_p;
	px_ih_t			*ih_p, *old_ih_p;
	cpuid_t			old_cpu_id;
	hrtime_t		start_time, end_time;
	int			ret = DDI_SUCCESS;
	extern const int	_ncpu;
	extern cpu_t		*cpu[];

	DBG(DBG_IB, dip, "px_ib_set_msix_target: msi_num %x new cpu_id %x\n",
	    msi_num, cpu_id);

	mutex_enter(&cpu_lock);

	/* Check for MSI64 support */
	if ((hdlp->ih_cap & DDI_INTR_FLAG_MSI64) && msi_state_p->msi_addr64) {
		msiq_rec_type = MSI64_REC;
		msi_type = MSI64_TYPE;
	} else {
		msiq_rec_type = MSI32_REC;
		msi_type = MSI32_TYPE;
	}

	if ((ret = px_lib_msi_getmsiq(dip, msi_num,
	    &old_msiq_id)) != DDI_SUCCESS) {

		mutex_exit(&cpu_lock);
		return (ret);
	}

	DBG(DBG_IB, dip, "px_ib_set_msix_target: current msiq 0x%x\n",
	    old_msiq_id);

	if ((ret = px_ib_get_intr_target(px_p,
	    px_msiqid_to_devino(px_p, old_msiq_id),
	    &old_cpu_id)) != DDI_SUCCESS) {

		mutex_exit(&cpu_lock);
		return (ret);
	}

	DBG(DBG_IB, dip, "px_ib_set_msix_target: current cpuid 0x%x\n",
	    old_cpu_id);

	if (cpu_id == old_cpu_id) {

		mutex_exit(&cpu_lock);
		return (DDI_SUCCESS);
	}

	/*
	 * Get lock, validate cpu and write it.
	 */
	if (!((cpu_id < _ncpu) && (cpu[cpu_id] &&
	    cpu_is_online(cpu[cpu_id])))) {
		/* Invalid cpu */
		DBG(DBG_IB, dip, "px_ib_set_msix_target: Invalid cpuid %x\n",
		    cpu_id);

		mutex_exit(&cpu_lock);
		return (DDI_EINVAL);
	}

	DBG(DBG_IB, dip, "px_ib_set_msix_target: Enabling CPU %d\n", cpu_id);

	if ((ret = px_add_msiq_intr(dip, rdip, hdlp,
	    msiq_rec_type, msi_num, cpu_id, &msiq_id)) != DDI_SUCCESS) {
		DBG(DBG_IB, dip, "px_ib_set_msix_target: Add MSI handler "
		    "failed, rdip 0x%p msi 0x%x\n", rdip, msi_num);

		mutex_exit(&cpu_lock);
		return (ret);
	}

	if ((ret = px_lib_msi_setmsiq(dip, msi_num,
	    msiq_id, msi_type)) != DDI_SUCCESS) {
		mutex_exit(&cpu_lock);

		(void) px_rem_msiq_intr(dip, rdip,
		    hdlp, msiq_rec_type, msi_num, msiq_id);

		return (ret);
	}

	if ((ret = px_ib_update_intr_state(px_p, rdip, hdlp->ih_inum,
	    px_msiqid_to_devino(px_p, msiq_id), hdlp->ih_pri,
	    PX_INTR_STATE_ENABLE, msiq_rec_type, msi_num)) != DDI_SUCCESS) {
		mutex_exit(&cpu_lock);

		(void) px_rem_msiq_intr(dip, rdip,
		    hdlp, msiq_rec_type, msi_num, msiq_id);

		return (ret);
	}

	mutex_exit(&cpu_lock);

	/*
	 * Remove the old handler, but first ensure it is finished.
	 *
	 * Each handler sets its PENDING flag before it clears the MSI state.
	 * Then it clears that flag when finished.  If a re-target occurs while
	 * the MSI state is DELIVERED, then it is not yet known which of the
	 * two handlers will take the interrupt.  So the re-target operation
	 * sets a RETARGET flag on both handlers in that case.  Monitoring both
	 * flags on both handlers then determines when the old handler can be
	 * be safely removed.
	 */
	mutex_enter(&ib_p->ib_ino_lst_mutex);

	ino_p = px_ib_locate_ino(ib_p, px_msiqid_to_devino(px_p, old_msiq_id));
	old_ih_p = px_ib_intr_locate_ih(px_ib_ino_locate_ipil(ino_p,
	    hdlp->ih_pri), rdip, hdlp->ih_inum, msiq_rec_type, msi_num);

	ino_p = px_ib_locate_ino(ib_p, px_msiqid_to_devino(px_p, msiq_id));
	ih_p = px_ib_intr_locate_ih(px_ib_ino_locate_ipil(ino_p, hdlp->ih_pri),
	    rdip, hdlp->ih_inum, msiq_rec_type, msi_num);

	if ((ret = px_lib_msi_getstate(dip, msi_num,
	    &msi_state)) != DDI_SUCCESS) {
		(void) px_rem_msiq_intr(dip, rdip,
		    hdlp, msiq_rec_type, msi_num, msiq_id);

		mutex_exit(&ib_p->ib_ino_lst_mutex);
		return (ret);
	}

	if (msi_state == PCI_MSI_STATE_DELIVERED) {
		ih_p->ih_intr_flags |= PX_INTR_RETARGET;
		old_ih_p->ih_intr_flags |= PX_INTR_RETARGET;
	}

	start_time = gethrtime();
	while (((ih_p->ih_intr_flags & PX_INTR_RETARGET) &&
	    (old_ih_p->ih_intr_flags & PX_INTR_RETARGET)) ||
	    (old_ih_p->ih_intr_flags & PX_INTR_PENDING)) {

		/* Wait for one second */
		delay(drv_usectohz(1000000));

		end_time = gethrtime() - start_time;
		if (end_time > px_ib_msix_retarget_timeout) {
			cmn_err(CE_WARN, "MSIX retarget %x is not completed, "
			    "even after waiting %llx ticks\n",
			    msi_num, end_time);
			break;
		}
	}

	ih_p->ih_intr_flags &= ~(PX_INTR_RETARGET);

	mutex_exit(&ib_p->ib_ino_lst_mutex);

	ret = px_rem_msiq_intr(dip, rdip,
	    hdlp, msiq_rec_type, msi_num, old_msiq_id);

	return (ret);
}


static void
px_fill_in_intr_devs(pcitool_intr_dev_t *dev, char *driver_name,
    char *path_name, int instance)
{
	(void) strncpy(dev->driver_name, driver_name, MAXMODCONFNAME-1);
	dev->driver_name[MAXMODCONFNAME] = '\0';
	(void) strncpy(dev->path, path_name, MAXPATHLEN-1);
	dev->dev_inst = instance;
}


/*
 * Return the dips or number of dips associated with a given interrupt block.
 * Size of dips array arg is passed in as dips_ret arg.
 * Number of dips returned is returned in dips_ret arg.
 * Array of dips gets returned in the dips argument.
 * Function returns number of dips existing for the given interrupt block.
 *
 * Note: this function assumes an enabled/valid INO, which is why it returns
 * the px node and (Internal) when it finds no other devices (and *devs_ret > 0)
 */
uint8_t
pxtool_ib_get_ino_devs(px_t *px_p, uint32_t ino, uint32_t msi_num,
    uint8_t *devs_ret, pcitool_intr_dev_t *devs)
{
	px_ib_t		*ib_p = px_p->px_ib_p;
	px_ino_t	*ino_p;
	px_ino_pil_t	*ipil_p;
	px_ih_t 	*ih_p;
	uint32_t 	num_devs = 0;
	char		pathname[MAXPATHLEN];
	int		i, j;

	mutex_enter(&ib_p->ib_ino_lst_mutex);
	ino_p = px_ib_locate_ino(ib_p, ino);
	if (ino_p != NULL) {
		for (j = 0, ipil_p = ino_p->ino_ipil_p; ipil_p;
		    ipil_p = ipil_p->ipil_next_p) {
			num_devs += ipil_p->ipil_ih_size;

			for (i = 0, ih_p = ipil_p->ipil_ih_head;
			    ((i < ipil_p->ipil_ih_size) && (i < *devs_ret));
			    i++, j++, ih_p = ih_p->ih_next) {
				(void) ddi_pathname(ih_p->ih_dip, pathname);

				if (ih_p->ih_msg_code == msi_num) {
					num_devs = *devs_ret = 1;
					px_fill_in_intr_devs(&devs[0],
					    (char *)ddi_driver_name(
					    ih_p->ih_dip), pathname,
					    ddi_get_instance(ih_p->ih_dip));
					goto done;
				}

				px_fill_in_intr_devs(&devs[j],
				    (char *)ddi_driver_name(ih_p->ih_dip),
				    pathname, ddi_get_instance(ih_p->ih_dip));
			}
		}

		*devs_ret = j;
	} else if (*devs_ret > 0) {
		(void) ddi_pathname(px_p->px_dip, pathname);
		strcat(pathname, " (Internal)");
		px_fill_in_intr_devs(&devs[0],
		    (char *)ddi_driver_name(px_p->px_dip),  pathname,
		    ddi_get_instance(px_p->px_dip));
		num_devs = *devs_ret = 1;
	}

done:
	mutex_exit(&ib_p->ib_ino_lst_mutex);

	return (num_devs);
}


int
pxtool_ib_get_msi_info(px_t *px_p, devino_t ino, msinum_t msi_num,
    ddi_intr_handle_impl_t *hdlp)
{
	px_ib_t		*ib_p = px_p->px_ib_p;
	px_ino_t	*ino_p;
	px_ino_pil_t	*ipil_p;
	px_ih_t 	*ih_p;
	int		i;

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	if ((ino_p = px_ib_locate_ino(ib_p, ino)) == NULL) {
		mutex_exit(&ib_p->ib_ino_lst_mutex);
		return (DDI_FAILURE);
	}

	for (ipil_p = ino_p->ino_ipil_p; ipil_p;
	    ipil_p = ipil_p->ipil_next_p) {
		for (i = 0, ih_p = ipil_p->ipil_ih_head;
		    ((i < ipil_p->ipil_ih_size) && ih_p);
		    i++, ih_p = ih_p->ih_next) {

			if (ih_p->ih_msg_code != msi_num)
				continue;

			hdlp->ih_dip = ih_p->ih_dip;
			hdlp->ih_inum = ih_p->ih_inum;
			hdlp->ih_cb_func = ih_p->ih_handler;
			hdlp->ih_cb_arg1 = ih_p->ih_handler_arg1;
			hdlp->ih_cb_arg2 = ih_p->ih_handler_arg2;
			if (ih_p->ih_rec_type == MSI64_REC)
				hdlp->ih_cap = DDI_INTR_FLAG_MSI64;
			hdlp->ih_pri = ipil_p->ipil_pil;
			hdlp->ih_ver = DDI_INTR_VERSION;

			mutex_exit(&ib_p->ib_ino_lst_mutex);
			return (DDI_SUCCESS);
		}
	}

	mutex_exit(&ib_p->ib_ino_lst_mutex);
	return (DDI_FAILURE);
}

void
px_ib_log_new_cpu(px_ib_t *ib_p, cpuid_t old_cpu_id, cpuid_t new_cpu_id,
    uint32_t ino)
{
	px_ino_t	*ino_p;
	px_ino_pil_t	*ipil_p;
	px_ih_t 	*ih_p;
	int		i;

	mutex_enter(&ib_p->ib_ino_lst_mutex);

	/* Log in OS data structures the new CPU. */
	if (ino_p = px_ib_locate_ino(ib_p, ino)) {

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
				px_ib_cpu_ticks_to_ih_nsec(ib_p,
				    ih_p, old_cpu_id);
			}
		}
	}

	mutex_exit(&ib_p->ib_ino_lst_mutex);
}
