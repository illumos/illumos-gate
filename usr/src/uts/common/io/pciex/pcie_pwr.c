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
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunpm.h>
#include <sys/epm.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/pcie.h>
#include <sys/pcie_impl.h>
#include <sys/promif.h>		/* prom_printf */
#include <sys/pcie_pwr.h>

/*
 * This file implements the power management functionality for
 * pci express switch and pci express-to-pci/pci-x bridge. All the
 * code in this file is generic and is not specific to a particular chip.
 * The algorithm, which decides when to go to a lower power is explained
 * below:
 *
 *	1. Initially when no children are attached, the driver is idle from
 *	PM framework point of view ( PM idle/PM busy).
 *
 *	2. Driver is PM busy if either a reference count called pwr_hold is
 *	greater than zero or driver is already at the lowest possible power
 *	level. The lowest possible power level for the driver is equal to the
 *	highest power level among its children. The PM busy condition is
 *	indicated by PCIE_PM_BUSY bit. At any point, only one pm_busy_component
 *	call is made for a nexus driver instance.
 *
 *	3. Driver is PM idle if the pwr_hold is zero and the lowest
 *	possible power level is less than the driver's current power level.
 *	At any point, only one pm_idle_component call is made for a nexus
 *	driver instance.
 *
 *	4. For any events like child attach, it increments pwr_hold and marks
 *	itslef busy, if it is not already done so. This temporary hold is
 *	removed when the event is complete.
 *
 *	5. Any child's power change requires the parent (this driver) to be
 *	full power. So it raises its power and increments pwr_hold. It also
 *	marks itself temporarily busy, if it is not already done. This hold
 *	is removed when the child power change is complete.
 *
 *	6. After each child power change, it evaluates what is the lowest
 *	possible power level. If the lowest possible power level is less than
 *	the current power level and pwr_hold is zero, then it marks itself
 *	idle. The lowest power level is equal or greater than the highest level
 *	among the children. It keeps track of children's power level by
 *	using counters.
 *
 *	7. Any code e.g., which is accessing the driver's own registers should
 *	place a temporary hold using pcie_pm_hold.
 */

static int pcie_pwr_change(dev_info_t *dip, pcie_pwr_t *pwr_p, int new);
static void pwr_update_counters(int *countersp, int olevel, int nlevel);
static int pwr_level_allowed(pcie_pwr_t *pwr_p);
static void pcie_add_comps(dev_info_t *dip, dev_info_t *cdip,
    pcie_pwr_t *pwr_p);
static void pcie_remove_comps(dev_info_t *dip, dev_info_t *cdip,
    pcie_pwr_t *pwr_p);
static void pcie_pm_subrelease(dev_info_t *dip, pcie_pwr_t *pwr_p);
static boolean_t pcie_is_pcie(dev_info_t *dip);
#ifdef DEBUG
static char *pcie_decode_pwr_op(pm_bus_power_op_t op);
#else
#define	pcie_decode_pwr_op
#endif

/*
 * power entry point.
 *
 * This function decides whether the PM request is honorable.
 * If yes, it then does what's necessary for switch or
 *    bridge to change its power.
 */
/* ARGSUSED */
int
pcie_power(dev_info_t *dip, int component, int level)
{
	pcie_pwr_t *pwr_p = PCIE_NEXUS_PMINFO(dip);
	int *counters = pwr_p->pwr_counters;
	int pmcaps = pwr_p->pwr_pmcaps;
	int ret = DDI_FAILURE;

#if defined(__i386) || defined(__amd64)
	if (dip)
		return (DDI_SUCCESS);
#endif /* defined(__i386) || defined(__amd64) */

	ASSERT(level != PM_LEVEL_UNKNOWN);
	/* PM should not asking for a level, which is unsupported */
	ASSERT(level == PM_LEVEL_D0 || level == PM_LEVEL_D3 ||
	    (level == PM_LEVEL_D1 && (pmcaps & PCIE_SUPPORTS_D1)) ||
	    (level == PM_LEVEL_D2 && (pmcaps & PCIE_SUPPORTS_D2)));

	mutex_enter(&pwr_p->pwr_lock);
	PCIE_DBG("%s(%d): pcie_power: change from %d to %d\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), pwr_p->pwr_func_lvl,
	    level);
	if (pwr_p->pwr_func_lvl == level) {
		PCIE_DBG("%s(%d): pcie_power: already at %d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip), level);
		ret = DDI_SUCCESS;
		goto pcie_pwr_done;
	}

	if (level < pwr_p->pwr_func_lvl) {
		/*
		 * Going to lower power. Reject this if we are either busy
		 * or there is a hold.
		 */
		if (pwr_p->pwr_flags & PCIE_PM_BUSY) {
			PCIE_DBG("%s(%d): pcie_power: rejecting change to %d "
			    "as busy\n", ddi_driver_name(dip),
			    ddi_get_instance(dip), level);
			goto pcie_pwr_done;
		}

		/*
		 * Now we know that we are neither busy nor there is a hold.
		 * At this point none of the children should be at full power.
		 * Reject the request if level reqested is lower than the level
		 * possible.
		 */
		ASSERT(!counters[PCIE_D0_INDEX] &&
		    !counters[PCIE_UNKNOWN_INDEX]);
		if (level < pwr_level_allowed(pwr_p)) {
			PCIE_DBG("%s(%d): pcie_power: rejecting level %d as"
			    " %d is the lowest possible\n",
			    ddi_driver_name(dip), ddi_get_instance(dip), level,
			    pwr_level_allowed(pwr_p));
			goto pcie_pwr_done;
		}
	}

	if (pcie_pwr_change(dip, pwr_p, level) != DDI_SUCCESS) {
		PCIE_DBG("%s(%d): pcie_power: attempt to change to %d "
		    " failed \n", ddi_driver_name(dip), ddi_get_instance(dip),
		    level);
		goto pcie_pwr_done;
	}
	pwr_p->pwr_func_lvl = level;
	PCIE_DBG("%s(%d): pcie_power: level changed to %d \n",
	    ddi_driver_name(dip), ddi_get_instance(dip), level);
	ret = DDI_SUCCESS;

pcie_pwr_done:
	mutex_exit(&pwr_p->pwr_lock);
	return (ret);
}

/*
 * Called by pcie_power() only. Caller holds the pwr_lock.
 *
 * dip - dev_info pointer
 * pwr_p - pm info for the node.
 * new     - new level
 */
static int
pcie_pwr_change(dev_info_t *dip, pcie_pwr_t *pwr_p, int new)
{
	uint16_t pmcsr;

	ASSERT(MUTEX_HELD(&pwr_p->pwr_lock));
	ASSERT(new != pwr_p->pwr_func_lvl);
	pmcsr = pci_config_get16(pwr_p->pwr_conf_hdl, pwr_p->pwr_pmcsr_offset);
	pmcsr &= ~PCI_PMCSR_STATE_MASK;
	switch (new) {
	case PM_LEVEL_D0:
		pmcsr |= PCI_PMCSR_D0;
		break;

	case PM_LEVEL_D1:
		pmcsr |= PCI_PMCSR_D1;
		break;

	case PM_LEVEL_D2:
		pmcsr |= PCI_PMCSR_D2;
		break;

	case PM_LEVEL_D3:
		pmcsr |= PCI_PMCSR_D3HOT;
		break;

	default:
		ASSERT(0);
		break;
	}
	/* Save config space, if going to D3 */
	if (new == PM_LEVEL_D3) {
		PCIE_DBG("%s(%d): pwr_change: saving config space regs\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		if (pci_save_config_regs(dip) != DDI_SUCCESS) {
			PCIE_DBG("%s(%d): pcie_pwr_change: failed to save "
			    "config space regs\n", ddi_driver_name(dip),
			    ddi_get_instance(dip));
			return (DDI_FAILURE);
		}
	}

	pci_config_put16(pwr_p->pwr_conf_hdl, pwr_p->pwr_pmcsr_offset, pmcsr);

	/*
	 * TBD: Taken from pci_pci driver. Is this required?
	 * No bus transactions should occur without waiting for
	 * settle time specified in PCI PM spec rev 2.1 sec 5.6.1
	 * To make things simple, just use the max time specified for
	 * all state transitions.
	 */
	delay(drv_usectohz(PCI_CLK_SETTLE_TIME));

	/*
	 * Restore config space if coming out of D3
	 */
	if (pwr_p->pwr_func_lvl == PM_LEVEL_D3) {
		PCIE_DBG("%s(%d): pcie_pwr_change: restoring config space\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		if (pci_restore_config_regs(dip) != DDI_SUCCESS) {
			PCIE_DBG("%s(%d): pcie_pwr_change: failed to restore "
			    "config space regs\n", ddi_driver_name(dip),
			    ddi_get_instance(dip));
			return (DDI_FAILURE);
		}
	}
	return (DDI_SUCCESS);
}

/*
 * bus_ctlops.bus_power function.
 *
 * This function handles PRE_ POST_ change notifications, sent by
 * PM framework related to child's power level change. It marks itself
 * idle or busy based on the children's power level.
 */
int
pcie_bus_power(dev_info_t *dip, void *impl_arg, pm_bus_power_op_t op,
    void *arg, void *result)
{
	pcie_pwr_t *pwr_p = PCIE_NEXUS_PMINFO(dip);
	int *counters = pwr_p->pwr_counters; /* nexus counters */
	int *child_counters; /* per child dip counters */
	pm_bp_child_pwrchg_t *bpc;
	pm_bp_has_changed_t *bphc;
	dev_info_t *cdip;
	int new_level;
	int old_level;
	int rv = DDI_SUCCESS;
	int level_allowed, comp;

#if defined(__i386) || defined(__amd64)
	if (dip)
		return (DDI_SUCCESS);
#endif /* defined(__i386) || defined(__amd64) */

	switch (op) {
	case BUS_POWER_PRE_NOTIFICATION:
	case BUS_POWER_POST_NOTIFICATION:
		bpc = (pm_bp_child_pwrchg_t *)arg;
		cdip = bpc->bpc_dip;
		new_level = bpc->bpc_nlevel;
		old_level = bpc->bpc_olevel;
		comp = bpc->bpc_comp;
		break;

	case BUS_POWER_HAS_CHANGED:
		bphc = (pm_bp_has_changed_t *)arg;
		cdip = bphc->bphc_dip;
		new_level = bphc->bphc_nlevel;
		old_level = bphc->bphc_olevel;
		comp = bphc->bphc_comp;
		break;

	default:
		break;

	}

	ASSERT(pwr_p);
	mutex_enter(&pwr_p->pwr_lock);
	switch (op) {
	case BUS_POWER_PRE_NOTIFICATION:
		PCIE_DBG("%s(%d): pcie_bus_power: %s@%d op %s %d->%d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    ddi_driver_name(cdip), ddi_get_instance(cdip),
		    pcie_decode_pwr_op(op), old_level, new_level);
		/*
		 * If the nexus doesn't want the child to go into
		 * non-D0 state, mark the child busy. This way PM
		 * framework will never try to lower the child's power.
		 * In case of pm_lower_power, marking busy won't help.
		 * So we need to specifically reject the attempt to
		 * go to non-D0 state.
		 */
		if (pwr_p->pwr_flags & PCIE_NO_CHILD_PM) {
			if (!PCIE_IS_COMPS_COUNTED(cdip)) {
				PCIE_DBG("%s(%d): pcie_bus_power: marking "
				    "child busy to disable pm \n",
				    ddi_driver_name(dip),
				    ddi_get_instance(dip));
				(void) pm_busy_component(cdip, 0);
			}
			if (new_level < PM_LEVEL_D0 && !comp) {
				PCIE_DBG("%s(%d): pcie_bus_power: rejecting "
				    "child's attempt to go to %d\n",
				    ddi_driver_name(dip), ddi_get_instance(dip),
				    new_level);
				rv = DDI_FAILURE;
			}
		}
		mutex_exit(&pwr_p->pwr_lock);
		if (rv == DDI_SUCCESS)
			rv = pcie_pm_hold(dip);
		return (rv);

	case BUS_POWER_HAS_CHANGED:
	case BUS_POWER_POST_NOTIFICATION:
		PCIE_DBG("%s(%d): pcie_bus_power: %s@%d op %s %d->%d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    ddi_driver_name(cdip), ddi_get_instance(cdip),
		    pcie_decode_pwr_op(op), old_level, new_level);
		/*
		 * Child device power changed
		 * If pm components of this child aren't accounted for
		 * then add the components to the counters. This can't
		 * be done in POST_ATTACH ctlop as pm info isn't created
		 * by then. Also because a driver can make a pm call during
		 * the attach.
		 */
		if (!PCIE_IS_COMPS_COUNTED(cdip)) {
			(void) pcie_pm_add_child(dip, cdip);
			if ((pwr_p->pwr_flags & PCIE_NO_CHILD_PM) &&
			    (op == BUS_POWER_HAS_CHANGED)) {
				PCIE_DBG("%s(%d): pcie_bus_power: marking "
				    "child busy to disable pm \n",
				    ddi_driver_name(dip),
				    ddi_get_instance(dip));
				(void) pm_busy_component(cdip, 0);
				/*
				 * If the driver has already changed to lower
				 * power(pm_power_has_changed) on its own,
				 * there is nothing we can do other than
				 * logging the warning message on the console.
				 */
				if (new_level < PM_LEVEL_D0)
					cmn_err(CE_WARN, "!Downstream device "
					    "%s@%d went to non-D0 state: "
					    "possible loss of link\n",
					    ddi_driver_name(cdip),
					    ddi_get_instance(cdip));
			}
		}


		/*
		 * If it is POST and device PM is supported, release the
		 * hold done in PRE.
		 */
		if (op == BUS_POWER_POST_NOTIFICATION &&
		    PCIE_SUPPORTS_DEVICE_PM(dip)) {
			pcie_pm_subrelease(dip, pwr_p);
		}

		if (*((int *)result) == DDI_FAILURE) {
			PCIE_DBG("%s(%d): pcie_bus_power: change for %s%d "
			    "failed\n", ddi_driver_name(dip),
			    ddi_get_instance(dip), ddi_driver_name(cdip),
			    ddi_get_instance(cdip));
			break;
		}
		/* Modify counters appropriately */
		pwr_update_counters(counters, old_level, new_level);

		child_counters = PCIE_CHILD_COUNTERS(cdip);
		pwr_update_counters(child_counters, old_level, new_level);

		/* If no device PM, return */
		if (!PCIE_SUPPORTS_DEVICE_PM(dip))
			break;

		level_allowed = pwr_level_allowed(pwr_p);
		/*
		 * Check conditions for marking busy
		 * Check the flag to set this busy only once for multiple
		 * busy conditions. Mark busy if our current lowest possible
		 * is equal or greater to the current level.
		 */
		if (level_allowed >= pwr_p->pwr_func_lvl &&
		    !(pwr_p->pwr_flags & PCIE_PM_BUSY)) {
			PCIE_DBG("%s(%d): pcie_bus_power: marking busy\n",
			    ddi_driver_name(dip), ddi_get_instance(dip));
			(void) pm_busy_component(dip, 0);
			pwr_p->pwr_flags |= PCIE_PM_BUSY;
			break;
		}
		/*
		 * Check conditions for marking idle.
		 * If our lowest possible level is less than our current
		 * level mark idle. Mark idle only if it is not already done.
		 */
		if ((level_allowed < pwr_p->pwr_func_lvl) &&
		    (pwr_p->pwr_hold == 0) &&
		    (pwr_p->pwr_flags & PCIE_PM_BUSY)) {
			/*
			 * For pci express, we should check here whether
			 * the link is in L1 state or not.
			 */
			PCIE_DBG("%s(%d): pcie_bus_power: marking idle\n",
			    ddi_driver_name(dip), ddi_get_instance(dip));
			(void) pm_idle_component(dip, 0);
			pwr_p->pwr_flags &= ~PCIE_PM_BUSY;
			break;
		}
		break;

	default:
		mutex_exit(&pwr_p->pwr_lock);
		return (pm_busop_bus_power(dip, impl_arg, op, arg, result));
	}
	mutex_exit(&pwr_p->pwr_lock);
	return (rv);
}

/*
 * Decrement the count of children at olevel by one and increment
 * count of children at nlevel by one.
 */
static void
pwr_update_counters(int *countersp, int olevel, int nlevel)
{
	uint32_t	index;

	ASSERT(olevel >= PM_LEVEL_UNKNOWN && olevel <= PM_LEVEL_D0);
	ASSERT(nlevel >= PM_LEVEL_UNKNOWN && nlevel <= PM_LEVEL_D0);

	index = (olevel == PM_LEVEL_UNKNOWN ? PCIE_UNKNOWN_INDEX : olevel);
	countersp[index]--;
	index = (nlevel == PM_LEVEL_UNKNOWN ? PCIE_UNKNOWN_INDEX : nlevel);
	countersp[index]++;
}

/*
 * Returns the lowest possible power level allowed for nexus
 * based on children's power level. Lowest possible level is
 * equal to the highest level among the children. It also checks
 * for the supported level
 * UNKNOWN = D0 > D1 > D2 > D3
 */
static int
pwr_level_allowed(pcie_pwr_t *pwr_p)
{
	int *counters = pwr_p->pwr_counters;
	int i, j;

	ASSERT(MUTEX_HELD(&pwr_p->pwr_lock));
	/*
	 * Search from UNKNOWN to D2. unknown is same as D0.
	 * find the highest level among the children. If that
	 * level is supported, return that level. If not,
	 * find the next higher supported level and return that
	 * level. For example, if the D1 is the highest among
	 * children and if D1 isn't supported return D0 as the
	 * lowest possible level. We don't need to look at D3
	 * as that is the default lowest level and it is always
	 * supported.
	 */
	for (i = PCIE_UNKNOWN_INDEX; i > 0; i--) {
		if (counters[i]) {
			if (i == PCIE_UNKNOWN_INDEX)
				return (PM_LEVEL_D0);
			/*
			 * i is the highest level among children. If this is
			 * supported, return i.
			 */
			if (PCIE_LEVEL_SUPPORTED(pwr_p->pwr_pmcaps, i))
				return (i);
			/* find the next higher supported level */
			for (j = i + 1; j <= PCIE_D0_INDEX; j++) {
				if (PCIE_LEVEL_SUPPORTED(pwr_p->pwr_pmcaps, j))
					return (j);
			}
		}
	}

	return (PM_LEVEL_D3);
}

/*
 * Update the counters with number pm components of the child
 * all components are assumed to be at UNKNOWN level.
 */
static void
pcie_add_comps(dev_info_t *dip, dev_info_t *cdip, pcie_pwr_t *pwr_p)
{
	int comps = PM_NUMCMPTS(cdip);
	pcie_pm_t *pcie_pm_p;
	pcie_pwr_child_t *cpwr_p;

	ASSERT(MUTEX_HELD(&pwr_p->pwr_lock));
	if (!comps)
		return;

	PCIE_DBG("%s(%d): pcie_add_comps: unknown level counter incremented "
	    "from %d by %d because of %s@%d\n",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    (pwr_p->pwr_counters)[PCIE_UNKNOWN_INDEX], comps,
	    ddi_driver_name(cdip), ddi_get_instance(cdip));
	(pwr_p->pwr_counters)[PCIE_UNKNOWN_INDEX] += comps;
	/*
	 * Allocate counters per child. This is a part of pcie
	 * pm info. If there is no pcie pm info, allocate it here.
	 * pcie pm info might already be there for pci express nexus
	 * driver e.g. pcieb. For all leaf nodes, it is allocated here.
	 */
	if ((pcie_pm_p = PCIE_PMINFO(cdip)) == NULL) {
		pcie_pm_p = (pcie_pm_t *)kmem_zalloc(
		    sizeof (pcie_pm_t), KM_SLEEP);
		PCIE_SET_PMINFO(cdip, pcie_pm_p);
	}
	cpwr_p = (pcie_pwr_child_t *)kmem_zalloc(sizeof (pcie_pwr_child_t),
	    KM_SLEEP);
	pcie_pm_p->pcie_par_pminfo = cpwr_p;
	(cpwr_p->pwr_child_counters)[PCIE_UNKNOWN_INDEX] += comps;
}

/*
 * Remove the pm components of a child from our counters.
 */
static void
pcie_remove_comps(dev_info_t *dip, dev_info_t *cdip, pcie_pwr_t *pwr_p)
{
	int i;
	int *child_counters;

	ASSERT(MUTEX_HELD(&pwr_p->pwr_lock));
	if (!(PCIE_PMINFO(cdip)) || !PCIE_PAR_PMINFO(cdip)) {
		if (PCIE_SUPPORTS_DEVICE_PM(dip)) {
			/*
			 * Driver never made a PM call and we didn't create
			 * any counters for this device. This also means that
			 * hold made at the PRE_ATTACH time, still remains.
			 * Remove the hold now. The correct thing to do is to
			 * stay at full power when a child is at full power
			 * whether a driver is there or not. This will be
			 * implemented in the future.
			 */
			pcie_pm_subrelease(dip, pwr_p);
		}
		return;
	}
	PCIE_DBG("%s(%d): pcie_remove_comps:counters decremented because of "
	    "%s@%d\n", ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(cdip), ddi_get_instance(cdip));
	child_counters = PCIE_CHILD_COUNTERS(cdip);
	/*
	 * Adjust the nexus counters. No need to adjust per child dip
	 * counters as we are freeing the per child dip info.
	 */
	for (i = 0; i < PCIE_MAX_PWR_LEVELS; i++) {
		ASSERT((pwr_p->pwr_counters)[i] >= child_counters[i]);
		(pwr_p->pwr_counters)[i] -= child_counters[i];
	}
	/* remove both parent pm info and pcie pminfo itself */
	kmem_free(PCIE_PAR_PMINFO(cdip), sizeof (pcie_pwr_child_t));
	kmem_free(PCIE_PMINFO(cdip), sizeof (pcie_pm_t));
	PCIE_RESET_PMINFO(cdip);
}

/*
 * Power management related initialization common to px and pcieb
 */
int
pwr_common_setup(dev_info_t *dip)
{
	pcie_pm_t		*pcie_pm_p;
	pcie_pwr_t		*pwr_p;
	int			pminfo_created = 0;

	/* Create pminfo, if it doesn't exist already */
	if ((pcie_pm_p = PCIE_PMINFO(dip)) == NULL) {
		pcie_pm_p = (pcie_pm_t *)kmem_zalloc(
		    sizeof (pcie_pm_t), KM_SLEEP);
		PCIE_SET_PMINFO(dip, pcie_pm_p);
		pminfo_created = 1;
	}
	pwr_p = (pcie_pwr_t *)kmem_zalloc(sizeof (pcie_pwr_t), KM_SLEEP);
	mutex_init(&pwr_p->pwr_lock, NULL, MUTEX_DRIVER, NULL);
	/* Initialize the power level and default level support */
	pwr_p->pwr_func_lvl = PM_LEVEL_UNKNOWN;
	pwr_p->pwr_pmcaps = PCIE_DEFAULT_LEVEL_SUPPORTED;

	if (pcie_plat_pwr_setup(dip) != DDI_SUCCESS)
		goto pwr_common_err;

	pcie_pm_p->pcie_pwr_p = pwr_p;
	return (DDI_SUCCESS);

pwr_common_err:
	mutex_destroy(&pwr_p->pwr_lock);
	kmem_free(pwr_p, sizeof (pcie_pwr_t));
	if (pminfo_created) {
		PCIE_RESET_PMINFO(dip);
		kmem_free(pcie_pm_p, sizeof (pcie_pm_t));
	}
	return (DDI_FAILURE);

}

/*
 * Undo whatever is done in pwr_common_setup. Called by px_detach or pxb_detach
 */
void
pwr_common_teardown(dev_info_t *dip)
{
	pcie_pm_t *pcie_pm_p = PCIE_PMINFO(dip);
	pcie_pwr_t *pwr_p;

	if (!pcie_pm_p || !(pwr_p = PCIE_NEXUS_PMINFO(dip)))
		return;

	pcie_plat_pwr_teardown(dip);
	mutex_destroy(&pwr_p->pwr_lock);
	pcie_pm_p->pcie_pwr_p = NULL;
	kmem_free(pwr_p, sizeof (pcie_pwr_t));
	/*
	 * If the parent didn't store have any pm info about
	 * this node, that means parent doesn't need pminfo when it handles
	 * POST_DETACH for this node. For example, if dip is the dip of
	 * root complex, then there is no parent pm info.
	 */
	if (!PCIE_PAR_PMINFO(dip)) {
		kmem_free(pcie_pm_p, sizeof (pcie_pm_t));
		PCIE_RESET_PMINFO(dip);
	}
}

/*
 * Raises the power and marks itself busy.
 */
int
pcie_pm_hold(dev_info_t *dip)
{
	pcie_pwr_t *pwr_p;

	/* If no PM info or no device PM, return */
	if (!PCIE_PMINFO(dip) || !(pwr_p = PCIE_NEXUS_PMINFO(dip)) ||
	    !(PCIE_SUPPORTS_DEVICE_PM(dip)))
		return (DDI_SUCCESS);

	/*
	 * If we are not at full power, then powerup.
	 * Need to be at full power so that link can be
	 * at L0. Similarly for PCI/PCI-X bus, it should be
	 * at full power.
	 */
	mutex_enter(&pwr_p->pwr_lock);
	ASSERT(pwr_p->pwr_hold >= 0);
	PCIE_DBG("%s(%d): pm_hold: incrementing hold \n",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	pwr_p->pwr_hold++;
	/* Mark itself busy, if it is not done already */
	if (!(pwr_p->pwr_flags & PCIE_PM_BUSY)) {
		PCIE_DBG("%s(%d): pm_hold: marking busy\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		pwr_p->pwr_flags |= PCIE_PM_BUSY;
		(void) pm_busy_component(dip, 0);
	}
	if (pwr_p->pwr_func_lvl == PM_LEVEL_D0) {
		mutex_exit(&pwr_p->pwr_lock);
		return (DDI_SUCCESS);
	}
	mutex_exit(&pwr_p->pwr_lock);
	if (pm_raise_power(dip, 0, PM_LEVEL_D0) != DDI_SUCCESS) {
		PCIE_DBG("%s(%d): pm_hold: attempt to raise power "
		    "from %d to %d failed\n", ddi_driver_name(dip),
		    ddi_get_instance(dip), pwr_p->pwr_func_lvl,
		    PM_LEVEL_D0);
		pcie_pm_release(dip);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Reverse the things done in pcie_pm_hold
 */
void
pcie_pm_release(dev_info_t *dip)
{
	pcie_pwr_t *pwr_p;

	/* If no PM info or no device PM, return */
	if (!PCIE_PMINFO(dip) || !(pwr_p = PCIE_NEXUS_PMINFO(dip)) ||
	    !(PCIE_SUPPORTS_DEVICE_PM(dip)))
		return;

	mutex_enter(&pwr_p->pwr_lock);
	pcie_pm_subrelease(dip, pwr_p);
	mutex_exit(&pwr_p->pwr_lock);
}

static void
pcie_pm_subrelease(dev_info_t *dip, pcie_pwr_t *pwr_p)
{
	int level;

	ASSERT(MUTEX_HELD(&pwr_p->pwr_lock));
	ASSERT(pwr_p->pwr_hold > 0);
	PCIE_DBG("%s(%d): pm_subrelease: decrementing hold \n",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	pwr_p->pwr_hold--;
	ASSERT(pwr_p->pwr_hold >= 0);
	ASSERT(pwr_p->pwr_flags & PCIE_PM_BUSY);
	level = pwr_level_allowed(pwr_p);
	if (pwr_p->pwr_hold == 0 && level < pwr_p->pwr_func_lvl) {
		PCIE_DBG("%s(%d): pm_subrelease: marking idle \n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		(void) pm_idle_component(dip, 0);
		pwr_p->pwr_flags &= ~PCIE_PM_BUSY;
	}
}

/*
 * Called when the child makes the first power management call.
 * sets up the counters. All the components of the child device are
 * assumed to be at unknown level. It also releases the power hold
 *	pwr_p - parent's pwr_t
 *	cdip   - child's dip
 */
int
pcie_pm_add_child(dev_info_t *dip, dev_info_t *cdip)
{
	pcie_pwr_t *pwr_p;

	/* If no PM info, return */
	if (!PCIE_PMINFO(dip) || !(pwr_p = PCIE_NEXUS_PMINFO(dip)))
		return (DDI_SUCCESS);

	ASSERT(MUTEX_HELD(&pwr_p->pwr_lock));
	ASSERT(pwr_p->pwr_func_lvl == PM_LEVEL_D0);
	pcie_add_comps(dip, cdip, pwr_p);

	/* If no device power management then return */
	if (!PCIE_SUPPORTS_DEVICE_PM(dip))
		return (DDI_SUCCESS);

	/*
	 * We have informed PM that we are busy at PRE_ATTACH time for
	 * this child. Release the hold and but don't clear the busy bit.
	 * If a device never changes power, hold will not be released
	 * and we stay at full power.
	 */
	ASSERT(pwr_p->pwr_hold > 0);
	PCIE_DBG("%s(%d): pm_add_child: decrementing hold \n",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	pwr_p->pwr_hold--;
	/*
	 * We must have made sure that busy bit
	 * is set when we put the hold
	 */
	ASSERT(pwr_p->pwr_flags & PCIE_PM_BUSY);
	return (DDI_SUCCESS);
}

/*
 * Adjust the counters when a child detaches
 * Marks itself idle if the idle conditions are met.
 * Called at POST_DETACH time
 */
int
pcie_pm_remove_child(dev_info_t *dip, dev_info_t *cdip)
{
	int *counters;
	int total;
	pcie_pwr_t *pwr_p;

	/* If no PM info, return */
	if (!PCIE_PMINFO(dip) || !(pwr_p = PCIE_NEXUS_PMINFO(dip)))
		return (DDI_SUCCESS);

	counters = pwr_p->pwr_counters;
	mutex_enter(&pwr_p->pwr_lock);
	pcie_remove_comps(dip, cdip, pwr_p);
	/* If no device power management then return */
	if (!PCIE_SUPPORTS_DEVICE_PM(dip)) {
		mutex_exit(&pwr_p->pwr_lock);
		return (DDI_SUCCESS);
	}
	total = (counters[PCIE_D0_INDEX] + counters[PCIE_UNKNOWN_INDEX] +
	    counters[PCIE_D1_INDEX] + counters[PCIE_D2_INDEX] +
	    counters[PCIE_D3_INDEX]);
	/*
	 * Mark idle if either there are no children or our lowest
	 * possible level is less than the current level. Mark idle
	 * only if it is not already done.
	 */
	if ((pwr_p->pwr_hold == 0) &&
	    (!total || (pwr_level_allowed(pwr_p) < pwr_p->pwr_func_lvl))) {
		if (pwr_p->pwr_flags & PCIE_PM_BUSY) {
			PCIE_DBG("%s(%d): pcie_bus_power: marking idle\n",
			    ddi_driver_name(dip), ddi_get_instance(dip));
			(void) pm_idle_component(dip, 0);
			pwr_p->pwr_flags &= ~PCIE_PM_BUSY;
		}
	}
	mutex_exit(&pwr_p->pwr_lock);
	return (DDI_SUCCESS);
}

boolean_t
pcie_is_pcie(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);
	ASSERT(bus_p);
	return (bus_p->bus_pcie_off != 0);
}

/*
 * Called by px_attach or pcieb_attach:: DDI_RESUME
 */
int
pcie_pwr_resume(dev_info_t *dip)
{
	dev_info_t *cdip;
	pcie_pwr_t *pwr_p = NULL;

#if defined(__i386) || defined(__amd64)
	if (dip)
		return (DDI_SUCCESS);
#endif /* defined(__i386) || defined(__amd64) */

	if (PCIE_PMINFO(dip))
		pwr_p = PCIE_NEXUS_PMINFO(dip);

	if (pwr_p) {
		/* Inform the PM framework that dip is at full power */
		if (PCIE_SUPPORTS_DEVICE_PM(dip)) {
			ASSERT(pwr_p->pwr_func_lvl == PM_LEVEL_D0);
			(void) pm_raise_power(dip, 0,
			    pwr_p->pwr_func_lvl);
		}
	}

	/*
	 * Code taken from pci driver.
	 * Restore config registers for children that did not save
	 * their own registers.  Children pwr states are UNKNOWN after
	 * a resume since it is possible for the PM framework to call
	 * resume without an actual power cycle. (ie if suspend fails).
	 */
	for (cdip = ddi_get_child(dip); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {
		boolean_t	is_pcie;

		/*
		 * Not interested in children who are not already
		 * init'ed.  They will be set up by init_child().
		 */
		if (i_ddi_node_state(cdip) < DS_INITIALIZED) {
			PCIE_DBG("%s(%d): "
			    "DDI_RESUME: skipping %s%d not in CF1\n",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    ddi_driver_name(cdip), ddi_get_instance(cdip));
			continue;
		}

		/*
		 * Only restore config registers if saved by nexus.
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "nexus-saved-config-regs") != 1)
			continue;

		PCIE_DBG("%s(%d): "
		    "DDI_RESUME: nexus restoring %s%d config regs\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    ddi_driver_name(cdip), ddi_get_instance(cdip));

		/* clear errors left by OBP scrubbing */
		pcie_clear_errors(cdip);

		/* PCIe workaround: disable errors during 4K config resore */
		is_pcie = pcie_is_pcie(cdip);
		if (is_pcie)
			pcie_disable_errors(cdip);
		(void) pci_restore_config_regs(cdip);
		if (is_pcie) {
			pcie_enable_errors(cdip);
			(void) pcie_enable_ce(cdip);
		}

		if (ndi_prop_remove(DDI_DEV_T_NONE, cdip,
		    "nexus-saved-config-regs") != DDI_PROP_SUCCESS) {
			PCIE_DBG("%s(%d): %s%d can't remove prop %s",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    ddi_driver_name(cdip), ddi_get_instance(cdip),
			    "nexus-saved-config-regs");
		}
	}
	return (DDI_SUCCESS);
}

/*
 * Called by pcie_detach or pcieb_detach:: DDI_SUSPEND
 */
int
pcie_pwr_suspend(dev_info_t *dip)
{
	dev_info_t *cdip;
	int i, *counters; /* per nexus counters */
	int *child_counters = NULL; /* per child dip counters */
	pcie_pwr_t *pwr_p = NULL;

#if defined(__i386) || defined(__amd64)
	if (dip)
		return (DDI_SUCCESS);
#endif /* defined(__i386) || defined(__amd64) */

	if (PCIE_PMINFO(dip))
		pwr_p = PCIE_NEXUS_PMINFO(dip);

	/*
	 * Mark all children to be unknown and bring our power level
	 * to full, if required. This is to avoid any panics while
	 * accessing the child's config space.
	 */
	if (pwr_p) {
		mutex_enter(&pwr_p->pwr_lock);
		if (PCIE_SUPPORTS_DEVICE_PM(dip) &&
		    pwr_p->pwr_func_lvl != PM_LEVEL_D0) {
			mutex_exit(&pwr_p->pwr_lock);
			if (pm_raise_power(dip, 0, PM_LEVEL_D0) !=
			    DDI_SUCCESS) {
				PCIE_DBG("%s(%d): pwr_suspend: attempt "
				    "to raise power from %d to %d "
				    "failed\n", ddi_driver_name(dip),
				    ddi_get_instance(dip), pwr_p->pwr_func_lvl,
				    PM_LEVEL_D0);
				return (DDI_FAILURE);
			}
			mutex_enter(&pwr_p->pwr_lock);
		}
		counters = pwr_p->pwr_counters;
		/*
		 * Update the nexus counters. At the resume time all
		 * components are considered to be at unknown level. Use the
		 * fact that counters for unknown level are at the end.
		 */
		for (i = 0; i < PCIE_UNKNOWN_INDEX; i++) {
			counters[PCIE_UNKNOWN_INDEX] += counters[i];
			counters[i] = 0;
		}
		mutex_exit(&pwr_p->pwr_lock);
	}

	/*
	 * Code taken from pci driver.
	 * Save the state of the configuration headers of child
	 * nodes.
	 */
	for (cdip = ddi_get_child(dip); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {
		boolean_t	is_pcie;

		/*
		 * Not interested in children who are not already
		 * init'ed.  They will be set up in init_child().
		 */
		if (i_ddi_node_state(cdip) < DS_INITIALIZED) {
			PCIE_DBG("%s(%d): DDI_SUSPEND: skipping "
			    "%s%d not in CF1\n", ddi_driver_name(dip),
			    ddi_get_instance(dip), ddi_driver_name(cdip),
			    ddi_get_instance(cdip));
			continue;
		}
		/*
		 * Update per child dip counters, if any. Counters
		 * will not exist if the child is not power manageable
		 * or if its power entry is never invoked.
		 */
		if (PCIE_PMINFO(cdip) && PCIE_PAR_PMINFO(cdip))
			child_counters = PCIE_CHILD_COUNTERS(cdip);
		if (child_counters && pwr_p) {
			mutex_enter(&pwr_p->pwr_lock);
			for (i = 0; i < PCIE_UNKNOWN_INDEX; i++) {
				child_counters[PCIE_UNKNOWN_INDEX] +=
				    child_counters[i];
				child_counters[i] = 0;
			}
			mutex_exit(&pwr_p->pwr_lock);
		}

		/*
		 * Only save config registers if not already saved by child.
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    SAVED_CONFIG_REGS) == 1) {
			continue;
		}

		/*
		 * The nexus needs to save config registers.  Create a property
		 * so it knows to restore on resume.
		 */
		if (ndi_prop_create_boolean(DDI_DEV_T_NONE, cdip,
		    "nexus-saved-config-regs") != DDI_PROP_SUCCESS) {
			PCIE_DBG("%s(%d): %s%d can't update prop %s",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    ddi_driver_name(cdip), ddi_get_instance(cdip),
			    "nexus-saved-config-regs");
		}
		PCIE_DBG("%s(%d): DDI_SUSPEND: saving config space for"
		    " %s%d\n", ddi_driver_name(dip), ddi_get_instance(dip),
		    ddi_driver_name(cdip), ddi_get_instance(cdip));

		/* PCIe workaround: disable errors during 4K config save */
		is_pcie = pcie_is_pcie(cdip);
		if (is_pcie)
			pcie_disable_errors(cdip);
		(void) pci_save_config_regs(cdip);
		if (is_pcie) {
			pcie_enable_errors(cdip);
			(void) pcie_enable_ce(cdip);
		}
	}
	return (DDI_SUCCESS);
}

#ifdef DEBUG
/*
 * Description of bus_power_op.
 */
typedef struct pcie_buspwr_desc {
	pm_bus_power_op_t pwr_op;
	char *pwr_desc;
} pcie_buspwr_desc_t;

static pcie_buspwr_desc_t pcie_buspwr_desc[] = {
	{BUS_POWER_CHILD_PWRCHG, "CHILD_PWRCHG"},
	{BUS_POWER_NEXUS_PWRUP, "NEXUS_PWRUP"},
	{BUS_POWER_PRE_NOTIFICATION, "PRE_NOTIFICATION"},
	{BUS_POWER_POST_NOTIFICATION, "POST_NOTIFICATION"},
	{BUS_POWER_HAS_CHANGED, "HAS_CHANGED"},
	{BUS_POWER_NOINVOL, "NOINVOL"},
	{-1, NULL}
};

/*
 * Returns description of the bus_power_op.
 */
static char *
pcie_decode_pwr_op(pm_bus_power_op_t op)
{
	pcie_buspwr_desc_t *descp = pcie_buspwr_desc;

	for (; descp->pwr_desc; descp++) {
		if (op == descp->pwr_op)
			return (descp->pwr_desc);
	}
	return ("UNKNOWN OP");
}
#endif
