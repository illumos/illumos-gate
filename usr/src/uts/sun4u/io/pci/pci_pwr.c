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

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/pci/pci_obj.h>
#include <sys/pci/pci_pwr.h>
#include <sys/pci.h>

static void pci_pwr_update_comp(pci_pwr_t *pwr_p, pci_pwr_chld_t *p, int comp,
	int lvl);

#ifdef DEBUG
static char *pci_pwr_bus_label[] = {"PM_LEVEL_B3", "PM_LEVEL_B2", \
	"PM_LEVEL_B1", "PM_LEVEL_B0"};
#endif

/*LINTLIBRARY*/

/*
 * Retreive the pci_pwr_chld_t structure for a given devinfo node.
 */
pci_pwr_chld_t *
pci_pwr_get_info(pci_pwr_t *pwr_p, dev_info_t *dip)
{
	pci_pwr_chld_t *p;

	ASSERT(PM_CAPABLE(pwr_p));
	ASSERT(MUTEX_HELD(&pwr_p->pwr_mutex));

	for (p = pwr_p->pwr_info; p != NULL; p = p->next) {
		if (p->dip == dip) {

			return (p);
		}
	}

	cmn_err(CE_PANIC, "unable to find pwr info data for %s@%s",
	    ddi_node_name(dip), ddi_get_name_addr(dip));

	/*NOTREACHED*/
	return (NULL);
}

/*
 * Create a pci_pwr_chld_t structure for a given devinfo node.
 */
void
pci_pwr_create_info(pci_pwr_t *pwr_p, dev_info_t *dip)
{
	pci_pwr_chld_t *p;

	ASSERT(PM_CAPABLE(pwr_p));

	DEBUG2(DBG_PWR, ddi_get_parent(dip), "ADDING NEW PWR_INFO %s@%s\n",
	    ddi_node_name(dip), ddi_get_name_addr(dip));

	p = kmem_zalloc(sizeof (struct pci_pwr_chld), KM_SLEEP);
	p->dip = dip;

	mutex_enter(&pwr_p->pwr_mutex);

	/*
	 * Until components are created for this device, bus
	 * should be at full power since power of child device
	 * is unknown.  Increment # children requiring "full power"
	 */
	p->flags |= PWR_FP_HOLD;
	pwr_p->pwr_fp++;

	p->next =  pwr_p->pwr_info;
	pwr_p->pwr_info = p;

	pci_pwr_change(pwr_p, pwr_p->current_lvl, pci_pwr_new_lvl(pwr_p));

	mutex_exit(&pwr_p->pwr_mutex);
}

void
pci_pwr_rm_info(pci_pwr_t *pwr_p, dev_info_t *cdip)
{
	pci_pwr_chld_t **prev_infop;
	pci_pwr_chld_t *infop = NULL;
	int i;

	ASSERT(PM_CAPABLE(pwr_p));

	mutex_enter(&pwr_p->pwr_mutex);

	for (prev_infop = &pwr_p->pwr_info; *prev_infop != NULL;
	    prev_infop = &((*prev_infop)->next)) {
		if ((*prev_infop)->dip == cdip) {
			infop = *prev_infop;
			break;
		}
	}

	if (infop == NULL) {

		mutex_exit(&pwr_p->pwr_mutex);
		return;
	}

	*prev_infop =  infop->next;

	/*
	 * Remove any reference counts for this child.
	 */
	if (infop->comp_pwr != NULL) {
		for (i = 0; i < infop->num_comps; i++) {
			pci_pwr_update_comp(pwr_p, infop, i, PM_LEVEL_NOLEVEL);
		}

		kmem_free(infop->comp_pwr, sizeof (int) * infop->num_comps);
	}

	if (infop->flags & PWR_FP_HOLD) {
		pwr_p->pwr_fp--;
	}

	pci_pwr_change(pwr_p, pwr_p->current_lvl, pci_pwr_new_lvl(pwr_p));
	mutex_exit(&pwr_p->pwr_mutex);
	kmem_free(infop, sizeof (struct pci_pwr_chld));
}

/*
 * Allocate space for component state information in pci_pwr_chld_t
 */
void
pci_pwr_add_components(pci_pwr_t *pwr_p, dev_info_t *cdip, pci_pwr_chld_t *p)
{
	int num_comps = PM_NUMCMPTS(cdip);
	int i;

	ASSERT(MUTEX_HELD(&pwr_p->pwr_mutex));
	/*
	 * Assume the power level of a component is UNKNOWN until
	 * notified otherwise.
	 */
	if (num_comps > 0) {
		p->comp_pwr =
		    kmem_alloc(sizeof (int) * num_comps, KM_SLEEP);
		p->num_comps = num_comps;

		DEBUG3(DBG_PWR, ddi_get_parent(cdip),
		    "ADDING %d COMPONENTS FOR %s@%s\n", num_comps,
		    ddi_node_name(cdip), ddi_get_name_addr(cdip));
	} else {
		cmn_err(CE_WARN, "%s%d device has %d components",
		    ddi_driver_name(cdip), ddi_get_instance(cdip),
		    num_comps);

		return;
	}

	/*
	 * Release the fp hold that was made when the device
	 * was created.
	 */
	ASSERT((p->flags & PWR_FP_HOLD) == PWR_FP_HOLD);
	p->flags &= ~PWR_FP_HOLD;
	pwr_p->pwr_fp--;

	for (i = 0; i < num_comps; i++) {
		/*
		 * Initialize the component lvl so that the
		 * state reference counts will be updated correctly.
		 */
		p->comp_pwr[i] = PM_LEVEL_NOLEVEL;
		pci_pwr_update_comp(pwr_p, p, i, PM_LEVEL_UNKNOWN);
	}
}

/*
 * Update the current power level for component.  Then adjust the
 * bus reference counter for given state.
 */
static void
pci_pwr_update_comp(pci_pwr_t *pwr_p, pci_pwr_chld_t *p, int comp,
			int lvl)
{
	ASSERT(MUTEX_HELD(&pwr_p->pwr_mutex));

	/*
	 * Remove old pwr state count for old PM level.
	 */
	switch (p->comp_pwr[comp]) {
	case PM_LEVEL_UNKNOWN:
		pwr_p->pwr_uk--;
		p->u01--;
		ASSERT(pwr_p->pwr_uk >= 0);
		break;
	case PM_LEVEL_D0:
		pwr_p->pwr_d0--;
		p->u01--;
		ASSERT(pwr_p->pwr_d0 >= 0);
		break;
	case PM_LEVEL_D1:
		pwr_p->pwr_d1--;
		p->u01--;
		ASSERT(pwr_p->pwr_d1 >= 0);
		break;
	case PM_LEVEL_D2:
		pwr_p->pwr_d2--;
		ASSERT(pwr_p->pwr_d2 >= 0);
		break;
	case PM_LEVEL_D3:
		pwr_p->pwr_d3--;
		ASSERT(pwr_p->pwr_d3 >= 0);
		break;
	default:
		break;
	}

	p->comp_pwr[comp] = lvl;
	/*
	 * Add new pwr state count for the new PM level.
	 */
	switch (lvl) {
	case PM_LEVEL_UNKNOWN:
		pwr_p->pwr_uk++;
		p->u01++;
		break;
	case PM_LEVEL_D0:
		pwr_p->pwr_d0++;
		p->u01++;
		break;
	case PM_LEVEL_D1:
		pwr_p->pwr_d1++;
		p->u01++;
		break;
	case PM_LEVEL_D2:
		pwr_p->pwr_d2++;
		break;
	case PM_LEVEL_D3:
		pwr_p->pwr_d3++;
		break;
	default:
		break;
	}

}

/*
 * Knowing the current state of all devices on the bus, return the
 * appropriate supported bus speed.
 */
int
pci_pwr_new_lvl(pci_pwr_t *pwr_p)
{
	int b_lvl;

	ASSERT(MUTEX_HELD(&pwr_p->pwr_mutex));

	if (pwr_p->pwr_fp > 0) {
		DEBUG1(DBG_PWR, pwr_p->pwr_dip, "new_lvl: "
		    "returning PM_LEVEL_B0 pwr_fp = %d\n", pwr_p->pwr_fp);

		return (PM_LEVEL_B0);
	}

	/*
	 * If any components are at unknown power levels, the
	 * highest power level has to be assumed for the device (D0).
	 */
	if (pwr_p->pwr_uk > 0) {
		DEBUG1(DBG_PWR, pwr_p->pwr_dip, "new_lvl: unknown "
		    "count is %d. returning PM_LEVEL_B0\n", pwr_p->pwr_uk);

		return (PM_LEVEL_B0);
	}

	/*
	 * Find the lowest theoretical level
	 * the bus can operate at.
	 */
	if (pwr_p->pwr_d0 > 0) {
		b_lvl = PM_LEVEL_B0;
		DEBUG1(DBG_PWR, pwr_p->pwr_dip,
		    "new_lvl: PM_LEVEL_B0 d0 count = %d\n",
		    pwr_p->pwr_d0);
	} else if (pwr_p->pwr_d1 > 0) {
		b_lvl = PM_LEVEL_B1;
		DEBUG1(DBG_PWR, pwr_p->pwr_dip,
		    "new_lvl: PM_LEVEL_B1 d1 count = %d\n",
		    pwr_p->pwr_d1);
	} else if (pwr_p->pwr_d2 > 0) {
		b_lvl = PM_LEVEL_B2;
		DEBUG1(DBG_PWR, pwr_p->pwr_dip,
		    "new_lvl: PM_LEVEL_B2 d2 count = %d\n",
		    pwr_p->pwr_d2);
	} else if (pwr_p->pwr_d3 > 0) {
		b_lvl = PM_LEVEL_B3;
		DEBUG1(DBG_PWR, pwr_p->pwr_dip,
		    "new_lvl: PM_LEVEL_B3 d3 count = %d\n",
		    pwr_p->pwr_d3);
	} else {
		DEBUG0(DBG_PWR, pwr_p->pwr_dip,
		    "new_lvl: PM_LEVEL_B3: all counts are 0\n");
		b_lvl = PM_LEVEL_B3;
	}

	/*
	 * Now find the closest supported level available.
	 * If the level isn't available, have to find the
	 * next highest power level (or lowest in B# terms).
	 */
	switch (b_lvl) {
	case PM_LEVEL_B3:
		if (pwr_p->pwr_flags & PCI_PWR_B3_CAPABLE) {
			break;
		}
		/*FALLTHROUGH*/
	case PM_LEVEL_B2:
		if (pwr_p->pwr_flags & PCI_PWR_B2_CAPABLE) {
			b_lvl = PM_LEVEL_B2;
			break;
		}
		/*FALLTHROUGH*/
	case PM_LEVEL_B1:
		if (pwr_p->pwr_flags & PCI_PWR_B1_CAPABLE) {
			b_lvl = PM_LEVEL_B1;
			break;
		}
		/*FALLTHROUGH*/
	case PM_LEVEL_B0:
		/*
		 * This level always supported
		 */
		b_lvl = PM_LEVEL_B0;
		break;
	}
	DEBUG1(DBG_PWR, pwr_p->pwr_dip,
	    "new_lvl: Adjusted Level is %s\n",
	    pci_pwr_bus_label[b_lvl]);

	return (b_lvl);

}

int
pci_raise_power(pci_pwr_t *pwr_p, int current, int new, void *impl_arg,
    pm_bp_nexus_pwrup_t bpn)
{
	int ret = DDI_SUCCESS, pwrup_res;

	ASSERT(MUTEX_HELD(&pwr_p->pwr_mutex));

	pci_pwr_component_busy(pwr_p);
	mutex_exit(&pwr_p->pwr_mutex);
	ret = pm_busop_bus_power(pwr_p->pwr_dip, impl_arg,
	    BUS_POWER_NEXUS_PWRUP, (void *) &bpn,
	    (void *) &pwrup_res);
	if (ret != DDI_SUCCESS || pwrup_res != DDI_SUCCESS) {
		mutex_enter(&pwr_p->pwr_mutex);
		pci_pwr_component_idle(pwr_p);
		mutex_exit(&pwr_p->pwr_mutex);
		cmn_err(CE_WARN, "%s%d pci_raise_power failed",
		    ddi_driver_name(pwr_p->pwr_dip),
		    ddi_get_instance(pwr_p->pwr_dip));
	}

	return (ret);
}

int
pci_pwr_ops(pci_pwr_t *pwr_p, dev_info_t *dip, void *impl_arg,
    pm_bus_power_op_t op, void *arg, void *result)
{
	pci_pwr_chld_t *p_chld;
	pm_bp_nexus_pwrup_t bpn;
	pm_bp_child_pwrchg_t *bpc = (pm_bp_child_pwrchg_t *)arg;
	dev_info_t *rdip = bpc->bpc_dip;
	int new_level, *res = (int *)result, ret = DDI_SUCCESS;

	mutex_enter(&pwr_p->pwr_mutex);
	switch (op) {
	case BUS_POWER_HAS_CHANGED:
		p_chld = pci_pwr_get_info(pwr_p, rdip);
		DEBUG5(DBG_PWR, dip, "%s@%s CHANGED_POWER cmp = %d "
		    "old = %d new = %d\n",
			ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    bpc->bpc_comp, bpc->bpc_olevel, bpc->bpc_nlevel);

		if (*res == DDI_FAILURE) {
			DEBUG0(DBG_PWR, rdip, "changed_power_req FAILED\n");
			break;
		} else {

			/*
			 * pci_pwr_add_components must be called here if
			 * comp_pwr hasn't been set up yet.  It has to be done
			 * here rather than in post-attach, since it is possible
			 * for power() of child to get called before attach
			 * completes.
			 */
			if (p_chld->comp_pwr == NULL)
				pci_pwr_add_components(pwr_p, rdip, p_chld);

			pci_pwr_update_comp(pwr_p, p_chld,
			    bpc->bpc_comp, bpc->bpc_nlevel);
		}

		new_level = pci_pwr_new_lvl(pwr_p);
		bpn.bpn_dip = pwr_p->pwr_dip;
		bpn.bpn_comp = PCI_PM_COMP_0;
		bpn.bpn_level = new_level;
		bpn.bpn_private = bpc->bpc_private;

		if (new_level > pwr_p->current_lvl)
			return (pci_raise_power(pwr_p, pwr_p->current_lvl,
			    new_level, impl_arg, bpn));
		else
			pci_pwr_change(pwr_p, pwr_p->current_lvl,
			    new_level);
		break;

	case BUS_POWER_PRE_NOTIFICATION:
		DEBUG5(DBG_PWR, dip, "PRE %s@%s cmp = %d old = %d "
		    "new = %d. TEMP FULL POWER\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    bpc->bpc_comp, bpc->bpc_olevel, bpc->bpc_nlevel);

		/*
		 * Any state changes require that the bus be at full
		 * power (B0) so that the device configuration
		 * registers can be accessed.  Make a fp hold here
		 * so device remains at full power during power
		 * configuration.
		 */

		pwr_p->pwr_fp++;
		DEBUG1(DBG_PWR, pwr_p->pwr_dip,
		    "incremented fp is %d in PRE_NOTE\n\n", pwr_p->pwr_fp);

		bpn.bpn_dip = pwr_p->pwr_dip;
		bpn.bpn_comp = PCI_PM_COMP_0;
		bpn.bpn_level = PM_LEVEL_B0;
		bpn.bpn_private = bpc->bpc_private;

		if (PM_LEVEL_B0 > pwr_p->current_lvl)
			return (pci_raise_power(pwr_p, pwr_p->current_lvl,
			    PM_LEVEL_B0, impl_arg, bpn));

		break;

	case BUS_POWER_POST_NOTIFICATION:
		p_chld = pci_pwr_get_info(pwr_p, rdip);
		DEBUG5(DBG_PWR, dip, "POST %s@%s cmp = %d old = %d new = %d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    bpc->bpc_comp, bpc->bpc_olevel, bpc->bpc_nlevel);

		if (*res == DDI_FAILURE) {
			DEBUG0(DBG_PWR, rdip, "child's power routine FAILED\n");
		} else {

			/*
			 * pci_pwr_add_components must be called here if
			 * comp_pwr hasen't been set up yet.  It has to be done
			 * here rather than in post-attach, since it is possible
			 * for power() of child to get called before attach
			 * completes.
			 */
			if (p_chld->comp_pwr == NULL)
				pci_pwr_add_components(pwr_p, rdip, p_chld);

			pci_pwr_update_comp(pwr_p, p_chld,
			    bpc->bpc_comp, bpc->bpc_nlevel);

		}

		pwr_p->pwr_fp--;
		DEBUG1(DBG_PWR, pwr_p->pwr_dip,
		    "decremented fp is %d in POST_NOTE\n\n", pwr_p->pwr_fp);

		new_level = pci_pwr_new_lvl(pwr_p);
		bpn.bpn_dip = pwr_p->pwr_dip;
		bpn.bpn_comp = PCI_PM_COMP_0;
		bpn.bpn_level = new_level;
		bpn.bpn_private = bpc->bpc_private;

		if (new_level > pwr_p->current_lvl)
			return (pci_raise_power(pwr_p, pwr_p->current_lvl,
			    new_level, impl_arg, bpn));
		else
			pci_pwr_change(pwr_p, pwr_p->current_lvl,
			    new_level);

		break;
	default:
		mutex_exit(&pwr_p->pwr_mutex);
		return (pm_busop_bus_power(dip, impl_arg, op, arg, result));
	}

	mutex_exit(&pwr_p->pwr_mutex);

	return (ret);
}

void
pci_pwr_resume(dev_info_t *dip, pci_pwr_t *pwr_p)
{
	dev_info_t *cdip;

	/*
	 * Inform the PM framework of the current state of the device.
	 * (it is unknown to PM framework at this point).
	 */
	if (PM_CAPABLE(pwr_p)) {
		pwr_p->current_lvl = pci_pwr_current_lvl(pwr_p);
		pm_power_has_changed(dip, PCI_PM_COMP_0,
		    pwr_p->current_lvl);
	}

	/*
	 * Restore config registers for children that did not save
	 * their own registers.  Children pwr states are UNKNOWN after
	 * a resume since it is possible for the PM framework to call
	 * resume without an actual power cycle. (ie if suspend fails).
	 */
	for (cdip = ddi_get_child(dip); cdip != NULL;
		cdip = ddi_get_next_sibling(cdip)) {

		/*
		 * Not interested in children who are not already
		 * init'ed.  They will be set up by init_child().
		 */
		if (i_ddi_node_state(cdip) < DS_INITIALIZED) {
			DEBUG2(DBG_DETACH, dip,
			    "DDI_RESUME: skipping %s%d not in CF1\n",
			    ddi_driver_name(cdip), ddi_get_instance(cdip));

			continue;
		}

		/*
		 * Only restore config registers if saved by nexus.
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    NEXUS_SAVED) == 1) {
			(void) pci_restore_config_regs(cdip);

			DEBUG2(DBG_PWR, dip,
			    "DDI_RESUME: nexus restoring %s%d config regs\n",
			    ddi_driver_name(cdip), ddi_get_instance(cdip));


			if (ndi_prop_remove(DDI_DEV_T_NONE, cdip,
			    NEXUS_SAVED) != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "%s%d can't remove prop %s",
				    ddi_driver_name(cdip),
				    ddi_get_instance(cdip),
				    NEXUS_SAVED);
			}
		}
	}
}

void
pci_pwr_suspend(dev_info_t *dip, pci_pwr_t *pwr_p)
{
	dev_info_t *cdip;

	/*
	 * Save the state of the configuration headers of child
	 * nodes.
	 */

	for (cdip = ddi_get_child(dip); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {
		pci_pwr_chld_t *p;
		int i;
		int num_comps;
		int ret;
		/*
		 * Not interested in children who are not already
		 * init'ed.  They will be set up in init_child().
		 */
		if (i_ddi_node_state(cdip) < DS_INITIALIZED) {
			DEBUG2(DBG_DETACH, dip, "DDI_SUSPEND: skipping "
			    "%s%d not in CF1\n", ddi_driver_name(cdip),
			    ddi_get_instance(cdip));

			continue;
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
		ret = ndi_prop_create_boolean(DDI_DEV_T_NONE, cdip,
		    NEXUS_SAVED);

		if (ret != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "%s%d can't update prop %s",
			    ddi_driver_name(cdip), ddi_get_instance(cdip),
			    NEXUS_SAVED);
		}

		if (!PM_CAPABLE(pwr_p)) {
			(void) pci_save_config_regs(cdip);

			continue;
		}

		mutex_enter(&pwr_p->pwr_mutex);
		p = pci_pwr_get_info(pwr_p, cdip);
		num_comps = p->num_comps;

		/*
		 * If a device has components, reset the power level
		 * to unknown.  This will ensure that the bus is full
		 * power so that saving register won't panic (if
		 * the device is already powered off, the child should
		 * have already done the save, but an incorrect driver
		 * may have forgotten).  If resetting power levels
		 * to unknown isn't done here, it would have to be done
		 * in resume since pci driver has no way of knowing
		 * actual state of HW (power cycle may not have
		 * occurred, and it was decided that poking into a
		 * child's config space should be avoided unless
		 * absolutely necessary).
		 */
		if (p->comp_pwr == NULL) {
			(void) pci_save_config_regs(cdip);
		} else {

			for (i = 0; i < num_comps; i++) {
				pci_pwr_update_comp(pwr_p, p, i,
				    PM_LEVEL_UNKNOWN);
			}
			/*
			 * ensure bus power is on before saving
			 * config regs.
			 */
			pci_pwr_change(pwr_p, pwr_p->current_lvl,
			    pci_pwr_new_lvl(pwr_p));

			(void) pci_save_config_regs(cdip);
		}
		mutex_exit(&pwr_p->pwr_mutex);
	}
}

void
pci_pwr_component_busy(pci_pwr_t *p)
{
	ASSERT(MUTEX_HELD(&p->pwr_mutex));
	if ((p->pwr_flags & PCI_PWR_COMP_BUSY) == 0) {
		if (pm_busy_component(p->pwr_dip, PCI_PM_COMP_0) ==
		    DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "%s%d pm_busy_component failed",
			    ddi_driver_name(p->pwr_dip),
			    ddi_get_instance(p->pwr_dip));
		} else {
			DEBUG0(DBG_PWR, p->pwr_dip,
			    "called PM_BUSY_COMPONENT().  BUSY BIT SET\n");
			p->pwr_flags |= PCI_PWR_COMP_BUSY;
		}
	} else {
		DEBUG0(DBG_PWR, p->pwr_dip, "BUSY BIT ALREADY SET\n");
	}
}

void
pci_pwr_component_idle(pci_pwr_t *p)
{
	ASSERT(MUTEX_HELD(&p->pwr_mutex));
	if (p->pwr_flags & PCI_PWR_COMP_BUSY) {
		if (pm_idle_component(p->pwr_dip, PCI_PM_COMP_0) ==
		    DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "%s%d pm_idle_component failed",
			    ddi_driver_name(p->pwr_dip),
			    ddi_get_instance(p->pwr_dip));
		} else {
			DEBUG0(DBG_PWR, p->pwr_dip,
			    "called PM_IDLE_COMPONENT() BUSY BIT CLEARED\n");
			p->pwr_flags &= ~PCI_PWR_COMP_BUSY;
		}
	} else {
		DEBUG0(DBG_PWR, p->pwr_dip, "BUSY BIT ALREADY CLEARED\n");
	}
}

void
pci_pwr_change(pci_pwr_t *pwr_p, int current, int new)
{
	ASSERT(MUTEX_HELD(&pwr_p->pwr_mutex));
	if (current == new) {
		DEBUG2(DBG_PWR, pwr_p->pwr_dip,
		    "No change in power required. Should be "
		    "busy. (current=%d) == (new=%d)\n",
		    current, new);
		pci_pwr_component_busy(pwr_p);

		return;
	}

	if (new < current) {
		DEBUG2(DBG_PWR, pwr_p->pwr_dip,
		    "should be idle (new=%d) < (current=%d)\n",
		    new, current);
		pci_pwr_component_idle(pwr_p);

		return;
	}

	if (new > current) {
		DEBUG2(DBG_PWR, pwr_p->pwr_dip, "pwr_change: "
		    "pm_raise_power() and should be busy. "
		    "(new=%d) > (current=%d)\n", new, current);
		pci_pwr_component_busy(pwr_p);
		mutex_exit(&pwr_p->pwr_mutex);
		if (pm_raise_power(pwr_p->pwr_dip, PCI_PM_COMP_0,
		    new) == DDI_FAILURE) {
			cmn_err(CE_WARN, "%s%d pm_raise_power failed",
			    ddi_driver_name(pwr_p->pwr_dip),
			    ddi_get_instance(pwr_p->pwr_dip));
		}
		mutex_enter(&pwr_p->pwr_mutex);

		return;
	}
}
