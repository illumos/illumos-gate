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
 * Platform Power Management master pseudo driver platform support.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ppmvar.h>
#include <sys/cpupm.h>

static struct ppm_domit *
ppm_get_domit_by_model(int model)
{
	struct ppm_domit *domit_p;
	for (domit_p = ppm_domit_data; (domit_p->name &&
	    (domit_p->model != model));	domit_p++)
		;
	ASSERT(domit_p);
	return (domit_p);
}

void
ppm_rebuild_cpu_domains(void)
{
	char *str = "ppm_rebuild_cpu_domains";
	cpupm_state_domains_t *dep;
	cpupm_state_domains_t *dep_next;
	struct ppm_domit *domit_p;
	ppm_domain_t *domp_old;
	ppm_domain_t *domp;
	ppm_dev_t *devp;
	ppm_db_t *dbp;
	uint_t cpu_id;
	cpuset_t dom_cpu_set;
	int result;
	dev_info_t *cpu_dip;

	/*
	 * Get the CPU domain data
	 */
	domit_p = ppm_get_domit_by_model(PPMD_CPU);

	/*
	 * Find the CPU domain created from ppm.conf. It's only a
	 * temporary domain used to make sure that all CPUs are
	 * claimed. There should only be one such domain defined.
	 */
	for (domp = ppm_domain_p; (domp && (domp->model != PPMD_CPU));
	    domp = domp->next)
		;
	if (domp == NULL) {
		cmn_err(CE_WARN, "%s: ppm.conf does not define a CPU domain!",
		    str);
		return;
	}
	domp_old = domp;
	for (domp = domp->next; domp; domp = domp->next) {
		if (domp->model == PPMD_CPU) {
			cmn_err(CE_WARN, "%s: Multiple CPU domains defined "
			    "in ppm.conf!", str);
			return;
		}
	}

	/*
	 * It is quite possible that the platform does not contain any
	 * power manageable CPUs. If so, devlist will be NULL.
	 */
	if (domp_old->devlist == NULL) {
		PPMD(D_CPU, ("%s: No CPUs claimed by ppm!\n", str));
		return;
	}

	/*
	 * Get the CPU dependencies as determined by the CPU driver. If
	 * the CPU driver didn't create a valid set of dependencies, then
	 * leave the domain as it is (which is unmanageable since
	 * PPM_CPU_READY is off).
	 */
	dep = cpupm_pstate_domains;
	if (dep == NULL) {
		PPMD(D_CPU, ("%s: No CPU dependency info!\n", str));
		return;
	}

	/*
	 * Build real CPU domains. OFFLINE the old one as we don't
	 * want it to be used when we're done.
	 */
	mutex_enter(&domp_old->lock);
	domp_old->dflags |= PPMD_OFFLINE;
	for (dep_next = dep; dep_next; dep_next = dep_next->pm_next) {
		domp = kmem_zalloc(sizeof (*domp), KM_SLEEP);
		domp->name =  kmem_zalloc(MAXNAMELEN, KM_SLEEP);
		(void) snprintf(domp->name, MAXNAMELEN, "acpi_cpu_domain_%d",
		    dep_next->pm_domain);
		mutex_init(&domp->lock, NULL, MUTEX_DRIVER, NULL);
		mutex_enter(&domp->lock);
		domp->dflags = domit_p->dflags | PPMD_CPU_READY;
		domp->pwr_cnt = 0;
		domp->propname = domp_old->propname;
		domp->model = domit_p->model;
		domp->status = domit_p->status;

		/*
		 * Add devices to new domain. As a precaution,
		 * make sure that the device is currently owned by the
		 * ppm.conf defined CPU domain. Adding the device to the
		 * domain will result in the domain's "devlist" and "owned"
		 * lists being properly formed. It will also update the
		 * dip pointer to the device structure. We have to manually
		 * build the "conflist" for the domain. But conveniently, the
		 * "conflist" data is easily obtainable from the "devlist".
		 */
		dom_cpu_set = dep_next->pm_cpus;
		do {
			CPUSET_FIND(dom_cpu_set, cpu_id);
			if (cpu_id == CPUSET_NOTINSET)
				break;

			ASSERT(cpu_id < NCPU);
			cpu_dip = ((cpupm_mach_state_t *)
			    (cpu[cpu_id]->cpu_m.mcpu_pm_mach_state))->ms_dip;
			devp = PPM_GET_PRIVATE(cpu_dip);
			ASSERT(devp && devp->domp == domp_old);
			devp = ppm_add_dev(cpu_dip, domp);
			dbp = kmem_zalloc(sizeof (struct ppm_db), KM_SLEEP);
			dbp->name = kmem_zalloc((strlen(devp->path) + 1),
			    KM_SLEEP);
			(void) strcpy(dbp->name, devp->path);
			dbp->next = domp->conflist;
			domp->conflist = dbp;

			CPUSET_ATOMIC_XDEL(dom_cpu_set, cpu_id, result);
		} while (result == 0);

		/*
		 * Note that we do not bother creating a "dc" list as there
		 * isn't one for x86 CPU power management. If this changes
		 * in the future some more work will need to be done to
		 * support it.
		 */
		ASSERT(domp_old->dc == NULL);

		/*
		 * Add the domain to the live list.
		 */
		domp->next = ppm_domain_p;
		ppm_domain_p = domp;

		mutex_exit(&domp->lock);
	}
	mutex_exit(&domp_old->lock);
}

/*
 * Used by ppm_redefine_topspeed() to set the highest power level of all CPUs
 * in a domain.
 */
void
ppm_set_topspeed(ppm_dev_t *cpup, int speed)
{
	for (cpup = cpup->domp->devlist; cpup != NULL; cpup = cpup->next)
		(*cpupm_set_topspeed_callb)(cpup->dip, speed);
}

/*
 * Redefine the highest power level for all CPUs in a domain. This
 * functionality is necessary because ACPI uses the _PPC to define
 * a CPU's highest power level *and* allows the _PPC to be redefined
 * dynamically. _PPC changes are communicated through _PPC change
 * notifications caught by the CPU device driver.
 */
void
ppm_redefine_topspeed(void *ctx)
{
	char *str = "ppm_redefine_topspeed";
	ppm_dev_t *cpup;
	ppm_dev_t *ncpup;
	int topspeed;
	int newspeed = -1;

	cpup = PPM_GET_PRIVATE((dev_info_t *)ctx);

	if (cpupm_get_topspeed_callb == NULL ||
	    cpupm_set_topspeed_callb == NULL) {
		cmn_err(CE_WARN, "%s: Cannot process request for instance %d "
		    "since cpupm interfaces are not initialized", str,
		    ddi_get_instance(cpup->dip));
		return;
	}

	if (!(cpup->domp->dflags & PPMD_CPU_READY)) {
		PPMD(D_CPU, ("%s: instance %d received _PPC change "
		    "notification before PPMD_CPU_READY", str,
		    ddi_get_instance(cpup->dip)));
		return;
	}

	/*
	 * Process each CPU in the domain.
	 */
	for (ncpup = cpup->domp->devlist; ncpup != NULL; ncpup = ncpup->next) {
		topspeed = (*cpupm_get_topspeed_callb)(ncpup->dip);
		if (newspeed == -1 || topspeed < newspeed)
			newspeed = topspeed;
	}

	ppm_set_topspeed(cpup, newspeed);
}

/*
 * Traverses all domains looking for CPU domains and for each CPU domain
 * redefines the topspeed for that domain. The reason that this is necessary
 * is that on x86 platforms ACPI allows the highest power level to be
 * redefined dynamically. Once all CPU devices have been started it we
 * need to go back and reinitialize the topspeeds (just in case it's changed).
 */
void
ppm_init_topspeed(void)
{
	ppm_domain_t *domp;
	for (domp = ppm_domain_p; domp;	domp = domp->next) {
		if (domp->model != PPMD_CPU || !PPM_DOMAIN_UP(domp))
			continue;
		if (domp->devlist == NULL)
			continue;
		ppm_redefine_topspeed(domp->devlist->dip);
	}
}

/*
 * For x86 platforms CPU domains must be built dynamically at bootime.
 * Until the domains have been built, refuse all power transition
 * requests.
 */
/* ARGSUSED */
boolean_t
ppm_manage_early_cpus(dev_info_t *dip, int new, int *result)
{
	ppm_dev_t *ppmd = PPM_GET_PRIVATE(dip);

	if (!(ppmd->domp->dflags & PPMD_CPU_READY)) {
		PPMD(D_CPU, ("ppm_manage_early_cpus: attempt to manage CPU "
		    "before it was ready dip(0x%p)", (void *)dip));
		return (B_TRUE);
	}
	*result = DDI_FAILURE;
	return (B_FALSE);
}

int
ppm_change_cpu_power(ppm_dev_t *ppmd, int newlevel)
{
#ifdef DEBUG
	char *str = "ppm_change_cpu_power";
#endif
	ppm_unit_t *unitp;
	ppm_domain_t *domp;
	ppm_dev_t *cpup;
	dev_info_t *dip;
	int oldlevel;
	int ret;

	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
	ASSERT(unitp);
	domp = ppmd->domp;
	cpup = domp->devlist;

	dip = cpup->dip;
	ASSERT(dip);

	oldlevel = cpup->level;

	PPMD(D_CPU, ("%s: old %d, new %d\n", str, oldlevel, newlevel))

	if (newlevel == oldlevel)
		return (DDI_SUCCESS);

	/* bring each cpu to next level */
	for (; cpup; cpup = cpup->next) {
		ret = pm_power(cpup->dip, 0, newlevel);
		PPMD(D_CPU, ("%s: \"%s\", changed to level %d, ret %d\n",
		    str, cpup->path, newlevel, ret))
		if (ret == DDI_SUCCESS) {
			cpup->level = newlevel;
			cpup->rplvl = PM_LEVEL_UNKNOWN;
			continue;
		}

		/*
		 * If the driver was unable to lower cpu speed,
		 * the cpu probably got busy; set the previous
		 * cpus back to the original level
		 */
		if (newlevel < oldlevel)
			ret = ppm_revert_cpu_power(cpup, oldlevel);

		return (ret);
	}

	return (DDI_SUCCESS);
}
