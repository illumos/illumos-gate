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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpupm.h>

/*
 * This callback is used to build the PPM CPU domains once
 * all the CPU devices have been started. The callback is
 * initialized by the PPM driver to point to a routine that
 * will build the domains.
 */
void (*cpupm_rebuild_cpu_domains)(void);

/*
 * This callback is used to reset the topspeed for all the
 * CPU devices. The callback is initialized by the PPM driver to
 * point to a routine that will reinitialize all the CPU devices
 * once all the CPU devices have been started and the CPU domains
 * built.
 */
void (*cpupm_init_topspeed)(void);

/*
 * This callback is used to redefine the topspeed for a CPU device.
 * Since all CPUs in a domain should have identical properties, this
 * callback is initialized by the PPM driver to point to a routine
 * that will redefine the topspeed for all devices in a CPU domain.
 * This callback is exercised whenever an ACPI _PPC change notification
 * is received by the CPU driver.
 */
void (*cpupm_redefine_topspeed)(void *);

/*
 * This callback is used by the PPM driver to call into the CPU driver
 * to find a CPU's current topspeed (i.e., it's current ACPI _PPC value).
 */
void (*cpupm_set_topspeed)(void *, int);

/*
 * This callback is used by the PPM driver to call into the CPU driver
 * to set a new topspeed for a CPU.
 */
int (*cpupm_get_topspeed)(void *);

/*
 * Used to dynamically keep track of the CPU dependencies as CPU
 * devices attach. Will subsequently be used by the PPM driver
 * to build PPM CPU domains.
 */
static cpupm_cpu_dependency_t *cpupm_cpu_dependencies = NULL;

/*
 * If we are unable to correctly identify a dependency for any CPU, then
 * we punt and all CPUs are managed as one domain.
 */
static boolean_t cpupm_dependencies_valid = B_TRUE;

/*
 * If any CPU fails to attach, then cpupm is disabled for all CPUs.
 */
static boolean_t cpupm_enabled = B_TRUE;

/*
 * Until all CPUs have succesfully attached, we do not allow
 * power management.
 */
static boolean_t cpupm_ready = B_FALSE;

/*
 * Print the CPU dependencies.
 */
static void
cpupm_print_cpu_dependencies()
{
	cpupm_cpu_dependency_t *dptr;
	cpupm_cpu_node_t *nptr;

	for (dptr = cpupm_cpu_dependencies; dptr != NULL;
	    dptr = dptr->cd_next) {
		for (nptr = dptr->cd_cpu; nptr != NULL; nptr = nptr->cn_next) {
			int instance = ddi_get_instance(nptr->cn_dip);
			cmn_err(CE_NOTE,
			    "print_cpu_dependencies: dependency %d "
			    "instance %d\n", dptr->cd_dependency_id, instance);
		}
	}
}

/*
 * Used to retrieve the dependencies built during CPUs attaching.
 */
cpupm_cpu_dependency_t *
cpupm_get_cpu_dependencies()
{
	return (cpupm_cpu_dependencies);
}

/*
 * Build dependencies as CPUs attach. Note that we don't need to worry
 * about locking the dependency lists as concurrency is not an issue.
 * This routine relies on the fact that the CPU devices are attached
 * sequentially by a single thread.
 */
void
cpupm_add_cpu2dependency(dev_info_t *dip, int cpu_dependency)
{
	cpupm_cpu_dependency_t *dptr;
	cpupm_cpu_node_t *nptr;

	if (!cpupm_dependencies_valid)
		return;

	if (cpu_dependency == -1) {
		cpupm_free_cpu_dependencies();
		return;
	}

	for (dptr = cpupm_cpu_dependencies; dptr != NULL;
	    dptr = dptr->cd_next) {
		if (dptr->cd_dependency_id == cpu_dependency)
			break;
	}

	/* new dependency is created and linked at the head */
	if (dptr == NULL) {
		dptr = kmem_zalloc(sizeof (cpupm_cpu_dependency_t), KM_SLEEP);
		dptr->cd_dependency_id = cpu_dependency;
		dptr->cd_next = cpupm_cpu_dependencies;
		cpupm_cpu_dependencies = dptr;
	}

	/* new cpu is created and linked at head of dependency */
	nptr = kmem_zalloc(sizeof (cpupm_cpu_node_t), KM_SLEEP);
	nptr->cn_dip = dip;
	nptr->cn_next = dptr->cd_cpu;
	dptr->cd_cpu = nptr;
}

/*
 * Free the CPU dependencies.
 */
void
cpupm_free_cpu_dependencies()
{
	cpupm_cpu_dependency_t *this_dependency, *next_dependency;
	cpupm_cpu_node_t *this_node, *next_node;

	cpupm_dependencies_valid = B_FALSE;
	this_dependency = cpupm_cpu_dependencies;
	while (this_dependency != NULL) {
		next_dependency = this_dependency->cd_next;

		/* discard CPU node chain */
		this_node = this_dependency->cd_cpu;
		while (this_node != NULL) {
			next_node = this_node->cn_next;
			kmem_free((void *)this_node,
			    sizeof (cpupm_cpu_node_t));
			this_node = next_node;
		}
		kmem_free((void *)this_dependency,
		    sizeof (cpupm_cpu_dependency_t));
		this_dependency = next_dependency;
	}
	cpupm_cpu_dependencies = NULL;
}

/*
 * If all CPUs have attached successfully, then the CPUs are
 * ready for power management.
 */
boolean_t
cpupm_is_ready()
{
#ifndef	__xpv
	if (!cpupm_enabled)
		return (B_FALSE);
	return (cpupm_ready);
#else
	return (B_FALSE);
#endif
}

/*
 * By default, cpupm is enabled. But if there are any errors attaching
 * any of the CPU devices, then it is disabled.
 */
void
cpupm_enable(boolean_t enable)
{
	if (!enable)
		cpupm_free_cpu_dependencies();
	cpupm_enabled = enable;
}

/*
 * Once all CPUs have been started, the PPM driver should build CPU
 * domains and initialize the topspeed for all CPU devices.
 */
void
cpupm_post_startup()
{
#ifndef	__xpv
	/*
	 * The CPU domain built by the PPM during CPUs attaching
	 * should be rebuilt with the information retrieved from
	 * ACPI.
	 */
	if (cpupm_rebuild_cpu_domains != NULL)
		(*cpupm_rebuild_cpu_domains)();

	/*
	 * If CPU power management was disabled, then there
	 * is nothing to do.
	 */
	if (!cpupm_enabled)
		return;

	cpupm_ready = B_TRUE;

	if (cpupm_init_topspeed != NULL)
		(*cpupm_init_topspeed)();
#else
	cpupm_ready = B_TRUE;
#endif
}
