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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2019 Peter Tribble.
 */

#include <sys/machsystm.h>
#include <sys/cpu_module.h>
#include <sys/dtrace.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/mach_descrip.h>
#include <sys/ldoms.h>
#include <sys/hypervisor_api.h>
#include <sys/soft_state.h>
#include <sys/mpo.h>

/*
 * Useful for disabling MP bring-up for an MP capable kernel
 * (a kernel that was built with MP defined)
 */
int use_mp = 1;			/* set to come up mp */

/*
 * Init CPU info - get CPU type info for processor_info system call.
 */
void
init_cpu_info(struct cpu *cp)
{
	processor_info_t *pi = &cp->cpu_type_info;
	int cpuid = cp->cpu_id;
	struct cpu_node *cpunode = &cpunodes[cpuid];

	cp->cpu_fpowner = NULL;		/* not used for V9 */

	/*
	 * Get clock-frequency property from cpunodes[] for the CPU.
	 */
	pi->pi_clock = (cpunode->clock_freq + 500000) / 1000000;

	/*
	 * Current frequency in Hz.
	 */
	cp->cpu_curr_clock = cpunode->clock_freq;

	/*
	 * Supported frequencies.
	 */
	cpu_set_supp_freqs(cp, NULL);

	(void) strcpy(pi->pi_processor_type, "sparcv9");
	(void) strcpy(pi->pi_fputypes, "sparcv9");

	/*
	 * cpu0 is always initialized at boot time, but it can be initialized
	 * again if it is dynamically removed and then re-added. We check if
	 * we are booting by verifying cpu_list. During boot, cpu0 is already
	 * in cpu_list when this function is called. When a cpu is dynamically
	 * added (after the boot) then it is added to cpu_list after this
	 * function is called.
	 */
	if (cpuid == cpu0.cpu_id && ncpus == 1 && cpu_list[0].cpu_id == cpuid) {
		/*
		 * cpu0 starts out running.  Other cpus are
		 * still in OBP land and we will leave them
		 * alone for now.
		 */
		CPU_SIGNATURE(OS_SIG, SIGST_RUN, SIGSUBST_NULL, cpuid);
		/*
		 * On first cpu setup, tell hv we are booting
		 */
		mach_set_soft_state(SIS_TRANSITION,
		    &SOLARIS_SOFT_STATE_BOOT_MSG);
#ifdef	lint
		cpuid = cpuid;
#endif	/* lint */
	}
}

/*
 * Routine used to cleanup a CPU that has been powered off. This will
 * destroy all per-cpu information related to this cpu.
 */
int
mp_cpu_unconfigure(int cpuid)
{
	int retval;
	extern void empty_cpu(int);
	extern int cleanup_cpu_common(int);

	ASSERT(MUTEX_HELD(&cpu_lock));

	retval = cleanup_cpu_common(cpuid);

	empty_cpu(cpuid);

	mpo_cpu_remove(cpuid);

	return (retval);
}

struct mp_find_cpu_arg {
	int cpuid;		/* set by mp_cpu_configure() */
	dev_info_t *dip;	/* set by mp_find_cpu() */
};

int
mp_find_cpu(dev_info_t *dip, void *arg)
{
	struct mp_find_cpu_arg *target = (struct mp_find_cpu_arg *)arg;
	char	*type;
	int	rv = DDI_WALK_CONTINUE;
	int	cpuid;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "device_type", &type))
		return (DDI_WALK_CONTINUE);

	if (strcmp(type, "cpu") != 0)
		goto out;

	cpuid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", -1);

	if (cpuid == -1) {
		cmn_err(CE_PANIC, "reg prop not found in cpu node");
	}

	cpuid = PROM_CFGHDL_TO_CPUID(cpuid);

	if (cpuid != target->cpuid)
		goto out;

	/* Found it */
	rv = DDI_WALK_TERMINATE;
	target->dip = dip;

out:
	ddi_prop_free(type);
	return (rv);
}

/*
 * Routine used to setup a newly inserted CPU in preparation for starting
 * it running code.
 */
int
mp_cpu_configure(int cpuid)
{
	md_t		*mdp;
	mde_cookie_t	rootnode, cpunode = MDE_INVAL_ELEM_COOKIE;
	int		listsz, i;
	mde_cookie_t	*listp = NULL;
	int		num_nodes;
	uint64_t	cpuid_prop;
	cpu_t		*cpu;
	processorid_t	id;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if ((mdp = md_get_handle()) == NULL)
		return (ENODEV);

	rootnode = md_root_node(mdp);

	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	num_nodes = md_node_count(mdp);

	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_SLEEP);

	num_nodes = md_scan_dag(mdp, rootnode, md_find_name(mdp, "cpu"),
	    md_find_name(mdp, "fwd"), listp);

	if (num_nodes < 0)
		return (ENODEV);

	for (i = 0; i < num_nodes; i++) {
		if (md_get_prop_val(mdp, listp[i], "id", &cpuid_prop))
			break;
		if (cpuid_prop == (uint64_t)cpuid) {
			cpunode = listp[i];
			break;
		}
	}

	if (cpunode == MDE_INVAL_ELEM_COOKIE)
		return (ENODEV);

	kmem_free(listp, listsz);

	mpo_cpu_add(mdp, cpuid);

	/*
	 * Note: uses cpu_lock to protect cpunodes
	 * which will be modified inside of fill_cpu and
	 * setup_exec_unit_mappings.
	 */
	fill_cpu(mdp, cpunode);

	/*
	 * Adding a CPU may cause the execution unit sharing
	 * relationships to change. Update the mappings in
	 * the cpunode structures.
	 */
	setup_chip_mappings(mdp);
	setup_exec_unit_mappings(mdp);

	/* propagate the updated mappings to the CPU structures */
	for (id = 0; id < NCPU; id++) {
		if ((cpu = cpu_get(id)) == NULL)
			continue;

		cpu_map_exec_units(cpu);
	}

	(void) md_fini_handle(mdp);

	if ((i = setup_cpu_common(cpuid)) != 0) {
		(void) cleanup_cpu_common(cpuid);
		return (i);
	}

	return (0);
}

/*
 * Platform-specific actions to be taken when all cpus are running
 * in the OS.
 */
void
cpu_mp_init(void)
{
	extern void recalc_xc_timeouts();
	extern int cif_cpu_mp_ready;

	/* N.B. This must happen after xc_init() has run. */
	recalc_xc_timeouts();

	if (!domaining_enabled())
		return;

	cif_cpu_mp_ready = 1;
}

void
populate_idstr(struct cpu *cp)
{
	char buf[CPU_IDSTRLEN];
	struct cpu_node *cpunode;
	processor_info_t *pi;

	cpunode = &cpunodes[cp->cpu_id];
	pi = &cp->cpu_type_info;
	if (cp->cpu_m.cpu_chip == CPU_CHIPID_INVALID) {
		(void) snprintf(buf, sizeof (buf),
		    "%s (cpuid %d, clock %d MHz)",
		    cpunode->name, cpunode->cpuid, pi->pi_clock);
	} else {
		(void) snprintf(buf, sizeof (buf),
		    "%s (chipid %d, clock %d MHz)",
		    cpunode->name, cp->cpu_m.cpu_chip, pi->pi_clock);
	}

	cp->cpu_idstr = kmem_alloc(strlen(buf) + 1, KM_SLEEP);
	(void) strcpy(cp->cpu_idstr, buf);

	cp->cpu_brandstr = kmem_alloc(strlen(cpunode->name) + 1, KM_SLEEP);
	(void) strcpy(cp->cpu_brandstr, cpunode->name);

	cmn_err(CE_CONT, "?cpu%d: %s\n", cp->cpu_id, cp->cpu_idstr);
}
