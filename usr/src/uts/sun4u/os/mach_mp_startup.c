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
/*
 * Copyright 2019 Peter Tribble.
 */

#include <sys/machsystm.h>
#include <sys/cpu_module.h>
#include <sys/dtrace.h>
#include <sys/cpu_sgnblk_defs.h>

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

	if (cpuid == cpu0.cpu_id) {
		/*
		 * cpu0 starts out running.  Other cpus are
		 * still in OBP land and we will leave them
		 * alone for now.
		 */
		CPU_SIGNATURE(OS_SIG, SIGST_RUN, SIGSUBST_NULL, cpuid);
#ifdef	lint
		cpuid = cpuid;
#endif	/* lint */
	}
}

/*
 * Routine used to cleanup a CPU that has been powered off.  This will
 * destroy all per-cpu information related to this cpu.
 */
int
mp_cpu_unconfigure(int cpuid)
{
	int retval;
	void empty_cpu(int);
	extern int cleanup_cpu_common(int);

	ASSERT(MUTEX_HELD(&cpu_lock));

	retval = cleanup_cpu_common(cpuid);

	empty_cpu(cpuid);

	return (retval);
}

struct mp_find_cpu_arg {
	int cpuid;		/* set by mp_cpu_configure() */
	dev_info_t *dip;	/* set by mp_find_cpu() */
};

int
mp_find_cpu(dev_info_t *dip, void *arg)
{
	extern int get_portid_ddi(dev_info_t *, dev_info_t **);
	struct mp_find_cpu_arg *target = (struct mp_find_cpu_arg *)arg;
	char *type;
	int rv = DDI_WALK_CONTINUE;
	int cpuid;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device_type", &type))
		return (DDI_WALK_CONTINUE);

	if (strcmp(type, "cpu") != 0)
		goto out;

	cpuid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cpuid", -1);

	if (cpuid == -1)
		cpuid = get_portid_ddi(dip, NULL);
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
	extern void fill_cpu_ddi(dev_info_t *);
	extern int setup_cpu_common(int);
	struct mp_find_cpu_arg target;

	ASSERT(MUTEX_HELD(&cpu_lock));

	target.dip = NULL;
	target.cpuid = cpuid;
	ddi_walk_devs(ddi_root_node(), mp_find_cpu, &target);

	if (target.dip == NULL)
		return (ENODEV);

	/*
	 * Note:  uses cpu_lock to protect cpunodes and ncpunodes
	 * which will be modified inside of fill_cpu_ddi().
	 */
	fill_cpu_ddi(target.dip);

	/*
	 * sun4v cpu setup may fail. sun4u assumes cpu setup to
	 * be always successful, so the return value is ignored.
	 */
	(void) setup_cpu_common(cpuid);

	return (0);
}

void
populate_idstr(struct cpu *cp)
{
	char buf[CPU_IDSTRLEN];
	struct cpu_node *cpunode;
	processor_info_t *pi;

	cpunode = &cpunodes[cp->cpu_id];
	pi = &cp->cpu_type_info;
	(void) snprintf(buf, sizeof (buf),
	    "%s (portid %d impl 0x%x ver 0x%x clock %d MHz)",
	    cpunode->name, cpunode->portid, cpunode->implementation,
	    cpunode->version, pi->pi_clock);
	cp->cpu_idstr = kmem_alloc(strlen(buf) + 1, KM_SLEEP);
	(void) strcpy(cp->cpu_idstr, buf);

	cp->cpu_brandstr = kmem_alloc(strlen(cpunode->name) + 1, KM_SLEEP);
	(void) strcpy(cp->cpu_brandstr, cpunode->name);

	cmn_err(CE_CONT, "?cpu%d: %s\n", cp->cpu_id, cp->cpu_idstr);
}
