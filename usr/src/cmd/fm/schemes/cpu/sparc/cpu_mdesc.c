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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/processor.h>
#include <fm/fmd_fmri.h>
#include <sys/param.h>
#include <string.h>
#include <errno.h>
#include <cpu_mdesc.h>

int
cpu_get_serialid_mdesc(uint32_t cpuid, uint64_t *serialidp)
{
	int i;
	md_cpumap_t *mcmp;

	for (i = 0, mcmp = cpu.cpu_mdesc_cpus;
	    i < cpu.cpu_mdesc_ncpus; i++, mcmp++) {
		if (cpuid == mcmp->cpumap_pid) {
			*serialidp = mcmp->cpumap_serialno;
			return (0);
		}
	}

	return (fmd_fmri_set_errno(ENOENT));
}

int
cpu_mdesc_init(void)
{
	md_t *mdp;
	mde_cookie_t *listp;
	md_cpumap_t *mcmp;
	int num_nodes, idx;
	size_t bufsiz = 0;

	if ((mdp = mdesc_devinit(&bufsiz)) == NULL)
		return (0); /* successful, no mdesc */

	num_nodes = md_node_count(mdp);
	listp = fmd_fmri_alloc(sizeof (mde_cookie_t) * num_nodes);

	cpu.cpu_mdesc_ncpus = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "cpu"),
	    md_find_name(mdp, "fwd"),
	    listp);

	cpu.cpu_mdesc_cpus = fmd_fmri_alloc(cpu.cpu_mdesc_ncpus *
	    sizeof (md_cpumap_t));

	for (idx = 0, mcmp = cpu.cpu_mdesc_cpus;
	    idx < cpu.cpu_mdesc_ncpus;
	    idx++, mcmp++) {
		uint64_t tl;

		if (md_get_prop_val(mdp, listp[idx], "id", &tl) < 0)
			tl = (uint64_t)-1; /* invalid value */
		mcmp->cpumap_id = tl;

		if (md_get_prop_val(mdp, listp[idx], "pid", &tl) < 0)
			tl = mcmp->cpumap_id;
		mcmp->cpumap_pid = tl;

		if (md_get_prop_val(mdp, listp[idx], "serial#",
		    &mcmp->cpumap_serialno) < 0)
			mcmp->cpumap_serialno = 0;
	}

	fmd_fmri_free(listp, sizeof (mde_cookie_t) * num_nodes);
	fmd_fmri_free(*mdp, bufsiz);
	(void) md_fini(mdp);

	return (0);
}

void
cpu_mdesc_fini(void)
{
	if (cpu.cpu_mdesc_cpus != NULL) {
		fmd_fmri_free(cpu.cpu_mdesc_cpus,
		    cpu.cpu_mdesc_ncpus * sizeof (md_cpumap_t));
	}
}
